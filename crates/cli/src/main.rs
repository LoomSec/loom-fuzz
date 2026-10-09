//! loom-fuzz 二进制：闭环管线串联（issue #7）。
//!
//! - `loom-fuzz run`：模式 A/B 装载 HitSet → xlayer 展开 → seed 编译
//!   → fuzz 定向执行（每 hit 一个独立会话——CFG 目标不同）→ oracle
//!   三值判决 → 落盘 fuzz_report.json + 每个 confirmed hit 的
//!   poc.json。退出码恒 0（判决如实落盘，无见证只降级不过滤）；
//!   输入/装载错误 fail-closed 退出 2 并指明缺什么。
//! - `loom-fuzz replay <poc.json>`：用 poc 的确定性参数重建会话重跑
//!   判决；退出码 0 = verdict 与 poc 记录一致，1 = 不一致。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use alloy_primitives::U256;
use clap::{Parser, Subcommand};

use loom_fuzz_fuzz::{DistanceTable, ExecConfig};
use loom_fuzz_oracle::{
    build_poc, coverage, hex_u256, replay, Budgets, FuzzReport, Guidance, Hit, HitEntry, HitReport,
    Poc, Verdict, REPORT_FORMAT,
};
use loom_fuzz_seed::{compile, locate, HitView, Target};
use loom_fuzz_seed::{Input as SeedInput, Tail};
use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::Xlayer;

use loom_fuzz_cli::{load_from_cli, load_from_shard};

const CONTRACT_ADDRESS: [u8; 20] = [0x22; 20];

#[derive(Parser)]
#[command(
    name = "loom-fuzz",
    version,
    about = "loom-evm 检测命中的见证闭环：种子 → 定向执行 → 族 oracle 三值判决"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // 子命令旗面天然不均
enum Cmd {
    /// 跑完整闭环：装载 → seed → fuzz → oracle → fuzz_report.json (+ poc.json)
    Run {
        /// .lst shard（模式 B 必需；模式 A 也要，步序 → pc 映射来源）
        #[arg(long)]
        shard: PathBuf,
        /// 运行时字节码 hex 文件
        #[arg(long)]
        code: PathBuf,
        /// 检测 pack（给 --loom-bin 走模式 A；可多次——
        /// arbitrary_call.lq / approval_drain.lq 并集查询，#20）。
        #[arg(long = "pack")]
        pack: Vec<PathBuf>,
        /// loom 二进制路径（模式 A）
        #[arg(long)]
        loom_bin: Option<PathBuf>,
        /// prestate 槽值 JSON（hex → hex 的 map）
        #[arg(long)]
        prestate: Option<PathBuf>,
        /// 确定性种子
        #[arg(long, default_value_t = 0xC0FF_EE00_0000_0001)]
        seed: u64,
        /// runs 预算上限（默认 60_000——时间预算先到为准；显式小
        /// 预算用于定向测试）
        #[arg(long, default_value_t = 60_000)]
        max_runs: u64,
        /// 时间预算（秒）
        #[arg(
            long = "time-budget",
            alias = "time-budget-secs",
            default_value_t = 300
        )]
        time_budget_secs: u64,
        /// 每 run 的 tx gas limit
        #[arg(long, default_value_t = 1_000_000)]
        gas_per_tx: u64,
        /// 值字典补充词（0x-hex，可重复）。M0 补法：shard 无
        /// registry/白名单事实段，注册表常量由调用方从 prestate
        /// 语义补充（docs/architecture.md 值字典定义）。
        #[arg(long = "dict-word")]
        dict_word: Vec<String>,
        /// 产物目录（fuzz_report.json / poc-*.json）
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// confirmed 的 hit 顺手生成 L2 exploit 工程（pocgen）并跑
        /// forge test（--emit-poc <dir>）；L2 无法机械组装的 hit 如实
        /// 标注"诚实降级"并继续（不中断 run）
        #[arg(long)]
        emit_poc: Option<PathBuf>,
        /// on-demand fork：JSON-RPC URL（env BLOCKMACHINE_RPC_URL 兜底，
        /// 默认 https://rpc-eth.blockmachine.io）。
        #[arg(long)]
        fork_url: Option<String>,
        /// pin block（数字/"latest"——latest 先解析成具体块号，确定性
        /// 前提）。
        #[arg(long, default_value = "latest")]
        fork_block: String,
        /// fork 后部署攻击合约（可多次）：`<addr>:<runtime-hex 或
        /// responder 或 responder-sender 或 forwarder>`（responder =
        /// 任何 call 返回 0x01…，responder-sender = 返回 msg.sender，
        /// ABI 右对齐；forwarder = 攻击代理入口——fallback 原样 CALL
        /// 转发 calldata 到分析合约，机械模板零个案，#34）。多值 =
        /// 多合约在场（合约表 = victim + 各部署）。
        #[arg(long = "deploy")]
        deploy: Vec<String>,
        /// 顶层交易入口合约地址（issue #34）：须在合约表内（分析
        /// 合约地址或某个 --deploy 地址）——caller 轮换 ATTACKER →
        /// 入口合约 → victim 的装载形态（deputy 场景 caller 守卫
        /// 绕过）。缺省 = 直接 call 分析合约（单步默认不变）。
        #[arg(long)]
        entry: Option<String>,
        /// 调用序列长度上限（issue #35）：1 = 单步默认（与旧行为
        /// 完全等价）；>1 时搜索在步级提案之上机械组装多步序列
        /// （append / splice / 步内变异），状态跨步持久。
        #[arg(long, default_value_t = 1)]
        max_steps: u32,
        /// 分析合约的链上真实地址：fork 态必须在真实地址上执行（否则
        /// 合约自身状态错位）——CLI 强制。
        #[arg(long)]
        contract_addr: Option<String>,
    },
    /// L2 exploit 影响层：poc.json → Foundry 工程 + forge test（绿灯 = 终判）
    Exploit {
        /// confirmed 的 poc.json
        poc: PathBuf,
        /// 运行时字节码 hex 文件
        #[arg(long)]
        code: PathBuf,
        /// 工程输出目录
        #[arg(long)]
        out: PathBuf,
        /// 生成 fork 模式工程（BlockMachine：run.sh + fork profile）
        #[arg(long)]
        fork: bool,
    },
    /// 重放 poc.json：重建会话重跑判决，打印 verdict JSON
    Replay {
        /// poc.json 路径
        poc: PathBuf,
        /// 运行时字节码 hex 文件
        #[arg(long)]
        code: PathBuf,
        /// prestate 槽值 JSON（覆盖 poc 内嵌 prestate）
        #[arg(long)]
        prestate: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("loom-fuzz: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run {
            shard,
            code,
            pack,
            loom_bin,
            prestate,
            seed,
            max_runs,
            time_budget_secs,
            gas_per_tx,
            dict_word,
            out,
            emit_poc,
            fork_url,
            fork_block,
            deploy,
            entry,
            max_steps,
            contract_addr,
        } => cmd_run(
            &shard,
            &code,
            &pack,
            loom_bin.as_deref(),
            prestate.as_deref(),
            seed,
            max_runs,
            time_budget_secs,
            gas_per_tx,
            &dict_word,
            &out,
            emit_poc.as_deref(),
            fork_url.as_deref(),
            &fork_block,
            &deploy,
            entry.as_deref(),
            max_steps,
            contract_addr.as_deref(),
        ),
        Cmd::Exploit {
            poc,
            code,
            out,
            fork,
        } => cmd_exploit(&poc, &code, &out, fork),
        Cmd::Replay {
            poc,
            code,
            prestate,
        } => cmd_replay(&poc, &code, prestate.as_deref()),
    }
}

/// prestate JSON（hex → hex 的 map）读取解析（fail-closed）。
fn read_prestate(path: Option<&Path>) -> Result<BTreeMap<U256, U256>, String> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("无法读取 prestate {}: {e}", path.display()))?;
    let raw: BTreeMap<String, String> = serde_json::from_str(&text)
        .map_err(|e| format!("prestate {} 不是 JSON map: {e}", path.display()))?;
    raw.into_iter()
        .map(|(k, v)| Ok((hex_u256(&k)?, hex_u256(&v)?)))
        .collect()
}

#[allow(clippy::too_many_arguments)] // 管线参数即 CLI 旗面，成组传递无益
fn cmd_run(
    shard_path: &Path,
    code_path: &Path,
    packs: &[PathBuf],
    loom_bin: Option<&Path>,
    prestate_path: Option<&Path>,
    seed: u64,
    max_runs: u64,
    time_budget_secs: u64,
    gas_per_tx: u64,
    dict_words: &[String],
    out_dir: &Path,
    emit_poc: Option<&Path>,
    fork_url: Option<&str>,
    fork_block: &str,
    deploy_flags: &[String],
    entry_flag: Option<&str>,
    max_steps: u32,
    contract_addr: Option<&str>,
) -> Result<ExitCode, String> {
    // 装载（模式 A 需 pack+loom-bin 成对；只给一个 = fail-closed）。
    let hitset = match (packs.is_empty(), loom_bin) {
        (false, Some(bin)) => {
            let pack_refs: Vec<&Path> = packs.iter().map(PathBuf::as_path).collect();
            load_from_cli(bin, &pack_refs, shard_path, code_path)
                .map_err(|e| format!("模式 A 装载失败: {e}"))?
        }
        (true, None) => {
            load_from_shard(shard_path, code_path).map_err(|e| format!("模式 B 装载失败: {e}"))?
        }
        (false, None) => return Err("给了 --pack 缺 --loom-bin（模式 A 需要成对）".to_string()),
        (true, Some(_)) => return Err("给了 --loom-bin 缺 --pack（模式 A 需要成对）".to_string()),
    };
    let prestate = read_prestate(prestate_path)?;
    // on-demand fork：pin block（latest → eth_blockNumber 具体块号）+
    // 执行地址归位（fork 态强制 --contract-addr，否则合约自身状态
    // 错位——fail-closed）。
    let key = std::env::var("BLOCKMACHINE_API_KEY").unwrap_or_default();
    let fork = match fork_url {
        Some(_) => {
            let url = fork_url
                .map(str::to_string)
                .or_else(|| std::env::var("BLOCKMACHINE_RPC_URL").ok())
                .unwrap_or_else(|| "https://rpc-eth.blockmachine.io".to_string());
            let block_number = loom_fuzz_fuzz::pin_block(&url, &key, fork_block)?;
            Some(loom_fuzz_fuzz::ForkConfig {
                rpc_url: url,
                block_number,
            })
        }
        None => None,
    };
    if fork.is_some() && contract_addr.is_none() {
        return Err(
            "fork 态必须 --contract-addr <真实地址>（执行地址归位，否则合约自身状态错位）"
                .to_string(),
        );
    }
    let exec_address: [u8; 20] = match contract_addr {
        Some(a) => {
            let b = loom_fuzz_oracle::hex_bytes(a)?;
            if b.len() != 20 {
                return Err(format!("--contract-addr 非 20 字节: {a:?}"));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&b);
            addr
        }
        None => CONTRACT_ADDRESS,
    };
    // fork 后部署：`<addr>:<runtime-hex|responder|responder-sender|
    // forwarder>`。多值 = 合约表多成员（#34）；forwarder = 机械攻击
    // 代理入口（fallback 原样 CALL 转发 calldata 到分析合约，victim
    // 帧 msg.sender = 代理合约）。
    let mut deployments: Vec<loom_fuzz_fuzz::Deployment> = Vec::new();
    for d in deploy_flags {
        let (addr, spec) = d.split_once(':').ok_or_else(|| {
            format!("--deploy 形态应为 <addr>:<runtime-hex|responder|responder-sender|forwarder>: {d:?}")
        })?;
        let address_bytes = loom_fuzz_oracle::hex_bytes(addr)?;
        if address_bytes.len() != 20 {
            return Err(format!("--deploy 地址非 20 字节: {addr:?}"));
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes);
        let runtime = match spec {
            "responder" => loom_fuzz_fuzz::responder_runtime({
                let mut w = [0u8; 32];
                w[31] = 1;
                w
            }),
            "responder-sender" => loom_fuzz_fuzz::responder_runtime_sender(),
            "forwarder" => loom_fuzz_fuzz::forwarder_runtime(exec_address),
            hex => loom_fuzz_oracle::hex_bytes(hex)?,
        };
        deployments.push(loom_fuzz_fuzz::Deployment { address, runtime });
    }
    // 入口合约（issue #34）：须在合约表内——victim 或某个部署地址，
    // 否则 fail-closed（不硬猜目标）。缺省 None = 直接 call victim。
    let entry: Option<[u8; 20]> = match entry_flag {
        Some(a) => {
            let b = loom_fuzz_oracle::hex_bytes(a)?;
            if b.len() != 20 {
                return Err(format!("--entry 非 20 字节地址: {a:?}"));
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&b);
            if addr != exec_address && !deployments.iter().any(|d| d.address == addr) {
                return Err(format!(
                    "--entry 地址 {a} 不在合约表内（须 = --contract-addr 或某个 --deploy 地址）"
                ));
            }
            Some(addr)
        }
        None => None,
    };
    let dict_extra: Vec<U256> = dict_words
        .iter()
        .map(|w| hex_u256(w))
        .collect::<Result<_, _>>()?;

    // shard/xlayer（seed 编译与 locate 用；装载已各自做过一次，
    // 此处为管线步重建——纯文件解析，确定性）。
    let shard_bytes = std::fs::read(shard_path).map_err(|e| format!("无法读取 shard: {e}"))?;
    let shard = Shard::from_bytes(&shard_bytes).map_err(|e| format!("shard 解析失败: {e}"))?;
    let view = Xlayer::new(&shard);

    // 补充字典词进每个 hit 的编译字典（registry 常量补法）。
    let mut reports: Vec<HitReport> = Vec::new();
    let mut hit_entries: Vec<HitEntry> = Vec::new();
    let mut assumptions: Vec<String> = Vec::new();
    let mut corpus_total = 0usize;
    let mut guided_runs_total = 0u64;
    let mut baseline: Option<u64> = None;
    let mut baseline_seen = false;

    for hit in &hitset.hits {
        let hit_view = CliHitView(hit);
        let func = locate(&shard, &view, &hit_view)
            .ok_or_else(|| format!("命中 selector {:#010x} 无法定位函数", hit.selector))?;
        let target = Target {
            hit: &hit_view,
            func,
        };
        let mut seed_out = compile(&shard, &view, &hitset.code, &target);
        for w in &dict_extra {
            if !seed_out.dict.words.contains(w) {
                seed_out.dict.words.push(*w);
            }
        }
        for a in &seed_out.assumptions {
            if !assumptions.contains(a) {
                assumptions.push(a.clone());
            }
        }

        let cfg = ExecConfig {
            code: hitset.code.clone(),
            address: exec_address,
            prestate: prestate.clone(),
            seed_rng: seed,
            max_runs,
            time_budget: Duration::from_secs(time_budget_secs),
            gas_per_tx,
            run_baseline: !baseline_seen,
            fork: fork.clone(),
            deployments: deployments.clone(),
            entry,
            max_steps,
            // revert 归因上下文：支配 guard（装载端已渲染 cond）。
            guard_context: hit
                .dominating_guards
                .iter()
                .map(|g| loom_fuzz_fuzz::GuardContext {
                    pc: g.pc,
                    cond: g.cond.clone(),
                })
                .collect(),
        };
        // ABI 形态基座种子：seed 编译器 M0 不产动态尾（其 assumption
        // 如实记录），管线泛型补 n = 1..=4 个零参槽 + 指针尾（末槽 =
        // 头宽）+ 定长动态尾的基座——动态参数的指针槽正确性由此进
        // 搜索空间（docs/architecture.md 职责边界），非 fixture 特设。
        let mut seeds = seed_out.inputs.clone();
        seeds.extend(abi_base_seeds(hit.selector));
        // dict-word 常量同时作"首槽候选种子"进场：registry 常量的
        // 文档化用途（shard 无此事实段，调用方补充）——(address,
        // bytes) 形参基座（首槽 = 常量、二槽 = 0x40 指针 + 定长尾），
        // 由执行验证而非假设。全量字典词不这样做（组合爆炸），仅
        // 调用方显式补充的少数常量。
        for w in &dict_extra {
            seeds.push(registry_candidate_seed(hit.selector, *w));
            seeds.extend(dict_slot_variants(hit.selector, *w));
            // 基座变体：常量落槽在 **ABI 形态基座**上（带指针尾）——
            // 动态形参函数（vvisr deposit 的 bytes 形参）裸头变体
            // 死在解码器，组合（常量×基座尾）只能等进化碰运气。
            for base in abi_base_seeds(hit.selector) {
                for k in 0..base.head.len() {
                    let mut variant = base.clone();
                    variant.head[k] = w.to_be_bytes::<32>();
                    seeds.push(variant);
                }
            }
        }
        // 全槽字典基座（issue #25）：**全字典词** × 槽位变体——
        // 与 --dict-word 的保留通道同机制，覆盖字典里的运行时/静态
        // 词（token 地址、阈值常量等）。规模上限 64：超了按字典序
        // 截断并记 assumption（落 fuzz_report）。
        let (base, note) = full_dict_base(seeds.len(), hit.selector, &seed_out.dict.words);
        seeds.extend(base);
        if let Some(note) = note {
            if !seed_out.assumptions.contains(&note) {
                seed_out.assumptions.push(note);
            }
        }
        // 搜索（issue #25/#29）：DictionaryProposer 为唯一路线——字典
        // 基座 + 多槽协同变异，反馈窗（corpus 精英 + revert 归因）驱动
        // 进化；判决独立，replay 不经搜索层。种子包成单步调用序列
        // （issue #35：step.target = 入口合约或 victim——entry 的生效
        // 形态；max_steps > 1 时进化环的组装算子在步级提案之上机械
        // 扩展多步序列）。
        let seed_target = entry.unwrap_or(exec_address);
        let seeds: Vec<loom_fuzz_fuzz::TxSequence> = seeds
            .iter()
            .map(|s| loom_fuzz_fuzz::TxSequence::single(seed_target, s.clone()))
            .collect();
        let session = loom_fuzz_fuzz::run_targeted(&cfg, &target, &seeds, &seed_out.dict);
        let calldatas: Vec<Vec<u8>> = session
            .best_steps
            .as_ref()
            .ok_or("会话无 best_steps（契约外：一 run 未执行）")?
            .steps
            .iter()
            .map(|s| loom_fuzz_oracle::calldata_of(&s.input))
            .collect();
        let report = loom_fuzz_oracle::judge_with(
            hit,
            &session,
            &calldatas,
            &loom_fuzz_oracle::JudgeInput {
                view: Some(&view),
                expected_evidence: None,
            },
        );
        corpus_total += session.corpus_size;
        guided_runs_total += session.best_runs;
        if cfg.run_baseline {
            baseline = session.baseline_runs_to_reach;
            baseline_seen = true;
        }
        {
            let mut entry = HitEntry::from_report(&report);
            entry.best_runs = session.best_runs;
            hit_entries.push(entry);
        }

        // confirmed → poc.json 落盘。
        if report.verdict == Verdict::Confirmed {
            let filename = format!("poc-{}-{}.json", hit.selector, report.hit.step);
            let poc = build_poc(&report, &cfg, seed, max_runs, time_budget_secs, &filename)
                .map_err(|e| format!("构造 poc 失败: {e}"))?;
            let json =
                serde_json::to_vec_pretty(&poc).map_err(|e| format!("序列化 poc 失败: {e}"))?;
            std::fs::create_dir_all(out_dir)
                .map_err(|e| format!("无法创建输出目录 {}: {e}", out_dir.display()))?;
            std::fs::write(out_dir.join(&filename), json)
                .map_err(|e| format!("写 poc 失败: {e}"))?;
            println!(
                "confirmed: {} ({} runs) → {filename}",
                hit.selector, session.best_runs
            );
            if let Some(dir) = emit_poc {
                let code_text = std::fs::read_to_string(code_path)
                    .map_err(|e| format!("无法读取 code: {e}"))?;
                let exploit_dir = dir.join(format!("exploit-{}-{}", hit.selector, hit.step));
                // L2 诚实降级（issue #28）：头形可解析但无通用价值影响
                // 组装路径的命中（如 anySwapOut 伪动态头）如实标注并继续
                // ——L1 confirmed 与 poc 落盘不受影响，与 run 的"退出码
                // 恒 0、降级不过滤"语义一致。
                match loom_fuzz_pocgen::generate_exploit(
                    &poc,
                    code_text.trim(),
                    &exploit_dir,
                    false,
                ) {
                    Ok((path, summary)) => {
                        println!("forge test 绿灯: {}", path.display());
                        println!("{summary}");
                    }
                    Err(e) => println!("L2 诚实降级: {e}"),
                }
            }
        } else {
            println!("{}: {} — {}", hit.selector, report.verdict, report.reason);
        }
        reports.push(report);
    }

    // fuzz_report.json（hits 为空也照落——如实空报告）。
    let table = DistanceTable::new(&hitset.code, &[]);
    let report = FuzzReport {
        format: REPORT_FORMAT.to_string(),
        seed,
        budgets: Budgets {
            max_runs,
            time_budget_secs,
            gas_per_tx,
        },
        hits: hit_entries,
        coverage: coverage(&reports, table.executable_pc_count()),
        corpus: corpus_total,
        assumptions,
        guidance: Guidance {
            guided_best_runs_total: guided_runs_total,
            baseline_runs_to_reach: baseline,
        },
    };
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("无法创建输出目录 {}: {e}", out_dir.display()))?;
    let json =
        serde_json::to_vec_pretty(&report).map_err(|e| format!("序列化 fuzz_report 失败: {e}"))?;
    std::fs::write(out_dir.join("fuzz_report.json"), &json)
        .map_err(|e| format!("写 fuzz_report 失败: {e}"))?;
    println!(
        "fuzz_report.json: {} hits, coverage {}%",
        report.hits.len(),
        report.coverage.percent
    );
    Ok(ExitCode::SUCCESS)
}

/// 补充常量的槽位扫描变体：n ∈ 1..=9 词头、第 k 槽 = 常量、其余
/// 零、无尾——"哪个槽该填哪个常量"由执行验证（不假设 ABI 形参
/// 位置；如 anyswap 的 code-size 守卫要求某槽 = 带码地址）。
/// 种子的字典序键（去重/截断用；与 seed crate 的 sort_key 同形）。
fn seed_sort_key(s: &SeedInput) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 20 + 32 + s.head.len() * 32 + 8);
    key.extend_from_slice(&s.selector.to_be_bytes());
    key.extend_from_slice(&s.caller);
    key.extend_from_slice(&s.value.to_be_bytes::<32>());
    for word in &s.head {
        key.extend_from_slice(word);
    }
    match &s.tail {
        Tail::Empty => key.push(0),
        Tail::Bytes(b) => {
            key.push(1);
            key.extend_from_slice(&(b.len() as u64).to_be_bytes());
            key.extend_from_slice(b);
        }
        Tail::Free => key.push(2),
    }
    key
}

fn dict_slot_variants(selector: u32, word: U256) -> Vec<SeedInput> {
    let mut out = Vec::new();
    for n in 1..=9usize {
        for k in 0..n {
            let mut head = vec![[0u8; 32]; n];
            head[k] = word.to_be_bytes::<32>();
            out.push(SeedInput {
                selector,
                caller: [0x33; 20],
                value: U256::ZERO,
                head,
                tail: Tail::Empty,
            });
        }
    }
    out
}

/// registry 常量候选种子（见调用点注释）：(address, bytes) 形参
/// ABI 基座，首槽 = 常量。
fn registry_candidate_seed(selector: u32, word: U256) -> SeedInput {
    let mut pointer = [0u8; 32];
    pointer[31] = 0x40;
    SeedInput {
        selector,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: vec![word.to_be_bytes::<32>(), pointer],
        tail: abi_tail(),
    }
}

/// 定长动态尾（len=4 + "loom" 前缀 32B 块，≥4 字节满足 oracle
/// trivial 长度下限）。
fn abi_tail() -> Tail {
    let mut tail = U256::from(4u64).to_be_bytes::<32>().to_vec();
    let mut block = [0u8; 32];
    block[..4].copy_from_slice(b"loom");
    tail.extend_from_slice(&block);
    Tail::Bytes(tail)
}

/// ABI 形态基座种子（见调用点注释）。tail = len 字（=4）+ 32B 块
/// 含 "loom" 前缀——≥4 字节，满足 oracle 的 trivial 长度下限。
/// n 到 9：真实函数头宽可达 0x120（9 槽，如 anySwapOut*WithPermit
/// 的 msg.data.length ≥ 4+0x120 守卫）。
fn abi_base_seeds(selector: u32) -> Vec<SeedInput> {
    let tail_bytes = match abi_tail() {
        Tail::Bytes(b) => b,
        _ => unreachable!("abi_tail 恒 Bytes"),
    };
    (1..=9)
        .flat_map(|n| {
            // 双假设：指针槽 = 头宽（ABI 标准形）**或全零**（动态形参
            // 偏移 0/未用形——vvisr deposit 实测 winning witness 是
            // word2=0 + 尾原样在场）。两个形态都进搜索空间。
            let pointer = {
                let mut head = vec![[0u8; 32]; n];
                head[n - 1] = U256::from(n as u64 * 0x20).to_be_bytes::<32>();
                head
            };
            let zero = vec![[0u8; 32]; n];
            [pointer, zero].into_iter().map(|head| SeedInput {
                selector,
                caller: [0x33; 20],
                value: U256::ZERO,
                head,
                tail: Tail::Bytes(tail_bytes.clone()),
            })
        })
        .collect()
}

struct CliHitView<'a>(&'a Hit);

impl HitView for CliHitView<'_> {
    fn selector(&self) -> u32 {
        self.0.selector
    }
    fn target_pcs(&self) -> &[u32] {
        &self.0.target_pcs
    }
    fn evidence(&self) -> &str {
        &self.0.evidence
    }
}

fn cmd_exploit(
    poc_path: &Path,
    code_path: &Path,
    out_dir: &Path,
    fork: bool,
) -> Result<ExitCode, String> {
    let text = std::fs::read_to_string(poc_path)
        .map_err(|e| format!("无法读取 poc {}: {e}", poc_path.display()))?;
    let poc: Poc = serde_json::from_str(&text).map_err(|e| format!("poc JSON 解析失败: {e}"))?;
    let code_text = std::fs::read_to_string(code_path)
        .map_err(|e| format!("无法读取 code {}: {e}", code_path.display()))?;
    let (path, summary) = loom_fuzz_pocgen::generate_exploit(&poc, code_text.trim(), out_dir, fork)
        .map_err(|e| format!("L2 exploit 生成/forge 失败: {e}"))?;
    println!("forge test 绿灯: {}", path.display());
    println!("{summary}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_replay(
    poc_path: &Path,
    code_path: &Path,
    prestate_path: Option<&Path>,
) -> Result<ExitCode, String> {
    let text = std::fs::read_to_string(poc_path)
        .map_err(|e| format!("无法读取 poc {}: {e}", poc_path.display()))?;
    let poc: Poc = serde_json::from_str(&text).map_err(|e| format!("poc JSON 解析失败: {e}"))?;
    let code_text = std::fs::read_to_string(code_path)
        .map_err(|e| format!("无法读取 code {}: {e}", code_path.display()))?;
    let code_hex = code_text.trim().trim_start_matches("0x");
    if code_hex.len() % 2 != 0 || !code_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("code {} 不是合法 hex", code_path.display()));
    }
    let code: Vec<u8> = (0..code_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&code_hex[i..i + 2], 16).expect("逐字符已验证"))
        .collect();
    // --prestate 缺省用 poc 内嵌布置（None）；给了才覆盖。
    let prestate_override = prestate_path.map(|p| read_prestate(Some(p))).transpose()?;
    let report = replay(&poc, &code, prestate_override).map_err(|e| format!("重放失败: {e}"))?;
    let out = serde_json::json!({
        "verdict": report.verdict.to_string(),
        "reason": report.reason,
        "poc_verdict": poc.verdict,
    });
    println!("{}", serde_json::to_string(&out).expect("JSON 序列化"));
    Ok(if report.verdict.to_string() == poc.verdict {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// 全槽字典基座：全字典词 × 槽位变体（裸头 + 带尾基座），执行
/// 验证选槽。规模上限 64（`reserved` = 保留通道已占额度，超出
/// 部分按字典序截断，返回截断 assumption）。
fn full_dict_base(
    reserved: usize,
    selector: u32,
    dict_words: &[U256],
) -> (Vec<SeedInput>, Option<String>) {
    const BASE_CAP: usize = 64;
    let mut candidates: Vec<SeedInput> = Vec::new();
    for w in dict_words {
        candidates.extend(dict_slot_variants(selector, *w));
        for base in abi_base_seeds(selector) {
            for k in 0..base.head.len() {
                let mut variant = base.clone();
                variant.head[k] = w.to_be_bytes::<32>();
                candidates.push(variant);
            }
        }
    }
    // 去重（字节序键）+ 字典序截断到剩余额度。
    candidates.sort_by_key(seed_sort_key);
    candidates.dedup_by_key(|s| seed_sort_key(s));
    let budget = BASE_CAP.saturating_sub(reserved);
    let total = candidates.len();
    let note = (total > budget).then(|| {
        format!(
            "全槽字典基座：词×槽变体 {total} 超上限额度 {budget}（保留通道 {reserved}），按字典序截断，未收录变体留搜索空间"
        )
    });
    (candidates.into_iter().take(budget).collect(), note)
}

#[cfg(test)]
mod seed_base_tests {
    use super::*;

    #[test]
    fn full_dict_base_caps_at_64_with_assumption() {
        // 500 个词 × 9 槽 × 2 族 ≫ 64：截断 + assumption。
        let words: Vec<U256> = (0..500u64).map(U256::from).collect();
        let (seeds, note) = full_dict_base(10, 0xdeadbeef, &words);
        assert!(seeds.len() <= 54, "截断到 64-reserved");
        assert!(note.unwrap().contains("按字典序截断"));
        // 确定性：同输入同输出。
        let (seeds2, _) = full_dict_base(10, 0xdeadbeef, &words);
        assert_eq!(seeds, seeds2);
    }

    #[test]
    fn full_dict_base_two_words_truncates_deterministically() {
        // 每词 ≥99 变体（9 裸头 + 9×10 槽基座×两族），2 词 ≫ 64：
        // 必截断（assumption 如实），且截断确定性。
        let words = vec![U256::from(1u64), U256::from(0x42u64)];
        let (seeds, note) = full_dict_base(0, 0xdeadbeef, &words);
        assert!(note.unwrap().contains("按字典序截断"));
        assert!(!seeds.is_empty());
        assert!(seeds.len() <= 64);
        let (seeds2, _) = full_dict_base(0, 0xdeadbeef, &words);
        assert_eq!(seeds, seeds2);
    }
}
