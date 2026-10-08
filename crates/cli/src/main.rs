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

use loom_fuzz_fuzz::{run_targeted, DistanceTable, ExecConfig};
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
enum Cmd {
    /// 跑完整闭环：装载 → seed → fuzz → oracle → fuzz_report.json (+ poc.json)
    Run {
        /// .lst shard（模式 B 必需；模式 A 也要，步序 → pc 映射来源）
        #[arg(long)]
        shard: PathBuf,
        /// 运行时字节码 hex 文件
        #[arg(long)]
        code: PathBuf,
        /// 检测 pack（给 --loom-bin 走模式 A；只给一个是 fail-closed 报错）
        #[arg(long)]
        pack: Option<PathBuf>,
        /// loom 二进制路径（模式 A）
        #[arg(long)]
        loom_bin: Option<PathBuf>,
        /// prestate 槽值 JSON（hex → hex 的 map）
        #[arg(long)]
        prestate: Option<PathBuf>,
        /// 确定性种子
        #[arg(long, default_value_t = 0xC0FF_EE00_0000_0001)]
        seed: u64,
        /// runs 预算上限
        #[arg(long, default_value_t = 2_000)]
        max_runs: u64,
        /// 时间预算（秒）
        #[arg(long, default_value_t = 300)]
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
        /// forge test（--emit-poc <dir>）
        #[arg(long)]
        emit_poc: Option<PathBuf>,
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
        } => cmd_run(
            &shard,
            &code,
            pack.as_deref(),
            loom_bin.as_deref(),
            prestate.as_deref(),
            seed,
            max_runs,
            time_budget_secs,
            gas_per_tx,
            &dict_word,
            &out,
            emit_poc.as_deref(),
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
    pack: Option<&Path>,
    loom_bin: Option<&Path>,
    prestate_path: Option<&Path>,
    seed: u64,
    max_runs: u64,
    time_budget_secs: u64,
    gas_per_tx: u64,
    dict_words: &[String],
    out_dir: &Path,
    emit_poc: Option<&Path>,
) -> Result<ExitCode, String> {
    // 装载（模式 A 需 pack+loom-bin 成对；只给一个 = fail-closed）。
    let hitset = match (pack, loom_bin) {
        (Some(p), Some(bin)) => {
            let packs = [p];
            load_from_cli(bin, &packs, shard_path, code_path)
                .map_err(|e| format!("模式 A 装载失败: {e}"))?
        }
        (None, None) => {
            load_from_shard(shard_path, code_path).map_err(|e| format!("模式 B 装载失败: {e}"))?
        }
        (Some(_), None) => return Err("给了 --pack 缺 --loom-bin（模式 A 需要成对）".to_string()),
        (None, Some(_)) => return Err("给了 --loom-bin 缺 --pack（模式 A 需要成对）".to_string()),
    };
    let prestate = read_prestate(prestate_path)?;
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
            address: CONTRACT_ADDRESS,
            prestate: prestate.clone(),
            seed_rng: seed,
            max_runs,
            time_budget: Duration::from_secs(time_budget_secs),
            gas_per_tx,
            run_baseline: !baseline_seen,
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
        }
        let session = run_targeted(&cfg, &target, &seeds, &seed_out.dict);
        let calldata = loom_fuzz_oracle::calldata_of(
            session
                .best_input
                .as_ref()
                .ok_or("会话无 best_input（契约外：一 run 未执行）")?,
        );
        let report = loom_fuzz_oracle::judge(hit, &session, &calldata);
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
                let (path, summary) =
                    loom_fuzz_pocgen::generate_exploit(&poc, code_text.trim(), &exploit_dir, false)
                        .map_err(|e| format!("L2 exploit 生成/forge 失败: {e}"))?;
                println!("forge test 绿灯: {}", path.display());
                println!("{summary}");
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
fn abi_base_seeds(selector: u32) -> Vec<SeedInput> {
    let tail_bytes = match abi_tail() {
        Tail::Bytes(b) => b,
        _ => unreachable!("abi_tail 恒 Bytes"),
    };
    (1..=4)
        .map(|n| {
            let mut head = vec![[0u8; 32]; n];
            head[n - 1][31] = (n as u8) * 0x20; // 指针槽 = 头宽
            SeedInput {
                selector,
                caller: [0x33; 20],
                value: U256::ZERO,
                head,
                tail: Tail::Bytes(tail_bytes.clone()),
            }
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
