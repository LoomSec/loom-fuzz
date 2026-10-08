//! fork 链上状态物化（issue #21）：`loom-fuzz fetch-state`。
//!
//! 两阶段 + 迭代加深（≤3 轮或触及集不变收敛）：
//! 1. **探测**（现有执行器，Genesis 空库）：probe-runs 次执行，
//!    从 witness trace 收集**触及地址集**（call target、SLOAD 地址、
//!    合约自身、caller、deployment）与**触及槽集**（地址, 槽）。
//! 2. **拉取**：JSON-RPC（ureq/rustls，pin block）批量取这些地址的
//!    code/balance/nonce 与槽值（eth_getCode/eth_getBalance/
//!    eth_getTransactionCount/eth_getStorageAt）。
//! 3. **hydration 后再探测一轮**：新路径可能触及更多——合并触及集，
//!    迭代加深。
//!
//! 产物 state.json：{addresses: {code_hex, balance, nonce, slots}},
//! 元数据 {rpc_url（**不存 key**）, block, fetched_at, digest}。
//! 环境变量：BLOCKMACHINE_RPC_URL（默认 https://rpc-eth.blockmachine.io）、
//! BLOCKMACHINE_API_KEY（空 = keyless 直连；非空 = Authorization: Bearer）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{
    probe_execute, ExecConfig, ForkAccount, ForkMeta, ForkStateFile, Input, StateSource,
};
use loom_fuzz_oracle::Hit;
use loom_fuzz_seed::{compile, locate, HitView, Target};
use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::Xlayer;
use sha3::{Digest, Keccak256};

use crate::{load_hits, read_code};

const MAX_ROUNDS: usize = 5;
const DEFAULT_RPC: &str = "https://rpc-eth.blockmachine.io";

pub struct FetchOutcome {
    pub addresses: usize,
    pub slots: usize,
    pub rounds: usize,
    pub out: std::path::PathBuf,
}

/// fetch-state 主流程。
#[allow(clippy::too_many_arguments)] // 物化参数即 CLI 旗面，成组传递无益
pub fn cmd_fetch_state(
    shard_path: &Path,
    code_path: &Path,
    pack: Option<&Path>,
    loom_bin: Option<&Path>,
    rpc_url: Option<&str>,
    block: &str,
    seed: u64,
    probe_runs: u64,
    out: &Path,
    contract_addr: Option<&str>,
    probe_calldata: Option<&str>,
) -> Result<FetchOutcome, String> {
    let hits = load_hits(shard_path, code_path, pack, loom_bin)?;
    let code = read_code(code_path)?;
    let shard = Shard::from_bytes(&std::fs::read(shard_path).map_err(|e| format!("shard: {e}"))?)
        .map_err(|e| format!("shard 解析: {e}"))?;
    let view = Xlayer::new(&shard);

    // RPC 配置：env 优先，flag 覆盖 RPC URL；key 只进 header 不落盘。
    let rpc = rpc_url
        .map(str::to_string)
        .or_else(|| std::env::var("BLOCKMACHINE_RPC_URL").ok())
        .unwrap_or_else(|| DEFAULT_RPC.to_string());
    let key = std::env::var("BLOCKMACHINE_API_KEY").unwrap_or_default();
    let block_tag = normalize_block(block)?;

    // 探测输入：hit[0] 的编译种子 + ABI 基座 + 随机填充（多样性）。
    let mut probe_inputs = build_probe_inputs(&shard, &view, &code, &hits, seed)?;
    // 引导输入：上轮 witness 的 calldata（如 operator 提供）——探测
    // 执行会沿真实路径 SLOAD 更深状态（如 token 的 owner 槽），使
    // 物化逼近 fork 全态，消除 witness 对不完整世界的伪依赖。
    if let Some(cd) = probe_calldata {
        let bytes = loom_fuzz_oracle::hex_bytes(cd)?;
        if bytes.len() < 4 {
            return Err("--probe-calldata 不足 4 字节".to_string());
        }
        if let Some(hit) = hits.first() {
            let reconstructed = loom_fuzz_oracle::input_from_calldata(
                [0x33; 20],
                alloy_primitives::U256::ZERO,
                &bytes,
            )?;
            let _ = hit;
            probe_inputs.push(reconstructed);
        }
    }

    // 分析合约的链上真实地址（其存储映射到执行地址 0x2222…22——
    // 执行器固定地址，见 CONTRACT_ADDRESS）：缺省则 0x2222 按普通
    // 地址查（基本为空，如实）。
    let contract_real = contract_addr
        .map(loom_fuzz_fuzz::fork_hex_addr)
        .transpose()?;
    // 迭代加深：探测 → 收集 → 拉取 → hydration 再探测。
    let mut state = ForkStateFile {
        addresses: BTreeMap::new(),
        meta: ForkMeta {
            rpc_url: rpc.clone(),
            block: block_tag.clone(),
            fetched_at: now_secs(),
            digest: String::new(),
        },
    };
    let mut prev_touched: Option<Touched> = None;
    let mut rounds = 0;
    for round in 1..=MAX_ROUNDS {
        rounds = round;
        // 探测：Genesis 首轮，其后 hydration 本 state（写临时文件加载）。
        let state_path = out.with_extension("hydrate.json");
        let state_source = if round == 1 {
            StateSource::Genesis
        } else {
            write_state(&state, &state_path)?;
            StateSource::StateFile(state_path.clone())
        };
        let cfg = ExecConfig {
            code: code.clone(),
            // 探测在执行地址上跑（contract-addr 时 = 真实地址，与
            // run --contract-addr 同——否则物化的合约条目 hydration
            // 不进 0x2222，探测永远停在守卫前）。
            address: contract_real.unwrap_or(crate::CONTRACT_ADDRESS),
            prestate: Default::default(),
            seed_rng: seed,
            max_runs: probe_runs,
            time_budget: Duration::from_secs(600),
            gas_per_tx: 1_000_000,
            run_baseline: false,
            state_source,
            deployments: Vec::new(),
        };
        let touched = probe(&cfg, &probe_inputs, probe_runs, seed);
        eprintln!(
            "[round {round}] touched: {} addrs / {} slots",
            touched.addresses.len(),
            touched.slots.len()
        );
        for (a, s) in &touched.slots {
            eprintln!("   slot {:?} @ {:02x?}", s, a);
        }
        // 收敛判定：触及集不变即停（状态已覆盖全部可达路径）。
        if prev_touched.as_ref() == Some(&touched) {
            break;
        }
        prev_touched = Some(touched.clone());
        // 拉取新增部分并合并。
        fetch_into(&mut state, &touched, &rpc, &key, &block_tag, contract_real)?;
        let _ = std::fs::remove_file(&state_path);
    }
    // digest = 内容 keccak。
    let digest = {
        let mut h = Keccak256::new();
        h.update(serde_json::to_vec(&state.addresses).expect("序列化不失败"));
        format!("0x{}", hex(&h.finalize()))
    };
    state.meta.digest = digest;
    state.meta.fetched_at = now_secs();
    write_state(&state, out)?;
    Ok(FetchOutcome {
        addresses: state.addresses.len(),
        slots: state.addresses.values().map(|a| a.slots.len()).sum(),
        rounds,
        out: out.to_path_buf(),
    })
}

/// 触及集：地址 + (地址, 槽)。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Touched {
    addresses: BTreeSet<[u8; 20]>,
    slots: BTreeSet<([u8; 20], U256)>,
}

fn probe(cfg: &ExecConfig, inputs: &[Input], runs: u64, seed: u64) -> Touched {
    // 只从**结构化种子输入**收集触及集：随机填充的 call target 全是
    // 噪声地址，会把物化范围炸到 RPC 限流之外。runs > 种子数时循环
    // 复用种子（执行确定性，触及集不变，纯冗余——截到种子数即可）。
    let _ = (runs, seed);
    let mut touched = Touched::default();
    for input in inputs {
        touched.addresses.insert(cfg.address);
        touched.addresses.insert(input.caller);
        let probe = probe_execute(cfg, input, 10_000_000);
        for c in &probe.trace.calls {
            touched.addresses.insert(c.target);
        }
        for (addr, slot) in &probe.sload_sites {
            touched.addresses.insert(*addr);
            touched.slots.insert((*addr, *slot));
        }
        for d in &probe.trace.deployments {
            touched.addresses.insert(d.address);
        }
    }
    touched
}

fn build_probe_inputs(
    shard: &Shard,
    view: &Xlayer<'_>,
    code: &[u8],
    hits: &[Hit],
    _seed: u64,
) -> Result<Vec<Input>, String> {
    let mut inputs = Vec::new();
    for hit in hits.iter().take(4) {
        struct Hv<'a>(&'a Hit);
        impl HitView for Hv<'_> {
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
        let hv = Hv(hit);
        let func = locate(shard, view, &hv)
            .ok_or_else(|| format!("命中 selector {:#010x} 无法定位", hit.selector))?;
        let out = compile(shard, view, code, &Target { hit: &hv, func });
        inputs.extend(out.inputs);
        // 探测基座 + 逐槽单位变体（slot k = 1）：穿透 amount>0 /
        // !=0 类基本守卫，让探测路径抵达存储读与外部 call——否则
        // 物化收集为空（vvisr 实测：零基座全死在首守卫前）。
        for base in crate::abi_base_seeds(hit.selector) {
            for k in 0..base.head.len() {
                let mut variant = base.clone();
                variant.head[k][31] = 1;
                inputs.push(variant);
            }
            inputs.push(base);
        }
    }
    Ok(inputs)
}

/// JSON-RPC 拉取触及集的 code/balance/nonce + 槽值，合并进 state。
fn fetch_into(
    state: &mut ForkStateFile,
    touched: &Touched,
    rpc: &str,
    key: &str,
    block: &str,
    contract_real: Option<[u8; 20]>,
) -> Result<(), String> {
    // 执行地址 0x2222…22 的存储查询改走真实合约地址（其自身状态
    // 经物化映射到执行地址；code 仍用分析产物，不覆盖）。
    let mut value_addresses = std::collections::BTreeSet::new();
    let query_addr = |addr: &[u8; 20]| -> String {
        if *addr == crate::CONTRACT_ADDRESS {
            if let Some(real) = contract_real {
                return addr_string(real);
            }
        }
        addr_string(*addr)
    };
    for addr in &touched.addresses {
        // 键 = 查询地址（contract-addr 时合约条目以真实地址为键——
        // 执行器在真实地址上跑，见 run --contract-addr）。
        let query_hex = query_addr(addr);
        let key_hex = query_hex.clone();
        let entry = state
            .addresses
            .entry(key_hex.clone())
            .or_insert_with(|| ForkAccount {
                code_hex: "0x".to_string(),
                balance: "0x0".to_string(),
                nonce: "0x0".to_string(),
                slots: BTreeMap::new(),
            });
        // 账户三件套（code 只在首次拉；重探测已 hydrated 的跳过）。
        if entry.code_hex == "0x" && entry.balance == "0x0" && entry.nonce == "0x0" {
            let code = rpc_call(
                rpc,
                key,
                "eth_getCode",
                serde_json::json!([query_hex, block]),
            )?;
            let balance = rpc_call(
                rpc,
                key,
                "eth_getBalance",
                serde_json::json!([query_hex, block]),
            )?;
            let nonce = rpc_call(
                rpc,
                key,
                "eth_getTransactionCount",
                serde_json::json!([query_hex, block]),
            )?;
            entry.code_hex = code.as_str().unwrap_or("0x").to_string();
            entry.balance = balance.as_str().unwrap_or("0x0").to_string();
            entry.nonce = nonce.as_str().unwrap_or("0x0").to_string();
        }
        let _ = &query_hex;
        // 槽值 + 槽值即地址扩展（存储常放合约地址——如 rewardsToken；
        // 值的地址也拉账户数据，迭代加深由外层轮次处理）。
        let existing = entry.slots.clone();
        for (a, slot) in &touched.slots {
            if *a != *addr {
                continue;
            }
            let slot_hex = loom_fuzz_fuzz::fork_u256_hex(*slot);
            if existing.contains_key(&slot_hex) {
                continue;
            }
            let value = rpc_call(
                rpc,
                key,
                "eth_getStorageAt",
                serde_json::json!([query_hex, slot_hex, block]),
            )?;
            let value_str = value.as_str().unwrap_or("0x0").to_string();
            if let Ok(v) = loom_fuzz_fuzz::fork_hex_u256(&value_str) {
                if !v.is_zero() && v < (U256::from(1u64) << 160) {
                    value_addresses.insert(v);
                }
            }
            entry.slots.insert(slot_hex, value_str);
        }
    }
    // 槽值引出的地址：补账户三件套（code/balance/nonce，无槽——
    // 其槽由后续轮的探测触及再拉）。
    for v in value_addresses {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&v.to_be_bytes::<32>()[12..]);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&w[12..]);
        let addr_hex = addr_string(addr_bytes);
        if state.addresses.contains_key(&addr_hex) {
            continue;
        }
        let code = rpc_call(
            rpc,
            key,
            "eth_getCode",
            serde_json::json!([addr_hex, block]),
        )?;
        let balance = rpc_call(
            rpc,
            key,
            "eth_getBalance",
            serde_json::json!([addr_hex, block]),
        )?;
        let nonce = rpc_call(
            rpc,
            key,
            "eth_getTransactionCount",
            serde_json::json!([addr_hex, block]),
        )?;
        state.addresses.insert(
            addr_hex,
            ForkAccount {
                code_hex: code.as_str().unwrap_or("0x").to_string(),
                balance: balance.as_str().unwrap_or("0x0").to_string(),
                nonce: nonce.as_str().unwrap_or("0x0").to_string(),
                slots: BTreeMap::new(),
            },
        );
    }
    Ok(())
}

fn rpc_call(
    rpc: &str,
    key: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build(),
    );
    // 429 退避重试（免费档限速；确定性对物化结果无影响——内容 pin
    // block，重试不改变结果）。
    let resp = {
        let mut attempt = 0;
        loop {
            let req = agent.post(rpc).header("Content-Type", "application/json");
            let req = if key.is_empty() {
                req
            } else {
                req.header("Authorization", &format!("Bearer {key}"))
            };
            match req.send(&body.to_string()) {
                Ok(r) => break r,
                Err(ureq::Error::StatusCode(s)) if s == 429 && attempt < 4 => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(attempt));
                }
                Err(e) => return Err(format!("RPC {method} 请求失败: {e}")),
            }
        }
    };
    let text = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("RPC {method} 读体失败: {e}"))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("RPC {method} JSON 非法: {e}"))?;
    if let Some(err) = json.get("error") {
        return Err(format!("RPC {method} 错误: {err}"));
    }
    Ok(json["result"].clone())
}

/// block 规范化：数字 → hex tag；"latest"/hex tag 原样。
fn normalize_block(block: &str) -> Result<String, String> {
    if block == "latest" || block.starts_with("0x") {
        return Ok(block.to_string());
    }
    let n: u64 = block
        .parse()
        .map_err(|_| format!("--block 非法（数字/latest/0x-hex）: {block:?}"))?;
    Ok(format!("0x{n:x}"))
}

fn write_state(state: &ForkStateFile, path: &Path) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(state).map_err(|e| format!("state 序列化: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录: {e}"))?;
    }
    std::fs::write(path, json).map_err(|e| format!("写 state: {e}"))
}

fn addr_string(a: [u8; 20]) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in a {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    s
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
