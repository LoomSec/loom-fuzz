//! poc.json（confirmed 时落盘，一键重放）+ 重放执行器。
//!
//! 重放 = 用 poc.json 的确定性参数（seed / max_runs / tx / prestate）
//! 重建 [`ExecConfig`]，以 tx 重建输入为唯一种子跑
//! [`loom_fuzz_fuzz::run_targeted`]，重新判决。verdict 逐字节一致
//! （测试断言）：见证输入本身是首种子，run 1 即到场，EVM 对
//! calldata+prestate 的执行确定性保证 trace 一致。
//!
//! calldata → Input 的重建是规范化的：head = 4B 后的完整 32B 块，
//! tail = 剩余字节（`Tail::Bytes`）。切分可能与原始 witness 不同，
//! 但序列化回 calldata 逐字节相同 → 执行等价 → verdict 一致。

use std::collections::BTreeMap;
use std::time::Duration;

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use loom_fuzz_fuzz::{
    run_targeted, ExecConfig, Input, Step, Tail, Target, TxSequence, ValueDictionary,
};
use loom_fuzz_seed::HitView;

use crate::hit::{Hit, HitFamily};
use crate::verdict::{judge_with, HitReport, JudgeInput, Verdict};

/// poc.json 格式标识（破坏性变更递增）。
pub const POC_FORMAT: &str = "loom-fuzz-poc@1";

/// 一键重放的见证工件（confirmed 专用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poc {
    pub format: String,
    /// 见证要素的 keccak256 摘要（selector/pc/calldata/prestate 的
    /// 规范化拼接），完整性标识，不参与重放。
    pub digest: String,
    /// "0x%08x"
    pub selector: String,
    pub step: u32,
    pub pc: u32,
    /// 只写 "confirmed"（poc 仅在 confirmed 时落盘）。
    pub verdict: String,
    /// 调用序列（issue #35）：witness = steps（各步 target + caller +
    /// value + calldata）。新 poc 恒写出；**旧单步 poc.json 无此
    /// 字段，replay 经 legacy `tx` 归一为单步序列**（向后兼容）。
    #[serde(default)]
    pub steps: Vec<PocStep>,
    /// 旧单步形态（只读兼容）：新 poc 恒 None 不写出。replay 时
    /// steps 为空则以此 + `contract` 归一单步序列。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx: Option<PocTx>,
    /// 存储槽 → 值（hex → hex）。
    pub prestate: BTreeMap<String, String>,
    /// 外部响应注入（M0 恒空，未来多交易/族扩展位）。
    pub responses: Vec<String>,
    pub seed: u64,
    pub max_runs: u64,
    pub time_budget_secs: u64,
    /// 臂 1 求值结果（hex 字；臂 3 / 求值 ⊥ = null）。replay 无
    /// shard，用它作求值承诺重放臂 1 判定（witness 变了即不一致）。
    #[serde(default)]
    pub evidence_value: Option<String>,
    /// on-demand fork 配置（None = Genesis；Some 时 replay 同参重建
    /// 远程状态——pin block 确定性）。
    #[serde(default)]
    pub fork: Option<PocFork>,
    /// fork 后部署的攻击合约（pocgen 据此刻蚀）。
    #[serde(default)]
    pub deployments: Vec<PocDeployment>,
    /// 顶层交易入口（issue #34；None = 直接 call victim，旧 poc
    /// 兼容）。Some 时 replay 同参重建——经攻击代理合约的见证
    /// 只有同入口重放才逐字节一致。
    #[serde(default)]
    pub entry: Option<String>,
    /// 执行地址（fork 态 = 真实地址；缺省 = 管线固定 0x2222…22）。
    #[serde(default)]
    pub contract: Option<String>,
    /// 检测族（#20；缺省 arbitrary_call——旧 poc 回放兼容）。
    #[serde(default)]
    pub family: HitFamily,
    /// 定罪的那次呼出（#20；target + input hex）。L2 通用动作选择
    /// 的形状依据；旧 poc 无此字段（None）= 形状不可用。
    #[serde(default)]
    pub call: Option<PocCall>,
    /// 手写 replay 命令串（含本文件名）。
    pub replay: String,
}

/// 定罪呼出（poc.json 形态；与 RecordedCall 同要素）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocCall {
    /// "0x" + 40 hex
    pub target: String,
    /// "0x" + hex
    pub input: String,
}

/// fork 配置（poc.json 形态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocFork {
    pub rpc_url: String,
    pub block_number: u64,
}

/// fork 后部署（poc.json 形态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocDeployment {
    /// "0x" + 40 hex
    pub address: String,
    pub runtime_hex: String,
}

/// 序列步（poc.json 形态；与 seed crate 的 Step 同要素：target +
/// calldata + caller + value）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocStep {
    /// "0x" + 40 hex
    pub target: String,
    /// "0x" + 40 hex
    pub caller: String,
    /// "0x" + 64 hex
    pub value: String,
    /// "0x" + hex（selector + head + tail 原始交易 calldata）
    pub calldata: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocTx {
    /// "0x" + 40 hex
    pub caller: String,
    /// "0x" + hex
    pub value: String,
    /// "0x" + hex（selector + head + tail 原始交易 calldata）
    pub calldata: String,
}

/// U256 → "0x" + 64 hex。
pub fn u256_hex(v: U256) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in v.to_be_bytes::<32>() {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// "0x"+hex → U256（fail-closed：非法即 Err）。
pub fn hex_u256(s: &str) -> Result<U256, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("非法 U256 hex: {s:?}"));
    }
    U256::from_str_radix(hex, 16).map_err(|e| format!("非法 U256 hex {s:?}: {e}"))
}

/// 字节 → "0x"+hex。
pub fn bytes_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for byte in b {
        s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    s
}

/// "0x"+hex → 字节。
pub fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("非法字节 hex: {s:?}"));
    }
    Ok((0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("逐字符已验证"))
        .collect())
}

/// calldata → Input 的规范化重建（见模块文档）。
pub fn input_from_calldata(
    caller: [u8; 20],
    value: U256,
    calldata: &[u8],
) -> Result<Input, String> {
    if calldata.len() < 4 {
        return Err(format!("calldata 不足 4 字节 selector: {}", calldata.len()));
    }
    let selector = u32::from_be_bytes(
        calldata[..4]
            .try_into()
            .map_err(|_| "selector 切片失败".to_string())?,
    );
    let rest = &calldata[4..];
    let head_len = rest.len() / 32;
    let (chunks, _) = rest[..head_len * 32].as_chunks::<32>();
    let head: Vec<[u8; 32]> = chunks.to_vec();
    let tail_rest = &rest[head_len * 32..];
    let tail = if tail_rest.is_empty() {
        Tail::Empty
    } else {
        Tail::Bytes(tail_rest.to_vec())
    };
    Ok(Input {
        selector,
        caller,
        value,
        head,
        tail,
    })
}

/// Input → 原始交易 calldata（与 revm TxEnv.data 逐字节一致；
/// `loom_fuzz_fuzz::calldata_of` 的公开形式）。
pub fn calldata_of(input: &Input) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + input.head.len() * 32);
    out.extend_from_slice(&input.selector.to_be_bytes());
    for word in &input.head {
        out.extend_from_slice(word);
    }
    if let Tail::Bytes(tail) = &input.tail {
        out.extend_from_slice(tail);
    }
    out
}

/// 见证要素的 keccak256 摘要（规范化拼接：selector|pc|各步
/// target+calldata|prestate 对；issue #35 起 calldata 为全序列）。
pub fn witness_digest(
    selector: u32,
    pc: u32,
    steps: &[Step],
    prestate: &BTreeMap<U256, U256>,
) -> String {
    let mut h = Keccak256::new();
    h.update(selector.to_be_bytes());
    h.update(pc.to_be_bytes());
    for s in steps {
        h.update(s.target);
        h.update(calldata_of(&s.input));
    }
    for (k, v) in prestate {
        h.update(k.to_be_bytes::<32>());
        h.update(v.to_be_bytes::<32>());
    }
    bytes_hex(&h.finalize())
}

/// 构造 poc（confirmed 判决 + 会话参数 + 落盘文件名）。
pub fn build_poc(
    hit_report: &HitReport,
    cfg: &ExecConfig,
    seed: u64,
    max_runs: u64,
    time_budget_secs: u64,
    poc_filename: &str,
) -> Result<Poc, String> {
    if hit_report.verdict != Verdict::Confirmed {
        return Err("只有 confirmed 判决落 poc.json（如实，不硬造）".to_string());
    }
    let witness = hit_report
        .witness
        .as_ref()
        .ok_or("confirmed 必有 witness（契约）")?;
    if witness.steps.is_empty() {
        return Err("confirmed 见证序列为空（契约外形态，如实报）".to_string());
    }

    let prestate: BTreeMap<String, String> = cfg
        .prestate
        .iter()
        .map(|(k, v)| (u256_hex(*k), u256_hex(*v)))
        .collect();
    let digest = witness_digest(
        hit_report.hit.selector,
        witness.pc,
        &witness.steps,
        &cfg.prestate,
    );
    let replay = if cfg.prestate.is_empty() {
        format!("loom-fuzz replay {poc_filename} --code <bytecode.hex>")
    } else {
        format!("loom-fuzz replay {poc_filename} --code <bytecode.hex> --prestate <slots.json>")
    };
    Ok(Poc {
        format: POC_FORMAT.to_string(),
        digest,
        selector: format!("{:#010x}", hit_report.hit.selector),
        step: hit_report.hit.step,
        pc: witness.pc,
        verdict: Verdict::Confirmed.to_string(),
        steps: witness
            .steps
            .iter()
            .map(|s| PocStep {
                target: bytes_hex(&s.target),
                caller: bytes_hex(&s.input.caller),
                value: u256_hex(s.input.value),
                calldata: bytes_hex(&calldata_of(&s.input)),
            })
            .collect(),
        tx: None,
        prestate,
        responses: Vec::new(),
        seed,
        max_runs,
        time_budget_secs,
        evidence_value: witness.evidence_value.clone(),
        fork: cfg.fork.as_ref().map(|f| PocFork {
            rpc_url: f.rpc_url.clone(),
            block_number: f.block_number,
        }),
        deployments: cfg
            .deployments
            .iter()
            .map(|d| PocDeployment {
                address: bytes_hex(&d.address),
                runtime_hex: bytes_hex(&d.runtime),
            })
            .collect(),
        entry: cfg.entry.map(|e| bytes_hex(&e)),
        contract: Some(bytes_hex(&cfg.address)),
        family: hit_report.hit.family,
        call: Some(PocCall {
            target: bytes_hex(&witness.evidence_call.target),
            input: bytes_hex(&witness.evidence_call.input),
        }),
        replay,
    })
}

impl Poc {
    /// 归一化调用序列（issue #35）：`steps` 优先；空则按 legacy
    /// `tx` + `contract`（缺省 0x2222…22）归一单步序列——**旧单步
    /// poc.json 由此保持可 replay**。两者皆空 = fail-closed 报错。
    pub fn normalized_steps(&self) -> Result<Vec<PocStep>, String> {
        if !self.steps.is_empty() {
            return Ok(self.steps.clone());
        }
        let Some(tx) = &self.tx else {
            return Err("poc 无 steps 且无 legacy tx（形态不认，fail-closed）".to_string());
        };
        let target = self
            .contract
            .clone()
            .unwrap_or_else(|| bytes_hex(&[0x22u8; 20]));
        Ok(vec![PocStep {
            target,
            caller: tx.caller.clone(),
            value: tx.value.clone(),
            calldata: tx.calldata.clone(),
        }])
    }
}

/// 重放：poc.json + 运行时字节码（--code）→ 重新判决。
/// `prestate_override` = `--prestate <file>` 显式覆盖（缺省用 poc 内
/// 嵌的 prestate）。见证序列经 `normalized_steps` 重建（issue #35；
/// 旧单步 poc 的 legacy `tx` 归一为单步序列——向后兼容）。
pub fn replay(
    poc: &Poc,
    code: &[u8],
    prestate_override: Option<BTreeMap<U256, U256>>,
) -> Result<HitReport, String> {
    if poc.format != POC_FORMAT {
        return Err(format!(
            "poc 格式不认: {:?}（本工具 {})",
            poc.format, POC_FORMAT
        ));
    }
    let prestate = match prestate_override {
        Some(p) => p,
        None => poc
            .prestate
            .iter()
            .map(|(k, v)| Ok((hex_u256(k)?, hex_u256(v)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?,
    };
    // 序列重建：逐步规范化（calldata → Input 的切分与原始 witness
    // 可能不同，但序列化回 calldata 逐字节相同 → 执行等价）。
    let mut steps: Vec<Step> = Vec::new();
    let mut calldatas: Vec<Vec<u8>> = Vec::new();
    for s in poc.normalized_steps()? {
        let target_b = hex_bytes(&s.target)?;
        if target_b.len() != 20 {
            return Err("poc.step.target 非 20 字节".to_string());
        }
        let mut target = [0u8; 20];
        target.copy_from_slice(&target_b);
        let calldata = hex_bytes(&s.calldata)?;
        let value = hex_u256(&s.value)?;
        let caller_b = hex_bytes(&s.caller)?;
        if caller_b.len() != 20 {
            return Err("poc.step.caller 非 20 字节".to_string());
        }
        let mut caller = [0u8; 20];
        caller.copy_from_slice(&caller_b);
        calldatas.push(calldata.clone());
        steps.push(Step {
            target,
            input: input_from_calldata(caller, value, &calldata)?,
        });
    }
    if steps.is_empty() {
        return Err("poc 序列归一后为空（契约外形态，fail-closed）".to_string());
    }
    let witness_seq = TxSequence { steps };

    let cfg = ExecConfig {
        code: code.to_vec(),
        address: match &poc.contract {
            Some(a) => {
                let b = hex_bytes(a)?;
                if b.len() != 20 {
                    return Err("poc.contract 非 20 字节".to_string());
                }
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&b);
                addr
            }
            None => [0x22; 20], // 与 run 管线同一固定合约地址
        },
        prestate,
        seed_rng: poc.seed,
        max_runs: poc.max_runs.max(1),
        time_budget: Duration::from_secs(poc.time_budget_secs.max(60)),
        gas_per_tx: 1_000_000,
        run_baseline: false,
        fork: poc.fork.as_ref().map(|f| loom_fuzz_fuzz::ForkConfig {
            rpc_url: f.rpc_url.clone(),
            block_number: f.block_number,
        }),
        deployments: poc
            .deployments
            .iter()
            .map(|d| {
                let b = hex_bytes(&d.address)?;
                if b.len() != 20 {
                    return Err("poc.deployment.address 非 20 字节".to_string());
                }
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                Ok(loom_fuzz_fuzz::Deployment {
                    address: a,
                    runtime: hex_bytes(&d.runtime_hex)?,
                })
            })
            .collect::<Result<_, String>>()?,
        entry: match &poc.entry {
            Some(a) => {
                let b = hex_bytes(a)?;
                if b.len() != 20 {
                    return Err("poc.entry 非 20 字节".to_string());
                }
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&b);
                Some(addr)
            }
            None => None,
        },
        // replay 的序列长度上限 = 见证序列长度（机械约束，不扩搜）。
        max_steps: witness_seq.steps.len() as u32,
        dynamic_head_evidence: false,
        // replay 不经搜索层（判决独立）；guard 上下文不参与重放。
        guard_context: Vec::new(),
    };
    let selector = u32::from_str_radix(poc.selector.trim_start_matches("0x"), 16)
        .map_err(|e| format!("poc.selector 非法: {e}"))?;
    struct PocHit {
        selector: u32,
        pc: u32,
    }
    impl HitView for PocHit {
        fn selector(&self) -> u32 {
            self.selector
        }
        fn target_pcs(&self) -> &[u32] {
            std::slice::from_ref(&self.pc)
        }
        fn evidence(&self) -> &str {
            ""
        }
    }
    let poc_hit = PocHit {
        selector,
        pc: poc.pc,
    };
    let hit = Hit {
        family: poc.family,
        selector,
        step: poc.step,
        target_pcs: vec![poc.pc],
        evidence: String::new(),
        evidence_expr: None,
        arm: None,
        dominating_guards: Vec::new(),
    };
    let target = Target {
        hit: &poc_hit,
        func: 0,
    };
    let report = run_targeted(
        &cfg,
        &target,
        &[witness_seq],
        &ValueDictionary { words: Vec::new() },
    );
    // replay：无 shard——臂 1 用 poc 内嵌的求值承诺重放判定。
    let expected_evidence = poc
        .evidence_value
        .as_deref()
        .map(hex_u256)
        .transpose()
        .map_err(|e| format!("poc.evidence_value 非法: {e}"))?;
    Ok(judge_with(
        &hit,
        &report,
        &calldatas,
        &JudgeInput {
            view: None,
            expected_evidence,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_fuzz_fuzz::{OutcomeKind, RecordedCall, WitnessTrace};

    fn confirmed_report() -> (HitReport, ExecConfig) {
        let prestate = BTreeMap::from([(U256::from(0xaaaau64), U256::from(1u64))]);
        let input = Input {
            selector: 0x90ce82d4,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: vec![[0u8; 32]; 2],
            tail: Tail::Bytes(vec![1, 2, 3, 4]),
        };
        let report = HitReport {
            verdict: Verdict::Confirmed,
            hit: Hit {
                family: Default::default(),
                selector: 0x90ce82d4,
                step: 19,
                target_pcs: vec![384],
                evidence: String::new(),
                evidence_expr: None,
                arm: None,
                dominating_guards: Vec::new(),
            },
            witness: Some(crate::verdict::Witness {
                evidence_value: None,
                trace: WitnessTrace {
                    contract: [0x22; 20],
                    deployments: Vec::new(),
                    visited_pcs: vec![384],
                    calls: vec![RecordedCall {
                        kind: "CALL".to_string(),
                        from: [0x22; 20],
                        step: 0,
                        target: [0x7d; 20],
                        value: U256::ZERO,
                        input: vec![1, 2, 3, 4],
                        pc: Some(384),
                    }],
                    outcome: OutcomeKind::Stop,
                    gas_used: 1,
                    truncated: false,
                    step_outcomes: vec![OutcomeKind::Stop],
                },
                steps: vec![Step {
                    target: [0x22; 20],
                    input,
                }],
                pc: 384,
                evidence_call: RecordedCall {
                    kind: "CALL".to_string(),
                    from: [0x22; 20],
                    step: 0,
                    target: [0x7d; 20],
                    value: U256::ZERO,
                    input: vec![1, 2, 3, 4],
                    pc: Some(384),
                },
            }),
            reason: String::new(),
        };
        let cfg = ExecConfig {
            code: vec![0x5b, 0x00],
            address: [0x22; 20],
            prestate,
            seed_rng: 42,
            max_runs: 10,
            time_budget: Duration::from_secs(5),
            gas_per_tx: 100_000,
            run_baseline: false,
            fork: None,
            deployments: Vec::new(),
            entry: None,
            max_steps: 1,
            dynamic_head_evidence: false,
            guard_context: Vec::new(),
        };
        (report, cfg)
    }

    #[test]
    fn poc_roundtrip_and_fields() {
        let (report, cfg) = confirmed_report();
        let poc = build_poc(&report, &cfg, 42, 10, 300, "poc-test.json").unwrap();
        assert_eq!(poc.format, POC_FORMAT);
        assert_eq!(poc.selector, "0x90ce82d4");
        assert_eq!(poc.pc, 384);
        assert_eq!(poc.step, 19);
        assert_eq!(poc.verdict, "confirmed");
        assert!(!poc.digest.is_empty());
        assert_eq!(poc.steps.len(), 1);
        assert!(poc.steps[0].calldata.starts_with("0x90ce82d4"));
        assert_eq!(poc.steps[0].target, bytes_hex(&[0x22; 20]));
        assert!(poc.tx.is_none(), "新 poc 不写出 legacy tx");
        assert_eq!(poc.prestate.len(), 1);
        assert!(poc.replay.contains("loom-fuzz replay poc-test.json"));
        assert!(poc.replay.contains("--code <bytecode.hex>"));
        // #20：族 + 定罪呼出留盘（L2 形状选择依据）。
        assert_eq!(poc.family, crate::HitFamily::ArbitraryCall);
        let call = poc.call.as_ref().expect("confirmed 必有定罪呼出");
        assert_eq!(call.target, bytes_hex(&[0x7d; 20]));
        assert_eq!(call.input, bytes_hex(&[1, 2, 3, 4]));

        // serde 往返逐字节一致。
        let json = serde_json::to_vec(&poc).unwrap();
        let back: Poc = serde_json::from_slice(&json).unwrap();
        assert_eq!(poc, back);
    }

    #[test]
    fn calldata_reconstruction_is_execution_equivalent() {
        let input = Input {
            selector: 0xdeadbeef,
            caller: [0x11; 20],
            value: U256::from(7u64),
            head: vec![[0xaau8; 32], [0xbbu8; 32]],
            tail: Tail::Bytes(vec![1, 2, 3]),
        };
        let calldata = calldata_of(&input);
        let rebuilt = input_from_calldata(input.caller, input.value, &calldata).unwrap();
        assert_eq!(calldata_of(&rebuilt), calldata);
    }

    #[test]
    fn hex_helpers_roundtrip() {
        for v in [U256::ZERO, U256::from(1u64), U256::MAX] {
            assert_eq!(hex_u256(&u256_hex(v)).unwrap(), v);
        }
        assert!(hex_u256("0xzz").is_err());
        assert!(hex_u256("0x").is_err());
        let b = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex_bytes(&bytes_hex(&b)).unwrap(), b);
        assert!(hex_bytes("0xabc").is_err());
    }

    #[test]
    fn build_poc_rejects_non_confirmed() {
        let (mut report, cfg) = confirmed_report();
        report.verdict = Verdict::Unreachable;
        assert!(build_poc(&report, &cfg, 42, 10, 300, "x.json").is_err());
    }
}
