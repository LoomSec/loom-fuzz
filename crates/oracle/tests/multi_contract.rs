//! 多合约装载验收（issue #34）：两合约在场（victim + 攻击代理），
//! 经攻击合约代理到达 victim 目标帧 confirmed；不经代理的直接
//! 对照（常数路径）不回归。
//!
//! victim 为手写最小字节码：JUMPDEST（target pc 0）后把整笔
//! calldata 原样 CALL 给固定 sink（arbitrary_call 臂 3 裸转发
//! 形态——input = 交易 calldata 自身，子串成立）。攻击代理 =
//! `forwarder_runtime`（fallback 原样 CALL 转发 calldata 到
//! victim）——victim 帧 msg.sender = 代理合约（caller 轮换
//! ATTACKER → 攻击合约 → victim）。

use std::collections::BTreeMap;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{forwarder_runtime, run_targeted, Deployment, ExecConfig};
use loom_fuzz_oracle::{build_poc, calldata_of, judge, replay, Hit, Verdict};
use loom_fuzz_seed::{HitView, Input, Tail, Target, ValueDictionary};

const VICTIM: [u8; 20] = [0x22; 20];
const PROXY: [u8; 20] = [0xaau8; 20];
const SINK: [u8; 20] = [0x11; 20];
const SELECTOR: u32 = 0xdeadbeef;

/// victim：pc0 JUMPDEST（target），calldata → mem 后 CALL(sink,
/// input = 整笔 calldata)，STOP。
fn victim_code() -> Vec<u8> {
    let mut code = vec![
        0x5b, // JUMPDEST (pc 0 = target)
        0x36, // CALLDATASIZE（copy size）
        0x60, 0x00, // PUSH1 0（calldata offset）
        0x60, 0x00, // PUSH1 0（mem destOffset）
        0x37, // CALLDATACOPY：mem[0..size] = calldata
        0x60, 0x00, // PUSH1 0（out size）
        0x60, 0x00, // PUSH1 0（out offset）
        0x36, // CALLDATASIZE（in size）
        0x60, 0x00, // PUSH1 0（in offset）
        0x60, 0x00, // PUSH1 0（value）
    ];
    code.push(0x73); // PUSH20 sink
    code.extend_from_slice(&SINK);
    code.extend_from_slice(&[0x5a, 0xf1, 0x00]); // GAS; CALL; STOP
    code
}

struct VictimHit;

impl HitView for VictimHit {
    fn selector(&self) -> u32 {
        SELECTOR
    }
    fn target_pcs(&self) -> &[u32] {
        &[0]
    }
    fn evidence(&self) -> &str {
        ""
    }
}

fn hit() -> Hit {
    Hit {
        family: Default::default(),
        selector: SELECTOR,
        step: 0,
        target_pcs: vec![0],
        evidence: String::new(),
        evidence_expr: None,
        arm: None,
        dominating_guards: Vec::new(),
    }
}

fn seed_input() -> Input {
    Input {
        selector: SELECTOR,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: vec![[0u8; 32]],
        tail: Tail::Empty,
    }
}

fn exec_config(entry: Option<[u8; 20]>, deployments: Vec<Deployment>) -> ExecConfig {
    ExecConfig {
        code: victim_code(),
        address: VICTIM,
        prestate: BTreeMap::new(),
        seed_rng: 42,
        max_runs: 8,
        time_budget: Duration::from_secs(30),
        gas_per_tx: 100_000,
        run_baseline: false,
        fork: None,
        deployments,
        entry,
        guard_context: Vec::new(),
    }
}

fn run_and_judge(cfg: &ExecConfig) -> loom_fuzz_oracle::HitReport {
    let hit = hit();
    let view = VictimHit;
    let target = Target {
        hit: &view,
        func: 0,
    };
    let session = run_targeted(
        cfg,
        &target,
        &[seed_input()],
        &ValueDictionary { words: vec![] },
    );
    assert!(
        session.reached,
        "种子首 run 应直达 target pc 0: {session:?}"
    );
    let calldata = calldata_of(session.best_input.as_ref().expect("reached 必有输入"));
    judge(&hit, &session, &calldata)
}

/// 两合约在场：顶层交易进攻击代理，代理 CALL 转发 calldata 到
/// victim，victim 目标帧的裸转发 call 臂 3 定罪——且定罪 call
/// 必须归属 victim 帧（from = victim，不是代理转发帧）。
#[test]
fn proxy_entry_confirms_via_victim_frame() {
    let deployments = vec![Deployment {
        address: PROXY,
        runtime: forwarder_runtime(VICTIM),
    }];
    let cfg = exec_config(Some(PROXY), deployments);
    let report = run_and_judge(&cfg);
    assert_eq!(
        report.verdict,
        Verdict::Confirmed,
        "reason: {}",
        report.reason
    );
    let witness = report.witness.expect("confirmed 必有 witness");

    // caller 轮换的记录：第一跳 = 代理合约 → victim（转发帧）。
    assert_eq!(witness.trace.calls.len(), 2, "代理帧 + victim 帧各一跳");
    let forward = &witness.trace.calls[0];
    assert_eq!(forward.from, PROXY);
    assert_eq!(forward.target, VICTIM);
    assert_eq!(forward.kind, "CALL");
    // 定罪 call 归属 victim 帧（代理转发帧的 input 也是 calldata
    // 子串——from 过滤保证不张冠李戴）。
    let evidence = &witness.evidence_call;
    assert_eq!(evidence.from, VICTIM);
    assert_eq!(evidence.target, SINK);
    assert_eq!(
        evidence.input,
        calldata_of(&witness.input),
        "臂 3 裸转发：input = 原始交易 calldata"
    );
    assert_eq!(witness.pc, 0);
}

/// 直接对照（不经代理）：单合约常数路径不回归。
#[test]
fn direct_entry_is_unchanged() {
    let cfg = exec_config(None, Vec::new());
    let report = run_and_judge(&cfg);
    assert_eq!(
        report.verdict,
        Verdict::Confirmed,
        "reason: {}",
        report.reason
    );
    let witness = report.witness.expect("confirmed 必有 witness");
    assert_eq!(witness.trace.calls.len(), 1, "直接路径仅 victim 一跳");
    assert_eq!(witness.evidence_call.from, VICTIM);
    assert_eq!(witness.evidence_call.target, SINK);
}

/// poc.json 穿透：entry 落盘、serde 往返、replay 同参重建 →
/// verdict 逐字节一致（经代理的见证只有同入口重放才一致）。
#[test]
fn poc_roundtrip_and_replay_with_entry() {
    let deployments = vec![Deployment {
        address: PROXY,
        runtime: forwarder_runtime(VICTIM),
    }];
    let cfg = exec_config(Some(PROXY), deployments);
    let report = run_and_judge(&cfg);
    let poc = build_poc(&report, &cfg, 42, 8, 30, "poc-proxy.json").unwrap();
    assert_eq!(
        poc.entry.as_deref(),
        Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    let json = serde_json::to_vec(&poc).unwrap();
    let back: loom_fuzz_oracle::Poc = serde_json::from_slice(&json).unwrap();
    assert_eq!(poc, back);

    let replayed = replay(&poc, &victim_code(), None).expect("replay 重建会话");
    assert_eq!(replayed.verdict, Verdict::Confirmed);
}
