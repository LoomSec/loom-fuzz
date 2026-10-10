//! 臂 1 oracle 的 revm 级 harness 测试（issue #19 验收）：
//! 路由器型微型合约——target = calldata 词（CALLDATALOAD(4)），
//! 到场后对空地址 low-level call 成功返回；evidence 求值 ==
//! call.target → 臂 1 confirmed。无需 shard：表达式视图用测试内
//! 手工节点表（与 eval 单测同机制）。

use std::collections::BTreeMap;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{run_targeted, ExecConfig};
use loom_fuzz_oracle::eval::{EvalViewDyn, OwnedNode};
use loom_fuzz_oracle::{judge_with, CallArm, Hit, JudgeInput, Verdict};
use loom_fuzz_seed::{HitView, Input, Tail, Target, TxSequence, ValueDictionary};

/// 微型路由器字节码：CALLDATALOAD(4) 作 target，空 input CALL 之。
/// 布局：5×PUSH1 0（out_size..value）+ PUSH1 4 CALLDATALOAD（to）
/// + PUSH2 0xffff（gas）+ CALL @16 + STOP。
const ROUTER_CODE: &[u8] = &[
    0x60, 0x00, // 0: out size
    0x60, 0x00, // 2: out offset
    0x60, 0x00, // 4: in size
    0x60, 0x00, // 6: in offset
    0x60, 0x00, // 8: value
    0x60, 0x04, // 10: calldata offset
    0x35, // 12: CALLDATALOAD → to
    0x61, 0xff, 0xff, // 13: gas
    0xf1, // 16: CALL（target pc）
    0x00, // 17: STOP
];

/// 表达式视图：节点 0 = CalldataWord(4)（evidence = calldata 槽 0）。
struct HarnessView;

impl EvalViewDyn for HarnessView {
    fn owned_node(&self, id: u32) -> Option<OwnedNode> {
        (id == 0).then_some(OwnedNode::CalldataWord(4))
    }
}

struct HarnessHit;

impl HitView for HarnessHit {
    fn selector(&self) -> u32 {
        0xdeadbeef
    }
    fn target_pcs(&self) -> &[u32] {
        &[16]
    }
    fn evidence(&self) -> &str {
        "calldata_word(0x4)"
    }
}

fn session() -> loom_fuzz_fuzz::SessionReport {
    // 输入：selector + 槽 0 = 目标地址 0x1234…（低 160 位即 call target）。
    let mut word = [0u8; 32];
    word[31] = 0x34;
    word[30] = 0x12;
    let target_addr: u64 = 0x1234;
    let _ = target_addr;
    let seed = Input {
        selector: 0xdeadbeef,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: vec![word],
        tail: Tail::Empty,
    };
    let cfg = ExecConfig {
        code: ROUTER_CODE.to_vec(),
        address: [0x22; 20],
        prestate: BTreeMap::new(),
        seed_rng: 7,
        max_runs: 10,
        time_budget: Duration::from_secs(30),
        gas_per_tx: 100_000,
        run_baseline: false,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        max_steps: 1,
            dynamic_head_evidence: false,
        guard_context: Vec::new(),
    };
    let hit = HarnessHit;
    let target = Target { hit: &hit, func: 0 };
    let report = run_targeted(
        &cfg,
        &target,
        &[TxSequence::single([0x22; 20], seed)],
        &ValueDictionary { words: vec![] },
    );
    assert!(report.reached, "harness 应到场: {report:?}");
    assert_eq!(report.trace.calls.len(), 1);
    assert_eq!(report.trace.calls[0].target[19], 0x34);
    assert_eq!(report.trace.calls[0].target[18], 0x12);
    report
}

fn hit() -> Hit {
    Hit {
        family: Default::default(),
        selector: 0xdeadbeef,
        step: 1,
        target_pcs: vec![16],
        evidence: "calldata_word(0x4)".to_string(),
        evidence_expr: Some(0),
        arm: Some(CallArm::Arm1),
        dominating_guards: Vec::new(),
    }
}

#[test]
fn arm1_confirmed_on_router_harness() {
    let report = session();
    let calldata =
        loom_fuzz_oracle::calldata_of(&report.best_steps.as_ref().unwrap().steps[0].input);
    let r = judge_with(
        &hit(),
        &report,
        &[calldata],
        &JudgeInput {
            view: Some(&HarnessView),
            expected_evidence: None,
        },
    );
    assert_eq!(r.verdict, Verdict::Confirmed, "{:?}", r.reason);
    assert!(r.reason.contains("臂 1"), "reason 应注明臂 1: {}", r.reason);
    // witness 带求值结果（hex 字）。
    let w = r.witness.expect("confirmed 有 witness");
    let v = U256::from_str_radix(w.evidence_value.unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!(v, U256::from(0x1234u64), "求值 = calldata 槽 0");
}

#[test]
fn arm1_replay_via_expected_evidence() {
    // replay 形态：无视图，用 poc 内嵌 evidence_value 重放判定。
    let report = session();
    let calldata =
        loom_fuzz_oracle::calldata_of(&report.best_steps.as_ref().unwrap().steps[0].input);
    let r = judge_with(
        &hit(),
        &report,
        std::slice::from_ref(&calldata),
        &JudgeInput {
            view: None,
            expected_evidence: Some(U256::from(0x1234u64)),
        },
    );
    assert_eq!(r.verdict, Verdict::Confirmed, "{:?}", r.reason);
    // 承诺值与 witness 不符 → 不成立（fail-closed）。
    let r_bad = judge_with(
        &hit(),
        &report,
        &[calldata],
        &JudgeInput {
            view: None,
            expected_evidence: Some(U256::from(0x9999u64)),
        },
    );
    assert_eq!(r_bad.verdict, Verdict::Unreachable);
}

#[test]
fn arm1_eval_bottom_is_fail_closed() {
    // 求值 ⊥（表达式视图缺节点）→ 不猜：unreachable 且 reason 如实。
    struct EmptyView;
    impl EvalViewDyn for EmptyView {
        fn owned_node(&self, _id: u32) -> Option<OwnedNode> {
            None
        }
    }
    let report = session();
    let calldata =
        loom_fuzz_oracle::calldata_of(&report.best_steps.as_ref().unwrap().steps[0].input);
    let r = judge_with(
        &hit(),
        &report,
        &[calldata],
        &JudgeInput {
            view: Some(&EmptyView),
            expected_evidence: None,
        },
    );
    assert_eq!(r.verdict, Verdict::Unreachable);
    assert!(r.reason.contains("臂 1"), "{:?}", r.reason);
}
