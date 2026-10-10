//! 分层搜索验收测试（issue #25）：
//! 1. revert 归因：两守卫 harness，feedback 报出正确 guard（pc+cond）；
//! 2. 多槽协同穿透：两槽需同时命中字典词才过比较；
//! 3. 基座规模受控（全槽字典基座 ≤64 + 截断 assumption）。

use std::collections::BTreeMap;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{
    run_targeted_with, ExecConfig, GuardContext, Input, OutcomeKind, ProposalBudget, Proposer,
    ProposerCtx, RunFeedback, ValueDictionary,
};
use loom_fuzz_seed::{HitView, Tail, Target};

struct Hit {
    selector: u32,
    pcs: Vec<u32>,
}

impl HitView for Hit {
    fn selector(&self) -> u32 {
        self.selector
    }
    fn target_pcs(&self) -> &[u32] {
        &self.pcs
    }
    fn evidence(&self) -> &str {
        ""
    }
}

/// 收集反馈的测试提案器（不产候选）。
struct CapturingProposer {
    seen: Vec<RunFeedback>,
}

impl Proposer for CapturingProposer {
    fn refresh(&mut self, _ctx: &ProposerCtx<'_>) {}
    fn propose(&mut self, feedback: &[RunFeedback], _b: ProposalBudget) -> Vec<Input> {
        self.seen.extend(feedback.iter().cloned());
        Vec::new()
    }
}

fn cfg_for(code: Vec<u8>, guards: Vec<GuardContext>) -> ExecConfig {
    ExecConfig {
        code,
        address: [0x22; 20],
        prestate: BTreeMap::new(),
        seed_rng: 7,
        // 提案器只在进化环被调用：max_runs 要给够代数（反馈窗
        // FEEDBACK_WINDOW 内仍含种子 run）。
        max_runs: 200,
        time_budget: Duration::from_secs(60),
        gas_per_tx: 200_000,
        run_baseline: false,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        max_steps: 1,
            dynamic_head_evidence: false,
        guard_context: guards,
    }
}

fn input(selector: u32, words: &[u64]) -> Input {
    Input {
        selector,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: words
            .iter()
            .map(|w| U256::from(*w).to_be_bytes::<32>())
            .collect(),
        tail: Tail::Empty,
    }
}

/// 两守卫 harness：word0 == MAGIC0 过 guard@pcA；word1 == MAGIC1 过
/// guard@pcB；两 guard 都过才到目标（EQ 链 + JUMPI）。任一失败
/// revert。
fn two_guard_harness(magic0: u64, magic1: u64) -> (Vec<u8>, u32, u32, u32) {
    // guard A：PUSH1 4 CALLDATALOAD PUSH2 m0 EQ PUSH1 destA JUMPI
    //   [PUSH1 0 PUSH1 0 REVERT] JUMPDEST …；guard B 同构（word1）。
    // dest 在 revert 块之后取 code.len()（不手算偏移）。
    let mut code = Vec::new();
    code.extend_from_slice(&[0x60, 0x04, 0x35, 0x61]);
    code.extend_from_slice(&(magic0 as u16).to_be_bytes());
    let guard_a = code.len() as u32; // EQ pc
    code.push(0x14);
    code.extend_from_slice(&[0x60, 0x00, 0x57]); // PUSH1 <回填> JUMPI
    let jmp_a = code.len() as u32 - 2; // dest 操作数的 pc
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]);
    let dest_a = code.len() as u32;
    code[jmp_a as usize] = dest_a as u8;
    code.push(0x5b); // JUMPDEST @ dest_a

    code.extend_from_slice(&[0x60, 0x24, 0x35, 0x61]);
    code.extend_from_slice(&(magic1 as u16).to_be_bytes());
    let guard_b = code.len() as u32;
    code.push(0x14);
    code.extend_from_slice(&[0x60, 0x00, 0x57]);
    let jmp_b = code.len() as u32 - 2;
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]);
    let dest_b = code.len() as u32;
    code[jmp_b as usize] = dest_b as u8;
    let target = code.len() as u32;
    code.push(0x5b); // 目标 JUMPDEST
    code.push(0x00); // STOP
    (code, guard_a, guard_b, target)
}

#[test]
fn revert_attribution_reports_last_passed_guard() {
    let (code, guard_a, guard_b, target) = two_guard_harness(0xaaaa, 0xbbbb);
    let guards = vec![
        GuardContext {
            pc: guard_a,
            cond: "==(calldata_word(0x4), 0xaaaa)".into(),
        },
        GuardContext {
            pc: guard_b,
            cond: "==(calldata_word(0x24), 0xbbbb)".into(),
        },
    ];
    let cfg = cfg_for(code, guards);
    let hit = Hit {
        selector: 0xdeadbeef,
        pcs: vec![target],
    };
    let target = Target { hit: &hit, func: 0 };
    // word0 对（过 guard A），word1 错（guard B 失败 revert）。
    let seed = input(0xdeadbeef, &[0xaaaa, 0x1234]);
    let mut cap = CapturingProposer { seen: Vec::new() };
    let seeds = [loom_fuzz_seed::TxSequence::single([0x22; 20], seed)];
    let report = run_targeted_with(
        &cfg,
        &target,
        &seeds,
        &ValueDictionary { words: vec![] },
        &mut cap,
    );
    assert!(!report.reached);
    let bad = cap
        .seen
        .iter()
        .find(|f| {
            f.outcome == OutcomeKind::Revert
                && f.seq.steps[0].input.head[0] == U256::from(0xaaaau64).to_be_bytes::<32>()
                && f.seq.steps[0].input.head[1] == U256::from(0x1234u64).to_be_bytes::<32>()
        })
        .expect("失败输入应有反馈（word0 过守卫 A、word1 错Revert）");
    assert_eq!(bad.outcome, OutcomeKind::Revert);
    let g = bad.reverted_guard.as_ref().expect("revert 归因应有 guard");
    assert_eq!(g.pc, guard_b, "应归因最近经过的守卫 B");
    assert!(g.cond_rendered.contains("0xbbbb"));
    assert!(g.polarity_failed);
    // 对照：guard A 不应出现在该反馈（它已通过）。
    assert_ne!(g.pc, guard_a);
}

#[test]
fn coordinated_pierces_two_slot_constraint() {
    let (code, _a, _b, target) = two_guard_harness(0xaaaa, 0xbbbb);
    // 字典含两个 magic → 全槽基座/协同可一步命中；max_runs 小，
    // 只靠协同算子的 k=2 覆盖（单槽字典变体只会逐个过守卫）。
    let dict = ValueDictionary {
        words: vec![U256::from(0xaaaau64), U256::from(0xbbbbu64)],
    };
    let cfg = ExecConfig {
        max_runs: 200,
        ..cfg_for(code, Vec::new())
    };
    let hit = Hit {
        selector: 0xdeadbeef,
        pcs: vec![target],
    };
    let target = Target { hit: &hit, func: 0 };
    let seed = input(0xdeadbeef, &[0x1, 0x2]);
    let report = run_targeted(&cfg, &target, &[seed], &dict);
    assert!(report.reached, "两槽协同应穿透同现约束: {report:?}");
}

// run_targeted 便捷引用（本测试文件顶部未导入；种子包成单步序列——
// steps.len()==1 与旧单步路径语义等价）。
fn run_targeted(
    cfg: &ExecConfig,
    target: &Target<'_>,
    seeds: &[Input],
    dict: &ValueDictionary,
) -> loom_fuzz_fuzz::SessionReport {
    let seeds: Vec<_> = seeds
        .iter()
        .cloned()
        .map(|i| loom_fuzz_seed::TxSequence::single([0x22; 20], i))
        .collect();
    loom_fuzz_fuzz::run_targeted(cfg, target, &seeds, dict)
}
