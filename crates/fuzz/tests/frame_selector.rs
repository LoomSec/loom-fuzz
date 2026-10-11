//! 帧归属 selector 一致性检查（issue #53）：pc 数值跨函数重叠的
//! "假到场"不计到场——到达步的顶层 calldata selector 必须 ==
//! hit selector（u32::MAX 哨兵 = fallback 命中跳过检查）。
//!
//! victim（手写汇编，迷你标签汇编器）：word0 选分支——
//! A（0xAAAA）与 B（0xBBBB）都经过同一 pc X（B 分支 JUMP 进 A 的
//! 尾部）——pc 数值重叠的复现形态。

use std::collections::BTreeMap;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{run_targeted, ExecConfig};
use loom_fuzz_seed::{HitView, Input, Tail, Target, TxSequence, ValueDictionary};

const VICTIM: [u8; 20] = [0x22; 20];
const SEL_A: u32 = 0xaaaaaaaa;
const SEL_B: u32 = 0xbbbbbbbb;

struct Asm {
    code: Vec<u8>,
    fixups: Vec<(u32, usize)>,
    labels: std::collections::HashMap<u32, usize>,
}

impl Asm {
    fn new() -> Self {
        Asm {
            code: Vec::new(),
            fixups: Vec::new(),
            labels: std::collections::HashMap::new(),
        }
    }
    fn op(&mut self, b: u8) {
        self.code.push(b);
    }
    fn push1(&mut self, v: u8) {
        self.code.extend_from_slice(&[0x60, v]);
    }
    fn push32(&mut self, v: U256) {
        self.code.push(0x7f);
        self.code.extend_from_slice(&v.to_be_bytes::<32>());
    }
    fn push1_label(&mut self, label: u32) {
        self.code.extend_from_slice(&[0x60, 0xff]);
        self.fixups.push((label, self.code.len() - 1));
    }
    fn label(&mut self, label: u32) {
        self.labels.insert(label, self.code.len());
        self.code.push(0x5b);
    }
    fn finish(mut self) -> (Vec<u8>, u32) {
        for (label, at) in self.fixups {
            let dest = self.labels[&label];
            assert!(dest < 0x100, "测试字节码用 PUSH1 跳转目标");
            self.code[at] = dest as u8;
        }
        (self.code, self.labels[&1] as u32)
    }
}

/// A/B 分支都经过 pc = label1（B 经 JUMP 落入 A 尾）——pc 数值重叠。
fn victim_code() -> (Vec<u8>, u32) {
    let mut a = Asm::new();
    a.push1(4);
    a.op(0x35); // word0 = CALLDATALOAD(4)
    a.push32(U256::from(SEL_A));
    a.op(0x14);
    a.push1_label(1);
    a.op(0x57); // A → label1
    a.push1(4);
    a.op(0x35);
    a.push32(U256::from(SEL_B));
    a.op(0x14);
    a.push1_label(2);
    a.op(0x57); // B → label2
    a.op(0x00);
    a.label(2);
    a.push1_label(1);
    a.op(0x56); // B 分支 JUMP 进 label1（pc 重叠）
    a.label(1);
    a.push1(0);
    a.push1(0);
    a.op(0xf3);
    a.finish()
}

struct Hit {
    selector: u32,
    pc: u32,
}

impl HitView for Hit {
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

fn cfg(code: &[u8]) -> ExecConfig {
    ExecConfig {
        code: code.to_vec(),
        address: VICTIM,
        prestate: BTreeMap::new(),
        seed_rng: 1,
        max_runs: 5,
        time_budget: Duration::from_secs(30),
        gas_per_tx: 100_000,
        run_baseline: false,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        max_steps: 1,
        dynamic_head_evidence: false,
        guard_slots: Vec::new(),
        guard_writers: Vec::new(),
        guard_context: Vec::new(),
    }
}

fn input(selector: u32) -> Input {
    Input {
        selector,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: vec![U256::from(SEL_A as u64).to_be_bytes::<32>()],
        tail: Tail::Empty,
    }
}

/// 跨函数假到场被拒：hit selector = A，跑 B 单步（同样过 pc X）
/// → reached=false。
#[test]
fn cross_function_false_arrival_is_rejected() {
    let (code, target_pc) = victim_code();
    let hit = Hit {
        selector: SEL_A,
        pc: target_pc,
    };
    let target = Target { hit: &hit, func: 0 };
    let report = run_targeted(
        &cfg(&code),
        &target,
        &[TxSequence::single(VICTIM, input(SEL_B))],
        &ValueDictionary { words: vec![] },
    );
    assert!(
        !report.reached,
        "B 分支过 pc {target_pc} 但 selector ≠ hit——假到场必须被拒"
    );
}

/// 同函数真到场通过：hit selector = A，跑 A 单步 → reached=true。
#[test]
fn same_function_true_arrival_passes() {
    let (code, target_pc) = victim_code();
    let hit = Hit {
        selector: SEL_A,
        pc: target_pc,
    };
    let target = Target { hit: &hit, func: 0 };
    let report = run_targeted(
        &cfg(&code),
        &target,
        &[TxSequence::single(VICTIM, input(SEL_A))],
        &ValueDictionary { words: vec![] },
    );
    assert!(
        report.reached,
        "A 分支过 pc {target_pc} 且 selector 一致——真到场"
    );
}

/// fallback 命中（u32::MAX 哨兵）跳过检查：hit selector 哨兵时
/// B 分支也到场（既有行为保留）。
#[test]
fn fallback_sentinel_skips_the_check() {
    let (code, target_pc) = victim_code();
    let hit = Hit {
        selector: u32::MAX,
        pc: target_pc,
    };
    let target = Target { hit: &hit, func: 0 };
    let report = run_targeted(
        &cfg(&code),
        &target,
        &[TxSequence::single(VICTIM, input(SEL_B))],
        &ValueDictionary { words: vec![] },
    );
    assert!(
        report.reached,
        "哨兵 = 无 selector 上下文，跳过帧归属检查（旧行为）"
    );
}
