//! 多交易 stateful 搜索验收（issue #35）：witness = 调用序列。
//!
//! 1. 两步序列（步1 布置存储槽 = MAGIC，步2 过守卫触发目标帧）
//!    confirmed；对应单步搜索（max_steps=1，同一预算）不可达
//!    ——单笔交易无法既布置又触发（布置路径 STOP，触发路径要求
//!    槽已布置），对照证明序列搜索的价值。
//! 2. poc.json 序列形态落盘 + serde 往返 + replay 逐字节一致。
//! 3. 旧单步 poc.json（legacy `tx` 字段、无 `steps`）仍可 replay
//!    ——序列化向后兼容。

use std::collections::BTreeMap;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{run_targeted, ExecConfig};
use loom_fuzz_oracle::{build_poc, calldata_of, judge, replay, Hit, Verdict};
use loom_fuzz_seed::{HitView, Input, Tail, Target, TxSequence, ValueDictionary};

const VICTIM: [u8; 20] = [0x22; 20];
const SINK: [u8; 20] = [0x11; 20];
const SELECTOR: u32 = 0xdeadbeef;
/// 布置分支标记（head[0]）：SSTORE(0, head[1])。
const SET_MAGIC: u64 = 0x51;
/// 触发分支标记（head[0]）：SLOAD(0) == MAGIC 才落到目标帧。
const GO_MAGIC: u64 = 0x67;
/// 目标帧守卫常量：槽 0 须等于 MAGIC（非零——空槽 0 过不了守卫，
/// 单步不可达的根因）。
const MAGIC: u64 = 0xc0de;

/// 迷你汇编器：PUSH1 目标占位（0xff）+ 标签回填——机械构造，
/// 非个案硬编码字节串。
struct Asm {
    code: Vec<u8>,
    /// (标签, 占位下标) 待回填。
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
    /// PUSH1 占位 + 记录回填点。
    fn push1_label(&mut self, label: u32) {
        self.code.extend_from_slice(&[0x60, 0xff]);
        self.fixups.push((label, self.code.len() - 1));
    }
    fn label(&mut self, label: u32) {
        self.labels.insert(label, self.code.len());
        self.code.push(0x5b); // JUMPDEST
    }
    fn finish(mut self) -> (Vec<u8>, u32) {
        for (label, at) in self.fixups {
            let dest = self.labels[&label];
            assert!(dest < 0x100, "测试字节码用 PUSH1 跳转目标");
            self.code[at] = dest as u8;
        }
        let target = self.labels[&3] as u32; // 标签 3 = 目标帧
        (self.code, target)
    }
}

/// victim：head[0] 选分支——SET 布置槽 0 = head[1]；GO 要求槽 0 ==
/// MAGIC 才进目标帧（JUMPDEST → 整笔 calldata 原样 CALL sink，
/// arbitrary_call 臂 3 裸转发形态）。
fn victim_code() -> (Vec<u8>, u32) {
    let mut a = Asm::new();
    // word0 = CALLDATALOAD(4)（selector 后第一槽 = head[0]）
    a.push1(4);
    a.op(0x35);
    // if word0 == SET_MAGIC → set 分支
    a.push32(U256::from(SET_MAGIC));
    a.op(0x14); // EQ
    a.push1_label(1);
    a.op(0x57); // JUMPI
                // if word0 == GO_MAGIC → go 分支
    a.push1(4);
    a.op(0x35);
    a.push32(U256::from(GO_MAGIC));
    a.op(0x14);
    a.push1_label(2);
    a.op(0x57);
    a.op(0x00); // 不匹配 → STOP
                // set 分支：SSTORE(0, CALLDATALOAD(36)（= head[1]）)
    a.label(1);
    a.push1(36);
    a.op(0x35);
    a.push1(0);
    a.op(0x55); // SSTORE
    a.op(0x00);
    // go 分支：SLOAD(0) == MAGIC → 目标帧
    a.label(2);
    a.push1(0);
    a.op(0x54); // SLOAD
    a.push32(U256::from(MAGIC));
    a.op(0x14);
    a.push1_label(3);
    a.op(0x57);
    a.op(0x00);
    // 目标帧：整笔 calldata 原样 CALL sink
    a.label(3);
    a.op(0x36); // CALLDATASIZE
    a.push1(0);
    a.push1(0);
    a.op(0x37); // CALLDATACOPY
    a.push1(0);
    a.push1(0);
    a.op(0x36);
    a.push1(0);
    a.push1(0);
    a.code.push(0x73); // PUSH20 sink
    a.code.extend_from_slice(&SINK);
    a.op(0x5a); // GAS
    a.op(0xf1); // CALL
    a.op(0x00);
    a.finish()
}

struct SeqHit {
    target_pc: u32,
}

impl HitView for SeqHit {
    fn selector(&self) -> u32 {
        SELECTOR
    }
    fn target_pcs(&self) -> &[u32] {
        std::slice::from_ref(&self.target_pc)
    }
    fn evidence(&self) -> &str {
        ""
    }
}

fn hit(target_pc: u32) -> Hit {
    Hit {
        family: Default::default(),
        selector: SELECTOR,
        step: 0,
        target_pcs: vec![target_pc],
        evidence: String::new(),
        evidence_expr: None,
        arm: None,
        dominating_guards: Vec::new(),
    }
}

fn cfg(code: &[u8], max_steps: u32, max_runs: u64) -> ExecConfig {
    ExecConfig {
        code: code.to_vec(),
        address: VICTIM,
        prestate: BTreeMap::new(),
        seed_rng: 42,
        max_runs,
        time_budget: Duration::from_secs(60),
        gas_per_tx: 200_000,
        run_baseline: false,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        max_steps,
        guard_context: Vec::new(),
    }
}

/// 种子 = 通用零参基座 + 字典词 × 槽位变体（管线 #25 既有机制：
/// seed 编译器从支配 guard 反解 guard 常量进值字典，管线生成
/// 全槽变体种子——此处字典词 = 分支/守卫常量，等价于真实 shard
/// 里 seed 编译器的产物形态，非个案硬编码）。
fn seeds(dict: &ValueDictionary) -> Vec<TxSequence> {
    let base = |head: Vec<[u8; 32]>| {
        TxSequence::single(
            VICTIM,
            Input {
                selector: SELECTOR,
                caller: [0x33; 20],
                value: U256::ZERO,
                head,
                tail: Tail::Empty,
            },
        )
    };
    let mut out = vec![base(vec![[0u8; 32]; 2])];
    for w in &dict.words {
        for k in 0..2 {
            let mut head = vec![[0u8; 32]; 2];
            head[k] = w.to_be_bytes::<32>();
            out.push(base(head));
        }
    }
    out
}

fn word(v: u64) -> [u8; 32] {
    U256::from(v).to_be_bytes::<32>()
}

/// 两步序列 confirmed：步1 布置（SET_MAGIC, MAGIC），步2 触发
/// （GO_MAGIC, 任意）→ 目标帧裸转发臂 3 定罪；单步对照 unreachable。
#[test]
fn two_step_sequence_confirms_and_single_step_is_unreachable() {
    let (code, target_pc) = victim_code();
    // 字典 = 分支/守卫常量（真实管线由 seed 编译器从 shard 支配
    // guard 反解提供——值字典定义见 docs/architecture.md）。
    let dict = ValueDictionary {
        words: vec![
            U256::from(SET_MAGIC),
            U256::from(GO_MAGIC),
            U256::from(MAGIC),
        ],
    };

    // 单步对照（issue #35 验收）：同一预算下 max_steps=1 不可达
    // ——布置路径 STOP、触发路径要求非零 MAGIC 已布置，单笔交易
    // 无法兼顾。
    let single = run_targeted(
        &cfg(&code, 1, 3_000),
        &target(target_pc),
        &seeds(&dict),
        &dict,
    );
    assert!(
        !single.reached,
        "单步不应到达目标帧（布置与触发不可兼得）: {single:?}"
    );
    let single_calldatas: Vec<Vec<u8>> = single
        .best_steps
        .as_ref()
        .map(|s| s.steps.iter().map(|st| calldata_of(&st.input)).collect())
        .unwrap_or_default();
    let single_report = judge(&hit(target_pc), &single, &single_calldatas);
    assert_eq!(single_report.verdict, Verdict::Unreachable);

    // 两步搜索：序列组装（append/splice）把"布置步"与"触发步"拼成
    // 状态ful 序列，状态跨步持久（同一 overlay 续跑）。
    let session = run_targeted(
        &cfg(&code, 2, 8_000),
        &target(target_pc),
        &seeds(&dict),
        &dict,
    );
    assert!(
        session.reached,
        "两步搜索应到达目标帧: best_runs={} runs_completed={}",
        session.best_runs, session.runs_completed
    );
    let calldatas: Vec<Vec<u8>> = session
        .best_steps
        .as_ref()
        .expect("reached 必有见证")
        .steps
        .iter()
        .map(|s| calldata_of(&s.input))
        .collect();
    let report = judge(&hit(target_pc), &session, &calldatas);
    assert_eq!(
        report.verdict,
        Verdict::Confirmed,
        "reason: {}",
        report.reason
    );
    let witness = report.witness.clone().expect("confirmed 必有 witness");

    // 序列形态：步1 布置、步2 触发；目标帧在步 2 到达。
    assert_eq!(witness.steps.len(), 2, "见证应是两步序列");
    assert_eq!(witness.steps[0].input.head[0], word(SET_MAGIC));
    assert_eq!(witness.steps[0].input.head[1], word(MAGIC));
    assert_eq!(witness.steps[1].input.head[0], word(GO_MAGIC));
    assert_eq!(witness.steps[0].target, VICTIM);
    assert_eq!(witness.steps[1].target, VICTIM);
    assert_eq!(witness.evidence_call.step, 1, "定罪 call 在第二步");
    assert_eq!(witness.evidence_call.target, SINK);
    assert_eq!(
        witness.evidence_call.input, calldatas[1],
        "臂 3 裸转发：input = 第二步 calldata"
    );
    assert_eq!(
        witness.trace.step_outcomes,
        vec![
            loom_fuzz_fuzz::OutcomeKind::Stop,
            loom_fuzz_fuzz::OutcomeKind::Stop
        ]
    );
    assert!(
        !witness.trace.truncated,
        "到场步之前不应有截断（到达步感知，如实）"
    );

    // poc.json 序列形态：落盘 + serde 往返 + replay 逐字节一致。
    let session_cfg = cfg(&code, 2, 3_000);
    let poc = build_poc(&report, &session_cfg, 42, 3_000, 60, "poc-seq.json").unwrap();
    assert_eq!(poc.steps.len(), 2);
    assert_eq!(poc.steps[0].target, loom_fuzz_oracle::bytes_hex(&VICTIM));
    let json = serde_json::to_vec(&poc).unwrap();
    let back: loom_fuzz_oracle::Poc = serde_json::from_slice(&json).unwrap();
    assert_eq!(poc, back);
    let replayed = replay(&poc, &code, None).expect("序列 poc replay");
    assert_eq!(replayed.verdict, Verdict::Confirmed);
}

fn target(target_pc: u32) -> Target<'static> {
    // 'static：测试内构造的 HitView 由 leak 供给（测试进程生命周期）。
    let hit: &'static SeqHit = Box::leak(Box::new(SeqHit { target_pc }));
    Target { hit, func: 0 }
}

/// 旧单步 poc.json（legacy `tx` 字段、无 `steps`）仍可 replay：
/// normalized_steps 归一单步序列，向后兼容钉死。
#[test]
fn legacy_single_step_poc_still_replays() {
    // 最简 victim：pc0 JUMPDEST（target）→ 整笔 calldata CALL sink。
    let mut code = vec![
        0x5b, // JUMPDEST (pc 0 = target)
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY
        0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00, 0x60, 0x00,
    ];
    code.push(0x73);
    code.extend_from_slice(&SINK);
    code.extend_from_slice(&[0x5a, 0xf1, 0x00]); // GAS; CALL; STOP

    let head = [0u8; 32];
    let mut calldata = SELECTOR.to_be_bytes().to_vec();
    calldata.extend_from_slice(&head);
    // 手工构造 legacy poc.json（#35 之前的单步形态：tx 在场、无
    // steps / entry / max_steps 等新字段——serde 缺省兜底）。
    let legacy = format!(
        r#"{{
            "format": "loom-fuzz-poc@1",
            "digest": "0x00",
            "selector": "0xdeadbeef",
            "step": 0,
            "pc": 0,
            "verdict": "confirmed",
            "tx": {{
                "caller": "0x3333333333333333333333333333333333333333",
                "value": "0x{}",
                "calldata": "{}"
            }},
            "prestate": {{}},
            "responses": [],
            "seed": 42,
            "max_runs": 100,
            "time_budget_secs": 300,
            "replay": "loom-fuzz replay legacy.json --code <bytecode.hex>"
        }}"#,
        "0".repeat(64),
        loom_fuzz_oracle::bytes_hex(&calldata),
    );
    let poc: loom_fuzz_oracle::Poc = serde_json::from_str(&legacy).expect("legacy poc 解析");
    let report = replay(&poc, &code, None).expect("legacy 单步 poc replay");
    assert_eq!(
        report.verdict,
        Verdict::Confirmed,
        "reason: {}",
        report.reason
    );
}
