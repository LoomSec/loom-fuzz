//! L3 多步攻击 PoC 验收（issue #36）：多步 confirmed witness →
//! 攻击合约 + 序列驱动的 Foundry 工程 **forge test 真跑绿灯**。
//!
//! fixture victim（手写汇编，迷你标签汇编器构造——机械，非个案
//! 硬编码字节串）：head[0]（calldata 词 0，offset 4）选分支——
//! SET（0x51）：SSTORE(0, head[1])（布置步，步1 的 witness 形态）；
//! GO（0x67）：SLOAD(0) == MAGIC 守卫（非零——空槽过不了，两步的
//! 必要性）→ 目标帧：TRV 形裸转发——to = head[1]、input = 动态尾
//! 内容（arbitrary_call 臂 3 的 L1 形状）。payload 步 calldata =
//! sel ++ [GO, SINK, 0x60 尾偏移] ++ [len=4, "loom"]。
//!
//! L3 合成期望：攻击合约 attack() 步0 布置（SSTORE MAGIC）、步1
//! 注入后 calldata = sel ++ [GO, token, 0x60] ++
//! abi.encodeCall(IERC20.transferFrom, (ROUTER, ATTACKER, BALANCE))
//! ——victim 转发该请求给受害资产 mock → transferFrom 抽干 ROUTER
//! 持仓 → 终点断言 balanceOf(ROUTER) == 0 绿灯。

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_fuzz::{run_targeted, ExecConfig};
use loom_fuzz_oracle::{build_poc, calldata_of, judge, Poc, PocCall, PocDeployment, POC_FORMAT};
use loom_fuzz_seed::{HitView, Input, Step, Tail, Target, TxSequence, ValueDictionary};

const ROUTER: [u8; 20] = [0x22; 20];
const SINK: [u8; 20] = [0x11; 20];
const SELECTOR: u32 = 0xdeadbeef;
const SET_MAGIC: u64 = 0x51;
const GO_MAGIC: u64 = 0x67;
const MAGIC: u64 = 0xc0de;

// ---------------------------------------------------------------------------
// 迷你标签汇编器（测试内构造 victim 字节码——机械，零个案）。
// ---------------------------------------------------------------------------
struct Asm {
    code: Vec<u8>,
    fixups: Vec<(u32, usize)>,
    labels: HashMap<u32, usize>,
}

impl Asm {
    fn new() -> Self {
        Asm {
            code: Vec::new(),
            fixups: Vec::new(),
            labels: HashMap::new(),
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
        let target = self.labels[&3] as u32;
        (self.code, target)
    }
}

/// fixture victim：布置/触发两分支 + TRV 形目标帧（to = head[1]，
/// input = 尾内容）。
fn victim_code() -> (Vec<u8>, u32) {
    let mut a = Asm::new();
    // word0 = CALLDATALOAD(4)
    a.push1(4);
    a.op(0x35);
    a.push32(U256::from(SET_MAGIC));
    a.op(0x14);
    a.push1_label(1);
    a.op(0x57);
    a.push1(4);
    a.op(0x35);
    a.push32(U256::from(GO_MAGIC));
    a.op(0x14);
    a.push1_label(2);
    a.op(0x57);
    a.op(0x00);
    // set：SSTORE(0, CALLDATALOAD(36))
    a.label(1);
    a.push1(36);
    a.op(0x35);
    a.push1(0);
    a.op(0x55);
    a.op(0x00);
    // go：SLOAD(0) == MAGIC → 目标帧
    a.label(2);
    a.push1(0);
    a.op(0x54);
    a.push32(U256::from(MAGIC));
    a.op(0x14);
    a.push1_label(3);
    a.op(0x57);
    a.op(0x00);
    // 目标帧：TRV 裸转发——calldata 全量入 mem，to = head[1]，
    // input = 尾内容（len 字在 0x64、内容在 0x84——标准 ABI 偏移 0x60）。
    a.label(3);
    a.op(0x36);
    a.push1(0);
    a.push1(0);
    a.op(0x37); // CALLDATACOPY(0, 0, size)
    a.push1(0);
    a.push1(0);
    a.push1(0x64);
    a.op(0x51); // inSize = mload(0x64)
    a.push1(0x84); // inOffset = 0x84
    a.push1(0); // value
    a.push1(36);
    a.op(0x35); // to = calldataload(36)
    a.op(0x5a);
    a.op(0xf1);
    a.op(0x00);
    a.finish()
}

struct FixtureHit {
    pc: u32,
}

impl HitView for FixtureHit {
    fn selector(&self) -> u32 {
        SELECTOR
    }
    fn target_pcs(&self) -> &[u32] {
        std::slice::from_ref(&self.pc)
    }
    fn evidence(&self) -> &str {
        ""
    }
}

fn word(v: u64) -> [u8; 32] {
    U256::from(v).to_be_bytes::<32>()
}

fn addr_word(a: [u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}

/// 两步 witness 序列（与 L3 合成期望一致：步0 布置、步1 触发）。
fn witness_sequence() -> TxSequence {
    let step0 = Input {
        selector: SELECTOR,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: vec![word(SET_MAGIC), word(MAGIC)],
        tail: Tail::Empty,
    };
    let mut tail = word(4).to_vec();
    tail.extend_from_slice(b"loom");
    tail.extend_from_slice(&[0u8; 28]);
    let step1 = Input {
        selector: SELECTOR,
        caller: [0x33; 20],
        value: U256::ZERO,
        head: vec![word(GO_MAGIC), addr_word(SINK), word(0x60)],
        tail: Tail::Bytes(tail),
    };
    TxSequence {
        steps: vec![
            Step {
                target: ROUTER,
                input: step0,
            },
            Step {
                target: ROUTER,
                input: step1,
            },
        ],
    }
}

/// 端到端：真跑搜索出两步 confirmed witness（#35 管线）→ L3 合成 →
/// forge test 绿灯。Attacker.sol 编译进工程并驱动序列重放。
#[test]
fn l3_two_step_exploit_forge_green() {
    let (code, target_pc) = victim_code();
    // ---- L1：序列搜索出 confirmed witness（loom 管线的真跑一段）----
    let cfg = ExecConfig {
        code: code.clone(),
        address: ROUTER,
        prestate: Default::default(),
        seed_rng: 42,
        max_runs: 8_000,
        time_budget: Duration::from_secs(60),
        gas_per_tx: 200_000,
        run_baseline: false,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        max_steps: 2,
        dynamic_head_evidence: false,
        guard_context: Vec::new(),
    };
    let hit_view = FixtureHit { pc: target_pc };
    let target = Target {
        hit: &hit_view,
        func: 0,
    };
    let dict = ValueDictionary {
        words: vec![
            U256::from(SET_MAGIC),
            U256::from(GO_MAGIC),
            U256::from(MAGIC),
        ],
    };
    let session = run_targeted(&cfg, &target, &[witness_sequence()], &dict);
    assert!(session.reached, "fixture 应可搜索到达: {session:?}");
    let seq = session.best_steps.as_ref().expect("reached 必有见证");
    let calldatas: Vec<Vec<u8>> = seq.steps.iter().map(|s| calldata_of(&s.input)).collect();
    let report = judge(
        &loom_fuzz_oracle::Hit {
            family: Default::default(),
            selector: SELECTOR,
            step: 0,
            target_pcs: vec![target_pc],
            evidence: String::new(),
            evidence_expr: None,
            arm: None,
            dominating_guards: Vec::new(),
        },
        &session,
        &calldatas,
    );
    assert_eq!(report.verdict, loom_fuzz_oracle::Verdict::Confirmed);
    // 见证确为两步（L3 的前提）。
    assert_eq!(report.witness.as_ref().unwrap().steps.len(), 2);

    // ---- L3：多步 poc → 攻击合约工程 + forge 真跑 ----
    let poc = build_poc(&report, &cfg, 42, 8_000, 60, "poc-l3.json").unwrap();
    assert_eq!(poc.steps.len(), 2, "poc.json 序列形态两步");
    let out = out_dir("l3-green");
    let (path, summary) = loom_fuzz_pocgen::generate_exploit(&poc, &hex(&code), &out, false)
        .expect("L3 工程应合成且 forge 绿灯");
    assert!(
        summary.contains("[PASS] testExploit"),
        "forge 绿灯: {summary}"
    );
    println!("forge 绿灯摘录:\n{summary}");

    // 攻击合约编译进工程且为序列驱动形态。
    let attacker_sol =
        std::fs::read_to_string(path.join("src/Attacker.sol")).expect("Attacker.sol 落盘");
    assert!(attacker_sol.contains("contract Attacker"));
    assert!(attacker_sol.contains("function attack()"));
    assert_eq!(
        attacker_sol.matches("(bool ok").count(),
        2,
        "attack() 应按 Poc.steps 逐步 call（两步两处）"
    );
    // 槽替换经 abi 编码表达（非硬编码裸字节串：witness 原 calldata
    // 的 hex 不应出现在攻击合约里）。
    let step_hex = hex(&calldata_of(&seq.steps[1].input));
    assert!(
        !attacker_sol.contains(&step_hex),
        "attack() 不得硬编码 witness 裸 calldata"
    );
    assert!(attacker_sol.contains("abi.encodeWithSelector"));
    assert!(attacker_sol.contains("abi.encodeCall"));
    // 构造器收 victim + 受害资产 + 在场合约表。
    assert!(attacker_sol.contains("constructor(address _router, address _asset"));
}

/// 诚实降级：多步非 arbitrary_call 族 → NoGenericAction（不硬套）。
#[test]
fn l3_multi_step_non_arbitrary_family_degrades() {
    let (code, target_pc) = victim_code();
    let _ = target_pc;
    let mut poc = two_step_poc_json();
    poc.family = loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy;
    let out = out_dir("l3-degrade");
    let err = loom_fuzz_pocgen::generate_exploit(&poc, &hex(&code), &out, false)
        .expect_err("非 arbitrary_call 族多步应诚实降级");
    assert!(
        matches!(err, loom_fuzz_pocgen::PocgenError::NoGenericAction(_)),
        "应 NoGenericAction 诚实降级: {err}"
    );
}

/// 诚实降级：payload 步头形与定罪目标无交叉 → BadShape。
#[test]
fn l3_payload_shape_mismatch_degrades() {
    let (code, _) = victim_code();
    let mut poc = two_step_poc_json();
    poc.call = Some(PocCall {
        target: "0x9999999999999999999999999999999999999999".into(),
        input: poc.call.as_ref().unwrap().input.clone(),
    });
    let out = out_dir("l3-badshape");
    let err = loom_fuzz_pocgen::generate_exploit(&poc, &hex(&code), &out, false)
        .expect_err("payload 目标槽不可定位应 BadShape");
    assert!(format!("{err}").contains("头形"), "BadShape: {err}");
}

// ---- 工具 ----

fn out_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("loom-l3-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            use std::fmt::Write as _;
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn u256_hex(v: U256) -> String {
    format!("0x{}", hex(&v.to_be_bytes::<32>()))
}

/// 与 witness_sequence 同形的两步 poc（降级路径用；不依赖搜索会话）。
fn two_step_poc_json() -> Poc {
    let step0 = {
        let mut cd = SELECTOR.to_be_bytes().to_vec();
        cd.extend_from_slice(&word(SET_MAGIC));
        cd.extend_from_slice(&word(MAGIC));
        cd
    };
    let step1 = {
        let mut cd = SELECTOR.to_be_bytes().to_vec();
        cd.extend_from_slice(&word(GO_MAGIC));
        cd.extend_from_slice(&addr_word(SINK));
        cd.extend_from_slice(&word(0x60));
        cd.extend_from_slice(&word(4));
        cd.extend_from_slice(b"loom");
        cd.extend_from_slice(&[0u8; 28]);
        cd
    };
    Poc {
        format: POC_FORMAT.to_string(),
        digest: "0x00".into(),
        selector: "0xdeadbeef".into(),
        step: 0,
        pc: 0,
        verdict: "confirmed".into(),
        steps: vec![
            loom_fuzz_oracle::PocStep {
                target: loom_fuzz_oracle::bytes_hex(&ROUTER),
                caller: loom_fuzz_oracle::bytes_hex(&[0x33; 20]),
                value: u256_hex(U256::ZERO),
                calldata: format!("0x{}", hex(&step0)),
            },
            loom_fuzz_oracle::PocStep {
                target: loom_fuzz_oracle::bytes_hex(&ROUTER),
                caller: loom_fuzz_oracle::bytes_hex(&[0x33; 20]),
                value: u256_hex(U256::ZERO),
                calldata: format!("0x{}", hex(&step1)),
            },
        ],
        tx: None,
        prestate: Default::default(),
        responses: vec![],
        seed: 42,
        max_runs: 100,
        time_budget_secs: 300,
        evidence_value: None,
        fork: None,
        deployments: vec![PocDeployment {
            address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            runtime_hex: "0x600160005260206000f3".into(),
        }],
        entry: None,
        contract: Some(loom_fuzz_oracle::bytes_hex(&ROUTER)),
        family: loom_fuzz_oracle::HitFamily::ArbitraryCall,
        call: Some(PocCall {
            target: loom_fuzz_oracle::bytes_hex(&SINK),
            input: format!("0x{}", hex(b"loom")),
        }),
        replay: String::new(),
    }
}
