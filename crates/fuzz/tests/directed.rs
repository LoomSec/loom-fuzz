//! 验收测试（issue #5）：
//! 1. trv-like fixture 到达目标帧（prestate 布置 serviceRegistry，
//!    命中 0x90ce82d4 / pc 384，trace 拦到 CALL）；
//! 2. 确定性：同 seed_rng 两次运行 best_input / WitnessTrace 序列化
//!    逐字节一致；
//! 3. 制导收益：guard-boundary fixture，guided best_runs vs 纯随机
//!    基线 baseline_runs_to_reach；
//! 4. 不可达诚实：target pc 设在代码外，reached=false、truncated
//!    如实、无 panic。

use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_primitives::U256;
use loom_fuzz_seed::{
    compile, locate, HitView, Input, SeedOutput, Tail, Target, TxSequence, ValueDictionary,
};
use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::Xlayer;
use sha3::{Digest, Keccak256};

use loom_fuzz_fuzz::{run_targeted, ExecConfig, SessionReport};

const CONTRACT_ADDRESS: [u8; 20] = [0x22; 20];
/// 必注册的一个 service 地址（测试断言用；其余注册项 = 值字典常量，
/// registry 多成员场景）。
const REGISTERED_SERVICE: u64 = 0x7d;
/// 注册的最大 service 数（值字典前 N 个常量 + 上面的固定项）。
const REGISTER_CAP: usize = 32;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// caller 侧 HitView impl（seed crate 约定：impl 放调用方）。
struct HitViewOf<'a>(&'a loom_fuzz_cli::Hit);

impl HitView for HitViewOf<'_> {
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

/// Solidity mapping(address => bool) 的槽位（首个状态变量 → slot 0）：
/// keccak256(abi.encode(key, slot))，key 为 32 字节字（address 右对齐）。
fn mapping_slot(key: U256, slot: u64) -> U256 {
    let mut hasher = Keccak256::new();
    hasher.update(key.to_be_bytes::<32>());
    hasher.update(U256::from(slot).to_be_bytes::<32>());
    U256::from_be_bytes(hasher.finalize().into())
}

/// ABI 形态的动态尾（`bytes calldata` 参数内容）：len 字 + 32B 对齐
/// 数据。执行器不感知 ABI（head 原样拼 + tail 原样拼），指针槽与尾
/// 内容的对应关系由输入构造方负责——见 lib.rs 职责边界。
fn abi_tail() -> Vec<u8> {
    let mut tail = U256::from(4u64).to_be_bytes::<32>().to_vec();
    tail.extend_from_slice(b"abcd");
    tail.extend_from_slice(&[0u8; 28]);
    tail
}

/// seed 编译器 M0 不产动态尾（其 assumption 如实记录），测试手工补
/// 一个 ABI 形态种子：指针槽 = 0x20，尾 = abi_tail()；其余槽取 0
/// （registry 成员留空，交给进化环从字典常量搜）。`nonce` 有值时
/// 落在槽 2（guard-boundary 的 `nonce == 0x42` 守卫）。
fn crafted_seed(selector: u32, head_len: usize, nonce: Option<u64>) -> Input {
    let mut head = vec![[0u8; 32]; head_len];
    if head_len >= 2 {
        // bytes 偏移指针槽（最后一个槽）= head 总宽（槽数 × 32）。
        head[head_len - 1][31] = (head_len as u8) * 0x20;
    }
    if let (Some(n), true) = (nonce, head_len >= 3) {
        head[2][31] = n as u8;
    }
    Input {
        selector,
        caller: [0x33; 20],
        value: U256::ZERO,
        head,
        tail: Tail::Bytes(abi_tail()),
    }
}

/// 装载 fixture（模式 B）+ 定位命中函数 + seed 编译。`selector` 指定
/// 用哪条命中（None = 唯一命中）。返回 (HitSet, seeds, func)。
fn load_case(
    dir: &str,
    shard_file: &str,
    code_file: &str,
    selector: Option<u32>,
) -> (loom_fuzz_cli::HitSet, SeedOutput, usize) {
    let dir = fixtures().join(dir);
    let hitset =
        loom_fuzz_cli::load_from_shard(&dir.join(shard_file), &dir.join(code_file)).unwrap();
    assert!(!hitset.hits.is_empty(), "fixture 应有检测命中");
    let hit = match selector {
        Some(sel) => hitset
            .hits
            .iter()
            .find(|h| h.selector == sel)
            .unwrap_or_else(|| panic!("无 selector {sel:#010x} 的命中")),
        None => &hitset.hits[0],
    };
    // shard 泄漏为 'static（测试进程存活期有效），让 Xlayer 与
    // HitSet 可一并返回而不纠缠借用。
    let shard: &'static Shard = Box::leak(Box::new({
        let bytes = std::fs::read(dir.join(shard_file)).unwrap();
        Shard::from_bytes(&bytes).unwrap()
    }));
    let view = Xlayer::new(shard);
    let func = locate(shard, &view, &HitViewOf(hit)).expect("命中应能定位函数");
    let target = Target {
        hit: &HitViewOf(hit),
        func,
    };
    let out = compile(shard, &view, &hitset.code, &target);
    (hitset, out, func)
}

fn exec_config(
    code: Vec<u8>,
    prestate: std::collections::BTreeMap<U256, U256>,
    max_runs: u64,
    baseline: bool,
) -> ExecConfig {
    ExecConfig {
        code,
        address: CONTRACT_ADDRESS,
        prestate,
        seed_rng: 0xC0FF_EE00_0000_0001,
        max_runs,
        time_budget: Duration::from_secs(300),
        gas_per_tx: 1_000_000,
        run_baseline: baseline,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        max_steps: 1,
        dynamic_head_evidence: false,
        guard_context: Vec::new(),
    }
}

/// 种子包成单步序列（steps.len()==1 与旧单步路径语义等价，issue #35）。
fn wrap(seeds: &[Input]) -> Vec<TxSequence> {
    seeds
        .iter()
        .cloned()
        .map(|i| TxSequence::single([0x22; 20], i))
        .collect()
}

/// prestate：registry 注册"值字典前 N 个常量 + 固定 0x7d"为 member
/// （value = 1）。值字典含 registry 常量是设计内的事（shard 无此
/// 事实段，M0 由调用方补）；多成员布置让静态字典知识直接可用于
/// 进化搜索，也把"找到哪个 member"如实留给 fuzzer。
/// 返回 (prestate, 注册地址集)。
fn registry_prestate(
    dict: &ValueDictionary,
) -> (
    std::collections::BTreeMap<U256, U256>,
    std::collections::BTreeSet<[u8; 20]>,
) {
    let mut prestate = std::collections::BTreeMap::new();
    let mut registered = std::collections::BTreeSet::new();
    let mut words: Vec<U256> = dict.words.iter().take(REGISTER_CAP).copied().collect();
    let fixed = U256::from(REGISTERED_SERVICE);
    if !words.contains(&fixed) {
        words.push(fixed);
    }
    for w in words {
        if w.is_zero() {
            continue; // 零地址不当 member（也不拦截"找到非零 member"的进化演示）
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&w.to_be_bytes::<32>()[12..]);
        prestate.insert(mapping_slot(w, 0), U256::from(1));
        registered.insert(addr);
    }
    (prestate, registered)
}

#[test]
fn trv_like_reaches_target_frame() {
    let (hitset, seeds_out, func) = load_case(
        "fixtures/trv-like",
        "trv-like.lst",
        "TrvLikeRouter.bin-runtime",
        Some(0x90ce82d4),
    );
    let hit = hitset
        .hits
        .iter()
        .find(|h| h.selector == 0x90ce82d4)
        .expect("trv-like 应有 forwardRequest 命中");
    assert_eq!(hit.target_pcs, vec![384], "命中帧 pc = CALL 指令");
    assert!(!seeds_out.inputs.is_empty(), "seed 编译应产出种子");

    let target = Target {
        hit: &HitViewOf(hit),
        func,
    };
    let dict = {
        // 字典补固定注册项（0x7d），保证它在搜索空间里。
        let mut words = seeds_out.dict.words.clone();
        let v = U256::from(REGISTERED_SERVICE);
        if !words.contains(&v) {
            words.push(v);
        }
        ValueDictionary { words }
    };
    let (prestate, registered) = registry_prestate(&dict);
    // seeds = 编译产物 + 手工 ABI 形态种子（见 crafted_seed 注释）。
    let head_len = 2; // (address service, bytes request)
    let mut seeds = seeds_out.inputs.clone();
    seeds.push(crafted_seed(hit.selector, head_len, None));

    let cfg = exec_config(hitset.code.clone(), prestate, 4_000, false);
    let report = run_targeted(&cfg, &target, &wrap(&seeds), &dict);

    assert!(report.reached, "应到达目标帧：{report:?}");
    println!(
        "trv-like 验收数据：best_runs = {}, runs_completed = {}, calls = {}, outcome = {:?}",
        report.best_runs,
        report.runs_completed,
        report.trace.calls.len(),
        report.trace.outcome
    );
    // 命中后择优继续（issue #46）：到场不即停——best_runs = 到场那次
    // 的计数，runs_completed = 总会话 runs（≥ best_runs）。
    assert!(report.best_runs <= report.runs_completed);
    let best = &report
        .best_steps
        .as_ref()
        .expect("命中即有 witness 输入")
        .steps[0]
        .input;
    assert_eq!(best.selector, 0x90ce82d4);
    assert!(
        !report.trace.calls.is_empty(),
        "执行期应拦到 CALL（裸转发效果）"
    );
    let call = report
        .trace
        .calls
        .iter()
        .find(|c| c.kind == "CALL")
        .expect("应有 CALL");
    // CALL 目标 = best_input.head[0] 的低 20 字节，且是注册过的 member。
    let mut expect_target = [0u8; 20];
    expect_target.copy_from_slice(&best.head[0][12..]);
    assert_eq!(call.target, expect_target);
    assert!(
        registered.contains(&call.target),
        "CALL 目标应是 registry member"
    );
    // CALL input = 动态尾解码出的 request（len 字 + 数据）。
    if let Tail::Bytes(tail) = &best.tail {
        let len = tail[31] as usize;
        assert_eq!(call.input, tail[32..32 + len]);
    }
    assert!(
        report.trace.visited_pcs.contains(&384),
        "trace 应含目标 pc 384"
    );
    assert!(!report.truncated);
}

#[test]
fn same_seed_is_byte_identical() {
    let (hitset, seeds_out, func) = load_case(
        "fixtures/trv-like",
        "trv-like.lst",
        "TrvLikeRouter.bin-runtime",
        Some(0x90ce82d4),
    );
    let hit = hitset
        .hits
        .iter()
        .find(|h| h.selector == 0x90ce82d4)
        .unwrap();
    let target = Target {
        hit: &HitViewOf(hit),
        func,
    };
    let dict = ValueDictionary {
        words: seeds_out.dict.words.clone(),
    };
    let (prestate, _registered) = registry_prestate(&dict);
    let mut seeds = seeds_out.inputs.clone();
    seeds.push(crafted_seed(hit.selector, 2, None));

    let cfg = exec_config(hitset.code.clone(), prestate, 4_000, false);
    let a = run_targeted(&cfg, &target, &wrap(&seeds), &dict);
    let b = run_targeted(&cfg, &target, &wrap(&seeds), &dict);
    assert!(a.reached && b.reached);
    // 全报告逐字节一致（无时间戳字段，预算由 runs 耗尽，确定性）。
    let sa = serde_json::to_vec(&a).unwrap();
    let sb = serde_json::to_vec(&b).unwrap();
    assert_eq!(sa, sb, "同 seed_rng 两次运行应逐字节一致");
    // 显式点 best_input / trace（poc.json 的复用对象）。
    assert_eq!(
        serde_json::to_vec(&a.best_steps).unwrap(),
        serde_json::to_vec(&b.best_steps).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&a.trace).unwrap(),
        serde_json::to_vec(&b.trace).unwrap()
    );
}

#[test]
fn guided_beats_pure_random_baseline() {
    let (hitset, seeds_out, func) = load_case(
        "fixtures/guard-boundary",
        "guard-boundary.lst",
        "GuardBoundaryRouter.bin-runtime",
        None,
    );
    let hit = &hitset.hits[0];
    // guard-boundary 的命中：forwardRequest 的裸转发 CALL。
    let target = Target {
        hit: &HitViewOf(hit),
        func,
    };
    let dict = ValueDictionary {
        words: seeds_out.dict.words.clone(),
    };
    let (prestate, _registered) = registry_prestate(&dict);
    // (address service, uint256 amount, uint256 nonce, bytes request)：
    // 槽 2 = nonce 0x42（编译种子已覆盖， crafted 种子保持），
    // 槽 3 = bytes 指针 0x20。
    let head_len = 4;
    let mut seeds = seeds_out.inputs.clone();
    seeds.push(crafted_seed(hit.selector, head_len, Some(0x42)));

    let cfg = exec_config(hitset.code.clone(), prestate, 2_000, true);
    let report: SessionReport = run_targeted(&cfg, &target, &wrap(&seeds), &dict);

    assert!(report.reached, "制导会话应到达：{report:?}");
    println!(
        "制导收益数据：guided best_runs = {}, baseline_runs_to_reach = {:?}, runs_completed = {}",
        report.best_runs, report.baseline_runs_to_reach, report.runs_completed
    );
    match report.baseline_runs_to_reach {
        Some(base) => assert!(
            report.best_runs < base,
            "guided {} 应快于纯随机基线 {}",
            report.best_runs,
            base
        ),
        // 同预算内纯随机基线未到达（守卫合取 + ABI 形态对纯随机是
        // 天文数字难度）——制导收益的最强形态，如实记录。
        None => eprintln!("baseline 在 {} runs 内未到达（纯随机）", cfg.max_runs),
    }
}

#[test]
fn unreachable_target_reported_honestly() {
    let (hitset, seeds_out, func) = load_case(
        "fixtures/trv-like",
        "trv-like.lst",
        "TrvLikeRouter.bin-runtime",
        Some(0x90ce82d4),
    );
    // target pc 设在代码外：任何执行都到不了。
    struct Nowhere;
    impl HitView for Nowhere {
        fn selector(&self) -> u32 {
            0x90ce82d4
        }
        fn target_pcs(&self) -> &[u32] {
            &[9_999_999]
        }
        fn evidence(&self) -> &str {
            ""
        }
    }
    let nowhere = Nowhere;
    let target = Target {
        hit: &nowhere,
        func,
    };
    let cfg = exec_config(hitset.code.clone(), Default::default(), 32, false);
    let report = run_targeted(
        &cfg,
        &target,
        &wrap(&seeds_out.inputs),
        &ValueDictionary { words: vec![] },
    );

    assert!(!report.reached);
    assert_eq!(report.runs_completed, 32, "未到达 = 跑满预算");
    assert!(!report.truncated, "gas 充足不应截断");
    // 未到达时如实给最接近的一次 witness（非见证，消费方看 reached）。
    assert!(report.best_steps.is_some());
}
