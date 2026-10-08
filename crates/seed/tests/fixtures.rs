//! 验收测试（issue #4）：trv-like 实解、guard-boundary golden、
//! minibank 退化路径、确定性。fixture 装载走 cli 的 `load_from_shard`
//! （模式 B，纯文件），与闭环管线同一入口。

use std::path::{Path, PathBuf};

use alloy_primitives::U256;
use loom_fuzz_cli::{load_from_shard, Hit, HitSet};
use loom_fuzz_oracle::HitFamily;
use loom_fuzz_seed::{compile, locate, HitView, Input, SeedOutput, Tail, Target};
use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::Xlayer;

/// `crates/cli` 的 `Hit` 的 HitView 包装（孤儿规则：trait 在 seed、
/// 类型在 cli，调用方侧 newtype 实现）。
struct W<'a>(&'a Hit);

impl HitView for W<'_> {
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

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures")
        .join(name)
}

/// 装载 fixture：shard + HitSet（模式 B 装载器）。
fn load(name: &str, lst: &str, bin: &str) -> (Shard, HitSet) {
    let dir = fixture_dir(name);
    let hitset = load_from_shard(&dir.join(lst), &dir.join(bin)).unwrap();
    let shard = Shard::open(dir.join(lst)).unwrap();
    (shard, hitset)
}

fn compile_hit<'a>(
    shard: &'a Shard,
    view: &Xlayer<'a>,
    hitset: &'a HitSet,
    hit: &'a Hit,
) -> SeedOutput {
    let func = locate(shard, view, &W(hit)).expect("定位命中函数");
    compile(shard, view, &hitset.code, &Target { hit: &W(hit), func })
}

fn head_word(input: &Input, slot: usize) -> Option<U256> {
    input.head.get(slot).map(|w| U256::from_be_bytes(*w))
}

/// 验收 1（trv-like）：非空种子集、selector 头、registry 成员测试
/// 不可解记录、值字典非空。
#[test]
fn trv_like_compiles_to_selector_seeds() {
    let (shard, hitset) = load("trv-like", "trv-like.lst", "TrvLikeRouter.bin-runtime");
    let view = Xlayer::new(&shard);
    // #20 多族：arbitrary 族仍恰好 1 条（approval_drain 族行并列存在）。
    let arbitrary = hitset
        .hits
        .iter()
        .filter(|h| h.family == HitFamily::ArbitraryCall)
        .count();
    assert_eq!(arbitrary, 1, "trv-like 应有 1 条裸转发命中");
    let out = compile_hit(&shard, &view, &hitset, &hitset.hits[0]);

    assert!(!out.inputs.is_empty(), "种子集非空");
    assert!(
        out.inputs.iter().all(|i| i.selector == 0x90ce82d4),
        "全部种子带 0x90ce82d4 selector 头"
    );
    assert!(
        out.assumptions
            .iter()
            .any(|a| a.contains("registry 成员测试")),
        "assumptions 含 registry 成员测试不可解记录：{:?}",
        out.assumptions
    );
    assert!(!out.dict.words.is_empty(), "值字典非空");
}

/// 验收 2（guard-boundary golden）：nonce==0x42 槽固定的种子存在；
/// 值字典含 amount<1000 的 c±1（999/1000/1001）；registry guard 记录。
#[test]
fn guard_boundary_golden() {
    let (shard, hitset) = load(
        "guard-boundary",
        "guard-boundary.lst",
        "GuardBoundaryRouter.bin-runtime",
    );
    let view = Xlayer::new(&shard);
    let arbitrary = hitset
        .hits
        .iter()
        .filter(|h| h.family == HitFamily::ArbitraryCall)
        .count();
    assert_eq!(arbitrary, 1, "guard-boundary 应有 1 条裸转发命中");
    let hit = &hitset.hits[0];
    let out = compile_hit(&shard, &view, &hitset, hit);
    assert_eq!(
        hit.selector, 0xb5d8edc6,
        "forwardRequest(address,uint256,uint256,bytes) selector"
    );

    // nonce（calldata 0x44 → 槽 2）== 0x42 的种子存在。
    assert!(
        out.inputs
            .iter()
            .any(|i| head_word(i, 2) == Some(U256::from(0x42u64))),
        "inputs 中应有 nonce 槽 == 0x42 的种子：{:?}",
        out.inputs
    );
    // amount（calldata 0x24 → 槽 1）的 c±1 边界变体。
    for v in [999u64, 1000, 1001] {
        assert!(out.dict.words.contains(&U256::from(v)), "值字典应含 {v}");
        assert!(
            out.inputs
                .iter()
                .any(|i| head_word(i, 1) == Some(U256::from(v))),
            "inputs 应含 amount 槽 == {v} 的变体"
        );
    }
    // registry 成员测试（services[service]）不可解记录。
    assert!(
        out.assumptions
            .iter()
            .any(|a| a.contains("registry 成员测试")),
        "assumptions 含 registry guard 记录：{:?}",
        out.assumptions
    );
}

/// 验收 3（退化路径）：构造 target_pcs 为空的假命中（minibank 无
/// arbitrary_call 命中——装载器产出空命中集，故走合成 Target），
/// 种子退化为 selector + 全零 head + Empty tail，assumptions 如实记录。
#[test]
fn degenerates_to_bare_selector_when_nothing_solvable() {
    let (shard, hitset) = load("simple/minibank", "minibank.lst", "MiniBank.bin-runtime");
    let view = Xlayer::new(&shard);
    assert!(
        hitset.hits.is_empty(),
        "minibank 无 arbitrary_call 命中（退化路径用合成 Target，如实注明）"
    );
    let selector = shard
        .functions()
        .iter()
        .find_map(|f| f.selector)
        .expect("minibank 至少有一个带 selector 的函数");

    struct Fake {
        selector: u32,
    }
    impl HitView for Fake {
        fn selector(&self) -> u32 {
            self.selector
        }
        fn target_pcs(&self) -> &[u32] {
            &[]
        }
        fn evidence(&self) -> &str {
            ""
        }
    }

    let fake = Fake { selector };
    let func = locate(&shard, &view, &fake).expect("按 selector 定位函数");
    let out = compile(&shard, &view, &hitset.code, &Target { hit: &fake, func });

    assert_eq!(
        out.inputs,
        vec![Input {
            selector,
            caller: [0u8; 20],
            value: U256::ZERO,
            head: Vec::new(),
            tail: Tail::Empty,
        }],
        "退化为 selector + 全零 head + Empty tail（不编造）"
    );
    assert!(
        out.assumptions.iter().any(|a| a.contains("无 guard 可解")),
        "assumptions 如实记录无可解 guard：{:?}",
        out.assumptions
    );
}

/// 验收 4（确定性）：同输入两次 compile，输出逐字段一致。
#[test]
fn compile_is_deterministic() {
    let (shard, hitset) = load(
        "guard-boundary",
        "guard-boundary.lst",
        "GuardBoundaryRouter.bin-runtime",
    );
    let view = Xlayer::new(&shard);
    let hit = &hitset.hits[0];
    let first = compile_hit(&shard, &view, &hitset, hit);
    let second = compile_hit(&shard, &view, &hitset, hit);
    assert_eq!(first, second, "同输入两次 compile 输出必须逐字段一致");
}
