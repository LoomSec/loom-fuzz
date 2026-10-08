//! 模式 B（纯文件装载）的钉死期望测试：不依赖 loom 二进制。
//!
//! - trv-like：arbitrary_call 恰好 1 条命中（selector 0x90ce82d4，
//!   evidence 与 loom `vuln_arbitrary` 行一致，target_pcs = 展开后
//!   call 的原点 pc），支配 guard 非空且含 serviceRegistry 检查那条
//!   require；approval_drain 族新增 1 条 drain_forward（同效果步序）。
//! - 三个 simple fixture（噪声 / 常量 call 边 / caller 受检 deputy）：
//!   无 arbitrary_call 命中；deputy-vault 是 deputy_call 的阳性样本
//!   （有 caller 守卫 + 目标可控——#20 前该形状被 caller_checked
//!   排除在 arbitrary 族外）。

use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

#[test]
fn trv_like_exactly_one_arbitrary_hit() {
    let hitset = loom_fuzz_cli::load_from_shard(
        &fixture("trv-like/trv-like.lst"),
        &fixture("trv-like/TrvLikeRouter.bin-runtime"),
    )
    .expect("trv-like 装载");

    // arbitrary 族：恰好 1 条（#20 前的既有断言不变）。
    let arbitrary: Vec<_> = hitset
        .hits
        .iter()
        .filter(|h| h.family == loom_fuzz_oracle::HitFamily::ArbitraryCall)
        .collect();
    assert_eq!(
        arbitrary.len(),
        1,
        "恰好 1 条 arbitrary 命中: {:?}",
        hitset.hits
    );
    let hit = arbitrary[0];
    assert_eq!(hit.selector, 0x90ce82d4, "forwardRequest 的 selector");
    assert_eq!(hit.evidence, "cast160(calldata_word(0x4))");
    assert!(!hit.target_pcs.is_empty(), "target_pcs 非空");

    // 支配 guard 非空，且含 serviceRegistry 检查那条 require
    // （`require(serviceRegistry[service], "unknown service")`，
    // caller 未受检——它是目标侧验证，不是 caller 检查）。
    assert!(!hit.dominating_guards.is_empty(), "dominating_guards 非空");
    let registry_guard = hit
        .dominating_guards
        .iter()
        .find(|g| {
            g.cond
                .contains("storage(this, mapping(0x0, cast160(calldata_word(0x4))))")
        })
        .expect("支配 guard 里必须有 serviceRegistry require 的存储读判别");
    assert!(registry_guard.polarity, "require 走真支");

    // approval_drain 族（#20）：同效果步序还有 1 条 drain_forward
    // （input 含输入派生切片、不提及 sender）。
    let drain = hitset
        .hits
        .iter()
        .filter(|h| h.family == loom_fuzz_oracle::HitFamily::ApprovalDrainForward)
        .count();
    assert_eq!(
        drain, 1,
        "trv-like 应有 1 条 drain_forward: {:?}",
        hitset.hits
    );
}

#[test]
fn simple_fixtures_have_no_arbitrary_hits() {
    let cases = [
        (
            "simple/minibank/minibank.lst",
            "simple/minibank/MiniBank.bin-runtime",
            0, // 总命中（arbitrary + approval_drain 全族）
        ),
        (
            "simple/public-router/public-router.lst",
            "simple/public-router/PublicRouter.bin-runtime",
            0,
        ),
        // deputy-vault：caller 守卫在场 + 目标可控 = deputy_call 阳性
        // （arbitrary 族仍必须为空——两臂互补）。
        (
            "simple/deputy-vault/deputy-vault.lst",
            "simple/deputy-vault/DeputyVault.bin-runtime",
            1,
        ),
    ];
    for (lst, code, total) in cases {
        let hitset =
            loom_fuzz_cli::load_from_shard(&fixture(lst), &fixture(code)).unwrap_or_else(|e| {
                panic!("{lst} 装载失败: {e}");
            });
        let arbitrary = hitset
            .hits
            .iter()
            .filter(|h| h.family == loom_fuzz_oracle::HitFamily::ArbitraryCall)
            .count();
        assert_eq!(arbitrary, 0, "{lst} 应无 arbitrary_call 命中");
        assert_eq!(
            hitset.hits.len(),
            total,
            "{lst} 全族命中数（approval_drain 并集语义）"
        );
        assert!(!hitset.code.is_empty(), "{lst} 字节码非空");
    }
}

#[test]
fn missing_shard_is_typed_error() {
    let err = loom_fuzz_cli::load_from_shard(
        &fixture("simple/minibank/nope.lst"),
        &fixture("simple/minibank/MiniBank.bin-runtime"),
    )
    .expect_err("不存在的 shard 必须报错");
    let msg = err.to_string();
    assert!(msg.contains("nope.lst"), "错误信息须指明路径，实际: {msg}");
}
