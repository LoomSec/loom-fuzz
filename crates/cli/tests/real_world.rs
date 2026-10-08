//! real-world fixtures 的模式 B 装载行集钉数（issue #20，纯文件、
//! 无需 LOOM_BIN——模式 A 对拍见 golden.rs）。族行集与
//! `loom query approval_drain.lq` 基线一致：
//! - vvisr：deputy_call 1（0x2e2d2984 step 119）+ drain_forward 1
//!   （0x21e6b53d step 12）+ arbitrary_call 1（0x2e2d2984 step 107）；
//! - anyswap：deputy_call 11 + drain_forward 0 + arbitrary_call 20。

use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn family_rows(hs: &loom_fuzz_cli::HitSet, family: loom_fuzz_oracle::HitFamily) -> Vec<(u32, u32)> {
    let mut rows: Vec<(u32, u32)> = hs
        .hits
        .iter()
        .filter(|h| h.family == family)
        .map(|h| (h.selector, h.step))
        .collect();
    rows.sort();
    rows
}

#[test]
fn vvisr_approval_drain_rowset() {
    let hs = loom_fuzz_cli::load_from_shard(
        &fixture("real-world/vvisr-rewards/vvisr.lst"),
        &fixture("real-world/vvisr-rewards/vvisr-rewards.bin-runtime"),
    )
    .unwrap();
    assert_eq!(
        family_rows(&hs, loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy),
        vec![(0x2e2d2984, 119)]
    );
    assert_eq!(
        family_rows(&hs, loom_fuzz_oracle::HitFamily::ApprovalDrainForward),
        vec![(0x21e6b53d, 12)]
    );
    assert_eq!(
        family_rows(&hs, loom_fuzz_oracle::HitFamily::ArbitraryCall),
        vec![(0x2e2d2984, 107)]
    );
}

#[test]
fn anyswap_approval_drain_rowset() {
    let hs = loom_fuzz_cli::load_from_shard(
        &fixture("real-world/anyswap-v4router/anyswapv4router.lst"),
        &fixture("real-world/anyswap-v4router/AnyswapV4Router.bin-runtime"),
    )
    .unwrap();
    let deputy = family_rows(&hs, loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy);
    assert_eq!(deputy.len(), 11, "deputy_call 基线 11 条: {deputy:?}");
    assert_eq!(
        family_rows(&hs, loom_fuzz_oracle::HitFamily::ApprovalDrainForward),
        Vec::new(),
        "drain_forward 基线 0 条"
    );
    assert_eq!(
        family_rows(&hs, loom_fuzz_oracle::HitFamily::ArbitraryCall).len(),
        20,
        "arbitrary_call 20 条"
    );
}
