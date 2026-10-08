//! 双模式 golden 对拍：每个 fixture 上 `load_from_cli`（loom 二进制在
//! 位）与 `load_from_shard`（纯文件）的 HitSet 必须逐字段相等
//! （code、hits 全部字段，含 dominating_guards）。
//!
//! `LOOM_BIN` 未设置或二进制不存在时跳过（打印原因）；fixture 的
//! 签入 shard 仍被模式 B 单测覆盖。本机 LOOM_BIN 指向 loom-evm 构建
//! 产物时必须实跑通过。

use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn loom_bin() -> Option<PathBuf> {
    let path = std::env::var_os("LOOM_BIN").map(PathBuf::from)?;
    if path.exists() {
        Some(path)
    } else {
        eprintln!("golden 对拍跳过：LOOM_BIN={path:?} 不存在");
        None
    }
}

/// 检测 pack：环境变量 LOOM_ARBITRARY_CALL_PACK 优先；否则从 LOOM_BIN
/// 路径推导 loom-evm 仓库根（target/debug/loom → ../../..）。
fn arbitrary_call_pack(loom: &Path) -> Option<PathBuf> {
    if let Some(pack) = std::env::var_os("LOOM_ARBITRARY_CALL_PACK") {
        let pack = PathBuf::from(pack);
        if pack.exists() {
            return Some(pack);
        }
        eprintln!("golden 对拍跳过：LOOM_ARBITRARY_CALL_PACK={pack:?} 不存在");
        return None;
    }
    let repo = loom.parent()?.parent()?.parent()?;
    let pack = repo.join("packs/detect/arbitrary_call.lq");
    if pack.exists() {
        Some(pack)
    } else {
        eprintln!("golden 对拍跳过：从 LOOM_BIN 推导不出 pack（{pack:?} 不存在）");
        None
    }
}

#[test]
fn cli_and_shard_loaders_agree_on_all_fixtures() {
    let Some(loom) = loom_bin() else {
        eprintln!("golden 对拍跳过：未设置 LOOM_BIN");
        return;
    };
    let Some(pack) = arbitrary_call_pack(&loom) else {
        return;
    };

    let fixtures: &[(&str, &str)] = &[
        (
            "trv-like/trv-like.lst",
            "trv-like/TrvLikeRouter.bin-runtime",
        ),
        (
            "simple/minibank/minibank.lst",
            "simple/minibank/MiniBank.bin-runtime",
        ),
        (
            "simple/public-router/public-router.lst",
            "simple/public-router/PublicRouter.bin-runtime",
        ),
        (
            "simple/deputy-vault/deputy-vault.lst",
            "simple/deputy-vault/DeputyVault.bin-runtime",
        ),
    ];
    let packs = [pack.as_path()];
    for (lst, code) in fixtures {
        let shard = fixture(lst);
        let from_shard =
            loom_fuzz_cli::load_from_shard(&shard, &fixture(code)).unwrap_or_else(|e| {
                panic!("{lst} 模式 B 装载失败: {e}");
            });
        let from_cli = loom_fuzz_cli::load_from_cli(&loom, &packs, &shard, &fixture(code))
            .unwrap_or_else(|e| panic!("{lst} 模式 A 装载失败: {e}"));
        assert_eq!(from_shard, from_cli, "{lst} 双模式 HitSet 必须逐字段相等");
        eprintln!("{lst}: 双模式一致（{} hits）", from_shard.hits.len());
    }
}
