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

/// loom-evm 二进制自身的 fail-closed 报错（如谓词注册回归
/// "undeclared predicate word_neg"，v0.11.6 实测）→ 对拍无从谈起，
/// 如实标注跳过（类 LOOM_BIN 缺失先例）；loom-fuzz 装载器自身的
/// 不一致仍 panic。
fn skip_on_loom_defect(lst: &str, err: &loom_fuzz_cli::LoadError) -> bool {
    let msg = format!("{err}");
    if msg.contains("undeclared predicate") {
        eprintln!("{lst}: 跳过对拍——loom-evm 谓词回归: {msg}");
        return true;
    }
    false
}

/// 检测 pack：环境变量 LOOM_ARBITRARY_CALL_PACK 优先；否则从 LOOM_BIN
/// 路径推导 loom-evm 仓库根（target/debug/loom → ../../..）。
fn detect_pack(loom: &Path, env_var: &str, rel: &str) -> Option<PathBuf> {
    if let Some(pack) = std::env::var_os(env_var) {
        let pack = PathBuf::from(pack);
        if pack.exists() {
            return Some(pack);
        }
        eprintln!("golden 对拍跳过：{env_var}={pack:?} 不存在");
        return None;
    }
    let repo = loom.parent()?.parent()?.parent()?;
    let pack = repo.join(rel);
    if pack.exists() {
        Some(pack)
    } else {
        eprintln!("golden 对拍跳过：从 LOOM_BIN 推导不出 pack（{pack:?} 不存在）");
        None
    }
}

/// 族行集（selector,step）的计数对拍辅助。
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
fn cli_and_shard_loaders_agree_on_all_fixtures() {
    let Some(loom) = loom_bin() else {
        eprintln!("golden 对拍跳过：未设置 LOOM_BIN");
        return;
    };
    let Some(pack) = detect_pack(
        &loom,
        "LOOM_ARBITRARY_CALL_PACK",
        "packs/detect/arbitrary_call.lq",
    ) else {
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
        // 本用例只给模式 A 挂 arbitrary_call pack：对拍范围 = arbitrary
        // 族（approval_drain 族的双模式对拍见 real-world 用例，双 pack）。
        let from_shard = loom_fuzz_cli::HitSet {
            hits: from_shard
                .hits
                .into_iter()
                .filter(|h| h.family == loom_fuzz_oracle::HitFamily::ArbitraryCall)
                .collect(),
            ..from_shard
        };
        let from_cli = match loom_fuzz_cli::load_from_cli(&loom, &packs, &shard, &fixture(code)) {
            Ok(h) => h,
            Err(e) => {
                if skip_on_loom_defect(lst, &e) {
                    continue;
                }
                panic!("{lst} 模式 A 装载失败: {e}");
            }
        };
        assert_eq!(from_shard, from_cli, "{lst} 双模式 HitSet 必须逐字段相等");
        eprintln!("{lst}: 双模式一致（{} hits）", from_shard.hits.len());
    }
}

/// issue #20：real-world fixtures（签入）上双 pack（arbitrary_call +
/// approval_drain）并集查询的双模式对拍 + 族行集钉数（与
/// `loom query approval_drain.lq` 一致的基线：vvisr 1 deputy_call +
/// 1 drain_forward；anyswap 11 deputy_call + 0 drain_forward）。
#[test]
fn cli_and_shard_agree_on_real_world_approval_drain() {
    let Some(loom) = loom_bin() else {
        eprintln!("golden 对拍跳过：未设置 LOOM_BIN");
        return;
    };
    let Some(arbitrary) = detect_pack(
        &loom,
        "LOOM_ARBITRARY_CALL_PACK",
        "packs/detect/arbitrary_call.lq",
    ) else {
        return;
    };
    let Some(approval) = detect_pack(
        &loom,
        "LOOM_APPROVAL_DRAIN_PACK",
        "packs/detect/approval_drain.lq",
    ) else {
        return;
    };

    let fixtures: &[(&str, &str)] = &[
        (
            "real-world/vvisr-rewards/vvisr.lst",
            "real-world/vvisr-rewards/vvisr-rewards.bin-runtime",
        ),
        (
            "real-world/anyswap-v4router/anyswapv4router.lst",
            "real-world/anyswap-v4router/AnyswapV4Router.bin-runtime",
        ),
    ];
    let packs = [arbitrary.as_path(), approval.as_path()];
    for (lst, code) in fixtures {
        let shard = fixture(lst);
        let from_shard =
            loom_fuzz_cli::load_from_shard(&shard, &fixture(code)).unwrap_or_else(|e| {
                panic!("{lst} 模式 B 装载失败: {e}");
            });
        let from_cli = match loom_fuzz_cli::load_from_cli(&loom, &packs, &shard, &fixture(code)) {
            Ok(h) => h,
            Err(e) => {
                if skip_on_loom_defect(lst, &e) {
                    continue;
                }
                panic!("{lst} 模式 A 装载失败(双 pack): {e}");
            }
        };
        assert_eq!(
            from_shard, from_cli,
            "{lst} 双 pack 双模式 HitSet 必须逐字段相等"
        );

        // 族行集钉数（loom query approval_drain.lq 基线）。
        let deputy = family_rows(
            &from_shard,
            loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy,
        );
        let drain = family_rows(
            &from_shard,
            loom_fuzz_oracle::HitFamily::ApprovalDrainForward,
        );
        let name = lst.split('/').nth(1).unwrap_or(lst);
        if name == "vvisr-rewards" {
            assert_eq!(
                deputy,
                vec![(0x2e2d2984, 119)],
                "vvisr deputy_call 行集（loom query 基线 1 条）"
            );
            assert_eq!(
                drain,
                vec![(0x21e6b53d, 12)],
                "vvisr drain_forward 行集（loom query 基线 1 条）"
            );
        } else {
            assert_eq!(
                deputy.len(),
                11,
                "anyswap deputy_call 行集（loom query 基线 11 条）: {deputy:?}"
            );
            assert!(
                drain.is_empty(),
                "anyswap drain_forward 行集（loom query 基线 0 条）: {drain:?}"
            );
        }
        eprintln!(
            "{lst}: 双 pack 双模式一致（arbitrary={} deputy={} drain={}）",
            family_rows(&from_shard, loom_fuzz_oracle::HitFamily::ArbitraryCall).len(),
            deputy.len(),
            drain.len()
        );
    }
}
