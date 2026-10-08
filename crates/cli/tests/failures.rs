//! 失败路径测试（模式 A 的 fail-closed 纪律）：不依赖真实 loom 二进制，
//! 用不存在的路径与非零退出的替身脚本覆盖。

use std::io::Write as _;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// 占位 pack：失败路径在 spawn/退出阶段就终止，pack 内容无关紧要。
fn dummy_packs() -> Vec<&'static Path> {
    vec![Path::new("/nonexistent/pack.lq")]
}

fn shard_and_code() -> (PathBuf, PathBuf) {
    (
        fixture("simple/minibank/minibank.lst"),
        fixture("simple/minibank/MiniBank.bin-runtime"),
    )
}

#[test]
fn missing_loom_binary_reports_path() {
    let (shard, code) = shard_and_code();
    let missing = Path::new("/nonexistent/loom-bin").to_path_buf();
    let err = loom_fuzz_cli::load_from_cli(&missing, &dummy_packs(), &shard, &code)
        .expect_err("必须报错");
    let msg = format!("{err}");
    assert!(
        msg.contains("/nonexistent/loom-bin"),
        "错误信息须含二进制路径，实际: {msg}"
    );
}

/// 非零退出的替身 loom：无论参数都往 stderr 打标记并以 42 退出。
fn fake_failing_loom() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("loom-fuzz-cli-fail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("loom");
    let mut f = std::fs::File::create(&script).unwrap();
    writeln!(f, "#!/bin/sh").unwrap();
    writeln!(f, "echo loom-boom-marker >&2").unwrap();
    writeln!(f, "exit 42").unwrap();
    drop(f);
    // 非 Windows 平台需要可执行位。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = script.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    script
}

#[test]
fn nonzero_exit_reports_stderr_summary() {
    let (shard, code) = shard_and_code();
    let fake = fake_failing_loom();
    let err =
        loom_fuzz_cli::load_from_cli(&fake, &dummy_packs(), &shard, &code).expect_err("必须报错");
    match &err {
        loom_fuzz_cli::LoadError::LoomExit { status, stderr } => {
            assert_eq!(status.code(), Some(42), "退出码原样保留，实际: {status}");
            assert!(
                stderr.contains("loom-boom-marker"),
                "stderr 摘要须含 loom 的报错，实际: {stderr}"
            );
        }
        other => panic!("应是 LoomExit，实际: {other:?}"),
    }
}

#[test]
fn empty_packs_rejected_before_spawn() {
    let (shard, code) = shard_and_code();
    // 二进制不存在但 packs 为空：先报 packs 为空（不走到 spawn）。
    let err = loom_fuzz_cli::load_from_cli(Path::new("/nonexistent/loom"), &[], &shard, &code)
        .expect_err("必须报错");
    assert!(
        matches!(err, loom_fuzz_cli::LoadError::LoomJson { .. }),
        "空 packs 应是 LoomJson 错误，实际: {err:?}"
    );
}
