//! 管线级验收测试（issue #7）：loom-fuzz 二进制 run / replay。
//!
//! 1. TRV confirmed：trv-like + prestate + dict-word → confirmed，
//!    poc.json 字段齐全；
//! 2. 重放一致：replay 同一 poc.json → exit 0、verdict 与 poc 记录
//!    一致（serde 级相等）；
//! 3. unreachable 不硬判：--max-runs 1 → Unreachable，poc 不落；
//! 4. inconclusive：--gas-per-tx 截断 → Inconclusive 如实；
//! 5. 噪声：minibank 无命中 → fuzz_report 照落、无 poc、exit 0。

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_loom-fuzz")
}

fn out_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("loom-fuzz-pipe-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn trv_args(dir: &Path) -> Vec<String> {
    let fx = fixtures();
    vec![
        "run".into(),
        "--shard".into(),
        fx.join("fixtures/trv-like/trv-like.lst")
            .to_string_lossy()
            .into(),
        "--code".into(),
        fx.join("fixtures/trv-like/TrvLikeRouter.bin-runtime")
            .to_string_lossy()
            .into(),
        "--prestate".into(),
        fx.join("fixtures/trv-like/prestate.json")
            .to_string_lossy()
            .into(),
        "--dict-word".into(),
        "0x7d".into(),
        "--out".into(),
        dir.to_string_lossy().into(),
    ]
}

fn run_cli(args: &[String]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("spawn loom-fuzz")
}

#[test]
fn trv_like_confirmed_with_poc() {
    let dir = out_dir("confirmed");
    let output = run_cli(&trv_args(&dir));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("fuzz_report.json")).expect("fuzz_report.json 落盘"),
    )
    .unwrap();
    assert_eq!(report["format"], "loom-fuzz-report@1");
    assert_eq!(report["hits"][0]["verdict"], "confirmed");
    assert_eq!(report["hits"][0]["selector"], "0x90ce82d4");
    assert_eq!(report["hits"][0]["pc"], 384);
    assert!(report["hits"][0]["best_runs"].as_u64().unwrap() > 0);
    assert!(report["coverage"]["total_pcs"].as_u64().unwrap() > 0);
    assert!(report["coverage"]["percent"].as_f64().unwrap() > 0.0);
    assert!(report["assumptions"].as_array().is_some());

    // poc.json：字段齐全（calldata/prestate/replay 非空）。
    let pocs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("poc-")
        })
        .collect();
    assert_eq!(pocs.len(), 1, "confirmed 恰好一个 poc");
    let poc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pocs[0].as_ref().unwrap().path()).unwrap()).unwrap();
    assert_eq!(poc["format"], "loom-fuzz-poc@1");
    assert_eq!(poc["verdict"], "confirmed");
    assert_eq!(poc["selector"], "0x90ce82d4");
    assert_eq!(poc["pc"], 384);
    assert_eq!(poc["step"], 19);
    assert!(poc["digest"].as_str().unwrap().starts_with("0x"));
    // issue #35：poc 序列化形态 = steps（单步 = 单元素序列）。
    assert_eq!(poc["steps"].as_array().unwrap().len(), 1);
    assert!(poc["steps"][0]["calldata"]
        .as_str()
        .unwrap()
        .starts_with("0x90ce82d4"));
    assert!(poc["steps"][0]["caller"]
        .as_str()
        .unwrap()
        .starts_with("0x"));
    assert!(poc["steps"][0]["target"]
        .as_str()
        .unwrap()
        .starts_with("0x"));
    assert!(poc.get("tx").is_none(), "新 poc 不写出 legacy tx");
    assert!(poc["prestate"].as_object().unwrap().len() == 1);
    assert!(poc["replay"].as_str().unwrap().contains("loom-fuzz replay"));
    assert!(poc["replay"]
        .as_str()
        .unwrap()
        .contains("--code <bytecode.hex>"));
    println!(
        "confirmed: best_runs={} coverage={}%",
        report["hits"][0]["best_runs"], report["coverage"]["percent"]
    );
}

#[test]
fn replay_reproduces_verdict() {
    let dir = out_dir("replay");
    let output = run_cli(&trv_args(&dir));
    assert!(output.status.success());
    let poc_path = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("poc-"))
        .expect("poc 落盘");
    let poc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&poc_path).unwrap()).unwrap();

    let fx = fixtures();
    let out = Command::new(bin())
        .arg("replay")
        .arg(&poc_path)
        .arg("--code")
        .arg(fx.join("fixtures/trv-like/TrvLikeRouter.bin-runtime"))
        .output()
        .expect("spawn replay");
    assert!(out.status.success(), "重放应 exit 0（verdict 一致）");
    let stdout: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("replay 打印 verdict JSON");
    // verdict 逐字节一致（serde 级相等）。
    assert_eq!(stdout["verdict"], poc["verdict"]);
    assert_eq!(stdout["verdict"], "confirmed");
}

#[test]
fn unreachable_is_not_forced() {
    let dir = out_dir("unreachable");
    let mut args = trv_args(&dir);
    args.push("--max-runs".into());
    args.push("1".into());
    let output = run_cli(&args);
    assert!(output.status.success(), "判决如实落盘仍 exit 0");

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("fuzz_report.json")).unwrap()).unwrap();
    assert_eq!(report["hits"][0]["verdict"], "unreachable");
    assert!(report["hits"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("预算耗尽"));
    // poc 不落（只落 fuzz_report）。
    let has_poc = std::fs::read_dir(&dir)
        .unwrap()
        .any(|e| e.unwrap().file_name().to_string_lossy().starts_with("poc-"));
    assert!(!has_poc, "unreachable 不落 poc.json");
}

#[test]
fn truncated_session_is_inconclusive() {
    let dir = out_dir("inconclusive");
    let mut args = trv_args(&dir);
    args.push("--gas-per-tx".into());
    args.push("25000".into());
    let output = run_cli(&args);
    assert!(output.status.success());

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("fuzz_report.json")).unwrap()).unwrap();
    assert_eq!(report["hits"][0]["verdict"], "inconclusive");
    assert!(report["hits"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("截断"));
}

#[test]
fn noise_fixture_reports_empty() {
    let dir = out_dir("noise");
    let fx = fixtures();
    let output = run_cli(&[
        "run".into(),
        "--shard".into(),
        fx.join("fixtures/simple/minibank/minibank.lst")
            .to_string_lossy()
            .into(),
        "--code".into(),
        fx.join("fixtures/simple/minibank/MiniBank.bin-runtime")
            .to_string_lossy()
            .into(),
        "--out".into(),
        dir.to_string_lossy().into(),
    ]);
    assert!(output.status.success(), "无命中也 exit 0（如实空报告）");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("fuzz_report.json")).unwrap()).unwrap();
    assert_eq!(report["hits"].as_array().unwrap().len(), 0);
    let has_poc = std::fs::read_dir(&dir)
        .unwrap()
        .any(|e| e.unwrap().file_name().to_string_lossy().starts_with("poc-"));
    assert!(!has_poc);
}

#[test]
fn fail_closed_on_missing_inputs() {
    // 缺 --code：clap 报错非零退出。
    let out = Command::new(bin())
        .args(["run", "--shard", "x.lst"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    // 模式 A 不成对：fail-closed 指明缺什么。
    let out = Command::new(bin())
        .args([
            "run", "--shard", "x.lst", "--code", "y.hex", "--pack", "p.lq",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--loom-bin"), "指明缺什么: {stderr}");
}

#[test]
fn entry_not_in_contract_table_fails_closed() {
    // issue #34：--entry 须在合约表内（victim 或 --deploy 地址），
    // 否则 fail-closed 退出 2 并指明缺什么（不硬猜目标）。
    let dir = out_dir("entry-fail");
    let fx = fixtures();
    let out = Command::new(bin())
        .args([
            "run",
            "--shard",
            &fx.join("fixtures/simple/minibank/minibank.lst")
                .to_string_lossy(),
            "--code",
            &fx.join("fixtures/simple/minibank/MiniBank.bin-runtime")
                .to_string_lossy(),
            "--entry",
            "0x9999999999999999999999999999999999999999",
            "--out",
            &dir.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("不在合约表"),
        "fail-closed 指明原因: {stderr}"
    );
}

#[test]
fn multi_deploy_with_forwarder_accepted() {
    // issue #34：多 --deploy（含机械 forwarder 代理规格）装载归一：
    // Genesis 态照跑（minibank 无命中 → 空报告 exit 0）。
    let dir = out_dir("multi-deploy");
    let fx = fixtures();
    let out = Command::new(bin())
        .args([
            "run",
            "--shard",
            &fx.join("fixtures/simple/minibank/minibank.lst")
                .to_string_lossy(),
            "--code",
            &fx.join("fixtures/simple/minibank/MiniBank.bin-runtime")
                .to_string_lossy(),
            "--deploy",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:forwarder",
            "--deploy",
            "0xcccccccccccccccccccccccccccccccccccccccc:responder-sender",
            "--out",
            &dir.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
