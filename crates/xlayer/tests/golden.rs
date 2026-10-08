//! golden 对拍（issue #8 验收核心）：同一 trv-like shard 上，本 crate
//! 的 DEFS 路由展开与 loom-evm 查询引擎装载时的展开必须产出相同的
//! (函数, 步序, kind) / (函数, 步序, polarity) 集合——loom 侧经
//! `LOOM_BIN` 环境变量定位的二进制跑诊断 pack 取得。
//!
//! `LOOM_BIN` 未设置或二进制不存在时跳过（打印原因），fixture 的
//! 签入 shard 仍被单测与本地的对拍覆盖。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::{XEntry, XNode, Xlayer};

/// loom 侧函数列的渲染（对齐 `loom query --json` 的 Func 列）：
/// 有 selector 渲染 `0x%08x`，fallback/receive 渲染 `f{local}@c0`。
fn render_fn(shard: &Shard, fn_idx: usize) -> String {
    match shard.functions()[fn_idx].selector {
        Some(selector) => format!("0x{selector:08x}"),
        None => format!("f{fn_idx}@c0"),
    }
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

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/trv-like/trv-like.lst")
}

/// 跑一条诊断 pack，返回该谓词的行（字符串列）。
fn loom_query_rows(
    loom: &Path,
    shard: &Path,
    tmp: &Path,
    pack_name: &str,
    decl: &str,
    pred: &str,
    rule: &str,
) -> Vec<Vec<String>> {
    let pack = tmp.join(pack_name);
    std::fs::write(&pack, format!("{decl}\n.query {pred}.\n{rule}\n")).unwrap();
    let output = Command::new(loom)
        .arg("query")
        .arg(&pack)
        .arg(shard)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "loom query 失败: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("loom query --json 输出应是 JSON");
    json["queries"]
        .as_array()
        .expect("queries 字段")
        .iter()
        .find(|q| q["predicate"] == pred)
        .unwrap_or_else(|| panic!("谓词 {pred} 无结果段"))["rows"]
        .as_array()
        .expect("rows 字段")
        .iter()
        .map(|row| {
            row.as_array()
                .expect("行应是数组")
                .iter()
                .map(|cell| cell.as_str().expect("单元格应是字符串").to_string())
                .collect()
        })
        .collect()
}

fn set_diff(a: &BTreeSet<Vec<String>>, b: &BTreeSet<Vec<String>>) -> String {
    a.difference(b)
        .map(|row| row.join(","))
        .collect::<Vec<_>>()
        .join("\n  ")
}

#[test]
fn golden_xeffect_xguard_match_loom_query() {
    let Some(loom) = loom_bin() else {
        eprintln!("golden 对拍跳过：未设置 LOOM_BIN");
        return;
    };
    let shard_path = fixture_path();
    if !shard_path.exists() {
        eprintln!("golden 对拍跳过：fixture 缺失 {shard_path:?}");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("loom-fuzz-xlayer-golden-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let shard = Shard::open(&shard_path).expect("解析 trv-like.lst");
    let view = Xlayer::new(&shard);

    // ---- xeffect：本侧的 (函数, 步序, kind) 集合 ----
    let mut ours_effects: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut ours_guards: BTreeSet<Vec<String>> = BTreeSet::new();
    for fn_idx in 0..shard.functions().len() {
        let rendered = render_fn(&shard, fn_idx);
        let entries = view.expand(fn_idx).expect("每函数都有展开流");
        for entry in entries {
            match entry {
                XEntry::Effect { kind, step, .. } => {
                    ours_effects.insert(vec![rendered.clone(), step.to_string(), kind.clone()])
                }
                XEntry::Guard { polarity, step, .. } => ours_guards.insert(vec![
                    rendered.clone(),
                    step.to_string(),
                    u32::from(*polarity).to_string(),
                ]),
                XEntry::Outcome { .. } => false,
            };
        }
    }

    // ---- loom 侧：诊断 pack 的 xeffect / xguard 行 ----
    let loom_effects: BTreeSet<Vec<String>> = loom_query_rows(
        &loom,
        &shard_path,
        &tmp,
        "diag_effect.lq",
        ".decl q(f:func, i:u32, k:str).",
        "q",
        "q(f,i,k) :- xeffect(f,i,k,_).",
    )
    .into_iter()
    .collect();
    let loom_guards: BTreeSet<Vec<String>> = loom_query_rows(
        &loom,
        &shard_path,
        &tmp,
        "diag_guard.lq",
        ".decl g(f:func, i:u32, p:u32).",
        "g",
        "g(f,i,p) :- xguard(f,i,p,_,_).",
    )
    .into_iter()
    .collect();
    // LOOM_BIN 与 fixture 都在却查无此行 = 契约破裂，必须红。
    assert!(!loom_effects.is_empty(), "loom 侧 xeffect 不应为空");
    assert!(!loom_guards.is_empty(), "loom 侧 xguard 不应为空");

    assert_eq!(
        ours_effects,
        loom_effects,
        "xeffect 集合不一致\n仅本侧:\n  {}\n仅 loom 侧:\n  {}",
        set_diff(&ours_effects, &loom_effects),
        set_diff(&loom_effects, &ours_effects),
    );
    assert_eq!(
        ours_guards,
        loom_guards,
        "xguard 集合不一致\n仅本侧:\n  {}\n仅 loom 侧:\n  {}",
        set_diff(&ours_guards, &loom_guards),
        set_diff(&loom_guards, &ours_guards),
    );
}

/// 定向断言（issue #8 验收的 fixture 版）：forwardRequest
/// （selector 0x90ce82d4）的展开视图里有 kind == "call" 的效果，
/// operands 含 target 与 input，且 input 子树能到达 b_calldata_slice /
/// calldata 节点（裸 calldata 转发——TRV 根因类的数据面证据）。
#[test]
fn forward_request_call_forwards_raw_calldata() {
    let shard_path = fixture_path();
    if !shard_path.exists() {
        eprintln!("fixture 缺失 {shard_path:?}，跳过");
        return;
    }
    let shard = Shard::open(&shard_path).expect("解析 trv-like.lst");
    let view = Xlayer::new(&shard);
    let selector = 0x90ce82d4u32;
    let fn_idx = shard
        .functions()
        .iter()
        .position(|f| f.selector == Some(selector))
        .expect("trv-like shard 有 forwardRequest");
    let entries = view.expand(fn_idx).expect("展开流存在");

    let call = entries.iter().find_map(|entry| match entry {
        XEntry::Effect { kind, operands, .. } if kind == "call" => Some(operands),
        _ => None,
    });
    let Some(operands) = call else {
        panic!("forwardRequest 展开视图里没有 call 效果");
    };
    let has = |name: &str| operands.iter().any(|(operand, _)| operand == name);
    assert!(has("target"), "call operands 缺 target: {operands:?}");
    assert!(has("input"), "call operands 缺 input: {operands:?}");
    let input = operands
        .iter()
        .find(|(operand, _)| operand == "input")
        .map(|(_, id)| *id)
        .unwrap();

    // 沿子引用走子树，收集可达节点的运算名。
    let mut ops = BTreeSet::new();
    let mut stack = vec![input];
    let mut seen = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = view.node(id).expect("子引用必须可解析");
        if let Some(op) = node.op() {
            ops.insert(op.to_string());
        }
        match node {
            XNode::Base(_) | XNode::Overlay(_) => stack.extend(node.child_ids()),
        }
    }
    assert!(
        ops.iter()
            .any(|op| op == "b_calldata_slice" || op == "calldata"),
        "input 子树里应能到达 b_calldata_slice/calldata 节点，实际运算名: {ops:?}"
    );
}
