//! 用真实 shard 文件做的集成测试。
//!
//! 输入是 loom-evm 写出的现成分片（不在仓库内，路径固定于 /tmp）：
//! - TRV 案例合约（60692 字节）：selector 0xe27fbed3 = forwardRequest，
//!   有一个 vuln_arbitrary 命中；
//! - Aave V3 fork 池（1.25MB，37 个函数）：大文件 + zlib DEFS 段覆盖。

use loom_fuzz_shard::{Entry, ExprNode, Shard};
use std::path::Path;

const TRV_ROUTER: &str = "/tmp/trv_router.lst";
const AAVE_POOL: &str =
    "/tmp/3e5e08d8844ae2cd651ebb2a7fb9b17957e955a905701a2e5df0debbfff407a5.lst";

/// fixture 是 loom-evm 写出的真实分片（真实合约分析产物，不进仓库）。
/// 缺失时优雅跳过——外部贡献者没有这两个 /tmp 文件，不应看到红测试。
fn open_fixture(path: &str) -> Option<Shard> {
    if !Path::new(path).exists() {
        eprintln!(
            "skip: 缺少 loom-evm 写出的测试分片 {path}（真实合约分析产物，不进仓库；\
             用 `loom store <bytecode> -o {path}` 在本机生成）"
        );
        return None;
    }
    Some(Shard::open(path).expect("fixture shard opens"))
}

#[test]
fn trv_function_table_contains_forward_request() {
    let Some(shard) = open_fixture(TRV_ROUTER) else {
        return;
    };
    let forward = shard
        .function_by_selector(0xe27fbed3)
        .expect("0xe27fbed3 (forwardRequest) 必须在函数表里");
    assert_eq!(forward.kind, "function");
    // 函数表整体自洽：manifest 计数与实际一致（解析期已校验），
    // 至少能列出全部 selector。
    let selectors: Vec<u32> = shard
        .functions()
        .iter()
        .filter_map(|f| f.selector)
        .collect();
    assert!(selectors.contains(&0xe27fbed3));
}

#[test]
fn trv_forward_request_reaches_effects() {
    let Some(shard) = open_fixture(TRV_ROUTER) else {
        return;
    };
    let forward = shard.function_by_selector(0xe27fbed3).unwrap();
    // 函数自身的事实流：input_read（selector 分发与 calldata 解码）。
    let own: Vec<_> = forward
        .effects()
        .filter_map(|e| match e {
            Entry::Effect { kind, pc, step, .. } => Some((kind.clone(), *pc, *step)),
            _ => None,
        })
        .collect();
    assert!(
        own.iter().any(|(kind, pc, _)| kind == "input_read" && *pc > 0),
        "forwardRequest 自身的 effect（input_read）必须有非空 pc: {own:?}"
    );

    // 函数体经 Apply 边进共享定义层（trampoline）；调用类 effect 在
    // DEFS 段里（x-layer 展开才是完整路由，那是 M1+；M0 读器暴露
    // 定义层原始效果，vuln_arbitrary 的 call 点就在其中）。
    let call_sites: Vec<(u32, u32)> = shard
        .definitions()
        .iter()
        .flat_map(|d| {
            d.entries.iter().filter_map(|e| match e {
                Entry::Effect { kind, pc, step, .. } if kind == "call" => Some((d.pc, *pc)),
                _ => None,
            })
        })
        .collect();
    assert!(
        !call_sites.is_empty() && call_sites.iter().all(|(_, pc)| *pc > 0),
        "DEFS 层必须有 pc 非空的 call effect（vuln_arbitrary 命中点族）: {call_sites:?}"
    );
}

#[test]
fn trv_guards_present() {
    let Some(shard) = open_fixture(TRV_ROUTER) else {
        return;
    };
    let guard_count: usize = shard
        .functions()
        .iter()
        .map(|f| f.guards().count())
        .sum();
    assert!(guard_count > 0, "shard 必须有 guard 条目");
}

#[test]
fn trv_expr_tree_traversable_with_calldata_slice() {
    let Some(shard) = open_fixture(TRV_ROUTER) else {
        return;
    };
    assert!(shard.manifest.nodes as usize == shard.exprs().len());

    // 找到 b_calldata_slice 形态节点并校验其子引用可解析（表达式树
    // 可遍历）。该节点在本分片是 Binary 形态（op + 两个子节点）。
    let slice_id = shard
        .exprs()
        .iter()
        .position(|n| n.op() == Some("b_calldata_slice"))
        .expect("表达式字典里必须有 b_calldata_slice 节点") as u32;
    let child_ok = match shard.expr(slice_id).unwrap() {
        ExprNode::Unary(_, a) => shard.expr(*a).is_some(),
        ExprNode::Binary(_, a, b) | ExprNode::Cmp(_, a, b) => {
            shard.expr(*a).is_some() && shard.expr(*b).is_some()
        }
        ExprNode::Ternary(_, a, b, c) => {
            shard.expr(*a).is_some() && shard.expr(*b).is_some() && shard.expr(*c).is_some()
        }
        ExprNode::Nary(_, args) => args.iter().all(|id| shard.expr(*id).is_some()),
        _ => false,
    };
    assert!(child_ok, "b_calldata_slice 的子节点必须都在字典内");

    // 字典规模与结构哈希尾一一对应。
    assert_eq!(shard.hashes.len(), shard.exprs().len());
}

#[test]
fn aave_pool_parses_with_37_functions() {
    // 大文件 + DEFS zlib 段：解析不 panic、计数精确。
    let Some(shard) = open_fixture(AAVE_POOL) else {
        return;
    };
    assert_eq!(shard.functions().len(), 37);
    assert_eq!(shard.manifest.functions as usize, 37);
    assert!(shard.manifest.nodes as usize == shard.exprs().len());
}

#[test]
fn corrupt_inputs_are_errors_not_panics() {
    use loom_fuzz_shard::Error;

    // 坏魔数。
    let bad_magic = Shard::from_bytes(b"XYZ rest of a fake shard");
    assert!(matches!(bad_magic, Err(Error::BadMagic)));

    // 截断的目录。
    let truncated = Shard::from_bytes(b"LST\x02\x00\x00\x00\x01");
    assert!(matches!(
        truncated,
        Err(Error::CountOutOfRange) | Err(Error::SegmentOutOfRange)
    ));

    // 声称巨量段数的目录头（防巨分配）。
    let mut forged = Vec::new();
    forged.extend_from_slice(b"LST");
    forged.extend_from_slice(&u32::MAX.to_le_bytes());
    let forged = Shard::from_bytes(&forged);
    assert!(matches!(forged, Err(Error::CountOutOfRange)));
}

#[test]
fn trv_step_numbering_counts_effects_in_order() {
    // x-layer 步序：Guard/Effect/Outcome 连续编号，Apply/Exit 不占号。
    let Some(shard) = open_fixture(TRV_ROUTER) else {
        return;
    };
    let forward = shard.function_by_selector(0xe27fbed3).unwrap();
    let steps: Vec<u32> = forward.entries.iter().filter_map(|e| e.step()).collect();
    assert!(!steps.is_empty());
    assert!(
        steps.iter().enumerate().all(|(i, s)| *s == i as u32),
        "步序必须从 0 连续递增: {steps:?}"
    );
    // Apply/Exit 条目（若有）不携带步序。
    for entry in &forward.entries {
        if matches!(entry, Entry::Apply { .. } | Entry::Exit { .. }) {
            assert_eq!(entry.step(), None);
        }
    }
}
