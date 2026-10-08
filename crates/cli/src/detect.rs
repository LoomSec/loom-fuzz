//! 模式 B 内置 arbitrary_call 检测推导（loom-fuzz 自行实现，不调用
//! loom）。语义照 loom-evm 的 packs 逐条对齐：
//!
//! - 检测臂（`packs/detect/arbitrary_call.lq` 的 `vuln_arbitrary`）：
//!   - 臂 3（裸转发，M0 主臂）：`xeffect(f,i,"call",_)` 的 `call_kind`
//!     operand 非 staticcall、`input` operand 子树含 `b_calldata_slice`
//!     / `calldata` 节点（`gen_raw_forward`），且
//!     `not caller_checked_at(f,i)` → 命中，证据 = `target` operand 渲染。
//!   - 臂 1（目标可控）：`target` operand 子树含 inputmark 节点
//!     （`calldata_word` / `b_calldata_slice` / `calldata`），
//!     `not whitelisted(f,x)` 且 `not caller_checked_at(f,i)` → 命中。
//!   - 臂 2/4（`identity_ref_contract`，需链上 oracle 事实）：无 oracle
//!     时装配为空，M0 不实现（纯文件模式本就没有 oracle 相）。
//! - `caller_checked_at`（`src/query/mod.rs` 内建）：存在步序 `gi < i`
//!   的 xguard，cond 满足 `caller_test`（msg.sender / tx.origin 提及，
//!   含 caller 键控 mapping 存储读两族），且
//!   `scope_cmp(c, sg, si)`（两作用域 prefix-comparable：任一方向
//!   ancestor-or-self）。
//! - `whitelisted`：M0 保守近似（见 lib.rs 文档头）——可信身份比对臂 +
//!   caller 键控 mapping 成员测试臂；`registry_validated` 族未实现。
//!
//! 所有集合语义都是 loom 关系的直接翻译：`subterm` = 自身或 DAG 后代
//! （自反、传递）；`match` 的 `...` = 深子式存在量词；无序比较（==/!=）
//! 双臂方向都认。

use std::collections::HashSet;

use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::{XEntry, Xlayer};

use crate::hitset::GuardFact;
use crate::render::{render_node, View};

/// 一条原始命中：函数下标 + 效果步序 + 证据 operand 的表达式 id
/// （渲染在装载装配期做，两种模式共用同一装配路径）+ 检测族（谓词
/// 维度；同一 call 效果可在多个族各命中一条——loom 行集并列语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHit {
    pub fn_idx: usize,
    pub step: u32,
    pub evidence: u32,
    pub family: loom_fuzz_oracle::HitFamily,
    /// arbitrary_call 族的检测臂；其它族无臂概念（None）。
    pub arm: Option<loom_fuzz_oracle::CallArm>,
}

const SENDER_OPS: [&str; 2] = ["msg.sender", "tx.origin"];
const INPUTMARK_OPS: [&str; 3] = ["calldata_word", "b_calldata_slice", "calldata"];
const RAW_FORWARD_OPS: [&str; 2] = ["b_calldata_slice", "calldata"];
const CMP_OPS: [&str; 2] = ["==", "!="];

/// 自反传递子式闭包（loom `subterm(x, y)`：y 是 x 自身或 DAG 后代）。
fn subtree(view: &impl View, root: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        out.push(id);
        if let Some(node) = view.node(id) {
            stack.extend(node.child_ids());
        }
    }
    out
}

fn op_of(view: &impl View, id: u32) -> Option<String> {
    view.node(id).and_then(|n| n.op().map(str::to_string))
}

fn is_op(view: &impl View, id: u32, ops: &[&str]) -> bool {
    op_of(view, id).is_some_and(|op| ops.contains(&op.as_str()))
}

fn children_of(view: &impl View, id: u32) -> Vec<u32> {
    view.node(id).map(|n| n.child_ids()).unwrap_or_default()
}

/// `__imm(v, 0)` 语义：CalldataWord(0) / Cast(_,0) / Param(0) / 值为 0
/// 的 Const 都匹配。
fn imm_is_zero(view: &impl View, id: u32) -> bool {
    view.node(id).and_then(|n| n.imm()) == Some(0)
}

/// inputmark：攻击者可控 = calldata 派生（loom `inputmark` 三臂）。
fn is_inputmark(view: &impl View, id: u32) -> bool {
    is_op(view, id, &INPUTMARK_OPS)
}

/// `caller_test`：guard 条件提及 caller 身份（loom 内建关系的 4 族）：
/// 1. 深 ==/!= 以 msg.sender / tx.origin 为直接操作数（无序双臂）；
/// 2. 深 `==(a, 0)` / `!=(a, 0)`，a 子树含存储读 `storage(this·, mapping(_,
///    sender))`（caller 键控 mapping 成员测试的编译形）；
/// 3. 深 `storage(this, ...mapping(_, sender))`。
fn caller_test(view: &impl View, cond: u32) -> bool {
    let nodes = subtree(view, cond);
    // 族 1：sender 叶子直接参与顶层无序比较。
    for &x in &nodes {
        if is_op(view, x, &CMP_OPS) {
            for child in children_of(view, x) {
                if is_op(view, child, &SENDER_OPS) {
                    return true;
                }
            }
        }
    }
    // 族 2：布尔成员测试（mapping[sender] ==/!= 0）。
    for &x in &nodes {
        if is_op(view, x, &CMP_OPS) {
            let children = children_of(view, x);
            if children.len() == 2 {
                for (a, zero) in [(children[0], children[1]), (children[1], children[0])] {
                    if imm_is_zero(view, zero) && has_mapping_sender_key(view, a) {
                        return true;
                    }
                }
            }
        }
    }
    // 族 3：storage(this, ...mapping(_, sender))。
    for &x in &nodes {
        if op_of(view, x).as_deref() == Some("storage") {
            let children = children_of(view, x);
            if children.len() == 2 && op_of(view, children[0]).as_deref() == Some("this") {
                for m in subtree(view, children[1]) {
                    if op_of(view, m).as_deref() == Some("mapping") {
                        let mc = children_of(view, m);
                        if mc.len() == 2 && is_op(view, mc[1], &SENDER_OPS) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// a 的子树里是否存在存储读 st（`storage` 规范形，2 元），其槽键是
/// 以 caller 为键的 mapping。
fn has_mapping_sender_key(view: &impl View, a: u32) -> bool {
    subtree(view, a).iter().any(|&st| {
        if op_of(view, st).as_deref() != Some("storage") {
            return false;
        }
        let sc = children_of(view, st);
        if sc.len() != 2 {
            return false;
        }
        let m = sc[1];
        op_of(view, m).as_deref() == Some("mapping") && {
            let mc = children_of(view, m);
            mc.len() == 2 && is_op(view, mc[1], &SENDER_OPS)
        }
    })
}

/// scope parent（shard 作用域表 + xlayer rebase mint 的新作用域；
/// id 0 是根，无 parent）。
fn scope_parent(shard: &Shard, view: &Xlayer<'_>, id: u32) -> Option<u32> {
    if id == 0 {
        return None;
    }
    let base = shard.scopes().len() as u32;
    if id <= base {
        Some(shard.scopes()[(id - 1) as usize].parent)
    } else {
        view.scopes_new()
            .get((id - base - 1) as usize)
            .map(|(parent, _, _)| *parent)
    }
}

/// `scope_cmp`：a、b 在作用域树里 prefix-comparable（任一方向
/// ancestor-or-self；loom 的 `is_ancestor_or_self` 照抄）。
fn scope_cmp(shard: &Shard, view: &Xlayer<'_>, a: u32, b: u32) -> bool {
    fn ancestor_or_self(shard: &Shard, view: &Xlayer<'_>, anc: u32, mut id: u32) -> bool {
        loop {
            if id == anc {
                return true;
            }
            if id == 0 {
                return anc == 0;
            }
            match scope_parent(shard, view, id) {
                Some(parent) => id = parent,
                None => return false,
            }
        }
    }
    ancestor_or_self(shard, view, a, b) || ancestor_or_self(shard, view, b, a)
}

/// `caller_checked_at(f, i)`：存在步序 gi < i 的 guard，cond 是
/// caller_test 且作用域覆盖命中作用域。
fn caller_checked_at(
    shard: &Shard,
    view: &Xlayer<'_>,
    entries: &[XEntry],
    i: u32,
    si: u32,
) -> bool {
    entries.iter().any(|entry| match entry {
        XEntry::Guard {
            cond,
            scope: sg,
            step: gi,
            ..
        } => *gi < i && scope_cmp(shard, view, *sg, si) && caller_test(view, *cond),
        _ => false,
    })
}

/// `trusted`（whitelist 臂 1 的引用侧）：caller 身份叶或含存储读子式。
fn trusted(view: &impl View, b: u32) -> bool {
    if is_op(view, b, &SENDER_OPS) {
        return true;
    }
    subtree(view, b)
        .iter()
        .any(|&s| op_of(view, s).as_deref() == Some("storage"))
}

/// `whitelisted` 的 M0 保守近似（lib.rs 文档头列出的折衷）：
/// - 臂 1：guard 深 ==(a, b)，x 在 a 子树里，b 是可信身份；
/// - 臂 2/3：`this`-mapping 布尔成员测试（==(mapping[x·], 0)）与
///   caller 键形（mapping 以 caller 为键、x 即 caller 叶）。
fn whitelisted(view: &impl View, guard_conds: &[u32], x: u32) -> bool {
    for &g in guard_conds {
        let nodes = subtree(view, g);
        // 可信身份比对臂。
        for &n in &nodes {
            if op_of(view, n).as_deref() == Some("==") {
                let nc = children_of(view, n);
                if nc.len() == 2 {
                    for (a, b) in [(nc[0], nc[1]), (nc[1], nc[0])] {
                        if subtree(view, a).contains(&x) && trusted(view, b) {
                            return true;
                        }
                    }
                }
            }
        }
        // caller 键控 mapping 成员测试臂。
        for &n in &nodes {
            if is_op(view, n, &CMP_OPS) {
                let nc = children_of(view, n);
                if nc.len() == 2 {
                    for (a, zero) in [(nc[0], nc[1]), (nc[1], nc[0])] {
                        if !imm_is_zero(view, zero) {
                            continue;
                        }
                        for st in subtree(view, a) {
                            if op_of(view, st).as_deref() != Some("storage") {
                                continue;
                            }
                            let sc = children_of(view, st);
                            if sc.len() != 2 || op_of(view, sc[0]).as_deref() != Some("this") {
                                continue;
                            }
                            let m = sc[1];
                            if op_of(view, m).as_deref() != Some("mapping") {
                                continue;
                            }
                            let mc = children_of(view, m);
                            if mc.len() != 2 {
                                continue;
                            }
                            if is_inputmark(view, x) && subtree(view, mc[0]).contains(&x) {
                                return true;
                            }
                            if mc[1] == x && is_op(view, x, &SENDER_OPS) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// 命中效果（步序 i、作用域 si）的支配 guard 集合：步序 gi < i 且
/// 作用域 prefix-comparable 的守卫，按步序升序（两种装载模式共用此
/// 定义，seed 编译的输入）。
pub fn dominating_guards(
    shard: &Shard,
    view: &Xlayer<'_>,
    entries: &[XEntry],
    i: u32,
    si: u32,
) -> Vec<GuardFact> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            XEntry::Guard {
                cond,
                polarity,
                scope: sg,
                pc,
                step: gi,
            } if *gi < i && scope_cmp(shard, view, *sg, si) => Some(GuardFact {
                cond: render_node(view, *cond),
                polarity: *polarity,
                pc: *pc,
            }),
            _ => None,
        })
        .collect()
}

/// 模式 A 回填：由 `(fn_idx, step)` 在展开流里定位 call 效果，按族
/// 给出证据表达式 id（+ arbitrary_call 的检测臂）——形状判定与
/// `detect_*` 同源（loom query 已定罪，此处不重复
/// caller_checked/whitelisted 检查）。deputy_call 的证据 = target
/// operand（同臂 1）；drain_forward 的证据 = input operand（L1 报告
/// 对象；oracle 判定走宽松 memmem，不求值）。定位不到 = 两模式步序
/// 语义分歧，fail-closed 报 `None`。
pub fn classify_hit(
    view: &Xlayer<'_>,
    fn_idx: usize,
    step: u32,
    family: loom_fuzz_oracle::HitFamily,
) -> Option<(u32, Option<loom_fuzz_oracle::CallArm>)> {
    let entries = view.expand(fn_idx)?;
    let entry = entries.iter().find(|e| match e {
        XEntry::Effect { kind, step: i, .. } => kind == "call" && *i == step,
        _ => false,
    })?;
    let XEntry::Effect { operands, .. } = entry else {
        return None;
    };
    let operand = |name: &str| operands.iter().find(|(n, _)| n == name).map(|(_, id)| *id);
    match family {
        loom_fuzz_oracle::HitFamily::ArbitraryCall => {
            let target = operand("target")?;
            // 臂 3 优先：非静态 call 且 input 子树含原始 calldata 切片。
            if let (Some(call_kind), Some(input)) = (operand("call_kind"), operand("input")) {
                if op_of(view, call_kind).as_deref() != Some("staticcall")
                    && subtree(view, input)
                        .iter()
                        .any(|&n| is_op(view, n, &RAW_FORWARD_OPS))
                {
                    return Some((target, Some(loom_fuzz_oracle::CallArm::Arm3)));
                }
            }
            Some((target, Some(loom_fuzz_oracle::CallArm::Arm1)))
        }
        loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy => Some((operand("target")?, None)),
        loom_fuzz_oracle::HitFamily::ApprovalDrainForward => Some((operand("input")?, None)),
    }
}

/// 内置 arbitrary_call 检测：扫描全部函数的 xlayer 展开流，产出
/// `(函数, 步序, 证据 operand)` 原始命中集（每函数每步序至多一条，
/// 臂 1 / 臂 3 并集去重——与 loom 关系语义的去重一致）。
pub fn detect_arbitrary_call(shard: &Shard, view: &Xlayer<'_>) -> Vec<RawHit> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    for fn_idx in 0..shard.functions().len() {
        let Some(entries) = view.expand(fn_idx) else {
            continue;
        };
        let guard_conds: Vec<u32> = entries
            .iter()
            .filter_map(|e| match e {
                XEntry::Guard { cond, .. } => Some(*cond),
                _ => None,
            })
            .collect();
        for entry in entries {
            let XEntry::Effect {
                kind,
                operands,
                step: i,
                scope: si,
                ..
            } = entry
            else {
                continue;
            };
            if kind != "call" {
                continue;
            }
            let operand = |name: &str| operands.iter().find(|(n, _)| n == name).map(|(_, id)| *id);
            let Some(target) = operand("target") else {
                continue; // calls_x 要求 target operand 存在
            };
            let checked = caller_checked_at(shard, view, entries, *i, *si);
            let mut hit = None;
            // 臂 3（裸转发）：非静态 call + input 含原始 calldata 切片。
            if let (Some(call_kind), Some(input)) = (operand("call_kind"), operand("input")) {
                if op_of(view, call_kind).as_deref() != Some("staticcall")
                    && subtree(view, input)
                        .iter()
                        .any(|&n| is_op(view, n, &RAW_FORWARD_OPS))
                {
                    hit = Some(loom_fuzz_oracle::CallArm::Arm3);
                }
            }
            // 臂 1（目标可控）：target 子树含 inputmark、未被白名单、
            // 无 caller 检查。loom 语义：∃ inputmark x 使 not
            // whitelisted(f, x)——某个子式被白名单不抑制其它子式的命中。
            if hit.is_none() {
                let arm1 = subtree(view, target)
                    .iter()
                    .filter(|&&n| is_inputmark(view, n))
                    .any(|&n| !whitelisted(view, &guard_conds, n));
                if arm1 {
                    hit = Some(loom_fuzz_oracle::CallArm::Arm1);
                }
            }
            if let Some(arm) = hit.filter(|_| !checked && seen.insert((fn_idx, *i))) {
                hits.push(RawHit {
                    fn_idx,
                    step: *i,
                    evidence: target,
                    family: loom_fuzz_oracle::HitFamily::ArbitraryCall,
                    arm: Some(arm),
                });
            }
        }
    }
    hits
}

/// 单 call 效果的 approval_drain 判定（Shard 无关的纯形状部分——
/// caller 守卫判定由调用方经 `caller_checked_at` 注入；单测直接钉
/// 语义）。返回各族的证据 operand id 列表（deputy → target；
/// drain → input），同一效果可多族命中。
fn approval_drain_shape(
    view: &impl View,
    guard_conds: &[u32],
    checked: bool,
    target: Option<u32>,
    input: Option<u32>,
) -> Vec<(u32, loom_fuzz_oracle::HitFamily)> {
    let mut out = Vec::new();
    // deputy_call：有 caller 守卫 ∧ 目标可控（inputmark 未被
    // 白名单）。loom 语义 ∃x：not whitelisted 不抑制其它子式。
    if checked {
        if let Some(target) = target {
            let controlled = subtree(view, target)
                .iter()
                .filter(|&&n| is_inputmark(view, n))
                .any(|&n| !whitelisted(view, guard_conds, n));
            if controlled {
                out.push((target, loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy));
            }
        }
    }
    // drain_forward：input 含输入派生词且整体不提及
    // msg.sender / tx.origin（自助形状排除臂）。
    if let Some(input) = input {
        let input_nodes = subtree(view, input);
        let has_inputmark = input_nodes.iter().any(|&n| is_inputmark(view, n));
        let mentions_sender = input_nodes.iter().any(|&n| is_op(view, n, &SENDER_OPS));
        if has_inputmark && !mentions_sender {
            out.push((input, loom_fuzz_oracle::HitFamily::ApprovalDrainForward));
        }
    }
    out
}

/// 内置 approval_drain 检测（issue #20，语义照
/// `packs/detect/approval_drain.lq` + `packs/generic/guards/caller.lq`
/// 逐条对齐）：
///
/// - **deputy_call** = `calls_x(f,i,t)` ∧ `subterm(t,x)` ∧ `inputmark(x)`
///   ∧ `not whitelisted(f,x)` ∧ **`caller_checked_at(f,i)`**——有 caller
///   守卫但目标仍可控 = confused deputy（与 arbitrary_call 臂 1 互补：
///   臂 1 要求无 caller 守卫）。
/// - **drain_forward** = `calls_x(f,i,_)` ∧ `xeffect_arg(f,i,"input",b)`
///   ∧ `subterm(b,x)` ∧ `inputmark(x)` ∧ **`not input_mentions_sender(b)`**
///   ——input 含输入派生词且整体不与 caller 绑定（自助形状排除臂）。
///   `input_mentions_sender` = `match(b, ... "msg.sender"|"tx.origin")`
///   深子式存在。
///
/// 两族间、与 arbitrary_call 间行集并列（同一 call 效果可多族命中，
/// 每族每 (fn,step) 至多一条——loom 各谓词独立查询的去重语义）。
pub fn detect_approval_drain(shard: &Shard, view: &Xlayer<'_>) -> Vec<RawHit> {
    let mut hits = Vec::new();
    for fn_idx in 0..shard.functions().len() {
        let Some(entries) = view.expand(fn_idx) else {
            continue;
        };
        let guard_conds: Vec<u32> = entries
            .iter()
            .filter_map(|e| match e {
                XEntry::Guard { cond, .. } => Some(*cond),
                _ => None,
            })
            .collect();
        for entry in entries {
            let XEntry::Effect {
                kind,
                operands,
                step: i,
                scope: si,
                ..
            } = entry
            else {
                continue;
            };
            if kind != "call" {
                continue;
            }
            let operand = |name: &str| operands.iter().find(|(n, _)| n == name).map(|(_, id)| *id);
            let checked = caller_checked_at(shard, view, entries, *i, *si);
            for (evidence, family) in approval_drain_shape(
                view,
                &guard_conds,
                checked,
                operand("target"),
                operand("input"),
            ) {
                hits.push(RawHit {
                    fn_idx,
                    step: *i,
                    evidence,
                    family,
                    arm: None,
                });
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// 单测：手工视图上钉 detection 语义的关键分支
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RNode;

    struct MapView(Vec<RNode>);

    impl View for MapView {
        fn node(&self, id: u32) -> Option<RNode> {
            self.0.get(id as usize).cloned()
        }
    }

    fn word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    #[test]
    fn caller_test_detects_sender_equality() {
        // 0: msg.sender；1: storage(this, 5)；2: ==(0, 1)——cond 即节点 2。
        let view = MapView(vec![
            RNode::Named("msg.sender".into(), vec![]),
            RNode::Named("storage".into(), vec![4, 5]),
            RNode::Named("==".into(), vec![0, 1]),
            RNode::Named("this".into(), vec![]),
            RNode::Named("this".into(), vec![]),
            RNode::Named("entry.world".into(), vec![]),
        ]);
        assert!(caller_test(&view, 2));
    }

    #[test]
    fn caller_test_detects_keyed_mapping_membership() {
        // require(whitelist[msg.sender]) 编译形：
        //   !=(storage(this, mapping(base, msg.sender)), 0)
        let view = MapView(vec![
            RNode::Named("this".into(), vec![]),        // 0
            RNode::Named("entry.world".into(), vec![]), // 1
            RNode::Named("msg.sender".into(), vec![]),  // 2
            RNode::Named("mapping".into(), vec![1, 2]), // 3
            RNode::Named("storage".into(), vec![0, 3]), // 4
            RNode::Const(word(0)),                      // 5
            RNode::Named("!=".into(), vec![4, 5]),      // 6 (cond)
        ]);
        assert!(caller_test(&view, 6));
    }

    #[test]
    fn caller_test_rejects_unrelated_guard() {
        // >(calldata_word(0x4), 0x100)：与 caller 无关。
        let view = MapView(vec![
            RNode::CalldataWord(0x4),
            RNode::Const(word(0x100)),
            RNode::Named(">".into(), vec![0, 1]),
        ]);
        assert!(!caller_test(&view, 2));
    }

    #[test]
    fn inputmark_and_raw_forward_leaves() {
        let view = MapView(vec![
            RNode::CalldataWord(0x4),                        // inputmark 但非裸转发叶
            RNode::Named("b_calldata_slice".into(), vec![]), // 两者皆是
        ]);
        assert!(is_inputmark(&view, 0));
        assert!(!is_op(&view, 0, &RAW_FORWARD_OPS));
        assert!(is_op(&view, 1, &RAW_FORWARD_OPS));
    }

    // approval_drain_shape 语义边界（issue #20）：
    // 视图：0 msg.sender；1 this；2 ==(msg.sender, this)（caller_test
    // 守卫 cond）；3 calldata_word(0x24)；4 cast160(3)（可控 target）；
    // 5 ==(4, 0)（白名单守卫：可控词比对可信身份）；6 Const；
    // 7 concat(3, 6)（input：含输入派生词）；8 concat(3, 0)（input：
    // 含输入派生词但提及 sender）。
    fn shape_view() -> MapView {
        MapView(vec![
            RNode::Named("msg.sender".into(), vec![]), // 0
            RNode::Named("this".into(), vec![]),       // 1
            RNode::Named("==".into(), vec![0, 1]),     // 2（caller 守卫）
            RNode::CalldataWord(0x24),                 // 3
            RNode::Named("cast160".into(), vec![3]),   // 4
            RNode::Named("==".into(), vec![4, 0]),     // 5（白名单守卫）
            RNode::Const(word(0x40)),                  // 6
            RNode::Named("concat".into(), vec![3, 6]), // 7
            RNode::Named("concat".into(), vec![3, 0]), // 8
        ])
    }

    #[test]
    fn deputy_hits_with_caller_guard_and_controlled_target() {
        let view = shape_view();
        // caller 守卫在场（checked=true）+ target 可控未白名单 → deputy。
        let hits = approval_drain_shape(&view, &[2], true, Some(4), None);
        assert_eq!(
            hits,
            vec![(4, loom_fuzz_oracle::HitFamily::ApprovalDrainDeputy)]
        );
    }

    #[test]
    fn deputy_absent_without_caller_guard_or_when_whitelisted() {
        let view = shape_view();
        // 无 caller 守卫（checked=false）：不是 deputy（那是
        // arbitrary_call 臂 1 的地盘——两臂互补）。
        assert!(approval_drain_shape(&view, &[2], false, Some(4), None).is_empty());
        // target 被白名单守卫覆盖（==(cast160(word), msg.sender)）→ 排除。
        assert!(approval_drain_shape(&view, &[2, 5], true, Some(4), None).is_empty());
        // target 无 inputmark（纯常量目标）→ 不可控，不命中。
        let const_view = MapView(vec![RNode::Const(word(0))]);
        assert!(approval_drain_shape(&const_view, &[], true, Some(0), None).is_empty());
    }

    #[test]
    fn drain_hits_only_when_inputmark_and_no_sender_binding() {
        let view = shape_view();
        // input 含输入派生词且不提及 sender → drain_forward。
        let hits = approval_drain_shape(&view, &[], false, None, Some(7));
        assert_eq!(
            hits,
            vec![(7, loom_fuzz_oracle::HitFamily::ApprovalDrainForward)]
        );
    }

    #[test]
    fn drain_excludes_sender_bound_and_pure_const_input() {
        let view = shape_view();
        // input 子树提及 msg.sender（自助形状，与 caller 绑定）→ 排除臂。
        assert!(approval_drain_shape(&view, &[], false, None, Some(8)).is_empty());
        // input 无输入派生词（纯常量）→ 不含可控内容，不命中。
        let const_view = MapView(vec![RNode::Const(word(0))]);
        assert!(approval_drain_shape(&const_view, &[], false, None, Some(0)).is_empty());
    }
}
