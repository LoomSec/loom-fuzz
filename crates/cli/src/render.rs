//! 证据表达式渲染器：把 xlayer 表达式节点（含代入 mint 的 overlay 节点）
//! 递归渲染成 loom 同款 S 表达式文本（`loom query --json` Expr 列的
//! [`render_node`](https://github.com/LoomSec/loom-evm) 移植子集，
//! 语义逐条对齐：同形节点必渲染同形文本）。
//!
//! 渲染前先做 loom 查询引擎装载期的规范化（`src/query/mod.rs` 的
//! canonical storage spelling）：3 元 `load.storage` / 带 world 孩子的
//! `storage` 节点统一成 2 元 `storage(owner, key)`（world 子项结构性
//! 识别后丢弃）——检测谓词（`caller_test` 的 mapping 臂等）与渲染共用
//! 同一规范化视图，与 loom 的 expr_op/expr_child 关系同形。

use loom_fuzz_xlayer::{XNode, Xlayer};

/// 规范化节点视图（owned）。`storage` 规范化已在此层完成：
/// `Named("storage", [owner, key])` 是唯一存储拼写。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RNode {
    /// 具名节点：op 名 + 孩子 id（Leaf/Env 孩子为空；Unary/Binary/Cmp/
    /// Ternary/Nary 按操作数序）。
    Named(String, Vec<u32>),
    /// 256 位常量（右对齐 32 字节）。
    Const([u8; 32]),
    /// 原始字节串（calldata 片段等）。
    ConstBytes(Vec<u8>),
    /// calldata 第 `off` 字。
    CalldataWord(u64),
    /// 位宽截断（`cast{bits}(a)`）。
    Cast(u32, u64),
    /// 形参槽位（`param.{slot}`）。
    Param(u32),
}

impl RNode {
    /// 该节点的运算名（语义同 loom 查询引擎的 `expr_op` 关系发射：
    /// Leaf/Env 返回名字，Const → "const"，ConstBytes → "const_bytes"，
    /// CalldataWord → "calldata_word"，Cast → "cast"，Param → "param"）。
    pub fn op(&self) -> Option<&str> {
        match self {
            RNode::Named(name, _) => Some(name),
            RNode::Const(_) => Some("const"),
            RNode::ConstBytes(_) => Some("const_bytes"),
            RNode::CalldataWord(_) => Some("calldata_word"),
            RNode::Cast(_, _) => Some("cast"),
            RNode::Param(_) => Some("param"),
        }
    }

    /// 孩子 id（按操作数序；与 loom 的 `expr_child` 关系同形）。
    pub fn child_ids(&self) -> Vec<u32> {
        match self {
            RNode::Named(_, children) => children.clone(),
            RNode::Cast(a, _) => vec![*a],
            RNode::Const(_) | RNode::ConstBytes(_) | RNode::CalldataWord(_) | RNode::Param(_) => {
                Vec::new()
            }
        }
    }

    /// 该节点携带的立即数（语义同 loom 匹配原语 `__imm`：CalldataWord
    /// 的字偏移 / Cast 的位宽 / Param 的槽位 / Const 的 u64 值）。
    pub fn imm(&self) -> Option<u64> {
        match self {
            RNode::CalldataWord(off) => Some(*off),
            RNode::Cast(_, bits) => Some(*bits),
            RNode::Param(slot) => Some(u64::from(*slot)),
            RNode::Const(word) => word_as_u64(word),
            RNode::Named(_, _) | RNode::ConstBytes(_) => None,
        }
    }
}

/// 规范化节点视图的只读接口：渲染与检测都建立在它之上（单测可用手工
/// 表直接实现本 trait，不依赖真实 shard）。
pub trait View {
    fn node(&self, id: u32) -> Option<RNode>;
}

impl View for Xlayer<'_> {
    /// 经 canonical storage spelling 规范化的节点。
    fn node(&self, id: u32) -> Option<RNode> {
        canon(self, id)
    }
}

fn word_as_u64(word: &[u8; 32]) -> Option<u64> {
    if word[..24].iter().all(|b| *b == 0) {
        Some(u64::from_be_bytes(
            word[24..].try_into().expect("32 - 24 = 8"),
        ))
    } else {
        None
    }
}

/// world 子项的结构性识别（loom `is_world_leaf` 照抄）：Leaf 名以
/// "world." 开头或恰为 "entry.world"。
fn is_world_leaf(view: &Xlayer<'_>, id: u32) -> bool {
    matches!(
        view.node(id),
        Some(XNode::Base(loom_fuzz_shard::ExprNode::Leaf(name)))
            if name.starts_with("world.") || name == "entry.world"
    ) || matches!(
        view.node(id),
        Some(XNode::Overlay(loom_fuzz_xlayer::NodeKey::Leaf(name)))
            if name.starts_with("world.") || name == "entry.world"
    )
}

/// 取 xlayer 节点并做 canonical storage 规范化（loom 查询引擎装载期
/// 的同一变换：3 元 `load.storage` / 带 world 孩子的 3 元 `storage`
/// （Nary 或 Ternary 形态）统一为 2 元 `storage(owner, key)`）。
pub fn canon(view: &Xlayer<'_>, id: u32) -> Option<RNode> {
    use loom_fuzz_shard::ExprNode as B;
    use loom_fuzz_xlayer::NodeKey as O;
    let node = view.node(id)?;
    Some(match node {
        XNode::Base(B::Nary(op, args)) if op == "load.storage" && args.len() == 3 => {
            RNode::Named("storage".to_string(), vec![args[1], args[2]])
        }
        XNode::Base(B::Nary(op, args)) if op == "storage" && args.len() == 3 => {
            if is_world_leaf(view, args[1]) {
                RNode::Named("storage".to_string(), vec![args[0], args[2]])
            } else {
                RNode::Named("storage".to_string(), vec![args[0], args[1]])
            }
        }
        XNode::Base(B::Ternary(op, a, b, c)) if op == "storage" => {
            if is_world_leaf(view, *b) {
                RNode::Named("storage".to_string(), vec![*a, *c])
            } else {
                RNode::Named("storage".to_string(), vec![*a, *b])
            }
        }
        XNode::Overlay(O::Nary(op, args)) if op == "load.storage" && args.len() == 3 => {
            RNode::Named("storage".to_string(), vec![args[1], args[2]])
        }
        XNode::Overlay(O::Nary(op, args)) if op == "storage" && args.len() == 3 => {
            if is_world_leaf(view, args[1]) {
                RNode::Named("storage".to_string(), vec![args[0], args[2]])
            } else {
                RNode::Named("storage".to_string(), vec![args[0], args[1]])
            }
        }
        XNode::Overlay(O::Ternary(op, a, b, c)) if op == "storage" => {
            if is_world_leaf(view, *b) {
                RNode::Named("storage".to_string(), vec![*a, *c])
            } else {
                RNode::Named("storage".to_string(), vec![*a, *b])
            }
        }
        XNode::Base(base) => match base {
            B::Leaf(s) | B::Env(s) => RNode::Named(s.clone(), Vec::new()),
            B::Const(w) => RNode::Const(*w),
            B::ConstBytes(b) => RNode::ConstBytes(b.clone()),
            B::CalldataWord(off) => RNode::CalldataWord(*off),
            B::Unary(op, a) => RNode::Named(op.clone(), vec![*a]),
            B::Binary(op, a, b) | B::Cmp(op, a, b) => RNode::Named(op.clone(), vec![*a, *b]),
            B::Ternary(op, a, b, c) => RNode::Named(op.clone(), vec![*a, *b, *c]),
            B::Nary(op, args) => RNode::Named(op.clone(), args.clone()),
            B::Cast(a, bits) => RNode::Cast(*a, *bits),
            B::Param(slot) => RNode::Param(*slot),
        },
        XNode::Overlay(key) => match key {
            O::Leaf(s) | O::Env(s) => RNode::Named(s.clone(), Vec::new()),
            O::Const(w) => RNode::Const(*w),
            O::ConstBytes(b) => RNode::ConstBytes(b.clone()),
            O::CalldataWord(off) => RNode::CalldataWord(*off),
            O::Unary(op, a) => RNode::Named(op.clone(), vec![*a]),
            O::Binary(op, a, b) | O::Cmp(op, a, b) => RNode::Named(op.clone(), vec![*a, *b]),
            O::Ternary(op, a, b, c) => RNode::Named(op.clone(), vec![*a, *b, *c]),
            O::Nary(op, args) => RNode::Named(op.clone(), args.clone()),
            O::Cast(a, bits) => RNode::Cast(*a, *bits),
            O::Param(slot) => RNode::Param(*slot),
        },
    })
}

const MAX_DEPTH: u32 = 32;

/// 递归渲染（loom `render_node` 移植）：深度超过 32 层渲染 "…"
/// （loom 同款防线；DAG 共享子树按展开路径各自渲染）。
pub fn render_node(view: &impl View, id: u32) -> String {
    render_at(view, id, 0)
}

fn render_at(view: &impl View, id: u32, depth: u32) -> String {
    if depth > MAX_DEPTH {
        return "…".to_string();
    }
    let Some(node) = view.node(id) else {
        return format!("<expr {id}?>");
    };
    let rec = |child: u32| render_at(view, child, depth + 1);
    match node {
        RNode::Named(name, children) if children.is_empty() => name,
        RNode::Named(name, children) => format!(
            "{name}({})",
            children
                .iter()
                .map(|c| rec(*c))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        RNode::Const(word) => {
            if let Some(v) = word_as_u64(&word) {
                format!("0x{v:x}")
            } else {
                let mut text = "0x".to_string();
                for b in word.iter().skip_while(|b| **b == 0) {
                    use std::fmt::Write as _;
                    let _ = write!(text, "{b:02x}");
                }
                text
            }
        }
        RNode::ConstBytes(bytes) => {
            use std::fmt::Write as _;
            let mut text = "0x".to_string();
            for b in &bytes {
                let _ = write!(text, "{b:02x}");
            }
            text
        }
        RNode::CalldataWord(off) => format!("calldata_word(0x{off:x})"),
        RNode::Cast(a, bits) => format!("cast{bits}({})", rec(a)),
        RNode::Param(slot) => format!("param.{slot}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工节点表测试视图：下标即节点 id。
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
    fn renders_leaf_env_and_calldata_word() {
        let view = MapView(vec![
            RNode::Named("msg.sender".into(), vec![]),
            RNode::CalldataWord(0x4),
            RNode::Named("this".into(), vec![]),
        ]);
        assert_eq!(render_node(&view, 0), "msg.sender");
        assert_eq!(render_node(&view, 2), "this");
        assert_eq!(render_node(&view, 1), "calldata_word(0x4)");
    }

    #[test]
    fn renders_cast_const_and_param() {
        let view = MapView(vec![
            RNode::CalldataWord(0x4),
            RNode::Cast(0, 160),
            RNode::Const(word(0)),
            RNode::Const(word(0x80)),
            RNode::Param(3),
        ]);
        assert_eq!(render_node(&view, 1), "cast160(calldata_word(0x4))");
        // u64 可表示的常量走 0x{v:x} 短形态（0 → 0x0）。
        assert_eq!(render_node(&view, 2), "0x0");
        assert_eq!(render_node(&view, 3), "0x80");
        assert_eq!(render_node(&view, 4), "param.3");
    }

    #[test]
    fn renders_wide_const_without_leading_zeros() {
        let mut w = [0u8; 32];
        w[0] = 0xde;
        w[31] = 0xad;
        let view = MapView(vec![RNode::Const(w)]);
        assert_eq!(
            render_node(&view, 0),
            "0xde000000000000000000000000000000000000000000000000000000000000ad"
        );
    }

    #[test]
    fn renders_binary_and_nary_shapes() {
        // trv-like 证据实形的迷你版：
        //   +(bytes_word(b_calldata_slice(+(calldata_word(0x24), 0x4), 0x20), 0x0), ...)
        let view = MapView(vec![
            RNode::CalldataWord(0x24),                           // 0
            RNode::Const(word(0x4)),                             // 1
            RNode::Named("+".into(), vec![0, 1]),                // 2
            RNode::Const(word(0x20)),                            // 3
            RNode::Named("b_calldata_slice".into(), vec![2, 3]), // 4
            RNode::Const(word(0)),                               // 5
            RNode::Named("bytes_word".into(), vec![4, 5]),       // 6
            RNode::Const(word(0xaa)),                            // 7
            RNode::Named("+".into(), vec![6, 7]),                // 8
        ]);
        assert_eq!(
            render_node(&view, 8),
            "+(bytes_word(b_calldata_slice(+(calldata_word(0x24), 0x4), 0x20), 0x0), 0xaa)"
        );
    }

    #[test]
    fn renders_const_bytes_as_full_hex() {
        let view = MapView(vec![RNode::ConstBytes(vec![0xde, 0xad, 0x00])]);
        assert_eq!(render_node(&view, 0), "0xdead00");
    }

    #[test]
    fn named_leaf_renders_without_parens() {
        let view = MapView(vec![
            RNode::Named("storage".into(), vec![1, 2]),
            RNode::Named("this".into(), vec![]),
            RNode::Named("entry.world".into(), vec![]),
        ]);
        assert_eq!(render_node(&view, 0), "storage(this, entry.world)");
    }
}
