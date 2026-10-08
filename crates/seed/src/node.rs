//! 结构化表达式节点视图：把 xlayer 节点（含代入 mint 的 overlay）
//! 规范化为 owned 的 [`Node`]（canonical storage spelling 与
//! `crates/cli/src/render.rs` 的 `canon` 同源逐条对齐），guard 求解
//! 与 assumption 文本渲染都建立在本层之上——**不解析渲染文本做求解**，
//! 渲染只用于给人看的 assumption 记录。
//!
//! 单测用手工节点表实现 [`View`]，不依赖真实 shard。

use loom_fuzz_shard::ExprNode as Base;
use loom_fuzz_xlayer::{NodeKey as Overlay, XNode, Xlayer};

/// 规范化节点（owned）。`storage` 规范化已在此层完成：
/// `Named("storage", [owner, key])` 是唯一存储拼写。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
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

impl Node {
    /// 该节点的运算名（语义同 `ExprNode::op`：Leaf/Env 返回名字，
    /// Const/ConstBytes/CalldataWord/Cast/Param 返回 None）。
    pub fn op(&self) -> Option<&str> {
        match self {
            Node::Named(name, _) => Some(name),
            Node::Const(_)
            | Node::ConstBytes(_)
            | Node::CalldataWord(_)
            | Node::Cast(_, _)
            | Node::Param(_) => None,
        }
    }

    /// 孩子 id（按操作数序）。
    pub fn child_ids(&self) -> Vec<u32> {
        match self {
            Node::Named(_, children) => children.clone(),
            Node::Cast(a, _) => vec![*a],
            Node::Const(_) | Node::ConstBytes(_) | Node::CalldataWord(_) | Node::Param(_) => {
                Vec::new()
            }
        }
    }
}

/// 规范化节点视图的只读接口：guard 求解建立在它之上（单测可用手工
/// 表直接实现本 trait，不依赖真实 shard）。
pub trait View {
    fn node(&self, id: u32) -> Option<Node>;
}

impl View for Xlayer<'_> {
    /// 经 canonical storage spelling 规范化的节点。
    fn node(&self, id: u32) -> Option<Node> {
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
        Some(XNode::Base(Base::Leaf(name))) if name.starts_with("world.") || name == "entry.world"
    ) || matches!(
        view.node(id),
        Some(XNode::Overlay(Overlay::Leaf(name)))
            if name.starts_with("world.") || name == "entry.world"
    )
}

/// 取 xlayer 节点并做 canonical storage 规范化（loom 查询引擎装载期
/// 的同一变换，与 cli 的 `canon` 同源：3 元 `load.storage` / 带 world
/// 孩子的 3 元 `storage`（Nary 或 Ternary 形态）统一为 2 元
/// `storage(owner, key)`）。
pub fn canon(view: &Xlayer<'_>, id: u32) -> Option<Node> {
    let node = view.node(id)?;
    Some(match node {
        XNode::Base(Base::Nary(op, args)) if op == "load.storage" && args.len() == 3 => {
            Node::Named("storage".to_string(), vec![args[1], args[2]])
        }
        XNode::Base(Base::Nary(op, args)) if op == "storage" && args.len() == 3 => {
            if is_world_leaf(view, args[1]) {
                Node::Named("storage".to_string(), vec![args[0], args[2]])
            } else {
                Node::Named("storage".to_string(), vec![args[0], args[1]])
            }
        }
        XNode::Base(Base::Ternary(op, a, b, c)) if op == "storage" => {
            if is_world_leaf(view, *b) {
                Node::Named("storage".to_string(), vec![*a, *c])
            } else {
                Node::Named("storage".to_string(), vec![*a, *b])
            }
        }
        XNode::Overlay(Overlay::Nary(op, args)) if op == "load.storage" && args.len() == 3 => {
            Node::Named("storage".to_string(), vec![args[1], args[2]])
        }
        XNode::Overlay(Overlay::Nary(op, args)) if op == "storage" && args.len() == 3 => {
            if is_world_leaf(view, args[1]) {
                Node::Named("storage".to_string(), vec![args[0], args[2]])
            } else {
                Node::Named("storage".to_string(), vec![args[0], args[1]])
            }
        }
        XNode::Overlay(Overlay::Ternary(op, a, b, c)) if op == "storage" => {
            if is_world_leaf(view, *b) {
                Node::Named("storage".to_string(), vec![*a, *c])
            } else {
                Node::Named("storage".to_string(), vec![*a, *b])
            }
        }
        XNode::Base(base) => match base {
            Base::Leaf(s) | Base::Env(s) => Node::Named(s.clone(), Vec::new()),
            Base::Const(w) => Node::Const(*w),
            Base::ConstBytes(b) => Node::ConstBytes(b.clone()),
            Base::CalldataWord(off) => Node::CalldataWord(*off),
            Base::Unary(op, a) => Node::Named(op.clone(), vec![*a]),
            Base::Binary(op, a, b) | Base::Cmp(op, a, b) => Node::Named(op.clone(), vec![*a, *b]),
            Base::Ternary(op, a, b, c) => Node::Named(op.clone(), vec![*a, *b, *c]),
            Base::Nary(op, args) => Node::Named(op.clone(), args.clone()),
            Base::Cast(a, bits) => Node::Cast(*a, *bits),
            Base::Param(slot) => Node::Param(*slot),
        },
        XNode::Overlay(key) => match key {
            Overlay::Leaf(s) | Overlay::Env(s) => Node::Named(s.clone(), Vec::new()),
            Overlay::Const(w) => Node::Const(*w),
            Overlay::ConstBytes(b) => Node::ConstBytes(b.clone()),
            Overlay::CalldataWord(off) => Node::CalldataWord(*off),
            Overlay::Unary(op, a) => Node::Named(op.clone(), vec![*a]),
            Overlay::Binary(op, a, b) | Overlay::Cmp(op, a, b) => {
                Node::Named(op.clone(), vec![*a, *b])
            }
            Overlay::Ternary(op, a, b, c) => Node::Named(op.clone(), vec![*a, *b, *c]),
            Overlay::Nary(op, args) => Node::Named(op.clone(), args.clone()),
            Overlay::Cast(a, bits) => Node::Cast(*a, *bits),
            Overlay::Param(slot) => Node::Param(*slot),
        },
    })
}

const MAX_DEPTH: u32 = 32;

/// 递归渲染（loom `render_node` 同款拼写，深度超过 32 层渲染 "…"）。
/// 只用于 assumption 的人读文本，不参与求解。
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
        Node::Named(name, children) if children.is_empty() => name,
        Node::Named(name, children) => format!(
            "{name}({})",
            children
                .iter()
                .map(|c| rec(*c))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Node::Const(word) => {
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
        Node::ConstBytes(bytes) => {
            use std::fmt::Write as _;
            let mut text = "0x".to_string();
            for b in &bytes {
                let _ = write!(text, "{b:02x}");
            }
            text
        }
        Node::CalldataWord(off) => format!("calldata_word(0x{off:x})"),
        Node::Cast(a, bits) => format!("cast{bits}({})", rec(a)),
        Node::Param(slot) => format!("param.{slot}"),
    }
}
