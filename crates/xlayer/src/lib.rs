//! x-layer 共享定义层效果物化（DEFS 路由展开，issue #8）。
//!
//! loom-evm 的 shard（.lst）里，函数事实流只含 `input_read` + `Apply`
//! 边；真正的 call 效果在被 Apply/Exit 的 DEFS 共享定义（trampoline）
//! 里。本 crate 自包含地复现 loom-evm 查询引擎装载时的 "route-ordered
//! expansion"（`loom-evm/src/query/mod.rs` 的 `SpliceSubst` + 展开主循环，
//! 语义逐条对齐）：把被 Apply/Exit 的定义体按路由序拼进函数视图，对
//! 表达式做帧实参代入，产出 `XEntry` 展开流（步序 `step` 只给
//! Guard/Effect/Outcome 递增，Apply/Exit 是控制边、不占步序）。
//!
//! 代入 mint 的 overlay 表达式节点接在 shard 表达式字典之后
//! （id ≥ 字典基数），经 [`Xlayer::node`] 可查；作用域 rebase mint 的
//! 新作用域接在 shard 作用域表之后。overlay/新作用域对本 crate 处理
//! 过的所有函数共享（与 loom 的每合约一个 `SpliceSubst` 一致）。
//!
//! 已知语义折衷（与 loom-evm 的差异，如实列出）：
//! - 不消费 READS 段（shard 读取器 M0 即跳过）：每帧 per-arrival-class
//!   读表恒为 None，load/mload/memory 查表只走 entry 内嵌的
//!   `args.reads`（loom 的 frame_class 查找恒落空后的回退路径）。
//! - 结构哈希不参与（golden 对拍不比对哈希）：overlay 节点没有哈希尾。

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use loom_fuzz_shard::{Definition, Entry, ExprNode, Function, Scope, Shard};

mod word;
pub use word::Word;

// ---------------------------------------------------------------------------
// 内部可哈希节点键（overlay 字典的键空间）
// ---------------------------------------------------------------------------

/// 表达式节点的可哈希内部表示（overlay 字典的键空间）。与 shard 的
/// [`ExprNode`] 同构，但名字为拥有的 `String`、可哈希——base 字典在
/// 构造期整体转换进同一键空间，使 mint 的去重（`overlay_ids`/`base_ids`）
/// 跨 base/overlay 统一。Cast 的位宽保留 shard 原生的 `u64`。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Leaf(String),
    Const([u8; 32]),
    ConstBytes(Vec<u8>),
    CalldataWord(u64),
    Env(String),
    Unary(String, u32),
    Binary(String, u32, u32),
    Cmp(String, u32, u32),
    Ternary(String, u32, u32, u32),
    Nary(String, Vec<u32>),
    Cast(u32, u64),
    Param(u32),
}

impl NodeKey {
    /// 该节点的运算名（叶子/环境节点返回名字；Const/ConstBytes/
    /// CalldataWord/Cast/Param 返回 None）。语义同 `ExprNode::op`。
    pub fn op(&self) -> Option<&str> {
        match self {
            NodeKey::Leaf(s) | NodeKey::Env(s) => Some(s),
            NodeKey::Unary(s, _)
            | NodeKey::Binary(s, _, _)
            | NodeKey::Cmp(s, _, _)
            | NodeKey::Ternary(s, _, _, _)
            | NodeKey::Nary(s, _) => Some(s),
            NodeKey::Const(_) | NodeKey::ConstBytes(_) | NodeKey::CalldataWord(_) => None,
            NodeKey::Cast(_, _) | NodeKey::Param(_) => None,
        }
    }

    /// 子节点 id（按操作数序）。
    pub fn child_ids(&self) -> Vec<u32> {
        match self {
            NodeKey::Unary(_, a) | NodeKey::Cast(a, _) => vec![*a],
            NodeKey::Binary(_, a, b) | NodeKey::Cmp(_, a, b) => vec![*a, *b],
            NodeKey::Ternary(_, a, b, c) => vec![*a, *b, *c],
            NodeKey::Nary(_, args) => args.clone(),
            NodeKey::Leaf(_)
            | NodeKey::Const(_)
            | NodeKey::ConstBytes(_)
            | NodeKey::CalldataWord(_)
            | NodeKey::Env(_)
            | NodeKey::Param(_) => Vec::new(),
        }
    }

    fn from_base(node: &ExprNode) -> NodeKey {
        match node {
            ExprNode::Leaf(s) => NodeKey::Leaf(s.clone()),
            ExprNode::Const(w) => NodeKey::Const(*w),
            ExprNode::ConstBytes(b) => NodeKey::ConstBytes(b.clone()),
            ExprNode::CalldataWord(off) => NodeKey::CalldataWord(*off),
            ExprNode::Env(s) => NodeKey::Env(s.clone()),
            ExprNode::Unary(op, a) => NodeKey::Unary(op.clone(), *a),
            ExprNode::Binary(op, a, b) => NodeKey::Binary(op.clone(), *a, *b),
            ExprNode::Cmp(op, a, b) => NodeKey::Cmp(op.clone(), *a, *b),
            ExprNode::Ternary(op, a, b, c) => NodeKey::Ternary(op.clone(), *a, *b, *c),
            ExprNode::Nary(op, args) => NodeKey::Nary(op.clone(), args.clone()),
            ExprNode::Cast(a, bits) => NodeKey::Cast(*a, *bits),
            ExprNode::Param(slot) => NodeKey::Param(*slot),
        }
    }
}

/// 节点视图：base 字典节点（借用 shard 的 `ExprNode`）或代入 mint 的
/// overlay 节点（借用本 crate 的 `NodeKey`）。两者都经
/// [`Xlayer::node`] 按统一 id 空间取出；沿 `child_ids` 走子树时
/// 可能跨 base/overlay 边界（代入只重写被替换的子树）。
pub enum XNode<'a> {
    Base(&'a ExprNode),
    Overlay(&'a NodeKey),
}

impl<'a> XNode<'a> {
    /// 运算名（语义同 `ExprNode::op`）。
    pub fn op(&self) -> Option<&str> {
        match self {
            XNode::Base(node) => node.op(),
            XNode::Overlay(key) => key.op(),
        }
    }

    /// 子节点 id（按操作数序）。
    pub fn child_ids(&self) -> Vec<u32> {
        match self {
            XNode::Base(node) => match node {
                ExprNode::Unary(_, a) | ExprNode::Cast(a, _) => vec![*a],
                ExprNode::Binary(_, a, b) | ExprNode::Cmp(_, a, b) => vec![*a, *b],
                ExprNode::Ternary(_, a, b, c) => vec![*a, *b, *c],
                ExprNode::Nary(_, args) => args.clone(),
                _ => Vec::new(),
            },
            XNode::Overlay(key) => key.child_ids(),
        }
    }
}

// ---------------------------------------------------------------------------
// 一步常量折叠（loom-evm facts.rs 照抄语义）
// ---------------------------------------------------------------------------

/// 一步常量折叠（loom-evm `fold_operator` 照抄）：重算出的算子节点
/// 在两个操作数（Cast 为一个）都是 `Const` 时折叠为具体语义
/// （`word` 模块的运算表）给出的常量；否则原样返回。
fn fold_operator(key: NodeKey, const_of: &dyn Fn(u32) -> Option<Word>) -> NodeKey {
    match key {
        NodeKey::Unary(op, a) => match const_of(a).and_then(|v| word::apply_unary_op(&op, v)) {
            Some(value) => NodeKey::Const(value.0),
            None => NodeKey::Unary(op, a),
        },
        NodeKey::Binary(op, a, b) => match (const_of(a), const_of(b)) {
            (Some(x), Some(y)) => match word::apply_binary_op(&op, x, y) {
                Some(value) => NodeKey::Const(value.0),
                None => NodeKey::Binary(op, a, b),
            },
            _ => NodeKey::Binary(op, a, b),
        },
        NodeKey::Cmp(op, a, b) => match (const_of(a), const_of(b)) {
            (Some(x), Some(y)) => {
                let holds = match op.as_str() {
                    "==" => Some(x == y),
                    "!=" => Some(x != y),
                    "<" => Some(x.cmp_u(y) == std::cmp::Ordering::Less),
                    ">" => Some(x.cmp_u(y) == std::cmp::Ordering::Greater),
                    "<=" => Some(x.cmp_u(y) != std::cmp::Ordering::Greater),
                    ">=" => Some(x.cmp_u(y) != std::cmp::Ordering::Less),
                    _ => None,
                };
                match holds {
                    Some(holds) => NodeKey::Const(Word::from_u64(u64::from(holds)).0),
                    None => NodeKey::Cmp(op, a, b),
                }
            }
            _ => NodeKey::Cmp(op, a, b),
        },
        NodeKey::Cast(a, bits) => match const_of(a) {
            Some(value) => {
                let folded = if bits >= 256 {
                    value
                } else {
                    value.bit_and(
                        Word::from_u64(1)
                            .shift_left(u32::try_from(bits).unwrap_or(256))
                            .wrapping_sub(Word::from_u64(1)),
                    )
                };
                NodeKey::Const(folded.0)
            }
            None => NodeKey::Cast(a, bits),
        },
        other => other,
    }
}

/// 字节/字边界折叠（loom-evm `fold_calldata_window` 照抄）：
/// `bytes_word(b_calldata_slice(at, 32), 0)` 折叠为 `CalldataWord(at)`，
/// 使代入重 mint 的字节串窗口节点与 emit 侧的 `calldata_word` 读
/// 同一字典 id。只对 `bytes_word` 二元节点生效。
fn fold_calldata_window(
    key: NodeKey,
    key_of: &dyn Fn(u32) -> NodeKey,
    const_of: &dyn Fn(u32) -> Option<Word>,
) -> NodeKey {
    let NodeKey::Binary(op, bytes, offset) = key else {
        return key;
    };
    if op != "bytes_word" {
        return NodeKey::Binary(op, bytes, offset);
    }
    let NodeKey::Binary(slice, at, len) = key_of(bytes) else {
        return NodeKey::Binary(op, bytes, offset);
    };
    if slice != "b_calldata_slice" && slice != "calldata_slice" {
        return NodeKey::Binary(op, bytes, offset);
    }
    match (const_of(at), const_of(len), const_of(offset)) {
        (Some(at), Some(len), Some(zero)) if len == Word::from_u64(32) && zero.is_zero() => {
            match at.as_u64() {
                Some(at) => NodeKey::CalldataWord(at),
                None => NodeKey::Binary(op, bytes, offset),
            }
        }
        _ => NodeKey::Binary(op, bytes, offset),
    }
}

// ---------------------------------------------------------------------------
// 展开产物
// ---------------------------------------------------------------------------

/// 展开视图条目：DEFS 路由展开后每函数的物化流。`step` 是 x-layer
/// 效果步序（只给 Guard/Effect/Outcome 递增；Apply/Exit 不产出条目、
/// 不占步序——与 loom 一致）。`pc` 取条目原点 pc。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XEntry {
    Guard {
        cond: u32,
        polarity: bool,
        scope: u32,
        pc: u32,
        step: u32,
    },
    Effect {
        kind: String,
        operands: Vec<(String, u32)>,
        scope: u32,
        pc: u32,
        step: u32,
    },
    Outcome {
        class: String,
        data: Option<u32>,
        scope: u32,
        pc: u32,
        step: u32,
    },
}

impl XEntry {
    /// 条目的效果步序。
    pub fn step(&self) -> u32 {
        match self {
            XEntry::Guard { step, .. }
            | XEntry::Effect { step, .. }
            | XEntry::Outcome { step, .. } => *step,
        }
    }
}

// ---------------------------------------------------------------------------
// 引擎模型（shard 的借用视图）
// ---------------------------------------------------------------------------

/// 引擎面对的模型视图：base 字典已转换为 `NodeKey` 键空间，函数/
/// 定义/作用域表借用 shard。单测用手工构造的表直接实例化，公开入口
/// 经 [`Xlayer::new`] 从 `&Shard` 构建。
struct Model<'a> {
    /// base 表达式字典（键空间转换后，与 shard.exprs() 同序同长）。
    exprs: Vec<NodeKey>,
    functions: &'a [Function],
    definitions: &'a [Definition],
    scopes: &'a [Scope],
}

/// 帧实参（Apply/Exit 边的实际参数），与 shard 的 `FrameArgs` 同构，
/// 额外可哈希（visited 去重键用）。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Args {
    stack: Vec<u32>,
    reached: u16,
    returndata_size: u32,
    returndata_epoch: u32,
    reads: Vec<(u32, u32)>,
}

impl From<&loom_fuzz_shard::FrameArgs> for Args {
    fn from(args: &loom_fuzz_shard::FrameArgs) -> Self {
        Args {
            stack: args.stack.clone(),
            reached: args.reached,
            returndata_size: args.returndata_size,
            returndata_epoch: args.returndata_epoch,
            reads: args.reads.clone(),
        }
    }
}

/// 定义实际参的读相关投影（loom-evm `project_args` 照抄）：保留栈顶
/// `height` 格（None = 全部），被截掉的深度折算进 `reached`——栈下
/// 方的格子按构造永不被该定义的行引用，按投影去重是精确的。
fn project_args(model: &Model, def: u32, args: &Args) -> Args {
    let need = model.definitions[def as usize].height.unwrap_or(u32::MAX) as usize;
    let len = args.stack.len();
    let keep = need.min(len);
    Args {
        stack: args.stack[len - keep..].to_vec(),
        reached: args.reached + (len - keep) as u16,
        returndata_size: args.returndata_size,
        returndata_epoch: args.returndata_epoch,
        reads: args.reads.clone(),
    }
}

// ---------------------------------------------------------------------------
// SpliceSubst：代入/退出解析/作用域重定（loom-evm 逐条对齐）
// ---------------------------------------------------------------------------

/// 每函数 x-layer 展开的代入工作量上限（loom 同值）：超过后不再
/// push 新帧（已发出的行保留），病态 web 形状降级而不是挂死。
const EXPAND_FUEL: usize = 5_000_000;

struct Subst<'m> {
    model: &'m Model<'m>,
    /// base 字典键 → id 的反向索引（mint 先去重，不复制 base 节点）。
    base_ids: HashMap<NodeKey, u32>,
    /// 代入 mint 的 overlay 节点，接在 base 字典之后（id ≥ 字典基数）。
    overlay: Vec<NodeKey>,
    overlay_ids: HashMap<NodeKey, u32>,
    /// (节点 id, 帧) → 代入结果。帧下标每函数从 0 重启，memo 也是。
    memo: HashMap<(u32, usize), u32>,
    fuel: Cell<usize>,
    /// Param(slot) 的 mint 缓存（跨函数共享，与 overlay 同属字典层）。
    param_ids: HashMap<u32, u32>,
    /// 帧表：frame → (apply 边的 scope, parent frame)。
    frames: Vec<(u32, usize)>,
    frame_args: Vec<Option<Args>>,
    /// (code_id, merge pc) → 形式变体定义下标（height = Some 的定义）。
    exit_index: HashMap<(u32, u32), u32>,
    scope_memo: HashMap<(u32, usize), u32>,
    scopes_new: Vec<(u32, u32, bool)>,
}

impl<'m> Subst<'m> {
    fn new(model: &'m Model<'m>) -> Self {
        let base_ids = model
            .exprs
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, key)| (key, i as u32))
            .collect();
        // exit_index 照抄 loom 的 `exit_index_of`：height = Some 的定义
        // 按 (code_id, pc) 建索引；同键后写覆盖先写（collect 语义）。
        let exit_index = model
            .definitions
            .iter()
            .enumerate()
            .filter_map(|(index, definition)| {
                definition
                    .height
                    .map(|_| ((definition.code_id, definition.pc), index as u32))
            })
            .collect();
        Subst {
            model,
            base_ids,
            overlay: Vec::new(),
            overlay_ids: HashMap::new(),
            memo: HashMap::new(),
            fuel: Cell::new(0),
            param_ids: HashMap::new(),
            frames: vec![(0, 0)],
            frame_args: vec![None],
            exit_index,
            scope_memo: HashMap::new(),
            scopes_new: Vec::new(),
        }
    }

    /// 每函数开头重置帧与 memo（overlay/scopes_new/param_ids 跨函数
    /// 共享，与 loom 每合约一个 SpliceSubst 一致）。
    fn reset_function(&mut self) {
        self.frames.clear();
        self.frames.push((0, 0));
        self.frame_args.clear();
        self.frame_args.push(None);
        self.scope_memo.clear();
        // 帧下标重启，一切帧键 memo 都必须随之清空——命中上一函数的
        // (id, frame) 是串味。
        self.memo.clear();
        self.fuel.set(EXPAND_FUEL);
    }

    fn key_at(&self, id: u32) -> &NodeKey {
        let base = self.model.exprs.len();
        if (id as usize) < base {
            &self.model.exprs[id as usize]
        } else {
            &self.overlay[id as usize - base]
        }
    }

    /// mint：先查 overlay 去重，再查 base 反向索引（结构相同则直接
    /// 用 base id，不复制），否则接在字典尾。
    fn mint(&mut self, key: NodeKey) -> u32 {
        if let Some(&id) = self.overlay_ids.get(&key) {
            return id;
        }
        if let Some(&id) = self.base_ids.get(&key) {
            return id;
        }
        let id = (self.model.exprs.len() + self.overlay.len()) as u32;
        self.overlay.push(key.clone());
        self.overlay_ids.insert(key, id);
        id
    }

    fn param_node(&mut self, slot: u32) -> u32 {
        if let Some(&id) = self.param_ids.get(&slot) {
            return id;
        }
        let id = self.mint(NodeKey::Param(slot));
        self.param_ids.insert(slot, id);
        id
    }

    fn push_frame(&mut self, scope: u32, parent: usize, args: Option<Args>) -> usize {
        self.frames.push((scope, parent));
        self.frame_args.push(args);
        self.frames.len() - 1
    }

    fn subst_id(&mut self, id: u32, frame: usize) -> u32 {
        self.fuel.set(self.fuel.get().saturating_sub(1));
        if self.frame_args[frame].is_none() {
            return id;
        }
        if let Some(&done) = self.memo.get(&(id, frame)) {
            return done;
        }
        let done = self.subst_id_compute(id, frame);
        self.memo.insert((id, frame), done);
        done
    }

    fn subst_id_compute(&mut self, id: u32, frame: usize) -> u32 {
        let key = self.key_at(id).clone();
        match key {
            NodeKey::Param(slot) => {
                let args = self.frame_args[frame].as_ref().unwrap().clone();
                let len = args.stack.len();
                if (slot as usize) < len {
                    args.stack[len - 1 - slot as usize]
                } else {
                    // 越界的形参槽：entry 高度之外的实参不存在，mint
                    // 一个 reached 偏移的 overlay Param 占位（loom 同）。
                    self.param_node(args.reached as u32 + slot - len as u32)
                }
            }
            NodeKey::Nary(op, children)
                if (op.starts_with("load.") || op == "mload")
                    && self.is_entry_state(children[0]) =>
            {
                let args = self.frame_args[frame].as_ref().unwrap().clone();
                if let Some(value) = self.table_lookup(id, &args) {
                    return value;
                }
                if let Some((_, value)) = self.preimage_match(id, frame) {
                    return value;
                }
                let mut mapped = vec![children[0]];
                for child in &children[1..] {
                    mapped.push(self.subst_id(*child, frame));
                }
                self.mint(NodeKey::Nary(op, mapped))
            }
            NodeKey::Binary(op, a, b) if op == "memory" => {
                // 无状态窗口 token（签名的 engine state 是 entry state 上
                // 的写链时，以 memory[off, len) 内嵌进表）：查表优先。
                let args = self.frame_args[frame].as_ref().unwrap().clone();
                if let Some(value) = self.table_lookup(id, &args) {
                    return value;
                }
                if let Some((_, value)) = self.preimage_match(id, frame) {
                    return value;
                }
                let a = self.subst_id(a, frame);
                let b = self.subst_id(b, frame);
                let key = fold_operator(NodeKey::Binary(op, a, b), &|x| self.const_of(x));
                self.mint(key)
            }
            NodeKey::Unary(op, a) => {
                let a = self.subst_id(a, frame);
                let key = fold_operator(NodeKey::Unary(op, a), &|x| self.const_of(x));
                self.mint(key)
            }
            NodeKey::Binary(op, a, b) => {
                let a = self.subst_id(a, frame);
                let b = self.subst_id(b, frame);
                let key = fold_operator(NodeKey::Binary(op, a, b), &|x| self.const_of(x));
                let key =
                    fold_calldata_window(key, &|x| self.key_at(x).clone(), &|x| self.const_of(x));
                self.mint(key)
            }
            NodeKey::Cmp(op, a, b) => {
                let a = self.subst_id(a, frame);
                let b = self.subst_id(b, frame);
                let key = fold_operator(NodeKey::Cmp(op, a, b), &|x| self.const_of(x));
                self.mint(key)
            }
            NodeKey::Ternary(op, a, b, c) => {
                let a = self.subst_id(a, frame);
                let b = self.subst_id(b, frame);
                let c = self.subst_id(c, frame);
                self.mint(NodeKey::Ternary(op, a, b, c))
            }
            NodeKey::Nary(op, children) => {
                let mapped: Vec<u32> = children
                    .iter()
                    .map(|child| self.subst_id(*child, frame))
                    .collect();
                self.mint(NodeKey::Nary(op, mapped))
            }
            NodeKey::Cast(a, bits) => {
                let a = self.subst_id(a, frame);
                let key = fold_operator(NodeKey::Cast(a, bits), &|x| self.const_of(x));
                self.mint(key)
            }
            _ => id,
        }
    }

    /// 读表精确查找：lookup 顺序与 loom 的 `table_lookup` 一致——
    /// per-arrival-class 表（本 crate 无 READS 段支持，恒 None）在前，
    /// entry 内嵌 `args.reads` 精确 `token == id` 命中。
    fn table_lookup(&self, id: u32, args: &Args) -> Option<u32> {
        args.reads
            .iter()
            .find(|(token, _)| *token == id)
            .map(|(_, value)| *value)
    }

    /// 形状失配求解器（loom 的 `preimage_match` 照抄）：表键是形式读、
    /// 节点是被代入后的形式——精确查找落空时，把每个表 token 经本帧
    /// 实参代入，接受像恰好是 `id` 的第一项（同一个运行时读，其值是
    /// 诚实答案；token 为 Param 的跳过——已被精确路径覆盖）。
    fn preimage_match(&mut self, id: u32, frame: usize) -> Option<(u32, u32)> {
        let args = self.frame_args[frame].as_ref()?.clone();
        args.reads
            .iter()
            .find(|(token, _)| {
                !matches!(self.key_at(*token), NodeKey::Param(_))
                    && self.subst_id(*token, frame) == id
            })
            .copied()
    }

    fn const_of(&self, id: u32) -> Option<Word> {
        match self.key_at(id) {
            NodeKey::Const(value) => Some(Word(*value)),
            _ => None,
        }
    }

    fn is_entry_state(&self, id: u32) -> bool {
        matches!(
            self.key_at(id),
            NodeKey::Leaf(name)
                if name == "entry.memory" || name == "entry.world" || name == "entry.transient"
        )
    }

    /// Exit 落点解析（loom 的 `resolve_exit` 照抄）：target 沿帧链 deep
    /// 代入后必须是 Const，取 pc 查 `exit_index`；landing 实参保持 RAW
    /// （exit 的原始 args，不做预代入——预代入会跳层、后面每一跳错位）。
    fn resolve_exit(
        &mut self,
        target: u32,
        args: &Args,
        frame: usize,
        code_id: u32,
    ) -> Option<(u32, Args)> {
        let resolved = self.subst_id_deep(target, frame);
        let NodeKey::Const(bytes) = self.key_at(resolved) else {
            return None;
        };
        let pc = Word(*bytes).as_u32()?;
        let def = self.exit_index.get(&(code_id, pc)).copied()?;
        Some((def, args.clone()))
    }

    /// 沿 parent 帧链逐层代入（loom 的 `subst_id_deep` 照抄）：实参里
    /// 活下来的 Param 读调用方帧（返回地址在 spill 区），所以代入要
    /// 一跳一跳走到根词汇表。跳数上限 = 帧数（landing 的 parent 链
    /// 在 exit 回边上可能成环，无界 chase 不会返回）。
    fn subst_id_deep(&mut self, id: u32, frame: usize) -> u32 {
        let mut cur = self.subst_id(id, frame);
        let mut f = frame;
        for _ in 0..=self.frames.len() {
            let parent = self.frames[f].1;
            if parent == f || self.frame_args[parent].is_none() {
                return cur;
            }
            cur = self.subst_id(cur, parent);
            f = parent;
        }
        cur
    }

    /// 帧实参的规范化（root 词汇表）形式（loom 的 `flat_args` 照抄）：
    /// 每条格、returndata_size/epoch、reads 的 value 都经 parent 的
    /// deep 代入。visited 去重键用它——实际参数相同的链拼进相同的行。
    fn flat_args(&mut self, frame: usize) -> Option<Args> {
        let args = self.frame_args[frame].clone()?;
        let parent = self.frames[frame].1;
        if parent == frame || self.frame_args[parent].is_none() {
            return Some(args);
        }
        Some(Args {
            stack: args
                .stack
                .iter()
                .map(|cell| self.subst_id_deep(*cell, parent))
                .collect(),
            reached: args.reached,
            returndata_size: self.subst_id_deep(args.returndata_size, parent),
            returndata_epoch: self.subst_id_deep(args.returndata_epoch, parent),
            reads: args
                .reads
                .iter()
                .map(|(token, value)| (*token, self.subst_id_deep(*value, parent)))
                .collect(),
        })
    }

    /// 体内部 scope 在 `frame` 体中的 x-layer scope（loom 的 `rebase`
    /// 照抄）：scope 0 抬升到 apply 边的 scope（根帧则 0）；非 0 递归
    /// 重定 parent、guard 只过一层 `subst_id`（非 deep）、polarity 原样，
    /// mint 进 scopes_new（id 接在 shard 作用域表后）。
    fn rebase(&mut self, scope: u32, frame: usize) -> u32 {
        if self.frame_args[frame].is_none() {
            return scope;
        }
        if let Some(&id) = self.scope_memo.get(&(scope, frame)) {
            return id;
        }
        let id = if scope == 0 {
            if frame == 0 {
                0
            } else {
                let (apply_scope, parent_frame) = self.frames[frame];
                self.rebase(apply_scope, parent_frame)
            }
        } else {
            let link = self.model.scopes[scope as usize - 1];
            let parent = self.rebase(link.parent, frame);
            let guard = self.subst_id(link.guard, frame);
            let id = (self.model.scopes.len() + self.scopes_new.len()) as u32 + 1;
            self.scopes_new.push((parent, guard, link.polarity));
            id
        };
        self.scope_memo.insert((scope, frame), id);
        id
    }
}

// ---------------------------------------------------------------------------
// 公开入口：Xlayer
// ---------------------------------------------------------------------------

/// DEFS 路由展开的物化视图：每函数一条 `XEntry` 展开流，加上代入
/// mint 的 overlay 表达式字典与 rebase mint 的新作用域。构造即展开
/// （与 loom 装载时一次性展开一致）；overlay/新作用域对所有函数共享。
pub struct Xlayer<'a> {
    shard: &'a Shard,
    model: Model<'a>,
    expansions: Vec<Vec<XEntry>>,
    overlay: Vec<NodeKey>,
    scopes_new: Vec<(u32, u32, bool)>,
}

impl<'a> Xlayer<'a> {
    /// 装载 shard 并展开全部函数。工作量为燃料制（每函数 500 万次
    /// subst 调用），病态形状降级不挂死。
    pub fn new(shard: &'a Shard) -> Self {
        let model = Model {
            exprs: shard.exprs().iter().map(NodeKey::from_base).collect(),
            functions: shard.functions(),
            definitions: shard.definitions(),
            scopes: shard.scopes(),
        };
        let mut subst = Subst::new(&model);
        let mut expansions = Vec::with_capacity(model.functions.len());
        for fn_idx in 0..model.functions.len() {
            expansions.push(expand_function(&mut subst, fn_idx));
        }
        // 先取回 overlay/scopes_new（subst 对 model 的借用随之结束），
        // 再把 model 移进结果。
        let overlay = std::mem::take(&mut subst.overlay);
        let scopes_new = std::mem::take(&mut subst.scopes_new);
        Xlayer {
            shard,
            model,
            expansions,
            overlay,
            scopes_new,
        }
    }

    /// 函数展开流（下标 = shard.functions() 的下标）。
    pub fn expand(&self, fn_idx: usize) -> Option<&[XEntry]> {
        self.expansions.get(fn_idx).map(Vec::as_slice)
    }

    /// 表达式字典节点：id < 字典基数时借用 shard 的 base 节点；否则
    /// 查本 crate 代入 mint 的 overlay 节点。子引用在统一 id 空间内，
    /// 沿 `XNode::child_ids` 走子树可能跨 base/overlay 边界。
    pub fn node(&self, id: u32) -> Option<XNode<'_>> {
        let base = self.model.exprs.len();
        if (id as usize) < base {
            self.shard.expr(id).map(XNode::Base)
        } else {
            self.overlay.get(id as usize - base).map(XNode::Overlay)
        }
    }

    /// overlay 节点的起始 id（= shard 表达式字典基数）。
    pub fn overlay_base(&self) -> u32 {
        self.model.exprs.len() as u32
    }

    /// 代入 mint 的 overlay 节点表（下标 + `overlay_base` = 节点 id）。
    pub fn overlay(&self) -> &[NodeKey] {
        &self.overlay
    }

    /// rebase mint 的新作用域（parent, guard, polarity）；其 id 从
    /// shard.scopes().len() + 1 起按序对应本表下标。
    pub fn scopes_new(&self) -> &[(u32, u32, bool)] {
        &self.scopes_new
    }
}

/// 单函数的路由序展开主循环（loom query 装载主循环照抄）：DFS 拼接
/// 被 Apply/Exit 的定义体，visited 键 = (定义, flat_args 投影)，
/// 燃料耗尽后不再 push 新帧（已发出的行保留）。
fn expand_function(subst: &mut Subst, fn_idx: usize) -> Vec<XEntry> {
    expand_function_fuel(subst, fn_idx, EXPAND_FUEL)
}

fn expand_function_fuel(subst: &mut Subst, fn_idx: usize, fuel: usize) -> Vec<XEntry> {
    // 从 subst 里拷出模型引用（'m 长于 subst 借用本身）：条目切片经它
    // 借用，同一循环体里才能再拿 &mut subst 做代入。
    let model = subst.model;
    let f = &model.functions[fn_idx];
    subst.reset_function();
    subst.fuel.set(fuel);
    // 变体按 head 共享（issue #137 类形状）：trampoline 定义经多条边、
    // 带着不同实参进入，每条边的拼接贡献各自的行——去重键是规范化
    // （root 词汇表）实参，等价链去重、展开有界。
    let mut visited: HashSet<(u32, Option<Args>)> = HashSet::new();
    // (stream, pos, frame)：stream = -1 是函数本体，≥ 0 是定义下标。
    let mut stack: Vec<(i64, usize, usize)> = vec![(-1, 0, 0)];
    let mut xidx = 0u32;
    let mut out = Vec::new();
    while let Some((stream, pos, frame)) = stack.last_mut() {
        let frame = *frame;
        let entries: &[Entry] = if *stream < 0 {
            &f.entries
        } else {
            &model.definitions[*stream as usize].entries
        };
        if *pos >= entries.len() {
            stack.pop();
            continue;
        }
        let entry = entries[*pos].clone();
        *pos += 1;
        match entry {
            Entry::Apply {
                definition,
                recur,
                scope,
                args,
                ..
            } => {
                let def = definition as usize;
                if !recur && def < model.definitions.len() {
                    let frame = subst.push_frame(scope, frame, args.map(|a| Args::from(&a)));
                    let key = subst
                        .flat_args(frame)
                        .map(|a| project_args(model, definition, &a));
                    if subst.fuel.get() > 0 && visited.insert((definition, key)) {
                        stack.push((def as i64, 0, frame));
                    }
                }
                continue;
            }
            Entry::Exit {
                target,
                scope,
                args,
                ..
            } => {
                // 返回边：经帧实参解析出落点变体，从 landing 继续走。
                let code_id = if *stream < 0 {
                    0
                } else {
                    model.definitions[*stream as usize].code_id
                };
                if let Some((def, sub_args)) =
                    subst.resolve_exit(target, &Args::from(&args), frame, code_id)
                {
                    let def = def as usize;
                    if def < model.definitions.len() {
                        let frame = subst.push_frame(scope, frame, Some(sub_args));
                        let key = subst
                            .flat_args(frame)
                            .map(|a| project_args(model, def as u32, &a));
                        if subst.fuel.get() > 0 && visited.insert((def as u32, key)) {
                            stack.push((def as i64, 0, frame));
                        }
                    }
                }
                continue;
            }
            Entry::Guard {
                cond,
                polarity,
                scope,
                pc,
                ..
            } => {
                let cond = subst.subst_id_deep(cond, frame);
                let scope = subst.rebase(scope, frame);
                out.push(XEntry::Guard {
                    cond,
                    polarity,
                    scope,
                    pc,
                    step: xidx,
                });
            }
            Entry::Effect {
                kind,
                operands,
                scope,
                pc,
                ..
            } => {
                let scope = subst.rebase(scope, frame);
                let operands = operands
                    .iter()
                    .map(|(name, x)| (name.clone(), subst.subst_id_deep(*x, frame)))
                    .collect();
                out.push(XEntry::Effect {
                    kind,
                    operands,
                    scope,
                    pc,
                    step: xidx,
                });
            }
            Entry::Outcome {
                class,
                data,
                scope,
                pc,
                ..
            } => {
                let scope = subst.rebase(scope, frame);
                let data = data.map(|x| subst.subst_id_deep(x, frame));
                out.push(XEntry::Outcome {
                    class,
                    data,
                    scope,
                    pc,
                    step: xidx,
                });
            }
        }
        xidx += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// 单元测试：代入语义的关键分支（手工模型直接驱动内部引擎）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工模型夹具：拥有函数/定义/作用域表，Model 借用之。
    struct Fx {
        functions: Vec<Function>,
        definitions: Vec<Definition>,
        scopes: Vec<Scope>,
    }

    impl Fx {
        fn new() -> Fx {
            Fx {
                functions: Vec::new(),
                definitions: Vec::new(),
                scopes: Vec::new(),
            }
        }

        fn model(&self, exprs: Vec<NodeKey>) -> Model<'_> {
            Model {
                exprs,
                functions: &self.functions,
                definitions: &self.definitions,
                scopes: &self.scopes,
            }
        }
    }

    /// recur 场景：函数流 = input_read、Apply(recur=?)、call；定义体
    /// 含一条 sload。
    fn recur_fx(recur: bool) -> Fx {
        let mut fx = Fx::new();
        fx.definitions.push(Definition {
            pc: 0,
            code_id: 0,
            height: Some(1),
            entries: vec![effect("sload", vec![("slot", 0)], 0)],
        });
        fx.functions.push(Function {
            kind: "function".to_string(),
            selector: Some(0xdeadbeef),
            name: Some("f".to_string()),
            entries: vec![
                effect("input_read", vec![], 0),
                apply(0, recur, Some(args(vec![]))),
                effect("call", vec![("target", 0)], 2),
            ],
        });
        fx
    }

    fn effect_kinds(out: &[XEntry]) -> Vec<&str> {
        out.iter()
            .map(|e| match e {
                XEntry::Effect { kind, .. } => kind.as_str(),
                _ => panic!("unexpected entry"),
            })
            .collect()
    }

    fn effect(kind: &str, operands: Vec<(&str, u32)>, step: u32) -> Entry {
        Entry::Effect {
            kind: kind.to_string(),
            operands: operands
                .into_iter()
                .map(|(name, id)| (name.to_string(), id))
                .collect(),
            scope: 0,
            pc: 0,
            step,
        }
    }

    fn apply(definition: u32, recur: bool, args: Option<Args>) -> Entry {
        Entry::Apply {
            definition,
            recur,
            scope: 0,
            instance: None,
            args: args.map(|a| loom_fuzz_shard::FrameArgs {
                stack: a.stack,
                reached: a.reached,
                returndata_size: a.returndata_size,
                returndata_epoch: a.returndata_epoch,
                reads: a.reads,
            }),
        }
    }

    fn args(stack: Vec<u32>) -> Args {
        Args {
            stack,
            reached: 0,
            returndata_size: 0,
            returndata_epoch: 0,
            reads: Vec::new(),
        }
    }

    /// Param 在实参高度内读栈顶下 slot；越界 mint reached 偏移的
    /// overlay Param，且重复代入复用同一 overlay id。
    #[test]
    fn param_out_of_range_mints_overlay() {
        let fx = Fx::new();
        let model = fx.model(vec![
            NodeKey::Const(Word::from_u64(0x11).0), // 0
            NodeKey::Param(0),                      // 1
            NodeKey::Param(2),                      // 2
        ]);
        let mut subst = Subst::new(&model);
        subst.reset_function();
        let mut with_args = args(vec![0]);
        with_args.reached = 5;
        let frame = subst.push_frame(0, 0, Some(with_args));
        // slot 0 < len 1：读栈顶。
        assert_eq!(subst.subst_id(1, frame), 0);
        // slot 2 >= len 1：mint Param(reached + slot - len) = Param(6)。
        let id = subst.subst_id(2, frame);
        assert!(id >= 3, "越界 Param 必须是 overlay id，实际 {id}");
        assert_eq!(subst.key_at(id), &NodeKey::Param(6));
        assert_eq!(subst.subst_id(2, frame), id, "重复代入必须复用同一 id");
    }

    /// reads 表精确命中：token == id 直接返回值，不做子代入。
    #[test]
    fn reads_exact_token_hit() {
        let fx = Fx::new();
        // 0: entry.world；1: load.storage[entry.world, 2]；2: key；3: value
        let model = fx.model(vec![
            NodeKey::Leaf("entry.world".to_string()),
            NodeKey::Nary("load.storage".to_string(), vec![0, 2]),
            NodeKey::Const(Word::from_u64(0x42).0),
            NodeKey::Const(Word::from_u64(0x99).0),
        ]);
        let mut subst = Subst::new(&model);
        subst.reset_function();
        let mut a = args(vec![]);
        a.reads = vec![(1, 3)];
        let frame = subst.push_frame(0, 0, Some(a));
        assert_eq!(subst.subst_id(1, frame), 3);
    }

    /// preimage_match：表值列恰是被查询节点时命中（token 非 Param）。
    #[test]
    fn preimage_match_hit() {
        let fx = Fx::new();
        // 0: entry.world；1: load[0,2]；2: key A；3: load[0,4]；4: key B
        let model = fx.model(vec![
            NodeKey::Leaf("entry.world".to_string()),
            NodeKey::Nary("load.storage".to_string(), vec![0, 2]),
            NodeKey::Const(Word::from_u64(0xaa).0),
            NodeKey::Nary("load.storage".to_string(), vec![0, 4]),
            NodeKey::Const(Word::from_u64(0xbb).0),
            NodeKey::Param(0), // 5
        ]);
        let mut subst = Subst::new(&model);
        subst.reset_function();
        // 查询 id=3；reads 的 token=1（≠3），其经本帧代入的像的表值
        // 是 3（emitter 记录的形式读 → 解析值）→ 命中返回 (1, 3)。
        let mut a = args(vec![]);
        a.reads = vec![(1, 3)];
        let frame = subst.push_frame(0, 0, Some(a));
        assert_eq!(subst.preimage_match(3, frame), Some((1, 3)));
        // Param token 跳过：reads 只有 Param token 时不命中。
        let mut a = args(vec![2]);
        a.reads = vec![(5, 3)];
        let frame = subst.push_frame(0, 0, Some(a));
        assert_eq!(subst.preimage_match(3, frame), None);
    }

    /// exit 落点解析：deep 代入出 Const pc 查 exit_index；非 Const
    /// 目标或未索引的 pc 解析失败。
    #[test]
    fn exit_landing_resolution() {
        let mut fx = Fx::new();
        fx.definitions.push(Definition {
            pc: 100,
            code_id: 7,
            height: Some(3),
            entries: Vec::new(),
        });
        let model = fx.model(vec![
            NodeKey::Const(Word::from_u64(100).0), // 0
            NodeKey::Param(0),                     // 1
            NodeKey::Const(Word::from_u64(200).0), // 2
        ]);
        let mut subst = Subst::new(&model);
        subst.reset_function();
        assert_eq!(subst.exit_index.get(&(7, 100)), Some(&0));
        // 根帧无实参：target 原样；Const(100) 在 (code_id 7, pc 100) 命中。
        assert_eq!(
            subst.resolve_exit(0, &args(vec![]), 0, 7),
            Some((0, args(vec![])))
        );
        // 根帧无实参：Param 目标无法解析为 Const。
        assert_eq!(subst.resolve_exit(1, &args(vec![]), 0, 7), None);
        // Const 目标但 pc 未索引。
        assert_eq!(subst.resolve_exit(2, &args(vec![]), 0, 7), None);
    }

    /// 主循环：recur 标记的 Apply 不展开；非 recur 拼接定义体、步序
    /// 只给 Guard/Effect/Outcome；燃料耗尽后不再 push 新帧。
    #[test]
    fn recur_apply_not_expanded() {
        // recur = true：定义体不拼接，步序不占号。
        let fx = recur_fx(true);
        let model = fx.model(vec![NodeKey::Leaf("this".to_string())]);
        let mut subst = Subst::new(&model);
        let out = expand_function_fuel(&mut subst, 0, EXPAND_FUEL);
        assert_eq!(effect_kinds(&out), ["input_read", "call"]);
        assert_eq!(out[0].step(), 0);
        assert_eq!(out[1].step(), 1);

        // 非 recur：定义体拼接进来（步序连续占号）。
        let fx = recur_fx(false);
        let model = fx.model(vec![NodeKey::Leaf("this".to_string())]);
        let mut subst = Subst::new(&model);
        let out = expand_function_fuel(&mut subst, 0, EXPAND_FUEL);
        assert_eq!(effect_kinds(&out), ["input_read", "sload", "call"]);

        // 燃料耗尽：帧照 push 但定义体不展开（已发出的行保留）。
        let out = expand_function_fuel(&mut subst, 0, 0);
        assert_eq!(effect_kinds(&out), ["input_read", "call"]);
    }
}
