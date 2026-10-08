//! seed 编译器（issue #4）：把命中帧的支配 guard 表达式机械反解为
//! fuzz 种子输入。静态知道的一切（selector 头、guard 右端常量、边界值
//! c±1、caller、存储槽）进场时就带着；fuzz 只搜静态不知道的部分
//! （存储 prestate、外部响应——显式标 [`FreeVar`] 进变异器搜索空间）。
//!
//! 输入是 xlayer 展开流的**结构化表达式节点**（不解析渲染文本）：
//! 支配 guard 的判定与 `crates/cli/src/detect.rs` 同源
//! （step < hit.step 且 scope prefix-comparable），此处按同一语义
//! 从 `Xlayer` 展开流重新派生（`Hit` 只存渲染文本，不存表达式 id，
//! guard 求解必须回到节点层）。
//!
//! 编译规则（对每个支配 guard 的 cond 子树逐比较节点求解，布尔连接词
//! 结构忽略、各比较独立合取——近似，如实记录在 assumptions）：
//! - `Cmp("==", CalldataWord(off), Const c)`（polarity=true，Cast 壳
//!   剥掉）→ 固定 calldata 字：off≥4 且 32 字节对齐才落槽
//!   `slot = (off-4)/32`，否则记 assumption。
//! - `Cmp("==", Env("msg.sender"), Const a)` / `Cmp("==", Leaf("this"),
//!   Const a)`（polarity=true）→ caller。
//! - `Cmp("==", storage(this, Const slot), Const v)` → 进不了 calldata：
//!   记 [`FreeVar`]（存储 prestate 提示 slot/value）+ assumption。
//! - `<`/`>`/`s<`/`s>` 家族（含 `<=`/`>=`，Const 在左的镜像同收）→
//!   值字典收 c-1/c/c+1（截断到 U256 范围），非 Const 端是 calldata
//!   字时为每个边界值生成一个种子变体（其他槽取默认）。
//! - mapping 派生、registry 成员测试、callee 响应等不可解形态 →
//!   assumption 如实记录，留搜索空间。
//! - 多约束组合：selector + 默认零参为基座，各可解 calldata 约束合取
//!   进基座；变体数超 [`MAX_SEEDS`] 按字典序截断并记 assumption。
//! - 无可解约束：退化为 selector + 全零 head + Empty tail（如实，不编造）。
//!
//! 已知未覆盖（如实列出，落 assumptions 或本注释）：
//! - 假支（polarity=false）等值/不等值约束不反解（留 assumption）。
//! - 有符号比较（`s<` 家族）的 c±1 按无符号截断，不做符号域换算。
//! - `msg.value` 约束、动态 calldata 尾（`Tail::Bytes`/`Tail::Free`）
//!   无规则触发——尾部目前恒为 `Empty`。
//! - 白名单/registry 常量：shard 无此事实段，值字典只收 guard/证据
//!   常量与字节码 PUSH 立即数。

mod compile;
mod node;

use serde::{Deserialize, Serialize};

pub use compile::{compile, locate};
pub use node::{canon, render_node, Node, View};

/// 种子集上限：变体数超此后按字典序截断并记 assumption。
pub const MAX_SEEDS: usize = 64;

/// 一条命中的只读视图：seed 编译所需的全部 `Hit` 列。`crates/cli` 的
/// `Hit` 与本仓库外的装载器实现本 trait 即可作为 [`Target`] 输入
/// （ impl 放调用方，避免 seed → cli 的依赖环：cli 将是管线的串联者）。
pub trait HitView {
    /// 函数 selector（无函数上下文为 `u32::MAX` 哨兵）。
    fn selector(&self) -> u32;
    /// 命中效果的原点 pc 集合（在 `func` 展开流中定位命中步序）。
    fn target_pcs(&self) -> &[u32];
    /// 证据表达式的规范化渲染文本（常量收割用；`Hit` 不存表达式 id）。
    fn evidence(&self) -> &str;
}

/// 编译目标：一条命中 + 所在函数下标（调用方经 [`locate`] 或自行
/// 从 selector 定位）。
pub struct Target<'a> {
    pub hit: &'a dyn HitView,
    pub func: usize,
}

/// 一条 fuzz 种子输入。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// calldata 头：4 字节函数选择子。
    pub selector: u32,
    /// `msg.sender`。
    pub caller: [u8; 20],
    /// 随附的 `msg.value`。
    pub value: alloy_primitives::U256,
    /// 定长参数槽（word0 = selector 后第一槽，32 字节对齐）。
    pub head: Vec<[u8; 32]>,
    /// 动态 calldata 尾。
    pub tail: Tail,
}

impl Input {
    /// 字典序排序键：selector / caller / value / head / tail 依次
    /// 拼成字节串（截断与去重的唯一依据，确定性）。
    fn sort_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + 20 + 32 + self.head.len() * 32 + 8);
        key.extend_from_slice(&self.selector.to_be_bytes());
        key.extend_from_slice(&self.caller);
        key.extend_from_slice(&self.value.to_be_bytes::<32>());
        for word in &self.head {
            key.extend_from_slice(word);
        }
        match &self.tail {
            Tail::Empty => key.push(0),
            Tail::Bytes(b) => {
                key.push(1);
                key.extend_from_slice(&(b.len() as u64).to_be_bytes());
                key.extend_from_slice(b);
            }
            Tail::Free => key.push(2),
        }
        key
    }
}

/// 动态 calldata 尾：`Empty` = 无尾；`Bytes` = 具体字节串；
/// `Free` = 显式标 free 的未知量（进变异器搜索空间）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tail {
    Empty,
    Bytes(Vec<u8>),
    Free,
}

/// 值字典：guard 常量 ∪ 证据常量 ∪ 字节码 PUSH 立即数（∪ 白名单/
/// registry 常量，shard 无此事实段故缺省）——去重升序，变异器的
/// 常量池来源。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueDictionary {
    pub words: Vec<alloy_primitives::U256>,
}

/// 显式标 free 的未知量（存储根、外部响应等）：不进种子，进变异器
/// 搜索空间。`hint` 是静态已知的提示值（如存储等值约束要求的
/// prestate 值）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeVar {
    pub what: String,
    pub hint: Option<alloy_primitives::U256>,
}

/// seed 编译产物：种子集 + 值字典 + free 未知量 + 未触发/不可解
/// 假设（全部如实记录，落盘进 fuzz_report）。全部 serde，poc.json
/// 直接复用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedOutput {
    /// 种子集（去重、字典序、上限 [`MAX_SEEDS`]）。
    pub inputs: Vec<Input>,
    pub dict: ValueDictionary,
    pub free: Vec<FreeVar>,
    /// 未触发/不可解假设，全部如实记录。
    pub assumptions: Vec<String>,
}
