//! 检测命中的内部表示（issue #7 自 `crates/cli` 迁入）。
//!
//! `Hit` / `GuardFact` / [`SELECTOR_SENTINEL`] 是闭环管线的只读数据
//! 类型：装载器（`crates/cli` 的模式 A/B）构造，oracle 判决与
//! poc/fuzz_report 落盘消费。放本 crate 是为了依赖方向无环：
//! cli（装载）→ oracle（判决），oracle 不回头依赖 cli。

use serde::{Deserialize, Serialize};

/// 无函数上下文的 selector 哨兵（fallback/receive 等无 selector 入口）。
pub const SELECTOR_SENTINEL: u32 = u32::MAX;

/// arbitrary_call 检测臂（mode B 检测时确定；mode A（loom CLI JSON）
/// 不携带结构化臂信息，留 None——oracle 按 evidence 形状与求值双路
/// 兜底判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallArm {
    /// 臂 1：目标可控（target 子树含 inputmark）。
    Arm1,
    /// 臂 3：裸转发（input 子树含原始 calldata 切片）。
    Arm3,
}

impl std::fmt::Display for CallArm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallArm::Arm1 => write!(f, "arm1"),
            CallArm::Arm3 => write!(f, "arm3"),
        }
    }
}

/// 一条检测命中的支配 guard 事实：`cond` 是守卫条件的规范化渲染
/// （loom 同款 S 表达式文本），`polarity` 是条件的真假支，`pc` 是
/// 产生该守卫的单字节码方程原点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardFact {
    pub cond: String,
    pub polarity: bool,
    pub pc: u32,
}

/// 一条检测命中：loom 检测的 `(函数, 帧, 证据表达式)` 三元组。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    /// 函数 selector；无函数上下文（fallback/receive 等）为
    /// [`SELECTOR_SENTINEL`] 哨兵。
    pub selector: u32,
    /// 命中效果的 loom 检测步序（效果步，装载行第二列）。
    pub step: u32,
    /// 命中效果的原点 pc 集合（xlayer 展开后 step → pc）。
    pub target_pcs: Vec<u32>,
    /// 证据表达式的规范化渲染文本（oracle 报告对象；模式 A 为 loom
    /// CLI JSON 原文，模式 B 为本仓库渲染器输出，golden 对拍一致）。
    pub evidence: String,
    /// 结构化证据表达式的节点 id（xlayer 统一 id 空间）+ 检测臂：
    /// mode B 装载时产出，臂 1 oracle 用求值器在 witness calldata 上
    /// 求值定罪；mode A（loom CLI JSON）无结构化 id，留 None。
    #[serde(default)]
    pub evidence_expr: Option<u32>,
    #[serde(default)]
    pub arm: Option<CallArm>,
    /// 支配 guard：步序早于命中步序、作用域与命中作用域
    /// prefix-comparable（ancestor-or-self 任一方向）的守卫，按步序
    /// 升序（seed 编译输入）。
    pub dominating_guards: Vec<GuardFact>,
}
