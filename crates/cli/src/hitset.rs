//! 统一内部表示 `HitSet` 与 typed 装载错误。
//!
//! `HitSet` 是闭环管线的唯一入口表示：每条命中携带函数 selector
//! （无函数上下文为 `u32::MAX` 哨兵）、经 xlayer 展开后的原点 pc
//! 集合、证据表达式的规范化渲染文本，以及支配 guard 事实（seed 编译
//! 输入）。两种装载器（`load_from_cli` / `load_from_shard`）产出
//! 逐字段相等的 `HitSet`。
//!
//! `Hit` / `GuardFact` / `SELECTOR_SENTINEL` 类型本体在
//! [`loom_fuzz_oracle`]（判决 crate），此处 re-export 保持既有路径
//! 可用；依赖方向 cli（装载）→ oracle（判决），无环。

use std::fmt;
use std::path::PathBuf;

pub use loom_fuzz_oracle::{GuardFact, Hit, SELECTOR_SENTINEL};

/// 装载产物：运行时字节码 + 检测命中集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HitSet {
    pub code: Vec<u8>,
    pub hits: Vec<Hit>,
}

/// 装载失败的 typed 错误。一切异常路径都报 `Err`（fail-closed），
/// 不静默降级。
#[derive(Debug)]
pub enum LoadError {
    /// 文件系统层面打不开/读不到（code_hex / shard / pack）。
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// shard 解析失败。
    Shard(loom_fuzz_shard::Error),
    /// bytecode.hex 不是合法 hex 文本。
    CodeHexInvalid { path: PathBuf, reason: String },
    /// loom 二进制无法执行（不存在 / 无权限）。
    LoomSpawn {
        path: PathBuf,
        source: std::io::Error,
    },
    /// loom 非零退出：`stderr` 为摘要（截断到 4 KiB）。
    LoomExit {
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// loom JSON 输出缺字段 / 形态不符：`reason` 指明缺什么。
    LoomJson { reason: String },
    /// loom 报告结果截断（`truncated=true` 或 rows 少于 total_rows）：
    /// 装载结果不可信，fail-closed 报错。
    LoomTruncated {
        predicate: String,
        total_rows: usize,
        served_rows: usize,
    },
    /// 存在未满足的 oracle demand（结果可能不完整），fail-closed 报错。
    LoomUnservedDemand { count: usize },
    /// loom Func 列渲染形态无法识别（既不是 `0x%08x` 也不是
    /// `f{local}@c{contract}`）——契约外输入，fail-closed。
    FuncUnrecognized { cell: String },
    /// 行形态不符：不是三列字符串 [func, step, t]。
    RowMalformed { predicate: String, reason: String },
    /// row 的 step 不是十进制数字字符串。
    StepMalformed { cell: String },
    /// row 的 selector 在 shard 函数表中查无此函数。
    SelectorNotFound { selector: u32 },
    /// row 指向的函数下标在 shard 函数表之外。
    FunctionIndexOutOfRange { index: usize, functions: usize },
    /// step 在函数展开流中找不到（或不是 Effect 条目）。
    StepNotFound { selector: u32, step: u32 },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io { path, source } => write!(f, "无法读取 {}: {source}", path.display()),
            LoadError::Shard(e) => write!(f, "shard 解析失败: {e}"),
            LoadError::CodeHexInvalid { path, reason } => {
                write!(f, "bytecode.hex 非法 ({}): {reason}", path.display())
            }
            LoadError::LoomSpawn { path, source } => {
                write!(f, "无法执行 loom 二进制 {}: {source}", path.display())
            }
            LoadError::LoomExit { status, stderr } => {
                write!(f, "loom 非零退出 ({status}): {stderr}")
            }
            LoadError::LoomJson { reason } => write!(f, "loom JSON 输出缺字段: {reason}"),
            LoadError::LoomTruncated { predicate, total_rows, served_rows } => write!(
                f,
                "loom 结果截断（{predicate}: total_rows={total_rows} > served={served_rows}），fail-closed"
            ),
            LoadError::LoomUnservedDemand { count } => {
                write!(f, "loom 有 {count} 个未满足 oracle demand，结果不完整，fail-closed")
            }
            LoadError::FuncUnrecognized { cell } => {
                write!(f, "loom Func 列渲染形态无法识别: {cell:?}")
            }
            LoadError::RowMalformed { predicate, reason } => {
                write!(f, "loom {predicate} 行形态不符: {reason}")
            }
            LoadError::StepMalformed { cell } => {
                write!(f, "loom step 列不是十进制数字: {cell:?}")
            }
            LoadError::SelectorNotFound { selector } => {
                write!(f, "shard 函数表中无 selector 0x{selector:08x}")
            }
            LoadError::FunctionIndexOutOfRange { index, functions } => {
                write!(f, "函数下标 {index} 越界（共 {functions} 个函数）")
            }
            LoadError::StepNotFound { selector, step } => {
                write!(f, "selector 0x{selector:08x} 的展开流中无步序 {step} 的效果")
            }
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Io { source, .. } | LoadError::LoomSpawn { source, .. } => Some(source),
            LoadError::Shard(e) => Some(e),
            _ => None,
        }
    }
}

impl From<loom_fuzz_shard::Error> for LoadError {
    fn from(e: loom_fuzz_shard::Error) -> Self {
        LoadError::Shard(e)
    }
}
