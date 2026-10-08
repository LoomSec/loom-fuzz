//! 输入双模式装载器（issue #3）：把 loom-evm 的检测命中归一为统一的
//! [`HitSet`] 内部表示。
//!
//! 两种装载器，同一表示：
//! - 模式 A（CLI 在位）：[`load_from_cli`] 子进程调用 loom-evm 发布的
//!   `loom` 二进制（`loom query <pack>... <shard> --json`），取
//!   `vuln_arbitrary` 谓词的 rows；契约 = loom CLI JSON 的最小稳定子集
//!   （见仓库 `docs/architecture.md`）。
//! - 模式 B（纯文件）：[`load_from_shard`] 只凭 `bytecode.hex` + `.lst`，
//!   内置 arbitrary_call 检测推导（不调用 loom）。
//!
//! 两种模式都经本仓库 [`loom_fuzz_xlayer`] 做 DEFS 路由展开（步序
//! → pc 映射、支配 guard 计算来源无感），保证闭环管线对装载来源无感。
//!
//! M0 模式 B 的已知语义折衷（与 loom packs 的近似，如实列出）：
//! - `whitelisted` 只实现 loom `whitelisted` 的部分臂（可信身份比对臂 +
//!   caller 键控 mapping 成员测试臂）；`registry_validated` 族
//!   （键控成员测试 / 独立状态绑定）未实现——对"注册表验证目标"类合约
//!   可能过报。golden 测试覆盖的 fixture 上与 loom 逐字段一致。

mod detect;
mod hitset;
mod load_cli;
mod load_shard;
mod render;

pub use detect::{detect_arbitrary_call, dominating_guards, RawHit};
pub use hitset::{GuardFact, Hit, HitSet, LoadError};
pub use load_cli::load_from_cli;
pub use load_shard::load_from_shard;
pub use render::{canon, render_node, RNode, View};
