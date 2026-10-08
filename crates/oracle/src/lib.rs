//! 族 oracle + 三值判决（issue #7）：闭环管线⑤⑥段——到目标帧后在
//! 具体 trace 上按族求值证据表达式，三值判决（confirmed /
//! unreachable / inconclusive，fail-closed：无见证只降级不过滤），
//! 产出 poc.json（confirmed 一键重放）与 fuzz_report.json（覆盖 +
//! 判决 + 假设全量落盘）。
//!
//! # 三值判决真值表
//!
//! | reached | truncated | 族 oracle | verdict |
//! |---|---|---|---|
//! | false | false | — | Unreachable（预算耗尽，FP 候选降级） |
//! | false | true | — | Inconclusive（截断如实报） |
//! | true | true | — | Inconclusive（到场 run 被截断，见证不完整） |
//! | true | false | 证据成立 | Confirmed + Witness |
//! | true | false | 证据不成立 | Unreachable（到场但谓词不成立，reason 如实） |
//! | true | false | 族未实现 | Inconclusive（fail-closed 不硬判 confirmed） |
//!
//! # arbitrary_call 臂 3 oracle（memcmp 级）
//!
//! 在 target pc 处（或其后同帧内）的 RecordedCall 找第一条例证：
//! kind ∈ {CALL, CALLCODE, DELEGATECALL}（STATICCALL 不收）且
//! **input 是原始交易 calldata 的字节子串**（memmem 自实现，长度
//! ≥ 4 防 trivial 空匹配）。这就是"call 的 input 内存区包含
//! calldata 原文切片"的具体 trace 判定——裸转发的 memcpy 级证据。
//! target pc 本身不是 call 时（未来其他族），M0 自然落到其后第一
//! 条 RecordedCall。
//!
//! # 重放一致性
//!
//! poc.json 只带确定性参数（seed/max_runs/tx/prestate）。重放以
//! tx 重建输入为唯一种子：见证输入 run 1 即到场，EVM 执行确定性
//! 保证 verdict 逐字节一致（测试断言）。calldata → Input 重建是
//! 规范化切分（head = 完整 32B 块，tail = 余字节），序列化回
//! calldata 逐字节相同，执行等价。

pub mod eval;
mod family;
mod hit;
mod poc;
mod report;
pub mod verdict;

pub use family::{check_arbitrary_call, CallCheck, CheckInput};
pub use hit::{CallArm, GuardFact, Hit, SELECTOR_SENTINEL};
pub use poc::{
    build_poc, bytes_hex, calldata_of, hex_bytes, hex_u256, input_from_calldata, replay, Poc,
    PocDeployment, PocFork, PocTx, POC_FORMAT,
};
pub use report::{coverage, Budgets, Coverage, FuzzReport, Guidance, HitEntry, REPORT_FORMAT};
pub use verdict::Family;
pub use verdict::{judge, judge_with, HitReport, JudgeInput, Verdict, Witness};
