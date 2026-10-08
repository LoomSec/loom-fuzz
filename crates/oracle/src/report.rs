//! fuzz_report.json：会话级落盘报告（覆盖统计 + 判决 + 未触发假设，
//! 全部落盘可重放，docs/architecture.md 管线末端）。
//!
//! 覆盖口径（如实记录）：visited = 各 hit 报告所基于 trace 的
//! visited_pcs 并集；total = CFG 可执行指令 pc 数（fuzz crate 的
//! DistanceTable 访问器）。这不是"全 corpus 探索并集"——那需要
//! 会话保留每 run trace（体积与价值不匹配），M0 取报告口径并写明。

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::verdict::HitReport;

pub const REPORT_FORMAT: &str = "loom-fuzz-report@1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzReport {
    pub format: String,
    pub seed: u64,
    pub budgets: Budgets,
    /// per-hit 判决。
    pub hits: Vec<HitEntry>,
    pub coverage: Coverage,
    /// corpus 规模（管线各会话 corpus 去重后的输入总数）。
    pub corpus: usize,
    /// seed 编译器的全量未触发/不可解假设（跨 hit 去重保留序）。
    pub assumptions: Vec<String>,
    pub guidance: Guidance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budgets {
    pub max_runs: u64,
    pub time_budget_secs: u64,
    pub gas_per_tx: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub visited_pcs: usize,
    pub total_pcs: usize,
    pub percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Guidance {
    /// 制导会话命中所用 runs（各 hit 之和；未命中取 runs_completed）。
    pub guided_best_runs_total: u64,
    /// 纯随机基线到达所需 runs（未到达 = null）；基线关闭 = null。
    pub baseline_runs_to_reach: Option<u64>,
}

/// per-hit 判决行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitEntry {
    /// "0x%08x"；无 selector 入口为 sentinel。
    pub selector: String,
    pub step: u32,
    /// 命中帧 pc（target_pcs 首元；witness 存在时取实际命中的 pc）。
    pub pc: u32,
    pub verdict: String,
    pub reason: String,
    pub best_runs: u64,
}

impl HitEntry {
    pub fn from_report(r: &HitReport) -> Self {
        let pc = r
            .witness
            .as_ref()
            .map(|w| w.pc)
            .or_else(|| r.hit.target_pcs.first().copied())
            .unwrap_or(0);
        HitEntry {
            selector: selector_hex(r.hit.selector),
            step: r.hit.step,
            pc,
            verdict: r.verdict.to_string(),
            reason: r.reason.clone(),
            best_runs: 0, // 由管线填（会话报告在场）
        }
    }
}

pub(crate) fn selector_hex(selector: u32) -> String {
    format!("{selector:#010x}")
}

/// 覆盖统计：visited = 各 trace 并集；total 由调用方从 CFG 取。
pub fn coverage<'a>(traces: impl IntoIterator<Item = &'a HitReport>, total_pcs: usize) -> Coverage {
    let visited: BTreeSet<u32> = traces
        .into_iter()
        .flat_map(|r| r.witness.as_ref().map(|w| w.trace.visited_pcs.clone()))
        .flatten()
        .collect();
    let visited_n = visited.len();
    let percent = if total_pcs == 0 {
        0.0
    } else {
        visited_n as f64 / total_pcs as f64 * 100.0
    };
    Coverage {
        visited_pcs: visited_n,
        total_pcs,
        percent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hit::Hit;
    use crate::verdict::Verdict;

    fn report(pcs: &[u32]) -> HitReport {
        HitReport {
            verdict: Verdict::Unreachable,
            hit: Hit {
                selector: 0x90ce82d4,
                step: 19,
                target_pcs: pcs.to_vec(),
                evidence: String::new(),
                evidence_expr: None,
                arm: None,
                dominating_guards: Vec::new(),
            },
            witness: None,
            reason: String::new(),
        }
    }

    #[test]
    fn coverage_unions_and_percent() {
        let mut a = report(&[1, 2]);
        a.witness = Some(crate::verdict::Witness {
            evidence_value: None,
            input: loom_fuzz_fuzz::Input {
                selector: 0,
                caller: [0; 20],
                value: alloy_primitives::U256::ZERO,
                head: Vec::new(),
                tail: loom_fuzz_fuzz::Tail::Empty,
            },
            trace: loom_fuzz_fuzz::WitnessTrace {
                visited_pcs: vec![1, 2, 3],
                calls: Vec::new(),
                outcome: loom_fuzz_fuzz::OutcomeKind::Stop,
                gas_used: 0,
                truncated: false,
            },
            pc: 1,
            evidence_call: loom_fuzz_fuzz::RecordedCall {
                kind: "CALL".to_string(),
                target: [0; 20],
                value: alloy_primitives::U256::ZERO,
                input: Vec::new(),
                pc: None,
            },
        });
        let b = report(&[3, 4]);
        let c = coverage([&a, &b], 10);
        assert_eq!(c.visited_pcs, 3); // {1,2,3}；b 无 witness 不计
        assert_eq!(c.total_pcs, 10);
        assert!((c.percent - 30.0).abs() < f64::EPSILON);
        let empty = coverage([], 0);
        assert_eq!(empty.percent, 0.0);
    }

    #[test]
    fn selector_hex_format() {
        assert_eq!(selector_hex(0x90ce82d4), "0x90ce82d4");
        assert_eq!(selector_hex(u32::MAX), "0xffffffff");
    }
}
