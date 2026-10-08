//! 三值判决（issue #7，fail-closed：无见证只降级不过滤）。
//!
//! 判决真值表（`SessionReport` × 族 oracle）：
//!
//! | reached | truncated | 族 oracle | verdict |
//! |---|---|---|---|
//! | false | false | — | **Unreachable**（预算耗尽，FP 候选降级） |
//! | false | true | — | **Inconclusive**（燃料/步数截断，如实报） |
//! | true | * | 臂 3 成立 | **Confirmed** + Witness |
//! | true | * | 不成立 | **Unreachable**（到场但证据谓词不成立，reason 如实记） |
//!
//! 未知族（M0 除 arbitrary_call 外的所有族）：到场均报
//! Unreachable-family-not-implemented？——不。fail-closed 的最稳形态：
//! 未知族**不判 confirmed**，判 Inconclusive 并注明族未实现（既不
//! 消灭也不确认）。到场未知族 = Inconclusive；未到场仍按上表前
//! 两行（与族无关）。

use loom_fuzz_fuzz::{RecordedCall, SessionReport, WitnessTrace};
use serde::{Deserialize, Serialize};

use loom_fuzz_seed::Input;

use crate::family::{check_arbitrary_call, CallCheck};
use crate::hit::Hit;

/// 三值判决。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Confirmed,
    Unreachable,
    Inconclusive,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Confirmed => write!(f, "confirmed"),
            Verdict::Unreachable => write!(f, "unreachable"),
            Verdict::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// 见证：confirmed 时在场证据的具体形态（poc.json 复用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    /// 到场输入（seed crate 的 Input，serde 已有）。
    pub input: Input,
    /// 到场那次 run 的 witness trace。
    pub trace: WitnessTrace,
    /// 命中的目标帧 pc。
    pub pc: u32,
    /// oracle 定罪的那次 call（arbitrary_call 臂 3 的例证）。
    pub evidence_call: RecordedCall,
}

/// 单条命中的判决报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitReport {
    pub verdict: Verdict,
    /// 原命中。
    pub hit: Hit,
    /// confirmed 时有。
    pub witness: Option<Witness>,
    /// 判决依据（unreachable：预算耗尽 / 证据谓词不成立；inconclusive：
    /// 截断燃料/步数）。
    pub reason: String,
}

/// 检测族标识（M0：按 loom 谓词名分发；本仓库装载产物只有
/// arbitrary_call 一族的推导，其余形态 future）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    ArbitraryCall,
    /// 族未知 / 未实现：fail-closed 不判 confirmed。
    Unknown,
}

/// 判决入口：`tx_calldata` = 触发该会话的最佳输入的原始交易
/// calldata（selector + head + tail 拼接，与 revm TxEnv.data 逐
/// 字节一致）。
pub fn judge(hit: &Hit, session: &SessionReport, tx_calldata: &[u8]) -> HitReport {
    // 到场那次 run 被截断（燃料/步数）：见证不完整——优先判
    // inconclusive，不跑族 oracle（trace 里的 call 可能根本没来得及
    // 派发）。
    if session.reached && session.truncated {
        return HitReport {
            verdict: Verdict::Inconclusive,
            hit: hit.clone(),
            witness: None,
            reason: "到场 run 被截断（燃料/步数），见证不完整（inconclusive，不硬判）".to_string(),
        };
    }
    if !session.reached {
        let reason = if session.truncated {
            "截断：燃料/步数耗尽，未到达目标帧（inconclusive，不硬判）".to_string()
        } else {
            format!(
                "预算耗尽未到达目标帧（{} runs，truncated=false）",
                session.runs_completed
            )
        };
        return HitReport {
            verdict: if session.truncated {
                Verdict::Inconclusive
            } else {
                Verdict::Unreachable
            },
            hit: hit.clone(),
            witness: None,
            reason,
        };
    }

    // 到场：跑族 oracle。
    let family = family_of(hit);
    if family != Family::ArbitraryCall {
        return HitReport {
            verdict: Verdict::Inconclusive,
            hit: hit.clone(),
            witness: None,
            reason: "到场但族检查器未实现（fail-closed：不判 confirmed）".to_string(),
        };
    }
    let trace = session.trace.clone();
    let Some(input) = session.best_input.clone() else {
        return HitReport {
            verdict: Verdict::Inconclusive,
            hit: hit.clone(),
            witness: None,
            reason: "到场但无 best_input（契约外形态，如实报）".to_string(),
        };
    };
    match check_arbitrary_call(hit, &trace.calls, tx_calldata) {
        CallCheck::Convicted(evidence_call) => {
            let pc = hit
                .target_pcs
                .iter()
                .copied()
                .find(|pc| trace.visited_pcs.contains(pc))
                .or(evidence_call.pc)
                .unwrap_or(0);
            HitReport {
                verdict: Verdict::Confirmed,
                hit: hit.clone(),
                witness: Some(Witness {
                    input,
                    trace,
                    pc,
                    evidence_call,
                }),
                reason: "到场且臂 3 证据成立：call input 是原始 calldata 的子串".to_string(),
            }
        }
        CallCheck::Rejected(reason) => HitReport {
            verdict: Verdict::Unreachable,
            hit: hit.clone(),
            witness: None,
            reason: format!("到场但证据谓词不成立：{reason}"),
        },
    }
}

/// 族分发（M0：全部按 arbitrary_call 处理——装载器的检测推导只有
/// 这一族；谓词名维度随 #9 多族推广再启用）。
pub fn family_of(_hit: &Hit) -> Family {
    Family::ArbitraryCall
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_fuzz_fuzz::OutcomeKind;

    fn session(reached: bool, truncated: bool) -> SessionReport {
        SessionReport {
            reached,
            best_runs: 1,
            best_input: reached.then(|| Input {
                selector: 0x90ce82d4,
                caller: [0x33; 20],
                value: alloy_primitives::U256::ZERO,
                head: Vec::new(),
                tail: loom_fuzz_seed::Tail::Empty,
            }),
            trace: WitnessTrace {
                visited_pcs: if reached { vec![384] } else { vec![0] },
                calls: if reached {
                    vec![RecordedCall {
                        kind: "CALL".to_string(),
                        target: [0x7d; 20],
                        value: alloy_primitives::U256::ZERO,
                        input: b"abcd".to_vec(),
                        pc: Some(384),
                    }]
                } else {
                    Vec::new()
                },
                outcome: OutcomeKind::Stop,
                gas_used: 1,
                truncated,
            },
            truncated,
            runs_completed: 1,
            baseline_runs_to_reach: None,
            corpus_size: 0,
        }
    }

    fn hit() -> Hit {
        Hit {
            selector: 0x90ce82d4,
            step: 19,
            target_pcs: vec![384],
            evidence: String::new(),
            dominating_guards: Vec::new(),
        }
    }

    const TX: &[u8] = b"\x90\xce\x82\xd4aaaabcd";

    #[test]
    fn truth_table_unreachable() {
        let r = judge(&hit(), &session(false, false), TX);
        assert_eq!(r.verdict, Verdict::Unreachable);
        assert!(r.reason.contains("预算耗尽"));
        assert!(r.witness.is_none());
    }

    #[test]
    fn truth_table_inconclusive_on_truncation() {
        let r = judge(&hit(), &session(false, true), TX);
        assert_eq!(r.verdict, Verdict::Inconclusive);
        assert!(r.reason.contains("截断"));
    }

    #[test]
    fn truth_table_confirmed() {
        let r = judge(&hit(), &session(true, false), TX);
        assert_eq!(r.verdict, Verdict::Confirmed);
        let w = r.witness.expect("confirmed 必有 witness");
        assert_eq!(w.pc, 384);
        assert_eq!(w.evidence_call.input, b"abcd");
    }

    #[test]
    fn truth_table_reached_but_truncated_is_inconclusive() {
        let r = judge(&hit(), &session(true, true), TX);
        assert_eq!(r.verdict, Verdict::Inconclusive);
        assert!(r.reason.contains("被截断"));
    }

    #[test]
    fn truth_table_reached_but_rejected_is_unreachable() {
        // 到场但 call input 不是 calldata 子串 → Unreachable（不硬判）。
        let mut s = session(true, false);
        s.trace.calls[0].input = b"zzzz".to_vec();
        let r = judge(&hit(), &s, TX);
        assert_eq!(r.verdict, Verdict::Unreachable);
        assert!(r.reason.contains("证据谓词不成立"));
    }
}
