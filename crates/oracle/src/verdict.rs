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

use alloy_primitives::U256;
use loom_fuzz_seed::Step;

use crate::family::{
    check_arbitrary_call, check_deputy_call, check_drain_forward, CallCheck, CheckInput,
};
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
    /// 到场调用序列（issue #35；单步 = 单元素序列，与旧单步
    /// witness 语义等价）。各步 = target + calldata + caller +
    /// value（seed crate 的 Step）。
    pub steps: Vec<Step>,
    /// 到场那次 run 的 witness trace。
    pub trace: WitnessTrace,
    /// 命中的目标帧 pc。
    pub pc: u32,
    /// oracle 定罪的那次 call（arbitrary_call 臂 1/臂 3 的例证；
    /// RecordedCall.step 标明它发生在序列的第几步）。
    pub evidence_call: RecordedCall,
    /// 臂 1 求值结果（hex 字）：evidence 表达式在 witness calldata 上
    /// 的具体值（臂 3 定罪 / 求值 ⊥ 时为 None）。poc.json 内嵌，
    /// replay 无 shard 时作求值承诺重放臂 1 判定。
    pub evidence_value: Option<String>,
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

/// 判决入口（无表达式视图 / 求值承诺的便捷形：臂 3 memcmp 或
/// fail-closed）。`calldatas` = 最佳序列各步的交易 calldata
/// （单步 = 单元素切片，见 [`judge_with`]）。
pub fn judge(hit: &Hit, session: &SessionReport, calldatas: &[Vec<u8>]) -> HitReport {
    judge_with(hit, session, calldatas, &JudgeInput::default())
}

/// 检测族标识 = [`HitFamily`]（装载产物的谓词维度；#20 起三族，
/// 族检查器见 family.rs）。
pub use crate::hit::HitFamily as Family;

/// 判决现场的可选输入：xlayer 表达式视图（臂 1 求值 / mode A 形状
/// 启发用）+ replay 的求值承诺。缺省两无 = 旧行为（臂 3 memcmp 或
/// expr 缺失时的 fail-closed）。
#[derive(Default)]
pub struct JudgeInput<'a> {
    pub view: Option<&'a dyn crate::eval::EvalViewDyn>,
    pub expected_evidence: Option<U256>,
}

/// 判决入口：`calldatas` = 最佳序列**各步的**原始交易 calldata
/// （selector + head + tail 拼接，与 revm TxEnv.data 逐字节一致；
/// 单步 = 单元素切片，与旧单参数形态等价）。族检查器按
/// RecordedCall.step 取对应步的 calldata 做子串/求值判定
/// （issue #35）。`input` 为表达式视图 / replay 求值承诺（见
/// [`JudgeInput`]）。
pub fn judge_with(
    hit: &Hit,
    session: &SessionReport,
    calldatas: &[Vec<u8>],
    ctx: &JudgeInput<'_>,
) -> HitReport {
    // 到场那次 run 被截断（燃料/步数，限到达步及之前——见执行器）：
    // 见证不完整——优先判 inconclusive，不跑族 oracle（trace 里的
    // call 可能根本没来得及派发）。
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

    // 到场：按族跑族检查器（family.rs）。
    let family = family_of(hit);
    let trace = session.trace.clone();
    let Some(best) = session.best_steps.clone() else {
        return HitReport {
            verdict: Verdict::Inconclusive,
            hit: hit.clone(),
            witness: None,
            reason: "到场但无 best_steps（契约外形态，如实报）".to_string(),
        };
    };
    let steps = best.steps;
    let check_input = CheckInput {
        view: ctx.view,
        expected_evidence: ctx.expected_evidence,
    };
    // 各族的"证据成立"判语文本（定罪时落 reason）。
    let (check, reason_ok) = match family {
        Family::ArbitraryCall => (
            check_arbitrary_call(hit, &trace.calls, calldatas, &check_input, trace.contract),
            String::new(), // 两臂各用自己的判语（历史行为不变）
        ),
        Family::ApprovalDrainDeputy => (
            check_deputy_call(hit, &trace.calls, calldatas, &check_input, trace.contract),
            "到场且 deputy_call 证据成立：call.target == cast160(evidence)（confused deputy：有 caller 守卫但目标仍由调用者控制）".to_string(),
        ),
        Family::ApprovalDrainForward => (
            check_drain_forward(hit, &trace.calls, calldatas, trace.contract),
            "到场且 drain_forward 证据成立：call input 含 calldata 派生切片（宽松 memmem：子串或 32B 头词覆盖）且整体不与 caller 绑定".to_string(),
        ),
    };
    // revert 步如实标注（inconclusive-step 的诚实形态：状态未变，
    // 序列续跑；归因经 revert 守卫反馈）。附加到定罪判语后。
    let revert_note = {
        let reverted: Vec<usize> = trace
            .step_outcomes
            .iter()
            .enumerate()
            .filter(|(_, o)| **o == loom_fuzz_fuzz::OutcomeKind::Revert)
            .map(|(i, _)| i + 1)
            .collect();
        if reverted.is_empty() {
            String::new()
        } else {
            format!("；序列 revert 步如实记录：第 {reverted:?} 步（状态未变）")
        }
    };
    match check {
        CallCheck::ConvictedArm3(evidence_call) => {
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
                    steps,
                    trace,
                    pc,
                    evidence_call,
                    evidence_value: None,
                }),
                reason: format!(
                    "到场且臂 3 证据成立：call input 是原始 calldata 的子串{revert_note}"
                ),
            }
        }
        CallCheck::ConvictedArm1(evidence_call) => {
            let pc = hit
                .target_pcs
                .iter()
                .copied()
                .find(|pc| trace.visited_pcs.contains(pc))
                .or(evidence_call.pc)
                .unwrap_or(0);
            // 臂 1 / deputy_call：求值结果留证（view 在场即重算；replay
            // 用内嵌承诺）。evidence 在**定罪 call 那一步**的 calldata
            // 上求值。
            let step_calldata = calldatas
                .get(evidence_call.step as usize)
                .cloned()
                .unwrap_or_default();
            let evidence_value = {
                let expr = hit.evidence_expr;
                match (ctx.view, expr) {
                    (Some(view), Some(e)) => crate::eval::eval_word(
                        view,
                        e,
                        &crate::eval::EvalEnv::new(step_calldata, default_this()),
                    ),
                    _ => ctx.expected_evidence,
                }
            }
            .map(crate::poc::u256_hex);
            HitReport {
                verdict: Verdict::Confirmed,
                hit: hit.clone(),
                witness: Some(Witness {
                    steps,
                    trace,
                    pc,
                    evidence_call,
                    evidence_value,
                }),
                reason: if reason_ok.is_empty() {
                    format!(
                        "到场且臂 1 证据成立：call.target == cast160(evidence)（目标可控）{revert_note}"
                    )
                } else {
                    format!("{reason_ok}{revert_note}")
                },
            }
        }
        CallCheck::ConvictedDrain(evidence_call) => {
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
                    steps,
                    trace,
                    pc,
                    evidence_call,
                    evidence_value: None,
                }),
                reason: format!("{reason_ok}{revert_note}"),
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

/// 与执行器/pocgen 同一约定：固定路由器地址（loom-fuzz 管线的
/// CONTRACT_ADDRESS）。
fn default_this() -> U256 {
    U256::from_be_bytes({
        let mut w = [0u8; 32];
        w[19] = 0x22;
        w
    })
}

/// 族分发：按命中谓词走对应族检查器（family.rs）。
pub fn family_of(hit: &Hit) -> Family {
    hit.family
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_fuzz_fuzz::OutcomeKind;
    use loom_fuzz_seed::TxSequence;

    fn session(reached: bool, truncated: bool) -> SessionReport {
        SessionReport {
            reached,
            best_runs: 1,
            best_steps: reached.then(|| {
                TxSequence::single(
                    [0x22; 20],
                    loom_fuzz_seed::Input {
                        selector: 0x90ce82d4,
                        caller: [0x33; 20],
                        value: alloy_primitives::U256::ZERO,
                        head: Vec::new(),
                        tail: loom_fuzz_seed::Tail::Empty,
                    },
                )
            }),
            trace: WitnessTrace {
                contract: [0x22; 20],
                visited_pcs: if reached { vec![384] } else { vec![0] },
                calls: if reached {
                    vec![RecordedCall {
                        kind: "CALL".to_string(),
                        from: [0x22; 20],
                        step: 0,
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
                deployments: Vec::new(),
                step_outcomes: if reached {
                    vec![OutcomeKind::Stop]
                } else {
                    Vec::new()
                },
            },
            truncated,
            runs_completed: 1,
            baseline_runs_to_reach: None,
            corpus_size: 0,
        }
    }

    fn hit() -> Hit {
        Hit {
            family: Default::default(),
            selector: 0x90ce82d4,
            step: 19,
            target_pcs: vec![384],
            evidence: String::new(),
            evidence_expr: None,
            arm: None,
            dominating_guards: Vec::new(),
        }
    }

    const TX: &[u8] = b"\x90\xce\x82\xd4aaaabcd";

    #[test]
    fn truth_table_unreachable() {
        let r = judge(&hit(), &session(false, false), &[TX.to_vec()]);
        assert_eq!(r.verdict, Verdict::Unreachable);
        assert!(r.reason.contains("预算耗尽"));
        assert!(r.witness.is_none());
    }

    #[test]
    fn truth_table_inconclusive_on_truncation() {
        let r = judge(&hit(), &session(false, true), &[TX.to_vec()]);
        assert_eq!(r.verdict, Verdict::Inconclusive);
        assert!(r.reason.contains("截断"));
    }

    #[test]
    fn truth_table_confirmed() {
        let r = judge(&hit(), &session(true, false), &[TX.to_vec()]);
        assert_eq!(r.verdict, Verdict::Confirmed);
        let w = r.witness.expect("confirmed 必有 witness");
        assert_eq!(w.pc, 384);
        assert_eq!(w.evidence_call.input, b"abcd");
    }

    #[test]
    fn truth_table_reached_but_truncated_is_inconclusive() {
        let r = judge(&hit(), &session(true, true), &[TX.to_vec()]);
        assert_eq!(r.verdict, Verdict::Inconclusive);
        assert!(r.reason.contains("被截断"));
    }

    #[test]
    fn truth_table_reached_but_rejected_is_unreachable() {
        // 到场但 call input 不是 calldata 子串 → Unreachable（不硬判）。
        let mut s = session(true, false);
        s.trace.calls[0].input = b"zzzz".to_vec();
        let r = judge(&hit(), &s, &[TX.to_vec()]);
        assert_eq!(r.verdict, Verdict::Unreachable);
        assert!(r.reason.contains("证据谓词不成立"));
    }
}
