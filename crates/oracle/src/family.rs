//! 族 oracle：到目标帧后在具体 trace 上求值证据表达式（按族定制
//! 检查器，docs/architecture.md 管线⑤）。M0 只实现 arbitrary_call
//! 族（臂 3 裸转发 memcmp 判定）；其他族 future——判决入口按族
//! 分发，未知族如实报 inconclusive-able 的 "未实现"（fail-closed
//! 不硬判 confirmed）。

use loom_fuzz_fuzz::RecordedCall;

use crate::eval;
use crate::hit::Hit;

/// arbitrary_call 判定结果（注明所用手臂）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallCheck {
    /// 臂 3 定罪：call input 是原始 calldata 的子串（裸转发）。
    ConvictedArm3(RecordedCall),
    /// 臂 1 定罪：call.target == cast160(evidence)（目标可控）。
    ConvictedArm1(RecordedCall),
    /// 未成立：`reason` 如实说明（到场但证据谓词不成立）。
    Rejected(String),
}

impl CallCheck {
    /// 定罪的那次 call（两臂同形时按判决方取）。
    pub fn call(&self) -> Option<&RecordedCall> {
        match self {
            CallCheck::ConvictedArm3(c) | CallCheck::ConvictedArm1(c) => Some(c),
            CallCheck::Rejected(_) => None,
        }
    }
}

/// memmem：haystack 中找 needle（自实现，无依赖；规模小，
/// O(n·m) 足够）。空 needle 恒命中——调用方负责长度下限。
pub(crate) fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// 单条 call 的 arbitrary_call 臂 3 证据判定：
/// - kind ∈ {CALL, CALLCODE, DELEGATECALL}（STATICCALL 不收——
///   static 上下文不能传 value，语义上不是任意调用漏洞面）；
/// - input 是**原始交易 calldata 的字节子串**（memcpy 级"裸转发"：
///   转发器原样吐出 attacker 控制的 calldata 切片）；
/// - input 长度 ≥ 4（防 trivial 空/短匹配）。
fn arm3_check(call: &RecordedCall, tx_calldata: &[u8]) -> bool {
    matches!(call.kind.as_str(), "CALL" | "CALLCODE" | "DELEGATECALL")
        && call.input.len() >= 4
        && memmem(tx_calldata, &call.input)
}

/// arbitrary_call 族 oracle（M0 = 臂 1 求值 + 臂 3 memcmp）。
///
/// 定罪路径（reason 注明所用手臂）：
/// - **臂 3（裸转发）**：call input 是原始交易 calldata 的字节子串
///   （memcmp 级，≥4B 防 trivial 匹配）。
/// - **臂 1（目标可控）**：call.target（低位 160）== 证据表达式在
///   witness calldata 上的求值结果（低位 160）——
///   `cast160(calldata_word(0x4))` 型证据的具体 trace 判定。
///
/// 手臂来源：Hit.arm（mode B 检测时确定）。arm 缺失（mode A）时
/// 按 evidence 形状启发（子树含 b_calldata_slice → 臂 3 优先），
/// 两路都试，先中先用。臂 1 求值需 xlayer 句柄；replay 模式（无
/// shard）用 poc 内嵌的 evidence_value 作求值承诺重放判定
/// （`expected_evidence`）。
pub struct CheckInput<'a> {
    /// 表达式节点视图（judge 现场）；None = replay（无 shard）。
    pub view: Option<&'a dyn eval::EvalViewDyn>,
    /// replay 模式：poc.json 内嵌的求值结果承诺（hex 解析后的字）。
    pub expected_evidence: Option<alloy_primitives::U256>,
}

/// 判定入口：`input.arm` 选择/兜底手臂，跑对应证据检查。
pub fn check_arbitrary_call(
    hit: &Hit,
    calls: &[RecordedCall],
    tx_calldata: &[u8],
    input: &CheckInput<'_>,
) -> CallCheck {
    let Some(min_pc) = hit.target_pcs.iter().min().copied() else {
        return CallCheck::Rejected("命中无 target pc（契约外输入）".to_string());
    };
    let candidates: Vec<&RecordedCall> = calls
        .iter()
        .filter(|c| c.pc.is_some_and(|pc| pc >= min_pc))
        .collect();
    if candidates.is_empty() {
        return CallCheck::Rejected(format!(
            "target pc {min_pc} 之后无 CALL 族效果（trace.calls 为空或都在 pc 之前）"
        ));
    }

    // 手臂：显式（mode B）> 形状启发（mode A）。
    let arm = hit.arm.or_else(|| shape_arm(hit, input));
    let mut arm3_note = None;
    let mut arm1_note = None;

    // 臂 3：memcmp（裸转发）。
    if !matches!(arm, Some(crate::CallArm::Arm1)) {
        for call in &candidates {
            if arm3_check(call, tx_calldata) {
                arm3_note = Some((*call).clone());
                break;
            }
        }
    }

    // 臂 1：target == cast160(evidence)。
    if !matches!(arm, Some(crate::CallArm::Arm3)) {
        arm1_note = arm1_check(hit, &candidates, tx_calldata, input);
    }

    match (arm3_note, arm1_note) {
        (Some(call), _) => CallCheck::ConvictedArm3(call),
        (None, Some(call)) => CallCheck::ConvictedArm1(call),
        (None, None) => {
            let kinds: Vec<&str> = candidates.iter().map(|c| c.kind.as_str()).collect();
            let why = match (arm, hit.evidence_expr, input.view.is_some()) {
                (Some(crate::CallArm::Arm1), _, false) if input.expected_evidence.is_none() => {
                    "臂 1 求值不可用（无表达式视图且无 poc 内嵌值）".to_string()
                }
                _ => "均不满足".to_string(),
            };
            CallCheck::Rejected(format!(
                "target pc {min_pc} 后 {} 条 call（kinds={kinds:?}）{why}：臂 3 input 非 calldata 子串；臂 1 target ≠ cast160(evidence)",
                candidates.len()
            ))
        }
    }
}

/// 臂 1 求值定罪：逐候选 call 比 target 低位 160。
fn arm1_check(
    hit: &Hit,
    candidates: &[&RecordedCall],
    tx_calldata: &[u8],
    input: &CheckInput<'_>,
) -> Option<RecordedCall> {
    // view 在场：求值器算（需结构化 expr id）；replay 无视图：用
    // poc 内嵌的求值承诺（expr id 可缺——承诺自带）。
    let value = if let Some(view) = input.view {
        let expr = hit.evidence_expr?;
        eval::eval_word(
            view,
            expr,
            &eval::EvalEnv::new(tx_calldata.to_vec(), default_this()),
        )?
    } else {
        input.expected_evidence?
    };
    let low160 =
        value & ((alloy_primitives::U256::from(1u64) << 160) - alloy_primitives::U256::from(1u64));
    candidates.iter().find_map(|call| {
        let mut target_bytes = [0u8; 32];
        target_bytes[12..].copy_from_slice(&call.target);
        (alloy_primitives::U256::from_be_bytes(target_bytes) == low160).then(|| (*call).clone())
    })
}

/// 与执行器同一约定：固定路由器地址（loom-fuzz 管线的 CONTRACT_ADDRESS）。
fn default_this() -> alloy_primitives::U256 {
    alloy_primitives::U256::from_be_bytes({
        let mut w = [0u8; 32];
        w[19] = 0x22;
        w
    })
}

/// 形状启发（mode A 兜底）：evidence 子树含 b_calldata_slice → 臂 3。
fn shape_arm(hit: &Hit, input: &CheckInput<'_>) -> Option<crate::CallArm> {
    let view = input.view?;
    let expr = hit.evidence_expr?;
    match eval::subtree_has_op(view, expr, "b_calldata_slice") {
        Some(true) => Some(crate::CallArm::Arm3),
        Some(false) => Some(crate::CallArm::Arm1),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn call(kind: &str, input: Vec<u8>, pc: Option<u32>) -> RecordedCall {
        RecordedCall {
            kind: kind.to_string(),
            target: [0x11; 20],
            value: U256::ZERO,
            input,
            pc,
        }
    }

    fn hit(pcs: &[u32]) -> Hit {
        Hit {
            selector: 0x90ce82d4,
            step: 19,
            target_pcs: pcs.to_vec(),
            evidence: "cast160(calldata_word(0x4))".to_string(),
            evidence_expr: None,
            arm: None,
            dominating_guards: Vec::new(),
        }
    }

    const TX: &[u8] = b"\x90\xce\x82\xd4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabcd";

    /// 无视图/承诺的判定输入（臂 3 路径与 fail-closed 用）。
    fn no_ctx() -> CheckInput<'static> {
        CheckInput {
            view: None,
            expected_evidence: None,
        }
    }

    #[test]
    fn arm3_convicts_on_calldata_substring() {
        // call input = 交易 calldata 的 "abcd" 切片。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"abcd".to_vec(), Some(384))],
            TX,
            &no_ctx(),
        );
        assert!(matches!(r, CallCheck::ConvictedArm3(_)));
    }

    #[test]
    fn arm3_rejects_staticcall_and_short_and_foreign() {
        // STATICCALL 不收。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("STATICCALL", b"abcd".to_vec(), Some(384))],
            TX,
            &no_ctx(),
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 长度 < 4 不收（trivial 防空匹配）。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"abc".to_vec(), Some(384))],
            TX,
            &no_ctx(),
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 非 calldata 子串不收。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"zzzz".to_vec(), Some(384))],
            TX,
            &no_ctx(),
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
    }

    #[test]
    fn arm3_first_call_at_or_after_min_target_pc() {
        // pc 在 target 之前的 call 不算；其后的算。
        let calls = vec![
            call("CALL", b"abcd".to_vec(), Some(100)),
            call("CALL", b"abcd".to_vec(), Some(390)),
        ];
        let r = check_arbitrary_call(&hit(&[384]), &calls, TX, &no_ctx());
        match r {
            CallCheck::ConvictedArm3(c) => assert_eq!(c.pc, Some(390)),
            other => panic!("应臂 3 定罪: {other:?}"),
        }
        // target pc 本身不是 call：落到其后第一条。
        let calls = vec![call("CALL", b"abcd".to_vec(), Some(500))];
        assert!(matches!(
            check_arbitrary_call(&hit(&[384]), &calls, TX, &no_ctx()),
            CallCheck::ConvictedArm3(_)
        ));
    }

    #[test]
    fn arm1_convicts_when_target_matches_evidence_value() {
        // evidence = calldata_word(0x4)：TX 槽 0 = "aaaa…"（0x61*32）。
        // 视图：节点 0 = CalldataWord(4)。
        struct V;
        impl crate::eval::EvalViewDyn for V {
            fn owned_node(&self, id: u32) -> Option<crate::eval::OwnedNode> {
                (id == 0).then_some(crate::eval::OwnedNode::CalldataWord(4))
            }
        }
        let mut h = hit(&[384]);
        h.evidence_expr = Some(0);
        h.arm = Some(crate::CallArm::Arm1);
        // call target = TX 槽 0 的低 160 位（0x61*20）。
        let mut target = [0u8; 20];
        target.copy_from_slice(&[0x61u8; 32][..20]);
        let mut c = call("CALL", b"zzzz".to_vec(), Some(384)); // input 非子串：排除臂 3
        c.target = target;
        let ctx = CheckInput {
            view: Some(&V),
            expected_evidence: None,
        };
        match check_arbitrary_call(&h, &[c.clone()], TX, &ctx) {
            CallCheck::ConvictedArm1(got) => assert_eq!(got.target, target),
            other => panic!("应臂 1 定罪: {other:?}"),
        }
        // target 不匹配 → 拒绝。
        let mut bad = c.clone();
        bad.target = [0x99; 20];
        assert!(matches!(
            check_arbitrary_call(&h, &[bad], TX, &ctx),
            CallCheck::Rejected(_)
        ));
        // replay 模式（无视图，有 poc 内嵌承诺）：同值应定罪。
        // 低位 160 位：target 放低位字节（高 12 字节零）。
        let low160 = {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&target);
            alloy_primitives::U256::from_be_bytes(w)
        };
        let ctx_replay = CheckInput {
            view: None,
            expected_evidence: Some(low160),
        };
        assert!(matches!(
            check_arbitrary_call(&h, &[c], TX, &ctx_replay),
            CallCheck::ConvictedArm1(_)
        ));
    }

    #[test]
    fn memmem_basics() {
        assert!(memmem(TX, b"abcd"));
        assert!(memmem(TX, TX));
        assert!(!memmem(TX, b"zzzz"));
        assert!(!memmem(b"ab", b"abcd"));
        assert!(memmem(TX, b""));
    }
}
