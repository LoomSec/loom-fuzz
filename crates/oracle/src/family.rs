//! 族 oracle：到目标帧后在具体 trace 上求值证据表达式（按族定制
//! 检查器，docs/architecture.md 管线⑤）。M0 实现三族：
//! arbitrary_call（臂 3 裸转发 memcmp + 臂 1 目标求值）、
//! approval_drain 的 deputy_call（同臂 1 求值）与 drain_forward
//! （宽松 memmem）；新族在判决入口按族分发扩展。

use loom_fuzz_fuzz::RecordedCall;

use crate::eval;
use crate::hit::Hit;

/// arbitrary_call 判定结果（注明所用手臂）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallCheck {
    /// 臂 3 定罪：call input 是原始 calldata 的子串（裸转发）。
    ConvictedArm3(RecordedCall),
    /// 臂 1 定罪：call.target == cast160(evidence)（目标可控）。
    /// deputy_call 族定罪复用本变体（同臂 1 求值定罪）。
    ConvictedArm1(RecordedCall),
    /// drain_forward 定罪：call input 含 calldata 派生切片
    /// （宽松 memmem，判定见 `drain_forward_check`）。
    ConvictedDrain(RecordedCall),
    /// 未成立：`reason` 如实说明（到场但证据谓词不成立）。
    Rejected(String),
}

impl CallCheck {
    /// 定罪的那次 call（各臂同形时按判决方取）。
    pub fn call(&self) -> Option<&RecordedCall> {
        match self {
            CallCheck::ConvictedArm3(c)
            | CallCheck::ConvictedArm1(c)
            | CallCheck::ConvictedDrain(c) => Some(c),
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
/// `contract` = 目标帧所属合约（trace.contract）——多合约在场时
/// 候选 call 必须是 victim 帧发出的（RecordedCall.from ==
/// contract）：pc 数值跨代码库不再可比，from 过滤是帧归属的
/// 正确性兜底（issue #34）。单合约会话下全部 call 的 from 均 =
/// victim，过滤恒过（默认行为不变）。
pub fn check_arbitrary_call(
    hit: &Hit,
    calls: &[RecordedCall],
    tx_calldata: &[u8],
    input: &CheckInput<'_>,
    contract: [u8; 20],
) -> CallCheck {
    let Some(min_pc) = hit.target_pcs.iter().min().copied() else {
        return CallCheck::Rejected("命中无 target pc（契约外输入）".to_string());
    };
    let candidates: Vec<&RecordedCall> = calls
        .iter()
        .filter(|c| c.pc.is_some_and(|pc| pc >= min_pc) && c.from == contract)
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

/// approval_drain 族 deputy_call 检查器：同臂 1 目标求值定罪
/// （复用 #19 求值器）——confused deputy 的 witness 具体形态 =
/// call.target（低 160）== 证据表达式在 witness calldata 上的求值
/// 结果（低 160）。view / 求值承诺两路同臂 1。
pub fn check_deputy_call(
    hit: &Hit,
    calls: &[RecordedCall],
    tx_calldata: &[u8],
    input: &CheckInput<'_>,
    contract: [u8; 20],
) -> CallCheck {
    let Some(min_pc) = hit.target_pcs.iter().min().copied() else {
        return CallCheck::Rejected("命中无 target pc（契约外输入）".to_string());
    };
    let candidates: Vec<&RecordedCall> = calls
        .iter()
        .filter(|c| c.pc.is_some_and(|pc| pc >= min_pc) && c.from == contract)
        .collect();
    if candidates.is_empty() {
        return CallCheck::Rejected(format!(
            "target pc {min_pc} 之后无 CALL 族效果（trace.calls 为空或都在 pc 之前）"
        ));
    }
    match arm1_check(hit, &candidates, tx_calldata, input) {
        Some(call) => CallCheck::ConvictedArm1(call),
        None => CallCheck::Rejected(format!(
            "target pc {min_pc} 后 {} 条 call：deputy_call 目标求值不成立（call.target ≠ cast160(evidence)）",
            candidates.len()
        )),
    }
}

/// approval_drain 族 drain_forward 检查器：**宽松 memmem**——
/// call input（≥4B 防 trivial）满足下列任一即定罪：
/// 1. input 是原始交易 calldata 的字节子串（同臂 3 memcpy 级）；
/// 2. input 含 calldata 的某个完整 32B 头词（词覆盖：input 整体不
///    是子串但由 calldata 词拼装的组装形——deputy 代传参数的常见
///    形态，如 selector + calldata_word 槽拼接）。
///
/// 语义选择（文档注明）：loom 检测臂只要求"input 子树含输入派生
/// 词"，trace 级精确反演 inputmark 对应切片需要表达式→内存区的
/// 符号映射（M0 无）；宽松 memmem 是其 sound 近似——子串/整词覆盖
/// 必蕴含"含输入派生内容"，反之不保证（残留 FP 由三值判决的
/// unreachable 臂如实降级）。
pub fn check_drain_forward(
    hit: &Hit,
    calls: &[RecordedCall],
    tx_calldata: &[u8],
    contract: [u8; 20],
) -> CallCheck {
    let Some(min_pc) = hit.target_pcs.iter().min().copied() else {
        return CallCheck::Rejected("命中无 target pc（契约外输入）".to_string());
    };
    let candidates: Vec<&RecordedCall> = calls
        .iter()
        .filter(|c| c.pc.is_some_and(|pc| pc >= min_pc) && c.from == contract)
        .collect();
    if candidates.is_empty() {
        return CallCheck::Rejected(format!(
            "target pc {min_pc} 之后无 CALL 族效果（trace.calls 为空或都在 pc 之前）"
        ));
    }
    let words: Vec<&[u8]> = tx_calldata
        .get(4..)
        .map(|rest| {
            let n = rest.len() / 32;
            (0..n).map(|i| &rest[i * 32..i * 32 + 32]).collect()
        })
        .unwrap_or_default();
    for call in &candidates {
        if call.input.len() < 4 {
            continue;
        }
        if memmem(tx_calldata, &call.input) {
            return CallCheck::ConvictedDrain((*call).clone());
        }
        // 词覆盖：任一完整 32B calldata 头词出现在 input 里。
        if words.iter().any(|w| memmem(&call.input, w)) {
            return CallCheck::ConvictedDrain((*call).clone());
        }
    }
    CallCheck::Rejected(format!(
        "target pc {min_pc} 后 {} 条 call：input 均非 calldata 子串且不含任何 32B 头词",
        candidates.len()
    ))
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
            from: [0x22; 20],
            target: [0x11; 20],
            value: U256::ZERO,
            input,
            pc,
        }
    }

    /// 单合约会话的合约表约定：victim = [0x22; 20]。
    const CONTRACT: [u8; 20] = [0x22; 20];

    fn hit(pcs: &[u32]) -> Hit {
        Hit {
            family: Default::default(),
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
            CONTRACT,
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
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 长度 < 4 不收（trivial 防空匹配）。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"abc".to_vec(), Some(384))],
            TX,
            &no_ctx(),
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 非 calldata 子串不收。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"zzzz".to_vec(), Some(384))],
            TX,
            &no_ctx(),
            CONTRACT,
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
        let r = check_arbitrary_call(&hit(&[384]), &calls, TX, &no_ctx(), CONTRACT);
        match r {
            CallCheck::ConvictedArm3(c) => assert_eq!(c.pc, Some(390)),
            other => panic!("应臂 3 定罪: {other:?}"),
        }
        // target pc 本身不是 call：落到其后第一条。
        let calls = vec![call("CALL", b"abcd".to_vec(), Some(500))];
        assert!(matches!(
            check_arbitrary_call(&hit(&[384]), &calls, TX, &no_ctx(), CONTRACT),
            CallCheck::ConvictedArm3(_)
        ));
    }

    #[test]
    fn candidates_are_limited_to_victim_frame() {
        // issue #34：多合约在场时 from ≠ victim 的 call（攻击代理
        // 转发帧等）不作候选——即使其 input 是 calldata 子串、pc
        // 数值 ≥ min_pc（pc 跨代码库不可比的正确性兜底）。
        let mut proxy_call = call("CALL", b"abcd".to_vec(), Some(390));
        proxy_call.from = [0xaau8; 20];
        let victim_call = call("CALL", b"abcd".to_vec(), Some(390));
        // 代理帧在前：旧数值语义会先命中它（input 子串成立）。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[proxy_call, victim_call],
            TX,
            &no_ctx(),
            CONTRACT,
        );
        match r {
            CallCheck::ConvictedArm3(c) => assert_eq!(c.from, CONTRACT),
            other => panic!("应定罪 victim 帧的 call: {other:?}"),
        }
        // 全是外帧 call → 拒绝（如实：到场但谓词不成立）。
        let mut foreign = call("CALL", b"abcd".to_vec(), Some(390));
        foreign.from = [0xaau8; 20];
        let r = check_arbitrary_call(&hit(&[384]), &[foreign], TX, &no_ctx(), CONTRACT);
        let msg = match r {
            CallCheck::Rejected(m) => m,
            other => panic!("应拒绝: {other:?}"),
        };
        assert!(
            msg.contains("无 CALL 族效果"),
            "外帧 call 不计入候选: {msg}"
        );
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
        match check_arbitrary_call(&h, &[c.clone()], TX, &ctx, CONTRACT) {
            CallCheck::ConvictedArm1(got) => assert_eq!(got.target, target),
            other => panic!("应臂 1 定罪: {other:?}"),
        }
        // target 不匹配 → 拒绝。
        let mut bad = c.clone();
        bad.target = [0x99; 20];
        assert!(matches!(
            check_arbitrary_call(&h, &[bad], TX, &ctx, CONTRACT),
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
            check_arbitrary_call(&h, &[c], TX, &ctx_replay, CONTRACT),
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

    // --- approval_drain 族（issue #20）---

    fn deputy_hit(pcs: &[u32]) -> Hit {
        Hit {
            family: crate::HitFamily::ApprovalDrainDeputy,
            ..hit(pcs)
        }
    }

    #[test]
    fn deputy_convicts_on_target_eval_and_rejects_mismatch() {
        // 同臂 1 求值定罪：evidence = calldata_word(0x4)，TX 槽 0。
        struct V;
        impl crate::eval::EvalViewDyn for V {
            fn owned_node(&self, id: u32) -> Option<crate::eval::OwnedNode> {
                (id == 0).then_some(crate::eval::OwnedNode::CalldataWord(4))
            }
        }
        let mut h = deputy_hit(&[384]);
        h.evidence_expr = Some(0);
        let mut target = [0u8; 20];
        target.copy_from_slice(&[0x61u8; 32][..20]);
        let mut c = call("CALL", b"zzzz".to_vec(), Some(384));
        c.target = target;
        let ctx = CheckInput {
            view: Some(&V),
            expected_evidence: None,
        };
        match check_deputy_call(&h, &[c.clone()], TX, &ctx, CONTRACT) {
            CallCheck::ConvictedArm1(got) => assert_eq!(got.target, target),
            other => panic!("应 deputy 定罪: {other:?}"),
        }
        // target 不匹配 → 拒绝（到场但证据谓词不成立）。
        let mut bad = c.clone();
        bad.target = [0x99; 20];
        assert!(matches!(
            check_deputy_call(&h, &[bad], TX, &ctx, CONTRACT),
            CallCheck::Rejected(_)
        ));
        // replay 承诺路径：无视图 + expected_evidence 同值定罪。
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
            check_deputy_call(&h, &[c], TX, &ctx_replay, CONTRACT),
            CallCheck::ConvictedArm1(_)
        ));
    }

    fn drain_hit(pcs: &[u32]) -> Hit {
        Hit {
            family: crate::HitFamily::ApprovalDrainForward,
            ..hit(pcs)
        }
    }

    #[test]
    fn drain_convicts_on_substring_or_word_cover() {
        // 臂 1：input 是 calldata 子串（memcpy 级）。
        let r = check_drain_forward(
            &drain_hit(&[384]),
            &[call("CALL", b"abcd".to_vec(), Some(384))],
            TX,
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::ConvictedDrain(_)));
        // 臂 2：input 非子串但含完整 32B calldata 头词（词覆盖——组装形）。
        // TX = selector + "aaaa…"(32B) + "bcd"。input = 0xbbbb + word0。
        let mut input = vec![0xbb, 0xbb, 0xbb, 0xbb];
        input.extend_from_slice(&[0x61u8; 32]);
        let r = check_drain_forward(
            &drain_hit(&[384]),
            &[call("CALL", input, Some(384))],
            TX,
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::ConvictedDrain(_)));
    }

    #[test]
    fn drain_rejects_foreign_short_and_truncated_word() {
        // 与 calldata 无关 → 拒绝。
        let r = check_drain_forward(
            &drain_hit(&[384]),
            &[call("CALL", b"zzzzzzzz".to_vec(), Some(384))],
            TX,
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 长度 < 4 → 拒绝（trivial 防空匹配）。
        let r = check_drain_forward(
            &drain_hit(&[384]),
            &[call("CALL", b"abc".to_vec(), Some(384))],
            TX,
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 改造词（中段异值，非完整 32B 头词也非子串——TX 的 0x62 只
        // 出现在词尾、前后文不匹配）→ 拒绝。
        let mut fake_word = [0x61u8; 32];
        fake_word[10] = 0x62;
        let r = check_drain_forward(
            &drain_hit(&[384]),
            &[call("CALL", fake_word.to_vec(), Some(384))],
            TX,
            CONTRACT,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
    }
}
