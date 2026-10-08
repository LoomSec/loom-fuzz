//! 族 oracle：到目标帧后在具体 trace 上求值证据表达式（按族定制
//! 检查器，docs/architecture.md 管线⑤）。M0 只实现 arbitrary_call
//! 族（臂 3 裸转发 memcmp 判定）；其他族 future——判决入口按族
//! 分发，未知族如实报 inconclusive-able 的 "未实现"（fail-closed
//! 不硬判 confirmed）。

use loom_fuzz_fuzz::RecordedCall;

use crate::hit::Hit;

/// arbitrary_call 臂 3 判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallCheck {
    /// 定罪：该 call 满足 memcmp 级证据。
    Convicted(RecordedCall),
    /// 未成立：`reason` 如实说明（到场但证据谓词不成立）。
    Rejected(String),
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

/// arbitrary_call 族 oracle（M0 = 臂 3 memcmp）。
///
/// 在 target pc 处（或其后同帧内）的 RecordedCall 中找第一条例证：
/// M0 取 `pc >= 最小 target pc` 的第一条 call（target pc 本身不是
/// call 时自然落到其后第一条——未来其他族再按帧语义细化）。
pub fn check_arbitrary_call(hit: &Hit, calls: &[RecordedCall], tx_calldata: &[u8]) -> CallCheck {
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
    for call in &candidates {
        if arm3_check(call, tx_calldata) {
            return CallCheck::Convicted((*call).clone());
        }
    }
    let kinds: Vec<&str> = candidates.iter().map(|c| c.kind.as_str()).collect();
    CallCheck::Rejected(format!(
        "target pc {min_pc} 后 {} 条 call（kinds={kinds:?}）均不满足臂 3 证据：非 CALL/CALLCODE/DELEGATECALL、input < 4 字节或 input 不是原始 calldata 的子串",
        candidates.len()
    ))
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
            dominating_guards: Vec::new(),
        }
    }

    const TX: &[u8] = b"\x90\xce\x82\xd4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabcd";

    #[test]
    fn arm3_convicts_on_calldata_substring() {
        // call input = 交易 calldata 的 "abcd" 切片。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"abcd".to_vec(), Some(384))],
            TX,
        );
        assert!(matches!(r, CallCheck::Convicted(_)));
    }

    #[test]
    fn arm3_rejects_staticcall_and_short_and_foreign() {
        // STATICCALL 不收。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("STATICCALL", b"abcd".to_vec(), Some(384))],
            TX,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 长度 < 4 不收（trivial 防空匹配）。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"abc".to_vec(), Some(384))],
            TX,
        );
        assert!(matches!(r, CallCheck::Rejected(_)));
        // 非 calldata 子串不收。
        let r = check_arbitrary_call(
            &hit(&[384]),
            &[call("CALL", b"zzzz".to_vec(), Some(384))],
            TX,
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
        let r = check_arbitrary_call(&hit(&[384]), &calls, TX);
        match r {
            CallCheck::Convicted(c) => assert_eq!(c.pc, Some(390)),
            CallCheck::Rejected(_) => panic!("应定罪"),
        }
        // target pc 本身不是 call：落到其后第一条。
        let calls = vec![call("CALL", b"abcd".to_vec(), Some(500))];
        assert!(matches!(
            check_arbitrary_call(&hit(&[384]), &calls, TX),
            CallCheck::Convicted(_)
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
