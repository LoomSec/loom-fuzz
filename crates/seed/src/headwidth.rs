//! 头宽从 loom 守卫事实推导（issue #48）：种子基座的头槽枚举上限
//! 不再盲扫 1..=12（whack-a-mole），而是由命中携带的支配 guard
//! 事实推出。
//!
//! # 事实源
//!
//! 两种装载模式都经 xlayer 渲染支配 guard（`Hit.dominating_guards`
//! 的 cond 文本），其中 `msg.data.length` 的**下界守卫**直接给出
//! calldata 最小字节数（如 anyswap 的 `s<=(0x120, -(msg.data.length,
//! 0x4))` → ≥ 4+0x120 = selector + 9 词）——种子基座只需覆盖到该
//! 宽度即可过守卫。这是静态事实推导（loom 检测器产出），非字节码
//! 扫描近似。
//!
//! # 解析的渲染形态（xlayer 规范化输出，机械匹配非合约特判）
//!
//! - `s<=(C, -(msg.data.length, K))` → 下界 C+K 字节
//! - `s<(C, -(msg.data.length, K))`  → 下界 C+K+1 字节（严格小于镜像）
//! - 右端为 `+(calldata_word(W), 0x4)` 形（界依赖 calldata 词）→
//!   宽度不可静态定，不计宽度但标记 **动态头证据**（abifix 零槽
//!   合成的启用依据之一）
//! - 上界形态（`msg.data.length` 在左）与无关 guard 一律跳过
//!
//! # 兜底
//!
//! 无可用守卫事实时 `None`——调用方保留有依据的默认（见 cli
//! 调用点注释），不硬编。

/// 头宽推导结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadWidth {
    /// calldata 最小字节数（下界守卫的最大值；无下界守卫 = None）。
    pub calldata_min_bytes: Option<u64>,
    /// 动态头证据：存在界依赖 calldata 词的 msg.data.length 守卫
    /// （嵌套动态结构——偏移头 + 尾的函数形态）。abifix 零槽合成
    /// 的启用依据（宽头保护由此事实替代，issue #48）。
    pub dynamic_head_evidence: bool,
}

/// 从支配 guard 渲染文本推导头宽。`guards` = (cond, polarity)；
/// 只消费 polarity=true（通过条件为真时才约束输入形态）。
pub fn derive<'a>(guards: impl IntoIterator<Item = &'a (String, bool)>) -> HeadWidth {
    let mut min_bytes: Option<u64> = None;
    let mut dynamic = false;
    for (cond, polarity) in guards {
        if !polarity {
            continue;
        }
        if !cond.contains("msg.data.length") {
            continue;
        }
        // 动态头证据：界依赖 calldata 词（嵌套动态尾结构）。
        if cond.contains("calldata_word") || cond.contains("b_calldata_slice") {
            dynamic = true;
            continue;
        }
        if let Some(lower) = parse_lower_bound(cond) {
            min_bytes = Some(min_bytes.map_or(lower, |m| m.max(lower)));
        }
    }
    HeadWidth {
        calldata_min_bytes: min_bytes,
        dynamic_head_evidence: dynamic,
    }
}

/// calldata 最小字节数 → 基座枚举的头词数上限：
/// `ceil((min_bytes - selector 4B) / 32)`，下限 4（无事实函数的
/// 有依据默认——既有行为的保守下限），上限 32（防垃圾值爆炸）。
pub fn head_words_cap(min_bytes: Option<u64>) -> usize {
    const FLOOR: usize = 4;
    const CAP: usize = 32;
    match min_bytes {
        None => FLOOR,
        Some(b) => {
            let words = b.saturating_sub(4).div_ceil(32) as usize;
            words.clamp(FLOOR, CAP)
        }
    }
}

/// 解析 `s<=(C, -(msg.data.length, K))` / 严格形的下界。
/// 形态不匹配（上界/动态界/其它）返回 None。
fn parse_lower_bound(cond: &str) -> Option<u64> {
    let strict = if cond.starts_with("s<=(") {
        false
    } else if cond.starts_with("s<(") {
        true
    } else {
        return None;
    };
    // 顶层拆分：左 = C，右 = -(msg.data.length, K)。
    let inner = cond
        .strip_prefix("s<=(")
        .or_else(|| cond.strip_prefix("s<("))?
        .strip_suffix(')')?;
    let (left, right) = split_top_level(inner)?;
    let c = parse_hex_const(left.trim())?;
    let right = right.trim().strip_prefix("-(")?.strip_suffix(')')?;
    let (m, k) = split_top_level(right)?;
    if m.trim() != "msg.data.length" {
        return None;
    }
    let k = parse_hex_const(k.trim())?;
    Some(c + k + u64::from(strict))
}

/// 按顶层逗号拆分（括号深度感知；渲染无字符串字面量，机械即可）。
fn split_top_level(s: &str) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => return Some((&s[..i], &s[i + 1..])),
            _ => {}
        }
    }
    None
}

/// 解析 0x-hex 常量（渲染形态 `0x[0-9a-f]+`）。
fn parse_hex_const(s: &str) -> Option<u64> {
    let hex = s.strip_prefix("0x")?;
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(cond: &str, polarity: bool) -> (String, bool) {
        (cond.to_string(), polarity)
    }

    #[test]
    fn anyswap_nine_word_guard_derives_min() {
        // anyswap：msg.data.length ≥ 4+0x120 → 9 词。
        let gs = [g("s<=(0x120, -(msg.data.length, 0x4))", true)];
        let hw = derive(&gs);
        assert_eq!(hw.calldata_min_bytes, Some(0x124));
        assert_eq!(head_words_cap(hw.calldata_min_bytes), 9);
        assert!(!hw.dynamic_head_evidence);
    }

    #[test]
    fn lifi_guards_derive_min_and_dynamic_evidence() {
        // LiFi facet：常量下界 0x100+4 与 word 依赖界（动态证据）。
        let gs = [
            g("s<=(0x100, -(msg.data.length, 0x4))", true),
            g(
                "s<=(0x100, -(msg.data.length, +(calldata_word(0x4), 0x4)))",
                true,
            ),
            g("s<=(0xc0, -(msg.data.length, 0x44))", true),
        ];
        let hw = derive(&gs);
        assert_eq!(hw.calldata_min_bytes, Some(0x104));
        assert!(hw.dynamic_head_evidence);
        assert_eq!(head_words_cap(hw.calldata_min_bytes), 8);
    }

    #[test]
    fn strict_and_upper_and_false_polarity_ignored() {
        // 严格形 +1；上界（length 在左）不收；polarity=false 不收。
        let gs = [
            g("s<(0x40, -(msg.data.length, 0x4))", true),
            g("s<(-(msg.data.length, 0x4), 0x100)", true),
            g("s<=(0x100, -(msg.data.length, 0x4))", false),
            g("==(calldata_word(0x4), 0x1)", true),
        ];
        let hw = derive(&gs);
        assert_eq!(hw.calldata_min_bytes, Some(0x45));
        assert!(!hw.dynamic_head_evidence);
    }

    #[test]
    fn no_facts_floor_default() {
        let hw: HeadWidth = derive(std::iter::empty::<&(String, bool)>());
        assert_eq!(hw.calldata_min_bytes, None);
        assert_eq!(head_words_cap(hw.calldata_min_bytes), 4);
        assert!(!hw.dynamic_head_evidence);
    }

    #[test]
    fn garbage_guard_does_not_panic() {
        let gs = [
            g("and(<(a, b), <=(c, d))", true),
            g("s<=(0xzz, -(msg.data.length, 0x4))", true),
            g("s<=(0x10, -(msg.data.length, ))", true),
            g("s<=(0x10)", true),
        ];
        let hw = derive(&gs);
        assert_eq!(hw.calldata_min_bytes, None);
    }
}
