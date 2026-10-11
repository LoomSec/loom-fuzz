//! 守卫存储依赖闭包——守卫槽解析（issue #54）：从支配 guard 的
//! 渲染文本解析守卫读的存储槽（loom 静态事实），供写者闭包/
//! fitness 信用/辅助制导消费（loom 标靶、loom-fuzz 打靶）。
//!
//! # 解析形态（xlayer 规范化渲染，机械匹配非合约特判）
//!
//! - `storage(this, 0x…)` → [`GuardSlot::Const`]（常量槽——运行时
//!   可精确匹配 SSTORE key）
//! - `storage(this, mapping(0xBASE, KEY))` → [`GuardSlot::Mapping`]
//!   （mapping 基槽，offset 0）
//! - `storage(this, +(0xK, mapping(0xBASE, KEY)))` → `Mapping`（结构体
//!   成员偏移 K）——TeamFinance 的 unlockTime(id) 即此形：
//!   `+(0x3, mapping(0xcc, calldata_word(0x4)))`
//!
//! mapping 派生槽的运行时 key 是 keccak 值（静态不可反解），
//! 匹配规则 = **写者闭包**：写该基槽派生槽的函数集（sound 近似——
//! 这些函数的 sstore 即写守卫族槽；静态不可关联动态 key 时保守
//! 按函数归组）。

use alloy_primitives::U256;

/// 守卫存储槽。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardSlot {
    /// 常量槽（运行时 SSTORE key 精确匹配）。
    Const(U256),
    /// mapping 基槽 + 结构体偏移（运行时按写者函数归组匹配）。
    Mapping { base: U256, offset: u64 },
}

impl GuardSlot {
    /// 匹配归组键：常量槽 = 槽值本身；mapping = 基槽（偏移并入
    /// 文档注记——运行时按基槽归组）。
    pub fn base_key(&self) -> U256 {
        match self {
            GuardSlot::Const(c) => *c,
            GuardSlot::Mapping { base, .. } => *base,
        }
    }
}

/// 从支配 guard 渲染文本解析守卫存储槽。`guards` = (cond, polarity)；
/// 只消费 polarity=true（通过条件为真时才约束执行形态）。
pub fn parse_guard_slots<'a>(
    guards: impl IntoIterator<Item = &'a (String, bool)>,
) -> Vec<GuardSlot> {
    let mut out: Vec<GuardSlot> = Vec::new();
    for (cond, polarity) in guards {
        if !polarity || !cond.contains("storage(this, ") {
            continue;
        }
        for arg in storage_args(cond) {
            if let Some(slot) = parse_slot_expr(arg.trim()) {
                if !out.contains(&slot) {
                    out.push(slot);
                }
            }
        }
    }
    out
}

/// 提取 cond 中全部 `storage(this, …)` 的参数子串（括号平衡）。
fn storage_args(cond: &str) -> Vec<&str> {
    let needle = "storage(this, ";
    let mut out = Vec::new();
    let mut rest = cond;
    while let Some(at) = rest.find(needle) {
        let inner = &rest[at + needle.len()..];
        let mut depth = 1i32;
        let mut end = inner.len();
        for (i, ch) in inner.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(&inner[..end]);
        rest = &inner[end..];
    }
    out
}

/// 解析槽参数表达式：`0x…` | `mapping(0xBASE, …)` | `+(0xK,
/// mapping(0xBASE, …))`；其它形态（calldata 直接索引等）不产出
/// （如实跳过）。
fn parse_slot_expr(s: &str) -> Option<GuardSlot> {
    if let Some(hex) = s.strip_prefix("0x") {
        let v = parse_hex(hex)?;
        return Some(GuardSlot::Const(v));
    }
    if let Some(inner) = s.strip_prefix("mapping(") {
        let base = inner.split_once(',')?.0.trim();
        return Some(GuardSlot::Mapping {
            base: parse_hex(base.strip_prefix("0x")?)?,
            offset: 0,
        });
    }
    if s.starts_with("+(") {
        let inner = s.strip_prefix("+(")?.strip_suffix(')')?;
        let (k, m) = inner.split_once(',')?;
        let offset = parse_hex(k.trim().strip_prefix("0x")?)?.to::<u64>();
        let base = m
            .trim()
            .strip_prefix("mapping(")?
            .split_once(',')?
            .0
            .trim()
            .strip_prefix("0x")?;
        return Some(GuardSlot::Mapping {
            base: parse_hex(base)?,
            offset,
        });
    }
    None
}

fn parse_hex(hex: &str) -> Option<U256> {
    if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    U256::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(cond: &str) -> (String, bool) {
        (cond.to_string(), true)
    }

    #[test]
    fn teamfinance_unlocktime_slot_parses() {
        // TeamFinance migrate 守卫：unlockTime(id) 形态。
        let gs = [g(
            "<(block.timestamp, storage(this, +(0x3, mapping(0xcc, calldata_word(0x4)))))",
        )];
        let slots = parse_guard_slots(&gs);
        assert_eq!(
            slots,
            vec![GuardSlot::Mapping {
                base: U256::from(0xccu64),
                offset: 3
            }]
        );
        assert_eq!(slots[0].base_key(), U256::from(0xccu64));
    }

    #[test]
    fn const_and_bare_mapping_parse() {
        let gs = [
            g("!=(0x0, cast8(storage(this, 0xd4)))"),
            g("==(storage(this, mapping(0x7, calldata_word(0x24))), 0x1)"),
        ];
        let slots = parse_guard_slots(&gs);
        assert!(slots.contains(&GuardSlot::Const(U256::from(0xd4u64))));
        assert!(slots.contains(&GuardSlot::Mapping {
            base: U256::from(0x7u64),
            offset: 0
        }));
    }

    #[test]
    fn polarity_false_and_non_storage_ignored() {
        let gs = [
            (">(storage(this, 0x5), 0x0)".to_string(), false),
            g("==(calldata_word(0x4), 0x1)"),
            g("==(storage(entry.world, 0x9), 0x1)"), // 非 this 存储不收
        ];
        assert!(parse_guard_slots(&gs).is_empty());
    }

    #[test]
    fn dedup_and_garbage_do_not_panic() {
        let gs = [
            g("==(storage(this, 0x5), storage(this, 0x5))"),
            g("==(storage(this, ), 0x1)"),
            g("==(storage(this, zz), 0x1)"),
            g("==(storage(this, calldata_word(0x4)), 0x1)"),
        ];
        let slots = parse_guard_slots(&gs);
        assert_eq!(slots, vec![GuardSlot::Const(U256::from(5u64))]);
    }
}
