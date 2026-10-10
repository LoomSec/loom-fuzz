//! 通用 ABI 自洽化变异算子（issue #46）：结构感知重编码——把候选
//! calldata 的偏移结构系统性改写为自洽布局（头区偏移词重新绑定
//! 合法段、数组段内层偏移递归修复、退化零槽合成最小动态段）。
//!
//! # 动机（#41 LiFi 实跑事实）
//!
//! 三层嵌套动态 ABI（头偏移 → 数组 → 元组 → 内层 bytes）的盲搜
//! 卡点是**偏移结构自洽性**：退化形态（全零指针）被 Solidity
//! decoder 宽容接受——能"到场"但 evidence 求值读到的槽位与
//! decoder 实际使用的槽位错位，臂 1/臂 3 均不成立。一旦偏移
//! 结构自洽，evidence 表达式与 decoder 读同一槽位，目标可控/
//! 裸转发判定自然成立——**内容可以是垃圾词**（执行验证兜底）。
//!
//! # 算法（机械通用，零个案）
//!
//! 1. **动态槽识别**（头区）：值为零（退化槽）或形状像偏移
//!    （32 对齐、≥ 0x20、落在尾区内）的词视为动态槽，其余为
//!    静态槽原样保留。判定思路与 pocgen `parse_head_shape` 同源。
//! 2. **原段切分**：非零动态槽按偏移排序、以相邻段首为界切出
//!    原段内容（verbatim 保留）；退化零槽无原段。
//! 3. **段内递归**（一层）：单元素数组段（首词 = 1、总长可整除）
//!    的元素内偏移词，若当前解释不合法（长度字越界/超上限），
//!    在段尾追加最小 bytes 块（len=4 + rng 词）并重指向。
//! 4. **重编码**：新尾 = 各段按头槽顺序拼接（零槽首槽继承残余
//!    原尾词，其余零槽合成最小段）；头动态槽写新偏移（累加）。
//!
//! 输出重编码后的 Input（head 等长、tail 可能增长），经与全部
//! 既有算子相同的执行验证路径——不保证自洽即定罪，只保证
//! "自洽结构进入搜索空间"。
//!
//! # 局限（如实）
//!
//! - 段内递归只处理单元素数组段（元组内 bytes 偏移）；多元素
//!   数组的内层偏移保持 verbatim（decoder 宽容 + 执行验证）。
//! - 动态槽识别可能把"恰好像偏移的静态数据词"误判为动态槽——
//!   执行验证兜底（自洽化候选失败即淘汰，与既有算子同纪律）。

use alloy_primitives::U256;
use loom_fuzz_seed::{Input, Tail};

use crate::rng::Rng;

/// 段长合理上限（与 pocgen TAIL_LEN_CAP 同约定：防垃圾值被误读
/// 为合法长度）。
const SEG_LEN_CAP: u64 = 4096;

fn to_u64(w: &[u8; 32]) -> Option<u64> {
    let v = U256::from_be_bytes(*w);
    (v <= U256::from(u64::MAX)).then(|| v.to::<u64>())
}

/// 词的形状是否"像偏移"：32 对齐、≥ 0x20、指向尾区内的词（args
/// 区下标 = 值/32，须在 [base_words, total_words) 内——即头之后、
/// calldata 界内）。
fn offset_shaped(w: &[u8; 32], slot: usize, base_words: usize, total_words: usize) -> bool {
    let Some(v) = to_u64(w) else { return false };
    v >= 0x20 && v.is_multiple_of(32) && {
        let target = (v / 32) as usize;
        slot < base_words && target >= base_words && target < total_words
    }
}

/// 最小动态段（合成材料：len=4 + rng 词——内容形状正确即可，
/// 语义由执行验证与后续进化填充）。
fn minimal_segment(rng: &mut Rng) -> Vec<[u8; 32]> {
    let mut len = [0u8; 32];
    len[31] = 4;
    vec![len, rng.word()]
}

fn word_one() -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = 1;
    w
}

/// 对段内容做一层内层偏移修复。基数（偏移相对的起点）按段形判定：
/// 单元素数组段（首词 = 1 且 ≥ 2 词）→ 元素基 = 词 1（元组内偏移
/// 相对元素头）；否则 → 段基 = 词 0（结构体内偏移相对段头）。无效
/// 内层偏移（目标越界/长度字非法）在段尾追加最小 bytes 块并重指向。
fn fix_segment(seg_words: &[[u8; 32]], rng: &mut Rng) -> Vec<[u8; 32]> {
    let mut out = seg_words.to_vec();
    if out.is_empty() {
        return out;
    }
    let base = if to_u64(&out[0]) == Some(1) && out.len() >= 2 {
        1
    } else {
        0
    };
    for j in base..out.len() {
        let Some(v) = to_u64(&out[j]) else { continue };
        if v < 0x20 || !v.is_multiple_of(32) {
            continue;
        }
        // 相对 base 的目标词 = base + v/32，须落在段内且该处有
        // 合法长度字（≤ 上限、内容在界内）。
        let target = base + (v / 32) as usize;
        let coherent = target < out.len() && {
            match to_u64(&out[target]) {
                Some(l) if l <= SEG_LEN_CAP => target + 1 + (l as usize).div_ceil(32) <= out.len(),
                _ => false,
            }
        };
        if !coherent {
            out.extend(minimal_segment(rng));
            let new_rel = (out.len() - 2 - base) * 32;
            out[j] = U256::from(new_rel as u64).to_be_bytes::<32>();
        }
    }
    out
}

/// 结构感知重编码：候选 calldata 的偏移结构自洽化（见模块文档）。
/// 无动态槽 / 无尾时原样返回（算子幂等 no-op）。
pub(crate) fn abi_coherence_fix(input: &Input, rng: &mut Rng, dynamic_head: bool) -> Input {
    let n_head = input.head.len();
    if n_head == 0 {
        return input.clone();
    }
    let tail_bytes: &[u8] = match &input.tail {
        Tail::Bytes(b) => b,
        _ => return input.clone(),
    };
    let n_tail_words = tail_bytes.len() / 32;
    if n_tail_words == 0 {
        return input.clone();
    }
    let total = n_head + n_tail_words;
    let tail_words: Vec<[u8; 32]> = tail_bytes[..n_tail_words * 32].as_chunks::<32>().0.to_vec();

    // 1. 动态槽识别。
    let mut dyn_slots: Vec<usize> = (0..n_head)
        .filter(|&k| input.head[k] == [0u8; 32] || offset_shaped(&input.head[k], k, n_head, total))
        .collect();
    if dyn_slots.is_empty() {
        return input.clone();
    }
    // 宽头保护（#46 回归红线）：头宽 > 4 且守卫事实无动态头证据
    // 时，零槽视为数据（anyswap permit 形 9 槽定长头全是参数数据，
    // 零值合法）——零槽合成只在小头或动态头证据在场时启用（issue
    // #48：证据 = 界依赖 calldata 词的 msg.data.length 守卫，替代
    // #46 的纯拍宽度阈值）；非零偏移形词不受此限。
    if n_head > 4 && !dynamic_head {
        dyn_slots.retain(|&k| input.head[k] != [0u8; 32]);
        if dyn_slots.is_empty() {
            return input.clone();
        }
    }

    // 2. 原段切分：非零槽按偏移排序，相邻段首为界；零槽无原段。
    let mut nonzero: Vec<(usize, usize)> = Vec::new(); // (slot, start_word_in_tail)
    for &k in &dyn_slots {
        if let Some(v) = to_u64(&input.head[k]) {
            if v > 0 {
                nonzero.push((k, ((v / 32) as usize).saturating_sub(n_head)));
            }
        }
    }
    nonzero.sort_by_key(|&(_, start)| start);
    // 越界起点（退化值）滤除，按零槽处理。
    nonzero.retain(|&(_, start)| start < n_tail_words);

    // 有界材料：原尾全词（供退化零槽复制共享）。
    let material: Vec<[u8; 32]> = tail_words.clone();

    let mut segments: Vec<(usize, Vec<[u8; 32]>)> = Vec::new();
    for &k in &dyn_slots {
        let content = match nonzero.iter().position(|&(slot, _)| slot == k) {
            Some(pos) => {
                let start = nonzero[pos].1;
                let end = nonzero
                    .get(pos + 1)
                    .map(|&(_, s)| s)
                    .unwrap_or(n_tail_words);
                let end = end.clamp(start, n_tail_words);
                tail_words[start..end].to_vec()
            }
            // 退化零槽 → 合成段（见 rebuild）。
            None => Vec::new(),
        };
        segments.push((k, content));
    }

    // 3. 段内递归 + 4. 重编码。偏移相对 args 区头（含头词）——
    // 与 Solidity ABI 编码约定一致。退化零槽合成段：材料 = 原尾
    // 复制共享（每个零槽得一份——段内容是什么类型无从得知， verbatim
    // 与单元素数组两形都进搜索空间，执行验证选择）；有界 32 词防
    // calldata 膨胀。
    let mut new_tail: Vec<[u8; 32]> = Vec::new();
    let mut new_head = input.head.clone();
    for (k, content) in &segments {
        let fixed = if content.is_empty() {
            let mat: Vec<[u8; 32]> = material.iter().take(32).copied().collect();
            let seg = if rng.below(2) == 0 {
                mat.clone() // 结构体猜测：verbatim
            } else {
                // 单元素数组猜测：[len=1] ++ 材料 ++ 填充——最小
                // 元素宽 8 词（覆盖常见元组宽；材料短时 rng 补，
                // 仍由执行验证裁定）。
                let mut s = vec![word_one()];
                s.extend(mat);
                while s.len() < 9 {
                    s.push(rng.word());
                }
                s
            };
            fix_segment(&seg, rng)
        } else {
            fix_segment(content, rng)
        };
        let offset = (n_head + new_tail.len()) * 32;
        new_tail.extend(fixed);
        new_head[*k] = U256::from(offset as u64).to_be_bytes::<32>();
    }

    Input {
        selector: input.selector,
        caller: input.caller,
        value: input.value,
        head: new_head,
        tail: Tail::Bytes(new_tail.concat()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(v: u64) -> [u8; 32] {
        U256::from(v).to_be_bytes::<32>()
    }

    fn value_word(w: &[u8; 32]) -> u64 {
        (U256::from_be_bytes(*w) & U256::from(u64::MAX)).to::<u64>()
    }

    fn input(head: Vec<[u8; 32]>, tail: Vec<[u8; 32]>) -> Input {
        Input {
            selector: 0x01c0a31a,
            caller: [0x33; 20],
            value: U256::ZERO,
            head,
            tail: Tail::Bytes(tail.concat()),
        }
    }

    /// 全词视图（头 ++ 尾）中，槽 slot 的偏移是否落在尾区界内
    /// （结构自洽的最低保证；段是否动态解码由内容决定——执行验证
    /// 兜底）。base = 尾区首词下标（args 下标）。
    fn points_in_bounds(words: &[[u8; 32]], slot: usize, base: usize) -> bool {
        let Some(v) = to_u64(&words[slot]) else {
            return false;
        };
        if v < 0x20 || !v.is_multiple_of(32) {
            return false;
        }
        let target = (v / 32) as usize;
        (base..words.len()).contains(&target)
    }

    #[test]
    fn degenerate_three_layer_head_gets_coherent_segments() {
        // LiFi 形退化输入：3 零槽头 + 残余尾词。修复后每个头槽
        // 指向合法段（偏移相对 args 头），且修复幂等。
        let degenerate = input(vec![[0u8; 32]; 3], vec![word(0xAAAA), word(0xBBBB)]);
        let fixed = abi_coherence_fix(&degenerate, &mut Rng::new(7), true);
        assert_eq!(fixed.head.len(), 3);
        let Tail::Bytes(tb) = &fixed.tail else {
            panic!("tail")
        };
        let tail_words: Vec<[u8; 32]> = tb.as_chunks::<32>().0.to_vec();
        let n_head_us = fixed.head.len();
        let n_head = n_head_us as u64;
        let full: Vec<[u8; 32]> = fixed
            .head
            .iter()
            .chain(tail_words.iter())
            .copied()
            .collect();
        for k in 0..3 {
            assert!(points_in_bounds(&full, k, n_head_us), "槽 {k} 界内");
        }
        // 偏移相对 args 头：槽 0 = n_head*32。
        assert_eq!(to_u64(&fixed.head[0]), Some(n_head * 32));
        // 材料复制共享：原尾词出现在新尾中（verbatim 或数组形
        // 前置 len=1——两种形状都保留材料）。
        let has_material = tail_words.iter().any(|w| *w == word(0xAAAA));
        assert!(has_material, "材料不丢: {tail_words:?}");
        // 幂等：再修不变。
        let fixed2 = abi_coherence_fix(&fixed, &mut Rng::new(7), true);
        assert_eq!(fixed.clone(), fixed2, "自洽化幂等");
    }

    #[test]
    fn coherent_lifi_seed_layout_is_preserved() {
        // 近似 LiFi 布局：3 偏移槽 → 段 A（bytes 形）/ 段 B（单元素
        // 数组，元组内层偏移无效 → 修复指向追加块）/ 段 C（定长）。
        // 重编码按序拼接并重算偏移——验证结构自洽而非旧偏移值。
        let tail_a = vec![word(4), word(0x1111), word(0x2222)];
        let tail_b = [word(1), word(0xAAAA), word(0x200)];
        let tail_c = [word(0xCCCC), word(0xDDDD)];
        let n_head = 3usize;
        let b_at = tail_a.len();
        let c_at = tail_a.len() + tail_b.len();
        let mut tail = tail_a.clone();
        tail.extend(tail_b.iter().copied());
        tail.extend(tail_c.iter().copied());
        let head = vec![
            word((n_head * 32) as u64),
            word(((n_head + b_at) * 32) as u64),
            word(((n_head + c_at) * 32) as u64),
        ];
        let coherent = input(head, tail);
        let fixed = abi_coherence_fix(&coherent, &mut Rng::new(9), true);
        let Tail::Bytes(tb) = &fixed.tail else {
            panic!("tail")
        };
        let tw: Vec<[u8; 32]> = tb.as_chunks::<32>().0.to_vec();
        let full: Vec<[u8; 32]> = fixed.head.iter().chain(tw.iter()).copied().collect();
        for k in 0..3 {
            assert!(points_in_bounds(&full, k, n_head), "槽 {k} 界内");
        }
        // 段 B 元组内层偏移：原 0x200 词（元素第 2 词）应被改写为
        // 元素相对自洽偏移（指向段内追加的最小 bytes 块）。
        let seg_b = value_word(&fixed.head[1]) as usize / 32 - n_head;
        let b_len = tw.len() - seg_b - tail_c.len();
        let inner_j = 2; // tail_b = [len=1, AAAA, 0x200] → 元素内第 2 词
        let inner_idx = seg_b + inner_j;
        assert_ne!(tw[inner_idx], word(0x200), "无效内层偏移应被改写");
        let seg: Vec<[u8; 32]> = tw[seg_b..seg_b + b_len].to_vec();
        let v = to_u64(&seg[inner_j]).expect("inner offset");
        // 元素相对偏移：目标词 = 元素头（词 1）+ v/32。
        let target = 1 + (v / 32) as usize;
        assert!(
            target < seg.len()
                && matches!(to_u64(&seg[target]), Some(l) if l <= SEG_LEN_CAP
                    && target + 1 + (l as usize).div_ceil(32) <= seg.len()),
            "段 B 元组内层偏移自洽: v={v:#x}"
        );
    }

    #[test]
    fn trv_shape_unchanged() {
        // TRV 形（数据槽 + 指针槽 + bytes 尾）已自洽 → 修复原样。
        let trv = input(
            vec![word(0x7d), word(0x40)],
            minimal_segment(&mut Rng::new(3)),
        );
        let fixed = abi_coherence_fix(&trv, &mut Rng::new(3), false);
        assert_eq!(fixed, trv, "自洽头形不破坏");
    }

    #[test]
    fn fixed_head_no_tail_is_noop() {
        // anyswap 定长头形（无尾）→ no-op。
        let anyswap = Input {
            selector: 0x1b91a934,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: vec![[0u8; 32]; 9],
            tail: Tail::Empty,
        };
        let fixed = abi_coherence_fix(&anyswap, &mut Rng::new(1), false);
        assert_eq!(fixed, anyswap);
    }
}
