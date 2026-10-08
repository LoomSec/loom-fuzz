//! 基础随机变异（issue #5 范围）：随机槽随机字节扰动 + 字典整词覆盖。
//! 比较操作数回灌 / 常量池整参覆盖 / 存储值入池 / 数值高斯缩放等精化
//! 算子是 #6 的职责。
//!
//! 全部随机性来自 [`Rng`]（seed_rng 决定），与执行器其它部分一样
//! 逐位确定。

use alloy_primitives::U256;
use loom_fuzz_seed::{Input, Tail, ValueDictionary};

use crate::rng::Rng;

/// 输入的去重键（corpus 去重用；与 seed crate 的 sort_key 同形：
/// selector/caller/value/head/tail 依次拼字节串）。
pub(crate) fn input_key(input: &Input) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 20 + 32 + input.head.len() * 32 + 8);
    key.extend_from_slice(&input.selector.to_be_bytes());
    key.extend_from_slice(&input.caller);
    key.extend_from_slice(&input.value.to_be_bytes::<32>());
    for word in &input.head {
        key.extend_from_slice(word);
    }
    match &input.tail {
        Tail::Empty => key.push(0),
        Tail::Bytes(b) => {
            key.push(1);
            key.extend_from_slice(&(b.len() as u64).to_be_bytes());
            key.extend_from_slice(b);
        }
        Tail::Free => key.push(2),
    }
    key
}

/// 纯随机输入：`dict = None` 时完全随机（基线用——无种子无制导
/// 也无静态知识；`Some` 时随机混入字典词（制导会话的种群填充用，
/// 字典 = 静态分析产物，属 fuzzer 的合法进场知识））。selector 固定
/// 为目标 selector（完全随机 selector 过不了 dispatcher，基线恒
/// 不可达，没有对照意义）。value 恒 0（payable 语义留给 #6）。
pub(crate) fn random_input(
    rng: &mut Rng,
    selector: u32,
    head_len: usize,
    dict: Option<&ValueDictionary>,
) -> Input {
    let head: Vec<[u8; 32]> = (0..head_len.max(1))
        .map(|_| {
            if let Some(d) = dict.filter(|d| !d.words.is_empty()) {
                if rng.below(2) == 0 {
                    return d.words[rng.below(d.words.len() as u64) as usize].to_be_bytes::<32>();
                }
            }
            rng.word()
        })
        .collect();
    Input {
        selector,
        caller: rng.address(),
        value: U256::ZERO,
        head,
        tail: Tail::Empty,
    }
}

/// 单点基础变异：对父代 clone 施加一个随机扰动。
///
/// 变异算子（等概率家族）：
/// - 随机 head 槽：50% 整词覆盖（字典非空时取字典词，否则随机词），
///   50% 随机单字节翻转；
/// - 10%：caller 换随机地址；
/// - tail 为 `Bytes` 时 20%：随机字节翻转（长度不变）。
pub(crate) fn mutate(rng: &mut Rng, parent: &Input, dict: &ValueDictionary) -> Input {
    let mut child = parent.clone();
    if !child.head.is_empty() {
        let slot = rng.below(child.head.len() as u64) as usize;
        if rng.below(2) == 0 {
            child.head[slot] = if !dict.words.is_empty() && rng.below(2) == 0 {
                dict.words[rng.below(dict.words.len() as u64) as usize].to_be_bytes::<32>()
            } else {
                rng.word()
            };
        } else {
            let byte = rng.below(32) as usize;
            child.head[slot][byte] ^= rng.next_u64() as u8;
        }
    }
    if rng.below(10) == 0 {
        child.caller = rng.address();
    }
    // 动态尾生成：tail 为 Empty/Free 时 15% 概率生成 ABI 形态的
    // 随机尾（len 字 + 32B 对齐随机数据，len ∈ 0..=64）。seed 编译器
    // M0 恒产 Empty 尾（其 assumption 已如实记录），动态尾只能由
    // 变异器带进搜索空间；比较操作数回灌等精化算子属 #6。
    if matches!(child.tail, Tail::Empty | Tail::Free) && rng.below(100) < 15 {
        let len = rng.below(65) as usize;
        let mut tail = U256::from(len).to_be_bytes::<32>().to_vec();
        let mut data = vec![0u8; len.div_ceil(32) * 32];
        rng.fill_bytes(&mut data);
        tail.extend_from_slice(&data);
        child.tail = Tail::Bytes(tail);
    }
    if let Tail::Bytes(tail) = &mut child.tail {
        if !tail.is_empty() && rng.below(5) == 0 {
            let byte = rng.below(tail.len() as u64) as usize;
            tail[byte] ^= rng.next_u64() as u8;
        }
    }
    child
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict() -> ValueDictionary {
        ValueDictionary {
            words: vec![U256::from(0x42u64), U256::from(0x1000u64)],
        }
    }

    #[test]
    fn mutate_is_deterministic_under_same_rng() {
        let parent = Input {
            selector: 0x90ce82d4,
            caller: [0x11; 20],
            value: U256::ZERO,
            head: vec![[0u8; 32]; 2],
            tail: Tail::Empty,
        };
        let d = dict();
        let a = mutate(&mut Rng::new(9), &parent, &d);
        let b = mutate(&mut Rng::new(9), &parent, &d);
        assert_eq!(a, b);
    }

    #[test]
    fn mutate_keeps_shape() {
        let parent = Input {
            selector: 0x90ce82d4,
            caller: [0x11; 20],
            value: U256::ZERO,
            head: vec![[0u8; 32]; 3],
            tail: Tail::Bytes(vec![1, 2, 3, 4]),
        };
        let d = dict();
        let mut rng = Rng::new(3);
        for _ in 0..64 {
            let child = mutate(&mut rng, &parent, &d);
            // 形状保持：selector/槽数/tail 长度不变；tail 内容允许
            // 扰动（变异算子的行为）。
            assert_eq!(child.selector, parent.selector);
            assert_eq!(child.head.len(), 3);
            match &child.tail {
                Tail::Bytes(t) => assert_eq!(t.len(), 4),
                other => panic!("tail 形状被改变: {other:?}"),
            }
        }
    }

    #[test]
    fn random_input_uses_dict_words() {
        let d = dict();
        let mut rng = Rng::new(5);
        let input = random_input(&mut rng, 0x90ce82d4, 4, Some(&d));
        assert_eq!(input.selector, 0x90ce82d4);
        assert_eq!(input.head.len(), 4);
        assert_eq!(input.value, U256::ZERO);

        // 纯随机模式：不混字典词。
        let pure = random_input(&mut Rng::new(5), 0x90ce82d4, 4, None);
        assert!(!d
            .words
            .iter()
            .any(|w| pure.head.contains(&w.to_be_bytes::<32>())));
    }
}
