//! 输入构造小工具：去重键 + 纯随机输入生成（制导会话种群填充与
//! 纯随机基线用）。变异算子本体（基础 legacy 系列 + #6 五算子）
//! 在 [`crate::mutators`] 模块。
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
pub fn random_input(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dict() -> ValueDictionary {
        ValueDictionary {
            words: vec![U256::from(0x42u64), U256::from(0x1000u64)],
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

    #[test]
    fn input_key_is_dedup_qualified() {
        let a = Input {
            selector: 0xdeadbeef,
            caller: [0x11; 20],
            value: U256::ZERO,
            head: vec![[0u8; 32]; 2],
            tail: Tail::Empty,
        };
        let mut b = a.clone();
        assert_eq!(input_key(&a), input_key(&b));
        b.head[1][31] = 1;
        assert_ne!(input_key(&a), input_key(&b));
        b = a.clone();
        b.tail = Tail::Bytes(vec![1]);
        assert_ne!(input_key(&a), input_key(&b));
    }
}
