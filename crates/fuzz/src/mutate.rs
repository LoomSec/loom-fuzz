//! 输入构造小工具：纯随机输入生成（制导会话种群填充与纯随机
//! 基线用）。变异算子本体（基础 legacy 系列 + #6 五算子）在
//! [`crate::mutators`] 模块；序列级组装算子在 [`crate::sequence`]。
//!
//! 全部随机性来自 [`Rng`]（seed_rng 决定），与执行器其它部分一样
//! 逐位确定。

use alloy_primitives::U256;
use loom_fuzz_seed::{Input, Tail, ValueDictionary};

use crate::rng::Rng;

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
}
