//! 可插拔提案器（issue #25 分层搜索）：DictionaryProposer（默认，
//! 既有基座 + 协同变异的封装）与 LlmProposer（feature `llm`，
//! LLM 候选 + fail-closed 回退字典）。**判决独立**：judge/oracle
//! 不感知提案器；LLM 只影响搜索路径不影响判决；replay 无 LLM
//! 参与，verdict 一致。

use alloy_primitives::U256;
use loom_fuzz_seed::{Input, ValueDictionary};

use crate::mutators::{mutate, MutCtx};
use crate::rng::Rng;

use super::exec::{ProposalBudget, Proposer, ProposerCtx, RunFeedback};

/// 一次 LLM 交互（prompt/响应全量落盘，fuzz_report llm_interactions
/// 节）。独立于 feature 门控（报告结构常需）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LlmInteraction {
    pub prompt: String,
    pub response: String,
    pub ok: bool,
    pub error: Option<String>,
}

/// 反馈窗口（每代喂给提案器的最近 N 条 run 反馈）。
pub const FEEDBACK_WINDOW: usize = 32;

/// 每代候选上限（与旧 select_parents 的前一半同量级）。
pub const DEFAULT_MAX_CANDIDATES: usize = 32;

/// 字典提案器（默认）：反馈前一半的父代各经一轮变异（既有五算子
/// + 多槽协同的封装；池经 `refresh` 每代刷新）。
///
/// 完全确定性（内部 xorshift64*，种子随 ExecConfig.seed_rng）。
pub struct DictionaryProposer {
    rng: Rng,
    consts: Vec<U256>,
    cmp_pool: Vec<U256>,
    storage_pool: Vec<(U256, U256)>,
}

impl DictionaryProposer {
    pub fn new(seed: u64) -> Self {
        DictionaryProposer {
            rng: Rng::new(seed),
            consts: Vec::new(),
            cmp_pool: Vec::new(),
            storage_pool: Vec::new(),
        }
    }
}

impl Proposer for DictionaryProposer {
    fn refresh(&mut self, ctx: &ProposerCtx<'_>) {
        self.consts = ctx.consts.to_vec();
        self.cmp_pool = ctx.cmp_pool.to_vec();
        self.storage_pool = ctx.storage_pool.to_vec();
    }

    fn propose(&mut self, feedback: &[RunFeedback], budget: ProposalBudget) -> Vec<Input> {
        if budget.max_candidates == 0 || budget.time_left.is_zero() {
            return Vec::new();
        }
        // 父代：按**距离升序**（fitness 最优优先）前一半（至少 1
        // 个），按输入去重。距离相同的按字典序键（确定性）。
        let mut parents: Vec<(u32, &Input)> = feedback
            .iter()
            .map(|f| (f.best_distance, &f.input))
            .collect();
        parents.sort_by_key(|(d, i)| (*d, input_key(i)));
        parents.dedup_by_key(|(_, i)| input_key(i));
        let keep = (parents.len() / 2).max(1).min(budget.max_candidates);
        parents
            .into_iter()
            .take(keep)
            .map(|(_, i)| i)
            .map(|parent| {
                let mut ctx = MutCtx::new(
                    &mut self.rng,
                    &self.consts,
                    &self.cmp_pool,
                    &self.storage_pool,
                );
                mutate(parent, &mut ctx)
            })
            .collect()
    }
}

/// 输入去重键（与 seed sort_key 同形）。
fn input_key(input: &Input) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 20 + 32 + input.head.len() * 32 + 8);
    key.extend_from_slice(&input.selector.to_be_bytes());
    key.extend_from_slice(&input.caller);
    key.extend_from_slice(&input.value.to_be_bytes::<32>());
    for word in &input.head {
        key.extend_from_slice(word);
    }
    match &input.tail {
        loom_fuzz_seed::Tail::Empty => key.push(0),
        loom_fuzz_seed::Tail::Bytes(b) => {
            key.push(1);
            key.extend_from_slice(&(b.len() as u64).to_be_bytes());
            key.extend_from_slice(b);
        }
        loom_fuzz_seed::Tail::Free => key.push(2),
    }
    key
}

/// 构造助手：从词列表组 head（LLM 候选解析用；≥1 词时尾部弃
/// 标点语义——LLM 只产定长词序列，动态尾仍归字典路径）。
pub fn words_to_input(selector: u32, caller: [u8; 20], words: &[U256]) -> Input {
    Input {
        selector,
        caller,
        value: U256::ZERO,
        head: words.iter().map(|w| w.to_be_bytes::<32>()).collect(),
        tail: loom_fuzz_seed::Tail::Empty,
    }
}

/// 从值字典的词上限（prompt 上下文防爆炸）。
pub const LLM_DICT_PREVIEW: usize = 24;

#[allow(dead_code)]
fn _dict_preview(dict: &ValueDictionary) -> Vec<U256> {
    dict.words.iter().take(LLM_DICT_PREVIEW).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{GuardFeedback, OutcomeKind};
    use std::time::Duration;

    fn fb(input: Input, distance: u32) -> RunFeedback {
        RunFeedback {
            input,
            outcome: OutcomeKind::Revert,
            best_distance: distance,
            reverted_guard: Some(GuardFeedback {
                pc: 7,
                cond_rendered: "x".into(),
                polarity_failed: true,
            }),
        }
    }

    #[test]
    fn dictionary_proposer_is_deterministic() {
        let mk = |a: u64| {
            let mut h = vec![[0u8; 32]; 2];
            h[0][31] = a as u8;
            Input {
                selector: 0xdeadbeef,
                caller: [0x33; 20],
                value: U256::ZERO,
                head: h,
                tail: loom_fuzz_seed::Tail::Empty,
            }
        };
        let feedback = vec![fb(mk(1), 2), fb(mk(2), 1)];
        let budget = ProposalBudget {
            max_candidates: 4,
            time_left: Duration::from_secs(1),
        };
        let run = || {
            let mut p = DictionaryProposer::new(9);
            p.refresh(&ProposerCtx {
                consts: &[U256::from(0x42u64)],
                cmp_pool: &[U256::from(0x99u64)],
                storage_pool: &[(U256::ZERO, U256::from(1u64))],
            });
            p.propose(&feedback, budget)
        };
        assert_eq!(run(), run(), "同种子同反馈提案应逐位确定");
        assert!(!run().is_empty());
    }
}
