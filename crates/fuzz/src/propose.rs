//! 提案器（issue #25 分层搜索，#29 决策简化）：DictionaryProposer
//! 是唯一实现——既有字典基座 + 多槽协同变异的封装，反馈窗/精英/
//! 池刷新结构由它承载。**判决独立**：judge/oracle 不感知提案器；
//! replay 不经搜索层，verdict 一致。

use alloy_primitives::U256;
use loom_fuzz_seed::Input;

use crate::mutators::{mutate, MutCtx};
use crate::rng::Rng;

use super::exec::{ProposalBudget, Proposer, ProposerCtx, RunFeedback};

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
    dynamic_head: bool,
}

impl DictionaryProposer {
    pub fn new(seed: u64) -> Self {
        DictionaryProposer {
            rng: Rng::new(seed),
            consts: Vec::new(),
            cmp_pool: Vec::new(),
            storage_pool: Vec::new(),
            dynamic_head: false,
        }
    }
}

impl Proposer for DictionaryProposer {
    fn refresh(&mut self, ctx: &ProposerCtx<'_>) {
        self.consts = ctx.consts.to_vec();
        self.cmp_pool = ctx.cmp_pool.to_vec();
        self.storage_pool = ctx.storage_pool.to_vec();
        self.dynamic_head = ctx.dynamic_head;
    }

    fn propose(&mut self, feedback: &[RunFeedback], budget: ProposalBudget) -> Vec<Input> {
        if budget.max_candidates == 0 || budget.time_left.is_zero() {
            return Vec::new();
        }
        // 父代：按**距离升序**（fitness 最优优先）前一半（至少 1
        // 个），按输入去重。距离相同的按字典序键（确定性）。
        // 父代是**序列**：取其中一步作步级变异亲本——单步父代不耗
        // 随机数（逐位等价旧路径）；多步父代随机挑一步（序列的其
        // 他步由执行环的组装算子负责传承/扩展）。
        let mut parents: Vec<(u32, &Input)> = feedback
            .iter()
            .map(|f| {
                let steps = &f.seq.steps;
                let idx = if steps.len() > 1 {
                    self.rng.below(steps.len() as u64) as usize
                } else {
                    0
                };
                (f.best_distance, &steps[idx].input)
            })
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
                ctx.dynamic_head = self.dynamic_head;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{GuardFeedback, OutcomeKind};
    use std::time::Duration;

    fn fb(input: Input, distance: u32) -> RunFeedback {
        RunFeedback {
            seq: loom_fuzz_seed::TxSequence::single([0x22; 20], input),
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
                dynamic_head: false,
            });
            p.propose(&feedback, budget)
        };
        assert_eq!(run(), run(), "同种子同反馈提案应逐位确定");
        assert!(!run().is_empty());
    }
}
