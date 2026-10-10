//! 序列级组装算子（issue #35）：把提案器的**步级**候选组装成调用
//! 序列——append（加长）/ splice（拼接素材）/ 步内变异（复用既有
//! 五变异算子）。全部机械通用（零个案），确定性由会话 rng
//! （xorshift64*）驱动。
//!
//! # 素材来源（信用分配的关键）
//!
//! 组装素材 = 反馈窗序列 **∪ 会话步级池**（step_pool：一切运行
//! 见过的步输入，去重有上限 FIFO）——多步攻击的"布置步"常常是
//! fitness 死路（布置分支离目标帧更远，整序列 min 距离反而变
//! 差，会被 corpus 精英淘汰），但它的步级输入在步级池里留存，
//! append/splice 随时可把它与"触发步"配对。无步级池时序列搜索
//! 会在信用分配上饿死（issue #35 实测）。
//!
//! # 配比（每次组装一次投掷）
//!
//! | 区间 | 行为 |
//! |---|---|
//! | 0-59 | 单步 `[proposed]`（与旧行为一致，步级利用为主） |
//! | 60-79 | append：取一素材序列（反馈或步级池单步），从合约表 |
//! |      | 选目标追加一步（新步输入克隆随机素材步或随机填充） |
//! | 80-99 | splice：两个不同素材序列拼接，截断到 `max_steps` |
//!
//! 组装出的多步序列再经一步内变异（50% 概率挑一步跑既有
//! `mutators::mutate`——五算子原样复用，池与会话共享）。
//!
//! **max_steps == 1 时本模块不消耗任何随机数且恒返回单步**
//! ——单步路径与旧行为逐位一致（回归保证）。

use alloy_primitives::U256;
use loom_fuzz_seed::{Input, Step, TxSequence, ValueDictionary};

use crate::mutate::random_input;
use crate::mutators::{mutate, MutCtx};
use crate::rng::Rng;

use super::exec::RunFeedback;

/// 组装上下文（会话级常量 + 共享池，见 exec.rs 进化环调用点）。
pub(crate) struct AssembleCtx<'a> {
    /// victim 地址（单步缺省目标 / 合约表首位）。
    pub address: [u8; 20],
    /// 合约表（victim + 各部署）：新步目标从中机械选取。
    pub table: &'a [[u8; 20]],
    /// 步级池（会话累积的步素材，以单步序列形态参与素材选取）。
    pub step_pool: &'a [Step],
    /// 序列长度上限（ExecConfig.max_steps）。
    pub max_steps: u32,
    /// 动态头证据（issue #48）→ 步内变异的 abifix 宽头放行。
    pub dynamic_head: bool,
    /// 目标 selector（随机填充步用）。
    pub selector: u32,
    /// head 槽数提示（随机填充步用）。
    pub head_len_hint: usize,
    /// 值字典（随机填充步用）。
    pub dict: &'a ValueDictionary,
    /// 常量池（步内变异用）。
    pub consts: &'a [U256],
    /// 比较操作数池（步内变异用）。
    pub cmp_pool: &'a [U256],
    /// 存储观测池（步内变异用）。
    pub storage_pool: &'a [(U256, U256)],
}

/// 素材视图：反馈窗序列 + 步级池单步序列，统一索引空间。
struct Sources<'a> {
    feedback: &'a [RunFeedback],
    step_pool: &'a [Step],
}

impl<'a> Sources<'a> {
    /// 非空素材序列数（反馈序列 + 步级池单步）。
    fn total(&self) -> u64 {
        let fb = self
            .feedback
            .iter()
            .filter(|f| !f.seq.steps.is_empty())
            .count() as u64;
        fb + self.step_pool.len() as u64
    }
    /// 取第 i 个素材序列的克隆（越界 = None，调用方已按 total 约束）。
    fn get(&self, i: u64) -> Option<TxSequence> {
        let n_fb = self
            .feedback
            .iter()
            .filter(|f| !f.seq.steps.is_empty())
            .count();
        if (i as usize) < n_fb {
            return self
                .feedback
                .iter()
                .map(|f| &f.seq)
                .filter(|s| !s.steps.is_empty())
                .nth(i as usize)
                .cloned();
        }
        self.step_pool.get(i as usize - n_fb).map(|st| TxSequence {
            steps: vec![st.clone()],
        })
    }
    /// 随机素材步（跨反馈序列与步级池的步级"基因"交换）。
    fn random_step(&self, rng: &mut Rng) -> Option<Step> {
        let total_steps: u64 = self
            .feedback
            .iter()
            .map(|f| f.seq.steps.len() as u64)
            .sum::<u64>()
            + self.step_pool.len() as u64;
        if total_steps == 0 {
            return None;
        }
        let mut r = rng.below(total_steps);
        for f in self.feedback {
            if r < f.seq.steps.len() as u64 {
                return Some(f.seq.steps[r as usize].clone());
            }
            r -= f.seq.steps.len() as u64;
        }
        Some(self.step_pool[r as usize].clone())
    }
}

/// 步级候选 → 调用序列（见模块文档配比）。
pub(crate) fn assemble(
    rng: &mut Rng,
    proposed: Input,
    feedback: &[RunFeedback],
    ctx: &AssembleCtx<'_>,
) -> TxSequence {
    if ctx.max_steps <= 1 {
        // 单步默认：不耗随机数，逐位等价旧路径。
        return TxSequence::single(ctx.address, proposed);
    }
    let src = Sources {
        feedback,
        step_pool: ctx.step_pool,
    };
    let roll = rng.below(100);
    let mut seq = if roll < crate::tuning::TUNING.seq_single_band {
        TxSequence::single(ctx.address, proposed)
    } else if roll < crate::tuning::TUNING.seq_append_band {
        append(rng, &proposed, &src, ctx)
    } else {
        splice(rng, &proposed, &src, ctx)
    };
    // 步内变异：多步序列 50% 挑一步跑既有五算子。
    if seq.steps.len() > 1 && rng.below(crate::tuning::TUNING.seq_step_mutate_denom) == 0 {
        let idx = rng.below(seq.steps.len() as u64) as usize;
        let mut mctx = MutCtx::new(rng, ctx.consts, ctx.cmp_pool, ctx.storage_pool);
        mctx.dynamic_head = ctx.dynamic_head;
        seq.steps[idx].input = mutate(&seq.steps[idx].input, &mut mctx);
    }
    seq
}

/// append：一素材序列（随机挑，缺省 `[proposed]`）+ 从合约表选
/// 目标追加一步（输入 50% 克隆随机素材步 / 50% 随机填充）。
fn append(rng: &mut Rng, proposed: &Input, src: &Sources<'_>, ctx: &AssembleCtx<'_>) -> TxSequence {
    let total = src.total();
    let mut seq = if total == 0 {
        TxSequence::single(ctx.address, proposed.clone())
    } else {
        src.get(rng.below(total)).expect("索引在 total 内")
    };
    if seq.steps.len() as u32 >= ctx.max_steps {
        return seq;
    }
    let target = ctx.table[rng.below(ctx.table.len() as u64) as usize];
    let input = if rng.below(2) == 0 {
        src.random_step(rng)
            .map(|st| st.input)
            .unwrap_or_else(|| random_input(rng, ctx.selector, ctx.head_len_hint, Some(ctx.dict)))
    } else {
        random_input(rng, ctx.selector, ctx.head_len_hint, Some(ctx.dict))
    };
    seq.steps.push(Step { target, input });
    seq
}

/// splice：两个不同素材序列拼接（素材不足时退化为素材 +
/// `[proposed]`），截断到 `max_steps`（至少留一步）。
fn splice(rng: &mut Rng, proposed: &Input, src: &Sources<'_>, ctx: &AssembleCtx<'_>) -> TxSequence {
    let total = src.total();
    let mut seq = match total {
        0 => TxSequence::single(ctx.address, proposed.clone()),
        1 => {
            let mut s = src.get(0).expect("total=1");
            s.steps
                .extend(TxSequence::single(ctx.address, proposed.clone()).steps);
            s
        }
        _ => {
            let a = rng.below(total);
            let mut b = rng.below(total);
            if b == a {
                b = (b + 1) % total;
            }
            let mut s = src.get(a).expect("索引在 total 内");
            s.steps.extend(src.get(b).expect("索引在 total 内").steps);
            s
        }
    };
    seq.steps.truncate(ctx.max_steps.max(1) as usize);
    seq
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(tag: u8) -> Input {
        let mut head = [0u8; 32];
        head[31] = tag;
        Input {
            selector: 0xdeadbeef,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: vec![head],
            tail: loom_fuzz_seed::Tail::Empty,
        }
    }

    fn fb(seq: TxSequence, distance: u32) -> RunFeedback {
        RunFeedback {
            seq,
            outcome: super::super::exec::OutcomeKind::Stop,
            best_distance: distance,
            reverted_guard: None,
        }
    }

    fn ctx<'a>(max_steps: u32, table: &'a [[u8; 20]]) -> AssembleCtx<'a> {
        static EMPTY_DICT: ValueDictionary = ValueDictionary { words: Vec::new() };
        AssembleCtx {
            address: [0x22; 20],
            table,
            step_pool: &[],
            max_steps,
            dynamic_head: false,
            selector: 0xdeadbeef,
            head_len_hint: 1,
            dict: &EMPTY_DICT,
            consts: &[],
            cmp_pool: &[],
            storage_pool: &[],
        }
    }

    const TABLE: [[u8; 20]; 2] = [[0x22; 20], [0xaau8; 20]];

    #[test]
    fn max_steps_one_is_always_single_no_rng_draw() {
        let mut rng = Rng::new(7);
        let feedback = vec![fb(
            TxSequence {
                steps: vec![
                    Step {
                        target: [0x22; 20],
                        input: input(1),
                    },
                    Step {
                        target: [0xaau8; 20],
                        input: input(2),
                    },
                ],
            },
            1,
        )];
        // max_steps = 1：无论反馈窗里有什么，恒单步且不耗 rng
        // （两次调用后流位置不变——用后续 draw 验证）。
        let c = ctx(1, &TABLE);
        let s1 = assemble(&mut rng, input(9), &feedback, &c);
        assert_eq!(s1.steps.len(), 1);
        assert_eq!(s1.steps[0].input, input(9));
        assert_eq!(s1.steps[0].target, [0x22; 20]);
        let probe = rng.below(1_000_000);
        let mut rng2 = Rng::new(7);
        assert_eq!(rng2.below(1_000_000), probe, "max_steps=1 不耗随机数");
    }

    #[test]
    fn append_extends_within_cap_and_targets_table() {
        let c = ctx(4, &TABLE);
        let feedback = vec![fb(TxSequence::single([0x22; 20], input(1)), 1)];
        let mut saw_multi = false;
        for seed in 0..50u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, input(9), &feedback, &c);
            assert!(!s.steps.is_empty() && s.steps.len() <= 4);
            assert!(s.steps.iter().all(|st| TABLE.contains(&st.target)));
            if s.steps.len() > 1 {
                saw_multi = true;
            }
        }
        assert!(saw_multi, "append 应多步出现");
    }

    #[test]
    fn splice_concatenates_and_truncates() {
        let c = ctx(3, &TABLE);
        let feedback = vec![
            fb(
                TxSequence {
                    steps: vec![
                        Step {
                            target: [0x22; 20],
                            input: input(1),
                        },
                        Step {
                            target: [0x22; 20],
                            input: input(2),
                        },
                    ],
                },
                1,
            ),
            fb(
                TxSequence {
                    steps: vec![
                        Step {
                            target: [0xaau8; 20],
                            input: input(3),
                        },
                        Step {
                            target: [0x22; 20],
                            input: input(4),
                        },
                    ],
                },
                2,
            ),
        ];
        for seed in 0..50u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, input(9), &feedback, &c);
            assert!(!s.steps.is_empty() && s.steps.len() <= 3);
        }
    }

    /// 步级池素材参与配对：布置步只在步级池（不在反馈窗）时，
    /// splice/append 也能组出 [setup, trigger]。
    #[test]
    fn step_pool_feeds_assembly() {
        let setup = Step {
            target: [0x22; 20],
            input: input(7),
        };
        let trigger = Step {
            target: [0x22; 20],
            input: input(8),
        };
        let step_pool = vec![setup.clone(), trigger.clone()];
        let ctx = AssembleCtx {
            step_pool: &step_pool,
            ..ctx(3, &TABLE)
        };
        // 反馈窗空：素材全来自步级池。
        let feedback = Vec::new();
        let mut saw_pair = false;
        for seed in 0..200u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, input(9), &feedback, &ctx);
            if s.steps.len() == 2
                && s.steps[0].input == setup.input
                && s.steps[1].input == trigger.input
            {
                saw_pair = true;
                break;
            }
        }
        assert!(saw_pair, "步级池素材应能被拼接成对");
    }

    #[test]
    fn assemble_is_deterministic() {
        let c = ctx(3, &TABLE);
        let feedback = vec![fb(TxSequence::single([0x22; 20], input(1)), 1)];
        let run = |seed: u64| {
            let mut rng = Rng::new(seed);
            assemble(&mut rng, input(9), &feedback, &c)
        };
        assert_eq!(run(42), run(42));
    }
}
