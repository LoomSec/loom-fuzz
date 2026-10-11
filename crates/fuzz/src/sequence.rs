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
//! | 0-44 | 单步 `[proposed]`（步级利用为主） |
//! | 45-64 | **定向配对**（issue #54）：步级池抽守卫写者步前置 + 目标步 |
//! | 65-84 | append：取一素材序列（反馈或步级池单步），从合约表 |
//! |      | 选目标追加一步（新步输入克隆随机素材步或随机填充） |
//! | 85-99 | splice：两个不同素材序列拼接，截断到 `max_steps` |
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
    /// 守卫写者 selector 集（issue #54 辅助制导：append 随机填充步
    /// 以 TUNING.guard_writer_step_denom 概率换用其一；空 = 关闭）。
    pub guard_writers: &'a [u32],
    /// 多合约探索函数表（issue #57）：shard 函数表 selector 集。
    /// append 随机填充步以 1/TUNING.seq_explore_denom 概率换用
    /// 其一（合约表任成员 × 函数表任 selector 的探索步）；空 =
    /// 关闭（不消耗投掷，逐位等价旧行为）。
    pub func_table: &'a [u32],
    /// 种子中的守卫写者步（issue #54 配对：调用方供给的已知良性
    /// 布置素材——selector ∈ guard_writers 的种子步，优先于池素材）。
    pub seed_writers: &'a [Step],
    /// 种子中的目标步（issue #54 配对：selector == 命中 selector 的
    /// 种子步——携带种子编译器/调用方供给的已知最优目标 calldata）。
    pub seed_targets: &'a [Step],
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
    } else if roll < crate::tuning::TUNING.seq_pair_band {
        pair(rng, &proposed, &src, ctx)
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

/// 定向配对（issue #54 多步拼序）：步级池中抽守卫写者步（selector
/// ∈ 守卫写者闭包——loom 事实驱动的布置步候选），与目标步配对。
/// 两种形态（各 50%）：
/// (a) `[写者, 目标]`——目标优先种子目标步（调用方供给的已知最优
///     目标 calldata）其次步级池中 selector == 命中 selector 的素材，
///     均原样使用（不交接防破坏）；缺省提案候选（效果词交接 = 参数
///     跨步耦合）。
/// (b) `写者前置`——写者步（种子写者 50% 优先）插到随机素材序列头部
///     （[lock, extend, migrate] 类多布置链由多次前置 + splice 拼出）。
/// 无写者素材（守卫写者集空 / 池尚无写者步）时退化 append——配对带
/// 不浪费。
fn pair(rng: &mut Rng, proposed: &Input, src: &Sources<'_>, ctx: &AssembleCtx<'_>) -> TxSequence {
    if ctx.guard_writers.is_empty() {
        return append(rng, proposed, src, ctx);
    }
    let writers: Vec<&Step> = src
        .step_pool
        .iter()
        .filter(|st| ctx.guard_writers.contains(&st.input.selector))
        .collect();
    let seed_writer = !ctx.seed_writers.is_empty() && rng.below(2) == 0;
    if writers.is_empty() && !seed_writer {
        return append(rng, proposed, src, ctx);
    }
    let writer: Step = if seed_writer {
        ctx.seed_writers[rng.below(ctx.seed_writers.len() as u64) as usize].clone()
    } else {
        (*writers[rng.below(writers.len() as u64) as usize]).clone()
    };
    if rng.below(2) == 0 {
        // 形态 (a)：写者 + 目标步。
        if !ctx.seed_targets.is_empty() && rng.below(2) == 0 {
            // 种子目标：已知最优目标 calldata，原样使用（不交接）。
            let target =
                ctx.seed_targets[rng.below(ctx.seed_targets.len() as u64) as usize].clone();
            // 双写者布置链（max_steps ≥ 3 且种子写者 ≥ 2）：[w1, w2,
            // 目标]——跨步语义链（如 建锁→改期→迁移：中间步是目标
            // 守卫的硬前置，两两步对永远到不了）由种子素材直接拼出。
            if ctx.max_steps >= 3 && ctx.seed_writers.len() >= 2 && rng.below(2) == 0 {
                let n = ctx.seed_writers.len() as u64;
                let i = rng.below(n) as usize;
                let mut j = rng.below(n - 1) as usize;
                if j >= i {
                    j += 1;
                }
                TxSequence {
                    steps: vec![
                        ctx.seed_writers[i].clone(),
                        ctx.seed_writers[j].clone(),
                        target,
                    ],
                }
            } else {
                TxSequence {
                    steps: vec![writer, target],
                }
            }
        } else {
            let pool_targets: Vec<&Step> = src
                .step_pool
                .iter()
                .filter(|st| st.input.selector == ctx.selector)
                .collect();
            if !pool_targets.is_empty() && rng.below(2) == 0 {
                // 池素材目标：已知最优 calldata，原样使用（不交接）。
                TxSequence {
                    steps: vec![
                        writer,
                        (*pool_targets[rng.below(pool_targets.len() as u64) as usize]).clone(),
                    ],
                }
            } else {
                let mut target = proposed.clone();
                handoff(rng, &mut target, ctx);
                TxSequence {
                    steps: vec![
                        writer,
                        Step {
                            target: ctx.address,
                            input: target,
                        },
                    ],
                }
            }
        }
    } else {
        // 形态 (b)：写者前置到随机素材序列头部。
        let total = src.total();
        if total == 0 {
            return TxSequence::single(ctx.address, proposed.clone());
        }
        let mut seq = src.get(rng.below(total)).expect("索引在 total 内");
        if seq.steps.len() as u32 >= ctx.max_steps {
            return TxSequence::single(ctx.address, proposed.clone());
        }
        seq.steps.insert(0, writer);
        seq
    }
}

/// 参数跨步耦合（issue #54）：配对序列的目标步从观测池交接一个词——
/// 守卫写者步执行后其读写的键值（nextId 类 id 词）已逐代入
/// storage/cmp 观测池（exec.rs 每代快照回灌），目标步的同义参数槽
/// 覆写为该词。零槽优先（未绑定词——不破坏 proposer 已解守卫绑定），
/// 无零槽随机槽。全部既有 loom 观测设施，零个案。
fn handoff(rng: &mut Rng, target: &mut Input, ctx: &AssembleCtx<'_>) {
    if target.head.is_empty() {
        return;
    }
    let word = if !ctx.storage_pool.is_empty() && rng.below(2) == 0 {
        Some(ctx.storage_pool[rng.below(ctx.storage_pool.len() as u64) as usize].1)
    } else if !ctx.cmp_pool.is_empty() {
        Some(ctx.cmp_pool[rng.below(ctx.cmp_pool.len() as u64) as usize])
    } else {
        None
    };
    let Some(word) = word else { return };
    let zeros: Vec<usize> = target
        .head
        .iter()
        .enumerate()
        .filter(|(_, w)| w.iter().all(|b| *b == 0))
        .map(|(i, _)| i)
        .collect();
    let slot = if !zeros.is_empty() && rng.below(2) == 0 {
        zeros[rng.below(zeros.len() as u64) as usize]
    } else {
        rng.below(target.head.len() as u64) as usize
    };
    target.head[slot] = word.to_be_bytes::<32>();
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
            .unwrap_or_else(|| fill_step(rng, ctx))
    } else {
        fill_step(rng, ctx)
    };
    seq.steps.push(Step { target, input });
    seq
}

/// 追加步的随机填充输入：守卫写者 selector 优先（1/denom，
/// issue #54），其次多合约探索带（1/TUNING.seq_explore_denom，
/// issue #57——shard 函数表任 selector × 合约表任成员）；两者
/// 皆空时不消耗投掷，逐位等价旧行为。
fn fill_step(rng: &mut Rng, ctx: &AssembleCtx<'_>) -> Input {
    let mut selector = ctx.selector;
    if !ctx.guard_writers.is_empty()
        && rng.below(crate::tuning::TUNING.guard_writer_step_denom) == 0
    {
        selector = ctx.guard_writers[rng.below(ctx.guard_writers.len() as u64) as usize];
    } else if !ctx.func_table.is_empty() && rng.below(crate::tuning::TUNING.seq_explore_denom) == 0
    {
        selector = ctx.func_table[rng.below(ctx.func_table.len() as u64) as usize];
    }
    random_input(rng, selector, ctx.head_len_hint, Some(ctx.dict))
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
            guard_writers: &[],
            seed_writers: &[],
            seed_targets: &[],
            func_table: &[],
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

    /// issue #54 辅助制导：append 随机填充步以
    /// 1/TUNING.guard_writer_step_denom 概率换用守卫写者 selector。
    #[test]
    fn guard_writers_bias_fill_steps() {
        let guard_writers = vec![0x1111_1111, 0x2222_2222];
        let ctx = AssembleCtx {
            guard_writers: &guard_writers,
            ..ctx(4, &TABLE)
        };
        let feedback = vec![fb(TxSequence::single([0x22; 20], input(1)), 1)];
        let mut hits = 0usize;
        for seed in 0..200u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, input(9), &feedback, &ctx);
            if s.steps
                .iter()
                .any(|st| guard_writers.contains(&st.input.selector))
            {
                hits += 1;
            }
        }
        assert!(hits > 0, "守卫写者 selector 应出现在追加步中");
    }

    /// issue #54 多步拼序：定向配对两种形态——(a) 写者 + 目标步
    /// （提案候选），(b) 写者前置到素材序列头部。
    #[test]
    fn pair_builds_writer_then_target() {
        let guard_writers = vec![0xdeadbeef];
        let writer_step = Step {
            target: [0x22; 20],
            input: input(7),
        };
        let step_pool = vec![writer_step.clone()];
        // selector 与写者不同：池素材目标过滤不命中，(a) 形态度
        // 用提案候选（测试确定性）。
        let base = ctx(3, &TABLE);
        let ctx = AssembleCtx {
            step_pool: &step_pool,
            guard_writers: &guard_writers,
            selector: 0x9999,
            ..base
        };
        let feedback = Vec::new();
        let mut proposed = input(9);
        proposed.selector = 0xcafebabe;
        let mut form_a = 0usize;
        let mut form_b = 0usize;
        for seed in 0..400u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, proposed.clone(), &feedback, &ctx);
            if s.steps.len() == 2
                && s.steps[0].input == writer_step.input
                && s.steps[1].input.selector == 0xcafebabe
                && s.steps[1].target == [0x22; 20]
            {
                form_a += 1;
            }
            if s.steps.len() >= 2 && s.steps[0].input == writer_step.input {
                form_b += 1;
            }
        }
        assert!(form_a > 0, "形态 (a) 写者+目标步应出现");
        assert!(form_b > 0, "形态 (b) 写者前置应出现");
    }

    /// issue #54 多步拼序：定向配对形态 (a)——种子写者 + 种子目标
    /// （已知最优 calldata 原样配对，不交接）。
    #[test]
    fn pair_prefers_seed_writer_and_seed_target() {
        let guard_writers = vec![0xdeadbeef];
        let seed_writer = Step {
            target: [0x22; 20],
            input: input(7),
        };
        let seed_target = Step {
            target: [0x22; 20],
            input: input(8),
        };
        let seed_writers = vec![seed_writer.clone()];
        let seed_targets = vec![seed_target.clone()];
        let ctx = AssembleCtx {
            step_pool: &[],
            guard_writers: &guard_writers,
            seed_writers: &seed_writers,
            seed_targets: &seed_targets,
            selector: 0x9999,
            ..ctx(3, &TABLE)
        };
        let feedback = Vec::new();
        let mut proposed = input(9);
        proposed.selector = 0xcafebabe;
        let mut hits = 0usize;
        for seed in 0..400u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, proposed.clone(), &feedback, &ctx);
            if s.steps == vec![seed_writer.clone(), seed_target.clone()] {
                hits += 1;
            }
        }
        assert!(hits > 0, "种子写者 + 种子目标应被直接配对");
    }

    /// issue #57 多合约探索带：函数表非空时 append 随机填充步以
    /// 1/TUNING.seq_explore_denom 概率换用函数表 selector（非命中
    /// selector 的探索步）；空函数表不消耗投掷。
    #[test]
    fn explore_band_uses_func_table() {
        let func_table = vec![0xaaaa0001, 0xaaaa0002, 0xaaaa0003];
        let actx = AssembleCtx {
            func_table: &func_table,
            ..ctx(4, &TABLE)
        };
        let feedback = vec![fb(TxSequence::single([0x22; 20], input(1)), 1)];
        let mut hits = 0usize;
        for seed in 0..400u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, input(9), &feedback, &actx);
            if s.steps
                .iter()
                .any(|st| func_table.contains(&st.input.selector))
            {
                hits += 1;
            }
        }
        assert!(hits > 0, "函数表 selector 应出现在探索步中");
        // 空函数表：探索带关闭（不 panic、不出现探索投掷效果）。
        let c = ctx(4, &TABLE);
        for seed in 0..50u64 {
            let mut rng = Rng::new(seed);
            let s = assemble(&mut rng, input(9), &feedback, &c);
            assert!(s.steps.iter().all(|st| st.input.selector == 0xdeadbeef));
        }
    }

    /// issue #54 参数跨步耦合：效果词交接把观测池词写进目标步零槽
    /// （未绑定词），观测池空时不改动。
    #[test]
    fn handoff_writes_pool_word_to_zero_slot() {
        let word = U256::from(0x2ee0u64);
        let storage_pool = vec![(U256::from(0xccu64), word)];
        let actx = AssembleCtx {
            storage_pool: &storage_pool,
            ..ctx(3, &TABLE)
        };
        let mut proposed = input(9);
        proposed.head = vec![[0u8; 32], [0xffu8; 32]];
        let mut zero_hits = 0usize;
        let mut nonzero_hits = 0usize;
        for seed in 0..200u64 {
            let mut rng = Rng::new(seed);
            let mut target = proposed.clone();
            handoff(&mut rng, &mut target, &actx);
            if target.head[0] == word.to_be_bytes::<32>() {
                zero_hits += 1;
            }
            if target.head[1] == word.to_be_bytes::<32>() {
                nonzero_hits += 1;
            }
        }
        assert!(zero_hits > 0, "零槽应收到观测池词");
        assert!(
            zero_hits > nonzero_hits,
            "零槽优先：零槽命中应多于非零槽（{zero_hits} vs {nonzero_hits}）"
        );
        // 观测池全空：不改动。
        let empty_ctx = ctx(3, &TABLE);
        let mut rng = Rng::new(1);
        let mut target = proposed.clone();
        handoff(&mut rng, &mut target, &empty_ctx);
        assert_eq!(target, proposed, "空观测池不交接");
    }
}
