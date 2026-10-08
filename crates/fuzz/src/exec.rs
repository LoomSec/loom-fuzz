//! 定向执行主逻辑：进化环 + 基线对照 + 报告组装。
//!
//! 预算双上限（runs / 时间），耗尽未达 → `reached = false`（不硬判，
//! unreachable / inconclusive 三值判决在 #7）。命中即停：`best_runs`
//! = 命中那次所用的 runs 计数；`best_input` / `trace` = 命中那次
//! run 的输入与 witness；未到达时为全程 fitness 最小的一次（如实，
//! 是最接近的见证候选，非见证）。

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use loom_fuzz_seed::{Input, Target, ValueDictionary};

use crate::cfg::DistanceTable;
use crate::evm;
use crate::mutate::{input_key, random_input};
use crate::mutators::{const_pool, Pools};
use crate::rng::Rng;

/// fork 后的攻击合约部署（CacheDB 本地写 overlay——"fork 后部署
/// 攻击合约"；Genesis 态同样可用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub address: [u8; 20],
    pub runtime: Vec<u8>,
}

/// 会话配置：合约字节码 + prestate 布置 + 预算 + 确定性种子。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecConfig {
    /// 运行时字节码。
    pub code: Vec<u8>,
    /// 合约地址（固定默认即可，如 [0x22; 20]）。
    pub address: [u8; 20],
    /// 存储槽 → 值 布置（registry 类等 prestate）。
    pub prestate: std::collections::BTreeMap<U256, U256>,
    /// 确定性种子：同值两次 `run_targeted` 逐字节一致。
    pub seed_rng: u64,
    /// 预算：runs 上限（制导会话与基线各自独立计数）。
    pub max_runs: u64,
    /// 预算：时间上限。
    #[serde(with = "duration_secs")]
    pub time_budget: Duration,
    /// 每 run 的 tx gas limit。燃料耗尽 → 该 run 如实标 truncated。
    pub gas_per_tx: u64,
    /// on-demand fork（None = Genesis 空库，默认现状）：AlloyDB 远程
    /// 状态 + CacheDB overlay，pin block 确定性。
    #[serde(default)]
    pub fork: Option<crate::fork::ForkConfig>,
    /// 攻击合约部署（setUp etch，overlay 在状态/prestate 上）。
    #[serde(default)]
    pub deployments: Vec<Deployment>,
    /// 支配 guard 上下文（revert 归因用；装载端经 xlayer 渲染 cond）。
    #[serde(default)]
    pub guard_context: Vec<GuardContext>,
    /// 是否跑纯随机基线（默认建议 true；`baseline_runs_to_reach`
    /// 是制导收益数据）。基线同预算、selector 固定为目标 selector、
    /// 无种子无制导。
    pub run_baseline: bool,
}

/// serde helper：`Duration` 以秒（u64）表示。
mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

/// 单条拦到的 CALL 族效果（含 SELFDESTRUCT）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCall {
    /// CALL / CALLCODE / DELEGATECALL / STATICCALL / CREATE / CREATE2 /
    /// SELFDESTRUCT。
    pub kind: String,
    /// 目标地址（CREATE 系为创建出的合约地址）。
    pub target: [u8; 20],
    pub value: U256,
    /// call input 的内存内容（CREATE 系为 initcode）。
    pub input: Vec<u8>,
    /// 产生该效果的指令 pc（step 流最后一条；钩子时机所限取不到
    /// 时为 None，如实）。
    pub pc: Option<u32>,
}

/// 交易级结局。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeKind {
    Return,
    Revert,
    OutOfGas,
    SelfDestruct,
    Stop,
    /// 非 OOG 的异常 halt（InvalidFEOpcode / 非法跳转 / 栈溢出等
    /// 细分 M0 不展开，如实归一类）。
    Invalid,
}

/// 一次 run 的 witness： visited pcs（去重排序，确定性）+ CALL 族
/// 效果 + 结局 + gas。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessTrace {
    pub visited_pcs: Vec<u32>,
    pub calls: Vec<RecordedCall>,
    pub outcome: OutcomeKind,
    pub gas_used: u64,
    /// 本 run 是否被截断（燃料耗尽或步数上限）。SessionReport 的
    /// `truncated` 取自报告所基于的这次 run。
    pub truncated: bool,
    /// 本 run 生效的部署（witness 记录；poc.json 落盘）。
    #[serde(default)]
    pub deployments: Vec<Deployment>,
}

/// 会话报告：全部 serde，poc.json 直接复用 best_input / trace。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    /// 是否到达 target_pcs。
    pub reached: bool,
    /// 到达所用 runs（未到达 = 本会话总 runs）。
    pub best_runs: u64,
    /// 到达时即见证输入；未到达时为全程 fitness 最小的一次输入
    /// （最接近的候选，非见证；消费方须先看 `reached`）。
    pub best_input: Option<Input>,
    /// `best_input` 对应那次 run 的 witness。
    pub trace: WitnessTrace,
    /// 报告所基于的 run 是否被截断（燃料/步数上限，诚实报告；
    /// inconclusive 判决的输入之一）。
    pub truncated: bool,
    /// 本会话实际完成的 runs（≤ max_runs）。
    pub runs_completed: u64,
    /// 同预算纯随机基线到达所用 runs；未到达为 None。基线
    /// selector 固定为目标 selector（完全随机 selector 过不了
    /// dispatcher，基线恒不可达，没有对照意义）。
    pub baseline_runs_to_reach: Option<u64>,
    /// 会话 corpus 规模（去重后保留的输入数；fuzz_report 的
    /// corpus 口径）。
    #[serde(default)]
    pub corpus_size: usize,
}

/// revert 归因（issue #25）：一条支配 guard 的失败记录——执行器在
/// revert 时归属"最近经过的支配 guard"（visited 序的最后一个 guard
/// pc；polarity_failed 恒 true = 该 guard 的通过条件未成立）。cond
/// 由装载端用 xlayer 渲染（loom 特色上下文）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardFeedback {
    pub pc: u32,
    pub cond_rendered: String,
    pub polarity_failed: bool,
}

/// 执行期支配 guard 上下文（ExecConfig 携带，装载端渲染 cond）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardContext {
    pub pc: u32,
    pub cond: String,
}

/// 单 run 的提案反馈（喂给 Proposer）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFeedback {
    pub input: Input,
    /// 本 run 的结局。
    pub outcome: OutcomeKind,
    /// 本 run 的 CFG 距离（fitness）。
    pub best_distance: u32,
    /// revert 归因：最近经过的支配 guard（非 revert = None）。
    pub reverted_guard: Option<GuardFeedback>,
}

/// 提案预算：数量上限 + 剩余时间（时间制预算）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalBudget {
    pub max_candidates: usize,
    pub time_left: Duration,
}

/// 提案器上下文：会话每代前刷新的共享池（变异器的池来源）。
#[derive(Debug, Clone, Copy)]
pub struct ProposerCtx<'a> {
    pub consts: &'a [U256],
    pub cmp_pool: &'a [U256],
    pub storage_pool: &'a [(U256, U256)],
}

/// 可插拔提案器（issue #25 分层搜索）： DictionaryProposer =
/// 既有基座 + 协同变异的封装；LlmProposer = LLM 候选 + 失败回退
/// 字典（fail-closed）。**判决独立**：judge/oracle 不感知提案器，
/// LLM 只影响搜索路径不影响判决；replay 无 LLM 参与。
pub trait Proposer {
    /// 会话每代前刷新共享池（默认 no-op；dictionary 需要）。
    fn refresh(&mut self, _ctx: &ProposerCtx<'_>) {}
    /// 给反馈与预算，产下一批候选。
    fn propose(&mut self, feedback: &[RunFeedback], budget: ProposalBudget) -> Vec<Input>;
    /// LLM 提案器的状态排泄（交互落盘 + 失败 assumption）；非 LLM
    /// 提案器默认空。CLI 据此填 fuzz_report.llm_interactions。
    fn drain_llm(&mut self) -> (Vec<crate::propose::LlmInteraction>, Vec<String>) {
        (Vec::new(), Vec::new())
    }
}

/// 步数上限（每 run）：gas 之外的硬兜（min gas/opcode ≥ 2，
/// 正常执行到不了这个量级；防 gas_per_tx 被设成天文数字时单
/// run 拖死会话）。
const STEP_CAP: u64 = 10_000_000;

/// corpus 上限（按 fitness 截断保留）。
const CORPUS_CAP: usize = 64;

/// 精英集上限（父代选择来源）。
const ELITE_CAP: usize = 16;

/// 种群下限：种子不足时用随机输入补到该数（多样性）。
const MIN_POPULATION: usize = 8;

/// 定向执行入口：CFG 距离制导的进化环 + 基线对照（默认
/// DictionaryProposer）。
pub fn run_targeted(
    cfg: &ExecConfig,
    target: &Target<'_>,
    seeds: &[Input],
    dict: &ValueDictionary,
) -> SessionReport {
    run_targeted_with(
        cfg,
        target,
        seeds,
        dict,
        &mut crate::propose::DictionaryProposer::new(cfg.seed_rng ^ 0x00D1_C710_AA8E_5EED),
    )
}

/// 定向执行入口（提案器可插拔版）：进化环由 `proposer` 驱动——
/// 每代 refresh 池 → 取反馈窗 → 提案 → 评估。**判决独立**：
/// oracle/judge 不感知提案器；replay 无 LLM 参与，verdict 一致。
pub fn run_targeted_with(
    cfg: &ExecConfig,
    target: &Target<'_>,
    seeds: &[Input],
    dict: &ValueDictionary,
    proposer: &mut dyn Proposer,
) -> SessionReport {
    let table = DistanceTable::new(&cfg.code, target.hit.target_pcs());

    // 制导会话。常量池（字典 ∪ PUSH 立即数）会话级构建一次。
    let consts = const_pool(&cfg.code, dict);
    let mut session = Session::new(cfg, &table, cfg.seed_rng);
    let head_len_hint = seeds.iter().map(|s| s.head.len()).max().unwrap_or(2).max(1);
    for seed in seeds {
        if session.run_one(seed) {
            break;
        }
    }
    // 种群不足补随机输入（保持多样性；不进 corpus 优先位）。
    while !session.reached && session.population_len() < MIN_POPULATION.min(cfg.max_runs as usize) {
        let filler = random_input(
            session.rng_mut(),
            target.hit.selector(),
            head_len_hint,
            Some(dict),
        );
        if session.run_one(&filler) {
            break;
        }
    }
    // 进化环：提案器驱动（默认 DictionaryProposer；LLM 只改搜索路径）。
    // 连续空代（提案器不产候选）三代即停——防零候选提案器把
    // 时间预算烧光（fail-closed：无候选 = 搜索无法继续）。
    let mut empty_gens = 0u32;
    while !session.reached && session.budget_left() && empty_gens < 3 {
        let cmp_pool = session.pools.cmp();
        let storage_pool = session.pools.storage();
        proposer.refresh(&ProposerCtx {
            consts: &consts,
            cmp_pool: &cmp_pool,
            storage_pool: &storage_pool,
        });
        let feedback = session.proposer_feedback();
        let candidates = proposer.propose(
            &feedback,
            ProposalBudget {
                max_candidates: crate::propose::DEFAULT_MAX_CANDIDATES,
                time_left: session.time_left(),
            },
        );
        if candidates.is_empty() {
            empty_gens += 1;
        } else {
            empty_gens = 0;
        }
        for child in candidates {
            if session.run_one(&child) {
                break;
            }
        }
    }
    let mut report = session.into_report();

    // 基线：独立 RNG 流（与制导流不共享状态），同预算纯随机——
    // 无种子、无制导、无字典（静态知识也不给，最严格对照）。
    if cfg.run_baseline {
        let mut baseline = Session::new(cfg, &table, cfg.seed_rng ^ 0x5DEE_CE66_1BAD_BEE5);
        while !baseline.reached && baseline.budget_left() {
            let input = random_input(
                baseline.rng_mut(),
                target.hit.selector(),
                head_len_hint,
                None,
            );
            baseline.run_one(&input);
        }
        report.baseline_runs_to_reach = baseline.reached.then_some(baseline.runs);
    }
    report
}

/// 一次评估的候选输入（种子直接进 corpus 优先位；变异/随机
/// 子代按 fitness 竞争）。
#[derive(Clone)]
struct Evaluated {
    input: Input,
    fitness: u32,
    trace: WitnessTrace,
    guard: Option<GuardFeedback>,
}

/// 会话（制导与基线共用）：预算控制 + corpus + 最优记录。
struct Session<'a> {
    cfg: &'a ExecConfig,
    table: &'a DistanceTable,
    rng: Rng,
    deadline: Instant,
    runs: u64,
    reached: bool,
    /// 命中那次的输入/trace/runs（reached 时即报告值）。
    hit: Option<Evaluated>,
    /// 全程 fitness 最小的一次（未命中时即报告值；并列取先到）。
    best: Option<Evaluated>,
    corpus: Vec<Evaluated>,
    corpus_keys: BTreeSet<Vec<u8>>,
    /// 比较操作数池 + 存储观测池（#6 算子 1/4 的回灌来源，
    /// 会话级累积，去重有上限）。
    pools: Pools,
    /// 反馈窗（每 run 一条，喂提案器；截 [`FEEDBACK_WINDOW`]）。
    feedback: Vec<RunFeedback>,
    /// 精英集：全程 fitness 最优的前 ELITE_CAP（父代选择压力来源）。
    elite: Vec<Evaluated>,
}

impl<'a> Session<'a> {
    fn new(cfg: &'a ExecConfig, table: &'a DistanceTable, seed: u64) -> Self {
        Session {
            cfg,
            table,
            rng: Rng::new(seed),
            deadline: Instant::now() + cfg.time_budget,
            runs: 0,
            reached: false,
            hit: None,
            best: None,
            corpus: Vec::new(),
            corpus_keys: BTreeSet::new(),
            pools: Pools::new(),
            feedback: Vec::new(),
            elite: Vec::new(),
        }
    }

    /// 反馈切片：corpus（全史 fitness 最优、去重）+ 最近窗口，截
    /// FEEDBACK_WINDOW。corpus 与旧 select_parents 的父代池同源——
    /// 保证 DictionaryProposer 的选择压力与旧进化环一致。
    fn proposer_feedback(&self) -> Vec<RunFeedback> {
        let mut out: Vec<RunFeedback> = self
            .corpus
            .iter()
            .map(|e| RunFeedback {
                input: e.input.clone(),
                outcome: e.trace.outcome,
                best_distance: e.fitness,
                reverted_guard: e.guard.clone(),
            })
            .collect();
        for f in self
            .feedback
            .iter()
            .rev()
            .take(crate::propose::FEEDBACK_WINDOW.saturating_sub(out.len()))
        {
            out.push(f.clone());
        }
        out
    }

    fn population_len(&self) -> usize {
        self.runs as usize
    }

    fn rng_mut(&mut self) -> &mut Rng {
        &mut self.rng
    }

    fn budget_left(&self) -> bool {
        self.runs < self.cfg.max_runs && Instant::now() < self.deadline
    }

    fn time_left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// 记录一条 run 反馈（revert 归因经 RunResult.feedback_guard）。
    fn push_feedback(&mut self, run: &crate::evm::RunResult, input: &Input, fitness: u32) {
        self.feedback.push(RunFeedback {
            input: input.clone(),
            outcome: run.trace.outcome,
            best_distance: fitness,
            reverted_guard: run.feedback_guard.clone(),
        });
        let window = crate::propose::FEEDBACK_WINDOW;
        if self.feedback.len() > window {
            self.feedback.drain(0..self.feedback.len() - window);
        }
    }

    /// 评估一个输入：执行 + fitness + 命中/最优/corpus 维护。
    /// 返回 true = 命中（调用方应停止产生新候选）。
    fn run_one(&mut self, input: &Input) -> bool {
        if !self.budget_left() {
            return self.reached;
        }
        self.runs += 1;
        let result = evm::execute(self.cfg, input, STEP_CAP);
        // 观测入池（去重有上限）：比较操作数 → 算子 1，SLOAD 键值
        // 对 → 算子 4。
        self.pools.absorb(&result);
        let fitness = self.table.fitness(result.visited_pcs.iter().copied());
        self.push_feedback(&result, input, fitness);
        let hit_now = result
            .visited_pcs
            .iter()
            .any(|&pc| self.table.is_target(pc));
        let evaluated = Evaluated {
            input: input.clone(),
            fitness,
            trace: result.trace,
            guard: result.feedback_guard.clone(),
        };
        if hit_now {
            self.reached = true;
            self.hit = Some(evaluated);
            return true;
        }
        let better = self.best.as_ref().is_none_or(|b| fitness < b.fitness);
        if better {
            self.best = Some(Evaluated {
                input: evaluated.input.clone(),
                fitness,
                trace: evaluated.trace.clone(),
                guard: evaluated.guard.clone(),
            });
        }
        // 精英集维护：按 fitness 插入截断（按输入去重）——父代选择
        // 压力来源（反馈窗只有最近 N 条，全史最优会滚出窗口）。
        if !self.elite.iter().any(|e| e.input == evaluated.input) {
            self.elite.push(evaluated.clone());
            self.elite.sort_by_key(|e| (e.fitness, input_key(&e.input)));
            self.elite.truncate(ELITE_CAP);
        }
        // 距离创新低 → 入 corpus（去重，cap 按 fitness 截断）。
        if self.corpus_keys.insert(input_key(&evaluated.input)) {
            self.corpus.push(evaluated);
            self.corpus.sort_by_key(|e| e.fitness);
            self.corpus.truncate(CORPUS_CAP);
        }
        false
    }

    fn into_report(self) -> SessionReport {
        let chosen = self.hit.clone().or(self.best);
        let (best_input, trace) = match chosen {
            Some(e) => (Some(e.input), e.trace),
            None => {
                // 一 run 未执行（max_runs = 0 或时间预算为 0）：
                // 无 witness 可报，如实给空 trace。
                (
                    None,
                    WitnessTrace {
                        visited_pcs: Vec::new(),
                        calls: Vec::new(),
                        outcome: OutcomeKind::Invalid,
                        gas_used: 0,
                        truncated: false,
                        deployments: Vec::new(),
                    },
                )
            }
        };
        let reached = self.reached;
        SessionReport {
            reached,
            // 命中即停：runs 即命中所用计数；未命中 = 总 runs。
            best_runs: self.runs,
            best_input,
            truncated: trace.truncated,
            trace,
            runs_completed: self.runs,
            baseline_runs_to_reach: None,
            corpus_size: self.corpus.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小可命中目标：字节码首字节即 JUMPDEST，target = [0]，
    /// 任何输入都命中——验证环路与报告语义。
    #[test]
    fn trivial_target_reaches_on_first_run() {
        struct Hit;
        impl loom_fuzz_seed::HitView for Hit {
            fn selector(&self) -> u32 {
                0
            }
            fn target_pcs(&self) -> &[u32] {
                &[0]
            }
            fn evidence(&self) -> &str {
                ""
            }
        }
        let hit = Hit;
        let target = Target { hit: &hit, func: 0 };
        let cfg = ExecConfig {
            code: vec![0x5b, 0x00], // JUMPDEST STOP
            address: [0x22; 20],
            prestate: Default::default(),
            seed_rng: 1,
            max_runs: 10,
            time_budget: Duration::from_secs(5),
            gas_per_tx: 100_000,
            run_baseline: false,
            fork: None,
            deployments: Vec::new(),
            guard_context: Vec::new(),
        };
        let seeds = vec![Input {
            selector: 0,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: Vec::new(),
            tail: loom_fuzz_seed::Tail::Empty,
        }];
        let report = run_targeted(&cfg, &target, &seeds, &ValueDictionary { words: vec![] });
        assert!(report.reached);
        assert_eq!(report.best_runs, 1);
        assert_eq!(report.runs_completed, 1);
        assert!(report.best_input.is_some());
        assert!(report.trace.visited_pcs.contains(&0));
    }

    /// 不可达目标（pc 指向 PUSH 数据区，永不执行）+ 零预算：不
    /// panic，如实 reached=false。
    #[test]
    fn unreachable_target_reports_honestly() {
        struct Hit;
        impl loom_fuzz_seed::HitView for Hit {
            fn selector(&self) -> u32 {
                0
            }
            fn target_pcs(&self) -> &[u32] {
                &[2] // PUSH 数据区
            }
            fn evidence(&self) -> &str {
                ""
            }
        }
        let hit = Hit;
        let target = Target { hit: &hit, func: 0 };
        let cfg = ExecConfig {
            code: vec![0x61, 0x00, 0x5b, 0x00], // PUSH2 005b 00（0x5b 是数据）
            address: [0x22; 20],
            prestate: Default::default(),
            seed_rng: 1,
            max_runs: 5,
            time_budget: Duration::from_secs(5),
            gas_per_tx: 100_000,
            run_baseline: false,
            fork: None,
            deployments: Vec::new(),
            guard_context: Vec::new(),
        };
        let report = run_targeted(&cfg, &target, &[], &ValueDictionary { words: vec![] });
        assert!(!report.reached);
        assert_eq!(report.runs_completed, 5);
        assert!(!report.truncated);
    }
}
