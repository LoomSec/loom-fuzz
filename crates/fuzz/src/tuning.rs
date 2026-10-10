//! 调参旋钮集中配置（issue #49）：搜索层的纯 tuning 数字全部收敛
//! 到本模块的 [`TUNING`]——每旋钮一行注释写明语义与依据。**这批值
//! 是调参产物（tuning），多数无理论依据**：改动必须跑全回归
//! （`cargo test --workspace` + anyswap/vvisr/LiFi 案例 confirmed）。
//!
//! 原则：能从静态事实推导的已由别处推导（头宽 = seed crate
//! headwidth，issue #48）；留在这里的都是经验值，集中一处便于
//! 审计与回归对照。CLI 不暴露（避免配置面膨胀），测试可经本模块
//! 读值断言。

use crate::mutators::HeadOp;

/// 集中调参表（值 = 当前生产值，本 PR 行为零变化）。
pub(crate) struct Tuning {
    // ---- 变异算子带（mutators.rs mutate() 的顶层投掷；roll =
    // rng.below(100)，区间左闭右开）----
    /// 定长头算子带上限：roll < 60 → 五算子+协同（头非空，否则
    /// 顺延下一带）。依据：定长算子是主生产力（#6 实测权重取舍）。
    pub head_op_band: u64,
    /// 变长尾算子带上限：60 ≤ roll < 80 → 尾 truncate/extend/
    /// block-replace。依据：尾内容破坏会把 ABI 形态打回解码失败态，
    /// 比例过高拖慢收敛（#5 验收 fixture 实测）。
    pub tail_op_band: u64,
    /// ABI 自洽化带上限：80 ≤ roll < 84 → abifix（issue #46；
    /// 有头有尾才适用，否则顺延 legacy）。依据：盲搜多轮未显示更高
    /// 配比的增益，取保守档最小化搜索面扰动。
    pub abifix_band: u64,
    /// 定长算子内部权重表（绝对区间底 = 前项累计；投掷
    /// rng.below(100) 后取第一个累计值 > roll 的可用算子，不可用
    /// 重投 8 次）。依据：#6 定稿权重 + #25 协同算子低权重专科
    /// （同现约束场景才赚）——**纯 tuning**。
    pub head_op_weights: &'static [(HeadOp, u64)],
    /// 高斯缩放比例集（百分比，固定 7 档 ±）。依据：#6 拍定的
    /// 固定比例集——**纯 tuning**。
    pub gaussian_scales: &'static [u64],

    // ---- 序列组装（sequence.rs；同 rng.below(100) 语义）----
    /// 单步带上限：roll < 60 → `[proposed]`（步级利用为主）。
    /// 依据：与 #25 分层搜索同思路——**纯 tuning**。
    pub seq_single_band: u64,
    /// append 带上限：60 ≤ roll < 80 → append；其余 splice。
    /// 依据：同上单步主导——**纯 tuning**。
    pub seq_append_band: u64,
    /// 多步序列的步内变异概率分母：rng.below(denom) == 0 即触发
    /// （denom=2 → 50%）。保持 below(denom) 投掷语义（值不变）。
    pub seq_step_mutate_denom: u64,

    // ---- 命中后择优继续（exec.rs，issue #46）----
    /// 到场后继续的 runs 上限（或预算/空代耗尽）：让语义自洽到场
    /// 有机会反超退化形态。依据：#46 盲搜实测窗口需求——**纯
    /// tuning**。
    pub post_hit_runs: u64,

    // ---- 池/集容量（去重有上限；保先收确定性）----
    /// 步级池 FIFO 上限（序列组装素材，issue #35）。依据：256 覆盖
    /// 会话内步形态多样性——**纯 tuning**。
    pub step_pool_cap: usize,
    /// 比较操作数池上限（算子 1 回灌源，issue #6）。**纯 tuning**。
    pub cmp_pool_cap: usize,
    /// 存储观测池上限（算子 4 回灌源，issue #6）。**纯 tuning**。
    pub storage_pool_cap: usize,
    /// corpus 保留上限（按 fitness 截断）。**纯 tuning**。
    pub corpus_cap: usize,
    /// 精英集上限（父代选择压力来源，issue #25）。**纯 tuning**。
    pub elite_cap: usize,
    /// 种群下限（种子不足时随机填充到该数）。**纯 tuning**。
    pub min_population: usize,
    /// 提案器反馈窗（每 run 一条，喂 DictionaryProposer）。**纯
    /// tuning**。
    pub feedback_window: usize,
    /// 每代候选上限。**纯 tuning**。
    pub max_candidates: usize,
    /// 每 run 步数硬兜（gas 之外的防拖死上限）。依据：min
    /// gas/opcode ≥ 2，正常执行到不了这个量级——**纯 tuning**。
    pub step_cap: u64,
    /// abifix 合成段的材料复制上限（词）。依据：防 calldata
    /// 膨胀——**纯 tuning**。
    pub abifix_material_cap: usize,
    /// legacy 动态尾生成概率（roll < n → 生成；legacy 系列 #5）。
    /// **纯 tuning**。
    pub legacy_tail_gen_percent: u64,
    /// legacy 动态尾长度上限（字节，below(cap+1) 语义 → 0..=cap）。
    /// **纯 tuning**。
    pub legacy_tail_len_cap: u64,
    /// legacy caller 替换概率分母（below(denom) == 0 → 替换）。
    /// **纯 tuning**。
    pub legacy_caller_denom: u64,
}

/// 生产调参值（唯一实例；不要散写魔法数——改这里并跑回归）。
pub(crate) const TUNING: Tuning = Tuning {
    head_op_band: 60,
    tail_op_band: 80,
    abifix_band: 84,
    head_op_weights: &[
        (HeadOp::CmpFeedback, 23),
        (HeadOp::ConstOverwrite, 23),
        (HeadOp::BoundaryIncDec, 18),
        (HeadOp::StorageReplay, 16),
        (HeadOp::GaussianScale, 10),
        (HeadOp::Coordinated, 8),
    ],
    gaussian_scales: &[10, 25, 50, 100, 200, 500, 1000],
    seq_single_band: 60,
    seq_append_band: 80,
    seq_step_mutate_denom: 2,
    post_hit_runs: 1536,
    step_pool_cap: 256,
    cmp_pool_cap: 256,
    storage_pool_cap: 128,
    corpus_cap: 64,
    elite_cap: 16,
    min_population: 8,
    feedback_window: 32,
    max_candidates: 32,
    step_cap: 10_000_000,
    abifix_material_cap: 32,
    legacy_tail_gen_percent: 15,
    legacy_tail_len_cap: 64,
    legacy_caller_denom: 10,
};
