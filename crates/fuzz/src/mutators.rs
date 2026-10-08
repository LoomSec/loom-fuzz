//! 精化变异器（issue #6）：五个定长槽算子 + 变长尾算子集，与 #5
//! 基础随机变异组合成单轮变异。机制参考 Echidna / MEDUSA 类成熟
//! 实现的算子思想，全部自行实现；loom 特色：常量池以 loom 静态
//! 事实字典（seed crate 产物）为先，码内 PUSH 立即数为补充——
//! 静态知识先于运行时收集，进场即全量可用。
//!
//! # 定长槽算子（head 槽，每轮至多应用一次）
//!
//! 1. **比较操作数回灌**（cmp）：inspector 在 step 钩子收 LT/GT/
//!    SLT/SGT/EQ 的两侧操作数进比较池（去重、排序、有上限）；变异
//!    时用池值整词覆写随机槽——穿 dispatcher / require 的定向穿透。
//! 2. **常量池整参覆盖**（const）：32B 槽整体覆写为常量池值（≠逐
//!    字节扰动）。池 = 码内 PUSH 立即数 ∪ seed 字典，构建一次、
//!    会话共享。
//! 3. **±1 边界变异**（boundary）：整数值加一/减一，U256 wrapping
//!    （0-1 → 2^256-1，MAX+1 → 0），与算子 2 配对跨 gt/lt 边界。
//! 4. **存储值入池**（storage）：inspector 记录 SLOAD 观测的键值对；
//!    变异时 90% 把**值** / 10% 把**键**覆写进参数槽——穿"参数须
//!    等于某槽内容"类检查。
//! 5. **数值高斯缩放**（gaussian）：按 ±{10,25,50,100,200,500,1000}%
//!    固定比例集随机取一档 + 符号，U256 wrapping 截断（大数不
//!    panic）；放大 = v*(100+p)/100，缩小 = v*100/(100+p)。
//!
//! # 变长尾算子（tail 的 Bytes 内容，字节级）
//!
//! - **truncate**：32B 边界随机截断（可截空 → tail 归 Empty）；
//! - **extend**：追加 1-2 个随机/字典词；
//! - **block-replace**：随机 32B 块整体替换。
//!
//! # 组合权重（每轮变异一次投掷，确定性由 xorshift64* 驱动）
//!
//! | 区间 | 行为 |
//! |---|---|
//! | 0-59 | 定长算子（head 非空时；否则落到 legacy）：cmp 25 / const 25 / boundary 20 / storage 20 / gaussian 10 |
//! | 60-79 | 变长尾算子（tail 为 Bytes 时；否则回落定长/legacy） |
//! | 80-99 | legacy 兜底（#5 基础：字节扰动 / 字典整词覆盖 / caller 换 / 尾字节扰动 / 动态尾生成） |
//!
//! 权重取舍：定长算子占大头（穿透型回灌是主生产力）；尾算子 20%
//! （尾内容破坏会把 ABI 形态打回解码失败态，比例过高会拖慢已定形
//! 种子的收敛——#5 验收 fixture 实测如此）。
//!
//! head 槽只落定长算子与 legacy-head 系列；tail 内容只落变长算子与
//! legacy 尾字节扰动/动态尾生成——分集由结构保证（算子实现只碰自己
//! 负责的区域，测试断言）。

use std::collections::BTreeSet;

use alloy_primitives::U256;
use loom_fuzz_seed::{Input, Tail, ValueDictionary};

use crate::evm::RunResult;
use crate::rng::Rng;

/// 比较池上限（观测值去重后保留量）。
const CMP_POOL_CAP: usize = 256;
/// 存储观测池上限（键值对去重后保留量）。
const STORAGE_POOL_CAP: usize = 128;

/// 高斯缩放比例集（百分数，固定）。
const SCALES: [u64; 7] = [10, 25, 50, 100, 200, 500, 1000];

/// 会话级运行时池：比较操作数 + 存储键值对。去重用 BTreeSet（天然
/// 排序，确定性：迭代序 = 排序序，与插入序无关）；超上限丢弃新项
/// （保先收，避免 LRU 状态引入非确定性）。
#[derive(Debug, Default)]
pub(crate) struct Pools {
    cmp: BTreeSet<U256>,
    storage: BTreeSet<(U256, U256)>,
}

impl Pools {
    pub(crate) fn new() -> Self {
        Pools::default()
    }

    /// 合入一次 run 的观测（去重 + 上限截断）。
    pub(crate) fn absorb(&mut self, run: &RunResult) {
        for pair in &run.cmp_observed {
            for v in pair {
                if self.cmp.len() < CMP_POOL_CAP {
                    self.cmp.insert(*v);
                }
            }
        }
        for kv in &run.storage_observed {
            if self.storage.len() < STORAGE_POOL_CAP {
                self.storage.insert(*kv);
            }
        }
    }

    pub(crate) fn cmp(&self) -> Vec<U256> {
        self.cmp.iter().copied().collect()
    }

    pub(crate) fn storage(&self) -> Vec<(U256, U256)> {
        self.storage.iter().copied().collect()
    }
}

/// 常量池：码内 PUSH 立即数 ∪ seed 字典（排序去重，会话构建一次）。
/// 静态事实字典先于运行时收集——loom 的进场知识优势。
pub(crate) fn const_pool(code: &[u8], dict: &ValueDictionary) -> Vec<U256> {
    let mut set = BTreeSet::new();
    for w in &dict.words {
        set.insert(*w);
    }
    for w in push_immediates(code) {
        set.insert(w);
    }
    set.into_iter().collect()
}

/// 字节码 PUSH1..PUSH32 立即数扫描（右对齐成字；数据区里的伪
/// 操作符不误认——与 seed crate 的 push_immediates 同规则，此处
/// 独立实现以保持 fuzz 模块自包含）。
fn push_immediates(code: &[u8]) -> Vec<U256> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let byte = code[i];
        if (0x60..=0x7f).contains(&byte) {
            let n = usize::from(byte - 0x5f);
            let end = (i + 1 + n).min(code.len());
            let mut word = [0u8; 32];
            let imm = &code[i + 1..end];
            word[32 - imm.len()..].copy_from_slice(imm);
            out.push(U256::from_be_bytes(word));
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// 单轮变异的输入上下文：随机源 + 常量池 + 运行时池（只读）。
pub(crate) struct MutCtx<'a> {
    pub rng: &'a mut Rng,
    pub consts: &'a [U256],
    pub cmp_pool: &'a [U256],
    pub storage_pool: &'a [(U256, U256)],
}

impl<'a> MutCtx<'a> {
    pub(crate) fn new(
        rng: &'a mut Rng,
        consts: &'a [U256],
        cmp_pool: &'a [U256],
        storage_pool: &'a [(U256, U256)],
    ) -> Self {
        MutCtx {
            rng,
            consts,
            cmp_pool,
            storage_pool,
        }
    }
}

/// 定长槽算子编号（测试与权重表共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadOp {
    CmpFeedback,
    ConstOverwrite,
    BoundaryIncDec,
    StorageReplay,
    GaussianScale,
    /// 多槽协同（issue #25）：k ∈ {2,3} 个不同槽同时从字典/比较池
    /// 抽词覆写——真实案例（vvisr fork 态）winning witness 需
    /// "from==字典词 ∧ amount 过阈值"同现，单槽变异 ~1e-6/子代。
    Coordinated,
}

/// 变长尾算子编号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TailOp {
    Truncate,
    Extend,
    BlockReplace,
}

// ---------------------------------------------------------------------------
// 算子 1-5（纯效果函数：给定槽与值，测试可直接钉住；随机选择在外层）
// ---------------------------------------------------------------------------

/// 算子 1：比较回灌——槽整体覆写为比较池值。
pub(crate) fn op_cmp_feedback(input: &mut Input, slot: usize, value: U256) {
    if let Some(word) = input.head.get_mut(slot) {
        *word = value.to_be_bytes::<32>();
    }
}

/// 算子 2：常量池整参覆盖。
pub(crate) fn op_const_overwrite(input: &mut Input, slot: usize, value: U256) {
    if let Some(word) = input.head.get_mut(slot) {
        *word = value.to_be_bytes::<32>();
    }
}

/// 算子 3：±1 边界（wrapping：0-1 → MAX，MAX+1 → 0）。
pub(crate) fn op_boundary(word: [u8; 32], inc: bool) -> [u8; 32] {
    let v = U256::from_be_bytes(word);
    let out = if inc {
        v.wrapping_add(U256::from(1u64))
    } else {
        v.wrapping_sub(U256::from(1u64))
    };
    out.to_be_bytes::<32>()
}

/// 算子 4：存储回灌——90% 值 / 10% 键覆写参数槽。
pub(crate) fn op_storage_replay(input: &mut Input, slot: usize, kv: (U256, U256), use_key: bool) {
    let v = if use_key { kv.0 } else { kv.1 };
    if let Some(word) = input.head.get_mut(slot) {
        *word = v.to_be_bytes::<32>();
    }
}

/// 算子 5：高斯缩放——比例集固定（±10/25/50/100/200/500/1000%），
/// wrapping 截断。up = v*(100+p)/100，down = v*100/(100+p)（先乘后
/// 除，精度损失如实接受）。
pub(crate) fn op_gaussian(word: [u8; 32], pct: u64, up: bool) -> [u8; 32] {
    let v = U256::from_be_bytes(word);
    let out = if up {
        v.wrapping_mul(U256::from(100 + pct)) / U256::from(100u64)
    } else {
        v.wrapping_mul(U256::from(100u64)) / U256::from(100 + pct)
    };
    out.to_be_bytes::<32>()
}

/// 变长：32B 边界截断。`keep_words` = 保留的 32B 块数（0 = 截空）。
pub(crate) fn tail_truncate(tail: &mut Vec<u8>, keep_words: usize) {
    tail.truncate(keep_words * 32);
}

/// 变长：追加 n 个词（随机或字典内容）。
pub(crate) fn tail_extend(tail: &mut Vec<u8>, words: &[[u8; 32]]) {
    for w in words {
        tail.extend_from_slice(w);
    }
}

/// 变长：第 word_idx 个 32B 块整体替换。
pub(crate) fn tail_block_replace(tail: &mut [u8], word_idx: usize, word: [u8; 32]) {
    let start = word_idx * 32;
    if let Some(block) = tail.get_mut(start..start + 32) {
        block.copy_from_slice(&word);
    }
}

// ---------------------------------------------------------------------------
// 单轮变异（随机选择算子 + 单点应用）
// ---------------------------------------------------------------------------

/// 定长算子按权重随机选一（cmp 23 / const 23 / boundary 18 /
/// storage 16 / gaussian 10 / coordinated 8——低权重专科：同现
/// 约束场景才赚，常规单槽约束下破坏兄弟槽）。池可用性作为参数
/// 传入（避开与 rng 的借用冲突）。
fn pick_head_op(
    rng: &mut Rng,
    has_cmp: bool,
    has_const: bool,
    has_storage: bool,
) -> Option<HeadOp> {
    if !has_cmp && !has_const && !has_storage {
        return None;
    }
    for _ in 0..8 {
        match rng.below(100) {
            0..=22 if has_cmp => return Some(HeadOp::CmpFeedback),
            23..=45 if has_const => return Some(HeadOp::ConstOverwrite),
            46..=63 => return Some(HeadOp::BoundaryIncDec), // 无池依赖
            64..=79 if has_storage => return Some(HeadOp::StorageReplay),
            80..=89 => return Some(HeadOp::GaussianScale), // 无池依赖
            // 协同 = 同现约束专科（低权重：多槽同时覆写常破坏兄弟槽
            // 的脆弱等值约束——guard-boundary 的 nonce 实测）；需要
            // 至少一个词池（字典/比较）。
            90..=97 if has_cmp || has_const => return Some(HeadOp::Coordinated),
            _ => continue,
        }
    }
    None
}

fn pick_tail_op(rng: &mut Rng) -> TailOp {
    match rng.below(3) {
        0 => TailOp::Truncate,
        1 => TailOp::Extend,
        _ => TailOp::BlockReplace,
    }
}

/// 单轮变异：对 parent clone 施加一个算子（定长 / 变长 / legacy
/// 兜底，权重见模块文档）。全部随机性经 `ctx.rng`（确定性）。
pub(crate) fn mutate(parent: &Input, ctx: &mut MutCtx<'_>) -> Input {
    let rng = &mut *ctx.rng;
    let mut child = parent.clone();
    let roll = rng.below(100);
    match roll {
        // 定长算子（head 非空；head 空回落 legacy）。
        0..=59 if !child.head.is_empty() => {
            let slot = rng.below(child.head.len() as u64) as usize;
            match pick_head_op(
                rng,
                !ctx.cmp_pool.is_empty(),
                !ctx.consts.is_empty(),
                !ctx.storage_pool.is_empty(),
            ) {
                Some(HeadOp::CmpFeedback) => {
                    let v = ctx.cmp_pool[rng.below(ctx.cmp_pool.len() as u64) as usize];
                    op_cmp_feedback(&mut child, slot, v);
                }
                Some(HeadOp::ConstOverwrite) => {
                    let v = ctx.consts[rng.below(ctx.consts.len() as u64) as usize];
                    op_const_overwrite(&mut child, slot, v);
                }
                Some(HeadOp::BoundaryIncDec) => {
                    let inc = rng.below(2) == 0;
                    child.head[slot] = op_boundary(child.head[slot], inc);
                }
                Some(HeadOp::StorageReplay) => {
                    let kv = ctx.storage_pool[rng.below(ctx.storage_pool.len() as u64) as usize];
                    let use_key = rng.below(10) == 0; // 10% 键
                    op_storage_replay(&mut child, slot, kv, use_key);
                }
                Some(HeadOp::GaussianScale) => {
                    let pct = SCALES[rng.below(SCALES.len() as u64) as usize];
                    let up = rng.below(2) == 0;
                    child.head[slot] = op_gaussian(child.head[slot], pct, up);
                }
                Some(HeadOp::Coordinated) => {
                    // k ∈ {2,3} 个不同槽，各从比较池/字典 50/50 抽词
                    // 同时覆写（单算子单应用：一轮一次协同）。k 不超
                    // 头槽数（头长 1 时退化单槽）。
                    let k = (2 + rng.below(2) as usize).min(child.head.len());
                    let mut chosen: Vec<usize> = vec![slot];
                    while chosen.len() < k {
                        let s = rng.below(child.head.len() as u64) as usize;
                        if !chosen.contains(&s) {
                            chosen.push(s);
                        }
                    }
                    for s in chosen {
                        let word = if !ctx.cmp_pool.is_empty() && rng.below(2) == 0 {
                            ctx.cmp_pool[rng.below(ctx.cmp_pool.len() as u64) as usize]
                        } else {
                            ctx.consts[rng.below(ctx.consts.len() as u64) as usize]
                        };
                        child.head[s] = word.to_be_bytes::<32>();
                    }
                }
                None => legacy_head(rng, &mut child),
            }
        }
        // 变长尾算子（tail 为 Bytes；否则回落 legacy）。
        50..=79 if matches!(child.tail, Tail::Bytes(_)) => {
            let op = pick_tail_op(rng);
            let Tail::Bytes(tail) = &mut child.tail else {
                unreachable!("matches 已判定")
            };
            let words = tail.len() / 32;
            match op {
                TailOp::Truncate => {
                    let keep = rng.below(words as u64 + 1) as usize;
                    tail_truncate(tail, keep);
                    if tail.is_empty() {
                        child.tail = Tail::Empty;
                    }
                }
                TailOp::Extend => {
                    let n = 1 + rng.below(2) as usize;
                    let mut add = Vec::with_capacity(n);
                    for _ in 0..n {
                        add.push(if !ctx.consts.is_empty() && rng.below(2) == 0 {
                            ctx.consts[rng.below(ctx.consts.len() as u64) as usize]
                                .to_be_bytes::<32>()
                        } else {
                            rng.word()
                        });
                    }
                    tail_extend(tail, &add);
                }
                TailOp::BlockReplace => {
                    if words > 0 {
                        let idx = rng.below(words as u64) as usize;
                        let w = if !ctx.consts.is_empty() && rng.below(2) == 0 {
                            ctx.consts[rng.below(ctx.consts.len() as u64) as usize]
                                .to_be_bytes::<32>()
                        } else {
                            rng.word()
                        };
                        tail_block_replace(tail, idx, w);
                    }
                }
            }
        }
        // legacy 兜底（#5 基础变异）。
        _ => legacy(rng, &mut child),
    }
    child
}

/// legacy 头系列：随机槽 50% 字典整词覆盖（有常量池时）/ 50% 单
/// 字节翻转 + 10% caller 替换。
fn legacy_head(rng: &mut Rng, child: &mut Input) {
    if child.head.is_empty() {
        return;
    }
    let slot = rng.below(child.head.len() as u64) as usize;
    if rng.below(2) == 0 {
        // 调用方经 MutCtx 传入常量池；legacy 路径无 ctx 访问时退回
        // 随机词——保持 #5 行为（字典覆盖由定长算子 2 承担主责）。
        child.head[slot] = rng.word();
    } else {
        let byte = rng.below(32) as usize;
        child.head[slot][byte] ^= rng.next_u64() as u8;
    }
    if rng.below(10) == 0 {
        child.caller = rng.address();
    }
}

/// legacy 尾系列：字节扰动 / 动态尾生成（与 #5 同语义）。
fn legacy_tail(rng: &mut Rng, child: &mut Input) {
    if matches!(child.tail, Tail::Empty | Tail::Free) && rng.below(100) < 15 {
        let len = rng.below(65) as usize;
        let mut tail = U256::from(len).to_be_bytes::<32>().to_vec();
        let mut data = vec![0u8; len.div_ceil(32) * 32];
        rng.fill_bytes(&mut data);
        tail.extend_from_slice(&data);
        child.tail = Tail::Bytes(tail);
    } else if let Tail::Bytes(tail) = &mut child.tail {
        if !tail.is_empty() && rng.below(5) == 0 {
            let byte = rng.below(tail.len() as u64) as usize;
            tail[byte] ^= rng.next_u64() as u8;
        }
    }
}

fn legacy(rng: &mut Rng, child: &mut Input) {
    legacy_head(rng, child);
    legacy_tail(rng, child);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::execute;
    use crate::exec::ExecConfig;
    use std::collections::BTreeMap;
    use std::time::Duration;

    /// 微型 harness：arg (=calldata 字 0) 与 magic 比较，通过则跳到
    /// dest 块（JUMPDEST），失败走 REVERT。`cmp_op` 为 LT/GT/EQ。
    /// 布局：PUSH1 4 CALLDATALOAD PUSHn magic CMP PUSH1 dest JUMPI
    /// [PUSH1 0 PUSH1 0 REVERT] JUMPDEST(target)
    fn cmp_harness(cmp_op: u8, magic: U256, magic_push: u8) -> (Vec<u8>, u32) {
        let mut code = vec![0x60, 0x04, 0x35]; // PUSH1 4 CALLDATALOAD
        code.push(magic_push);
        code.extend_from_slice(&magic_bytes(magic, magic_push));
        code.push(cmp_op);
        // dest = 当前 pc + 2(PUSH1) + 1(JUMPI) + 5(revert 序列) = pc+8
        let dest = code.len() as u32 + 8;
        code.push(0x60);
        code.push(dest as u8);
        code.push(0x57); // JUMPI
        code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]); // revert
        assert_eq!(code.len() as u32, dest);
        code.push(0x5b); // JUMPDEST = target
        code.push(0x00); // STOP
        (code, dest)
    }

    /// 按 PUSH 宽度右对齐取 magic 字节。
    fn magic_bytes(v: U256, push: u8) -> Vec<u8> {
        let n = usize::from(push - 0x5f);
        let b = v.to_be_bytes::<32>();
        b[32 - n..].to_vec()
    }

    fn cfg_for(code: Vec<u8>, prestate: BTreeMap<U256, U256>) -> ExecConfig {
        ExecConfig {
            code,
            address: [0x22; 20],
            prestate,
            seed_rng: 1,
            max_runs: 1,
            time_budget: Duration::from_secs(5),
            gas_per_tx: 100_000,
            run_baseline: false,
            fork: None,
            deployments: Vec::new(),
            guard_context: Vec::new(),
        }
    }

    fn input_with(arg: U256) -> Input {
        Input {
            selector: 0,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: vec![arg.to_be_bytes::<32>()],
            tail: Tail::Empty,
        }
    }

    fn run(code: &[u8], input: &Input, prestate: BTreeMap<U256, U256>) -> crate::evm::RunResult {
        execute(&cfg_for(code.to_vec(), prestate), input, 1_000_000)
    }

    // -- 算子 1：比较回灌穿 EQ ------------------------------------------

    #[test]
    fn op1_cmp_feedback_pierces_eq() {
        let magic = U256::from(0x1234u64);
        let (code, dest) = cmp_harness(0x14, magic, 0x61); // EQ
                                                           // 第一次执行：arg=0，比较失败（revert），比较池应有 magic。
        let first = run(&code, &input_with(U256::ZERO), BTreeMap::new());
        assert!(!first.trace.visited_pcs.contains(&dest));
        let mut pool = Pools::new();
        pool.absorb(&first);
        let cmp = pool.cmp();
        assert!(cmp.contains(&magic), "比较池应收 magic: {cmp:?}");
        assert!(cmp.contains(&U256::ZERO));

        // 应用回灌算子：槽 0 覆写为 magic，再次执行应过比较。
        let mut child = input_with(U256::from(0xdeadbeefu64));
        op_cmp_feedback(&mut child, 0, magic);
        let second = run(&code, &child, BTreeMap::new());
        assert!(second.trace.visited_pcs.contains(&dest), "回灌后应通过比较");
    }

    // -- 算子 2：常量池整参覆盖一步命中 ---------------------------------

    #[test]
    fn op2_const_pool_covers_whole_word() {
        let magic = U256::from(0xbeefu64);
        let (code, dest) = cmp_harness(0x14, magic, 0x62); // PUSH2 magic
        let consts = const_pool(&code, &ValueDictionary { words: vec![] });
        assert!(consts.contains(&magic), "常量池应含码内 PUSH 立即数 magic");
        let mut child = input_with(U256::from(0xabcdefu64));
        op_const_overwrite(&mut child, 0, magic);
        let r = run(&code, &child, BTreeMap::new());
        assert!(r.trace.visited_pcs.contains(&dest));
    }

    // -- 算子 3：±1 跨边界（两侧方向 + wrapping） -------------------------

    #[test]
    fn op3_boundary_crosses_lt_and_gt() {
        // 注意操作数序：harness 栈顶是 magic，EVM LT/GT 按
        // `top OP second` 求值 → LT 档实际判定 magic < arg
        // （arg > magic 才过）。两侧边界方向都测到：
        let v = U256::from(0x100u64);
        // arg < v 型检查（harness GT 档：v > arg 才过）：arg = v 失败，
        // v-1 通过。
        let (lt_code, lt_dest) = cmp_harness(0x11, v, 0x61); // GT 档
        let fail = run(&lt_code, &input_with(v), BTreeMap::new());
        assert!(!fail.trace.visited_pcs.contains(&lt_dest));
        let mut child = input_with(v);
        child.head[0] = op_boundary(child.head[0], false); // v-1
        let pass = run(&lt_code, &child, BTreeMap::new());
        assert!(
            pass.trace.visited_pcs.contains(&lt_dest),
            "v-1 应过 arg<v 检查"
        );

        // arg > v 型检查（harness LT 档：v < arg 才过）：arg = v 失败，
        // v+1 通过。
        let (gt_code, gt_dest) = cmp_harness(0x10, v, 0x61); // LT 档
        let fail = run(&gt_code, &input_with(v), BTreeMap::new());
        assert!(!fail.trace.visited_pcs.contains(&gt_dest));
        let mut child = input_with(v);
        child.head[0] = op_boundary(child.head[0], true); // v+1
        let pass = run(&gt_code, &child, BTreeMap::new());
        assert!(
            pass.trace.visited_pcs.contains(&gt_dest),
            "v+1 应过 arg>v 检查"
        );
    }

    #[test]
    fn op3_boundary_wraps() {
        // 0-1 → MAX；MAX+1 → 0（256 位进位/借位传播）。
        let zero = [0u8; 32];
        let max = U256::MAX.to_be_bytes::<32>();
        assert_eq!(op_boundary(zero, false), max);
        assert_eq!(op_boundary(max, true), zero);
        // 中间值：0x100 ±1。
        let v = U256::from(0x100u64).to_be_bytes::<32>();
        assert_eq!(
            U256::from_be_bytes(op_boundary(v, false)),
            U256::from(0xffu64)
        );
        assert_eq!(
            U256::from_be_bytes(op_boundary(v, true)),
            U256::from(0x101u64)
        );
    }

    // -- 算子 4：存储回灌穿 "arg == sload(slot)" -------------------------

    #[test]
    fn op4_storage_replay_pierces_sload_eq() {
        // harness：SLOAD(slot) 与 arg 比较（EQ），等值则过。
        let slot = U256::from(0x05u64);
        let value = U256::from(0xc0ffeeu64);
        let mut code = vec![0x60, 0x05, 0x54]; // PUSH1 5 SLOAD
        code.extend_from_slice(&[0x60, 0x04, 0x35]); // PUSH1 4 CALLDATALOAD
        code.push(0x14); // EQ
        let dest = code.len() as u32 + 8;
        code.push(0x60);
        code.push(dest as u8);
        code.push(0x57);
        code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]);
        code.push(0x5b);
        code.push(0x00);

        let mut prestate = BTreeMap::new();
        prestate.insert(slot, value);
        // arg 不对 → 失败；存储池应有 (slot, value)。
        let first = run(&code, &input_with(U256::from(0x42u64)), prestate.clone());
        let mut pool = Pools::new();
        pool.absorb(&first);
        assert!(
            pool.storage().contains(&(slot, value)),
            "存储池应收 (slot, value)"
        );

        // 90% 路径：值覆写参数槽 → 通过。
        let mut child = input_with(U256::from(0x42u64));
        op_storage_replay(&mut child, 0, (slot, value), false);
        let pass = run(&code, &child, prestate.clone());
        assert!(
            pass.trace.visited_pcs.contains(&dest),
            "值回灌后应过 require(arg == sload)"
        );
        // 10% 路径：键覆写（不穿，但算子行为如实可验证）。
        let mut child = input_with(U256::from(0x42u64));
        op_storage_replay(&mut child, 0, (slot, value), true);
        assert_eq!(U256::from_be_bytes(child.head[0]), slot);
    }

    // -- 算子 5：高斯缩放（比例生效 + wrapping 不 panic） -----------------

    #[test]
    fn op5_gaussian_scales_and_wraps() {
        let v = U256::from(1_000_000_000_000_000_000u128); // 10^18
        let up50 = U256::from_be_bytes(op_gaussian(v.to_be_bytes::<32>(), 50, true));
        assert_eq!(up50, v * U256::from(150u64) / U256::from(100u64));
        let down50 = U256::from_be_bytes(op_gaussian(v.to_be_bytes::<32>(), 50, false));
        assert_eq!(down50, v * U256::from(100u64) / U256::from(150u64));

        // EQ harness：magic = v，arg = 2v 失败；down 100%（减半）→ v 通过。
        let (code, dest) = cmp_harness(0x14, v, 0x7f); // PUSH32
        let fail = run(&code, &input_with(v * U256::from(2u64)), BTreeMap::new());
        assert!(!fail.trace.visited_pcs.contains(&dest));
        let mut child = input_with(v * U256::from(2u64));
        child.head[0] = op_gaussian(child.head[0], 100, false);
        let pass = run(&code, &child, BTreeMap::new());
        assert!(
            pass.trace.visited_pcs.contains(&dest),
            "缩 100%（减半）应命中"
        );

        // 极端：MAX 上缩 1000% wrapping 不 panic，且落在合法域。
        let scaled = op_gaussian(U256::MAX.to_be_bytes::<32>(), 1000, true);
        let _ = U256::from_be_bytes(scaled);
    }

    // -- 定长/变长分集 ----------------------------------------------------

    #[test]
    fn head_ops_never_touch_tail() {
        let tail_bytes = vec![0xaau8; 64];
        for op in [
            HeadOp::CmpFeedback,
            HeadOp::ConstOverwrite,
            HeadOp::BoundaryIncDec,
            HeadOp::StorageReplay,
            HeadOp::GaussianScale,
        ] {
            let parent = Input {
                selector: 0xdeadbeef,
                caller: [0x11; 20],
                value: U256::ZERO,
                head: vec![[0u8; 32]; 2],
                tail: Tail::Bytes(tail_bytes.clone()),
            };
            // 直接经公共变异入口多轮投掷，tail 只可能落变长/legacy
            // 系列；此处用 op 枚举钉住定长五算子的纯效果。
            let mut child = parent.clone();
            match op {
                HeadOp::CmpFeedback => op_cmp_feedback(&mut child, 0, U256::from(9u64)),
                HeadOp::ConstOverwrite => op_const_overwrite(&mut child, 0, U256::from(9u64)),
                HeadOp::BoundaryIncDec => {
                    child.head[0] = op_boundary(child.head[0], true);
                }
                HeadOp::StorageReplay => {
                    op_storage_replay(&mut child, 0, (U256::ZERO, U256::from(9u64)), false)
                }
                HeadOp::GaussianScale => {
                    child.head[0] = op_gaussian(child.head[0], 50, true);
                }
                HeadOp::Coordinated => {
                    // 纯效果走 propose 路径；此分集测试只要求不碰 tail。
                }
            }
            assert_eq!(child.tail, Tail::Bytes(tail_bytes.clone()), "{op:?}");
        }
    }

    #[test]
    fn tail_ops_never_touch_head() {
        let head = vec![[0xbbu8; 32]; 2];
        let mut tail = vec![0xaau8; 64];
        tail_truncate(&mut tail, 1);
        assert_eq!(tail, vec![0xaau8; 32]);
        tail_extend(&mut tail, &[[0xccu8; 32]]);
        let mut expect = vec![0xaau8; 32];
        expect.extend_from_slice(&[0xccu8; 32]);
        assert_eq!(tail, expect);
        tail_block_replace(&mut tail, 1, [0xddu8; 32]);
        assert_eq!(tail[32..], [0xddu8; 32]);
        // 头槽未被任何尾算子触碰（函数签名上就不接收 head）。
        assert_eq!(head, vec![[0xbbu8; 32]; 2]);
    }

    #[test]
    fn chooser_respects_domains_and_is_deterministic() {
        let consts = const_pool(
            &[0x60, 0x2a, 0x61, 0x01, 0x02],
            &ValueDictionary {
                words: vec![U256::from(0x42u64)],
            },
        );
        assert!(consts.contains(&U256::from(0x2au64)));
        assert!(consts.contains(&U256::from(0x0102u64)));
        assert!(consts.contains(&U256::from(0x42u64)));

        let parent = Input {
            selector: 0xdeadbeef,
            caller: [0x11; 20],
            value: U256::ZERO,
            head: vec![[0u8; 32]; 2],
            tail: Tail::Bytes(vec![0u8; 64]),
        };
        let cmp_pool = vec![U256::from(0x99u64)];
        let storage_pool = vec![(U256::from(1u64), U256::from(2u64))];
        let mut rng_a = Rng::new(11);
        let mut ctx_a = MutCtx::new(&mut rng_a, &consts, &cmp_pool, &storage_pool);
        let a = mutate(&parent, &mut ctx_a);
        let mut rng_b = Rng::new(11);
        let mut ctx_b = MutCtx::new(&mut rng_b, &consts, &cmp_pool, &storage_pool);
        let b = mutate(&parent, &mut ctx_b);
        assert_eq!(a, b, "同 seed 同输入变异应逐位确定");
        // 分集：头槽数与 selector 永不变；tail 要么 Bytes 要么 Empty。
        assert_eq!(a.head.len(), 2);
        assert_eq!(a.selector, parent.selector);
        assert!(matches!(a.tail, Tail::Bytes(_) | Tail::Empty));
    }

    #[test]
    fn pools_dedup_and_cap() {
        let cfg = cfg_for(vec![0x5b, 0x00], BTreeMap::new());
        let input = input_with(U256::ZERO);
        let mut run = execute(&cfg, &input, 1_000_000);
        run.cmp_observed = [[U256::from(1u64), U256::from(2u64)]].to_vec();
        run.storage_observed = vec![(U256::from(3u64), U256::from(4u64))];
        let mut pool = Pools::new();
        for _ in 0..4 {
            pool.absorb(&run); // 重复吸收：去重
        }
        assert_eq!(pool.cmp().len(), 2);
        assert_eq!(pool.storage().len(), 1);
        // 上限：灌爆 cmp 池。
        let mut run2 = execute(&cfg, &input, 1_000_000);
        run2.cmp_observed = (0..600u64)
            .map(|i| [U256::from(i), U256::from(i + 1000)])
            .collect();
        pool.absorb(&run2);
        assert!(pool.cmp().len() <= CMP_POOL_CAP);
        assert!(pool.storage().len() <= STORAGE_POOL_CAP);
    }
}
