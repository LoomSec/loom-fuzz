//! CFG 静态分析与 PC 距离表（零第三方依赖，直接扫字节码）。
//!
//! 基本块切分：pc 0 与每个 JUMPDEST 起块，至 JUMP/JUMPI/终止指令
//! （STOP/RETURN/REVERT/INVALID/SELFDESTRUCT）止；PUSH1..PUSH32
//! 立即数区跳过不当操作码。边：
//! - 顺序下落（块尾非 JUMP/终止指令）；
//! - JUMPI：fallthrough + taken；JUMP：仅 taken；
//! - taken 目标解析：紧邻 JUMP(JUMPI) 前一条是 PUSHn const 且
//!   `code[const] == JUMPDEST` 则定值解析，否则保守连全部 JUMPDEST
//!   块（上近似——距离只可能偏小，不会把可达报成不可达）。
//!
//! 从含 target pc 的块多源反向 BFS，得每块到目标集的边距离；
//! 不可达块 = `u32::MAX`。fitness = visited pcs 的块距离最小值。

use std::collections::{BTreeSet, VecDeque};

use revm::bytecode::opcode;

/// 一条块边（from → to），均为块下标。
#[derive(Debug, Clone, Copy)]
struct Edge {
    from: usize,
    to: usize,
}

/// pc → 所在块下标映射的稠密表：`u32::MAX` = 该 pc 无块（落在
/// PUSH 立即数区的 pc 不是可执行位置——target pc 落数据区即
/// 不可达，如实）。
#[derive(Debug, Clone)]
pub struct DistanceTable {
    /// pc → 块下标（密集数组，下标即 pc）。
    pc_to_block: Vec<u32>,
    /// 块（按下标）→ 到目标集的距离（BFS 边数；`u32::MAX` = 不可达）。
    block_dist: Vec<u32>,
    target_pcs: BTreeSet<u32>,
}

impl DistanceTable {
    /// 构建距离表。`target_pcs` 为空时无目标：一切 fitness 为
    /// `u32::MAX`，`is_target` 恒 false（如实，不编造）。
    pub fn new(code: &[u8], target_pcs: &[u32]) -> Self {
        let blocks = split_blocks(code);
        let jumpdest_blocks: Vec<usize> = blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| code[b.start as usize] == opcode::JUMPDEST)
            .map(|(i, _)| i)
            .collect();

        // PUSH 立即数区的 pc 不可执行：pc_to_block 只标指令 pc。
        let is_data = data_region_mask(code);
        let mut pc_to_block = vec![u32::MAX; code.len()];
        for (i, b) in blocks.iter().enumerate() {
            for pc in b.start..=b.end {
                if !is_data[pc as usize] {
                    pc_to_block[pc as usize] = i as u32;
                }
            }
        }

        // 正向边 + 收集反向邻接。
        let mut edges: Vec<Edge> = Vec::new();
        for (i, b) in blocks.iter().enumerate() {
            // 块尾可能是 PUSH 数据字节：取最后一条指令 pc。
            let last_pc = b.last_instr as usize;
            match code[last_pc] {
                opcode::JUMP => {
                    push_taken_edge(code, &blocks, &jumpdest_blocks, i, last_pc, &mut edges);
                }
                opcode::JUMPI => {
                    push_taken_edge(code, &blocks, &jumpdest_blocks, i, last_pc, &mut edges);
                    // fallthrough。
                    if i + 1 < blocks.len() {
                        edges.push(Edge { from: i, to: i + 1 });
                    }
                }
                opcode::STOP
                | opcode::RETURN
                | opcode::REVERT
                | opcode::INVALID
                | opcode::SELFDESTRUCT => {}
                _ => {
                    // 块尾非终止指令（代码截断形态）：顺序下落。
                    if i + 1 < blocks.len() {
                        edges.push(Edge { from: i, to: i + 1 });
                    }
                }
            }
        }

        let mut reverse: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
        for e in edges {
            reverse[e.to].push(e.from);
        }

        // 多源 BFS：源 = 含 target pc 的块。
        let mut block_dist = vec![u32::MAX; blocks.len()];
        let mut queue: VecDeque<usize> = VecDeque::new();
        for &pc in target_pcs {
            if let Some(&b) = pc_to_block.get(pc as usize) {
                if b != u32::MAX && block_dist[b as usize] == u32::MAX {
                    block_dist[b as usize] = 0;
                    queue.push_back(b as usize);
                }
            }
        }
        while let Some(b) = queue.pop_front() {
            let d = block_dist[b];
            for &prev in &reverse[b] {
                if block_dist[prev] == u32::MAX {
                    block_dist[prev] = d + 1;
                    queue.push_back(prev);
                }
            }
        }

        DistanceTable {
            pc_to_block,
            block_dist,
            target_pcs: target_pcs.iter().copied().collect(),
        }
    }

    /// visited 是否命中任一 target pc。
    pub fn is_target(&self, pc: u32) -> bool {
        self.target_pcs.contains(&pc)
    }

    /// 单个 pc 的块距离（pc 不在任何块 = `u32::MAX`）。
    pub fn pc_distance(&self, pc: u32) -> u32 {
        match self.pc_to_block.get(pc as usize) {
            Some(&b) if b != u32::MAX => self.block_dist[b as usize],
            _ => u32::MAX,
        }
    }

    /// fitness(run) = visited pcs 的块距离最小值；空集或无可达 =
    /// `u32::MAX`。
    pub fn fitness(&self, visited_pcs: impl IntoIterator<Item = u32>) -> u32 {
        let mut best = u32::MAX;
        for pc in visited_pcs {
            let d = self.pc_distance(pc);
            if d < best {
                best = d;
            }
        }
        best
    }

    /// 块数（测试与诊断用）。
    #[cfg(test)]
    pub(crate) fn block_count(&self) -> usize {
        self.block_dist.len()
    }

    /// 可执行指令 pc 数（coverage 的 total 口径：pc_to_block 有效
    /// 项计数——每个非 PUSH 数据区的指令 pc 恰属一块）。
    pub fn executable_pc_count(&self) -> usize {
        self.pc_to_block.iter().filter(|&&b| b != u32::MAX).count()
    }
}

/// 基本块：[start, end]（含两端 pc；end 可能是 PUSH 数据字节），
/// `last_instr` = 块内最后一条指令 pc（边的语义由它决定）。
#[derive(Debug, Clone, Copy)]
struct Block {
    start: u32,
    end: u32,
    last_instr: u32,
}

/// 线性扫描切基本块：pc 0 / JUMPDEST / 终止指令之后起新块；
/// PUSH 立即数区跳过。
fn split_blocks(code: &[u8]) -> Vec<Block> {
    let is_terminator = |op: u8| {
        matches!(
            op,
            opcode::JUMP
                | opcode::JUMPI
                | opcode::STOP
                | opcode::RETURN
                | opcode::REVERT
                | opcode::INVALID
                | opcode::SELFDESTRUCT
        )
    };

    let mut blocks = Vec::new();
    let mut start: Option<u32> = None;
    let mut last_instr: Option<u32> = None;
    let mut i = 0usize;
    while i < code.len() {
        if start.is_none() {
            start = Some(i as u32);
        }
        let op = code[i];
        if is_terminator(op) {
            // 终止指令本身就是块内最后一条指令。
            last_instr = Some(i as u32);
            blocks.push(Block {
                start: start.take().unwrap(),
                end: i as u32,
                last_instr: i as u32,
            });
            i += 1;
        } else if (opcode::PUSH1..=opcode::PUSH32).contains(&op) {
            last_instr = Some(i as u32);
            i += 1 + usize::from(op - opcode::PUSH1 + 1);
        } else {
            if op == opcode::JUMPDEST && start != Some(i as u32) {
                // JUMPDEST 落在一个块中间：前一块在 JUMPDEST 前结束。
                blocks.push(Block {
                    start: start.take().unwrap(),
                    end: i as u32 - 1,
                    last_instr: last_instr.take().unwrap_or(i as u32 - 1),
                });
                start = Some(i as u32);
            }
            last_instr = Some(i as u32);
            i += 1;
        }
    }
    if let Some(s) = start {
        blocks.push(Block {
            start: s,
            end: code.len() as u32 - 1,
            last_instr: last_instr.unwrap_or(s),
        });
    }
    blocks
}

/// PUSH 立即数区掩码：数据字节标 true（线性扫描，与切块同一跳过
/// 规则——数据区里的伪操作码不当指令）。
fn data_region_mask(code: &[u8]) -> Vec<bool> {
    let mut mask = vec![false; code.len()];
    let mut i = 0usize;
    while i < code.len() {
        let op = code[i];
        if (opcode::PUSH1..=opcode::PUSH32).contains(&op) {
            let n = usize::from(op - opcode::PUSH1 + 1);
            let end = (i + 1 + n).min(code.len());
            for m in &mut mask[i + 1..end] {
                *m = true;
            }
            i += 1 + n;
        } else {
            i += 1;
        }
    }
    mask
}

/// 解析 JUMP/JUMPI 的 taken 边：紧邻前一条是 PUSHn const 且指向
/// JUMPDEST → 定值边；否则保守连全部 JUMPDEST 块。
fn push_taken_edge(
    code: &[u8],
    blocks: &[Block],
    jumpdest_blocks: &[usize],
    from: usize,
    jump_pc: usize,
    edges: &mut Vec<Edge>,
) {
    if let Some(target) = resolve_push_const(code, jump_pc) {
        // 目标 pc 落在某块首（JUMPDEST 必为块首）。
        let to = blocks
            .iter()
            .position(|b| b.start == target)
            .unwrap_or_else(|| {
                // 防御：指向 JUMPDEST 则必有块；理论不到达。
                jumpdest_blocks
                    .first()
                    .copied()
                    .expect("JUMPDEST 集合非空则 blocks 非空")
            });
        edges.push(Edge { from, to });
    } else {
        for &to in jumpdest_blocks {
            edges.push(Edge { from, to });
        }
    }
}

/// JUMP/JUMPI 紧邻前一条指令若是 PUSHn，返回其 const 立即数（u32，
/// 截断），否则 None。前一条指令定位需跳过它自己的 PUSH 数据——从
/// 块首线性扫到 jump_pc，记录最后一条指令的 pc 与立即数。
fn resolve_push_const(code: &[u8], jump_pc: usize) -> Option<u32> {
    let mut i = 0usize;
    let mut last_push: Option<(usize, u8)> = None;
    while i < jump_pc.min(code.len()) {
        let op = code[i];
        if (opcode::PUSH1..=opcode::PUSH32).contains(&op) {
            last_push = Some((i, op));
            i += 1 + usize::from(op - opcode::PUSH1 + 1);
        } else {
            i += 1;
        }
    }
    let (push_pc, op) = last_push?;
    // 紧邻判定：PUSH 指令区结束必须正好是 jump_pc。
    if push_pc + 1 + usize::from(op - opcode::PUSH1 + 1) != jump_pc {
        return None;
    }
    let n = usize::from(op - opcode::PUSH1 + 1);
    let imm = code.get(push_pc + 1..push_pc + 1 + n)?;
    let mut word = [0u8; 4];
    word[4 - imm.len()..].copy_from_slice(imm);
    let target = u32::from_be_bytes(word);
    (target < code.len() as u32 && code[target as usize] == opcode::JUMPDEST).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PUSH1 3 PUSH1 0 JUMP  JUMPDEST PUSH1 0 PUSH1 0 RETURN
    /// 块 0: [0,4]（JUMP @4），块 1: [5,10]（RETURN @10）。
    const JUMP_CODE: &[u8] = &[
        0x60, 0x03, 0x60, 0x00, 0x56, 0x5b, 0x60, 0x00, 0x60, 0x00, 0xf3,
    ];

    /// 取块 i 的起始 pc（测试断言用）。
    fn block_start(table: &DistanceTable, i: usize) -> Option<u32> {
        // 经 pc_to_block 反查：块 i 的首个指令 pc。
        (0..table.pc_to_block.len() as u32).find(|&pc| table.pc_to_block[pc as usize] == i as u32)
    }

    #[test]
    fn split_finds_jumpdest_blocks() {
        let blocks = split_blocks(JUMP_CODE);
        assert_eq!(blocks.len(), 2);
        assert_eq!((blocks[0].start, blocks[0].end), (0, 4));
        assert_eq!((blocks[1].start, blocks[1].end), (5, 10));
    }

    #[test]
    fn resolved_jump_gives_zero_distance_at_target() {
        let table = DistanceTable::new(JUMP_CODE, &[8]);
        assert_eq!(table.pc_distance(8), 0);
        // 块 0 经 JUMP 一跳到块 1。
        assert_eq!(table.pc_distance(0), 1);
        assert!(table.is_target(8));
        assert!(!table.is_target(0));
    }

    /// PUSH 数据区里的伪 JUMPDEST 不当块首/指令：0x5b 落在 PUSH2
    /// 立即数区。
    #[test]
    fn push_data_not_opcode() {
        let code: &[u8] = &[0x61, 0x5b, 0x00, 0x60, 0x00, 0x56];
        let table = DistanceTable::new(code, &[5]);
        assert_eq!(table.block_count(), 1);
        assert_eq!(block_start(&table, 0), Some(0));
        // 数据区 pc 不属于任何块。
        assert_eq!(table.pc_distance(1), u32::MAX);
        // JUMP 前一条 PUSH1 0 解析不出 JUMPDEST → 保守边为空集，
        // 单块内距离只看目标位置。
        assert_eq!(table.pc_distance(5), 0);
    }

    /// JUMPI 双目标：taken 定值解析 + fallthrough 续接。
    #[test]
    fn jumpi_has_fallthrough_and_taken() {
        // pc0-1: PUSH1 6，pc2: JUMPI，pc3: JUMPDEST，pc4-5: PUSH1 0，
        // pc6: JUMPDEST，pc7: STOP。块：[0,2] [3,5] [6,7]。
        let code: &[u8] = &[0x60, 0x06, 0x57, 0x5b, 0x60, 0x00, 0x5b, 0x00];
        let table = DistanceTable::new(code, &[7]);
        // 目标块 [6,7] 距离 0。
        assert_eq!(table.pc_distance(7), 0);
        // fallthrough 块 [3,5] 顺序下落续接目标 → 距离 1。
        assert_eq!(table.pc_distance(3), 1);
        // 块 [0,2] taken 直达目标 → 距离 1。
        assert_eq!(table.pc_distance(0), 1);
    }

    /// 解析不到 PUSH const 的 JUMPI：taken 保守连全部 JUMPDEST。
    /// fallthrough 死路（STOP 块）距离仍 MAX——保守边只从 JUMPI
    /// 块出发，这是上近似而非全连接。
    #[test]
    fn unresolved_jumpi_conservative_to_all_jumpdests() {
        // pc0: DUP1，pc1: JUMPI，pc2: STOP，pc3: JUMPDEST，pc4: STOP。
        // 块：[0,1] [2,2] [3,4]。唯一 JUMPDEST 块是 [3,4]。
        let code: &[u8] = &[0x80, 0x57, 0x00, 0x5b, 0x00];
        let table = DistanceTable::new(code, &[4]);
        assert_eq!(table.pc_distance(4), 0);
        // 保守 taken 边 0→[3,4]：没有它，fallthrough 停在 STOP，
        // 块 [0,1] 将是 MAX。
        assert_eq!(table.pc_distance(0), 1);
        // fallthrough 落进的 STOP 块到目标无路径。
        assert_eq!(table.pc_distance(2), u32::MAX);
    }

    #[test]
    fn unreachable_target_is_max() {
        // 目标 pc 7 是 PUSH1 的立即数字节（code[6] = 0x60）：数据区
        // pc 不可执行——不构成目标块，执行也永不访问（is_target 只在
        // visited pcs 上判定，visited 只含指令 pc）。
        let table = DistanceTable::new(JUMP_CODE, &[7]);
        assert_eq!(table.pc_distance(7), u32::MAX);
        assert_eq!(table.fitness([0, 4, 6]), u32::MAX);
    }

    #[test]
    fn fitness_is_min_over_visited() {
        let table = DistanceTable::new(JUMP_CODE, &[8]);
        assert_eq!(table.fitness([0, 8]), 0);
        assert_eq!(table.fitness([0]), 1);
        assert_eq!(table.fitness([]), u32::MAX);
    }

    #[test]
    fn empty_targets_all_max() {
        let table = DistanceTable::new(JUMP_CODE, &[]);
        assert_eq!(table.pc_distance(0), u32::MAX);
        assert!(!table.is_target(8));
    }
}
