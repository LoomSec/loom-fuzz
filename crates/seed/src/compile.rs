//! seed 编译主逻辑：支配 guard 结构化反解 → [`SeedOutput`]。
//!
//! 支配 guard 的判定与 `crates/cli/src/detect.rs` 的
//! `dominating_guards` 同源（step < hit.step 且 scope
//! prefix-comparable），此处按同一语义从 xlayer 展开流重新派生。
//! 命中步序/作用域 `Hit` 未存（只存渲染文本与 pc），用
//! `target_pcs` 在 `func` 展开流中定位效果步序（pc 匹配的全部
//! 效果步序都取，guard 按 (cond, polarity, pc) 去重）。

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::U256;
use loom_fuzz_shard::Shard;
use loom_fuzz_xlayer::{XEntry, Xlayer};

use crate::node::{render_node, Node, View};
use crate::{FreeVar, HitView, Input, SeedOutput, Tail, Target, ValueDictionary, MAX_SEEDS};

/// 比较操作符家族：`<`/`>`/`s<`/`s>`（含 `<=`/`>=` 与同族有符号形）。
const BOUNDARY_OPS: [&str; 8] = ["<", ">", "<=", ">=", "s<", "s>", "s<=", "s>="];

// ---------------------------------------------------------------------------
// 命中定位与支配 guard 派生（与 cli detect.rs 同源）
// ---------------------------------------------------------------------------

/// 从 selector + target_pcs 定位函数下标：优先"selector 匹配且展开流
/// 中有 pc 命中目标"的函数，退化为纯 selector 匹配。
pub fn locate(shard: &Shard, view: &Xlayer<'_>, hit: &dyn HitView) -> Option<usize> {
    let mut by_selector = None;
    for (idx, func) in shard.functions().iter().enumerate() {
        if func.selector != Some(hit.selector()) {
            continue;
        }
        by_selector.get_or_insert(idx);
        let pc_hit = view.expand(idx).is_some_and(|entries| {
            entries
                .iter()
                .any(|e| matches!(e, XEntry::Effect { pc, .. } if hit.target_pcs().contains(pc)))
        });
        if pc_hit {
            return Some(idx);
        }
    }
    by_selector
}

/// scope parent（shard 作用域表 + xlayer rebase mint 的新作用域；
/// id 0 是根，无 parent）。与 cli detect.rs 的 `scope_parent` 同源。
fn scope_parent(shard: &Shard, view: &Xlayer<'_>, id: u32) -> Option<u32> {
    if id == 0 {
        return None;
    }
    let base = shard.scopes().len() as u32;
    if id <= base {
        Some(shard.scopes()[(id - 1) as usize].parent)
    } else {
        view.scopes_new()
            .get((id - base - 1) as usize)
            .map(|(parent, _, _)| *parent)
    }
}

/// `scope_cmp`：a、b 在作用域树里 prefix-comparable（任一方向
/// ancestor-or-self；loom 的 `is_ancestor_or_self` 照抄）。
fn scope_cmp(shard: &Shard, view: &Xlayer<'_>, a: u32, b: u32) -> bool {
    fn ancestor_or_self(shard: &Shard, view: &Xlayer<'_>, anc: u32, mut id: u32) -> bool {
        loop {
            if id == anc {
                return true;
            }
            if id == 0 {
                return anc == 0;
            }
            match scope_parent(shard, view, id) {
                Some(parent) => id = parent,
                None => return false,
            }
        }
    }
    ancestor_or_self(shard, view, a, b) || ancestor_or_self(shard, view, b, a)
}

/// 一条支配 guard：cond 表达式 id（结构化，未经渲染）+ 真假支 + pc。
struct DominatingGuard {
    cond: u32,
    polarity: bool,
    pc: u32,
}

/// 命中效果（pc ∈ target_pcs）的全部效果步序，按步序升序。
fn hit_steps(entries: &[XEntry], target_pcs: &[u32]) -> Vec<(u32, u32)> {
    entries
        .iter()
        .filter_map(|e| match e {
            XEntry::Effect {
                step, scope, pc, ..
            } if target_pcs.contains(pc) => Some((*step, *scope)),
            _ => None,
        })
        .collect()
}

/// 支配 guard 集合：步序 gi < i 且 scope prefix-comparable，按步序
/// 升序，(cond, polarity, pc) 去重（多个命中步序共享 guard 时只收
/// 一次）。与 cli detect.rs 的 `dominating_guards` 同源。
fn dominating_guards(
    shard: &Shard,
    view: &Xlayer<'_>,
    entries: &[XEntry],
    steps: &[(u32, u32)],
) -> Vec<DominatingGuard> {
    let mut out: Vec<DominatingGuard> = Vec::new();
    for &(i, si) in steps {
        for entry in entries {
            let XEntry::Guard {
                cond,
                polarity,
                scope: sg,
                pc,
                step: gi,
            } = entry
            else {
                continue;
            };
            if *gi >= i || !scope_cmp(shard, view, *sg, si) {
                continue;
            }
            if out
                .iter()
                .any(|g| g.cond == *cond && g.polarity == *polarity && g.pc == *pc)
            {
                continue;
            }
            out.push(DominatingGuard {
                cond: *cond,
                polarity: *polarity,
                pc: *pc,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 求解：比较节点分类与规则
// ---------------------------------------------------------------------------

/// 剥掉 Cast 壳后的操作数分类。
enum Operand {
    /// calldata 第 `off` 字（Cast 壳已剥，`width` 是最内截断位宽，
    /// None = 全宽 256）。
    Calldata { off: u64, width: Option<u64> },
    /// `msg.sender` / `tx.origin`。
    Sender,
    /// `this`。
    This,
    /// 存储读 `storage(owner, key)`（canonical 2 元拼写）。
    Storage { owner_this: bool, key: u32 },
    /// 256 位常量。
    Const(U256),
    /// 其它形态（含 mapping 派生键——其本身也是 Storage 的 key）。
    Other,
}

/// 剥 Cast 壳（收集最内层位宽做常量适配检查）。
fn peel_cast(view: &impl View, mut id: u32) -> (u32, Option<u64>) {
    let mut width = None;
    while let Some(Node::Cast(inner, bits)) = view.node(id) {
        width = Some(bits);
        id = inner;
    }
    (id, width)
}

/// 操作数分类。
fn classify(view: &impl View, id: u32) -> Operand {
    let (id, width) = peel_cast(view, id);
    match view.node(id) {
        Some(Node::CalldataWord(off)) => Operand::Calldata { off, width },
        Some(Node::Named(name, _)) if name == "msg.sender" || name == "tx.origin" => {
            Operand::Sender
        }
        Some(Node::Named(name, _)) if name == "this" => Operand::This,
        Some(Node::Named(name, children)) if name == "storage" && children.len() == 2 => {
            let owner_this = matches!(
                view.node(children[0]),
                Some(Node::Named(owner, _)) if owner == "this"
            );
            Operand::Storage {
                owner_this,
                key: children[1],
            }
        }
        Some(Node::Const(word)) => Operand::Const(U256::from_be_bytes(word)),
        _ => Operand::Other,
    }
}

/// calldata 字偏移 → 参数槽。off≥4 且 (off-4) 32 字节对齐才落槽。
fn calldata_slot(off: u64) -> Option<usize> {
    if off < 4 {
        return None;
    }
    let rel = off - 4;
    if !rel.is_multiple_of(32) {
        return None;
    }
    Some((rel / 32) as usize)
}

/// 常量是否适配截断位宽（width = None 全宽恒适配）。
fn fits_width(c: U256, width: Option<u64>) -> bool {
    match width {
        None | Some(256) => true,
        Some(bits) => c < (U256::from(1) << bits),
    }
}

/// 比较节点求解的累积结果（全部守卫共享，合取）。
struct Solved {
    /// calldata 槽等值固定（slot → 字值）。
    fixes: BTreeMap<usize, [u8; 32]>,
    /// caller 等值固定。
    caller: Option<[u8; 20]>,
    /// 边界变体：(槽, 边界值)（跨守卫累计，组装期去重）。
    boundaries: Vec<(usize, U256)>,
    /// 值字典积累（去重排序在组装期）。
    dict: BTreeSet<U256>,
    free: Vec<FreeVar>,
    assumptions: Vec<String>,
    /// 是否有可解的 calldata/caller 约束（无可解 → 退化路径）。
    solvable: bool,
}

impl Solved {
    fn assume(&mut self, text: String) {
        if !self.assumptions.contains(&text) {
            self.assumptions.push(text);
        }
    }

    fn add_free(&mut self, what: String, hint: Option<U256>) {
        if !self.free.iter().any(|f| f.what == what) {
            self.free.push(FreeVar { what, hint });
        }
    }

    /// `Cmp("==", CalldataWord(off), Const c)`（polarity=true）→ 落槽。
    fn fix_calldata(&mut self, pc: u32, off: u64, width: Option<u64>, c: U256, rendered: &str) {
        let Some(slot) = calldata_slot(off) else {
            let why = if off < 4 {
                "selector 区 calldata 字不可控"
            } else {
                "calldata 字偏移非 32 字节对齐，无法落槽"
            };
            self.assume(format!("guard@pc{pc}: {rendered}：{why}，留搜索空间"));
            return;
        };
        if !fits_width(c, width) {
            self.assume(format!(
                "guard@pc{pc}: {rendered}：常量 {c:#x} 超出截断位宽 {:?}，约束不可解，留搜索空间",
                width
            ));
            return;
        }
        let word = c.to_be_bytes::<32>();
        if let Some(prev) = self.fixes.get(&slot) {
            if *prev != word {
                let prev_v = U256::from_be_bytes(*prev);
                self.assume(format!(
                    "guard@pc{pc}: {rendered}：槽 {slot} 等值冲突（{prev_v:#x} vs {c:#x}），约束不可合取，留搜索空间"
                ));
            }
            return;
        }
        self.fixes.insert(slot, word);
        self.solvable = true;
    }

    /// `Cmp("==", Env("msg.sender")|Leaf("this"), Const a)` → caller。
    fn fix_caller(&mut self, pc: u32, c: U256, rendered: &str) {
        let limit = U256::from(1) << 160;
        if c >= limit {
            self.assume(format!(
                "guard@pc{pc}: {rendered}：地址常量 {c:#x} 超 160 位，约束不可解，留搜索空间"
            ));
            return;
        }
        let word = c.to_be_bytes::<32>();
        let addr: [u8; 20] = word[12..].try_into().expect("32 - 12 = 20");
        if let Some(prev) = self.caller {
            if prev != addr {
                self.assume(format!(
                    "guard@pc{pc}: {rendered}：caller 等值冲突（0x{} vs {c:#x}），约束不可合取，留搜索空间",
                    hex20(prev)
                ));
            }
            return;
        }
        self.caller = Some(addr);
        self.solvable = true;
    }

    /// `Cmp("==", storage(this, key), Const v)`：进不了 calldata——
    /// Const 槽记 FreeVar（prestate 提示 slot/value）+ assumption；
    /// mapping 派生键（registry 成员测试）只记 assumption。
    fn fix_storage(&mut self, view: &impl View, pc: u32, key: u32, v: U256, rendered: &str) {
        let key_is_const = matches!(view.node(key), Some(Node::Const(_)));
        if key_is_const {
            let slot = match view.node(key) {
                Some(Node::Const(word)) => U256::from_be_bytes(word),
                _ => unreachable!("key_is_const 已判定"),
            };
            self.add_free(
                format!("guard@pc{pc}: 存储 prestate slot {slot:#x}（要求 == {v:#x}）"),
                Some(v),
            );
            self.assume(format!(
                "guard@pc{pc}: {rendered}：存储等值约束不可直接进 calldata，slot {slot:#x} 标 free 进搜索空间"
            ));
        } else {
            self.assume(format!(
                "guard@pc{pc}: {rendered}：registry 成员测试/存储派生键，服务地址未知，留搜索空间"
            ));
        }
    }

    /// 边界家族：值字典收 c-1/c/c+1（截断到 U256 合法范围）；非 Const
    /// 端是 calldata 字时为每个边界值生成变体。
    fn boundary(&mut self, view: &impl View, pc: u32, other: u32, c: U256, rendered: &str) {
        let one = U256::from(1);
        let neighbors = [c.saturating_sub(one), c, c.saturating_add(one)];
        for v in neighbors {
            self.dict.insert(v);
        }
        if let Operand::Calldata { off, width } = classify(view, other) {
            let Some(slot) = calldata_slot(off) else {
                self.assume(format!(
                    "guard@pc{pc}: {rendered}：边界常量 {c:#x} 已入字典，但 calldata 端偏移 0x{off:x} 无法落槽，未生成变体"
                ));
                return;
            };
            for v in neighbors {
                if fits_width(v, width) {
                    self.boundaries.push((slot, v));
                }
            }
            self.solvable = true;
        } else {
            self.assume(format!(
                "guard@pc{pc}: {rendered}：边界常量 {c:#x}（±1）已入字典，但比较左端不可控，未生成变体"
            ));
        }
    }
}

fn hex20(addr: [u8; 20]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(40);
    for b in addr {
        let _ = write!(text, "{b:02x}");
    }
    text
}

/// 对一个比较节点求解（op 已取出，a/b 为操作数 id）。
fn solve_cmp(
    view: &impl View,
    op: &str,
    a: u32,
    b: u32,
    polarity: bool,
    pc: u32,
    out: &mut Solved,
) {
    let text = render_cmp(view, op, a, b);
    match op {
        "==" => {
            if !polarity {
                out.assume(format!(
                    "guard@pc{pc}: {text}：假支等值约束不反解，留搜索空间"
                ));
                return;
            }
            match (classify(view, a), classify(view, b)) {
                (Operand::Calldata { off, width }, Operand::Const(c))
                | (Operand::Const(c), Operand::Calldata { off, width }) => {
                    out.fix_calldata(pc, off, width, c, &text);
                }
                (Operand::Sender, Operand::Const(c)) | (Operand::Const(c), Operand::Sender) => {
                    out.fix_caller(pc, c, &text);
                }
                (Operand::This, Operand::Const(c)) | (Operand::Const(c), Operand::This) => {
                    out.fix_caller(pc, c, &text);
                }
                (
                    Operand::Storage {
                        owner_this: true,
                        key,
                    },
                    Operand::Const(v),
                )
                | (
                    Operand::Const(v),
                    Operand::Storage {
                        owner_this: true,
                        key,
                    },
                ) => out.fix_storage(view, pc, key, v, &text),
                (Operand::Const(x), Operand::Const(y)) => {
                    if x != y {
                        out.assume(format!(
                            "guard@pc{pc}: {text}：恒假 guard（不可达支），如实记录"
                        ));
                    }
                }
                _ => out.assume(format!(
                    "guard@pc{pc}: {text}：等值形态未解（存储非 this / 双方非常量），留搜索空间"
                )),
            }
        }
        "!=" => {
            // registry 成员测试编译形：`!=(storage(this, mapping(...)),
            // 0)`——键是 calldata 派生，服务地址静态未知。
            let registry_member_test = [a, b].iter().any(|&id| {
                matches!(
                    classify(view, id),
                    Operand::Storage { owner_this: true, key }
                        if !matches!(view.node(key), Some(Node::Const(_)))
                )
            });
            if registry_member_test {
                out.assume(format!(
                    "guard@pc{pc}: {text}：registry 成员测试，服务地址未知，留搜索空间"
                ));
            } else {
                out.assume(format!(
                    "guard@pc{pc}: {text}：不等约束不反解（polarity={polarity}），留搜索空间"
                ));
            }
        }
        _ if BOUNDARY_OPS.contains(&op) => {
            let both_const = matches!(classify(view, a), Operand::Const(_))
                && matches!(classify(view, b), Operand::Const(_));
            if both_const {
                // 双边常量：可折叠与否已由 xlayer 常折叠处理；无可反解。
                return;
            }
            let found = match (classify(view, a), classify(view, b)) {
                (Operand::Const(c), _) => Some((c, b)),
                (_, Operand::Const(c)) => Some((c, a)),
                _ => None,
            };
            match found {
                Some((c, other_id)) => out.boundary(view, pc, other_id, c, &text),
                None => out.assume(format!(
                    "guard@pc{pc}: {text}：边界比较无常量端，未解，留搜索空间"
                )),
            }
        }
        _ => out.assume(format!(
            "guard@pc{pc}: {text}：比较算子 {op:?} 未覆盖，留搜索空间"
        )),
    }
}

/// 渲染比较节点文本（assumption 记录用；cmp 节点自身 id 未传入，
/// 用 op + 两个操作数拼同形文本）。
fn render_cmp(view: &impl View, op: &str, a: u32, b: u32) -> String {
    format!("{}({}, {})", op, render_node(view, a), render_node(view, b))
}

/// 自反传递子树闭包（DAG 展开，去重），含自身。
fn subtree(view: &impl View, root: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        out.push(id);
        if let Some(node) = view.node(id) {
            stack.extend(node.child_ids());
        }
    }
    out
}

/// 收集子树的全部 Const 叶子进字典。
fn harvest_consts(view: &impl View, root: u32, dict: &mut BTreeSet<U256>) {
    for id in subtree(view, root) {
        if let Some(Node::Const(word)) = view.node(id) {
            dict.insert(U256::from_be_bytes(word));
        }
    }
}

/// 证据渲染文本的常量收割：`Hit` 只存渲染文本（不存表达式 id），
/// 这里按 0x-hex token 扫文本收常量（只做字典收割，不做 guard 求解）。
fn harvest_evidence_consts(evidence: &str, dict: &mut BTreeSet<U256>) {
    for token in evidence.split(|c: char| !(c.is_ascii_hexdigit() || c == 'x')) {
        let Some(hex) = token.strip_prefix("0x") else {
            continue;
        };
        if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Ok(v) = U256::from_str_radix(hex, 16) {
            dict.insert(v);
        }
    }
}

/// 字节码 PUSH 立即数扫描（PUSH1..PUSH32，右对齐成字）。
fn push_immediates(code: &[u8], dict: &mut BTreeSet<U256>) {
    let mut i = 0;
    while i < code.len() {
        let byte = code[i];
        if (0x60..=0x7f).contains(&byte) {
            let n = usize::from(byte - 0x5f);
            let end = (i + 1 + n).min(code.len());
            let mut word = [0u8; 32];
            let imm = &code[i + 1..end];
            word[32 - imm.len()..].copy_from_slice(imm);
            dict.insert(U256::from_be_bytes(word));
            i = end;
        } else {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// 组装：约束 → 种子集
// ---------------------------------------------------------------------------

/// 以 selector + 默认零参为基座，各可解约束合取进基座；边界值各生成
/// 一个变体。去重、字典序截断到 [`MAX_SEEDS`]。
fn assemble(target: &dyn HitView, solved: &Solved) -> (Vec<Input>, Option<String>) {
    let head_len = solved
        .fixes
        .keys()
        .chain(solved.boundaries.iter().map(|(slot, _)| slot))
        .max()
        .map_or(0, |max| max + 1);

    let base_words = |overrides: &BTreeMap<usize, U256>| {
        let mut head = vec![[0u8; 32]; head_len];
        for (slot, word) in &solved.fixes {
            head[*slot] = *word;
        }
        for (slot, v) in overrides {
            head[*slot] = v.to_be_bytes::<32>();
        }
        head
    };

    let mut variants: Vec<BTreeMap<usize, U256>> = vec![BTreeMap::new()];
    let mut seen_boundary = BTreeSet::new();
    for (slot, v) in &solved.boundaries {
        if seen_boundary.insert((*slot, *v)) {
            variants.push(BTreeMap::from([(*slot, *v)]));
        }
    }

    let caller = solved.caller.unwrap_or([0u8; 20]);
    let inputs: Vec<Input> = variants
        .iter()
        .map(|overrides| Input {
            selector: target.selector(),
            caller,
            value: U256::ZERO,
            head: base_words(overrides),
            tail: Tail::Empty,
        })
        .collect();

    // 去重 + 字典序。
    let mut keyed: BTreeMap<Vec<u8>, Input> = BTreeMap::new();
    for input in inputs {
        keyed.insert(input.sort_key(), input);
    }
    let total = keyed.len();
    let truncated = total > MAX_SEEDS;
    let inputs: Vec<Input> = keyed.into_values().take(MAX_SEEDS).collect();
    let note = truncated.then(|| {
        format!("种子变体数 {total} 超上限 {MAX_SEEDS}，按字典序截断，未收录变体留搜索空间")
    });
    (inputs, note)
}

// ---------------------------------------------------------------------------
// 公开入口
// ---------------------------------------------------------------------------

/// seed 编译：支配 guard 结构化反解为 [`SeedOutput`]。静态知道的一切
/// 进场时就带着；不可解形态全部如实记 assumptions（落盘进 fuzz_report）。
pub fn compile(shard: &Shard, xlayer: &Xlayer<'_>, code: &[u8], target: &Target<'_>) -> SeedOutput {
    let entries = xlayer.expand(target.func).unwrap_or(&[]);
    let steps = hit_steps(entries, target.hit.target_pcs());
    let guards = dominating_guards(shard, xlayer, entries, &steps);

    let mut solved = Solved {
        fixes: BTreeMap::new(),
        caller: None,
        boundaries: Vec::new(),
        dict: BTreeSet::new(),
        free: Vec::new(),
        assumptions: Vec::new(),
        solvable: false,
    };

    for guard in &guards {
        // 值字典：全部支配 guard 的 Const 叶子。
        harvest_consts(xlayer, guard.cond, &mut solved.dict);
        // 逐比较节点求解（布尔连接词结构忽略，各比较独立）。
        for id in subtree(xlayer, guard.cond) {
            // 经 View 取规范化节点（xlayer.node 是未规范化的原始节点）。
            let Some(Node::Named(op, children)) = View::node(xlayer, id) else {
                continue;
            };
            if children.len() != 2 || !is_cmp_op(&op) {
                continue;
            }
            solve_cmp(
                xlayer,
                &op,
                children[0],
                children[1],
                guard.polarity,
                guard.pc,
                &mut solved,
            );
        }
    }

    // 值字典：证据常量（文本收割）+ 字节码 PUSH 立即数。
    harvest_evidence_consts(target.hit.evidence(), &mut solved.dict);
    push_immediates(code, &mut solved.dict);

    if !solved.solvable {
        solved.assume(
            "无 guard 可解：种子退化为 selector + 全零 head + Empty tail（如实，不编造）"
                .to_string(),
        );
    }

    let (inputs, truncation) = assemble(target.hit, &solved);
    if let Some(note) = truncation {
        solved.assume(note);
    }

    SeedOutput {
        inputs,
        dict: ValueDictionary {
            words: solved.dict.into_iter().collect(),
        },
        free: solved.free,
        assumptions: solved.assumptions,
    }
}

/// cmp 节点判定：`ExprNode::Cmp` 拼装的比较算子（二元、算子在
/// 比较/等值家族）。xlayer 不保留 Cmp/Binary 区分，按算子名认。
fn is_cmp_op(op: &str) -> bool {
    op == "==" || op == "!=" || BOUNDARY_OPS.contains(&op)
}

// ---------------------------------------------------------------------------
// 单测：手工节点表上钉求解规则的关键分支（与 cli detect.rs 测试同构）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::View;

    /// 手工节点表测试视图：下标即节点 id。
    struct MapView(Vec<Node>);

    impl View for MapView {
        fn node(&self, id: u32) -> Option<Node> {
            self.0.get(id as usize).cloned()
        }
    }

    fn word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn addr_word(hex20: u64) -> [u8; 32] {
        word(hex20) // 低 20 字节即地址（高 12 字节为 0）
    }

    fn solved() -> Solved {
        Solved {
            fixes: BTreeMap::new(),
            caller: None,
            boundaries: Vec::new(),
            dict: BTreeSet::new(),
            free: Vec::new(),
            assumptions: Vec::new(),
            solvable: false,
        }
    }

    #[test]
    fn calldata_eq_const_fixes_slot() {
        // 2: ==(calldata_word(0x44), 0x42) → 槽 (0x44-4)/32 = 2。
        let view = MapView(vec![
            Node::CalldataWord(0x44),
            Node::Const(word(0x42)),
            Node::Named("==".into(), vec![0, 1]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 0, 1, true, 278, &mut out);
        assert_eq!(out.fixes.get(&2), Some(&word(0x42)));
        assert!(out.solvable);
        assert!(out.assumptions.is_empty());
    }

    #[test]
    fn calldata_unaligned_records_assumption() {
        // off=0x24 是合法槽 1；off=0x25 非对齐。
        let view = MapView(vec![
            Node::CalldataWord(0x25),
            Node::Const(word(1)),
            Node::Named("==".into(), vec![0, 1]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 0, 1, true, 9, &mut out);
        assert!(out.fixes.is_empty());
        assert!(out.assumptions.iter().any(|a| a.contains("非 32 字节对齐")));
    }

    #[test]
    fn calldata_below_selector_region_records_assumption() {
        let view = MapView(vec![
            Node::CalldataWord(0x0),
            Node::Const(word(1)),
            Node::Named("==".into(), vec![0, 1]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 0, 1, true, 9, &mut out);
        assert!(out.assumptions.iter().any(|a| a.contains("selector 区")));
    }

    #[test]
    fn cast_wrapped_calldata_fixes_with_width_check() {
        // cast160(calldata_word(0x4)) == a：a 超 160 位 → assumption；
        // 合法地址 → 落槽 0。
        let view = MapView(vec![
            Node::CalldataWord(0x4),        // 0
            Node::Cast(0, 160),             // 1
            Node::Const(addr_word(0xbeef)), // 2
            Node::Named("==".into(), vec![1, 2]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 1, 2, true, 9, &mut out);
        assert_eq!(out.fixes.get(&0), Some(&addr_word(0xbeef)));

        let view = MapView(vec![
            Node::CalldataWord(0x4), // 0
            Node::Cast(0, 160),      // 1
            Node::Const((U256::from(1u64) << U256::from(160u64)).to_be_bytes::<32>()), // 2：超 160 位
            Node::Named("==".into(), vec![1, 2]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 1, 2, true, 9, &mut out);
        assert!(out.fixes.is_empty());
        assert!(out.assumptions.iter().any(|a| a.contains("超出截断位宽")));
    }

    #[test]
    fn sender_and_this_eq_const_fix_caller() {
        for leaf in ["msg.sender", "this"] {
            let view = MapView(vec![
                Node::Named(leaf.into(), vec![]),
                Node::Const(addr_word(0xaa)),
                Node::Named("==".into(), vec![0, 1]),
            ]);
            let mut out = solved();
            solve_cmp(&view, "==", 0, 1, true, 9, &mut out);
            let mut want = [0u8; 20];
            want[18..].copy_from_slice(&0xaau16.to_be_bytes());
            assert_eq!(out.caller, Some(want), "leaf={leaf}");
        }
    }

    #[test]
    fn storage_const_slot_eq_const_marks_free() {
        // ==(storage(this, 0x5), 0x99)：FreeVar + assumption，不进 fixes。
        let view = MapView(vec![
            Node::Named("this".into(), vec![]),        // 0
            Node::Const(word(0x5)),                    // 1
            Node::Named("storage".into(), vec![0, 1]), // 2
            Node::Const(word(0x99)),                   // 3
            Node::Named("==".into(), vec![2, 3]),      // 4
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 2, 3, true, 7, &mut out);
        assert_eq!(out.free.len(), 1);
        assert_eq!(out.free[0].hint, Some(U256::from(0x99u64)));
        assert!(out.free[0].what.contains("slot 0x5"));
        assert!(out.assumptions.iter().any(|a| a.contains("标 free")));
        assert!(!out.solvable);
    }

    #[test]
    fn registry_member_test_records_assumption() {
        // !=(storage(this, mapping(entry.world, cast160(calldata_word(0x4)))), 0)
        let view = MapView(vec![
            Node::Named("this".into(), vec![]),        // 0
            Node::Named("entry.world".into(), vec![]), // 1
            Node::CalldataWord(0x4),                   // 2
            Node::Cast(2, 160),                        // 3
            Node::Named("mapping".into(), vec![1, 3]), // 4
            Node::Named("storage".into(), vec![0, 4]), // 5
            Node::Const(word(0)),                      // 6
            Node::Named("!=".into(), vec![5, 6]),      // 7
        ]);
        let mut out = solved();
        solve_cmp(&view, "!=", 5, 6, true, 278, &mut out);
        assert!(out
            .assumptions
            .iter()
            .any(|a| a.contains("registry 成员测试")));
    }

    #[test]
    fn boundary_family_collects_neighbors_and_variants() {
        // <(calldata_word(0x24), 0x3e8) → 字典 {999,1000,1001}，变体槽 1。
        let view = MapView(vec![
            Node::CalldataWord(0x24),            // 0
            Node::Const(word(1000)),             // 1
            Node::Named("<".into(), vec![0, 1]), // 2
        ]);
        let mut out = solved();
        solve_cmp(&view, "<", 0, 1, true, 5, &mut out);
        for v in [999u64, 1000, 1001] {
            assert!(out.dict.contains(&U256::from(v)), "dict 缺 {v}");
        }
        assert_eq!(out.boundaries.len(), 3);
        assert!(out.boundaries.iter().all(|(slot, _)| *slot == 1));
        assert!(out.solvable);

        // 镜像形态：Const 在左，s< 家族同样收。
        let view = MapView(vec![
            Node::Const(word(7)),                 // 0
            Node::CalldataWord(0x4),              // 1
            Node::Named("s>".into(), vec![0, 1]), // 2
        ]);
        let mut out = solved();
        solve_cmp(&view, "s>", 0, 1, true, 5, &mut out);
        for v in [6u64, 7, 8] {
            assert!(out.dict.contains(&U256::from(v)), "dict 缺 {v}");
        }
        assert!(out.boundaries.iter().all(|(slot, _)| *slot == 0));
    }

    #[test]
    fn boundary_clamps_to_u256_range() {
        // c = 0：c-1 截断回 0（去重后字典 {0,1}）；c = MAX：c+1 截断回 MAX。
        let view = MapView(vec![
            Node::CalldataWord(0x4),
            Node::Const(word(0)),
            Node::Named("<".into(), vec![0, 1]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "<", 0, 1, true, 5, &mut out);
        assert_eq!(out.dict.len(), 2);
        assert!(out.dict.contains(&U256::ZERO));
        assert!(out.dict.contains(&U256::from(1u64)));

        let view = MapView(vec![
            Node::CalldataWord(0x4),
            Node::Const([0xff; 32]),
            Node::Named("<".into(), vec![0, 1]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "<", 0, 1, true, 5, &mut out);
        assert!(out.dict.contains(&U256::MAX));
        assert!(out.dict.contains(&(U256::MAX - U256::from(1u64))));
    }

    #[test]
    fn false_polarity_eq_not_solved() {
        let view = MapView(vec![
            Node::CalldataWord(0x4),
            Node::Const(word(1)),
            Node::Named("==".into(), vec![0, 1]),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 0, 1, false, 9, &mut out);
        assert!(out.fixes.is_empty());
        assert!(out.assumptions.iter().any(|a| a.contains("假支等值约束")));
    }

    #[test]
    fn conflicting_slot_fixes_record_assumption() {
        let view = MapView(vec![
            Node::CalldataWord(0x4),
            Node::Const(word(1)),
            Node::Const(word(2)),
        ]);
        let mut out = solved();
        solve_cmp(&view, "==", 0, 1, true, 9, &mut out);
        solve_cmp(&view, "==", 0, 2, true, 10, &mut out);
        assert_eq!(out.fixes.get(&0), Some(&word(1)), "先收先生效");
        assert!(out.assumptions.iter().any(|a| a.contains("等值冲突")));
    }

    #[test]
    fn assemble_truncates_to_max_seeds() {
        let target = FakeHit {
            selector: 0xdeadbeef,
        };
        let mut out = solved();
        // 30 个边界约束 × 3 变体 + 基座 = 91 > 64。
        for i in 0..30u64 {
            out.boundaries.push((i as usize, U256::from(1000u64 + i)));
            out.boundaries.push((i as usize, U256::from(2000u64 + i)));
            out.boundaries.push((i as usize, U256::from(3000u64 + i)));
        }
        let (inputs, note) = assemble(&target, &out);
        assert_eq!(inputs.len(), MAX_SEEDS);
        assert!(note.unwrap().contains("按字典序截断"));
    }

    struct FakeHit {
        selector: u32,
    }

    impl HitView for FakeHit {
        fn selector(&self) -> u32 {
            self.selector
        }
        fn target_pcs(&self) -> &[u32] {
            &[]
        }
        fn evidence(&self) -> &str {
            ""
        }
    }

    #[test]
    fn push_immediates_right_aligned() {
        // PUSH1 0x2a PUSH2 0x0102 PUSH32 0xff.. ADD
        let mut code = vec![0x60, 0x2a, 0x61, 0x01, 0x02];
        code.push(0x7f);
        code.extend_from_slice(&[0xff; 32]);
        code.push(0x01);
        let mut dict = BTreeSet::new();
        push_immediates(&code, &mut dict);
        assert!(dict.contains(&U256::from(0x2au64)));
        assert!(dict.contains(&U256::from(0x0102u64)));
        assert!(dict.contains(&U256::from_be_bytes([0xff; 32])));
        // PUSH 数据区里的 0x60/0x7f 不得被误认为操作符：code 里 0xff×32
        // 含 0x60? 不含；再验一个数据区含伪操作符的：
        let code = vec![0x62, 0x60, 0x7f, 0x01];
        let mut dict = BTreeSet::new();
        push_immediates(&code, &mut dict);
        assert_eq!(dict.len(), 1);
        assert!(dict.contains(&U256::from(0x607f01u64)));
    }

    #[test]
    fn harvest_evidence_consts_from_rendered_text() {
        let mut dict = BTreeSet::new();
        harvest_evidence_consts(
            "cast160(calldata_word(0x4)) 与 +(0x20, 0xaa) 及超宽 0xde000000000000000000000000000000000000000000000000000000000000ad",
            &mut dict,
        );
        assert!(dict.contains(&U256::from(0x20u64)));
        assert!(dict.contains(&U256::from(0xaau64)));
        let mut wide = [0u8; 32];
        wide[0] = 0xde;
        wide[31] = 0xad;
        assert!(dict.contains(&U256::from_be_bytes(wide)));
    }
}
