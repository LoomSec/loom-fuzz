//! 证据表达式求值器（issue #19）：在 witness calldata 上求 xlayer
//! 表达式节点的具体值，喂 arbitrary_call 臂 1 oracle 定罪
//!（call.target == cast160(evidence) 的具体 trace 判定）。
//!
//! 覆盖节点子集（其余 ⊥ = None，fail-closed 不猜）：
//!
//! | 节点 | 语义 |
//! |---|---|
//! | `Leaf("this")` | 路由器地址（求值环境注入） |
//! | `Const` / `ConstBytes` | 常量字 / 字节串（右对齐 ≤32B） |
//! | `CalldataWord(off)` | witness calldata[off..off+32] 右对齐（越界补零，同 EVM calldataload） |
//! | `Cast(a, bits)` | 截断低位 bits（bits ≥ 256 恒等） |
//! | `Unary` / `Binary` | 算术/位运算——**复用 xlayer `word` 运算表**（loom-evm 语义照抄的同一实现，非复制） |
//! | `Cmp` | `==`/`!=`/`<`/`>`/`<=`/`>=` 无符号比较 → 0/1 |
//! | `bytes_word(a, i)` | 字节串 a（`b_calldata_slice`/`ConstBytes`）的第 i 个 32B 字，右对齐越界补零 |
//! | `b_calldata_slice(off, len)` | witness calldata[off..off+len]（越界截断） |
//! | `Ternary` | `select`/`ite`/`?:`：c ≠ 0 ? a : b |
//! | `Env` / `Param` / `memory` / `keccak` / `concat` 等其它 `Nary` | ⊥（不猜，M1 再加） |
//!
//! 求值环境：witness 的完整交易 calldata 字节串（selector + head +
//! tail，与 revm TxEnv.data 逐字节一致）+ this 地址。确定性：纯函数。
//! 节点视图是 owned 形态（`OwnedNode`），`Xlayer` 与各 crate 的
//! 手工测试表都能实现 `EvalViewDyn`。

use alloy_primitives::U256;

/// 节点的 owned 形态（求值期间免借用，dyn 可用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedNode {
    Leaf(String),
    Const([u8; 32]),
    ConstBytes(Vec<u8>),
    CalldataWord(u64),
    Env(String),
    Unary(String, u32),
    Binary(String, u32, u32),
    Cmp(String, u32, u32),
    Ternary(String, u32, u32, u32),
    Nary(String, Vec<u32>),
    Cast(u32, u64),
    Param(u32),
}

impl OwnedNode {
    /// 运算名（叶子/环境节点返回名字）。
    pub fn op(&self) -> Option<&str> {
        match self {
            OwnedNode::Leaf(s) | OwnedNode::Env(s) => Some(s),
            OwnedNode::Unary(s, _)
            | OwnedNode::Binary(s, _, _)
            | OwnedNode::Cmp(s, _, _)
            | OwnedNode::Ternary(s, _, _, _)
            | OwnedNode::Nary(s, _) => Some(s),
            _ => None,
        }
    }

    /// 子节点 id（按操作数序）。
    pub fn child_ids(&self) -> Vec<u32> {
        match self {
            OwnedNode::Unary(_, a) | OwnedNode::Cast(a, _) => vec![*a],
            OwnedNode::Binary(_, a, b) | OwnedNode::Cmp(_, a, b) => vec![*a, *b],
            OwnedNode::Ternary(_, a, b, c) => vec![*a, *b, *c],
            OwnedNode::Nary(_, args) => args.clone(),
            _ => Vec::new(),
        }
    }
}

/// 只读节点访问（owned 形态；`Xlayer` 有内建实现）。
pub trait EvalViewDyn {
    fn owned_node(&self, id: u32) -> Option<OwnedNode>;
}

impl EvalViewDyn for loom_fuzz_xlayer::Xlayer<'_> {
    fn owned_node(&self, id: u32) -> Option<OwnedNode> {
        use loom_fuzz_shard::ExprNode as E;
        use loom_fuzz_xlayer::{NodeKey as K, XNode};
        match self.node(id)? {
            XNode::Base(n) => Some(match n {
                E::Leaf(s) => OwnedNode::Leaf(s.clone()),
                E::Const(w) => OwnedNode::Const(*w),
                E::ConstBytes(b) => OwnedNode::ConstBytes(b.clone()),
                E::CalldataWord(off) => OwnedNode::CalldataWord(*off),
                E::Env(s) => OwnedNode::Env(s.clone()),
                E::Unary(op, a) => OwnedNode::Unary(op.clone(), *a),
                E::Binary(op, a, b) => OwnedNode::Binary(op.clone(), *a, *b),
                E::Cmp(op, a, b) => OwnedNode::Cmp(op.clone(), *a, *b),
                E::Ternary(op, a, b, c) => OwnedNode::Ternary(op.clone(), *a, *b, *c),
                E::Nary(op, args) => OwnedNode::Nary(op.clone(), args.clone()),
                E::Cast(a, bits) => OwnedNode::Cast(*a, *bits),
                E::Param(p) => OwnedNode::Param(*p),
            }),
            XNode::Overlay(k) => Some(match k {
                K::Leaf(s) => OwnedNode::Leaf(s.clone()),
                K::Const(w) => OwnedNode::Const(*w),
                K::ConstBytes(b) => OwnedNode::ConstBytes(b.clone()),
                K::CalldataWord(off) => OwnedNode::CalldataWord(*off),
                K::Env(s) => OwnedNode::Env(s.clone()),
                K::Unary(op, a) => OwnedNode::Unary(op.clone(), *a),
                K::Binary(op, a, b) => OwnedNode::Binary(op.clone(), *a, *b),
                K::Cmp(op, a, b) => OwnedNode::Cmp(op.clone(), *a, *b),
                K::Ternary(op, a, b, c) => OwnedNode::Ternary(op.clone(), *a, *b, *c),
                K::Nary(op, args) => OwnedNode::Nary(op.clone(), args.clone()),
                K::Cast(a, bits) => OwnedNode::Cast(*a, *bits),
                K::Param(p) => OwnedNode::Param(*p),
            }),
        }
    }
}

/// 求值环境：witness calldata + this。
pub struct EvalEnv {
    pub calldata: Vec<u8>,
    pub this: U256,
}

impl EvalEnv {
    pub fn new(calldata: Vec<u8>, this: U256) -> Self {
        EvalEnv { calldata, this }
    }
}

/// calldataload 语义：calldata[off..off+32] 右对齐，越界补零。
fn calldata_word(calldata: &[u8], off: u64) -> U256 {
    let off = off as usize;
    let mut word = [0u8; 32];
    if off < calldata.len() {
        let n = (calldata.len() - off).min(32);
        word[32 - n..].copy_from_slice(&calldata[off..off + n]);
    }
    U256::from_be_bytes(word)
}

/// 字节串求值（b_calldata_slice / ConstBytes）；非字节节点 ⊥。
fn eval_bytes(view: &dyn EvalViewDyn, id: u32, env: &EvalEnv) -> Option<Vec<u8>> {
    match view.owned_node(id)? {
        OwnedNode::ConstBytes(b) => Some(b),
        OwnedNode::Nary(op, args) => {
            if op != "b_calldata_slice" || args.len() != 2 {
                return None;
            }
            let off = eval_word(view, args[0], env)?;
            let len = eval_word(view, args[1], env)?;
            let (off, len) = (u64::try_from(off).ok()?, u64::try_from(len).ok()?);
            let start = off as usize;
            if start >= env.calldata.len() {
                return Some(Vec::new());
            }
            let end = start.saturating_add(len as usize).min(env.calldata.len());
            Some(env.calldata[start..end].to_vec())
        }
        _ => None,
    }
}

/// 字求值：主入口。⊥ = None（fail-closed 不猜）。
pub fn eval_word(view: &dyn EvalViewDyn, id: u32, env: &EvalEnv) -> Option<U256> {
    use loom_fuzz_xlayer::word::{apply_binary_op, apply_unary_op, Word};
    let word = |w: Word| U256::from_be_bytes(w.0);
    match view.owned_node(id)? {
        OwnedNode::Leaf(name) => (name == "this").then_some(env.this),
        OwnedNode::Const(w) => Some(U256::from_be_bytes(w)),
        OwnedNode::ConstBytes(b) => (b.len() <= 32).then(|| {
            let mut w = [0u8; 32];
            w[32 - b.len()..].copy_from_slice(&b);
            U256::from_be_bytes(w)
        }),
        OwnedNode::CalldataWord(off) => Some(calldata_word(&env.calldata, off)),
        OwnedNode::Cast(a, bits) => {
            let v = eval_word(view, a, env)?;
            if bits >= 256 {
                Some(v)
            } else {
                let mask = (U256::from(1u64) << bits) - U256::from(1u64);
                Some(v & mask)
            }
        }
        OwnedNode::Unary(op, a) => {
            let x = eval_word(view, a, env)?;
            apply_unary_op(&op, Word(x.to_be_bytes())).map(word)
        }
        OwnedNode::Binary(op, a, b) => {
            let x = eval_word(view, a, env)?;
            let y = eval_word(view, b, env)?;
            apply_binary_op(&op, Word(x.to_be_bytes()), Word(y.to_be_bytes())).map(word)
        }
        OwnedNode::Cmp(op, a, b) => {
            let x = eval_word(view, a, env)?;
            let y = eval_word(view, b, env)?;
            let holds = match op.as_str() {
                "==" => Some(x == y),
                "!=" => Some(x != y),
                "<" => Some(x < y),
                ">" => Some(x > y),
                "<=" => Some(x <= y),
                ">=" => Some(x >= y),
                _ => None,
            }?;
            Some(U256::from(holds as u64))
        }
        OwnedNode::Ternary(op, c, a, b) => {
            if !matches!(op.as_str(), "select" | "ite" | "?:") {
                return None;
            }
            let cond = eval_word(view, c, env)?;
            eval_word(view, if cond.is_zero() { b } else { a }, env)
        }
        OwnedNode::Nary(op, args) => {
            if op != "bytes_word" || args.len() != 2 {
                return None; // keccak / concat / 其它 Nary：⊥（M1 再加）。
            }
            let bytes = eval_bytes(view, args[0], env)?;
            let idx = eval_word(view, args[1], env)?;
            let idx = usize::try_from(idx).ok()?;
            let start = idx.checked_mul(32)?;
            let mut w = [0u8; 32];
            for (i, slot) in w.iter_mut().enumerate() {
                if let Some(b) = bytes.get(start + i) {
                    *slot = *b;
                }
            }
            Some(U256::from_be_bytes(w))
        }
        // Env / Param / 未覆盖形态：⊥。
        _ => None,
    }
}

/// evidence 子树是否含某算子（family 的形状启发用）。
pub fn subtree_has_op(view: &dyn EvalViewDyn, root: u32, op: &str) -> Option<bool> {
    let mut stack = vec![root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = view.owned_node(id)?;
        if node.op() == Some(op) {
            return Some(true);
        }
        stack.extend(node.child_ids());
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工节点表测试视图：下标即节点 id。
    struct MapView(Vec<OwnedNode>);

    impl EvalViewDyn for MapView {
        fn owned_node(&self, id: u32) -> Option<OwnedNode> {
            self.0.get(id as usize).cloned()
        }
    }

    fn word(v: u64) -> [u8; 32] {
        U256::from(v).to_be_bytes::<32>()
    }

    fn env() -> EvalEnv {
        // calldata = 0xdeadbeef + 32×0xaa + "hello world"（4+32+11）。
        let mut cd = vec![0xde, 0xad, 0xbe, 0xef];
        cd.extend_from_slice(&[0xaau8; 32]);
        cd.extend_from_slice(b"hello world");
        EvalEnv::new(cd, U256::from(0x22u64))
    }

    #[test]
    fn const_and_this() {
        let view = MapView(vec![
            OwnedNode::Const(word(0x42)),
            OwnedNode::Leaf("this".into()),
            OwnedNode::Leaf("msg.sender".into()),
        ]);
        let env = env();
        assert_eq!(eval_word(&view, 0, &env), Some(U256::from(0x42u64)));
        assert_eq!(eval_word(&view, 1, &env), Some(U256::from(0x22u64)));
        assert_eq!(eval_word(&view, 2, &env), None, "非 this 叶子 ⊥");
    }

    #[test]
    fn env_param_and_memory_are_bottom() {
        let view = MapView(vec![
            OwnedNode::Env("msg.value".into()),
            OwnedNode::Param(0),
            OwnedNode::Nary("memory".into(), vec![0, 1]),
            OwnedNode::Nary("keccak".into(), vec![0]),
        ]);
        let env = env();
        for id in 0..4 {
            assert_eq!(eval_word(&view, id, &env), None, "id={id} 应 ⊥");
        }
    }

    #[test]
    fn calldata_word_right_aligned_and_zero_padded() {
        let view = MapView(vec![
            OwnedNode::CalldataWord(0),
            OwnedNode::CalldataWord(4),
            OwnedNode::CalldataWord(36), // 只有 11 字节尾巴
            OwnedNode::CalldataWord(1000),
        ]);
        let env = env();
        // 字 0 = calldata[0..32] = deadbeef + 28×0xaa。
        let mut w0 = [0xaau8; 32];
        w0[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(eval_word(&view, 0, &env), Some(U256::from_be_bytes(w0)));
        assert_eq!(
            eval_word(&view, 1, &env),
            Some(U256::from_be_bytes([0xaau8; 32]))
        );
        let v = eval_word(&view, 2, &env).unwrap();
        assert_eq!(
            v,
            U256::from_be_bytes({
                let mut w = [0u8; 32];
                w[21..].copy_from_slice(b"hello world");
                w
            })
        );
        assert_eq!(eval_word(&view, 3, &env), Some(U256::ZERO));
    }

    #[test]
    fn arithmetic_uses_xlayer_word_table() {
        // +(0x10, *(0x3, 0x4)) = 0x1c；-(0x10, 0x4) = 0xc；&(0x10, 0x4) = 0。
        let view = MapView(vec![
            OwnedNode::Const(word(0x10)),        // 0
            OwnedNode::Const(word(0x3)),         // 1
            OwnedNode::Const(word(0x4)),         // 2
            OwnedNode::Binary("*".into(), 1, 2), // 3
            OwnedNode::Binary("+".into(), 0, 3), // 4
            OwnedNode::Binary("-".into(), 0, 2), // 5
            OwnedNode::Binary("&".into(), 0, 2), // 6
        ]);
        let env = env();
        assert_eq!(eval_word(&view, 4, &env), Some(U256::from(0x1cu64)));
        assert_eq!(eval_word(&view, 5, &env), Some(U256::from(0xcu64)));
        assert_eq!(eval_word(&view, 6, &env), Some(U256::from(0u64)));
    }

    #[test]
    fn cast_truncates() {
        let full = [0xffu8; 32];
        let view = MapView(vec![
            OwnedNode::Const(full),  // 0
            OwnedNode::Cast(0, 160), // 1
            OwnedNode::Cast(0, 256), // 2：恒等
            OwnedNode::Cast(0, 0),   // 3：归零
        ]);
        let env = env();
        let low160 = U256::from_be_bytes(full) & ((U256::from(1u64) << 160) - U256::from(1u64));
        assert_eq!(eval_word(&view, 1, &env), Some(low160));
        assert_eq!(eval_word(&view, 2, &env), Some(U256::from_be_bytes(full)));
        assert_eq!(eval_word(&view, 3, &env), Some(U256::ZERO));
    }

    #[test]
    fn cmp_returns_zero_one() {
        let view = MapView(vec![
            OwnedNode::Const(word(5)),         // 0
            OwnedNode::Const(word(9)),         // 1
            OwnedNode::Cmp("<".into(), 0, 1),  // 2
            OwnedNode::Cmp(">".into(), 0, 1),  // 3
            OwnedNode::Cmp("==".into(), 0, 0), // 4
            OwnedNode::Cmp("s<".into(), 0, 1), // 5：未覆盖算子 ⊥
        ]);
        let env = env();
        assert_eq!(eval_word(&view, 2, &env), Some(U256::from(1u64)));
        assert_eq!(eval_word(&view, 3, &env), Some(U256::from(0u64)));
        assert_eq!(eval_word(&view, 4, &env), Some(U256::from(1u64)));
        assert_eq!(eval_word(&view, 5, &env), None);
    }

    #[test]
    fn slice_and_bytes_word() {
        // 32B 窗口：bytes_word(b_calldata_slice(4, 32), 0) ≡
        // CalldataWord(4)（xlayer 常量折叠的同源语义）。
        let view = MapView(vec![
            OwnedNode::Const(word(4)),                              // 0
            OwnedNode::Const(word(32)),                             // 1
            OwnedNode::Nary("b_calldata_slice".into(), vec![0, 1]), // 2
            OwnedNode::Const(word(0)),                              // 3
            OwnedNode::Nary("bytes_word".into(), vec![2, 3]),       // 4
        ]);
        let env = env();
        assert_eq!(
            eval_word(&view, 4, &env),
            Some(U256::from_be_bytes([0xaau8; 32]))
        );
        // 短窗口：窗口[start..start+32] 零填充在尾部（数据居高位）——
        // 与 CalldataWord 的右对齐不同源，按窗口读语义钉死。
        // calldata[36..47] = "hello world"（4 + 32 之后）。
        let view2 = MapView(vec![
            OwnedNode::Const(word(36)),                             // 0
            OwnedNode::Const(word(11)),                             // 1
            OwnedNode::Nary("b_calldata_slice".into(), vec![0, 1]), // 2
            OwnedNode::Const(word(0)),                              // 3
            OwnedNode::Nary("bytes_word".into(), vec![2, 3]),       // 4
        ]);
        let mut expect = [0u8; 32];
        expect[..11].copy_from_slice(b"hello world");
        assert_eq!(
            eval_word(&view2, 4, &env),
            Some(U256::from_be_bytes(expect))
        );
        assert_eq!(subtree_has_op(&view2, 4, "b_calldata_slice"), Some(true));
        assert_eq!(subtree_has_op(&view2, 4, "keccak"), Some(false));
    }

    #[test]
    fn ternary_select() {
        let view = MapView(vec![
            OwnedNode::Const(word(1)),                    // 0
            OwnedNode::Const(word(0xaaaa)),               // 1
            OwnedNode::Const(word(0xbbbb)),               // 2
            OwnedNode::Ternary("select".into(), 0, 1, 2), // 3
            OwnedNode::Ternary("cond".into(), 0, 1, 2),   // 4：非 select/ite ⊥
        ]);
        let env = env();
        assert_eq!(eval_word(&view, 3, &env), Some(U256::from(0xaaaau64)));
        assert_eq!(eval_word(&view, 4, &env), None);
    }
}
