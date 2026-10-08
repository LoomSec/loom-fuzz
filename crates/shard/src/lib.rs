//! loom-evm shard（.lst）文件的独立读取器。
//!
//! 只依赖文件格式（见仓库 `docs/shard-format.md`），不依赖 loom-evm 代码。
//! M0 暴露的只读视图：函数表（selector → 函数）、表达式字典
//! （loom IR 表达式树）、每函数的事实流条目（guard / effect / outcome /
//! apply / exit，含 kind、pc 与 x-layer 步序），以及作用域/定义/may-summary。

use std::fmt;
use std::path::Path;

// ---------------------------------------------------------------------------
// 错误类型
// ---------------------------------------------------------------------------

/// shard 解析失败。所有错误都是 typed 的：截断/伪造的输入永远报
/// `Err`，不 panic。
#[derive(Debug)]
pub enum Error {
    /// 文件系统层面打不开/读不到。
    Io(std::io::Error),
    /// 魔数不是 `LST`。
    BadMagic,
    /// 声明的计数/长度与剩余字节不成比例（防伪造 count 造成的巨分配）。
    CountOutOfRange,
    /// 段目录指向文件范围之外。
    SegmentOutOfRange,
    /// 未知的段压缩编码。
    UnknownCodec(u32),
    /// zlib 段解压失败或与声明的解压长度不符。
    CorruptCompression,
    /// 结构引用越界（表达式子节点 / 字符串 id / code_id 下标 / 作用域）。
    BadReference(&'static str),
    /// 作用域 parent 链成环或自指。
    ScopeCycle,
    /// DIGEST 段的 manifest 计数与解析出的流不一致。
    ManifestMismatch,
    /// 非 utf8 字符串。
    BadUtf8,
    /// 结构哈希尾长度与节点数不符。
    HashTailMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "shard io: {e}"),
            Error::BadMagic => write!(f, "bad shard magic (expected LST)"),
            Error::CountOutOfRange => write!(f, "declared count out of range"),
            Error::SegmentOutOfRange => write!(f, "segment out of range"),
            Error::UnknownCodec(c) => write!(f, "unknown segment codec {c}"),
            Error::CorruptCompression => write!(f, "corrupt compressed segment"),
            Error::BadReference(what) => write!(f, "shard reference out of range: {what}"),
            Error::ScopeCycle => write!(f, "scope parent cycle"),
            Error::ManifestMismatch => write!(f, "digest counts disagree with the streams"),
            Error::BadUtf8 => write!(f, "invalid utf-8 in shard"),
            Error::HashTailMismatch => write!(f, "expression hash tail length mismatch"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ---------------------------------------------------------------------------
// 公开模型
// ---------------------------------------------------------------------------

/// DIGEST 段尾部的证书完备性声明（loomstore-design §5.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// 每条入口路由都被证明。
    Complete,
    /// 调用图 chase 丢了配置（认证的欠近似）。
    ChaseSpills(usize),
    /// 部分入口划分：proved 个有证书，uncovered 个未证明准入。
    PartialPartition { proved: usize, uncovered: usize },
    /// 视图在资源限制处截断（格式定义了它，当前写出器不写）。
    ViewTruncated(String),
    /// 有界资源把部分区域降级为保守上近似（marks = 降级标记数）。
    Degraded(usize),
}

/// DIGEST 段的 manifest 计数（与对应段的实际条目数一致性已校验）。
#[derive(Debug, Clone, Copy)]
pub struct Manifest {
    pub nodes: u32,
    pub functions: u32,
    pub definitions: u32,
    pub scopes: u32,
}

/// 表达式字典节点（loom IR）。子节点都是字典内的 id（拓扑序：子先于父，
/// 字典是 DAG）。名称内联为 `String`（词表小）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprNode {
    /// 叶子：具名实体（如 `"this"`、`"entry.world"`、`"msg.sender"`）。
    Leaf(String),
    /// 256 位常量（右对齐 32 字节，写出时已去前导零）。
    Const([u8; 32]),
    /// 原始字节串（calldata 片段等）。
    ConstBytes(Vec<u8>),
    /// calldata 第 `off` 字（32 字节槽）。
    CalldataWord(u64),
    /// 环境读取（op 名见 Leaf 说明）。
    Env(String),
    /// 一元运算。
    Unary(String, u32),
    /// 二元运算（`+`、`*`、`storage`、`mapping`、`.` 等 op 名）。
    Binary(String, u32, u32),
    /// 比较（`==`、`!=`、`<`、`s<` 等）。
    Cmp(String, u32, u32),
    /// 三元（`choice(cond, a, b)` 等）。
    Ternary(String, u32, u32, u32),
    /// N 元（`concat`、`keccak` 等）。
    Nary(String, Vec<u32>),
    /// 位宽截断/类型转换。
    Cast(u32, u64),
    /// 形参槽位（定义体的形式入口）。
    Param(u32),
}

impl ExprNode {
    /// 该节点的运算名（叶子/环境节点返回其名字；Const/ConstBytes/
    /// CalldataWord/Cast/Param 返回 None）。
    pub fn op(&self) -> Option<&str> {
        match self {
            ExprNode::Leaf(s) | ExprNode::Env(s) => Some(s),
            ExprNode::Unary(s, _)
            | ExprNode::Binary(s, _, _)
            | ExprNode::Cmp(s, _, _)
            | ExprNode::Ternary(s, _, _, _)
            | ExprNode::Nary(s, _) => Some(s),
            ExprNode::Const(_) | ExprNode::ConstBytes(_) | ExprNode::CalldataWord(_) => None,
            ExprNode::Cast(_, _) | ExprNode::Param(_) => None,
        }
    }
}

/// Apply/Exit 边携带的实参帧（全部为表达式字典 id，reads 把被调用
/// 定义的形式读节点映射到调用方词汇表上的项）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameArgs {
    pub stack: Vec<u32>,
    pub reached: u16,
    pub returndata_size: u32,
    pub returndata_epoch: u32,
    pub reads: Vec<(u32, u32)>,
}

/// 事实流条目（walk 顺序 = 路由顺序）。`step` 是 x-layer 的效果步序：
/// 只给 Guard/Effect/Outcome 编号、按流顺序递增；Apply/Exit 是控制边，
/// 不占用效果序号（与 `loom facts` JSON 流同源）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// 守卫：cond 是表达式 id；pc 是产生该分支的单字节码方程原点。
    Guard {
        cond: u32,
        polarity: bool,
        scope: u32,
        pc: u32,
        step: u32,
    },
    /// 效果（`"sload"`/`"sstore"`/`"call"`/`"input_read"` 等 kind；
    /// operands 为具名表达式 id）。
    Effect {
        kind: String,
        operands: Vec<(String, u32)>,
        scope: u32,
        pc: u32,
        step: u32,
    },
    /// 结局（`"return"`/`"revert"`/`"stop"`/`"selfdestruct"` 等 class）。
    Outcome {
        class: String,
        data: Option<u32>,
        scope: u32,
        pc: u32,
        step: u32,
    },
    /// 应用一条定义体（内部/共享调用边）。
    Apply {
        definition: u32,
        recur: bool,
        scope: u32,
        instance: Option<u32>,
        args: Option<FrameArgs>,
    },
    /// 跳回形式目标的返回边。
    Exit {
        target: u32,
        scope: u32,
        pc: u32,
        args: FrameArgs,
    },
}

impl Entry {
    /// 条目的 scope id（0 = 根；非 0 对应作用域表下标 id-1）。
    pub fn scope(&self) -> u32 {
        match self {
            Entry::Guard { scope, .. }
            | Entry::Effect { scope, .. }
            | Entry::Outcome { scope, .. }
            | Entry::Apply { scope, .. }
            | Entry::Exit { scope, .. } => *scope,
        }
    }

    /// x-layer 效果步序（Guard/Effect/Outcome 才有；控制边返回 None）。
    pub fn step(&self) -> Option<u32> {
        match self {
            Entry::Guard { step, .. }
            | Entry::Effect { step, .. }
            | Entry::Outcome { step, .. } => Some(*step),
            Entry::Apply { .. } | Entry::Exit { .. } => None,
        }
    }

    /// 条目的原点 pc（Apply 无 pc，返回 None）。
    pub fn pc(&self) -> Option<u32> {
        match self {
            Entry::Guard { pc, .. }
            | Entry::Effect { pc, .. }
            | Entry::Outcome { pc, .. }
            | Entry::Exit { pc, .. } => Some(*pc),
            Entry::Apply { .. } => None,
        }
    }
}

/// 一个函数的事实流容器。
#[derive(Debug, Clone)]
pub struct Function {
    /// `"function"` / `"fallback"` / `"receive"` 等。
    pub kind: String,
    /// 4 字节函数选择子；fallback/无名入口为 None。
    pub selector: Option<u32>,
    pub name: Option<String>,
    /// 事实流条目（路由顺序）。
    pub entries: Vec<Entry>,
}

impl Function {
    /// 该函数的效果条目（含步序、kind、pc）。
    pub fn effects(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|e| matches!(e, Entry::Effect { .. }))
    }

    /// 该函数的守卫条目。
    pub fn guards(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|e| matches!(e, Entry::Guard { .. }))
    }
}

/// 共享定义体（内部函数/蹦床定义）。
#[derive(Debug, Clone)]
pub struct Definition {
    pub pc: u32,
    pub code_id: u32,
    /// 形式变体的入口高度（None = v1 具体定义）。
    pub height: Option<u32>,
    pub entries: Vec<Entry>,
}

/// 作用域（id 从 1 开始；`scopes[id - 1]`）。
#[derive(Debug, Clone, Copy)]
pub struct Scope {
    pub parent: u32,
    /// 守卫条件表达式 id。
    pub guard: u32,
    pub polarity: bool,
}

/// 调用目标分类（may-summary）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallTarget {
    /// 常量地址（aux = 表达式 id）。
    Const(u32),
    /// 存储槽派生（代理实现；aux = 表达式 id）。
    Slot(u32),
    /// 真正动态（aux = 表达式 id）。
    Dynamic(u32),
}

/// may-summary（SUMM 段）：预筛用的"可能"关系。
#[derive(Debug, Clone, Default)]
pub struct Summaries {
    /// (func, slot expr)：sload 读过。
    pub reads_s: Vec<(u32, u32)>,
    /// (func, slot expr)：sstore 写过。
    pub writes_s: Vec<(u32, u32)>,
    /// (func, slot expr)：call 可能先于该槽的 sstore（CEI 窗口）。
    pub cbw_s: Vec<(u32, u32)>,
    /// (func, slot expr)：return 数据提及该槽的读。
    pub retdep_s: Vec<(u32, u32)>,
    /// (func, call target)。
    pub calls_s: Vec<(u32, CallTarget)>,
    /// 效果种类位图（bit 定义见 docs/shard-format.md §8）；旧分片为 None。
    pub kinds: Option<u64>,
}

// ---------------------------------------------------------------------------
// shard 本体
// ---------------------------------------------------------------------------

/// 一个解析完成的 shard：表达式字典 + 函数/定义事实流 + 作用域 +
/// may-summary。全部字段只读访问。
#[derive(Debug)]
pub struct Shard {
    /// 语义 digest（合约标识，hex 无前缀）。
    pub digest: String,
    /// 认证欠近似的 spill 计数。
    pub chase_spills: Option<usize>,
    pub coverage: Coverage,
    pub unresolved_control: Option<usize>,
    pub manifest: Manifest,
    /// 每个表达式节点的结构哈希（keccak-256，与字典同序）。
    pub hashes: Vec<[u8; 32]>,
    strings: Vec<String>,
    exprs: Vec<ExprNode>,
    functions: Vec<Function>,
    definitions: Vec<Definition>,
    scopes: Vec<Scope>,
    summaries: Summaries,
}

impl Shard {
    /// 解析整个 shard 文件。
    pub fn open(path: impl AsRef<Path>) -> Result<Shard, Error> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// 从内存字节解析（`open` 的底层入口）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Shard, Error> {
        reader::parse(bytes)
    }

    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    pub fn exprs(&self) -> &[ExprNode] {
        &self.exprs
    }

    /// 表达式字典下标访问（越界 panic——解析期已校验全部子引用，
    /// 字典本身的访问由调用者保证）。
    pub fn expr(&self, id: u32) -> Option<&ExprNode> {
        self.exprs.get(id as usize)
    }

    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// selector（4 字节选择子，如 0xe27fbed3）→ 函数。无 selector 的
    /// fallback/receive 不在此索引内。
    pub fn function_by_selector(&self, selector: u32) -> Option<&Function> {
        self.functions
            .iter()
            .find(|f| f.selector == Some(selector))
    }

    pub fn definitions(&self) -> &[Definition] {
        &self.definitions
    }

    /// 作用域表（id 从 1 开始；`scopes[id - 1]` 才是 id 的作用域）。
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn summaries(&self) -> &Summaries {
        &self.summaries
    }
}

// ---------------------------------------------------------------------------
// 二进制读取
// ---------------------------------------------------------------------------

mod reader {
    use super::*;

    const MAGIC: &[u8; 3] = b"LST";

    mod seg {
        pub const DIGEST: u32 = 1;
        pub const STRS: u32 = 2;
        pub const EXPR: u32 = 3;
        pub const FUNC: u32 = 4;
        pub const DEFS: u32 = 5;
        pub const SCOPE: u32 = 6;
        pub const SUMM: u32 = 7;
    }

    mod codec {
        pub const RAW: u32 = 0;
        pub const ZLIB: u32 = 1;
    }

    /// 字节游标：所有读取 bounds-checked；count 在分配前按最小条目
    /// 字节数校验（防伪造 count → 巨分配）。
    pub(crate) struct Cursor<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Cursor<'a> {
        pub(crate) fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, pos: 0 }
        }

        pub(crate) fn remaining(&self) -> usize {
            self.bytes.len() - self.pos
        }

        pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
            let end = self
                .pos
                .checked_add(n)
                .filter(|end| *end <= self.bytes.len())
                .ok_or(Error::CountOutOfRange)?;
            let slice = &self.bytes[self.pos..end];
            self.pos = end;
            Ok(slice)
        }

        pub(crate) fn u8(&mut self) -> Result<u8, Error> {
            Ok(self.take(1)?[0])
        }

        pub(crate) fn u16(&mut self) -> Result<u16, Error> {
            Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
        }

        pub(crate) fn u32(&mut self) -> Result<u32, Error> {
            Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
        }

        pub(crate) fn u64(&mut self) -> Result<u64, Error> {
            Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
        }

        /// 无符号 LEB128，至多 10 字节。
        pub(crate) fn varint(&mut self) -> Result<u64, Error> {
            let mut value = 0_u64;
            let mut shift = 0_u32;
            loop {
                let byte = self.u8()?;
                value |= ((byte & 0x7f) as u64) << shift;
                if byte & 0x80 == 0 {
                    return Ok(value);
                }
                shift += 7;
                if shift > 63 {
                    return Err(Error::CountOutOfRange);
                }
            }
        }

        /// zigzag（DEFS 的 pc 增量）。
        pub(crate) fn zigzag(&mut self) -> Result<i64, Error> {
            let value = self.varint()?;
            Ok(((value >> 1) as i64) ^ -((value & 1) as i64))
        }

        /// 声明计数 × 最小条目字节数 ≤ 剩余字节，否则必然是损坏。
        pub(crate) fn count(&mut self, min_entry: usize) -> Result<usize, Error> {
            let n = self.varint()?;
            self.bounded(n, min_entry)
        }

        pub(crate) fn bounded(&self, n: u64, min_entry: usize) -> Result<usize, Error> {
            let n = usize::try_from(n).map_err(|_| Error::CountOutOfRange)?;
            if n > self.remaining() / min_entry.max(1) {
                return Err(Error::CountOutOfRange);
            }
            Ok(n)
        }

        pub(crate) fn utf8(&mut self, n: usize) -> Result<&'a str, Error> {
            std::str::from_utf8(self.take(n)?).map_err(|_| Error::BadUtf8)
        }
    }

    struct DirectoryEntry {
        kind: u32,
        codec: u32,
        offset: u64,
        clen: u64,
        ulen: u64,
    }

    fn parse_directory(bytes: &[u8]) -> Result<Vec<DirectoryEntry>, Error> {
        let mut r = Cursor::new(bytes);
        if r.take(3)? != MAGIC {
            return Err(Error::BadMagic);
        }
        let count = r.u32()? as usize;
        // 每条目 32 字节，且必须在文件内。
        if count > r.remaining() / 32 {
            return Err(Error::CountOutOfRange);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(DirectoryEntry {
                kind: r.u32()?,
                codec: r.u32()?,
                offset: r.u64()?,
                clen: r.u64()?,
                ulen: r.u64()?,
            });
        }
        for e in &entries {
            let end = e
                .offset
                .checked_add(e.clen)
                .and_then(|end| usize::try_from(end).ok())
                .filter(|end| *end <= bytes.len())
                .ok_or(Error::SegmentOutOfRange)?;
            let _ = end;
        }
        Ok(entries)
    }

    fn segment_body(
        bytes: &[u8],
        dir: &[DirectoryEntry],
        kind: u32,
    ) -> Result<Vec<u8>, Error> {
        let entry = dir
            .iter()
            .find(|e| e.kind == kind)
            .ok_or(Error::SegmentOutOfRange)?;
        let offset = usize::try_from(entry.offset).map_err(|_| Error::SegmentOutOfRange)?;
        let clen = usize::try_from(entry.clen).map_err(|_| Error::SegmentOutOfRange)?;
        let body = bytes
            .get(offset..offset.checked_add(clen).ok_or(Error::SegmentOutOfRange)?)
            .ok_or(Error::SegmentOutOfRange)?;
        match entry.codec {
            codec::RAW => Ok(body.to_vec()),
            codec::ZLIB => {
                let out = miniz_oxide::inflate::decompress_to_vec_zlib(body)
                    .map_err(|_| Error::CorruptCompression)?;
                if out.len() as u64 != entry.ulen {
                    return Err(Error::CorruptCompression);
                }
                Ok(out)
            }
            other => Err(Error::UnknownCodec(other)),
        }
    }

    fn parse_coverage(d: &mut Cursor, chase_spills: Option<usize>) -> Result<Coverage, Error> {
        if d.remaining() == 0 {
            return Ok(match chase_spills {
                Some(spills) => Coverage::ChaseSpills(spills),
                None => Coverage::Complete,
            });
        }
        Ok(match d.u8()? {
            0 => Coverage::Complete,
            1 => Coverage::ChaseSpills(d.count(1)?),
            2 => Coverage::PartialPartition {
                proved: d.count(1)?,
                uncovered: d.count(1)?,
            },
            3 => {
                let len = d.u16()? as usize;
                Coverage::ViewTruncated(d.utf8(len)?.to_string())
            }
            4 => Coverage::Degraded(d.count(1)?),
            _ => return Err(Error::CountOutOfRange),
        })
    }

    fn parse_frame_args(r: &mut Cursor, must: bool) -> Result<Option<FrameArgs>, Error> {
        if r.u8()? == 0 {
            return if must {
                Err(Error::BadReference("exit entry without frame args"))
            } else {
                Ok(None)
            };
        }
        let cells = r.count(1)?;
        let mut stack = Vec::with_capacity(cells);
        for _ in 0..cells {
            stack.push(r.varint()? as u32);
        }
        let reached = r.varint()? as u16;
        let returndata_size = r.varint()? as u32;
        let returndata_epoch = r.varint()? as u32;
        let reads = r.count(2)?;
        let mut table = Vec::with_capacity(reads);
        for _ in 0..reads {
            table.push((r.varint()? as u32, r.varint()? as u32));
        }
        Ok(Some(FrameArgs {
            stack,
            reached,
            returndata_size,
            returndata_epoch,
            reads: table,
        }))
    }

    /// 读一条事实流条目；`step` 是调用方的步序计数器（只给
    /// Guard/Effect/Outcome 递增）。
    fn parse_entry(
        r: &mut Cursor,
        strings: &[String],
        step: &mut u32,
    ) -> Result<Entry, Error> {
        let str_at = |r: &mut Cursor| -> Result<String, Error> {
            let id = r.varint()?;
            strings
                .get(id as usize)
                .cloned()
                .ok_or(Error::BadReference("string id"))
        };
        Ok(match r.u8()? {
            0 => {
                let entry = Entry::Guard {
                    cond: r.varint()? as u32,
                    polarity: r.u8()? != 0,
                    scope: r.varint()? as u32,
                    pc: r.varint()? as u32,
                    step: *step,
                };
                *step += 1;
                entry
            }
            1 => {
                let kind = str_at(r)?;
                let scope = r.varint()? as u32;
                let pc = r.varint()? as u32;
                let n = r.u8()? as usize;
                let mut operands = Vec::with_capacity(n);
                for _ in 0..n {
                    operands.push((str_at(r)?, r.varint()? as u32));
                }
                let entry = Entry::Effect {
                    kind,
                    operands,
                    scope,
                    pc,
                    step: *step,
                };
                *step += 1;
                entry
            }
            2 => {
                let class = str_at(r)?;
                let scope = r.varint()? as u32;
                let pc = r.varint()? as u32;
                let data = if r.u8()? != 0 {
                    Some(r.varint()? as u32)
                } else {
                    None
                };
                let entry = Entry::Outcome {
                    class,
                    data,
                    scope,
                    pc,
                    step: *step,
                };
                *step += 1;
                entry
            }
            3 => Entry::Apply {
                definition: r.varint()? as u32,
                recur: r.u8()? != 0,
                scope: r.varint()? as u32,
                instance: match r.varint()? as u32 {
                    u32::MAX => None,
                    value => Some(value),
                },
                args: parse_frame_args(r, false)?,
            },
            4 => Entry::Exit {
                target: r.varint()? as u32,
                scope: r.varint()? as u32,
                pc: r.varint()? as u32,
                args: parse_frame_args(r, true)?.expect("checked present"),
            },
            _ => return Err(Error::CountOutOfRange),
        })
    }

    fn parse_entries(r: &mut Cursor, strings: &[String]) -> Result<Vec<Entry>, Error> {
        let n = r.count(1)?;
        let mut entries = Vec::with_capacity(n);
        let mut step = 0_u32;
        for _ in 0..n {
            entries.push(parse_entry(r, strings, &mut step)?);
        }
        Ok(entries)
    }

    pub(super) fn parse(bytes: &[u8]) -> Result<Shard, Error> {
        let dir = parse_directory(bytes)?;

        // DIGEST（+ manifest 计数与覆盖证书）。
        let digest_seg = segment_body(bytes, &dir, seg::DIGEST)?;
        let mut d = Cursor::new(&digest_seg);
        let len = d.u16()? as usize;
        let digest = d.utf8(len)?.to_string();
        let chase_spills = if d.u8()? != 0 {
            Some(d.count(1)?)
        } else {
            None
        };
        let manifest = Manifest {
            nodes: d.varint()? as u32,
            functions: d.varint()? as u32,
            definitions: d.varint()? as u32,
            scopes: d.varint()? as u32,
        };
        let coverage = parse_coverage(&mut d, chase_spills)?;
        let unresolved_control = if d.remaining() == 0 {
            None
        } else if d.u8()? != 0 {
            Some(d.count(1)?)
        } else {
            None
        };

        // STRS。
        let strs_seg = segment_body(bytes, &dir, seg::STRS)?;
        let mut s = Cursor::new(&strs_seg);
        let n = s.count(2)?;
        let mut strings = Vec::with_capacity(n);
        for _ in 0..n {
            let len = s.u16()? as usize;
            strings.push(s.utf8(len)?.to_string());
        }

        // EXPR（节点 + 结构哈希尾）。
        let expr_seg = segment_body(bytes, &dir, seg::EXPR)?;
        let mut e = Cursor::new(&expr_seg);
        let nodes = e.count(1)?;
        let mut exprs: Vec<ExprNode> = Vec::with_capacity(nodes);
        for _ in 0..nodes {
            let str_at = |e: &mut Cursor| -> Result<String, Error> {
                let id = e.varint()?;
                strings
                    .get(id as usize)
                    .cloned()
                    .ok_or(Error::BadReference("string id"))
            };
            let node = match e.u8()? {
                0 => ExprNode::Leaf(str_at(&mut e)?),
                1 => {
                    let len = e.count(1)?;
                    if len > 32 {
                        return Err(Error::BadReference("constant word"));
                    }
                    let mut word = [0u8; 32];
                    word[32 - len..].copy_from_slice(e.take(len)?);
                    ExprNode::Const(word)
                }
                2 => {
                    let len = e.count(1)?;
                    ExprNode::ConstBytes(e.take(len)?.to_vec())
                }
                3 => ExprNode::CalldataWord(e.varint()?),
                4 => ExprNode::Env(str_at(&mut e)?),
                5 => ExprNode::Unary(str_at(&mut e)?, e.varint()? as u32),
                6 => ExprNode::Binary(str_at(&mut e)?, e.varint()? as u32, e.varint()? as u32),
                7 => ExprNode::Cmp(str_at(&mut e)?, e.varint()? as u32, e.varint()? as u32),
                8 => ExprNode::Ternary(
                    str_at(&mut e)?,
                    e.varint()? as u32,
                    e.varint()? as u32,
                    e.varint()? as u32,
                ),
                9 => {
                    let op = str_at(&mut e)?;
                    let arity = e.count(1)?;
                    let mut args = Vec::with_capacity(arity);
                    for _ in 0..arity {
                        args.push(e.varint()? as u32);
                    }
                    ExprNode::Nary(op, args)
                }
                10 => ExprNode::Cast(e.varint()? as u32, e.varint()?),
                11 => ExprNode::Param(e.varint()? as u32),
                _ => return Err(Error::CountOutOfRange),
            };
            exprs.push(node);
        }
        // 结构哈希尾：节点数 × 32（count 校验已限住 nodes）。
        let hashes = {
            let n = nodes
                .checked_mul(32)
                .filter(|n| *n == e.remaining())
                .ok_or(Error::HashTailMismatch)?;
            let mut hashes = Vec::with_capacity(nodes);
            for chunk in e.take(n)?.as_chunks::<32>().0 {
                hashes.push(*chunk);
            }
            hashes
        };

        // FUNC。
        let func_seg = segment_body(bytes, &dir, seg::FUNC)?;
        let mut f = Cursor::new(&func_seg);
        let n = f.count(4)?; // kind str id 至少 1 字节 + selector 4 + ...
        let mut functions = Vec::with_capacity(n);
        for _ in 0..n {
            let kind_id = f.varint()?;
            let kind = strings
                .get(kind_id as usize)
                .cloned()
                .ok_or(Error::BadReference("string id"))?;
            let selector = match f.u32()? {
                u32::MAX => None,
                value => Some(value),
            };
            let name = if f.u8()? != 0 {
                let id = f.varint()?;
                Some(
                    strings
                        .get(id as usize)
                        .cloned()
                        .ok_or(Error::BadReference("string id"))?,
                )
            } else {
                None
            };
            let entries = parse_entries(&mut f, &strings)?;
            functions.push(Function {
                kind,
                selector,
                name,
                entries,
            });
        }

        // DEFS（code_id 去重表 + pc 增量）。
        let defs_seg = segment_body(bytes, &dir, seg::DEFS)?;
        let mut d2 = Cursor::new(&defs_seg);
        let code_id_count = d2.count(1)?;
        let mut code_ids = Vec::with_capacity(code_id_count);
        for _ in 0..code_id_count {
            code_ids.push(d2.varint()? as u32);
        }
        let n = d2.count(5)?; // zigzag 至少 1 字节 + code_id 下标 1 + height 1
        let mut definitions = Vec::with_capacity(n);
        let mut pc = 0_i64;
        for _ in 0..n {
            // checked_add：伪造的 pc 增量在 debug 下会让裸 + 溢出 panic、
            // release 下回绕后可能落回合法区间——溢出一律按解析错误处理。
            pc = pc
                .checked_add(d2.zigzag()?)
                .ok_or(Error::BadReference("definition pc"))?;
            if pc < 0 || pc > u32::MAX as i64 {
                return Err(Error::BadReference("definition pc"));
            }
            let code_id = *code_ids
                .get(d2.varint()? as usize)
                .ok_or(Error::BadReference("code_id index"))?;
            let height = if d2.u8()? != 0 {
                Some(d2.varint()? as u32)
            } else {
                None
            };
            let entries = parse_entries(&mut d2, &strings)?;
            definitions.push(Definition {
                pc: pc as u32,
                code_id,
                height,
                entries,
            });
        }

        // SCOPE。
        let scope_seg = segment_body(bytes, &dir, seg::SCOPE)?;
        let mut sc = Cursor::new(&scope_seg);
        let n = sc.count(3)?;
        let mut scopes = Vec::with_capacity(n);
        for _ in 0..n {
            scopes.push(Scope {
                parent: sc.varint()? as u32,
                guard: sc.varint()? as u32,
                polarity: sc.u8()? != 0,
            });
        }

        // SUMM。
        let summ_seg = segment_body(bytes, &dir, seg::SUMM)?;
        let summaries = parse_summaries(&summ_seg)?;

        // READS（可选段；M0 不消费，解析即跳过——目录按键查找）。
        // （这里显式不读 seg 8：未知/可选段的跳过策略见格式规范 §0.1。）

        // ---- 一致性校验 ----
        if manifest.nodes as usize != exprs.len()
            || manifest.functions as usize != functions.len()
            || manifest.definitions as usize != definitions.len()
            || manifest.scopes as usize != scopes.len()
        {
            return Err(Error::ManifestMismatch);
        }

        // 表达式子引用越界校验（读端的安全边界）。
        let check = |id: u32, what: &'static str| -> Result<(), Error> {
            if id as usize >= exprs.len() {
                return Err(Error::BadReference(what));
            }
            Ok(())
        };
        for node in &exprs {
            match node {
                ExprNode::Leaf(_)
                | ExprNode::Const(_)
                | ExprNode::ConstBytes(_)
                | ExprNode::CalldataWord(_)
                | ExprNode::Env(_)
                | ExprNode::Param(_) => {}
                ExprNode::Unary(_, a) => check(*a, "unary operand")?,
                ExprNode::Binary(_, a, b) | ExprNode::Cmp(_, a, b) => {
                    check(*a, "binary operand")?;
                    check(*b, "binary operand")?;
                }
                ExprNode::Ternary(_, a, b, c) => {
                    check(*a, "ternary operand")?;
                    check(*b, "ternary operand")?;
                    check(*c, "ternary operand")?;
                }
                ExprNode::Nary(_, args) => {
                    for a in args {
                        check(*a, "nary operand")?;
                    }
                }
                ExprNode::Cast(a, _) => check(*a, "cast operand")?,
            }
        }

        // 作用域：guard 合法、parent 不越界/不自指、链无环。
        let scope_count = scopes.len();
        for (index, scope) in scopes.iter().enumerate() {
            check(scope.guard, "scope guard")?;
            let id = index as u32 + 1;
            if scope.parent as usize > scope_count || scope.parent == id {
                return Err(Error::BadReference("scope parent"));
            }
        }
        // 三色 DFS：parent 链必须终止。
        const WHITE: u8 = 0;
        const GRAY: u8 = 1;
        const BLACK: u8 = 2;
        let mut color = vec![WHITE; scope_count + 1];
        for start in 1..=scope_count as u32 {
            if color[start as usize] != WHITE {
                continue;
            }
            color[start as usize] = GRAY;
            let mut path = vec![start];
            while let Some(node) = path.last().copied() {
                let parent = scopes[node as usize - 1].parent;
                if parent == 0 {
                    color[node as usize] = BLACK;
                    path.pop();
                    continue;
                }
                match color[parent as usize] {
                    GRAY => return Err(Error::ScopeCycle),
                    BLACK => {
                        color[node as usize] = BLACK;
                        path.pop();
                    }
                    WHITE => {
                        color[parent as usize] = GRAY;
                        path.push(parent);
                    }
                    _ => unreachable!(),
                }
            }
        }

        Ok(Shard {
            digest,
            chase_spills,
            coverage,
            unresolved_control,
            manifest,
            hashes,
            strings,
            exprs,
            functions,
            definitions,
            scopes,
            summaries,
        })
    }

    fn parse_summaries(bytes: &[u8]) -> Result<Summaries, Error> {
        let mut summaries = Summaries::default();
        let mut su = Cursor::new(bytes);
        for relation in [
            &mut summaries.reads_s,
            &mut summaries.writes_s,
            &mut summaries.cbw_s,
            &mut summaries.retdep_s,
        ] {
            let n = su.count(2)?;
            for _ in 0..n {
                relation.push((su.varint()? as u32, su.varint()? as u32));
            }
        }
        let n = su.count(3)?;
        for _ in 0..n {
            let func = su.varint()? as u32;
            let class = su.u8()?;
            let aux = su.varint()? as u32;
            let target = match class {
                0 => CallTarget::Const(aux),
                1 => CallTarget::Slot(aux),
                _ => CallTarget::Dynamic(aux),
            };
            summaries.calls_s.push((func, target));
        }
        summaries.kinds = if su.remaining() > 0 {
            Some(su.varint()?)
        } else {
            None
        };
        Ok(summaries)
    }
}

// ---------------------------------------------------------------------------
// 单元测试：编码原语与防伪造边界
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::reader::Cursor;
    use super::*;

    /// LEB128 编解码往返（含多字节边界 127/128/2^63-1 类值）。
    #[test]
    fn varint_roundtrip() {
        let cases: Vec<u64> = vec![0, 1, 127, 128, 300, u32::MAX as u64, u64::MAX];
        let mut buf = Vec::new();
        for v in &cases {
            // 内联写出（与格式规范 §0 相同的 LEB128）。
            let mut x = *v;
            loop {
                let mut byte = (x & 0x7f) as u8;
                x >>= 7;
                if x != 0 {
                    byte |= 0x80;
                }
                buf.push(byte);
                if x == 0 {
                    break;
                }
            }
        }
        let mut c = Cursor::new(&buf);
        for v in &cases {
            assert_eq!(c.varint().unwrap(), *v);
        }
        assert_eq!(c.remaining(), 0);
    }

    /// zigzag 编解码往返（负 delta 与 0）。
    #[test]
    fn zigzag_roundtrip() {
        let cases: Vec<i64> = vec![0, 1, -1, 63, -64, 1_000_000, -1_000_000];
        let mut buf = Vec::new();
        for v in &cases {
            let encoded = ((*v << 1) ^ (*v >> 63)) as u64;
            let mut x = encoded;
            loop {
                let mut byte = (x & 0x7f) as u8;
                x >>= 7;
                if x != 0 {
                    byte |= 0x80;
                }
                buf.push(byte);
                if x == 0 {
                    break;
                }
            }
        }
        let mut c = Cursor::new(&buf);
        for v in &cases {
            assert_eq!(c.zigzag().unwrap(), *v);
        }
    }

    /// 超长 varint（>10 字节）报错而不是无限循环。
    #[test]
    fn varint_too_long_rejected() {
        let buf = [0x80u8; 11];
        let mut c = Cursor::new(&buf);
        assert!(matches!(c.varint(), Err(Error::CountOutOfRange)));
    }

    /// 截断输入：take 越界报错。
    #[test]
    fn truncated_take_rejected() {
        let mut c = Cursor::new(&[1, 2]);
        assert!(matches!(c.u32(), Err(Error::CountOutOfRange)));
    }

    /// count × 最小条目字节数 > 剩余字节即拒（防伪造巨分配）。
    #[test]
    fn count_guard_rejects_oversized() {
        let mut c = Cursor::new(&[0x05]); // varint 5
        assert!(matches!(c.count(32), Err(Error::CountOutOfRange)));
    }
}
