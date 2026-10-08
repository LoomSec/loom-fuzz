# loom-evm shard（.lst）文件格式规范

> 本文档是 loom-fuzz 消费 loom-evm 分析产物（shard 文件）的**契约文档**。
> 规范按 loom-evm `write_shard` 的写出逻辑描述（src/store/mod.rs）；读取器
> 可以为了容错接受更宽的范围，但"什么会被写出来"以本文为准。
> 读完本文不需要再看 loom-evm 代码即可实现独立 reader。

## 0. 总览

shard 是**一个合约**的已检查事实（checked facts）的持久化形式：表达式字典
（loom IR 表达式树）、函数/定义的事实流（guard / effect / outcome / apply /
exit）、作用域表与 may-summary。文件结构：

```
+--------+---------+----------------+---------+
| MAGIC  | dir len |   directory    | bodies  |
| "LST"  | u32 LE  | count × 32B    | 段载荷  |
+--------+---------+----------------+---------+
```

- 所有多字节整数**小端**（LE），除 varint/zigzag 外。
- **varint**：无符号 LEB128，最多 10 字节（移位 > 63 即错）。格式里所有
  id / 计数 / 长度都用它（`wv`）。
- **zigzag**：`(v << 1) ^ (v >> 63)` 后再 LEB128（`wz`），只用于 DEFS 段
  的 pc 增量。
- 固定宽度辅助：`w8`=u8，`w16`=u16 LE，`w32`=u32 LE，`w64`=u64 LE。

### 0.1 段目录（directory）

紧跟 7 字节文件头：

| 字段   | 类型   | 含义                             |
|--------|--------|----------------------------------|
| magic  | 3 字节 | ASCII `"LST"`                    |
| count  | u32 LE | 目录条目数（= 段数）             |

随后 `count` 条定长 32 字节目录项：

| 字段   | 类型   | 含义                                       |
|--------|--------|--------------------------------------------|
| kind   | u32 LE | 段类型（见 0.2）                           |
| codec  | u32 LE | 0 = 原始；1 = zlib（miniz-oxide 风格）     |
| offset | u64 LE | 段体在文件中的起始偏移                     |
| clen   | u64 LE | 段体长度（压缩后）                         |
| ulen   | u64 LE | 解压后长度（codec=1 时必须精确相等）       |

段体从 `7 + count*32` 开始、按目录顺序紧密排列；offset/clen 必须落在文件
长度内。目录是**按键查找**的，不是按位置：reader 必须按 kind 查目录，
不得假设第 N 项是什么段，也不得假设任何段存在（除 DIGEST/EXPR/STRS/
FUNC/DEFS/SCOPE/SUMM 七个标准段外，未来可能新增可选段——未知的 kind
跳过即可）。

### 0.2 段类型（kind）

| 值 | 名称   | 内容                                     |
|----|--------|------------------------------------------|
| 1  | DIGEST | 语义 digest 字符串 + manifest 计数 + 覆盖证书 |
| 2  | STRS   | 全局字符串 intern 表                     |
| 3  | EXPR   | 表达式字典（节点 + 结构哈希尾）          |
| 4  | FUNC   | 函数表（kind/selector/name + 事实流）    |
| 5  | DEFS    | 共享定义体（code_id 表驱动 + 事实流）   |
| 6  | SCOPE  | 作用域表                                 |
| 7  | SUMM   | may-summary 关系（预筛用）               |
| 8  | READS  | 可选：按到达类的读取表（design §5.1）    |

只有 **FUNC 与 DEFS 可能被压缩**（写出器对 ≥ 4096 字节的段体做 zlib
压缩，级别 9；更小的段恒为 RAW）。DIGEST/STRS/EXPR/SCOPE/SUMM 恒为
RAW——头部路径与预筛路径不应为此付出解压开销。READS 仅在非空时写出。

## 1. DIGEST 段（kind 1，RAW）

```
u16 LE        digest 字符串长度（字节）
utf8          digest 字符串（合约的语义标识：keccak，hex，无前缀）
u8            chase_spills 标记：0 = 无；1 = 后跟 varint（spill 计数）
varint × 4    manifest 计数：expr 节点数、函数数、定义数、作用域数
u8            coverage 标签（见下）
[...]         coverage 载荷（按标签）
u8            unresolved_control 标记：0 = 无；1 = 后跟 varint
```

coverage 标签（写出器在段尾写出的证书完备性声明）：

| 标签 | 形态                        | 载荷                          |
|------|-----------------------------|-------------------------------|
| 0    | `Complete`                  | 无                            |
| 1    | `ChaseSpills(n)`            | varint n                      |
| 2    | `PartialPartition{p,u}`     | varint p、varint u            |
| 3    | `ViewTruncated{limit}`      | u16 长度 + utf8               |
| 4    | `Degraded(n)`               | varint n                      |

读端容错：段在旧版本分片中可能更早结束——coverage 标签缺失时由
chase_spills 推导（None → Complete，Some(n) → ChaseSpills(n)）；
unresolved_control 缺失即 None。

manifest 计数必须与对应段的实际条目数一致（读端应校验，不一致即损坏）。

## 2. STRS 段（kind 2，RAW）

```
varint        字符串数 n
重复 n 次：
  u16 LE      字节长度
  utf8        字符串内容
```

这是**全 shard 共享**的 intern 表：表达式节点的 op/叶子名、effect 的
kind 名、函数 kind/name、outcome 的 class 名都以 varint id 引用本表。

## 3. EXPR 段（kind 3，RAW）

```
varint        节点数 n
重复 n 次：    一个表达式节点（tag u8 区分形态，见下）
n × 32 字节   结构哈希尾：每个节点一个 keccak-256（按节点顺序）
```

节点 tag：

| tag | 形态            | 载荷（varint 除非注明）              |
|-----|-----------------|--------------------------------------|
| 0   | `Leaf(name)`    | str id                               |
| 1   | `Const(word)`   | varint len（≤32）+ len 字节大端补齐到 32 字节（去掉前导零的 256 位常量） |
| 2   | `ConstBytes`    | varint len + len 字节原始内容        |
| 3   | `CalldataWord`  | varint calldata 字偏移               |
| 4   | `Env(name)`     | str id（如 `"msg.sender"`）          |
| 5   | `Unary(op, a)`  | str id、子节点 id                    |
| 6   | `Binary(op,a,b)`| str id、两个子节点 id                |
| 7   | `Cmp(op, a, b)` | str id、两个子节点 id（比较运算）    |
| 8   | `Ternary(op,a,b,c)` | str id、三个子节点 id            |
| 9   | `Nary(op, args)`| str id、varint 元数、元数个 子节点 id |
| 10  | `Cast(a, bits)` | 子节点 id、varint 位宽               |
| 11  | `Param(slot)`   | varint 形参槽位                      |

所有子节点 id 都是**本段内的字典下标**（0 起，拓扑序：子先于父）。字典
是 DAG（共享子树只存一份）。读端必须校验子节点 id < n（loom-evm 读端
做全量引用完整性检查；M0 reader 至少校验子节点下标不越界）。

## 4. 事实流条目编码（FUNC/DEFS 共用）

函数体与定义体是同一编码的**条目流**（walk 顺序 = 路由顺序）：

```
varint        条目数 n
重复 n 次：    tag u8 区分条目形态
```

条目 tag：

| tag | 条目 | 载荷 |
|-----|------|------|
| 0 | `Guard` | varint cond（表达式 id）、u8 polarity（0/1）、varint scope、varint pc |
| 1 | `Effect` | str id kind、varint scope、varint pc、u8 操作数数、每操作数 (str id 名, varint 表达式 id) |
| 2 | `Outcome` | str id class、varint scope、varint pc、u8 data 标记（1 = 后跟 varint 表达式 id；0 = 无） |
| 3 | `Apply` | varint definition（定义 id）、u8 recur、varint scope、varint instance（u32::MAX = 无）、frame args（见 4.1） |
| 4 | `Exit` | varint target（pc）、varint scope、varint pc、frame args（必有，Option 编码见 4.1） |

语义注记（loom 层含义，供 fuzz 制导使用）：

- `pc` 是产生该守卫/效果/结局的**单字节码方程**的原点 pc（guard 与
  effect/outcome 同一来源）；effect 的 `kind` 是字符串（`"sload"` /
  `"sstore"` / `"call"` / `"callcode"` / `"delegatecall"` / `"staticcall"` /
  `"create"` / `"create2"` / `"input_read"` / `"mem_window"` / `"world_read"` /
  `"log"` / `"tstore"` / `"tload"` 等），`operands` 是具名表达式 id 列表
  （call 有 `target`/`input`/`value`/`call_kind`/`returndata` 等）。
- guard 的 `polarity` 是条件的真假支；`scope` 是作用域 id（0 = 根，
  非 0 时作用域表下标为 id-1，见 §6）。
- **步序（xeffect 序号）与 `loom facts` JSON 流同源**：x-layer 给
  Guard/Effect/Outcome 条目按序编一个递增序号（Apply/Exit 是控制边，
  不占用效果序号）。reader 暴露原始条目顺序即可复原两种编号。

### 4.1 FrameArgs（Apply/Exit 的实参帧）

```
u8            0 = 无（None）；1 = 有
varint        stack 单元数；每个 varint（表达式 id）
varint        reached（u16 语义：调用方机器实际拥有的入口单元数）
varint        returndata_size（表达式 id）
varint        returndata_epoch（表达式 id）
varint        reads 表长度；每行 varint read + varint value
```

Exit 条目写出时恒为 Some（loom-evm 读端对缺失 Exit args 报错）。

## 5. FUNC 段（kind 4，可能 zlib）

```
varint        函数数 n
重复 n 次：
  str id      kind（"function" / "fallback" / "receive" 等）
  u32 LE      selector（u32::MAX = 无 selector，如 fallback）
  u8          name 标记：1 = 后跟 str id；0 = 无
  条目流      （§4 编码）
```

selector 是该函数的 4 字节函数选择子（原始 u32 值，如 0xe27fbed3）。

## 6. DEFS 段（kind 5，可能 zlib，表驱动）

```
varint        不同 code_id 数 m
varint × m    code_id 值（去重表）
varint        定义数 n
重复 n 次：
  zigzag      pc 增量（累加得真实 pc；首条增量即 pc 本身）
  varint      code_id 下标（索引上面的去重表）
  u8          height 标记：1 = 后跟 varint；0 = 无（v1 具体定义）
  条目流      （§4 编码）
```

## 7. SCOPE 段（kind 6，RAW）

```
varint        作用域数 n（作用域 id 从 1 开始；id k 对应第 k 条）
重复 n 次：
  varint      parent（0 = 根；否则父作用域 id）
  varint      guard（表达式 id：该作用域的守卫条件）
  u8          polarity
```

读端校验：guard 是合法表达式 id；parent ≤ n 且 parent ≠ 自身 id；
parent 链必须终止（无环）。

## 8. SUMM 段（kind 7，RAW，may-summary 预筛）

```
重复 4 个关系（顺序固定：reads_s、writes_s、cbw_s、retdep_s）：
  varint      行数；每行 varint func + varint expr
varint        calls_s 行数；每行 varint func + u8 class + varint aux
              （class：0 = Const、1 = Slot、2 = Dynamic；aux 为表达式 id）
varint        kinds 位图（段尾；旧分片可能缺失，缺失即 None）
```

kinds 位定义（效果种类存在性位图，第 N 位 = 存在）：bit0 sstore、
bit1 sload、bit2 call、bit3 callcode、bit4 delegatecall、bit5 staticcall、
bit7 create、bit8 selfdestruct、bit9 tstore、bit10 tload、
bit11 call_with_value；bit6/bit12 保留未用。

## 9. READS 段（kind 8，可选，RAW)

仅当发射方按到达类拆分了读取表时写出：

```
varint        记录数；每条：varint def、varint entry、varint class、
varint        table 行数；每行 varint token + varint value
```

不消费该段的 reader 直接跳过（目录按键查找正是为此）。

## 10. 读端健壮性要求（防伪造/截断分片）

loom-evm 读端的防资源耗尽做法，独立 reader 应等价实现：

- 所有 count 在用于分配前按"每条目最小字节数 × count ≤ 剩余字节"校验；
  varint 最多 10 字节，移位 > 63 报错。
- 段范围（offset+clen）必须先于读取校验落在文件内；zlib 段解压后长度
  必须等于 ulen。
- 表达式子节点 id、字符串 id、code_id 下标、作用域 parent 均校验越界。
- 结构哈希尾长度 = 节点数 × 32（用 checked_mul，防乘法回绕）。
- manifest 计数（DIGEST 段）与解析出的实际条目数一致性校验。
