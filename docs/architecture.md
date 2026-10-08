# loom-fuzz 架构

loom-fuzz 是 loom-evm 检测命中的**见证闭环**：每条命中 `(函数, 帧, 证据表达式)` 经过"种子 → 定向执行 → 族 oracle"得到三值判决（confirmed / unreachable / inconclusive），无见证只降级不过滤。

## 输入双模式

loom-fuzz 从不依赖 loom-evm 的代码，只通过两种**文件/进程契约**之一获取分析产物：

### 模式 A：loom CLI 在位

目标机器已安装 loom-evm 发布的二进制（`loom`）。loom-fuzz 以子进程方式调用：

- `loom query <pack>... <shard> --json` → 检测 pack 的 `vuln_arbitrary` 谓词 rows
- **额外输入**：`bytecode.hex`（运行时字节码 hex 文本）——`.lst` 不含字节码，
  `HitSet.code` 必须由调用方单独提供（两个装载器签名都收 `code_hex`）。

适用：分析与 fuzz 同机的交互式工作流。CLI 的 JSON 输出即契约，loom-evm 端需保证其稳定性（发版纪律）。

**模式 A 契约 = loom CLI JSON 的最小稳定子集**（`loom query --json` 顶层）：

| 字段 | 类型 | 处置 |
|---|---|---|
| `queries` | 数组 | 按键 `predicate` 查找 `"vuln_arbitrary"` 结果段；缺段 = typed 报错（`LoomJson`） |
| `queries[].predicate` | 字符串 | 谓词名 |
| `queries[].rows` | 字符串数组的数组 | `vuln_arbitrary` 的行：`[func, step, t]` 三列（见下） |
| `queries[].total_rows` | uint | 与 `rows.len()` 不等即视为截断，fail-closed 报错（`LoomTruncated`） |
| `truncated` | bool | `true` 即结果不完整，fail-closed 报错（同上） |
| `unserved_demand` | uint | `> 0` 表示有 oracle demand 未满足（结果可能不完整），fail-closed 报错（`LoomUnservedDemand`） |
| `unserved_keys` | 字符串数组 | 仅供诊断展示 |

`vuln_arbitrary` 行形态：`[func, step, t]`，全部字符串列——

| 列 | 类型 | 示例 | 说明 |
|---|---|---|---|
| `func` | `0x%08x` \| `f{local}@c{contract}` | `"0x90ce82d4"` | 有 selector 函数的渲染；无 selector（fallback/receive 等）渲染 `f{local}@c{contract}`（单 shard 装载要求 `c0`）；其它形态（如 `def...@c...`）= 契约外输入，fail-closed 报错（`FuncUnrecognized`） |
| `step` | 十进制数字字符串 | `"19"` | 效果步序（x-layer 步序），非数字 = typed 报错 |
| `t` | 表达式渲染文本 | `"cast160(calldata_word(0x4))"` | 证据表达式原文，原样保留为 `Hit.evidence` |

步序 → pc 映射与支配 guard **两种模式都走本仓库 xlayer 展开**（不发
`loom facts`）：装载器内部统一，loom 展开步序已由 xlayer golden 对拍
验证一致，保证检测来源对 pc/guard 计算无感。

### 模式 B：纯文件

只有两份文件：`bytecode.hex`（运行时字节码）+ `.lst`（`loom store` 产出的 shard）。loom-fuzz 内置读取器（`crates/shard`，格式契约见 `docs/shard-format.md`）自行解析函数表、表达式字典、effect/guard 事实流。

适用：CI、分析产物分享、异机执行、loom-evm 未安装的环境。

### 汇合

两种模式归一为同一内部表示 `HitSet`：

```
HitSet {
  code: Vec<u8>,                        // 运行时字节码
  hits: Vec<Hit>,                       // 每条检测命中
}
Hit {
  selector: u32,                        // 函数 selector（无函数上下文 u32::MAX 哨兵）
  target_pcs: Vec<u32>,                 // 帧 → PC 集合（定向目标）
  evidence: String,                     // 证据表达式的规范化渲染文本（oracle 求值对象）
  dominating_guards: Vec<GuardFact>,    // 支配 guard（seed 编译输入）
}
GuardFact { cond: String, polarity: bool, pc: u32 }
```

模式 A/B 只是 HitSet 的两个装载器（`crates/cli` 里的 `load_from_cli` / `load_from_shard`），闭环管线对来源无感。

- 模式 A：`load_from_cli(loom_bin, packs, shard, code_hex)`——子进程
  `loom query`，fail-closed（二进制缺失 / 非零退出 / JSON 缺字段 /
  截断 / 未满足 demand / Func 列无法识别，全部 typed 报错）。
- 模式 B：`load_from_shard(shard, code_hex)`——纯文件，内置
  arbitrary_call 检测推导（臂 3 裸转发 + 臂 1 目标可控；
  `caller_test` / `scope_cmp` 语义照 loom-evm 内建关系逐条对齐）。
  M0 已知近似：`whitelisted` 只实现可信身份比对与 caller 键控
  mapping 成员测试两臂（`registry_validated` 族未实现，可能对
  注册表验证类合约过报）；`identity_ref_contract`（臂 2/4，需链上
  oracle）在无 oracle 时装配为空，模式 B 不实现。
- 两模式等价性由 golden 对拍测试钉死：同一 shard 上
  `load_from_cli` 与 `load_from_shard` 的 HitSet 逐字段相等
  （code、hits 全部字段含 dominating_guards）。

## 闭环管线

```
HitSet
  │  ⓪ 装载前经 xlayer 展开（crates/xlayer）：shard 原始流只含
  │     input_read + Apply 边，DEFS 路由展开（帧实参代入 + 作用域
  │     rebase）物化为 xeffect/xguard/xoutcome 视图后才进闭环
  │  ① seed 编译（crates/seed）
  │     支配 guard 代数形状 → 精确种子 Input：
  │     selector 头 / guard 常量 / 边界值 ±1 / caller / 存储槽(标 free)
  ▼
定向执行（crates/fuzz）
  │  ② revm 单合约会话，种子进场
  │  ③ --target 制导：CFG PC 距离表，距离缩小的输入保留进化
  │  ④ 变异：比较操作数回灌 / 常量池整参覆盖 / 存储值入池 / 数值高斯缩放
  ▼
族 oracle + 三值判决
  │  ⑤ 到目标帧后在具体 trace 上求值证据表达式（按族定制检查器）
  │  ⑥ confirmed → 生成 Foundry PoC 工程（Solidity 代码，forge test 绿灯 = 终判；
  │        exploit 级 PoC 含价值影响断言，见 #10）
  │        ｜预算耗尽 → unreachable｜截断 → inconclusive
  ▼
fuzz_report.json（覆盖统计 + 未触发假设，全部落盘可重放，确定性种子）
```

## Crate 规划

| crate | 职责 | 状态 |
|---|---|---|
| `crates/shard` | .lst 读取器（纯文件模式的核心） | M0.1 已就绪（PR #1） |
| `crates/xlayer` | shard 原始流 → xeffect 展开视图（DEFS 路由展开，#8） | M0.2 已就绪 |
| `crates/seed` | guard 事实 → 种子 Input | 待开工 |
| `crates/fuzz` | revm 执行 + --target 制导 + 变异器 + witness 记录 | 待开工 |
| `crates/oracle` | 证据表达式族检查器 + 三值判决 + poc/report 落盘 | 待开工 |
| `crates/cli` | 入口：模式 A/B 装载 + 管线串联 | M0.3 双模式装载器已就绪（PR #3） |

## 边界纪律

- loom-fuzz 的 CI 永远不需要 loom-evm 的代码或私有访问权；模式 A 的契约 = loom-evm 发版 CLI 的 JSON 输出。
- 证据表达式求值器（oracle 侧）与表达式节点定义自包含在 loom-fuzz；两边语义分歧时以 loom-evm 的执行语义（concrete interpreter）为裁判，分歧本身作为 issue 记录。
- 一切产物落盘可重放；预算制；fail-closed。
