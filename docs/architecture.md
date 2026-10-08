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
族 oracle + 三值判决（crates/oracle）
  │  ⑤ 到目标帧后在具体 trace 上求值证据表达式（按族定制检查器；
  │     M0 = arbitrary_call，按检测臂定罪（Hit.arm，mode B 装载时确定）：
  │     臂 3 裸转发：target pc 后的 RecordedCall，kind ∈
  │     {CALL,CALLCODE,DELEGATECALL} 且 input 是原始交易 calldata
  │     的字节子串（≥4B 防 trivial 匹配）；
  │     臂 1 目标可控：call.target（低 160）== 证据表达式在 witness
  │     calldata 上的求值结果（evidence_expr + xlayer 求值器，
  │     cast160(calldata_word/b_calldata_slice) 形态 → Confirmed+Witness，
  │     求值结果以 evidence_value 内嵌 poc.json，replay 作承诺重放））
  │  ⑥ 判决真值表（fail-closed：无见证只降级不过滤）：
  │        reached && !truncated && 证据成立 → confirmed → poc.json
  │          （loom-fuzz-poc@1：tx/prestate/seed/max_runs + replay 命令串，
  │          replay 用确定性参数重建会话重跑，verdict 逐字节一致）
  │        未到达 → unreachable（FP 候选降级）｜truncated → inconclusive
  ▼
fuzz_report.json（loom-fuzz-report@1：per-hit 判决 + 覆盖 + corpus 规模
  + seed 编译全量假设 + guided vs baseline 数据；空命中集也照落）
  │  分层搜索（issue #25）：进化环由可插拔 Proposer 驱动——
  │    DictionaryProposer（默认：反馈前一半父代 × 五算子+多槽协同
  │    变异，k∈{2,3} 槽同轮覆写）/ LlmProposer（--proposer llm，
  │    OpenAI 兼容 chat/completions；prompt/响应落 fuzz_report，
  │    失败 fail-closed 回退字典）。revert 归因（loom 特色）：
  │    执行器记录最近经过的支配 guard（pc + xlayer 渲染 cond），
  │    随 RunFeedback 喂提案器。**判决独立**：judge/oracle 不感知
  │    提案器；replay 无 LLM，verdict 一致。
  │  L2（issue #10）：confirmed 的 poc.json 进 exploit 影响层——
  ▼
Foundry 工程（crates/pocgen 机械合成，forge test 绿灯 = 终判）
  │  资产模型：MockERC20（工程自带）全额 mint 给路由器（受害者持仓）
  │  有害动作：ERC20 drain = transferFrom(router, attacker, BALANCE)，
  │    allowance[router][router] 槽 vm.store 机械布置（标准槽公式）
  │  双断言：L1 require(ok)（转发成功）+ L2 require(balanceOf(attacker)
  │    == BALANCE)（缴获严格等于全额）
  │  ｜非 confirmed 不进 L2（typed error 诚实降级）
  ▼
forge test 绿灯（`loom-fuzz exploit <poc.json> --code … [--fork]`
  或 `run --emit-poc <dir>`；fork 模式 = BlockMachine，见工程 README）
```

## CLI（crates/cli 的 bin）

```sh
# 闭环：模式 B 装载 → seed → fuzz（每 hit 一个独立会话）→ oracle → 落盘
loom-fuzz run --shard x.lst --code bytecode.hex [--prestate slots.json]   [--pack arbitrary_call.lq --loom-bin /path/to/loom]   # 模式 A（成对给）
  [--seed N] [--max-runs N] [--gas-per-tx N] [--dict-word 0x..]... [--out dir]
# 重放 poc.json：重建会话重跑判决；exit 0 = verdict 与记录一致
loom-fuzz replay poc-….json --code bytecode.hex [--prestate slots.json]
# on-demand fork 执行（env BLOCKMACHINE_RPC_URL/_API_KEY；key 空 = keyless）
loom-fuzz run … --fork-url <url> --fork-block latest --contract-addr 0x… \
  --deploy 0x…:responder-sender   # 或 <hex runtime> / responder
  [--proposer dictionary|llm]     # 提案器（llm 需 env LLM_API_*）
# L2 exploit 影响层：confirmed poc.json → Foundry 工程 + forge test
loom-fuzz exploit poc-….json --code bytecode.hex --out exploit/ [--fork]
```

- prestate / dict-word：shard 无 registry/白名单事实段的 M0 补法——
  布置经 `--prestate`（hex→hex map），registry 常量经 `--dict-word`
  进值字典与候选种子（docs 值字典定义）。种子尾部 M0 恒空，管线另补
  泛型 ABI 形态基座种子（n=1..4 零参槽 + 指针尾），指针槽正确性由此
  进搜索空间。
- 判决 exit 语义：`run` 恒 0（判决如实落盘）；输入/装载错误 fail-closed
  退出 2 并指明缺什么；`replay` 0 = 一致、1 = 不一致。

## L1 / L2 两层模型（issue #10）

- **L1 = 到场 + 控制呼出**（M0 已完，oracle）：到达 target pc 且
  trace 上的呼出满足证据谓词（arbitrary_call 臂 3 = 任意目标 +
  任意 calldata，msg.sender = 路由器）。产出 poc.json。
- **L2 = 把 primitive 组装成盗窃**（pocgen）：选有害动作、布置
  受害者资产、断言缴获。机械合成——calldata 由
  `abi.encodeWithSelector` / `abi.encodeCall` 在 Solidity 侧表达，
  合成器只注入参数（字节码 / prestate / BALANCE / 地址），不逐字节
  手写。**forge test 绿灯 = 终判**；红灯 fail-closed 报错。
- 有害动作集合按族扩展（`HarmfulAction` enum + 选择函数挂点），
  M0 只实现 ERC20 drain 臂。

## Crate 规划

| crate | 职责 | 状态 |
|---|---|---|
| `crates/shard` | .lst 读取器（纯文件模式的核心） | M0.1 已就绪（PR #1） |
| `crates/xlayer` | shard 原始流 → xeffect 展开视图（DEFS 路由展开，#8） | M0.2 已就绪 |
| `crates/seed` | guard 事实 → 种子 Input（支配 guard 结构化反解：selector 头 / guard 常量 / 边界值 ±1 / caller / 存储槽标 free） | M0.3 已就绪 |
| `crates/fuzz` | revm 执行 + --target 制导 + 变异器 + witness 记录 | M0.4 已就绪（#5） |
| `crates/oracle` | 证据表达式族检查器 + 三值判决 + poc/report 落盘 | M0.5 已就绪（#7） |
| `crates/pocgen` | L2 exploit 合成：primitive → 价值影响 Foundry PoC（forge 绿灯 = 终判） | M0.6 已就绪（#10） |
| `crates/cli` | 入口：模式 A/B 装载 + 管线串联 + run/replay/exploit 子命令 | M0.3 双模式装载器已就绪（PR #3） |

## 边界纪律

- loom-fuzz 的 CI 永远不需要 loom-evm 的代码或私有访问权；模式 A 的契约 = loom-evm 发版 CLI 的 JSON 输出。
- 证据表达式求值器（oracle 侧）与表达式节点定义自包含在 loom-fuzz；两边语义分歧时以 loom-evm 的执行语义（concrete interpreter）为裁判，分歧本身作为 issue 记录。
- 一切产物落盘可重放；预算制；fail-closed。
