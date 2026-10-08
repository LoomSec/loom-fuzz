# loom-fuzz

Witness fuzzing for EVM bytecode, guided end-to-end by [loom-evm](https://github.com/LoomSec/loom-evm)'s static analysis.

loom-evm 的检测命中是精确的 `(函数, 帧, 证据表达式)` 三元组。loom-fuzz 把三元组的每一列编译成闭环的一个角色——种子、目标、判决——回答唯一重要的问题：**这条命中真实可达吗，能不能直接生成可 `forge test` 的 exploit PoC？**

**产出物 = Solidity PoC 代码**：检测出问题，就生成一份 Foundry 测试工程（`test/PoC.t.sol` + `foundry.toml` + 工程自带 `MockERC20`/`IERC20`/`Vm`，零外部依赖），`vm.etch`/`vm.prank`/`vm.store` 布置见证，收尾为价值影响断言（`balanceOf(attacker) == 转入全额`）。**`forge test` 绿灯即终判**——和手写 PoC 同一形态，但是机械合成的（calldata 由 `abi.encodeCall` 表达，不逐字节手写）。

```sh
loom-fuzz exploit out/poc-….json --code bytecode.hex --out exploit/   # L2 影响层
# fork 模式（BlockMachine）：--fork 生成 run.sh + fork profile
#   BLOCKMACHINE_RPC_URL / BLOCKMACHINE_API_KEY 环境变量约定：
#   key 为空 = 直接无 key 连接；非空 = Bearer 头经 anvil 代理附加
#   （forge test 无 header 旗，anvil --fork-header 是 foundry 族内惯用通路）。
```

| 命中列 | 在闭环中的角色 |
|---|---|
| 函数 selector | 种子 calldata 头（怎么进场） |
| 帧 | 定向目标 PC 集合（往哪走） |
| 证据表达式 | oracle——到帧后在具体 trace 上求值，为真即见证（到场后验什么） |

三个输入同源同词汇，不存在"找到的洞和报的洞是不是同一个"的对齐问题。

## 判决（三值，fail-closed）

- **confirmed** — 见证复现，产出 Foundry PoC 工程（`forge test` 绿灯即终判）
- **unreachable** — 预算耗尽未到达该帧（FP 候选，降级不消灭）
- **inconclusive** — 燃料/步数截断，如实报告，绝不硬判

无见证 ⇒ 只降级，不过滤。

## 输入从哪来

loom-evm 反编译产出的静态事实直接编译成 fuzz 的输入空间：

- 种子：支配 guard 的代数形状反解为精确初始输入（selector、guard 常量、边界值 999/1000/1001 型、caller、存储槽）
- 值字典：证据表达式里的常量、白名单成员、注册表槽键
- 定向：帧 → PC 距离表，距离缩小的输入保留进化

静态知道的一切，fuzzer 进场时就带着；剩下的未知量（存储根、外部调用响应）才是 fuzz 的搜索空间。

## 输入双模式

- **loom CLI 在位**：调用 loom-evm 发布的 `loom` 二进制（`query --json` / `facts`）装载命中与 pc 映射
- **纯文件**：只给 `bytecode.hex` + `.lst` shard，内置读取器（`crates/shard`）自行解析

两种模式归一为同一 `HitSet`，闭环管线对来源无感。详见 [docs/architecture.md](docs/architecture.md) 与 [docs/shard-format.md](docs/shard-format.md)。

## 里程碑

- **M0**：单合约、纯字节码、单交易见证闭环，arbitrary_call 族先行；验收 = TRV 样本出 confirmed、噪声行出 unreachable
- **M0.2**：`crates/xlayer`——DEFS 路由展开自包含复现（与 `loom query` 诊断 pack 在同一 shard 上对拍一致，#8）；TRV 形状样本见 `fixtures/trv-like/`（真实 TRV 字节码受阻见 #11）
- **M0.3**：`crates/cli` 双模式装载器（PR #3）+ `crates/seed` 支配 guard 反解种子编译器（#4，golden 样本 `fixtures/guard-boundary/`）
- **M0.4**：`crates/fuzz` revm 单合约定向执行器——CFG PC 距离制导 + witness 记录（#5；revm 42 / CANCUN，确定性 xorshift64* 进化环 + 纯随机基线对照）
- **M0.5**：`crates/oracle` arbitrary_call 族 oracle + 三值判决 + `loom-fuzz` CLI 管线（run/replay，poc.json 一键重放 verdict 逐字节一致，#7）
- **M0.6**：`crates/pocgen` exploit 影响层——L1 witness → L2 价值影响 Foundry PoC，forge test 绿灯 = 终判（#10，fork 模式 = BlockMachine）
- **M0.7**：on-demand fork 执行——revm AlloyDB 远程状态（pin block）+ CacheDB overlay（--deploy 攻击合约），anvil 同款叠层（#21）
- **M0.8**：分层搜索——全槽字典基座 + 多槽协同变异 + 可插拔 LLM 提案器（revert 归因进反馈，判决独立；#25）

```sh
loom-fuzz run --shard hit.lst --code bytecode.hex --prestate slots.json --out out/
loom-fuzz replay out/poc-….json --code bytecode.hex   # exit 0 = verdict 一致
```
- **M1+**：多检测族推广、存储根 RPC 注入、（后续）多交易状态ful 与 fork 场景

## License

MIT OR Apache-2.0（首个代码提交时附带）。
