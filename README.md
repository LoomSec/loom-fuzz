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
- **M0.8**：分层搜索——全槽字典基座 + 多槽协同变异（dictionary 为唯一搜索路线，#29 决策移除外部模型提案器）；revert 归因（loom 静态事实）辅助进化，判决独立（#25/#29）
- **M0.9**：approval_drain 族（issue #20）——deputy_call（有 caller 守卫但目标可控 = confused deputy）/ drain_forward（input 含输入派生词且不与 caller 绑定）的装载（模式 A 双 pack 并集 / 模式 B 内置推导逐条对齐 loom packs）+ 族 oracle（deputy 复用臂 1 求值 / drain 宽松 memmem）+ L2 通用 ERC20 形状动作选择（不匹配如实报"无通用动作"）。签入 fixtures/real-world/（vvisr RewardsHypervisor / anyswap V4Router）。
- **M1.0**：多合约装载（issue #34）——`--deploy` 多值（合约表 = victim + 各部署）+ 机械 `forwarder` 攻击代理规格 + `--entry` 入口（caller 轮换 ATTACKER → 攻击合约 → victim 的第一环）；witness 记 call 的 `from` 与目标帧 `contract`，oracle 按 victim 帧过滤（多合约 trace pc 数值跨代码库的正确性兜底）。Genesis / fork 两态、模式 A/B 归一不变；#35 序列搜索在合约表上扩展。
- **M1.1**：多交易 stateful 搜索（issue #35）——witness = 调用序列（`Step = target + calldata + caller + value`，steps.len()==1 与单步路径逐位等价）：逐步执行于同一 CacheDB overlay（状态跨步持久，revert 步如实记 step_outcomes），oracle 任意步到达即 L1 到场、族检查器逐步 calldata；序列级组装算子（append / splice / 步内变异，素材 = 反馈窗 ∪ 会话步级池——布置步 fitness 死路的信用分配留存），`--max-steps` 机械约束（默认 1 = 单步）；poc.json `steps` 序列化，旧单步 poc 经 legacy `tx` 归一可 replay。
- **M1.2**：pocgen L3 多步攻击 PoC 机械合成（issue #36）——`src/Attacker.sol` 攻击合约（构造器收 victim + 受害资产 + 在场合约表；attack() 按 Poc.steps 依次 `target.call{value}(calldata)`，逐步独立头形解析后 abi 编码重新表达）+ testExploit（布置 → 部署 Attacker → attack() → 终点断言与 L2 同锚：受害资产 ROUTER 持仓归零）；steps.len()==1 走原 L2 路径（回归保证）；多步非 arbitrary_call 族 / payload 头形不可组装 = 诚实降级（fail-closed）。验收：两步 fixture（布置存储 → TRV 形裸转发）forge test 绿灯。

```sh
loom-fuzz run --shard hit.lst --code bytecode.hex --prestate slots.json --out out/
loom-fuzz replay out/poc-….json --code bytecode.hex   # exit 0 = verdict 一致
```
- **M1+**：多检测族推广、存储根 RPC 注入、（后续）多交易状态ful 与 fork 场景

## 真实案例复现

两个真实主网合约的全链路（loom shard → dictionary 搜索 confirmed → 机械合成 L2 PoC → `forge test` 绿灯）均已实测打通。环境约定：仓库根 `.env` 提供 `BLOCKMACHINE_RPC_URL`（eth 归档端点）与 `BLOCKMACHINE_API_KEY`（**空 = 无 key 直连**，非空经 anvil `--fork-header` Bearer 代理）；跑 golden/实跑前 `set -a && . .env && set +a`，并 `export LOOM_BIN=<loom-evm 二进制路径>`。

### vvisr RewardsHypervisor（eth `0xc9f27a50f82571c1c8423a42970613b8dbda14ef`）

fork 态 arbitrary_call（pin 块 + `--deploy` 攻击合约）：

```sh
loom-fuzz run --shard fixtures/real-world/vvisr-rewards/vvisr.lst \
  --code fixtures/real-world/vvisr-rewards/vvisr-rewards.bin-runtime \
  --contract-addr 0xc9f27a50f82571c1c8423a42970613b8dbda14ef \
  --deploy 0x000000000000000000000000000000000000C0DE:responder-sender \
  --dict-word 0x000000000000000000000000000000000000C0DE \
  --seed 42 --fork-url "$BLOCKMACHINE_RPC_URL" --time-budget 600 --out /tmp/out-x
```

实测：confirmed 689 runs / 106s；`--emit-poc` 产物 `forge test` 绿灯（eth fork + `vm.etch` 真实运行时 + responder `0x…C0DE`）。

### anyswap V4Router（eth `0x6b7a87899490ece95443e979ca9485cbe7e71522`）

Genesis 态 arbitrary_call（router 无外部状态依赖）：

```sh
loom-fuzz run --shard fixtures/real-world/anyswap-v4router/anyswapv4router.lst \
  --code fixtures/real-world/anyswap-v4router/AnyswapV4Router.bin-runtime \
  --seed 42 --max-runs 2000 \
  --dict-word 0x00000000000000000000000022222222222222222222222222222222222222 \
  --emit-poc /tmp/any-poc --out /tmp/out-y
```

实测：4 条命中 confirmed（58/20/58/20 runs）；其中 2 条（`0x1b91a934` / `0x8d7d3eea` 形）L2 PoC `forge test` 绿灯（`[PASS] testExploit()`），另 2 条如实"L2 诚实降级"（定长头零词注入点不足，fail-closed 不硬生成）。

### anyswap V4Router——fork 态 + 攻击代理入口（多合约组合，`fixtures/real-world/anyswap-v4router-fork/`）

真实链上状态（pin 块 26151585）+ caller 链 = ATTACKER → forwarder 代理 → router。完整命令与实测输出见该目录 README；核心链路：fuzz confirmed（`0x1b91a934` @58 runs，seed 2024）→ `replay` 判决一致 → `exploit --fork` 生成 fork profile 工程 → `bash run.sh`（anvil Bearer 代理）`[PASS] testExploit()` 绿灯。

### LiFi Diamond（eth `0x5A9Fd7c39a6C488E715437D7b1f3C823d5596eD1`，pin 块 14420686）

fork 态 + **种子语料确认**（`--seed-calldata`，issue #41 第二阶段）：Diamond 是 EIP-2535 proxy——分析/执行对象是攻击 trace 定位的 **CBridge facet**（在 diamond 地址上执行，facet 存储本就在 diamond 上）。`swapAndStartBridgeTokensViaCBridge` 的 `_swapData[0] = (callTo=USDT, callData=transferFrom(victim, caller, amount))` 单条即 drain（native `sendingAssetId` 免 pull）。实测：confirmed（arbitrary_call 臂 3，267 runs，seed 42）→ replay 一致 → `exploit --fork` 头形外 → replay 模板 → `bash run.sh` `[PASS] testExploit()` 绿灯。完整命令与两阶段记录见 `fixtures/real-world/lifi-diamond/README.md`。

## License

MIT OR Apache-2.0（首个代码提交时附带）。
