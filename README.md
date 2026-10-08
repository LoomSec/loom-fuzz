# loom-fuzz

Witness fuzzing for EVM bytecode, guided end-to-end by [loom-evm](https://github.com/LoomSec/loom-evm)'s static analysis.

loom-evm 的检测命中是精确的 `(函数, 帧, 证据表达式)` 三元组。loom-fuzz 把三元组的每一列编译成闭环的一个角色——种子、目标、判决——回答唯一重要的问题：**这条命中真实可达吗，见证输入是什么？**

| 命中列 | 在闭环中的角色 |
|---|---|
| 函数 selector | 种子 calldata 头（怎么进场） |
| 帧 | 定向目标 PC 集合（往哪走） |
| 证据表达式 | oracle——到帧后在具体 trace 上求值，为真即见证（到场后验什么） |

三个输入同源同词汇，不存在"找到的洞和报的洞是不是同一个"的对齐问题。

## 判决（三值，fail-closed）

- **confirmed** — 见证复现，`poc.json` 可一键重放
- **unreachable** — 预算耗尽未到达该帧（FP 候选，降级不消灭）
- **inconclusive** — 燃料/步数截断，如实报告，绝不硬判

无见证 ⇒ 只降级，不过滤。

## 输入从哪来

loom-evm 反编译产出的静态事实直接编译成 fuzz 的输入空间：

- 种子：支配 guard 的代数形状反解为精确初始输入（selector、guard 常量、边界值 999/1000/1001 型、caller、存储槽）
- 值字典：证据表达式里的常量、白名单成员、注册表槽键
- 定向：帧 → PC 距离表，距离缩小的输入保留进化

静态知道的一切，fuzzer 进场时就带着；剩下的未知量（存储根、外部调用响应）才是 fuzz 的搜索空间。

## 里程碑

- **M0**：单合约、纯字节码、单交易见证闭环，arbitrary_call 族先行；验收 = TRV 样本出 confirmed、噪声行出 unreachable
- **M1+**：多检测族推广、存储根 RPC 注入、（后续）多交易状态ful 与 fork 场景

## License

MIT OR Apache-2.0（首个代码提交时附带）。
