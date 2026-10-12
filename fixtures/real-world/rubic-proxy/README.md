# rubic-proxy

Rubic Proxy（`0x3335A88bb18fD3b6824b59Af62b50CE494143333`，eth
主网）——2022-12-25 被攻击（~$1.4M）：`routerCallNative` 系列把
`_data` 原样 CALL 到 `params.router`，以受害人对 proxy 的 ERC20
授权完成转移（DeFiHackLabs `src/test/2022-12/Rubic_exp.sol`，
26 个受害地址）。

- 链：Ethereum 主网，pin 块 **16260580**（`0xf81de4`）
- 白名单参考：`getAvailableRouters()` 含 USDC
  （`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`）

## 文件

- `rubic.lst`：loom-evm LoomStore shard（37 函数）。
- `RubicProxy.bin-runtime`：pin 块运行时字节码。
- `seed-routerCallNative.hex`：2-arg `routerCallNative(tuple,bytes)`
    语料种子（`_data = transferFrom(victim, probe, 1e12)` 形，
    机械抄 DHL PoC 形）。
- `seed-e515ae40.hex`：0xe515ae40（9+ 头词变体函数，
    (string,tuple,bytes) 猜测布局）语料种子。

## 检测事实（loom query，mode A/B 一致）

- `arbitrary_call.lq`：`vuln_arbitrary` 1 条——0xe515ae40 step
  54（evidence 退化为 `cast160×3(calldata_word(0x4))`，真实性存疑）。
- `approval_drain.lq`：`deputy_call` 3 条——全部 admin/fee 面
  （sweepTokens / collectIntegratorFee×2，特权函数转代币是设计
  行为）。

## 实跑状态（issue #66 轴 1）：**检测层阻塞**

真正的漏洞函数 `routerCallNative(0x0b6b2d42)` 未被任何谓词命中：
loom decompile 显示其函数体只有 calldata 长度守卫 +
`f0x301d()`（内部 helper），helper 体内的 CALL 未恢复进效果流
（`gen_sink_call` 0 条）。loom-fuzz 以 shard 命中为靶子，漏洞
函数无靶子 = 搜索无从进场。已提上游
[LoomSec/loom-evm#227](https://github.com/LoomSec/loom-evm/issues/227)。

附带发现（evidence）：0xe515ae40 真实形态未解（RouterNotAvailable
守卫在 (string,tuple,bytes) 猜测布局下不通过；白名单含 USDC 说明
checked 词位与猜测布局不符）。loom-evm#227 修复后本目录重测。

## 复现命令

```sh
set -a && . .env && set +a
B=fixtures/real-world/rubic-proxy
loom-fuzz run --shard $B/rubic.lst --code $B/RubicProxy.bin-runtime \
  --contract-addr 0x3335A88bb18fD3b6824b59Af62b50CE494143333 \
  --seed 42 --max-runs 60000 --time-budget 300 \
  --seed-calldata "$(cat $B/seed-routerCallNative.hex)" \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 16260580 --out /tmp/out-rubic
```
