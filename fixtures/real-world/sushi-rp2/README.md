# sushi-rp2

SushiSwap **RouteProcessor2**（`0x044b75f554b886A065b9567891e45c79542d7357`，
eth 主网）——2023-04-09 被攻击（~$3.3M）：`processRoute` 系列不校验
用户输入 `route` 的 pool 字段 + `uniswapV3SwapCallback` 无 caller
校验，攻击者以假 pool 触发回调，借受害人对 RP2 的 WETH 授权完成
转移（DeFiHackLabs `src/test/2023-04/Sushi_Router_exp.sol`）。

- 链：Ethereum 主网，pin 块 **17007841**（攻击块）
- 受害地址：`0x31d3243CfB54B34Fc9C73e1CB1137124bD6B13E1`（WETH 授权给 RP2）
- 参考 tx：`0x04b166e7b4ab5105a8e9c85f08f6346de1c66368687215b0e0b58d6e5002bc32`

## 文件

- `rp2.lst`：loom-evm LoomStore shard（loom store 产物）。
- `RouteProcessor2.bin-runtime`：pin 块运行时字节码。
- `seed-processRoute.hex`：processRoute 语料种子（route 编码
  pool = 0x0000…c0de01 假池，机械抄 DHL PoC 形）。
- `seed-callback.hex`：uniswapV3SwapCallback 直调语料种子
  （(100e18, 0, abi.encode(WETH, victim)) 形）。
- `callbacker-runtime.hex`：假池攻击合约 runtime（手写 EVM，
  634B）：swap() 被调时硬编码两次呼出——
  `uniswapV3SwapCallback(WETH, victim)` + `WETH.transfer(probe,
  100e18)`。语料层补法：两次硬编呼出零引擎改动（通用 reenter
  模板见 loom-fuzz#68）。

## 检测事实（loom query，mode A/B 一致）

- `arbitrary_call.lq`：`vuln_arbitrary` 9 条——0x2646478b
  （processRoute）×4，evidence `cast160(calldata_word(0x44))`
  （route 内 pool 词）；0x93b3774c ×5。
- `approval_drain.lq`：`deputy_call` 2 条（uniswapV3SwapCallback
  0xfa461e33 / tridentCLSwapCallback 0xe2a7b501，evidence =
  route 尾词 cast160）。

## 实跑状态（issue #66 轴 1）

- #71 修复前：7 个退化 confirmed（call to 0x0 的 trivial 匹配）
  ——已全部消除；#72 后重搜零假 confirmed。
- 真实获利 witness（假池触发回调 + WETH 转移的组合形态）：搜索
  中。结构性观察：deputy callback 命中只能靠顶层直调到场，
  真重入路径的回调发生在 processRoute 步帧内——通用 reenter
  部署模板（loom-fuzz#68）落地前，callbacker 手写 runtime 是
  唯一语料通道。

## 复现命令

```sh
set -a && . .env && set +a
B=fixtures/real-world/sushi-rp2
loom-fuzz run --shard $B/rp2.lst --code $B/RouteProcessor2.bin-runtime \
  --contract-addr 0x044b75f554b886A065b9567891e45c79542d7357 \
  --seed 42 --max-runs 100000 --time-budget 600 --max-steps 3 \
  --seed-calldata "$(cat $B/seed-processRoute.hex)" \
  --seed-calldata "$(cat $B/seed-callback.hex)" \
  --deploy 0x0000000000000000000000000000000000c0de01:$(cat $B/callbacker-runtime.hex) \
  --dict-word 0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 \
  --dict-word 0x00000000000000000000000031d3243cfb54b34fc9c73e1cb1137124bd6b13e1 \
  --dict-word 0x0000000000000000000000003333333333333333333333333333333333333333 \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 17007841 --out /tmp/out-sushi
```
