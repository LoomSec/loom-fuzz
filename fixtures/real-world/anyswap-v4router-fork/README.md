# anyswap V4Router——fork 态 + 攻击代理入口（多合约组合）

eth 主网 `0x6b7a87899490ece95443e979ca9485cbe7e71522`，pin 块 26151585。
与 `../anyswap-v4router/`（Genesis 态）不同：本案例在**真实链上状态下**
确认命中，且 witness 经**攻击代理合约**（`forwarder` 模板，`--entry`）
进场——caller 链 = ATTACKER → 代理 → router，多合约组合在场
（responder + forwarder + victim）。issue #40 签入。

## 产物

- `anyswapv4router.lst` / `AnyswapV4Router.bin-runtime`：loom-evm shard 与运行时
- `poc-462530868-26.json`：`anySwapOutUnderlyingWithPermit`（0x1b91a934）
  confirmed @58 runs（seed 2024），臂 1 目标可控，fork 块 26151585，
  entry=forwarder，replay 一致
- `poc-3988649442-40.json`：另一 9 槽 permit 形（0x8d7d3eea）confirmed @20 runs

## 复现

```sh
set -a && . .env && set +a   # BLOCKMACHINE_RPC_URL / BLOCKMACHINE_API_KEY
export LOOM_BIN=<loom-evm 二进制>

# ① 定向 fuzz（命中是随机的，confirmed 通常在百 runs 内出现；
#    debug loom 跑全 shard 较慢，release 更快）
loom-fuzz run --shard fixtures/real-world/anyswap-v4router-fork/anyswapv4router.lst \
  --code fixtures/real-world/anyswap-v4router-fork/AnyswapV4Router.bin-runtime \
  --contract-addr 0x6b7a87899490ece95443e979ca9485cbe7e71522 \
  --seed 2024 --max-runs 60000 --time-budget 300 \
  --dict-word 0x0000000000000000000000002222222222222222222222222222222222222222 \
  --deploy 0x000000000000000000000000000000000000C0DE:responder \
  --deploy 0x00000000000000000000000000000000c0de0001:forwarder \
  --entry 0x00000000000000000000000000000000c0de0001 \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 26151585 \
  --out /tmp/out-any-fork

# ② replay 判决一致
loom-fuzz replay fixtures/real-world/anyswap-v4router-fork/poc-462530868-26.json \
  --code fixtures/real-world/anyswap-v4router-fork/AnyswapV4Router.bin-runtime

# ③ L2 PoC 合成（fork profile：run.sh = anvil Bearer 代理 + forge test）
loom-fuzz exploit fixtures/real-world/anyswap-v4router-fork/poc-462530868-26.json \
  --code fixtures/real-world/anyswap-v4router-fork/AnyswapV4Router.bin-runtime \
  --out /tmp/any-fork-l2 --fork
cd /tmp/any-fork-l2 && bash run.sh   # [PASS] testExploit()
```
