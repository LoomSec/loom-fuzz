# socket-route

SocketGateway **routeId 406 漏洞路由**（
`0xCC5fDA5e3cA925bd0bb428C8b2669496eE43067e` 实现，入口网关
`0x3a23F943181408EAC424116Af7b7790c94Cb97a5`，eth 主网）——
2024-01-16 被攻击（~$3.3M）：新上线路由的 `performAction` 把
`swapExtraData` 原样 CALL 到 `fromToken`，借受害人对 **网关** 的
USDC 授权完成转移（DeFiHackLabs
`src/test/2024-01/SocketGateway_exp.sol`；漏洞在路由不在网关——
同 LiFi Diamond facet 教训）。

- 链：Ethereum 主网，pin 块 **19021453**（攻击块）
- 受害地址：`0x7d03149A2843E4200f07e858d6c0216806Ca4242`
- 授权模型：受害 approve 给**网关** → 执行必须经网关
  `executeRoute(406, routeData)`（delegatecall 上下文），
  直接 fuzz 路由合约破坏授权模型。

## 文件

- `socket-route.lst`：漏洞**路由**合约 shard（12 函数）——检测
  事实丰富（见下），但执行路径须走网关。
- `socket-gateway.lst`：网关 shard（218 函数，2.8MB）——可执行
  目标（授权模型正确），检测命中落在路由表/delegatecall 面。
- `SocketVulnRoute.bin-runtime` / `SocketGateway.bin-runtime`：
  pin 块运行时字节码。
- `seed-executeRoute.hex`：`executeRoute(406, routeData)` 语料
  种子（routeData = performAction(USDC, USDC, 0, probe, 0,
  transferFrom(victim, probe, 1e12)) 形，机械抄 DHL PoC 形）。

## 检测事实（loom query）

- 路由 shard：`vuln_arbitrary`/`vuln_drain`/`drain_forward` 齐——
  performAction（0x7899f9ed）step 33/80 的 swapExtraData 切片
  （`b_calldata_slice(+(calldata_word(0xa4), 0x4), 0x20)`）=
  真实漏洞形。
- 网关 shard：783 hits（大头是路由表查找/delegatecall 面），
  无直接漏洞形——**两 shard 分裂：检测在路由、可执行性在网关**。

## 实跑状态（issue #66 轴 1）：分析中

- 网关 fuzz（executeRoute 种子）：60k runs × 各 hit 未到场——
  routeId 406 的路由表查找 + delegatecall 深链，搜索预算待加长。
- 架构观察：检测 shard 与执行 shard 分裂是本案例的结构性特征
  （facet/route 类漏洞普遍），值得评估"以路由 shard 制导、网关
  地址执行"的跨 shard 装载形态（新 issue 待开）。

## 复现命令

```sh
set -a && . .env && set +a
B=fixtures/real-world/socket-route
loom-fuzz run --shard $B/socket-gateway.lst --code $B/SocketGateway.bin-runtime \
  --contract-addr 0x3a23F943181408EAC424116Af7b7790c94Cb97a5 \
  --seed 42 --max-runs 60000 --time-budget 300 \
  --seed-calldata "$(cat $B/seed-executeRoute.hex)" \
  --dict-word 0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 \
  --dict-word 0x0000000000000000000000007d03149a2843e4200f07e858d6c0216806ca4242 \
  --dict-word 0x0000000000000000000000003333333333333333333333333333333333333333 \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 19021453 --out /tmp/out-socket
```
