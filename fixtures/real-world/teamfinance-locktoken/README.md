# TeamFinance LockToken——真实多步攻击案例探索（issue #41）

Team Finance **LockToken**（proxy `0xE2fE530C047f2d85298b07D9333C05737f1435fB`，
实现 `0x48d118c9185e4dbafe7f3813f8f29ec8a6248359`，eth 主网）——
2022-10-27 被攻击（~$15.8M）：`migrate(id, params, …)` 的
`params.token0/token1/recipient/sqrtPriceX96` 全可控且无 caller
守卫，把 LockToken 代持的 UniV2 LP 迁到攻击者指定 V3 仓位。真实
事件本身就是**多交易**：`lockToken()`（拿 NFT lock id）+ 4 笔
`extendLockDuration`（使 unlockTime 满足 migrate 条件）+ `migrate`。

- 链：Ethereum 主网，pin 块 **15837893**（`0xf1aac5`——注意
  任务初期给的 `0xf1c225` = 15837989 有误，以十进制为准）
- 攻击 tx：`0xb2e3ea72d353da43a2ac9a8f1670fd16463ab370e563b9b5b26119b2601277ce`
- 参考：DeFiHackLabs `src/test/2022-10/TeamFinance_exp.sol`
  （`preWorks()` 与 `testExploit()` 天然映射多步 witness）

## 关键事实：漏洞在实现合约，不在 proxy（同 LiFi Diamond 教训）

trace（debug_traceTransaction + callTracer）显示
`CALL proxy → DELEGATECALL 0x48d1…8359`——分析/执行对象是**实现
合约运行时**（在 proxy 地址上执行，存储 = proxy 真实存储）。

## 族命中分析（主要风险点的实跑结论）

`arbitrary_call.lq` + `approval_drain.lq` 对 **proxy** shard 的命中
全是 transparent admin 面（upgradeTo/changeAdmin/admin/
implementation——设计本意，与漏洞无关）。对**实现** shard：

- `vuln_arbitrary`（臂 1 目标可控）×3，其中 **migrate
  （0xb86f3ea6）step 62 命中**：evidence = `cast160(calldata_word(0x84))`
  ——族可容纳 ✓（arm1 判定自动对齐 evidence 槽与 decoder）。
- `deputy_call` 0、`drain_forward` 0——"特权 migrate 缺 caller
  守卫 + 输入派生 recipient"形态不在 deputy（要求 caller 守卫在
  场）/drain 谓词覆盖内；arm1 容纳已足够。

**坑**：mode A（loom query）在此 shard 上报 `undeclared predicate
word_neg`（loom-evm 侧，release 二进制）——本案例全走 mode B
（纯 shard 内置推导），装载产物与命中分析已用 dump 探针钉死。

## witness 构造（机械，零个案）

| 步 | 调用 | 关键参数 |
|---|---|---|
| 1 | `lockToken{value:0.5ETH}` | selfmadeToken, 1e9, unlockTime=ts+5 → 铸出 NFT id（pin 块实测 **15328**，逐 id 扫描探针定位） |
| 2 | `extendLockDuration(15328, ts+40005)` | 满足 migrate 的 unlockTime 条件 |
| 3 | `migrate(15328, params, true, sqrtPriceX96, _mintNFT)` | params 照抄 PoC；**词 4（_mintNFT 槽）填 selfmadeToken 地址**——arm1 evidence=cast160(词4) 与 migrate 步 pc 8143 处 STATICCALL(selfmadeToken) 目标对齐（机械槽对齐，非语义 hack） |

通用引擎缺口与补齐（本 PR）：`--seed-calldata` 增加 `@<wei>`
后缀携带 msg.value（payable 前置步；lockToken 需 0.5 ETH 锁定费）。

## 复现命令

```sh
set -a && . .env && set +a
B=fixtures/real-world/teamfinance-locktoken
 loom-fuzz run --shard $B/teamfinance-impl.lst --code $B/TeamFinanceLockToken-impl.bin-runtime \
  --contract-addr 0xE2fE530C047f2d85298b07D9333C05737f1435fB \
  --seed 42 --max-runs 60000 --time-budget 900 --max-steps 3 \
  --seed-calldata "$(cat $B/seed-lockToken.hex)@500000000000000000" \
  --seed-calldata "$(cat $B/seed-extendLockDuration.hex)" \
  --seed-calldata "$(cat $B/seed-migrate.hex)" \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 15837893 --out /tmp/out-tf
```

## 实测记录（如实）

- ✅ 字节码/shard/族命中/witness 逐步执行（探针）：3 步序列
  `[lock ✓, extend ✓, migrate 到场 ✓(pc 8143 经过，后续 V3
  createPool revert——L1 定罪不需整笔成功)]`。
- ✅ lockToken 的 5 个 arm1 hit 全部 confirmed（441–1318 runs）。
- ⚠️ **migrate hit（0xb86f3ea6 step 62）的 confirmed 未达成**：
  真 3 步序列的搜索组装未在预算内拼出。已识别的搜索层机制
  （非 bug，如实记录）：
  1. **pc 数值跨函数重叠**——lockToken 单步同样经过 pc 8143
     （同合约多函数的 pc 空间共享数值），造成"假到场"被命中后
     择优窗口（POST_HIT 1536 runs）吸收搜索时间；
  2. 真 3 步需 append/splice 精确拼序 `[lock, extend, migrate]`，
     在窗口内未出现（组合概率 × fork 执行速度）。
- ✅ 单步对照（`--max-steps 1` 同语料同预算）：migrate 单步
  unreachable（id 前提不存在 + 无前置状态）——多步必要性成立。
- L3 PoC：未达（migrate confirmed 未出，无 poc 可合成）。

后续方向（搜索层通用改进，不进个案）：到场帧归属（Hit 带
selector 的 pc 空间过滤—— witness 步的 selector 与 hit selector
一致性检查，消除跨函数假到场）；POST_HIT 窗口对"择优冠军含
目标步"的动态延长。

## 文件

- `TeamFinanceLockToken.bin-runtime` / `teamfinance.lst`：proxy（留档）。
- `TeamFinanceLockToken-impl.bin-runtime` / `teamfinance-impl.lst`：分析/执行对象（实现）。
- `seed-*.hex`：三步语料（cast calldata 机械编码）。
- `address.txt`：proxy 地址。
