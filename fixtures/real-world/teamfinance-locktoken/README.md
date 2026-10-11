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

### 钉环境复验（PR #59 BlockEnv 钉 pin 块后，issue #41 收尾）

- ✅ **migrate 多步 confirmed 达成**（钉 timestamp=1666855379）：
  - seed 42：confirmed @3560 runs（poc-3094298278-62，3 步
    [lock(0.5ETH), migrate, migrate(junk)]，有效 witness 前 2 步）。
  - seed 2024：confirmed @4434 runs（2 步 [lock(0.5ETH), migrate]）。
- ✅ **witness 语义健全**（forge 直接调试，pin 块 fork 态真实
  proxy）：两个 seed 的 setup 步 lockToken 均真实成功——
  unlockTime = **1666855384 = pin_ts + 5**（守卫比较把 pin 块
  时间戳喂进 cmp 池，搜索把词推到 1.6e9 量级，裕量 5 秒）；
  `Soundness` forge 测试 2/2 PASS（step0 成功 + step1 可执行）。
- ✅ **L3 fork 直通绿灯（issue #61，pocgen 环境保真）**：
  `loom-fuzz exploit --fork` 生成 fork 直通工程（不 etch 分析对象，
  pin 块 15837893 真链上状态 = 执行环境）+ L1-only 终点断言（价值
  形态超出 ERC20 drain 模型——migrate 的 LP 迁移/V3 仓位形态，
  机械判定零个案）。forge 真跑 **PASS**：
  - step0 lockToken **真实成功**（proxy 部署态在场：真实 USDT
    decimals 查询、真实价格预言机 STATICCALL、selfmadeToken
    transferFrom、`Deposit` NFT 15328——完整 delegatecall 路径）；
  - step1 migrate 执行后经 `StepOutcome` 如实 emit（L3 调用方 =
    Attacker 合约 ≠ witness caller 0x3333…，迁移的 sender 守卫
    revert——臂后 revert 合法，oracle L1 语义不依赖整笔成功）；
  - 价值断言局限工程内明确标注「形态超出 ERC20 模型，仅 L1」，
    臂证据资产（selfmadeToken）余额变化经 `AffectedAssetBalance`
    事件展示。
  - 注意：poc-3094298278-62 原始 step0 的 unlockTime=12396 是
    timestamp=0 旧环境的搜索产物（L1 到场语义下过守卫的方式），
    直通 pin 块环境会如实 "Invalid unlock time" revert；按本文件
    上文 Soundness 验证书形换入 unlockTime=0x635a31d8（pin_ts+5）
    后全绿——witness 语义健全性 #41 已独立确认，非 pocgen 缺陷。
- ✅ 单步对照（--max-steps 1，seed 42）：migrate unreachable
  （21038 runs）——多步必要性成立。

### 历史记录（#52–#58 探索期，timestamp=0 旧环境）

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

### 价值影响层（PR #64，issue #64 通用设计——禁止 case-by-case）

- ✅ **L3 fork 直通工程 forge 绿灯**：`exploit poc --fork` 生成
  ProfitTest——witness 逐字重放（prank witness caller）× 受益槽
  候选注入（payload 头词 address 形词逐候选 fresh fork 试执行）×
  三族资产级 delta 断言（ERC20 balanceOf / ETH 余额 / ERC721
  ownerOf）。实测（seed 2024 migrate poc，13 条 trace 资产清单）：
  `CandidateTried(profit: true, "ETH:recipient-balance")`——
  重放中协议向 witness caller（0x3333…33）净流入 > 0.5 ETH
  （lock 0.5 ETH 支出后的净正流入）；其余资产逐资产
  `AssetUnaffected` 标注。run.sh pin 块 fork 下 1/1 PASS。
- ✅ 逐资产标注分支同样实测：旧 poc（无 trace_calls，清单退化
  为定罪目标单资产）+ 无获利候选 = 红灯 + 全程 Candidate*/
  AssetUnaffected 标注（诚实，不伪造绿灯）。
- 生成工程见 `/tmp/tf-profit-l3b`（绿灯）/ `/tmp/tf-profit-l3`
  （标注分支，均临时目录，重生成可复现）。
