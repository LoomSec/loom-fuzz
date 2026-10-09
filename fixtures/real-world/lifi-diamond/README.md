# LiFi Diamond——fork 态单 tx 任意呼出 drain（issue #41）

LiFi **Diamond**（`0x5A9Fd7c39a6C488E715437D7b1f3C823d5596eD1`，eth
主网）——2022-03-20 被攻击（约 60 万美元）：`swapAndStartBridgeTokensViaCBridge`
的 `_swapData[]` 里 `callTo.call(callData)` 全可控；29 个受害钱包历史
approve 过 Diamond（fork 态 allowance 真实存在），`_swapData[1..]` 填
`callTo=受害代币, callData=transferFrom(victim, attacker, amount)` 即 drain。

- 链：Ethereum 主网，pin 块 **14420686**（`0xdc0ace`；攻击 tx
  `0x4b4143cbe7f5475029cf23d6dcbb56856366d91794426f2e33819b9b1aac4e96`
  在其后一块 14420687）
- 事故链接：
  - https://etherscan.io/address/0x5A9Fd7c39a6C488E715437D7b1f3C823d5596eD1
  - DeFiHackLabs 参考 PoC：`src/test/2022-03/LiFi_exp.sol`

## 关键事实：漏洞在 facet，不在 proxy 字节码

Diamond 是 EIP-2535 proxy（`lifi.bin-runtime` 只有 fallback 分发，
loom 对其出的是"按 selector 查 facet 表 delegatecall"的命中——Diamond
的**设计本意**，非漏洞）。攻击 trace（debug_traceTransaction +
callTracer）显示 `swapAndStartBridgeTokensViaCBridge` 的第一次
DELEGATECALL 目标是 **CBridge facet `0x73a499e043b03fc047189ab1ba72eb595ff1fc8e`**——
`_swapData` 解析与 `callTo.call(callData)` 都在 facet 内。

因此本案例的分析/执行对象是 **facet 运行时**（在 diamond 地址上执行：
fork 态 executor 把 facet 字节码 etch 进 overlay，`address(this)` =
diamond、存储 = diamond 的真实存储——EIP-2535 的存储本就活在
diamond 上）：

- `lifi-cbridge-facet.bin-runtime` / `lifi-cbridge-facet.lst`：facet
  运行时与 loom shard（`loom store` 产物）。
- `lifi.bin-runtime` / `lifi.lst`：proxy 运行时与 shard（留档对拍：
  proxy 只有 1 函数 fallback，loom 命中是 facet 表查找——非本案例
  目标）。

## 检测事实（loom query 对拍基线）

`arbitrary_call.lq` + `approval_drain.lq` 对 facet shard：

- `vuln_arbitrary` **4 条**（全部 selector `0x01c0a31a`，step
  339/444/466/483）——evidence = `cast160(bytes_word(b_calldata_slice(…)))`
  即 `_swapData[k].callTo` 从 calldata 派生后裸呼出（臂 1 目标可控）。
- `drain_forward` 1 条（step 339）——呼出 input 含 calldata 派生切片。

## 文件

- `lifi-cbridge-facet.lst` / `lifi-cbridge-facet.bin-runtime`：分析/执行对象（CBridge facet）。
- `lifi.lst` / `lifi.bin-runtime`：Diamond proxy（留档）。
- `address.txt`：Diamond 地址。
- `poc-*.json`：confirmed witness（fuzz 产物，force-add）。

## 复现

```sh
set -a && . .env && set +a
export LOOM_BIN=<loom-evm release 二进制>

loom-fuzz run \
  --shard fixtures/real-world/lifi-diamond/lifi-cbridge-facet.lst \
  --code fixtures/real-world/lifi-diamond/lifi-cbridge-facet.bin-runtime \
  --pack <loom-evm>/packs/detect/arbitrary_call.lq \
  --pack <loom-evm>/packs/detect/approval_drain.lq \
  --loom-bin "$LOOM_BIN" \
  --contract-addr 0x5A9Fd7c39a6C488E715437D7b1f3C823d5596eD1 \
  --seed 42 --max-runs 60000 --time-budget 300 \
  --dict-word 0x0000000000000000000000002222222222222222222222222222222222222222 \
  --dict-word 0x000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7 \
  --dict-word 0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 14420686 \
  --out /tmp/out-lifi
```

## 盲搜第三阶段记录（issue #46 ABI 自洽化算子，如实）

引擎新增**通用 ABI 自洽化变异算子**（`crates/fuzz/src/abifix.rs`）：
结构感知重编码（头偏移槽重绑定 + 段内层偏移递归修复 + 退化零槽
材料复制共享/形状双假设合成），配比 4%（变异环 80..=83 带）；配合
**命中后择优继续**（到场后继续 ≤1536 runs，按目标 pc 后 CALL 族
效果数择优——语义自洽到场 vs 退化到场的进化信用代理，判决独立）。

单会话探针（fork 态直跑算子产物）证明**路径存在**：全零 16 词尾的
退化父代经 verbatim 形修复后 **reached=true**（pc 1413 CALL 执行，
evidence 与 decoder 读同一槽位——臂 1 可判）。但全管线盲搜 2 轮
× 3 seeds（42/2024/7 × 60k runs × 300s，与 #41 同量级预算）未在
到场后窗口内命中该父代形态——corpus 缺少"≥8 词近零尾"的父代
（尾词靠 extend 算子零词累积，谱系还要保零头），joint 概率在窗口
内不足：

```
===== seed 42 / 2024 / 7（同形态）=====
29401882: unreachable — 到场但证据谓词不成立：target pc 1413 后 1 条 call（CALL）：
          臂 3 input 非 calldata 子串；臂 1 target ≠ cast160(evidence)
29401882: unreachable — 预算耗尽未到达目标帧（60000 runs）
```

结论：算子按设计工作（探针钉死），搜索动力学未在预算内走到自洽
谱系——**盲搜 confirmed 未达成**（诚实报告）。嵌套 ABI 盲搜的已知
剩余缺口：尾材料结构化（零偏置 extend / 段材料池注入）。回归基线
对照：anyswap genesis 命令在 main（d283021）复跑同样全部
unreachable（环境与记录漂移，与本算子无关）；vvisr fork 态复跑
confirmed 473 runs（健康）。

## 种子语料确认（issue #41 第二阶段，--seed-calldata）

通用种子语料注入 `--seed-calldata <0x-hex>`（PR #45）：完整
calldata 原形态直接进初始种子群体（AFL 种子语料同款概念，与
`--dict-word` 单槽填词互补，引擎零个案）。LiFi 攻击 calldata 经
`cast calldata` 按真实函数签名编码（**LiFiData 是含 string 的元组
→ 整体动态编码头**，三层偏移：头 3 偏移词 → LiFiData → swapData
数组 → 元组内层 callData），`_swapData[0]` =
`(callTo=USDT, sendingAssetId=0(native 免 pull), fromAmount=0,
callData=transferFrom(victim 0x8de133…fd7d1, caller, 0x2a3c4547b2))`——
victim/额度取 DeFiHackLabs PoC 的 USDT 项（pin 块 allowance 真实）。

```sh
loom-fuzz run \
  --shard fixtures/real-world/lifi-diamond/lifi-cbridge-facet.lst \
  --code fixtures/real-world/lifi-diamond/lifi-cbridge-facet.bin-runtime \
  --pack <loom-evm>/packs/detect/arbitrary_call.lq \
  --loom-bin "$LOOM_BIN" \
  --contract-addr 0x5A9Fd7c39a6C488E715437D7b1f3C823d5596eD1 \
  --seed 42 --max-runs 20000 --time-budget 120 \
  --dict-word 0x0000000000000000000000002222222222222222222222222222222222222222 \
  --seed-calldata "$(cat fixtures/real-world/lifi-diamond/seed-swapAndStartBridgeViaCBridge.hex)" \
  --fork-url "$BLOCKMACHINE_RPC_URL" --fork-block 14420686 \
  --out /tmp/out-lifi
```

实测（第二阶段）：

- **confirmed**：`29401882 (267 runs) → poc-29401882-339.json`——
  arbitrary_call **臂 3**（`callTo.call(callData)` 的 input = calldata
  子串）+ drain_forward 族同证据（双 pack 跑时同 selector+step 的
  poc 文件名相抵，签入的 poc 为 arbitrary 族）。
- **replay 一致**：`{"verdict":"confirmed",…}` exit 0。
- **L2 fork 绿灯**：`exploit --fork` → 头形解析对三层嵌套尾判
  BadShape（头词无定罪目标交叉）→ fork 态通用 replay 模板 →
  `bash run.sh` → `[PASS] testExploit()`。整笔 witness 在 drain 后的
  bridge 步按原路径 revert（到场证据不受整笔结局影响；replay 模板
  已改低层 call + `require(!ok)` 断言——既绕过 forge 对内存形
  revert 载荷的解码崩溃，又保持 fail-closed：整笔成功 = 红灯）。
- drain_forward 族的 drain 模板 L2（`require(ok)` 绑整笔成功）对
  本案例如实不适用（witness 同形必 revert）——用 arbitrary 族的
  replay 模板达成绿灯，drain poc 不再签入。

对比第一阶段（无种子语料）：7 轮 fuzz 到场但退化形态（callTo=0）
定罪失败；第二阶段种子进场后 **267 runs 确认**（前 266 runs 为排
队中的编译/基座种子，语料自身第 1 次执行即到场）。

## 实测记录（issue #41 第一阶段，如实）

**检测与到场达成，confirmed 未达成**——7 轮 fork 态 fuzz（seed
42/2024 × 字典词组合 × 60k–200k runs）的结果稳定可复现：

- **到场 ✅**：搜索可靠到达 step 339 的目标帧（target pc 1413，
  `callTo.call(callData)` 处），见证 trace 记录到该处真实 CALL。
- **定罪 ❌**：到场见证的 `_swapData[0]` 语义退化——`callTo = 0`、
  `callData` 空（`address(0).call("")`），臂 3（input ≥4B 子串）与
  臂 1（target ≠ cast160(evidence)）均不成立，oracle 如实判
  unreachable（fail-closed 按设计工作）。
- **卡点（能力边界，非 bug）**：`_swapData` 是**三层嵌套动态 ABI**
  （头 2 偏移词 → 数组 → 元组 → 内层 bytes 偏移），变异器随机装配出
  语义自洽尾的概率在预算内不足；退化形态（全零指针）反而被
  Solidity decoder 宽容接受到达目标帧——fitness 无法区分两种"到场"。
- **本轮修复的真实缺口**：基座/字典变体的头槽上限 9 → **12**——
  LiFi（8 LiFiData + 2 偏移 = 10 槽）与 Rubic `routerCall`（8 元组 +
  router + 偏移 = 10 槽）的函数头超出旧上限会让指针槽永远缺一词
  （已修，见 `crates/cli/src/main.rs` 的 abi_base_seeds/
  dict_slot_variants）。修复后 LiFi 仍停在同退化形态，根因是嵌套
  尾自洽性而非头宽。
- **Rubic 备选**（`0x3335A88bb18fD3b6824b59Af62b50CE494143333`，pin
  16260580 = `0xf81de4`）：shard 出 `vuln_arbitrary` 1 条
  （`routerCall`，evidence = 头槽 0，定长头形应更易）+ `deputy_call`
  3 条；2 轮 fuzz（12 槽头修复后）均未到场——同 ABI 自洽性卡点。

后续方向（不进引擎个案逻辑）：嵌套 ABI 的通用尾装配增强（如基于
cmp 池偏移语义的指针修复算子），或 witness 字典补充真实攻击
calldata 形态作为种子（fixture 层补法，合规）。

