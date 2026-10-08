# vvisr-rewards

Visor Finance **RewardsHypervisor**（vVISR 质押合约）——2021-12-21 被攻击
（约 820 万美元），confused deputy 经典样本：`deposit(visrDeposit, from, to)`
不校验 `from` 即以其名义 mint shares 并任意呼出。

- 链上地址：`0xc9f27a50f82571c1c8423a42970613b8dbda14ef`（见 address.txt）
- 链：Ethereum 主网（⚠️ 不在 Polygon——`.env` 的 `BLOCKMACHINE_RPC_URL`
  若指向 rpc-polygon 会得到空状态；用 CLI 默认 `rpc-eth.blockmachine.io`
  或显式 `--fork-url`）
- 事故链接：
  - https://etherscan.io/address/0xc9f27a50f82571c8423a42970613b8dbda14ef#code
  - https://blog.csdn.net/Timmbe/article/details/123410123（攻击分析）

## 文件

- `vvisr.lst`：loom-evm LoomStore shard（loom 仓库 `loom store` 产物）。
- `vvisr-rewards.bin-runtime`：运行时字节码 hex。
- `address.txt`：地址 + chain + provenance。

## 检测事实（loom query 对拍基线，issue #20）

- `approval_drain.lq`：**deputy_call 1 条**（selector `0x2e2d2984` step
  119，`deposit` 的任意呼出——有 caller 守卫但目标可控）+
  **drain_forward 1 条**（selector `0x21e6b53d` step 12）。
- `arbitrary_call.lq`：`vuln_arbitrary` 1 条（同 selector step 107）。

golden 测试（`crates/cli/tests/golden.rs` + `crates/cli/tests/real_world.rs`）
对拍这两种 pack 的双模式装载行集。

## 来源

2026-10-08 从 BlockMachine `https://rpc-eth.blockmachine.io` 拉取
（`eth_getCode` @ latest），shard 为 loom-evm ingest 产物。
