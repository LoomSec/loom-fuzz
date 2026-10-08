# anyswap-v4router

Anyswap V4 Router（Multichain 系）——真实生产路由器字节码，arbitrary
call + approval deputy 混合形态样本。

- 链上地址：**未随样本记录**（见 address.txt——/tmp/real-cases 提供物
  无地址元数据，本目录不臆造未验证值）。
- 链：Ethereum 主网（来源标注；Genesis 回归（`loom-fuzz run` 不带
  `--fork-url`）不需要网络，fork 态用 CLI 默认
  `rpc-eth.blockmachine.io`）
- 背景链接：
  - https://rekt.news/multichain-rekt/（Multichain 系风险背景）

## 文件

- `anyswapv4router.lst`：loom-evm LoomStore shard。
- `AnyswapV4Router.bin-runtime`：运行时字节码 hex。
- `address.txt`：地址 + chain + provenance。

## 检测事实（loom query 对拍基线，issue #20）

- `approval_drain.lq`：**deputy_call 11 条**（0x0175b1c4×3 / 0x25121b76×2
  / 0x3f88de89×2 / 0x456862aa / 0x825bb13c / 0x87cc6e2f×2）+
  **drain_forward 0 条**。
- `arbitrary_call.lq`：`vuln_arbitrary` 20 条。
- Genesis 回归基线（issue #20 前已钉）：4 条臂 1 confirmed（selector
  0x1b91a934×3 / 0x241dc2df，best_runs 58/20/58/20）。

golden 测试对拍这两种 pack 的双模式装载行集。
