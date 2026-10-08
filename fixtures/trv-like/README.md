# TrvLikeRouter fixture

`TrvLikeRouter.sol` 是 TRVRouter 形状的语义样本：注册表解析的 service、
裸 calldata 转发、无 caller/签名校验（2026-10-07 TRV 根因类：
计划中的签名校验从未实现）。真实 TRV 字节码进 fixtures 受阻见 #11，
本合约形状等价先行。

`.abi` / `.bin-runtime` / `trv-like.lst` 均签入，由 solc 0.8.19 + loom-evm
的 `loom store` 生成：

```sh
solc --optimize --optimize-runs 200 --metadata-hash none \
  --bin-runtime --abi -o fixtures/trv-like --overwrite TrvLikeRouter.sol
loom store fixtures/trv-like/TrvLikeRouter.bin-runtime \
  -o fixtures/trv-like/trv-like.lst
```

签入的 shard 使 `cargo test` 保持确定性、不需要 solc 与 loom 二进制
（golden 对拍测试除外：它通过 `LOOM_BIN` 环境变量定位 loom 二进制，
未设置时自动跳过）。
