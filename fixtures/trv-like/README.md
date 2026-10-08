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

`prestate.json`：serviceRegistry 布置（issue #7）——
`slot = keccak256(abi.encode(0x000000000000000000000000000000000000007d, 0))`
（solc `mapping(address => bool)` 首槽 slot 0），value = 1。
注册 0x…7d 使 `forwardRequest(service = 0x…7d)` 过 registry 检查；
service 无代码，CALL 按 EVM 语义对空账户返回成功（`require(ok)` 过）。
槽值用 foundry cast 求得（注意第一个字必须足 32 字节——address 左填充）：

```sh
cast keccak   0x000000000000000000000000000000000000000000000000000000000000007d  0000000000000000000000000000000000000000000000000000000000000000
# = 0x6515432d9c8ed80ddc22d864380ff3c9b81ae737e57d049dd92abee2d8e1a7da
```

## exploit PoC 生成（M0.6）

```sh
loom-fuzz run --shard fixtures/trv-like/trv-like.lst   --code fixtures/trv-like/TrvLikeRouter.bin-runtime   --prestate fixtures/trv-like/prestate.json   --dict-word 0x7d --emit-poc out/ --out out/
# out/exploit-2429453012-19/ 即机械合成的 Foundry 工程（forge test 绿灯 = 终判）
```
