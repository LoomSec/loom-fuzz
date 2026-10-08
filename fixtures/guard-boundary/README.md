# GuardBoundaryRouter fixture

`GuardBoundaryRouter.sol` 是 seed 编译器的 golden 样本：同一函数里
同时含两类可解 guard——

- `require(amount < 1000)`：`<` 边界家族（值字典收 999/1000/1001，
  每个边界值生成一个种子变体）；
- `require(nonce == 0x42)`：`==` calldata 等值（nonce 槽固定 0x42）；
- `require(services[service])`：registry 成员测试（mapping 派生键，
  静态不可解——assumption 如实记录，留搜索空间）。

`service.call(request)` 是 arbitrary_call 臂 3 裸转发（有命中）。

`.abi` / `.bin-runtime` / `guard-boundary.lst` 均签入，由 solc 0.8.19 +
loom-evm 的 `loom store` 生成：

```sh
solc --optimize --optimize-runs 200 --metadata-hash none \
  --bin-runtime --abi -o fixtures/guard-boundary --overwrite GuardBoundaryRouter.sol
loom store fixtures/guard-boundary/GuardBoundaryRouter.bin-runtime \
  -o fixtures/guard-boundary/guard-boundary.lst
```

签入的 shard 使 `cargo test` 保持确定性、不需要 solc 与 loom 二进制。
