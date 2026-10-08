# simple fixtures（模式 B 检测的负样本组）

三个小合约，覆盖 arbitrary_call 检测的三类"无命中"形状。源码与
`.bin-runtime` 拷贝自 loom-evm 仓库（`fixtures/example/`，MIT 许可），
shard 由 loom-evm 的 `loom store` 生成。loom-fuzz 不依赖 loom-evm
代码——这里只是分析产物的来源标注。

| 目录 | 来源 | 形状 |
|---|---|---|
| `minibank/` | `loom-evm/fixtures/example/MiniBank.sol` | 噪声样本：owner/ledger 检查，无 arbitrary_call 命中 |
| `public-router/` | `loom-evm/fixtures/example/PublicRouter.sol` | 常量 call 边（DEPUTY/TOKEN 编译期常量）：0 命中 |
| `deputy-vault/` | `loom-evm/fixtures/example/DeputyVault.sol` | caller 受检（`require(msg.sender == operator \|\| whitelisted[msg.sender])`）：0 命中 |

再生成（在 loom-evm 仓库 checkout 旁，LOOM 指向其构建产物）：

```sh
LOOM=/path/to/loom-evm/target/debug/loom
SRC=/path/to/loom-evm/fixtures/example
for base in MiniBank PublicRouter DeputyVault; do
  name=$(echo "$base" | tr 'A-Z' 'a-z' | sed 's/publicrouter/public-router/;s/deputyvault/deputy-vault/')
  cp "$SRC/$base.sol" "$SRC/$base.bin-runtime" "fixtures/simple/$name/"
  "$LOOM" store "fixtures/simple/$name/$base.bin-runtime" \
    -o "fixtures/simple/$name/$name.lst"
done
```

`.bin-runtime` 同时充当双模式装载器的 `code_hex` 输入（运行时字节码
hex 文本）。签入 shard 使 `cargo test` 确定性、无需 loom 二进制
（golden 对拍测试除外：经 `LOOM_BIN` 定位，未设置时跳过）。
