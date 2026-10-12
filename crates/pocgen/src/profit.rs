//! 价值影响层（issue #64，通用设计——禁止 case-by-case）：
//!
//! **判别原则**：pocgen 永远合成"调用序列 + 槽注入 + delta 断言"，
//! 从不从"协议怎么被偷"出发；协议特定语义只从 witness 本身读。
//!
//! 四层机械结构：
//! 1. **资产清单**：witness trace 触及地址 ∪ 定罪呼出目标（去重）；
//!    分叉直通下逐资产运行时探测（ERC20 balanceOf / ERC721
//!    ownerOf / ETH），不认识的形态逐资产标注——不加协议语义。
//! 2. **受益槽定位**：payload 头词中 address 形（< 2^160 且非零）
//!    词 = 候选 recipient 槽（#28 目标槽交叉定位的推广：不追求
//!    唯一匹配，多候选逐一注入试执行选优）。
//! 3. **转移词汇表（完备最小集，三族 EIP）**：任何 attacker 获利 =
//!    资产所有权向 attacker 转移，标准接口只有 ERC20
//!    （transfer/transferFrom/balanceOf）、ETH（call{value}）、
//!    ERC721（ownerOf 翻转）。加族是词汇扩展非个案。
//! 4. **资产级增量断言**：清单内每资产 assert RECIPIENT Δ>0 /
//!    ownerOf 翻转；取不到的**逐资产标注**（issue #61 的整体
//!    L1-only 退级由此降级为资产级标注的缺省形态）。

use std::fmt::Write as _;

use alloy_primitives::U256;
use loom_fuzz_oracle::{hex_bytes, Poc, PocCall};

use crate::synth::{addr_expr, u256_hex64, HeadShape};

/// 机械资产清单：定罪呼出目标 ∪ trace 触及目标（去重、保序）。
/// 不含任何协议语义——是不是代币、属哪族，全部留给运行时探测。
pub(crate) fn asset_inventory(poc: &Poc) -> Vec<[u8; 20]> {
    let mut out: Vec<[u8; 20]> = Vec::new();
    let mut push = |c: &PocCall| {
        if let Ok(b) = hex_bytes(&c.target) {
            if b.len() == 20 {
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    };
    if let Some(c) = &poc.call {
        push(c);
    }
    for c in &poc.trace_calls {
        push(c);
    }
    out
}

/// 受益槽候选：payload 头词中 address 形词（值 < 2^160 且非零）。
/// 机械形态判据，不含协议语义；多候选由测试逐一注入试执行选优。
pub(crate) fn beneficiary_slots(shape: &HeadShape) -> Vec<usize> {
    shape
        .words
        .iter()
        .enumerate()
        .filter(|(_, w)| **w != U256::ZERO && **w < U256::from(1u64) << 160)
        .map(|(i, _)| i)
        .collect()
}

/// 每资产的 ERC721 tokenId 候选（机械）：trace 中目标 == 该资产的
/// 呼出 input 的全部 32B 词。探测 ownerOf 翻转用；空 = 该资产按
/// ERC20/ETH 族探测。
pub(crate) fn token_id_candidates(poc: &Poc, asset: [u8; 20]) -> Vec<U256> {
    let mut out = Vec::new();
    let mut scan = |c: &PocCall| {
        let Ok(t) = hex_bytes(&c.target) else {
            return;
        };
        if t.len() != 20 || t != asset {
            return;
        }
        let Ok(input) = hex_bytes(&c.input) else {
            return;
        };
        // 词候选从 selector（4B）后开始按 32B 对齐切（截到 8 个防膨胀）。
        if input.len() < 36 {
            return;
        }
        let (chunks, _) = input[4..].as_chunks::<32>();
        for chunk in chunks {
            let w = U256::from_be_bytes::<32>(*chunk);
            if w != U256::ZERO && !out.contains(&w) {
                out.push(w);
                if out.len() >= 8 {
                    return;
                }
            }
        }
    };
    if let Some(c) = &poc.call {
        scan(c);
    }
    for c in &poc.trace_calls {
        scan(c);
    }
    out
}

/// IERC721 最小接口（ownerOf——转移词汇表 ERC721 族的机械锚点）。
pub(crate) fn ierc721_sol() -> String {
    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// 价值影响层 ERC721 族探测的最小接口（pocgen 机械合成）。
interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
}
"#
    .to_string()
}

/// 受益人 = payload 末步 caller（机械：witness 自身的行为——谁发起
/// 定罪步，谁的资产 delta 可测且可 prank 重放）。
pub(crate) fn recipient_of(poc: &Poc) -> Option<[u8; 20]> {
    let steps = poc.normalized_steps().ok()?;
    let last = steps.last()?;
    hex_bytes(&last.caller).ok().and_then(|b| {
        if b.len() == 20 {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b);
            Some(a)
        } else {
            None
        }
    })
}

/// ERC20 balanceOf 运行时探测（staticcall；形态不符 = ok false）。
fn probe_erc20_sol() -> &'static str {
    "    function _erc20Balance(address asset, address who) internal view returns (bool ok, uint256 bal) {\n        (bool s, bytes memory r) = asset.staticcall{gas: 100_000}(abi.encodeWithSelector(0x70a08231, who));\n        if (!s || r.length != 32) return (false, 0);\n        bal = abi.decode(r, (uint256));\n        return (true, bal);\n    }\n"
}

/// ERC721 ownerOf 运行时探测。
fn probe_erc721_sol() -> &'static str {
    "    function _erc721Owner(address asset, uint256 tid) internal view returns (bool ok, address owner) {\n        (bool s, bytes memory r) = asset.staticcall{gas: 100_000}(abi.encodeWithSelector(0x6352211e, tid));\n        if (!s || r.length != 32) return (false, address(0));\n        owner = abi.decode(r, (address));\n        return (true, owner);\n    }\n"
}

/// 价值影响层 fork 直通测试合约（issue #64）。
///
/// 结构：每受益槽候选一次 `vm.createSelectFork` 新鲜分叉 →
/// `attempt(slot)` 外部调用（try/catch 隔离）内 prank 逐字重放
/// witness（payload 词[slot] := RECIPIENT）→ 三族资产级 delta
/// 计数。任一候选产生获利即绿灯；逐资产/逐候选标注全程 emit。
///
/// 调用方契约：`poc.fork` 在场（fork 直通）、steps 非空、末步
/// caller 为 20 字节（受益人）。
pub(crate) fn profit_test_sol(
    poc: &Poc,
    shape_last: &HeadShape,
    calldata_last: &[u8],
    contract: [u8; 20],
) -> String {
    let fork = poc.fork.as_ref().expect("调用方已校验 fork 在场");
    let steps = poc.normalized_steps().expect("调用方已归一");
    let last = steps.len() - 1;
    let recipient = recipient_of(poc).expect("调用方已校验");
    let inventory = asset_inventory(poc);
    let slots = beneficiary_slots(shape_last);
    let router = addr_expr(contract);
    let recipient_expr = addr_expr(recipient);

    // 每步常量 + 重放序（函数体在 _replay；payload soft——L1 语义）。
    let mut step_consts = String::new();
    let mut fund = String::new();
    let mut replay = String::new();
    let mut funded: Vec<String> = Vec::new();
    for (i, s) in steps.iter().enumerate() {
        let t = hex_bytes(&s.target).expect("调用方已校验");
        let c = hex_bytes(&s.caller).expect("调用方已校验");
        let v = U256::from_be_bytes({
            let b = hex_bytes(&s.value).expect("调用方已校验");
            let mut w = [0u8; 32];
            w.copy_from_slice(&b);
            w
        });
        let c_expr = addr_expr(c.try_into().expect("len 20"));
        let _ = writeln!(
            step_consts,
            "    address constant T{i} = {};",
            addr_expr(t.try_into().expect("len 20"))
        );
        let _ = writeln!(step_consts, "    address constant C{i} = {c_expr};");
        let _ = writeln!(step_consts, "    uint256 constant V{i} = {v};");
        if !funded.contains(&c_expr) {
            funded.push(c_expr.clone());
            let _ = writeln!(fund, "        vm.deal({c_expr}, 100 ether);");
        }
        if i == last {
            let _ = writeln!(
                replay,
                "        vm.prank(C{i});\n        (bool ok{i}, bytes memory ret{i}) = T{i}.call{{value: V{i}, gas: 4_000_000}}(payload);\n        emit StepOutcome({i}, ok{i}, ret{i});"
            );
        } else {
            let _ = writeln!(
                replay,
                "        bytes memory data{i} = hex\"{hex}\";",
                hex = {
                    let b = hex_bytes(&s.calldata).expect("调用方已校验");
                    b.iter()
                        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
                            let _ = write!(s, "{x:02x}");
                            s
                        })
                }
            );
            let _ = writeln!(
                replay,
                "        vm.prank(C{i});\n        (bool ok{i}, ) = T{i}.call{{value: V{i}, gas: 4_000_000}}(data{i});\n        require(ok{i}, \"L3 step {i} failed\");"
            );
        }
    }

    // 资产清单常量 + tokenId 字面量初始化（标量常量 + memory 数组装配）。
    let mut asset_consts = String::new();
    let mut tid_init = String::new();
    for (i, a) in inventory.iter().enumerate() {
        let _ = writeln!(
            asset_consts,
            "    address constant A{i} = {};",
            addr_expr(*a)
        );
        let tids = token_id_candidates(poc, *a);
        let _ = writeln!(
            tid_init,
            "        tids[{i}] = new uint256[]({});",
            tids.len()
        );
        for (k, w) in tids.iter().enumerate() {
            let _ = writeln!(
                tid_init,
                "        tids[{i}][{k}] = uint256(0x{});",
                u256_hex64(*w)
            );
        }
    }

    let n_assets = inventory.len();
    let mut slot_init: Vec<String> = slots
        .iter()
        .enumerate()
        .map(|(k, s)| format!("        slots[{k}] = {s};"))
        .collect();
    slot_init.push(
        "        slots[{last}] = type(uint256).max; // verbatim：不注入，witness 原样"
            .replace("{last}", &slots.len().to_string()),
    );
    let slot_init = slot_init.join("\n");
    let asset_init = (0..n_assets)
        .map(|i| format!("        assets[{i}] = A{i};"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload_hex: String = calldata_last.iter().fold(
        String::with_capacity(calldata_last.len() * 2),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    );

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {{IERC20}} from "../src/IERC20.sol";
import {{IERC721}} from "../src/IERC721.sol";
import {{Vm}} from "../src/Vm.sol";

/// 价值影响层测试（issue #64，pocgen 机械合成，勿手改）。
/// witness 逐字重放 × 受益槽候选注入 × 三族资产级 delta 断言；
/// 取不到的逐资产标注（诚实，不伪造绿灯）。
contract ProfitTest {{
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    string constant FORK_URL = "{fork_url}";
    uint256 constant FORK_BLOCK = {fork_block};
    address constant ROUTER = {router};
    address constant RECIPIENT = {recipient_expr};
{step_consts}
{asset_consts}
    bytes constant PAYLOAD = hex"{payload_hex}";

    event CandidateTried(uint256 slot, bool profit, string note);
    event StepOutcome(uint256 step, bool ok, bytes returndata);
    event CandidateFailed(uint256 slot, bytes err);
    event AssetUnaffected(address asset, string family, string detail);

    function testExploit() public {{
        bool any = false;
        uint256[] memory slots = new uint256[]({n_slots});
{slot_init}
        for (uint256 ci = 0; ci < slots.length; ci++) {{
            vm.createSelectFork(FORK_URL, FORK_BLOCK);
            try this.attempt(slots[ci]) returns (bool gained, string memory note) {{
                if (gained) any = true;
                emit CandidateTried(slots[ci], gained, note);
            }} catch (bytes memory err) {{
                emit CandidateFailed(slots[ci], err);
            }}
        }}
        require(any, "no candidate recipient produced attacker profit (see Candidate*/Asset* annotations)");
    }}

    /// 单候选尝试：快照 → prank 逐字重放（payload 词[slot] :=
    /// RECIPIENT）→ 三族资产级 delta 探测。
    function attempt(uint256 slot) external returns (bool, string memory) {{
        address[] memory assets = new address[]({n_assets});
{asset_init}
        uint256[][] memory tids = new uint256[][]({n_assets});
{tid_init}
        // 资金垫底先行，余额快照在后——deal 的绝对置额不计入利润。
{fund}
        uint256 balBefore = RECIPIENT.balance;
        (bool[] memory ercOk, uint256[] memory balB) = _snap(assets);
        _replay(slot);
        bool gained = false;
        string memory note = "";
        if (RECIPIENT.balance > balBefore) {{
            gained = true;
            note = "ETH:recipient-balance ";
        }}
        for (uint256 ai = 0; ai < assets.length; ai++) {{
            (bool g, string memory n) = _assetProfit(assets[ai], balB[ai], ercOk[ai], tids[ai]);
            if (g) {{
                gained = true;
                note = string.concat(note, n);
            }}
        }}
        return (gained, note);
    }}

    /// witness 逐字重放：布置步硬断言（真实环境布置必须成功）；
    /// payload 步 soft（L1 语义：臂执行不依赖整笔成功，臂后 revert
    /// 合法）——结果如实 emit。
    function _replay(uint256 slot) internal {{
        bytes memory payload = PAYLOAD;
        if (slot != type(uint256).max) {{
            uint256 recipientWord = uint256(uint160(RECIPIENT));
            assembly {{
                mstore(add(add(payload, 36), mul(slot, 32)), recipientWord)
            }}
        }}
{replay}
    }}

    /// ERC20 balanceOf 快照（机械探测：形态不符 = ok false）。
    function _snap(address[] memory assets) internal view returns (bool[] memory, uint256[] memory) {{
        bool[] memory okFlags = new bool[](assets.length);
        uint256[] memory bals = new uint256[](assets.length);
        for (uint256 i = 0; i < assets.length; i++) {{
            (okFlags[i], bals[i]) = _erc20Balance(assets[i], RECIPIENT);
        }}
        return (okFlags, bals);
    }}

    /// 单资产三族 delta 探测（机械，逐资产标注）。
    function _assetProfit(address asset, uint256 balB, bool erc20ok, uint256[] memory tids) internal returns (bool, string memory) {{
        if (erc20ok) {{
            (, uint256 balAfter) = _erc20Balance(asset, RECIPIENT);
            if (balAfter > balB) {{
                return (true, string.concat("ERC20:", _toHex(asset), " "));
            }}
            emit AssetUnaffected(asset, "ERC20", "balanceOf delta <= 0");
        }}
        for (uint256 t = 0; t < tids.length; t++) {{
            (bool okT, address ownerBefore) = _erc721Owner(asset, tids[t]);
            if (okT) {{
                (, address ownerAfter) = _erc721Owner(asset, tids[t]);
                if (ownerAfter == RECIPIENT && ownerBefore != RECIPIENT) {{
                    return (true, string.concat("ERC721:", _toHex(asset), " "));
                }}
                emit AssetUnaffected(asset, "ERC721", "ownerOf not flipped to recipient");
            }}
        }}
        return (false, "");
    }}

{pe20}
{pe721}
    function _toHex(address a) internal pure returns (string memory) {{
        bytes memory s = new bytes(42);
        s[0] = "0"; s[1] = "x";
        bytes memory hexd = "0123456789abcdef";
        bytes20 ab = bytes20(a);
        for (uint256 i = 0; i < 20; i++) {{
            s[2 + i * 2] = hexd[uint8(ab[i]) >> 4];
            s[3 + i * 2] = hexd[uint8(ab[i]) & 0xf];
        }}
        return string(s);
    }}
}}
"#,
        fork_url = fork.rpc_url,
        fork_block = fork.block_number,
        n_slots = slots.len() + 1,
        pe20 = probe_erc20_sol(),
        pe721 = probe_erc721_sol(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_fuzz_oracle::{bytes_hex, PocStep, POC_FORMAT};

    fn addr_word(a: [u8; 20]) -> U256 {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        U256::from_be_bytes(w)
    }

    fn word64(v: u64) -> String {
        u256_hex64(U256::from(v))
    }

    /// 最小 fork poc：一步 payload，头词含一个地址形词（受益槽候选）。
    fn fork_poc(evidence_input: Vec<u8>) -> Poc {
        let asset = [0xddu8; 20];
        let caller = [0x33u8; 20];
        let mut cd = 0xb86f3ea6u32.to_be_bytes().to_vec();
        cd.extend_from_slice(&U256::from(0x3be0u64).to_be_bytes::<32>());
        cd.extend_from_slice(&addr_word(asset).to_be_bytes::<32>());
        cd.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
        Poc {
            format: POC_FORMAT.to_string(),
            digest: "0x00".into(),
            selector: "0xb86f3ea6".into(),
            step: 0,
            pc: 8143,
            verdict: "confirmed".into(),
            steps: vec![PocStep {
                target: "0x2222222222222222222222222222222222222222".into(),
                caller: bytes_hex(&caller),
                value: word64(0),
                calldata: format!("0x{}", {
                    let mut s = String::new();
                    for b in &cd {
                        let _ = write!(s, "{b:02x}");
                    }
                    s
                }),
            }],
            tx: None,
            prestate: Default::default(),
            responses: vec![],
            seed: 42,
            max_runs: 100,
            time_budget_secs: 300,
            evidence_value: None,
            fork: Some(loom_fuzz_oracle::PocFork {
                rpc_url: "https://example.invalid".into(),
                block_number: 15837893,
            }),
            deployments: vec![],
            entry: None,
            contract: Some("0x2222222222222222222222222222222222222222".into()),
            family: loom_fuzz_oracle::HitFamily::ArbitraryCall,
            call: Some(PocCall {
                target: bytes_hex(&asset),
                input: format!("0x{}", {
                    let mut s = String::new();
                    for b in &evidence_input {
                        let _ = write!(s, "{b:02x}");
                    }
                    s
                }),
            }),
            trace_calls: vec![PocCall {
                target: bytes_hex(&asset),
                input: format!("0x{}", {
                    let mut s = String::new();
                    for b in &evidence_input {
                        let _ = write!(s, "{b:02x}");
                    }
                    s
                }),
            }],
            replay: String::new(),
        }
    }

    #[test]
    fn inventory_dedups_call_and_trace() {
        let poc = fork_poc(vec![0x70, 0xa0, 0x82, 0x31]);
        let inv = asset_inventory(&poc);
        assert_eq!(inv, vec![[0xddu8; 20]], "call ∪ trace 去重");
    }

    #[test]
    fn beneficiary_slots_address_shaped_only() {
        let poc = fork_poc(vec![]);
        let steps = poc.normalized_steps().unwrap();
        let cd = hex_bytes(&steps[0].calldata).unwrap();
        let shape = crate::synth::parse_head_shape(&cd).unwrap();
        let slots = beneficiary_slots(&shape);
        assert_eq!(
            slots,
            vec![0, 1],
            "word0(0x3be0) 与 word1(地址) 均为地址形非零词"
        );
    }

    #[test]
    fn token_id_candidates_from_trace_inputs() {
        let mut input = 0x70a08231u32.to_be_bytes().to_vec();
        input.extend_from_slice(&U256::from(7u64).to_be_bytes::<32>());
        let poc = fork_poc(input);
        let tids = token_id_candidates(&poc, [0xddu8; 20]);
        assert_eq!(tids, vec![U256::from(7u64)]);
    }

    #[test]
    fn profit_test_renders_three_families_and_annotations() {
        let mut input = 0x70a08231u32.to_be_bytes().to_vec();
        input.extend_from_slice(&U256::from(7u64).to_be_bytes::<32>());
        let poc = fork_poc(input);
        let steps = poc.normalized_steps().unwrap();
        let cd = hex_bytes(&steps[0].calldata).unwrap();
        let shape = crate::synth::parse_head_shape(&cd).unwrap();
        let body = profit_test_sol(&poc, &shape, &cd, [0x22; 20]);
        assert!(body.contains("vm.createSelectFork(FORK_URL, FORK_BLOCK)"));
        assert!(body.contains("mstore(add(add(payload, 36), mul(slot, 32)), recipientWord)"));
        assert!(body.contains("0x70a08231"), "ERC20 族探测");
        assert!(body.contains("0x6352211e"), "ERC721 族探测");
        assert!(body.contains("RECIPIENT.balance"), "ETH 族探测");
        assert!(body.contains("AssetUnaffected"), "逐资产标注");
        assert!(body.contains("require(any"), "无获利候选 = 红灯 + 标注");
        assert!(body.contains("vm.prank(C0)"), "witness caller 重放");
    }

    #[test]
    fn recipient_is_last_step_caller() {
        let poc = fork_poc(vec![]);
        assert_eq!(recipient_of(&poc), Some([0x33u8; 20]));
    }
}
