//! approval_drain 族 L2 通用动作测试（issue #20）：
//! 1. select_action 形状判定：transferFrom / transfer / 不匹配
//!    NoGenericAction（keccak 选择子现算，钉标准值）；
//! 2. 通用 drain 工程 forge 真跑绿灯：手工最小 deputy 路由器
//!    （calldata = target + 透传 input——confused deputy 形）+
//!    transferFrom 定罪呼出 → 缴获断言成立；
//! 3. 形状不匹配 → NoGenericAction 诚实降级（不硬套）。

use std::collections::BTreeMap;

use alloy_primitives::U256;
use loom_fuzz_oracle::{bytes_hex, HitFamily, Poc, PocCall, PocTx};
use loom_fuzz_pocgen::{generate_exploit, PocgenError};

/// 最小 deputy 路由器（forge 编译的 DeputyRouter 运行时，717B）：
/// `forward(address target, bytes data)`——target/data 均调用者可控
/// （confused deputy 形）。calldata = abi.encodeWithSelector(
/// forward, TOKEN, input)。
const DEPUTY_ROUTER_HEX: &str = include_str!("fixtures/deputy-router.runtime.hex");

const ROUTER: [u8; 20] = [0x22; 20];
const ATTACKER: [u8; 20] = [0x33; 20];
const TOKEN: [u8; 20] = [0x77; 20];

/// 造一槽 32B 字（右对齐）。
fn word(v: U256) -> Vec<u8> {
    v.to_be_bytes::<32>().to_vec()
}

fn addr_word(a: [u8; 20]) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}

fn transfer_from_input(from: [u8; 20], to: [u8; 20], amount: U256) -> Vec<u8> {
    let mut input = 0x23b872ddu32.to_be_bytes().to_vec();
    input.extend_from_slice(&addr_word(from));
    input.extend_from_slice(&addr_word(to));
    input.extend_from_slice(&amount.to_be_bytes::<32>());
    input
}

fn transfer_input(to: [u8; 20], amount: U256) -> Vec<u8> {
    let mut input = 0xa9059cbbu32.to_be_bytes().to_vec();
    input.extend_from_slice(&addr_word(to));
    input.extend_from_slice(&amount.to_be_bytes::<32>());
    input
}

/// deputy 族 poc：定罪呼出 = (target=TOKEN, input)，witness calldata =
/// abi.encodeWithSelector(DeputyRouter.forward, TOKEN, input)。
fn deputy_poc(input: Vec<u8>) -> Poc {
    // forward(address,bytes) 的选择子（forge 编译产物恒定 0x6fadcf72；
    // 与 synth 的 ERC20 选择子一样走 keccak 语义，此处钉编译产物值）。
    let mut calldata = 0x6fadcf72u32.to_be_bytes().to_vec();
    calldata.extend_from_slice(&addr_word(TOKEN)); // target
    calldata.extend_from_slice(&word(U256::from(0x40u64))); // bytes 偏移
    calldata.extend_from_slice(&word(U256::from(input.len()))); // bytes 长度
    calldata.extend_from_slice(&input);
    // 动态尾 32B 对齐补齐。
    let pad = (32 - input.len() % 32) % 32;
    calldata.resize(calldata.len() + pad, 0);
    Poc {
        format: loom_fuzz_oracle::POC_FORMAT.to_string(),
        digest: "0x00".to_string(),
        selector: "0x2e2d2984".to_string(),
        step: 119,
        pc: 42,
        verdict: "confirmed".to_string(),
        tx: PocTx {
            caller: bytes_hex(&ATTACKER),
            value: "0x".to_string() + &"0".repeat(64),
            calldata: bytes_hex(&calldata),
        },
        prestate: BTreeMap::new(),
        responses: Vec::new(),
        seed: 42,
        max_runs: 2_000,
        time_budget_secs: 300,
        evidence_value: None,
        fork: None,
        deployments: Vec::new(),
        entry: None,
        contract: Some(bytes_hex(&ROUTER)),
        family: HitFamily::ApprovalDrainDeputy,
        call: Some(PocCall {
            target: bytes_hex(&TOKEN),
            input: bytes_hex(&input),
        }),
        replay: String::new(),
    }
}

fn out_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "loom-fuzz-pocgen-ad-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn select_action_matches_erc20_shapes_and_keccak_selectors() {
    use loom_fuzz_pocgen::select_action;
    // transferFrom(ROUTER, ATTACKER, AMT)：victim = from。
    let amount = U256::from(1_000u64);
    let poc = deputy_poc(transfer_from_input(ROUTER, ATTACKER, amount));
    match select_action(&poc).expect("transferFrom 形应识别") {
        loom_fuzz_pocgen::HarmfulAction::Erc20TransferFrom {
            from,
            to,
            amount: a,
        } => {
            assert_eq!(from, ROUTER);
            assert_eq!(to, ATTACKER);
            assert_eq!(a, amount);
        }
        other => panic!("应 Erc20TransferFrom: {other:?}"),
    }
    // transfer(ATTACKER, AMT)：victim = 路由器自身。
    let poc = deputy_poc(transfer_input(ATTACKER, amount));
    match select_action(&poc).expect("transfer 形应识别") {
        loom_fuzz_pocgen::HarmfulAction::Erc20Transfer { to, amount: a } => {
            assert_eq!(to, ATTACKER);
            assert_eq!(a, amount);
        }
        other => panic!("应 Erc20Transfer: {other:?}"),
    }
    // 非 ERC20 selector → NoGenericAction。
    let mut foreign = 0xdeadbeefu32.to_be_bytes().to_vec();
    foreign.extend_from_slice(&word(U256::from(1u64)));
    let poc = deputy_poc(foreign);
    assert!(matches!(
        select_action(&poc),
        Err(PocgenError::NoGenericAction(_))
    ));
    // 旧 poc（无定罪呼出）→ NoGenericAction。
    let mut old = deputy_poc(transfer_input(ATTACKER, amount));
    old.call = None;
    assert!(matches!(
        select_action(&old),
        Err(PocgenError::NoGenericAction(_))
    ));
}

#[test]
fn generic_drain_project_passes_forge() {
    let amount = U256::from(1_000_000u64);
    let poc = deputy_poc(transfer_from_input(ROUTER, ATTACKER, amount));
    let dir = out_dir("drain");
    let (path, summary) = generate_exploit(&poc, DEPUTY_ROUTER_HEX, &dir, false)
        .unwrap_or_else(|e| panic!("生成/执行失败: {e}"));
    println!("forge 输出:\n{summary}");
    assert!(summary.contains("[PASS]"), "forge 应绿灯: {summary}");
    assert!(summary.contains("1 passed"), "forge 应绿灯: {summary}");
    let body = std::fs::read_to_string(path.join("test/PoC.t.sol")).unwrap();
    // 机械布置：victim 余额 + allowance keccak 槽公式 + verbatim 重放。
    assert!(body.contains("vm.etch(VICTIM_TOKEN, address(token).code)"));
    assert!(
        body.contains("keccak256(abi.encode("),
        "keccak 槽公式: {body}"
    );
    assert!(body.contains("IERC20(VICTIM_TOKEN).balanceOf("));
}

#[test]
fn mismatched_shape_degrades_honestly() {
    let mut foreign = 0xdeadbeefu32.to_be_bytes().to_vec();
    foreign.extend_from_slice(&word(U256::from(1u64)));
    let poc = deputy_poc(foreign);
    let dir = out_dir("nodegrade");
    let err = generate_exploit(&poc, DEPUTY_ROUTER_HEX, &dir, false).unwrap_err();
    match err {
        PocgenError::NoGenericAction(msg) => {
            assert!(msg.contains("非 ERC20 transfer/transferFrom"), "{msg}")
        }
        other => panic!("应 NoGenericAction，得 {other:?}"),
    }
}
