//! L2 exploit 影响层（issue #10）：L1 witness（到场 + 控制呼出）→
//! L2 价值影响 PoC——**forge test 绿灯 = 终判**。
//!
//! # 两层模型
//!
//! - **L1**（M0 已完，`crates/oracle`）：到场 target pc + 控制呼出
//!   （arbitrary_call 臂 3 = 任意目标 + 任意 calldata，msg.sender =
//!   路由器）。
//! - **L2**（本 crate）：把 primitive 组装成盗窃——选有害动作、布置
//!   受害者资产、断言缴获。机械合成，不手写个案 calldata。
//!
//! # 合成三要素（arbitrary_call 臂 3 的 L2 形状）
//!
//! 1. **资产模型**：生成的 Foundry 工程自带自写 `MockERC20.sol`
//!    （最小 ERC20，solc 0.8.19 兼容；槽布局钉死：balanceOf = slot
//!    0、allowance = slot 1——vm.store 公式的依据）。setUp（测试体
//!    首部）：部署 MockERC20，mint 全额给**路由器合约本身**（受害者
//!    = 目标合约的关联持仓）。
//! 2. **有害动作选择（机械）**：臂 3 primitive = 任意目标 + 任意
//!    calldata 呼出。对 ERC20 目标合成
//!    `transferFrom(router, attacker, BALANCE)`——需要
//!    allowance[router][router]，setUp 用 `vm.store` 机械布置
//!    （槽 = keccak256(abi.encode(router, keccak256(abi.encode(
//!    router, 1))))，标准 ERC20 布局）。有害动作集合的扩展接口：
//!    [`HarmfulAction`] + [`select_action`]，M0 只实现 ERC20 drain 臂。
//! 3. **PoC 测试体**：`vm.etch(router, <运行时字节码>)` + poc.json
//!    prestate（registry 槽）`vm.store` + `vm.prank(attacker)` +
//!    calldata 机械合成——解析 witness calldata 的头形（臂 3 router
//!    形：槽 0 = 目标地址（address-clean 校验），末槽 = 尾指针
//!    （值 = 头宽，校验）），service 槽替换为 VICTIM_ASSET、request
//!    槽替换为 `abi.encodeCall(IERC20.transferFrom, …)`。调用序列 =
//!    一次 forwardRequest。收尾断言：① L1 `assertTrue(ok)`（转发
//!    成功）② L2 `assertEq(token.balanceOf(attacker), BALANCE)`（余额
//!    严格等于转入全额——终点断言）。
//!
//! # fork 模式（BlockMachine）
//!
//! `--fork` 生成 fork 配置：foundry.toml fork profile（
//! `eth_rpc_url = "${BLOCKMACHINE_RPC_URL}"`）+ `run.sh`——
//! `BLOCKMACHINE_API_KEY` 为空 = 直接无 key 连接；非空 =
//! `forge test --fork-url "$RPC" -H "Authorization: Bearer $KEY"`
//! （foundry.toml 不能带头，header 由脚本表达）。资产模型差异
//! （链上真实余额、跳过 vm.etch）见工程 README；M0 验收以字节码
//! 模式为准，fork plumbing 最小测试环境门控（见 tests/）。
//!
//! # 诚实降级
//!
//! 入口校验 poc.verdict：非 confirmed（unreachable / inconclusive）
//! 不进 L2——typed error（fail-closed，不假装成功）。
//!
//! # forge 执行
//!
//! 生成工程后在工程目录跑 `forge test`（PATH 找 forge）——工程
//! 零外部依赖（自写 `MockERC20` + 最小 `Vm` cheatcode 接口 +
//! 自带断言 helper，不依赖 forge-std）。绿灯 → 返回工程路径；
//! 红灯 / forge 缺失 → typed error 带输出（fail-closed）。

mod project;
mod synth;

pub use project::forge_test;
pub use synth::{
    generate_exploit, generate_exploit_with, select_action, ExploitParams, HarmfulAction,
    PocgenError, ROUTER_ADDRESS,
};
