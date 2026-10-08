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
//! # 合成三要素（arbitrary_call 的 L2 形状）
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
//!    calldata 机械合成——广义头形解析（issue #28：定长槽 + 至多一
//!    个动态尾偏移槽；逐槽尝试尾偏移解释，末槽==n·32 不再是前提）
//!    后槽替换：目标槽（与 poc.json 定罪呼出目标交叉定位）=
//!    VICTIM_ASSET；动态头形的尾偏移槽 =
//!    `abi.encodeCall(IERC20.transferFrom, …)`；定长头形的零词按
//!    debit/recipient/amount 角色序注入（ERC20 标准形——与
//!    select_action 同类的 ABI 形状知识）。调用序列 = 一次头形合成
//!    调用。收尾断言：① L1 `require(ok)`（路由器调用成功）② L2
//!    `require(balanceOf(ROUTER) == 0)`（每个受害资产的路由器持仓
//!    严格归零——终点断言；缴获路径因 router 逻辑而异，统一锚在
//!    路由器持仓）。
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
