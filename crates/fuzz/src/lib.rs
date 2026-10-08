//! 定向执行器（issue #5）：revm 单合约会话，种子进场，fitness = 距目标
//! PC 集合的 CFG 距离，距离缩小的输入保留进化，直到命中目标帧（或预算
//! 耗尽如实报告）。产出 [`SessionReport`]：best_input / WitnessTrace 全部
//! serde，poc.json 直接复用。
//!
//! # revm 集成方式（版本/API 要点）
//!
//! - `revm = 42.0.1`（default-features off，仅 `std` + `secp256k1`——
//!   后者保留 ecrecover 预编译，arbitrary_call 臂 1 目标可控类合约会
//!   走到；不启用 c-kzg/blst：blob 交易不在见证形态内）。
//! - 部署不走 create 交易：`CacheDB::insert_account_info` 直接布置
//!   合约账户（balance/nonce/code = legacy bytecode），prestate 存储槽
//!   走 `insert_account_storage`。CALL 目标的空账户由 EVM 语义自然处理。
//! - `Context::mainnet().with_db(db).modify_cfg_chained(...)` +
//!   `build_mainnet_with_inspector(inspector)`；`SpecId::CANCUN`（经
//!   `set_spec_and_mainnet_gas_params` 同设 mainnet gas 参数表）。
//!   M0 目标合约为 solc 0.8.x 形态，语义 ⊆ CANCUN；不启 AMSTERDAM+
//!   新语义（EIP-8037 等），保持确定性基线简单。`gas_price = 0`、
//!   `disable_nonce_check` / `disable_balance_check`：见证只关心合约
//!   内部控制流，不为手续费/nonce/余额背书（caller 账户仍布置大额
//!   余额，余额敏感分支读到的是确定值）。
//! - `TxEnv` = call(cfg.address) + caller/value/calldata（calldata 由
//!   [`Input`] 序列化：selector 4B + head 槽原样拼接 + tail 原样拼接）。
//! - Inspector（revm-inspector `Inspector` trait）：`step` 钩子记 pc
//!   （`ExtBytecode::pc()`）进有序集；`call` / `create` 钩子读
//!   `CallInputs.input.bytes(ctx)`（SharedBuffer 立即拷贝，防止子帧
//!   归还内存后覆写）与 target/value；CALL 指令的 pc 取 step 流的
//!   最后一条（call 钩子在 CALL 指令执行后触发）。步数超上限时在
//!   step 钩子里 `set_action(Return(new_oog))` 主动截停，如实标
//!   truncated。
//!
//! # ABI 职责边界（重要）
//!
//! 执行器**不感知 ABI**：`Input.head` 的槽原样拼进 calldata，
//! `Input.tail` 原样接在头后。动态参数（guard-boundary / trv-like
//! 的 `forwardRequest` 都有 `bytes calldata` 形参）的 head 指针槽
//! （0x40 型）由种子 / 变异器负责正确性——seed 编译器产 `Tail::Empty`
//! 时 calldata 就是裸头；若种子 / 变异器给出 `Tail::Bytes`（如手工
//! 构造的 ABI 编码尾），执行器照拼不误，但指针槽与尾内容的对应关系
//! 是输入构造方的责任。M0 种子尾部恒空；动态尾由变异器的"动态尾
//! 生成"（legacy 系列）与变长尾算子带进搜索空间（#6）。
//!
//! # CFG 距离表
//!
//! 自实现静态分析（无第三方依赖）：基本块从 pc 0 与每个 JUMPDEST
//! 切起，至 JUMP/JUMPI/终止指令（STOP/RETURN/REVERT/INVALID/
//! SELFDESTRUCT）止；PUSH 立即数区不当操作码。边 = 顺序下落 +
//! JUMPI 双目标 + JUMP 单目标；JUMP(JUMPI) 前一条可静态看到
//! PUSH const 且指向 JUMPDEST 则解析出 taken 目标，否则保守指向
//! 全部 JUMPDEST 块。从目标块反向 BFS 得每块距离（不可达 =
//! `u32::MAX`）；fitness(run) = visited pcs 的块距离最小值；visited
//! 含任一 target pc 即命中。
//!
//! # 变异算子（issue #6，`mutators` 模块）
//!
//! 单轮变异 = 一次随机投掷定算子 + 单点应用，全部经 xorshift64*
//! （确定性）。权重：60% 定长算子（head 槽）/ 20% 变长尾算子
//! （tail 的 Bytes 内容）/ 20% legacy 兜底（#5 基础系列）。定长五
//! 算子：
//!
//! 1. **比较操作数回灌**（cmp，25/100）：inspector step 钩子收
//!    LT/GT/SLT/SGT/EQ 两侧操作数进比较池（BTreeSet 去重排序、
//!    上限 256）；变异时池值整词覆写随机槽——穿 dispatcher /
//!    require 的定向穿透。两侧都收（结果条件收需回读已弹出的
//!    操作数，机制复杂无收益）。
//! 2. **常量池整参覆盖**（const，25/100）：32B 槽整体覆写。常量池
//!    = 码内 PUSH 立即数 ∪ seed 静态字典，会话构建一次。
//! 3. **±1 边界变异**（boundary，20/100）：U256 wrapping 加减一，
//!    与算子 2 配对跨 gt/lt 边界。
//! 4. **存储值入池**（storage，20/100）：inspector 记 SLOAD 键值对
//!    （step 记键 / step_end 收值，上限 128）；变异时 90% 值 / 10%
//!    键覆写参数槽——穿"参数须等于某槽内容"类检查。
//! 5. **数值高斯缩放**（gaussian，10/100）：±{10,25,50,100,200,
//!    500,1000}% 固定比例集随机一档 + 符号，wrapping 截断。
//!
//! 变长尾算子：truncate（32B 边界截断，可截空）/ extend（追加 1-2
//! 词）/ block-replace（32B 块整体替换）。head 槽只落定长算子与
//! legacy-head 系列，tail 内容只落变长算子与 legacy 尾系列（分集
//! 由结构保证，测试断言）。
//!
//! 与 Echidna / MEDUSA 类成熟实现的机制差异：算子思想同源（比较
//! 回灌≈Echidna 的 dynamic dictionary、存储回灌≈MEDUSA 的 storage
//! 感测），但全部自行实现，且 loom 的特色是**静态事实先于运行时
//! 收集**——常量池以 loom 静态分析产物（seed 字典：guard 常量 ∪
//! 证据常量 ∪ PUSH 立即数）为底，运行时观测池（cmp / storage）为
//! 增量补充；池全部有上限、去重、排序，迭代序即确定序。
//!
//! # 制导与基线
//!
//! 进化环：初始种群 = seeds（空则退化为 selector + 零参），每代
//! 按 fitness 排序保留前一半，变异产生子代（见上）；距离创新低入
//! corpus 并记录。预算双上限（runs / 时间），耗尽未达 →
//! `reached = false`，不硬判（unreachable / inconclusive 三值判决
//! 在 #7）。基线：同一 [`ExecConfig`] 纯随机（selector 固定为目标
//! 的随机槽位输入，无种子无制导无字典，同预算）跑一遍，
//! `baseline_runs_to_reach` 记入报告作制导收益数据；
//! `ExecConfig.run_baseline` 可关。
//!
//! # 确定性
//!
//! 同 `seed_rng` 两次 `run_targeted`：内部一切随机性来自自实现的
//! xorshift64*（`rng` 模块），pc 记录用 BTreeSet，corpus 去重键是
//! 字节序；revm 本身确定性。report 的 best_input / WitnessTrace 逐
//! 字节一致（测试断言）。

mod cfg;
mod evm;
mod exec;
mod fork;
mod mutate;
mod mutators;
pub mod propose;
mod rng;

pub use cfg::DistanceTable;
pub use exec::{
    run_targeted, run_targeted_with, Deployment, ExecConfig, GuardContext, GuardFeedback,
    OutcomeKind, ProposalBudget, Proposer, ProposerCtx, RecordedCall, RunFeedback, SessionReport,
    WitnessTrace,
};
pub use fork::{pin_block, responder_runtime, responder_runtime_sender, ForkConfig, ForkDb};
pub use loom_fuzz_seed::{HitView, Input, Tail, Target, ValueDictionary};
pub use propose::DictionaryProposer;
pub use rng::Rng;
