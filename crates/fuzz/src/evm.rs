//! revm 42 集成：单合约会话执行 + witness inspector。
//!
//! 部署不走 create 交易：`CacheDB` 直接布置合约账户与 prestate 槽；
//! `TxEnv` = call(entry 或 address) + caller/value/calldata（多合约
//! 在场时 entry 为表内入口合约，issue #34）。每 run 新建 EVM
//! （CacheDB 从 `ExecConfig` 原始布置重建，journal 无跨 run 泄漏），
//! 保证确定性。详见 lib.rs 的 revm 集成方式文档注释。

use std::collections::BTreeSet;

use alloy_primitives::U256;
use revm::handler::MainnetContext;
use revm::{
    bytecode::{opcode, Bytecode},
    context::{CfgEnv, Context, TxEnv},
    context_interface::ContextTr,
    database::CacheDB,
    database_interface::EmptyDB,
    inspector::Inspector,
    interpreter::{
        interpreter_types::{Jumps, LoopControl},
        CallInputs, CallScheme, CreateInputs, Interpreter, InterpreterAction, InterpreterResult,
    },
    primitives::{hardfork::SpecId, Address, Bytes, TxKind},
    InspectCommitEvm, MainBuilder, MainContext,
};

use crate::exec::{ExecConfig, OutcomeKind, RecordedCall, WitnessTrace};
use loom_fuzz_seed::{Input, Tail, TxSequence};

/// 单 run 的执行结果（内部表示，序列化形态见 WitnessTrace）。
pub(crate) struct RunResult {
    pub trace: WitnessTrace,
    /// fitness 计算所需的 visited pcs（各步并集，有序去重）。
    pub visited_pcs: Vec<u32>,
    /// 本 run 观测到的比较操作数对（LT/GT/SLT/SGT/EQ，step 时栈顶
    /// 两元；ISZERO 不收——单操作数，无回灌价值）。
    pub cmp_observed: Vec<[U256; 2]>,
    /// 本 run 观测到的 storage 键值对（SLOAD：step 记键、step_end
    /// 收值）。
    pub storage_observed: Vec<(U256, U256)>,
    /// revert 归因：最近经过的支配 guard（ExecConfig.guard_context
    /// 非空且某步 Revert 时产出——取最近 revert 步的归因）。
    pub feedback_guard: Option<crate::exec::GuardFeedback>,
}

/// 泛型上下文：Genesis（EmptyDB）与 fork（ForkDb 包装）通用。
type CtxFor<DB> = MainnetContext<CacheDB<DB>>;

/// witness inspector：`step` 记 pc + 比较操作数 + SLOAD 键；`step_end`
/// 收 SLOAD 值；`call`/`create` 记 CALL 族效果；步数超上限主动 OOG
/// 截停。
pub(crate) struct WitnessInspector {
    step_cap: u64,
    steps: u64,
    /// step 流最后一条 pc（call 钩子在 CALL 指令执行后触发，此值
    /// 即 CALL/CREATE 指令的 pc）。
    last_pc: Option<u32>,
    visited: BTreeSet<u32>,
    /// 访问序（revert 归因："最近经过的支配 guard" = visited 序的
    /// 最后一个 guard pc）。
    visited_order: Vec<u32>,
    calls: Vec<RecordedCall>,
    /// 步数上限触发的截停（gas 未耗尽，人为截停，如实标 truncated）。
    step_capped: bool,
    /// 比较操作数观测（#6 算子 1 的变异池来源）。
    cmp_observed: Vec<[U256; 2]>,
    /// SLOAD 观测（#6 算子 4 的变异池来源）。
    storage_observed: Vec<(U256, U256)>,
    /// step 时暂存的 SLOAD 键，step_end 对值。
    pending_sload: Option<U256>,
}

impl WitnessInspector {
    fn new(step_cap: u64) -> Self {
        WitnessInspector {
            step_cap,
            steps: 0,
            last_pc: None,
            visited: BTreeSet::new(),
            visited_order: Vec::new(),
            calls: Vec::new(),
            step_capped: false,
            cmp_observed: Vec::new(),
            storage_observed: Vec::new(),
            pending_sload: None,
        }
    }
}

/// 收比较操作数的指令家族（ISZERO 除外：单操作数，无回灌价值）。
fn is_cmp(op: u8) -> bool {
    matches!(
        op,
        opcode::LT | opcode::GT | opcode::SLT | opcode::SGT | opcode::EQ
    )
}

impl<DB: revm::DatabaseRef> Inspector<CtxFor<DB>> for WitnessInspector {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut CtxFor<DB>) {
        self.steps += 1;
        let pc = interp.bytecode.pc() as u32;
        self.last_pc = Some(pc);
        self.visited.insert(pc);
        self.visited_order.push(pc);
        // 比较操作数观测：step 在指令执行前触发，栈顶两元即操作数。
        // 两侧都收（不判定比较结果——结果条件收需要 step_end 回读已
        // 弹出的操作数，机制复杂且无收益：收两侧天然覆盖"未通过的
        // 一侧"）。
        let op = interp.bytecode.opcode();
        if is_cmp(op) {
            if let (Ok(a), Ok(b)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                self.cmp_observed.push([a, b]);
            }
        } else if op == opcode::SLOAD {
            // step_end 收值（值在指令执行后上栈）。
            self.pending_sload = interp.stack.peek(0).ok();
        }
        if self.steps >= self.step_cap {
            // 主动截停：按 OOG 收尾（gas 记满额），上层据
            // `step_capped` 如实标 truncated。
            self.step_capped = true;
            let result = InterpreterResult::new_oog(interp.gas.limit(), 0);
            interp
                .bytecode
                .set_action(InterpreterAction::Return(result));
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter, _context: &mut CtxFor<DB>) {
        if let Some(key) = self.pending_sload.take() {
            if let Ok(value) = interp.stack.peek(0) {
                self.storage_observed.push((key, value));
            }
        }
    }

    fn call(
        &mut self,
        context: &mut CtxFor<DB>,
        inputs: &mut CallInputs,
    ) -> Option<revm::interpreter::CallOutcome> {
        let kind = match inputs.scheme {
            CallScheme::Call => "CALL",
            CallScheme::CallCode => "CALLCODE",
            CallScheme::DelegateCall => "DELEGATECALL",
            CallScheme::StaticCall => "STATICCALL",
        };
        // SharedBuffer 指向的共享内存会被子帧归还覆写：立即拷贝。
        let input = inputs.input.bytes(context).to_vec();
        // 顶层交易帧也过本钩子（step 流为空，last_pc = None）：它不是
        // CALL 指令的执行期效果，不记。
        self.last_pc?;
        self.calls.push(RecordedCall {
            kind: kind.to_string(),
            from: inputs.caller.into_array(),
            step: 0,
            target: inputs.target_address.into_array(),
            value: inputs.value.get(),
            input,
            pc: self.last_pc,
        });
        None
    }

    fn create(
        &mut self,
        context: &mut CtxFor<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<revm::interpreter::CreateOutcome> {
        let scheme = inputs.scheme();
        let kind = match scheme {
            revm::interpreter::CreateScheme::Create => "CREATE",
            revm::interpreter::CreateScheme::Create2 { .. } => "CREATE2",
            revm::interpreter::CreateScheme::Custom { .. } => "CREATE",
        };
        self.last_pc?;
        // CREATE 目标地址 = creator 地址 + nonce（CREATE2 再加盐与
        // initcode hash）；nonce 从 journal 现取，取不到退化为 0
        // （created_address 退化为 creator+0 形态，如实记录即可）。
        let nonce = revm::context_interface::JournalTr::load_account(
            context.journal_mut(),
            inputs.caller(),
        )
        .map(|load| load.data.info.nonce)
        .unwrap_or(0);
        let target = inputs.created_address(nonce).into_array();
        self.calls.push(RecordedCall {
            kind: kind.to_string(),
            from: inputs.caller().into_array(),
            step: 0,
            target,
            value: inputs.value(),
            input: inputs.init_code().to_vec(),
            pc: self.last_pc,
        });
        None
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: revm::primitives::U256) {
        self.calls.push(RecordedCall {
            kind: "SELFDESTRUCT".to_string(),
            from: contract.into_array(),
            step: 0,
            target: target.0.into(),
            value,
            input: Vec::new(),
            pc: self.last_pc,
        });
    }
}

/// 单 run：布置世界状态 → **逐步执行调用序列**（同一 CacheDB
/// overlay 续跑，`inspect_tx_commit` 逐步提交——状态跨步持久，
/// revert 步只回滚自身效果）→ 收 witness。各步 input 序列化为
/// calldata（selector 4B + head 原样拼接 + tail 原样拼接；执行器
/// 不感知 ABI，指针槽正确性是种子/变异器的责任，见 lib.rs 职责
/// 边界）。
///
/// fork 态（cfg.fork = Some）：世界 = CacheDB(远端 AlloyDB 读路径 +
/// 共享缓存) 叠层——overlay（合约/prestate/deployments/caller）照旧
/// 写 CacheDB 本地，miss 时按 pin block 远程读（on-demand，任何深度）。
///
/// `targets` = 目标 pc 集合（排序）：定位**到达步**——trace.truncated
/// 只计到达步及其之前的截断（之后的步不影响已成立的到场见证，如实
/// 不夸大 inconclusive）。
pub(crate) fn execute(
    cfg: &ExecConfig,
    seq: &TxSequence,
    step_cap: u64,
    targets: &[u32],
) -> RunResult {
    match &cfg.fork {
        None => execute_on(cfg, CacheDB::new(EmptyDB::new()), seq, step_cap, targets),
        Some(fork) => {
            let key = std::env::var("BLOCKMACHINE_API_KEY").unwrap_or_default();
            let remote =
                crate::fork::ForkDb::shared(fork, &key).expect("CLI 已校验 fork 连通性（契约内）");
            execute_on(
                cfg,
                CacheDB::new(revm::database_interface::WrapDatabaseRef(remote)),
                seq,
                step_cap,
                targets,
            )
        }
    }
}

/// 世界布置 + 执行（DB 泛型：Genesis 空库 / fork 远端）。
fn execute_on<DB: revm::DatabaseRef>(
    cfg: &ExecConfig,
    mut db: CacheDB<DB>,
    seq: &TxSequence,
    step_cap: u64,
    targets: &[u32],
) -> RunResult {
    // 合约账户（固定布置，不走 create 交易）。
    db.insert_account_info(
        Address::from(cfg.address),
        revm::state::AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code: Some(Bytecode::new_legacy(Bytes::from(cfg.code.clone()))),
            ..Default::default()
        },
    );
    // prestate 存储槽。
    for (slot, value) in &cfg.prestate {
        db.insert_account_storage(Address::from(cfg.address), *slot, *value)
            .expect("CacheDB 插槽不落盘，不会失败");
    }
    // fork 后部署的攻击合约（overlay 在远端状态/prestate 之上）。
    for deploy in &cfg.deployments {
        db.insert_account_info(
            Address::from(deploy.address),
            revm::state::AccountInfo {
                balance: U256::ZERO,
                nonce: 1,
                code: Some(Bytecode::new_legacy(Bytes::from(deploy.runtime.clone()))),
                ..Default::default()
            },
        );
    }
    // caller 账户：大额余额（余额敏感分支读到确定值）、nonce 0。
    // 序列各步 caller 可能不同：逐一步布置（重复插入同值，幂等）。
    for step in &seq.steps {
        db.insert_account_info(
            Address::from(step.input.caller),
            revm::state::AccountInfo {
                balance: U256::from(u128::MAX),
                nonce: 0,
                ..Default::default()
            },
        );
    }

    let ctx: CtxFor<DB> =
        Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg_env: &mut CfgEnv| {
                cfg_env.set_spec_and_mainnet_gas_params(SpecId::CANCUN);
                cfg_env.disable_nonce_check = true;
                cfg_env.disable_balance_check = true;
            });

    let mut evm = ctx.build_mainnet_with_inspector(WitnessInspector::new(step_cap));

    // 逐步执行：inspector 每步换新（pc/call 记录不跨步混淆），状态
    // 经 inspect_tx_commit 逐步提交进 overlay（revert 步提交的是
    // 回滚后状态 = 无效果，EVM 语义自然正确）。
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut step_visited: Vec<Vec<u32>> = Vec::with_capacity(seq.steps.len());
    let mut step_outcomes: Vec<OutcomeKind> = Vec::with_capacity(seq.steps.len());
    let mut step_truncs: Vec<bool> = Vec::with_capacity(seq.steps.len());
    let mut calls: Vec<RecordedCall> = Vec::new();
    let mut cmp_observed: Vec<[U256; 2]> = Vec::new();
    let mut storage_observed: Vec<(U256, U256)> = Vec::new();
    let mut gas_used: u64 = 0;
    let mut feedback_guard: Option<crate::exec::GuardFeedback> = None;

    for (i, step) in seq.steps.iter().enumerate() {
        debug_assert!(
            step.target == cfg.address || cfg.deployments.iter().any(|d| d.address == step.target),
            "step.target 须在合约表内（装载层已 fail-closed 校验）"
        );
        evm.inspector = WitnessInspector::new(step_cap);
        let tx = TxEnv::builder()
            .caller(Address::from(step.input.caller))
            .kind(TxKind::Call(Address::from(step.target)))
            .value(step.input.value)
            .data(Bytes::from(calldata_of(&step.input)))
            .gas_limit(cfg.gas_per_tx)
            .build()
            .expect("Legacy 无签名域校验，TxEnv 构造不失败");
        let result = match evm.inspect_tx_commit(tx) {
            Ok(result) => result,
            // 交易验证失败（如 gas limit 低于 intrinsic gas——预算
            // 配置过紧）：如实记该步截断（inconclusive 数据源），
            // 不 panic；后续步照跑（状态未被污染）。
            Err(_e) => {
                step_visited.push(Vec::new());
                step_outcomes.push(OutcomeKind::Invalid);
                step_truncs.push(true);
                gas_used += cfg.gas_per_tx;
                continue;
            }
        };
        // 合并本步 witness（call 的步号如实标注）。
        for mut call in std::mem::take(&mut evm.inspector.calls) {
            call.step = i as u32;
            calls.push(call);
        }
        let inspector = &evm.inspector;
        let (outcome, gas, truncated_by_gas) = map_result(&result);
        let truncated = inspector.step_capped || truncated_by_gas;
        visited.extend(inspector.visited.iter().copied());
        step_visited.push(inspector.visited.iter().copied().collect());
        cmp_observed.extend(inspector.cmp_observed.iter().copied());
        storage_observed.extend(inspector.storage_observed.iter().copied());
        step_outcomes.push(outcome);
        step_truncs.push(truncated);
        gas_used += gas;
        // revert 归因：最近 revert 步的 visited 序最后一个 guard pc。
        if outcome == OutcomeKind::Revert && !cfg.guard_context.is_empty() {
            feedback_guard = inspector.visited_order.iter().rev().find_map(|pc| {
                cfg.guard_context
                    .iter()
                    .find(|g| g.pc == *pc)
                    .map(|g| crate::exec::GuardFeedback {
                        pc: g.pc,
                        cond_rendered: g.cond.clone(),
                        polarity_failed: true,
                    })
            });
        }
    }

    // 到达步 = 首个 visited 含目标 pc 的步；截断如实只计到达步及
    // 之前（之后步的截断不动摇已成立的到场见证）。
    let arrival = step_visited
        .iter()
        .position(|pcs| pcs.iter().any(|pc| targets.contains(pc)));
    let truncated = match arrival {
        Some(k) => step_truncs[..=k].iter().any(|t| *t),
        None => step_truncs.iter().any(|t| *t),
    };
    RunResult {
        trace: WitnessTrace {
            contract: cfg.address,
            visited_pcs: visited.iter().copied().collect(),
            calls,
            outcome: step_outcomes
                .last()
                .copied()
                .unwrap_or(OutcomeKind::Invalid),
            gas_used,
            truncated,
            deployments: cfg.deployments.clone(),
            step_outcomes,
        },
        visited_pcs: visited.iter().copied().collect(),
        cmp_observed,
        storage_observed,
        feedback_guard,
    }
}

/// `Input` → calldata 字节串：selector 4B 大端 + head 槽依次拼接 +
/// tail 原样拼接（`Empty`/`Free` 无尾）。
pub(crate) fn calldata_of(input: &Input) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + input.head.len() * 32);
    out.extend_from_slice(&input.selector.to_be_bytes());
    for word in &input.head {
        out.extend_from_slice(word);
    }
    if let Tail::Bytes(tail) = &input.tail {
        out.extend_from_slice(tail);
    }
    out
}

/// ExecutionResult → (OutcomeKind, gas_used, 燃料截断)。
fn map_result(
    result: &revm::context_interface::result::ExecutionResult,
) -> (OutcomeKind, u64, bool) {
    use revm::context_interface::result::{ExecutionResult, HaltReason, SuccessReason};
    match result {
        ExecutionResult::Success { reason, gas, .. } => {
            let kind = match reason {
                SuccessReason::Return => OutcomeKind::Return,
                SuccessReason::Stop => OutcomeKind::Stop,
                SuccessReason::SelfDestruct => OutcomeKind::SelfDestruct,
            };
            (kind, gas.tx_gas_used(), false)
        }
        ExecutionResult::Revert { gas, .. } => (OutcomeKind::Revert, gas.tx_gas_used(), false),
        ExecutionResult::Halt { reason, gas, .. } => {
            // OOG halt → OutOfGas（truncated 数据源之一）；其它异常
            // halt 统一如实归 Invalid（InvalidFEOpcode/非法跳转/栈
            // 溢出等的细分对 witness 判决无增益，M0 不展开）。
            let oog = matches!(reason, HaltReason::OutOfGas(_));
            let kind = if oog {
                OutcomeKind::OutOfGas
            } else {
                OutcomeKind::Invalid
            };
            (kind, gas.tx_gas_used(), oog)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小字节码：MSTORE 一个 32B word 到 mem[0..32]，CALL 固定
    /// 目标取该 word 作 input，STOP。验证 inspector 确实从共享内存
    /// 记录到了 call input 内容。
    #[test]
    fn inspector_records_call_input_memory() {
        let mut word = [0u8; 32];
        word[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let target = [0x11u8; 20];
        let mut code = Vec::new();
        code.push(0x7f); // PUSH32 word
        code.extend_from_slice(&word);
        code.push(0x60);
        code.push(0x00); // PUSH1 0（mem offset）
        code.push(0x52); // MSTORE
        code.extend_from_slice(&[
            0x60, 0x00, // out size 0
            0x60, 0x00, // out offset 0
            0x60, 0x20, // in size 32
            0x60, 0x00, // in offset 0
            0x60, 0x00, // value 0
        ]);
        code.push(0x73); // PUSH20 target
        code.extend_from_slice(&target);
        code.extend_from_slice(&[0x61, 0xff, 0xff]); // PUSH2 gas
        code.push(0xf1); // CALL
        code.push(0x00); // STOP

        let cfg = ExecConfig {
            code,
            address: [0x22; 20],
            prestate: Default::default(),
            seed_rng: 1,
            max_runs: 1,
            time_budget: std::time::Duration::from_secs(5),
            gas_per_tx: 100_000,
            run_baseline: false,
            fork: None,
            deployments: Vec::new(),
            entry: None,
            max_steps: 1,
            dynamic_head_evidence: false,
            guard_context: Vec::new(),
        };
        let input = Input {
            selector: 0xdeadbeef,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: Vec::new(),
            tail: Tail::Empty,
        };
        let seq = TxSequence::single([0x22; 20], input);
        let run = execute(&cfg, &seq, 1_000_000, &[0]);
        assert_eq!(run.trace.calls.len(), 1);
        let call = &run.trace.calls[0];
        assert_eq!(call.kind, "CALL");
        assert_eq!(call.target, target);
        assert_eq!(call.value, U256::ZERO);
        assert_eq!(call.input, word.to_vec());
        // CALL 指令的 pc = 倒数第二条指令（CALL @ len-2）。
        assert_eq!(call.pc, Some((cfg.code.len() - 2) as u32));
        assert_eq!(run.trace.outcome, OutcomeKind::Stop);
    }

    /// 步数上限触发主动截停：死循环字节码（JUMPDEST 处无条件跳回
    /// 自身）gas 给足也不停机，step_cap 必须兜住并标 truncated。
    #[test]
    fn step_cap_stops_infinite_loop() {
        // pc0: JUMPDEST, pc1: PUSH1 0, pc3: JUMP（目标 0 = JUMPDEST）。
        let code: Vec<u8> = vec![0x5b, 0x60, 0x00, 0x56];
        let cfg = ExecConfig {
            code,
            address: [0x22; 20],
            prestate: Default::default(),
            seed_rng: 1,
            max_runs: 1,
            time_budget: std::time::Duration::from_secs(5),
            gas_per_tx: 1_000_000,
            run_baseline: false,
            fork: None,
            deployments: Vec::new(),
            entry: None,
            max_steps: 1,
            dynamic_head_evidence: false,
            guard_context: Vec::new(),
        };
        let input = Input {
            selector: 0,
            caller: [0x33; 20],
            value: U256::ZERO,
            head: Vec::new(),
            tail: Tail::Empty,
        };
        let seq = TxSequence::single([0x22; 20], input);
        let run = execute(&cfg, &seq, 100, &[0]);
        assert!(run.trace.truncated);
        assert_eq!(run.trace.outcome, OutcomeKind::OutOfGas);
        assert!(run.trace.visited_pcs.len() <= 4);
    }
}
