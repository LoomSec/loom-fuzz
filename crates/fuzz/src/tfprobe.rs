//! 临时诊断（issue #41 TeamFinance，提交前移除）：3 步序列逐步执行。
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use alloy_primitives::U256;
    use loom_fuzz_seed::{Input, Step, Tail, TxSequence};

    use crate::exec::{ExecConfig, OutcomeKind};
    use crate::fork::ForkConfig;

    fn hexb(s: &str) -> Vec<u8> {
        let s = s.trim().trim_start_matches("0x");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn read_input(path: &str, value: U256) -> Input {
        let text = std::fs::read_to_string(path).unwrap();
        let hex = text.trim().trim_start_matches("0x");
        let cd: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let (head, _) = cd[4..].as_chunks::<32>();
        Input {
            selector: u32::from_be_bytes(cd[..4].try_into().unwrap()),
            caller: [0x33; 20],
            value,
            head: head.to_vec(),
            tail: Tail::Bytes(cd[4 + head.len() * 32..].to_vec()),
        }
    }

    #[test]
    fn probe_migrate_hit_confirms() {
        if std::env::var("LOOM_FUZZ_FORK_TEST").ok().as_deref() != Some("1") {
            eprintln!("fork 探针跳过");
            return;
        }
        let code = hexb(
            &std::fs::read_to_string(
                "../../fixtures/real-world/teamfinance-locktoken/TeamFinanceLockToken-impl.bin-runtime",
            )
            .unwrap(),
        );
        let mut proxy = [0u8; 20];
        proxy.copy_from_slice(&hexb("0xE2fE530C047f2d85298b07D9333C05737f1435fB"));
        let cfg = ExecConfig {
            code,
            address: proxy,
            prestate: BTreeMap::new(),
            seed_rng: 1,
            max_runs: 3,
            time_budget: Duration::from_secs(120),
            gas_per_tx: 2_000_000,
            run_baseline: false,
            fork: Some(ForkConfig {
                rpc_url: std::env::var("BLOCKMACHINE_RPC_URL").unwrap(),
                block_number: 15837893,
            }),
            deployments: Vec::new(),
            entry: None,
            max_steps: 1,
            dynamic_head_evidence: false,
            guard_context: Vec::new(),
        };
        struct H;
        impl loom_fuzz_seed::HitView for H {
            fn selector(&self) -> u32 { 0xb86f3ea6 }
            fn target_pcs(&self) -> &[u32] { &[8143] }
            fn evidence(&self) -> &str { "" }
        }
        let hit = H;
        let target = loom_fuzz_seed::Target { hit: &hit, func: 0 };
        let base = "../../fixtures/real-world/teamfinance-locktoken";
        let seq = TxSequence {
            steps: vec![
                Step { target: proxy, input: read_input(&format!("{base}/seed-lockToken.hex"), U256::from(500000000000000000u128)) },
                Step { target: proxy, input: read_input(&format!("{base}/seed-extendLockDuration.hex"), U256::ZERO) },
                Step { target: proxy, input: read_input(&format!("{base}/seed-migrate.hex"), U256::ZERO) },
            ],
        };
        let report = crate::run_targeted(&cfg, &target, &[seq], &loom_fuzz_seed::ValueDictionary { words: vec![] });
        eprintln!("reached={} runs={} outcomes={:?}", report.reached, report.runs_completed, report.trace.step_outcomes);
        for c in &report.trace.calls {
            if c.pc.is_some_and(|p| p >= 8143) {
                let hex: String = c.target.iter().fold(String::new(), |mut s, b| { use std::fmt::Write as _; let _ = write!(s, "{b:02x}"); s });
                eprintln!("   pc>=8143: {} -> 0x{} step={} in_len={}", c.kind, hex, c.step, c.input.len());
            }
        }
    }

    #[test]
    fn probe_teamfinance_three_step() {
        if std::env::var("LOOM_FUZZ_FORK_TEST").ok().as_deref() != Some("1") {
            eprintln!("fork 探针跳过");
            return;
        }
        let code = hexb(
            &std::fs::read_to_string(
                "../../fixtures/real-world/teamfinance-locktoken/TeamFinanceLockToken-impl.bin-runtime",
            )
            .unwrap(),
        );
        let mut proxy = [0u8; 20];
        proxy.copy_from_slice(&hexb("0xE2fE530C047f2d85298b07D9333C05737f1435fB"));
        let cfg = ExecConfig {
            code,
            address: proxy,
            prestate: BTreeMap::new(),
            seed_rng: 1,
            max_runs: 1,
            time_budget: Duration::from_secs(120),
            gas_per_tx: 2_000_000,
            run_baseline: false,
            fork: Some(ForkConfig {
                rpc_url: std::env::var("BLOCKMACHINE_RPC_URL").unwrap(),
                block_number: 15837893,
            }),
            deployments: Vec::new(),
            entry: None,
            max_steps: 3,
            dynamic_head_evidence: false,
            guard_context: Vec::new(),
        };
        let base = "../../fixtures/real-world/teamfinance-locktoken";
        // id 扫描：lockToken 成功后逐 id 试 extend，定位真实 nextId。
        for id in 15318u64..15332 {
            let cd = format!("{:08x}", 0x76704de0u32)
                + &format!("{id:064x}")
                + &format!("{:064x}", 1666895384u64);
            let hexb2 = |s: &str| -> Vec<u8> {
                (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
            };
            let ext_cd = hexb2(&cd);
            let (h, _) = ext_cd[4..].as_chunks::<32>();
            let seq = TxSequence {
                steps: vec![
                    Step { target: proxy, input: read_input(&format!("{base}/seed-lockToken.hex"), U256::from(500000000000000000u128)) },
                    Step { target: proxy, input: Input {
                        selector: 0x76704de0,
                        caller: [0x33; 20],
                        value: U256::ZERO,
                        head: h.to_vec(),
                        tail: Tail::Empty,
                    } },
                ],
            };
            let run = crate::evm::execute(&cfg, &seq, 10_000_000, &[]);
            eprintln!("id={id}: outcomes={:?}", run.trace.step_outcomes);
        }
        for (tag, lock_value) in [("value=0", U256::ZERO), ("value=0.5e18", U256::from(500000000000000000u128))] {
            let seq = TxSequence {
                steps: vec![
                    Step { target: proxy, input: read_input(&format!("{base}/seed-lockToken.hex"), lock_value) },
                    Step { target: proxy, input: read_input(&format!("{base}/seed-extendLockDuration.hex"), U256::ZERO) },
                    Step { target: proxy, input: read_input(&format!("{base}/seed-migrate.hex"), U256::ZERO) },
                ],
            };
            let run = crate::evm::execute(&cfg, &seq, 10_000_000, &[]);
            eprintln!("=== {tag}: step_outcomes={:?}", run.trace.step_outcomes);
            for c in &run.trace.calls {
                let hex: String = c
                    .target
                    .iter()
                    .fold(String::new(), |mut s, b| {
                        use std::fmt::Write as _;
                        let _ = write!(s, "{b:02x}");
                        s
                    });
                eprintln!(
                    "   {} -> 0x{} pc={:?} step={} in_len={}",
                    c.kind, hex, c.pc, c.step, c.input.len()
                );
            }
            let _ = OutcomeKind::Stop;
        }
    }
}
