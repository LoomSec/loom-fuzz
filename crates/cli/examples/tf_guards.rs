//! 临时：dump TeamFinance migrate hit 的全部守卫 cond + shard sstore 形态。
fn main() {
    let shard = loom_fuzz_shard::Shard::from_bytes(
        &std::fs::read("fixtures/real-world/teamfinance-locktoken/teamfinance-impl.lst").unwrap(),
    )
    .unwrap();
    let view = loom_fuzz_xlayer::Xlayer::new(&shard);
    let _ = view;
    // 模式 B 装载拿 hit + guards
    let hitset = loom_fuzz_cli::load_from_shard(
        std::path::Path::new("fixtures/real-world/teamfinance-locktoken/teamfinance-impl.lst"),
        std::path::Path::new("fixtures/real-world/teamfinance-locktoken/TeamFinanceLockToken-impl.bin-runtime"),
    )
    .unwrap();
    for h in &hitset.hits {
        if h.selector != 0xb86f3ea6 { continue; }
        println!("=== migrate hit guards:");
        for g in &h.dominating_guards {
            println!("  [{}] {}", g.polarity, g.cond);
        }
    }
    // shard 原始事实：sstore 效果形态（前若干条）
    println!("=== shard functions: {}", shard.functions().len());
}
