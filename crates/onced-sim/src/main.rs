//! Extended deterministic-simulation-testing campaign runner.
//!
//! Run a soak: `ONCED_SIM_SEEDS=500 ONCED_SIM_STEPS=4000 cargo run -p onced-sim`
//! On any invariant violation the simulation panics with the exact seed, which
//! reproduces the failure deterministically.

use onced_sim::{Durability, Simulation, Stats};

fn main() {
    let seeds = env_u64("ONCED_SIM_SEEDS", 200);
    let steps = env_u64("ONCED_SIM_STEPS", 2_000);

    // Soak both durability disciplines: strict (fsync per commit) and group
    // commit (one fsync per flush, crashes lose un-flushed writes).
    for mode in [Durability::Strict, Durability::GroupCommit] {
        eprintln!("onced-sim [{mode:?}]: {seeds} seeds x {steps} steps of fault-injected ops...");
        let mut total = Stats::default();
        for seed in 0..seeds {
            let mut sim = Simulation::with_mode(seed, mode);
            let stats = sim.run(steps);
            sim.cleanup();
            total.accumulate(&stats);
            if seed % 25 == 0 {
                eprintln!("  seed {seed}/{seeds} ok");
            }
        }
        println!("[{mode:?}] all invariants held across {seeds} seeds x {steps} steps.");
        println!("{total:#?}");
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
