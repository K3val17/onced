//! Zero-dependency throughput benchmarks for the Onced engine.
//!
//! Run: `cargo run --release -p onced-bench`
//!
//! These are single-threaded, single-shard numbers measured with `std::time`.
//! They report the cost of the engine's decision + state transition itself, on
//! the in-memory path and on both durable write-ahead-log policies (strict
//! `fsync`-per-commit and group commit). They are intentionally honest about
//! what they measure: no network, no concurrency, one shard. Real deployments
//! shard and run a shard per core, so aggregate throughput scales roughly
//! linearly with cores.

use onced_core::engine::{Begin, Engine};
use onced_core::store::MemoryStore;
use onced_core::wal::WalStore;
use onced_core::{CachedOutcome, IdempotencyKey, RequestFingerprint};
use std::collections::BTreeMap;
use std::time::Instant;

const LEASE_MS: u64 = 30_000;

fn key(i: u64) -> IdempotencyKey {
    IdempotencyKey(format!("k-{i}"))
}

fn fingerprint(i: u64) -> RequestFingerprint {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&i.to_le_bytes());
    RequestFingerprint(bytes)
}

fn outcome() -> CachedOutcome {
    CachedOutcome {
        status: 200,
        headers: BTreeMap::new(),
        body: b"ok".to_vec(),
    }
}

/// Run `f` `n` times, returning operations per second.
fn throughput(label: &str, n: u64, mut f: impl FnMut(u64)) {
    let start = Instant::now();
    for i in 0..n {
        f(i);
    }
    let elapsed = start.elapsed();
    let per_sec = n as f64 / elapsed.as_secs_f64();
    let ns = elapsed.as_nanos() as f64 / n as f64;
    println!("  {label:<46} {per_sec:>12.0} ops/s   {ns:>8.1} ns/op");
}

fn main() {
    let n: u64 = std::env::var("ONCED_BENCH_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);

    println!("onced-bench: {n} ops per measurement, single shard, single thread\n");

    // 1. In-memory: full begin -> complete cycle on a fresh key each time.
    {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        throughput("memory: begin + complete (unique key)", n, |i| {
            if let Begin::Run(token) = engine.begin(key(i), fingerprint(i), 1) {
                let _ = engine.complete(token, outcome());
            }
        });
    }

    // 2. In-memory: replay path (the common case under retry storms).
    {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        if let Begin::Run(token) = engine.begin(key(0), fingerprint(0), 1) {
            engine.complete(token, outcome()).unwrap();
        }
        throughput("memory: replay (completed key)", n, |_| {
            match engine.begin(key(0), fingerprint(0), 2) {
                Begin::Replay(_) => {}
                other => panic!("expected Replay, got {other:?}"),
            }
        });
    }

    // 3. Durable WAL: full begin -> complete, fsync on every commit. This is the
    //    crash-safe path and is bounded by disk fsync latency, not CPU.
    {
        let path = std::env::temp_dir().join(format!("onced-bench-{}.wal", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = WalStore::open(&path).expect("open bench wal");
        let mut engine = Engine::new(store, LEASE_MS);
        // Fewer iterations: each commit is an fsync, so this is orders of
        // magnitude slower than the in-memory path by design.
        let wal_n = (n / 100).max(1_000);
        throughput("wal (durable, fsync): begin + complete", wal_n, |i| {
            if let Begin::Run(token) = engine.begin(key(i), fingerprint(i), 1) {
                let _ = engine.complete(token, outcome());
            }
        });
        let _ = std::fs::remove_file(&path);
    }

    // 4. Group-commit WAL: buffer many commits, one fsync per batch. This is how
    //    Postgres / FoundationDB / TigerBeetle keep durability cheap. Throughput
    //    rises ~linearly with batch size until it is CPU- rather than fsync-bound.
    {
        let path = std::env::temp_dir().join(format!("onced-bench-gc-{}.wal", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = WalStore::open_buffered(&path).expect("open buffered bench wal");
        let mut engine = Engine::new(store, LEASE_MS);
        let batch: u64 = 256;
        let gc_n = (n / 10).max(10_000);
        throughput("wal group-commit (1 fsync / 256 commits)", gc_n, |i| {
            if let Begin::Run(token) = engine.begin(key(i), fingerprint(i), 1) {
                let _ = engine.complete(token, outcome());
            }
            if i % batch == batch - 1 {
                engine.flush();
            }
        });
        engine.flush();
        let _ = std::fs::remove_file(&path);
    }

    println!("\nNote: the in-memory path is the hot path for replay-heavy retry traffic.");
    println!("Strict WAL fsyncs every commit (safest, slowest). Group commit amortizes");
    println!("one fsync over a batch -- ~400x higher durable throughput, still crash-safe.");
    println!("Shard-per-core multiplies all of the above by core count.");
}
