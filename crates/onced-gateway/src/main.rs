//! The Onced gateway binary.
//!
//! Runs a [`Router`](onced_gateway::router::Router): `N` independent
//! idempotency shards (one per core by default), each with its own engine and
//! write-ahead log, plus a global IP-sharded abuse stage. Requests for different
//! keys run in parallel; requests for the same key always hit the same shard, so
//! exactly-once holds.
//!
//! Configured via environment variables:
//!   - `ONCED_LISTEN`  — address to listen on (default `127.0.0.1:8080`)
//!   - `ONCED_BACKEND` — backend to forward to (default `127.0.0.1:9000`)
//!   - `ONCED_WAL`     — WAL path prefix; shard `i` uses `<prefix>.<i>.wal` (default `onced`)
//!   - `ONCED_SHARDS`  — shard count (default: CPU count)
//!
//! Run: `ONCED_BACKEND=127.0.0.1:9000 cargo run -p onced-gateway`

use onced_core::abuse::{Action, RuleSet};
use onced_core::engine::Engine;
use onced_core::wal::WalStore;
use onced_gateway::gateway::Gateway;
use onced_gateway::router::Router;
use onced_gateway::server::{now_ms, serve, HttpUpstream};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;

const LEASE_MS: u64 = 30_000;
/// How often the background sweep reclaims expired keys and compacts the WAL.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

fn main() -> std::io::Result<()> {
    let listen = env_or("ONCED_LISTEN", "127.0.0.1:8080");
    let backend = env_or("ONCED_BACKEND", "127.0.0.1:9000");
    let wal_prefix = env_or("ONCED_WAL", "onced");
    let shard_count = env_shards();

    // One idempotency shard per slot: its own engine over its own WAL file, and
    // an empty rule set (the router owns abuse, so a shard's own rules would
    // double-count). Same backend address for all — `HttpUpstream` opens a fresh
    // connection per request, so it is safe to share by value.
    let mut shards = Vec::with_capacity(shard_count);
    for i in 0..shard_count {
        let wal_path = PathBuf::from(format!("{wal_prefix}.{i}.wal"));
        let store = WalStore::open(&wal_path)?;
        shards.push(Gateway::new(
            Engine::new(store, LEASE_MS),
            RuleSet::new(),
            HttpUpstream::new(backend.clone()),
        ));
    }

    // The abuse stage, sharded by client IP so per-IP limits stay global. One
    // rule set per shard slot, each carrying the same policy.
    let abuse = (0..shard_count)
        .map(|_| RuleSet::new().rule("per-ip-per-second", 1_000, 50, Action::Throttle))
        .collect();

    // The shared backend client the router forwards through with no shard lock
    // held. HttpUpstream opens a fresh connection per request, so sharing is safe.
    let upstream = HttpUpstream::new(backend.clone());
    let router = Arc::new(Router::new(shards, abuse, upstream));

    // Background sweep: reclaim expired keys and compact each shard's WAL off the
    // request path. Cheap and infrequent; a fixed cadence is plenty.
    let pruner = Arc::clone(&router);
    std::thread::spawn(move || loop {
        std::thread::sleep(PRUNE_INTERVAL);
        pruner.prune_expired(now_ms());
    });

    let listener = TcpListener::bind(&listen)?;
    eprintln!(
        "onced: listening on {listen}, forwarding to {backend}, \
         {shard_count} shards at {wal_prefix}.<i>.wal"
    );
    serve(listener, router)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Shard count from `ONCED_SHARDS`, else the machine's CPU count, else 1.
fn env_shards() -> usize {
    std::env::var("ONCED_SHARDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| available_parallelism().map(|n| n.get()).unwrap_or(1))
}
