//! The high-performance async Onced gateway binary (tokio + axum + reqwest).
//!
//! Same exactly-once engine, abuse rules, sharding, and durability as
//! `onced-gateway`, but with an async transport: HTTP keep-alive on the front,
//! a connection-pooled backend client, and async backend forwards.
//!
//! Configured via environment variables (same as `onced-gateway`, plus an
//! `http(s)://` backend base is accepted):
//!   - `ONCED_LISTEN` — address to listen on (default `127.0.0.1:8080`)
//!   - `ONCED_BACKEND` — backend base URL or host:port (default `127.0.0.1:9000`)
//!   - `ONCED_WAL` — WAL path prefix; shard `i` uses `<prefix>.<i>.wal`
//!   - `ONCED_SHARDS` — shard count (default: CPU count)
//!   - `ONCED_FINGERPRINT_KEY` — 64 lowercase hex chars (32 bytes); HMAC-SHA256 key
//!     for request fingerprints. If absent, derived from the WAL prefix.
//!
//! Run: `ONCED_BACKEND=127.0.0.1:9000 cargo run --release -p onced-fast`

use onced_core::abuse::{Action, RuleSet};
use onced_core::engine::Engine;
use onced_core::hash::sha256;
use onced_core::wal::WalStore;
use onced_fast::{serve_fast, Proxy};
use onced_gateway::gateway::{Gateway, NoopUpstream};
use onced_gateway::router::Router;
use onced_gateway::server::now_ms;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;

const LEASE_MS: u64 = 30_000;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listen = env_or("ONCED_LISTEN", "127.0.0.1:8080");
    let backend = env_or("ONCED_BACKEND", "127.0.0.1:9000");
    let wal_prefix = env_or("ONCED_WAL", "onced-fast");
    let shard_count = env_shards();

    let fingerprint_key = env_fingerprint_key(&wal_prefix);

    // One shard per slot: own engine + WAL, empty rule set (the router owns
    // abuse), and a NoopUpstream (the async transport forwards out of band).
    let mut shards = Vec::with_capacity(shard_count);
    for i in 0..shard_count {
        let wal_path = PathBuf::from(format!("{wal_prefix}.{i}.wal"));
        let store = WalStore::open(&wal_path)?;
        shards.push(
            Gateway::new(Engine::new(store, LEASE_MS), RuleSet::new(), NoopUpstream)
                .with_fingerprint_key(fingerprint_key),
        );
    }
    let abuse = (0..shard_count)
        .map(|_| RuleSet::new().rule("per-ip-per-second", 1_000, 50, Action::Throttle))
        .collect();
    let router = Router::new(shards, abuse, NoopUpstream);
    let proxy = Arc::new(Proxy::new(router, backend.clone()));

    // Background sweep: reclaim expired keys + compact each WAL, off the hot path.
    let pruner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PRUNE_INTERVAL);
        loop {
            tick.tick().await;
            pruner.router().prune_expired(now_ms());
        }
    });

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!("onced-fast: listening on {listen}, forwarding to {backend}, {shard_count} shards");
    serve_fast(listener, proxy).await
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_shards() -> usize {
    std::env::var("ONCED_SHARDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| available_parallelism().map(|n| n.get()).unwrap_or(1))
}

/// The HMAC-SHA256 fingerprint key (see `onced-gateway/src/main.rs` for full
/// rationale). Reads `ONCED_FINGERPRINT_KEY` (64 lowercase hex chars = 32 bytes)
/// or falls back to `sha256(wal_prefix)` for a stable process-local default.
fn env_fingerprint_key(wal_prefix: &str) -> [u8; 32] {
    if let Ok(hex) = std::env::var("ONCED_FINGERPRINT_KEY") {
        if let Some(key) = parse_hex32(&hex) {
            return key;
        }
        eprintln!(
            "onced-fast: ONCED_FINGERPRINT_KEY must be exactly 64 lowercase hex characters; \
             falling back to derived key"
        );
    }
    sha256(wal_prefix.as_bytes())
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
