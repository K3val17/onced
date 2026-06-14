//! The Onced gateway binary.
//!
//! Configured via environment variables:
//!   - `ONCED_LISTEN`  — address to listen on   (default `127.0.0.1:8080`)
//!   - `ONCED_BACKEND` — backend to forward to   (default `127.0.0.1:9000`)
//!   - `ONCED_WAL`     — write-ahead log path     (default `onced.wal`)
//!
//! Run: `ONCED_BACKEND=127.0.0.1:9000 cargo run -p onced-gateway`

use onced_core::abuse::{Action, RuleSet};
use onced_core::engine::Engine;
use onced_core::wal::WalStore;
use onced_gateway::gateway::Gateway;
use onced_gateway::server::{serve, HttpUpstream};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

const LEASE_MS: u64 = 30_000;

fn main() -> std::io::Result<()> {
    let listen = env_or("ONCED_LISTEN", "127.0.0.1:8080");
    let backend = env_or("ONCED_BACKEND", "127.0.0.1:9000");
    let wal_path = env_or("ONCED_WAL", "onced.wal");

    let store = WalStore::open(Path::new(&wal_path))?;
    let rules = RuleSet::new().rule("per-ip-per-second", 1_000, 50, Action::Throttle);
    let gateway = Arc::new(Mutex::new(Gateway::new(
        Engine::new(store, LEASE_MS),
        rules,
        HttpUpstream::new(backend.clone()),
    )));

    let listener = TcpListener::bind(&listen)?;
    eprintln!("onced: listening on {listen}, forwarding to {backend}, wal at {wal_path}");
    serve(listener, gateway)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
