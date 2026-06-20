//! Shard-per-core routing: turn one lock-bound gateway into N independent
//! shards that run in parallel.
//!
//! # Why shard
//!
//! `onced-core` is **single-threaded per shard** by design (see the `store`
//! module): each shard owns a disjoint slice of keys, so the engine never needs
//! internal locking on the hot path. A single [`Gateway`] behind one `Mutex`
//! honours that — but it also serialises *every* request through one lock,
//! including the slow backend forward. Throughput is then one core's worth no
//! matter how many cores the box has.
//!
//! The [`Router`] keeps the single-threaded-per-shard guarantee while unlocking
//! parallelism: it holds `N` shards, each its own [`Gateway`] over its own
//! engine and write-ahead log, and routes each request to a shard by a stable
//! hash. Requests for different keys land on different shards and run with no
//! shared lock between them, so aggregate throughput scales with shard (≈ core)
//! count. Requests for the *same* key always hash to the same shard, so
//! exactly-once is preserved exactly as in the single-shard case.
//!
//! # Two independent routings
//!
//! A request has two identities, and they must be routed independently:
//!
//! - **Idempotency key** decides the *idempotency* shard. Same key → same shard,
//!   always, or exactly-once would break.
//! - **Client identity (IP)** decides the *abuse* shard. If abuse were sharded by
//!   key instead, one IP's requests would scatter across shards and each shard
//!   would see only a fraction of that IP's traffic — so the effective rate
//!   limit would silently become `limit × N`.
//!
//! So the router runs a **separate, IP-sharded abuse stage first**, then
//! dispatches the surviving request to its key shard. The per-shard gateways are
//! built with empty rule sets; the router owns all abuse decisions.

use crate::gateway::{
    health_ok, metrics_response, path_of, too_many_requests, BeginPhase, Gateway, Metrics, Upstream,
};
use crate::http::{Request, Response};
use crate::server::Handle;
use onced_core::abuse::{RuleSet, Verdict};
use onced_core::store::Store;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// A sharded gateway: `N` independent idempotency shards plus a separate,
/// IP-sharded abuse stage. Implements [`Handle`], so the server drives it
/// exactly like a single gateway.
pub struct Router<S: Store, U: Upstream> {
    /// One idempotency shard per slot, each its own engine + WAL behind its own
    /// lock. Indexed by `hash(idempotency-key) % shards.len()`.
    shards: Vec<Mutex<Gateway<S, U>>>,
    /// Abuse rule sets, indexed by `hash(client-identity) % abuse.len()`, so an
    /// IP's whole traffic lands on one rule set and limits stay global.
    abuse: Vec<Mutex<RuleSet>>,
    /// The shared backend client. The router forwards through this **without**
    /// holding any shard lock, so a slow backend call never blocks other keys on
    /// the same shard. Stateless (a fresh connection per request), hence shared.
    upstream: U,
    /// Requests rejected by the abuse stage (counted here, not in any shard).
    denied: AtomicU64,
    /// Rotating cursor for keyless requests, which carry no idempotency state and
    /// so may go to any shard; round-robin spreads their load evenly.
    next_shard: AtomicUsize,
}

impl<S: Store, U: Upstream> Router<S, U> {
    /// Build a router from per-shard gateways and per-shard abuse rule sets.
    ///
    /// Each [`Gateway`] in `shards` should be constructed with its own engine and
    /// write-ahead log (a distinct WAL path) and an **empty** [`RuleSet`] — the
    /// router owns abuse, so a shard's own rules would double-count. `abuse` is
    /// the IP-sharded rule sets; it need not be the same length as `shards`.
    ///
    /// `upstream` is the shared backend client the router forwards through with
    /// no shard lock held.
    ///
    /// # Panics
    /// If either `shards` or `abuse` is empty.
    pub fn new(shards: Vec<Gateway<S, U>>, abuse: Vec<RuleSet>, upstream: U) -> Self {
        assert!(!shards.is_empty(), "router needs at least one shard");
        assert!(!abuse.is_empty(), "router needs at least one abuse shard");
        Router {
            shards: shards.into_iter().map(Mutex::new).collect(),
            abuse: abuse.into_iter().map(Mutex::new).collect(),
            upstream,
            denied: AtomicU64::new(0),
            next_shard: AtomicUsize::new(0),
        }
    }

    /// Aggregate every shard's counters (plus the router's own `denied`) into one
    /// snapshot for `/metrics`.
    fn aggregate_metrics(&self) -> Metrics {
        let mut total = Metrics::default();
        for shard in &self.shards {
            let shard = shard.lock().unwrap_or_else(|p| p.into_inner());
            total.merge(shard.metrics());
        }
        // Denials happen in the router's abuse stage, not in any shard.
        total.denied += self.denied.load(Ordering::Relaxed);
        total
    }

    /// Index of the idempotency shard that owns `key`.
    fn shard_for_key(&self, key: &str) -> usize {
        hash(key) % self.shards.len()
    }

    /// Index of the abuse shard that owns `identity`.
    fn abuse_for_identity(&self, identity: &str) -> usize {
        hash(identity) % self.abuse.len()
    }
}

impl<S, U> Handle for Router<S, U>
where
    S: Store + Send,
    U: Upstream + Send + Sync,
{
    fn handle(&self, request: &Request, now_ms: u64) -> Response {
        // 1. Operational endpoints are answered by the router itself, before any
        //    sharding — `/metrics` must report the *aggregate*, not one shard.
        match path_of(request) {
            "/healthz" => return health_ok(),
            "/metrics" => return metrics_response(&self.aggregate_metrics()),
            _ => {}
        }

        // 2. Abuse stage, sharded by client identity so each IP's limit is global.
        let identity = request.header("x-forwarded-for").unwrap_or("anonymous");
        let abuse_idx = self.abuse_for_identity(identity);
        {
            let mut rules = self.abuse[abuse_idx]
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Verdict::Deny { rule, action } = rules.evaluate(identity, now_ms) {
                self.denied.fetch_add(1, Ordering::Relaxed);
                return too_many_requests(&rule, action);
            }
        }

        // 3. Idempotency stage, sharded by key. A request with a key always hashes
        //    to the same shard (so exactly-once holds); a keyless request carries
        //    no state, so round-robin it to spread load.
        let shard_idx = match request.header("idempotency-key") {
            Some(key) => self.shard_for_key(key),
            None => self.next_shard.fetch_add(1, Ordering::Relaxed) % self.shards.len(),
        };

        // Phase 1 — under the shard lock, decide. Drop the lock immediately after.
        let ticket = {
            let mut shard = self.shards[shard_idx]
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match shard.begin_phase(request, now_ms) {
                BeginPhase::Done(response) => return response,
                BeginPhase::Forward(ticket) => ticket,
            }
        };

        // Phase 2 — the slow backend call, with **no shard lock held**, so other
        // keys on this shard run in parallel and a concurrent same-key retry sees
        // InProgress and is told to wait.
        let forwarded = self.upstream.forward(request);

        // Phase 3 — re-acquire the lock only to commit the outcome.
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        shard.complete_phase(ticket, forwarded, now_ms)
    }
}

/// A stable, process-local hash for routing. `DefaultHasher` is not
/// cryptographic, but routing only needs a balanced, deterministic spread, and
/// the same string always maps to the same shard within a process — which is all
/// correctness requires.
fn hash(value: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as usize
}

#[cfg(test)]
mod tests {
    use super::Router;
    use crate::gateway::{Gateway, Upstream};
    use crate::http::{Request, Response};
    use crate::server::Handle;
    use onced_core::abuse::{Action, RuleSet};
    use onced_core::engine::Engine;
    use onced_core::store::MemoryStore;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A backend that counts total calls across all shards (shared counter).
    struct CountingUpstream {
        calls: Arc<AtomicU32>,
    }

    impl Upstream for CountingUpstream {
        fn forward(&self, _request: &Request) -> std::io::Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Response {
                status: 201,
                headers: Vec::new(),
                body: b"charged".to_vec(),
            })
        }
    }

    /// Build an `n`-shard router whose shards all forward to one shared call
    /// counter. `abuse` is the router's IP-sharded rule sets.
    fn router(
        n: usize,
        calls: Arc<AtomicU32>,
        abuse: Vec<RuleSet>,
    ) -> Router<MemoryStore, CountingUpstream> {
        let shards = (0..n)
            .map(|_| {
                Gateway::new(
                    Engine::new(MemoryStore::new(), 30_000),
                    RuleSet::new(), // shards never run abuse; the router owns it
                    CountingUpstream {
                        calls: Arc::clone(&calls),
                    },
                )
            })
            .collect();
        // The router forwards through its own shared upstream (same call counter),
        // not the shards' — they exist only to hold per-shard idempotency state.
        let upstream = CountingUpstream {
            calls: Arc::clone(&calls),
        };
        Router::new(shards, abuse, upstream)
    }

    fn post(key: Option<&str>, ip: &str, body: &[u8]) -> Request {
        let mut headers = vec![("X-Forwarded-For".to_string(), ip.to_string())];
        if let Some(key) = key {
            headers.push(("Idempotency-Key".to_string(), key.to_string()));
        }
        Request {
            method: "POST".into(),
            target: "/charge".into(),
            headers,
            body: body.to_vec(),
        }
    }

    fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Exactly-once survives sharding: a retried key always lands on the same
    /// shard, so the backend is hit once and the retry replays — across many
    /// keys spread over several shards.
    #[test]
    fn exactly_once_holds_across_shards() {
        let calls = Arc::new(AtomicU32::new(0));
        let r = router(8, Arc::clone(&calls), vec![RuleSet::new()]);

        // 50 distinct keys, each sent twice. Backend must be hit exactly 50 times.
        for i in 0..50 {
            let key = format!("k{i}");
            let first = r.handle(&post(Some(&key), "10.0.0.1", b"x"), 1_000);
            let second = r.handle(&post(Some(&key), "10.0.0.1", b"x"), 1_010);
            assert_eq!(header(&first, "Onced-Status"), Some("created"));
            assert_eq!(header(&second, "Onced-Status"), Some("replayed"));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            50,
            "each key must reach the backend exactly once despite sharding"
        );
    }

    /// Abuse limits stay global even though idempotency is sharded by key: one IP
    /// hammering many *different* keys (which scatter across shards) is still
    /// blocked once its global quota is exceeded.
    #[test]
    fn abuse_limit_is_global_across_shards() {
        let calls = Arc::new(AtomicU32::new(0));
        // One abuse shard, limit 3 per window, block over it.
        let r = router(
            8,
            Arc::clone(&calls),
            vec![RuleSet::new().rule("strict", 1_000, 3, Action::Block)],
        );

        // Same IP, 5 different keys (so they hit different idempotency shards).
        let mut statuses = Vec::new();
        for i in 0..5 {
            let key = format!("k{i}");
            statuses.push(r.handle(&post(Some(&key), "10.0.0.7", b"x"), 0).status);
        }
        // First 3 allowed (201), the rest blocked (429) — proving the limit is
        // global, not per-shard.
        assert_eq!(statuses, vec![201, 201, 201, 429, 429]);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "blocked requests must not reach the backend"
        );
    }

    /// `/metrics` aggregates across all shards and includes router-level denials.
    #[test]
    fn metrics_aggregate_across_shards() {
        let calls = Arc::new(AtomicU32::new(0));
        let r = router(
            4,
            Arc::clone(&calls),
            vec![RuleSet::new().rule("strict", 1_000, 2, Action::Block)],
        );

        // 2 allowed creates on distinct keys/shards, then 1 denied.
        r.handle(&post(Some("a"), "10.0.0.8", b"x"), 0);
        r.handle(&post(Some("b"), "10.0.0.8", b"x"), 0);
        r.handle(&post(Some("c"), "10.0.0.8", b"x"), 0); // denied

        let body = String::from_utf8(r.handle(&metrics_get(), 0).body).unwrap();
        assert!(body.contains("onced_requests_total 2"), "body: {body}");
        assert!(body.contains("onced_outcomes_total{outcome=\"created\"} 2"));
        assert!(body.contains("onced_outcomes_total{outcome=\"denied\"} 1"));
    }

    fn metrics_get() -> Request {
        Request {
            method: "GET".into(),
            target: "/metrics".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}
