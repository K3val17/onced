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
    health_ok, metrics_response, path_of, too_many_requests, BeginPhase, ForwardTicket, Gateway,
    Metrics, Upstream,
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

    /// Reclaim expired keys and compact every shard's store. Call periodically
    /// from a background thread (e.g. once a minute), never on the request path.
    pub fn prune_expired(&self, now_ms: u64) {
        for shard in &self.shards {
            let mut shard = shard.lock().unwrap_or_else(|p| p.into_inner());
            shard.prune_expired(now_ms);
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

    // --- Stages, shared by the sync ([`Handle`]) and async drivers ---

    /// Answer the operational endpoints (`/healthz`, `/metrics`) the router owns
    /// itself, before any sharding. `None` if this is a normal request.
    fn operational_response(&self, request: &Request) -> Option<Response> {
        match path_of(request) {
            "/healthz" => Some(health_ok()),
            // `/metrics` must report the aggregate across shards, not one shard.
            "/metrics" => Some(metrics_response(&self.aggregate_metrics())),
            _ => None,
        }
    }

    /// The abuse stage, sharded by client identity so each IP's limit is global.
    /// `Some(429)` if denied (and counted), `None` if allowed.
    fn deny_if_abusive(&self, request: &Request, now_ms: u64) -> Option<Response> {
        let identity = request.header("x-forwarded-for").unwrap_or("anonymous");
        let idx = self.abuse_for_identity(identity);
        let mut rules = self.abuse[idx].lock().unwrap_or_else(|p| p.into_inner());
        if let Verdict::Deny { rule, action } = rules.evaluate(identity, now_ms) {
            self.denied.fetch_add(1, Ordering::Relaxed);
            Some(too_many_requests(&rule, action))
        } else {
            None
        }
    }

    /// The idempotency shard a request routes to: by key hash if it carries one
    /// (same key → same shard, so exactly-once holds), else round-robin.
    fn route_shard(&self, request: &Request) -> usize {
        match request.header("idempotency-key") {
            Some(key) => self.shard_for_key(key),
            None => self.next_shard.fetch_add(1, Ordering::Relaxed) % self.shards.len(),
        }
    }

    /// Phase 1 under the shard lock: either a final response (`Err`) or a ticket
    /// to forward (`Ok`). The lock is dropped before returning, so the backend
    /// call happens unlocked.
    fn begin_on(
        &self,
        shard_idx: usize,
        request: &Request,
        now_ms: u64,
    ) -> Result<ForwardTicket, Response> {
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match shard.begin_phase(request, now_ms) {
            BeginPhase::Done(response) => Err(response),
            BeginPhase::Forward(ticket) => Ok(ticket),
        }
    }

    /// Phase 3 under the shard lock: commit the backend response (or its failure).
    fn complete_on(
        &self,
        shard_idx: usize,
        ticket: ForwardTicket,
        forwarded: std::io::Result<Response>,
        now_ms: u64,
    ) -> Response {
        let mut shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        shard.complete_phase(ticket, forwarded, now_ms)
    }

    /// Drive a request with an **async** backend forward: operational + abuse +
    /// shard `begin_phase` run synchronously (the shard locks are held only
    /// briefly, never across an `await`), then `forward` is awaited with no lock
    /// held, then `complete_phase` commits. This is what the tokio/hyper transport
    /// uses, so backend calls scale without a thread each. `forward` is invoked
    /// only when the engine actually needs the backend (not on replay/409/422).
    pub async fn handle_async<F, Fut>(&self, request: &Request, now_ms: u64, forward: F) -> Response
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = std::io::Result<Response>>,
    {
        if let Some(response) = self.operational_response(request) {
            return response;
        }
        if let Some(denied) = self.deny_if_abusive(request, now_ms) {
            return denied;
        }
        let shard_idx = self.route_shard(request);
        let ticket = match self.begin_on(shard_idx, request, now_ms) {
            Ok(ticket) => ticket,
            Err(done) => return done,
        };
        let forwarded = forward().await;
        self.complete_on(shard_idx, ticket, forwarded, now_ms)
    }
}

impl<S, U> Handle for Router<S, U>
where
    S: Store + Send,
    U: Upstream + Send + Sync,
{
    fn handle(&self, request: &Request, now_ms: u64) -> Response {
        if let Some(response) = self.operational_response(request) {
            return response;
        }
        if let Some(denied) = self.deny_if_abusive(request, now_ms) {
            return denied;
        }
        let shard_idx = self.route_shard(request);
        // Phase 1 (locked) → Phase 2 backend call (unlocked) → Phase 3 (locked).
        let ticket = match self.begin_on(shard_idx, request, now_ms) {
            Ok(ticket) => ticket,
            Err(done) => return done,
        };
        let forwarded = self.upstream.forward(request);
        self.complete_on(shard_idx, ticket, forwarded, now_ms)
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

    /// Concurrency stress (matklad-style real-thread test, complementing the
    /// deterministic sim): 64 threads hammer the SAME key at once through the
    /// real `Router::handle` (which drops the shard lock during the forward).
    /// Across every interleaving the backend is hit exactly once, exactly one
    /// request is `created`, and the rest replay or are told to wait. Repeated to
    /// shake out timing.
    #[test]
    fn concurrent_same_key_hits_backend_once_under_contention() {
        use std::thread;
        for _ in 0..25 {
            let calls = Arc::new(AtomicU32::new(0));
            let router = Arc::new(router(8, Arc::clone(&calls), vec![RuleSet::new()]));

            let results: Vec<(u16, Option<String>)> = (0..64)
                .map(|_| {
                    let r = Arc::clone(&router);
                    thread::spawn(move || {
                        let resp = r.handle(&post(Some("hot"), "10.0.0.1", b"x"), 1_000);
                        (
                            resp.status,
                            header(&resp, "Onced-Status").map(str::to_string),
                        )
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect();

            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "backend must be hit exactly once under contention"
            );
            let created = results
                .iter()
                .filter(|(_, s)| s.as_deref() == Some("created"))
                .count();
            assert_eq!(created, 1, "exactly one request creates the outcome");
            for (status, tag) in &results {
                assert!(
                    matches!(
                        (status, tag.as_deref()),
                        (201, Some("created"))
                            | (201, Some("replayed"))
                            | (409, Some("in-progress"))
                    ),
                    "unexpected response: {status} {tag:?}"
                );
            }
        }
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
