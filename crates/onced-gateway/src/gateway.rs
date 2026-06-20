//! The gateway handler: where `onced-core`'s idempotency engine and abuse rules
//! meet real HTTP traffic.
//!
//! For each request the handler:
//!   1. runs the abuse [`RuleSet`](onced_core::abuse::RuleSet) over the caller's
//!      identity (the `X-Forwarded-For` header) and returns `429` if it trips;
//!   2. if an `Idempotency-Key` header is present, runs the request through the
//!      engine — replaying the stored response on a retry, and only ever calling
//!      the backend (the [`Upstream`]) **once** per key;
//!   3. otherwise forwards straight through.
//!
//! The backend is abstracted behind the [`Upstream`] trait, so the exactly-once
//! and abuse behaviour can be tested without sockets.
//!
//! Production code is written test-first; the tests below are watched failing
//! before `Gateway` and `Upstream` exist.

use crate::http::{Request, Response};
use onced_core::abuse::{Action, RuleSet, Verdict};
use onced_core::engine::{Begin, Engine};
use onced_core::store::Store;
use onced_core::{CachedOutcome, IdempotencyKey, RequestFingerprint};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

/// The backend the gateway protects. Abstracted so the exactly-once and abuse
/// behaviour can be tested without real sockets.
pub trait Upstream {
    /// Forward `request` to the backend and return its response.
    fn forward(&self, request: &Request) -> std::io::Result<Response>;
}

/// Operational counters the gateway exposes at `/metrics`. Plain `u64`s: the
/// gateway is driven single-threaded per shard (callers serialise on a lock),
/// so no atomics are needed.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    /// Proxied requests (excludes the `/healthz` and `/metrics` endpoints).
    pub requests_total: u64,
    /// First attempts that ran the backend once and cached the outcome.
    pub created: u64,
    /// Retries served from cache without touching the backend.
    pub replayed: u64,
    /// Concurrent duplicates told to retry shortly (`409`).
    pub in_progress: u64,
    /// Key reused with a different request (`422`).
    pub mismatch: u64,
    /// Requests denied by an abuse rule (`429`).
    pub denied: u64,
    /// Backend forwarding failures (`502`).
    pub upstream_error: u64,
    /// Requests forwarded straight through (no `Idempotency-Key`).
    pub passthrough: u64,
}

impl Metrics {
    /// Fold another shard's counters into this one. Used by the sharded
    /// [`Router`](crate::router::Router) to aggregate per-shard metrics into a
    /// single `/metrics` view.
    pub fn merge(&mut self, other: &Metrics) {
        self.requests_total += other.requests_total;
        self.created += other.created;
        self.replayed += other.replayed;
        self.in_progress += other.in_progress;
        self.mismatch += other.mismatch;
        self.denied += other.denied;
        self.upstream_error += other.upstream_error;
        self.passthrough += other.passthrough;
    }

    /// Render as Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP onced_requests_total Proxied requests handled.\n");
        out.push_str("# TYPE onced_requests_total counter\n");
        out.push_str(&format!("onced_requests_total {}\n", self.requests_total));
        out.push_str("# HELP onced_outcomes_total Responses by how they were produced.\n");
        out.push_str("# TYPE onced_outcomes_total counter\n");
        for (outcome, n) in [
            ("created", self.created),
            ("replayed", self.replayed),
            ("in_progress", self.in_progress),
            ("mismatch", self.mismatch),
            ("denied", self.denied),
            ("upstream_error", self.upstream_error),
            ("passthrough", self.passthrough),
        ] {
            out.push_str(&format!(
                "onced_outcomes_total{{outcome=\"{outcome}\"}} {n}\n"
            ));
        }
        out
    }
}

/// The Onced gateway: an idempotency engine, abuse rules, and a backend.
pub struct Gateway<S: Store, U: Upstream> {
    engine: Engine<S>,
    rules: RuleSet,
    upstream: U,
    metrics: Metrics,
}

impl<S: Store, U: Upstream> Gateway<S, U> {
    /// Build a gateway from an engine, a rule set, and a backend.
    pub fn new(engine: Engine<S>, rules: RuleSet, upstream: U) -> Self {
        Self {
            engine,
            rules,
            upstream,
            metrics: Metrics::default(),
        }
    }

    /// A snapshot of the operational counters.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Handle one request end to end (operational endpoints, abuse, then
    /// idempotency) and produce the response to send back to the client. This is
    /// the single-shard entry point; the sharded [`Router`](crate::router::Router)
    /// instead runs a shared abuse stage and calls [`handle_after_abuse`].
    ///
    /// [`handle_after_abuse`]: Gateway::handle_after_abuse
    pub fn handle(&mut self, request: &Request, now_ms: u64) -> Response {
        // Operational endpoints bypass abuse rules and idempotency entirely: a
        // load balancer must be able to poll liveness without a key or a quota.
        match path_of(request) {
            "/healthz" => return health_ok(),
            "/metrics" => return metrics_response(&self.metrics),
            _ => {}
        }

        // Abuse defense, keyed on the caller's identity. In the single-shard
        // case this is the whole abuse stage.
        let identity = request.header("x-forwarded-for").unwrap_or("anonymous");
        if let Verdict::Deny { rule, action } = self.rules.evaluate(identity, now_ms) {
            self.metrics.denied += 1;
            return too_many_requests(&rule, action);
        }

        self.handle_after_abuse(request, now_ms)
    }

    /// The idempotency + passthrough stage, run *after* the abuse check has
    /// already passed.
    ///
    /// The sharded [`Router`](crate::router::Router) calls this directly: it
    /// runs its own shared, IP-sharded abuse stage before dispatch, so abuse
    /// counters stay global even though idempotency state is sharded by key.
    /// `requests_total` counts requests that reached this stage (i.e. were not
    /// denied); denials are counted separately by whoever ran the abuse stage.
    pub fn handle_after_abuse(&mut self, request: &Request, now_ms: u64) -> Response {
        self.metrics.requests_total += 1;

        // Idempotency is opt-in via the Idempotency-Key header (like Stripe).
        let Some(key) = request.header("idempotency-key") else {
            return self.pass_through(request);
        };
        let key = IdempotencyKey(key.to_string());
        let fingerprint = fingerprint_of(request);

        match self.engine.begin(key, fingerprint, now_ms) {
            Begin::Run(token) => {
                let response = match self.upstream.forward(request) {
                    Ok(response) => response,
                    // Leave the token in-progress: its lease lets a later retry
                    // take over rather than wedging the key forever.
                    Err(_) => {
                        self.metrics.upstream_error += 1;
                        return bad_gateway();
                    }
                };
                // Exactly-once holds as long as the backend call finishes within
                // the lease. If it overran and a retry took over, complete()
                // returns an error here and the takeover's result is the one
                // served; pick a lease comfortably above backend latency.
                let _ = self.engine.complete(token, to_outcome(&response));
                self.metrics.created += 1;
                tag(response, "created")
            }
            Begin::Replay(outcome) => {
                self.metrics.replayed += 1;
                tag(from_outcome(outcome), "replayed")
            }
            Begin::InProgress => {
                self.metrics.in_progress += 1;
                tagged_status(409, "in-progress")
            }
            Begin::Mismatch => {
                self.metrics.mismatch += 1;
                tagged_status(422, "mismatch")
            }
        }
    }

    fn pass_through(&mut self, request: &Request) -> Response {
        match self.upstream.forward(request) {
            Ok(response) => {
                self.metrics.passthrough += 1;
                response
            }
            Err(_) => {
                self.metrics.upstream_error += 1;
                bad_gateway()
            }
        }
    }
}

/// The path portion of the request target, without any query string. Shared
/// with the router, which intercepts operational endpoints before sharding.
pub(crate) fn path_of(request: &Request) -> &str {
    request.target.split('?').next().unwrap_or(&request.target)
}

/// The `200 ok` liveness response served at `/healthz`.
pub(crate) fn health_ok() -> Response {
    Response {
        status: 200,
        headers: vec![("Onced-Status".to_string(), "healthy".to_string())],
        body: b"ok".to_vec(),
    }
}

/// The Prometheus-format response served at `/metrics`.
pub(crate) fn metrics_response(metrics: &Metrics) -> Response {
    Response {
        status: 200,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; version=0.0.4".to_string(),
        )],
        body: metrics.render().into_bytes(),
    }
}

/// 256-bit fingerprint of the meaningful request content (method, target, body),
/// so a key reused with a different request is detected as a mismatch.
fn fingerprint_of(request: &Request) -> RequestFingerprint {
    let mut bytes = [0u8; 32];
    for (salt, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut hasher = DefaultHasher::new();
        (salt as u64).hash(&mut hasher);
        request.method.hash(&mut hasher);
        request.target.hash(&mut hasher);
        request.body.hash(&mut hasher);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    RequestFingerprint(bytes)
}

fn to_outcome(response: &Response) -> CachedOutcome {
    CachedOutcome {
        status: response.status,
        headers: response.headers.iter().cloned().collect::<BTreeMap<_, _>>(),
        body: response.body.clone(),
    }
}

fn from_outcome(outcome: CachedOutcome) -> Response {
    Response {
        status: outcome.status,
        headers: outcome.headers.into_iter().collect(),
        body: outcome.body,
    }
}

/// Attach the `Onced-Status` header describing how the response was produced.
fn tag(mut response: Response, status: &str) -> Response {
    response
        .headers
        .push(("Onced-Status".to_string(), status.to_string()));
    response
}

fn tagged_status(code: u16, status: &str) -> Response {
    Response {
        status: code,
        headers: vec![("Onced-Status".to_string(), status.to_string())],
        body: Vec::new(),
    }
}

/// The `429` response for a request denied by an abuse rule. Shared with the
/// router, whose abuse stage produces the same response shape.
pub(crate) fn too_many_requests(rule: &str, action: Action) -> Response {
    let action = match action {
        Action::Challenge => "challenge",
        Action::Throttle => "throttle",
        Action::Block => "block",
    };
    Response {
        status: 429,
        headers: vec![
            ("Onced-Status".to_string(), "denied".to_string()),
            ("Onced-Rule".to_string(), rule.to_string()),
            ("Onced-Action".to_string(), action.to_string()),
        ],
        body: Vec::new(),
    }
}

fn bad_gateway() -> Response {
    Response {
        status: 502,
        headers: vec![("Onced-Status".to_string(), "upstream-error".to_string())],
        body: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::gateway::{Gateway, Upstream};
    use crate::http::{Request, Response};
    use onced_core::abuse::{Action, RuleSet};
    use onced_core::engine::Engine;
    use onced_core::store::MemoryStore;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// An `Upstream` that counts how many times the backend is actually called.
    struct CountingUpstream {
        calls: Arc<AtomicU32>,
        status: u16,
        body: Vec<u8>,
    }

    impl Upstream for CountingUpstream {
        fn forward(&self, _request: &Request) -> std::io::Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Response {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn post(key: Option<&str>, body: &[u8]) -> Request {
        let mut headers = vec![("X-Forwarded-For".to_string(), "10.0.0.1".to_string())];
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

    fn gateway(calls: Arc<AtomicU32>) -> Gateway<MemoryStore, CountingUpstream> {
        Gateway::new(
            Engine::new(MemoryStore::new(), 30_000),
            RuleSet::new(),
            CountingUpstream {
                calls,
                status: 201,
                body: b"charged".to_vec(),
            },
        )
    }

    /// THE headline end-to-end guarantee: retrying with the same key hits the
    /// backend exactly once; the second response is the replayed first one.
    #[test]
    fn retried_request_hits_the_backend_exactly_once() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = gateway(calls.clone());

        let first = gw.handle(&post(Some("k1"), b"amount=100"), 1_000);
        let second = gw.handle(&post(Some("k1"), b"amount=100"), 1_050);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "backend must be called once"
        );
        assert_eq!(first.body, b"charged");
        assert_eq!(second.body, b"charged");
        assert_eq!(second.status, 201);
        assert_eq!(header(&first, "Onced-Status"), Some("created"));
        assert_eq!(header(&second, "Onced-Status"), Some("replayed"));
    }

    #[test]
    fn different_keys_each_reach_the_backend() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = gateway(calls.clone());
        gw.handle(&post(Some("k1"), b"x"), 1_000);
        gw.handle(&post(Some("k2"), b"x"), 1_000);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn same_key_different_body_is_rejected_without_calling_backend() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = gateway(calls.clone());
        gw.handle(&post(Some("k1"), b"amount=100"), 1_000);
        let resp = gw.handle(&post(Some("k1"), b"amount=999"), 1_010);
        assert_eq!(resp.status, 422);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a mismatched retry must not reach the backend"
        );
    }

    #[test]
    fn requests_without_a_key_are_forwarded_each_time() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = gateway(calls.clone());
        gw.handle(&post(None, b"x"), 1_000);
        gw.handle(&post(None, b"x"), 1_000);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    fn get(path: &str) -> Request {
        Request {
            method: "GET".into(),
            target: path.into(),
            headers: vec![("X-Forwarded-For".to_string(), "10.0.0.1".to_string())],
            body: Vec::new(),
        }
    }

    /// `/healthz` answers 200 without a key, without a quota, and without ever
    /// touching the backend — a load balancer must be able to poll it freely.
    #[test]
    fn healthz_is_served_locally_without_touching_the_backend() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = Gateway::new(
            Engine::new(MemoryStore::new(), 30_000),
            // A rule that would deny everything if health checks were subject to it.
            RuleSet::new().rule("strict", 1000, 1, Action::Block),
            CountingUpstream {
                calls: calls.clone(),
                status: 201,
                body: b"x".to_vec(),
            },
        );

        for _ in 0..10 {
            let resp = gw.handle(&get("/healthz"), 0);
            assert_eq!(resp.status, 200);
            assert_eq!(resp.body, b"ok");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "health checks must not proxy"
        );
        assert_eq!(
            gw.metrics().requests_total,
            0,
            "health checks are not proxied requests"
        );
    }

    /// `/metrics` reflects what actually happened: one create, one replay.
    #[test]
    fn metrics_count_created_and_replayed_outcomes() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = gateway(calls);

        gw.handle(&post(Some("k1"), b"x"), 1_000); // created
        gw.handle(&post(Some("k1"), b"x"), 1_010); // replayed
        gw.handle(&post(None, b"x"), 1_020); // passthrough

        let m = gw.metrics();
        assert_eq!(m.requests_total, 3);
        assert_eq!(m.created, 1);
        assert_eq!(m.replayed, 1);
        assert_eq!(m.passthrough, 1);

        let body = String::from_utf8(gw.handle(&get("/metrics"), 1_030).body).unwrap();
        assert!(body.contains("onced_requests_total 3"));
        assert!(body.contains("onced_outcomes_total{outcome=\"created\"} 1"));
        assert!(body.contains("onced_outcomes_total{outcome=\"replayed\"} 1"));
    }

    #[test]
    fn an_abuse_rule_blocks_with_429_before_the_backend() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut gw = Gateway::new(
            Engine::new(MemoryStore::new(), 30_000),
            RuleSet::new().rule("strict", 1000, 2, Action::Block),
            CountingUpstream {
                calls: calls.clone(),
                status: 201,
                body: b"ok".to_vec(),
            },
        );

        assert_eq!(gw.handle(&post(Some("a"), b"x"), 0).status, 201);
        assert_eq!(gw.handle(&post(Some("b"), b"x"), 0).status, 201);
        let blocked = gw.handle(&post(Some("c"), b"x"), 0);
        assert_eq!(blocked.status, 429);
        assert_eq!(header(&blocked, "Onced-Action"), Some("block"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the blocked request must not reach the backend"
        );
    }
}
