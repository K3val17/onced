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

/// The Onced gateway: an idempotency engine, abuse rules, and a backend.
pub struct Gateway<S: Store, U: Upstream> {
    engine: Engine<S>,
    rules: RuleSet,
    upstream: U,
}

impl<S: Store, U: Upstream> Gateway<S, U> {
    /// Build a gateway from an engine, a rule set, and a backend.
    pub fn new(engine: Engine<S>, rules: RuleSet, upstream: U) -> Self {
        Self {
            engine,
            rules,
            upstream,
        }
    }

    /// Handle one request and produce the response to send back to the client.
    pub fn handle(&mut self, request: &Request, now_ms: u64) -> Response {
        // 1. Abuse defense, keyed on the caller's identity.
        let identity = request.header("x-forwarded-for").unwrap_or("anonymous");
        if let Verdict::Deny { rule, action } = self.rules.evaluate(identity, now_ms) {
            return too_many_requests(&rule, action);
        }

        // 2. Idempotency is opt-in via the Idempotency-Key header (like Stripe).
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
                    Err(_) => return bad_gateway(),
                };
                // Exactly-once holds as long as the backend call finishes within
                // the lease. If it overran and a retry took over, complete()
                // returns an error here and the takeover's result is the one
                // served; pick a lease comfortably above backend latency.
                let _ = self.engine.complete(token, to_outcome(&response));
                tag(response, "created")
            }
            Begin::Replay(outcome) => tag(from_outcome(outcome), "replayed"),
            Begin::InProgress => tagged_status(409, "in-progress"),
            Begin::Mismatch => tagged_status(422, "mismatch"),
        }
    }

    fn pass_through(&self, request: &Request) -> Response {
        self.upstream
            .forward(request)
            .unwrap_or_else(|_| bad_gateway())
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

fn too_many_requests(rule: &str, action: Action) -> Response {
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
