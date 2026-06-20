//! The idempotency engine: the one-directional state machine that turns a
//! stream of possibly-duplicated requests into an **exactly-once effect**.
//!
//! Written test-first: the tests below are the behavioural specification, and
//! the deterministic simulation in `onced-sim` exercises the same state machine
//! through millions of fault-injected schedules.

use crate::store::Store;
use crate::{CachedOutcome, Fence, IdempotencyKey, KeyState, RequestFingerprint};

/// The idempotency engine. Owns one [`Store`] shard and the monotonic fence
/// counter for that shard. Single-threaded per shard by design (see the `store`
/// module docs), so it needs no internal synchronisation.
pub struct Engine<S: Store> {
    store: S,
    /// How long a worker may hold a key before its lease is presumed dead and a
    /// retry is allowed to take over.
    lease_ms: u64,
    /// How long a completed key's cached outcome is honoured. After this, the key
    /// is expired and a fresh request may recycle it — the bounded-keyspace
    /// discipline Stripe applies (24h key recycling).
    ttl_ms: u64,
    /// Next fence to mint. Monotonic; never reused within a shard's lifetime.
    next_fence: u64,
}

/// Default time-to-live for a completed key's cached outcome: 24 hours, matching
/// Stripe's idempotency-key recycling window.
pub const DEFAULT_TTL_MS: u64 = 24 * 60 * 60 * 1_000;

/// The decision [`Engine::begin`] returns for an incoming request.
#[derive(Debug)]
pub enum Begin {
    /// First (or taking-over) attempt: execute the side effect, then call
    /// [`Engine::complete`] with the returned token.
    Run(RunToken),
    /// The side effect already happened for this key — replay this result and
    /// run nothing.
    Replay(CachedOutcome),
    /// Another live attempt holds this key; wait briefly and retry, or surface a
    /// "retry shortly" response.
    InProgress,
    /// The key was reused with a *different* request. Reject; never replay.
    Mismatch,
}

/// Proof that the holder is the worker authorised to complete a specific key.
/// Carries the fence, so a stalled-then-resumed worker is detected at
/// completion time and refused.
#[derive(Debug, Clone)]
pub struct RunToken {
    key: IdempotencyKey,
    fence: Fence,
}

/// Why a [`Engine::complete`] call was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum CompleteError {
    /// The lease was taken over by a newer worker; this token is stale.
    StaleFence,
    /// The key is already completed; its outcome is immutable.
    AlreadyCompleted,
    /// No record for this key (e.g. pruned by TTL). Should be rare.
    Unknown,
}

impl<S: Store> Engine<S> {
    /// Create an engine over `store`, with a per-key lease of `lease_ms` and the
    /// [`DEFAULT_TTL_MS`] completed-key time-to-live.
    pub fn new(store: S, lease_ms: u64) -> Self {
        Self::with_ttl(store, lease_ms, DEFAULT_TTL_MS)
    }

    /// Create an engine with an explicit completed-key time-to-live. After
    /// `ttl_ms` past completion, a key is expired and a brand-new request may
    /// recycle it.
    pub fn with_ttl(store: S, lease_ms: u64, ttl_ms: u64) -> Self {
        // Seed the fence counter above anything recovered from a durable store,
        // so a freshly minted fence never collides with a fence a live worker
        // might still hold after a crash. A fresh/empty store yields 1.
        let next_fence = store.max_in_progress_fence() + 1;
        Self {
            store,
            lease_ms,
            ttl_ms,
            next_fence,
        }
    }

    /// Make every preceding state change durable (one `fsync` for a group-commit
    /// store). Call after a batch of `begin`/`complete` and before acknowledging
    /// those operations to clients.
    pub fn flush(&mut self) {
        self.store.flush();
    }

    /// Reclaim space: drop every completed key whose TTL has elapsed at `now_ms`,
    /// and compact the underlying store so the freed records' storage is actually
    /// returned (for the WAL, a crash-safe log rewrite). In-progress keys are
    /// always retained — a live lease must survive. Run this periodically (e.g.
    /// once a minute), not on the request path.
    pub fn prune_expired(&mut self, now_ms: u64) {
        let ttl_ms = self.ttl_ms;
        self.store.compact(&mut |_key, state| match state {
            // A completed key is kept only while still within its TTL.
            KeyState::Completed {
                completed_at_ms, ..
            } => now_ms < completed_at_ms.saturating_add(ttl_ms),
            // A live (or recoverable) lease is always kept.
            KeyState::InProgress { .. } => true,
        });
    }

    fn mint_fence(&mut self) -> Fence {
        let fence = Fence(self.next_fence);
        self.next_fence += 1;
        fence
    }

    /// Record a fresh in-progress attempt and hand back its run token.
    fn start(
        &mut self,
        key: IdempotencyKey,
        fingerprint: RequestFingerprint,
        now_ms: u64,
    ) -> Begin {
        let fence = self.mint_fence();
        self.store.put(
            key.clone(),
            KeyState::InProgress {
                fence,
                fingerprint,
                lease_expires_at_ms: now_ms.saturating_add(self.lease_ms),
            },
        );
        Begin::Run(RunToken { key, fence })
    }

    /// Decide what to do with an incoming request bearing `key`.
    pub fn begin(
        &mut self,
        key: IdempotencyKey,
        fingerprint: RequestFingerprint,
        now_ms: u64,
    ) -> Begin {
        // Decide the action while only *reading* the store, so the immutable
        // borrow ends before any mutation (`start`) runs.
        enum Action {
            Start,
            Replay(CachedOutcome),
            InProgress,
            Mismatch,
        }

        let action = match self.store.get(&key) {
            None => Action::Start,
            Some(KeyState::Completed {
                fingerprint: stored,
                outcome,
                completed_at_ms,
            }) => {
                if now_ms >= completed_at_ms.saturating_add(self.ttl_ms) {
                    // The key's outcome has outlived its TTL: recycle it as if it
                    // were a brand-new key, whatever request now bears it.
                    Action::Start
                } else if *stored == fingerprint {
                    Action::Replay(outcome.clone())
                } else {
                    Action::Mismatch
                }
            }
            Some(KeyState::InProgress {
                fingerprint: stored,
                lease_expires_at_ms,
                ..
            }) => {
                if *stored != fingerprint {
                    Action::Mismatch
                } else if now_ms >= *lease_expires_at_ms {
                    Action::Start // lease expired: take over the dead worker's key
                } else {
                    Action::InProgress
                }
            }
        };

        match action {
            Action::Start => self.start(key, fingerprint, now_ms),
            Action::Replay(outcome) => Begin::Replay(outcome),
            Action::InProgress => Begin::InProgress,
            Action::Mismatch => Begin::Mismatch,
        }
    }

    /// Commit the outcome of a side effect, completing at `now_ms` (which starts
    /// the key's TTL clock). Only the current fence holder may complete, and once
    /// completed the result is immutable until it expires.
    pub fn complete(
        &mut self,
        token: RunToken,
        outcome: CachedOutcome,
        now_ms: u64,
    ) -> Result<(), CompleteError> {
        let fingerprint = match self.store.get(&token.key) {
            Some(KeyState::InProgress {
                fence, fingerprint, ..
            }) => {
                if *fence != token.fence {
                    return Err(CompleteError::StaleFence);
                }
                *fingerprint
            }
            Some(KeyState::Completed { .. }) => return Err(CompleteError::AlreadyCompleted),
            None => return Err(CompleteError::Unknown),
        };

        self.store.put(
            token.key,
            KeyState::Completed {
                fingerprint,
                outcome,
                completed_at_ms: now_ms,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::{Begin, CompleteError, Engine};
    use crate::store::MemoryStore;
    use crate::{CachedOutcome, IdempotencyKey, RequestFingerprint};
    use std::collections::BTreeMap;

    const LEASE_MS: u64 = 30_000;

    fn key(s: &str) -> IdempotencyKey {
        IdempotencyKey(s.to_string())
    }

    fn fp(byte: u8) -> RequestFingerprint {
        RequestFingerprint([byte; 32])
    }

    fn outcome(status: u16, body: &[u8]) -> CachedOutcome {
        CachedOutcome {
            status,
            headers: BTreeMap::new(),
            body: body.to_vec(),
        }
    }

    fn run_token(
        engine: &mut Engine<MemoryStore>,
        k: &IdempotencyKey,
        f: RequestFingerprint,
        now: u64,
    ) -> crate::engine::RunToken {
        match engine.begin(k.clone(), f, now) {
            Begin::Run(token) => token,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    /// The headline guarantee: the first request runs the side effect once; a
    /// retry carrying the same key replays the stored result without re-running.
    #[test]
    fn operation_runs_once_then_replays_on_retry() {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        let k = key("charge-1");
        let f = fp(1);

        let token = run_token(&mut engine, &k, f, 1_000);
        let result = outcome(201, b"charged");
        engine
            .complete(token, result.clone(), 1_000)
            .expect("the only in-flight attempt should complete");

        match engine.begin(k, f, 1_005) {
            Begin::Replay(replayed) => assert_eq!(replayed, result),
            other => panic!("retry should Replay, got {other:?}"),
        }
    }

    /// A second request for a key whose first attempt is still in flight (lease
    /// not expired) must not run the side effect a second time.
    #[test]
    fn concurrent_request_while_in_progress_is_told_to_wait() {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        let k = key("charge-2");
        let f = fp(2);

        let _first = run_token(&mut engine, &k, f, 1_000);
        assert!(matches!(engine.begin(k, f, 1_005), Begin::InProgress));
    }

    /// The same key carrying a *different* request must never be confused with
    /// the original — not while in progress, and not after completion.
    #[test]
    fn same_key_with_a_different_request_is_a_mismatch() {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        let k = key("charge-3");
        let original = fp(1);
        let imposter = fp(9);

        let token = run_token(&mut engine, &k, original, 1_000);
        assert!(matches!(
            engine.begin(k.clone(), imposter, 1_001),
            Begin::Mismatch
        ));

        engine.complete(token, outcome(200, b"ok"), 1_001).unwrap();
        assert!(matches!(engine.begin(k, imposter, 1_002), Begin::Mismatch));
    }

    /// If the original worker stalls past its lease, a new worker takes over;
    /// the stalled worker's stale fence must not be allowed to write a result,
    /// and the result that *is* stored is the new worker's.
    #[test]
    fn a_stale_fence_cannot_overwrite_the_outcome() {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        let k = key("charge-4");
        let f = fp(1);

        let stalled = run_token(&mut engine, &k, f, 1_000);
        // Lease expires at 1_000 + LEASE_MS; a retry at that instant takes over.
        let fresh = run_token(&mut engine, &k, f, 1_000 + LEASE_MS);

        assert_eq!(
            engine.complete(stalled, outcome(500, b"stale"), 1_000 + LEASE_MS),
            Err(CompleteError::StaleFence),
        );

        let good = outcome(201, b"fresh");
        engine
            .complete(fresh, good.clone(), 1_000 + LEASE_MS)
            .unwrap();

        assert!(matches!(engine.begin(k, f, 1_000 + LEASE_MS + 1), Begin::Replay(o) if o == good));
    }

    /// A completed key is immutable: a duplicate completion is rejected and the
    /// originally stored outcome is preserved.
    #[test]
    fn completed_key_is_immutable() {
        let mut engine = Engine::new(MemoryStore::new(), LEASE_MS);
        let k = key("charge-5");
        let f = fp(1);

        let token = run_token(&mut engine, &k, f, 1_000);
        let first = outcome(201, b"first");
        engine
            .complete(token.clone(), first.clone(), 1_000)
            .unwrap();

        assert_eq!(
            engine.complete(token, outcome(200, b"second"), 1_001),
            Err(CompleteError::AlreadyCompleted),
        );
        assert!(matches!(engine.begin(k, f, 1_001), Begin::Replay(o) if o == first));
    }

    /// Within its TTL a completed key still replays; once the TTL elapses the key
    /// is recycled, so a brand-new request — even a *different* one reusing the
    /// same key string — gets to Run rather than replaying a stale outcome. This
    /// is Stripe's bounded-keyspace key recycling.
    #[test]
    fn a_completed_key_is_recycled_after_its_ttl() {
        const TTL: u64 = 10_000;
        let mut engine = Engine::with_ttl(MemoryStore::new(), LEASE_MS, TTL);
        let k = key("charge-ttl");
        let f = fp(1);

        let token = run_token(&mut engine, &k, f, 1_000);
        engine
            .complete(token, outcome(201, b"first"), 1_000)
            .unwrap();

        // Just before expiry: still replays the cached outcome.
        assert!(matches!(
            engine.begin(k.clone(), f, 1_000 + TTL - 1),
            Begin::Replay(o) if o == outcome(201, b"first")
        ));

        // At/after expiry: recycled. A different request reusing the key now Runs
        // (rather than being rejected as a mismatch against the expired outcome).
        let different = fp(9);
        assert!(matches!(
            engine.begin(k, different, 1_000 + TTL),
            Begin::Run(_)
        ));
    }
}
