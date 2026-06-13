//! The idempotency engine: the one-directional state machine that turns a
//! stream of possibly-duplicated requests into an **exactly-once effect**.
//!
//! Production code is written test-first (TDD). The tests below are the full
//! behavioural specification for Phase 1; they are written and watched failing
//! before the engine that satisfies them exists.

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
    /// Next fence to mint. Monotonic; never reused within a shard's lifetime.
    next_fence: u64,
}

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
    /// Create an engine over `store`, with a per-key lease of `lease_ms`.
    pub fn new(store: S, lease_ms: u64) -> Self {
        Self {
            store,
            lease_ms,
            next_fence: 1,
        }
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
            }) => {
                if *stored == fingerprint {
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

    /// Commit the outcome of a side effect. Only the current fence holder may
    /// complete, and once completed the result is immutable.
    pub fn complete(
        &mut self,
        token: RunToken,
        outcome: CachedOutcome,
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
            .complete(token, result.clone())
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

        engine.complete(token, outcome(200, b"ok")).unwrap();
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
            engine.complete(stalled, outcome(500, b"stale")),
            Err(CompleteError::StaleFence),
        );

        let good = outcome(201, b"fresh");
        engine.complete(fresh, good.clone()).unwrap();

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
        engine.complete(token.clone(), first.clone()).unwrap();

        assert_eq!(
            engine.complete(token, outcome(200, b"second")),
            Err(CompleteError::AlreadyCompleted),
        );
        assert!(matches!(engine.begin(k, f, 1_001), Begin::Replay(o) if o == first));
    }
}
