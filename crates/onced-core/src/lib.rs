//! # onced-core
//!
//! Storage-agnostic, runtime-agnostic core for **exactly-once effect** and
//! **abuse defense**. This crate is *pure*: it contains only logic and data
//! types — no I/O, no clock, no threads, and no randomness of its own.
//! Everything that is a source of non-determinism (time, persistence, network)
//! is injected by the caller.
//!
//! That purity is deliberate. It is what makes the engine **deterministically
//! simulation-testable** (drive it through millions of fault-injected schedules
//! from a single replayable seed), and it is what lets the core run *anywhere*,
//! including macOS, while the performance-critical I/O layer targets Linux.
//!
//! See `docs/superpowers/specs/2026-06-13-onced-design.md` for the full design.
//!
//! This file establishes the shared vocabulary (the persisted key states); the
//! behaviour that operates on it lives in [`engine`], [`store`], and [`wal`].

#![forbid(unsafe_code)]

pub mod abuse;
pub mod engine;
pub mod hash;
pub mod hll;
pub mod pow;
pub mod replication;
pub mod sketch;
pub mod store;
pub mod velocity;
pub mod wal;

#[cfg(test)]
mod proptests;

use std::collections::BTreeMap;

/// A client-supplied idempotency key — e.g. the value of an `Idempotency-Key`
/// HTTP header. Two requests carrying the same key are intended to produce the
/// same effect *exactly once*.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdempotencyKey(pub String);

/// A 32-byte fingerprint of the *meaningful* content of a request (method,
/// path, canonicalized body, and any chosen headers).
///
/// Stripe and the IETF `Idempotency-Key` draft both compare this against the
/// stored fingerprint so that a key reused with *different* parameters is
/// rejected, rather than silently returning the wrong cached response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestFingerprint(pub [u8; 32]);

/// A monotonically increasing fencing token, handed out when a key is locked.
///
/// If a worker stalls (GC pause, network hiccup) and resumes after its lease has
/// expired, it presents a *stale* fence and its writes are rejected — the holder
/// of the highest fence wins. See Kleppmann, "How to do distributed locking".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fence(pub u64);

/// The cached outcome of the first successful execution for a key: exactly what
/// we replay, verbatim, to every later request that carries the same key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedOutcome {
    /// HTTP-style status code of the original response.
    pub status: u16,
    /// Response headers to replay (ordered for deterministic comparison).
    pub headers: BTreeMap<String, String>,
    /// Response body bytes to replay.
    pub body: Vec<u8>,
}

/// The persisted state of a single idempotency key.
///
/// The states form a **one-directional DAG** (Stripe / brandur): an `InProgress`
/// key may only advance to `Completed`, and a `Completed` outcome is never
/// overwritten — until it expires past its TTL and the key is recycled. That
/// monotonicity is the invariant the deterministic simulation asserts after
/// every operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// A fenced worker currently holds the lock and is executing the side effect.
    InProgress {
        /// The fence held by the active worker.
        fence: Fence,
        /// Binds this key to the specific request that started it.
        fingerprint: RequestFingerprint,
        /// Injected wall-clock millis after which the lease is presumed dead and
        /// a retry may take over the key with a fresh fence.
        lease_expires_at_ms: u64,
    },
    /// The side effect ran exactly once; `outcome` is replayed to all retries.
    Completed {
        /// Binds the cached outcome to the request that produced it.
        fingerprint: RequestFingerprint,
        /// The response to replay for every future request bearing this key.
        outcome: CachedOutcome,
        /// Injected wall-clock millis at which the key completed. After
        /// `completed_at_ms + ttl` the key is expired and may be recycled by a
        /// brand-new request — the 24h key-recycling Stripe applies so the keyspace
        /// does not grow without bound.
        completed_at_ms: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase-0 smoke test: the vocabulary compiles and behaves as plain data.
    /// Real transition logic is added under TDD in Phase 1.
    #[test]
    fn vocabulary_is_constructible_and_distinct() {
        let fingerprint = RequestFingerprint([7u8; 32]);

        let in_progress = KeyState::InProgress {
            fence: Fence(1),
            fingerprint,
            lease_expires_at_ms: 31_000,
        };
        let completed = KeyState::Completed {
            fingerprint,
            outcome: CachedOutcome {
                status: 200,
                headers: BTreeMap::new(),
                body: b"ok".to_vec(),
            },
            completed_at_ms: 12_000,
        };

        // An in-progress key is distinct from a completed one.
        assert_ne!(in_progress, completed);
        // Fences are monotonically comparable (higher fence wins).
        assert!(Fence(2) > Fence(1));
        // Keys are usable as map/set members.
        assert_eq!(IdempotencyKey("k".into()), IdempotencyKey("k".into()));
    }
}
