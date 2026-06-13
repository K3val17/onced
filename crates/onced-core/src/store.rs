//! Storage for idempotency-key records.
//!
//! The core assumes **single-threaded access per shard** (the thread-per-core,
//! shared-nothing design): each core owns a disjoint set of keys, so the engine
//! never contends on a lock for the hot path. Durable and pluggable backends
//! (write-ahead log, Redis, Postgres) arrive in Phase 2; for now `MemoryStore`
//! is the only implementor.

use crate::{IdempotencyKey, KeyState};
use std::collections::HashMap;

/// A shard's worth of idempotency-key records.
///
/// Implementors need no internal locking: the engine drives a `Store` from a
/// single thread per shard.
pub trait Store {
    /// Fetch the current state of `key`, if any.
    fn get(&self, key: &IdempotencyKey) -> Option<&KeyState>;

    /// Insert or overwrite the state of `key`.
    fn put(&mut self, key: IdempotencyKey, state: KeyState);

    /// Highest fence currently recorded among in-progress keys (0 if none).
    /// After recovery the engine seeds its fence counter above this, so a freshly
    /// minted fence never collides with one a live worker might still hold.
    /// Stores that are always constructed empty may use this default.
    fn max_in_progress_fence(&self) -> u64 {
        0
    }
}

/// An in-memory [`Store`] for tests and development.
#[derive(Debug, Default)]
pub struct MemoryStore {
    keys: HashMap<IdempotencyKey, KeyState>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &IdempotencyKey) -> Option<&KeyState> {
        self.keys.get(key)
    }

    fn put(&mut self, key: IdempotencyKey, state: KeyState) {
        self.keys.insert(key, state);
    }
}
