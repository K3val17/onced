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

    /// Make every preceding [`put`](Store::put) durable. For an in-memory store
    /// this is a no-op; for a group-commit write-ahead log it is the single
    /// `fsync` that commits a whole batch. A caller that needs durability must
    /// call this before acknowledging the operation.
    fn flush(&mut self) {}

    /// Drop every entry for which `keep` returns false, and reclaim any space
    /// their superseded records held. For an append-only log this is compaction
    /// (a Bitcask-style merge): the live entries are rewritten to a fresh log and
    /// the old, bloated one is replaced atomically. Default: retain nothing-aware
    /// no-op for stores without reclaimable storage that also need no eviction.
    fn compact(&mut self, keep: &mut dyn FnMut(&IdempotencyKey, &KeyState) -> bool) {
        let _ = keep;
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

    fn compact(&mut self, keep: &mut dyn FnMut(&IdempotencyKey, &KeyState) -> bool) {
        self.keys.retain(|key, state| keep(key, state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CachedOutcome, RequestFingerprint};
    use std::collections::BTreeMap;

    fn state() -> KeyState {
        KeyState::Completed {
            fingerprint: RequestFingerprint([0u8; 32]),
            outcome: CachedOutcome {
                status: 200,
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
            completed_at_ms: 0,
        }
    }

    /// `compact` drops exactly the entries the predicate rejects, keeping the rest.
    #[test]
    fn memory_store_compact_drops_rejected_keys() {
        let mut store = MemoryStore::new();
        store.put(IdempotencyKey("keep".into()), state());
        store.put(IdempotencyKey("drop".into()), state());

        store.compact(&mut |key, _| key.0 == "keep");

        assert!(store.get(&IdempotencyKey("keep".into())).is_some());
        assert!(store.get(&IdempotencyKey("drop".into())).is_none());
    }
}
