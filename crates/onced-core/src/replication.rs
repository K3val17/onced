//! Synchronous WAL replication: the durability core of distributed mode.
//!
//! A single-node WAL survives a *process* crash (it replays from disk). It does
//! not survive the *machine* dying. [`ReplicatedStore`] closes that gap: it
//! wraps a primary store and one or more replica stores and writes every record
//! to all of them before the write returns. So once an effect is committed, it
//! is durable on every replica, and if the primary node is lost the effect is
//! recovered from a replica unchanged. Exactly-once survives a node death, not
//! just a process crash.
//!
//! This is the replication *mechanism*, kept pure and deterministic so it can be
//! tested without a network: the replicas are any [`Store`] (in tests, local
//! WALs standing in for remote nodes). Shipping records to a genuinely remote
//! replica, leader election, and automatic failover are the transport and
//! control-plane layers built on top of this guarantee.

use crate::store::Store;
use crate::{IdempotencyKey, KeyState};

/// A [`Store`] that writes synchronously to a primary plus N replicas, so every
/// committed record is durable on all of them before the write returns. Reads
/// and the recovered fence come from the primary (replica 0); on primary loss,
/// promote any replica, which holds the identical durable log.
pub struct ReplicatedStore<S: Store> {
    replicas: Vec<S>,
}

impl<S: Store> ReplicatedStore<S> {
    /// Build a replicated store. `replicas[0]` is the primary (serves reads);
    /// the rest are synchronous replicas.
    ///
    /// # Panics
    /// If `replicas` is empty.
    pub fn new(replicas: Vec<S>) -> Self {
        assert!(
            !replicas.is_empty(),
            "a replicated store needs at least one node"
        );
        Self { replicas }
    }

    /// How many nodes (primary + replicas) this store writes to.
    pub fn node_count(&self) -> usize {
        self.replicas.len()
    }
}

impl<S: Store> Store for ReplicatedStore<S> {
    fn get(&self, key: &IdempotencyKey) -> Option<&KeyState> {
        self.replicas[0].get(key)
    }

    fn put(&mut self, key: IdempotencyKey, state: KeyState) {
        // Write to every node before returning. Each underlying store is
        // fail-stop on its own durability, so reaching the end means the record
        // is durable everywhere. Replicas first, primary last (the primary takes
        // ownership of the originals).
        let last = self.replicas.len() - 1;
        for replica in &mut self.replicas[..last] {
            replica.put(key.clone(), state.clone());
        }
        self.replicas[last].put(key, state);
    }

    fn flush(&mut self) {
        for replica in &mut self.replicas {
            replica.flush();
        }
    }

    fn compact(&mut self, keep: &mut dyn FnMut(&IdempotencyKey, &KeyState) -> bool) {
        for replica in &mut self.replicas {
            replica.compact(&mut *keep);
        }
    }

    fn max_in_progress_fence(&self) -> u64 {
        self.replicas[0].max_in_progress_fence()
    }
}

#[cfg(test)]
mod tests {
    use super::ReplicatedStore;
    use crate::engine::{Begin, Engine};
    use crate::store::{MemoryStore, Store};
    use crate::wal::WalStore;
    use crate::{CachedOutcome, IdempotencyKey, KeyState, RequestFingerprint};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path(tag: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "onced-repl-{}-{}-{}.wal",
            std::process::id(),
            tag,
            n
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn completed() -> KeyState {
        KeyState::Completed {
            fingerprint: RequestFingerprint([3u8; 32]),
            outcome: CachedOutcome {
                status: 200,
                headers: BTreeMap::new(),
                body: b"done".to_vec(),
            },
            completed_at_ms: 0,
        }
    }

    /// Every write lands on every node.
    #[test]
    fn a_write_reaches_every_replica() {
        let mut store = ReplicatedStore::new(vec![
            MemoryStore::new(),
            MemoryStore::new(),
            MemoryStore::new(),
        ]);
        assert_eq!(store.node_count(), 3);

        let key = IdempotencyKey("k".into());
        store.put(key.clone(), completed());

        // Drop the wrapper into its replicas and check each one independently.
        let replicas = store.replicas;
        for replica in &replicas {
            assert_eq!(replica.get(&key), Some(&completed()));
        }
    }

    /// THE distributed guarantee: a committed effect survives the *primary node*
    /// being destroyed. Recovery from a replica alone still replays the outcome,
    /// so exactly-once holds across a node death, not just a process crash.
    #[test]
    fn exactly_once_survives_primary_node_death() {
        let primary = temp_path("primary");
        let replica = temp_path("replica");
        let key = IdempotencyKey("charge".into());
        let fingerprint = RequestFingerprint([1u8; 32]);
        let outcome = CachedOutcome {
            status: 201,
            headers: BTreeMap::new(),
            body: b"charged".to_vec(),
        };

        // Commit through the replicated store (primary + one replica).
        {
            let store = ReplicatedStore::new(vec![
                WalStore::open(&primary).unwrap(),
                WalStore::open(&replica).unwrap(),
            ]);
            let mut engine = Engine::new(store, 30_000);
            let token = match engine.begin(key.clone(), fingerprint, 1_000) {
                Begin::Run(token) => token,
                other => panic!("expected Run, got {other:?}"),
            };
            engine.complete(token, outcome.clone(), 1_000).unwrap();
        }

        // The PRIMARY NODE is lost entirely (its disk is gone).
        std::fs::remove_file(&primary).unwrap();

        // Promote the replica: recover from it alone. The committed effect must
        // still be there, and a retry replays it exactly.
        let mut engine = Engine::new(WalStore::open(&replica).unwrap(), 30_000);
        match engine.begin(key, fingerprint, 2_000) {
            Begin::Replay(got) => assert_eq!(got, outcome),
            other => panic!("exactly-once must survive primary death, got {other:?}"),
        }

        let _ = std::fs::remove_file(&replica);
    }
}
