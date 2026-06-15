//! # onced-sim
//!
//! Deterministic simulation testing (DST) for the Onced idempotency engine, in
//! the FoundationDB / TigerBeetle tradition. Because `onced-core` is pure — time
//! is injected and there is no internal threading or randomness — a single
//! seeded generator can drive the engine through a long, randomized sequence of
//! operations with injected faults, and **any failure replays exactly from its
//! seed**.
//!
//! The simulator runs a durable engine (over a real write-ahead log) and a set
//! of virtual workers that retry operations under a small space of keys, while
//! injecting:
//!   - **crashes** — drop and recover the engine from the WAL (in-flight worker
//!     tokens survive, modelling a worker that outlives a gateway restart);
//!   - **clock jumps** — sometimes past the lease, forcing takeovers;
//!   - **stale completions** — a worker whose lease was taken over still tries to
//!     commit.
//!
//! After every operation it checks the load-bearing invariants and panics with
//! the seed if one is violated:
//!   1. **Exactly-once effect** — a key is successfully completed at most once,
//!      *ever*, across all crashes and takeovers.
//!   2. **Durability** — after a crash, every committed key replays its exact
//!      committed outcome.
//!   3. **Replay consistency** — a `Replay` always returns the committed outcome.
//!   4. **Fencing** — a stale token never commits (it is refused).

#![forbid(unsafe_code)]

use onced_core::engine::{Begin, CompleteError, Engine, RunToken};
use onced_core::wal::WalStore;
use onced_core::{CachedOutcome, IdempotencyKey, RequestFingerprint};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of distinct keys the workers contend over. Small, so the same key is
/// repeatedly retried, crashed, and taken over.
const KEY_SPACE: u64 = 8;
/// Per-key lease. Clock jumps routinely exceed it to force takeovers.
const LEASE_MS: u64 = 1_000;

/// A deterministic xorshift64 generator — reproducible from a seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid the zero state, which xorshift cannot leave.
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Counters proving the campaign actually exercised the hard paths (so a passing
/// run is meaningful, not vacuous).
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub steps: u64,
    pub runs: u64,
    pub replays: u64,
    pub in_progress: u64,
    pub completes_ok: u64,
    pub stale_fences: u64,
    pub already_completed: u64,
    pub crashes: u64,
    pub takeovers: u64,
}

impl Stats {
    /// Fold another run's counters into this one.
    pub fn accumulate(&mut self, other: &Stats) {
        self.steps += other.steps;
        self.runs += other.runs;
        self.replays += other.replays;
        self.in_progress += other.in_progress;
        self.completes_ok += other.completes_ok;
        self.stale_fences += other.stale_fences;
        self.already_completed += other.already_completed;
        self.crashes += other.crashes;
        self.takeovers += other.takeovers;
    }
}

/// A worker that holds a run token for a key, plus the outcome it intends to
/// commit. Survives crashes (the worker is a separate process from the gateway).
struct Inflight {
    index: u64,
    token: RunToken,
    outcome: CachedOutcome,
}

/// One simulation run, seeded and self-contained (its own WAL file).
pub struct Simulation {
    seed: u64,
    rng: Rng,
    wal_path: PathBuf,
    engine: Engine<WalStore>,
    now_ms: u64,
    inflight: Vec<Inflight>,
    /// Oracle: the committed outcome per key index (what replays must return).
    committed: HashMap<u64, CachedOutcome>,
    /// Oracle: count of successful completions per key index (must stay <= 1).
    successful_completes: HashMap<u64, u64>,
    /// Monotonic source of distinct outcome bodies.
    next_body: u64,
    stats: Stats,
}

fn key_of(index: u64) -> IdempotencyKey {
    IdempotencyKey(format!("key-{index}"))
}

/// A stable fingerprint per key, so the simulation never produces spurious
/// mismatches (mismatch behaviour is covered by the engine's unit tests).
fn fingerprint_of(index: u64) -> RequestFingerprint {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&index.to_le_bytes());
    RequestFingerprint(bytes)
}

impl Simulation {
    /// Create a fresh simulation for `seed`, backed by a unique temp WAL file.
    pub fn new(seed: u64) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let wal_path = std::env::temp_dir().join(format!(
            "onced-sim-{}-{seed}-{unique}.wal",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&wal_path);

        let store = WalStore::open(&wal_path).expect("open sim wal");
        Simulation {
            seed,
            rng: Rng::new(seed),
            wal_path,
            engine: Engine::new(store, LEASE_MS),
            now_ms: 1,
            inflight: Vec::new(),
            committed: HashMap::new(),
            successful_completes: HashMap::new(),
            next_body: 0,
            stats: Stats::default(),
        }
    }

    /// Run `steps` operations and return the run's statistics.
    pub fn run(&mut self, steps: u64) -> Stats {
        for _ in 0..steps {
            self.step();
        }
        self.stats.clone()
    }

    /// Remove this run's WAL file. Call when the run is finished with.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.wal_path);
    }

    fn step(&mut self) {
        match self.rng.below(100) {
            0..=39 => self.do_begin(),
            40..=69 => self.do_complete(),
            70..=84 => self.do_advance_clock(),
            _ => self.do_crash(),
        }
        self.stats.steps += 1;
    }

    fn make_outcome(&mut self) -> CachedOutcome {
        self.next_body += 1;
        CachedOutcome {
            status: 200,
            headers: std::collections::BTreeMap::new(),
            body: self.next_body.to_le_bytes().to_vec(),
        }
    }

    fn do_begin(&mut self) {
        let index = self.rng.below(KEY_SPACE);
        let key = key_of(index);
        let fingerprint = fingerprint_of(index);
        let had_inflight = self.inflight.iter().any(|w| w.index == index);

        match self.engine.begin(key, fingerprint, self.now_ms) {
            Begin::Run(token) => {
                self.stats.runs += 1;
                if had_inflight {
                    // A new token was issued while another worker held one: this
                    // is a lease takeover. The old token is now stale.
                    self.stats.takeovers += 1;
                }
                let outcome = self.make_outcome();
                self.inflight.push(Inflight {
                    index,
                    token,
                    outcome,
                });
            }
            Begin::Replay(outcome) => {
                self.stats.replays += 1;
                assert_eq!(
                    self.committed.get(&index),
                    Some(&outcome),
                    "seed {}: replay returned an outcome the oracle never committed for key {index}",
                    self.seed
                );
            }
            Begin::InProgress => self.stats.in_progress += 1,
            Begin::Mismatch => {
                panic!(
                    "seed {}: unexpected Mismatch (fingerprints are fixed per key)",
                    self.seed
                )
            }
        }
    }

    fn do_complete(&mut self) {
        if self.inflight.is_empty() {
            return;
        }
        let which = self.rng.below(self.inflight.len() as u64) as usize;
        let worker = self.inflight.remove(which);
        let index = worker.index;

        match self.engine.complete(worker.token, worker.outcome.clone()) {
            Ok(()) => {
                self.stats.completes_ok += 1;
                let count = self.successful_completes.entry(index).or_insert(0);
                *count += 1;
                // INVARIANT 1: exactly-once effect.
                assert_eq!(
                    *count, 1,
                    "seed {}: key {index} was successfully completed {count} times \
                     -- exactly-once is violated",
                    self.seed
                );
                self.committed.insert(index, worker.outcome);
            }
            Err(CompleteError::StaleFence) => {
                // INVARIANT 4: a superseded worker is refused.
                self.stats.stale_fences += 1;
            }
            Err(CompleteError::AlreadyCompleted) => {
                self.stats.already_completed += 1;
                assert!(
                    self.committed.contains_key(&index),
                    "seed {}: complete reported AlreadyCompleted for key {index}, \
                     but the oracle has no commit",
                    self.seed
                );
            }
            Err(CompleteError::Unknown) => {
                panic!(
                    "seed {}: unexpected Unknown completing key {index}",
                    self.seed
                )
            }
        }
    }

    fn do_advance_clock(&mut self) {
        // Half the time a small step; half the time past the lease (forcing
        // takeovers of any in-flight key).
        let jump = if self.rng.below(2) == 0 {
            self.rng.below(LEASE_MS / 2) + 1
        } else {
            LEASE_MS + self.rng.below(LEASE_MS)
        };
        self.now_ms += jump;
    }

    fn do_crash(&mut self) {
        self.stats.crashes += 1;

        // Drop the engine (closing the WAL) and recover from disk. In-flight
        // worker tokens deliberately survive.
        let store = WalStore::open(&self.wal_path).expect("recover sim wal");
        self.engine = Engine::new(store, LEASE_MS);

        // INVARIANT 2: every committed key replays its exact outcome post-crash.
        let committed: Vec<(u64, CachedOutcome)> = self
            .committed
            .iter()
            .map(|(index, outcome)| (*index, outcome.clone()))
            .collect();
        for (index, expected) in committed {
            match self.engine.begin(key_of(index), fingerprint_of(index), self.now_ms) {
                Begin::Replay(got) => assert_eq!(
                    got, expected,
                    "seed {}: durability violated -- key {index} replayed the wrong outcome after crash",
                    self.seed
                ),
                other => panic!(
                    "seed {}: durability violated -- committed key {index} did not replay after crash (got {})",
                    self.seed,
                    begin_name(&other)
                ),
            }
        }
    }
}

fn begin_name(begin: &Begin) -> &'static str {
    match begin {
        Begin::Run(_) => "Run",
        Begin::Replay(_) => "Replay",
        Begin::InProgress => "InProgress",
        Begin::Mismatch => "Mismatch",
    }
}

#[cfg(test)]
mod tests {
    use super::{Simulation, Stats};

    /// The campaign: many seeds, each a long fault-injected run. The real checks
    /// are the invariant assertions inside the simulation; reaching the end means
    /// none fired. The counter assertions prove the run exercised crashes,
    /// recoveries, takeovers, and replays — so a clean pass is not vacuous.
    #[test]
    fn exactly_once_holds_across_seeds_and_faults() {
        let mut total = Stats::default();
        for seed in 0..12u64 {
            let mut sim = Simulation::new(seed);
            let stats = sim.run(400);
            sim.cleanup();
            total.accumulate(&stats);
        }

        assert!(
            total.completes_ok > 0,
            "campaign committed nothing: {total:?}"
        );
        assert!(total.crashes > 0, "campaign injected no crashes: {total:?}");
        assert!(total.replays > 0, "campaign never replayed: {total:?}");
        assert!(
            total.takeovers > 0,
            "campaign never took over a lease: {total:?}"
        );
        assert!(
            total.stale_fences > 0,
            "campaign never refused a stale fence: {total:?}"
        );

        eprintln!("DST campaign held all invariants: {total:?}");
    }
}
