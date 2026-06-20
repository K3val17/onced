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
    /// Group-commit flushes (buffered mode only).
    pub flushes: u64,
    /// Completions of an orphaned token whose begin was lost on a pre-flush
    /// crash (buffered mode only) — refused with `Unknown`, never a double effect.
    pub unknown_completes: u64,
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
        self.flushes += other.flushes;
        self.unknown_completes += other.unknown_completes;
    }
}

/// Which write-ahead-log durability discipline a simulation drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// One `fsync` per write: a completed key is durable the instant it commits.
    Strict,
    /// Group commit: writes are durable only after an explicit flush. A crash
    /// before flush loses un-flushed writes — which the engine must tolerate
    /// without ever exposing two different durable outcomes for one key.
    GroupCommit,
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
    mode: Durability,
    rng: Rng,
    wal_path: PathBuf,
    engine: Engine<WalStore>,
    now_ms: u64,
    inflight: Vec<Inflight>,
    /// Oracle: the in-memory committed outcome per key (what a replay must return
    /// *now*). In group-commit mode this is reset to `durable` after a crash,
    /// since un-flushed completions are lost.
    committed: HashMap<u64, CachedOutcome>,
    /// Oracle: the *durable* outcome per key — set once it has been flushed, and
    /// asserted never to change (the durable exactly-once invariant). In strict
    /// mode a completion is durable immediately, so this mirrors `committed`.
    durable: HashMap<u64, CachedOutcome>,
    /// Oracle: count of successful completions per key index. In strict mode this
    /// must stay <= 1; in group-commit mode a lost completion may be retried, so
    /// it is not asserted on.
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
    /// Create a fresh **strict-durability** simulation for `seed`.
    pub fn new(seed: u64) -> Self {
        Self::with_mode(seed, Durability::Strict)
    }

    /// Create a fresh simulation for `seed` under durability `mode`, backed by a
    /// unique temp WAL file.
    pub fn with_mode(seed: u64, mode: Durability) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let wal_path = std::env::temp_dir().join(format!(
            "onced-sim-{}-{seed}-{unique}.wal",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&wal_path);

        let store = open_store(&wal_path, mode);
        Simulation {
            seed,
            mode,
            rng: Rng::new(seed),
            wal_path,
            engine: Engine::new(store, LEASE_MS),
            now_ms: 1,
            inflight: Vec::new(),
            committed: HashMap::new(),
            durable: HashMap::new(),
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
        let roll = self.rng.below(100);
        match self.mode {
            // Strict mode keeps the original distribution exactly (no flush step:
            // every write is durable the instant it commits).
            Durability::Strict => match roll {
                0..=39 => self.do_begin(),
                40..=69 => self.do_complete(),
                70..=84 => self.do_advance_clock(),
                _ => self.do_crash(),
            },
            // Group-commit mode interleaves explicit flushes; crashes between
            // flushes are where un-flushed writes are lost.
            Durability::GroupCommit => match roll {
                0..=34 => self.do_begin(),
                35..=59 => self.do_complete(),
                60..=74 => self.do_flush(),
                75..=84 => self.do_advance_clock(),
                _ => self.do_crash(),
            },
        }
        self.stats.steps += 1;
    }

    /// Group commit: flush the WAL, making every preceding write durable. Every
    /// key currently committed in memory is now on disk, so it becomes durable —
    /// and its durable outcome must never change (asserted in `mark_durable`).
    fn do_flush(&mut self) {
        self.stats.flushes += 1;
        self.engine.flush();
        let now_durable: Vec<(u64, CachedOutcome)> = self
            .committed
            .iter()
            .map(|(index, outcome)| (*index, outcome.clone()))
            .collect();
        for (index, outcome) in now_durable {
            self.mark_durable(index, outcome);
        }
    }

    /// Record `outcome` as the durable outcome for `index`, asserting the durable
    /// exactly-once invariant: once a key is durable, its outcome never changes.
    fn mark_durable(&mut self, index: u64, outcome: CachedOutcome) {
        match self.durable.get(&index) {
            Some(existing) => assert_eq!(
                *existing, outcome,
                "seed {}: durable outcome for key {index} changed \
                 -- durable exactly-once is violated",
                self.seed
            ),
            None => {
                self.durable.insert(index, outcome);
            }
        }
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
                self.committed.insert(index, worker.outcome.clone());
                match self.mode {
                    Durability::Strict => {
                        // Durable immediately, so a key completes at most once.
                        let count = self.successful_completes.entry(index).or_insert(0);
                        *count += 1;
                        // INVARIANT 1 (strict): exactly-once effect.
                        assert_eq!(
                            *count, 1,
                            "seed {}: key {index} was successfully completed {count} times \
                             -- strict exactly-once is violated",
                            self.seed
                        );
                        self.mark_durable(index, worker.outcome);
                    }
                    // In group-commit mode the completion is only in memory until
                    // the next flush; a pre-flush crash may revert it and a retry
                    // may complete again. Durability is asserted at flush time.
                    Durability::GroupCommit => {}
                }
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
            Err(CompleteError::Unknown) => match self.mode {
                // Strict: a begin is durable before its token escapes, so the
                // record always exists at completion time.
                Durability::Strict => panic!(
                    "seed {}: unexpected Unknown completing key {index}",
                    self.seed
                ),
                // Group commit: the begin may have been lost on a pre-flush crash,
                // orphaning this token. Refusal is correct — no double effect.
                Durability::GroupCommit => self.stats.unknown_completes += 1,
            },
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
        // worker tokens deliberately survive (a worker outlives a gateway crash).
        let store = open_store(&self.wal_path, self.mode);
        self.engine = Engine::new(store, LEASE_MS);

        // In group-commit mode a crash loses every un-flushed write, so the
        // in-memory oracle must fall back to what was durable. (In strict mode
        // `durable` already equals `committed`, so this is a no-op.)
        if self.mode == Durability::GroupCommit {
            self.committed = self.durable.clone();
        }

        // INVARIANT 2: every key the oracle believes is durable replays its exact
        // outcome after the crash.
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

/// Open the WAL store in the discipline this simulation drives.
fn open_store(path: &std::path::Path, mode: Durability) -> WalStore {
    match mode {
        Durability::Strict => WalStore::open(path).expect("open strict sim wal"),
        Durability::GroupCommit => WalStore::open_buffered(path).expect("open buffered sim wal"),
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
    use super::{Durability, Simulation, Stats};

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

    /// Group-commit campaign: the same fault injection, but writes are durable
    /// only after a flush, and crashes between flushes lose un-flushed writes.
    /// The load-bearing checks run inside the simulation; reaching the end means
    /// none fired. They are: **durable exactly-once** — a key's durable outcome,
    /// once flushed, never changes (`mark_durable`); **durability** — every
    /// durable key replays its exact outcome after a crash that wiped the
    /// un-flushed tail; and **no double effect** — an orphaned token (its begin
    /// lost pre-flush) is refused with `Unknown`, never silently re-run. The
    /// counter assertions prove the run actually exercised flushes, data-losing
    /// crashes, and orphaned-token refusals, so a clean pass is not vacuous.
    #[test]
    fn group_commit_holds_durable_exactly_once_across_crashes() {
        let mut total = Stats::default();
        let mut durable_seen = false;
        for seed in 0..16u64 {
            let mut sim = Simulation::with_mode(seed, Durability::GroupCommit);
            let stats = sim.run(600);
            durable_seen |= !sim.durable.is_empty();
            sim.cleanup();
            total.accumulate(&stats);
        }

        assert!(total.flushes > 0, "campaign never flushed: {total:?}");
        assert!(total.crashes > 0, "campaign injected no crashes: {total:?}");
        assert!(
            total.completes_ok > 0,
            "campaign committed nothing: {total:?}"
        );
        assert!(durable_seen, "campaign never made a key durable: {total:?}");
        assert!(
            total.unknown_completes > 0,
            "campaign never orphaned a token across a pre-flush crash \
             (group-commit recovery path unexercised): {total:?}"
        );

        eprintln!("group-commit DST held durable exactly-once: {total:?}");
    }
}
