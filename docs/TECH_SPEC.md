# Onced Technical Specification

An internal deep-dive, written to teach. It explains every hard idea in Onced:
what problem it solves, how the code solves it, the research it stands on, and
the subtle traps that make it hard. Read it top to bottom once, then use it as a
reference. Code is cited as `crate/file.rs :: symbol` so you can jump to it.

The guiding idea: Onced is small on the surface (a proxy that dedupes requests)
but it touches most of the hard problems in distributed systems. The value is in
the reasoning, not the line count.

---

## 1. The one idea: exactly-once *effect*, not exactly-once *delivery*

You cannot guarantee a message is *delivered* across a network exactly once. This
is not an engineering gap, it is a proven impossibility (Fischer, Lynch and
Paterson, 1985: consensus is impossible in an asynchronous network if even one
node can fail). A sender can never know whether a lost acknowledgement means the
receiver missed the message or only missed the ack, so it must retry, so the
receiver must expect duplicates.

So Onced does not chase the impossible guarantee. It delivers the useful one:
exactly-once **effect**. The charge, the credit, the email happens once even if
the request arrives a hundred times. Pat Helland put it well: "idempotence is not
a medical condition." You design the *operation* so that repeating it is safe,
and you remember the *outcome* so repeats return the same answer.

The End-to-End Argument (Saltzer, Reed and Clark, 1984) says this kind of
guarantee belongs at the endpoint that cares, not buried in the network. That is
exactly where Onced sits: directly in front of the backend that does the work.

**The mental model.** A client attaches an `Idempotency-Key` to a write. Onced
remembers, per key, "have I done this, and if so what was the result?" First time:
do it once, store the result. Every retry after: return the stored result without
touching the backend. That is the whole product. Everything else is making that
correct under crashes, concurrency, and abuse.

---

## 2. The idempotency state machine

Code: `onced-core/src/engine.rs`, state in `onced-core/src/lib.rs :: KeyState`.

Each key moves through a **one-directional** state machine (Stripe and brandur
call it a one-directional DAG). A key is either:

- `InProgress { fence, fingerprint, lease_expires_at_ms }`: a worker is running
  the side effect right now.
- `Completed { fingerprint, outcome, completed_at_ms }`: the side effect ran once;
  `outcome` is replayed to every later retry.

"One-directional" means a `Completed` outcome is never overwritten (until it
expires, see TTL). That monotonicity is the backbone invariant.

Two operations drive it:

`Engine::begin(key, fingerprint, now_ms) -> Begin` returns one of:

- `Run(token)`: you are the worker, execute the side effect then call `complete`.
- `Replay(outcome)`: already done, here is the answer, run nothing.
- `InProgress`: someone else holds it right now, wait and retry (the gateway maps
  this to HTTP 409).
- `Mismatch`: this key was used before with a *different* request, refuse it
  (HTTP 422).

`Engine::complete(token, outcome, now_ms)` commits the outcome, but only if the
token is still the rightful holder (see fencing).

**The subtle part: `begin` decides while only reading, then mutates.** Look at
`engine.rs :: begin`. It first computes an `Action` enum from a read-only borrow
of the store, then drops that borrow before calling `start` (which mutates). This
is not ceremony. Rust's borrow checker forbids holding a shared read borrow across
a mutation, and writing it this way also makes the decision logic a pure function
of the current state, which is what lets the simulation test reason about it.

---

## 3. Fencing tokens and leases: the stalled-worker problem

Code: `onced-core/src/lib.rs :: Fence`, `engine.rs :: mint_fence`, the lease check
in `begin`, the fence check in `complete`.

Here is the trap. Worker A calls `begin`, gets the key, and starts the side
effect. Then A stalls: a garbage-collection pause, a slow disk, a network hiccup.
While A is frozen, its lease (a deadline, `lease_expires_at_ms`) expires. A retry
arrives, worker B takes over the key, runs the effect, and commits. Then A wakes
up, finishing its old work, and tries to commit too. If you let A commit, you have
two effects and a corrupted outcome.

The fix is a **fencing token** (Martin Kleppmann, "How to do distributed
locking"). Every time a key is started or taken over, the engine mints a new,
strictly increasing number, the fence, and hands it to the worker inside its
token. At `complete` time the engine checks: does your fence still match the one
recorded for the key? B took over, so the key now records B's higher fence. A
presents its stale lower fence, the check fails, and A is refused with
`StaleFence`. The holder of the highest fence wins. A monotonic counter is the
simplest correct distributed lock.

**The restart trap (the one most people miss).** Fences must keep increasing even
across a process restart. If the engine restarts and resets its counter to 1, it
could re-mint a fence that a still-alive pre-crash worker is holding, and then
that stale worker would wrongly be accepted. So on startup the engine seeds its
counter *above* anything found in the recovered log: `Engine::with_ttl` sets
`next_fence = store.max_in_progress_fence() + 1`. There is a dedicated WAL test
for exactly this (`wal.rs :: a_recovered_in_progress_lease_invalidates_the_pre_crash_token`)
and the simulation hammers it under random crashes.

---

## 4. Request fingerprints and mismatch safety

Code: `onced-core/src/lib.rs :: RequestFingerprint`, gateway
`onced-gateway/src/gateway.rs :: fingerprint_of`.

A client could reuse one idempotency key for two genuinely different requests, by
mistake or maliciously. If Onced blindly replayed the first outcome, it would
answer the second, different request with the wrong cached result. That is a
correctness hole and a security hole.

So Onced stores a 256-bit fingerprint of the meaningful request content (method,
path, body) alongside the key. On a retry it compares fingerprints. Same key and
same fingerprint: replay. Same key, different fingerprint: `Mismatch`, refuse
(422), never a wrong replay. The gateway builds the fingerprint with four salted
hash passes into 32 bytes. The IETF `Idempotency-Key` draft and Stripe both do
this comparison for the same reason.

---

## 5. Time-to-live and a bounded keyspace

Code: `engine.rs :: DEFAULT_TTL_MS`, the expiry check in `begin`, `prune_expired`.

If completed keys lived forever, the store would grow without bound. Stripe
recycles idempotency keys after 24 hours, and Onced does the same. A `Completed`
record carries `completed_at_ms`. In `begin`, if `now_ms >= completed_at_ms + ttl`
the key is treated as brand new and recycled, whatever request now bears it. The
default TTL is 24 hours (`DEFAULT_TTL_MS`), tunable with `Engine::with_ttl`.

Recycling frees keys *logically*. Reclaiming the memory and disk they hold is a
separate step: `Engine::prune_expired(now_ms)` sweeps out expired completed keys
and compacts the log (see section 8). The gateway runs this on a background thread
once a minute, off the request path.

---

## 6. Durability: the write-ahead log

Code: `onced-core/src/wal.rs`.

A crash must not lose a committed effect. The discipline is the classic database
write-ahead log (Jim Gray, "The Transaction Concept"): before you acknowledge a
state change, append it to a log on disk and force it to stable storage with
`fsync`. On restart you replay the log to rebuild the in-memory index exactly.
This is also the Bitcask design (Sheehy and Smith): an in-memory hash index in
front of an append-only on-disk log.

`WalStore` keeps a `HashMap` index plus an append-only file. Each record is framed
as `[length: u32][crc32: u32][payload]` and the CRC is the real IEEE 802.3 CRC-32
(pinned against published check values in `wal.rs :: crc32_matches_known_ieee_vectors`,
so a different-but-self-consistent checksum cannot slip through).

### 6.1 Torn tail versus interior corruption (a real bug we fixed)

A crash in the middle of an append leaves a **torn tail**: the last record is only
partly written. That is normal and recoverable, you truncate it and replay the
rest.

The trap: the original code stopped at the *first* record that failed to decode
and truncated everything after it. That is correct for a torn tail at the end, but
catastrophic for a bit-flip in the *middle* of the log, because it would silently
discard every still-good record after the flip. Silent loss of durable data is the
worst kind of bug (ALICE, Pillai et al. OSDI 2014, and RocksDB both treat
mid-file checksum failure as corruption, not as end-of-data).

The fix (`wal.rs :: open_with` and `is_complete_frame`): when decoding stops
early, decide *why*. If the leftover bytes are an incomplete frame, it is a torn
tail, truncate and recover. If the leftover bytes are a *complete* frame whose
checksum is wrong, that is interior corruption, so fail loudly instead of silently
dropping durable data.

### 6.2 fsync honesty (fsyncgate)

`WalStore` is fail-stop: if a write or `fsync` errors, it panics rather than
pretend the data is durable. This looks harsh but it is correct. The Postgres
"fsyncgate" incident (2018) showed that retrying a failed `fsync` is a lie,
because the kernel may have already dropped the dirty page and cleared the error,
so the second `fsync` succeeds while the data is gone. Postgres now panics on
`fsync` failure for the same reason. There is a comment in the code so nobody
"helpfully" turns the panic into a retry loop.

A further hardening: after the compaction rename (section 8) Onced also fsyncs the
parent directory (`wal.rs :: sync_parent_dir`), because on several filesystems the
rename itself can be lost on power loss unless the directory entry is flushed.

---

## 7. Group commit: durability without paying a fsync per write

Code: `wal.rs :: open_buffered`, `flush_pending`, `Store::flush`, `Engine::flush`.

`fsync` is slow, on the order of milliseconds, because it waits for the disk. One
`fsync` per commit caps you near a hundred commits per second. The fix is **group
commit** (DeWitt et al. 1984; used by Postgres, MySQL, FoundationDB, TigerBeetle):
buffer many records in memory, then make the whole batch durable with a single
`fsync`.

`WalStore` has two modes. Strict (`open`) fsyncs every write, simplest and safest.
Group commit (`open_buffered`) only appends to an in-memory buffer; nothing reaches
the file until an explicit `flush`. In the benchmark this lifts durable throughput
from about 130 ops/s to roughly 53,000 ops/s, about 400 times, while staying
crash-safe.

**The contract you must honour.** Acknowledge an operation only *after* a flush.
Anything still in the buffer when the process dies is treated as never
acknowledged. The client never saw success, so it retries, and the retry either
replays (if a later flush captured it) or re-runs. Exactly-once on the
*acknowledged* outcome is preserved. This is proven, not assumed: the simulation
runs a full group-commit mode (section 12) that crashes between flushes and checks
durable exactly-once holds.

---

## 8. WAL compaction: bounded disk

Code: `Store::compact`, `wal.rs` compaction in the `Store for WalStore` impl,
`Engine::prune_expired`.

An append-only log grows forever: every overwrite of a key leaves the old record
behind as dead weight. Compaction reclaims it. This is the Bitcask "merge" and the
log-structured cleaning idea (Rosenblum and Ousterhout, 1992): rewrite the log so
it contains exactly one record per live key, dropping the superseded and expired
ones.

The hard part is doing it crash-safely. Onced writes the compacted log to a
*temporary* file, fsyncs it, then atomically `rename`s it over the live path. A
crash before the rename leaves the old log intact; a crash after it leaves the new
one; there is never a half-written log. The atomic rename is the commit point.
This is the same checkpoint-and-swap discipline ARIES (Mohan et al. 1992) uses for
recovery.

---

## 9. Abuse defense: counting a lot of things cheaply

The same engine that asks "have I seen this exact operation?" is the right place
to ask "have I seen too many operations from this actor?" All of these data
structures share a theme: bounded memory and a known, provable error.

### 9.1 Sliding-window rate limiter

Code: `onced-core/src/abuse.rs :: SlidingWindowLimiter`.

A fixed window (reset the counter every minute) has a famous flaw: an attacker
fires the full limit at 0:59 and again at 1:00 and gets double the rate across the
boundary. A sliding log (remember every timestamp) is exact but uses unbounded
memory. The Cloudflare sliding-window-counter is the sweet spot: keep just two
counters per key, the current window and the previous, and estimate the trailing
rate as `current + previous * (overlap fraction)`. O(1) memory per key, and it
denies the boundary-burst attack. Cloudflare reports about 0.003 percent error at
billions of decisions per day.

**The DoS we fixed.** The per-key map grew without bound, so an attacker rotating
through millions of IPs or card numbers could exhaust memory. Now the map is hard
capped (`DEFAULT_MAX_KEYS`) with O(1) eviction when a brand-new key arrives at
capacity. An attacker cycling fresh keys never accumulates a count anyway, so
eviction costs the defense nothing.

### 9.2 Count-Min Sketch

Code: `onced-core/src/sketch.rs`.

To count frequencies of many items in fixed memory, the Count-Min Sketch (Cormode
and Muthukrishnan, 2005) hashes each item into `depth` rows of `width` counters
and takes the minimum across rows as the estimate. It never under-counts, and with
`width = ceil(e / epsilon)` and `depth = ceil(ln(1 / delta))` the estimate exceeds
the truth by more than `epsilon * N` with probability at most `delta`. Onced
verifies both properties empirically as property tests
(`proptests.rs :: cms_never_underestimates`, `cms_respects_epsilon_n_error_bound`).

### 9.3 HyperLogLog

Code: `onced-core/src/hll.rs`.

To count *distinct* items in tiny memory, HyperLogLog (Flajolet et al. 2007) looks
at the position of the leading 1-bit in each item's hash, keeps the max per bucket,
and combines buckets with a harmonic mean. With `m` buckets the standard error is
`1.04 / sqrt(m)`, a few percent at a few kilobytes, to count millions of distinct
items. A property test checks the error stays within four standard errors
(`proptests.rs :: hll_relative_error_within_four_sigma`).

### 9.4 Distinct-target velocity: the carding signal

Code: `onced-core/src/velocity.rs :: DistinctVelocityLimiter`.

A rate limiter counts *how many* requests an actor makes. It misses the fraud
pattern that matters most: one actor touching *many distinct targets*. An IP
trying 500 card numbers (carding), or one IP hitting 500 accounts (credential
stuffing) looks fine to a rate limiter if each individual target is hit only once.
`DistinctVelocityLimiter` flags an actor whose count of *distinct* targets in a
window exceeds a threshold, using a HyperLogLog per actor so memory is bounded no
matter how wide the fan-out, with the actor set itself capped against rotation.

---

## 10. Sharding: scaling across cores without breaking exactly-once

Code: `onced-gateway/src/router.rs :: Router`.

A single engine behind one lock serialises every request and caps you at one core.
The `Router` runs N independent shards, each its own engine and WAL behind its own
lock. This is the shared-nothing, thread-per-core design (Seastar, glommio, Redis):
each shard owns a disjoint slice of keys, so there is no shared mutable state on
the hot path.

**Why plain modulo hashing, not consistent hashing.** Requests route by
`hash(key) % N`. Consistent hashing and rendezvous hashing exist to minimise key
remapping when the *number of nodes changes at runtime*. Onced fixes N at startup,
so that cost never occurs, and adopting a hash ring would add per-request work for
zero benefit. The only requirement is that a key maps to the same shard every time
within a process, which `DefaultHasher` (SipHash) gives.

**Two independent routings.** A request has two identities, and routing them the
same way would break something. The idempotency key decides the *idempotency*
shard, because the same key must always reach the same shard or exactly-once
breaks. The client IP decides the *abuse* shard separately, because if abuse were
sharded by key, one IP's traffic would scatter across shards and each would see
only a fraction of it, silently turning a limit of L into L times N. So the router
runs a separate IP-sharded abuse stage first, then dispatches to the key shard.

---

## 11. Two-phase handling: do not hold a lock across the network

Code: `gateway.rs :: begin_phase`, `complete_phase`; `router.rs :: handle_async`.

The naive handler holds the shard lock from `begin`, through the slow backend
call, to `complete`. That means even unrelated keys on the same shard wait behind
one slow backend request. So handling is split into three phases: `begin_phase`
(under the lock, decide and mint a token), the backend forward (with no lock held),
then `complete_phase` (under the lock, commit). The lock is held only for the fast
in-memory state transitions, never across the network.

**Race A, the hazard this creates, and why it is safe.** While a worker is mid
forward with the lock released, its lease can expire and a retry can take over.
Now two workers may both call the backend. The stored outcome is still
exactly-once, because fencing refuses the slower worker's commit, but the backend
was called twice. The mitigation is to set the lease comfortably above backend
latency. This is not left as a hopeful comment: it is a checked property
(`gateway.rs :: stale_fence_after_lease_takeover_commits_only_the_survivors_outcome`)
and a 64-thread real-thread stress test
(`router.rs :: concurrent_same_key_hits_backend_once_under_contention`).

---

## 12. Replication: surviving a whole node dying

Code: `onced-core/src/replication.rs :: ReplicatedStore`.

A single-node WAL survives a process crash, because it replays from disk. It does
not survive the machine itself dying. `ReplicatedStore` wraps a primary plus N
replica stores and writes every record to all of them before the write returns. So
a committed effect is durable on every node, and if the primary is destroyed a
replica is promoted and the effect is recovered unchanged. Exactly-once survives a
node death, proven by `exactly_once_survives_primary_node_death`, which commits
through the replicated store, deletes the primary's file entirely, and recovers
from the replica alone.

This is the replication *mechanism*, kept pure so it is tested without a network.
Shipping records to a genuinely remote replica, leader election, and automatic
failover are the transport and control-plane layers that sit on top of this
verified guarantee.

---

## 13. Transports: the same engine behind three front doors

The engine is transport-agnostic. Three transports drive it, all preserving
exactly-once (each has a real-socket test):

- `onced-gateway/src/server.rs`: a hand-rolled HTTP/1.1 reverse proxy on
  `std::net`, thread-per-connection. Zero dependencies, fully auditable. The
  default.
- `onced-fast`: an async transport on tokio, axum, and reqwest, with HTTP
  keep-alive and a connection-pooled backend client. The forward is async, so a
  backend call costs a task, not a thread.
- `onced-uring`: a Linux io_uring transport on monoio, one runtime pinned per CPU
  with `SO_REUSEPORT`. io_uring batches accept, read, and write into a shared ring,
  so they cost almost no per-operation syscall overhead. This is the raw-speed path.

The seam that makes this clean is the `server.rs :: Handle` trait and the pure
`router.rs :: handle_async` method, which holds the per-shard lock only briefly and
never across the `await`, so the async transports are correct by the same argument
as the synchronous one.

---

## 14. How it is proven, not just believed

This is the part to copy into other projects. Correctness claims about money-moving
code are worthless without automatic verification.

**Deterministic simulation testing** (`onced-sim`). The whole reason `onced-core`
is pure, with time injected as `now_ms` and no internal threads or randomness, is
this: a single seeded generator can drive the engine through a long random sequence
of operations with injected faults (crashes, clock jumps past the lease, lease
takeovers, fingerprint mismatches), checking the invariants after *every* step, and
any failure replays exactly from its seed. This is the FoundationDB, TigerBeetle,
and Antithesis approach. A soak holds every invariant across millions of
fault-injected operations. The invariants checked are: exactly-once effect,
durability, fencing, replay consistency, and mismatch safety.

**Property-based testing** (`proptests.rs`, proptest). Instead of a few hand-picked
cases, generate thousands of structured inputs and shrink any failure to a minimal
counterexample. Used for WAL round-trip, decoder robustness, and the sketch and HLL
error bounds.

**Mutation testing** (cargo-mutants). This grades the *tests*. It mutates the
source (flip a comparison, delete a branch) and checks that some test fails. If no
test fails, that line is untested. A run on `onced-core` (197 mutants) found 34
survivors, of which 14 were real gaps now closed with targeted tests; the rest are
equivalent mutants (for example a 0.673 constant versus the 0.676 the formula
yields, which no test can or should distinguish). This is how you know the tests
actually bite.

**Fuzzing** (cargo-fuzz). The two parsers that read untrusted bytes, the WAL record
decoder and the HTTP request parser, are fuzzed. Tens of millions of executions,
zero panics. Their only contract is: never panic, over-read, or hang on any input.

**The verification gate.** Every change is gated on CI being green before it is
considered done: format, clippy with warnings as errors, the full test suite, and
the simulation soak, on a clean machine. This is the Karpathy LLM-OS "one thing":
never finish on "looks done."

---

## 15. The discipline that makes all of it possible

One choice underlies everything above: **the core is pure**. `onced-core` has no
I/O, no clock, no threads, and no randomness of its own. Every source of
non-determinism is injected by the caller, time as a `now_ms` argument, storage
behind the `Store` trait, the network behind the transport. This is ports and
adapters (hexagonal architecture).

Purity buys three things at once. It makes the engine deterministically
simulation-testable, because the test controls every input including the clock and
when crashes happen. It makes the engine portable, because it has no platform
dependencies (it builds and runs on macOS even though the io_uring fast path is
Linux only). And it keeps the correctness-critical code zero-dependency and
auditable, because there is nothing to pull in. The heavy crates (tokio, monoio)
live only in the optional transport crates, never in the core.

If you take one lesson: push all the non-determinism to the edges, and the hard
middle becomes testable.

---

## References

- Fischer, Lynch, Paterson (1985), "Impossibility of Distributed Consensus with One
  Faulty Process" (FLP).
- Saltzer, Reed, Clark (1984), "End-to-End Arguments in System Design."
- Pat Helland (2012), "Idempotence Is Not a Medical Condition."
- Martin Kleppmann, "How to do distributed locking" (fencing tokens).
- Jim Gray, "The Transaction Concept" (write-ahead logging).
- Sheehy, Smith, "Bitcask: A Log-Structured Hash Table."
- Pillai et al. (OSDI 2014), "All File Systems Are Not Created Equal" (ALICE).
- Mohan et al. (1992), "ARIES."
- Rosenblum, Ousterhout (1992), "The Design and Implementation of a Log-Structured
  File System."
- PostgreSQL "fsyncgate" (2018); Postgres fsync error handling.
- DeWitt et al. (1984), group commit.
- Cormode, Muthukrishnan (2005), "Count-Min Sketch."
- Flajolet et al. (2007), "HyperLogLog."
- Cloudflare, "How we built rate limiting capable of scaling to millions of
  domains" (sliding-window counter).
- FoundationDB and TigerBeetle on deterministic simulation testing.
