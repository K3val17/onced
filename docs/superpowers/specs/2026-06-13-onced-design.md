# Onced — Design Specification

> **Status:** Draft v0.1 — design-complete, implementation starting (Phase 0 → 1)
> **Date:** 2026-06-13
> **Codename:** `onced` (one + -ced; rename candidates: Tollgate, Janus, Gatekeeper)
> **One line:** Stripe's `Idempotency-Key` reliability guarantee *plus* Cloudflare-grade
> abuse defense, extracted into a fast, language-agnostic, open-source engine.

---

## 0. Who this document is for

This spec is written so that a careful engineer who is **not** a distributed-systems
specialist can read it top to bottom and understand both *what* we are building and
*why each decision is the one the best companies in the world make*. Section 1 is a
plain-English primer. The rigour deepens from Section 4 onward.

---

## 1. Plain-English primer

### 1.1 The "double-click" problem (idempotency)

A customer clicks **Pay**. The request leaves their phone, reaches your server, your
server charges them — and then the Wi-Fi drops *before the "success" reply gets back
to the phone*. The app sees no reply, so it does the "safe" thing and **retries**. Now
you have charged them twice.

The fix the whole industry uses: the client attaches a unique **idempotency key** (a
random string) to the operation. The *first* time the server sees that key it does the
work and remembers the result. Every *later* request carrying the same key gets the
**remembered result replayed back** — the charge never happens a second time. The
operation has happened **exactly once**, no matter how many times it was retried.

That is the entire reliability story behind Stripe's famous `Idempotency-Key` header.
It sounds simple. It is not — the hard parts are *concurrency* (two retries arriving at
the exact same moment), *crash safety* (the server dies mid-charge), and *correctness*
(never replaying the wrong answer). Almost every team re-implements this badly. **Onced
implements it once, correctly, and fast, for everyone.**

### 1.2 "Exactly once" is a lie people tell — we deliver the honest version

A foundational result in computer science (the **FLP impossibility**, 1985, and the
**End-to-End Argument**, 1984 — both cited in §11) proves you can *never* guarantee a
message is *delivered* exactly once across a network, because the acknowledgement that
would prove it can itself be lost. So we don't chase the impossible thing. We deliver
the *useful* thing: **exactly-once effect.** The side effect — the charge, the wallet
credit, the email — happens once, even though the *message* may arrive many times. Pat
Helland's phrase: make the *effect* idempotent and stop worrying about the delivery.

### 1.3 The "carding attack" problem (abuse defense)

A fraud ring steals 50,000 credit-card numbers and wants to know which still work. They
fire thousands of tiny \$1 authorizations at your checkout. Each individual request
looks legitimate. The *pattern* — huge **velocity** from one source, many distinct cards,
many failures — is the attack. Defending against it means counting events across
sliding time windows, per IP, per account, per card-fingerprint, *in real time*, within a
few milliseconds, without a heavyweight Spark/Flink cluster.

Onced folds this in as a **first-class feature**, not an afterthought, because the engine
is *already* sitting in front of every state-changing request counting keys — the exact
place abuse defense belongs.

### 1.4 Why these two features belong in one product

Idempotency and abuse defense are the **same primitive** seen from two angles:
*"I am keeping track, per identity, of what has happened recently, and deciding whether
to let this next thing through."* Idempotency asks *"have I seen this exact operation
before?"*; abuse defense asks *"have I seen too many operations from this actor?"* One
hot-path interceptor, one in-memory index, two guarantees.

---

## 2. The gap (why this does not already exist)

| Neighbour | What it does | Why it is **not** this |
|---|---|---|
| **Temporal / Restate** | Durable execution | Forces you to **rewrite your app as workflows** (worker + server + a third service, 100+ LoC). |
| **DBOS** (Stonebraker, Zaharia) | Durable workflows in Postgres | Lighter (7 LoC) but **Postgres-coupled**, Python/TS-first, not a sub-ms language-agnostic interceptor. |
| **Stripe idempotency** | The exact UX we want | **Proprietary/internal.** Public reimplementations are per-language and Postgres-row-locked (slow hot path). |
| **Cloudflare Rate Limiting** | Abuse defense at the edge | **Closed SaaS**, network-layer, not tied to exactly-once business effects. |
| **Service meshes (Envoy, etc.)** | Cross-cutting proxy concerns | **No idempotency / exactly-once primitive at all.** |
| **TigerBeetle** | Blazing double-entry ledger | Deliberately omits the application layer (idempotency, dedup, reconciliation) — Onced is a natural front-end to it. |

**Conclusion:** there is no fast, open-source, language-agnostic engine that delivers
exactly-once *effect* + abuse defense as a drop-in layer. That is the gap.

---

## 3. Goals / Non-goals

### Goals
1. **Correctness first.** Money-grade. Provable via deterministic simulation testing (§9).
2. **Exactly-once effect** for any state-changing operation, replay- and crash-safe.
3. **Abuse/velocity/fraud defense** as a co-equal headline feature.
4. **Two form factors from one core:** (a) embeddable Rust library; (b) language-agnostic
   network gateway (HTTP today, gRPC/queue-consumer later).
5. **Best-in-class performance:** sub-millisecond p99 added latency on the hot path.
6. **Operable by a solo developer:** one binary, clear config, strong defaults.

### Non-goals (v1) — *YAGNI*
- Not a general database, message broker, or workflow engine.
- Not a full WAF or ML fraud-scoring platform (we provide the *real-time counting
  substrate* and a rules engine; pluggable ML scoring is a later extension point).
- No multi-region consensus in v1 (single-writer + durable log first; geo-replication
  is a designed-for-later extension, §7.4).

---

## 4. Core concepts & vocabulary

| Term | Meaning |
|---|---|
| **Idempotency key** | Client-supplied unique string identifying one logical operation. |
| **Request fingerprint** | 32-byte hash of the *meaningful* request content (method, path, canonical body). Detects a key reused with different parameters — which must be **rejected**, never silently mis-replayed. |
| **Recovery point** | A durable marker of how far an operation has progressed. The operation is a one-directional DAG of phases; on crash we resume from the last recovery point (brandur/Stripe). |
| **Fence (fencing token)** | Monotonic integer handed out at lock time. A stalled-then-resumed worker presents a stale fence and is rejected; the highest fence wins (Kleppmann). |
| **Cached outcome** | The stored `(status, headers, body)` of the first successful execution, replayed to all retries. |
| **Identity** | The dimension abuse defense counts over: IP, account, API key, card-fingerprint, or a composite. |

---

## 5. Architecture

Ports-and-adapters (hexagonal). The **core is pure**: no clock, no threads, no I/O, no
randomness of its own — every source of non-determinism is *injected*. This is the single
most important architectural decision: it is what makes the engine deterministically
simulation-testable (§9) and what lets the core run **anywhere, including macOS**, while
the performance-critical I/O layer targets Linux.

```
                       ┌──────────────────────────────────────────┐
   client ── HTTP ──▶  │  onced-gateway  (data plane)             │
   (Idempotency-Key)   │  thread-per-core, io_uring on Linux      │
                       │  Tokio fallback for portable dev/macOS   │
                       └───────────────┬──────────────────────────┘
                                       │ calls (pure)
                       ┌───────────────▼──────────────────────────┐
                       │  onced-core   (pure logic, no I/O)        │
                       │  • idempotency state machine              │
                       │  • abuse-defense counters + rules         │
                       │  injected: Clock, Store, Rng              │
                       └───────────────┬──────────────────────────┘
                                       │ trait: Store
                       ┌───────────────▼──────────────────────────┐
                       │  onced-store  (durability)                │
                       │  • in-memory index + WAL + recovery       │
                       │  • pluggable: memory / WAL / (Redis,PG)   │
                       └──────────────────────────────────────────┘

   onced-sim  ── drives onced-core with a simulated Clock/Store/Network,
                 injecting crashes, partitions, clock skew, reordering.
```

### Crates (Rust workspace)
- **`onced-core`** — pure state machine + abuse primitives. The heart. (Phase 1–2, 4)
- **`onced-store`** — durable storage: in-memory + write-ahead log + crash recovery; a
  `Store` trait so backends are swappable. (Phase 2)
- **`onced-gateway`** — the network data plane: HTTP reverse proxy that reads
  `Idempotency-Key`, calls core, forwards to the user's backend, caches the response.
  (Phase 3)
- **`onced-sim`** — deterministic simulation testing harness + fault injection. (Phase 5)
- **`onced`** — the shipping binary that wires the above with config. (Phase 6)

---

## 6. The idempotency state machine (the heart)

A key's life is a **one-directional DAG** — it advances and never cycles back (Stripe;
brandur). States:

```
        first request, key unseen
   ─────────────────────────────────▶  [ InProgress { fence, fingerprint } ]
                                               │  backend returns
                                               ▼
                                        [ Completed { fingerprint, outcome } ]
```

**Transition rules (the correctness core):**

1. **First sight of a key** → atomically create `InProgress`, mint a `fence`, store the
   request fingerprint. Forward the request to the backend.
2. **Concurrent second request, same key, while `InProgress`** → it does **not** run the
   backend. It either *waits* for the in-flight one to complete (then replays its
   outcome) or returns `409 Conflict / retry-after` — configurable. Only one fence holder
   may write the outcome.
3. **Request arrives while `Completed`** → replay the cached `outcome` verbatim. Backend
   is never touched. (Exactly-once effect achieved.)
4. **Fingerprint mismatch** (same key, different request body) → `422 Unprocessable` /
   `mismatch` error. Never replay a different operation's answer.
5. **Crash between steps** → on recovery, the WAL replays state up to the last recovery
   point; an `InProgress` key whose lease (fence + deadline) expired may be retried by a
   new fence holder (the old holder's writes are rejected by the fencing check).
6. **TTL** → keys expire (default 24h, per Stripe) and are pruned; a reused key after
   pruning is treated as new.

This is a small, explicit, testable automaton — deliberately so, because it is the part
that must be *proven*, not merely *believed*.

---

## 7. The abuse-defense module

### 7.1 Counting substrate (Cloudflare-grade)
- **Sliding-window counter:** two counters per (identity, rule) with a weighted estimate
  of the last *N* seconds. Cloudflare reports a **0.003% error** with this technique and
  uses it for **billions of decisions/day** — it beats fixed windows, whose boundaries
  attackers deliberately straddle.
- **Count-Min Sketch** for high-cardinality keys (e.g. per-card across millions of
  cards): Cloudflare's Pingora uses CMS for per-key limits at **20M req/s with ~1000×
  memory savings** vs a naive hashmap (Cormode–Muthukrishnan, 2005).
- **HyperLogLog** for cardinality questions ("how many *distinct* cards from this IP in
  10 min?" — the carding signal) (Flajolet et al., 2007).
- **Bloom / quotient filter** for "have we seen this token before?" seen-sets.

### 7.2 Rules engine
Declarative rules over identities and windows, e.g.
`if distinct_cards(ip, 10m) > 20 then challenge`,
`if failed_auths(account, 1m) > 5 then block 15m`. Decisions: **allow / challenge /
throttle / block**, with reason codes for auditability.

### 7.3 Pluggable scoring (extension point)
The rules engine exposes a `Score` trait so an ML model (ONNX, or a remote service à la
Stripe Radar / Sift) can be added later without touching the hot path.

### 7.4 Designed-for-later: distribution
Counters are CRDT-friendly (mergeable). v1 is single-writer; geo-distribution merges
sketches across nodes (coordination-avoidant, Bailis et al.) — explicitly out of scope
for v1 but the data structures are chosen to allow it.

---

## 8. Storage & durability

- **In-memory index** (the hot path) for O(1) key lookups and counter updates.
- **Write-ahead log (WAL):** every state transition is appended and `fsync`ed before it
  is acknowledged — the classic database durability discipline (Gray). Recovery replays
  the WAL to rebuild the index.
- **`Store` trait** keeps backends swappable: `MemoryStore` (tests/dev),
  `WalStore` (default durable), and later adapters (Redis, Postgres) for teams that want
  to reuse existing infra.
- **Group commit / batched fsync** for throughput under load (amortize the fsync).

---

## 9. Correctness strategy — Deterministic Simulation Testing (DST)

This is the headline *quality* differentiator and the thing that lets **you personally
verify and trust the system**.

DST makes every source of non-determinism — clock, thread interleaving, disk I/O,
network ordering, RNG — **injectable and reproducible**. The simulator then drives the
pure core through *millions* of randomized schedules with injected crashes, partitions,
clock skew, message reordering and duplication, **all from a single random seed** so any
failure **replays exactly**.

- FoundationDB pioneered this; **TigerBeetle** used it to pass **Jepsen in three years**;
  its largest DST cluster simulates **~2 millennia of runtime per day**.
- We assert **invariants** continuously, e.g.: *a `Completed` outcome is never
  overwritten*; *the backend side effect is invoked at most once per key*; *a stale fence
  never writes*; *abuse counters never under-count below the true sliding window*.
- Layered on top: **property-based tests** (proptest) for the state machine, plus a
  later **Jepsen** suite (Kingsbury) for the networked gateway.

The promise to the user: when this is done, "it works" is backed by *evidence* — a seed
you can re-run — not by assertion.

---

## 10. Performance & portability

- **Thread-per-core, shared-nothing** data plane (the ScyllaDB/Seastar lineage). On Linux
  we use **`io_uring`** (via `glommio` / `monoio`; Apache Iggy migrated to exactly this in
  2026). Each core owns a shard of keys → no cross-core locking on the hot path.
- **Portability:** the runtime is behind a trait. macOS/dev uses a **Tokio** fallback (no
  io_uring on Darwin). `onced-core` is pure and runs everywhere, so **you can develop and
  verify the entire correctness story on your Mac**; the io_uring fast path is a
  Linux-production optimization, not a dev dependency.
- **Targets (to be benchmarked, not assumed):** p99 added latency < 1 ms; > 1M
  idempotency decisions/s/node; abuse-counter update in tens of nanoseconds.

---

## 11. API surface (sketch — finalized in Phase 3)

**Gateway (language-agnostic):**
```
POST /charge                       Idempotency-Key: 8f3a...   →  forwarded once
                                   (retry with same key → cached response, backend untouched)
```
Response headers: `Onced-Status: created | replayed | in-progress | mismatch`,
`Onced-Fence: <n>`, plus abuse decisions `Onced-Decision: allow | challenge | block`.

**Embeddable library (Rust):**
```rust
let decision = engine.begin(key, fingerprint, identity, &clock)?;
match decision { Begin::Run(guard) => { /* do work */ guard.complete(outcome)?; }
                 Begin::Replay(outcome) => return outcome,
                 Begin::InProgress => /* wait or 409 */,
                 Begin::Mismatch => /* 422 */ }
```

---

## 12. Threat model (security-relevant)

- **Replayed requests** (network or malicious) → neutralized by idempotency (exactly-once
  effect). This *is* replay-attack defense.
- **Key forgery / collision** → keys are namespaced per tenant/credential; fingerprint
  binds the key to its request so a stolen key cannot drive a *different* operation.
- **Resource exhaustion** (memory via unbounded keys) → TTL + bounded sketches + per-tenant
  quotas.
- **Abuse / carding / credential stuffing** → the abuse module (§7).
- **Out of scope v1:** TLS termination (front with a real LB), authN of the caller
  (assumed upstream), and ML-grade fraud scoring (extension point).

---

## 13. Phased roadmap (the "few weeks")

| Phase | Deliverable | Proof |
|---|---|---|
| **0** | Workspace, spec, compiling skeleton, CI | `cargo test` green |
| **1** | Idempotency state machine in `onced-core` (in-memory), **TDD** | unit + property tests |
| **2** | Durability: WAL + crash recovery in `onced-store` | crash/recovery property tests |
| **3** | `onced-gateway` HTTP reverse proxy (Tokio first) | end-to-end retry test |
| **4** | Abuse-defense module: sliding window + CMS + rules | accuracy + load tests |
| **5** | `onced-sim` DST harness + fault injection | seeded invariant runs |
| **6** | Thread-per-core io_uring fast path, observability, benchmarks, docs, packaging | benchmark report vs alternatives |

Each phase is independently reviewable and leaves the tree green. We do **not** advance
until the current phase's proof exists.

---

## 14. Prior art & references

### Foundational theory (the "h-index > 100" spine)
- J. Saltzer, D. Reed, D. Clark, **"End-to-End Arguments in System Design,"** ACM TOCS,
  1984. *Why exactly-once belongs at the endpoints — the theoretical licence for Onced.*
- M. Fischer, N. Lynch, M. Paterson, **"Impossibility of Distributed Consensus with One
  Faulty Process"** (FLP), JACM, 1985. *Why we target exactly-once* effect*, not delivery.*
- J. Gray, **"The Transaction Concept: Virtues and Limitations,"** VLDB, 1981. *Durability
  / WAL discipline.*
- P. Helland, **"Idempotence Is Not a Medical Condition,"** ACM Queue / CACM, 2012; and
  **"Life Beyond Distributed Transactions,"** CIDR, 2007. *The canonical idempotency view.*
- M. Kleppmann, **"How to do distributed locking,"** 2016. *Fencing tokens.*
- P. Bailis et al., **"Coordination Avoidance in Database Systems,"** VLDB, 2014.
  *Path to later geo-distribution without consensus on the hot path.*

### Probabilistic data structures
- G. Cormode, S. Muthukrishnan, **"The Count-Min Sketch and its Applications,"** 2005.
- P. Flajolet et al., **"HyperLogLog,"** 2007.
- B. Bloom, **"Space/Time Trade-offs in Hash Coding with Allowable Errors,"** CACM, 1970.

### Industry practice we are copying
- Stripe, **"Designing robust and predictable APIs with idempotency"** (B. Leach), 2017.
- brandur.org, **"Implementing Stripe-like Idempotency Keys in Postgres."**
- IETF draft, **"The Idempotency-Key HTTP Header Field."**
- FoundationDB / **TigerBeetle** deterministic simulation testing; W. Wilson, *"Testing
  Distributed Systems w/ Deterministic Simulation,"* Strange Loop 2014; K. Kingsbury,
  **Jepsen.**
- Cloudflare, **rate-limiting architecture** (sliding-window counter; Pingora Count-Min
  Sketch).
- M. Stonebraker, M. Zaharia et al., **DBOS**; Temporal; Restate — durable-execution
  positioning.
- B. Costa / ScyllaDB **Seastar**; DataDog **glommio**; ByteDance **monoio**; Apache
  **Iggy** — thread-per-core / io_uring data plane.

---

## 15. Open questions (to resolve as we build)
1. Wait-vs-reject default for concurrent in-progress keys (§6.2) — likely *short wait then
   reject*, configurable.
2. WAL format: custom binary vs adopt an embedded log (e.g. `redb`) for v1.
3. Fingerprint canonicalization rules for request bodies (JSON key ordering, etc.).
4. Exact rule DSL for the abuse engine (config file vs embedded expression language).
