# Onced

**Exactly-once effect + abuse defense, as open infrastructure.**

Onced sits in front of your API, webhook handlers, or queue consumers and guarantees a
state-changing operation happens **exactly once** — no matter how many times a client
retries. It is the reliability primitive Stripe exposes as `Idempotency-Key`, extracted
into a fast, language-agnostic, open-source engine. The same core provides **real-time
abuse and fraud defense** (velocity limits, carding / credential-stuffing detection)
using Cloudflare-style sliding-window + Count-Min-Sketch counters.

> **Status: core feature-complete and proven.** Idempotency engine, crash-safe durability,
> abuse toolkit, a runnable HTTP gateway, and a deterministic-simulation test harness are
> all built, merged, and green (43 tests, zero external dependencies). The Linux io_uring
> thread-per-core fast path is the one remaining optimization.
>
> Design + research grounding: [`docs/superpowers/specs/2026-06-13-onced-design.md`](docs/superpowers/specs/2026-06-13-onced-design.md)

## Why it exists

You can never guarantee a network message is *delivered* exactly once (FLP, 1985). So
Onced delivers the honest, useful guarantee instead — **exactly-once *effect***: the
charge / credit / email happens once even if the request arrives many times. The
End-to-End Argument (Saltzer, Reed & Clark, 1984) says this guarantee belongs at the
application endpoint, which is exactly where Onced lives. Today every team re-implements
this themselves, slowly and per-language. Onced does it once, correctly, and fast.

## The guarantees

- **Exactly-once effect** — a key completes at most once, ever, across retries, crashes,
  and lease takeovers.
- **Durability** — once a commit is acknowledged it survives a crash and replays
  byte-identical (append + `fsync` to a write-ahead log before ack).
- **Fencing** — a stalled worker whose lease was taken over can never overwrite the
  committed result (fencing tokens, after Kleppmann).
- **Mismatch safety** — the same key carrying a *different* request is rejected, never
  served a stale replay.

## How it works

A drop-in HTTP gateway. Send your request with an `Idempotency-Key` header:

- **First time** → Onced runs it against your backend once, stores the outcome, returns it.
- **Retry (same key)** → Onced replays the stored outcome without touching your backend.
- **In flight** → concurrent duplicate gets `409`, told to retry shortly.
- **Key reused with a different body** → `422`, never a wrong replay.
- **Over a velocity limit** → `429` from the abuse layer before your backend is touched.

```
client ──Idempotency-Key──▶ onced-gateway ──(once)──▶ your backend
                                  │
                                  ├─ WAL (durable, crash-safe)
                                  └─ abuse rules (rate / carding / credential-stuffing)
```

## Quickstart

```sh
# 1. point Onced at your backend and run it
ONCED_BACKEND=127.0.0.1:9000 cargo run --release -p onced-gateway
# listens on 127.0.0.1:8080 by default (ONCED_LISTEN, ONCED_WAL to override)

# 2. send the same request twice with one key — backend is hit once
curl -X POST localhost:8080/charge -H 'Idempotency-Key: abc-123' -d 'amount=500'
curl -X POST localhost:8080/charge -H 'Idempotency-Key: abc-123' -d 'amount=500'  # replayed
```

## Observability

The gateway serves two operational endpoints locally, bypassing abuse rules and
idempotency (so a load balancer can poll liveness without a key or a quota):

- `GET /healthz` → `200 ok` for liveness checks.
- `GET /metrics` → Prometheus-format counters: total proxied requests and a breakdown
  of outcomes (`created`, `replayed`, `in_progress`, `mismatch`, `denied`,
  `upstream_error`, `passthrough`). `replayed` is your duplicate-suppression rate;
  `denied` is your abuse-block rate.

## Performance

Single shard, single thread, measured with `cargo run --release -p onced-bench`:

| Path | Throughput | Latency |
|---|---|---|
| Replay (retry-storm hot path) | ~30M ops/s | ~33 ns/op |
| Begin + complete, in-memory | ~4.4M ops/s | ~230 ns/op |
| Begin + complete, durable WAL — group commit (1 `fsync`/batch) | ~53K ops/s | ~19 µs/op |
| Begin + complete, durable WAL — strict (1 `fsync`/commit) | ~130 ops/s | ~8 ms/op |

The replay path — the common case under a retry storm — is nearly free. For durable
writes, **group commit** (buffer many commits, one `fsync` per batch — how Postgres,
FoundationDB, and TigerBeetle do it) is ~400× faster than `fsync`-per-commit. The
durability contract: acknowledge an operation only *after* `flush`. An operation still
buffered when the process dies is treated as never-acknowledged — the client retries, and
the retry either replays (if a later op flushed it) or re-runs. Onced's exactly-once
guarantee on the *acknowledged* outcome is preserved; you simply choose how many commits
to batch behind one `fsync`. Shard-per-core then scales throughput ~linearly with cores.

## Architecture

Ports-and-adapters. The core is **pure**: no I/O, no clock, no threads, no randomness —
all non-determinism is injected (time enters as `now_ms`). That is what makes it both
deterministic-simulation-testable and trivially portable.

| Crate | Role |
|---|---|
| `onced-core` | Pure state machine + abuse primitives (idempotency engine, WAL, sliding-window limiter, Count-Min Sketch, HyperLogLog). No I/O. |
| `onced-gateway` | Network data plane — hand-rolled HTTP/1.1, wires the engine + abuse rules in front of a backend. Runnable binary. |
| `onced-sim` | Deterministic simulation testing: seeded fault injection (crashes, clock jumps, lease takeovers) asserting the invariants after every step. |
| `onced-bench` | Zero-dependency throughput benchmarks. |

## Correctness

Onced is built to be **proven, not believed**. The simulation harness (the FoundationDB /
TigerBeetle approach) drives the engine through long randomized, fault-injected schedules
from a single replayable seed, asserting exactly-once, durability, fencing, and replay
consistency after every operation. A recent soak held all invariants across 60,000
operations through ~9,000 simulated crashes and dozens of lease takeovers.

```sh
cargo test --workspace                                            # 43 tests
ONCED_SIM_SEEDS=500 ONCED_SIM_STEPS=4000 cargo run -p onced-sim   # extended soak
```

## Dependencies

**None.** The entire workspace builds with the Rust standard library only — no crates.io
downloads. This keeps it auditable, offline-buildable, and supply-chain-clean.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
