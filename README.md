# Onced

**Exactly-once effect and abuse defense, as open infrastructure.**

Onced sits in front of your API, webhook handlers, or queue consumers and makes a
state-changing operation happen **exactly once**, no matter how many times a client
retries. It is the reliability primitive Stripe exposes as `Idempotency-Key`, extracted
into a fast, language-agnostic, open-source engine. The same core also provides real-time
abuse and fraud defense (velocity limits, carding and credential-stuffing detection) using
Cloudflare-style sliding-window and Count-Min-Sketch counters.

**In one sentence, for newcomers:** Onced is a doorman for your backend. If the same
request knocks twice with the same ticket (an `Idempotency-Key`), the doorman runs it once
and hands everyone after that a copy of what happened the first time. He also turns away
anyone knocking far too fast.

> **Status: feature-complete and CI-verified.** Idempotency engine, crash-safe durability,
> abuse toolkit, three runnable transports (a zero-dependency HTTP gateway, an async
> tokio/axum gateway, and a Linux io_uring fast path), and a deterministic-simulation test
> harness are all built and green: 80 tests across the suite, plus property-based tests,
> a fault-injection soak, mutation testing, and fuzzing. A Docker image is published to
> `ghcr.io`.
>
> Design and research grounding: [`docs/superpowers/specs/2026-06-13-onced-design.md`](docs/superpowers/specs/2026-06-13-onced-design.md)

## What Onced is, and what it is not

It helps to be clear up front about the edges of the tool.

**Onced is:**

- A drop-in gateway that makes a write happen once, even when clients retry.
- A way to dedupe webhooks, payment submissions, and order submissions without
  re-implementing idempotency in every service and every language.
- A first line of abuse defense (rate limits, velocity caps, carding detection) that runs
  before a request ever reaches your backend.
- Self-hostable, open source, and language-agnostic. It speaks plain HTTP, so any stack
  can sit behind it.

**Onced is not:**

- Not a database or a message queue. It remembers the *outcome* of an operation for a
  limited time (24 hours by default), not your data forever.
- Not exactly-once *delivery*. Guaranteeing a network message is delivered exactly once is
  impossible (this is a well-known result, FLP 1985). Onced gives the guarantee that
  actually matters instead: exactly-once *effect*. The charge, email, or credit happens
  once even if the request arrives many times.
- Not a full fraud platform or web application firewall. The abuse layer is volume and
  velocity defense, not machine-learning risk scoring or a managed rules marketplace.
- Not a replacement for your backend's own validation. It sits in front; your backend
  still owns the business logic.

## Why it exists

You can never guarantee a network message is *delivered* exactly once. So Onced delivers
the honest, useful guarantee instead: exactly-once *effect*. The charge, credit, or email
happens once even if the request arrives many times. The End-to-End Argument (Saltzer,
Reed and Clark, 1984) says this guarantee belongs at the application endpoint, which is
exactly where Onced lives. Today every team re-implements this themselves, slowly and once
per language. Onced does it once, correctly, and fast.

## The guarantees

- **Exactly-once effect.** A key completes at most once, ever, across retries, crashes,
  and lease takeovers.
- **Durability.** Once a commit is acknowledged it survives a crash and replays
  byte-identical (append and `fsync` to a write-ahead log before the ack).
- **Fencing.** A stalled worker whose lease was taken over can never overwrite the
  committed result (fencing tokens, after Kleppmann).
- **Mismatch safety.** The same key carrying a *different* request is rejected, never
  served a stale replay.
- **Bounded growth.** A completed key's cached outcome lives for a time-to-live (24 hours
  by default, like Stripe), after which the key is recycled. A background sweep physically
  reclaims expired records and compacts the write-ahead log (a Bitcask-style merge), so the
  keyspace and the log do not grow without bound.

## How it works

A drop-in HTTP gateway. Send your request with an `Idempotency-Key` header:

- **First time:** Onced runs it against your backend once, stores the outcome, returns it.
- **Retry with the same key:** Onced replays the stored outcome without touching your backend.
- **In flight:** a concurrent duplicate gets `409`, told to retry shortly.
- **Key reused with a different body:** `422`, never a wrong replay.
- **Over a velocity limit:** `429` from the abuse layer before your backend is touched.

```
client --Idempotency-Key--> onced-gateway --(once)--> your backend
                                  |
                                  +- WAL (durable, crash-safe)
                                  +- abuse rules (rate / carding / credential-stuffing)
```

## Quickstart

Run it with Docker (no toolchain needed):

```sh
docker run -p 8080:8080 -e ONCED_BACKEND=host.docker.internal:9000 ghcr.io/k3val17/onced:latest
```

Or build and run from source:

```sh
# 1. point Onced at your backend and run it
ONCED_BACKEND=127.0.0.1:9000 cargo run --release -p onced-gateway
# listens on 127.0.0.1:8080 by default (ONCED_LISTEN, ONCED_WAL, ONCED_SHARDS to override)

# 2. send the same request twice with one key. the backend is hit once
curl -X POST localhost:8080/charge -H 'Idempotency-Key: abc-123' -d 'amount=500'
curl -X POST localhost:8080/charge -H 'Idempotency-Key: abc-123' -d 'amount=500'  # replayed
```

Or run the whole thing end to end. This spins up a backend, sends duplicates, shows the
backend is charged once, then prints metrics:

```sh
./examples/demo.sh      # requires python3 and curl
```

## Observability

The gateway serves two operational endpoints locally, bypassing abuse rules and
idempotency so a load balancer can poll liveness without a key or a quota:

- `GET /healthz` returns `200 ok` for liveness checks.
- `GET /metrics` returns Prometheus-format counters: total proxied requests and a breakdown
  of outcomes (`created`, `replayed`, `in_progress`, `mismatch`, `denied`,
  `upstream_error`, `passthrough`). `replayed` is your duplicate-suppression rate and
  `denied` is your abuse-block rate.

## Performance

Single shard, single thread, measured with `cargo run --release -p onced-bench`:

| Path | Throughput | Latency |
|---|---|---|
| Replay (retry-storm hot path) | ~30M ops/s | ~33 ns/op |
| Begin and complete, in-memory | ~4.4M ops/s | ~230 ns/op |
| Begin and complete, durable WAL, group commit (1 `fsync` per batch) | ~53K ops/s | ~19 µs/op |
| Begin and complete, durable WAL, strict (1 `fsync` per commit) | ~130 ops/s | ~8 ms/op |

The replay path, which is the common case under a retry storm, is nearly free. For durable
writes, **group commit** (buffer many commits, one `fsync` per batch, the way Postgres,
FoundationDB, and TigerBeetle do it) is about 400 times faster than one `fsync` per commit.
The durability contract is simple: acknowledge an operation only *after* a flush. An
operation still buffered when the process dies is treated as never acknowledged, so the
client retries, and the retry either replays (if a later op flushed it) or re-runs. The
exactly-once guarantee on the acknowledged outcome is preserved either way; you just choose
how many commits to batch behind one `fsync`.

The gateway runs a **shard-per-core router** (one shard per CPU by default). Each shard is
an independent engine and WAL, and requests are routed by `hash(Idempotency-Key)` so the
same key always lands on the same shard (exactly-once preserved) while different keys run
in parallel with no shared lock. Abuse limits are routed separately by client IP, so
per-IP quotas stay global even though idempotency state is sharded. Throughput scales close
to linearly with shard count.

## Architecture

Ports and adapters. The core is **pure**: no I/O, no clock, no threads, no randomness of
its own. All non-determinism is injected (time enters as `now_ms`). That is what makes it
both deterministic-simulation-testable and trivially portable.

| Crate | Role |
|---|---|
| `onced-core` | Pure state machine and abuse primitives (idempotency engine, WAL, sliding-window limiter, Count-Min Sketch, HyperLogLog). No I/O. |
| `onced-gateway` | Network data plane. Hand-rolled HTTP/1.1, wires the engine and abuse rules in front of a backend. Runnable binary with a shard-per-core router. |
| `onced-sim` | Deterministic simulation testing. Seeded fault injection (crashes, clock jumps, lease takeovers, fingerprint mismatches) asserting the invariants after every step. |
| `onced-bench` | Zero-dependency throughput benchmarks. |
| `onced-fast` | Optional high-performance async transport (tokio, axum, reqwest). HTTP keep-alive, a connection-pooled backend client, async forwards, and TLS to the backend. Reuses the same engine through the two-phase `Router::handle_async`. |
| `onced-uring` | Optional Linux-only io_uring transport (monoio), thread-per-core for the lowest syscall overhead. Excluded from the default build; validated on Linux CI. |

## Correctness

Onced is built to be proven, not believed. The simulation harness (the FoundationDB and
TigerBeetle approach) drives the engine through long randomized, fault-injected schedules
from a single replayable seed, asserting exactly-once, durability, fencing, replay
consistency, and mismatch safety after every operation. It is graded by mutation testing
(cargo-mutants) so the tests themselves are proven to catch bugs, and the two
untrusted-input parsers are fuzzed (cargo-fuzz). A recent soak held every invariant across
tens of thousands of simulated crashes and lease takeovers.

```sh
cargo test --workspace                                            # full suite
ONCED_SIM_SEEDS=500 ONCED_SIM_STEPS=4000 cargo run -p onced-sim   # extended fault-injection soak
```

## Dependencies

**The core is zero-dependency.** `onced-core` (engine, WAL, abuse, sketches), the
`onced-gateway` HTTP/1.1 reverse proxy, the simulation harness, and the benchmarks all
build with the Rust standard library only, with no crates.io downloads, so the
correctness-critical code stays auditable, offline-buildable, and supply-chain-clean.

The optional `onced-fast` and `onced-uring` crates are the exceptions: they pull a vetted
async stack (tokio, axum, reqwest, rustls) or the monoio io_uring runtime for higher
throughput. They are pure transports over the same zero-dependency engine, so you can run
the zero-dependency `onced-gateway` and never build them.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
