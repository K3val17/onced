# Onced

![Rust](https://img.shields.io/badge/Rust-stable-b7410e?style=flat-square)
![Tests](https://img.shields.io/badge/tests-88_passing-16a34a?style=flat-square)
![Core deps](https://img.shields.io/badge/core-zero_dependencies-0f766e?style=flat-square)
![Unsafe](https://img.shields.io/badge/unsafe-forbidden-475569?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-d4af37?style=flat-square)

**Exactly-once effect and abuse defense, as open infrastructure.**

Onced sits in front of your API, webhook handlers, or queue consumers and guarantees a state-changing operation happens exactly once, no matter how many times a client retries. It is the reliability primitive that Stripe exposes as `Idempotency-Key`, pulled out into a fast, language-agnostic, open-source engine. The same core does real-time abuse and fraud defense (velocity limits, carding and credential-stuffing detection) with sliding-window and Count-Min-Sketch counters.

## Why it exists

You can never guarantee a network message is *delivered* exactly once (FLP, 1985). So Onced gives the honest, useful guarantee instead: exactly-once *effect*. The charge, the credit, the email happens once even if the request arrives many times. The End-to-End Argument (Saltzer, Reed and Clark, 1984) says that guarantee belongs at the application endpoint, which is exactly where Onced lives. Today every team rebuilds this themselves, slowly, once per language. Onced does it once, correctly, and fast.

## The guarantees

- **Exactly-once effect.** A key completes at most once, ever, across retries, crashes, and lease takeovers.
- **Durability.** Once a commit is acknowledged it survives a crash and replays byte-identical. Append and `fsync` to a write-ahead log before the ack.
- **Survives node death.** Synchronous WAL replication carries the exactly-once guarantee across a node failover, not just a process restart.
- **Fencing.** A stalled worker whose lease was taken over can never overwrite the committed result (fencing tokens, after Kleppmann).
- **Mismatch safety.** The same key carrying a *different* request is rejected, never served a stale replay.
- **Bounded growth.** A completed key's cached outcome lives for a TTL (24h by default, like Stripe), then the key is recycled. A background sweep reclaims expired records and compacts the log with a Bitcask-style merge, so the keyspace and the log do not grow without bound.

## How it works

A drop-in HTTP gateway. Send your request with an `Idempotency-Key` header:

- **First time.** Onced runs it against your backend once, stores the outcome, returns it.
- **Retry, same key.** Onced replays the stored outcome without touching your backend.
- **In flight.** A concurrent duplicate gets `409`, told to retry shortly.
- **Key reused with a different body.** `422`, never a wrong replay.
- **Over a velocity limit.** `429` from the abuse layer before your backend is touched.

```
client --Idempotency-Key--> onced-gateway --(once)--> your backend
                                 |
                                 +- WAL (durable, crash-safe, replicated)
                                 +- abuse rules (rate / carding / credential-stuffing)
```

## Quickstart

```sh
# 1. point Onced at your backend and run it
ONCED_BACKEND=127.0.0.1:9000 cargo run --release -p onced-gateway
# listens on 127.0.0.1:8080 (ONCED_LISTEN, ONCED_WAL, ONCED_SHARDS to override)

# 2. send the same request twice with one key. the backend is hit once.
curl -X POST localhost:8080/charge -H 'Idempotency-Key: abc-123' -d 'amount=500'
curl -X POST localhost:8080/charge -H 'Idempotency-Key: abc-123' -d 'amount=500'  # replayed
```

Or run it end to end (spins up a backend, sends duplicates, shows the backend is charged once, prints metrics):

```sh
./examples/demo.sh      # requires python3 + curl
```

## Performance

Single shard, single thread, measured with `cargo run --release -p onced-bench`:

| Path | Throughput | Latency |
|---|---|---|
| Replay (retry-storm hot path) | ~30M ops/s | ~33 ns/op |
| Begin + complete, in-memory | ~4.4M ops/s | ~230 ns/op |
| Begin + complete, durable WAL, group commit (1 `fsync`/batch) | ~53K ops/s | ~19 us/op |
| Begin + complete, durable WAL, strict (1 `fsync`/commit) | ~130 ops/s | ~8 ms/op |

The replay path, the common case under a retry storm, is nearly free. For durable writes, group commit (buffer many commits, one `fsync` per batch, the way Postgres, FoundationDB, and TigerBeetle do it) is about 400x faster than `fsync`-per-commit. The durability contract: acknowledge an operation only *after* flush. An operation still buffered when the process dies is treated as never-acknowledged, so the client retries and the retry either replays or re-runs. The exactly-once guarantee on the *acknowledged* outcome holds. You choose how many commits to batch behind one `fsync`.

The gateway runs a shard-per-core router (one shard per CPU by default). Each shard is an independent engine and WAL, and requests are routed by `hash(Idempotency-Key)` so the same key always lands on the same shard while different keys run in parallel with no shared lock. Abuse limits route separately by client IP, so per-IP quotas stay global even though idempotency state is sharded. Throughput scales close to linearly with shard count. On Linux, the `onced-uring` crate adds a thread-per-core io_uring transport (SO_REUSEPORT) for the high-throughput path.

## Architecture

Ports and adapters. The core is pure: no I/O, no clock, no threads, no randomness. All non-determinism is injected (time enters as `now_ms`). That is what makes it both deterministic-simulation-testable and trivially portable.

| Crate | Role |
|---|---|
| `onced-core` | Pure state machine and abuse primitives (idempotency engine, WAL, sliding-window limiter, Count-Min Sketch, HyperLogLog). No I/O. |
| `onced-gateway` | Network data plane: hand-rolled HTTP/1.1, wires the engine and abuse rules in front of a backend. Runnable binary with a shard-per-core router. |
| `onced-uring` | Linux io_uring thread-per-core transport (SO_REUSEPORT, keep-alive) for the high-throughput path. |
| `onced-sim` | Deterministic simulation testing: seeded fault injection (crashes, clock jumps, lease takeovers) asserting the invariants after every step. |
| `onced-bench` | Zero-dependency throughput benchmarks. |
| `onced-fast` | Optional async transport (tokio + axum + reqwest): HTTP keep-alive, connection-pooled backend client, async forwards, TLS to the backend. Reuses the same engine. |

## Correctness

Onced is built to be proven, not believed. The simulation harness (the FoundationDB and TigerBeetle approach) drives the engine through long randomized, fault-injected schedules from a single replayable seed, asserting exactly-once, durability, fencing, and replay consistency after every operation. A recent soak held every invariant across 60,000 operations through about 9,000 simulated crashes and dozens of lease takeovers. The suite is graded with `cargo-mutants` and fuzzed with `cargo-fuzz` (20M+ executions, zero crashes).

```sh
cargo test --workspace                                            # 88 tests
ONCED_SIM_SEEDS=500 ONCED_SIM_STEPS=4000 cargo run -p onced-sim   # extended soak
```

## Dependencies

The core is zero-dependency. `onced-core` (engine, WAL, abuse, sketches), the `onced-gateway` HTTP/1.1 reverse proxy, the simulation harness, and the benchmarks all build with the Rust standard library only. No crates.io downloads, so the correctness-critical code stays auditable, offline-buildable, and supply-chain-clean. `#![forbid(unsafe_code)]` holds in every safe-path crate.

The optional `onced-fast` and `onced-uring` crates are the exception: they pull a vetted async or io_uring stack for a higher-throughput transport over the same zero-dependency engine. You can run the zero-dep `onced-gateway` and never build them.

## License

Apache-2.0. See [LICENSE](LICENSE).
