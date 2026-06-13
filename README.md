# Onced

**Exactly-once effect + abuse defense, as open infrastructure.**

Onced sits in front of your API, webhook handlers, or queue consumers and guarantees a
state-changing operation happens **exactly once** — no matter how many times a client
retries. It is the reliability primitive Stripe exposes as `Idempotency-Key`, extracted
into a fast, language-agnostic, open-source engine. The same core provides **real-time
abuse and fraud defense** (velocity limits, carding / credential-stuffing detection)
using Cloudflare-style sliding-window + Count-Min-Sketch counters.

> **Status: early development (Phase 0).** Design is complete; implementation in progress.
> Read the design: [`docs/superpowers/specs/2026-06-13-onced-design.md`](docs/superpowers/specs/2026-06-13-onced-design.md)

## Why it exists

You can never guarantee a network message is *delivered* exactly once (FLP, 1985). So
Onced delivers the honest, useful guarantee instead — **exactly-once *effect***: the
charge / credit / email happens once even if the request arrives many times. The
End-to-End Argument (Saltzer, Reed & Clark, 1984) says this guarantee belongs at the
application endpoint, which is exactly where Onced lives. Today every team re-implements
this themselves, slowly and per-language. Onced does it once, correctly, and fast.

## Architecture at a glance

| Crate | Role | Status |
|---|---|---|
| `onced-core` | Pure, deterministic state machine + abuse primitives (no I/O). Runs anywhere, incl. macOS. | Phase 0–1 |
| `onced-store` | Durable storage: WAL + crash recovery, pluggable backends. | planned |
| `onced-gateway` | Network data plane (HTTP), thread-per-core / io_uring on Linux. | planned |
| `onced-sim` | Deterministic simulation testing harness + fault injection. | planned |

## Correctness

Onced is built to be **proven, not believed**: deterministic simulation testing (the
FoundationDB / TigerBeetle approach) drives the core through millions of randomized,
fault-injected schedules from a single replayable seed.

## License

Apache-2.0
