---
name: onced-navigator
description: Use when locating or modifying code in the Onced engine. A routing map plus ripgrep recipes to page in precise slices of this repo instead of bulk-loading whole files. Trigger on "where is", "find", "navigate", or before editing onced-core/onced-gateway/onced-sim.
---

# Onced Navigator

Page in precise slices; never bulk-load the repo. The working set should hold the one
function you are changing and its callers — not whole modules. Laws live in
[`CLAUDE.md`](../../../CLAUDE.md); design rationale in
`docs/superpowers/specs/2026-06-13-onced-design.md`. This skill is the *retrieval* layer.

## Routing map — which crate owns what

| Concern | Crate / module | Key symbols |
|---|---|---|
| Idempotency state machine | `onced-core/src/engine.rs` | `Engine`, `begin`, `complete`, `Begin`, `RunToken`, `CompleteError` |
| Storage trait + in-memory | `onced-core/src/store.rs` | `Store`, `MemoryStore`, `flush` |
| Crash-safe durability | `onced-core/src/wal.rs` | `WalStore`, `open`, `open_buffered`, `encode_record`, `decode_record` |
| Abuse / rate limiting | `onced-core/src/abuse.rs` | `SlidingWindowLimiter`, `RuleSet`, `Verdict`, `Action` |
| Frequency / distinct counts | `onced-core/src/{sketch,hll}.rs` | `CountMinSketch`, `HyperLogLog` |
| HTTP wire format | `onced-gateway/src/http.rs` | `parse_request`, `write_response`, `Request`, `Response` |
| Request handling + metrics | `onced-gateway/src/gateway.rs` | `Gateway::handle`, `Metrics`, `Upstream` |
| TCP server / backend client | `onced-gateway/src/server.rs` | `serve`, `HttpUpstream`, `now_ms` |
| Simulation / fault injection | `onced-sim/src/lib.rs` | `Simulation::step`, invariant asserts |

Resolve the concern in this table first, then `rg` the symbol — do not open the file blind.

## Ripgrep recipes (page in, don't load)

```sh
rg -n 'fn complete' crates/onced-core/src/engine.rs   # locate, then read that range only
rg -n 'StaleFence|fence'        crates/onced-core/src # where fencing is enforced
rg -n 'impl Store for'          crates/onced-core/src # every Store implementor
rg -n 'assert' crates/onced-sim/src/lib.rs            # the invariants the sim proves
rg -n 'fn handle' crates/onced-gateway/src/gateway.rs # the request decision tree
```

After `rg` gives a line number, read that line range — not the whole file.

## Before you change engine behavior

- Re-read the four invariants in `CLAUDE.md` and keep all four.
- Add a failing test first (TDD); new engine behavior also gets a check in `onced-sim`.
- Run the green gate: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check`.
- A simulation failure reports a **seed** — it replays the bug deterministically.
