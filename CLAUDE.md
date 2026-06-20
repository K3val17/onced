# Onced — Architecture Laws

Onced is an open-source Rust engine for **exactly-once effect** (idempotency, like
Stripe's `Idempotency-Key`) plus **real-time abuse/fraud defense**, as a drop-in layer
in front of any API, webhook, or queue consumer.

This file is a behavioral contract, not documentation. Every line constrains how you
act. Facts you can derive at runtime (file layout, module list, signatures) are **not**
here — `rg`/`grep`/AST-read them on demand. Keep this file under 200 lines.

## Invariants — never break these

- **Exactly-once effect.** A key is successfully completed at most once, ever — across
  retries, crashes, and lease takeovers.
- **Durability.** Once `complete` returns `Ok`, the outcome survives a crash and replays
  byte-identical. Append + `fsync` to the WAL *before* acknowledging.
- **Fencing.** A worker whose lease was taken over (stale fence) is refused at
  `complete`. Never let a stale fence overwrite a committed outcome.
- **Replay consistency.** A `Replay` returns exactly the committed outcome; a reused key
  with a different request fingerprint is a `Mismatch`, never a replay.

If a change cannot preserve all four, stop and surface the conflict.

## Design laws

- **`onced-core` is pure.** No I/O, no clock, no threads, no randomness inside core.
  Inject all non-determinism: time enters as `now_ms: u64`. This is what makes core
  deterministic and simulation-testable. Do not add a dependency on the system clock,
  `std::thread`, or RNG to core.
- **Zero external dependencies.** The whole workspace builds with std only — no crates.io
  downloads. Hand-roll over pulling a dep. This keeps it auditable, offline-buildable,
  and supply-chain-clean. Adding any dependency requires explicit human approval.
- **Ports and adapters.** Core defines traits (`Store`, `Upstream`); I/O lives in
  adapter crates behind them. Keep the boundary clean so the io_uring/async fast path
  can be swapped in without touching core logic.
- **`#![forbid(unsafe_code)]`** stays in every crate.

## Workflow laws

- **TDD.** Write the failing test first, watch it RED, then write minimal code to GREEN.
  The tests are the behavioral spec — keep them readable and intent-revealing.
- **Green gate before commit.** `cargo test --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, and `cargo fmt --all -- --check` must all pass.
- **Prove, don't believe.** Correctness claims about the engine are backed by the
  deterministic simulation harness (`onced-sim`), not by inspection. New invariants get a
  simulation check, not just a unit test.
- **Commit per green milestone.** Conventional-commit subjects (`feat(core):`, `test(sim):`).

## Commands

- Test everything: `cargo test --workspace`
- Lint clean: `cargo clippy --workspace --all-targets -- -D warnings`
- Format check: `cargo fmt --all -- --check`
- Simulation soak: `ONCED_SIM_SEEDS=500 ONCED_SIM_STEPS=4000 cargo run -p onced-sim`
- Run the gateway: `ONCED_BACKEND=host:port cargo run -p onced-gateway`
  (env: `ONCED_LISTEN`, `ONCED_BACKEND`, `ONCED_WAL`)
- Throughput bench: `cargo run --release -p onced-bench`

## Where to look (pointers, not contents)

- Design rationale + research grounding: `docs/superpowers/specs/2026-06-13-onced-design.md`
- Toolchain: Rust stable via rustup. `source ~/.cargo/env` if cargo is not on PATH.

## Commit trailer

End commit messages with:

```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```
