# Contributing to Onced

Thanks for your interest. Onced is correctness-first infrastructure, so the bar is the
green gate below and the architecture laws in [`CLAUDE.md`](CLAUDE.md) — read those first;
they are short and load-bearing.

## The non-negotiables

- **Zero external dependencies.** The workspace builds with std only. Hand-roll over
  pulling a crate; adding any dependency needs a discussion first.
- **`onced-core` stays pure.** No I/O, clock, threads, or randomness in core — inject
  them. Time enters as `now_ms`.
- **The four invariants hold:** exactly-once effect, durability, fencing, replay
  consistency. A change that can't preserve them is not mergeable.

## Workflow

1. Write the failing test first (TDD), watch it RED, then make it GREEN.
2. New engine behavior gets a simulation check in `onced-sim`, not just a unit test.
3. Run the green gate before every commit:

   ```sh
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   ```

4. Use conventional-commit subjects (`feat(core):`, `fix(wal):`, `test(sim):`).

## The test arsenal

Correctness here is held by many kinds of tests, each catching what the others
miss. The green gate runs the stable ones; two heavier tools run on demand.

- **Example/unit + TDD** — the behavioral spec for each function.
- **Property-based** (`proptest`, dev-dep) — WAL round-trip, decoder robustness,
  Count-Min/HLL error bounds. In `onced-core/src/proptests.rs`.
- **Deterministic simulation** (`onced-sim`) — seeded fault injection (crashes,
  clock jumps, lease takeovers, fingerprint mismatches) under both durability
  modes, asserting the invariants after every step. Failures replay from a seed.
- **Concurrency stress** — real-thread same-key contention + the lease-takeover
  race, in `onced-gateway`.
- **Crash-consistency** — torn tails, interior corruption, compaction crash
  windows, in `onced-core/src/wal.rs`.
- **Integration over real sockets** — exactly-once + robustness (oversized body,
  slow backend, 5xx), in `onced-gateway` and `onced-fast`.
- **Mutation testing** (`cargo-mutants`) — grades whether the tests actually
  bite: `cargo mutants -p onced-core`. New logic should leave no *killable*
  survivor (equivalent mutants are expected and documented in commit history).
- **Coverage-guided fuzzing** (`cargo-fuzz`, nightly) — the two untrusted-input
  parsers; see `fuzz/README.md`.

## Reporting a correctness bug

If you can make the simulation harness fail, include the **seed** — every failure replays
deterministically from it. That is the single most useful thing in a bug report.
