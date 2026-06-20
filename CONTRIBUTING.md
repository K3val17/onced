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

## Reporting a correctness bug

If you can make the simulation harness fail, include the **seed** — every failure replays
deterministically from it. That is the single most useful thing in a bug report.
