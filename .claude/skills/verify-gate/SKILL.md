---
name: verify-gate
description: Use before declaring ANY change done. The verification gate — the keystone of safe agentic work (Karpathy LLM-OS "the one thing"). Runs the full green gate locally, then confirms CI is green. Never finish on "looks done."
---

# Verify Gate

**The rule: no change is "done" until an automatic check proves it.** Vibes are
the enemy; the gate is the job. This is the keystone — earn autonomy only as the
gate proves out.

## Local gate (run every time, before commit)

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

All three must pass. A failure means the change is not done — fix it, don't
rationalize past it.

## Remote gate (the real proof — a clean machine)

After pushing, the change is not done until CI is green:

```sh
gh run watch "$(gh run list --limit 1 --json databaseId -q '.[0].databaseId')" --exit-status
```

Two lanes must pass:
- **`ci`** — fmt + clippy + tests + deterministic-simulation soak (cross-platform).
- **`iouring`** — builds + exactly-once test for the Linux io_uring transport.

If CI fails: read the log (`gh run view --log-failed`), fix, push, re-watch.
Only when both lanes are green is the change shippable.

## Heavier gates (on demand, not every commit)

- **Mutation testing** (proves the tests bite): `cargo mutants -p onced-core`.
  New core logic should leave no *killable* survivor.
- **Fuzzing** (untrusted-input parsers): `cargo +nightly fuzz run decode_record`.

## The discipline

Touching the exactly-once / durability / fencing invariants? The deterministic
simulation (`onced-sim`) is the gate — a new invariant gets a checked property
there, not just a unit test. Live-money semantics never ship on inspection alone.
