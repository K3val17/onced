# Onced fuzz targets

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the two parsers that read
untrusted bytes: the WAL record decoder and the HTTP/1.1 request parser. Their
only contract is *never panic, over-read, or hang* on any input.

This crate is excluded from the workspace (nightly-only) so the normal build
stays on stable.

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run decode_record    # WAL record decoder
cargo +nightly fuzz run parse_request    # HTTP request parser
```

A crash is written to `fuzz/artifacts/`; check the reproducer in as a
regression and add a matching unit test (TDD the fix).
