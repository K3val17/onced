#![no_main]
//! Coverage-guided fuzzing of the WAL record decoder. It parses untrusted
//! on-disk bytes after a crash, so the only contract is: never panic, never
//! over-read, never hang — return `Some(record)` or `None`. libFuzzer drives it
//! with mutated bytes; any panic is a crash regression that gets checked in.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((consumed, _key, _state, _chain)) = onced_core::wal::decode_record(data) {
        // A successful decode must report a length within the input.
        assert!(consumed <= data.len());
    }
});
