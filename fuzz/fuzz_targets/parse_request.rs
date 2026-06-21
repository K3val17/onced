#![no_main]
//! Coverage-guided fuzzing of the hand-rolled HTTP/1.1 request parser. It reads
//! untrusted bytes off a socket, so it must never panic, over-read, or hang on
//! any input — only return a parsed request or an error.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `&[u8]` implements `BufRead`, so it drives the parser directly.
    let mut reader = data;
    let _ = onced_gateway::http::parse_request(&mut reader);
});
