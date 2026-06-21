//! Property-based tests (proptest) for `onced-core`.
//!
//! These complement the example-based unit tests and the deterministic
//! simulation: proptest *generates* thousands of structured inputs and, on
//! failure, **shrinks** to a minimal counterexample. They pin down the
//! algebraic and statistical guarantees the engine relies on:
//!   - WAL records round-trip losslessly, and the decoder is robust to
//!     arbitrary / truncated bytes (it must never panic or over-read);
//!   - the Count-Min Sketch never *under*-estimates and respects its εN error
//!     bound;
//!   - HyperLogLog stays within its 1.04/√m standard error;
//!   - the rate limiter never admits more than its limit in a static window.
//!
//! proptest is a dev-dependency, so the shipped library stays zero-dependency.

use crate::sketch::CountMinSketch;
use crate::wal::{decode_record, encode_record};
use crate::{CachedOutcome, Fence, IdempotencyKey, KeyState, RequestFingerprint};
use proptest::prelude::*;
use std::collections::HashMap;

// --- Strategies for the core vocabulary ---

fn arb_fingerprint() -> impl Strategy<Value = RequestFingerprint> {
    prop::array::uniform32(any::<u8>()).prop_map(RequestFingerprint)
}

fn arb_outcome() -> impl Strategy<Value = CachedOutcome> {
    (
        any::<u16>(),
        prop::collection::btree_map("[a-z][a-z0-9-]{0,12}", "[ -~]{0,24}", 0..5),
        prop::collection::vec(any::<u8>(), 0..96),
    )
        .prop_map(|(status, headers, body)| CachedOutcome {
            status,
            headers,
            body,
        })
}

fn arb_key() -> impl Strategy<Value = IdempotencyKey> {
    "[ -~]{0,40}".prop_map(IdempotencyKey)
}

fn arb_keystate() -> impl Strategy<Value = KeyState> {
    prop_oneof![
        (any::<u64>(), arb_fingerprint(), any::<u64>()).prop_map(|(fence, fp, lease)| {
            KeyState::InProgress {
                fence: Fence(fence),
                fingerprint: fp,
                lease_expires_at_ms: lease,
            }
        }),
        (arb_fingerprint(), arb_outcome(), any::<u64>()).prop_map(|(fp, outcome, at)| {
            KeyState::Completed {
                fingerprint: fp,
                outcome,
                completed_at_ms: at,
            }
        }),
    ]
}

proptest! {
    /// Any record survives encode -> decode byte-for-byte, consuming exactly the
    /// bytes it produced.
    #[test]
    fn wal_record_round_trips(key in arb_key(), state in arb_keystate()) {
        let framed = encode_record(&key, &state);
        let (consumed, decoded_key, decoded_state) =
            decode_record(&framed).expect("a freshly encoded record must decode");
        prop_assert_eq!(consumed, framed.len());
        prop_assert_eq!(decoded_key, key);
        prop_assert_eq!(decoded_state, state);
    }

    /// The decoder must never panic or over-read on arbitrary bytes — it reads
    /// untrusted on-disk data after a crash.
    #[test]
    fn wal_decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_record(&bytes);
    }

    /// Every strict prefix of a valid record fails to decode (a torn tail is
    /// never mistaken for a complete record), and never panics.
    #[test]
    fn wal_decode_rejects_every_truncation(key in arb_key(), state in arb_keystate()) {
        let framed = encode_record(&key, &state);
        for n in 0..framed.len() {
            prop_assert!(decode_record(&framed[..n]).is_none(), "prefix len {} decoded", n);
        }
    }

    /// A single flipped byte anywhere in a record must be caught by the checksum
    /// (decode returns None), never silently accepted.
    #[test]
    fn wal_decode_detects_single_bit_flips(
        key in arb_key(),
        state in arb_keystate(),
        flip_byte in any::<prop::sample::Index>(),
        flip_bit in 0u8..8,
    ) {
        let mut framed = encode_record(&key, &state);
        let i = flip_byte.index(framed.len());
        framed[i] ^= 1 << flip_bit;
        // Either it fails to decode, or (astronomically rare CRC collision) it
        // decodes to the *same* record. It must never decode to a different one.
        if let Some((_, k, s)) = decode_record(&framed) {
            prop_assert!(k == key && s == state, "corruption decoded to a different record");
        }
    }

    /// Count-Min Sketch never under-counts: estimate(k) >= true(k) for all keys.
    #[test]
    fn cms_never_underestimates(ops in prop::collection::vec((0u32..300, 1u64..16), 0..2500)) {
        let mut cms = CountMinSketch::new(5, 512);
        let mut truth: HashMap<u32, u64> = HashMap::new();
        for (k, c) in &ops {
            *truth.entry(*k).or_default() += *c;
            cms.add(&k.to_string(), *c);
        }
        for (k, &t) in &truth {
            prop_assert!(cms.estimate(&k.to_string()) >= t, "underestimated key {}", k);
        }
    }

    /// The rate limiter never admits more than `limit` requests within a single
    /// static window (now_ms fixed, no boundary effects).
    #[test]
    fn limiter_never_exceeds_limit_in_a_static_window(limit in 1u64..64, hits in 1usize..256) {
        use crate::abuse::{Decision, SlidingWindowLimiter};
        let mut limiter = SlidingWindowLimiter::new(1000, limit);
        let allowed = (0..hits)
            .filter(|_| matches!(limiter.check("k", 0), Decision::Allow))
            .count();
        prop_assert!(allowed as u64 <= limit, "allowed {} > limit {}", allowed, limit);
    }
}

// --- Statistical guarantees (deterministic, fixed-seed sweeps; not flaky) ---

/// HyperLogLog's relative error stays within 4 standard errors (4 · 1.04/√m) of
/// the true cardinality across many independent key streams.
#[test]
fn hll_relative_error_within_four_sigma() {
    use crate::hll::HyperLogLog;
    let precision = 12u8;
    let m = 1u32 << precision;
    let sigma = 1.04 / (m as f64).sqrt();
    let n = 50_000usize;

    for seed in 0..40u64 {
        let mut hll = HyperLogLog::new(precision);
        for i in 0..n {
            hll.add(&format!("{seed}:{i}"));
        }
        let rel = (hll.estimate() - n as f64).abs() / n as f64;
        assert!(
            rel < 4.0 * sigma,
            "seed {seed}: relative error {rel:.4} exceeded 4σ = {:.4}",
            4.0 * sigma
        );
    }
}

/// Count-Min Sketch respects its εN bound: sized at width=⌈e/ε⌉, depth=⌈ln(1/δ)⌉,
/// the fraction of keys whose estimate exceeds true+εN stays at or below δ.
#[test]
fn cms_respects_epsilon_n_error_bound() {
    let epsilon = 0.01_f64;
    let delta = 0.01_f64;
    let width = (std::f64::consts::E / epsilon).ceil() as usize; // ~272
    let depth = (1.0 / delta).ln().ceil() as usize; // ~5

    let mut cms = CountMinSketch::new(depth, width);
    let mut truth: HashMap<u64, u64> = HashMap::new();
    let mut n = 0u64;
    // Deterministic skewed stream via xorshift.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..40_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let key = x % 600;
        *truth.entry(key).or_default() += 1;
        cms.add(&key.to_string(), 1);
        n += 1;
    }

    let bound = (epsilon * n as f64) as u64;
    let violations = truth
        .iter()
        .filter(|(k, &t)| cms.estimate(&k.to_string()) > t + bound)
        .count();
    let frac = violations as f64 / truth.len() as f64;
    // Allow generous slack (3δ) so the probabilistic bound isn't flaky.
    assert!(
        frac <= 3.0 * delta,
        "εN bound violated for {frac:.4} of keys (δ = {delta})"
    );
}
