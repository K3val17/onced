//! # Proof-of-Work Challenge Module
//!
//! Provides a stateless, server-issued proof-of-work (PoW) challenge so the
//! gateway can force abusive clients to burn CPU before proceeding — a
//! CAPTCHA-free deterrent that couples cleanly to the abuse layer's
//! `Action::Challenge` variant.
//!
//! ## Design Rationale
//!
//! ### Stateless by construction
//!
//! The challenge value is `HMAC-SHA256(server_secret, identity || window_index ||
//! request_hash)`. Because the server secret and the current time window index are
//! the only moving parts, any server in the cluster can re-derive the same
//! challenge for any request without storing per-client state. This is the same
//! "self-expiring token" pattern used by TOTP (RFC 6238).
//!
//! ### Request binding
//!
//! Including `identity` (e.g. the client IP or API key) and `request_hash` (the
//! SHA-256 of the request line + canonical headers) inside the HMAC message binds
//! the challenge to the specific (client, request) pair:
//!
//! - A valid nonce for `/login` cannot be submitted against `/transfer`.
//! - A valid nonce minted for IP A cannot be used by IP B.
//! - A valid nonce cannot be pre-computed ahead of the request because the
//!   `request_hash` is not known until the request arrives.
//! - Solved tokens are not replayable across time windows.
//!
//! ### Time-window expiry (clock-skew tolerant)
//!
//! `window_index = now_ms / window_ms`. The verifier accepts nonces from both the
//! current window and the immediately preceding one. This gives clients up to
//! `2 * window_ms - 1` ms to solve and submit, while ensuring that tokens from
//! two or more windows ago are always rejected — without any server-side storage.
//!
//! ### Difficulty and adaptive scaling
//!
//! `difficulty` is the number of leading zero bits required in
//! `SHA256(challenge || nonce_le_bytes)`. Expected work is `2^difficulty` hashes.
//! The `difficulty_for` function maps the limiter's overage ratio to a difficulty
//! value, letting the gateway progressively raise the cost as abuse intensifies.

#![allow(clippy::needless_range_loop)]

use crate::hash::{hmac_sha256, sha256};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A server-issued proof-of-work challenge, bound to a specific (identity,
/// request) pair and valid for one time window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The 32-byte challenge value.  The client must find a `nonce: u64` such
    /// that `SHA256(challenge || nonce.to_le_bytes())` has at least `difficulty`
    /// leading zero bits.
    pub challenge: [u8; 32],
    /// Number of leading zero bits required in the solution hash.
    pub difficulty: u8,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Issue a PoW challenge for a given (identity, request) pair.
///
/// The challenge value is `HMAC-SHA256(server_secret, identity || window_index
/// || request_hash)` where `window_index = now_ms / window_ms`.  This binds
/// the challenge to the current time window, the client identity, and the
/// specific request so that:
///
/// - It expires when the window rolls over (self-expiring, no storage needed).
/// - It cannot be replayed for a different request or identity.
/// - It cannot be pre-computed before the request arrives.
///
/// # Parameters
///
/// - `server_secret` — a private key known only to the server cluster.
/// - `identity`      — a string identifying the client (IP, API key, …).
/// - `request_hash`  — a 32-byte fingerprint of the request content.
/// - `difficulty`    — required leading zero bits (higher = more CPU work).
/// - `window_ms`     — window length in milliseconds (e.g. `60_000` for 1 min).
/// - `now_ms`        — current wall-clock time in milliseconds (injected, never
///   read from the system clock).
pub fn challenge(
    server_secret: &[u8],
    identity: &str,
    request_hash: &[u8],
    difficulty: u8,
    window_ms: u64,
    now_ms: u64,
) -> Challenge {
    let value = derive_challenge(server_secret, identity, request_hash, window_ms, now_ms);
    Challenge {
        challenge: value,
        difficulty,
    }
}

/// Verify that a client-supplied `nonce` correctly solves the PoW challenge.
///
/// The verifier re-derives the challenge for **both the current window and the
/// immediately preceding window** (to tolerate clock skew between client and
/// server).  A nonce from two or more windows ago is always rejected.
///
/// Returns `true` if and only if:
/// 1. The re-derived challenge matches (correct identity + request binding).
/// 2. `SHA256(challenge || nonce.to_le_bytes())` has at least `difficulty`
///    leading zero bits.
pub fn verify(
    server_secret: &[u8],
    identity: &str,
    request_hash: &[u8],
    difficulty: u8,
    nonce: u64,
    window_ms: u64,
    now_ms: u64,
) -> bool {
    let nonce_bytes = nonce.to_le_bytes();

    // Accept the current window and the immediately preceding one (clock skew).
    let current_idx = now_ms / window_ms;
    for window_idx in [current_idx, current_idx.saturating_sub(1)] {
        let c = derive_challenge_at(server_secret, identity, request_hash, window_idx);
        if check_solution(&c, &nonce_bytes, difficulty) {
            return true;
        }
    }
    false
}

/// Count the number of leading zero bits in a 32-byte SHA-256 digest.
///
/// This is used to check whether a nonce meets the required difficulty.
/// Each leading zero byte contributes 8 bits; the first non-zero byte
/// contributes `leading_zeros()` of that byte.
///
/// # Examples
///
/// ```
/// use onced_core::pow::leading_zero_bits;
/// let mut d = [0u8; 32];
/// assert_eq!(leading_zero_bits(&d), 256);
/// d[0] = 0x01;
/// assert_eq!(leading_zero_bits(&d), 7);
/// d[0] = 0x0f;
/// assert_eq!(leading_zero_bits(&d), 4);
/// ```
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in digest.iter() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Compute an adaptive difficulty level based on how much traffic exceeds the
/// allowed rate.
///
/// The formula is:
/// ```text
/// difficulty = base + floor(K * overage_ratio).min(CAP)
/// ```
/// where `K = 4.0` and `CAP = 20`, giving the range `[base, base + 20]`.
///
/// This keeps difficulty at `base` when traffic is within limits, then scales
/// linearly as abuse grows, capped so legitimate (if slow) clients can still
/// solve the challenge in reasonable time.
///
/// # Parameters
///
/// - `base`          — minimum difficulty (e.g. `8` for light throttling).
/// - `overage_ratio` — `(actual_rate - allowed_rate) / allowed_rate`, clamped
///   to `[0, ∞)`.  A value of `1.0` means twice the limit.
///
/// # Guarantees
///
/// - Monotonically non-decreasing in `overage_ratio`.
/// - Saturating at `base.saturating_add(CAP)` (never wraps).
/// - Negative `overage_ratio` is treated as zero (no penalty below the limit).
pub fn difficulty_for(base: u8, overage_ratio: f64) -> u8 {
    const K: f64 = 4.0;
    const CAP: u8 = 20;
    if overage_ratio <= 0.0 {
        return base;
    }
    let delta = (K * overage_ratio).floor() as u64;
    let delta = delta.min(CAP as u64) as u8;
    base.saturating_add(delta)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Build the HMAC message: `identity_bytes || window_index_le || request_hash`.
fn build_hmac_message(identity: &str, window_index: u64, request_hash: &[u8]) -> Vec<u8> {
    let id_bytes = identity.as_bytes();
    let mut msg = Vec::with_capacity(id_bytes.len() + 8 + request_hash.len());
    msg.extend_from_slice(id_bytes);
    msg.extend_from_slice(&window_index.to_le_bytes());
    msg.extend_from_slice(request_hash);
    msg
}

/// Derive the challenge for a specific window index.
fn derive_challenge_at(
    server_secret: &[u8],
    identity: &str,
    request_hash: &[u8],
    window_index: u64,
) -> [u8; 32] {
    let msg = build_hmac_message(identity, window_index, request_hash);
    hmac_sha256(server_secret, &msg)
}

/// Derive the challenge for the current window (`now_ms / window_ms`).
fn derive_challenge(
    server_secret: &[u8],
    identity: &str,
    request_hash: &[u8],
    window_ms: u64,
    now_ms: u64,
) -> [u8; 32] {
    derive_challenge_at(server_secret, identity, request_hash, now_ms / window_ms)
}

/// Check whether `SHA256(challenge || nonce_bytes)` meets `difficulty`.
fn check_solution(c: &[u8; 32], nonce_bytes: &[u8; 8], difficulty: u8) -> bool {
    let mut preimage = Vec::with_capacity(40);
    preimage.extend_from_slice(c);
    preimage.extend_from_slice(nonce_bytes);
    let digest = sha256(&preimage);
    leading_zero_bits(&digest) >= difficulty as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-server-secret";
    const IDENTITY: &str = "192.168.1.1";
    const REQUEST_HASH: &[u8] = &[0xAB; 32];
    const WINDOW_MS: u64 = 60_000; // 1 minute
    const NOW_MS: u64 = 1_000_000; // arbitrary, mid-window

    // -----------------------------------------------------------------------
    // Helper: brute-force a valid nonce for small difficulties (tests only).
    // -----------------------------------------------------------------------

    fn find_nonce(c: &Challenge) -> u64 {
        for nonce in 0u64..10_000_000 {
            let nonce_bytes = nonce.to_le_bytes();
            let mut preimage = Vec::with_capacity(40);
            preimage.extend_from_slice(&c.challenge);
            preimage.extend_from_slice(&nonce_bytes);
            let digest = sha256(&preimage);
            if leading_zero_bits(&digest) >= c.difficulty as u32 {
                return nonce;
            }
        }
        panic!("no valid nonce found within 10M iterations (difficulty too high for test?)");
    }

    // -----------------------------------------------------------------------
    // Core round-trip
    // -----------------------------------------------------------------------

    /// A nonce found by brute force must pass verify().
    #[test]
    fn valid_nonce_verifies() {
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 8, WINDOW_MS, NOW_MS);
        let nonce = find_nonce(&c);
        assert!(verify(
            SECRET,
            IDENTITY,
            REQUEST_HASH,
            8,
            nonce,
            WINDOW_MS,
            NOW_MS
        ));
    }

    /// Nonce 0 is (almost certainly) wrong for any meaningful difficulty.
    #[test]
    fn wrong_nonce_fails() {
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 10, WINDOW_MS, NOW_MS);
        // Compute what nonce 0 produces and assert it does NOT meet difficulty
        // (if by cosmic coincidence it does, the test is vacuous but won't panic).
        let nonce_bytes = 0u64.to_le_bytes();
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(&c.challenge);
        preimage.extend_from_slice(&nonce_bytes);
        let digest = sha256(&preimage);
        if leading_zero_bits(&digest) < 10 {
            assert!(!verify(
                SECRET,
                IDENTITY,
                REQUEST_HASH,
                10,
                0,
                WINDOW_MS,
                NOW_MS
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Request binding
    // -----------------------------------------------------------------------

    /// A nonce solved for one request_hash must not verify for a different one.
    #[test]
    fn different_request_hash_fails() {
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 8, WINDOW_MS, NOW_MS);
        let nonce = find_nonce(&c);

        let other_hash = &[0xCD; 32];
        assert!(!verify(
            SECRET, IDENTITY, other_hash, 8, nonce, WINDOW_MS, NOW_MS
        ));
    }

    /// A nonce solved for one identity must not verify for a different one.
    #[test]
    fn different_identity_fails() {
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 8, WINDOW_MS, NOW_MS);
        let nonce = find_nonce(&c);

        assert!(!verify(
            SECRET,
            "10.0.0.2",
            REQUEST_HASH,
            8,
            nonce,
            WINDOW_MS,
            NOW_MS
        ));
    }

    // -----------------------------------------------------------------------
    // Time-window expiry
    // -----------------------------------------------------------------------

    /// A nonce from the immediately previous window is accepted (clock skew).
    #[test]
    fn previous_window_is_accepted() {
        // Solve the challenge at the start of the previous window.
        let prev_now = NOW_MS - WINDOW_MS;
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 8, WINDOW_MS, prev_now);
        let nonce = find_nonce(&c);

        // Verify from the current window — should accept the previous window.
        assert!(verify(
            SECRET,
            IDENTITY,
            REQUEST_HASH,
            8,
            nonce,
            WINDOW_MS,
            NOW_MS
        ));
    }

    /// A nonce from two windows ago (stale) must be rejected.
    #[test]
    fn stale_window_is_rejected() {
        // Solve the challenge two windows back.
        let stale_now = NOW_MS - 2 * WINDOW_MS;
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 8, WINDOW_MS, stale_now);
        let nonce = find_nonce(&c);

        // Verify from the current window — two-window-old nonce must fail.
        assert!(!verify(
            SECRET,
            IDENTITY,
            REQUEST_HASH,
            8,
            nonce,
            WINDOW_MS,
            NOW_MS
        ));
    }

    // -----------------------------------------------------------------------
    // Difficulty edge cases
    // -----------------------------------------------------------------------

    /// Difficulty 0 requires zero leading bits — any nonce must pass.
    #[test]
    fn difficulty_zero_always_passes() {
        assert!(verify(
            SECRET,
            IDENTITY,
            REQUEST_HASH,
            0,
            0,
            WINDOW_MS,
            NOW_MS
        ));
        assert!(verify(
            SECRET,
            IDENTITY,
            REQUEST_HASH,
            0,
            12345,
            WINDOW_MS,
            NOW_MS
        ));
    }

    /// With difficulty 12 a brute-forced nonce must indeed produce >= 12
    /// leading zero bits in the solution hash.
    #[test]
    fn higher_difficulty_needs_more_leading_zeros() {
        let c = challenge(SECRET, IDENTITY, REQUEST_HASH, 12, WINDOW_MS, NOW_MS);
        let nonce = find_nonce(&c);
        let nonce_bytes = nonce.to_le_bytes();
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(&c.challenge);
        preimage.extend_from_slice(&nonce_bytes);
        let digest = sha256(&preimage);
        assert!(
            leading_zero_bits(&digest) >= 12,
            "found nonce has only {} leading zero bits",
            leading_zero_bits(&digest)
        );
    }

    // -----------------------------------------------------------------------
    // leading_zero_bits
    // -----------------------------------------------------------------------

    #[test]
    fn leading_zero_bits_all_zeros() {
        let d = [0u8; 32];
        assert_eq!(leading_zero_bits(&d), 256);
    }

    #[test]
    fn leading_zero_bits_first_byte_nonzero() {
        let mut d = [0u8; 32];
        // 0x80 = 1000_0000 => 0 leading zeros in the byte.
        d[0] = 0x80;
        assert_eq!(leading_zero_bits(&d), 0);
        // 0x40 = 0100_0000 => 1 leading zero in the byte.
        d[0] = 0x40;
        assert_eq!(leading_zero_bits(&d), 1);
        // 0x01 = 0000_0001 => 7 leading zeros in the byte.
        d[0] = 0x01;
        assert_eq!(leading_zero_bits(&d), 7);
    }

    #[test]
    fn leading_zero_bits_first_byte_zero_second_nonzero() {
        let mut d = [0u8; 32];
        d[0] = 0x00;
        // 0x0f = 0000_1111 => 4 leading zeros in this byte.
        d[1] = 0x0f;
        // Total: 8 (first byte) + 4 = 12.
        assert_eq!(leading_zero_bits(&d), 12);
    }

    #[test]
    fn leading_zero_bits_all_ones() {
        let d = [0xFFu8; 32];
        assert_eq!(leading_zero_bits(&d), 0);
    }

    // -----------------------------------------------------------------------
    // difficulty_for
    // -----------------------------------------------------------------------

    #[test]
    fn difficulty_for_zero_overage_returns_base() {
        assert_eq!(difficulty_for(8, 0.0), 8);
        assert_eq!(difficulty_for(8, -1.0), 8);
    }

    #[test]
    fn difficulty_for_is_monotonic() {
        let base = 8u8;
        let ratios = [0.0, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0];
        let difficulties: Vec<u8> = ratios.iter().map(|&r| difficulty_for(base, r)).collect();
        for w in difficulties.windows(2) {
            assert!(
                w[1] >= w[0],
                "difficulty_for is not monotonic: {} then {}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn difficulty_for_is_capped() {
        // Extreme overage should not overflow or exceed base + 20.
        let result = difficulty_for(8, 1_000_000.0);
        assert_eq!(result, 8u8.saturating_add(20));
    }

    #[test]
    fn difficulty_for_saturates_on_base_near_max() {
        // base close to u8::MAX should not wrap.
        let result = difficulty_for(250, 100.0);
        assert_eq!(result, 255); // saturating_add stops at 255
    }
}
