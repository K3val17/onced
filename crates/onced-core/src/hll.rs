//! HyperLogLog: distinct-count (cardinality) estimation in fixed memory.
//!
//! Where the Count-Min Sketch answers "how *often*?", HyperLogLog answers "how
//! *many distinct*?" — the sharpest carding signal of all: *how many distinct
//! card numbers has this one IP tried in the last 10 minutes?* A genuine
//! customer touches one or two cards; a fraud ring touches hundreds. HyperLogLog
//! (Flajolet et al., 2007) estimates that distinct count to within ~1.6% using a
//! few kilobytes, no matter whether the true count is ten or ten million.
//!
//! The idea: hash each item, use the top `p` bits to pick one of `m = 2^p`
//! registers, and record in that register the longest run of leading zeros seen
//! in the rest of the hash. Long zero-runs are rare, so the longest one observed
//! is a fingerprint of how many distinct items hashed there; harmonic-mean those
//! across all registers and you get the cardinality.
//!
//! Hashing is deterministic (fixed-seed `DefaultHasher`), so estimates are
//! reproducible — important for testing a probabilistic structure.
//!
//! Production code is written test-first; the tests below are watched failing
//! before `HyperLogLog` exists.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A HyperLogLog distinct-count estimator with `2^precision` registers.
pub struct HyperLogLog {
    precision: u32,
    registers: Vec<u8>,
}

impl HyperLogLog {
    /// Create a sketch with `2^precision` registers. Precision 4..=16 trades
    /// memory for accuracy (relative error ~= 1.04 / sqrt(2^precision)).
    pub fn new(precision: u8) -> Self {
        assert!((4..=16).contains(&precision), "precision must be in 4..=16");
        let precision = precision as u32;
        Self {
            precision,
            registers: vec![0u8; 1usize << precision],
        }
    }

    /// Observe `key`. Idempotent for a given key: re-adding it changes nothing.
    pub fn add(&mut self, key: &str) {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        let p = self.precision;
        let index = (hash >> (64 - p)) as usize;
        // Shift the index bits out, then set a guard bit so the rank is bounded
        // by (64 - p) + 1 even when the suffix is all zeros.
        let suffix = (hash << p) | (1u64 << (p - 1));
        let rank = suffix.leading_zeros() as u8 + 1;

        if rank > self.registers[index] {
            self.registers[index] = rank;
        }
    }

    /// Estimate the number of distinct keys observed.
    pub fn estimate(&self) -> f64 {
        let m = self.registers.len() as f64;
        let alpha = match self.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };

        let harmonic: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let raw = alpha * m * m / harmonic;

        // Small-range correction: when many registers are still empty, linear
        // counting is far more accurate than the raw HLL estimate.
        let zeros = self.registers.iter().filter(|&&r| r == 0).count();
        if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hll::HyperLogLog;

    /// An empty sketch estimates zero distinct items.
    #[test]
    fn empty_estimates_zero() {
        let hll = HyperLogLog::new(12);
        assert_eq!(hll.estimate(), 0.0);
    }

    /// Adding the same item ten thousand times is still one distinct item.
    #[test]
    fn duplicates_do_not_inflate_cardinality() {
        let mut hll = HyperLogLog::new(12);
        for _ in 0..10_000 {
            hll.add("same-card");
        }
        assert!(
            hll.estimate() < 5.0,
            "estimate {} should be ~1 for a single distinct key",
            hll.estimate()
        );
    }

    /// Mid-range cardinality is estimated within ~10% (well inside the structure's
    /// error budget at this precision).
    #[test]
    fn estimates_mid_range_cardinality() {
        let mut hll = HyperLogLog::new(12);
        let n = 5_000usize;
        for i in 0..n {
            hll.add(&format!("card-{i}"));
        }
        let estimate = hll.estimate();
        let error = (estimate - n as f64).abs() / n as f64;
        assert!(error < 0.10, "estimate {estimate} vs {n}, error {error}");
    }

    /// Large cardinality (the pure-HLL regime, past the small-range correction)
    /// is also within ~10%.
    #[test]
    fn estimates_large_cardinality() {
        let mut hll = HyperLogLog::new(12);
        let n = 50_000usize;
        for i in 0..n {
            hll.add(&format!("user-{i}"));
        }
        let estimate = hll.estimate();
        let error = (estimate - n as f64).abs() / n as f64;
        assert!(error < 0.10, "estimate {estimate} vs {n}, error {error}");
    }
}
