//! Count-Min Sketch: frequency estimation over a huge key space in fixed memory.
//!
//! A carding attacker hits checkout with thousands of distinct stolen cards;
//! tracking an exact per-card counter would cost unbounded memory. A Count-Min
//! Sketch (Cormode & Muthukrishnan, 2005) answers "how many times have I seen
//! this key?" in `O(depth * width)` memory regardless of how many distinct keys
//! exist. Cloudflare's Pingora uses exactly this for per-key limits at ~20M
//! req/s with ~1000x the memory savings of a hash map.
//!
//! It has **one-sided error**: it may over-estimate (hash collisions add other
//! keys' counts) but it never under-estimates. Taking the *minimum* across
//! `depth` independent rows cancels most collision noise. That one-sided
//! guarantee is exactly what abuse defense wants: a heavy hitter can never hide.
//!
//! Production code is written test-first; the tests below are watched failing
//! before `CountMinSketch` exists.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A Count-Min Sketch: `depth` rows of `width` counters. Each key maps to one
/// column per row (via an independent hash); `add` bumps those cells and
/// `estimate` returns the minimum across them.
pub struct CountMinSketch {
    depth: usize,
    width: usize,
    counters: Vec<u64>,
}

impl CountMinSketch {
    /// Create a sketch with `depth` rows and `width` counters per row. Larger
    /// `width` lowers the over-estimate per row; larger `depth` lowers the
    /// probability of a large over-estimate.
    pub fn new(depth: usize, width: usize) -> Self {
        assert!(depth > 0 && width > 0, "depth and width must be non-zero");
        Self {
            depth,
            width,
            counters: vec![0; depth * width],
        }
    }

    /// The column `key` hashes to in `row`. Mixing the row index into the hash
    /// gives an independent hash function per row from one hasher family.
    fn column(&self, row: usize, key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        row.hash(&mut hasher);
        key.hash(&mut hasher);
        (hasher.finish() % self.width as u64) as usize
    }

    /// Record `count` occurrences of `key`.
    pub fn add(&mut self, key: &str, count: u64) {
        for row in 0..self.depth {
            let column = self.column(row, key);
            let cell = &mut self.counters[row * self.width + column];
            *cell = cell.saturating_add(count);
        }
    }

    /// Estimate the total count recorded for `key`. Never an under-estimate.
    pub fn estimate(&self, key: &str) -> u64 {
        (0..self.depth)
            .map(|row| self.counters[row * self.width + self.column(row, key)])
            .min()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use crate::sketch::CountMinSketch;
    use std::collections::HashMap;

    /// With no collisions (a single key), the estimate is exact; an unseen key
    /// in an empty sketch reads zero.
    #[test]
    fn estimates_a_lone_key_exactly() {
        let mut cms = CountMinSketch::new(4, 256);
        for _ in 0..7 {
            cms.add("card-1", 1);
        }
        assert_eq!(cms.estimate("card-1"), 7);
        assert_eq!(cms.estimate("never-seen"), 0);
    }

    /// The core invariant: the estimate is never below the true count, for every
    /// key, no matter how many distinct keys collide into the sketch.
    #[test]
    fn never_underestimates_across_many_keys() {
        let mut cms = CountMinSketch::new(5, 512);
        let mut truth: HashMap<String, u64> = HashMap::new();

        let mut state = 0x1234_5678u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..2000 {
            let key = format!("k{}", next() % 300);
            let count = 1 + next() % 5;
            *truth.entry(key.clone()).or_insert(0) += count;
            cms.add(&key, count);
        }

        for (key, &true_count) in &truth {
            assert!(
                cms.estimate(key) >= true_count,
                "underestimated {key}: {} < {true_count}",
                cms.estimate(key)
            );
        }
    }

    /// A heavy hitter (the carding signal) stands far above the light traffic it
    /// hides among.
    #[test]
    fn surfaces_a_heavy_hitter() {
        let mut cms = CountMinSketch::new(5, 1024);
        for _ in 0..1000 {
            cms.add("attacker-ip", 1);
        }
        for i in 0..500 {
            cms.add(&format!("user{i}"), 1);
        }

        assert!(cms.estimate("attacker-ip") >= 1000);
        assert!(cms.estimate("attacker-ip") > 10 * cms.estimate("user42").max(1));
    }
}
