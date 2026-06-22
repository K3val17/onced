//! Distinct-target velocity detection: the carding / credential-stuffing signal.
//!
//! A plain rate limiter counts *how many* requests an actor makes. That misses
//! the most important fraud pattern: one actor touching *many distinct targets*.
//! An IP trying 500 different card numbers (carding), or one stolen card seen
//! from 500 different IPs, or one IP hitting 500 different accounts (credential
//! stuffing) all look fine to a rate limiter if each individual target is hit
//! only once, but they are exactly what fraud looks like.
//!
//! [`DistinctVelocityLimiter`] flags an actor whose count of *distinct* targets
//! in the current window exceeds a threshold. Distinct-counting is done with a
//! [`HyperLogLog`](crate::hll::HyperLogLog) per actor, so memory is bounded
//! regardless of how many distinct targets an actor throws at it, and the number
//! of tracked actors is itself capped (a key-rotation flood cannot exhaust
//! memory). Like the rest of the core, time is injected (`now_ms`).

use crate::abuse::Decision;
use crate::hll::HyperLogLog;
use std::collections::HashMap;

/// Default cap on tracked actors (bounds total memory).
pub const DEFAULT_MAX_ACTORS: usize = 100_000;
/// HyperLogLog precision per actor. p=10 gives ~3% standard error at a few
/// hundred bytes per actor, which is ample for an order-of-magnitude threshold.
const PRECISION: u8 = 10;

/// One actor's distinct-target counter for the current fixed window.
struct ActorWindow {
    window_index: u64,
    seen: HyperLogLog,
}

/// Flags an actor that touches more than `max_distinct` distinct targets within
/// a fixed `window_ms` window. O(1) bounded memory per actor.
pub struct DistinctVelocityLimiter {
    window_ms: u64,
    max_distinct: u64,
    max_actors: usize,
    actors: HashMap<String, ActorWindow>,
}

impl DistinctVelocityLimiter {
    /// Flag any actor exceeding `max_distinct` distinct targets per `window_ms`.
    pub fn new(window_ms: u64, max_distinct: u64) -> Self {
        Self::with_capacity(window_ms, max_distinct, DEFAULT_MAX_ACTORS)
    }

    /// As [`new`](Self::new), with an explicit cap on tracked actors.
    pub fn with_capacity(window_ms: u64, max_distinct: u64, max_actors: usize) -> Self {
        assert!(window_ms > 0, "window_ms must be non-zero");
        assert!(max_actors > 0, "max_actors must be non-zero");
        Self {
            window_ms,
            max_distinct,
            max_actors,
            actors: HashMap::new(),
        }
    }

    /// Number of actors currently tracked (bounded by `max_actors`).
    pub fn tracked_actors(&self) -> usize {
        self.actors.len()
    }

    /// Record that `actor` touched `target` at `now_ms`, and return whether the
    /// actor is now over its distinct-target budget for the window.
    pub fn check(&mut self, actor: &str, target: &str, now_ms: u64) -> Decision {
        let window_index = now_ms / self.window_ms;

        // Bound memory: evict one actor before admitting a brand-new one at cap.
        if self.actors.len() >= self.max_actors && !self.actors.contains_key(actor) {
            if let Some(victim) = self.actors.keys().next().cloned() {
                self.actors.remove(&victim);
            }
        }

        let entry = self.actors.entry(actor.to_string()).or_insert(ActorWindow {
            window_index,
            seen: HyperLogLog::new(PRECISION),
        });

        // Fixed window: a new window starts a fresh distinct-count.
        if entry.window_index != window_index {
            entry.window_index = window_index;
            entry.seen = HyperLogLog::new(PRECISION);
        }

        entry.seen.add(target);

        if entry.seen.estimate() > self.max_distinct as f64 {
            Decision::Deny
        } else {
            Decision::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DistinctVelocityLimiter;
    use crate::abuse::Decision;

    /// Carding: one actor fanning out to many distinct targets is flagged.
    #[test]
    fn flags_an_actor_hitting_many_distinct_targets() {
        let mut limiter = DistinctVelocityLimiter::new(1_000, 20);
        let mut last = Decision::Allow;
        for i in 0..200 {
            last = limiter.check("ip-1", &format!("card-{i}"), 0);
        }
        assert_eq!(
            last,
            Decision::Deny,
            "200 distinct targets must trip the limit"
        );
    }

    /// The same target hit repeatedly is NOT carding: distinct count stays at 1.
    #[test]
    fn the_same_target_repeated_is_never_flagged() {
        let mut limiter = DistinctVelocityLimiter::new(1_000, 20);
        for _ in 0..500 {
            assert_eq!(limiter.check("ip-1", "card-x", 0), Decision::Allow);
        }
    }

    /// A small number of distinct targets stays under the limit.
    #[test]
    fn a_few_distinct_targets_are_allowed() {
        let mut limiter = DistinctVelocityLimiter::new(1_000, 20);
        for i in 0..5 {
            assert_eq!(
                limiter.check("ip-1", &format!("acct-{i}"), 0),
                Decision::Allow
            );
        }
    }

    /// Distinct actors are independent; one carder does not flag a clean actor.
    #[test]
    fn actors_are_counted_independently() {
        let mut limiter = DistinctVelocityLimiter::new(1_000, 20);
        for i in 0..200 {
            limiter.check("carder", &format!("card-{i}"), 0);
        }
        assert_eq!(limiter.check("clean", "card-1", 0), Decision::Allow);
    }

    /// A new window resets the distinct-count, so yesterday's fan-out does not
    /// permanently condemn an actor.
    #[test]
    fn a_new_window_resets_the_distinct_count() {
        let mut limiter = DistinctVelocityLimiter::new(1_000, 20);
        for i in 0..200 {
            limiter.check("ip-1", &format!("card-{i}"), 0);
        }
        // Next window: a single new target is fine again.
        assert_eq!(limiter.check("ip-1", "card-new", 5_000), Decision::Allow);
    }

    /// A flood of distinct actors cannot grow memory without bound.
    #[test]
    fn tracked_actors_stay_bounded() {
        let cap = 128;
        let mut limiter = DistinctVelocityLimiter::with_capacity(1_000, 20, cap);
        for i in 0..10_000 {
            limiter.check(&format!("ip-{i}"), "target", 0);
        }
        assert!(limiter.tracked_actors() <= cap);
    }
}
