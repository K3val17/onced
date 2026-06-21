//! Abuse / velocity defense.
//!
//! The same engine that asks "have I seen this exact operation before?"
//! (idempotency) is the right place to ask "have I seen *too many* operations
//! from this actor?" (abuse defense). This module provides the real-time
//! counting substrate.
//!
//! [`SlidingWindowLimiter`] is the Cloudflare-style **sliding-window counter**:
//! it keeps just two counters per key (the current and previous fixed windows)
//! and estimates the trailing-window rate by weighting the previous window by
//! how much of it still overlaps the trailing window. This costs O(1) memory per
//! key, and — unlike a fixed window — it denies an attacker who tries to burst
//! across a window boundary (fire the full limit at the end of one window and
//! again at the start of the next). Cloudflare reports ~0.003% error from this
//! approximation while making billions of decisions per day.
//!
//! Like the rest of the core, time is *injected* (`now_ms`), so behaviour is
//! deterministic and simulation-testable. `now_ms` is assumed monotonic
//! non-decreasing (the gateway supplies a monotonic clock).
//!
//! Production code is written test-first; the tests below are watched failing
//! before `SlidingWindowLimiter` and `Decision` exist.

use std::collections::HashMap;

/// The verdict for one request against a limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Within budget — let it through.
    Allow,
    /// Over budget — reject (or, at a higher layer, challenge / throttle).
    Deny,
}

/// The two fixed-window counters tracked per key.
struct WindowCounter {
    /// Index of the window `current` belongs to (`now_ms / window_ms`).
    window_index: u64,
    /// Hits recorded in the current window.
    current: u64,
    /// Hits recorded in the immediately preceding window.
    previous: u64,
}

/// Default cap on the number of distinct keys a limiter tracks, bounding its
/// memory regardless of how many distinct keys it sees. One `WindowCounter` is a
/// few words, so ~1M keys is on the order of tens of MB.
pub const DEFAULT_MAX_KEYS: usize = 1_000_000;

/// A Cloudflare-style sliding-window rate limiter: O(1) memory per key, and
/// resistant to window-boundary bursting (see module docs). The number of
/// tracked keys is hard-capped so a key-rotation flood cannot exhaust memory.
pub struct SlidingWindowLimiter {
    window_ms: u64,
    limit: u64,
    max_keys: usize,
    counters: HashMap<String, WindowCounter>,
}

impl SlidingWindowLimiter {
    /// Create a limiter allowing up to `limit` hits per trailing `window_ms`,
    /// tracking up to [`DEFAULT_MAX_KEYS`] distinct keys.
    pub fn new(window_ms: u64, limit: u64) -> Self {
        Self::with_capacity(window_ms, limit, DEFAULT_MAX_KEYS)
    }

    /// Create a limiter with an explicit cap on tracked keys.
    pub fn with_capacity(window_ms: u64, limit: u64, max_keys: usize) -> Self {
        assert!(window_ms > 0, "window_ms must be non-zero");
        assert!(max_keys > 0, "max_keys must be non-zero");
        Self {
            window_ms,
            limit,
            max_keys,
            counters: HashMap::new(),
        }
    }

    /// How many distinct keys are currently tracked (bounded by `max_keys`).
    pub fn tracked_keys(&self) -> usize {
        self.counters.len()
    }

    /// Record a hit for `key` at `now_ms` and return whether it is within budget.
    /// `now_ms` is assumed monotonic non-decreasing.
    pub fn check(&mut self, key: &str, now_ms: u64) -> Decision {
        let window_ms = self.window_ms;
        let limit = self.limit;
        let window_index = now_ms / window_ms;

        // Bound memory: before admitting a brand-new key at capacity, evict one
        // tracked key. Under a key-rotation flood this keeps the map from growing
        // without bound; an evicted key simply restarts its count — and an
        // attacker cycling fresh keys never accumulates one anyway, so the
        // eviction costs the defense nothing.
        if self.counters.len() >= self.max_keys && !self.counters.contains_key(key) {
            if let Some(victim) = self.counters.keys().next().cloned() {
                self.counters.remove(&victim);
            }
        }

        let counter = self
            .counters
            .entry(key.to_string())
            .or_insert(WindowCounter {
                window_index,
                current: 0,
                previous: 0,
            });

        // Roll the windows forward to `window_index`.
        if window_index == counter.window_index + 1 {
            // Advanced exactly one window: last window becomes "previous".
            counter.previous = counter.current;
            counter.current = 0;
            counter.window_index = window_index;
        } else if window_index > counter.window_index + 1 {
            // Skipped one or more windows: nothing recent survives.
            counter.previous = 0;
            counter.current = 0;
            counter.window_index = window_index;
        }
        // Otherwise `window_index <= counter.window_index`: same window, keep
        // accumulating (a non-advancing monotonic clock).

        counter.current += 1;

        // Weight the previous window by how much of it still overlaps the
        // trailing `window_ms` ending at `now_ms`.
        let elapsed = now_ms % window_ms;
        let prev_weight = (window_ms - elapsed) as f64 / window_ms as f64;
        let estimate = counter.current as f64 + counter.previous as f64 * prev_weight;

        if estimate <= limit as f64 {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

/// What to do when a rule's budget is exceeded. The engine only *classifies*;
/// how to act (return an error, add latency, drop the request) is the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Make the caller prove itself (e.g. a CAPTCHA or step-up auth).
    Challenge,
    /// Deliberately slow the caller down.
    Throttle,
    /// Reject outright.
    Block,
}

/// The outcome of evaluating a [`RuleSet`] for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No rule tripped.
    Allow,
    /// A rule tripped: `rule` names it, `action` is what to do.
    Deny { rule: String, action: Action },
}

/// One named limit and the action to take when it is exceeded.
struct Rule {
    name: String,
    limiter: SlidingWindowLimiter,
    action: Action,
}

/// An ordered set of rate-limit rules evaluated together over the same key.
/// Every rule is recorded on each request (so each dimension stays accurate),
/// and the first rule to trip — in insertion order — decides the verdict.
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// An empty rule set (allows everything).
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule: up to `limit` hits per trailing `window_ms`, else `action`.
    pub fn rule(mut self, name: &str, window_ms: u64, limit: u64, action: Action) -> Self {
        self.rules.push(Rule {
            name: name.to_string(),
            limiter: SlidingWindowLimiter::new(window_ms, limit),
            action,
        });
        self
    }

    /// Record this request against every rule and return the verdict.
    pub fn evaluate(&mut self, key: &str, now_ms: u64) -> Verdict {
        let mut verdict = Verdict::Allow;
        for rule in &mut self.rules {
            let denied = matches!(rule.limiter.check(key, now_ms), Decision::Deny);
            if denied && verdict == Verdict::Allow {
                verdict = Verdict::Deny {
                    rule: rule.name.clone(),
                    action: rule.action,
                };
            }
        }
        verdict
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::abuse::{Action, Decision, RuleSet, SlidingWindowLimiter, Verdict};

    /// Up to and including the limit is allowed; the next request is denied.
    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let mut limiter = SlidingWindowLimiter::new(1000, 5);
        for _ in 0..5 {
            assert!(matches!(limiter.check("ip-1", 0), Decision::Allow));
        }
        assert!(matches!(limiter.check("ip-1", 0), Decision::Deny));
    }

    /// The defining property of a *sliding* window: a burst at the end of one
    /// window cannot be immediately doubled at the start of the next. A fixed
    /// window would reset to zero at the boundary and let the attacker through.
    #[test]
    fn sliding_window_blocks_boundary_bursting() {
        let mut limiter = SlidingWindowLimiter::new(1000, 5);
        for _ in 0..5 {
            assert!(matches!(limiter.check("ip-1", 999), Decision::Allow));
        }
        assert!(matches!(limiter.check("ip-1", 1000), Decision::Deny));
    }

    /// Two full windows later, an old burst has fully decayed out of the count.
    #[test]
    fn old_traffic_decays_after_two_windows() {
        let mut limiter = SlidingWindowLimiter::new(1000, 5);
        for _ in 0..5 {
            limiter.check("ip-1", 0);
        }
        assert!(matches!(limiter.check("ip-1", 2000), Decision::Allow));
    }

    /// Different keys (IPs, accounts, card fingerprints) are counted separately.
    #[test]
    fn keys_are_counted_independently() {
        let mut limiter = SlidingWindowLimiter::new(1000, 1);
        assert!(matches!(limiter.check("a", 0), Decision::Allow));
        assert!(matches!(limiter.check("a", 0), Decision::Deny));
        assert!(matches!(limiter.check("b", 0), Decision::Allow));
    }

    /// The previous window contributes in proportion to its overlap with the
    /// trailing window. Halfway into the next window, a previously-full window of
    /// 10 contributes 10 * 0.5 = 5, leaving headroom for exactly 5 more.
    #[test]
    fn previous_window_is_weighted_by_overlap() {
        let mut limiter = SlidingWindowLimiter::new(1000, 10);
        for _ in 0..10 {
            limiter.check("ip-1", 0);
        }

        let mut allowed = 0;
        for _ in 0..10 {
            if matches!(limiter.check("ip-1", 1500), Decision::Allow) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5);
    }

    /// `tracked_keys` reports the exact number of distinct keys held.
    #[test]
    fn tracked_keys_reports_the_exact_count() {
        let mut limiter = SlidingWindowLimiter::with_capacity(1000, 5, 128);
        limiter.check("a", 0);
        limiter.check("b", 0);
        limiter.check("a", 0); // repeat — still two distinct keys
        assert_eq!(limiter.tracked_keys(), 2);
    }

    /// Eviction happens only at capacity, not before: building up to exactly the
    /// cap evicts nothing, and the next new key keeps the map at the cap.
    #[test]
    fn eviction_happens_only_at_capacity() {
        let cap = 4;
        let mut limiter = SlidingWindowLimiter::with_capacity(1000, 100, cap);
        for k in ["a", "b", "c", "d"] {
            limiter.check(k, 0);
        }
        assert_eq!(
            limiter.tracked_keys(),
            cap,
            "no key should be evicted while building up to the cap"
        );
        limiter.check("e", 0); // at cap: evicts exactly one to make room
        assert_eq!(limiter.tracked_keys(), cap, "stays at the cap");
    }

    /// A key-rotation flood (an attacker cycling through millions of distinct
    /// IPs/cards) must not grow the limiter without bound. Tracked keys stay at
    /// or below the configured cap.
    #[test]
    fn tracked_keys_stay_bounded_under_key_rotation() {
        let cap = 128;
        let mut limiter = SlidingWindowLimiter::with_capacity(1000, 5, cap);
        for i in 0..10_000 {
            limiter.check(&format!("ip-{i}"), 0);
        }
        assert!(
            limiter.tracked_keys() <= cap,
            "limiter memory must stay bounded, got {} keys",
            limiter.tracked_keys()
        );
    }

    #[test]
    fn rules_allow_when_every_rule_passes() {
        let mut rules = RuleSet::new()
            .rule("per-second", 1000, 100, Action::Throttle)
            .rule("per-minute", 60_000, 1000, Action::Block);
        assert_eq!(rules.evaluate("ip-1", 0), Verdict::Allow);
    }

    #[test]
    fn rules_deny_with_the_tripped_rules_action() {
        let mut rules = RuleSet::new().rule("strict", 1000, 2, Action::Block);
        assert_eq!(rules.evaluate("ip-1", 0), Verdict::Allow);
        assert_eq!(rules.evaluate("ip-1", 0), Verdict::Allow);
        assert_eq!(
            rules.evaluate("ip-1", 0),
            Verdict::Deny {
                rule: "strict".into(),
                action: Action::Block,
            }
        );
    }

    #[test]
    fn rules_first_tripped_in_order_wins() {
        let mut rules = RuleSet::new()
            .rule("loose-throttle", 1000, 100, Action::Throttle)
            .rule("strict-block", 1000, 2, Action::Block);
        rules.evaluate("ip-1", 0);
        rules.evaluate("ip-1", 0);
        assert_eq!(
            rules.evaluate("ip-1", 0),
            Verdict::Deny {
                rule: "strict-block".into(),
                action: Action::Block,
            }
        );
    }

    #[test]
    fn rules_keep_keys_independent() {
        let mut rules = RuleSet::new().rule("strict", 1000, 1, Action::Challenge);
        assert_eq!(rules.evaluate("a", 0), Verdict::Allow);
        assert_eq!(
            rules.evaluate("a", 0),
            Verdict::Deny {
                rule: "strict".into(),
                action: Action::Challenge,
            }
        );
        assert_eq!(rules.evaluate("b", 0), Verdict::Allow);
    }
}
