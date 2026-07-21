//! # Path bias detection
//!
//! Guards exist so that only a few relays ever learn your address. That gives
//! a guard leverage nothing else on the path has: it sees every circuit you
//! attempt, and it can *choose which ones work*.
//!
//! A guard that quietly fails every circuit whose middle hop it doesn't
//! control, while completing the ones it does, steers you onto adversary
//! paths without ever forging a signature or breaking a cipher. Every circuit
//! you end up using was built correctly — that's what makes it hard to see.
//! From inside, it looks like an unreliable network, and the natural response
//! (retry, and the retry succeeds) is exactly the behaviour the attack wants.
//!
//! So count. A guard on a healthy network fails some circuits, because
//! networks are unreliable — but it fails them at roughly the rate everything
//! else does. A guard failing four out of five, when your other guards fail
//! one in ten, isn't unlucky.
//!
//! This mirrors Tor's `pathbias` accounting. As there, the answer is to
//! notice and warn rather than act automatically: an aggressive detector is
//! itself an attack surface (get a client to drop honest guards and it must
//! choose new ones, which an attacker can race to supply), and a client that
//! silently drops guards on a flaky connection has been talked out of guard
//! pinning by its own network.
//!
//! ## What "failure" means here
//!
//! Only circuits that failed *after* the guard accepted them. A guard that's
//! simply unreachable is a different problem with a different fix, and
//! counting it here would blame a guard for the network being down.

use std::collections::HashMap;

/// Don't judge a guard until it has this many attempts.
///
/// Two failures out of two is a 100% failure rate and means nothing. Tor uses
/// a similar floor for the same reason: small samples manufacture outrage.
pub const MIN_ATTEMPTS: u32 = 20;

/// Warn when a guard's success rate falls below this.
///
/// 0.30 is deliberately generous. Real guards on real networks have bad days,
/// and the cost of a false positive — scaring a user about an honest relay,
/// or worse, teaching them to ignore the warning — is high. A guard *below*
/// this is not having a bad day.
pub const WARN_SUCCESS_RATE: f64 = 0.30;

/// Per-guard circuit outcome counts.
#[derive(Debug, Default, Clone, Copy)]
pub struct GuardStats {
    pub attempts: u32,
    pub successes: u32,
}

impl GuardStats {
    pub fn failures(&self) -> u32 { self.attempts.saturating_sub(self.successes) }

    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 { return 1.0; }   // no evidence ⇒ no accusation
        self.successes as f64 / self.attempts as f64
    }

    /// Enough evidence, and bad enough, to tell the user about.
    pub fn is_suspicious(&self) -> bool {
        self.attempts >= MIN_ATTEMPTS && self.success_rate() < WARN_SUCCESS_RATE
    }
}

/// Circuit outcomes per guard.
#[derive(Debug, Default)]
pub struct PathBias {
    guards: HashMap<String, GuardStats>,
}

impl PathBias {
    pub fn new() -> Self { Self::default() }

    /// A circuit was attempted through this guard (the guard accepted it).
    pub fn note_attempt(&mut self, guard_hex: &str) {
        self.guards.entry(guard_hex.to_string()).or_default().attempts += 1;
    }

    /// That circuit completed.
    pub fn note_success(&mut self, guard_hex: &str) {
        self.guards.entry(guard_hex.to_string()).or_default().successes += 1;
    }

    pub fn stats(&self, guard_hex: &str) -> GuardStats {
        self.guards.get(guard_hex).copied().unwrap_or_default()
    }

    /// Guards whose failure rate is too lopsided to be luck.
    ///
    /// Returns them rather than acting: the caller decides whether to warn,
    /// deprioritise, or ignore. Dropping a guard automatically hands an
    /// attacker a lever — make the honest guard look bad, and the client goes
    /// shopping for a new one.
    pub fn suspicious(&self) -> Vec<(String, GuardStats)> {
        let mut v: Vec<(String, GuardStats)> = self.guards.iter()
            .filter(|(_, s)| s.is_suspicious())
            .map(|(g, s)| (g.clone(), *s))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Every guard we have counts for, worst first — for a status display.
    pub fn all(&self) -> Vec<(String, GuardStats)> {
        let mut v: Vec<(String, GuardStats)> = self.guards.iter()
            .map(|(g, s)| (g.clone(), *s)).collect();
        v.sort_by(|a, b| a.1.success_rate().partial_cmp(&b.1.success_rate())
            .unwrap_or(std::cmp::Ordering::Equal));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(pb: &mut PathBias, guard: &str, attempts: u32, successes: u32) {
        for i in 0..attempts {
            pb.note_attempt(guard);
            if i < successes { pb.note_success(guard); }
        }
    }

    #[test]
    fn no_evidence_is_not_evidence_of_guilt() {
        let pb = PathBias::new();
        let s = pb.stats("never-seen");
        assert_eq!(s.success_rate(), 1.0);
        assert!(!s.is_suspicious());
    }

    #[test]
    fn a_short_unlucky_streak_is_not_an_accusation() {
        let mut pb = PathBias::new();
        run(&mut pb, "aa", 3, 0);   // 0% — but from three attempts
        assert!(pb.suspicious().is_empty(),
                "three failures is a bad afternoon, not an attack");
    }

    #[test]
    fn a_healthy_guard_is_left_alone() {
        let mut pb = PathBias::new();
        run(&mut pb, "aa", 100, 92);
        assert!(pb.suspicious().is_empty());
    }

    #[test]
    fn a_flaky_but_plausible_guard_is_left_alone() {
        let mut pb = PathBias::new();
        run(&mut pb, "aa", 100, 55);   // bad, but networks are bad
        assert!(pb.suspicious().is_empty(),
                "55% is a poor guard, not evidence of steering");
    }

    #[test]
    fn a_guard_failing_almost_everything_is_flagged() {
        let mut pb = PathBias::new();
        run(&mut pb, "aa", 100, 8);    // 8% — not luck
        let sus = pb.suspicious();
        assert_eq!(sus.len(), 1);
        assert_eq!(sus[0].0, "aa");
        assert_eq!(sus[0].1.failures(), 92);
    }

    #[test]
    fn guards_are_judged_separately() {
        let mut pb = PathBias::new();
        run(&mut pb, "good", 100, 95);
        run(&mut pb, "bad",  100, 5);
        let sus = pb.suspicious();
        assert_eq!(sus.len(), 1, "a healthy guard mustn't be tarred by a bad one");
        assert_eq!(sus[0].0, "bad");
    }

    #[test]
    fn all_lists_worst_first() {
        let mut pb = PathBias::new();
        run(&mut pb, "good", 50, 48);
        run(&mut pb, "bad",  50, 2);
        let all = pb.all();
        assert_eq!(all[0].0, "bad", "a status display should lead with the problem");
    }
}
