//! # Adaptive circuit build timeout
//!
//! How long should a client wait for a circuit before giving up?
//!
//! A fixed number can only be wrong in two directions. Too short and you
//! abandon circuits that were about to complete, then rebuild them — burning
//! relay work and making a slow network slower, exactly when it can least
//! afford it. Too long and a dead guard costs the user thirty seconds of
//! staring at a spinner before anything is retried. ΦNET used fifteen seconds
//! everywhere, which is a guess about a number that varies by orders of
//! magnitude between a LAN testnet and a congested network of volunteers on
//! home connections.
//!
//! The network already knows the answer: it's in the build times themselves.
//! So record them, and set the timeout at a percentile of what this client
//! actually observes. If most circuits complete in 2 seconds, waiting 15 is
//! silly. If they take 20, cutting at 15 guarantees failure.
//!
//! This mirrors Tor's `circuitstats.c`, which sets the timeout at roughly the
//! 80th percentile of a fitted distribution. Ours is simpler — an empirical
//! percentile over a sliding window, no Pareto fit — because the fitting
//! exists to extrapolate from few samples, and the honest alternative when
//! samples are few is to not adapt yet.
//!
//! ## Why a percentile and not a mean
//!
//! Build times are heavy-tailed: a few circuits take far longer than typical
//! because one hop is overloaded or a packet was lost. A mean is dragged
//! around by those outliers; a percentile says "most circuits are done by
//! now" and is stable under them. The tail is precisely what we want to
//! abandon.
//!
//! ## Anonymity note
//!
//! The timeout is derived from this client's own observations and never sent
//! anywhere. It does shape *behaviour* — a client that gives up at 4s behaves
//! differently from one that waits 15s — but so does every other adaptive
//! thing, and the alternative (a fixed constant everyone shares) is a much
//! stronger fingerprint than a value drawn from the same network conditions
//! every nearby client sees.

use std::collections::VecDeque;
use std::time::Duration;

/// Percentile of observed build times to cut at.
///
/// 80 means: keep waiting long enough for four out of five circuits that
/// would have succeeded, and abandon the slowest fifth rather than let them
/// hold up the user. Tor lands in the same neighbourhood for the same reason.
pub const TIMEOUT_PERCENTILE: f64 = 0.80;

/// How many recent builds to keep.
///
/// Enough to be stable, short enough to track a network that changed — a
/// guard that got slow an hour ago shouldn't still be inflating the timeout.
pub const WINDOW: usize = 100;

/// Don't adapt until we've seen at least this many builds.
///
/// With three samples the "80th percentile" is noise wearing a statistic's
/// clothes. Until then, use the fixed default: being conservative while
/// ignorant is the whole point.
pub const MIN_SAMPLES: usize = 20;

/// Used before enough samples exist, and as the floor/ceiling anchor.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Never cut below this, however fast the network looks.
///
/// A burst of fast builds on a LAN testnet shouldn't produce a 50ms timeout
/// that fails every real circuit the moment conditions change.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(1500);

/// Never wait longer than this, however slow things look.
///
/// Past this the user has left. Better to abandon and retry on a fresh path
/// than to keep faith with a circuit that's clearly stuck.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60);

/// A sliding window of circuit build times, and the timeout derived from it.
#[derive(Debug, Default)]
pub struct BuildTimes {
    samples: VecDeque<Duration>,
}

impl BuildTimes {
    pub fn new() -> Self { Self { samples: VecDeque::with_capacity(WINDOW) } }

    /// Record a circuit that finished building.
    ///
    /// Only *successful* builds are recorded. A timeout isn't evidence about
    /// how long circuits take — it's evidence about how long we were willing
    /// to wait, and feeding it back would ratchet the timeout down towards
    /// itself: we time out at 4s, record 4s, compute a lower percentile, time
    /// out sooner, and so on until nothing ever completes. This is the same
    /// class of bug as a bandwidth scanner reading its own degraded output.
    pub fn record(&mut self, d: Duration) {
        if self.samples.len() >= WINDOW { self.samples.pop_front(); }
        self.samples.push_back(d);
    }

    pub fn len(&self) -> usize { self.samples.len() }
    pub fn is_empty(&self) -> bool { self.samples.is_empty() }

    /// The current timeout: a percentile of observed builds, clamped.
    pub fn timeout(&self) -> Duration {
        if self.samples.len() < MIN_SAMPLES { return DEFAULT_TIMEOUT; }
        let mut v: Vec<Duration> = self.samples.iter().copied().collect();
        v.sort_unstable();
        // Nearest-rank: the smallest value at or above the percentile.
        let idx = ((v.len() as f64) * TIMEOUT_PERCENTILE).ceil() as usize;
        let idx = idx.saturating_sub(1).min(v.len() - 1);
        let p = v[idx];
        // Some headroom past the percentile: cutting *exactly* at it would
        // abandon a fifth of circuits that were merely typical-slow.
        let with_slack = p.mul_f64(1.5);
        with_slack.clamp(MIN_TIMEOUT, MAX_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_default_until_it_knows_better() {
        let mut b = BuildTimes::new();
        for _ in 0..(MIN_SAMPLES - 1) { b.record(Duration::from_millis(100)); }
        assert_eq!(b.timeout(), DEFAULT_TIMEOUT,
                   "must not adapt off a handful of samples");
    }

    #[test]
    fn adapts_down_on_a_fast_network() {
        let mut b = BuildTimes::new();
        for _ in 0..MIN_SAMPLES { b.record(Duration::from_millis(500)); }
        let t = b.timeout();
        assert!(t < DEFAULT_TIMEOUT, "fast network should shorten the wait, got {t:?}");
        assert!(t >= MIN_TIMEOUT, "but never below the floor");
    }

    #[test]
    fn adapts_up_on_a_slow_network() {
        let mut b = BuildTimes::new();
        for _ in 0..MIN_SAMPLES { b.record(Duration::from_secs(20)); }
        assert!(b.timeout() > DEFAULT_TIMEOUT,
                "a network where builds take 20s must not cut at 15");
    }

    #[test]
    fn a_few_slow_outliers_do_not_drag_the_timeout() {
        let mut b = BuildTimes::new();
        for _ in 0..95 { b.record(Duration::from_millis(400)); }
        for _ in 0..5  { b.record(Duration::from_secs(45)); }   // stragglers
        let t = b.timeout();
        assert!(t < Duration::from_secs(5),
                "the point of a percentile is to ignore the tail, got {t:?}");
    }

    #[test]
    fn clamped_at_both_ends() {
        let mut fast = BuildTimes::new();
        for _ in 0..MIN_SAMPLES { fast.record(Duration::from_micros(10)); }
        assert_eq!(fast.timeout(), MIN_TIMEOUT, "a LAN burst mustn't set a 15µs timeout");

        let mut slow = BuildTimes::new();
        for _ in 0..MIN_SAMPLES { slow.record(Duration::from_secs(600)); }
        assert_eq!(slow.timeout(), MAX_TIMEOUT, "past a minute the user is gone");
    }

    #[test]
    fn window_forgets_old_conditions() {
        let mut b = BuildTimes::new();
        for _ in 0..WINDOW { b.record(Duration::from_secs(30)); }   // congested
        for _ in 0..WINDOW { b.record(Duration::from_millis(300)); } // recovered
        assert_eq!(b.len(), WINDOW, "window must not grow without bound");
        assert!(b.timeout() < Duration::from_secs(5),
                "an hour-old slowdown shouldn't still inflate the timeout");
    }
}
