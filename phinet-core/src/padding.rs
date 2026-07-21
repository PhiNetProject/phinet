// phinet-core/src/padding.rs
//!
//! # Circuit-level padding scheduler
//!
//! ΦNET has had per-link constant-rate padding (`session.rs::TrafficPadder`)
//! for a while. That helps obscure *whether* a peer connection is in use,
//! but it doesn't help against the more sophisticated attack: an observer
//! who sees the timing of cells flowing through a circuit can
//! statistically distinguish hidden-service traffic from regular browsing
//! traffic, fingerprint visited sites, and correlate bursts at entry +
//! exit to deanonymize users.
//!
//! Per-circuit padding addresses this by emitting **fake DROP cells**
//! into circuits according to a scheduler's policy. The receiving relay
//! recognizes the DROP marker and discards the cell — the padding only
//! affects on-wire traffic shape.
//!
//! ## Why a trait instead of a fixed scheduler
//!
//! Padding research is an active area. The simplest scheduler is
//! constant-rate: a cell every N ms. That works but is bandwidth-wasteful
//! and doesn't adapt to real traffic. More sophisticated schedulers like
//! WTF-PAD (Juarez et al. 2016) use Markov-chain models that adapt to
//! observed traffic patterns. Rather than commit to one scheme, we expose
//! a `PaddingScheduler` trait that any implementation can satisfy.
//!
//! Current implementations:
//!
//! - `NoPadding` — disables circuit padding entirely (useful for testing
//!   or low-threat deployments where the bandwidth cost isn't justified)
//! - `ConstantRate` — naive: emit one DROP cell every `interval`
//! - `AdaptiveBurst` — only emit padding when no real traffic has flowed
//!   for `idle_threshold`. Bandwidth-efficient; reasonable default.
//!
//! Future implementations a contributor could ship:
//!
//! - `WtfPad` — full WTF-PAD with Adaptive Padding and the
//!   "histogram-of-inter-packet-times" Markov model. Multi-week project;
//!   needs traffic-distribution data from a deployed network.
//! - `RegulaTor` — recent (2022) reactive padding with proven defense
//!   against website-fingerprinting attacks.
//! - `Maybenot` — Mike Perry's framework that lets a state machine
//!   describe arbitrary padding policies.
//!
//! ## How it integrates
//!
//! The circuit cell pump checks `should_pad_now()` periodically. When
//! the scheduler returns `Yes(deadline)`, a DROP cell is enqueued for
//! emission at that deadline. When real traffic flows, the scheduler is
//! notified via `on_real_cell()` so it can update its state.
//!
//! ## Threat model
//!
//! Padding makes traffic-shape attacks harder, not impossible. Against:
//!
//! - **Local observer at one hop**: padding works well — they see
//!   constant-rate or adaptive cells indistinguishable from real traffic.
//! - **Global passive adversary** (sees both ends of circuit): padding
//!   helps but doesn't fully eliminate correlation. Tor's research
//!   community has shown that even WTF-PAD has limits against
//!   sophisticated correlation attacks.
//! - **Active attacker who can drop/delay cells**: padding doesn't help
//!   — they can confirm timing by manipulation.
//!
//! Padding is one defensive layer. Combined with guard pinning, vanguards,
//! and traffic-mixing across many circuits, it raises the bar
//! considerably.

use std::time::{Duration, Instant};

/// Decision returned by `should_pad_now`. Tells the cell pump whether
/// to emit a DROP cell now, wait, or do nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PadDecision {
    /// Emit a padding cell immediately.
    Now,
    /// Don't pad now; check again after this duration. Used when the
    /// scheduler wants to be polled at a future time without committing
    /// to send a cell.
    SleepFor(Duration),
    /// No padding for this circuit at all (e.g. `NoPadding` impl).
    Never,
}

/// Padding scheduler interface. Implementations decide *when* a DROP
/// cell should be emitted based on whatever state and policy they want.
///
/// Implementations must be `Send + Sync` so the cell pump can access
/// them from multiple tokio tasks without external locking. Most impls
/// will use atomic state internally.
///
/// **Idempotency**: `should_pad_now()` may be called many times per
/// second; it should be cheap (no I/O). State updates happen via
/// `on_real_cell()` and `on_padding_cell()` callbacks.
pub trait PaddingScheduler: Send + Sync {
    /// Identifier for diagnostics. E.g. `"none"`, `"constant-1hz"`,
    /// `"adaptive-5s"`.
    fn name(&self) -> &str;

    /// Should a padding cell be emitted right now? Called repeatedly
    /// by the cell pump.
    fn should_pad_now(&self, now: Instant) -> PadDecision;

    /// Called whenever a real (non-padding) cell flows on this circuit
    /// in either direction. Lets the scheduler reset its idle timer
    /// or adjust its model.
    fn on_real_cell(&self, now: Instant);

    /// Called whenever a padding cell is sent. Lets the scheduler
    /// advance its state machine, increment counters, etc.
    fn on_padding_cell(&self, now: Instant);
}

// ── Implementations ──────────────────────────────────────────────────

/// Disables padding entirely. `should_pad_now` always returns
/// `Never`. Useful for tests, low-bandwidth links, or deployments
/// where the bandwidth cost of padding isn't justified.
pub struct NoPadding;

impl PaddingScheduler for NoPadding {
    fn name(&self) -> &str { "none" }
    fn should_pad_now(&self, _: Instant) -> PadDecision { PadDecision::Never }
    fn on_real_cell(&self, _: Instant) {}
    fn on_padding_cell(&self, _: Instant) {}
}

/// Naive constant-rate scheduler: emit one DROP cell every `interval`,
/// regardless of real traffic.
///
/// Pros: simplest possible defense, easy to reason about.
/// Cons: bandwidth-expensive, doesn't adapt, observable as "regular
/// padding" pattern (an attacker who knows the rate can subtract it).
pub struct ConstantRate {
    interval: Duration,
    last_padding: std::sync::Mutex<Instant>,
}

impl ConstantRate {
    pub fn new(interval: Duration) -> Self {
        Self { interval, last_padding: std::sync::Mutex::new(Instant::now()) }
    }
}

impl PaddingScheduler for ConstantRate {
    fn name(&self) -> &str { "constant-rate" }

    fn should_pad_now(&self, now: Instant) -> PadDecision {
        let last = *self.last_padding.lock().unwrap();
        let elapsed = now.duration_since(last);
        if elapsed >= self.interval {
            PadDecision::Now
        } else {
            PadDecision::SleepFor(self.interval - elapsed)
        }
    }

    fn on_real_cell(&self, _: Instant) {
        // Constant-rate ignores real traffic.
    }

    fn on_padding_cell(&self, now: Instant) {
        *self.last_padding.lock().unwrap() = now;
    }
}

/// Adaptive scheduler that only emits padding when the circuit has
/// been idle. Cheaper than constant-rate; matches how Tor's "circuit
/// keepalive" + "negotiate-padding" works at a high level.
///
/// Logic:
/// - Track timestamp of last *real* cell on this circuit.
/// - If real-cell-idle-time > `idle_threshold`, emit padding at
///   intervals of `padding_interval`.
/// - Once real traffic resumes, stop padding until idle again.
///
/// This means padding is most useful when a circuit is "alive but
/// quiet" (e.g. a hidden-service connection waiting for the other
/// side to send) — exactly when traffic-shape attacks gain the most
/// signal-to-noise.
pub struct AdaptiveBurst {
    idle_threshold:   Duration,
    padding_interval: Duration,
    state: std::sync::Mutex<AdaptiveBurstState>,
}

struct AdaptiveBurstState {
    last_real:    Instant,
    last_padding: Instant,
}

impl AdaptiveBurst {
    pub fn new(idle_threshold: Duration, padding_interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            idle_threshold,
            padding_interval,
            state: std::sync::Mutex::new(AdaptiveBurstState {
                last_real:    now,
                last_padding: now,
            }),
        }
    }
}

impl PaddingScheduler for AdaptiveBurst {
    fn name(&self) -> &str { "adaptive-burst" }

    fn should_pad_now(&self, now: Instant) -> PadDecision {
        let s = self.state.lock().unwrap();
        let real_idle = now.duration_since(s.last_real);

        // If there's been recent real traffic, don't pad — wait until
        // we've been idle for the threshold.
        if real_idle < self.idle_threshold {
            return PadDecision::SleepFor(self.idle_threshold - real_idle);
        }

        // We're in idle territory. Has it been long enough since our
        // last padding cell?
        let padding_idle = now.duration_since(s.last_padding);
        if padding_idle >= self.padding_interval {
            PadDecision::Now
        } else {
            PadDecision::SleepFor(self.padding_interval - padding_idle)
        }
    }

    fn on_real_cell(&self, now: Instant) {
        let mut s = self.state.lock().unwrap();
        s.last_real = now;
    }

    fn on_padding_cell(&self, now: Instant) {
        let mut s = self.state.lock().unwrap();
        s.last_padding = now;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_padding_never_emits() {
        let s = NoPadding;
        for _ in 0..10 {
            assert_eq!(s.should_pad_now(Instant::now()), PadDecision::Never);
        }
    }

    #[test]
    fn constant_rate_emits_at_interval() {
        let interval = Duration::from_millis(100);
        let s = ConstantRate::new(interval);
        let t0 = Instant::now();

        // Just after creation, no cell yet — should sleep
        let d = s.should_pad_now(t0);
        assert!(matches!(d, PadDecision::SleepFor(_)));

        // After interval has elapsed, should pad
        let t1 = t0 + interval + Duration::from_millis(1);
        // Set last_padding manually to simulate it never having fired
        *s.last_padding.lock().unwrap() = t0;
        assert_eq!(s.should_pad_now(t1), PadDecision::Now);

        // After we record the padding, should sleep again
        s.on_padding_cell(t1);
        assert!(matches!(s.should_pad_now(t1), PadDecision::SleepFor(_)));
    }

    #[test]
    fn constant_rate_ignores_real_cells() {
        // Real-cell notifications shouldn't reset its schedule.
        let s = ConstantRate::new(Duration::from_millis(100));
        let t0 = Instant::now();
        *s.last_padding.lock().unwrap() = t0;

        // Real cell flows
        s.on_real_cell(t0 + Duration::from_millis(50));

        // Should still want to pad after interval
        let t_later = t0 + Duration::from_millis(150);
        assert_eq!(s.should_pad_now(t_later), PadDecision::Now);
    }

    #[test]
    fn adaptive_burst_skips_padding_when_busy() {
        // Circuit with recent real traffic shouldn't emit padding.
        let s = AdaptiveBurst::new(
            Duration::from_secs(5),    // idle threshold
            Duration::from_secs(1),    // padding interval
        );
        let t0 = Instant::now();

        // Just sent a real cell
        s.on_real_cell(t0);

        // 1 sec later: still within idle threshold, must sleep
        let result = s.should_pad_now(t0 + Duration::from_secs(1));
        assert!(matches!(result, PadDecision::SleepFor(_)));
    }

    #[test]
    fn adaptive_burst_emits_when_idle() {
        let s = AdaptiveBurst::new(
            Duration::from_secs(5),
            Duration::from_secs(1),
        );
        let t0 = Instant::now();

        // Force a starting state where last_real is in the past.
        {
            let mut state = s.state.lock().unwrap();
            state.last_real = t0;
            state.last_padding = t0;
        }

        // 6 seconds later: past idle threshold AND past padding
        // interval since our last (synthetic) padding cell.
        let t_idle = t0 + Duration::from_secs(6);
        assert_eq!(s.should_pad_now(t_idle), PadDecision::Now);
    }

    #[test]
    fn adaptive_burst_resumes_quiet_after_real_traffic() {
        // After being idle and emitting padding, when real traffic
        // resumes, padding should pause.
        let s = AdaptiveBurst::new(
            Duration::from_secs(5),
            Duration::from_secs(1),
        );
        let t0 = Instant::now();
        {
            let mut state = s.state.lock().unwrap();
            state.last_real = t0;
            state.last_padding = t0;
        }

        // Padding should fire at t0 + 6s
        let t_idle = t0 + Duration::from_secs(6);
        assert_eq!(s.should_pad_now(t_idle), PadDecision::Now);
        s.on_padding_cell(t_idle);

        // Real traffic resumes
        let t_real = t_idle + Duration::from_millis(100);
        s.on_real_cell(t_real);

        // Now: not idle long enough, must sleep
        let result = s.should_pad_now(t_real + Duration::from_secs(1));
        assert!(matches!(result, PadDecision::SleepFor(_)));
    }

    #[test]
    fn schedulers_are_send_sync() {
        // Compile-time check: trait objects must work for cross-task use.
        fn check<T: Send + Sync>() {}
        check::<Box<dyn PaddingScheduler>>();
        check::<NoPadding>();
        check::<ConstantRate>();
        check::<AdaptiveBurst>();
    }

    #[test]
    fn name_distinguishes_implementations() {
        assert_eq!(NoPadding.name(), "none");
        assert_eq!(ConstantRate::new(Duration::from_secs(1)).name(), "constant-rate");
        assert_eq!(AdaptiveBurst::new(Duration::from_secs(1), Duration::from_secs(1)).name(),
                   "adaptive-burst");
    }
}
