// phinet-core/src/congestion.rs
//! Circuit congestion control (Tor Proposal 324, "cc_vegas").
//!
//! ## Why this exists
//!
//! The legacy circuit flow-control in [`crate::stream`] uses a *fixed*
//! window: `CIRCUIT_WINDOW_START` cells (1000), refilled a fixed
//! `CIRCUIT_SENDME_INC` (100) per SENDME, capped at 2×. That window
//! never adapts to the actual path. On a fast, uncongested path 1000
//! cells is far too little to keep the pipe full (throughput is capped
//! at `window / RTT`); on a slow or congested path it is too much, so
//! cells pile up in relay queues, inflating latency for *every* circuit
//! sharing those relays. This is exactly the problem Tor had before
//! 2023, and exactly what Proposal 324 fixed.
//!
//! ## What Prop 324 does
//!
//! Replace the fixed window with a **congestion window** (`cwnd`, in
//! cells) that adapts per-circuit from RTT measurements, using a
//! TCP-Vegas-style controller. The sender times each SENDME: the RTT
//! is the interval between emitting the DATA cell that *triggers* a
//! SENDME and receiving that SENDME back. From the RTT stream we
//! estimate how many cells are currently *queued* in the path:
//!
//! ```text
//!   BDP   = cwnd * RTT_min / RTT_current          (cells in flight that "fit")
//!   queue = cwnd - BDP = cwnd * (RTT - RTT_min) / RTT
//! ```
//!
//! Then, once per congestion-window update:
//!
//! ```text
//!   if queue < alpha:   cwnd += cc_cwnd_inc      (path underused → grow)
//!   if queue > beta:    cwnd -= cc_cwnd_inc      (queue building → shrink)
//!   else:               hold                     (in the sweet spot)
//! ```
//!
//! During **slow start** the window doubles each RTT until the first
//! congestion signal (`queue > gamma`), then it switches to the
//! steady-state additive rule above. This is the SS/AIMD structure of
//! TCP Vegas, which keeps only a small, bounded number of cells queued
//! in the network rather than letting the window grow until loss.
//!
//! ## Scope of this module
//!
//! This is the pure controller: feed it RTT samples and SENDME acks,
//! ask it whether it may send. It holds no timers and does no I/O, so
//! it is fully deterministic and unit-testable. Wiring it into
//! `circuit_mgr` (replacing `circ_send_window`) is the integration
//! step; see the module docs there. Constants mirror Tor's consensus
//! defaults (`cc_*` params) so behaviour matches a real Tor circuit.

use std::time::{Duration, Instant};

// ── Consensus-parameter defaults (Tor prop324 `cc_*`) ─────────────────

/// SENDME cadence: the receiver emits one SENDME per this many DATA
/// cells. Tor's `cc_sendme_inc` default. RTT is sampled once per
/// SENDME, so this also sets how often `cwnd` updates. Must match the
/// value the peer uses to authenticate SENDME cadence.
pub const CC_SENDME_INC: u32 = 31;

/// Absolute floor for `cwnd`, in cells. Tor's `cc_cwnd_min`. Below
/// this a circuit cannot make forward progress under RTT jitter.
pub const CC_CWND_MIN: u32 = 124;

/// Ceiling for `cwnd`, in cells. Tor's `cc_cwnd_max` default is very
/// large; we clamp to a sane per-circuit memory bound.
pub const CC_CWND_MAX: u32 = 20_000;

/// Initial `cwnd`, in cells. Tor's `cc_cwnd_init` (roughly 4× the
/// SENDME increment). Small enough not to burst a slow path on the
/// first RTT, large enough to get a usable RTT sample quickly.
pub const CC_CWND_INIT: u32 = 4 * CC_SENDME_INC;

/// Steady-state additive step for `cwnd`, in cells, per update. Tor's
/// `cc_cwnd_inc`.
pub const CC_CWND_INC: u32 = CC_SENDME_INC;

/// How many `cwnd`-updates share one additive step in steady state.
/// Tor's `cc_cwnd_inc_rate`: apply `CC_CWND_INC` once per this many
/// SENDME acks (1 = every ack). Keeps growth gentle on long paths.
pub const CC_CWND_INC_RATE: u32 = 1;

/// Vegas queue lower bound (`cc_vegas_alpha`), in cells. If the
/// estimated in-network queue is below this, the path is underused and
/// `cwnd` grows.
pub const CC_VEGAS_ALPHA: u32 = 3 * CC_SENDME_INC;

/// Vegas queue upper bound (`cc_vegas_beta`), in cells. Above this the
/// queue is building and `cwnd` shrinks.
pub const CC_VEGAS_BETA: u32 = 6 * CC_SENDME_INC;

/// Vegas slow-start exit threshold (`cc_vegas_gamma`), in cells. During
/// slow start, the first time the estimated queue exceeds this we exit
/// slow start into steady state.
pub const CC_VEGAS_GAMMA: u32 = 5 * CC_SENDME_INC;

/// Multiplicative back-off applied to `cwnd` when we exit slow start
/// (numerator/denominator). Tor drops to the Vegas estimate; we use a
/// conservative 3/4 to avoid an immediate second overshoot.
pub const CC_SS_BACKOFF_NUM: u32 = 3;
pub const CC_SS_BACKOFF_DEN: u32 = 4;

/// EWMA smoothing for the RTT estimate (numerator/denominator applied
/// to the *old* value; the new sample gets the remainder). 7/8 is the
/// classic TCP SRTT weight and matches Tor's RTT smoothing intent.
const RTT_EWMA_OLD_NUM: u32 = 7;
const RTT_EWMA_OLD_DEN: u32 = 8;

// ── Controller ────────────────────────────────────────────────────────

/// Per-circuit Vegas congestion controller.
///
/// One instance lives on the *originating* end of a circuit (the side
/// that sends DATA and receives SENDME acks). Relays that only forward
/// do not run a controller; they honour the cadence.
#[derive(Debug, Clone)]
pub struct Vegas {
    /// Congestion window, in cells. The sender may have at most `cwnd`
    /// cells in flight (sent but not yet SENDME-acked).
    cwnd: u32,
    /// Cells sent but not yet acked by a SENDME.
    inflight: u32,
    /// Whether we are still in slow start (exponential growth).
    slow_start: bool,
    /// Minimum RTT observed so far — our estimate of the path's
    /// propagation delay with an empty queue. Everything above this is
    /// treated as queueing delay.
    rtt_min: Option<Duration>,
    /// EWMA-smoothed current RTT.
    rtt_ewma: Option<Duration>,
    /// Send-time of the DATA cell that will trigger the next SENDME,
    /// i.e. the cell at index `next_sendme_at`. Set when that cell is
    /// sent; consumed when the SENDME arrives to compute the RTT.
    sendme_trigger_sent: Option<Instant>,
    /// Absolute count of cells sent on this circuit, used to know which
    /// send is the SENDME trigger (`total_sent % CC_SENDME_INC == 0`).
    total_sent: u64,
    /// Ack counter, for `CC_CWND_INC_RATE` pacing of the additive step.
    acks_since_inc: u32,
}

impl Default for Vegas {
    fn default() -> Self {
        Self::new()
    }
}

impl Vegas {
    /// Fresh controller at the initial window, in slow start.
    pub fn new() -> Self {
        Self {
            cwnd: CC_CWND_INIT,
            inflight: 0,
            slow_start: true,
            rtt_min: None,
            rtt_ewma: None,
            sendme_trigger_sent: None,
            total_sent: 0,
            acks_since_inc: 0,
        }
    }

    /// Current congestion window in cells.
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Cells currently in flight (sent, not yet acked).
    pub fn inflight(&self) -> u32 {
        self.inflight
    }

    /// True while the controller is still in exponential slow start.
    pub fn in_slow_start(&self) -> bool {
        self.slow_start
    }

    /// Whether a DATA cell may be sent right now: only if fewer than
    /// `cwnd` cells are in flight.
    pub fn can_send(&self) -> bool {
        self.inflight < self.cwnd
    }

    /// How many cells may be sent right now before hitting `cwnd`.
    pub fn send_allowance(&self) -> u32 {
        self.cwnd.saturating_sub(self.inflight)
    }

    /// Record that one DATA cell was sent at `now`. Increments inflight
    /// and, if this cell is a SENDME trigger (every `CC_SENDME_INC`th
    /// cell), remembers its send-time for the RTT sample.
    ///
    /// Callers should gate this on [`can_send`](Self::can_send); if
    /// called while the window is full it still records (so accounting
    /// stays correct) but that indicates a bug in the caller's pacing.
    pub fn on_send(&mut self, now: Instant) {
        self.inflight = self.inflight.saturating_add(1);
        self.total_sent += 1;
        // The cell whose 1-based index is a multiple of the increment is
        // the one the receiver will answer with a SENDME.
        if self.total_sent % CC_SENDME_INC as u64 == 0 {
            self.sendme_trigger_sent = Some(now);
        }
    }

    /// Record receipt of a circuit SENDME ack at `now`. Frees a window
    /// of `CC_SENDME_INC` in-flight cells, folds the RTT sample into the
    /// estimator, and runs one Vegas `cwnd` update.
    ///
    /// Returns the RTT sample if one was available for this ack.
    pub fn on_sendme(&mut self, now: Instant) -> Option<Duration> {
        // A SENDME acknowledges CC_SENDME_INC cells' worth of window.
        let acked = CC_SENDME_INC.min(self.inflight);
        self.inflight -= acked;

        let rtt = self.sendme_trigger_sent.take().map(|sent| {
            let sample = now.saturating_duration_since(sent);
            self.fold_rtt(sample);
            sample
        });

        // Only update the window when we actually have an RTT estimate;
        // without one we cannot estimate the queue.
        if self.rtt_ewma.is_some() {
            self.update_cwnd();
        }
        rtt
    }

    /// Fold a fresh RTT sample into `rtt_min` and the EWMA.
    fn fold_rtt(&mut self, sample: Duration) {
        self.rtt_min = Some(match self.rtt_min {
            Some(m) => m.min(sample),
            None => sample,
        });
        self.rtt_ewma = Some(match self.rtt_ewma {
            None => sample,
            Some(old) => {
                // ewma = old*7/8 + sample*1/8, in nanoseconds to avoid
                // Duration's lack of scalar mul/div ergonomics.
                let on = old.as_nanos() as u128;
                let sn = sample.as_nanos() as u128;
                let mixed = (on * RTT_EWMA_OLD_NUM as u128
                    + sn * (RTT_EWMA_OLD_DEN - RTT_EWMA_OLD_NUM) as u128)
                    / RTT_EWMA_OLD_DEN as u128;
                Duration::from_nanos(mixed as u64)
            }
        });
    }

    /// Estimated number of cells queued in the network right now:
    /// `queue = cwnd * (rtt - rtt_min) / rtt`. Zero if the current RTT
    /// is at the minimum (empty queue) or if we lack samples.
    pub fn queue_estimate(&self) -> u32 {
        let (Some(rtt), Some(min)) = (self.rtt_ewma, self.rtt_min) else {
            return 0;
        };
        let rtt_ns = rtt.as_nanos();
        if rtt_ns == 0 {
            return 0;
        }
        let excess = rtt.saturating_sub(min).as_nanos();
        // cwnd * excess / rtt, all in u128 to avoid overflow.
        let q = (self.cwnd as u128 * excess) / rtt_ns;
        q.min(u32::MAX as u128) as u32
    }

    /// One Vegas congestion-window update. Called once per SENDME ack
    /// after the RTT estimator has a value.
    fn update_cwnd(&mut self) {
        let queue = self.queue_estimate();

        if self.slow_start {
            if queue > CC_VEGAS_GAMMA {
                // Congestion detected during slow start: exit to steady
                // state and back the window off toward the estimate.
                self.slow_start = false;
                let backed = (self.cwnd as u64 * CC_SS_BACKOFF_NUM as u64
                    / CC_SS_BACKOFF_DEN as u64) as u32;
                self.set_cwnd(backed);
            } else {
                // Exponential growth: one full window per RTT. Each
                // SENDME acks CC_SENDME_INC cells, and there are
                // cwnd/CC_SENDME_INC SENDMEs per RTT, so adding
                // CC_SENDME_INC per SENDME doubles cwnd each RTT.
                self.set_cwnd(self.cwnd.saturating_add(CC_SENDME_INC));
            }
            return;
        }

        // Steady state (Vegas AIMD-ish additive control).
        self.acks_since_inc += 1;
        if queue < CC_VEGAS_ALPHA {
            // Underutilised: grow, paced by CC_CWND_INC_RATE.
            if self.acks_since_inc >= CC_CWND_INC_RATE {
                self.acks_since_inc = 0;
                self.set_cwnd(self.cwnd.saturating_add(CC_CWND_INC));
            }
        } else if queue > CC_VEGAS_BETA {
            // Queue building: shrink one step immediately.
            self.acks_since_inc = 0;
            self.set_cwnd(self.cwnd.saturating_sub(CC_CWND_INC));
        }
        // alpha <= queue <= beta: hold — the sweet spot.
    }

    /// Set `cwnd`, clamped to `[CC_CWND_MIN, CC_CWND_MAX]`.
    fn set_cwnd(&mut self, target: u32) {
        self.cwnd = target.clamp(CC_CWND_MIN, CC_CWND_MAX);
    }

    /// Smoothed RTT estimate, if any samples have arrived.
    pub fn rtt_ewma(&self) -> Option<Duration> {
        self.rtt_ewma
    }

    /// Minimum observed RTT (propagation-delay estimate), if any.
    pub fn rtt_min(&self) -> Option<Duration> {
        self.rtt_min
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Send `n` cells spaced `step` apart starting at `t0`, then deliver
    /// their SENDME acks with a path RTT of `rtt`. Returns the final
    /// controller. Models a steady path where every trigger cell sees
    /// the same round-trip.
    fn run_flow(v: &mut Vegas, t0: Instant, n: u32, step: Duration, rtt: Duration) {
        let mut send_times = Vec::new();
        let mut t = t0;
        for _ in 0..n {
            v.on_send(t);
            send_times.push(t);
            t += step;
        }
        // Ack every CC_SENDME_INCth cell at send_time + rtt.
        for i in (CC_SENDME_INC..=n).step_by(CC_SENDME_INC as usize) {
            let trigger_time = send_times[(i - 1) as usize];
            v.on_sendme(trigger_time + rtt);
        }
    }

    #[test]
    fn starts_in_slow_start_at_init_window() {
        let v = Vegas::new();
        assert_eq!(v.cwnd(), CC_CWND_INIT);
        assert!(v.in_slow_start());
        assert_eq!(v.inflight(), 0);
        assert!(v.can_send());
    }

    #[test]
    fn can_send_tracks_inflight_against_cwnd() {
        let mut v = Vegas::new();
        let t = Instant::now();
        for _ in 0..CC_CWND_INIT {
            assert!(v.can_send());
            v.on_send(t);
        }
        // Window now full.
        assert!(!v.can_send());
        assert_eq!(v.send_allowance(), 0);
        assert_eq!(v.inflight(), CC_CWND_INIT);
    }

    #[test]
    fn sendme_frees_a_window_of_inflight() {
        let mut v = Vegas::new();
        let t = Instant::now();
        for _ in 0..CC_SENDME_INC {
            v.on_send(t);
        }
        assert_eq!(v.inflight(), CC_SENDME_INC);
        v.on_sendme(t + Duration::from_millis(50));
        assert_eq!(v.inflight(), 0);
    }

    #[test]
    fn rtt_min_and_ewma_track_samples() {
        let mut v = Vegas::new();
        let t0 = Instant::now();
        // First trigger cell at index CC_SENDME_INC, acked 100ms later.
        for _ in 0..CC_SENDME_INC {
            v.on_send(t0);
        }
        v.on_sendme(t0 + Duration::from_millis(100));
        assert_eq!(v.rtt_min(), Some(Duration::from_millis(100)));
        assert_eq!(v.rtt_ewma(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn slow_start_grows_window_on_uncongested_path() {
        let mut v = Vegas::new();
        let t0 = Instant::now();
        let start = v.cwnd();
        // Constant low RTT and no queue → keep growing in slow start.
        run_flow(&mut v, t0, CC_SENDME_INC * 4, Duration::from_micros(10),
                 Duration::from_millis(20));
        assert!(v.cwnd() > start, "cwnd should grow: {} !> {}", v.cwnd(), start);
        assert!(v.in_slow_start(), "no congestion signal → still in slow start");
    }

    #[test]
    fn exits_slow_start_when_queue_exceeds_gamma() {
        let mut v = Vegas::new();
        let t0 = Instant::now();
        // Pump the window up first on a clean path.
        run_flow(&mut v, t0, CC_SENDME_INC * 8, Duration::from_micros(1),
                 Duration::from_millis(20));
        let big = v.cwnd();
        let t1 = t0 + Duration::from_secs(10);
        // Now RTT jumps far above the minimum → large queue estimate →
        // must trip the gamma threshold and leave slow start, backing off.
        run_flow(&mut v, t1, CC_SENDME_INC * 2, Duration::from_micros(1),
                 Duration::from_millis(400));
        assert!(!v.in_slow_start(), "high RTT should end slow start");
        assert!(v.cwnd() < big, "should back off on congestion: {} !< {}",
                v.cwnd(), big);
    }

    #[test]
    fn steady_state_shrinks_when_queue_over_beta() {
        let mut v = Vegas::new();
        // Force steady state with a known baseline RTT.
        let t0 = Instant::now();
        run_flow(&mut v, t0, CC_SENDME_INC, Duration::from_micros(1),
                 Duration::from_millis(20)); // establishes rtt_min = 20ms
        v.slow_start = false;
        v.cwnd = 2000;
        let before = v.cwnd();
        // Sustained high RTT (queue >> beta) → shrink.
        let t1 = t0 + Duration::from_secs(5);
        run_flow(&mut v, t1, CC_SENDME_INC * 3, Duration::from_micros(1),
                 Duration::from_millis(300));
        assert!(v.cwnd() < before, "queue>beta must shrink cwnd: {} !< {}",
                v.cwnd(), before);
    }

    #[test]
    fn steady_state_grows_when_queue_under_alpha() {
        let mut v = Vegas::new();
        let t0 = Instant::now();
        run_flow(&mut v, t0, CC_SENDME_INC, Duration::from_micros(1),
                 Duration::from_millis(50)); // rtt_min = 50ms
        v.slow_start = false;
        v.cwnd = 500;
        let before = v.cwnd();
        // RTT stays at the minimum → queue ~ 0 < alpha → grow.
        let t1 = t0 + Duration::from_secs(2);
        run_flow(&mut v, t1, CC_SENDME_INC * 3, Duration::from_micros(1),
                 Duration::from_millis(50));
        assert!(v.cwnd() > before, "queue<alpha must grow cwnd: {} !> {}",
                v.cwnd(), before);
    }

    #[test]
    fn cwnd_never_below_min_or_above_max() {
        let mut v = Vegas::new();
        v.set_cwnd(0);
        assert_eq!(v.cwnd(), CC_CWND_MIN);
        v.set_cwnd(u32::MAX);
        assert_eq!(v.cwnd(), CC_CWND_MAX);
    }

    #[test]
    fn queue_estimate_zero_at_min_rtt() {
        let mut v = Vegas::new();
        let t0 = Instant::now();
        run_flow(&mut v, t0, CC_SENDME_INC, Duration::from_micros(1),
                 Duration::from_millis(30));
        // Current EWMA == min == 30ms → no excess → zero queue.
        assert_eq!(v.queue_estimate(), 0);
    }

    #[test]
    fn queue_estimate_scales_with_excess_rtt() {
        let mut v = Vegas::new();
        v.cwnd = 1000;
        v.rtt_min = Some(Duration::from_millis(100));
        v.rtt_ewma = Some(Duration::from_millis(200));
        // queue = 1000 * (200-100)/200 = 500.
        assert_eq!(v.queue_estimate(), 500);
    }

    #[test]
    fn no_cwnd_update_before_first_rtt_sample() {
        let mut v = Vegas::new();
        let start = v.cwnd();
        // A SENDME with no prior trigger send (e.g. spurious) must not
        // move the window, since there is no RTT to reason about.
        v.on_sendme(Instant::now());
        assert_eq!(v.cwnd(), start);
    }

    #[test]
    fn total_throughput_bound_improves_over_fixed_window() {
        // Sanity: on a fat, low-latency path the adaptive window climbs
        // well past the legacy fixed CIRCUIT_WINDOW_START (1000), which
        // is the whole point — the fixed window caps throughput at
        // window/RTT regardless of available capacity.
        let mut v = Vegas::new();
        let t0 = Instant::now();
        run_flow(&mut v, t0, CC_SENDME_INC * 40, Duration::from_nanos(1),
                 Duration::from_millis(10));
        assert!(v.cwnd() > 1000,
                "adaptive cwnd {} should exceed legacy fixed window 1000",
                v.cwnd());
    }
}
