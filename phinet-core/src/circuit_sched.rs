//! # Circuit scheduling
//!
//! A relay carrying two circuits has to choose whose cell goes next. Right
//! now it doesn't choose: every circuit shares one queue and cells leave in
//! the order they arrived.
//!
//! First-in-first-out sounds fair, and is, in the sense that nobody is
//! skipped. But the circuits aren't alike. Someone downloading a large file
//! offers cells as fast as the link will take them; someone loading a page
//! offers a handful and then waits for the reply. In one queue, the download's
//! cells sit in front of the page's — not because they're more important, but
//! because there are more of them. The page waits behind a backlog it didn't
//! create, and the person watching it concludes the network is slow. The
//! download barely notices the millisecond it would have lost by yielding.
//!
//! So the choice isn't fairness against unfairness. It's which unfairness:
//! FIFO quietly prefers whoever is loudest.
//!
//! ## The heuristic
//!
//! Track how many cells each circuit has sent recently, and serve the
//! quietest first. A circuit that's been silent goes now; one that's been
//! flooding waits its turn. Bulk transfers pay a delay they can't perceive,
//! interactive traffic gets latency it very much can, and total throughput is
//! unchanged — the same cells go out, in a better order.
//!
//! "Recently" is doing the work. A plain total would let a circuit that was
//! busy an hour ago be penalised forever, and let one that has just started
//! flooding look innocent for a long time. So counts **decay**: each is
//! multiplied by a factor as time passes, and a circuit's score reflects the
//! recent past, weighted toward now. That's an exponentially weighted moving
//! average — one multiply per update, no history to store, which matters when
//! it runs per cell.
//!
//! This is Tor's `circuitmux_ewma`, for the same reasons.
//!
//! ## Why the half-life is a policy decision
//!
//! Too short and the average is noise: one burst and a circuit is condemned,
//! one quiet moment and a flooder is forgiven. Too long and it stops
//! describing the present — a circuit that finished its download minutes ago
//! is still being punished. The value below says "the last few seconds
//! matter, the last minute barely does", which matches how long a person will
//! wait for a page before deciding something is broken.
//!
//! ## What this cannot do
//!
//! Scheduling reorders cells within one relay's queue. It doesn't create
//! bandwidth, and it can't help a circuit whose bottleneck is elsewhere. It
//! also doesn't distinguish *kinds* of traffic — only volume. A downloader
//! who paced themselves would be treated as interactive, which is fine: the
//! only thing being asked is that a circuit which has taken a lot recently
//! yields to one that hasn't.
//!
//! ## Scheduling must happen before sealing
//!
//! A link session seals each frame with a monotonic nonce counter, so the
//! order frames are sealed in is the order the peer will try to open them in.
//! Seal a batch and then reorder it and the peer receives nonces running
//! backwards and drops every frame — the link goes quiet with no error worth
//! the name, because each frame is individually well-formed and simply
//! arrives at a moment the cipher isn't expecting.
//!
//! So queues hold *unsealed* messages, and the writer seals whatever the
//! scheduler hands it, at the moment it writes it. Seal order is then wire
//! order by construction, and there is no window in which the two can
//! disagree. Anything that seals earlier — batching, a cache, a "fast path"
//! that pre-frames — silently reintroduces this.
//!
//! ## Ordering within a circuit is not negotiable
//!
//! Cells on a circuit are a stream: reorder them and the far end decrypts
//! garbage. The scheduler chooses *which circuit* goes next and never
//! reorders a circuit's own cells.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long until a circuit's activity counts for half as much.
///
/// Ten seconds: long enough to see a sustained transfer rather than a blip,
/// short enough that a finished download stops being punished while the user
/// is still looking at the screen.
pub const HALF_LIFE: Duration = Duration::from_secs(10);

/// Below this, a score is indistinguishable from silence — drop the entry so
/// idle circuits don't accumulate forever.
const NEGLIGIBLE: f64 = 0.001;

/// Per-circuit activity, decayed.
#[derive(Debug, Default)]
pub struct EwmaScheduler {
    scores: HashMap<u32, f64>,
    last_decay: Option<Instant>,
}

impl EwmaScheduler {
    pub fn new() -> Self { Self::default() }

    /// Apply decay for the time that's passed.
    ///
    /// Done lazily rather than on a timer: a timer would either wake the
    /// process constantly or leave scores stale between ticks, and the maths
    /// is the same either way — decay is a function of elapsed time, so it
    /// can be computed whenever someone asks.
    fn decay(&mut self, now: Instant) {
        let last = match self.last_decay { Some(t) => t, None => { self.last_decay = Some(now); return; } };
        let dt = now.duration_since(last).as_secs_f64();
        if dt <= 0.0 { return; }
        self.last_decay = Some(now);

        // Halve every HALF_LIFE: factor = 2^(-dt/half_life).
        let factor = 0.5f64.powf(dt / HALF_LIFE.as_secs_f64());
        self.scores.retain(|_, v| { *v *= factor; *v > NEGLIGIBLE });
    }

    /// Record cells sent on a circuit.
    pub fn note_sent(&mut self, cid: u32, cells: u32, now: Instant) {
        self.decay(now);
        *self.scores.entry(cid).or_insert(0.0) += cells as f64;
    }

    /// A circuit's current score. Unknown circuits score zero — silence.
    pub fn score(&self, cid: u32) -> f64 {
        self.scores.get(&cid).copied().unwrap_or(0.0)
    }

    /// Pick which circuit to serve next: the quietest with something to send.
    ///
    /// Ties go to the lowest circuit id — arbitrary, but *stable*, which
    /// matters more: a tie-break that varies would reorder circuits for no
    /// reason and make behaviour hard to reason about.
    pub fn next(&mut self, ready: &[u32], now: Instant) -> Option<u32> {
        self.decay(now);
        ready.iter().copied().min_by(|a, b| {
            let sa = self.score(*a);
            let sb = self.score(*b);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal).then(a.cmp(b))
        })
    }

    /// Forget a circuit that's gone.
    pub fn forget(&mut self, cid: u32) { self.scores.remove(&cid); }

    pub fn tracked(&self) -> usize { self.scores.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> Instant {
        // A fixed origin so tests can move time deliberately.
        Instant::now() + Duration::from_secs(secs)
    }

    #[test]
    fn a_silent_circuit_goes_first() {
        // The entire point: the page load shouldn't queue behind the
        // download's backlog.
        let mut s = EwmaScheduler::new();
        let t = at(0);
        s.note_sent(1, 500, t);                       // bulk transfer
        assert_eq!(s.next(&[1, 2], t), Some(2));      // 2 has said nothing
    }

    #[test]
    fn the_quieter_of_two_busy_circuits_goes_first() {
        let mut s = EwmaScheduler::new();
        let t = at(0);
        s.note_sent(1, 500, t);
        s.note_sent(2, 10, t);
        assert_eq!(s.next(&[1, 2], t), Some(2));
    }

    #[test]
    fn a_finished_download_stops_being_punished() {
        // Without decay, one big transfer would condemn a circuit for the
        // rest of its life.
        let mut s = EwmaScheduler::new();
        s.note_sent(1, 1000, at(0));
        s.note_sent(2, 1, at(0));
        // A minute later — six half-lives — circuit 1 has been quiet.
        s.note_sent(2, 30, at(60));
        assert_eq!(s.next(&[1, 2], at(60)), Some(1),
                   "old activity must fade, or fairness is permanent punishment");
    }

    #[test]
    fn decay_halves_over_the_half_life() {
        let mut s = EwmaScheduler::new();
        s.note_sent(1, 100, at(0));
        let before = s.score(1);
        s.next(&[1], at(10));                          // forces decay
        let after = s.score(1);
        assert!((after - before / 2.0).abs() < 1.0,
                "expected ~{} got {}", before / 2.0, after);
    }

    #[test]
    fn a_flooder_cannot_hide_behind_one_quiet_moment() {
        // Too short a half-life would forgive instantly; check it doesn't.
        let mut s = EwmaScheduler::new();
        s.note_sent(1, 1000, at(0));
        s.note_sent(2, 5, at(0));
        assert_eq!(s.next(&[1, 2], at(1)), Some(2), "one second is not absolution");
    }

    #[test]
    fn ties_are_stable() {
        // Two idle circuits must not swap places on each call — churn for no
        // reason is just noise in something that should be predictable.
        let mut s = EwmaScheduler::new();
        let t = at(0);
        assert_eq!(s.next(&[7, 3], t), Some(3));
        assert_eq!(s.next(&[7, 3], t), Some(3));
    }

    #[test]
    fn only_ready_circuits_are_chosen() {
        // A circuit with nothing queued must never be selected, however quiet.
        let mut s = EwmaScheduler::new();
        let t = at(0);
        s.note_sent(1, 100, t);
        assert_eq!(s.next(&[1], t), Some(1), "the only option, even if busy");
        assert_eq!(s.next(&[], t), None);
    }

    #[test]
    fn idle_circuits_are_forgotten() {
        // The table must not grow for the life of the relay.
        let mut s = EwmaScheduler::new();
        s.note_sent(1, 10, at(0));
        assert_eq!(s.tracked(), 1);
        s.next(&[], at(600));   // ten minutes of silence
        assert_eq!(s.tracked(), 0, "a score of ~0 is just silence with a HashMap entry");
    }

    #[test]
    fn a_closed_circuit_is_dropped_immediately() {
        let mut s = EwmaScheduler::new();
        s.note_sent(1, 10, at(0));
        s.forget(1);
        assert_eq!(s.score(1), 0.0);
    }

    #[test]
    fn throughput_is_not_reduced_only_reordered() {
        // Scheduling must never drop a circuit from consideration entirely —
        // whoever is ready gets served, the question is only who first.
        let mut s = EwmaScheduler::new();
        let t = at(0);
        s.note_sent(1, 10_000, t);
        assert_eq!(s.next(&[1], t), Some(1),
                   "a busy circuit still gets served when it's the only one");
    }

    #[test]
    fn time_going_backwards_does_not_break_it() {
        // Instant is monotonic, but the arithmetic shouldn't depend on that.
        let mut s = EwmaScheduler::new();
        s.note_sent(1, 100, at(10));
        s.next(&[1], at(5));
        assert!(s.score(1) > 0.0);
    }
}
