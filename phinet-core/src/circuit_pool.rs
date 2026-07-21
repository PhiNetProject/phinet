//! # Preemptive circuit pool
//!
//! Building a circuit is three ntor handshakes across three relays, each a
//! round trip over the wider internet. It takes seconds — and until now ΦNET
//! did all of it *after* someone asked for a page, so every `.phinet` fetch
//! opened with a thirty-second stare at a spinner. The work isn't avoidable,
//! but the *waiting* is: circuits can be built before anyone wants one.
//!
//! So the node keeps a few clean circuits warm. A fetch takes one that's
//! already finished handshaking and gets on with the rendezvous, and the pool
//! quietly builds a replacement in the background.
//!
//! ## What can and can't be pre-built
//!
//! A rendezvous circuit is generic — any three relays will do, because the
//! rendezvous point is *our* choice. That makes it poolable.
//!
//! An introduction circuit is not: its last hop must be the intro point named
//! in the service's descriptor, which we don't know until someone names a
//! site. Tor solves this by pre-building three hops and extending by one when
//! the target appears; ΦNET builds a path in one shot, so that would need the
//! builder split in half. Worth doing later — half the wait is still half the
//! wait.
//!
//! ## Why a pooled circuit isn't a weaker circuit
//!
//! Pooled circuits are built exactly like on-demand ones: same weighted path
//! selection, same guard, same layer-2 vanguard substitution. The only
//! difference is *when*. A circuit that has never carried a stream is
//! indistinguishable from one built a moment ago, which is the whole reason
//! this optimisation is available.
//!
//! ## Freshness
//!
//! Circuits don't sit in the pool indefinitely. A path chosen ten minutes ago
//! reflects a consensus and a guard set that may have moved, and a circuit
//! held open forever is a long-lived correlation handle. Tor retires unused
//! circuits on a timer; so do we.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::circuit::{CircuitId, LinkSpec};

/// How many clean circuits to keep warm.
///
/// Two, not ten. Each one is an open circuit consuming relay state and padding
/// bandwidth whether or not it's ever used, and on a small network a greedy
/// pool would monopolise the very relays everyone else needs. Two covers a
/// fetch plus the next click.
pub const POOL_TARGET: usize = 2;

/// Retire a clean circuit after this long unused.
///
/// Ten minutes matches Tor's dirtiness window. Long enough that a browsing
/// session keeps hitting warm circuits, short enough that a pooled path can't
/// drift far from the current consensus.
pub const MAX_IDLE: Duration = Duration::from_secs(10 * 60);

/// Don't rebuild instantly after a failure.
///
/// If the network is down, or there aren't enough relays for a path, retrying
/// in a tight loop just burns CPU and floods the log with the same complaint.
pub const REBUILD_BACKOFF: Duration = Duration::from_secs(15);

/// A circuit that's built, handshaked, and has never carried a stream.
#[derive(Clone, Debug)]
pub struct PooledCircuit {
    pub cid: CircuitId,
    /// The full path, kept so a caller can reject a circuit whose terminal
    /// collides with the service it's about to visit.
    pub path: Vec<LinkSpec>,
    pub built_at: Instant,
}

impl PooledCircuit {
    pub fn terminal_hex(&self) -> Option<String> {
        self.path.last().map(|h| hex::encode(h.node_id))
    }

    pub fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.built_at) > MAX_IDLE
    }
}

/// The warm set. Cheap to clone-check, guarded by the node's own lock.
#[derive(Default)]
pub struct CircuitPool {
    ready: VecDeque<PooledCircuit>,
    /// Set when a build fails, so the maintenance loop waits before retrying.
    last_failure: Option<Instant>,
}

impl CircuitPool {
    pub fn new() -> Self { Self::default() }

    pub fn len(&self) -> usize { self.ready.len() }
    pub fn is_empty(&self) -> bool { self.ready.is_empty() }

    pub fn push(&mut self, c: PooledCircuit) { self.ready.push_back(c); }

    pub fn note_failure(&mut self, now: Instant) { self.last_failure = Some(now); }

    /// Whether the maintenance loop should try to build another circuit.
    pub fn wants_more(&self, now: Instant) -> bool {
        if let Some(t) = self.last_failure {
            if now.duration_since(t) < REBUILD_BACKOFF { return false; }
        }
        self.ready.len() < POOL_TARGET
    }

    /// Remove and return circuits that have gone stale, so the caller can
    /// tear them down. (Destroying needs async and the node; the pool only
    /// decides *which*.)
    pub fn drain_stale(&mut self, now: Instant) -> Vec<PooledCircuit> {
        let mut out = Vec::new();
        let mut keep = VecDeque::with_capacity(self.ready.len());
        while let Some(c) = self.ready.pop_front() {
            if c.is_stale(now) { out.push(c); } else { keep.push_back(c); }
        }
        self.ready = keep;
        out
    }

    /// Take a clean circuit whose terminal hop isn't `avoid_terminal_hex`.
    ///
    /// The exclusion exists because a rendezvous point on the service's own
    /// relay means rendezvousing with itself, which fails — and on a small
    /// network a random draw hits that often enough to matter.
    pub fn take(&mut self, now: Instant, avoid_terminal_hex: Option<&str>) -> Option<PooledCircuit> {
        let idx = self.ready.iter().position(|c| {
            if c.is_stale(now) { return false; }
            match (avoid_terminal_hex, c.terminal_hex()) {
                (Some(bad), Some(t)) => t != bad,
                _ => true,
            }
        })?;
        self.ready.remove(idx)
    }

    /// Every circuit, for teardown at shutdown.
    pub fn take_all(&mut self) -> Vec<PooledCircuit> {
        self.ready.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: u8) -> LinkSpec {
        LinkSpec {
            host: "10.0.0.1".into(), port: 7700,
            node_id: [id; 32], static_pub: [id; 32],
        }
    }

    fn circ(cid: u32, terminal: u8, age: Duration) -> PooledCircuit {
        PooledCircuit {
            cid: CircuitId(cid),
            path: vec![spec(1), spec(2), spec(terminal)],
            built_at: Instant::now() - age,
        }
    }

    #[test]
    fn takes_a_clean_circuit() {
        let mut p = CircuitPool::new();
        p.push(circ(1, 9, Duration::ZERO));
        assert!(p.take(Instant::now(), None).is_some());
        assert!(p.is_empty(), "taken circuits must leave the pool");
    }

    #[test]
    fn refuses_a_circuit_terminating_on_the_service() {
        let mut p = CircuitPool::new();
        p.push(circ(1, 9, Duration::ZERO));
        let hs = hex::encode([9u8; 32]);
        // A rendezvous point on the service's own relay can't work; the pool
        // must decline rather than hand back a circuit that will fail.
        assert!(p.take(Instant::now(), Some(&hs)).is_none());
        assert_eq!(p.len(), 1, "a declined circuit stays for another caller");
    }

    #[test]
    fn picks_a_usable_circuit_over_a_colliding_one() {
        let mut p = CircuitPool::new();
        p.push(circ(1, 9, Duration::ZERO));   // collides
        p.push(circ(2, 4, Duration::ZERO));   // fine
        let hs = hex::encode([9u8; 32]);
        let got = p.take(Instant::now(), Some(&hs)).expect("should find the usable one");
        assert_eq!(got.terminal_hex().unwrap(), hex::encode([4u8; 32]));
    }

    #[test]
    fn stale_circuits_are_not_handed_out() {
        let mut p = CircuitPool::new();
        p.push(circ(1, 9, MAX_IDLE + Duration::from_secs(1)));
        assert!(p.take(Instant::now(), None).is_none(),
                "a circuit past MAX_IDLE reflects a stale consensus");
    }

    #[test]
    fn drain_stale_returns_only_the_old() {
        let mut p = CircuitPool::new();
        p.push(circ(1, 9, MAX_IDLE + Duration::from_secs(1)));
        p.push(circ(2, 4, Duration::ZERO));
        let dead = p.drain_stale(Instant::now());
        assert_eq!(dead.len(), 1);
        assert_eq!(p.len(), 1, "fresh circuits survive the sweep");
    }

    #[test]
    fn wants_more_until_target() {
        let mut p = CircuitPool::new();
        let now = Instant::now();
        assert!(p.wants_more(now));
        for i in 0..POOL_TARGET { p.push(circ(i as u32, 4, Duration::ZERO)); }
        assert!(!p.wants_more(now), "a full pool shouldn't keep building");
    }

    #[test]
    fn backoff_pauses_rebuilding_after_a_failure() {
        let mut p = CircuitPool::new();
        let now = Instant::now();
        p.note_failure(now);
        assert!(!p.wants_more(now), "must not retry instantly");
        assert!(p.wants_more(now + REBUILD_BACKOFF + Duration::from_secs(1)),
                "but must resume once the backoff expires");
    }
}
