//! # Denial-of-service mitigation
//!
//! Every expensive thing a relay does, it does because a stranger asked. A
//! CREATE cell costs an ntor handshake — real CPU, on a curve, before the
//! sender has proved anything at all. A connection costs a socket and a task.
//! None of it requires an account, a payment, or a reputation, because
//! requiring any of those would defeat the point of the network.
//!
//! That's a fine trade right up until someone opens circuits in a loop. Then
//! the same openness that lets an anonymous stranger use the network lets an
//! anonymous stranger exhaust it, and a relay dies not from a clever attack
//! but from arithmetic.
//!
//! So: track what each client address is costing us, and start refusing when
//! it stops looking like use and starts looking like a flood.
//!
//! ## Why this is per-address, and why that's imperfect
//!
//! Address is a weak identity. An attacker with a /24 gets 256 buckets, and
//! clients behind one NAT share a bucket and can starve each other. Both are
//! real, and neither is fixable here — an anonymity network can't ask who you
//! are before deciding whether to serve you. The point isn't to stop a
//! determined adversary; it's to make the cheap version of the attack cost
//! more than a shell loop, and to keep one broken client from taking the
//! relay down for everyone else.
//!
//! Tor's `dos.c` makes the same bargain for the same reasons.
//!
//! ## Relays are exempt
//!
//! A relay in the consensus builds circuits through us constantly — that's
//! its job, and it's the traffic the network is made of. Rate-limiting our
//! own peers would be self-inflicted: the network's normal operation would
//! look exactly like the attack. Exemption is keyed on consensus membership,
//! which an attacker can't grant themselves.
//!
//! ## Refusing is not free either
//!
//! A refusal must cost us less than the work it prevents, or the defence is
//! the attack. So the check is a hash lookup and two integer comparisons
//! before any crypto happens — never after.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Circuits one address may create per minute before we start refusing.
///
/// A browsing client builds a handful: a few for the pool, a couple per
/// hidden-service fetch. Sixty a minute is an order of magnitude above real
/// use and still trivially under what a loop achieves.
pub const MAX_CIRCUITS_PER_MIN: u32 = 60;

/// Allow a short burst above the sustained rate.
///
/// Opening an app legitimately creates several circuits at once. A limiter
/// with no burst punishes exactly the moment a real user is most likely to
/// notice.
pub const CIRCUIT_BURST: u32 = 20;

/// Concurrent connections from one address.
///
/// Sockets and read tasks are the cheap-to-request, expensive-to-hold
/// resource. One address holding hundreds open isn't using the network.
pub const MAX_CONNS_PER_IP: u32 = 12;

/// Window over which the circuit rate is measured.
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Forget an address after this long idle, so the table doesn't grow forever
/// — a table that grows without bound is itself a DoS.
const STALE_AFTER: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone)]
struct ClientStats {
    /// Tokens available for circuit creation, refilled over time.
    tokens: f64,
    last_refill: Instant,
    conns: u32,
    last_seen: Instant,
    /// Total refusals — for logging, so an operator can tell "under attack"
    /// from "misconfigured".
    refused: u64,
}

impl ClientStats {
    fn new(now: Instant) -> Self {
        Self {
            tokens: (MAX_CIRCUITS_PER_MIN + CIRCUIT_BURST) as f64,
            last_refill: now,
            conns: 0,
            last_seen: now,
            refused: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let per_sec = MAX_CIRCUITS_PER_MIN as f64 / RATE_WINDOW.as_secs_f64();
        let ceiling = (MAX_CIRCUITS_PER_MIN + CIRCUIT_BURST) as f64;
        self.tokens = (self.tokens + elapsed * per_sec).min(ceiling);
        self.last_refill = now;
    }
}

/// Per-address accounting for circuit creation and connections.
#[derive(Debug, Default)]
pub struct DosGuard {
    clients: HashMap<IpAddr, ClientStats>,
    /// Addresses that are relays in the consensus, and so exempt.
    exempt: Vec<IpAddr>,
    enabled: bool,
}

impl DosGuard {
    /// Disabled by default: a limiter that switches itself on before the
    /// operator has decided anything is a good way to break a testnet.
    pub fn new() -> Self { Self::default() }

    pub fn set_enabled(&mut self, on: bool) { self.enabled = on; }
    pub fn is_enabled(&self) -> bool { self.enabled }

    /// Tell the guard which addresses belong to consensus relays.
    ///
    /// Refreshed from the consensus, so a new relay joining stops being
    /// rate-limited without a restart.
    pub fn set_exempt(&mut self, addrs: Vec<IpAddr>) { self.exempt = addrs; }

    fn is_exempt(&self, ip: &IpAddr) -> bool {
        // Loopback is us — the local client, the CLI, the tests.
        ip.is_loopback() || self.exempt.contains(ip)
    }

    /// May this address create a circuit right now?
    ///
    /// Call *before* the handshake, not after: the whole point is to refuse
    /// before spending the CPU that makes the flood worth sending.
    pub fn allow_circuit(&mut self, ip: IpAddr) -> bool {
        if !self.enabled || self.is_exempt(&ip) { return true; }
        let now = Instant::now();
        let st = self.clients.entry(ip).or_insert_with(|| ClientStats::new(now));
        st.last_seen = now;
        st.refill(now);
        if st.tokens >= 1.0 {
            st.tokens -= 1.0;
            true
        } else {
            st.refused += 1;
            false
        }
    }

    /// May this address open another connection?
    pub fn allow_connection(&mut self, ip: IpAddr) -> bool {
        if !self.enabled || self.is_exempt(&ip) { return true; }
        let now = Instant::now();
        let st = self.clients.entry(ip).or_insert_with(|| ClientStats::new(now));
        st.last_seen = now;
        if st.conns >= MAX_CONNS_PER_IP {
            st.refused += 1;
            return false;
        }
        st.conns += 1;
        true
    }

    /// A connection closed. Must be called or the limit leaks and eventually
    /// locks out an honest client permanently.
    pub fn release_connection(&mut self, ip: IpAddr) {
        if let Some(st) = self.clients.get_mut(&ip) {
            st.conns = st.conns.saturating_sub(1);
            st.last_seen = Instant::now();
        }
    }

    /// How many times we've refused this address.
    pub fn refused_count(&self, ip: &IpAddr) -> u64 {
        self.clients.get(ip).map(|s| s.refused).unwrap_or(0)
    }

    /// Addresses we're currently refusing, for the operator's log.
    pub fn offenders(&self) -> Vec<(IpAddr, u64)> {
        let mut v: Vec<(IpAddr, u64)> = self.clients.iter()
            .filter(|(_, s)| s.refused > 0)
            .map(|(ip, s)| (*ip, s.refused))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    /// Drop idle entries. The table is itself an attack surface: an attacker
    /// spraying from a large address range shouldn't be able to grow it
    /// without limit.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.clients.retain(|_, s| {
            s.conns > 0 || now.duration_since(s.last_seen) < STALE_AFTER
        });
    }

    pub fn tracked(&self) -> usize { self.clients.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(203, 0, 113, n)) }

    fn on() -> DosGuard {
        let mut g = DosGuard::new();
        g.set_enabled(true);
        g
    }

    #[test]
    fn disabled_by_default_allows_everything() {
        // An operator who hasn't opted in must not discover the limiter by
        // having their testnet fall over.
        let mut g = DosGuard::new();
        for _ in 0..10_000 { assert!(g.allow_circuit(ip(1))); }
    }

    #[test]
    fn ordinary_use_is_never_refused() {
        let mut g = on();
        // A browsing session: a pool top-up and a few fetches.
        for _ in 0..12 { assert!(g.allow_circuit(ip(1)), "real use must not trip the limit"); }
    }

    #[test]
    fn a_flood_is_refused() {
        let mut g = on();
        let mut allowed = 0;
        for _ in 0..500 { if g.allow_circuit(ip(1)) { allowed += 1; } }
        assert!(allowed <= (MAX_CIRCUITS_PER_MIN + CIRCUIT_BURST) as usize,
                "a loop got {allowed} circuits through");
        assert!(g.refused_count(&ip(1)) > 0);
    }

    #[test]
    fn a_burst_is_tolerated_before_the_limit_bites() {
        let mut g = on();
        // Opening the app builds several at once; that's not an attack.
        for i in 0..CIRCUIT_BURST { assert!(g.allow_circuit(ip(1)), "refused at burst {i}"); }
    }

    #[test]
    fn one_attacker_does_not_lock_out_everyone_else() {
        let mut g = on();
        for _ in 0..500 { g.allow_circuit(ip(1)); }        // flooder
        assert!(g.allow_circuit(ip(2)), "an unrelated client must still be served");
    }

    #[test]
    fn relays_are_exempt_because_their_job_looks_like_the_attack() {
        let mut g = on();
        g.set_exempt(vec![ip(9)]);
        for _ in 0..1000 { assert!(g.allow_circuit(ip(9)), "a consensus relay must never be limited"); }
    }

    #[test]
    fn loopback_is_exempt() {
        let mut g = on();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..1000 { assert!(g.allow_circuit(lo), "our own client must not be limited"); }
    }

    #[test]
    fn connection_limit_holds_and_releases() {
        let mut g = on();
        for _ in 0..MAX_CONNS_PER_IP { assert!(g.allow_connection(ip(1))); }
        assert!(!g.allow_connection(ip(1)), "past the cap it must refuse");
        g.release_connection(ip(1));
        assert!(g.allow_connection(ip(1)), "a closed connection must free a slot");
    }

    #[test]
    fn releasing_more_than_opened_does_not_underflow() {
        let mut g = on();
        g.allow_connection(ip(1));
        for _ in 0..10 { g.release_connection(ip(1)); }
        for _ in 0..MAX_CONNS_PER_IP { assert!(g.allow_connection(ip(1))); }
    }

    #[test]
    fn tokens_refill_over_time() {
        let mut g = on();
        for _ in 0..500 { g.allow_circuit(ip(1)); }
        assert!(!g.allow_circuit(ip(1)));
        // Rewind the clock rather than sleep a minute in a unit test.
        if let Some(st) = g.clients.get_mut(&ip(1)) {
            st.last_refill = Instant::now() - Duration::from_secs(60);
        }
        assert!(g.allow_circuit(ip(1)),
                "a client refused a minute ago must be served again");
    }

    #[test]
    fn the_tracking_table_cannot_grow_forever() {
        let mut g = on();
        for n in 0..200 { g.allow_circuit(ip(n as u8)); }
        assert!(g.tracked() > 0);
        for (_, st) in g.clients.iter_mut() {
            st.last_seen = Instant::now() - Duration::from_secs(11 * 60);
        }
        g.cleanup();
        assert_eq!(g.tracked(), 0, "idle entries must be forgotten");
    }

    #[test]
    fn open_connections_survive_cleanup() {
        let mut g = on();
        g.allow_connection(ip(1));
        if let Some(st) = g.clients.get_mut(&ip(1)) {
            st.last_seen = Instant::now() - Duration::from_secs(11 * 60);
        }
        g.cleanup();
        assert_eq!(g.tracked(), 1, "forgetting a live connection would leak its slot");
    }
}
