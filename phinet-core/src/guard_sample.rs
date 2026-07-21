//! # The sampled guard set
//!
//! Guards work by being few. Only your guard learns that *you* are the one
//! sending traffic, so the fewer relays ever hold that position, the fewer
//! chances an adversary has to be one of them. Pick three and keep them for
//! months and an attacker running 1% of the network has roughly a 3% shot,
//! once.
//!
//! The attack is on "once". If a client replaces a guard whenever one looks
//! unreachable, the adversary doesn't need to win the lottery — they need the
//! client to keep buying tickets. Knock your guards offline, or just wait for
//! ordinary churn, and each replacement is a fresh draw. Over a year the
//! client has tried dozens of guards, each of which learned its address, and
//! the probability that *none* of them was hostile drops toward zero. The
//! defence quietly inverts into a way of introducing the client to the whole
//! network.
//!
//! ΦNET has the persistence half — guards are kept for months. What it lacks
//! is a bound on how many distinct guards it will *ever* try:
//! `maintain_guards_from_consensus` offers every relay in the consensus as a
//! candidate, and whenever a slot frees, the next relay fills it. There's no
//! limit on total draws over a client's lifetime, and the "random" choice is
//! consensus order.
//!
//! The fix (Tor's proposal 271) is to decide *once* which guards you are ever
//! willing to use: draw a bounded random sample from the network, persist it,
//! and never use a guard outside it. Churn then reshuffles which sampled
//! guard you're on, not which guards exist for you. An adversary who knocks
//! out your guards achieves a rotation within a set they can't influence,
//! and the total number of relays that ever learn your address stays bounded
//! for the life of the client.
//!
//! ## The three sets
//!
//! - **Sampled** — the bounded draw. Membership is decided once and expires
//!   only with age. This is the set that matters for the security property.
//! - **Filtered** — sampled guards currently usable: still in the consensus,
//!   still running. A guard that vanishes for a week stays *sampled*, so its
//!   return doesn't cost a new draw.
//! - **Confirmed** — guards through which a circuit actually completed, in
//!   the order they first did. Order matters: preferring the
//!   longest-standing working guard means a temporary outage doesn't
//!   permanently promote whoever happened to be up during it.
//!
//! **Primary** guards are the first few of confirmed-then-filtered, and are
//! what actually gets used.
//!
//! ## Why sampling can't be topped up eagerly
//!
//! It's tempting to keep the sample full: if it drops to 18 of 20, add two.
//! But that hands an adversary the same lever in a different shape — remove
//! sampled guards from the consensus (or make them look down) and the client
//! obligingly draws replacements, which is the churn attack again. So the
//! sample is only topped up when it's genuinely too small to work with, and
//! entries leave on age, not on being temporarily unavailable.

use serde::{Deserialize, Serialize};

/// How many guards a client is ever willing to consider.
///
/// Large enough to survive years of churn without a redraw; small enough that
/// the set is a meaningful bound. Tor uses a similar figure.
pub const SAMPLE_SIZE: usize = 20;

/// Only top up if the usable sample falls below this.
///
/// The gap between this and `SAMPLE_SIZE` is deliberate: it's the slack that
/// stops an adversary from triggering a redraw by making a few sampled guards
/// look unavailable.
pub const MIN_FILTERED: usize = 5;

/// How long a sampled entry stays in the set.
pub const SAMPLE_LIFETIME_SECS: u64 = 120 * 24 * 3600;

/// How many guards to actually use.
pub const PRIMARY_COUNT: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SampledGuard {
    pub node_id_hex: String,
    /// When this entry joined the sample.
    pub added: u64,
    /// When a circuit first completed through it, if ever. Doubles as the
    /// confirmation order.
    #[serde(default)]
    pub confirmed_at: Option<u64>,
}

impl SampledGuard {
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.added) > SAMPLE_LIFETIME_SECS
    }
    pub fn is_confirmed(&self) -> bool { self.confirmed_at.is_some() }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SampledSet {
    pub guards: Vec<SampledGuard>,
}

impl SampledSet {
    pub fn new() -> Self { Self::default() }

    pub fn len(&self) -> usize { self.guards.len() }
    pub fn is_empty(&self) -> bool { self.guards.is_empty() }

    pub fn contains(&self, node_id_hex: &str) -> bool {
        self.guards.iter().any(|g| g.node_id_hex == node_id_hex)
    }

    /// Drop entries that have aged out.
    pub fn expire(&mut self, now: u64) {
        self.guards.retain(|g| !g.is_expired(now));
    }

    /// Sampled guards that are currently usable.
    pub fn filtered(&self, live: &[String]) -> Vec<&SampledGuard> {
        self.guards.iter().filter(|g| live.contains(&g.node_id_hex)).collect()
    }

    /// Top up the sample — but only if it's genuinely too thin.
    ///
    /// `candidates` is every relay currently eligible to be a guard. Returns
    /// how many were added.
    ///
    /// The `MIN_FILTERED` check is the security-relevant part: without it,
    /// an adversary who can make sampled guards look unavailable can force
    /// fresh draws at will, which is the attack the sample exists to stop.
    pub fn maybe_extend<R: rand::Rng>(
        &mut self,
        rng: &mut R,
        candidates: &[String],
        live: &[String],
        now: u64,
    ) -> usize {
        self.expire(now);
        if self.filtered(live).len() >= MIN_FILTERED && !self.guards.is_empty() {
            return 0;
        }
        let mut pool: Vec<&String> = candidates.iter()
            .filter(|c| !self.contains(c))
            .collect();
        if pool.is_empty() { return 0; }

        // Uniform, not consensus order. Order-based selection means every
        // client with the same consensus picks the same guards, which
        // concentrates the network on whoever sorts first and makes one relay
        // worth attacking.
        use rand::seq::SliceRandom;
        pool.shuffle(rng);

        let want = SAMPLE_SIZE.saturating_sub(self.guards.len());
        let mut added = 0;
        for c in pool.into_iter().take(want) {
            self.guards.push(SampledGuard {
                node_id_hex: c.clone(), added: now, confirmed_at: None,
            });
            added += 1;
        }
        added
    }

    /// Record that a circuit completed through this guard.
    ///
    /// Only the first success sets the timestamp — it's the confirmation
    /// *order* that's wanted, and re-stamping on every success would reorder
    /// the list by recent activity, which is not the same thing.
    pub fn confirm(&mut self, node_id_hex: &str, now: u64) {
        if let Some(g) = self.guards.iter_mut().find(|g| g.node_id_hex == node_id_hex) {
            if g.confirmed_at.is_none() { g.confirmed_at = Some(now); }
        }
    }

    /// The guards to actually use, best first.
    ///
    /// Confirmed guards come first in the order they were confirmed, then
    /// unconfirmed sampled guards. A guard that has worked for months should
    /// not lose its place to one that happened to be reachable this morning.
    pub fn primary(&self, live: &[String]) -> Vec<String> {
        let mut confirmed: Vec<&SampledGuard> = self.filtered(live).into_iter()
            .filter(|g| g.is_confirmed())
            .collect();
        confirmed.sort_by_key(|g| g.confirmed_at.unwrap_or(u64::MAX));

        let unconfirmed: Vec<&SampledGuard> = self.filtered(live).into_iter()
            .filter(|g| !g.is_confirmed())
            .collect();

        confirmed.into_iter().chain(unconfirmed)
            .map(|g| g.node_id_hex.clone())
            .take(PRIMARY_COUNT)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn ids(n: usize) -> Vec<String> { (0..n).map(|i| format!("{i:064x}")).collect() }

    fn rng() -> StdRng { StdRng::seed_from_u64(42) }

    #[test]
    fn the_sample_is_bounded() {
        // The whole security property: however big the network, a client is
        // only ever willing to try this many guards.
        let mut s = SampledSet::new();
        let all = ids(500);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        assert_eq!(s.len(), SAMPLE_SIZE);
    }

    #[test]
    fn a_healthy_sample_is_not_topped_up() {
        // Eager top-up would recreate the churn attack: make guards look
        // down, get fresh draws.
        let mut s = SampledSet::new();
        let all = ids(100);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let added = s.maybe_extend(&mut rng(), &all, &all, 0);
        assert_eq!(added, 0);
        assert_eq!(s.len(), SAMPLE_SIZE);
    }

    #[test]
    fn losing_a_few_guards_does_not_trigger_a_redraw() {
        // The attack: knock out sampled guards, watch the client draw new
        // ones, repeat until it draws yours.
        let mut s = SampledSet::new();
        let all = ids(100);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let before = s.len();

        // Attacker takes down all but 6 of the sampled guards.
        let live: Vec<String> = s.guards.iter().take(6).map(|g| g.node_id_hex.clone()).collect();
        let added = s.maybe_extend(&mut rng(), &all, &live, 100);
        assert_eq!(added, 0, "6 usable guards is enough; drawing more is the attack");
        assert_eq!(s.len(), before);
    }

    #[test]
    fn a_gutted_sample_is_topped_up() {
        // But a client with two usable guards has to do something.
        let mut s = SampledSet::new();
        let all = ids(100);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let live: Vec<String> = s.guards.iter().take(2).map(|g| g.node_id_hex.clone()).collect();
        // Sample is at SAMPLE_SIZE so nothing can be added — expire most of
        // it first, as a year of ageing would.
        s.guards.truncate(3);
        let added = s.maybe_extend(&mut rng(), &all, &live, 100);
        assert!(added > 0, "a client with 2 usable guards must be able to continue");
    }

    #[test]
    fn a_guard_that_vanishes_temporarily_stays_sampled() {
        // Otherwise its return costs a fresh draw, which is the churn attack
        // with extra steps.
        let mut s = SampledSet::new();
        let all = ids(100);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let gone = s.guards[0].node_id_hex.clone();
        let live: Vec<String> = all.iter().filter(|x| **x != gone).cloned().collect();
        s.maybe_extend(&mut rng(), &all, &live, 100);
        assert!(s.contains(&gone), "a guard down for an hour hasn't stopped being ours");
    }

    #[test]
    fn entries_expire_with_age() {
        let mut s = SampledSet::new();
        let all = ids(50);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        s.expire(SAMPLE_LIFETIME_SECS + 1);
        assert!(s.is_empty());
    }

    #[test]
    fn selection_is_not_consensus_order() {
        // Order-based picking makes every client choose the same guards, and
        // that relay becomes worth attacking.
        let all = ids(200);
        let mut a = SampledSet::new();
        let mut b = SampledSet::new();
        a.maybe_extend(&mut StdRng::seed_from_u64(1), &all, &all, 0);
        b.maybe_extend(&mut StdRng::seed_from_u64(2), &all, &all, 0);
        let av: Vec<&str> = a.guards.iter().map(|g| g.node_id_hex.as_str()).collect();
        let bv: Vec<&str> = b.guards.iter().map(|g| g.node_id_hex.as_str()).collect();
        assert_ne!(av, bv, "two clients drew identical samples — that isn't random");
    }

    #[test]
    fn primary_prefers_guards_that_have_actually_worked() {
        let mut s = SampledSet::new();
        let all = ids(50);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let worked = s.guards[7].node_id_hex.clone();
        s.confirm(&worked, 500);
        assert_eq!(s.primary(&all)[0], worked);
    }

    #[test]
    fn confirmation_order_is_stable() {
        // A guard that has served for months shouldn't be demoted by one that
        // happened to be up this morning.
        let mut s = SampledSet::new();
        let all = ids(50);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let old = s.guards[1].node_id_hex.clone();
        let new = s.guards[2].node_id_hex.clone();
        s.confirm(&old, 100);
        s.confirm(&new, 900);
        let p = s.primary(&all);
        assert_eq!(p[0], old);
        assert_eq!(p[1], new);
    }

    #[test]
    fn re_confirming_does_not_reorder() {
        let mut s = SampledSet::new();
        let all = ids(50);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let a = s.guards[1].node_id_hex.clone();
        let b = s.guards[2].node_id_hex.clone();
        s.confirm(&a, 100);
        s.confirm(&b, 200);
        s.confirm(&a, 9999);   // busy today
        assert_eq!(s.primary(&all)[0], a, "recent activity is not seniority");
    }

    #[test]
    fn primary_skips_guards_that_are_down() {
        let mut s = SampledSet::new();
        let all = ids(50);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        let down = s.guards[0].node_id_hex.clone();
        s.confirm(&down, 100);
        let live: Vec<String> = all.iter().filter(|x| **x != down).cloned().collect();
        assert!(!s.primary(&live).contains(&down));
    }

    #[test]
    fn primary_is_bounded() {
        let mut s = SampledSet::new();
        let all = ids(50);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        assert_eq!(s.primary(&all).len(), PRIMARY_COUNT);
    }

    #[test]
    fn a_tiny_network_still_yields_guards() {
        // Three relays: everything must still work, just without much choice.
        let mut s = SampledSet::new();
        let all = ids(3);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        assert_eq!(s.len(), 3);
        assert_eq!(s.primary(&all).len(), 3);
    }

    #[test]
    fn no_candidates_is_not_a_panic() {
        let mut s = SampledSet::new();
        assert_eq!(s.maybe_extend(&mut rng(), &[], &[], 0), 0);
        assert!(s.primary(&[]).is_empty());
    }

    #[test]
    fn survives_a_round_trip_to_disk() {
        // The set is only a bound if it outlives the process.
        let mut s = SampledSet::new();
        let all = ids(30);
        s.maybe_extend(&mut rng(), &all, &all, 0);
        s.confirm(&s.guards[0].node_id_hex.clone(), 5);
        let j = serde_json::to_string(&s).unwrap();
        let back: SampledSet = serde_json::from_str(&j).unwrap();
        assert_eq!(back.len(), s.len());
        assert_eq!(back.primary(&all), s.primary(&all));
    }
}
