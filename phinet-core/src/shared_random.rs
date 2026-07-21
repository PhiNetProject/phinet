//! # Shared randomness
//!
//! Blinding stops a directory from reading what it holds. It doesn't stop an
//! attacker from *choosing* what it holds.
//!
//! Ring positions come from hashing node ids and service keys with the
//! period. Every input is public and every future period is computable today,
//! so an attacker can work offline: pick a service worth watching, compute
//! where it will land next week, then grind node ids until one lands beside
//! it. Come the period rollover they're a directory for that service,
//! perfectly placed, having spent nothing but CPU. Do it with a handful of
//! relays and they hold every replica — and can make the service
//! unreachable, or watch everyone who asks for it.
//!
//! The defence is to make next period's ring unknowable until it arrives:
//! mix in a value nobody can predict and no single party controls. Then
//! grinding can't start early, and by the time the value is known the
//! positions are already fixed.
//!
//! ## Why "nobody can predict" isn't enough on its own
//!
//! The obvious version — every authority sends a random number, hash them
//! together — has a hole. Whoever contributes last sees the others' values
//! and can try many of their own, choosing the one that lands the ring
//! favourably. A single value that unpredictable-in-general is still
//! chooseable by the last participant is not shared randomness; it's the last
//! authority's randomness.
//!
//! So it's commit-then-reveal. Every authority first publishes a *commitment*
//! — a hash of its value — and only once all commitments are in does anyone
//! reveal. By then it's too late to change your mind: your commitment already
//! names your value, and any other value fails to match its hash. The last
//! revealer learns everything and can influence nothing.
//!
//! This is Tor's design (proposal 250) and it exists for exactly this reason.
//!
//! ## What it costs
//!
//! An authority that commits and then refuses to reveal is annoying: it can
//! withhold, see the outcome, and decide. Withholding still influences the
//! result by removing a contribution. The mitigation is that it's *visible* —
//! a missing reveal is an accusation with a name on it — and that the value
//! stays usable with the remaining reveals. An adversary who controls enough
//! authorities to do this repeatedly already controls the consensus, and the
//! ring is the least of the problem.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Bytes of randomness each authority contributes.
pub const CONTRIBUTION_LEN: usize = 32;

/// Commit to a value without revealing it.
///
/// The commitment binds: only the matching value hashes to it, so publishing
/// this now removes any freedom to change the value later.
pub fn commit(authority_id: &str, value: &[u8; CONTRIBUTION_LEN], period: u64) -> String {
    let mut h = Sha256::new();
    h.update(b"phinet-srv-commit-v1");
    h.update(authority_id.as_bytes());
    h.update(period.to_be_bytes());
    h.update(value);
    hex::encode(h.finalize())
}

/// Does a revealed value match what was committed?
pub fn check_reveal(
    authority_id: &str,
    value: &[u8; CONTRIBUTION_LEN],
    period: u64,
    commitment: &str,
) -> bool {
    // Constant time isn't needed: both sides are public by the reveal phase.
    commit(authority_id, value, period) == commitment
}

/// A reveal that matched its commitment.
#[derive(Clone, Debug, PartialEq)]
pub struct Reveal {
    pub authority_id: String,
    pub value: [u8; CONTRIBUTION_LEN],
}

/// Compute the shared random value from verified reveals.
///
/// Reveals are sorted by authority id, so every authority computes the same
/// value regardless of the order they arrived in — a value that depended on
/// arrival order would differ per authority, and a ring that differs per
/// authority is not a ring.
///
/// Returns `None` below `min_reveals`: a value derived from one contribution
/// is that contributor's choice, and using it would be worse than admitting
/// we have no shared randomness, because it would look like we did.
pub fn compute_srv(reveals: &[Reveal], period: u64, min_reveals: usize) -> Option<String> {
    let mut sorted: BTreeMap<&str, &[u8; CONTRIBUTION_LEN]> = BTreeMap::new();
    for r in reveals {
        // One contribution per authority. Without this, an authority could
        // submit many and drown out the others.
        sorted.insert(r.authority_id.as_str(), &r.value);
    }
    if sorted.len() < min_reveals { return None; }

    let mut h = Sha256::new();
    h.update(b"phinet-srv-v1");
    h.update(period.to_be_bytes());
    for (id, v) in &sorted {
        h.update((id.len() as u32).to_be_bytes());
        h.update(id.as_bytes());
        h.update(*v);
    }
    Some(hex::encode(h.finalize()))
}

/// Fresh randomness for this authority's contribution.
pub fn fresh_contribution() -> [u8; CONTRIBUTION_LEN] {
    use rand::RngCore;
    let mut v = [0u8; CONTRIBUTION_LEN];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(b: u8) -> [u8; 32] { [b; 32] }

    fn reveal(id: &str, b: u8) -> Reveal {
        Reveal { authority_id: id.into(), value: val(b) }
    }

    #[test]
    fn a_commitment_binds_its_value() {
        let c = commit("a1", &val(7), 100);
        assert!(check_reveal("a1", &val(7), 100, &c));
        assert!(!check_reveal("a1", &val(8), 100, &c),
                "if another value matched, committing would mean nothing");
    }

    #[test]
    fn a_commitment_is_bound_to_its_author() {
        // Otherwise an authority could replay someone else's commitment and
        // reveal their value as its own.
        let c = commit("a1", &val(7), 100);
        assert!(!check_reveal("a2", &val(7), 100, &c));
    }

    #[test]
    fn a_commitment_is_bound_to_its_period() {
        // Reusing last period's commitment would let an authority contribute
        // a value it already knows the effect of.
        let c = commit("a1", &val(7), 100);
        assert!(!check_reveal("a1", &val(7), 101, &c));
    }

    #[test]
    fn a_commitment_hides_its_value() {
        // Not a proof, but the obvious failure — a commitment that's just the
        // value in a hat — would show up here.
        let c = commit("a1", &val(7), 100);
        assert!(!c.contains("0707"));
    }

    #[test]
    fn every_authority_computes_the_same_value() {
        // The whole point: one ring, agreed by all, in any arrival order.
        let a = vec![reveal("a1", 1), reveal("a2", 2), reveal("a3", 3)];
        let b = vec![reveal("a3", 3), reveal("a1", 1), reveal("a2", 2)];
        assert_eq!(compute_srv(&a, 1, 2), compute_srv(&b, 1, 2));
    }

    #[test]
    fn every_contribution_changes_the_result() {
        // If one authority's value could be ignored, that authority has been
        // silently excluded from a protocol whose only purpose is that nobody
        // is in sole control.
        let base = vec![reveal("a1", 1), reveal("a2", 2)];
        let diff = vec![reveal("a1", 1), reveal("a2", 9)];
        assert_ne!(compute_srv(&base, 1, 2), compute_srv(&diff, 1, 2));
    }

    #[test]
    fn the_value_changes_every_period() {
        // A ring that never moves lets a directory sit beside a service
        // forever, which is what all of this is trying to prevent.
        let r = vec![reveal("a1", 1), reveal("a2", 2)];
        assert_ne!(compute_srv(&r, 1, 2), compute_srv(&r, 2, 2));
    }

    #[test]
    fn one_authority_cannot_flood_the_input() {
        // Many reveals from one authority must count once, or it can drown
        // out everyone else and choose the outcome alone.
        let honest = vec![reveal("a1", 1), reveal("a2", 2)];
        let flooded = vec![
            reveal("a1", 1), reveal("a1", 1), reveal("a1", 1), reveal("a2", 2),
        ];
        assert_eq!(compute_srv(&honest, 1, 2), compute_srv(&flooded, 1, 2));
    }

    #[test]
    fn too_few_reveals_produce_nothing() {
        // A value from a single contributor is that contributor's choice.
        // Better to have no shared randomness than to have something that
        // looks like it but isn't.
        assert!(compute_srv(&[reveal("a1", 1)], 1, 2).is_none());
        assert!(compute_srv(&[], 1, 2).is_none());
    }

    #[test]
    fn a_missing_authority_still_yields_a_value() {
        // An authority that commits and then withholds its reveal shouldn't
        // be able to stop the network by sulking.
        let r = vec![reveal("a1", 1), reveal("a2", 2)];
        assert!(compute_srv(&r, 1, 2).is_some());
    }

    #[test]
    fn fresh_contributions_are_not_all_the_same() {
        assert_ne!(fresh_contribution(), fresh_contribution());
    }
}
