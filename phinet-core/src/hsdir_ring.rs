//! # The hidden-service directory hashring
//!
//! Where should a hidden service's descriptor live, and who should a client
//! ask for it?
//!
//! ΦNET's first answer was "everywhere" and "everyone": publishing broadcast
//! the descriptor to every peer, and looking one up broadcast a query and
//! waited for whoever happened to have it. That works at three relays, and it
//! has two problems that get worse with every relay added.
//!
//! It doesn't scale. Publishing is O(relays) messages, repeated every twenty
//! minutes per service, and a lookup wakes the whole network to find one
//! record. At a hundred relays and a hundred services, most of the network's
//! traffic is bookkeeping.
//!
//! And it's a census. Every relay learns every service that exists, because
//! every relay is handed every descriptor. A network whose purpose is hiding
//! who is talking to whom hands out a complete list of what there is to talk
//! to, to anyone who runs a relay.
//!
//! The fix is the one Tor uses: hash services and relays onto the same ring,
//! and let position decide. A descriptor goes to the few relays sitting just
//! after it on the ring; a client computes the same positions and asks those
//! relays directly. Publishing becomes a handful of messages, lookup stops
//! being a broadcast, and no relay sees more than the slice of the ring it
//! happens to sit on.
//!
//! ## Why the ring rotates
//!
//! Positions include the time period, so the ring reshuffles daily. A relay
//! that would otherwise sit next to a given service forever — quietly logging
//! every client that asks after it — gets moved along.
//!
//! ## Replicas
//!
//! Each descriptor is placed at several independent positions, so losing one
//! relay doesn't take a service offline. Independent placement matters:
//! putting all replicas adjacent would mean one operator with a few
//! consecutive positions could disappear a service.
//!
//! ## Blinded keys
//!
//! Callers index by a *blinded* key, not the service's identity: see
//! `hs_blind`. The service's identity moved by a per-period factor anyone can
//! derive from the identity itself — so a client who knows the address
//! computes the same position, while a directory holding the descriptor
//! cannot work backwards to learn whose it is, or match it to the same
//! service next period.
//!
//! This module doesn't do the blinding; it only sees keys. That's deliberate
//! — the ring's job is placement, and it shouldn't care whether what it's
//! placing is identifying.
//!
//! ## Position grinding, and the salt that prevents it
//!
//! Ring positions come from the node id, the period, and `ring_salt`. If the
//! salt were public and constant, every future ring would be computable
//! today: an attacker could grind node ids offline until one landed beside a
//! service they wanted to watch, and be in place when the period turned over.
//!
//! So the salt should be the period's shared random value — a number the
//! authorities produce together, by commit-then-reveal, that none of them can
//! choose alone and nobody knows early (see `shared_random`). Grinding can't
//! begin until the value is public, and by then the positions are fixed.
//!
//! The salt is a parameter rather than a fixed source because a network whose
//! authorities haven't agreed a value still has to work. Passing the network
//! id makes the ring predictable — worse, but not broken, and honest.

use sha2::{Digest, Sha256};

/// How many relays store each replica of a descriptor.
///
/// Three: enough that a relay going down doesn't lose the descriptor, few
/// enough that publishing stays cheap. Tor uses a similar spread for the same
/// balance.
pub const HSDIR_SPREAD: usize = 3;

/// How many independent positions each descriptor is placed at.
///
/// Two placements of three relays each means six relays hold a descriptor,
/// drawn from two unrelated parts of the ring — so an operator would need
/// contiguous control of a specific region to erase a service.
pub const HSDIR_REPLICAS: u8 = 2;

/// A relay's position on the ring for this period.
///
/// Depends on the relay's identity, the period, and the salt — so it moves
/// every period, and a relay can't choose where it sits (short of grinding
/// node ids; see the module docs).
pub fn hsdir_index(node_id_hex: &str, period: u64, ring_salt: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"phinet-hsdir-index-v1");
    h.update(node_id_hex.as_bytes());
    h.update(period.to_be_bytes());
    h.update(ring_salt.as_bytes());
    h.finalize().into()
}

/// A descriptor's position on the ring, for one replica.
///
/// The replica number is part of the hash rather than an offset, so the two
/// replicas land in unrelated places instead of near neighbours.
pub fn hs_index(hs_id: &str, replica: u8, period: u64, ring_salt: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"phinet-hs-index-v1");
    h.update(hs_id.as_bytes());
    h.update([replica]);
    h.update(period.to_be_bytes());
    h.update(ring_salt.as_bytes());
    h.finalize().into()
}

/// Which relays are responsible for a service's descriptor this period.
///
/// Walks the ring clockwise from each replica's position and takes the next
/// `HSDIR_SPREAD` relays, wrapping at the end. Both the service (publishing)
/// and the client (looking up) run this and get the same answer, which is the
/// whole point: no broadcast, no guessing.
///
/// `relays` is the candidate set — normally every RUNNING relay in the
/// consensus. The result is deduplicated (replicas can overlap on a small
/// network) and never includes more relays than exist.
///
/// On a network smaller than the spread, this returns everyone — which is
/// exactly what broadcast did, so the change is a no-op until there are
/// enough relays for it to matter.
pub fn responsible_hsdirs(
    hs_id: &str,
    relays: &[String],
    period: u64,
    ring_salt: &str,
) -> Vec<String> {
    if relays.is_empty() { return Vec::new(); }

    // Sort relays by ring position once; both replicas walk the same ring.
    let mut ring: Vec<([u8; 32], String)> = relays.iter()
        .map(|r| (hsdir_index(r, period, ring_salt), r.clone()))
        .collect();
    ring.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out: Vec<String> = Vec::new();
    for replica in 0..HSDIR_REPLICAS {
        let target = hs_index(hs_id, replica, period, ring_salt);
        // First relay at or after the target position.
        let start = ring.partition_point(|(idx, _)| idx < &target);
        for k in 0..HSDIR_SPREAD {
            let (_, id) = &ring[(start + k) % ring.len()];
            if !out.contains(id) { out.push(id.clone()); }
            if out.len() >= relays.len() { return out; }   // whole network
        }
    }
    out
}

/// Is this relay one of the ones that should hold this descriptor?
///
/// A relay uses this to decide whether an unsolicited descriptor is something
/// it ought to be storing, rather than accepting anything anyone pushes.
pub fn is_responsible(
    my_node_id_hex: &str,
    hs_id: &str,
    relays: &[String],
    period: u64,
    ring_salt: &str,
) -> bool {
    responsible_hsdirs(hs_id, relays, period, ring_salt)
        .iter().any(|r| r == my_node_id_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relays(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{:064x}", i)).collect()
    }

    #[test]
    fn publisher_and_client_agree() {
        // The entire point: two parties computing independently must land on
        // the same relays, or a lookup asks nobody who has it.
        let r = relays(50);
        let a = responsible_hsdirs("service", &r, 100, "salt");
        let b = responsible_hsdirs("service", &r, 100, "salt");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn a_small_network_means_everyone_which_is_what_broadcast_did() {
        // Below the spread, the ring picks the whole network — so switching
        // from broadcast to the ring changes nothing until there are enough
        // relays for it to matter.
        let r = relays(3);
        let got = responsible_hsdirs("service", &r, 1, "salt");
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn only_a_slice_of_a_large_network_is_responsible() {
        // The scaling claim: publishing touches a handful of relays, not all
        // of them, and most relays never learn the service exists.
        let r = relays(200);
        let got = responsible_hsdirs("service", &r, 1, "salt");
        assert!(got.len() <= (HSDIR_SPREAD * HSDIR_REPLICAS as usize),
                "got {} relays; publishing should stay cheap", got.len());
        assert!(got.len() >= HSDIR_SPREAD, "and redundant enough to survive a loss");
    }

    #[test]
    fn replicas_land_in_unrelated_places() {
        // If both replicas clustered, one operator holding a few adjacent
        // positions could erase a service.
        let r = relays(200);
        let a = responsible_hsdirs("svc", &r, 5, "salt");
        // With 200 relays and independent replica positions, the two groups
        // should not be the same three relays.
        assert!(a.len() > HSDIR_SPREAD,
                "replicas collapsed onto one spot: {:?}", a);
    }

    #[test]
    fn the_ring_moves_between_periods() {
        // Otherwise a relay sits next to a service forever, logging everyone
        // who asks after it.
        let r = relays(200);
        let p1 = responsible_hsdirs("svc", &r, 1, "salt");
        let p2 = responsible_hsdirs("svc", &r, 2, "salt");
        assert_ne!(p1, p2, "the ring must reshuffle each period");
    }

    #[test]
    fn different_services_land_in_different_places() {
        let r = relays(200);
        let a = responsible_hsdirs("svc-a", &r, 1, "salt");
        let b = responsible_hsdirs("svc-b", &r, 1, "salt");
        assert_ne!(a, b, "every service on the same relays is just broadcast again");
    }

    #[test]
    fn wraps_around_the_end_of_the_ring() {
        // A service hashing past the last relay must wrap to the first, not
        // return a short list.
        let r = relays(10);
        for i in 0..200 {
            let got = responsible_hsdirs(&format!("svc{i}"), &r, 1, "salt");
            assert!(got.len() >= HSDIR_SPREAD,
                    "service {i} got only {} dirs — ring didn't wrap", got.len());
        }
    }

    #[test]
    fn a_responsible_relay_knows_it_is() {
        let r = relays(50);
        let dirs = responsible_hsdirs("svc", &r, 1, "salt");
        assert!(is_responsible(&dirs[0], "svc", &r, 1, "salt"));
        let outsider = r.iter().find(|x| !dirs.contains(x)).unwrap();
        assert!(!is_responsible(outsider, "svc", &r, 1, "salt"),
                "a relay off the ring position shouldn't store the descriptor");
    }

    #[test]
    fn empty_network_is_not_a_panic() {
        assert!(responsible_hsdirs("svc", &[], 1, "salt").is_empty());
    }

    #[test]
    fn relay_order_does_not_matter() {
        // The consensus may list relays in any order; the ring must not.
        let mut r = relays(40);
        let a = responsible_hsdirs("svc", &r, 1, "salt");
        r.reverse();
        let b = responsible_hsdirs("svc", &r, 1, "salt");
        assert_eq!(a, b);
    }
}
