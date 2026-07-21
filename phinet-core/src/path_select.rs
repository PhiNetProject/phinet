// phinet-core/src/path_select.rs
//!
//! # Path selection
//!
//! Picks a 3-hop circuit (guard → middle → exit) from a consensus
//! document, weighted by bandwidth and constrained by:
//!
//! - **Position constraints** — guards need GUARD flag, exits need
//!   EXIT flag. Middle hops just need RUNNING + STABLE.
//! - **Subnet diversity** — no two hops on the same /16. Adversaries
//!   running multiple relays on a single /16 (e.g. one cloud region)
//!   shouldn't be able to capture two hops on the same circuit.
//! - **No same-relay reuse** — can't pick the same node_id twice.
//! - **Self-exclusion** — never pick our own node as a hop.
//! - **Guard pinning** — once a client picks a guard, they keep it
//!   for `GUARD_LIFETIME` (currently 60 days, see `guards.rs`). This
//!   selector exposes a `pick_guard` that respects that policy by
//!   only selecting from a passed-in candidate set.
//!
//! ## Bandwidth weighting
//!
//! Tor's path-selection picks each hop with probability proportional
//! to the relay's measured bandwidth. This matches the network's
//! actual capacity distribution: high-bandwidth relays get more
//! traffic, congesting fewer of them. Without weighting, a small
//! relay shows up in path proposals as often as a 1 GB/s relay,
//! and the small ones become bottlenecks.
//!
//! Implementation: standard weighted random sampling. We sum
//! bandwidths to get the total, pick a random `u64 < total`, walk
//! the candidate list adding bandwidths until we cross the picked
//! value. O(n) per pick which is fine for n in the thousands.

use crate::directory::{ConsensusDocument, PeerEntry, PeerFlags};
use rand::Rng;

/// One hop in a selected path. Aliases of `PeerEntry`'s relevant
/// fields, for convenience — the caller usually just needs the
/// node_id, host, port, and static_pub to dial.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedHop {
    pub node_id_hex:   String,
    pub host:          String,
    pub port:          u16,
    pub static_pub_hex: String,
}

impl From<&PeerEntry> for SelectedHop {
    fn from(p: &PeerEntry) -> Self {
        Self {
            node_id_hex:    p.node_id_hex.clone(),
            host:           p.host.clone(),
            port:           p.port,
            static_pub_hex: p.static_pub_hex.clone(),
        }
    }
}

impl SelectedHop {
    /// Convert to a `LinkSpec` suitable for `PhiNode::build_circuit`.
    /// Returns an error if the hex-encoded fields don't decode to
    /// 32 bytes (the on-wire sizes for node_id and static_pub).
    pub fn to_link_spec(&self) -> std::result::Result<crate::circuit::LinkSpec, PathError> {
        let node_id = hex_to_32(&self.node_id_hex)
            .ok_or_else(|| PathError::InsufficientRelays(
                format!("hop has malformed node_id_hex: {}", self.node_id_hex)))?;
        let static_pub = hex_to_32(&self.static_pub_hex)
            .ok_or_else(|| PathError::InsufficientRelays(
                format!("hop has malformed static_pub_hex: {}", self.static_pub_hex)))?;
        Ok(crate::circuit::LinkSpec {
            host: self.host.clone(),
            port: self.port,
            node_id,
            static_pub,
        })
    }
}

impl SelectedPath {
    /// Convert each hop to a `LinkSpec`, returning the vec ready to
    /// pass to `PhiNode::build_circuit`. Fails if any hop has
    /// malformed hex fields.
    pub fn to_link_specs(&self) -> std::result::Result<Vec<crate::circuit::LinkSpec>, PathError> {
        self.hops.iter().map(|h| h.to_link_spec()).collect()
    }
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    if v.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Some(arr)
}

/// A 3-hop path. Indexed `0=guard, 1=middle, 2=exit`.
#[derive(Clone, Debug)]
pub struct SelectedPath {
    pub hops: Vec<SelectedHop>,
}

/// Errors specific to path selection.
#[derive(Debug)]
pub enum PathError {
    /// Not enough relays in the consensus to satisfy constraints
    /// (e.g. <3 relays, or no exits, or every relay is on the same /16).
    InsufficientRelays(String),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::InsufficientRelays(s) => write!(f, "insufficient relays: {s}"),
        }
    }
}
impl std::error::Error for PathError {}

/// Filter the consensus down to peers eligible for a given position.
///
/// Position constraints:
/// - **Guard**: STABLE + FAST + GUARD + RUNNING + VALID
/// - **Middle**: STABLE + FAST + RUNNING + VALID
/// - **Exit**: STABLE + FAST + EXIT + RUNNING + VALID
///
/// Returns a vec of references into the consensus's peer list.
pub fn eligible_for_position<'a>(
    consensus: &'a ConsensusDocument,
    position: Position,
) -> Vec<&'a PeerEntry> {
    let required = match position {
        Position::Guard  => PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::GUARD
                          | PeerFlags::RUNNING | PeerFlags::VALID,
        Position::Middle => PeerFlags::STABLE | PeerFlags::FAST
                          | PeerFlags::RUNNING | PeerFlags::VALID,
        Position::Exit   => PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::EXIT
                          | PeerFlags::RUNNING | PeerFlags::VALID,
    };
    consensus.peers.iter()
        .filter(|p| (p.flags & required.bits()) == required.bits())
        .filter(|p| p.bandwidth_kbs > 0)  // exclude unmeasured relays
        .collect()
}

/// Position in the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position { Guard, Middle, Exit }

/// Weighted-random pick from a candidate list, weighted by
/// `bandwidth_kbs`. Returns `None` if the list is empty.
///
/// Uses a single linear scan: pick a target value uniformly in
/// `[0, total)`, walk the list summing bandwidths, return the relay
/// whose accumulated weight crosses the target. This is a standard
/// O(n) weighted-random algorithm.
pub fn weighted_random_pick<'a, R: Rng>(
    rng: &mut R,
    candidates: &[&'a PeerEntry],
) -> Option<&'a PeerEntry> {
    if candidates.is_empty() { return None; }
    let total: u64 = candidates.iter().map(|p| p.bandwidth_kbs as u64).sum();
    if total == 0 {
        // All zero-bandwidth relays — fall back to uniform random
        // since the weighting can't differentiate them.
        let idx = rng.gen_range(0..candidates.len());
        return Some(candidates[idx]);
    }
    let mut target = rng.gen_range(0..total);
    for p in candidates {
        let bw = p.bandwidth_kbs as u64;
        if target < bw { return Some(*p); }
        target -= bw;
    }
    // Defensive fallback (shouldn't hit due to the loop math above)
    candidates.last().copied()
}

/// Extract the /16 (first two octets) of an IPv4 host. For non-IPv4
/// hosts (IPv6, hostnames) returns the host string itself, so two
/// such peers are only considered same-subnet if they're literally
/// the same string. This is more permissive than Tor's policy (which
/// uses /16 for IPv4 and /32 for IPv6) but errs on the side of
/// allowing path selection to succeed.
fn subnet_key(host: &str) -> String {
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        let o = addr.octets();
        format!("ipv4-{}.{}", o[0], o[1])
    } else if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        // /48 for IPv6 — first three 16-bit groups
        let s = addr.segments();
        format!("ipv6-{:x}:{:x}:{:x}", s[0], s[1], s[2])
    } else {
        // Hostname: use it verbatim. Operators rarely host two relays
        // at the same hostname so this is usually safe.
        format!("host-{host}")
    }
}

/// Select a full 3-hop path from the consensus. Returns the picked
/// guard, middle, and exit relays — in order — satisfying all
/// constraints listed in the module docstring.
///
/// Do two relays belong to the same declared operator family?
///
/// An empty family means "unaffiliated" and never conflicts — otherwise every
/// relay that hasn't set one would be considered related to every other.
fn same_family(a: &str, b: &str) -> bool {
    !a.is_empty() && a == b
}

/// `excluded_node_ids` is a set of node_id_hex values to skip
/// entirely (e.g. our own node_id, recently-failed peers,
/// blacklisted relays).
///
/// `pinned_guard` overrides random guard selection: if `Some`, that
/// peer is used as the guard regardless of bandwidth weight. This is
/// how guard pinning interacts with path selection — the client's
/// `guards.rs` picks one guard per session and feeds it here.
pub fn select_path<R: Rng>(
    rng: &mut R,
    consensus: &ConsensusDocument,
    excluded_node_ids: &[String],
    pinned_guard: Option<&PeerEntry>,
) -> std::result::Result<SelectedPath, PathError> {
    let exclude = |p: &&PeerEntry| !excluded_node_ids.iter().any(|e| e == &p.node_id_hex);

    // ── Guard ─────────────────────────────────────────────────────
    let guard_family: String;
    let guard: SelectedHop = match pinned_guard {
        Some(g) => { guard_family = g.family.clone(); SelectedHop::from(g) }
        None => {
            let guards: Vec<&PeerEntry> = eligible_for_position(consensus, Position::Guard)
                .into_iter()
                .filter(|p| exclude(p))
                .collect();
            let pick = weighted_random_pick(rng, &guards)
                .ok_or_else(|| PathError::InsufficientRelays(
                    "no relays with GUARD flag available".into()))?;
            guard_family = pick.family.clone();
            SelectedHop::from(pick)
        }
    };
    let guard_subnet = subnet_key(&guard.host);

    // ── Exit ──────────────────────────────────────────────────────
    let exit_candidates: Vec<&PeerEntry> = eligible_for_position(consensus, Position::Exit)
        .into_iter()
        .filter(|p| exclude(p))
        .filter(|p| p.node_id_hex != guard.node_id_hex)
        .filter(|p| subnet_key(&p.host) != guard_subnet)
        .filter(|p| !same_family(&p.family, &guard_family))
        .collect();
    let exit_peer = weighted_random_pick(rng, &exit_candidates)
        .ok_or_else(|| PathError::InsufficientRelays(
            "no exit relays available after subnet/family/exclusion filtering. \
             If every relay you run declares the same family, that is this rule \
             working: one operator's relays cannot form a diverse path".into()))?;
    let exit_family = exit_peer.family.clone();
    let exit = SelectedHop::from(exit_peer);
    let exit_subnet = subnet_key(&exit.host);

    // ── Middle ────────────────────────────────────────────────────
    let middle_candidates: Vec<&PeerEntry> = eligible_for_position(consensus, Position::Middle)
        .into_iter()
        .filter(|p| exclude(p))
        .filter(|p| p.node_id_hex != guard.node_id_hex
                 && p.node_id_hex != exit.node_id_hex)
        .filter(|p| {
            let s = subnet_key(&p.host);
            s != guard_subnet && s != exit_subnet
        })
        .filter(|p| !same_family(&p.family, &guard_family)
                 && !same_family(&p.family, &exit_family))
        .collect();
    let middle_peer = weighted_random_pick(rng, &middle_candidates)
        .ok_or_else(|| PathError::InsufficientRelays(
            "no middle relays available after subnet/family/exclusion filtering".into()))?;
    let middle = SelectedHop::from(middle_peer);

    Ok(SelectedPath {
        hops: vec![guard, middle, exit],
    })
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{ConsensusDocument, PeerEntry, PeerFlags};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn peer(id: &str, host: &str, bw: u32, flags: PeerFlags) -> PeerEntry {
        peer_fam(id, host, bw, flags, "")
    }

    pub(super) fn peer_fam(id: &str, host: &str, bw: u32, flags: PeerFlags, family: &str) -> PeerEntry {
        PeerEntry {
            node_id_hex: id.into(),
            host: host.into(),
            port: 7700,
            static_pub_hex: format!("{:0<64}", id),
            flags: flags.bits(),
            bandwidth_kbs: bw,
            exit_policy_summary: String::new(),
            family: family.into(),
        }
    }

    pub(super) fn all_flags() -> PeerFlags {
        PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::GUARD | PeerFlags::EXIT
        | PeerFlags::RUNNING | PeerFlags::VALID
    }

    fn build_consensus(peers: Vec<PeerEntry>) -> ConsensusDocument {
        ConsensusDocument {
            network_id: "test".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 0,
            valid_until: u64::MAX,
            peers,
            signatures: Vec::new(),
        }
    }

    #[test]
    fn select_path_with_minimum_diverse_relays() {
        // 3 relays on different /16s, all flags. Must succeed.
        let consensus = build_consensus(vec![
            peer("aa", "10.0.0.1", 1000, all_flags()),
            peer("bb", "11.0.0.1", 1000, all_flags()),
            peer("cc", "12.0.0.1", 1000, all_flags()),
        ]);
        let mut rng = StdRng::seed_from_u64(42);
        let path = select_path(&mut rng, &consensus, &[], None).unwrap();
        assert_eq!(path.hops.len(), 3);
        // All three are distinct
        let mut ids = vec![&path.hops[0].node_id_hex, &path.hops[1].node_id_hex, &path.hops[2].node_id_hex];
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3, "all hops must be distinct");
    }

    #[test]
    fn select_path_avoids_same_subnet() {
        // 4 relays: 3 on the same /16, 1 elsewhere. The guard slot
        // takes one of the same-/16 peers; the rest must avoid it.
        // With only 1 peer on a different /16, we cannot fill all 3
        // slots without a /16 collision — this should fail.
        let consensus = build_consensus(vec![
            peer("aa", "10.0.0.1", 1000, all_flags()),
            peer("bb", "10.0.0.2", 1000, all_flags()),
            peer("cc", "10.0.0.3", 1000, all_flags()),
            peer("dd", "11.0.0.1", 1000, all_flags()),
        ]);
        let mut had_failure = false;
        for seed in 0..20 {
            let mut rng = StdRng::seed_from_u64(seed);
            let result = select_path(&mut rng, &consensus, &[], None);
            if result.is_err() { had_failure = true; }
            if let Ok(path) = result {
                // If it succeeded, /16s must all be distinct
                let s0 = subnet_key(&path.hops[0].host);
                let s1 = subnet_key(&path.hops[1].host);
                let s2 = subnet_key(&path.hops[2].host);
                assert_ne!(s0, s1);
                assert_ne!(s1, s2);
                assert_ne!(s0, s2);
            }
        }
        // Stronger constraint: with only 4 relays distributed 3+1
        // across two /16s, no path should ever satisfy all three
        // slots being on different /16s. Verify by checking a
        // narrower 3-relay topology.
        let _ = had_failure;
        let consensus2 = build_consensus(vec![
            peer("aa", "10.0.0.1", 1000, all_flags()),
            peer("bb", "10.0.0.2", 1000, all_flags()),
            peer("cc", "10.0.0.3", 1000, all_flags()),
        ]);
        let mut rng2 = StdRng::seed_from_u64(0);
        let result = select_path(&mut rng2, &consensus2, &[], None);
        assert!(result.is_err(), "3 relays all on same /16 cannot satisfy path");
    }

    #[test]
    fn select_path_excludes_self() {
        // Exclude one of the relays; selected hops must not include it.
        let consensus = build_consensus(vec![
            peer("aa", "10.0.0.1", 1000, all_flags()),
            peer("bb", "11.0.0.1", 1000, all_flags()),
            peer("cc", "12.0.0.1", 1000, all_flags()),
            peer("dd", "13.0.0.1", 1000, all_flags()),
        ]);
        let mut rng = StdRng::seed_from_u64(7);
        let path = select_path(&mut rng, &consensus, &["aa".into()], None).unwrap();
        for hop in &path.hops {
            assert_ne!(hop.node_id_hex, "aa", "excluded id must not appear");
        }
    }

    #[test]
    fn select_path_respects_pinned_guard() {
        let consensus = build_consensus(vec![
            peer("aa", "10.0.0.1", 100, all_flags()),
            peer("bb", "11.0.0.1", 1000, all_flags()),
            peer("cc", "12.0.0.1", 1000, all_flags()),
        ]);
        let pinned = peer("aa", "10.0.0.1", 100, all_flags());
        let mut rng = StdRng::seed_from_u64(99);
        let path = select_path(&mut rng, &consensus, &[], Some(&pinned)).unwrap();
        // Pinned guard must be hop 0 even though its bw is much lower
        assert_eq!(path.hops[0].node_id_hex, "aa");
    }

    #[test]
    fn select_path_requires_exit_flag() {
        // 4 relays, none with EXIT flag — selection must fail.
        let no_exit = PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::GUARD
                    | PeerFlags::RUNNING | PeerFlags::VALID;
        let consensus = build_consensus(vec![
            peer("aa", "10.0.0.1", 1000, no_exit),
            peer("bb", "11.0.0.1", 1000, no_exit),
            peer("cc", "12.0.0.1", 1000, no_exit),
            peer("dd", "13.0.0.1", 1000, no_exit),
        ]);
        let mut rng = StdRng::seed_from_u64(1);
        let result = select_path(&mut rng, &consensus, &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn select_path_empty_consensus_fails() {
        let consensus = build_consensus(vec![]);
        let mut rng = StdRng::seed_from_u64(0);
        let result = select_path(&mut rng, &consensus, &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn weighted_pick_zero_bandwidth_fallback() {
        // All relays with bw=0 must still produce a pick (uniform fallback).
        let p1 = peer("aa", "h1", 0, all_flags());
        let p2 = peer("bb", "h2", 0, all_flags());
        let candidates = vec![&p1, &p2];
        let mut rng = StdRng::seed_from_u64(0);
        let pick = weighted_random_pick(&mut rng, &candidates);
        assert!(pick.is_some());
    }

    #[test]
    fn weighted_pick_proportional_distribution() {
        // 1000 picks across two relays with 9:1 bandwidth ratio
        // should produce ~90% / ~10% distribution. Tolerance is
        // wide because 1000 trials with binomial variance.
        let p1 = peer("aa", "h1", 900, all_flags());
        let p2 = peer("bb", "h2", 100, all_flags());
        let candidates = vec![&p1, &p2];

        let mut rng = StdRng::seed_from_u64(424242);
        let mut count_aa = 0;
        let n = 1000;
        for _ in 0..n {
            let pick = weighted_random_pick(&mut rng, &candidates).unwrap();
            if pick.node_id_hex == "aa" { count_aa += 1; }
        }
        // Expect ~900. Tolerance: ±50 covers >99% confidence interval.
        assert!(count_aa > 850 && count_aa < 950,
            "weighted pick produced {} of {} for 9:1 ratio (expected ~900)",
            count_aa, n);
    }

    #[test]
    fn weighted_pick_empty_returns_none() {
        let candidates: Vec<&PeerEntry> = vec![];
        let mut rng = StdRng::seed_from_u64(0);
        assert!(weighted_random_pick(&mut rng, &candidates).is_none());
    }

    #[test]
    fn subnet_key_ipv4_groups_by_16() {
        assert_eq!(subnet_key("10.0.0.1"), subnet_key("10.0.255.255"));
        assert_ne!(subnet_key("10.0.0.1"), subnet_key("10.1.0.1"));
        assert_ne!(subnet_key("10.0.0.1"), subnet_key("11.0.0.1"));
    }

    #[test]
    fn subnet_key_distinguishes_address_families() {
        assert_ne!(subnet_key("10.0.0.1"), subnet_key("::1"));
        assert_ne!(subnet_key("10.0.0.1"), subnet_key("example.com"));
    }

    #[test]
    fn eligible_for_position_filters_correctly() {
        let consensus = build_consensus(vec![
            peer("aa", "10.0.0.1", 100, all_flags()),                    // all
            peer("bb", "10.0.0.2", 100, PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::RUNNING | PeerFlags::VALID),
            peer("cc", "10.0.0.3", 100, PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::EXIT | PeerFlags::RUNNING | PeerFlags::VALID),
            peer("dd", "10.0.0.4", 0,   all_flags()),                    // bw=0 excluded
        ]);

        let guards = eligible_for_position(&consensus, Position::Guard);
        assert_eq!(guards.iter().map(|p| p.node_id_hex.as_str()).collect::<Vec<_>>(),
                   vec!["aa"]);  // only aa has GUARD with bw>0

        let exits = eligible_for_position(&consensus, Position::Exit);
        let exit_ids: Vec<_> = exits.iter().map(|p| p.node_id_hex.as_str()).collect();
        assert!(exit_ids.contains(&"aa"));
        assert!(exit_ids.contains(&"cc"));
        assert!(!exit_ids.contains(&"bb"));
        assert!(!exit_ids.contains(&"dd"));

        let middles = eligible_for_position(&consensus, Position::Middle);
        // bb, aa, cc all qualify as middle (need only STABLE+FAST+RUNNING+VALID)
        let middle_ids: Vec<_> = middles.iter().map(|p| p.node_id_hex.as_str()).collect();
        assert!(middle_ids.contains(&"aa"));
        assert!(middle_ids.contains(&"bb"));
        assert!(middle_ids.contains(&"cc"));
        assert!(!middle_ids.contains(&"dd"));
    }

    #[test]
    fn selected_hop_to_link_spec_roundtrip() {
        // 32-byte hex strings (64 hex chars) decode cleanly.
        let hop = SelectedHop {
            node_id_hex:    "aa".repeat(32),
            host:           "10.0.0.1".into(),
            port:           7700,
            static_pub_hex: "bb".repeat(32),
        };
        let ls = hop.to_link_spec().expect("conversion");
        assert_eq!(ls.host, "10.0.0.1");
        assert_eq!(ls.port, 7700);
        assert_eq!(ls.node_id, [0xaau8; 32]);
        assert_eq!(ls.static_pub, [0xbbu8; 32]);
    }

    #[test]
    fn selected_hop_to_link_spec_rejects_short_hex() {
        let hop = SelectedHop {
            node_id_hex:    "aa".into(),  // too short
            host:           "10.0.0.1".into(),
            port:           7700,
            static_pub_hex: "bb".repeat(32),
        };
        assert!(hop.to_link_spec().is_err());
    }

    #[test]
    fn selected_path_to_link_specs_collects_all() {
        let consensus = build_consensus(vec![
            peer("aa".repeat(32).as_str(), "10.0.0.1", 1000, all_flags()),
            peer("bb".repeat(32).as_str(), "11.0.0.1", 1000, all_flags()),
            peer("cc".repeat(32).as_str(), "12.0.0.1", 1000, all_flags()),
        ]);
        // Override static_pub_hex to be 64-char so the conversion test
        // sees real hex (peer() uses the id padded with 0s — for these
        // test ids it's already 64 chars).
        let mut rng = StdRng::seed_from_u64(42);
        let path = select_path(&mut rng, &consensus, &[], None).unwrap();
        let specs = path.to_link_specs().expect("convert");
        assert_eq!(specs.len(), 3);
    }

    #[test]
    fn select_path_runs_with_realistic_consensus() {
        // Simulate a small but realistic network: 20 relays, mixed
        // flag distributions, mixed /16s, mixed bandwidths. Selection
        // should succeed reliably across many seeds.
        let mut peers = Vec::new();
        for i in 0..20u32 {
            let mut flags = PeerFlags::STABLE | PeerFlags::FAST
                          | PeerFlags::RUNNING | PeerFlags::VALID;
            if i % 3 == 0 { flags |= PeerFlags::GUARD; }
            if i % 4 == 0 { flags |= PeerFlags::EXIT; }
            let host = format!("{}.0.0.1", 10 + i);  // distinct /16 each
            let bw = 100 + (i * 50);
            peers.push(peer(&format!("{:02x}", i), &host, bw, flags));
        }
        let consensus = build_consensus(peers);
        let mut success = 0;
        for seed in 0..50 {
            let mut rng = StdRng::seed_from_u64(seed);
            if select_path(&mut rng, &consensus, &[], None).is_ok() {
                success += 1;
            }
        }
        assert_eq!(success, 50,
            "every selection should succeed on this realistic topology");
    }
}

#[cfg(test)]
mod family_tests {
    use super::*;
    use super::tests::{all_flags, peer_fam};
    use crate::directory::ConsensusDocument;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn consensus(peers: Vec<PeerEntry>) -> ConsensusDocument {
        ConsensusDocument {
            network_id: "test".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 0,
            valid_until: u64::MAX,
            peers,
            signatures: Vec::new(),
        }
    }

    #[test]
    fn unaffiliated_relays_never_conflict() {
        // The common case: nobody declares a family. Empty must not be read
        // as "everyone is related", or no path could ever be built.
        assert!(!same_family("", ""));
    }

    #[test]
    fn same_declared_family_conflicts() {
        assert!(same_family("acme", "acme"));
        assert!(!same_family("acme", "other"));
        assert!(!same_family("", "acme"));
    }

    #[test]
    fn path_avoids_two_relays_from_one_operator() {
        // Six relays, but four belong to one operator across two subnets —
        // exactly the case /16 diversity misses. A path must not contain two
        // of theirs.
        let mut rng = StdRng::seed_from_u64(7);
        let c = consensus(vec![
            peer_fam("aa", "10.0.0.1",  1000, all_flags(), "bigco"),
            peer_fam("bb", "11.0.0.1",  1000, all_flags(), "bigco"),
            peer_fam("cc", "12.0.0.1",  1000, all_flags(), "bigco"),
            peer_fam("dd", "13.0.0.1",  1000, all_flags(), "bigco"),
            peer_fam("ee", "14.0.0.1",  1000, all_flags(), ""),
            peer_fam("ff", "15.0.0.1",  1000, all_flags(), ""),
        ]);
        for _ in 0..50 {
            let p = select_path(&mut rng, &c, &[], None).expect("a path exists");
            let fams: Vec<String> = p.hops.iter()
                .map(|h| c.peers.iter()
                    .find(|e| e.node_id_hex == h.node_id_hex)
                    .map(|e| e.family.clone()).unwrap_or_default())
                .collect();
            let bigco = fams.iter().filter(|f| *f == "bigco").count();
            assert!(bigco <= 1,
                    "path used {} relays from one operator: {:?}", bigco, fams);
        }
    }

    #[test]
    fn one_operator_declaring_everything_cannot_build_a_path() {
        // Not a bug — the point. If every relay is run by the same person,
        // there is no diverse path to build, and saying so is more honest
        // than quietly handing back a circuit that isn't one.
        let mut rng = StdRng::seed_from_u64(3);
        let c = consensus(vec![
            peer_fam("aa", "10.0.0.1", 1000, all_flags(), "solo"),
            peer_fam("bb", "11.0.0.1", 1000, all_flags(), "solo"),
            peer_fam("cc", "12.0.0.1", 1000, all_flags(), "solo"),
        ]);
        let r = select_path(&mut rng, &c, &[], None);
        assert!(r.is_err(), "three relays from one operator is not a path");
    }
}
