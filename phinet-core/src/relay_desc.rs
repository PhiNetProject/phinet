//! # Relay descriptors
//!
//! How does an authority learn that a relay's operator also runs three other
//! relays?
//!
//! Today: it doesn't. ΦNET's authorities vote on what they can *observe* — a
//! relay's address, whether it answers, how fast it is. Observation can't see
//! intent, and family is pure intent: two relays in different datacentres,
//! run by one person, look exactly like two unrelated relays from outside. So
//! `--family` only works when the operator's own authority reports it, which
//! means it only works for people who run authorities. For everyone else the
//! flag does nothing, and the path diversity it promises is a fiction.
//!
//! The missing piece is a way for a relay to *say* something and have that
//! statement survive leaving the wire. A ΦNET handshake authenticates a link:
//! it proves the peer at the other end holds the key for a node id, right
//! now, to us. It says nothing a third party can check later, so a claim made
//! over a link can't be relayed, cached, or voted on by anyone who wasn't
//! there.
//!
//! A descriptor is that statement: a small signed document in which a relay
//! declares what it is, which anyone can verify without having spoken to it.
//!
//! ## The key that didn't exist
//!
//! A relay's identity is a `PhiCert` plus an x25519 static secret. The cert
//! establishes the node id; x25519 does key agreement — neither signs. So
//! relays acquire an Ed25519 identity key here, and the descriptor is signed
//! with it.
//!
//! ## Binding: why the signing key isn't a second identity
//!
//! A signature only means something if you know whose key it is. Anyone can
//! generate an Ed25519 key and claim to be node `abc…` — nothing in the
//! mathematics objects.
//!
//! The binding comes from the link. When a relay connects, the ΦNET handshake
//! proves it holds the cert and static key for its node id: only the real
//! node can do that. The signing key it presents over that authenticated link
//! is therefore genuinely its own, and we pin it. Afterwards, a descriptor
//! for that node id — arriving over any path, gossiped through any peer —
//! must verify against the pinned key.
//!
//! This gives descriptors what they were missing: they can travel. Everything
//! after the first meeting is verifiable by anyone.
//!
//! ## What this deliberately does not solve
//!
//! Pinning binds a key to a node id **for nodes we have met**. A descriptor
//! for a node id we've never linked to can't be verified against anything, so
//! we don't accept it. On a small network where everyone links to everyone,
//! that costs nothing. On a large one it means descriptors propagate only as
//! far as the acquaintance graph, and the real fix is to carry the signing
//! key inside the `PhiCert` itself — so the node id *commits* to it and no
//! meeting is required.
//!
//! That's the right design and it isn't done here, because changing the cert
//! changes every node id on the network, and node id churn is the thing that
//! caused the consensus/rotation failures this codebase has already fought.
//! It should happen at a version boundary, deliberately, not as a side effect
//! of adding family support.
//!
//! ## Self-declared, therefore not trusted
//!
//! Nothing here is a claim about honesty. A relay can declare any family it
//! likes, including none, and lie about its exit policy. A descriptor proves
//! *who said it*, not that it's true. Bandwidth stays measured rather than
//! declared for exactly this reason — it's the one field with an incentive to
//! inflate. Family works despite being unverifiable because lying about it
//! gains an attacker nothing they couldn't get by staying silent, which is
//! the same reason Tor's `MyFamily` is self-declared.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// How long a descriptor stays fresh.
///
/// A descriptor is a statement about the present. Left to stand forever, a
/// relay that changed its policy a year ago would still be advertising the
/// old one, and — worse — an attacker replaying an old descriptor could undo
/// a change the operator made deliberately.
pub const DESC_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Reject descriptors claiming to be from the future by more than this.
///
/// Clocks disagree; a few minutes of skew is ordinary. A descriptor dated
/// next week is not a clock problem.
pub const MAX_CLOCK_SKEW_SECS: u64 = 10 * 60;

/// A relay's signed self-declaration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RelayDescriptor {
    /// The node this describes. Must match the link it was pinned over.
    pub node_id_hex: String,
    /// Ed25519 public key that signs this descriptor, hex.
    pub signing_pub_hex: String,
    /// Address the relay believes it's reachable at.
    pub host: String,
    pub port: u16,
    /// x25519 static public key, hex — the `B` clients use for ntor.
    pub static_pub_hex: String,
    /// Operator family label. Empty means unaffiliated.
    #[serde(default)]
    pub family: String,
    /// Exit policy summary the relay claims to enforce.
    #[serde(default)]
    pub exit_policy_summary: String,
    /// Unix seconds this was published.
    pub published: u64,
    /// Ed25519 signature over `canonical_bytes`, hex.
    pub signature_hex: String,
}

/// Everything the signature covers.
///
/// Length-prefixed rather than concatenated: without prefixes, a relay in
/// family "ab" with host "c" and one in family "a" with host "bc" produce the
/// same bytes, and a signature over one would verify the other. Every field
/// the reader acts on is included — a field outside the signature is a field
/// an attacker can rewrite in transit, which is the bug that forced tonight's
/// re-vote.
pub fn canonical_bytes(d: &RelayDescriptor) -> Vec<u8> {
    fn lp(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"phinet-relay-desc-v1");
    lp(&mut out, &d.node_id_hex);
    lp(&mut out, &d.signing_pub_hex);
    lp(&mut out, &d.host);
    out.extend_from_slice(&d.port.to_be_bytes());
    lp(&mut out, &d.static_pub_hex);
    lp(&mut out, &d.family);
    lp(&mut out, &d.exit_policy_summary);
    out.extend_from_slice(&d.published.to_be_bytes());
    out
}

/// Build and sign a descriptor.
#[allow(clippy::too_many_arguments)]
pub fn build(
    signing: &SigningKey,
    node_id_hex: String,
    host: String,
    port: u16,
    static_pub_hex: String,
    family: String,
    exit_policy_summary: String,
    published: u64,
) -> RelayDescriptor {
    let mut d = RelayDescriptor {
        node_id_hex,
        signing_pub_hex: hex::encode(signing.verifying_key().to_bytes()),
        host,
        port,
        static_pub_hex,
        family,
        exit_policy_summary,
        published,
        signature_hex: String::new(),
    };
    let sig = signing.sign(&canonical_bytes(&d));
    d.signature_hex = hex::encode(sig.to_bytes());
    d
}

#[derive(Debug, PartialEq)]
pub enum DescError {
    BadSignature,
    /// The signing key isn't the one we pinned for this node id over an
    /// authenticated link. Either the node rotated keys (which it may not do
    /// unilaterally) or someone is impersonating it.
    WrongKey,
    Expired,
    FromTheFuture,
    Malformed(&'static str),
}

/// Check a descriptor's signature and freshness.
///
/// `expect_signing_pub` is the key pinned for this node id. `None` means we
/// have never met this node: the signature can be checked for internal
/// consistency, but consistency is not identity — anyone can sign their own
/// lies correctly — so this returns `WrongKey` rather than pretending.
pub fn verify(
    d: &RelayDescriptor,
    expect_signing_pub: Option<&str>,
    now: u64,
) -> Result<(), DescError> {
    let pinned = expect_signing_pub.ok_or(DescError::WrongKey)?;
    if pinned != d.signing_pub_hex { return Err(DescError::WrongKey); }

    if d.published > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(DescError::FromTheFuture);
    }
    if now.saturating_sub(d.published) > DESC_LIFETIME_SECS {
        return Err(DescError::Expired);
    }

    let pk_bytes: [u8; 32] = hex::decode(&d.signing_pub_hex).ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(DescError::Malformed("signing_pub"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| DescError::Malformed("signing_pub not a point"))?;
    let sig_bytes: [u8; 64] = hex::decode(&d.signature_hex).ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(DescError::Malformed("signature"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(&canonical_bytes(d), &sig).map_err(|_| DescError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey { SigningKey::generate(&mut OsRng) }

    fn desc(k: &SigningKey, family: &str, published: u64) -> RelayDescriptor {
        build(k, "aa".repeat(32), "10.0.0.1".into(), 7700, "bb".repeat(32),
              family.into(), "default".into(), published)
    }

    fn pin(k: &SigningKey) -> String { hex::encode(k.verifying_key().to_bytes()) }

    #[test]
    fn a_relays_own_descriptor_verifies() {
        let k = key();
        let d = desc(&k, "acme", 1000);
        assert_eq!(verify(&d, Some(&pin(&k)), 1000), Ok(()));
    }

    #[test]
    fn an_unmet_node_is_not_trusted_just_because_it_signed_correctly() {
        // The whole point of pinning: a valid signature proves someone owns a
        // key, not that the key owns the node id. Anyone can sign their own
        // claim to be someone else.
        let k = key();
        let d = desc(&k, "acme", 1000);
        assert_eq!(verify(&d, None, 1000), Err(DescError::WrongKey));
    }

    #[test]
    fn impersonation_with_a_different_key_is_refused() {
        let real = key();
        let attacker = key();
        // Attacker claims the same node id, signs perfectly with their key.
        let forged = desc(&attacker, "attacker", 1000);
        assert_eq!(verify(&forged, Some(&pin(&real)), 1000), Err(DescError::WrongKey));
    }

    #[test]
    fn tampering_with_family_breaks_the_signature() {
        // Family is the field with an attack behind it: tag every relay into
        // one family and path selection refuses to build anything.
        let k = key();
        let mut d = desc(&k, "", 1000);
        d.family = "everyone".into();
        assert_eq!(verify(&d, Some(&pin(&k)), 1000), Err(DescError::BadSignature));
    }

    #[test]
    fn tampering_with_the_address_breaks_the_signature() {
        let k = key();
        let mut d = desc(&k, "", 1000);
        d.host = "evil.example".into();
        assert_eq!(verify(&d, Some(&pin(&k)), 1000), Err(DescError::BadSignature));
    }

    #[test]
    fn tampering_with_the_static_key_breaks_the_signature() {
        // Swapping `B` would let an attacker terminate ntor handshakes meant
        // for this relay.
        let k = key();
        let mut d = desc(&k, "", 1000);
        d.static_pub_hex = "cc".repeat(32);
        assert_eq!(verify(&d, Some(&pin(&k)), 1000), Err(DescError::BadSignature));
    }

    #[test]
    fn an_old_descriptor_expires() {
        // Otherwise a replayed descriptor could undo a policy change the
        // operator made deliberately.
        let k = key();
        let d = desc(&k, "", 1000);
        assert_eq!(verify(&d, Some(&pin(&k)), 1000 + DESC_LIFETIME_SECS + 1),
                   Err(DescError::Expired));
    }

    #[test]
    fn small_clock_skew_is_tolerated() {
        let k = key();
        let d = desc(&k, "", 1000);
        assert_eq!(verify(&d, Some(&pin(&k)), 999), Ok(()), "clocks disagree; that's normal");
    }

    #[test]
    fn a_descriptor_from_next_week_is_refused() {
        let k = key();
        let d = desc(&k, "", 100_000);
        assert_eq!(verify(&d, Some(&pin(&k)), 1000), Err(DescError::FromTheFuture));
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Without length prefixes, ("ab","c") and ("a","bc") hash the same,
        // and a signature over one verifies the other.
        let k = key();
        let a = build(&k, "n".into(), "h".into(), 1, "s".into(),
                      "ab".into(), "c".into(), 1);
        let b = build(&k, "n".into(), "h".into(), 1, "s".into(),
                      "a".into(), "bc".into(), 1);
        assert_ne!(canonical_bytes(&a), canonical_bytes(&b));
    }

    #[test]
    fn round_trips_through_json() {
        let k = key();
        let d = desc(&k, "acme", 1000);
        let s = serde_json::to_string(&d).unwrap();
        let back: RelayDescriptor = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
        assert_eq!(verify(&back, Some(&pin(&k)), 1000), Ok(()));
    }
}
