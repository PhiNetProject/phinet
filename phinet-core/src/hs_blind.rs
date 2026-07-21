//! # Key blinding
//!
//! The hashring decides which relays hold a service's descriptor. That fixed
//! the broadcast — publishing no longer tells the whole network what exists —
//! but it left something behind: the relays that *do* hold a descriptor know
//! exactly whose it is, because it's filed under the service's identity. A
//! smaller census is still a census, and the directories are precisely the
//! relays best placed to keep one. Worse, the filing is stable: the same
//! service lands under the same name forever, so a directory can watch a
//! service appear, disappear, and come back, and know it's the same one.
//!
//! Blinding removes the directory's ability to read what it is holding.
//!
//! The idea is that a public key can be *moved* by a factor derived from
//! public information. Given a service's identity key `A` and a time period,
//! anyone can compute `A' = h·A` where `h = H(A, period)`. The service, which
//! knows the secret scalar `a`, can compute the matching `a' = h·a` and sign
//! with it. So:
//!
//! - A **client** who knows `A` (it's the .phinet address they typed) derives
//!   `A'` and asks for it.
//! - A **directory** sees only `A'`. It can verify the descriptor is
//!   correctly signed — the signature checks against `A'` — but cannot invert
//!   the hash to recover `A`. It stores a document it cannot attribute.
//! - Next period the factor changes, so `A'` changes. The same service is
//!   filed under an unrelated name, and the directory can't tell it's the
//!   same service, or even that it existed before.
//!
//! The directory is reduced to what it actually needs to know: this blob is
//! internally consistent, and someone will come asking for it.
//!
//! ## Why the maths works
//!
//! Ed25519 keys are `A = a·B` for a secret scalar `a` and the standard base
//! point `B`. Scalar multiplication is associative, so `h·A = h·(a·B) =
//! (h·a)·B`. Multiplying the public key by `h` and multiplying the secret by
//! `h` land on the same key — which is what makes it possible for the client
//! and the service to derive matching halves without ever exchanging
//! anything.
//!
//! Recovering `A` from `A'` would mean dividing by `h` — fine if you know
//! `h`, and you only know `h` if you already know `A`. That circularity is
//! the privacy: the blinded key is only reversible by someone who already has
//! the answer.
//!
//! ## Signing has to be done by hand
//!
//! `ed25519_dalek::SigningKey` derives its scalar from a seed and won't sign
//! with a scalar handed to it — reasonably, since that's a footgun in every
//! other context. A blinded key has no seed: `a'` is a product, not a hash of
//! anything. So the signature is constructed directly per RFC 8032, which
//! is what Tor's implementation does for the same reason.
//!
//! The nonce needs care. Ed25519 is deterministic: `r = H(prefix, message)`,
//! where `prefix` is the half of the seed hash not used for the scalar.
//! Blinding must derive a fresh prefix too — reusing the unblinded prefix
//! across two blinded keys would produce two signatures under different keys
//! from the same nonce, and a nonce reused across different scalars leaks the
//! scalars. That is how private keys get extracted from real systems, so the
//! prefix is blinded alongside the scalar.
//!
//! ## What blinding does not do
//!
//! A directory still learns that *a* service exists at that ring position and
//! sees the clients who ask for it. Blinding hides identity and linkage, not
//! existence or traffic.
//!
//! And it does nothing about ring *position* being predictable. If the ring
//! depends only on public values, an attacker can compute next period's
//! layout in advance and grind node ids to sit next to a service they care
//! about. That's what the shared random value in the consensus is for, and
//! blinding without it leaves the targeting attack open — see `hsdir_ring`.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Domain separator for the blinding factor.
pub const BLIND_STRING: &[u8] = b"phinet-hs-blind-v1";

/// Derive the blinding factor `h` for an identity key and period.
///
/// Clamped the way Ed25519 clamps scalars: clearing the low three bits keeps
/// the result in the prime-order subgroup, so blinding can't push a key into
/// a small subgroup where signatures behave strangely. `Scalar::from_bytes_mod_order`
/// then reduces it, so `h` is always a valid scalar.
pub fn blinding_factor(identity_pub: &[u8; 32], period: u64, salt: &str) -> Scalar {
    let mut h = Sha512::new();
    h.update(BLIND_STRING);
    h.update(identity_pub);
    h.update(period.to_be_bytes());
    h.update(salt.as_bytes());
    let digest = h.finalize();

    let mut b = [0u8; 32];
    b.copy_from_slice(&digest[..32]);
    // Standard Ed25519 clamping.
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    Scalar::from_bytes_mod_order(b)
}

/// Blind a **public** key: what a client computes from a .phinet address.
///
/// Fails only if `identity_pub` isn't a valid curve point — which means the
/// address was never a real key.
pub fn blind_public(identity_pub: &[u8; 32], period: u64, salt: &str) -> Option<[u8; 32]> {
    let a = CompressedEdwardsY(*identity_pub).decompress()?;
    let h = blinding_factor(identity_pub, period, salt);
    Some((h * a).compress().to_bytes())
}

/// A blinded signing key: a scalar and nonce prefix, with no seed behind them.
pub struct BlindedSigningKey {
    scalar: Scalar,
    prefix: [u8; 32],
    public: [u8; 32],
}

impl BlindedSigningKey {
    pub fn public_bytes(&self) -> [u8; 32] { self.public }
}

/// Blind a **secret** key: what the hidden service does before signing.
///
/// `seed` is the 32-byte Ed25519 secret (`SigningKey::to_bytes()`).
pub fn blind_secret(seed: &[u8; 32], period: u64, salt: &str) -> BlindedSigningKey {
    // Recover the scalar and nonce prefix the way RFC 8032 does.
    let hash = Sha512::digest(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&hash[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a_bytes);

    let identity_pub = (&a * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let h = blinding_factor(&identity_pub, period, salt);
    let blinded_scalar = h * a;

    // Blind the nonce prefix too. Two blinded keys sharing a prefix would
    // sign different messages under different scalars with the same nonce,
    // and that leaks both scalars.
    let mut ph = Sha512::new();
    ph.update(b"phinet-hs-blind-prefix-v1");
    ph.update(&hash[32..]);
    ph.update(period.to_be_bytes());
    ph.update(salt.as_bytes());
    let pd = ph.finalize();
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&pd[..32]);

    let public = (&blinded_scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    BlindedSigningKey { scalar: blinded_scalar, prefix, public }
}

/// Sign with a blinded key, per RFC 8032.
pub fn sign_blinded(k: &BlindedSigningKey, msg: &[u8]) -> [u8; 64] {
    // r = H(prefix, msg) — deterministic, so no RNG can fail us here.
    let mut h = Sha512::new();
    h.update(k.prefix);
    h.update(msg);
    let r = Scalar::from_hash(h);

    let cap_r = (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    // k_hash = H(R, A, msg)
    let mut h2 = Sha512::new();
    h2.update(cap_r);
    h2.update(k.public);
    h2.update(msg);
    let kh = Scalar::from_hash(h2);

    let s = r + kh * k.scalar;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&cap_r);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// Verify a blinded signature. Ordinary Ed25519 verification — the blinded
/// key is a normal public key, which is the point: a directory needs no
/// special code, and learns nothing extra by running it.
pub fn verify_blinded(blinded_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = match VerifyingKey::from_bytes(blinded_pub) { Ok(v) => v, Err(_) => return false };
    let s = Signature::from_bytes(sig);
    vk.verify(msg, &s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    #[test]
    fn client_and_service_derive_the_same_blinded_key() {
        // The load-bearing property. The client blinds the public key it read
        // from the address; the service blinds its secret. If these disagree,
        // nobody can find anything.
        let (seed, pubk) = keypair();
        let from_secret = blind_secret(&seed, 42, "salt").public_bytes();
        let from_public = blind_public(&pubk, 42, "salt").expect("valid key");
        assert_eq!(from_secret, from_public);
    }

    #[test]
    fn a_blinded_signature_verifies_under_the_blinded_key() {
        let (seed, _) = keypair();
        let k = blind_secret(&seed, 7, "salt");
        let sig = sign_blinded(&k, b"descriptor");
        assert!(verify_blinded(&k.public_bytes(), b"descriptor", &sig));
    }

    #[test]
    fn a_directory_can_verify_without_knowing_the_service() {
        // A directory only ever has the blinded key. It must be able to check
        // the signature with it and nothing else.
        let (seed, pubk) = keypair();
        let k = blind_secret(&seed, 9, "salt");
        let sig = sign_blinded(&k, b"desc");
        let blinded = blind_public(&pubk, 9, "salt").unwrap();
        assert!(verify_blinded(&blinded, b"desc", &sig));
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let (seed, _) = keypair();
        let k = blind_secret(&seed, 1, "salt");
        let sig = sign_blinded(&k, b"real descriptor");
        assert!(!verify_blinded(&k.public_bytes(), b"forged descriptor", &sig));
    }

    #[test]
    fn the_blinded_key_is_not_the_identity_key() {
        // If these matched, the directory would be holding the identity and
        // blinding would be theatre.
        let (seed, pubk) = keypair();
        assert_ne!(blind_secret(&seed, 1, "salt").public_bytes(), pubk);
    }

    #[test]
    fn periods_are_unlinkable() {
        // A directory that sees the same service in consecutive periods must
        // not be able to tell it's the same service.
        let (_, pubk) = keypair();
        let p1 = blind_public(&pubk, 1, "salt").unwrap();
        let p2 = blind_public(&pubk, 2, "salt").unwrap();
        assert_ne!(p1, p2, "the same name every period is no better than no blinding");
    }

    #[test]
    fn the_salt_changes_the_result() {
        // So a shared random value per period can feed in and make positions
        // unpredictable in advance.
        let (_, pubk) = keypair();
        assert_ne!(blind_public(&pubk, 1, "salt-a").unwrap(),
                   blind_public(&pubk, 1, "salt-b").unwrap());
    }

    #[test]
    fn different_services_blind_differently() {
        let (_, a) = keypair();
        let (_, b) = keypair();
        assert_ne!(blind_public(&a, 1, "s").unwrap(), blind_public(&b, 1, "s").unwrap());
    }

    #[test]
    fn blinding_is_deterministic() {
        // Two clients typing the same address must reach the same directory.
        let (_, pubk) = keypair();
        assert_eq!(blind_public(&pubk, 5, "s").unwrap(), blind_public(&pubk, 5, "s").unwrap());
    }

    #[test]
    fn signatures_are_deterministic() {
        let (seed, _) = keypair();
        let k = blind_secret(&seed, 3, "s");
        assert_eq!(sign_blinded(&k, b"m"), sign_blinded(&k, b"m"));
    }

    #[test]
    fn nonces_differ_across_periods() {
        // Reusing a nonce across two different scalars leaks both. This is the
        // failure that has extracted real private keys from real systems, so
        // check the prefix actually moves.
        let (seed, _) = keypair();
        let a = blind_secret(&seed, 1, "s");
        let b = blind_secret(&seed, 2, "s");
        let sa = sign_blinded(&a, b"same message");
        let sb = sign_blinded(&b, b"same message");
        assert_ne!(&sa[..32], &sb[..32], "R must differ, or the scalars are recoverable");
    }

    #[test]
    fn a_key_from_another_period_does_not_verify() {
        let (seed, pubk) = keypair();
        let k = blind_secret(&seed, 1, "s");
        let sig = sign_blinded(&k, b"desc");
        let wrong = blind_public(&pubk, 2, "s").unwrap();
        assert!(!verify_blinded(&wrong, b"desc", &sig));
    }

    #[test]
    fn a_junk_address_is_rejected_not_panicked_on() {
        // Someone will type nonsense with the right number of characters, so
        // a bad address must return None rather than panic the daemon.
        assert!(blind_public(&[0x02u8; 32], 1, "s").is_none());

        // Note: not every 32-byte string is rejected — plenty decompress to
        // real points (0xff… does), and that's fine. Blinding a point nobody
        // holds the secret for produces a key nobody can sign under; the
        // signature check is what rejects it. This test is about not
        // crashing, not about validating addresses.
        for junk in [[0xffu8; 32], [0x03u8; 32], [0x09u8; 32]] {
            let _ = blind_public(&junk, 1, "s");   // must not panic
        }
    }

    #[test]
    fn the_blinded_key_is_a_usable_ed25519_key() {
        // Directories run stock verification against it; if blinding produced
        // a point outside the prime-order subgroup that would misbehave.
        use ed25519_dalek::VerifyingKey;
        let (seed, _) = keypair();
        let k = blind_secret(&seed, 11, "s");
        assert!(VerifyingKey::from_bytes(&k.public_bytes()).is_ok());
    }
}
