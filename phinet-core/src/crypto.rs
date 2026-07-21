// phinet-core/src/crypto.rs
//! ΦNET Cryptographic Primitives
//!
//! Hybrid key exchange: X25519 (classical) + ML-KEM-1024 (post-quantum).
//! Session encryption: ChaCha20-Poly1305.
//! Key derivation: HKDF-SHA256.
//! Hashing: SHA-256, BLAKE2b-256.
//!
//! ## Security review fixes (May 2026)
//!
//! Issues identified in an external review and addressed here:
//!
//! - **Hard-fail on ML-KEM errors.** Previously `encap_mlkem` /
//!   `decap_mlkem` returned a zero shared secret on parse failure
//!   or empty input, allowing an attacker who substituted an empty
//!   `mlkem_ek` to silently downgrade the hybrid handshake to
//!   X25519-only. Now both functions return `Result` and propagate
//!   errors. The `hybrid_kem_x25519_only_fallback` test that
//!   previously encoded the silent-downgrade behavior has been
//!   replaced with three tests that prove malformed/empty inputs
//!   are rejected.
//!
//! - **Transcript binding in `combine`.** The HKDF salt was a
//!   static byte string `phinet-hybrid-v1`. Two handshakes with
//!   identical (x_ss, mlkem_ss) values would derive identical
//!   session keys regardless of context — a footgun for downstream
//!   protocols. Now `combine` takes a `transcript_hash` derived
//!   from the responder's pub bundle, the initiator's ephemeral
//!   pub, and the ML-KEM ciphertext. Any deviation (e.g. an
//!   attacker substituting the responder bundle in transit) yields
//!   divergent session keys and the first-packet decryption fails.
//!
//! - **AAD honored.** The `aead_encrypt` / `aead_decrypt` functions
//!   accepted an `aad` parameter but ignored it. Routing metadata
//!   that callers expected to be authenticated wasn't. Now the AAD
//!   is properly bound via `chacha20poly1305::aead::Payload`.
//!
//! See `session.rs` for the corresponding session-layer fixes
//! (session_id AAD binding, role-byte nonce hardening).
//!
//! ## Note on hybrid KEM usage
//!
//! These hybrid KEM functions are presently exercised only by
//! their own tests; the live circuit handshake uses `ntor.rs`
//! which has its own (correct, transcript-bound) KDF. The fixes
//! above harden the API for any future code that picks it up.

use crate::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem1024,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ── Static X25519 keypair (long-lived per node) ───────────────────────

pub struct StaticKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Rebuild a keypair from a persisted secret. The static key must
    /// survive restarts: it's the `B` that the consensus publishes for
    /// this relay, and clients encrypt their ntor handshake to it. A node
    /// that regenerates it on every start silently invalidates its own
    /// consensus entry — every CREATE then fails with "wrong server_id or
    /// B" and circuits can't be built through it.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] { self.secret.to_bytes() }

    pub fn public_bytes(&self) -> [u8; 32] { *self.public.as_bytes() }
}

// ── ML-KEM-1024 sizes (confirmed by test) ────────────────────────────
pub const MLKEM_EK_BYTES: usize = 1568;
pub const MLKEM_CT_BYTES: usize = 1568;
pub const MLKEM_DK_BYTES: usize = 3168;
pub const MLKEM_SS_BYTES: usize = 32;

// ── Wire key bundle ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePublicKeys {
    pub x25519_pub: String, // hex 32 bytes
    pub mlkem_ek:   String, // hex 1568 bytes
}

// ── Key generation ────────────────────────────────────────────────────

/// Generate X25519 + ML-KEM-1024 keypairs.
/// Returns (public bundle, dk_bytes, x25519 secret).
pub fn generate_keypairs() -> (WirePublicKeys, Vec<u8>, StaticSecret) {
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_public = PublicKey::from(&x_secret);
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let ek_enc   = ek.as_bytes();
    let dk_enc   = dk.as_bytes();
    let bundle = WirePublicKeys {
        x25519_pub: hex::encode(x_public.as_bytes()),
        mlkem_ek:   hex::encode(ek_enc.as_slice()),
    };
    (bundle, dk_enc.to_vec(), x_secret)
}

// ── Hybrid ciphertext ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Initiator ephemeral X25519 public key (hex 32 bytes)
    pub x25519_ephem_pub: String,
    /// ML-KEM-1024 ciphertext (hex 1568 bytes), empty = X25519 only
    pub mlkem_ct: String,
}

// ── Initiator: encapsulate ────────────────────────────────────────────

pub fn hybrid_encapsulate(
    peer: &WirePublicKeys,
) -> Result<(HybridCiphertext, Zeroizing<Vec<u8>>)> {
    // X25519 ephemeral DH
    let our_e    = StaticSecret::random_from_rng(OsRng);
    let our_epub = PublicKey::from(&our_e);
    let peer_x   = parse_x25519_pub(&peer.x25519_pub)?;
    let x_ss     = Zeroizing::new(our_e.diffie_hellman(&peer_x).to_bytes());

    // ML-KEM encapsulation. Hard-fail: if the peer's ek is malformed
    // or empty, we refuse to proceed rather than silently downgrade
    // to X25519-only. A peer that advertises a `WirePublicKeys` with
    // a missing/broken ML-KEM ek is either misconfigured or being
    // MITM'd; either way the post-quantum guarantee is gone and we
    // should not pretend otherwise.
    let (mlkem_ct_hex, mlkem_ss) = encap_mlkem(&peer.mlkem_ek)?;

    // Bind the shared secret to the handshake transcript. Without
    // this, two sessions with identical (x_ss, mlkem_ss) values
    // (e.g. via a key-reuse bug or a rogue MITM that re-runs the
    // KEM with attacker-chosen randomness) would derive identical
    // session keys. Including the transcript hash means the KDF
    // output is unique per (initiator_epub, responder_pub_bundle,
    // mlkem_ct) tuple even if the raw shared secrets collide.
    let transcript = transcript_hash(
        peer,
        our_epub.as_bytes(),
        &mlkem_ct_hex,
    );

    let shared = combine(x_ss.as_ref(), mlkem_ss.as_slice(), &transcript);
    Ok((HybridCiphertext {
        x25519_ephem_pub: hex::encode(our_epub.as_bytes()),
        mlkem_ct: mlkem_ct_hex,
    }, shared))
}

/// ML-KEM encapsulation, propagating errors up. Replaces the prior
/// silent-zero behavior that allowed a malformed/empty ek to coerce
/// the hybrid handshake into X25519-only without the caller noticing.
fn encap_mlkem(ek_hex: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
    if ek_hex.is_empty() {
        return Err(Error::Crypto("mlkem ek is empty (refusing silent downgrade)".into()));
    }
    let ek_raw = hex::decode(ek_hex)
        .map_err(|e| Error::Crypto(format!("mlkem ek hex: {e}")))?;
    if ek_raw.len() != MLKEM_EK_BYTES {
        return Err(Error::Crypto(format!(
            "mlkem ek length: got {}, expected {}",
            ek_raw.len(), MLKEM_EK_BYTES)));
    }
    let ek_enc: &ml_kem::Encoded<<MlKem1024 as KemCore>::EncapsulationKey> =
        ek_raw.as_slice().try_into()
            .map_err(|_| Error::Crypto("mlkem ek size".into()))?;
    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(ek_enc);
    let (ct, ss) = ek.encapsulate(&mut OsRng)
        .map_err(|_| Error::Crypto("mlkem encapsulate failed".into()))?;
    let ct_slice: &[u8] = ct.as_slice();
    Ok((hex::encode(ct_slice), Zeroizing::new(ss.to_vec())))
}

// ── Responder: decapsulate ────────────────────────────────────────────

pub fn hybrid_decapsulate(
    our_bundle: &WirePublicKeys,
    x_secret: &StaticSecret,
    dk_bytes: &[u8],
    ct: &HybridCiphertext,
) -> Result<Zeroizing<Vec<u8>>> {
    let peer_e = parse_x25519_pub(&ct.x25519_ephem_pub)?;
    let x_ss   = Zeroizing::new(x_secret.diffie_hellman(&peer_e).to_bytes());

    // Hard-fail on ML-KEM problems (matches encap path).
    let mlkem_ss = decap_mlkem(dk_bytes, &ct.mlkem_ct)?;

    // Independently re-derive the transcript hash from inputs the
    // responder has. If the initiator computed one transcript and we
    // compute a different one (e.g. because they sent us a ct that
    // doesn't match their stated ephemeral pub, or because our
    // bundle differs from what they thought), the resulting session
    // keys won't match and decryption of the first message fails.
    let initiator_epub: [u8; 32] = hex::decode(&ct.x25519_ephem_pub)
        .map_err(|e| Error::Crypto(format!("x25519_ephem_pub hex: {e}")))?
        .try_into()
        .map_err(|_| Error::Crypto("x25519_ephem_pub size".into()))?;
    let transcript = transcript_hash(our_bundle, &initiator_epub, &ct.mlkem_ct);

    Ok(combine(x_ss.as_ref(), mlkem_ss.as_slice(), &transcript))
}

fn decap_mlkem(dk_bytes: &[u8], ct_hex: &str) -> Result<Zeroizing<Vec<u8>>> {
    if ct_hex.is_empty() {
        return Err(Error::Crypto("mlkem ct is empty (refusing silent downgrade)".into()));
    }
    if dk_bytes.len() != MLKEM_DK_BYTES {
        return Err(Error::Crypto(format!(
            "mlkem dk length: got {}, expected {}",
            dk_bytes.len(), MLKEM_DK_BYTES)));
    }
    let ct_raw = hex::decode(ct_hex)
        .map_err(|e| Error::Crypto(format!("mlkem ct hex: {e}")))?;
    if ct_raw.len() != MLKEM_CT_BYTES {
        return Err(Error::Crypto(format!(
            "mlkem ct length: got {}, expected {}",
            ct_raw.len(), MLKEM_CT_BYTES)));
    }
    let dk_enc: &ml_kem::Encoded<<MlKem1024 as KemCore>::DecapsulationKey> =
        dk_bytes.try_into()
            .map_err(|_| Error::Crypto("mlkem dk size".into()))?;
    let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(dk_enc);
    let ct_arr: &[u8; MLKEM_CT_BYTES] = ct_raw.as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("mlkem ct size".into()))?;
    let ct: Ciphertext<MlKem1024> = (*ct_arr).into();
    let ss = dk.decapsulate(&ct)
        .map_err(|_| Error::Crypto("mlkem decapsulate failed".into()))?;
    Ok(Zeroizing::new(ss.to_vec()))
}

/// Hash of the handshake transcript: protocol label, responder's
/// static X25519 pub, responder's ML-KEM ek, initiator's ephemeral
/// X25519 pub, ML-KEM ciphertext. Used as part of the KDF input so
/// session keys are bound to the specific handshake context.
///
/// Length-prefixing every component prevents canonicalization
/// attacks where an attacker reorganizes bytes to look like a
/// different concatenation.
fn transcript_hash(
    responder: &WirePublicKeys,
    initiator_epub: &[u8; 32],
    mlkem_ct_hex: &str,
) -> [u8; 32] {
    const LABEL: &[u8] = b"phinet-hybrid-transcript-v1";
    let resp_x = hex::decode(&responder.x25519_pub).unwrap_or_default();
    let resp_ek = hex::decode(&responder.mlkem_ek).unwrap_or_default();
    let mlkem_ct = hex::decode(mlkem_ct_hex).unwrap_or_default();

    let mut h = Sha256::new();
    h.update((LABEL.len() as u32).to_be_bytes());
    h.update(LABEL);
    h.update((resp_x.len() as u32).to_be_bytes());
    h.update(&resp_x);
    h.update((resp_ek.len() as u32).to_be_bytes());
    h.update(&resp_ek);
    h.update((initiator_epub.len() as u32).to_be_bytes());
    h.update(initiator_epub);
    h.update((mlkem_ct.len() as u32).to_be_bytes());
    h.update(&mlkem_ct);
    h.finalize().into()
}

fn combine(x: &[u8], k: &[u8], transcript: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    // Domain-separated IKM: each component is length-prefixed so
    // (x, k, transcript) can't be ambiguously parsed as a different
    // concatenation. The HKDF salt is now the transcript hash —
    // sessions with different transcripts derive different keys
    // even if the raw DH outputs are identical.
    let mut ikm = Vec::with_capacity(x.len() + k.len() + 32 + 12);
    ikm.extend_from_slice(b"x25519");
    ikm.extend_from_slice(&(x.len() as u32).to_be_bytes());
    ikm.extend_from_slice(x);
    ikm.extend_from_slice(b"mlkem ");
    ikm.extend_from_slice(&(k.len() as u32).to_be_bytes());
    ikm.extend_from_slice(k);
    Zeroizing::new(hkdf_derive(&ikm, transcript, b"phinet-hybrid-v2-session", 64))
}

// ── AEAD ──────────────────────────────────────────────────────────────
//
// AAD ("additional authenticated data") is *authenticated* but not
// encrypted: the AEAD verifier rejects ciphertext if the AAD doesn't
// match what was bound at encrypt time. Used to bind ciphertext to
// metadata that mustn't be tampered with — e.g. routing target, hop
// address, session identifier, direction.
//
// Previously AAD was accepted as a parameter but ignored. That meant
// callers thought they were authenticating metadata when in fact they
// weren't. Wired through now.

pub fn aead_encrypt(key: &[u8; 32], nonce_ctr: u64, aad: &[u8], pt: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::Payload;
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(&nonce96(nonce_ctr), Payload { msg: pt, aad })
        .expect("aead encrypt")
}

pub fn aead_decrypt(key: &[u8; 32], nonce_ctr: u64, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(&nonce96(nonce_ctr), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)
}

fn nonce96(ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_le_bytes());
    Nonce::from(n)
}

// ── HKDF ──────────────────────────────────────────────────────────────

pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

// ── Per-hop onion key ─────────────────────────────────────────────────

pub fn derive_hop_key(priv_key: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    let shared = priv_key.diffie_hellman(&PublicKey::from(*peer_pub));
    hkdf_derive(shared.as_bytes(), b"phinet-onion-v1", b"hop-key", 32)
        .try_into()
        .unwrap()
}

// ── Hashing ───────────────────────────────────────────────────────────

pub fn sha256(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b, Digest as _};
    Blake2b::<blake2::digest::typenum::U32>::digest(data).into()
}

// ── Helpers ───────────────────────────────────────────────────────────

pub fn parse_x25519_pub(hex_str: &str) -> Result<PublicKey> {
    let b: [u8; 32] = hex::decode(hex_str)
        .map_err(|e| Error::Crypto(format!("x25519 hex: {e}")))?
        .try_into()
        .map_err(|_| Error::Crypto("x25519 wrong length".into()))?;
    Ok(PublicKey::from(b))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let k  = [0x42u8; 32];
        let ct = aead_encrypt(&k, 7, b"", b"hello phinet");
        assert_eq!(aead_decrypt(&k, 7, b"", &ct).unwrap(), b"hello phinet");
    }

    #[test]
    fn aead_wrong_key_fails() {
        let ct = aead_encrypt(&[1u8; 32], 0, b"", b"x");
        assert!(aead_decrypt(&[2u8; 32], 0, b"", &ct).is_err());
    }

    #[test]
    fn hkdf_is_deterministic() {
        let a = hkdf_derive(b"k", b"s", b"i", 32);
        assert_eq!(a, hkdf_derive(b"k", b"s", b"i", 32));
        assert_ne!(a, hkdf_derive(b"k2", b"s", b"i", 32));
    }

    #[test]
    fn x25519_dh_symmetric() {
        let a = StaticKeypair::generate();
        let b = StaticKeypair::generate();
        assert_eq!(
            a.secret.diffie_hellman(&b.public).as_bytes(),
            b.secret.diffie_hellman(&a.public).as_bytes(),
        );
    }

    #[test]
    fn hop_key_symmetric() {
        let a = StaticKeypair::generate();
        let b = StaticKeypair::generate();
        assert_eq!(
            derive_hop_key(&a.secret, b.public.as_bytes()),
            derive_hop_key(&b.secret, a.public.as_bytes()),
        );
    }

    #[test]
    fn hybrid_kem_full_roundtrip() {
        let (bundle, dk_bytes, x_secret) = generate_keypairs();
        let (ct, ss_i) = hybrid_encapsulate(&bundle).unwrap();
        let ss_r = hybrid_decapsulate(&bundle, &x_secret, &dk_bytes, &ct).unwrap();
        assert_eq!(*ss_i, *ss_r, "shared secrets must match");
    }

    #[test]
    fn hybrid_kem_rejects_empty_mlkem_ek() {
        // Previously this fell back to X25519-only silently. Now it
        // must fail loudly so a MITM attacker can't strip the PQ
        // contribution by sending an empty ek.
        let (mut bundle, _, _) = generate_keypairs();
        bundle.mlkem_ek = String::new();
        let r = hybrid_encapsulate(&bundle);
        assert!(r.is_err(), "must reject empty mlkem_ek");
        let e = format!("{:?}", r.err().unwrap());
        assert!(e.contains("mlkem") || e.contains("downgrade"),
            "error should mention mlkem/downgrade: {}", e);
    }

    #[test]
    fn hybrid_kem_rejects_malformed_mlkem_ek() {
        let (mut bundle, _, _) = generate_keypairs();
        bundle.mlkem_ek = "deadbeef".into();   // wrong length
        let r = hybrid_encapsulate(&bundle);
        assert!(r.is_err());
    }

    #[test]
    fn hybrid_kem_rejects_empty_ct_on_decap() {
        let (bundle, dk_bytes, x_secret) = generate_keypairs();
        let bad_ct = HybridCiphertext {
            x25519_ephem_pub: hex::encode([0x42u8; 32]),
            mlkem_ct: String::new(),
        };
        let r = hybrid_decapsulate(&bundle, &x_secret, &dk_bytes, &bad_ct);
        assert!(r.is_err(), "must reject empty mlkem_ct");
    }

    #[test]
    fn hybrid_kem_transcript_binding_detects_responder_pub_swap() {
        // An attacker who substitutes the responder's pub bundle but
        // forwards real X25519 / ML-KEM secrets would produce
        // matching shared-secret bytes. With transcript binding, the
        // KDF inputs differ and the derived session keys diverge —
        // first ciphertext fails to decrypt.
        let (real_bundle, dk_bytes, x_secret) = generate_keypairs();
        let (attacker_bundle, _, _) = generate_keypairs();

        // Initiator thinks they're talking to the real responder
        let (ct, ss_initiator) = hybrid_encapsulate(&real_bundle).unwrap();

        // Responder receives via attacker_bundle (substituted by MITM)
        let ss_responder = hybrid_decapsulate(
            &attacker_bundle, &x_secret, &dk_bytes, &ct,
        ).unwrap();

        assert_ne!(*ss_initiator, *ss_responder,
            "transcript binding must produce divergent keys when responder bundle differs");
    }

    #[test]
    fn hybrid_kem_full_roundtrip_with_nonempty_data() {
        // End-to-end: derive shared secret, use it as session key,
        // round-trip encrypt+decrypt a payload. This is the
        // integration check that the new transcript binding doesn't
        // break the regular happy path.
        let (bundle, dk_bytes, x_secret) = generate_keypairs();
        let (ct, ss_i) = hybrid_encapsulate(&bundle).unwrap();
        let ss_r = hybrid_decapsulate(&bundle, &x_secret, &dk_bytes, &ct).unwrap();
        assert_eq!(*ss_i, *ss_r);

        // Use the derived key for a session
        let key_i: [u8; 32] = ss_i[..32].try_into().unwrap();
        let key_r: [u8; 32] = ss_r[..32].try_into().unwrap();
        assert_eq!(key_i, key_r);

        let pt = b"the quick brown fox jumps over the lazy dog";
        let aad = b"phinet-test-aad";
        let ct = aead_encrypt(&key_i, 1, aad, pt);
        assert_eq!(aead_decrypt(&key_r, 1, aad, &ct).unwrap(), pt);
    }
}
