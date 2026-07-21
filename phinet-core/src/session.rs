// phinet-core/src/session.rs
//! Per-connection forward-secret sessions with traffic padding.

use crate::{crypto::{aead_decrypt, aead_encrypt, hkdf_derive}, Result};
use rand::{rngs::OsRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const CELL_SIZE: usize = 512;

// ── Session ───────────────────────────────────────────────────────────

pub struct Session {
    send_key:   Zeroizing<[u8; 32]>,
    recv_key:   Zeroizing<[u8; 32]>,
    send_nonce: AtomicU64,
    recv_nonce: AtomicU64,
    /// Per-session 16-byte identifier derived deterministically from
    /// the shared secret. Both peers compute the same value because
    /// the derivation salt is order-invariant. Used as AEAD AAD so
    /// ciphertext can't be replayed across two distinct sessions
    /// even if (improbably) their AEAD keys collide.
    session_id: [u8; 16],
    /// Initiator-vs-responder direction. Mixed into the nonce so a
    /// hypothetical (key, nonce_ctr) collision across the two
    /// directions of a single session can't happen — direction byte
    /// guarantees uniqueness.
    is_initiator: bool,
}

impl Session {
    pub fn new(shared: &[u8], initiator: bool) -> Self {
        // Derive 64 bytes for keys + 16 bytes for session_id from
        // domain-separated KDF info labels. The session_id binds
        // every AEAD operation to this specific shared secret so an
        // attacker can't mix-and-match ciphertext across sessions.
        let km = hkdf_derive(shared, b"phinet-session-v2", b"keys", 64);
        let id_bytes = hkdf_derive(shared, b"phinet-session-v2", b"session-id", 16);
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&id_bytes);

        let (sk, rk) = if initiator {
            (km[..32].try_into().unwrap(), km[32..].try_into().unwrap())
        } else {
            (km[32..].try_into().unwrap(), km[..32].try_into().unwrap())
        };
        Self {
            send_key:    Zeroizing::new(sk),
            recv_key:    Zeroizing::new(rk),
            send_nonce:  AtomicU64::new(0),
            recv_nonce:  AtomicU64::new(0),
            session_id,
            is_initiator: initiator,
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let n = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        // AAD binds ciphertext to (session_id, send-direction). On
        // decrypt the peer constructs the matching AAD from their
        // recv direction; they only authenticate if both ends agree
        // on the session AND the direction. Tampering with the
        // packet metadata fails the AEAD check.
        let aad = self.aad_send();
        aead_encrypt(&self.send_key, self.nonce_ctr_send(n), &aad, plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let n = self.recv_nonce.fetch_add(1, Ordering::SeqCst);
        let aad = self.aad_recv();
        aead_decrypt(&self.recv_key, self.nonce_ctr_recv(n), &aad, ciphertext)
    }

    /// AAD for encrypts: 16-byte session_id + role byte (0 = data
    /// from initiator, 1 = data from responder). The role byte
    /// reflects who *sent* this packet.
    fn aad_send(&self) -> [u8; 17] {
        let mut a = [0u8; 17];
        a[..16].copy_from_slice(&self.session_id);
        a[16] = if self.is_initiator { 0 } else { 1 };
        a
    }

    /// AAD for decrypts: same session_id, opposite role byte.
    fn aad_recv(&self) -> [u8; 17] {
        let mut a = [0u8; 17];
        a[..16].copy_from_slice(&self.session_id);
        a[16] = if self.is_initiator { 1 } else { 0 };
        a
    }

    /// Nonce counter encoding for outbound packets: top bit of high
    /// byte holds the role (0=initiator, 1=responder), low 63 bits
    /// hold the per-direction counter. The nonce96() function will
    /// convert this u64 into a 96-bit ChaCha20-Poly1305 nonce.
    ///
    /// The role bit means even if both directions of a session were
    /// somehow keyed identically (a bug we don't have, but defense
    /// in depth), nonces from the two directions can never collide.
    fn nonce_ctr_send(&self, ctr: u64) -> u64 {
        let role: u64 = if self.is_initiator { 0 } else { 1 << 63 };
        (ctr & ((1 << 63) - 1)) | role
    }

    fn nonce_ctr_recv(&self, ctr: u64) -> u64 {
        let role: u64 = if self.is_initiator { 1 << 63 } else { 0 };
        (ctr & ((1 << 63) - 1)) | role
    }

    /// Derive a key for proving cert-rotation authenticity. Keyed by
    /// the session's own send_key but domain-separated so the raw
    /// AEAD key is never exposed and this key is unique per-direction.
    /// Both peers derive the same value from their (send_key, recv_key)
    /// pair because the derivation mixes both ends.
    pub fn rotation_link_key(&self) -> [u8; 32] {
        let mut material = Vec::with_capacity(64);
        // Always use the smaller key first so both sides agree.
        let a: &[u8] = self.send_key.as_ref();
        let b: &[u8] = self.recv_key.as_ref();
        if a < b {
            material.extend_from_slice(a);
            material.extend_from_slice(b);
        } else {
            material.extend_from_slice(b);
            material.extend_from_slice(a);
        }
        let out = hkdf_derive(&material, b"phinet-cert-rotate-v1", b"link", 32);
        let mut k = [0u8; 32];
        k.copy_from_slice(&out);
        k
    }
}

// ── Ephemeral keypair ─────────────────────────────────────────────────

/// One-time X25519 keypair for handshake key exchange.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] { *self.public.as_bytes() }

    pub fn dh(&self, peer: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer).to_bytes()
    }
}

// ── Traffic padding ───────────────────────────────────────────────────

pub struct TrafficPadder;

impl TrafficPadder {
    /// A dummy cell: first byte = 0xFF (PADDING marker), rest random.
    pub fn dummy_cell() -> Vec<u8> {
        let mut cell = vec![0u8; CELL_SIZE];
        cell[0] = 0xFF;
        OsRng.fill_bytes(&mut cell[1..]);
        cell
    }

    pub fn is_dummy(payload: &[u8]) -> bool {
        payload.first() == Some(&0xFF)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_encrypt_decrypt() {
        let s = [0x42u8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        let ct = alice.encrypt(b"hello");
        assert_eq!(bob.decrypt(&ct).unwrap(), b"hello");
    }

    #[test]
    fn session_bidirectional() {
        let s = [0x11u8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        assert_eq!(bob.decrypt(&alice.encrypt(b"a2b")).unwrap(), b"a2b");
        assert_eq!(alice.decrypt(&bob.encrypt(b"b2a")).unwrap(), b"b2a");
    }

    #[test]
    fn replay_rejected() {
        let s = [0x33u8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        let ct = alice.encrypt(b"msg");
        assert!(bob.decrypt(&ct).is_ok());
        assert!(bob.decrypt(&ct).is_err()); // nonce counter advanced
    }

    #[test]
    fn session_id_deterministic_across_peers() {
        // Both peers derive identical session_id from the same shared secret.
        let s = [0xAAu8; 64];
        let alice = Session::new(&s, true);
        let bob   = Session::new(&s, false);
        assert_eq!(alice.session_id, bob.session_id,
            "both peers must derive same session_id from same shared");
    }

    #[test]
    fn session_id_differs_per_shared_secret() {
        let alice1 = Session::new(&[0x11u8; 64], true);
        let alice2 = Session::new(&[0x22u8; 64], true);
        assert_ne!(alice1.session_id, alice2.session_id,
            "different shared secrets must produce different session_ids");
    }

    #[test]
    fn ciphertext_from_one_session_rejected_by_another() {
        // Two distinct sessions with totally different shared secrets
        // each produce ciphertext. Replay of session-A's ciphertext
        // through session-B's decrypt must fail — both because the
        // key differs AND because session_id AAD differs.
        let alice_a = Session::new(&[0x42u8; 64], true);
        let _bob_a  = Session::new(&[0x42u8; 64], false);
        let _alice_b = Session::new(&[0x99u8; 64], true);
        let bob_b    = Session::new(&[0x99u8; 64], false);

        let ct_a = alice_a.encrypt(b"private message session A");
        let r = bob_b.decrypt(&ct_a);
        assert!(r.is_err(),
            "ciphertext from session A must not decrypt with session B's key");
    }

    #[test]
    fn nonce_direction_byte_separates_send_and_recv() {
        // A session's nonce_ctr_send(N) and nonce_ctr_recv(N) must
        // differ — they encode opposite role bits. This means even
        // if some bug caused send_key == recv_key (which we don't
        // do, but defense in depth), nonce reuse across the two
        // directions cannot happen.
        let s = [0x55u8; 64];
        let alice = Session::new(&s, true);
        for n in [0u64, 1, 100, 99_999] {
            assert_ne!(alice.nonce_ctr_send(n), alice.nonce_ctr_recv(n),
                "send/recv nonce must differ at counter {}", n);
        }
        // Initiator and responder both compute matching pair: the
        // initiator's send corresponds to the responder's recv.
        let bob = Session::new(&s, false);
        for n in [0u64, 1, 7] {
            assert_eq!(alice.nonce_ctr_send(n), bob.nonce_ctr_recv(n),
                "alice-send must match bob-recv at counter {}", n);
        }
    }

    #[test]
    fn aad_metadata_tampering_breaks_decrypt() {
        // The AAD-binding test: an attacker who could swap the
        // 17-byte AAD in transit must cause decryption to fail.
        // Hand-craft an AAD mismatch using the low-level AEAD calls
        // to simulate the attack.
        use crate::crypto::{aead_decrypt, aead_encrypt};
        let key = [0x77u8; 32];
        let real_aad   = b"real-aad-1234567X";
        let forged_aad = b"forged-aad-12345Y";
        let ct = aead_encrypt(&key, 0, real_aad, b"top secret");
        // Decrypt with correct AAD: should succeed
        assert_eq!(aead_decrypt(&key, 0, real_aad, &ct).unwrap(), b"top secret");
        // Decrypt with forged AAD: must fail
        assert!(aead_decrypt(&key, 0, forged_aad, &ct).is_err(),
            "AAD tampering must cause AEAD failure");
    }

    #[test]
    fn dummy_cell_marker() {
        let d = TrafficPadder::dummy_cell();
        assert_eq!(d.len(), CELL_SIZE);
        assert!(TrafficPadder::is_dummy(&d));
        assert!(!TrafficPadder::is_dummy(&[0x00u8, 0x01]));
    }

    #[test]
    fn ephemeral_keypair_dh() {
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();
        assert_eq!(a.dh(&b.public), b.dh(&a.public));
    }
}
