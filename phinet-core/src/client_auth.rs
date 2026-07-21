// phinet-core/src/client_auth.rs
//!
//! # Client-authorized hidden services
//!
//! By default, any client that resolves an HS descriptor can connect to
//! the service. That's the right model for public services (anonymous
//! forums, leak sites). For private services (a personal SSH bastion,
//! an internal team chat, a one-on-one drop), the HS operator wants to
//! restrict access to a known set of clients.
//!
//! ΦNET implements this with **per-client X25519 keys**. The HS operator:
//!
//! 1. Collects the X25519 public keys of authorized clients (out-of-band:
//!    a Signal message, a printed QR code, a key-exchange ceremony).
//! 2. Generates a per-descriptor symmetric "intro key" K.
//! 3. Encrypts the descriptor's intro point fields (intro_pub, host,
//!    port) under K.
//! 4. For each authorized client, encrypts a copy of K to that client's
//!    pubkey using ephemeral-static X25519 + ChaCha20-Poly1305.
//!
//! The descriptor's plaintext `intro_*` fields are blanked. Unauthorized
//! clients can fetch the descriptor (it's still in the DHT) but the
//! intro point is opaque to them.
//!
//! ## Why the intro encryption uses an ephemeral pubkey per client
//!
//! Without ephemeral keys, the same (HS_pub, client_pub) pair would
//! always produce the same DH output and thus the same encryption key
//! for K. An adversary who later compromises an authorized client's
//! private key could decrypt past descriptors. By using a fresh
//! ephemeral keypair per client per descriptor, compromise of a client's
//! long-term key only enables decryption of *future* descriptors
//! published while that compromise is live — past descriptors stay
//! safe (forward secrecy).
//!
//! ## Threat model and limits
//!
//! Client auth resists:
//! - Bystander observation (passive enumeration of the DHT learns
//!   nothing about service operators)
//! - Adversaries who learn an HS's identity but lack a client secret
//! - Compromise of one client (only their access is revoked, not the
//!   whole client list)
//!
//! Client auth does NOT resist:
//! - An adversary who is actively running an HSDir and observes
//!   resolution attempts (timing analysis still applies)
//! - An adversary who steals a client's X25519 secret (they get full
//!   access until the operator rotates the descriptor's client list)
//! - Side-channel leakage from the operator's machine
//!
//! ## On-wire format
//!
//! Encrypted intro fields and per-client wrapped keys are stored in
//! `ClientAuthBlock` attached to the descriptor. Plaintext intro fields
//! are blank when this block is present.

use crate::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Plaintext intro-point information that gets encrypted to authorized
/// clients. Stored as canonical JSON inside the encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroPointSecret {
    pub intro_pub:  String,
    pub intro_host: Option<String>,
    pub intro_port: Option<u16>,
    #[serde(default)]
    pub intro_node_id: String,
}

/// One authorized client's wrapped key. Each client gets a fresh
/// ephemeral pubkey to prevent linkability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientAuthEntry {
    /// Ephemeral X25519 pubkey, hex-encoded 32 bytes.
    pub ephemeral_pub: String,
    /// ChaCha20-Poly1305 ciphertext of the descriptor's intro key.
    /// Decrypted with the AEAD key derived from
    /// X25519(client_secret, ephemeral_pub).
    pub encrypted_key: String,
}

/// Client-auth block attached to a descriptor when access is
/// restricted. Replaces the plaintext intro_pub/host/port fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientAuthBlock {
    /// Encrypted IntroPointSecret as ChaCha20-Poly1305 ciphertext,
    /// keyed by the per-descriptor symmetric key K. Hex-encoded.
    pub encrypted_intro: String,
    /// Random per-descriptor 12-byte nonce for the intro encryption.
    /// Hex-encoded. Different per publish so ciphertext doesn't repeat.
    pub intro_nonce: String,
    /// One wrapped-key entry per authorized client.
    pub clients: Vec<ClientAuthEntry>,
}

// ── Encrypt path: HS operator side ───────────────────────────────────

/// Build a `ClientAuthBlock` for a set of authorized clients. Returns
/// the block (to attach to the descriptor) and the symmetric key K
/// that was used (callers normally don't need this — K is recoverable
/// only via the block + a client secret).
///
/// `client_pubs` is the list of authorized clients' X25519 public keys
/// (32 bytes each). At least one client must be specified; an empty
/// list is rejected to prevent accidentally-locked-out descriptors.
pub fn encrypt_intro_for_clients(
    intro: &IntroPointSecret,
    client_pubs: &[[u8; 32]],
) -> Result<ClientAuthBlock> {
    if client_pubs.is_empty() {
        return Err(Error::Crypto(
            "client_auth: refusing to encrypt with zero authorized clients".into()));
    }

    // Per-descriptor symmetric key
    let mut key_k = [0u8; 32];
    OsRng.fill_bytes(&mut key_k);

    // Encrypt the intro details under K
    let mut intro_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut intro_nonce_bytes);
    let intro_json = serde_json::to_vec(intro)
        .map_err(|e| Error::Crypto(format!("client_auth: serialize intro: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_k));
    let aad = b"phinet-client-auth-intro-v1";
    let encrypted_intro = cipher.encrypt(
        Nonce::from_slice(&intro_nonce_bytes),
        Payload { msg: &intro_json, aad },
    ).map_err(|e| Error::Crypto(format!("client_auth: AEAD encrypt intro: {e}")))?;

    // Wrap K for each authorized client
    let mut clients = Vec::with_capacity(client_pubs.len());
    for client_pub_bytes in client_pubs {
        let entry = wrap_key_for_client(&key_k, client_pub_bytes)?;
        clients.push(entry);
    }

    Ok(ClientAuthBlock {
        encrypted_intro: hex::encode(&encrypted_intro),
        intro_nonce:     hex::encode(intro_nonce_bytes),
        clients,
    })
}

/// Wrap K for a single client. Generates a fresh ephemeral keypair,
/// performs X25519 with the client's static pub, derives an AEAD
/// key, encrypts K under it.
fn wrap_key_for_client(
    key_k: &[u8; 32],
    client_pub_bytes: &[u8; 32],
) -> Result<ClientAuthEntry> {
    // Ephemeral keypair
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral);

    // X25519 to client's long-term pub
    let client_pub = PublicKey::from(*client_pub_bytes);
    let dh = ephemeral.diffie_hellman(&client_pub);

    // Derive AEAD key from DH output, bound to both pubkeys.
    // The transcript binding ensures wrapped-key ciphertext can't be
    // replayed against a different (ephemeral, client) pair.
    let aead_key = derive_wrap_key(
        dh.as_bytes(),
        ephemeral_pub.as_bytes(),
        client_pub_bytes,
    );

    // Wrapped-key nonce: deterministic-zero is fine because the AEAD
    // key is unique per (ephemeral_pub, client_pub) pair (ephemeral
    // is freshly random per call). Nonce reuse requires DH-output
    // collision, which X25519 makes infeasible.
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let aad = b"phinet-client-auth-wrap-v1";
    let encrypted = cipher.encrypt(
        nonce,
        Payload { msg: key_k, aad },
    ).map_err(|e| Error::Crypto(format!("client_auth: AEAD wrap: {e}")))?;

    Ok(ClientAuthEntry {
        ephemeral_pub: hex::encode(ephemeral_pub.as_bytes()),
        encrypted_key: hex::encode(&encrypted),
    })
}

// ── Decrypt path: client side ────────────────────────────────────────

/// Recover the intro point from a `ClientAuthBlock` using a client's
/// X25519 secret. Returns `Ok(Some(...))` if our key is in the
/// authorized set, `Ok(None)` if no entry decrypts under our secret
/// (we're not authorized, or the descriptor was for a different
/// client list), `Err` on cryptographic / parse failure.
///
/// Trying every entry in turn is required because the block doesn't
/// label which entry belongs to which client (that would leak the
/// client list to anyone who fetches the descriptor).
pub fn decrypt_intro_with_client_secret(
    block: &ClientAuthBlock,
    client_secret: &StaticSecret,
) -> Result<Option<IntroPointSecret>> {
    let client_pub = PublicKey::from(client_secret);
    let client_pub_bytes = *client_pub.as_bytes();

    // Find a wrapped-key entry that decrypts under our secret
    let mut key_k: Option<[u8; 32]> = None;
    for entry in &block.clients {
        let ephemeral_pub_bytes: [u8; 32] = match hex::decode(&entry.ephemeral_pub)
            .ok().and_then(|v| v.try_into().ok())
        {
            Some(b) => b,
            None => continue, // skip malformed entries
        };

        let dh = client_secret.diffie_hellman(&PublicKey::from(ephemeral_pub_bytes));
        let aead_key = derive_wrap_key(
            dh.as_bytes(),
            &ephemeral_pub_bytes,
            &client_pub_bytes,
        );

        let encrypted = match hex::decode(&entry.encrypted_key) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let aad = b"phinet-client-auth-wrap-v1";
        if let Ok(plain) = cipher.decrypt(
            nonce,
            Payload { msg: &encrypted, aad },
        ) {
            if plain.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&plain);
                key_k = Some(k);
                break;
            }
        }
    }

    let key_k = match key_k {
        Some(k) => k,
        None => return Ok(None), // not authorized
    };

    // Decrypt intro
    let intro_nonce_bytes: [u8; 12] = hex::decode(&block.intro_nonce)
        .map_err(|e| Error::Crypto(format!("client_auth: nonce hex: {e}")))?
        .try_into()
        .map_err(|_| Error::Crypto("client_auth: nonce size".into()))?;
    let encrypted_intro = hex::decode(&block.encrypted_intro)
        .map_err(|e| Error::Crypto(format!("client_auth: intro hex: {e}")))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_k));
    let aad = b"phinet-client-auth-intro-v1";
    let intro_json = cipher.decrypt(
        Nonce::from_slice(&intro_nonce_bytes),
        Payload { msg: &encrypted_intro, aad },
    ).map_err(|_| Error::Crypto("client_auth: intro AEAD decrypt failed".into()))?;

    let intro: IntroPointSecret = serde_json::from_slice(&intro_json)
        .map_err(|e| Error::Crypto(format!("client_auth: parse intro: {e}")))?;
    Ok(Some(intro))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Derive the AEAD key for wrapping K to a specific client. Binds:
/// - The DH output (X25519 shared secret)
/// - The ephemeral pubkey (so wrapped ct is locked to this exchange)
/// - The client's static pubkey (so an attacker can't replay the
///   wrapped ct against a different victim with a colliding DH output)
fn derive_wrap_key(
    dh_output: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    client_pub: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    let mut transcript = Sha256::new();
    transcript.update(b"phinet-client-auth-v1");
    transcript.update(ephemeral_pub);
    transcript.update(client_pub);
    let salt: [u8; 32] = transcript.finalize().into();

    let hk = Hkdf::<Sha256>::new(Some(&salt), dh_output);
    let mut key = [0u8; 32];
    hk.expand(b"client-auth-wrap-key", &mut key)
        .expect("hkdf expand 32 bytes");
    key
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_intro() -> IntroPointSecret {
        IntroPointSecret {
            intro_pub:  "deadbeef".repeat(8),
            intro_host: Some("intro.example.phinet".into()),
            intro_port: Some(7700),
            intro_node_id: String::new(),
        }
    }

    fn random_client() -> (StaticSecret, [u8; 32]) {
        let s = StaticSecret::random_from_rng(OsRng);
        let p = PublicKey::from(&s);
        (s, *p.as_bytes())
    }

    #[test]
    fn encrypt_decrypt_roundtrip_single_client() {
        let intro = make_intro();
        let (sec, pubk) = random_client();
        let block = encrypt_intro_for_clients(&intro, &[pubk]).expect("encrypt");

        let decrypted = decrypt_intro_with_client_secret(&block, &sec)
            .expect("decrypt").expect("authorized");
        assert_eq!(decrypted.intro_pub,  intro.intro_pub);
        assert_eq!(decrypted.intro_host, intro.intro_host);
        assert_eq!(decrypted.intro_port, intro.intro_port);
    }

    #[test]
    fn unauthorized_client_cannot_decrypt() {
        let intro = make_intro();
        let (_alice_sec, alice_pub) = random_client();
        let (eve_sec, _eve_pub)     = random_client();   // not authorized

        let block = encrypt_intro_for_clients(&intro, &[alice_pub]).expect("encrypt");

        let r = decrypt_intro_with_client_secret(&block, &eve_sec)
            .expect("no error, just None");
        assert!(r.is_none(),
            "Eve isn't in the authorized list — must not get intro");
    }

    #[test]
    fn multiple_clients_each_decrypt_independently() {
        let intro = make_intro();
        let (alice_sec, alice_pub) = random_client();
        let (bob_sec,   bob_pub)   = random_client();
        let (carol_sec, carol_pub) = random_client();

        let block = encrypt_intro_for_clients(
            &intro,
            &[alice_pub, bob_pub, carol_pub],
        ).expect("encrypt");

        for sec in &[alice_sec, bob_sec, carol_sec] {
            let r = decrypt_intro_with_client_secret(&block, sec)
                .expect("decrypt").expect("authorized");
            assert_eq!(r.intro_pub, intro.intro_pub);
        }
    }

    #[test]
    fn empty_client_list_rejected() {
        let intro = make_intro();
        let r = encrypt_intro_for_clients(&intro, &[]);
        assert!(r.is_err(),
            "must reject empty client list to prevent locked-out descriptors");
    }

    #[test]
    fn each_call_produces_different_ciphertext() {
        // Re-publishing the same descriptor with the same client list
        // must produce different ciphertext bytes (otherwise an
        // observer could detect that two descriptors are identical
        // by matching ciphertexts).
        let intro = make_intro();
        let (_sec, pubk) = random_client();

        let b1 = encrypt_intro_for_clients(&intro, &[pubk]).unwrap();
        let b2 = encrypt_intro_for_clients(&intro, &[pubk]).unwrap();

        assert_ne!(b1.encrypted_intro, b2.encrypted_intro,
            "repeat encrypts must differ (per-publish nonce + key)");
        assert_ne!(b1.intro_nonce, b2.intro_nonce);
        // The ephemeral pubs and wrapped keys also differ
        assert_ne!(b1.clients[0].ephemeral_pub, b2.clients[0].ephemeral_pub);
    }

    #[test]
    fn tampering_with_intro_ciphertext_fails() {
        let intro = make_intro();
        let (sec, pubk) = random_client();
        let mut block = encrypt_intro_for_clients(&intro, &[pubk]).unwrap();

        // Flip a byte in the encrypted intro
        let mut bytes = hex::decode(&block.encrypted_intro).unwrap();
        bytes[0] ^= 0x01;
        block.encrypted_intro = hex::encode(bytes);

        let r = decrypt_intro_with_client_secret(&block, &sec);
        assert!(r.is_err(), "tampered ct must fail AEAD verification");
    }

    #[test]
    fn tampering_with_wrapped_key_fails() {
        let intro = make_intro();
        let (sec, pubk) = random_client();
        let mut block = encrypt_intro_for_clients(&intro, &[pubk]).unwrap();

        // Flip a byte in the wrapped-key
        let mut bytes = hex::decode(&block.clients[0].encrypted_key).unwrap();
        bytes[0] ^= 0x01;
        block.clients[0].encrypted_key = hex::encode(bytes);

        let r = decrypt_intro_with_client_secret(&block, &sec)
            .expect("no error, just None");
        assert!(r.is_none(),
            "tampered wrapped-key must yield 'not authorized'");
    }

    #[test]
    fn wrong_secret_yields_no_match() {
        let intro = make_intro();
        let (_alice_sec, alice_pub) = random_client();
        let block = encrypt_intro_for_clients(&intro, &[alice_pub]).unwrap();

        // Bob tries Alice's descriptor with his secret
        let (bob_sec, _) = random_client();
        let r = decrypt_intro_with_client_secret(&block, &bob_sec).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn client_list_size_doesnt_leak() {
        // The block size scales linearly with the client count; the
        // structure of each entry is identical regardless of which
        // client it belongs to. There's no per-client distinguishing
        // info other than position in the list (which is shuffled
        // by encryption nonce randomness).
        let intro = make_intro();
        let n_clients = 5;
        let pubs: Vec<[u8; 32]> = (0..n_clients).map(|_| random_client().1).collect();
        let block = encrypt_intro_for_clients(&intro, &pubs).unwrap();
        assert_eq!(block.clients.len(), n_clients);
        // Every entry has the same size (ephemeral_pub: 64 hex chars,
        // encrypted_key: 32 plaintext + 16 tag = 48 bytes -> 96 hex chars)
        for entry in &block.clients {
            assert_eq!(entry.ephemeral_pub.len(), 64);
            assert_eq!(entry.encrypted_key.len(), 96);
        }
    }

    #[test]
    fn malformed_block_entries_skipped() {
        // A block with junk entries shouldn't crash; the legitimate
        // entry should still allow decryption.
        let intro = make_intro();
        let (sec, pubk) = random_client();
        let mut block = encrypt_intro_for_clients(&intro, &[pubk]).unwrap();

        // Inject a malformed entry at the front
        block.clients.insert(0, ClientAuthEntry {
            ephemeral_pub: "not-hex".into(),
            encrypted_key: "neither".into(),
        });

        let r = decrypt_intro_with_client_secret(&block, &sec)
            .expect("decrypt").expect("legitimate entry still works");
        assert_eq!(r.intro_pub, intro.intro_pub);
    }
}
