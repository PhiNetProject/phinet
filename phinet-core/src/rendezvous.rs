// phinet-core/src/rendezvous.rs
//! Rendezvous protocol: the core primitive that keeps hidden service
//! operator IP addresses hidden from clients.
//!
//! # Flow
//!
//! ```text
//!   HS setup:
//!     HS picks 3 relays from consensus with Intro flag.
//!     HS builds 3-hop circuit to each. On each circuit:
//!       HS → Intro: ESTABLISH_INTRO(auth_key)
//!       Intro → HS: INTRO_ESTABLISHED
//!     HS publishes signed descriptor:
//!       { hs_id, intro_points: [(intro_node_id, intro_auth_pub) × 3],
//!         hs_static_b_pub, expiry_ts, sig }
//!
//!   Client connect:
//!     1. Client fetches descriptor by hs_id from HSDir ring.
//!     2. Client picks random RP from consensus.
//!     3. Client builds 3-hop circuit to RP.
//!        Client → RP: ESTABLISH_RENDEZVOUS(cookie_20_bytes)
//!        RP → Client: RENDEZVOUS_ESTABLISHED
//!     4. Client picks one intro point I from descriptor.
//!     5. Client builds 3-hop circuit to I.
//!     6. Client sends to I:
//!        INTRODUCE1(intro_auth_key, encrypted_payload)
//!        where payload = encrypt_to(hs_static_b_pub,
//!          (rp_node_id || rp_host || rp_port || cookie || X))
//!        where X is the client's fresh ntor ephemeral for end-to-end
//!        handshake with HS.
//!     7. I validates auth, sends INTRODUCE_ACK to client and
//!        forwards INTRODUCE2(encrypted_payload) on its HS-facing
//!        intro circuit to HS.
//!     8. HS receives INTRODUCE2, decrypts with its static b_secret,
//!        obtains (rp, cookie, X).
//!     9. HS builds 3-hop circuit to rp.
//!    10. HS sends RENDEZVOUS1(cookie, Y, auth) where (X, Y) ntor-
//!        derives the end-to-end keys.
//!    11. RP looks up cookie, finds client's circuit, splices by
//!        sending RENDEZVOUS2(Y, auth) on it.
//!    12. Client verifies auth, installs end-to-end keys.
//!
//!   Now: client's 3-hop-to-RP + HS's 3-hop-to-RP = 6-hop end-to-end
//!        onion path, encrypted end-to-end with ntor keys neither RP
//!        nor intro can see. Neither side knows the other's IP. ✓
//!
//! # What this module provides
//!
//! * [`IntroState`] — per-intro-circuit state on both HS and intro sides
//! * [`RendezvousState`] — per-RP-circuit state with cookie lookup
//! * Wire-format encoders/decoders for all 5 rendezvous payloads
//! * Encryption of the INTRODUCE1 payload to the HS's static key
//! * Verification of the RENDEZVOUS handshake
//!
//! The `CircuitManager` drives these; this module is pure data + codec.

use crate::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Protocol identifier tag woven into every MAC and KDF in the HS
/// layer, so keys derived here cannot collide with ntor circuit keys.
pub const HS_PROTOID: &[u8] = b"phinet-hs-rendezvous-v1";

/// Cookie size: 20 bytes is enough entropy to make collision
/// infeasible while fitting comfortably in one cell.
pub const COOKIE_LEN: usize = 20;

/// Plaintext layout for the encrypted INTRODUCE1 blob:
///   RP_NODE_ID (32) || COOKIE (20) || RP_HOST (20 padded) || RP_PORT (2) = 74
pub const INTRO1_PLAINTEXT_LEN: usize = 32 + COOKIE_LEN + 20 + 2;

/// Auth tag on RENDEZVOUS1/2: 32 bytes HMAC-SHA256 truncation.
pub const HS_AUTH_LEN: usize = 32;

// ── ESTABLISH_INTRO ───────────────────────────────────────────────────
//
// HS → Intro: "I am hs_id, accept INTRODUCE1s signed with this auth key"
// Payload:
//   AUTH_KEY_TYPE  u8    = 2 (Ed25519) — currently we use x25519 for simplicity
//   AUTH_KEY_LEN   u16   = 32
//   AUTH_KEY       [u8]  hs_intro_auth_pub
//   HANDSHAKE_AUTH u32   = 0 (reserved for future extensions)
//   SIG_LEN        u16   = 32
//   SIG            [u8]  HMAC-SHA256(intro_circuit_digest, "intro")

#[derive(Clone, Debug)]
pub struct EstablishIntro {
    pub auth_key_pub: [u8; 32],
    pub sig:          [u8; 32],
}

impl EstablishIntro {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 32 + 4 + 2 + 32);
        out.push(2u8);                         // auth key type
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(&self.auth_key_pub);
        out.extend_from_slice(&0u32.to_be_bytes());  // reserved
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 + 32 + 4 + 2 + 32 {
            return Err(Error::Crypto("establish_intro: too short".into()));
        }
        if buf[0] != 2 {
            return Err(Error::Crypto("establish_intro: unsupported auth type".into()));
        }
        let key_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if key_len != 32 || buf.len() < 3 + 32 + 4 + 2 + 32 {
            return Err(Error::Crypto("establish_intro: bad auth_key_len".into()));
        }
        let mut auth_key_pub = [0u8; 32];
        auth_key_pub.copy_from_slice(&buf[3..35]);
        // skip reserved u32 at [35..39], sig_len u16 at [39..41]
        let sig_len = u16::from_be_bytes([buf[39], buf[40]]) as usize;
        if sig_len != 32 || buf.len() < 41 + 32 {
            return Err(Error::Crypto("establish_intro: bad sig_len".into()));
        }
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&buf[41..73]);
        Ok(Self { auth_key_pub, sig })
    }
}

// ── ESTABLISH_RENDEZVOUS ──────────────────────────────────────────────
//
// Client → RP: "register cookie C and splice to my circuit when it arrives"
// Payload: just the 20-byte cookie.

#[derive(Clone, Debug)]
pub struct EstablishRendezvous {
    pub cookie: [u8; COOKIE_LEN],
}

impl EstablishRendezvous {
    pub fn encode(&self) -> Vec<u8> { self.cookie.to_vec() }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < COOKIE_LEN {
            return Err(Error::Crypto("establish_rendezvous: too short".into()));
        }
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&buf[..COOKIE_LEN]);
        Ok(Self { cookie })
    }
}

// ── INTRODUCE1 / INTRODUCE2 ───────────────────────────────────────────
//
// Introduce1 is client → intro. Introduce2 is intro → HS (same bytes,
// intro just forwards). The header tells the intro which auth key
// this is for; the encrypted payload is opaque to the intro.

#[derive(Clone, Debug)]
pub struct Introduce {
    /// Which intro auth key this is targeting (intro uses this to look
    /// up which HS circuit to forward on).
    pub auth_key_pub: [u8; 32],
    /// Client ntor ephemeral — server (HS) uses this with its static b
    /// to derive end-to-end keys. Kept in clear because the client's
    /// identity is never implied by X.
    pub client_ntor_x: [u8; 32],
    /// Symmetric-encrypted blob containing (rp_node_id, rp_addr, cookie).
    /// Encrypted to HS's static x25519 pub using client_ntor_x as the
    /// ephemeral, ChaCha20 of the stream with HKDF-derived key.
    pub enc_payload:  Vec<u8>,
    /// HMAC tag over the encrypted blob.
    pub mac:          [u8; 32],
}

#[derive(Clone, Debug)]
pub struct IntroducePlaintext {
    pub rp_node_id: [u8; 32],
    pub rp_host:    String,    // IPv4 dotted
    pub rp_port:    u16,
    pub cookie:     [u8; COOKIE_LEN],
}

impl Introduce {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 2 + self.enc_payload.len() + 32);
        out.extend_from_slice(&self.auth_key_pub);
        out.extend_from_slice(&self.client_ntor_x);
        out.extend_from_slice(&(self.enc_payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.enc_payload);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 + 32 + 2 + 32 {
            return Err(Error::Crypto("introduce: too short".into()));
        }
        let mut auth_key_pub  = [0u8; 32]; auth_key_pub.copy_from_slice(&buf[0..32]);
        let mut client_ntor_x = [0u8; 32]; client_ntor_x.copy_from_slice(&buf[32..64]);
        let enc_len = u16::from_be_bytes([buf[64], buf[65]]) as usize;
        if buf.len() < 66 + enc_len + 32 {
            return Err(Error::Crypto("introduce: truncated".into()));
        }
        let enc_payload = buf[66..66 + enc_len].to_vec();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[66 + enc_len..66 + enc_len + 32]);
        Ok(Self { auth_key_pub, client_ntor_x, enc_payload, mac })
    }

    /// Build a complete INTRODUCE1 payload. The caller supplies the
    /// HS's published static x25519 pub and the plaintext info.
    pub fn build_for_hs(
        hs_static_b_pub: &[u8; 32],
        auth_key_pub:    &[u8; 32],
        plaintext:       &IntroducePlaintext,
    ) -> (Self, StaticSecret) {
        // Fresh client ephemeral — used both for encryption and as the
        // ntor X for end-to-end handshake.
        let client_sk = StaticSecret::random_from_rng(OsRng);
        Self::build_for_hs_with_ephemeral(hs_static_b_pub, auth_key_pub, plaintext, client_sk)
    }

    /// Build INTRODUCE using a caller-supplied ephemeral.
    ///
    /// The client must use the same ephemeral it stashed in its
    /// pending_rendezvous state at `establish_rendezvous_on` time —
    /// otherwise the HS computes AUTH over one X while the client
    /// verifies AUTH over a different X, and verification fails.
    ///
    /// This was a real bug caught by the `rendezvous_e2e` integration
    /// test: `build_for_hs` generated a fresh ephemeral every call,
    /// which meant `send_introduce1` used one X but the client's
    /// stashed pending_rendezvous held a different X1.
    pub fn build_for_hs_with_ephemeral(
        hs_static_b_pub: &[u8; 32],
        auth_key_pub:    &[u8; 32],
        plaintext:       &IntroducePlaintext,
        client_sk:       StaticSecret,
    ) -> (Self, StaticSecret) {
        let client_x  = *PublicKey::from(&client_sk).as_bytes();

        // ECDH with HS's static b
        let hs_b = PublicKey::from(*hs_static_b_pub);
        let shared = Zeroizing::new(client_sk.diffie_hellman(&hs_b).to_bytes());

        // HKDF to derive (stream_key, mac_key)
        let (stream_key, mac_key) = derive_intro_keys(shared.as_ref(), &client_x, hs_static_b_pub);

        // Plaintext: rp_node_id (32) || cookie (20) || rp_host pad (16) || rp_port (2)
        let pt = encode_intro_plaintext(plaintext);

        // ChaCha20 stream cipher over plaintext
        let mut ct = pt.clone();
        apply_chacha20(&stream_key, &mut ct);

        // HMAC-SHA256 over (auth_key_pub || client_x || ciphertext)
        let mac = hmac_intro(&mac_key, auth_key_pub, &client_x, &ct);

        (Self {
            auth_key_pub:  *auth_key_pub,
            client_ntor_x: client_x,
            enc_payload:   ct,
            mac,
        }, client_sk)
    }

    /// HS side: decrypt INTRODUCE2 payload using the HS's static
    /// b_secret. Verifies MAC before returning plaintext.
    pub fn open_at_hs(
        &self,
        hs_b_secret:     &StaticSecret,
        hs_static_b_pub: &[u8; 32],
    ) -> Result<IntroducePlaintext> {
        let client_x_pub = PublicKey::from(self.client_ntor_x);
        let shared = Zeroizing::new(hs_b_secret.diffie_hellman(&client_x_pub).to_bytes());

        let (stream_key, mac_key) = derive_intro_keys(
            shared.as_ref(), &self.client_ntor_x, hs_static_b_pub);

        let expected = hmac_intro(
            &mac_key, &self.auth_key_pub, &self.client_ntor_x, &self.enc_payload);
        if !ct_eq_32(&expected, &self.mac) {
            return Err(Error::AuthFailed);
        }

        let mut pt = self.enc_payload.clone();
        apply_chacha20(&stream_key, &mut pt);
        decode_intro_plaintext(&pt)
    }
}

fn encode_intro_plaintext(p: &IntroducePlaintext) -> Vec<u8> {
    let mut out = Vec::with_capacity(INTRO1_PLAINTEXT_LEN);
    out.extend_from_slice(&p.rp_node_id);
    out.extend_from_slice(&p.cookie);
    let mut host_bytes = [0u8; 20];
    let hb = p.rp_host.as_bytes();
    let hlen = hb.len().min(20);
    host_bytes[..hlen].copy_from_slice(&hb[..hlen]);
    out.extend_from_slice(&host_bytes[..20]);
    out.extend_from_slice(&p.rp_port.to_be_bytes());
    assert_eq!(out.len(), INTRO1_PLAINTEXT_LEN);
    out
}

fn decode_intro_plaintext(buf: &[u8]) -> Result<IntroducePlaintext> {
    if buf.len() < INTRO1_PLAINTEXT_LEN {
        return Err(Error::Crypto("intro plaintext: too short".into()));
    }
    let mut rp_node_id = [0u8; 32]; rp_node_id.copy_from_slice(&buf[0..32]);
    let mut cookie     = [0u8; 20]; cookie.copy_from_slice(&buf[32..52]);
    let host_raw       = &buf[52..72];
    let hlen           = host_raw.iter().position(|&b| b == 0).unwrap_or(20);
    let rp_host        = String::from_utf8_lossy(&host_raw[..hlen]).to_string();
    let rp_port        = u16::from_be_bytes([buf[72], buf[73]]);
    Ok(IntroducePlaintext { rp_node_id, rp_host, rp_port, cookie })
}

// ── RENDEZVOUS1 / RENDEZVOUS2 ─────────────────────────────────────────
//
// RENDEZVOUS1: HS → RP: (cookie || Y || AUTH). RP looks up cookie.
// RENDEZVOUS2: RP → client: (Y || AUTH). Client verifies AUTH.

#[derive(Clone, Debug)]
pub struct Rendezvous1 {
    pub cookie: [u8; COOKIE_LEN],
    pub server_y: [u8; 32],
    pub auth: [u8; HS_AUTH_LEN],
}

impl Rendezvous1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COOKIE_LEN + 32 + HS_AUTH_LEN);
        out.extend_from_slice(&self.cookie);
        out.extend_from_slice(&self.server_y);
        out.extend_from_slice(&self.auth);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < COOKIE_LEN + 32 + HS_AUTH_LEN {
            return Err(Error::Crypto("rendezvous1: too short".into()));
        }
        let mut cookie   = [0u8; COOKIE_LEN]; cookie.copy_from_slice(&buf[0..COOKIE_LEN]);
        let mut server_y = [0u8; 32];         server_y.copy_from_slice(&buf[COOKIE_LEN..COOKIE_LEN+32]);
        let mut auth     = [0u8; HS_AUTH_LEN];
        auth.copy_from_slice(&buf[COOKIE_LEN+32..COOKIE_LEN+32+HS_AUTH_LEN]);
        Ok(Self { cookie, server_y, auth })
    }
}

#[derive(Clone, Debug)]
pub struct Rendezvous2 {
    pub server_y: [u8; 32],
    pub auth:     [u8; HS_AUTH_LEN],
}

impl Rendezvous2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + HS_AUTH_LEN);
        out.extend_from_slice(&self.server_y);
        out.extend_from_slice(&self.auth);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 + HS_AUTH_LEN {
            return Err(Error::Crypto("rendezvous2: too short".into()));
        }
        let mut server_y = [0u8; 32]; server_y.copy_from_slice(&buf[0..32]);
        let mut auth     = [0u8; HS_AUTH_LEN]; auth.copy_from_slice(&buf[32..32+HS_AUTH_LEN]);
        Ok(Self { server_y, auth })
    }
}

// ── End-to-end handshake (client ↔ HS) ────────────────────────────────

/// Keys installed end-to-end between client and HS after a successful
/// rendezvous. Same layout as `NtorKeys` but scoped to the HS circuit.
pub struct E2EKeys {
    pub client_to_hs_key: Zeroizing<[u8; 32]>,
    pub hs_to_client_key: Zeroizing<[u8; 32]>,
    pub c2h_digest_seed:  [u8; 20],
    pub h2c_digest_seed:  [u8; 20],
}

/// HS side: given client X (from INTRODUCE2), derive end-to-end keys
/// and produce the AUTH tag to include in RENDEZVOUS1.
pub fn hs_finalize(
    hs_b_secret:  &StaticSecret,
    hs_b_pub:     &[u8; 32],
    client_x_pub: &[u8; 32],
) -> (E2EKeys, [u8; 32], [u8; HS_AUTH_LEN]) {
    // HS fresh ephemeral Y
    let y_sk = StaticSecret::random_from_rng(OsRng);
    let y_pub = *PublicKey::from(&y_sk).as_bytes();

    let x_pub = PublicKey::from(*client_x_pub);
    let ss_xy = Zeroizing::new(y_sk.diffie_hellman(&x_pub).to_bytes());
    let ss_xb = Zeroizing::new(hs_b_secret.diffie_hellman(&x_pub).to_bytes());

    let keys = expand_e2e(ss_xy.as_ref(), ss_xb.as_ref(), client_x_pub, &y_pub, hs_b_pub);
    let auth = compute_e2e_auth(&keys, client_x_pub, &y_pub, hs_b_pub, true);
    (keys, y_pub, auth)
}

/// Client side: given HS Y (from RENDEZVOUS2) and HS static B, verify
/// AUTH and derive the same end-to-end keys.
pub fn client_finalize(
    client_x_sk:   &StaticSecret,
    client_x_pub:  &[u8; 32],
    hs_b_pub:      &[u8; 32],
    server_y_pub:  &[u8; 32],
    received_auth: &[u8; HS_AUTH_LEN],
) -> Result<E2EKeys> {
    let y = PublicKey::from(*server_y_pub);
    let b = PublicKey::from(*hs_b_pub);
    let ss_xy = Zeroizing::new(client_x_sk.diffie_hellman(&y).to_bytes());
    let ss_xb = Zeroizing::new(client_x_sk.diffie_hellman(&b).to_bytes());

    let keys = expand_e2e(ss_xy.as_ref(), ss_xb.as_ref(), client_x_pub, server_y_pub, hs_b_pub);
    let expected = compute_e2e_auth(&keys, client_x_pub, server_y_pub, hs_b_pub, true);
    if !ct_eq_32(&expected, received_auth) {
        return Err(Error::AuthFailed);
    }
    Ok(keys)
}

// ── KDF / MAC helpers ─────────────────────────────────────────────────

fn derive_intro_keys(shared: &[u8], client_x: &[u8; 32], hs_b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hkdf::Hkdf;
    let mut salt = Vec::with_capacity(HS_PROTOID.len() + 64);
    salt.extend_from_slice(HS_PROTOID);
    salt.extend_from_slice(b":intro:");
    salt.extend_from_slice(client_x);
    salt.extend_from_slice(hs_b);
    let h = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut keys = [0u8; 64];
    h.expand(b"intro-keys", &mut keys).expect("hkdf intro");
    let mut stream = [0u8; 32]; stream.copy_from_slice(&keys[0..32]);
    let mut mac    = [0u8; 32]; mac.copy_from_slice(&keys[32..64]);
    (stream, mac)
}

fn hmac_intro(mac_key: &[u8; 32], auth_pub: &[u8; 32], client_x: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("hmac");
    mac.update(HS_PROTOID);
    mac.update(b":intro-mac:");
    mac.update(auth_pub);
    mac.update(client_x);
    mac.update(ct);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn apply_chacha20(key: &[u8; 32], buf: &mut [u8]) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;
    let nonce = [0u8; 12]; // one-time key per shared secret — nonce can be fixed
    let mut c = ChaCha20::new(key.into(), (&nonce).into());
    c.apply_keystream(buf);
}

fn expand_e2e(
    ss_xy:   &[u8],
    ss_xb:   &[u8],
    x_pub:   &[u8; 32],
    y_pub:   &[u8; 32],
    b_pub:   &[u8; 32],
) -> E2EKeys {
    use hkdf::Hkdf;
    let mut ikm = Vec::with_capacity(32*5 + HS_PROTOID.len());
    ikm.extend_from_slice(ss_xy);
    ikm.extend_from_slice(ss_xb);
    ikm.extend_from_slice(x_pub);
    ikm.extend_from_slice(y_pub);
    ikm.extend_from_slice(b_pub);
    ikm.extend_from_slice(HS_PROTOID);

    let h = Hkdf::<Sha256>::new(Some(b"phinet-hs-e2e-salt"), &ikm);
    let mut km = [0u8; 32 + 32 + 20 + 20];
    h.expand(b"e2e-expand", &mut km).expect("hkdf e2e");

    let mut c2h = [0u8; 32]; c2h.copy_from_slice(&km[0..32]);
    let mut h2c = [0u8; 32]; h2c.copy_from_slice(&km[32..64]);
    let mut c2hd = [0u8; 20]; c2hd.copy_from_slice(&km[64..84]);
    let mut h2cd = [0u8; 20]; h2cd.copy_from_slice(&km[84..104]);

    E2EKeys {
        client_to_hs_key: Zeroizing::new(c2h),
        hs_to_client_key: Zeroizing::new(h2c),
        c2h_digest_seed:  c2hd,
        h2c_digest_seed:  h2cd,
    }
}

fn compute_e2e_auth(
    keys:    &E2EKeys,
    x_pub:   &[u8; 32],
    y_pub:   &[u8; 32],
    b_pub:   &[u8; 32],
    _server: bool,
) -> [u8; HS_AUTH_LEN] {
    use hmac::{Hmac, Mac};
    // Use one of the keys as MAC key; safe because both sides derive it.
    let mac_key: [u8; 32] = *keys.client_to_hs_key;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).expect("hmac");
    mac.update(HS_PROTOID);
    mac.update(b":e2e-auth:");
    mac.update(x_pub);
    mac.update(y_pub);
    mac.update(b_pub);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HS_AUTH_LEN];
    out.copy_from_slice(&tag[..HS_AUTH_LEN]);
    out
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    crate::timing::ct_eq_32(a, b)
}

// ── Cookie helper ─────────────────────────────────────────────────────

pub fn fresh_cookie() -> [u8; COOKIE_LEN] {
    let mut c = [0u8; COOKIE_LEN];
    OsRng.fill_bytes(&mut c);
    c
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establish_intro_roundtrip() {
        let msg = EstablishIntro { auth_key_pub: [0xAA; 32], sig: [0xBB; 32] };
        let enc = msg.encode();
        let dec = EstablishIntro::decode(&enc).unwrap();
        assert_eq!(dec.auth_key_pub, msg.auth_key_pub);
        assert_eq!(dec.sig,          msg.sig);
    }

    #[test]
    fn establish_rendezvous_roundtrip() {
        let msg = EstablishRendezvous { cookie: [0x42; COOKIE_LEN] };
        let enc = msg.encode();
        let dec = EstablishRendezvous::decode(&enc).unwrap();
        assert_eq!(dec.cookie, msg.cookie);
    }

    #[test]
    fn intro_plaintext_roundtrip() {
        let pt = IntroducePlaintext {
            rp_node_id: [0xCC; 32],
            rp_host:    "192.168.1.42".into(),
            rp_port:    7700,
            cookie:     [0xDD; COOKIE_LEN],
        };
        let enc = encode_intro_plaintext(&pt);
        let dec = decode_intro_plaintext(&enc).unwrap();
        assert_eq!(dec.rp_node_id, pt.rp_node_id);
        assert_eq!(dec.rp_host,    pt.rp_host);
        assert_eq!(dec.rp_port,    pt.rp_port);
        assert_eq!(dec.cookie,     pt.cookie);
    }

    #[test]
    fn introduce_encrypt_decrypt() {
        // HS has static key
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();

        let auth_key_pub = [0x11u8; 32];
        let plaintext = IntroducePlaintext {
            rp_node_id: [0x22; 32],
            rp_host:    "10.0.0.1".into(),
            rp_port:    9001,
            cookie:     fresh_cookie(),
        };

        let (intro, _client_sk) = Introduce::build_for_hs(&hs_pub, &auth_key_pub, &plaintext);
        // Round trip via encode/decode
        let enc = intro.encode();
        let dec = Introduce::decode(&enc).unwrap();
        assert_eq!(dec.auth_key_pub,  auth_key_pub);
        assert_eq!(dec.client_ntor_x, intro.client_ntor_x);

        // HS opens
        let opened = dec.open_at_hs(&hs_sec, &hs_pub).unwrap();
        assert_eq!(opened.rp_node_id, plaintext.rp_node_id);
        assert_eq!(opened.rp_host,    plaintext.rp_host);
        assert_eq!(opened.rp_port,    plaintext.rp_port);
        assert_eq!(opened.cookie,     plaintext.cookie);
    }

    #[test]
    fn introduce_rejects_tampered_mac() {
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();
        let (mut intro, _) = Introduce::build_for_hs(
            &hs_pub, &[0u8; 32],
            &IntroducePlaintext {
                rp_node_id: [0; 32],
                rp_host:    "1.1.1.1".into(),
                rp_port:    1,
                cookie:     [0; COOKIE_LEN],
            });
        // Flip a bit in the ciphertext
        intro.enc_payload[0] ^= 1;
        let res = intro.open_at_hs(&hs_sec, &hs_pub);
        assert!(matches!(res, Err(Error::AuthFailed)));
    }

    #[test]
    fn introduce_rejects_wrong_hs_key() {
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();

        let wrong_sec = StaticSecret::random_from_rng(OsRng);
        let wrong_pub = *PublicKey::from(&wrong_sec).as_bytes();

        let (intro, _) = Introduce::build_for_hs(
            &hs_pub, &[0u8; 32],
            &IntroducePlaintext {
                rp_node_id: [0; 32],
                rp_host:    "1.1.1.1".into(),
                rp_port:    1,
                cookie:     [0; COOKIE_LEN],
            });
        // Wrong HS tries to open
        let res = intro.open_at_hs(&wrong_sec, &wrong_pub);
        assert!(matches!(res, Err(Error::AuthFailed)));
    }

    #[test]
    fn rendezvous1_roundtrip() {
        let m = Rendezvous1 {
            cookie:   [0x11; COOKIE_LEN],
            server_y: [0x22; 32],
            auth:     [0x33; HS_AUTH_LEN],
        };
        let enc = m.encode();
        let d   = Rendezvous1::decode(&enc).unwrap();
        assert_eq!(d.cookie,   m.cookie);
        assert_eq!(d.server_y, m.server_y);
        assert_eq!(d.auth,     m.auth);
    }

    #[test]
    fn rendezvous2_roundtrip() {
        let m = Rendezvous2 { server_y: [0x77; 32], auth: [0x99; HS_AUTH_LEN] };
        let d = Rendezvous2::decode(&m.encode()).unwrap();
        assert_eq!(d.server_y, m.server_y);
        assert_eq!(d.auth,     m.auth);
    }

    #[test]
    fn e2e_handshake_symmetric() {
        // HS static key
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();

        // Client ephemeral
        let client_sk  = StaticSecret::random_from_rng(OsRng);
        let client_pub = *PublicKey::from(&client_sk).as_bytes();

        // HS finalizes
        let (hs_keys, y_pub, auth) = hs_finalize(&hs_sec, &hs_pub, &client_pub);

        // Client verifies
        let client_keys = client_finalize(&client_sk, &client_pub, &hs_pub, &y_pub, &auth).unwrap();

        // Both sides agree on keys
        assert_eq!(*hs_keys.client_to_hs_key, *client_keys.client_to_hs_key);
        assert_eq!(*hs_keys.hs_to_client_key, *client_keys.hs_to_client_key);
        assert_eq!(hs_keys.c2h_digest_seed,   client_keys.c2h_digest_seed);
        assert_eq!(hs_keys.h2c_digest_seed,   client_keys.h2c_digest_seed);
    }

    #[test]
    fn e2e_rejects_tampered_auth() {
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();
        let client_sk  = StaticSecret::random_from_rng(OsRng);
        let client_pub = *PublicKey::from(&client_sk).as_bytes();

        let (_keys, y_pub, mut auth) = hs_finalize(&hs_sec, &hs_pub, &client_pub);
        auth[0] ^= 1; // tamper

        let res = client_finalize(&client_sk, &client_pub, &hs_pub, &y_pub, &auth);
        assert!(matches!(res, Err(Error::AuthFailed)));
    }

    #[test]
    fn e2e_rejects_wrong_hs_pub() {
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();
        let client_sk  = StaticSecret::random_from_rng(OsRng);
        let client_pub = *PublicKey::from(&client_sk).as_bytes();

        let (_keys, y_pub, auth) = hs_finalize(&hs_sec, &hs_pub, &client_pub);

        // Client is told a DIFFERENT hs_pub — must fail
        let wrong_pub = [0xABu8; 32];
        let res = client_finalize(&client_sk, &client_pub, &wrong_pub, &y_pub, &auth);
        assert!(matches!(res, Err(Error::AuthFailed)));
    }

    #[test]
    fn cookie_is_random() {
        let c1 = fresh_cookie();
        let c2 = fresh_cookie();
        assert_ne!(c1, c2);
    }

    #[test]
    fn full_roundtrip_e2e_through_intro() {
        // Simulate the full INTRODUCE → RENDEZVOUS flow, cryptographically.
        // (Wire/circuit forwarding is tested in the circuit_mgr module.)
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();

        let cookie = fresh_cookie();
        let plaintext = IntroducePlaintext {
            rp_node_id: [0xF0; 32],
            rp_host:    "203.0.113.5".into(),
            rp_port:    443,
            cookie,
        };

        // Client builds INTRODUCE1
        let (intro, client_sk) = Introduce::build_for_hs(&hs_pub, &[0xAA; 32], &plaintext);
        let client_x = intro.client_ntor_x;

        // Intro forwards (no decryption)
        let forwarded = Introduce::decode(&intro.encode()).unwrap();

        // HS decrypts
        let opened = forwarded.open_at_hs(&hs_sec, &hs_pub).unwrap();
        assert_eq!(opened.cookie, cookie);

        // HS runs end-to-end handshake, producing RENDEZVOUS1
        let (hs_keys, y_pub, auth) = hs_finalize(&hs_sec, &hs_pub, &client_x);
        let r1 = Rendezvous1 { cookie, server_y: y_pub, auth };

        // RP receives RENDEZVOUS1, matches cookie, strips to RENDEZVOUS2
        assert_eq!(r1.cookie, cookie);
        let r2 = Rendezvous2 { server_y: r1.server_y, auth: r1.auth };

        // Client verifies and derives keys
        let client_keys = client_finalize(&client_sk, &client_x, &hs_pub, &r2.server_y, &r2.auth).unwrap();

        assert_eq!(*hs_keys.client_to_hs_key, *client_keys.client_to_hs_key);
    }
}
