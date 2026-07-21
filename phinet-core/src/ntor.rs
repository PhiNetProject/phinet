// phinet-core/src/ntor.rs
//! ntor handshake — one-way authenticated key agreement.
//!
//! Provides forward secrecy (both sides contribute fresh ephemerals) and
//! authenticates the server's long-term static key to the client.
//! The client is NOT authenticated; this is intentional — clients want
//! anonymity, not identity.
//!
//! Used to build hop-by-hop keys during circuit construction. Each EXTEND
//! operation runs one ntor handshake between the client and the new hop,
//! with the client's message wrapped in an already-established layer.
//!
//! Hybrid post-quantum: when ntor is used inside PHINET circuits, the
//! ntor shared secret is combined with the ML-KEM-1024 shared secret
//! from the connection-level hybrid handshake, so breaking either the
//! DH layer OR the lattice layer is not enough.

use crate::{Error, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Protocol identifier. Mixed into every KDF and HMAC tag so that keys
/// derived here cannot be confused with keys derived by any other
/// protocol sharing the same primitives.
pub const PROTOID: &[u8] = b"ntor-x25519-chacha20-phinet-v1";

/// Fixed salt for HKDF-Extract. In ntor, this plays the role of
/// `t_key` from the Tor spec.
const T_KEY:    &[u8] = b"phinet:ntor:t_key";
/// Info tag for the "verify" output of KDF (used inside the AUTH MAC).
const T_VERIFY: &[u8] = b"phinet:ntor:t_verify";
/// Info tag for the final session-keys expansion.
const T_EXPAND: &[u8] = b"phinet:ntor:t_expand";
/// Per-spec, the "m_expand" personalisation, appended once to the AUTH input.
const M_SERVER: &[u8] = b"Server";

/// Bytes of keying material derived from one successful ntor handshake.
/// Layout:
///   `[0..20]`   forward_digest_seed
///   `[20..40]`  backward_digest_seed
///   `[40..72]`  forward_key   (client → hop)
///   `[72..104]` backward_key  (hop → client)
pub const NTOR_KEYS_BYTES: usize = 104;

/// Wire size of the client's initial message: `server_id | B | X`.
pub const CLIENT_HANDSHAKE_LEN: usize = 32 + 32 + 32;
/// Wire size of the server's response: `Y | AUTH`.
pub const SERVER_HANDSHAKE_LEN: usize = 32 + 32;

// ── Per-hop symmetric state ───────────────────────────────────────────

/// Symmetric state derived from one ntor handshake. Installed on both
/// sides of a circuit hop.
#[derive(Clone)]
pub struct NtorKeys {
    pub forward_digest_seed:  [u8; 20],
    pub backward_digest_seed: [u8; 20],
    pub forward_key:          Zeroizing<[u8; 32]>,
    pub backward_key:         Zeroizing<[u8; 32]>,
}

impl NtorKeys {
    /// Parse the 104-byte KDF output into the structured keys.
    fn from_bytes(km: &[u8; NTOR_KEYS_BYTES]) -> Self {
        let mut fds = [0u8; 20];
        let mut bds = [0u8; 20];
        let mut fk  = [0u8; 32];
        let mut bk  = [0u8; 32];
        fds.copy_from_slice(&km[0..20]);
        bds.copy_from_slice(&km[20..40]);
        fk.copy_from_slice(&km[40..72]);
        bk.copy_from_slice(&km[72..104]);
        Self {
            forward_digest_seed:  fds,
            backward_digest_seed: bds,
            forward_key:          Zeroizing::new(fk),
            backward_key:         Zeroizing::new(bk),
        }
    }
}

// ── Client side ───────────────────────────────────────────────────────

/// Client-side in-progress handshake. The caller must keep this value
/// alive between `client_handshake_start` and `client_handshake_finish`.
pub struct ClientHandshake {
    /// Ephemeral private key.
    x_priv: StaticSecret,
    /// Ephemeral public `X = x·G` (cached so we don't recompute).
    x_pub:  [u8; 32],
    /// Server long-term identity (not a key; just the bound node_id).
    server_id: [u8; 32],
    /// Server long-term static key `B` (public).
    server_b:  [u8; 32],
}

/// Begin a handshake. Returns the handshake state to carry forward and
/// the 96-byte message to send to the server.
pub fn client_handshake_start(
    server_id: &[u8; 32],
    server_b:  &[u8; 32],
) -> (ClientHandshake, [u8; CLIENT_HANDSHAKE_LEN]) {
    let x_priv = StaticSecret::random_from_rng(OsRng);
    let x_pub  = *PublicKey::from(&x_priv).as_bytes();

    let mut msg = [0u8; CLIENT_HANDSHAKE_LEN];
    msg[0..32].copy_from_slice(server_id);
    msg[32..64].copy_from_slice(server_b);
    msg[64..96].copy_from_slice(&x_pub);

    (ClientHandshake {
        x_priv,
        x_pub,
        server_id: *server_id,
        server_b:  *server_b,
    }, msg)
}

/// Finish the handshake using the server's 64-byte response.
/// Verifies the AUTH tag before returning keys. Constant-time compare.
pub fn client_handshake_finish(
    hs:         ClientHandshake,
    server_msg: &[u8; SERVER_HANDSHAKE_LEN],
) -> Result<NtorKeys> {
    let y_pub_bytes: [u8; 32] = server_msg[0..32].try_into().unwrap();
    let auth_recv:   [u8; 32] = server_msg[32..64].try_into().unwrap();

    let y_pub   = PublicKey::from(y_pub_bytes);
    let server_b_pub = PublicKey::from(hs.server_b);

    // Client-side exponentiations:
    //   EXP(Y, x) — forward secrecy (both ephemerals)
    //   EXP(B, x) — authenticates server's static key
    let ss_yx = Zeroizing::new(hs.x_priv.diffie_hellman(&y_pub).to_bytes());
    let ss_bx = Zeroizing::new(hs.x_priv.diffie_hellman(&server_b_pub).to_bytes());

    let (key_seed, verify) = derive_seed_verify(
        ss_yx.as_ref(),
        ss_bx.as_ref(),
        &hs.server_id,
        &hs.server_b,
        &hs.x_pub,
        &y_pub_bytes,
    );

    let auth_expect = compute_auth(
        verify.as_ref(),
        &hs.server_id,
        &hs.server_b,
        &y_pub_bytes,
        &hs.x_pub,
    );

    if !ct_eq(&auth_recv, &auth_expect) {
        return Err(Error::AuthFailed);
    }

    let mut km = [0u8; NTOR_KEYS_BYTES];
    Hkdf::<Sha256>::from_prk(key_seed.as_ref())
        .map_err(|_| Error::Crypto("ntor prk".into()))?
        .expand(T_EXPAND, &mut km)
        .map_err(|_| Error::Crypto("ntor expand".into()))?;
    Ok(NtorKeys::from_bytes(&km))
}

// ── Server side ───────────────────────────────────────────────────────

/// One-shot server handshake. Returns (keys to install, 64-byte reply
/// to send back to client).
///
/// `server_b_secret` is the server's long-term static secret; it
/// corresponds to `server_b_pub`. `server_id` is the server's PHINET
/// node_id (bound to its certificate).
pub fn server_handshake(
    server_id:       &[u8; 32],
    server_b_pub:    &[u8; 32],
    server_b_secret: &StaticSecret,
    client_msg:      &[u8; CLIENT_HANDSHAKE_LEN],
) -> Result<(NtorKeys, [u8; SERVER_HANDSHAKE_LEN])> {
    // Sanity: client must have addressed us specifically.
    if &client_msg[0..32] != server_id.as_slice()
        || &client_msg[32..64] != server_b_pub.as_slice()
    {
        return Err(Error::Handshake("ntor: wrong server_id or B".into()));
    }
    let x_pub_bytes: [u8; 32] = client_msg[64..96].try_into().unwrap();
    let x_pub = PublicKey::from(x_pub_bytes);

    // Server ephemeral
    let y_priv = StaticSecret::random_from_rng(OsRng);
    let y_pub  = *PublicKey::from(&y_priv).as_bytes();

    // Server-side exponentiations mirror client:
    //   EXP(X, y) == EXP(Y, x)
    //   EXP(X, b) == EXP(B, x)
    let ss_xy = Zeroizing::new(y_priv.diffie_hellman(&x_pub).to_bytes());
    let ss_xb = Zeroizing::new(server_b_secret.diffie_hellman(&x_pub).to_bytes());

    let (key_seed, verify) = derive_seed_verify(
        ss_xy.as_ref(),
        ss_xb.as_ref(),
        server_id,
        server_b_pub,
        &x_pub_bytes,
        &y_pub,
    );

    let auth = compute_auth(
        verify.as_ref(),
        server_id,
        server_b_pub,
        &y_pub,
        &x_pub_bytes,
    );

    let mut reply = [0u8; SERVER_HANDSHAKE_LEN];
    reply[0..32].copy_from_slice(&y_pub);
    reply[32..64].copy_from_slice(&auth);

    let mut km = [0u8; NTOR_KEYS_BYTES];
    Hkdf::<Sha256>::from_prk(key_seed.as_ref())
        .map_err(|_| Error::Crypto("ntor prk".into()))?
        .expand(T_EXPAND, &mut km)
        .map_err(|_| Error::Crypto("ntor expand".into()))?;
    Ok((NtorKeys::from_bytes(&km), reply))
}

// ── Internal KDF helpers ──────────────────────────────────────────────

/// Derive (KEY_SEED, verify) from shared secrets and handshake transcript.
/// Both values are 32 bytes. `verify` is used inside the AUTH MAC; the
/// KEY_SEED is used to expand into session keys separately.
fn derive_seed_verify(
    ss_ephem: &[u8],
    ss_static: &[u8],
    server_id: &[u8; 32],
    server_b:  &[u8; 32],
    x_pub:     &[u8; 32],
    y_pub:     &[u8; 32],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    // secret_input = EXP_ephem || EXP_static || id || B || X || Y || PROTOID
    let mut secret = Vec::with_capacity(32*6 + PROTOID.len());
    secret.extend_from_slice(ss_ephem);
    secret.extend_from_slice(ss_static);
    secret.extend_from_slice(server_id);
    secret.extend_from_slice(server_b);
    secret.extend_from_slice(x_pub);
    secret.extend_from_slice(y_pub);
    secret.extend_from_slice(PROTOID);

    // HKDF-Extract with salt = T_KEY gives the KEY_SEED.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(T_KEY), &secret);
    let mut key_seed = [0u8; 32];
    key_seed.copy_from_slice(prk.as_slice());

    // "verify" is HKDF-Expand from KEY_SEED with the T_VERIFY tag.
    let mut verify = [0u8; 32];
    Hkdf::<Sha256>::from_prk(&key_seed)
        .expect("hkdf from prk")
        .expand(T_VERIFY, &mut verify)
        .expect("hkdf expand verify");

    (Zeroizing::new(key_seed), Zeroizing::new(verify))
}

/// AUTH = HMAC-SHA256(verify, server_id || B || Y || X || PROTOID || "Server")
fn compute_auth(
    verify:    &[u8],
    server_id: &[u8; 32],
    server_b:  &[u8; 32],
    y_pub:     &[u8; 32],
    x_pub:     &[u8; 32],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(verify).expect("hmac key");
    mac.update(server_id);
    mac.update(server_b);
    mac.update(y_pub);
    mac.update(x_pub);
    mac.update(PROTOID);
    mac.update(M_SERVER);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time 32-byte equality check. Never returns early.
/// Delegates to the audited `subtle` crate via `timing::ct_eq_32`.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    crate::timing::ct_eq_32(a, b)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn server_keypair() -> ([u8; 32], [u8; 32], StaticSecret) {
        let sk     = StaticSecret::random_from_rng(OsRng);
        let pk     = *PublicKey::from(&sk).as_bytes();
        // Fake node_id from pk (in real code this is the PhiCert hash).
        let mut id = [0u8; 32];
        id.copy_from_slice(&pk);
        id[0] ^= 0xAA;
        (id, pk, sk)
    }

    #[test]
    fn ntor_full_roundtrip() {
        let (sid, spub, ssec) = server_keypair();
        let (cs, cmsg)        = client_handshake_start(&sid, &spub);
        let (srv_keys, smsg)  = server_handshake(&sid, &spub, &ssec, &cmsg).unwrap();
        let cli_keys          = client_handshake_finish(cs, &smsg).unwrap();

        // Symmetric: client's forward key matches server's forward key.
        assert_eq!(cli_keys.forward_key.as_slice(),
                   srv_keys.forward_key.as_slice());
        assert_eq!(cli_keys.backward_key.as_slice(),
                   srv_keys.backward_key.as_slice());
        assert_eq!(cli_keys.forward_digest_seed,
                   srv_keys.forward_digest_seed);
    }

    #[test]
    fn ntor_wrong_server_id_fails() {
        let (sid, spub, ssec) = server_keypair();
        let (_, cmsg)         = client_handshake_start(&sid, &spub);

        let mut bad_sid = sid;
        bad_sid[0] ^= 0x01;
        assert!(server_handshake(&bad_sid, &spub, &ssec, &cmsg).is_err());
    }

    #[test]
    fn ntor_wrong_server_b_fails() {
        let (sid, spub, ssec) = server_keypair();
        let (_, cmsg)         = client_handshake_start(&sid, &spub);

        let mut bad_b = spub;
        bad_b[0] ^= 0x01;
        assert!(server_handshake(&sid, &bad_b, &ssec, &cmsg).is_err());
    }

    #[test]
    fn ntor_tampered_auth_fails() {
        let (sid, spub, ssec) = server_keypair();
        let (cs, cmsg)        = client_handshake_start(&sid, &spub);
        let (_, mut smsg)     = server_handshake(&sid, &spub, &ssec, &cmsg).unwrap();

        // Flip one bit in AUTH.
        smsg[50] ^= 0x08;
        assert!(matches!(
            client_handshake_finish(cs, &smsg),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn ntor_wrong_static_key_fails() {
        let (sid, spub, _ssec) = server_keypair();
        let evil_sec           = StaticSecret::random_from_rng(OsRng);
        let (cs, cmsg)         = client_handshake_start(&sid, &spub);

        // An attacker tries to impersonate the server with their own secret.
        let (_, evil_reply) = server_handshake(&sid, &spub, &evil_sec, &cmsg).unwrap();

        // Client must reject: attacker's reply doesn't prove knowledge of
        // the real B's secret, so AUTH won't match.
        assert!(matches!(
            client_handshake_finish(cs, &evil_reply),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn ntor_forward_secret_across_runs() {
        // Two independent handshakes with the same server produce
        // independent session keys.
        let (sid, spub, ssec) = server_keypair();

        let (cs1, m1)          = client_handshake_start(&sid, &spub);
        let (_, r1)            = server_handshake(&sid, &spub, &ssec, &m1).unwrap();
        let k1                 = client_handshake_finish(cs1, &r1).unwrap();

        let (cs2, m2)          = client_handshake_start(&sid, &spub);
        let (_, r2)            = server_handshake(&sid, &spub, &ssec, &m2).unwrap();
        let k2                 = client_handshake_finish(cs2, &r2).unwrap();

        assert_ne!(k1.forward_key.as_slice(), k2.forward_key.as_slice());
        assert_ne!(k1.backward_key.as_slice(), k2.backward_key.as_slice());
    }

    #[test]
    fn ct_eq_constant_time() {
        let a = [0x42u8; 32];
        let mut b = a;
        assert!(ct_eq(&a, &b));
        b[17] ^= 1;
        assert!(!ct_eq(&a, &b));
    }
}
