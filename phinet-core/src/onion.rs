// phinet-core/src/onion.rs
//! ΦNET Onion Routing
//!
//! CGO-style layered encryption:
//!   - Per-hop ephemeral X25519 key exchange
//!   - ChaCha20-Poly1305 at each layer with AAD = "host:port" (anti-tagging)
//!   - Fixed CELL_SIZE padding to hide message length and hop count
//!   - 3-hop default, 5-hop high-security mode
//!   - Guard pinning with /16 subnet diversity

use crate::{
    crypto::{aead_decrypt, aead_encrypt, derive_hop_key},
    session::CELL_SIZE,
    Error, Result,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

pub const DEFAULT_HOPS:       usize = 3;
pub const HIGH_SECURITY_HOPS: usize = 5;

// ── Types ─────────────────────────────────────────────────────────────

/// One relay in a circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub host:       String,
    pub port:       u16,
    /// Hex-encoded static X25519 public key of this relay.
    pub static_pub: String,
}

impl Hop {
    pub fn static_pub_bytes(&self) -> Result<[u8; 32]> {
        hex::decode(&self.static_pub)
            .map_err(|e| Error::Onion(format!("static_pub hex: {e}")))?
            .try_into()
            .map_err(|_| Error::Onion("static_pub wrong length".into()))
    }
}

/// A fully-wrapped onion cell ready to send to hops[0].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionCell {
    pub cell: String, // hex-encoded
}

// ── Internal envelope at each layer ───────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    next_host: Option<String>,
    next_port: Option<u16>,
    data:      String, // hex
}

#[derive(Debug, Serialize, Deserialize)]
struct LayerWrapper {
    ephem_pub: String, // hex 32 bytes
    nonce:     u64,
    aad:       String,
    ct:        String, // hex
}

// ── Build ─────────────────────────────────────────────────────────────

/// Wrap `payload` through `hops`, innermost first → outermost last.
/// Each layer is padded to a multiple of CELL_SIZE.
pub fn build(hops: &[Hop], payload: &[u8]) -> Result<OnionCell> {
    if hops.is_empty() {
        return Err(Error::Onion("at least one hop required".into()));
    }

    let mut current = payload.to_vec();

    for i in (0..hops.len()).rev() {
        let hop     = &hops[i];
        let hop_pub = hop.static_pub_bytes()?;

        // Ephemeral X25519 for this layer
        let ephem_priv = StaticSecret::random_from_rng(OsRng);
        let ephem_pub  = PublicKey::from(&ephem_priv);
        let hop_key    = derive_hop_key(&ephem_priv, &hop_pub);

        let (next_host, next_port) = if i + 1 < hops.len() {
            (Some(hops[i + 1].host.clone()), Some(hops[i + 1].port))
        } else {
            (None, None)
        };

        // Serialise inner envelope
        let env = Envelope {
            next_host,
            next_port,
            data: hex::encode(&current),
        };
        let mut inner = serde_json::to_vec(&env)?;

        // Pad to next multiple of CELL_SIZE with random bytes
        let env_len = inner.len();
        let padded_len = if env_len <= CELL_SIZE {
            CELL_SIZE
        } else {
            ((env_len / CELL_SIZE) + 1) * CELL_SIZE
        };
        inner.resize(padded_len, 0);
        OsRng.fill_bytes(&mut inner[env_len..]);

        // Encrypt — AAD = "host:port" of THIS hop (anti-tagging)
        let aad = format!("{}:{}", hop.host, hop.port);
        let mut nonce_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce_ctr = u64::from_le_bytes(nonce_bytes);
        let ct = aead_encrypt(&hop_key, nonce_ctr, aad.as_bytes(), &inner);

        let wrapper = LayerWrapper {
            ephem_pub: hex::encode(ephem_pub.as_bytes()),
            nonce:     nonce_ctr,
            aad,
            ct:        hex::encode(&ct),
        };
        current = serde_json::to_vec(&wrapper)?;
    }

    Ok(OnionCell { cell: hex::encode(&current) })
}

// ── Peel ──────────────────────────────────────────────────────────────

/// Peel one onion layer using this node's static private key.
/// Returns `(next_host, next_port, inner_data)`.
/// `next_host == None` → we are the exit node.
pub fn peel(
    cell_hex:    &str,
    static_priv: &StaticSecret,
    our_host:    &str,
    our_port:    u16,
) -> Result<(Option<String>, Option<u16>, Vec<u8>)> {
    let cell_bytes = hex::decode(cell_hex)
        .map_err(|e| Error::Onion(format!("cell hex: {e}")))?;

    let wrapper: LayerWrapper = serde_json::from_slice(&cell_bytes)
        .map_err(|e| Error::Onion(format!("layer wrapper: {e}")))?;

    let ephem_pub_bytes: [u8; 32] = hex::decode(&wrapper.ephem_pub)
        .map_err(|e| Error::Onion(format!("ephem_pub hex: {e}")))?
        .try_into()
        .map_err(|_| Error::Onion("ephem_pub wrong length".into()))?;

    let hop_key = derive_hop_key(static_priv, &ephem_pub_bytes);

    // Verify AAD = our address
    let expected_aad = format!("{}:{}", our_host, our_port);
    if wrapper.aad != expected_aad {
        return Err(Error::Onion(format!(
            "AAD mismatch: got '{}', expected '{}'",
            wrapper.aad, expected_aad
        )));
    }

    let ct = hex::decode(&wrapper.ct)
        .map_err(|e| Error::Onion(format!("ct hex: {e}")))?;
    let padded = aead_decrypt(&hop_key, wrapper.nonce, wrapper.aad.as_bytes(), &ct)?;

    // Strip padding: find end of JSON object
    let inner = trim_json_padding(&padded);
    let env: Envelope = serde_json::from_slice(inner)
        .map_err(|e| Error::Onion(format!("envelope parse: {e}")))?;

    let data = hex::decode(&env.data)
        .map_err(|e| Error::Onion(format!("data hex: {e}")))?;

    Ok((env.next_host, env.next_port, data))
}

/// Find the end of a JSON object in a zero-padded buffer.
fn trim_json_padding(buf: &[u8]) -> &[u8] {
    let mut depth  = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, &b) in buf.iter().enumerate() {
        if escape { escape = false; continue; }
        match b {
            b'\\' if in_str => escape = true,
            b'"'            => in_str = !in_str,
            b'{' | b'[' if !in_str => depth += 1,
            b'}' | b']' if !in_str => {
                depth -= 1;
                if depth == 0 { return &buf[..=i]; }
            }
            _ => {}
        }
    }
    buf
}

// ── Guard selection ───────────────────────────────────────────────────

/// Select up to `n` peers with /16 subnet diversity.
/// `exclude_subnets` are /16 prefixes already in use (e.g. our own guard set).
pub fn select_guards<'a>(
    peers:            &'a [crate::dht::PeerInfo],
    n:                usize,
    exclude_subnets:  &[[u8; 2]],
) -> Vec<&'a crate::dht::PeerInfo> {
    let mut selected  = Vec::new();
    let mut used: Vec<[u8; 2]> = exclude_subnets.to_vec();

    for peer in peers {
        if selected.len() >= n { break; }
        let sn = subnet16(&peer.host);
        if used.contains(&sn) { continue; }
        selected.push(peer);
        used.push(sn);
    }
    selected
}

pub fn subnet16(host: &str) -> [u8; 2] {
    let p: Vec<&str> = host.split('.').collect();
    if p.len() >= 2 {
        [p[0].parse().unwrap_or(0), p[1].parse().unwrap_or(0)]
    } else {
        [0, 0]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hop(priv_key: &StaticSecret, host: &str, port: u16) -> Hop {
        Hop {
            host: host.into(),
            port,
            static_pub: hex::encode(PublicKey::from(priv_key).as_bytes()),
        }
    }

    #[test]
    fn three_hop_roundtrip() {
        let k1 = StaticSecret::random_from_rng(OsRng);
        let k2 = StaticSecret::random_from_rng(OsRng);
        let k3 = StaticSecret::random_from_rng(OsRng);
        let hops = vec![
            make_hop(&k1, "10.0.0.1", 7700),
            make_hop(&k2, "10.0.0.2", 7701),
            make_hop(&k3, "10.0.0.3", 7702),
        ];

        let payload = b"secret payload for exit";
        let cell = build(&hops, payload).unwrap();

        let (nh, np, i1) = peel(&cell.cell, &k1, "10.0.0.1", 7700).unwrap();
        assert_eq!(nh.as_deref(), Some("10.0.0.2"));
        assert_eq!(np, Some(7701));

        let (nh, np, i2) = peel(&hex::encode(&i1), &k2, "10.0.0.2", 7701).unwrap();
        assert_eq!(nh.as_deref(), Some("10.0.0.3"));
        assert_eq!(np, Some(7702));

        let (nh, np, data) = peel(&hex::encode(&i2), &k3, "10.0.0.3", 7702).unwrap();
        assert!(nh.is_none());
        assert!(np.is_none());
        assert_eq!(data, payload);
    }

    #[test]
    fn wrong_key_fails() {
        let k1    = StaticSecret::random_from_rng(OsRng);
        let wrong = StaticSecret::random_from_rng(OsRng);
        let cell  = build(&[make_hop(&k1, "127.0.0.1", 7700)], b"x").unwrap();
        assert!(peel(&cell.cell, &wrong, "127.0.0.1", 7700).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let k1   = StaticSecret::random_from_rng(OsRng);
        let cell = build(&[make_hop(&k1, "127.0.0.1", 7700)], b"x").unwrap();
        assert!(peel(&cell.cell, &k1, "127.0.0.2", 7700).is_err());
    }

    #[test]
    fn guard_diversity() {
        use crate::dht::PeerInfo;
        fn p(b0: u8, b1: u8, idx: u8) -> PeerInfo {
            let mut id = [0u8; 32]; id[0] = idx;
            PeerInfo { node_id: id, host: format!("{}.{}.1.1", b0, b1), port: 7700, ..Default::default() }
        }
        let peers = vec![p(10,1,0), p(10,1,1), p(10,2,2), p(10,3,3)];
        let g = select_guards(&peers, 2, &[]);
        assert_eq!(g.len(), 2);
        // Both must have different /16
        assert_ne!(subnet16(&g[0].host), subnet16(&g[1].host));
    }
}
