// phinet-core/src/circuit.rs
//! Circuit layer: fixed-size cells, multiplexed streams, per-hop crypto.
//!
//! This is the wire-level primitive used to carry all inter-node
//! encrypted traffic once a circuit is built. The flow is:
//!
//!   Application → Stream (RELAY_BEGIN/DATA/END with stream_id)
//!     → Relay cell (relay_command | recognized | stream_id | digest | data)
//!     → layered ChaCha20 encryption (one layer per hop, reverse order)
//!     → Cell (circ_id | RELAY | 507-byte payload) = 512 bytes
//!     → sent over the existing connection-level Session
//!
//! This module provides the cell/relay-cell serialization and the per-hop
//! state machine. Circuit construction itself (CREATE, EXTEND2, routing
//! peel between hops) lives in the node driver.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed cell size on the wire.
pub const CELL_SIZE: usize = 512;

/// Cell header is 4-byte circ_id + 1-byte command.
pub const CELL_HEADER: usize = 5;

/// Payload bytes inside one cell (after header).
pub const CELL_PAYLOAD: usize = CELL_SIZE - CELL_HEADER; // 507

/// Relay-cell header fields, pre-data:
///   cmd(1) | recognized(2) | stream_id(2) | digest(4) | length(2) = 11 bytes
pub const RELAY_HEADER: usize = 11;

/// Maximum `data` bytes in one relay cell.
pub const RELAY_DATA_MAX: usize = CELL_PAYLOAD - RELAY_HEADER; // 496

/// Maximum hops we ever build a circuit through.
/// 3 is standard; 5 is `--high-security`. Anything longer defeats the
/// EXTEND bound and invites circuit-length correlation.
pub const MAX_HOPS: usize = 5;

/// How long a circuit can sit idle (no cells in either direction)
/// before the idle-eviction loop tears it down. Matches Tor's
/// CircuitTimeout default: circuits get expensive (key state, stream
/// muxes, hop HopStates) and a long-running daemon that never evicts
/// would leak them forever.
///
/// 1 hour is long enough that a user's occasional web browsing holds
/// the same circuit (useful: rebuilding a 3-hop circuit costs a round
/// trip per hop), but short enough that abandoned circuits don't
/// accumulate.
pub const CIRCUIT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// Number of `RELAY_EARLY` cells a client is allowed to emit per
/// circuit. Exactly `MAX_HOPS` — one per EXTEND. Enforced so a
/// compromised hop cannot silently extend the circuit further.
pub const MAX_RELAY_EARLY: u32 = MAX_HOPS as u32;

// ── Cell command ──────────────────────────────────────────────────────

/// Cell command byte. Values match the design-doc table.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellCommand {
    Padding    = 0,
    Create     = 1,
    Created    = 2,
    Relay      = 3,
    Destroy    = 4,
    RelayEarly = 5,
    Versions   = 6,
    NetInfo    = 7,
}

impl CellCommand {
    pub fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => Self::Padding,
            1 => Self::Create,
            2 => Self::Created,
            3 => Self::Relay,
            4 => Self::Destroy,
            5 => Self::RelayEarly,
            6 => Self::Versions,
            7 => Self::NetInfo,
            _ => return Err(Error::Crypto(format!("unknown cell cmd: {b}"))),
        })
    }
}

// ── Circuit ID ────────────────────────────────────────────────────────

/// Circuit identifier, unique per connection. 0 means "no circuit"
/// (reserved for connection-level commands like VERSIONS, PADDING).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CircuitId(pub u32);

impl CircuitId {
    pub const NONE: CircuitId = CircuitId(0);
    pub fn is_valid(self) -> bool { self.0 != 0 }
}

// ── Cell ──────────────────────────────────────────────────────────────

/// One fixed-size cell as seen on the wire (after Session decryption).
#[derive(Clone)]
pub struct Cell {
    pub circ_id: CircuitId,
    pub command: CellCommand,
    pub payload: [u8; CELL_PAYLOAD],
}

impl Cell {
    /// Construct a new cell with zeroed payload.
    pub fn new(circ_id: CircuitId, command: CellCommand) -> Self {
        Self { circ_id, command, payload: [0u8; CELL_PAYLOAD] }
    }

    /// Construct with explicit payload bytes (padded to full length).
    pub fn with_payload(
        circ_id: CircuitId,
        command: CellCommand,
        data:    &[u8],
    ) -> Result<Self> {
        if data.len() > CELL_PAYLOAD {
            return Err(Error::Crypto(format!(
                "cell payload too large: {} > {}",
                data.len(), CELL_PAYLOAD
            )));
        }
        let mut payload = [0u8; CELL_PAYLOAD];
        payload[..data.len()].copy_from_slice(data);
        Ok(Self { circ_id, command, payload })
    }

    /// Serialize to fixed 512 bytes.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut out = [0u8; CELL_SIZE];
        out[0..4].copy_from_slice(&self.circ_id.0.to_le_bytes());
        out[4] = self.command as u8;
        out[5..].copy_from_slice(&self.payload);
        out
    }

    /// Parse from 512 bytes.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> Result<Self> {
        let circ_id = CircuitId(u32::from_le_bytes(buf[0..4].try_into().unwrap()));
        let command = CellCommand::from_byte(buf[4])?;
        let mut payload = [0u8; CELL_PAYLOAD];
        payload.copy_from_slice(&buf[5..]);
        Ok(Self { circ_id, command, payload })
    }
}

// ── Relay command ─────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayCommand {
    // Stream ops
    Begin       = 1,
    Data        = 2,
    End         = 3,
    Connected   = 4,
    SendMe      = 5,
    // Circuit ops
    Extend2     = 6,
    Extended2   = 7,
    Truncate    = 8,
    Truncated   = 9,
    Drop        = 10,
    ComInject   = 11,
    // Hidden service ops
    EstablishIntro        = 32,
    EstablishRendezvous   = 33,
    Introduce1            = 34,
    Introduce2            = 35,
    Rendezvous1           = 36,
    Rendezvous2           = 37,
    IntroEstablished      = 38,
    RendezvousEstablished = 39,
    IntroduceAck          = 40,
}

impl RelayCommand {
    pub fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            1  => Self::Begin,
            2  => Self::Data,
            3  => Self::End,
            4  => Self::Connected,
            5  => Self::SendMe,
            6  => Self::Extend2,
            7  => Self::Extended2,
            8  => Self::Truncate,
            9  => Self::Truncated,
            10 => Self::Drop,
            11 => Self::ComInject,
            32 => Self::EstablishIntro,
            33 => Self::EstablishRendezvous,
            34 => Self::Introduce1,
            35 => Self::Introduce2,
            36 => Self::Rendezvous1,
            37 => Self::Rendezvous2,
            38 => Self::IntroEstablished,
            39 => Self::RendezvousEstablished,
            40 => Self::IntroduceAck,
            _  => return Err(Error::Crypto(format!("unknown relay cmd: {b}"))),
        })
    }
}

// ── Relay cell (inside cell payload) ──────────────────────────────────

/// Parsed relay-cell view. `data` carries the command-specific payload.
#[derive(Clone)]
pub struct RelayCell {
    pub command:    RelayCommand,
    /// Zero after successful decryption at the terminal hop; non-zero
    /// means pass through. Written by the originator as 0 and filled
    /// with random bytes by pass-through hops to prevent guessing.
    pub recognized: u16,
    pub stream_id:  u16,
    pub digest:     u32,
    pub data:       Vec<u8>,
}

impl RelayCell {
    pub fn new(cmd: RelayCommand, stream_id: u16, data: Vec<u8>) -> Result<Self> {
        if data.len() > RELAY_DATA_MAX {
            return Err(Error::Crypto(format!(
                "relay data too large: {} > {}",
                data.len(), RELAY_DATA_MAX
            )));
        }
        Ok(Self {
            command: cmd,
            recognized: 0,
            stream_id,
            digest: 0,
            data,
        })
    }

    /// Serialize relay cell into 507-byte cell payload (zero-padded).
    pub fn to_payload(&self) -> [u8; CELL_PAYLOAD] {
        let mut out = [0u8; CELL_PAYLOAD];
        out[0] = self.command as u8;
        out[1..3].copy_from_slice(&self.recognized.to_be_bytes());
        out[3..5].copy_from_slice(&self.stream_id.to_be_bytes());
        out[5..9].copy_from_slice(&self.digest.to_be_bytes());
        let len = self.data.len() as u16;
        out[9..11].copy_from_slice(&len.to_be_bytes());
        out[11..11 + self.data.len()].copy_from_slice(&self.data);
        // Remaining bytes are zero; irrelevant: cell is encrypted on the wire.
        out
    }

    /// Parse relay cell from a 507-byte payload slice.
    pub fn from_payload(buf: &[u8; CELL_PAYLOAD]) -> Result<Self> {
        let command    = RelayCommand::from_byte(buf[0])?;
        let recognized = u16::from_be_bytes(buf[1..3].try_into().unwrap());
        let stream_id  = u16::from_be_bytes(buf[3..5].try_into().unwrap());
        let digest     = u32::from_be_bytes(buf[5..9].try_into().unwrap());
        let length     = u16::from_be_bytes(buf[9..11].try_into().unwrap()) as usize;
        if length > RELAY_DATA_MAX {
            return Err(Error::Crypto(format!(
                "relay length field out of range: {length}"
            )));
        }
        let data = buf[11..11 + length].to_vec();
        Ok(Self { command, recognized, stream_id, digest, data })
    }

    /// True if this relay cell is intended for the hop that just decrypted
    /// it (rather than being passed further along). The terminal cell has
    /// recognized=0 AND a digest that matches the running hash.
    ///
    /// `running_hash` is the hop's rolling `Sha256` over all relay cells
    /// seen in this direction so far. Returns `true` and consumes the
    /// hash state on success. On mismatch returns `false` and `running_hash`
    /// is left untouched.
    pub fn is_recognized_at(&self, payload: &[u8; CELL_PAYLOAD], running: &Sha256) -> bool {
        if self.recognized != 0 {
            return false;
        }
        // Compute rolling digest: existing state + this cell with digest=0.
        let mut h = running.clone();
        let mut buf = *payload;
        // Zero out the digest field (bytes 5..9) before hashing.
        buf[5] = 0; buf[6] = 0; buf[7] = 0; buf[8] = 0;
        h.update(&buf);
        let tag = h.finalize();
        let expected = u32::from_be_bytes(tag[..4].try_into().unwrap());
        expected == self.digest
    }

    /// Stamp a correct digest into this cell using the given rolling hash.
    /// Updates `running` in place so subsequent cells chain correctly.
    pub fn stamp_digest(&mut self, running: &mut Sha256) {
        // Serialize with digest=0, update running, take first 4 bytes.
        self.digest = 0;
        let mut buf = self.to_payload();
        buf[5] = 0; buf[6] = 0; buf[7] = 0; buf[8] = 0;
        running.update(&buf);
        let tag = running.clone().finalize();
        self.digest = u32::from_be_bytes(tag[..4].try_into().unwrap());
    }
}

use zeroize::Zeroizing;

// ── Per-hop symmetric state ───────────────────────────────────────────

/// State installed after a successful ntor with a hop. Used both on the
/// client (one entry per hop in a built circuit) and on relay hops
/// (one entry per circuit this hop participates in).
///
/// Each direction carries an independent ChaCha20 keystream counter.
/// Both ends must stay synchronised — every cell sent increments the
/// sender's counter and the corresponding receiver's counter. If a cell
/// is dropped, decryption fails and the circuit should be torn down.
///
/// Keys are wrapped in `Zeroizing` so they are securely wiped on drop;
/// this prevents stale circuit keys from lingering in memory after a
/// circuit is destroyed.
pub struct HopState {
    pub forward_key:     Zeroizing<[u8; 32]>,
    pub backward_key:    Zeroizing<[u8; 32]>,
    pub forward_nonce:   u64,
    pub backward_nonce:  u64,
    pub forward_digest:  Sha256,
    pub backward_digest: Sha256,
}

impl HopState {
    pub fn from_ntor(keys: &crate::ntor::NtorKeys) -> Self {
        let mut fwd = Sha256::new();
        fwd.update(keys.forward_digest_seed);
        let mut bwd = Sha256::new();
        bwd.update(keys.backward_digest_seed);
        Self {
            forward_key:     Zeroizing::new(*keys.forward_key),
            backward_key:    Zeroizing::new(*keys.backward_key),
            forward_nonce:   0,
            backward_nonce:  0,
            forward_digest:  fwd,
            backward_digest: bwd,
        }
    }

    /// Build the innermost end-to-end layer from rendezvous `E2EKeys`.
    ///
    /// This is a `HopState` like any hop's, but it isn't a hop on the
    /// path — it's a virtual layer shared directly between client and
    /// HS, sitting *inside* the hop-onion. Applied by the sender after
    /// all its path-hop layers on outbound cells, and peeled by the
    /// receiver after all its path-hop layers on inbound cells.
    ///
    /// Orientation depends on which end we are, because `E2EKeys` names
    /// its keys by absolute direction (client→HS / HS→client) whereas
    /// `HopState` names them by relative direction (the local end's
    /// forward = "what I send", backward = "what I receive"):
    ///
    ///   * **client** (`is_client = true`): forward = client_to_hs,
    ///     backward = hs_to_client.
    ///   * **HS** (`is_client = false`): forward = hs_to_client,
    ///     backward = client_to_hs.
    ///
    /// The digest seeds follow the same swap so both ends' rolling
    /// recognition hashes stay in lockstep per direction.
    pub fn from_e2e_keys(keys: &crate::rendezvous::E2EKeys, is_client: bool) -> Self {
        let (fwd_key, bwd_key, fwd_seed, bwd_seed) = if is_client {
            (*keys.client_to_hs_key, *keys.hs_to_client_key,
             keys.c2h_digest_seed,   keys.h2c_digest_seed)
        } else {
            (*keys.hs_to_client_key, *keys.client_to_hs_key,
             keys.h2c_digest_seed,   keys.c2h_digest_seed)
        };
        let mut fwd = Sha256::new();
        fwd.update(fwd_seed);
        let mut bwd = Sha256::new();
        bwd.update(bwd_seed);
        Self {
            forward_key:     Zeroizing::new(fwd_key),
            backward_key:    Zeroizing::new(bwd_key),
            forward_nonce:   0,
            backward_nonce:  0,
            forward_digest:  fwd,
            backward_digest: bwd,
        }
    }
}

// ── Onion layer encryption (ChaCha20 stream cipher, no auth tag) ──────
//
// Authentication is end-to-end via the relay-cell digest, and hop-by-hop
// via the connection-level Session (which uses ChaCha20-Poly1305). The
// onion layer itself only needs confidentiality, so raw ChaCha20 fits
// in the fixed 512-byte cell envelope without adding 16 bytes per layer.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

fn nonce96(ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_le_bytes());
    n
}

/// Apply ChaCha20 in place with the given key and counter.
/// Encryption and decryption are the same operation (XOR with keystream).
fn crypt_in_place(key: &[u8; 32], nonce_ctr: u64, buf: &mut [u8]) {
    let n = nonce96(nonce_ctr);
    let mut c = ChaCha20::new(key.into(), (&n).into());
    c.apply_keystream(buf);
}

/// Encrypt a 507-byte payload for a specific hop (as the originator).
/// Advances `hop.forward_nonce` so subsequent cells use fresh keystream.
pub fn onion_encrypt_forward(hop: &mut HopState, payload: &mut [u8; CELL_PAYLOAD]) {
    crypt_in_place(&hop.forward_key, hop.forward_nonce, payload);
    hop.forward_nonce = hop.forward_nonce.wrapping_add(1);
}

/// Decrypt one layer of a cell in the forward direction. Called at a
/// relay hop on every incoming cell. The caller then inspects the
/// recognized field to decide whether to process locally or forward.
pub fn onion_decrypt_forward(hop: &mut HopState, payload: &mut [u8; CELL_PAYLOAD]) {
    crypt_in_place(&hop.forward_key, hop.forward_nonce, payload);
    hop.forward_nonce = hop.forward_nonce.wrapping_add(1);
}

/// Encrypt a cell going backward (away from the terminal hop, toward
/// the client). Called both by the originating hop and by intermediate
/// hops as they add their outer layer.
pub fn onion_encrypt_backward(hop: &mut HopState, payload: &mut [u8; CELL_PAYLOAD]) {
    crypt_in_place(&hop.backward_key, hop.backward_nonce, payload);
    hop.backward_nonce = hop.backward_nonce.wrapping_add(1);
}

/// Decrypt one backward layer on the client side. The client calls
/// this repeatedly (hops 0..N) until `is_recognized_at` returns true.
pub fn onion_decrypt_backward(hop: &mut HopState, payload: &mut [u8; CELL_PAYLOAD]) {
    crypt_in_place(&hop.backward_key, hop.backward_nonce, payload);
    hop.backward_nonce = hop.backward_nonce.wrapping_add(1);
}

// ── EXTEND2 / EXTENDED2 payload codec ─────────────────────────────────
//
// EXTEND2 wire layout inside a relay cell's `data` field:
//   nspec            u8         number of link specifiers (1 or 2)
//   [each spec]:
//     lspec_type     u8         0 = IPv4+port, 2 = legacy node_id (32 bytes)
//     lspec_len      u8
//     lspec_body     [u8]
//   htype            u16 BE     2 = ntor handshake
//   hlen             u16 BE     length of hdata (96 for ntor)
//   hdata            [u8]       the ntor client message
//
// EXTENDED2 layout: hlen (u16 BE) then hdata (the 64-byte ntor reply).

pub const LSPEC_IPV4:       u8 = 0;
pub const LSPEC_NODE_ID:    u8 = 2;
/// 32-byte x25519 static public key of the target hop. Required for
/// the ntor handshake: the receiver validates that the `B` in the
/// CREATE message matches its own static public key, so the client
/// must know the target's static_pub to address it correctly.
pub const LSPEC_STATIC_PUB: u8 = 3;
pub const HTYPE_NTOR:    u16 = 2;

/// Minimal identifier for "who is the next hop?" — enough for an
/// honest middle hop to open a TCP connection and match the target's
/// node_id during its own handshake.
#[derive(Clone, Debug)]
/// Information needed to extend a circuit to a specific peer: its
/// network address, node_id, and x25519 static public key. The
/// static_pub is required for the ntor handshake — without it, the
/// client can't construct a CREATE/EXTEND2 message addressed to this
/// specific peer (the receiver validates that the `B` in the message
/// matches its own static public key).
pub struct LinkSpec {
    pub host:    String,
    pub port:    u16,
    pub node_id: [u8; 32],
    /// x25519 static public key of the peer. Must match what the
    /// peer would serve in its handshake. Populated by the client
    /// from its peer-table entry.
    pub static_pub: [u8; 32],
}

/// Serialize an EXTEND2 payload for an ntor handshake to the given next
/// hop. `ntor_client_msg` is the 96-byte output of
/// `ntor::client_handshake_start`.
pub fn build_extend2(next: &LinkSpec, ntor_client_msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);

    // Three link specifiers: IPv4+port, node_id, static_pub
    out.push(3u8); // nspec

    // IPv4+port spec (6 bytes: 4 addr + 2 port)
    out.push(LSPEC_IPV4);
    out.push(6u8);
    let addr: std::net::Ipv4Addr = next.host.parse()
        .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1));
    out.extend_from_slice(&addr.octets());
    out.extend_from_slice(&next.port.to_be_bytes());

    // Node ID spec
    out.push(LSPEC_NODE_ID);
    out.push(32u8);
    out.extend_from_slice(&next.node_id);

    // Static pub spec (x25519 pubkey for ntor)
    out.push(LSPEC_STATIC_PUB);
    out.push(32u8);
    out.extend_from_slice(&next.static_pub);

    // Handshake type + data
    out.extend_from_slice(&HTYPE_NTOR.to_be_bytes());
    out.extend_from_slice(&(ntor_client_msg.len() as u16).to_be_bytes());
    out.extend_from_slice(ntor_client_msg);

    out
}

/// Parse an EXTEND2 payload. Returns (next hop link spec, ntor message).
pub fn parse_extend2(buf: &[u8]) -> Result<(LinkSpec, Vec<u8>)> {
    if buf.is_empty() {
        return Err(Error::Crypto("extend2: empty".into()));
    }
    let mut i = 0;
    let nspec = buf[i] as usize; i += 1;
    if nspec == 0 || nspec > 8 {
        return Err(Error::Crypto(format!("extend2: bad nspec {nspec}")));
    }

    let mut host    = String::new();
    let mut port    = 0u16;
    let mut node_id = [0u8; 32];
    let mut static_pub = [0u8; 32];
    let mut have_addr = false;
    let mut have_id   = false;
    let mut have_pub  = false;

    for _ in 0..nspec {
        if i + 2 > buf.len() {
            return Err(Error::Crypto("extend2: truncated spec header".into()));
        }
        let ty  = buf[i]; i += 1;
        let ln  = buf[i] as usize; i += 1;
        if i + ln > buf.len() {
            return Err(Error::Crypto("extend2: truncated spec body".into()));
        }
        let body = &buf[i..i + ln];
        i += ln;
        match ty {
            LSPEC_IPV4 if ln == 6 => {
                host = format!("{}.{}.{}.{}", body[0], body[1], body[2], body[3]);
                port = u16::from_be_bytes([body[4], body[5]]);
                have_addr = true;
            }
            LSPEC_NODE_ID if ln == 32 => {
                node_id.copy_from_slice(body);
                have_id = true;
            }
            LSPEC_STATIC_PUB if ln == 32 => {
                static_pub.copy_from_slice(body);
                have_pub = true;
            }
            _ => {} // unknown spec — ignore
        }
    }
    if !have_addr || !have_id {
        return Err(Error::Crypto("extend2: missing IPv4 or node_id spec".into()));
    }
    // static_pub is optional in the wire format for backward
    // compatibility with tests that don't carry it; but extends sent
    // by our own build_extend2 always include it. When missing, we
    // leave static_pub as zeros — the receiving hop won't be able to
    // verify the ntor handshake, which is fine: that's exactly the
    // behaviour we want (reject handshakes we can't authenticate).
    let _ = have_pub;

    if i + 4 > buf.len() {
        return Err(Error::Crypto("extend2: truncated htype/hlen".into()));
    }
    let htype = u16::from_be_bytes([buf[i], buf[i+1]]);   i += 2;
    let hlen  = u16::from_be_bytes([buf[i], buf[i+1]]) as usize; i += 2;
    if htype != HTYPE_NTOR {
        return Err(Error::Crypto(format!("extend2: unknown htype {htype}")));
    }
    if i + hlen > buf.len() {
        return Err(Error::Crypto("extend2: truncated hdata".into()));
    }
    let hdata = buf[i..i + hlen].to_vec();

    Ok((LinkSpec { host, port, node_id, static_pub }, hdata))
}

/// Serialize EXTENDED2 payload (just the 64-byte ntor reply, length-prefixed).
pub fn build_extended2(ntor_server_reply: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + ntor_server_reply.len());
    out.extend_from_slice(&(ntor_server_reply.len() as u16).to_be_bytes());
    out.extend_from_slice(ntor_server_reply);
    out
}

pub fn parse_extended2(buf: &[u8]) -> Result<Vec<u8>> {
    if buf.len() < 2 {
        return Err(Error::Crypto("extended2: too short".into()));
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return Err(Error::Crypto("extended2: truncated hdata".into()));
    }
    Ok(buf[2..2 + n].to_vec())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_roundtrip() {
        let mut data = vec![0u8; 200];
        for (i, b) in data.iter_mut().enumerate() { *b = (i % 251) as u8; }
        let c = Cell::with_payload(CircuitId(42), CellCommand::Relay, &data).unwrap();

        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);

        let parsed = Cell::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.circ_id, CircuitId(42));
        assert_eq!(parsed.command, CellCommand::Relay);
        assert_eq!(&parsed.payload[..200], &data[..]);
        // Remainder should be zero padding.
        assert!(parsed.payload[200..].iter().all(|&b| b == 0));
    }

    #[test]
    fn cell_rejects_oversize_payload() {
        let data = vec![1u8; CELL_PAYLOAD + 1];
        let r = Cell::with_payload(CircuitId(1), CellCommand::Relay, &data);
        assert!(r.is_err());
    }

    #[test]
    fn unknown_cell_cmd_rejected() {
        let mut bytes = [0u8; CELL_SIZE];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4] = 255;
        assert!(Cell::from_bytes(&bytes).is_err());
    }

    #[test]
    fn circuit_id_none() {
        assert!(!CircuitId::NONE.is_valid());
        assert!(CircuitId(1).is_valid());
    }

    #[test]
    fn relay_cell_roundtrip() {
        let rc  = RelayCell::new(RelayCommand::Data, 7, b"hello".to_vec()).unwrap();
        let buf = rc.to_payload();
        let parsed = RelayCell::from_payload(&buf).unwrap();
        assert_eq!(parsed.command,   RelayCommand::Data);
        assert_eq!(parsed.stream_id, 7);
        assert_eq!(parsed.recognized, 0);
        assert_eq!(parsed.data,      b"hello");
    }

    #[test]
    fn relay_cell_max_data() {
        let data   = vec![0xAB; RELAY_DATA_MAX];
        let rc     = RelayCell::new(RelayCommand::Data, 1, data.clone()).unwrap();
        let parsed = RelayCell::from_payload(&rc.to_payload()).unwrap();
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn relay_cell_rejects_oversize() {
        let data = vec![0u8; RELAY_DATA_MAX + 1];
        assert!(RelayCell::new(RelayCommand::Data, 1, data).is_err());
    }

    #[test]
    fn relay_cell_length_field_bounds_checked() {
        let mut buf = [0u8; CELL_PAYLOAD];
        buf[0] = RelayCommand::Data as u8;
        // length = RELAY_DATA_MAX + 1
        let bad = (RELAY_DATA_MAX as u16 + 1).to_be_bytes();
        buf[9] = bad[0]; buf[10] = bad[1];
        assert!(RelayCell::from_payload(&buf).is_err());
    }

    #[test]
    fn digest_chains_forward() {
        // Two successive cells: second cell's digest must be over both.
        let mut running = Sha256::new();
        running.update(b"seed");

        let mut c1 = RelayCell::new(RelayCommand::Data, 1, b"one".to_vec()).unwrap();
        c1.stamp_digest(&mut running);
        let payload1 = c1.to_payload();

        let mut c2 = RelayCell::new(RelayCommand::Data, 1, b"two".to_vec()).unwrap();
        c2.stamp_digest(&mut running);
        let payload2 = c2.to_payload();

        // Verifier side
        let mut verifier = Sha256::new();
        verifier.update(b"seed");

        let p1 = RelayCell::from_payload(&payload1).unwrap();
        assert!(p1.is_recognized_at(&payload1, &verifier));
        // advance verifier state as a recognised cell would
        let mut tmp1 = payload1;
        tmp1[5] = 0; tmp1[6] = 0; tmp1[7] = 0; tmp1[8] = 0;
        verifier.update(&tmp1);

        let p2 = RelayCell::from_payload(&payload2).unwrap();
        assert!(p2.is_recognized_at(&payload2, &verifier));
    }

    #[test]
    fn recognized_nonzero_never_matches() {
        let mut running = Sha256::new();
        running.update(b"seed");

        let mut rc = RelayCell::new(RelayCommand::Data, 1, b"x".to_vec()).unwrap();
        rc.stamp_digest(&mut running);
        let mut payload = rc.to_payload();
        // Tamper with recognized field
        payload[1] = 0xFF;
        let parsed = RelayCell::from_payload(&payload).unwrap();
        let verifier = Sha256::new();
        assert!(!parsed.is_recognized_at(&payload, &verifier));
    }

    #[test]
    fn size_constants_consistent() {
        assert_eq!(CELL_HEADER + CELL_PAYLOAD, CELL_SIZE);
        assert_eq!(RELAY_HEADER + RELAY_DATA_MAX, CELL_PAYLOAD);
    }

    // ── Onion layering ────────────────────────────────────────────────

    fn fake_hop(fk: u8, bk: u8) -> HopState {
        let keys = crate::ntor::NtorKeys {
            forward_digest_seed:  [1; 20],
            backward_digest_seed: [2; 20],
            forward_key:  zeroize::Zeroizing::new([fk; 32]),
            backward_key: zeroize::Zeroizing::new([bk; 32]),
        };
        HopState::from_ntor(&keys)
    }

    #[test]
    fn onion_single_hop_roundtrip() {
        let mut client = fake_hop(0xAA, 0xBB);
        let mut hop    = fake_hop(0xAA, 0xBB);

        let plaintext: [u8; CELL_PAYLOAD] = [0x42; CELL_PAYLOAD];

        // Client encrypts
        let mut buf = plaintext;
        onion_encrypt_forward(&mut client, &mut buf);
        assert_ne!(buf, plaintext, "ciphertext must differ from plaintext");

        // Hop decrypts
        onion_decrypt_forward(&mut hop, &mut buf);
        assert_eq!(buf, plaintext, "decryption must recover plaintext");

        // Nonces advanced
        assert_eq!(client.forward_nonce, 1);
        assert_eq!(hop.forward_nonce,    1);
    }

    #[test]
    fn onion_three_hop_roundtrip() {
        // Client has three hop states. Server side simulates each hop
        // peeling one layer in sequence.
        let (mut c_g, mut c_m, mut c_e) = (
            fake_hop(0x11, 0xAA),
            fake_hop(0x22, 0xBB),
            fake_hop(0x33, 0xCC),
        );
        let (mut h_g, mut h_m, mut h_e) = (
            fake_hop(0x11, 0xAA),
            fake_hop(0x22, 0xBB),
            fake_hop(0x33, 0xCC),
        );

        let plaintext: [u8; CELL_PAYLOAD] = [0x77; CELL_PAYLOAD];
        let mut buf = plaintext;

        // Client layers: innermost = E, then M, then G (outermost)
        onion_encrypt_forward(&mut c_e, &mut buf);
        onion_encrypt_forward(&mut c_m, &mut buf);
        onion_encrypt_forward(&mut c_g, &mut buf);

        // Hops peel in order G → M → E
        onion_decrypt_forward(&mut h_g, &mut buf);
        onion_decrypt_forward(&mut h_m, &mut buf);
        onion_decrypt_forward(&mut h_e, &mut buf);

        assert_eq!(buf, plaintext, "full three-hop onion roundtrip");
    }

    #[test]
    fn onion_backward_three_hop() {
        let (mut c_g, mut c_m, mut c_e) = (
            fake_hop(0x11, 0xAA),
            fake_hop(0x22, 0xBB),
            fake_hop(0x33, 0xCC),
        );
        let (mut h_g, mut h_m, mut h_e) = (
            fake_hop(0x11, 0xAA),
            fake_hop(0x22, 0xBB),
            fake_hop(0x33, 0xCC),
        );

        // E originates a backward cell
        let plaintext: [u8; CELL_PAYLOAD] = [0x99; CELL_PAYLOAD];
        let mut buf = plaintext;
        onion_encrypt_backward(&mut h_e, &mut buf);
        // M adds its layer as it forwards
        onion_encrypt_backward(&mut h_m, &mut buf);
        // G adds its layer as it forwards
        onion_encrypt_backward(&mut h_g, &mut buf);

        // Client peels G, then M, then E
        onion_decrypt_backward(&mut c_g, &mut buf);
        onion_decrypt_backward(&mut c_m, &mut buf);
        onion_decrypt_backward(&mut c_e, &mut buf);

        assert_eq!(buf, plaintext);
    }

    #[test]
    fn onion_counter_divergence_fails() {
        let mut client = fake_hop(0xAA, 0xBB);
        let mut hop    = fake_hop(0xAA, 0xBB);

        let pt: [u8; CELL_PAYLOAD] = [0x55; CELL_PAYLOAD];
        let mut buf = pt;
        onion_encrypt_forward(&mut client, &mut buf);

        // Simulate a dropped cell: advance hop's nonce without decrypting.
        hop.forward_nonce = 5;
        onion_decrypt_forward(&mut hop, &mut buf);
        assert_ne!(buf, pt, "desynchronised nonce must not recover plaintext");
    }

    // ── EXTEND2 codec ────────────────────────────────────────────────

    #[test]
    fn extend2_roundtrip() {
        let next = LinkSpec {
            host:    "127.0.0.1".into(),
            port:    7700,
            node_id: [0xEEu8; 32],
            static_pub: [0xABu8; 32],
        };
        let ntor_msg = vec![0xAAu8; 96];

        let ser = build_extend2(&next, &ntor_msg);
        let (got, msg) = parse_extend2(&ser).unwrap();

        assert_eq!(got.host, next.host);
        assert_eq!(got.port, next.port);
        assert_eq!(got.node_id, next.node_id);
        assert_eq!(msg, ntor_msg);
    }

    #[test]
    fn extended2_roundtrip() {
        let reply = vec![0x11u8; 64];
        let ser   = build_extended2(&reply);
        let got   = parse_extended2(&ser).unwrap();
        assert_eq!(got, reply);
    }

    #[test]
    fn extend2_rejects_wrong_htype() {
        let mut bad = build_extend2(
            &LinkSpec {
                host: "1.2.3.4".into(),
                port: 1,
                node_id: [0;32],
                static_pub: [0;32],
            },
            &[0u8; 96],
        );
        // Flip htype field. Layout: nspec(1) + 3 specs:
        //   IPv4 (1+1+6=8) + NodeID (1+1+32=34) + StaticPub (1+1+32=34) = 76 bytes
        // Then htype at offset 1 + 76 = 77.
        let htype_pos = 1 + 8 + 34 + 34;
        bad[htype_pos]     = 0xFF;
        bad[htype_pos + 1] = 0xFF;
        assert!(parse_extend2(&bad).is_err());
    }
}
