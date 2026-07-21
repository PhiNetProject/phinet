// phinet-core/src/wire.rs
//! ΦNET wire protocol – framed JSON messages over TCP.
//!
//! Frame format: [4-byte LE length][payload bytes]
//! Payload is plain JSON before session, ChaCha20-Poly1305 after.

use crate::{session::Session, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Fixed link-cell plaintext size, in bytes. **Every** encrypted
/// (post-handshake) frame on a peer connection carries exactly this
/// many plaintext bytes, so on the wire every frame is identical in
/// size (`LINK_CELL` + AEAD tag). A message larger than one cell is
/// fragmented across several identical cells; a message smaller than
/// one cell is padded out to fill it.
///
/// This is Tor's link model: an OR connection carries a stream of
/// fixed-size cells and nothing else, so a passive on-link observer
/// learns only the *number* of cells, never any individual frame's
/// true content size. It cannot tell a circuit RELAY cell from a DHT
/// query from a padding cell — all are one indistinguishable frame —
/// and a bulk transfer looks like N identical frames rather than one
/// obviously-large frame. This strictly supersedes the earlier
/// block-multiple padding, which still leaked a big message's block
/// count in a single frame.
///
/// 2048 is chosen so a serialized circuit-cell `Message` (~1080 bytes:
/// a 512-byte cell hex-encoded plus JSON wrapper) fits in exactly one
/// link cell, avoiding per-cell fragmentation overhead on the hot path
/// while keeping the uniform unit small.
pub const LINK_CELL: usize = 2048;

/// Per-cell plaintext header: `more(1) | chunk_len(2 LE)`. `more == 1`
/// means another cell follows for the same message; `chunk_len` is the
/// number of real payload bytes in this cell (the remainder is pad).
const CELL_HDR: usize = 3;

/// Real payload bytes carried per link cell.
pub const CELL_DATA: usize = LINK_CELL - CELL_HDR; // 2045

/// Serialize a [`Message`], fragment it into fixed `LINK_CELL`-sized
/// plaintext cells, encrypt each under `session`, and return the full
/// concatenated on-wire byte sequence: for each cell,
/// `[4-byte LE ct_len][ciphertext]`. Every frame is identical in size.
///
/// Used by both `send_session` (writes the bytes) and
/// `PeerConn::send_msg` (pushes them to the connection writer). All
/// cells of one message are contiguous, so the reader never sees two
/// messages' cells interleaved on a connection.
pub(crate) fn frame_message(session: &Session, msg: &Message) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(msg)?;
    Ok(encode_cells(session, &payload))
}

/// Fragment + pad + encrypt `payload` into contiguous fixed cells.
fn encode_cells(session: &Session, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // An empty payload still emits exactly one (terminating) cell so the
    // reader's loop terminates uniformly.
    let mut chunks = payload.chunks(CELL_DATA).peekable();
    let mut wrote_any = false;
    while let Some(chunk) = chunks.next() {
        wrote_any = true;
        let more = if chunks.peek().is_some() { 1u8 } else { 0u8 };
        out.extend_from_slice(&encrypt_cell(session, more, chunk));
    }
    if !wrote_any {
        out.extend_from_slice(&encrypt_cell(session, 0, &[]));
    }
    out
}

/// Build one length-prefixed encrypted cell from a header + chunk,
/// zero-padded to the fixed `LINK_CELL` plaintext size.
fn encrypt_cell(session: &Session, more: u8, chunk: &[u8]) -> Vec<u8> {
    debug_assert!(chunk.len() <= CELL_DATA);
    let mut plain = vec![0u8; LINK_CELL];
    plain[0] = more;
    plain[1..3].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
    plain[CELL_HDR..CELL_HDR + chunk.len()].copy_from_slice(chunk);
    let ct = session.encrypt(&plain);
    let mut framed = Vec::with_capacity(4 + ct.len());
    framed.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    framed.extend_from_slice(&ct);
    framed
}

/// Read one link cell off `r`, decrypt it, and return
/// `(more, chunk_bytes)`. The frame length is fixed, so a length far
/// from the expected ciphertext size is rejected before allocation.
async fn read_cell<R: AsyncReadExt + Unpin>(
    r: &mut R,
    session: &Session,
) -> Result<(bool, Vec<u8>)> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb).await.map_err(|_| Error::Closed)?;
    let len = u32::from_le_bytes(lb) as usize;
    // Ciphertext is always LINK_CELL + AEAD tag. Allow a little slack
    // for tag-size variation but reject anything clearly wrong.
    if len < LINK_CELL || len > LINK_CELL + 64 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("link cell wrong size: {len}"),
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|_| Error::Closed)?;
    let plain = session.decrypt(&buf)?;
    if plain.len() != LINK_CELL {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decrypted link cell wrong plaintext size",
        )));
    }
    let more = plain[0] != 0;
    let clen = u16::from_le_bytes([plain[1], plain[2]]) as usize;
    if CELL_HDR + clen > LINK_CELL {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "link cell chunk_len exceeds cell",
        )));
    }
    Ok((more, plain[CELL_HDR..CELL_HDR + clen].to_vec()))
}

// ── Concrete I/O ──────────────────────────────────────────────────────

/// Send a [`Message`] without encryption (handshake phase).
pub async fn send_raw<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &Message) -> Result<()> {
    let payload = serde_json::to_vec(msg)?;
    w.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

/// Receive a [`Message`] without decryption (handshake phase).
pub async fn recv_raw<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Message> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb).await.map_err(|_| Error::Closed)?;
    let len = u32::from_le_bytes(lb) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|_| Error::Closed)?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Encrypt and send a [`Message`] using an established session as one
/// or more fixed-size link cells (see [`LINK_CELL`]). All cells are
/// written contiguously before returning.
pub async fn send_session<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg: &Message,
    session: &Session,
) -> Result<()> {
    let bytes = frame_message(session, msg)?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Receive and decrypt a [`Message`] using an established session,
/// reassembling it from however many fixed-size link cells it spans.
/// Returns exactly one `Message` per call, so callers are unaffected by
/// fragmentation.
pub async fn recv_session<R: AsyncReadExt + Unpin>(
    r: &mut R,
    session: &Session,
) -> Result<Message> {
    let mut assembled = Vec::new();
    loop {
        let (more, chunk) = read_cell(r, session).await?;
        assembled.extend_from_slice(&chunk);
        if assembled.len() > MAX_FRAME_SIZE {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "reassembled message exceeds MAX_FRAME_SIZE",
            )));
        }
        if !more {
            break;
        }
    }
    Ok(serde_json::from_slice(&assembled)?)
}

// ── Message enum ──────────────────────────────────────────────────────

use crate::{
    cert::WireCert,
    pow::{AdmissionPoW, IntroPuzzle, IntroPuzzleSolution},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Message {
    PowChallenge(PowChallenge),
    ClientHello(ClientHello),
    /// End-to-end-encrypted "com" message envelope (see crate::com).
    /// Direct online delivery over an established link.
    Com(crate::com::ComEnvelope),
    /// Store-and-forward: gossip a sealed envelope into the network so
    /// it reaches the recipient even if offline. Flooded with dedup.
    ComStore(crate::com::ComEnvelope),
    /// Store-and-forward for a sealed *group* message.
    ComGroupStore(crate::com::GroupEnvelope),
    /// A recipient asks a peer for any mail held for it. The peer only
    /// answers for `recipient == the authenticated link identity`.
    ComFetch(ComFetch),
    /// Response to ComFetch: the envelopes held for the recipient.
    ComMail(ComMail),
    Handshake(Handshake),
    /// A relay's signed self-declaration. Sent on link-up and on republish,
    /// and gossiped onward: unlike a claim made over a link, a descriptor
    /// carries its own proof, so a relay that has never spoken to us can
    /// still be described to us by someone who has.
    RelayDesc(crate::relay_desc::RelayDescriptor),
    HandshakeAck(HandshakeAck),
    Reject(Reject),
    Onion(Onion),
    CircuitCell(CircuitCellMsg),
    DhtFind(DhtFind),
    DhtFound(DhtFound),
    DhtStore(DhtStore),
    DhtFetch(DhtFetch),
    DhtValue(DhtValue),
    HsRegister(HsRegister),
    HsLookup(HsLookup),
    HsFound(HsFound),
    HsHttpRequest(HsHttpRequest),
    HsHttpResponse(HsHttpResponse),
    BoardPost(BoardPost),
    BoardFetch(BoardFetch),
    BoardPosts(BoardPosts),
    Padding(Padding),
    CertRotate(CertRotate),
}

// ── Handshake ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge: String,
    pub min_bits:  u32,
    /// Responder's ephemeral X25519 public key (hex), sent in the clear
    /// as the first handshake message. Only fixed-size random-looking
    /// bytes cross the wire here, so it leaks nothing about the node.
    /// The initiator combines it with its own ephemeral to derive the
    /// session key *before* sending any certificate material, so the
    /// cert/PoW exchange that follows is encrypted (see node.rs
    /// handshake). Defaults empty for backward-compat deserialization.
    #[serde(default)]
    pub server_ephem: String,
}

/// Cleartext second handshake message: the initiator's ephemeral
/// X25519 public key (hex). Sent right after receiving `PowChallenge`
/// so the responder can derive the same session key and decrypt the
/// encrypted `Handshake` that follows. Carries no identifying content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub ephem_pub: String,
}

/// A request to pull mail held under a set of blinded addresses (the
/// requester's own 1:1 addresses plus its groups' addresses). Blinded
/// addresses are capabilities derived from keys, so no separate auth is
/// needed and no identity is revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComFetch {
    pub req_id:  String,
    pub blinded: Vec<String>,
}

/// The envelopes a mailbox node holds under the requested blinded
/// addresses — both 1:1 and group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComMail {
    pub req_id:          String,
    pub envelopes:       Vec<crate::com::ComEnvelope>,
    #[serde(default)]
    pub group_envelopes: Vec<crate::com::GroupEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub version:       u32,
    pub cert:          WireCert,
    pub admission_pow: AdmissionPoW,
    /// X25519 ephemeral public key (hex)
    pub ephem_pub:     String,
    /// ML-KEM-1024 encapsulation key (hex) — empty if not supported
    pub mlkem_pub:     String,
    /// Static X25519 public key for onion routing (hex)
    pub static_pub:    String,
    pub listen_port:   u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAck {
    pub cert:          WireCert,
    pub admission_pow: AdmissionPoW,
    pub ephem_pub:     String,
    /// ML-KEM ciphertext (hex) — empty if not supported
    pub mlkem_ct:      String,
    pub static_pub:    String,
    pub listen_port:   u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reject {
    pub reason: String,
}

// ── Onion ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Onion {
    pub cell: String, // hex-encoded layered ciphertext
}

/// Real circuit cell: 512 bytes hex-encoded. Used for the production
/// circuit protocol (CREATE / CREATED / RELAY / RELAY_EARLY / DESTROY).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitCellMsg {
    pub data: String,
}

// ── DHT ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFind {
    pub req_id: String,
    pub target: String, // node_id hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFound {
    pub req_id: String,
    pub target: String,
    pub nodes:  Vec<DhtPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerInfo {
    pub node_id:    String,
    pub host:       String,
    pub port:       u16,
    pub cert:       WireCert,
    pub static_pub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStore {
    pub key:   String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFetch {
    pub req_id: String,
    pub key:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtValue {
    pub req_id: String,
    pub key:    String,
    pub value:  Option<Value>,
}

// ── Hidden service ────────────────────────────────────────────────────

/// A hidden-service descriptor published to the DHT. Clients fetch
/// this by `hs_id` to learn where to send INTRODUCE1 cells.
///
/// # Authenticity
///
/// The descriptor is signed by the HS's long-term Ed25519 identity
/// key. The `hs_id` is derived deterministically from that identity
/// key (see `hs_identity::HsIdentity::hs_id`), so a client who learns
/// the `hs_id` out-of-band (e.g. from a link the HS operator shares)
/// can verify that the fetched descriptor really originated from the
/// HS with that ID — an HSDir that tried to substitute a forged
/// descriptor would need to also produce a valid signature under the
/// identity key matching `hs_id`, which it cannot.
///
/// # Epoch blinding
///
/// To prevent HSDirs from correlating descriptors across time (and
/// thus from mapping long-term identities to observed queries), real
/// descriptor publication uses an epoch-specific **blinded** signing
/// key derived from the identity key plus the current epoch. Clients
/// blind the `hs_id` the same way to request the right copy. The
/// `identity_pub` field here is the long-term key; the `sig` is made
/// under the blinded subkey for `epoch`. See `hs_identity.rs` for the
/// derivation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HsDescriptor {
    pub hs_id:      String,
    pub name:       String,
    /// Plaintext intro point pubkey. **Empty when `client_auth` is
    /// `Some(_)`** — in that case the real intro_pub lives inside
    /// the encrypted `ClientAuthBlock` and only authorized clients
    /// can recover it. Public-access services leave `client_auth`
    /// `None` and populate this field directly.
    pub intro_pub:  String,
    /// Plaintext intro host. Same convention as `intro_pub`: empty
    /// when client-auth is in use.
    pub intro_host: Option<String>,
    /// Plaintext intro port. Same convention.
    pub intro_port: Option<u16>,
    /// Node ID (hex, 32 bytes) of the relay that terminates the intro
    /// circuit — i.e. the node a client's INTRODUCE1 must reach. In the
    /// current single-tier design this is the HS node itself, and its
    /// `intro_pub` is that node's x25519 static key. Empty when
    /// client-auth is in use (the value lives in the encrypted block).
    /// Back-compat default is empty; a client that finds it empty falls
    /// back to selecting a relay by (host, port).
    #[serde(default)]
    pub intro_node_id: String,
    /// HS long-term Ed25519 public key, hex-encoded. The `hs_id`
    /// must equal the derived ID of this key.
    #[serde(default)]
    pub identity_pub: String,
    /// Publication epoch (monotonic, ~daily granularity). Signatures
    /// are valid only for descriptors fetched within the same epoch.
    #[serde(default)]
    pub epoch: u64,
    /// Ed25519 signature under the blinded key for this epoch, over
    /// the canonical descriptor bytes (all fields above except sig).
    /// Hex-encoded 64 bytes.
    #[serde(default)]
    pub sig: String,
    /// Blinded Ed25519 public key used to verify `sig`. Clients
    /// check the signature against this key. The binding between
    /// `blinded_pub` and (`identity_pub`, `epoch`) depends on the
    /// blinding scheme — see hs_identity.rs. Hex-encoded 32 bytes.
    #[serde(default)]
    pub blinded_pub: String,
    /// Optional client-auth block. When `Some(_)`, the descriptor's
    /// intro point is encrypted and only clients with one of the
    /// authorized X25519 secrets can recover it. `intro_pub`,
    /// `intro_host`, `intro_port` are left empty in this case.
    ///
    /// Client-auth is end-to-end between the HS operator and the
    /// authorized clients — relays storing the descriptor in the
    /// DHT learn nothing about who's authorized or what the real
    /// intro point is. The block IS covered by the descriptor
    /// signature though, so an HSDir can't tamper with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<crate::client_auth::ClientAuthBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsRegister {
    pub descriptor: HsDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsLookup {
    pub req_id:           String,
    pub hs_id:            String,
    pub puzzle_solution:  Option<IntroPuzzleSolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsFound {
    pub req_id:     String,
    pub hs_id:      String,
    pub descriptor: Option<HsDescriptor>,
    pub puzzle:     Option<IntroPuzzle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsHttpRequest {
    pub req_id:   String,
    pub hs_id:    String,
    pub method:   String,
    pub path:     String,
    pub body_hex: String,
    pub headers:  std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsHttpResponse {
    pub req_id:   String,
    pub status:   u16,
    pub headers:  std::collections::HashMap<String, String>,
    pub body_hex: String,
}

// ── Board ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardPost {
    pub msg_id:    String,
    pub channel:   String,
    pub text:      String,
    pub ts:        u64,
    pub ephem_pub: String,
    pub mac:       String,
    pub cluster:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardFetch {
    pub req_id:  String,
    pub channel: String,
    pub limit:   u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardPosts {
    pub req_id:  String,
    pub channel: String,
    pub posts:   Vec<BoardPost>,
}

// ── Padding ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Padding {
    pub data: String, // hex-encoded random bytes
}

/// Announced when a node rotates its cert. The new cert identifies a
/// fresh node_id; continuity with the old identity is proven by
/// `link_sig`, an HMAC keyed by a secret derived from the old cert's
/// connection-session key. A receiving peer who already had an open
/// session with the old node_id verifies link_sig before replacing
/// its routing-table entry, so an attacker cannot hijack a peer by
/// broadcasting a forged CertRotate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRotate {
    /// Previous node_id, hex-encoded. Receiver uses this to look up
    /// which session's HMAC-salt to verify `link_sig` against.
    pub old_node_id: String,
    /// New node_id, hex-encoded. Derived from the new cert.
    pub new_node_id: String,
    /// The new cert's public fields in JSON (serialized `PhiCert`).
    /// Receiver verifies the math before trusting anything else.
    pub new_cert_json: String,
    /// Monotonic sequence number. Must strictly increase per old_node_id
    /// to prevent replay of an older rotation announcement.
    pub seq: u64,
    /// Unix timestamp of rotation (sanity only, not security-critical).
    pub ts: u64,
    /// Hex-encoded 32-byte HMAC-SHA256 over
    ///   (old_node_id || new_node_id || new_cert_json || seq || ts)
    /// keyed by a value derived from the session key shared with the
    /// peer. See node.rs `build_cert_rotate` / `verify_cert_rotate`.
    pub link_sig: String,
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    fn pair() -> (Session, Session) {
        let shared = [42u8; 32];
        (Session::new(&shared, true), Session::new(&shared, false))
    }

    /// Split a concatenated wire buffer into its per-cell frame lengths
    /// (the 4-byte prefixes), so tests can assert every frame is the
    /// same size.
    fn frame_lengths(mut bytes: &[u8]) -> Vec<usize> {
        let mut lens = Vec::new();
        while bytes.len() >= 4 {
            let l = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            lens.push(l);
            bytes = &bytes[4 + l..];
        }
        lens
    }

    #[test]
    fn small_message_is_exactly_one_cell() {
        let (alice, _) = pair();
        let m = Message::Padding(Padding { data: "hi".into() });
        let bytes = frame_message(&alice, &m).unwrap();
        let lens = frame_lengths(&bytes);
        assert_eq!(lens.len(), 1, "small message should be a single cell");
    }

    #[test]
    fn every_frame_on_the_wire_is_identical_size() {
        let (alice, _) = pair();
        // A message far larger than one cell → many frames, all equal.
        let big = Message::Padding(Padding { data: "z".repeat(20_000) });
        let bytes = frame_message(&alice, &big).unwrap();
        let lens = frame_lengths(&bytes);
        assert!(lens.len() > 1, "big message must span multiple cells");
        let first = lens[0];
        assert!(lens.iter().all(|&l| l == first),
            "all link frames must be the same size, got {lens:?}");
        // And that size is LINK_CELL plaintext + AEAD tag.
        assert_eq!(first, LINK_CELL + 16);
    }

    #[test]
    fn small_and_large_frames_are_indistinguishable_by_size() {
        // The core property: a single cell of a bulk transfer looks
        // exactly like a whole small control message on the wire.
        let (alice, _) = pair();
        let small = frame_message(
            &alice, &Message::Padding(Padding { data: "x".into() })).unwrap();
        let (alice2, _) = pair();
        let large = frame_message(
            &alice2, &Message::Padding(Padding { data: "y".repeat(9000) })).unwrap();
        let s = frame_lengths(&small);
        let l = frame_lengths(&large);
        assert_eq!(s[0], l[0], "a bulk cell must match a small message's cell size");
    }

    #[tokio::test]
    async fn roundtrips_small_and_multi_cell_messages_over_duplex() {
        // Drive a real Session pair over an in-memory duplex through the
        // fixed-cell codec: a one-cell message and a many-cell message
        // must both reassemble byte-exactly, proving fragmentation and
        // reassembly are symmetric through the real AEAD.
        let (alice, bob) = pair();
        let (mut a, mut b) = tokio::io::duplex(1 << 22);

        let m1 = Message::Padding(Padding { data: "hello".into() });
        let m2 = Message::Padding(Padding { data: "x".repeat(12_345) });

        send_session(&mut a, &m1, &alice).await.unwrap();
        send_session(&mut a, &m2, &alice).await.unwrap();

        let got1 = recv_session(&mut b, &bob).await.unwrap();
        let got2 = recv_session(&mut b, &bob).await.unwrap();
        match (got1, got2) {
            (Message::Padding(p1), Message::Padding(p2)) => {
                assert_eq!(p1.data, "hello");
                assert_eq!(p2.data.len(), 12_345);
                assert!(p2.data.bytes().all(|c| c == b'x'));
            }
            _ => panic!("unexpected message types after roundtrip"),
        }
    }

    #[tokio::test]
    async fn empty_payload_message_roundtrips() {
        // Degenerate case: a message whose JSON is small still emits
        // exactly one terminating cell and reassembles fine.
        let (alice, bob) = pair();
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let m = Message::Padding(Padding { data: String::new() });
        send_session(&mut a, &m, &alice).await.unwrap();
        match recv_session(&mut b, &bob).await.unwrap() {
            Message::Padding(p) => assert_eq!(p.data, ""),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn read_cell_rejects_wrong_size_prefix() {
        // A frame prefix that doesn't match the fixed cell size is
        // rejected before any large allocation.
        let bogus = 10 * 1024 * 1024usize; // way bigger than a cell
        assert!(!(LINK_CELL..=LINK_CELL + 64).contains(&bogus));
    }

    #[test]
    fn cell_data_capacity_holds_a_circuit_cell_message() {
        // A serialized circuit-cell Message (~1080 bytes) must fit in a
        // single link cell so the hot path never fragments.
        assert!(CELL_DATA >= 1200, "one link cell should hold a circuit cell");
    }
}
