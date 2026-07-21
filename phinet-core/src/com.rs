// phinet-core/src/com.rs
//! **com** — ΦNET-native end-to-end encrypted messaging.
//!
//! `com` is a Telegram-style messenger that rides on ΦNET. ΦNET gives
//! it *anonymity and metadata resistance* (circuits, guards, fixed
//! cells, obfuscated transports); this module adds the *end-to-end
//! confidentiality and authenticity* of the message content itself, so
//! that even the ΦNET relays carrying a message — and any mailbox/relay
//! node that stores it — cannot read it or forge it.
//!
//! ## Identity
//!
//! A user's com address is their ΦNET node identity: `(node_id,
//! static_pub)`, where `static_pub` is the node's long-term X25519
//! public key (already advertised in the handshake / `PeerInfo`). No
//! separate account system — if you can reach a node on ΦNET and know
//! its static key, you can message it.
//!
//! ## Sealing (the crypto)
//!
//! Each message is sealed to the recipient with a construction close to
//! the Noise `X` pattern, giving three properties at once:
//!
//! - **Confidentiality**: only the holder of the recipient's static
//!   secret can derive the key.
//! - **Forward secrecy** (per message): a fresh ephemeral X25519 key is
//!   mixed in, so compromising a long-term secret later doesn't reveal
//!   past messages' ephemeral half.
//! - **Sender authentication**: the sender's *static* secret is also
//!   mixed in, so a successful open proves the sender holds the secret
//!   for the `sender_pub` in the envelope. No separate signature needed.
//!
//! ```text
//!   e            = ephemeral X25519 (per message)
//!   ss_fs        = DH(e,           recipient_pub)   // forward secrecy
//!   ss_auth      = DH(sender_stat, recipient_pub)   // sender auth
//!   key          = HKDF(ss_fs ‖ ss_auth, salt=e_pub, info="phinet-com-v1")
//!   ciphertext   = ChaCha20Poly1305(key, nonce=0, aad=ctx, plaintext)
//! ```
//!
//! The recipient recomputes `ss_fs = DH(recip_stat, e_pub)` and
//! `ss_auth = DH(recip_stat, sender_pub)`; if the AEAD tag verifies, the
//! sender is authenticated. A forger who sets `sender_pub` to someone
//! else's key but lacks that secret derives a different `ss_auth` and
//! the tag fails.
//!
//! ## Transport-agnostic envelope
//!
//! [`ComEnvelope`] is just a sealed blob plus routing headers. It can be
//! delivered any way ΦNET can move bytes: directly over an established
//! peer link (implemented today), over a circuit to the recipient's
//! hidden service (anonymous delivery, next step), or parked in a DHT
//! mailbox for offline recipients (store-and-forward, next step). The
//! sealing is identical regardless of path.

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::{aead_decrypt, aead_encrypt, hkdf_derive};
use crate::{Error, Result};

// ── Contact ───────────────────────────────────────────────────────────

/// Someone you can message: their ΦNET node id, their static X25519
/// public key (their com address), and a local display name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub node_id:      [u8; 32],
    pub static_pub:   [u8; 32],
    pub display_name: String,
}

impl Contact {
    pub fn new(node_id: [u8; 32], static_pub: [u8; 32], name: impl Into<String>) -> Self {
        Self { node_id, static_pub, display_name: name.into() }
    }
}

// ── Sealed envelope ───────────────────────────────────────────────────

/// Mailbox blinding epoch length: one day. Blinded addresses rotate
/// every epoch so a relay can't link a recipient's mail across days.
pub const EPOCH_SECS: u64 = 86_400;

/// Current blinding epoch.
pub fn current_epoch() -> u64 { now_secs() / EPOCH_SECS }

/// Blinded mailbox address for a recipient in a given epoch:
/// `HKDF(recipient_static_pub, salt=epoch, info="com-mailbox-blind")`.
/// Anyone who knows the recipient's static key (i.e. a contact) can
/// compute it to *store* mail; a relay indexing by it learns only an
/// opaque per-epoch tag, never the recipient's node id.
pub fn blinded_addr(recipient_pub: &[u8; 32], epoch: u64) -> String {
    let salt = epoch.to_le_bytes();
    hex::encode(hkdf_derive(recipient_pub, &salt, b"com-mailbox-blind", 32))
}

/// A sealed, end-to-end-encrypted message. **Sealed-sender**: the
/// sender's identity lives *inside* the ciphertext, so relays never see
/// who sent it. **Blinded addressing**: `blinded_to` is a per-epoch tag,
/// so relays never see the recipient's node id either. All a mailbox
/// node learns is "opaque tag X has a sealed blob."
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComEnvelope {
    /// Random 16-byte message id (hex), for dedup.
    pub msg_id:     String,
    /// Per-epoch blinded recipient address (hex 32). Relays index on
    /// this; it reveals no identity.
    pub blinded_to: String,
    /// Blinding epoch the address was computed for (recipient checks a
    /// small window around its own clock).
    pub epoch:      u64,
    /// Per-message ephemeral X25519 pub (hex 32) — outer confidentiality
    /// DH. The only plaintext key material; random-looking, no identity.
    pub ephem_pub:  String,
    /// Unix seconds when sealed (bound into the AEAD).
    pub timestamp:  u64,
    /// AEAD ciphertext of `sender_id ‖ sender_pub ‖ body`, keyed by the
    /// ephemeral→recipient DH. Hides the sender from relays.
    pub ciphertext: String,
    /// AEAD tag over `ciphertext`, keyed by the sender→recipient static
    /// DH. Proves the sender holds the secret for the `sender_pub`
    /// revealed inside `ciphertext` — sealed-sender authentication.
    pub auth_tag:   String,
}

impl ComEnvelope {
    /// The blinded address this envelope is stored under.
    pub fn blinded_addr(&self) -> &str { &self.blinded_to }

    /// Compact binary encoding for circuit injection, where the relay
    /// payload budget is tight (< ~496 bytes). Layout:
    /// `msg_id(16) ‖ blinded(32) ‖ epoch(8) ‖ ephem(32) ‖ ts(8) ‖
    ///  auth_tag(16) ‖ ciphertext(rest)`.
    pub fn to_compact(&self) -> Option<Vec<u8>> {
        let msg_id  = hex::decode(&self.msg_id).ok()?;
        let blinded = hex::decode(&self.blinded_to).ok()?;
        let ephem   = hex::decode(&self.ephem_pub).ok()?;
        let tag     = hex::decode(&self.auth_tag).ok()?;
        let ct      = hex::decode(&self.ciphertext).ok()?;
        if msg_id.len() != 16 || blinded.len() != 32 || ephem.len() != 32
            || tag.len() != 16 { return None; }
        let mut b = Vec::with_capacity(112 + ct.len());
        b.extend_from_slice(&msg_id);
        b.extend_from_slice(&blinded);
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.extend_from_slice(&ephem);
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&tag);
        b.extend_from_slice(&ct);
        Some(b)
    }

    /// Inverse of [`to_compact`](ComEnvelope::to_compact).
    pub fn from_compact(b: &[u8]) -> Option<ComEnvelope> {
        if b.len() < 112 { return None; }
        Some(ComEnvelope {
            msg_id:     hex::encode(&b[0..16]),
            blinded_to: hex::encode(&b[16..48]),
            epoch:      u64::from_le_bytes(b[48..56].try_into().ok()?),
            ephem_pub:  hex::encode(&b[56..88]),
            timestamp:  u64::from_le_bytes(b[88..96].try_into().ok()?),
            auth_tag:   hex::encode(&b[96..112]),
            ciphertext: hex::encode(&b[112..]),
        })
    }
}

/// A successfully-opened message: authenticated sender + plaintext body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedMessage {
    pub msg_id:     [u8; 16],
    pub sender_id:  [u8; 32],
    /// The sender's static pub, *authenticated* by a successful open.
    pub sender_pub: [u8; 32],
    pub timestamp:  u64,
    pub body:       String,
}

// ── Seal / open (sealed-sender + blinded address) ─────────────────────

fn conf_key(ss: &[u8; 32], ephem_pub: &[u8; 32]) -> [u8; 32] {
    hkdf_derive(ss, ephem_pub, b"com-seal-conf", 32).try_into().unwrap()
}
fn auth_key(ss: &[u8; 32], ephem_pub: &[u8; 32]) -> [u8; 32] {
    hkdf_derive(ss, ephem_pub, b"com-seal-auth", 32).try_into().unwrap()
}

/// Seal `plaintext` for a recipient identified only by their static key.
/// Produces a sealed-sender, blinded-address envelope: relays learn
/// neither party's identity, and only the recipient can open it while
/// still authenticating the sender.
pub fn seal(
    sender_secret: &StaticSecret,
    sender_id:     [u8; 32],
    sender_pub:    [u8; 32],
    recipient_pub: [u8; 32],
    epoch:         u64,
    timestamp:     u64,
    plaintext:     &[u8],
) -> ComEnvelope {
    let e     = StaticSecret::random_from_rng(OsRng);
    let e_pub = PublicKey::from(&e);
    let r_pub = PublicKey::from(recipient_pub);

    // Confidentiality: ephemeral → recipient. Hides the inner (which
    // carries the sender identity) from everyone but the recipient.
    let k_conf = conf_key(&e.diffie_hellman(&r_pub).to_bytes(), e_pub.as_bytes());

    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);

    let mut inner = Vec::with_capacity(64 + plaintext.len());
    inner.extend_from_slice(&sender_id);
    inner.extend_from_slice(&sender_pub);
    inner.extend_from_slice(plaintext);

    let aad = seal_aad(&e_pub.to_bytes(), timestamp);
    let ct  = aead_encrypt(&k_conf, 0, &aad, &inner);

    // Authentication: sender static → recipient. A MAC (empty-plaintext
    // AEAD) over the ciphertext that only the holder of `sender_secret`
    // could produce for this recipient.
    let k_auth = auth_key(&sender_secret.diffie_hellman(&r_pub).to_bytes(), e_pub.as_bytes());
    let tag    = aead_encrypt(&k_auth, 0, &ct, &[]);

    ComEnvelope {
        msg_id:     hex::encode(msg_id),
        blinded_to: blinded_addr(&recipient_pub, epoch),
        epoch,
        ephem_pub:  hex::encode(e_pub.as_bytes()),
        timestamp,
        ciphertext: hex::encode(ct),
        auth_tag:   hex::encode(tag),
    }
}

fn seal_aad(ephem_pub: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(40);
    a.extend_from_slice(ephem_pub);
    a.extend_from_slice(&ts.to_le_bytes());
    a
}

/// Open an envelope addressed to us. Decrypts with our static secret to
/// recover the sender identity (sealed-sender), then verifies the
/// sender-authentication tag. Fails on the wrong recipient, a tampered
/// ciphertext, or a forged sender.
pub fn open(
    our_secret: &StaticSecret,
    our_pub:    [u8; 32],
    env:        &ComEnvelope,
) -> Result<OpenedMessage> {
    // Cheap reject: is this addressed to one of our recent blinded
    // addresses? (Bounds work before doing DH on junk.)
    if !addressed_to_us(&our_pub, env) {
        return Err(Error::Crypto("com: not addressed to us".into()));
    }
    let ephem_pub = hex32(&env.ephem_pub)
        .ok_or_else(|| Error::Crypto("com: bad ephem_pub".into()))?;
    let msg_id: [u8; 16] = hex::decode(&env.msg_id).ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Crypto("com: bad msg_id".into()))?;
    let ct = hex::decode(&env.ciphertext)
        .map_err(|_| Error::Crypto("com: bad ciphertext hex".into()))?;
    let tag = hex::decode(&env.auth_tag)
        .map_err(|_| Error::Crypto("com: bad auth_tag hex".into()))?;

    // Confidentiality: recover the inner (sender_id ‖ sender_pub ‖ body).
    let k_conf = conf_key(
        &our_secret.diffie_hellman(&PublicKey::from(ephem_pub)).to_bytes(),
        &ephem_pub);
    let aad = seal_aad(&ephem_pub, env.timestamp);
    let inner = aead_decrypt(&k_conf, 0, &aad, &ct)?;
    if inner.len() < 64 {
        return Err(Error::Crypto("com: inner too short".into()));
    }
    let sender_id:  [u8; 32] = inner[0..32].try_into().unwrap();
    let sender_pub: [u8; 32] = inner[32..64].try_into().unwrap();
    let body = String::from_utf8_lossy(&inner[64..]).into_owned();

    // Authentication: recompute the sender→recipient DH from the now-
    // known sender_pub and verify the tag. Only a sender holding the
    // secret for sender_pub could have produced it.
    let k_auth = auth_key(
        &our_secret.diffie_hellman(&PublicKey::from(sender_pub)).to_bytes(),
        &ephem_pub);
    aead_decrypt(&k_auth, 0, &ct, &tag)
        .map_err(|_| Error::Crypto("com: sender authentication failed".into()))?;

    Ok(OpenedMessage { msg_id, sender_id, sender_pub, timestamp: env.timestamp, body })
}

/// True if `env.blinded_to` matches one of our blinded addresses within
/// a ±1 epoch window (tolerating clock skew across the day boundary).
pub fn addressed_to_us(our_pub: &[u8; 32], env: &ComEnvelope) -> bool {
    let e = env.epoch;
    [e.wrapping_sub(1), e, e.wrapping_add(1)]
        .iter()
        .any(|&ep| blinded_addr(our_pub, ep) == env.blinded_to)
}

/// Our own blinded addresses for the current ±1 epoch window — the set a
/// recipient asks relays about when pulling mail.
pub fn my_blinded_addrs(our_pub: &[u8; 32]) -> Vec<String> {
    let e = current_epoch();
    vec![
        blinded_addr(our_pub, e.wrapping_sub(1)),
        blinded_addr(our_pub, e),
        blinded_addr(our_pub, e.wrapping_add(1)),
    ]
}

// ── Groups & channels ─────────────────────────────────────────────────

/// A group or channel: a shared symmetric key plus membership. A
/// *group* is a many-to-many conversation; a *channel* is the same
/// machinery with `is_channel = true` and an `admins` set the UI uses to
/// restrict who may post (readers still hold the key to decrypt).
///
/// Group messages are sealed under a per-message key derived from the
/// shared `key`, and delivered to a per-epoch blinded *group* address
/// that every member can compute, so one store fans out to all readers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub group_id:   [u8; 16],
    pub name:       String,
    pub key:        [u8; 32],
    pub members:    Vec<[u8; 32]>,
    pub is_channel: bool,
    pub admins:     Vec<[u8; 32]>,
    /// Per-sender Ed25519 verification keys: `node_id → sign_pub`.
    /// Bound on first authenticated sighting (TOFU) and thereafter
    /// enforced, so one member can't later spoof another's `sender_id`.
    #[serde(default)]
    pub signer_keys: Vec<([u8; 32], [u8; 32])>,
}

impl Group {
    /// Create a new group/channel with a fresh random key, `creator` as
    /// the first member/admin, and the creator's signing key recorded.
    pub fn create(name: &str, creator: [u8; 32], creator_sign_pub: [u8; 32],
                  is_channel: bool) -> Self {
        let mut group_id = [0u8; 16];
        OsRng.fill_bytes(&mut group_id);
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Group {
            group_id, name: name.to_string(), key,
            members: vec![creator], is_channel, admins: vec![creator],
            signer_keys: vec![(creator, creator_sign_pub)],
        }
    }

    pub fn id_hex(&self) -> String { hex::encode(self.group_id) }

    /// Look up the recorded signing key for a member.
    pub fn signer_of(&self, node_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.signer_keys.iter().find(|(id, _)| id == node_id).map(|(_, k)| *k)
    }

    /// Record `node_id → sign_pub`. Returns `Ok(true)` if newly bound,
    /// `Ok(false)` if it already matched, and `Err` on a conflict (a
    /// different key already bound to this node id → spoofing attempt).
    pub fn bind_signer(&mut self, node_id: [u8; 32], sign_pub: [u8; 32]) -> Result<bool> {
        match self.signer_of(&node_id) {
            Some(existing) if existing == sign_pub => Ok(false),
            Some(_) => Err(Error::Crypto("com: group signer key conflict".into())),
            None => { self.signer_keys.push((node_id, sign_pub)); Ok(true) }
        }
    }

    /// Per-epoch blinded mailbox address for this group.
    pub fn blinded_addr(&self, epoch: u64) -> String {
        hex::encode(hkdf_derive(&self.group_id, &epoch.to_le_bytes(),
                                b"com-group-blind", 32))
    }
    pub fn my_blinded_addrs(&self) -> Vec<String> {
        let e = current_epoch();
        vec![self.blinded_addr(e.wrapping_sub(1)),
             self.blinded_addr(e),
             self.blinded_addr(e.wrapping_add(1))]
    }
}

/// Derive a node's stable Ed25519 com group-signing key from its static
/// X25519 secret, so it needs no extra persistence and is bound to the
/// node's identity.
pub fn group_signer(static_secret: &StaticSecret) -> ed25519_dalek::SigningKey {
    let seed = hkdf_derive(&static_secret.to_bytes(), b"com-group-signer",
                           b"phinet-com-v1", 32);
    let seed: [u8; 32] = seed.try_into().unwrap();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// The public half of [`group_signer`].
pub fn group_sign_pub(static_secret: &StaticSecret) -> [u8; 32] {
    group_signer(static_secret).verifying_key().to_bytes()
}

/// Transcript signed for a group message: binds sender, content, and the
/// per-message salt so a signature can't be replayed onto other content.
fn group_sig_transcript(group_id: &[u8; 16], salt: &[u8; 16], ts: u64,
                        sender_id: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(16 + 16 + 8 + 32 + body.len());
    t.extend_from_slice(group_id);
    t.extend_from_slice(salt);
    t.extend_from_slice(&ts.to_le_bytes());
    t.extend_from_slice(sender_id);
    t.extend_from_slice(body);
    t
}

/// A sealed, **signed** group message. Confidentiality is via a
/// per-message key derived from the group key and a random salt (no
/// nonce reuse across senders). Authenticity is per-sender: the sender's
/// Ed25519 `signature` (verified against the `sign_pub` carried inside
/// the ciphertext, bound to `sender_id` by TOFU) prevents one member
/// from spoofing another's `sender_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupEnvelope {
    pub msg_id:     String, // hex 16, also the per-message KDF salt
    pub group_id:   String, // hex 16
    pub blinded_to: String, // hex 32, per-epoch group address
    pub epoch:      u64,
    pub timestamp:  u64,
    pub ciphertext: String, // AEAD(mk, sender_id ‖ sign_pub ‖ body)
    pub signature:  String, // hex 64, Ed25519 over the transcript
}

fn group_msg_key(group_key: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    hkdf_derive(group_key, salt, b"com-group-msg", 32).try_into().unwrap()
}

/// Seal + sign a message to a group.
pub fn seal_group(group: &Group, sender_id: [u8; 32],
                  signer: &ed25519_dalek::SigningKey, epoch: u64,
                  timestamp: u64, plaintext: &[u8]) -> GroupEnvelope {
    use ed25519_dalek::Signer;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let sign_pub = signer.verifying_key().to_bytes();

    let mut inner = Vec::with_capacity(64 + plaintext.len());
    inner.extend_from_slice(&sender_id);
    inner.extend_from_slice(&sign_pub);
    inner.extend_from_slice(plaintext);

    let mk  = group_msg_key(&group.key, &salt);
    let aad = { let mut a = group.group_id.to_vec();
                a.extend_from_slice(&timestamp.to_le_bytes()); a };
    let ct  = aead_encrypt(&mk, 0, &aad, &inner);

    let sig = signer.sign(&group_sig_transcript(
        &group.group_id, &salt, timestamp, &sender_id, plaintext));

    GroupEnvelope {
        msg_id:     hex::encode(salt),
        group_id:   group.id_hex(),
        blinded_to: group.blinded_addr(epoch),
        epoch,
        timestamp,
        ciphertext: hex::encode(ct),
        signature:  hex::encode(sig.to_bytes()),
    }
}

/// Decrypt + verify a group message. Returns `(sender_id, sign_pub,
/// body)`; the signature is checked against the carried `sign_pub`.
/// Callers must additionally enforce the `sender_id → sign_pub` binding
/// via [`Group::bind_signer`] to stop member spoofing.
pub fn open_group(group: &Group, env: &GroupEnvelope)
    -> Result<([u8; 32], [u8; 32], String)>
{
    use ed25519_dalek::Verifier;
    let salt: [u8; 16] = hex::decode(&env.msg_id).ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Crypto("com: bad group msg salt".into()))?;
    let ct = hex::decode(&env.ciphertext)
        .map_err(|_| Error::Crypto("com: bad group ciphertext".into()))?;
    let mk = group_msg_key(&group.key, &salt);
    let aad = { let mut a = group.group_id.to_vec();
                a.extend_from_slice(&env.timestamp.to_le_bytes()); a };
    let inner = aead_decrypt(&mk, 0, &aad, &ct)?;
    if inner.len() < 64 {
        return Err(Error::Crypto("com: group inner too short".into()));
    }
    let sender_id: [u8; 32] = inner[0..32].try_into().unwrap();
    let sign_pub:  [u8; 32] = inner[32..64].try_into().unwrap();
    let body = &inner[64..];

    // Verify the sender's signature over the transcript.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&sign_pub)
        .map_err(|_| Error::Crypto("com: bad group sign_pub".into()))?;
    let sig_bytes: [u8; 64] = hex::decode(&env.signature).ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Crypto("com: bad group signature".into()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&group_sig_transcript(&group.group_id, &salt, env.timestamp,
                                    &sender_id, body), &sig)
        .map_err(|_| Error::Crypto("com: group signature verify failed".into()))?;

    Ok((sender_id, sign_pub, String::from_utf8_lossy(body).into_owned()))
}

/// Control payload carried inside a *1:1* sealed message to invite
/// someone to a group/channel (distributes the shared key privately).
/// The recipient's message handler recognises this and adds the group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInvite {
    #[serde(rename = "type")]
    pub kind: String, // always "group-invite"
    pub group: Group,
}

/// Encode a group invite as a 1:1 message body.
pub fn encode_invite(group: &Group) -> String {
    serde_json::to_string(&GroupInvite { kind: "group-invite".into(), group: group.clone() })
        .unwrap_or_default()
}

/// If `body` is a group invite, decode it.
pub fn decode_invite(body: &str) -> Option<Group> {
    let inv: GroupInvite = serde_json::from_str(body).ok()?;
    if inv.kind == "group-invite" { Some(inv.group) } else { None }
}

// ── Inbox / conversation store ────────────────────────────────────────

/// One stored message in a conversation thread.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMessage {
    pub msg_id:    [u8; 16],
    /// The *other* party in this conversation (node id).
    pub peer_id:   [u8; 32],
    /// True if we sent it, false if we received it.
    pub outgoing:  bool,
    pub timestamp: u64,
    pub body:      String,
}

/// A simple message store grouping messages into per-peer conversation
/// threads. In-memory with optional JSON persistence. Deduplicates on
/// `msg_id` so a message delivered twice (e.g. via two paths) is stored
/// once.
#[derive(Default)]
pub struct Inbox {
    messages: Vec<StoredMessage>,
    seen:     std::collections::HashSet<[u8; 16]>,
}

impl Inbox {
    pub fn new() -> Self { Self::default() }

    /// Record a message. Returns `false` if it was a duplicate (already
    /// present by `msg_id`) and thus ignored.
    pub fn record(&mut self, m: StoredMessage) -> bool {
        if !self.seen.insert(m.msg_id) {
            return false;
        }
        self.messages.push(m);
        true
    }

    /// All messages exchanged with `peer`, in chronological order.
    pub fn conversation(&self, peer: &[u8; 32]) -> Vec<&StoredMessage> {
        let mut v: Vec<&StoredMessage> =
            self.messages.iter().filter(|m| &m.peer_id == peer).collect();
        v.sort_by_key(|m| m.timestamp);
        v
    }

    /// Remove a message by id (unsend). Keeps the id in `seen` so a
    /// re-gossiped copy can't resurrect it. Returns true if one was removed.
    pub fn remove(&mut self, msg_id: &[u8; 16]) -> bool {
        let before = self.messages.len();
        self.messages.retain(|m| &m.msg_id != msg_id);
        self.seen.insert(*msg_id);
        before != self.messages.len()
    }

    /// Distinct peers we have a thread with, most-recently-active first.
    pub fn threads(&self) -> Vec<[u8; 32]> {
        let mut last: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        for m in &self.messages {
            let e = last.entry(m.peer_id).or_insert(0);
            *e = (*e).max(m.timestamp);
        }
        let mut peers: Vec<([u8; 32], u64)> = last.into_iter().collect();
        peers.sort_by(|a, b| b.1.cmp(&a.1));
        peers.into_iter().map(|(p, _)| p).collect()
    }

    pub fn len(&self) -> usize { self.messages.len() }
    pub fn is_empty(&self) -> bool { self.messages.is_empty() }

    /// Serialize the whole store to JSON (for persistence).
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.messages).unwrap_or_else(|_| "[]".into())
    }

    /// Load a store from JSON produced by [`to_json`](Inbox::to_json).
    pub fn from_json(s: &str) -> Self {
        let messages: Vec<StoredMessage> = serde_json::from_str(s).unwrap_or_default();
        let seen = messages.iter().map(|m| m.msg_id).collect();
        Self { messages, seen }
    }
}

// ── Mailbox (store-and-forward for offline delivery) ──────────────────

/// A relay-side store of sealed envelopes awaiting delivery, keyed by
/// recipient node id. Any node can hold mail for any recipient — the
/// envelopes are end-to-end sealed, so a mailbox node learns only *that*
/// someone has mail for a recipient, never its contents. Entries expire
/// after a TTL and each recipient box is capped to bound memory.
///
/// This is what makes com work when the recipient is offline: a sender
/// gossips the envelope into the network, mailbox nodes hold it, and the
/// recipient pulls it when it next connects.
pub struct Mailbox {
    boxes:       std::collections::HashMap<String, Vec<(u64, ComEnvelope)>>,
    gboxes:      std::collections::HashMap<String, Vec<(u64, GroupEnvelope)>>,
    seen:        std::collections::HashSet<String>,
    ttl_secs:    u64,
    max_per_box: usize,
}

impl Mailbox {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            boxes:  std::collections::HashMap::new(),
            gboxes: std::collections::HashMap::new(),
            seen:   std::collections::HashSet::new(),
            ttl_secs,
            max_per_box: 256,
        }
    }

    /// Store a 1:1 envelope under its blinded address. Returns `true` if
    /// new (re-gossip), `false` if a duplicate (stop the flood).
    pub fn store(&mut self, env: ComEnvelope, now: u64) -> bool {
        if !self.seen.insert(env.msg_id.clone()) {
            return false;
        }
        let box_ = self.boxes.entry(env.blinded_to.clone()).or_default();
        box_.push((now, env));
        if box_.len() > self.max_per_box {
            let overflow = box_.len() - self.max_per_box;
            box_.drain(0..overflow);
        }
        true
    }

    /// Store a group envelope under its blinded group address.
    pub fn store_group(&mut self, env: GroupEnvelope, now: u64) -> bool {
        if !self.seen.insert(format!("g:{}", env.msg_id)) {
            return false;
        }
        let box_ = self.gboxes.entry(env.blinded_to.clone()).or_default();
        box_.push((now, env));
        if box_.len() > self.max_per_box {
            let overflow = box_.len() - self.max_per_box;
            box_.drain(0..overflow);
        }
        true
    }

    /// 1:1 envelopes held under `blinded` (non-destructive).
    pub fn peek(&self, blinded: &str) -> Vec<ComEnvelope> {
        self.boxes.get(blinded)
            .map(|v| v.iter().map(|(_, e)| e.clone()).collect())
            .unwrap_or_default()
    }

    /// Group envelopes held under `blinded`.
    pub fn peek_group(&self, blinded: &str) -> Vec<GroupEnvelope> {
        self.gboxes.get(blinded)
            .map(|v| v.iter().map(|(_, e)| e.clone()).collect())
            .unwrap_or_default()
    }

    /// Drop expired entries. Call periodically.
    pub fn evict_expired(&mut self, now: u64) {
        let ttl = self.ttl_secs;
        for box_ in self.boxes.values_mut() {
            box_.retain(|(t, _)| now.saturating_sub(*t) < ttl);
        }
        for box_ in self.gboxes.values_mut() {
            box_.retain(|(t, _)| now.saturating_sub(*t) < ttl);
        }
        self.boxes.retain(|_, v| !v.is_empty());
        self.gboxes.retain(|_, v| !v.is_empty());
    }

    /// Total envelopes held (diagnostics/tests).
    pub fn len(&self) -> usize {
        self.boxes.values().map(|v| v.len()).sum::<usize>()
            + self.gboxes.values().map(|v| v.len()).sum::<usize>()
    }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

// ── helpers ───────────────────────────────────────────────────────────

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

/// Current unix time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct Peer { secret: StaticSecret, pub_: [u8; 32], id: [u8; 32] }
    fn peer(tag: u8) -> Peer {
        let secret = StaticSecret::random_from_rng(OsRng);
        let pub_ = *PublicKey::from(&secret).as_bytes();
        Peer { secret, pub_, id: [tag; 32] }
    }

    const E: u64 = 100; // a fixed test epoch

    #[test]
    fn seal_open_roundtrip() {
        let a = peer(1); let b = peer(2);
        let env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1000, b"hello bob");
        let o = open(&b.secret, b.pub_, &env).unwrap();
        assert_eq!(o.body, "hello bob");
        assert_eq!(o.sender_id, a.id);
        assert_eq!(o.sender_pub, a.pub_);
    }

    #[test]
    fn envelope_hides_sender_and_recipient_identity() {
        // Sealed-sender + blinded address: nothing in the wire envelope
        // reveals either party's node id or the sender's key.
        let a = peer(1); let b = peer(2);
        let env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"secret");
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains(&hex::encode(a.id)), "sender id must not appear");
        assert!(!json.contains(&hex::encode(a.pub_)), "sender pub must not appear");
        assert!(!json.contains(&hex::encode(b.id)), "recipient id must not appear");
        // The blinded address is present but is not the recipient's id.
        assert_eq!(env.blinded_to, blinded_addr(&b.pub_, E));
        assert_ne!(env.blinded_to, hex::encode(b.id));
    }

    #[test]
    fn blinded_addr_rotates_per_epoch() {
        let b = peer(2);
        assert_ne!(blinded_addr(&b.pub_, 100), blinded_addr(&b.pub_, 101));
        // Recipient recognizes its own address within the ±1 window.
        let env = seal(&peer(1).secret, [1;32], peer(1).pub_, b.pub_, current_epoch(), 1, b"x");
        assert!(addressed_to_us(&b.pub_, &env));
        assert!(!addressed_to_us(&peer(9).pub_, &env));
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let a = peer(1); let b = peer(2); let eve = peer(3);
        let env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"secret");
        assert!(open(&eve.secret, eve.pub_, &env).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let a = peer(1); let b = peer(2);
        let mut env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"transfer 10");
        let mut ct = hex::decode(&env.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        env.ciphertext = hex::encode(ct);
        assert!(open(&b.secret, b.pub_, &env).is_err());
    }

    #[test]
    fn forged_sender_fails_auth() {
        // Mallory sends to Bob but tries to look like Alice. She can seal
        // confidentiality (ephemeral→Bob), but cannot forge the auth tag
        // without Alice's secret, and she can't put Alice's sender_pub in
        // the inner and still pass auth. Simulate by tampering the tag.
        let a = peer(1); let b = peer(2); let mallory = peer(4);
        let mut env = seal(&mallory.secret, a.id, a.pub_, b.pub_, E, 1, b"pay mallory");
        // Even if the inner were swapped, the tag won't verify against a
        // sender_pub Mallory doesn't own. Tamper the tag to represent any
        // forgery attempt: open must fail.
        let mut tag = hex::decode(&env.auth_tag).unwrap();
        tag[0] ^= 0x01;
        env.auth_tag = hex::encode(tag);
        assert!(open(&b.secret, b.pub_, &env).is_err(),
            "forged/tampered auth must fail");
    }

    #[test]
    fn auth_binds_sender_pub() {
        // A genuine message authenticates: the recovered sender_pub is
        // exactly the sealing key, proven by the auth tag verifying.
        let a = peer(1); let b = peer(2);
        let env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"real");
        let o = open(&b.secret, b.pub_, &env).unwrap();
        assert_eq!(o.sender_pub, a.pub_);
    }

    #[test]
    fn each_message_uses_fresh_ephemeral() {
        let a = peer(1); let b = peer(2);
        let e1 = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"a");
        let e2 = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"a");
        assert_ne!(e1.ephem_pub, e2.ephem_pub);
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    // ── Inbox ──────────────────────────────────────────────────────────

    #[test]
    fn envelope_compact_roundtrip_fits_relay_cell() {
        let a = peer(1); let b = peer(2);
        let env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 9, b"circuit injected hi");
        let c = env.to_compact().expect("encode");
        assert!(c.len() <= 496, "compact envelope must fit a relay cell: {}", c.len());
        let back = crate::com::ComEnvelope::from_compact(&c).expect("decode");
        // Recovers identically and still opens.
        assert_eq!(back.blinded_to, env.blinded_to);
        assert_eq!(open(&b.secret, b.pub_, &back).unwrap().body, "circuit injected hi");
    }

    #[test]
    fn inbox_dedup_and_threads() {
        let mut ibx = Inbox::new();
        let m = StoredMessage { msg_id: [1;16], peer_id: [2;32], outgoing: false,
                                timestamp: 10, body: "hi".into() };
        assert!(ibx.record(m.clone()));
        assert!(!ibx.record(m.clone()));
        ibx.record(StoredMessage { msg_id: [2;16], peer_id: [2;32], outgoing: true,
                                   timestamp: 20, body: "yo".into() });
        ibx.record(StoredMessage { msg_id: [3;16], peer_id: [5;32], outgoing: false,
                                   timestamp: 30, body: "hey".into() });
        assert_eq!(ibx.len(), 3);
        assert_eq!(ibx.conversation(&[2;32]).len(), 2);
        assert_eq!(ibx.threads()[0], [5;32]);
    }

    #[test]
    fn inbox_json_roundtrip() {
        let mut ibx = Inbox::new();
        ibx.record(StoredMessage { msg_id: [7;16], peer_id: [8;32], outgoing: true,
                                   timestamp: 42, body: "persist me".into() });
        let json = ibx.to_json();
        let back = Inbox::from_json(&json);
        assert_eq!(back.len(), 1);
        assert_eq!(back.conversation(&[8;32])[0].body, "persist me");
    }

    // ── Mailbox (blinded) ──────────────────────────────────────────────

    #[test]
    fn mailbox_store_peek_by_blinded_addr() {
        let a = peer(1); let b = peer(2);
        let mut mb = Mailbox::new(3600);
        let env = seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"m1");
        let addr = env.blinded_to.clone();
        assert!(mb.store(env.clone(), 100));
        assert!(!mb.store(env, 100), "dup");
        assert_eq!(mb.peek(&addr).len(), 1);
        assert_eq!(mb.peek("deadbeef").len(), 0);
    }

    #[test]
    fn mailbox_evicts_expired() {
        let a = peer(1); let b = peer(2);
        let mut mb = Mailbox::new(60);
        mb.store(seal(&a.secret, a.id, a.pub_, b.pub_, E, 1, b"old"), 1_000);
        assert_eq!(mb.len(), 1);
        mb.evict_expired(1_061);
        assert_eq!(mb.len(), 0);
    }

    #[test]
    fn offline_recipient_opens_held_mail() {
        let a = peer(1); let b = peer(2);
        let mut mb = Mailbox::new(3600);
        let ep = current_epoch();
        for i in 0..3u8 {
            let body = format!("msg {i}");
            mb.store(seal(&a.secret, a.id, a.pub_, b.pub_, ep, i as u64, body.as_bytes()), 100);
        }
        // Bob pulls by his own blinded addresses.
        let mut bodies: Vec<String> = my_blinded_addrs(&b.pub_).iter()
            .flat_map(|addr| mb.peek(addr))
            .map(|e| open(&b.secret, b.pub_, &e).unwrap().body)
            .collect();
        bodies.sort();
        assert_eq!(bodies, vec!["msg 0", "msg 1", "msg 2"]);
    }

    // ── Groups & channels ──────────────────────────────────────────────

    #[test]
    fn group_seal_open_roundtrip() {
        let alice = peer(1);
        let signer = group_signer(&alice.secret);
        let g = Group::create("devs", alice.id, signer.verifying_key().to_bytes(), false);
        let env = seal_group(&g, alice.id, &signer, E, 1000, b"gm hello");
        let (sender, _sp, body) = open_group(&g, &env).unwrap();
        assert_eq!(sender, alice.id);
        assert_eq!(body, "gm hello");
    }

    #[test]
    fn group_messages_use_distinct_keys() {
        let a = peer(1); let s = group_signer(&a.secret);
        let g = Group::create("x", a.id, s.verifying_key().to_bytes(), false);
        let e1 = seal_group(&g, a.id, &s, E, 1, b"a");
        let e2 = seal_group(&g, a.id, &s, E, 1, b"a");
        assert_ne!(e1.msg_id, e2.msg_id, "per-message salt must differ");
        assert_ne!(e1.ciphertext, e2.ciphertext, "no nonce reuse");
        assert_ne!(e1.signature, e2.signature);
    }

    #[test]
    fn non_member_without_key_cannot_open_group() {
        let a = peer(1); let s = group_signer(&a.secret);
        let g = Group::create("secret-room", a.id, s.verifying_key().to_bytes(), false);
        let env = seal_group(&g, a.id, &s, E, 1, b"classified");
        let other = Group::create("secret-room", a.id, s.verifying_key().to_bytes(), false);
        assert!(open_group(&other, &env).is_err(), "different key can't open");
    }

    #[test]
    fn group_member_cannot_spoof_another_members_sender_id() {
        // Alice and Mallory are both members (share the group key).
        // Mallory tries to post as Alice: she can encrypt (has the key)
        // but must sign. If she signs with her own key but claims
        // Alice's sender_id, the bound signer check rejects it; if she
        // omits a valid signature, verification fails outright.
        let alice   = peer(1);
        let mallory = peer(4);
        let a_signer = group_signer(&alice.secret);
        let m_signer = group_signer(&mallory.secret);
        let mut g = Group::create("crew", alice.id,
                                  a_signer.verifying_key().to_bytes(), false);
        // Alice's real message binds alice.id → alice's sign key.
        let real = seal_group(&g, alice.id, &a_signer, E, 1, b"hi from alice");
        let (sid, spub, _b) = open_group(&g, &real).unwrap();
        g.bind_signer(sid, spub).unwrap();

        // Mallory forges: claims sender_id = alice.id but signs with her key.
        let forged = seal_group(&g, alice.id, &m_signer, E, 2, b"give mallory admin");
        let (fsid, fspub, _fb) = open_group(&g, &forged).unwrap(); // sig valid for HER key
        // The signer binding for alice.id is Alice's key, not Mallory's.
        assert_eq!(fsid, alice.id);
        assert_ne!(fspub, a_signer.verifying_key().to_bytes());
        assert!(g.bind_signer(fsid, fspub).is_err(),
            "claiming alice's id with a different signing key must be rejected");
    }

    #[test]
    fn tampered_group_signature_fails() {
        let a = peer(1); let s = group_signer(&a.secret);
        let g = Group::create("x", a.id, s.verifying_key().to_bytes(), false);
        let mut env = seal_group(&g, a.id, &s, E, 1, b"real");
        let mut sig = hex::decode(&env.signature).unwrap();
        sig[0] ^= 0x01;
        env.signature = hex::encode(sig);
        assert!(open_group(&g, &env).is_err());
    }

    #[test]
    fn group_invite_roundtrips_through_1to1() {
        let alice = peer(1); let bob = peer(2);
        let s = group_signer(&alice.secret);
        let g = Group::create("crew", alice.id, s.verifying_key().to_bytes(), false);
        let invite_body = encode_invite(&g);
        let env = seal(&alice.secret, alice.id, alice.pub_, bob.pub_, E, 1,
                       invite_body.as_bytes());
        let o = open(&bob.secret, bob.pub_, &env).unwrap();
        let recovered = decode_invite(&o.body).expect("should decode invite");
        assert_eq!(recovered.group_id, g.group_id);
        assert_eq!(recovered.key, g.key);
        assert_eq!(recovered.name, "crew");
        // Invite carries the creator's signer binding.
        assert_eq!(recovered.signer_of(&alice.id), Some(s.verifying_key().to_bytes()));
    }

    #[test]
    fn channel_flag_and_admins() {
        let admin = peer(7);
        let sp = group_sign_pub(&admin.secret);
        let ch = Group::create("announcements", admin.id, sp, true);
        assert!(ch.is_channel);
        assert_eq!(ch.admins, vec![admin.id]);
        assert_eq!(ch.members, vec![admin.id]);
    }

    #[test]
    fn group_mailbox_delivery() {
        let a = peer(1); let s = group_signer(&a.secret);
        let g = Group::create("room", a.id, s.verifying_key().to_bytes(), false);
        let mut mb = Mailbox::new(3600);
        let ep = current_epoch();
        let env = seal_group(&g, a.id, &s, ep, 1, b"in the room");
        let addr = env.blinded_to.clone();
        assert!(mb.store_group(env, 10));
        let held = mb.peek_group(&addr);
        assert_eq!(held.len(), 1);
        assert_eq!(open_group(&g, &held[0]).unwrap().2, "in the room");
    }
}

// ── Contact addresses ───────────────────────────────────────────────
//
// A com "address" is what one person shares with another *out of band*
// so they can be messaged. It bundles the node_id (for the blinded
// mailbox address) and the static x25519 key (for sealing). Crucially,
// this is the ONLY way to become reachable: there is no public roster of
// participants to enumerate. Membership stays private — you can only
// message someone whose address you were directly given.

/// Encode a node_id + static key as a shareable address: `phi:<128 hex>`.
pub fn address_encode(node_id: &[u8; 32], static_pub: &[u8; 32]) -> String {
    format!("phi:{}{}", hex::encode(node_id), hex::encode(static_pub))
}

/// Parse a shareable address back into (node_id, static_pub). Accepts
/// the value with or without the `phi:` prefix and tolerates surrounding
/// whitespace. Returns `None` on any malformed input.
pub fn address_decode(s: &str) -> Option<([u8; 32], [u8; 32])> {
    let s = s.trim();
    let s = s.strip_prefix("phi:").unwrap_or(s);
    if s.len() != 128 { return None; }
    let node_id: [u8; 32]    = hex::decode(&s[..64]).ok()?.try_into().ok()?;
    let static_pub: [u8; 32] = hex::decode(&s[64..]).ok()?.try_into().ok()?;
    Some((node_id, static_pub))
}

#[cfg(test)]
mod address_tests {
    use super::*;
    #[test]
    fn address_roundtrips() {
        let nid = [7u8; 32]; let spk = [9u8; 32];
        let enc = address_encode(&nid, &spk);
        assert!(enc.starts_with("phi:"));
        assert_eq!(address_decode(&enc), Some((nid, spk)));
        assert_eq!(address_decode(&format!("  {enc}\n")), Some((nid, spk)));
        assert_eq!(address_decode("phi:abcd"), None);
        assert_eq!(address_decode("not an address"), None);
    }
}

// ── Unsend (delete) markers ─────────────────────────────────────────
//
// An unsend is delivered as an ordinary sealed com message whose body is a
// delete marker referencing the msg_id to remove. The recipient honors it
// by deleting that message instead of displaying the marker.

const DELETE_PREFIX: &str = "\u{1}com-delete\u{1}";

/// Encode an unsend instruction for `msg_id`.
pub fn encode_delete(msg_id: &[u8; 16]) -> String {
    format!("{DELETE_PREFIX}{}", hex::encode(msg_id))
}

/// Parse an unsend marker → the msg_id to delete, if this body is one.
pub fn decode_delete(body: &str) -> Option<[u8; 16]> {
    let h = body.strip_prefix(DELETE_PREFIX)?;
    hex::decode(h).ok().and_then(|v| <[u8; 16]>::try_from(v).ok())
}

#[cfg(test)]
mod delete_tests {
    use super::*;
    #[test]
    fn delete_marker_roundtrips() {
        let id = [7u8; 16];
        let enc = encode_delete(&id);
        assert_eq!(decode_delete(&enc), Some(id));
        assert_eq!(decode_delete("hello"), None);
    }
    #[test]
    fn remove_deletes_and_blocks_resurrection() {
        let mut ib = Inbox::new();
        let m = StoredMessage { msg_id: [1u8;16], peer_id: [2u8;32], outgoing: false,
            timestamp: 1, body: "hi".into() };
        assert!(ib.record(m.clone()));
        assert!(ib.remove(&[1u8;16]));
        assert_eq!(ib.len(), 0);
        // A re-gossiped copy must not come back.
        assert!(!ib.record(m));
        assert_eq!(ib.len(), 0);
    }
}
