// phinet-core/src/directory.rs
//!
//! # Directory authorities
//!
//! A small set of trusted servers that publish a signed **consensus
//! document** listing the peers in the network. Clients fetch the
//! consensus from any authority, verify the threshold of signatures,
//! and use the listed peers (with bandwidth weights and flags) for
//! path selection.
//!
//! ## Why
//!
//! Without a consensus, every peer has an idiosyncratic view of the
//! network. An adversary who controls a few peers can feed clients
//! a sybil-saturated peer table and degrade their anonymity. With
//! a consensus signed by k-of-n authorities, the worst an adversary
//! can do is cause inconsistency between authorities (which clients
//! detect by sig threshold) — they can't insert peers into the
//! network without authority cooperation.
//!
//! ## Trust model
//!
//! - **Authorities are not anonymous.** Each authority has a long-
//!   term Ed25519 identity key; that public key is hardcoded into
//!   client builds (or distributed out-of-band).
//! - **Threshold trust.** Clients accept a consensus if k ≥ THRESHOLD
//!   authorities have signed it. Compromise of fewer than threshold
//!   authorities can't poison the consensus.
//! - **Authority list is small and slow-changing.** Adding a new
//!   authority requires a software release. This is the only point
//!   in the system that is not fully decentralized — a deliberate
//!   tradeoff for sybil resistance.
//!
//! ## Voting flow (out of scope here, but documented)
//!
//! Each authority observes the network independently (descriptor
//! gossip, bandwidth scans, flag-policy checks) and publishes a
//! signed **vote** every ~1 hour. The consensus is built by merging
//! votes deterministically:
//!   - For each peer, take the median bandwidth observation
//!   - For each flag, take majority opinion (≥ ⌈n/2⌉ of authorities)
//!   - Sort peer list by node_id (canonical order)
//!   - Each authority then signs the resulting consensus bytes
//! Authorities exchange signatures and any one of them publishes the
//! signed bundle. Clients fetch from any authority — the threshold
//! check ensures the document is genuine regardless of which one.
//!
//! This module implements the wire format and verification side; the
//! actual distributed-voting protocol is operator-deployable code
//! that lives outside the library.

use crate::{Error, Result};
use crate::hs_identity::HsIdentity;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tag for consensus signing. A signature over
/// canonical consensus bytes is only valid under this tag — preventing
/// signatures intended for one network from being replayed in another.
const CONSENSUS_TAG: &[u8] = b"phi-consensus-v1:";

/// Domain-separation tag for authority votes. Same construction as
/// CONSENSUS_TAG but for the per-authority "I observe these peers"
/// step that feeds into consensus building.
const VOTE_TAG: &[u8] = b"phi-vote-v1:";

/// Default threshold: at least ⌈2n/3⌉ authority signatures required
/// to accept a consensus. With 4 authorities you'd need 3; with 7
/// authorities you'd need 5. Matches Tor's directory authority
/// threshold convention.
pub fn threshold_for(num_authorities: usize) -> usize {
    // ⌈2n/3⌉. Integer arithmetic: (2n + 2) / 3.
    (2 * num_authorities + 2) / 3
}

bitflags::bitflags! {
    /// Per-peer flags carried in the consensus, used by clients for
    /// path selection. Inspired by Tor's `s` line in microdescriptors.
    ///
    /// Reasonable client policy:
    ///   - **Guard hop**: require `STABLE | FAST | GUARD`
    ///   - **Middle hop**: require `STABLE | FAST`
    ///   - **Exit hop**: require `STABLE | FAST | EXIT`
    ///
    /// Flags are set by authorities based on observed behavior over
    /// a measurement window; a peer that's been online > threshold %
    /// of the last 30 days gets `STABLE`, > 250 KB/s sustained earns
    /// `FAST`, etc.
    #[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PeerFlags: u32 {
        /// Long-uptime peer suitable for long-lived circuits.
        const STABLE = 1 << 0;
        /// High-bandwidth peer suitable for stream-heavy circuits.
        const FAST   = 1 << 1;
        /// Suitable as a guard (entry) hop. Implies long uptime +
        /// high reliability + likely on a stable IP.
        const GUARD  = 1 << 2;
        /// Permits exit traffic (per its own ExitPolicy).
        const EXIT   = 1 << 3;
        /// Currently the peer is responsive on its advertised port.
        const RUNNING = 1 << 4;
        /// Authority has verified the peer's identity vs. the
        /// embedded static_pub via a fresh ntor handshake recently.
        const VALID  = 1 << 5;
    }
}

/// One peer's row in the consensus.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PeerEntry {
    /// Hex-encoded node_id (32 bytes from PhiCert).
    pub node_id_hex:   String,
    /// IP or hostname.
    pub host:          String,
    /// TCP port for the peer-protocol (PoW + handshake).
    pub port:          u16,
    /// Hex-encoded X25519 static public key (32 bytes) — used as
    /// the `B` parameter in ntor for circuit extension to this peer.
    pub static_pub_hex: String,
    /// Bitflags from `PeerFlags`.
    pub flags:         u32,
    /// Median observed bandwidth in kilobytes/sec — used as a weight
    /// in path selection so high-bandwidth peers carry proportionally
    /// more circuits.
    pub bandwidth_kbs: u32,
    /// Compact summary of the peer's exit policy: empty for non-exit,
    /// "default" for the standard exit policy, or a custom encoding
    /// the client knows how to interpret. Full policy is fetched
    /// from the peer directly when needed.
    pub exit_policy_summary: String,
    /// Operator family: a label an operator puts on every relay they run.
    ///
    /// Subnet diversity catches relays sitting in the same /16, but not one
    /// person running relays in three different datacentres. To a traffic
    /// analyst those are one relay wearing three hats, and a circuit built
    /// through two of them isn't a three-hop circuit — it's a two-hop circuit
    /// that looks like three. Path selection refuses to use two relays from
    /// the same family.
    ///
    /// Empty means unaffiliated. This is self-declared and therefore
    /// unenforceable: an operator who wants to hide their relays are related
    /// simply doesn't set it. It defends against accident (an honest operator
    /// concentrating traffic without realising) rather than against malice,
    /// which is exactly what Tor's MyFamily does, and it's still worth having
    /// — most concentration is accidental.
    #[serde(default)]
    pub family: String,
}

/// A consensus document. Signed by some subset of authorities; the
/// client verifies that ≥ THRESHOLD of those signatures are valid
/// under the trusted authority public-key set.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConsensusDocument {
    /// Network identifier — distinguishes mainnet, testnet, etc.
    /// Different network_ids cannot share a consensus.
    pub network_id: String,
    /// Commitments published this period, to be checked against next
    /// period's reveals. Carried in the consensus because that's the only
    /// document every authority already agrees on and signs.
    #[serde(default)]
    pub srv_commitments: Vec<SrvCommitment>,
    /// Shared random value for this period, if the authorities produced one.
    ///
    /// Feeds the hidden-service directory ring, so nobody can compute next
    /// period's layout in advance and grind node ids to sit beside a service
    /// they want to watch. Empty means the authorities didn't agree one, and
    /// the ring falls back to a predictable salt — see `hsdir_ring`.
    #[serde(default)]
    pub shared_random: String,
    /// Unix seconds when this consensus becomes valid.
    pub valid_after: u64,
    /// Unix seconds when this consensus expires. Clients ignore
    /// expired consensuses.
    pub valid_until: u64,
    /// Sorted by node_id_hex. Sorting is part of the canonical form,
    /// so two authorities computing consensus from the same vote set
    /// produce byte-identical bytes (and thus identical signatures
    /// when they sign the same input).
    pub peers: Vec<PeerEntry>,
    /// Signatures collected from authorities. Each entry has the
    /// authority's identity public key + Ed25519 sig over the
    /// canonical consensus bytes (with the `signatures` field cleared).
    pub signatures: Vec<AuthoritySignature>,
}

/// A single authority's signature on a consensus.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthoritySignature {
    /// Hex-encoded Ed25519 public key of the signing authority.
    pub authority_pub_hex: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub sig_hex: String,
}

/// A vote: one authority's observation of the network. Authorities
/// One authority's commitment for the coming period.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SrvCommitment {
    pub authority_pub_hex: String,
    pub commitment: String,
}

/// publish votes; consensus is built by merging votes deterministically.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuthorityVote {
    pub network_id: String,
    pub valid_after: u64,
    pub valid_until: u64,
    pub peers: Vec<PeerEntry>,
    /// The signing authority's identity public key.
    pub authority_pub_hex: String,
    /// Commitment to the random value this authority will contribute *next*
    /// period: `H(authority, period+1, value)`.
    ///
    /// Published a period ahead on purpose. By the time anyone reveals a
    /// value, its commitment is already public and signed, so the value can't
    /// be chosen after seeing what everyone else picked — which is the whole
    /// difference between shared randomness and the last authority's
    /// randomness.
    #[serde(default)]
    pub srv_commit: String,
    /// The value committed to last period, revealed now, hex.
    #[serde(default)]
    pub srv_reveal: String,
    /// Authority's signature over the canonical vote bytes.
    pub sig_hex: String,
}

/// Compute the canonical bytes for a consensus document. Used both
/// when signing (authority side) and verifying (client side). The
/// `signatures` field is excluded — we sign over everything else,
/// then attach signatures.
///
/// Canonical form:
///   tag || network_id_len || network_id ||
///   valid_after || valid_until ||
///   num_peers || (per-peer canonical bytes)*
///
/// All integers are big-endian. All strings are length-prefixed (u32
/// big-endian) so the parse is unambiguous.
fn canonical_consensus_bytes(d: &ConsensusDocument) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(CONSENSUS_TAG);
    write_lp_string(&mut out, &d.network_id);
    out.extend_from_slice(&d.valid_after.to_be_bytes());
    out.extend_from_slice(&d.valid_until.to_be_bytes());
    out.extend_from_slice(&(d.peers.len() as u32).to_be_bytes());
    for p in &d.peers {
        write_peer_canonical(&mut out, p);
    }
    // The shared random value is signed like everything else. It decides
    // where every hidden service's descriptor lives, so an unsigned one would
    // let anyone between a client and the consensus choose the ring — which
    // is the exact attack the value exists to prevent.
    write_lp_string(&mut out, &d.shared_random);
    // The commitments are signed too. Next period's reveals are checked
    // against these, so rewriting one in transit would make an honest
    // authority's reveal fail its check and drop out of the computation —
    // influencing the value without contributing to it, which is precisely
    // what commit-and-reveal is designed to prevent.
    out.extend_from_slice(&(d.srv_commitments.len() as u32).to_be_bytes());
    for c in &d.srv_commitments {
        write_lp_string(&mut out, &c.authority_pub_hex);
        write_lp_string(&mut out, &c.commitment);
    }
    out
}

/// Same idea for a vote.
fn canonical_vote_bytes(v: &AuthorityVote) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(VOTE_TAG);
    write_lp_string(&mut out, &v.network_id);
    out.extend_from_slice(&v.valid_after.to_be_bytes());
    out.extend_from_slice(&v.valid_until.to_be_bytes());
    write_lp_string(&mut out, &v.authority_pub_hex);
    out.extend_from_slice(&(v.peers.len() as u32).to_be_bytes());
    for p in &v.peers {
        write_peer_canonical(&mut out, p);
    }
    // Both are signed. An unsigned commitment could be swapped in transit,
    // which would let an attacker invalidate an honest authority's reveal and
    // remove it from the computation — influencing the value without
    // contributing to it.
    write_lp_string(&mut out, &v.srv_commit);
    write_lp_string(&mut out, &v.srv_reveal);
    out
}

fn write_lp_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn write_peer_canonical(out: &mut Vec<u8>, p: &PeerEntry) {
    write_lp_string(out, &p.node_id_hex);
    write_lp_string(out, &p.host);
    out.extend_from_slice(&p.port.to_be_bytes());
    write_lp_string(out, &p.static_pub_hex);
    out.extend_from_slice(&p.flags.to_be_bytes());
    out.extend_from_slice(&p.bandwidth_kbs.to_be_bytes());
    write_lp_string(out, &p.exit_policy_summary);
    // Family is signed like everything else. It arrives over plain HTTP, and
    // an unsigned field there is an invitation: label every relay as one
    // family and path selection refuses to build anything, or strip the
    // labels and clients silently lose the diversity they thought they had.
    // The signature is the only reason fetching a consensus over HTTP is
    // safe, so it has to cover every field the client acts on.
    //
    // Adding it changes the signed bytes: consensuses signed by older
    // authorities will no longer verify, and the network needs a fresh vote.
    // That's the correct trade — a compatible-but-forgeable field isn't worth
    // keeping.
    write_lp_string(out, &p.family);
}

/// Abstraction over how an authority's Ed25519 signing happens.
///
/// The default implementation is `FileBackedSigner` — keeps the
/// secret in process memory, signs in software via ed25519-dalek.
/// This is what the file-based `gen-identity` workflow produces.
///
/// For production deployments, a hardware-security-module backed
/// signer can replace this. The HSM holds the secret, exposes a
/// signing API, and never reveals the key to userspace. The trait
/// is the single integration point: implement `sign(msg)` to call
/// out to your HSM (PKCS#11, YubiKey OpenPGP, AWS CloudHSM, etc),
/// then pass an instance to `DirectoryAuthority::with_signer`.
///
/// **Why a trait instead of a concrete struct**: the alternative
/// is hardcoding a particular HSM vendor or wiring `pkcs11` into
/// every build. Both are wrong: HSM choice is operator-specific,
/// and most users never need one. The trait keeps the core code
/// dep-free while letting operators swap in their hardware.
pub trait ConsensusSigner: Send + Sync {
    /// Sign `msg` and return the 64-byte Ed25519 signature.
    /// Must be deterministic: signing the same message twice with
    /// the same key returns identical signatures (Ed25519 is
    /// deterministic by construction; HSMs that support Ed25519
    /// are required to honor this).
    fn sign(&self, msg: &[u8]) -> [u8; 64];

    /// The public key corresponding to the secret used for signing.
    /// Embedded in vote and consensus signature records so verifiers
    /// know which authority signed.
    fn public_key(&self) -> [u8; 32];

    /// Hex-encoded public key — convenience wrapper for the wire
    /// format. Default implementation hex-encodes `public_key()`.
    fn pub_hex(&self) -> String {
        hex::encode(self.public_key())
    }
}

/// Default file-backed signer. Wraps an `HsIdentity` — the secret
/// stays in process memory and signing happens in software.
///
/// This is what `gen-identity` produces and what every operator
/// uses by default. Tier 0 / tier 1 in `AUTHORITY_KEY_MGMT.md`.
pub struct FileBackedSigner {
    identity: HsIdentity,
}

impl FileBackedSigner {
    pub fn new(identity: HsIdentity) -> Self {
        Self { identity }
    }
}

impl ConsensusSigner for FileBackedSigner {
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.identity.secret_bytes());
        signing.sign(msg).to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }
}

// ── HSM signer integration sketch ────────────────────────────────────
//
// The pattern below is deliberately not enabled by default — every
// HSM vendor's API differs and pulling in (e.g.) the `pkcs11` crate
// would force every build to depend on it. Operators who want HSM
// integration copy this skeleton into their fork:
//
// ```ignore
// use pkcs11::{Ctx, types::*};
//
// pub struct Pkcs11Signer {
//     ctx: Ctx,
//     session: CK_SESSION_HANDLE,
//     priv_key: CK_OBJECT_HANDLE,
//     pub_bytes: [u8; 32],
// }
//
// impl ConsensusSigner for Pkcs11Signer {
//     fn sign(&self, msg: &[u8]) -> [u8; 64] {
//         // CKM_EDDSA is the PKCS#11 mechanism for Ed25519
//         let mech = CK_MECHANISM { mechanism: CKM_EDDSA,
//                                   pParameter: std::ptr::null_mut(),
//                                   ulParameterLen: 0 };
//         self.ctx.sign_init(self.session, &mech, self.priv_key)
//             .expect("HSM sign_init");
//         let sig = self.ctx.sign(self.session, msg)
//             .expect("HSM sign");
//         let mut arr = [0u8; 64];
//         arr.copy_from_slice(&sig);
//         arr
//     }
//
//     fn public_key(&self) -> [u8; 32] { self.pub_bytes }
// }
//
// // Construction looks like:
// let signer = Pkcs11Signer::open("/usr/lib/yubihsm_pkcs11.so", &user_pin)?;
// let auth   = DirectoryAuthority::with_signer(Box::new(signer), "phinet-mainnet");
// ```
//
// YubiKey integration via PIV uses a similar pattern with the
// `yubikey-rs` crate. AWS CloudHSM exposes the same PKCS#11 surface.
// See AUTHORITY_KEY_MGMT.md for operational guidance.


/// A directory authority. Holds an Ed25519 identity (or any
/// `ConsensusSigner` for HSM-backed deployments) and signs votes
/// and consensus documents.
///
/// Reuses `HsIdentity` infrastructure since the underlying primitive
/// (Ed25519 keypair with persisted secret) is identical. The identity
/// public key is what clients hardcode into their trust set.
///
/// **Two construction modes**:
///   - `new(identity, network_id)` — backwards-compatible. Wraps
///     an `HsIdentity` in a `FileBackedSigner` automatically.
///   - `with_signer(signer, network_id)` — generic over any
///     `ConsensusSigner`. Use this for HSM, YubiKey, or other
///     hardware-backed signing.
pub struct DirectoryAuthority {
    /// Boxed signer abstraction. For `new()` callers this is a
    /// `FileBackedSigner`; HSM operators construct via `with_signer`
    /// and pass their own implementation.
    signer: Box<dyn ConsensusSigner>,
    network_id: String,
}

impl DirectoryAuthority {
    /// Wrap an existing identity as an authority for `network_id`.
    /// The identity is used through a `FileBackedSigner` (secret in
    /// process memory, software signing). For HSM-backed signing,
    /// use `with_signer` instead.
    pub fn new(identity: HsIdentity, network_id: impl Into<String>) -> Self {
        Self {
            signer: Box::new(FileBackedSigner::new(identity)),
            network_id: network_id.into(),
        }
    }

    /// Construct from a custom `ConsensusSigner` implementation. This
    /// is the entry point for HSM-backed deployments: the operator
    /// supplies a signer that delegates to their hardware.
    ///
    /// ```ignore
    /// let signer = MyHsmSigner::connect_to_yubikey()?;
    /// let auth = DirectoryAuthority::with_signer(Box::new(signer), "phinet-mainnet");
    /// ```
    pub fn with_signer(signer: Box<dyn ConsensusSigner>, network_id: impl Into<String>) -> Self {
        Self {
            signer,
            network_id: network_id.into(),
        }
    }

    /// Generate a fresh authority. Operators normally do this once
    /// and persist by saving the underlying identity. Only available
    /// in file-backed mode (HSMs generate keys via their own tools).
    pub fn generate(network_id: impl Into<String>) -> Self {
        Self::new(HsIdentity::generate(), network_id)
    }

    /// The authority's Ed25519 identity public key (hex-encoded).
    /// This is what clients embed in their trusted-authority list.
    pub fn pub_hex(&self) -> String {
        self.signer.pub_hex()
    }

    /// The authority's Ed25519 identity public key (raw 32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    /// The network this authority is voting for.
    pub fn network_id(&self) -> &str { &self.network_id }

    /// Build and sign a vote over `peers`. The authority's view of
    /// the network gets attested to: bandwidth observations, flag
    /// assignments, etc. Other authorities will merge votes to
    /// produce a consensus.
    pub fn vote(&self, valid_after: u64, valid_until: u64, peers: Vec<PeerEntry>) -> AuthorityVote {
        self.vote_with_srv(valid_after, valid_until, peers, String::new(), String::new())
    }

    /// Vote, contributing to the shared random value.
    ///
    /// `srv_commit` binds the value this authority will reveal next period;
    /// `srv_reveal` is the value it committed to last period. Both are signed
    /// with the rest of the vote.
    pub fn vote_with_srv(
        &self,
        valid_after: u64,
        valid_until: u64,
        mut peers: Vec<PeerEntry>,
        srv_commit: String,
        srv_reveal: String,
    ) -> AuthorityVote {
        // Canonical sort by node_id so byte form is deterministic.
        peers.sort_by(|a, b| a.node_id_hex.cmp(&b.node_id_hex));
        let mut v = AuthorityVote {
            network_id: self.network_id.clone(),
            valid_after,
            valid_until,
            peers,
            authority_pub_hex: self.pub_hex(),
            srv_commit,
            srv_reveal,
            sig_hex: String::new(),
        };
        let canonical = canonical_vote_bytes(&v);
        let sig = self.signer.sign(&canonical);
        v.sig_hex = hex::encode(sig);
        v
    }

    /// Sign a consensus document. The document's `peers` and
    /// validity window must already be set; this appends our
    /// signature to `signatures`.
    ///
    /// Multiple authorities run this in turn (or concurrently); each
    /// produces an `AuthoritySignature` over the same canonical
    /// bytes. Once enough have signed, the document is publishable.
    pub fn sign_consensus(&self, doc: &mut ConsensusDocument) {
        // Canonicalize without signatures
        let mut for_sign = doc.clone();
        for_sign.signatures.clear();
        let canonical = canonical_consensus_bytes(&for_sign);
        let sig = self.signer.sign(&canonical);
        doc.signatures.push(AuthoritySignature {
            authority_pub_hex: self.pub_hex(),
            sig_hex: hex::encode(sig),
        });
    }
}

/// Verify a vote's signature: the canonical bytes must be signed by
/// the public key embedded in the `authority_pub_hex` field. Returns
/// `Ok(())` only if the signature is valid.
///
/// Note this only verifies *that* the vote was signed by *some* key;
/// callers must separately check that the key is one they trust
/// (i.e. matches an authority in their hardcoded list).
pub fn verify_vote(v: &AuthorityVote) -> Result<()> {
    let pub_bytes = decode_pub(&v.authority_pub_hex)?;
    let sig_bytes = decode_sig(&v.sig_hex)?;
    let vk = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| Error::Crypto(format!("vote: bad pub: {e}")))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let canonical = canonical_vote_bytes(v);
    vk.verify(&canonical, &sig)
        .map_err(|e| Error::Crypto(format!("vote sig: {e}")))?;
    Ok(())
}

/// Verify a consensus document.
///
/// Returns `Ok(())` iff:
///   1. The current time falls within `[valid_after, valid_until]`
///      (caller's clock — clients with skew need to sync first).
///   2. At least `min_signatures` of the embedded signatures are
///      valid Ed25519 signatures under known authority public keys.
///   3. Each valid signature is from a *distinct* authority (no
///      double-counting if the same authority signed twice).
///
/// `trusted_authorities` is the client's hardcoded set of authority
/// pubkeys (32-byte Ed25519). Signatures from unknown keys are
/// silently ignored — they don't count toward the threshold but
/// don't cause rejection.
///
/// `min_signatures` should typically be `threshold_for(trusted_authorities.len())`.
pub fn verify_consensus(
    doc: &ConsensusDocument,
    trusted_authorities: &[[u8; 32]],
    min_signatures: usize,
    now_unix: u64,
) -> Result<()> {
    // (1) Validity window
    if now_unix < doc.valid_after {
        return Err(Error::Crypto(format!(
            "consensus not yet valid (valid_after={}, now={})",
            doc.valid_after, now_unix)));
    }
    if now_unix > doc.valid_until {
        return Err(Error::Crypto(format!(
            "consensus expired (valid_until={}, now={})",
            doc.valid_until, now_unix)));
    }

    // (2) + (3) Signatures
    let mut for_verify = doc.clone();
    for_verify.signatures.clear();
    let canonical = canonical_consensus_bytes(&for_verify);

    // Set of authority pubs that have already provided a valid sig,
    // so we don't double-count if the same authority signed twice.
    let mut counted = std::collections::HashSet::<[u8; 32]>::new();

    for asig in &doc.signatures {
        let pub_bytes = match decode_pub(&asig.authority_pub_hex) {
            Ok(b) => b,
            Err(_) => continue,  // malformed entry — skip silently
        };
        // Only count signatures from trusted authorities
        if !trusted_authorities.iter().any(|t| t == &pub_bytes) {
            continue;
        }
        let sig_bytes = match decode_sig(&asig.sig_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let vk = match VerifyingKey::from_bytes(&pub_bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        if vk.verify(&canonical, &sig).is_ok() {
            counted.insert(pub_bytes);
        }
    }

    if counted.len() < min_signatures {
        return Err(Error::Crypto(format!(
            "consensus has only {} valid authority signatures (need {})",
            counted.len(), min_signatures)));
    }
    Ok(())
}

/// Build a consensus by merging a set of votes. Deterministic:
///
///   - Validity window: latest `valid_after`, earliest `valid_until`
///     across votes (the intersection of authority-claimed windows).
///   - Peer set: union over all votes. For each peer:
///     - **Bandwidth**: median across observing authorities.
///     - **Flags**: a flag is set iff a majority of authorities that
///       observed the peer set it.
///     - **host/port/static_pub**: the value reported by a majority,
///       or — on tie — the smallest value lexicographically (a tie
///       breaker so consensus is deterministic; in practice ties
///       indicate authorities have diverged on observation, and
///       operators should investigate).
///   - Output sorted by `node_id_hex`.
///
/// The input votes' signatures are NOT verified by this function —
/// the caller is expected to call `verify_vote` on each vote first
/// and discard those that fail.
///
/// Returns the unsigned consensus document; authorities then sign it
/// via `sign_consensus` and exchange signatures.
pub fn build_consensus(network_id: &str, votes: &[AuthorityVote]) -> ConsensusDocument {
    build_consensus_with_srv(network_id, votes, None, 0)
}

/// Build a consensus, computing the shared random value from the votes'
/// reveals.
///
/// `prev` is last period's consensus, which holds the commitments these
/// reveals are checked against. Without it a reveal proves nothing — anyone
/// can "reveal" a number they picked a second ago — so a missing previous
/// consensus means no shared randomness this period rather than randomness
/// nobody vouched for.
pub fn build_consensus_with_srv(
    network_id: &str,
    votes: &[AuthorityVote],
    prev: Option<&ConsensusDocument>,
    period: u64,
) -> ConsensusDocument {
    let mut doc = build_consensus_inner(network_id, votes);

    // Check each reveal against the commitment published last period.
    let mut reveals = Vec::new();
    if let Some(prev) = prev {
        for v in votes {
            if v.srv_reveal.is_empty() { continue; }
            let value: [u8; 32] = match hex::decode(&v.srv_reveal).ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                Some(x) => x,
                None => continue,
            };
            let commitment = prev.srv_commitments.iter()
                .find(|c| c.authority_pub_hex == v.authority_pub_hex)
                .map(|c| c.commitment.clone());
            let commitment = match commitment { Some(c) => c, None => continue };
            // A reveal that doesn't match its commitment is the attack this
            // protocol exists to stop: an authority that saw the others'
            // values and picked a better one. Drop it — the value it
            // committed to is the only one it gets.
            if crate::shared_random::check_reveal(
                &v.authority_pub_hex, &value, period, &commitment)
            {
                reveals.push(crate::shared_random::Reveal {
                    authority_id: v.authority_pub_hex.clone(),
                    value,
                });
            }
        }
    }
    // Two reveals minimum: a value from one contributor is that
    // contributor's choice, and shipping it would look like shared
    // randomness while being the opposite.
    doc.shared_random = crate::shared_random::compute_srv(&reveals, period, 2)
        .unwrap_or_default();

    // Carry this period's commitments forward for next period to check.
    let mut commitments: Vec<SrvCommitment> = votes.iter()
        .filter(|v| !v.srv_commit.is_empty())
        .map(|v| SrvCommitment {
            authority_pub_hex: v.authority_pub_hex.clone(),
            commitment: v.srv_commit.clone(),
        })
        .collect();
    commitments.sort_by(|a, b| a.authority_pub_hex.cmp(&b.authority_pub_hex));
    commitments.dedup_by(|a, b| a.authority_pub_hex == b.authority_pub_hex);
    doc.srv_commitments = commitments;

    doc
}

fn build_consensus_inner(network_id: &str, votes: &[AuthorityVote]) -> ConsensusDocument {
    let valid_after = votes.iter().map(|v| v.valid_after).max().unwrap_or(0);
    let valid_until = votes.iter().map(|v| v.valid_until).min().unwrap_or(0);

    // Group peer entries by node_id_hex. Each group is the set of
    // (peer_entry, authority_pub) pairs that observed that peer.
    let mut by_id: std::collections::HashMap<String, Vec<&PeerEntry>> =
        std::collections::HashMap::new();
    for v in votes {
        for p in &v.peers {
            by_id.entry(p.node_id_hex.clone()).or_default().push(p);
        }
    }

    let mut merged: Vec<PeerEntry> = by_id.into_iter().map(|(node_id, observations)| {
        let n = observations.len();
        // host/port/static_pub: majority vote with lex tiebreak
        let host = majority_or_min(observations.iter().map(|o| o.host.clone()));
        let static_pub_hex = majority_or_min(
            observations.iter().map(|o| o.static_pub_hex.clone()));
        let port = majority_or_min_u16(observations.iter().map(|o| o.port));
        let exit_policy_summary = majority_or_min(
            observations.iter().map(|o| o.exit_policy_summary.clone()));
        // Family is now carried in signed relay descriptors, so every
        // authority that has received a relay's descriptor sees the same
        // claim — and can't invent one, because it isn't the signer. That
        // makes a plain majority meaningful again: authorities are agreeing
        // about a fact they all observed, the way they do for host and port.
        //
        // Silence still loses, because an authority that hasn't yet received
        // a descriptor votes empty, and an absent observation shouldn't
        // outvote a present one. An authority that lies now has to lie about
        // something its peers can check.
        let family = majority_or_min(
            observations.iter()
                .map(|o| o.family.clone())
                .filter(|f| !f.is_empty()));

        // Bandwidth: median
        let mut bws: Vec<u32> = observations.iter().map(|o| o.bandwidth_kbs).collect();
        bws.sort_unstable();
        let bandwidth_kbs = bws[bws.len() / 2];

        // Flags: each flag bit set iff majority of observers set it
        let majority_threshold = (n + 1) / 2;  // ⌈n/2⌉
        let mut flags: u32 = 0;
        for bit in 0..32 {
            let mask = 1u32 << bit;
            let count = observations.iter().filter(|o| o.flags & mask != 0).count();
            if count >= majority_threshold {
                flags |= mask;
            }
        }

        PeerEntry {
            node_id_hex: node_id,
            host,
            port,
            static_pub_hex,
            flags,
            bandwidth_kbs,
            exit_policy_summary,
            family,
        }
    }).collect();

    merged.sort_by(|a, b| a.node_id_hex.cmp(&b.node_id_hex));

    ConsensusDocument {
        network_id: network_id.to_string(),
        shared_random: String::new(),
        srv_commitments: Vec::new(),
        valid_after,
        valid_until,
        peers: merged,
        signatures: Vec::new(),
    }
}

/// Returns the majority value of an iterator of strings, breaking
/// ties by lexicographically smallest. Used in consensus construction
/// for fields like host/port/static_pub_hex.
fn majority_or_min<I: IntoIterator<Item = String>>(items: I) -> String {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    counts.into_iter()
        .max_by(|a, b| {
            // Higher count wins; on tie, smaller string wins.
            a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0))
        })
        .map(|(s, _)| s)
        .unwrap_or_default()
}

fn majority_or_min_u16<I: IntoIterator<Item = u16>>(items: I) -> u16 {
    let mut counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    counts.into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|(s, _)| s)
        .unwrap_or(0)
}

fn decode_pub(hex_str: &str) -> Result<[u8; 32]> {
    let v = hex::decode(hex_str)
        .map_err(|_| Error::Crypto("authority pub: bad hex".into()))?;
    let arr: [u8; 32] = v.try_into()
        .map_err(|_| Error::Crypto("authority pub: not 32 bytes".into()))?;
    Ok(arr)
}

fn decode_sig(hex_str: &str) -> Result<[u8; 64]> {
    let v = hex::decode(hex_str)
        .map_err(|_| Error::Crypto("sig: bad hex".into()))?;
    let arr: [u8; 64] = v.try_into()
        .map_err(|_| Error::Crypto("sig: not 64 bytes".into()))?;
    Ok(arr)
}

/// Hash a consensus document for caching / quick comparison. Two
/// consensuses with the same canonical bytes (regardless of which
/// signatures are attached) hash identically, so clients can detect
/// "I already have this consensus" cheaply.
pub fn consensus_hash(d: &ConsensusDocument) -> [u8; 32] {
    let mut for_hash = d.clone();
    for_hash.signatures.clear();
    let bytes = canonical_consensus_bytes(&for_hash);
    let mut h = Sha256::new();
    h.update(&bytes);
    h.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_peer(node_id: &str, host: &str, port: u16, bw: u32, flags: u32) -> PeerEntry {
        PeerEntry {
            node_id_hex: node_id.into(),
            host: host.into(),
            port,
            static_pub_hex: format!("{:0<64}", node_id),  // dummy distinct from id
            flags,
            bandwidth_kbs: bw,
            exit_policy_summary: String::new(),
            family: String::new(),
        }
    }

    #[test]
    fn threshold_calculation() {
        // ⌈2n/3⌉
        assert_eq!(threshold_for(1), 1);
        assert_eq!(threshold_for(3), 2);
        assert_eq!(threshold_for(4), 3);
        assert_eq!(threshold_for(5), 4);
        assert_eq!(threshold_for(7), 5);
        assert_eq!(threshold_for(9), 6);
    }

    #[test]
    fn vote_sign_and_verify_roundtrip() {
        let auth = DirectoryAuthority::generate("phinet-mainnet");
        let peers = vec![
            fake_peer("aa", "10.0.0.1", 7700, 1000, PeerFlags::FAST.bits() | PeerFlags::RUNNING.bits()),
            fake_peer("bb", "10.0.0.2", 7700, 500, PeerFlags::STABLE.bits()),
        ];
        let vote = auth.vote(1000, 2000, peers);
        verify_vote(&vote).expect("vote must verify");
    }

    #[test]
    fn vote_with_tampered_peers_fails() {
        let auth = DirectoryAuthority::generate("phinet-mainnet");
        let mut vote = auth.vote(1000, 2000, vec![fake_peer("aa", "h", 1, 100, 0)]);
        // Tamper: change a peer's bandwidth — sig should no longer verify.
        vote.peers[0].bandwidth_kbs = 999_999;
        assert!(verify_vote(&vote).is_err());
    }

    #[test]
    fn vote_with_wrong_authority_pub_fails() {
        let auth = DirectoryAuthority::generate("phinet-mainnet");
        let other = DirectoryAuthority::generate("phinet-mainnet");
        let mut vote = auth.vote(1000, 2000, vec![fake_peer("aa", "h", 1, 100, 0)]);
        // Replace signing-pub claim with someone else's pub. Now the
        // sig was made by `auth` but vote claims to be from `other`.
        vote.authority_pub_hex = other.pub_hex();
        assert!(verify_vote(&vote).is_err());
    }

    #[test]
    fn consensus_sign_and_verify_threshold() {
        let auths: Vec<_> = (0..3)
            .map(|_| DirectoryAuthority::generate("phinet-mainnet"))
            .collect();
        let trusted: Vec<[u8; 32]> = auths.iter()
            .map(|a| {
                let raw = hex::decode(a.pub_hex()).unwrap();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                arr
            })
            .collect();

        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![fake_peer("aa", "h", 1, 100, 0)],
            signatures: Vec::new(),
        };
        for a in &auths {
            a.sign_consensus(&mut doc);
        }

        // Threshold for 3 = 2. We have 3 sigs, all from trusted auths.
        verify_consensus(&doc, &trusted, threshold_for(trusted.len()), 1500)
            .expect("consensus must verify");
    }

    #[test]
    fn consensus_below_threshold_rejected() {
        let auths: Vec<_> = (0..4)
            .map(|_| DirectoryAuthority::generate("phinet-mainnet"))
            .collect();
        let trusted: Vec<[u8; 32]> = auths.iter()
            .map(|a| decode_pub(&a.pub_hex()).unwrap())
            .collect();

        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![],
            signatures: Vec::new(),
        };
        // Only 2 of 4 sign — threshold for 4 is 3.
        auths[0].sign_consensus(&mut doc);
        auths[1].sign_consensus(&mut doc);

        let result = verify_consensus(&doc, &trusted, threshold_for(4), 1500);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("only 2 valid"));
    }

    #[test]
    fn consensus_with_unknown_authority_sig_ignored() {
        let real = DirectoryAuthority::generate("phinet-mainnet");
        let imposter = DirectoryAuthority::generate("phinet-mainnet");
        let trusted = vec![decode_pub(&real.pub_hex()).unwrap()];

        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![],
            signatures: Vec::new(),
        };
        // Imposter signs first — should be ignored
        imposter.sign_consensus(&mut doc);
        // Real authority signs — should count
        real.sign_consensus(&mut doc);

        // Threshold of 1 with 1 trusted authority
        verify_consensus(&doc, &trusted, 1, 1500)
            .expect("consensus must verify with imposter sig ignored");
    }

    #[test]
    fn consensus_expired_rejected() {
        let auth = DirectoryAuthority::generate("phinet-mainnet");
        let trusted = vec![decode_pub(&auth.pub_hex()).unwrap()];
        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut doc);

        // now = 3000 (past valid_until=2000)
        let result = verify_consensus(&doc, &trusted, 1, 3000);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("expired"));
    }

    #[test]
    fn consensus_not_yet_valid_rejected() {
        let auth = DirectoryAuthority::generate("phinet-mainnet");
        let trusted = vec![decode_pub(&auth.pub_hex()).unwrap()];
        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut doc);

        let result = verify_consensus(&doc, &trusted, 1, 500);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("not yet valid"));
    }

    #[test]
    fn consensus_tampered_peer_invalidates_sig() {
        let auth = DirectoryAuthority::generate("phinet-mainnet");
        let trusted = vec![decode_pub(&auth.pub_hex()).unwrap()];
        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![fake_peer("aa", "h", 1, 100, 0)],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut doc);
        // Tamper after signing
        doc.peers[0].bandwidth_kbs = 9999;

        let result = verify_consensus(&doc, &trusted, 1, 1500);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("only 0 valid"),
            "tampered consensus must have zero valid sigs, got: {:?}", result);
    }

    #[test]
    fn double_signature_from_same_authority_counts_once() {
        // Defensive: even if an authority's sig appears twice in the
        // signatures vec (perhaps by accident), they should count as
        // one toward the threshold.
        let auth1 = DirectoryAuthority::generate("phinet-mainnet");
        let auth2 = DirectoryAuthority::generate("phinet-mainnet");
        let trusted = vec![
            decode_pub(&auth1.pub_hex()).unwrap(),
            decode_pub(&auth2.pub_hex()).unwrap(),
        ];

        let mut doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![],
            signatures: Vec::new(),
        };
        // auth1 signs twice — should still count as 1
        auth1.sign_consensus(&mut doc);
        auth1.sign_consensus(&mut doc);
        assert_eq!(doc.signatures.len(), 2);

        // Threshold of 2 should be unmet (we only have 1 distinct authority)
        let result = verify_consensus(&doc, &trusted, 2, 1500);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("only 1 valid"));
    }

    #[test]
    fn build_consensus_takes_median_bandwidth() {
        // 3 authorities observe 3 different bandwidths for the same peer.
        // The consensus should report the median.
        let auths: Vec<_> = (0..3).map(|_| DirectoryAuthority::generate("net")).collect();
        let votes: Vec<_> = auths.iter().enumerate().map(|(i, a)| {
            // Bandwidths: 100, 500, 1000 — median = 500
            let bw = match i { 0 => 100, 1 => 500, 2 => 1000, _ => 0 };
            a.vote(1000, 2000, vec![fake_peer("aa", "10.0.0.1", 7700, bw, 0)])
        }).collect();

        let consensus = build_consensus("net", &votes);
        assert_eq!(consensus.peers.len(), 1);
        assert_eq!(consensus.peers[0].bandwidth_kbs, 500);
    }

    #[test]
    fn build_consensus_majority_flags() {
        // 5 authorities. 4 see FAST flag, 1 doesn't.
        // 2 see EXIT, 3 don't.
        let auths: Vec<_> = (0..5).map(|_| DirectoryAuthority::generate("net")).collect();
        let votes: Vec<_> = auths.iter().enumerate().map(|(i, a)| {
            let mut flags = 0u32;
            if i != 4 { flags |= PeerFlags::FAST.bits(); }   // 4/5 see FAST
            if i < 2  { flags |= PeerFlags::EXIT.bits(); }   // 2/5 see EXIT
            a.vote(1000, 2000, vec![fake_peer("aa", "h", 1, 100, flags)])
        }).collect();

        let consensus = build_consensus("net", &votes);
        let p = &consensus.peers[0];
        assert!(p.flags & PeerFlags::FAST.bits() != 0,
            "FAST should be set (majority)");
        assert!(p.flags & PeerFlags::EXIT.bits() == 0,
            "EXIT should NOT be set (minority)");
    }

    #[test]
    fn build_consensus_validity_window_intersection() {
        // Authority A says valid_after=1000, valid_until=3000
        // Authority B says valid_after=1500, valid_until=2500
        // Consensus should be the intersection: [1500, 2500]
        let a = DirectoryAuthority::generate("net");
        let b = DirectoryAuthority::generate("net");
        let v1 = a.vote(1000, 3000, vec![fake_peer("aa", "h", 1, 100, 0)]);
        let v2 = b.vote(1500, 2500, vec![fake_peer("aa", "h", 1, 100, 0)]);
        let consensus = build_consensus("net", &[v1, v2]);
        assert_eq!(consensus.valid_after, 1500);
        assert_eq!(consensus.valid_until, 2500);
    }

    #[test]
    fn build_consensus_sorts_peers_canonically() {
        // Peer entries from votes can come in any order, but the
        // consensus must sort by node_id_hex so the canonical bytes
        // are deterministic across authorities.
        let a = DirectoryAuthority::generate("net");
        let v = a.vote(1000, 2000, vec![
            fake_peer("ff", "h3", 3, 100, 0),
            fake_peer("aa", "h1", 1, 100, 0),
            fake_peer("cc", "h2", 2, 100, 0),
        ]);
        let consensus = build_consensus("net", &[v]);
        let ids: Vec<_> = consensus.peers.iter().map(|p| p.node_id_hex.clone()).collect();
        assert_eq!(ids, vec!["aa", "cc", "ff"]);
    }

    #[test]
    fn consensus_hash_stable_across_signatures() {
        // The hash should depend only on content, not on which auths
        // signed. Two copies of the same consensus with different
        // signature sets should hash the same.
        let auth = DirectoryAuthority::generate("net");
        let mut doc1 = ConsensusDocument {
            network_id: "net".into(), valid_after: 1, valid_until: 2,
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            peers: vec![fake_peer("aa", "h", 1, 100, 0)],
            signatures: Vec::new(),
        };
        let doc2 = doc1.clone();
        auth.sign_consensus(&mut doc1);
        // doc2 unsigned
        assert_eq!(consensus_hash(&doc1), consensus_hash(&doc2));
    }

    #[test]
    fn full_voting_flow() {
        // End-to-end: 3 authorities each vote, votes are collected,
        // consensus is built deterministically, all 3 authorities sign
        // it, client verifies threshold of signatures.
        let auths: Vec<_> = (0..3).map(|_| DirectoryAuthority::generate("net")).collect();
        let trusted: Vec<[u8; 32]> = auths.iter()
            .map(|a| decode_pub(&a.pub_hex()).unwrap())
            .collect();

        // Each authority sees the same peers but with slightly different bandwidths
        let votes: Vec<_> = auths.iter().enumerate().map(|(i, a)| {
            let bw = 100 + (i as u32) * 50;  // 100, 150, 200
            let flags = PeerFlags::FAST.bits() | PeerFlags::RUNNING.bits();
            a.vote(1000, 2000, vec![
                fake_peer("aaaa", "10.0.0.1", 7700, bw, flags),
                fake_peer("bbbb", "10.0.0.2", 7700, bw / 2, flags),
            ])
        }).collect();

        // Verify each vote first
        for v in &votes {
            verify_vote(v).expect("each vote must self-verify");
        }

        // Build consensus
        let mut consensus = build_consensus("net", &votes);
        assert_eq!(consensus.peers.len(), 2);
        // Median of {100, 150, 200} = 150
        assert_eq!(consensus.peers[0].bandwidth_kbs, 150);
        assert_eq!(consensus.peers[1].bandwidth_kbs, 75);

        // All three authorities sign
        for a in &auths {
            a.sign_consensus(&mut consensus);
        }

        // Client verifies with threshold = ⌈2*3/3⌉ = 2
        verify_consensus(&consensus, &trusted, threshold_for(3), 1500)
            .expect("end-to-end consensus must verify");
    }

    // ── ConsensusSigner trait ────────────────────────────────────────

    /// Custom signer that delegates to ed25519-dalek but tracks how
    /// many times `sign` was called. Mirrors what an HSM-backed
    /// signer's surface looks like: opaque holding of the secret,
    /// only `sign(msg)` and `public_key()` exposed.
    struct CountingSigner {
        inner: HsIdentity,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl ConsensusSigner for CountingSigner {
        fn sign(&self, msg: &[u8]) -> [u8; 64] {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let signing = ed25519_dalek::SigningKey::from_bytes(&self.inner.secret_bytes());
            signing.sign(msg).to_bytes()
        }
        fn public_key(&self) -> [u8; 32] { self.inner.public_key() }
    }

    #[test]
    fn custom_signer_via_with_signer() {
        // Authority constructed with a custom signer should produce
        // votes/consensus signatures that verify identically to those
        // from the file-backed default. This is the contract every
        // HSM-backed signer must honor.
        let id = HsIdentity::generate();
        let pub_hex = hex::encode(id.public_key());
        let signer = CountingSigner {
            inner: id,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let auth = DirectoryAuthority::with_signer(
            Box::new(signer),
            "phinet-test",
        );
        assert_eq!(auth.pub_hex(), pub_hex);

        let vote = auth.vote(1000, 2000, vec![
            fake_peer("aa", "h1", 1, 100, PeerFlags::FAST.bits() | PeerFlags::RUNNING.bits()),
        ]);
        verify_vote(&vote).expect("custom-signer vote must verify");

        let mut doc = ConsensusDocument {
            network_id: "phinet-test".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000, valid_until: 2000,
            peers: vec![],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut doc);
        assert_eq!(doc.signatures.len(), 1);
        let trusted = vec![{
            let v = hex::decode(&pub_hex).unwrap();
            let mut a = [0u8; 32]; a.copy_from_slice(&v); a
        }];
        verify_consensus(&doc, &trusted, 1, 1500)
            .expect("custom-signer consensus must verify");
    }

    #[test]
    fn file_backed_signer_matches_legacy_path() {
        // Direct FileBackedSigner usage should produce byte-identical
        // signatures to what the legacy `DirectoryAuthority::new`
        // path produces — which is in fact what we now build under
        // the hood. This test fails if FileBackedSigner ever drifts
        // from "wraps an HsIdentity directly" semantics.
        let id1 = HsIdentity::generate();
        let id2_seed = id1.secret_bytes();   // same secret
        let id2 = HsIdentity::from_secret_bytes(&id2_seed);

        let auth1 = DirectoryAuthority::new(id1, "net");
        let auth2 = DirectoryAuthority::with_signer(
            Box::new(FileBackedSigner::new(id2)),
            "net",
        );

        // Same input → same canonical bytes → same Ed25519 sig
        // (Ed25519 is deterministic).
        let msg = b"identical-message";
        let s1 = auth1.signer.sign(msg);
        let s2 = auth2.signer.sign(msg);
        assert_eq!(s1, s2,
            "FileBackedSigner must produce identical sigs for identical secret+msg");
    }
}

#[cfg(test)]
mod family_signing_tests {
    use super::*;

    fn peer(family: &str) -> PeerEntry {
        PeerEntry {
            node_id_hex: "aa".into(),
            host: "10.0.0.1".into(),
            port: 7700,
            static_pub_hex: "bb".into(),
            flags: 63,
            bandwidth_kbs: 1000,
            exit_policy_summary: "default".into(),
            family: family.into(),
        }
    }

    fn doc(family: &str) -> ConsensusDocument {
        ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 0,
            valid_until: 100,
            peers: vec![peer(family)],
            signatures: Vec::new(),
        }
    }

    #[test]
    fn family_is_covered_by_the_signature() {
        // The consensus travels over plain HTTP; the signature is the only
        // thing standing between a client and a forged one. A field the
        // client acts on but the signature ignores can be rewritten in
        // transit — tag every relay into one family and path selection
        // refuses to build a circuit at all.
        let a = canonical_consensus_bytes(&doc(""));
        let b = canonical_consensus_bytes(&doc("attacker-injected"));
        assert_ne!(a, b, "family must change the signed bytes, or it's forgeable");
    }

    #[test]
    fn identical_documents_still_sign_identically() {
        assert_eq!(canonical_consensus_bytes(&doc("acme")),
                   canonical_consensus_bytes(&doc("acme")));
    }
}

#[cfg(test)]
mod srv_signing_tests {
    use super::*;

    fn doc(srv: &str) -> ConsensusDocument {
        ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: srv.into(),
            srv_commitments: Vec::new(),
            valid_after: 0,
            valid_until: 100,
            peers: Vec::new(),
            signatures: Vec::new(),
        }
    }

    #[test]
    fn shared_random_is_covered_by_the_signature() {
        // It decides where every descriptor lives. Left unsigned, anyone on
        // the path could pick the ring — and picking the ring is the whole
        // attack the value defends against.
        assert_ne!(canonical_consensus_bytes(&doc("")),
                   canonical_consensus_bytes(&doc("deadbeef")));
    }
}

#[cfg(test)]
mod srv_protocol_tests {
    use super::*;
    use crate::shared_random;

    fn authority(_seed: u8) -> DirectoryAuthority {
        DirectoryAuthority::generate("test")
    }

    /// One full period: each authority commits to next period's value and
    /// reveals the one it committed to last period.
    fn vote_for(
        a: &DirectoryAuthority,
        period: u64,
        next_value: &[u8; 32],
        reveal_now: Option<&[u8; 32]>,
    ) -> AuthorityVote {
        let commit = shared_random::commit(&a.pub_hex(), next_value, period + 1);
        let reveal = reveal_now.map(hex::encode).unwrap_or_default();
        a.vote_with_srv(0, 100, Vec::new(), commit, reveal)
    }

    #[test]
    fn authorities_agree_a_value_no_one_of_them_chose() {
        let (a1, a2) = (authority(1), authority(2));
        let (v1, v2) = ([7u8; 32], [9u8; 32]);

        // Period 1: commit only. Nothing to reveal yet, so no value.
        let p1 = build_consensus_with_srv("test", &[
            vote_for(&a1, 1, &v1, None),
            vote_for(&a2, 1, &v2, None),
        ], None, 1);
        assert!(p1.shared_random.is_empty(), "nothing revealed yet");
        assert_eq!(p1.srv_commitments.len(), 2);

        // Period 2: reveal what was committed. Now there's a value.
        let p2 = build_consensus_with_srv("test", &[
            vote_for(&a1, 2, &[1u8; 32], Some(&v1)),
            vote_for(&a2, 2, &[2u8; 32], Some(&v2)),
        ], Some(&p1), 2);
        assert!(!p2.shared_random.is_empty(), "two honest reveals must produce a value");
    }

    #[test]
    fn a_reveal_that_breaks_its_commitment_is_dropped() {
        // The attack: see everyone else's reveal, then pick a value that
        // lands the ring where you want it.
        let (a1, a2) = (authority(1), authority(2));
        let (v1, v2) = ([7u8; 32], [9u8; 32]);
        let p1 = build_consensus_with_srv("test", &[
            vote_for(&a1, 1, &v1, None),
            vote_for(&a2, 1, &v2, None),
        ], None, 1);

        let honest = build_consensus_with_srv("test", &[
            vote_for(&a1, 2, &[1u8; 32], Some(&v1)),
            vote_for(&a2, 2, &[2u8; 32], Some(&v2)),
        ], Some(&p1), 2);

        // a2 reveals something it never committed to.
        let cheated = build_consensus_with_srv("test", &[
            vote_for(&a1, 2, &[1u8; 32], Some(&v1)),
            vote_for(&a2, 2, &[2u8; 32], Some(&[0xAA; 32])),
        ], Some(&p1), 2);

        // Only a1's reveal survives → below the minimum → no value at all.
        assert!(cheated.shared_random.is_empty(),
                "a cheating authority must not be able to steer the value");
        assert_ne!(honest.shared_random, cheated.shared_random);
    }

    #[test]
    fn without_last_periods_commitments_there_is_no_value() {
        // A reveal checked against nothing proves nothing: anyone can
        // "reveal" a number they chose a moment ago.
        let (a1, a2) = (authority(1), authority(2));
        let c = build_consensus_with_srv("test", &[
            vote_for(&a1, 2, &[1u8; 32], Some(&[7u8; 32])),
            vote_for(&a2, 2, &[2u8; 32], Some(&[9u8; 32])),
        ], None, 2);
        assert!(c.shared_random.is_empty());
    }

    #[test]
    fn one_authority_alone_cannot_produce_a_value() {
        // Otherwise the "shared" random value is one participant's choice.
        let a1 = authority(1);
        let v1 = [7u8; 32];
        let p1 = build_consensus_with_srv("test", &[vote_for(&a1, 1, &v1, None)], None, 1);
        let p2 = build_consensus_with_srv("test", &[
            vote_for(&a1, 2, &[1u8; 32], Some(&v1)),
        ], Some(&p1), 2);
        assert!(p2.shared_random.is_empty());
    }

    #[test]
    fn commitments_are_covered_by_the_vote_signature() {
        let a = authority(1);
        let mut v = vote_for(&a, 1, &[7u8; 32], None);
        assert!(verify_vote(&v).is_ok());
        v.srv_commit = "tampered".into();
        assert!(verify_vote(&v).is_err(),
                "an unsigned commitment could be swapped to invalidate an honest reveal");
    }

    #[test]
    fn reveals_are_covered_by_the_vote_signature() {
        let a = authority(1);
        let mut v = vote_for(&a, 2, &[1u8; 32], Some(&[7u8; 32]));
        assert!(verify_vote(&v).is_ok());
        v.srv_reveal = hex::encode([0xFFu8; 32]);
        assert!(verify_vote(&v).is_err());
    }
}
