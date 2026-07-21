// phinet-core/src/node.rs
//! ΦNET Node — the full async network entity.

use crate::{
    board::MessageBoard,
    cert::PhiCert,
    crypto::StaticKeypair,
    dht::{DhtStore, PeerInfo, RoutingTable},
    error::{Error, Result},
    hidden_service::HsManager,
    onion::{self},
    pow::{solve_admission, verify_admission, AdmissionPoW},
    session::{EphemeralKeypair, Session, TrafficPadder},
    store::SiteStore,
    wire::{
        self, BoardFetch, BoardPost, BoardPosts, DhtFind, DhtFound,
        DhtPeerInfo, DhtValue, Handshake,
        HandshakeAck, HsFound, HsLookup, Message, Onion, Padding,
        PowChallenge, Reject,
    },
};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}},
    time::Duration,
};
use tokio::{
    io::{BufReader, BufWriter},
    net::TcpListener,
    sync::{mpsc, Mutex, RwLock as ARwLock},
    time,
};
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey;

pub const PROTOCOL_VERSION: u32    = 2;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const ROTATE_INTERVAL:   Duration = Duration::from_secs(3600);
pub const PADDING_RATE_HZ:   f64      = 1.0;
/// A peer that sends nothing (not even padding) for this many seconds is
/// treated as dead and reaped. Padding is 1 Hz, so 30s is ~30 missed
/// cells — comfortably past any transient hiccup, well under the minutes
/// a half-open TCP link would otherwise linger.
pub const STALE_PEER_SECS:   u64      = 90;

// ── Peer connection ───────────────────────────────────────────────────

/// Releases a connection slot when the connection task ends — however it
/// ends. A limit that only decrements on the happy path is a limit that
/// eventually refuses everyone.
struct ConnSlot {
    node: Arc<PhiNode>,
    ip:   std::net::IpAddr,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.node.dos.lock().unwrap().release_connection(self.ip);
    }
}

/// Per-circuit send queues for one peer link, and the policy that picks
/// between them.
///
/// The queues exist because scheduling needs somewhere to choose *from*. With
/// a single channel there's nothing to decide: cells leave in the order they
/// arrived, which silently prefers whoever sends most.
pub struct CellQueues {
    inner:  std::sync::Mutex<CellQueuesInner>,
    notify: tokio::sync::Notify,
}

struct CellQueuesInner {
    /// Unsealed messages. They must stay unsealed until the writer takes
    /// them: the link session seals with a monotonic nonce counter, so the
    /// order frames are *sealed* in is the order the receiver will try to
    /// open them in. Sealing at enqueue and then reordering hands the peer
    /// frames whose nonces run backwards, and it drops every one of them.
    ///
    /// So the scheduler reorders messages; sealing happens once, at the
    /// write, in whatever order the scheduler settled on.
    q:     HashMap<u32, std::collections::VecDeque<Message>>,
    sched: crate::circuit_sched::EwmaScheduler,
}

impl Default for CellQueues {
    fn default() -> Self { Self::new() }
}

impl CellQueues {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(CellQueuesInner {
                q: HashMap::new(),
                sched: crate::circuit_sched::EwmaScheduler::new(),
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Queue a message for a circuit. Sealed later, by the writer.
    pub fn push(&self, cid: u32, msg: Message) {
        {
            let mut g = self.inner.lock().unwrap();
            g.q.entry(cid).or_default().push_back(msg);
        }
        self.notify.notify_one();
    }

    /// Take the next frame: the quietest circuit that has something waiting.
    ///
    /// Within a circuit the queue is strictly FIFO — cells on a circuit are a
    /// stream, and reordering them makes the far end decrypt garbage. Only
    /// the choice *between* circuits is scheduled.
    pub fn pop_next(&self) -> Option<(u32, Message)> {
        let mut g = self.inner.lock().unwrap();
        let ready: Vec<u32> = g.q.iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, _)| *k)
            .collect();
        if ready.is_empty() { return None; }
        let now = std::time::Instant::now();
        let cid = g.sched.next(&ready, now)?;
        let msg = g.q.get_mut(&cid).and_then(|v| v.pop_front())?;
        g.sched.note_sent(cid, 1, now);
        if g.q.get(&cid).map(|v| v.is_empty()).unwrap_or(false) {
            g.q.remove(&cid);
        }
        Some((cid, msg))
    }

    pub async fn wait(&self) { self.notify.notified().await; }

    pub fn forget(&self, cid: u32) {
        let mut g = self.inner.lock().unwrap();
        g.q.remove(&cid);
        g.sched.forget(cid);
    }
}

pub struct PeerConn {
    pub info:    PeerInfo,
    sender:      mpsc::Sender<Vec<u8>>,
    pub session: Arc<Session>,
    /// Unix seconds of the last cell received from this peer. Because
    /// peers exchange padding at `PADDING_RATE_HZ`, a live link refreshes
    /// this every second; a peer that vanishes (e.g. hard power-off,
    /// where TCP never signals close) goes silent and is reaped by the
    /// liveness loop. Without this a dead half-open link lingers in the
    /// peer table and pollutes the consensus snapshot as a ghost.
    last_seen:   AtomicU64,
    /// The address this peer actually connected from, as opposed to the one
    /// it advertises in `info.host`. Rate limiting has to use the real
    /// socket: a flooder can put anything it likes in its own peer info.
    /// `None` for links we dialled out to, which we chose and don't limit.
    pub remote_ip: Option<std::net::IpAddr>,
    /// Circuit cells waiting to go out on this link, scheduled rather than
    /// queued FIFO. See `circuit_sched`.
    pub queues: Arc<CellQueues>,
}

impl PeerConn {
    /// Mark the peer as heard-from just now.
    pub fn touch(&self) {
        self.last_seen.store(crate::com::now_secs(), Ordering::Relaxed);
    }
    /// Seconds since we last received anything from this peer.
    pub fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_seen.load(Ordering::Relaxed))
    }
    pub async fn send_msg(&self, msg: &Message) -> Result<()> {
        // Serialize + fragment into fixed-size link cells (see
        // wire::LINK_CELL). The read side is wire::recv_session, which
        // reassembles symmetrically. All cells of this message are one
        // contiguous buffer so they can't interleave with another
        // message's cells on the connection writer.
        let frame = crate::wire::frame_message(&self.session, msg)?;
        self.sender.send(frame).await.map_err(|_| Error::Closed)
    }

    /// Send a circuit cell, scheduled against this link's other circuits.
    ///
    /// Unlike `send_msg`, this doesn't go straight to the writer: it joins
    /// its circuit's queue and leaves when the scheduler picks it. A circuit
    /// that has been quiet goes ahead of one that has been flooding, so a
    /// page load doesn't wait behind a download's backlog.
    pub fn send_circuit_msg(&self, cid: u32, msg: Message) -> Result<()> {
        self.queues.push(cid, msg);
        Ok(())
    }
}

// ── Node ──────────────────────────────────────────────────────────────

/// HS-side pending rendezvous action. Queued by `handle_introduce2`
/// after successful decrypt + AUTH derivation; drained by
/// `hs_rendezvous_drainer` which builds the RP circuit and sends
/// RENDEZVOUS1 through it.
struct HsRendezvousIntent {
    rp_node_id: [u8; 32],
    rp_host:    String,
    rp_port:    u16,
    cookie:     [u8; 20],
    server_y:   [u8; 32],
    auth:       [u8; crate::rendezvous::HS_AUTH_LEN],
    e2e_keys:   crate::rendezvous::E2EKeys,
}

/// Result of resolving an HsDescriptor to a usable intro point.
/// For public services this trivially mirrors the descriptor's
/// public fields; for client-authorized services the contents
/// were decrypted from the descriptor's `ClientAuthBlock`.
#[derive(Debug, Clone)]
pub struct ResolvedIntro {
    pub intro_pub:  [u8; 32],
    pub intro_host: Option<String>,
    pub intro_port: Option<u16>,
    /// Node ID (32 bytes) of the intro-terminating relay (the HS node in
    /// the single-tier design). Zero if the descriptor didn't carry one
    /// (legacy), in which case `hs_fetch` cannot target the terminal hop
    /// precisely and returns an error.
    pub intro_node_id: [u8; 32],
}

/// The response an `hs_fetch` returns to its caller: the HTTP-ish
/// status, content type, and raw body bytes served by the hidden
/// service over the end-to-end rendezvous channel.
#[derive(Debug, Clone)]
pub struct HsFetchResponse {
    pub status:       u16,
    pub content_type: String,
    pub body:         Vec<u8>,
}

/// Parse the minimal `status\ncontent-type\n\n<body>` framing that
/// `serve_hs_request` produces. Returns `None` if the framing is
/// malformed (missing header lines or the blank-line separator).
fn parse_hs_response(bytes: &[u8]) -> Option<HsFetchResponse> {
    // Find the blank-line separator ("\n\n").
    let sep = bytes.windows(2).position(|w| w == b"\n\n")?;
    let header = std::str::from_utf8(&bytes[..sep]).ok()?;
    let body   = bytes[sep + 2..].to_vec();
    let mut lines = header.splitn(2, '\n');
    let status: u16 = lines.next()?.trim().parse().ok()?;
    let content_type = lines.next().unwrap_or("application/octet-stream").trim().to_string();
    Some(HsFetchResponse { status, content_type, body })
}

pub struct PhiNode {
    pub host:    String,
    pub port:    u16,
    pub cert:    RwLock<PhiCert>,
    pub keypair: StaticKeypair,
    pub pow:     AdmissionPoW,

    pub routing: RoutingTable,
    pub dht:     DhtStore,
    pub board:   MessageBoard,
    pub hs_mgr:  HsManager,
    pub store:   Arc<SiteStore>,

    peers:  ARwLock<HashMap<[u8; 32], Arc<PeerConn>>>,
    /// Clean circuits built ahead of demand. See `circuit_pool`.
    pool:   std::sync::Mutex<crate::circuit_pool::CircuitPool>,
    /// Operator family label, reported to the bandwidth scanner and thence
    /// into the consensus. Empty means unaffiliated. See `path_select`.
    family: std::sync::RwLock<String>,
    /// Observed circuit build times, which set the build timeout. See
    /// `circuit_timing`.
    build_times: std::sync::Mutex<crate::circuit_timing::BuildTimes>,
    /// Per-guard circuit outcomes, to catch a guard steering us onto paths
    /// it controls. See `path_bias`.
    path_bias: std::sync::Mutex<crate::path_bias::PathBias>,
    /// Per-address circuit/connection limits. Off unless the operator turns
    /// it on. See `dos`.
    dos: std::sync::Mutex<crate::dos::DosGuard>,
    /// Ed25519 key this relay signs its descriptor with. See `relay_desc`.
    signing_key: std::sync::RwLock<Option<ed25519_dalek::SigningKey>>,
    /// Signing keys pinned to node ids, learned over authenticated links.
    /// A descriptor claiming a node id must match what we pinned for it —
    /// otherwise a valid signature would only prove someone owns *a* key.
    pinned_keys: std::sync::RwLock<HashMap<[u8; 32], String>>,
    /// Verified descriptors, by node id hex.
    descriptors: std::sync::RwLock<HashMap<String, crate::relay_desc::RelayDescriptor>>,
    /// The bounded set of guards this client is ever willing to use, and
    /// where it's persisted. See `guard_sample`.
    guard_sample: std::sync::RwLock<crate::guard_sample::SampledSet>,
    guard_sample_path: std::sync::RwLock<Option<std::path::PathBuf>>,
    guards: ARwLock<Vec<PeerInfo>>,

    /// Persistent guard tracking. Survives daemon restarts to prevent
    /// the first-hop rotation attack.
    pub guard_mgr: Arc<crate::guards::GuardManager>,

    /// Layer-2 vanguard set for HS-related circuits. Used as the
    /// second hop of any circuit built via `build_hs_circuit`. See
    /// `vanguards.rs` for the threat model. Persistent across daemon
    /// restarts.
    pub vanguards: Arc<crate::vanguards::Vanguards>,

    /// Operator-configured padding scheduler for HS-side circuits.
    /// `None` means use `NoPadding` (no traffic generated). Set via
    /// `set_hs_padding_scheduler` from daemon startup or runtime.
    /// Applies to circuits built via the HS rendezvous drain
    /// (`drain_hs_pending_rendezvous`); doesn't affect general
    /// `build_circuit` calls.
    pub hs_padding_scheduler: ARwLock<Option<Arc<dyn crate::padding::PaddingScheduler>>>,

    /// Per-node state machine for multi-hop circuits (CREATE/EXTEND2/RELAY).
    /// Shared across all peer connections so a RelayCircuit on one
    /// incoming conn can forward to a different outgoing conn.
    pub circuits: ARwLock<crate::circuit_mgr::CircuitManager>,

    /// HS-side pending rendezvous intents. Each entry is an
    /// INTRODUCE2 we've decrypted and ready to act on. A background
    /// task drains these, builds circuits to the named RPs, and sends
    /// RENDEZVOUS1. Queue is bounded to prevent OOM from a flood of
    /// introductions.
    hs_pending_rendezvous: ARwLock<std::collections::VecDeque<HsRendezvousIntent>>,

    /// Client-side rendezvous completion waiters. Keyed by the RP
    /// origin-circuit id. When `hs_fetch` (or any caller) drives a
    /// rendezvous, it registers a oneshot here before sending
    /// INTRODUCE1, then awaits it. `handle_rendezvous2` fires the
    /// matching sender once it has either installed the e2e keys
    /// (`Ok`) or rejected a forged/failed RENDEZVOUS2 (`Err`). This is
    /// the bridge between the async handle-loop (which processes the
    /// inbound RENDEZVOUS2 cell) and the orchestration future that
    /// initiated the fetch — without it, `hs_fetch` has no way to know
    /// the handshake finished and would have to poll `e2e_keys`.
    rendezvous_waiters: ARwLock<HashMap<
        crate::circuit::CircuitId,
        tokio::sync::oneshot::Sender<Result<()>>,
    >>,

    /// Client-side waiters for active HS descriptor lookups, keyed by the
    /// lookup req_id. `lookup_hs_descriptor` registers one, broadcasts an
    /// HsLookup to peers, and awaits the first HsFound that carries a
    /// descriptor. Needed because `get_hs` is a purely local cache read —
    /// descriptors are only stored on the node that published them, so a
    /// client must ask the network before it can rendezvous.
    hs_lookup_waiters: ARwLock<HashMap<
        String,
        tokio::sync::oneshot::Sender<Option<crate::wire::HsDescriptor>>,
    >>,

    /// Client-side collectors for end-to-end HS responses. Keyed by the
    /// RP origin CircuitId. After `hs_fetch` sends its request over the
    /// e2e channel it registers an mpsc sender here; the origin
    /// dispatch pushes each inbound e2e DATA chunk into it and signals
    /// end-of-response by dropping the sender (on END) so the collector
    /// sees the channel close. Separate from the stream mux because e2e
    /// HS responses aren't tied to an exit TCP stream.
    hs_response_collectors: ARwLock<HashMap<
        crate::circuit::CircuitId,
        tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    >>,

    /// Monotonic sequence number for our own cert rotations.
    /// Starts at 0; each rotation broadcast increments and includes it,
    /// so peers can reject replays and out-of-order announcements.
    rotation_seq: AtomicU64,

    /// Last rotation sequence accepted per old-node-id. Guards against
    /// replay of a stale CertRotate: a peer who sees a valid rotation
    /// with seq=N will reject any later rotation from the same old_id
    /// with seq≤N.
    seen_rotation_seqs: ARwLock<HashMap<[u8; 32], u64>>,

    /// Persistent replay cache for gossip messages (DHT stores, HS
    /// descriptors, board posts). Entries have a TTL so the cache
    /// stays bounded across long-running nodes.
    pub replay_cache: Arc<crate::replay::ReplayCache>,

    /// Exit-side TCP write halves, keyed by (circ_id, stream_id). When
    /// we accept a BEGIN from a client and open a TCP connection, the
    /// write half goes here so subsequent DATA cells can be pumped
    /// into the socket. Read half is owned by a spawned task.
    exit_writers: ARwLock<HashMap<
        (crate::circuit::CircuitId, u16),
        Arc<Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>>
    >>,

    /// Exit policy: rules for which destinations this node will
    /// open TCP connections to when acting as an exit. Default
    /// blocks private ranges, loopback, and common abuse ports.
    /// Wrapped in RwLock so operators (and integration tests) can
    /// adjust the policy at runtime without restarting.
    pub exit_policy: RwLock<crate::exit_policy::ExitPolicy>,

    pub high_security: bool,

    /// Triggered by `shutdown()`. Background loops observe this via
    /// `shutdown.notified()` and exit cleanly. The accept loop in
    /// `run()` selects on this too, so a shutdown signal causes
    /// `run()` to return `Ok(())` rather than hang forever.
    ///
    /// Using `Notify` (not `oneshot`) so multiple tasks can observe
    /// the same signal — notify_waiters wakes all current waiters.
    shutdown: Arc<tokio::sync::Notify>,

    /// Set once the node has started shutting down. Background tasks
    /// check this on each loop iteration to avoid racing past the
    /// shutdown signal. Without this flag, a task that's mid-sleep
    /// when `shutdown()` is called could wake up and do one more
    /// iteration before seeing the Notify.
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,

    /// Pluggable transport for peer-to-peer connections. Default
    /// is `PlainTcp`. Operators in censored regions can swap in a
    /// `SubprocessTransport` wrapping obfs4proxy/meek-client/snowflake-client
    /// to disguise ΦNET traffic.
    ///
    /// **Currently used for outbound `connect()` only.** The accept
    /// loop in `run()` still binds a raw TCP listener — relays accept
    /// connections from many transports, and which one a peer dialed
    /// in on isn't visible here (the obfs is on the wire below us).
    /// Replacing the listener with `transport.listen()` is a
    /// straightforward extension when needed.
    /// connections from many transports, and which one a peer dialed
    /// in on isn't visible here (the obfs is on the wire below us).
    /// Replacing the listener with `transport.listen()` is a
    /// straightforward extension when needed.
    pub transport: Arc<dyn crate::transport::Transport>,

    /// Client-only mode: this node consumes the network but doesn't
    /// participate as a relay. In this mode the accept loop in
    /// `run()` doesn't bind a listener at all, so no one can dial
    /// in. Outbound circuit-build still works.
    ///
    /// Default: false (participate as a relay).
    pub client_only: std::sync::atomic::AtomicBool,

    /// Trusted directory-authority Ed25519 public keys. Used by
    /// `verify_consensus` to decide which signatures count toward
    /// the threshold. Empty by default (operator must populate
    /// either via daemon flags or by loading from a trust file).
    pub trusted_authorities: tokio::sync::RwLock<Vec<[u8; 32]>>,

    /// Most recently fetched-and-verified consensus document. Set
    /// by `consensus_fetch_loop` (or a manual `consensus_load`
    /// control command). Path selection consults this for
    /// authoritative bandwidth weights and flag info.
    pub cached_consensus: tokio::sync::RwLock<Option<crate::directory::ConsensusDocument>>,
    /// End-to-end "com" message store (received + sent), grouped into
    /// per-peer conversation threads.
    pub com_inbox: ARwLock<crate::com::Inbox>,
    /// Store-and-forward mailbox: sealed envelopes this node holds on
    /// behalf of (possibly offline) recipients until they pull them.
    pub com_mailbox: ARwLock<crate::com::Mailbox>,
    /// Learned com contacts: node id → static X25519 key. Populated from
    /// authenticated peers and from senders of opened messages, so we
    /// can seal a reply to someone even after they go offline.
    pub com_contacts: ARwLock<std::collections::HashMap<[u8; 32], [u8; 32]>>,
    /// Groups and channels we're a member of, keyed by group id.
    pub com_groups: ARwLock<std::collections::HashMap<[u8; 16], crate::com::Group>>,
}

impl PhiNode {
    pub fn new(host: &str, port: u16, cert: PhiCert, store: Arc<SiteStore>) -> Arc<Self> {
        Self::new_with_keypair(host, port, cert, store, StaticKeypair::generate())
    }

    /// Build a node with a caller-supplied static keypair. Relays must pass
    /// a *persisted* key: the consensus publishes this key as the relay's
    /// `B`, so regenerating it on restart invalidates the published entry
    /// and every client CREATE fails the ntor handshake.
    pub fn new_with_keypair(
        host: &str, port: u16, cert: PhiCert, store: Arc<SiteStore>,
        keypair: StaticKeypair,
    ) -> Arc<Self> {
        let node_id = cert.node_id();
        let pow     = solve_admission(&cert).expect("admission PoW failed");
        Arc::new(PhiNode {
            host:    host.to_string(),
            port,
            cert:    RwLock::new(cert),
            keypair,
            pow,
            routing: RoutingTable::new(node_id),
            dht:     DhtStore::new(),
            board:   {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("board.log");
                MessageBoard::open(path).unwrap_or_else(|e| {
                    warn!("board: persistence disabled: {}", e);
                    MessageBoard::new()
                })
            },
            hs_mgr:  HsManager::new(store.clone()),
            store,
            peers:         ARwLock::new(HashMap::new()),
            pool:          std::sync::Mutex::new(crate::circuit_pool::CircuitPool::new()),
            family:        std::sync::RwLock::new(String::new()),
            build_times:   std::sync::Mutex::new(crate::circuit_timing::BuildTimes::new()),
            path_bias:     std::sync::Mutex::new(crate::path_bias::PathBias::new()),
            dos:           std::sync::Mutex::new(crate::dos::DosGuard::new()),
            signing_key:   std::sync::RwLock::new(None),
            pinned_keys:   std::sync::RwLock::new(HashMap::new()),
            descriptors:   std::sync::RwLock::new(HashMap::new()),
            guard_sample:  std::sync::RwLock::new(crate::guard_sample::SampledSet::new()),
            guard_sample_path: std::sync::RwLock::new(None),
            guards:        ARwLock::new(Vec::new()),
            guard_mgr: {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("guards.json");
                Arc::new(crate::guards::GuardManager::open(path).unwrap_or_else(|e| {
                    warn!("guards: persistence disabled: {}", e);
                    crate::guards::GuardManager::open(
                        std::path::PathBuf::from("/tmp/phinet_guards.json")
                    ).unwrap()
                }))
            },
            vanguards: {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("vanguards.json");
                Arc::new(crate::vanguards::Vanguards::open(path).unwrap_or_else(|e| {
                    warn!("vanguards: persistence disabled: {}", e);
                    crate::vanguards::Vanguards::open(
                        std::path::PathBuf::from("/tmp/phinet_vanguards.json")
                    ).unwrap()
                }))
            },
            hs_padding_scheduler: ARwLock::new(None),
            circuits:      ARwLock::new(crate::circuit_mgr::CircuitManager::new()),
            hs_pending_rendezvous: ARwLock::new(std::collections::VecDeque::new()),
            rendezvous_waiters:    ARwLock::new(HashMap::new()),
            hs_lookup_waiters:     ARwLock::new(HashMap::new()),
            hs_response_collectors: ARwLock::new(HashMap::new()),
            rotation_seq:          AtomicU64::new(0),
            seen_rotation_seqs:    ARwLock::new(HashMap::new()),
            replay_cache: {
                let dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".phinet");
                let path = dir.join("replay.log");
                // 24-hour TTL: long enough that legitimate delayed
                // messages still dedupe, short enough that the cache
                // doesn't grow unbounded.
                Arc::new(crate::replay::ReplayCache::open(path, 24 * 3600).unwrap_or_else(|e| {
                    warn!("replay: persistence disabled: {}", e);
                    crate::replay::ReplayCache::open(
                        std::path::PathBuf::from("/tmp/phinet_replay.log"),
                        24 * 3600,
                    ).unwrap()
                }))
            },
            exit_writers:  ARwLock::new(HashMap::new()),
            exit_policy:   RwLock::new(crate::exit_policy::ExitPolicy::default()),
            high_security: false,
            shutdown:      Arc::new(tokio::sync::Notify::new()),
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            transport: Arc::new(crate::transport::PlainTcp),
            client_only:         std::sync::atomic::AtomicBool::new(false),
            trusted_authorities: tokio::sync::RwLock::new(Vec::new()),
            cached_consensus:    tokio::sync::RwLock::new(None),
            com_inbox:           ARwLock::new(crate::com::Inbox::new()),
            com_mailbox:         ARwLock::new(crate::com::Mailbox::new(24 * 3600)),
            com_contacts:        ARwLock::new(std::collections::HashMap::new()),
            com_groups:          ARwLock::new(std::collections::HashMap::new()),
        })
    }

    pub fn node_id(&self) -> [u8; 32]  { self.cert.read().unwrap().node_id() }
    pub fn node_id_hex(&self) -> String { hex::encode(self.node_id()) }

    /// Current depth of the HS-side pending-rendezvous queue. Used by
    /// integration tests to confirm INTRODUCE2 decryption and intent
    /// enqueueing succeeded.
    pub async fn hs_rendezvous_pending_len(&self) -> usize {
        self.hs_pending_rendezvous.read().await.len()
    }

    /// Current public x25519 static key for this node. Needed by
    /// rendezvous clients that are told about us via a descriptor.
    pub fn static_pub(&self) -> [u8; 32] {
        self.keypair.public_bytes()
    }

    /// Snapshot of currently-connected peers' PeerInfo. Used primarily
    /// for diagnostics, CLI status output, and integration tests.
    pub async fn peers_snapshot(&self) -> Vec<crate::dht::PeerInfo> {
        self.peers.read().await.values()
            .map(|p| p.info.clone())
            .collect()
    }

    // ── Server ────────────────────────────────────────────────────────

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let client_only = self.client_only.load(std::sync::atomic::Ordering::Relaxed);
        let addr        = format!("{}:{}", self.host, self.port);

        // In client-only mode we don't bind a listener — the node
        // doesn't accept inbound connections. Outbound circuit
        // construction (build_circuit, connect, hs_fetch) all still
        // work because they go through the transport's dial path.
        let listener: Option<TcpListener> = if client_only {
            info!("ΦNET node in client-only mode (no listener)");
            info!("  node_id = {}…", &self.node_id_hex()[..16]);
            None
        } else {
            let l = TcpListener::bind(&addr).await?;
            info!("ΦNET node listening on {}", addr);
            info!("  node_id = {}…", &self.node_id_hex()[..16]);
            Some(l)
        };

        // Background tasks
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.guard_refresh_loop().await });
        }
        {
            // Cert rotation changes the node_id, which conflicts with the
            // stable identity that consensus relies on (a rotated relay no
            // longer matches its consensus entry → reap/reconnect churn that
            // tears down circuits). OFF by default; opt in with
            // PHINET_CERT_ROTATE=1 for ephemeral client unlinkability only.
            if std::env::var("PHINET_CERT_ROTATE").as_deref() == Ok("1") {
                let n = Arc::clone(&self);
                tokio::spawn(async move { n.rotation_loop().await });
            }
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.hs_republish_loop().await });
        }
        {
            // Keep circuits warm so a fetch doesn't start with three
            // handshakes the user has to sit through.
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.circuit_pool_loop().await });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.com_maintenance_loop().await });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    // Race sleep against shutdown so the task doesn't
                    // linger ~5 minutes after a shutdown signal.
                    tokio::select! {
                        _ = time::sleep(Duration::from_secs(300)) => {}
                        _ = n.shutdown.notified() => break,
                    }
                    if n.is_shutting_down() { break; }
                    n.dht.evict_expired();
                    let dropped = n.replay_cache.evict_expired();
                    if dropped > 0 {
                        debug!("replay: evicted {} expired entries", dropped);
                    }
                    // Idle circuit eviction: reclaim state from
                    // circuits that haven't been used in
                    // CIRCUIT_IDLE_TIMEOUT. Without this, a daemon
                    // running for weeks accumulates dead circuits
                    // forever (each one holds ~KB of key state +
                    // stream mux).
                    let (o, r) = {
                        let mut mgr = n.circuits.write().await;
                        mgr.evict_idle_circuits()
                    };
                    if o > 0 || r > 0 {
                        info!("evicted {} idle origin circuits and {} idle relay circuits",
                              o, r);
                    }
                }
                debug!("gc loop: shutting down");
            });
        }
        // Dead-peer reaper: a live link is audible every second (padding),
        // so a peer silent for STALE_PEER_SECS has vanished without a
        // clean TCP close. Evict it from the peer table + routing so it
        // stops being snapshotted into the consensus as a ghost.
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = time::sleep(Duration::from_secs(15)) => {}
                        _ = n.shutdown.notified() => break,
                    }
                    if n.is_shutting_down() { break; }
                    n.reap_dead_peers(crate::com::now_secs()).await;
                }
                debug!("reaper loop: shutting down");
            });
        }
        {
            let n = Arc::clone(&self);
            tokio::spawn(async move { n.hs_rendezvous_drain_loop().await });
        }

        loop {
            // Select on accept vs shutdown so shutdown() causes a
            // clean return rather than an orphaned accept loop.
            // In client-only mode `listener` is None and we just
            // wait on shutdown — background tasks (consensus
            // refresh, guard rotation, etc) keep running.
            match &listener {
                Some(l) => {
                    tokio::select! {
                        accept_result = l.accept() => {
                            let (stream, addr) = accept_result?;
                            let node = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = node.handle_incoming(stream, addr).await {
                                    debug!("incoming {}: {}", addr, e);
                                }
                            });
                        }
                        _ = self.shutdown.notified() => {
                            info!("ΦNET node on {} shutting down", addr);
                            return Ok(());
                        }
                    }
                }
                None => {
                    // Client-only: no listener. Just wait for shutdown.
                    self.shutdown.notified().await;
                    info!("ΦNET client shutting down");
                    return Ok(());
                }
            }
        }
    }

    /// Signal every background task to stop, so `run()` returns
    /// cleanly. Idempotent — calling twice is fine.
    ///
    /// After shutdown, the PhiNode is no longer usable for new
    /// work. Outstanding operations (pending handshakes, in-flight
    /// circuit-build ntor steps) complete or fail based on their
    /// own timeouts; this method doesn't block to drain them.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        // notify_waiters wakes every task currently awaiting notified().
        // Tasks that later call notified() will see shutdown_flag set.
        self.shutdown.notify_waiters();
    }

    /// True if `shutdown()` has been called. Background tasks check
    /// this in their loops to avoid racing past the shutdown signal.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    // ── Handshake (responder) ─────────────────────────────────────────

    async fn handle_incoming<S>(self: Arc<Self>, stream: S, addr: SocketAddr) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Refuse before the handshake, not after. Everything below this line
        // costs CPU and memory that the peer hasn't earned yet, which is
        // precisely what makes flooding worthwhile.
        let peer_ip = addr.ip();
        if !self.dos.lock().unwrap().allow_connection(peer_ip) {
            debug!("refusing connection from {} — too many open", peer_ip);
            return Ok(());
        }
        // From here on the slot is held, so every exit path must release it.
        let _conn_slot = ConnSlot { node: Arc::clone(&self), ip: peer_ip };
        // Use tokio::io::split (works on any Unpin AsyncRead+AsyncWrite)
        // instead of TcpStream::into_split. The latter is only on
        // OwnedReadHalf/OwnedWriteHalf which are TCP-specific. Going
        // generic lets the same handler accept connections from
        // PlainTcp transport, obfs4 SOCKS5 streams, future TLS-wrapped
        // streams, etc — exactly what the Transport abstraction is for.
        let (r, w)  = tokio::io::split(stream);
        let mut rd  = BufReader::new(r);
        let mut wr  = BufWriter::new(w);

        // Step 1: send our ephemeral X25519 pub in the clear (inside a
        // PowChallenge). Only fixed-size random bytes cross the wire.
        let our_ephem = EphemeralKeypair::generate();
        wire::send_raw(&mut wr, &Message::PowChallenge(PowChallenge {
            challenge:    hex::encode(rand_bytes(32)),
            min_bits:     256,
            server_ephem: hex::encode(our_ephem.public_bytes()),
        })).await?;

        // Step 2: receive the initiator's ephemeral (cleartext ClientHello)
        // and derive the session key. Everything after this is encrypted.
        let ch = match time::timeout(HANDSHAKE_TIMEOUT, wire::recv_raw(&mut rd))
            .await.map_err(|_| Error::Handshake("timeout".into()))??
        {
            Message::ClientHello(c) => c,
            _ => return Err(Error::Handshake("expected CLIENT_HELLO".into())),
        };
        let ephem_peer: [u8; 32] = hex::decode(&ch.ephem_pub)
            .ok().and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Handshake("bad client ephem_pub".into()))?;
        let shared  = our_ephem.dh(&PublicKey::from(ephem_peer));
        let session = Arc::new(Session::new(&shared, false));

        // Step 3: read the initiator's HANDSHAKE — now encrypted under
        // the session, so the certificate (and its bit-size) never
        // appears on the wire in the clear.
        let msg = time::timeout(HANDSHAKE_TIMEOUT,
                                wire::recv_session(&mut rd, &session))
            .await.map_err(|_| Error::Handshake("timeout".into()))??;
        let hs = match msg {
            Message::Handshake(h) => h,
            _ => return Err(Error::Handshake("expected HANDSHAKE".into())),
        };

        let peer_cert = PhiCert::from_wire(&hs.cert)
            .map_err(|e| Error::Handshake(format!("cert: {e}")))?;
        if !peer_cert.verify() {
            wire::send_session(&mut wr, &Message::Reject(Reject { reason: "invalid cert".into() }), &session).await?;
            return Err(Error::Handshake("invalid cert".into()));
        }
        if !verify_admission(&peer_cert, &hs.admission_pow) {
            wire::send_session(&mut wr, &Message::Reject(Reject { reason: "invalid pow".into() }), &session).await?;
            return Err(Error::Handshake("invalid PoW".into()));
        }

        // Step 4: send our HANDSHAKE_ACK, also encrypted.
        let my_cert = self.cert.read().unwrap().clone();
        wire::send_session(&mut wr, &Message::HandshakeAck(HandshakeAck {
            cert:          my_cert.to_wire(),
            admission_pow: self.pow.clone(),
            ephem_pub:     String::new(), // ephemeral already exchanged in the clear
            mlkem_ct:      String::new(),
            static_pub:    hex::encode(self.keypair.public_bytes()),
            listen_port:   self.port,
        }), &session).await?;

        let info = PeerInfo {
            node_id:    peer_cert.node_id(),
            host:       addr.ip().to_string(),
            port:       hs.listen_port,
            cert:       hs.cert,
            static_pub: hs.static_pub,
        };
        self.register_peer(info, session, rd, wr, Some(addr.ip())).await
    }

    // ── Connect (initiator) ───────────────────────────────────────────

    pub async fn connect(self: Arc<Self>, host: &str, port: u16) -> Result<()> {
        // Dial via the configured transport. Default is PlainTcp; an
        // operator running with obfs4 / meek / snowflake configured
        // gets the obfuscated bytes-on-wire here transparently.
        let stream = self.transport.dial(host, port).await
            .map_err(|e| Error::Handshake(format!("transport dial: {e}")))?;
        let (r, w)  = tokio::io::split(stream);
        let mut rd  = BufReader::new(r);
        let mut wr  = BufWriter::new(w);

        // Step 1: receive the responder's ephemeral (cleartext
        // PowChallenge) and derive the session key up front.
        let challenge = match wire::recv_raw(&mut rd).await? {
            Message::PowChallenge(c) => c,
            _ => return Err(Error::Handshake("expected POW_CHALLENGE".into())),
        };
        let server_ephem: [u8; 32] = hex::decode(&challenge.server_ephem)
            .ok().and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Handshake("bad server ephem".into()))?;
        let our_ephem = EphemeralKeypair::generate();
        let shared    = our_ephem.dh(&PublicKey::from(server_ephem));
        let session   = Arc::new(Session::new(&shared, true));

        // Step 2: announce our ephemeral in the clear so the responder
        // derives the same key.
        wire::send_raw(&mut wr, &Message::ClientHello(wire::ClientHello {
            ephem_pub: hex::encode(our_ephem.public_bytes()),
        })).await?;

        // Step 3: send our HANDSHAKE encrypted under the session — the
        // certificate never crosses the wire in the clear.
        let cert = self.cert.read().unwrap().clone();
        wire::send_session(&mut wr, &Message::Handshake(Handshake {
            version:       PROTOCOL_VERSION,
            cert:          cert.to_wire(),
            admission_pow: self.pow.clone(),
            ephem_pub:     String::new(), // ephemeral already exchanged in the clear
            mlkem_pub:     String::new(),
            static_pub:    hex::encode(self.keypair.public_bytes()),
            listen_port:   self.port,
        }), &session).await?;

        // Step 4: read the encrypted HANDSHAKE_ACK.
        let msg = time::timeout(HANDSHAKE_TIMEOUT,
                                wire::recv_session(&mut rd, &session))
            .await.map_err(|_| Error::Handshake("timeout".into()))??;
        let ack = match msg {
            Message::HandshakeAck(a) => a,
            Message::Reject(r)       => return Err(Error::Handshake(r.reason)),
            _ => return Err(Error::Handshake("expected ACK".into())),
        };

        let peer_cert = PhiCert::from_wire(&ack.cert)?;
        let info      = PeerInfo {
            node_id:    peer_cert.node_id(),
            host:       host.to_string(),
            port,
            cert:       ack.cert,
            static_pub: ack.static_pub,
        };
        self.register_peer(info, session, rd, wr, None).await
    }

    /// Lightweight reachability + identity probe. Dials `host:port`, completes
    /// the handshake, and returns the node_id that actually answers there —
    /// then drops the connection (no peer registered). Used to verify a
    /// consensus/genesis candidate is a real, reachable relay whose advertised
    /// address hosts the advertised identity. NAT'd clients (no inbound
    /// reachability) time out and fail; ghosts (dead identity) answer with a
    /// different node_id (or nothing) and are rejected by the caller.
    pub async fn probe_relay(&self, host: &str, port: u16) -> Option<[u8; 32]> {
        let stream = match time::timeout(
            Duration::from_secs(6), self.transport.dial(host, port)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };
        let (r, w) = tokio::io::split(stream);
        let mut rd = BufReader::new(r);
        let mut wr = BufWriter::new(w);

        // Step 1: responder ephemeral → session key.
        let challenge = match wire::recv_raw(&mut rd).await {
            Ok(Message::PowChallenge(c)) => c,
            _ => return None,
        };
        let server_ephem: [u8; 32] = hex::decode(&challenge.server_ephem).ok()
            .and_then(|b| b.try_into().ok())?;
        let our_ephem = EphemeralKeypair::generate();
        let shared    = our_ephem.dh(&PublicKey::from(server_ephem));
        let session   = Arc::new(Session::new(&shared, true));

        // Step 2: announce our ephemeral.
        if wire::send_raw(&mut wr, &Message::ClientHello(wire::ClientHello {
            ephem_pub: hex::encode(our_ephem.public_bytes()),
        })).await.is_err() { return None; }

        // Step 3: send our handshake.
        let cert = self.cert.read().unwrap().clone();
        if wire::send_session(&mut wr, &Message::Handshake(Handshake {
            version:       PROTOCOL_VERSION,
            cert:          cert.to_wire(),
            admission_pow: self.pow.clone(),
            ephem_pub:     String::new(),
            mlkem_pub:     String::new(),
            static_pub:    hex::encode(self.keypair.public_bytes()),
            listen_port:   self.port,
        }), &session).await.is_err() { return None; }

        // Step 4: read ACK → the identity actually answering at this address.
        let msg = time::timeout(HANDSHAKE_TIMEOUT,
                                wire::recv_session(&mut rd, &session)).await.ok()?.ok()?;
        let ack = match msg { Message::HandshakeAck(a) => a, _ => return None };
        let peer_cert = PhiCert::from_wire(&ack.cert).ok()?;
        Some(peer_cert.node_id())
        // rd/wr dropped here — probe connection closed, nothing registered.
    }

    /// Verify current peers are reachable relays answering with their
    /// advertised identity. Returns only peers that pass the probe — used by
    /// `gen-genesis` so NAT'd clients and stale ghosts never enter a genesis.
    pub async fn verified_relays(self: &Arc<Self>) -> Vec<crate::dht::PeerInfo> {
        let candidates = self.all_peers().await;
        let mut ok = Vec::new();
        for p in candidates {
            if let Some(answered) = self.probe_relay(&p.host, p.port).await {
                if answered == p.node_id {
                    ok.push(p);
                }
            }
        }
        ok
    }

    // ── Peer registration ─────────────────────────────────────────────

    async fn register_peer<R, W>(
        self: Arc<Self>,
        info: PeerInfo,
        session: Arc<Session>,
        reader: BufReader<R>,
        writer: BufWriter<W>,
        // The socket this peer connected from, for inbound links. `None`
        // when we dialled out — we chose that peer, so there's nothing to
        // rate limit.
        remote_ip: Option<std::net::IpAddr>,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Reject connections to ourselves
        if info.node_id == self.node_id() {
            debug!("Rejected self-connection from {}:{}", info.host, info.port);
            return Err(Error::Handshake("self-connection rejected".into()));
        }

        // Reject already-connected peers
        if self.peers.read().await.contains_key(&info.node_id) {
            debug!("Already connected to {}…", &hex::encode(info.node_id)[..12]);
            return Ok(());
        }

        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        let queues = Arc::new(CellQueues::new());
        let peer = Arc::new(PeerConn {
            info: info.clone(),
            sender: tx,
            session: Arc::clone(&session),
            last_seen: AtomicU64::new(crate::com::now_secs()),
            remote_ip,
            queues: Arc::clone(&queues),
        });

        self.routing.add_peer(info.clone());
        self.peers.write().await.insert(info.node_id, Arc::clone(&peer));

        // Send our descriptor over the link the handshake just authenticated.
        // The peer pins the signing key it sees here, and from then on can
        // check anything we sign — including descriptors that reach it via
        // someone else.
        if let Some(d) = self.my_descriptor() {
            let _ = peer.send_msg(&Message::RelayDesc(d)).await;
        }
        // Remember the peer's static key so we can seal com messages to
        // it later, including after it disconnects.
        if let Some(pk) = hex::decode(&info.static_pub).ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        {
            self.com_contacts.write().await.insert(info.node_id, pk);
        }
        info!("Peer {}…  @{}:{}", &hex::encode(info.node_id)[..12], info.host, info.port);

        // Persistent guard tracking: every outbound-initiated successful
        // connection is a candidate for becoming a guard, and any
        // connection to an already-chosen guard should be marked.
        self.guard_mgr.add_candidate(&info.node_id, &info.host, info.port);
        self.guard_mgr.mark_success(&info.node_id);
        self.guard_mgr.save_best_effort();

        // Writer task.
        //
        // Two sources: control frames (handshakes, com, padding) go straight
        // out, and circuit cells are chosen by the scheduler. Control is
        // checked first because it's low-volume and latency-sensitive —
        // and because a busy relay must never be too loaded to answer a
        // handshake. Circuit cells then leave quietest-first rather than in
        // arrival order.
        let wq = Arc::clone(&queues);
        let wsession = Arc::clone(&session);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut wr = writer;
            let mut rx = rx;
            loop {
                // Control first.
                match rx.try_recv() {
                    Ok(frame) => {
                        if wr.write_all(&frame).await.is_err() { break; }
                        if wr.flush().await.is_err()           { break; }
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                }
                // Then whichever circuit the scheduler picks. Sealing happens
                // here, so seal order is wire order and the peer's nonce
                // counter always advances by one.
                if let Some((_cid, msg)) = wq.pop_next() {
                    let frame = match crate::wire::frame_message(&wsession, &msg) {
                        Ok(f) => f,
                        Err(e) => { debug!("framing circuit cell: {}", e); continue; }
                    };
                    if wr.write_all(&frame).await.is_err() { break; }
                    if wr.flush().await.is_err()           { break; }
                    continue;
                }
                // Nothing to send: sleep until either side has work. Both
                // arms are cancel-safe, so losing the race can't drop a frame
                // — it stays queued and we come back for it.
                tokio::select! {
                    r = rx.recv() => match r {
                        Some(frame) => {
                            if wr.write_all(&frame).await.is_err() { break; }
                            if wr.flush().await.is_err()           { break; }
                        }
                        None => break,
                    },
                    _ = wq.wait() => {}
                }
            }
        });

        // Padding task
        if PADDING_RATE_HZ > 0.0 {
            let p = Arc::clone(&peer);
            tokio::spawn(async move {
                let interval = Duration::from_secs_f64(1.0 / PADDING_RATE_HZ);
                loop {
                    time::sleep(interval).await;
                    let _ = p.send_msg(&Message::Padding(Padding {
                        data: hex::encode(TrafficPadder::dummy_cell()),
                    })).await;
                }
            });
        }

        // Reader task
        let node    = Arc::clone(&self);
        let peer_id = info.node_id;
        let sess    = Arc::clone(&session);
        tokio::spawn(async move {
            let mut rd = reader;
            loop {
                match wire::recv_session(&mut rd, &sess).await {
                    Ok(msg)            => { peer.touch(); Arc::clone(&node).dispatch(msg, &peer).await },
                    Err(Error::Closed) => break,
                    Err(e)             => { debug!("peer: {}", e); break; }
                }
            }
            node.peers.write().await.remove(&peer_id);
            info!("Peer {}… disconnected", &hex::encode(peer_id)[..12]);
        });

        Ok(())
    }

    // ── Dispatch ──────────────────────────────────────────────────────

    async fn dispatch(self: Arc<Self>, msg: Message, src: &Arc<PeerConn>) {
        match msg {
            Message::Onion(o)       => self.handle_onion(o).await,
            Message::CircuitCell(c)  => self.handle_circuit_cell(c, src).await,
            Message::DhtFind(f)     => self.handle_dht_find(f, src).await,
            Message::DhtFound(f)    => self.handle_dht_found(f),
            Message::DhtStore(s)    => {
                // DHT store: the key uniquely identifies the record,
                // so (key|first 8 bytes of value) is a natural replay ID.
                let rid = format!("dht:{}", hex::encode(&s.key));
                if !self.replay_cache.mark(&rid) {
                    debug!("dht store: replay rejected {}", &rid[..24.min(rid.len())]);
                } else {
                    self.dht.put(s.key, s.value)
                }
            }
            Message::RelayDesc(d)   => {
                // If this descriptor describes the peer that sent it, the
                // link authenticated them: the handshake proved they hold the
                // cert and static key for that node id, so the signing key
                // they present is theirs and we can pin it. This first
                // meeting is the only moment a key becomes attributable —
                // afterwards, everything is checked against the pin.
                if d.node_id_hex == hex::encode(src.info.node_id) {
                    if !self.pin_signing_key(src.info.node_id, d.signing_pub_hex.clone()) {
                        return;   // key changed under us — refuse, don't re-pin
                    }
                }
                // Verified against the key pinned for this node id when we
                // first met it over an authenticated link. A descriptor for a
                // node we've never met has nothing to check against, so it's
                // refused — a correct signature over a lie is still a lie.
                let id = d.node_id_hex.clone();
                if self.accept_descriptor(d.clone()) {
                    debug!("accepted descriptor for {} (family={:?})",
                           &id[..12.min(id.len())], d.family);
                    // Gossip onward. A descriptor carries its own proof, so
                    // passing it on can't launder a forgery: the next relay
                    // checks the same pin we did.
                    let peers = self.peers.read().await;
                    for p in peers.values() {
                        if p.info.node_id != src.info.node_id {
                            let _ = p.send_msg(&Message::RelayDesc(d.clone())).await;
                        }
                    }
                }
            }
            Message::DhtFetch(f)    => self.handle_dht_fetch(f, src).await,
            Message::HsRegister(r)  => {
                // Verify the descriptor was signed by its claimed HS
                // identity before caching it. An attacker who controls
                // an HSDir or who gossips descriptors can't redirect
                // clients to attacker-controlled intros because the
                // binding hs_id → identity_pub → signature is enforced.
                //
                // Descriptors without signatures (identity_pub or sig
                // fields empty) are rejected — v1 of the network
                // requires signed descriptors.
                if let Err(e) = crate::hs_identity::verify_descriptor(&r.descriptor) {
                    debug!("hs register: reject unsigned/invalid descriptor for {}: {}",
                           r.descriptor.hs_id, e);
                    return;
                }
                let rid = format!("hs:{}", r.descriptor.hs_id);
                if !self.replay_cache.mark(&rid) {
                    debug!("hs register: replay rejected {}", r.descriptor.hs_id);
                } else {
                    self.dht.put_hs(&r.descriptor)
                }
            }
            Message::HsLookup(l)    => self.handle_hs_lookup(l, src).await,
            Message::HsFound(f)     => self.handle_hs_found(f).await,
            Message::BoardPost(p)   => self.handle_board_post(p, src).await,
            Message::BoardFetch(f)  => self.handle_board_fetch(f, src).await,
            Message::Padding(_)     => {} // cover traffic, discard
            Message::Com(env)       => self.handle_com(env).await,
            Message::ComStore(env)  => self.handle_com_store(env, src).await,
            Message::ComGroupStore(env) => self.handle_com_group_store(env, src).await,
            Message::ComFetch(f)    => self.handle_com_fetch(f, src).await,
            Message::ComMail(m)     => self.handle_com_mail(m).await,
            Message::CertRotate(r)  => self.handle_cert_rotate(r, src).await,
            _                       => {}
        }
    }

    // ── com (end-to-end messaging) ────────────────────────────────────

    /// Handle an inbound com envelope: if it's addressed to us and
    /// opens, store the decrypted message in our inbox. Otherwise drop
    /// (a full mailbox deployment would relay/park it instead).
    async fn handle_com(&self, env: crate::com::ComEnvelope) {
        match crate::com::open(&self.keypair.secret, self.static_pub(), &env) {
            Ok(opened) => {
                self.com_contacts.write().await
                    .insert(opened.sender_id, opened.sender_pub);
                // An unsend: delete the referenced message rather than store this.
                if let Some(del_id) = crate::com::decode_delete(&opened.body) {
                    self.com_inbox.write().await.remove(&del_id);
                    return;
                }
                // A message body may be a group invite (key distribution)
                // rather than a chat message.
                if let Some(group) = crate::com::decode_invite(&opened.body) {
                    let gid = group.group_id;
                    self.com_groups.write().await.insert(gid, group.clone());
                    info!("com: joined group/channel '{}' ({})",
                          group.name, group.id_hex());
                    return;
                }
                let stored = crate::com::StoredMessage {
                    msg_id:    opened.msg_id,
                    peer_id:   opened.sender_id,
                    outgoing:  false,
                    timestamp: opened.timestamp,
                    body:      opened.body,
                };
                if self.com_inbox.write().await.record(stored) {
                    info!("com: message from {}…",
                          &hex::encode(opened.sender_id)[..12]);
                }
            }
            Err(_) => debug!("com: envelope not for us / undecryptable, dropping"),
        }
    }

    /// Store-and-forward for a 1:1 sealed envelope. If addressed to us
    /// (by blinded address), open it; otherwise hold it in our mailbox
    /// and re-gossip once. Sealed-sender + blinded addressing mean we
    /// learn nothing about who is talking to whom.
    async fn handle_com_store(&self, env: crate::com::ComEnvelope, src: &Arc<PeerConn>) {
        if crate::com::addressed_to_us(&self.static_pub(), &env) {
            self.handle_com(env).await;
            return;
        }
        let fresh = self.com_mailbox.write().await.store(env.clone(), crate::com::now_secs());
        if !fresh { return; }
        let peers = self.peers.read().await;
        for p in peers.values() {
            if p.info.node_id != src.info.node_id {
                let _ = p.send_msg(&Message::ComStore(env.clone())).await;
            }
        }
    }

    /// Store-and-forward for a group message. We can't tell if it's "for
    /// us" (group addresses are shared), so always hold + re-gossip; the
    /// maintenance loop pulls group mail for groups we're in.
    async fn handle_com_group_store(&self, env: crate::com::GroupEnvelope, src: &Arc<PeerConn>) {
        // If it's for a group we're in, file it immediately too.
        if let Some(gid) = hex::decode(&env.group_id).ok()
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
        {
            let found = self.com_groups.read().await.get(&gid).cloned();
            if let Some(group) = found {
                self.file_group_msg(&group, &env).await;
            }
        }
        let fresh = self.com_mailbox.write().await
            .store_group(env.clone(), crate::com::now_secs());
        if !fresh { return; }
        let peers = self.peers.read().await;
        for p in peers.values() {
            if p.info.node_id != src.info.node_id {
                let _ = p.send_msg(&Message::ComGroupStore(env.clone())).await;
            }
        }
    }

    /// Serve mail held under the blinded addresses the requester asks
    /// for. The addresses are capabilities (derived from a recipient's
    /// or group's key), so knowing one already implies authorization;
    /// contents are sealed regardless.
    async fn handle_com_fetch(&self, msg: crate::wire::ComFetch, src: &Arc<PeerConn>) {
        let (mut envelopes, mut group_envelopes) = (Vec::new(), Vec::new());
        {
            let mb = self.com_mailbox.read().await;
            for a in &msg.blinded {
                envelopes.extend(mb.peek(a));
                group_envelopes.extend(mb.peek_group(a));
            }
        }
        let _ = src.send_msg(&Message::ComMail(crate::wire::ComMail {
            req_id: msg.req_id, envelopes, group_envelopes,
        })).await;
    }

    /// File pulled mail: 1:1 envelopes addressed to us, and group
    /// envelopes for groups we belong to.
    async fn handle_com_mail(&self, msg: crate::wire::ComMail) {
        for env in msg.envelopes {
            if crate::com::addressed_to_us(&self.static_pub(), &env) {
                self.handle_com(env).await;
            }
        }
        for env in msg.group_envelopes {
            if let Some(gid) = hex::decode(&env.group_id).ok()
                .and_then(|v| <[u8; 16]>::try_from(v).ok())
            {
                if let Some(group) = self.com_groups.read().await.get(&gid).cloned() {
                    self.file_group_msg(&group, &env).await;
                }
            }
        }
    }

    /// Decrypt + verify a group message and record it in the group's
    /// conversation thread. Enforces the per-sender signer binding
    /// (TOFU): the first authenticated message from a member fixes its
    /// signing key; a later message claiming that member's id with a
    /// different key is rejected as spoofing.
    async fn file_group_msg(&self, group: &crate::com::Group,
                            env: &crate::com::GroupEnvelope) {
        let Ok((sender_id, sign_pub, body)) = crate::com::open_group(group, env)
            else { return };
        // Enforce + persist the signer binding on the stored group.
        {
            let mut groups = self.com_groups.write().await;
            if let Some(g) = groups.get_mut(&group.group_id) {
                if let Err(_) = g.bind_signer(sender_id, sign_pub) {
                    warn!("com: dropped group msg — signer spoofing attempt for {}…",
                          &hex::encode(sender_id)[..12]);
                    return;
                }
            }
        }
        let msg_id: [u8; 16] = hex::decode(&env.msg_id).ok()
            .and_then(|v| v.try_into().ok()).unwrap_or([0u8; 16]);
        let outgoing = sender_id == self.node_id();
        self.com_inbox.write().await.record(crate::com::StoredMessage {
            msg_id,
            peer_id: Self::group_thread_id(&group.group_id),
            outgoing,
            timestamp: env.timestamp,
            body,
        });
    }

    /// This node's stable Ed25519 com group-signing key.
    fn com_signer(&self) -> ed25519_dalek::SigningKey {
        crate::com::group_signer(&self.keypair.secret)
    }
    /// Public half of our com group-signing key.
    pub fn com_sign_pub(&self) -> [u8; 32] {
        crate::com::group_sign_pub(&self.keypair.secret)
    }

    /// Stable 32-byte conversation id for a group (namespaced so it
    /// can't collide with a real node id).
    pub fn group_thread_id(gid: &[u8; 16]) -> [u8; 32] {
        let mut buf = b"com-group".to_vec();
        buf.extend_from_slice(gid);
        crate::crypto::sha256(&buf)
    }

    /// Inject a sealed envelope into store-and-forward gossip as if it
    /// originated here. Called at a circuit exit for circuit-routed
    /// (sender-anonymous) delivery.
    async fn inject_com_store(&self, env: crate::com::ComEnvelope) {
        if crate::com::addressed_to_us(&self.static_pub(), &env) {
            self.handle_com(env).await;
            return;
        }
        let fresh = self.com_mailbox.write().await.store(env.clone(), crate::com::now_secs());
        if !fresh { return; }
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::ComStore(env.clone())).await;
        }
    }

    /// Pick up to `n` connected peers as a circuit path (deduplicated by
    /// node). Real anonymity wants ≥3 relays across distinct /16s from
    /// the consensus; this is the minimal "use whatever we're connected
    /// to" chooser for injection when a full path isn't available.
    /// Select up to `n` relays for an anonymity circuit. Prefers path
    /// diversity — distinct nodes and distinct /16 subnets per hop — but will
    /// still fill the path with same-subnet relays rather than fall short,
    /// so a circuit is always built when enough distinct nodes exist. Self is
    /// excluded and candidate order is shuffled for unpredictability.
    async fn com_circuit_path(&self, n: usize) -> Vec<crate::circuit::LinkSpec> {
        use rand::seq::SliceRandom;
        let me = self.node_id();
        let peers = self.peers.read().await;
        let mut cands: Vec<_> = peers.values().filter(|p| p.info.node_id != me).collect();
        cands.shuffle(&mut rand::thread_rng());

        let spec = |p: &&std::sync::Arc<PeerConn>| -> Option<crate::circuit::LinkSpec> {
            let sp = hex::decode(&p.info.static_pub).ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())?;
            Some(crate::circuit::LinkSpec {
                host: p.info.host.clone(), port: p.info.port,
                node_id: p.info.node_id, static_pub: sp,
            })
        };

        // Pass 1: prefer distinct /16 subnets (and distinct nodes).
        let mut out: Vec<crate::circuit::LinkSpec> = Vec::new();
        let mut used_subnets: Vec<[u8; 2]> = Vec::new();
        let mut used_nodes: Vec<[u8; 32]> = Vec::new();
        for p in &cands {
            if out.len() >= n { break; }
            let sn = crate::onion::subnet16(&p.info.host);
            if used_subnets.contains(&sn) { continue; }
            if let Some(ls) = spec(p) {
                used_subnets.push(sn);
                used_nodes.push(p.info.node_id);
                out.push(ls);
            }
        }
        // Pass 2: if we still need hops, fill from remaining distinct nodes
        // even if their subnet repeats — a full circuit beats a short one.
        if out.len() < n {
            for p in &cands {
                if out.len() >= n { break; }
                if used_nodes.contains(&p.info.node_id) { continue; }
                if let Some(ls) = spec(p) {
                    used_nodes.push(p.info.node_id);
                    out.push(ls);
                }
            }
        }
        out
    }

    /// **Sender-anonymous** send: seal the message, build a circuit
    /// through connected relays, and inject the envelope at the exit —
    /// so our own guard never sees us originate com traffic. Falls back
    /// to plain gossip (`com_send`) if no circuit can be built or the
    /// envelope is too large for a relay cell. Records our own copy.
    pub async fn com_send_anonymous(self: &Arc<Self>, recipient_id: [u8; 32],
                                    recipient_pub: [u8; 32], body: &str) -> Result<[u8; 16]>
    {
        let ts    = crate::com::now_secs();
        let epoch = crate::com::current_epoch();
        let env = crate::com::seal(&self.keypair.secret, self.node_id(), self.static_pub(),
                                   recipient_pub, epoch, ts, body.as_bytes());
        let msg_id: [u8; 16] = hex::decode(&env.msg_id).ok()
            .and_then(|v| v.try_into().ok()).unwrap_or([0u8; 16]);
        if crate::com::decode_invite(body).is_none() && crate::com::decode_delete(body).is_none() {
            self.com_inbox.write().await.record(crate::com::StoredMessage {
                msg_id, peer_id: recipient_id, outgoing: true, timestamp: ts,
                body: body.to_string(),
            });
        }

        // Anonymity layer (best effort): when we can build a circuit, inject
        // the envelope at the exit so our guard doesn't see us *originate* it.
        let compact = env.to_compact();
        let path = self.com_circuit_path(crate::circuit::MAX_HOPS).await;
        let can_circuit = compact.as_ref().map(|c| c.len() <= crate::circuit::RELAY_DATA_MAX)
            .unwrap_or(false) && !path.is_empty();

        if can_circuit {
            if let Ok(cid) = Arc::clone(self).build_circuit(path).await {
                let _ = self.send_origin_relay(
                    cid, crate::circuit::RelayCommand::ComInject, compact.unwrap()).await;
                let _ = self.destroy_circuit(cid).await;
            }
        }

        // Delivery guarantee: ALWAYS also gossip as store-and-forward. Circuit
        // injection alone only reaches a recipient if the single exit's onward
        // gossip happens to reach them — which silently fails for NAT'd nodes
        // (e.g. phones). Direct gossip is the path that reliably works; the
        // recipient dedups by msg_id, so a message that arrives both via the
        // circuit exit AND via gossip is still delivered exactly once.
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::ComStore(env.clone())).await;
        }
        Ok(msg_id)
    }

    /// Send a 1:1 com message. Seals (sealed-sender + blinded address),
    /// records our copy, and gossips it as store-and-forward — delivering
    /// online or offline.
    pub async fn com_send(self: &Arc<Self>, recipient_id: [u8; 32],
                          recipient_pub: [u8; 32], body: &str) -> Result<[u8; 16]>
    {
        let ts    = crate::com::now_secs();
        let epoch = crate::com::current_epoch();
        let env = crate::com::seal(
            &self.keypair.secret, self.node_id(), self.static_pub(),
            recipient_pub, epoch, ts, body.as_bytes());
        let msg_id: [u8; 16] = hex::decode(&env.msg_id).ok()
            .and_then(|v| v.try_into().ok()).unwrap_or([0u8; 16]);

        // Don't record group invites as visible chat messages.
        if crate::com::decode_invite(body).is_none() && crate::com::decode_delete(body).is_none() {
            self.com_inbox.write().await.record(crate::com::StoredMessage {
                msg_id, peer_id: recipient_id, outgoing: true, timestamp: ts,
                body: body.to_string(),
            });
        }
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::ComStore(env.clone())).await;
        }
        Ok(msg_id)
    }

    /// Pull mail for us and for every group we're in, from all peers.
    pub async fn com_pull(self: &Arc<Self>) {
        let mut blinded = crate::com::my_blinded_addrs(&self.static_pub());
        for g in self.com_groups.read().await.values() {
            blinded.extend(g.my_blinded_addrs());
        }
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::ComFetch(crate::wire::ComFetch {
                req_id:  hex::encode(rand_bytes(8)),
                blinded: blinded.clone(),
            })).await;
        }
    }

    /// Send by node id, resolving the recipient's key from a live peer
    /// or learned contacts. Works online and offline.
    /// Resolve a recipient's static (x25519) public key by node id from
    /// the only two sources an anonymity-preserving messenger should use:
    /// a live link peer, or a contact we were explicitly given (added by
    /// address). There is deliberately **no** lookup against a global
    /// directory — you can only message someone whose address you hold.
    async fn com_resolve_pub(&self, recipient_id: &[u8; 32]) -> Option<[u8; 32]> {
        if let Some(p) = self.peers.read().await.get(recipient_id) {
            if let Some(k) = hex::decode(&p.info.static_pub).ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                return Some(k);
            }
        }
        self.com_contacts.read().await.get(recipient_id).copied()
    }

    /// Add a contact from an address shared out of band (see
    /// `com::address_decode`). This is how you become able to message
    /// someone — by holding their address, not by browsing a roster.
    pub async fn com_add_contact(&self, node_id: [u8; 32], static_pub: [u8; 32]) {
        self.com_contacts.write().await.insert(node_id, static_pub);
    }

    /// This node's own shareable com address. Hand it to people you want
    /// to be reachable by; it reveals nothing until you give it out.
    pub fn com_my_address(&self) -> String {
        crate::com::address_encode(&self.node_id(), &self.static_pub())
    }

    pub async fn com_send_to(self: &Arc<Self>, recipient_id: [u8; 32], body: &str)
        -> Result<[u8; 16]>
    {
        let recipient_pub = self.com_resolve_pub(&recipient_id).await
            .ok_or_else(|| Error::Handshake(
                "com: unknown recipient (add them by address first)".into()))?;
        // Prefer sender-anonymous circuit injection; it falls back to
        // plain gossip if no circuit can be built.
        self.com_send_anonymous(recipient_id, recipient_pub, body).await
    }

    /// Unsend a message: remove it from our own thread, and tell the peer to
    /// remove it too (best effort — a sealed delete marker delivered the same
    /// way as any message). Honest limit: a peer that already read it, or a
    /// modified client, may retain a copy; this is a courtesy unsend, not a
    /// guarantee the bytes are gone from the other device.
    pub async fn com_delete(self: &Arc<Self>, peer_id: [u8; 32], msg_id: [u8; 16]) -> Result<()> {
        self.com_inbox.write().await.remove(&msg_id);
        if let Some(recipient_pub) = self.com_resolve_pub(&peer_id).await {
            let body = crate::com::encode_delete(&msg_id);
            let _ = self.com_send_anonymous(peer_id, recipient_pub, &body).await;
        }
        Ok(())
    }

    /// A Tor-style view of this node's identity and the relays that make up
    /// its circuit entry: the persistent guards (entry hops) plus the relays
    /// it's currently connected to. Circuits are built on demand through these.
    pub async fn circuit_info(&self) -> serde_json::Value {
        let guards = self.guard_mgr.list();
        let peers = self.peers_snapshot().await;

        // A representative circuit path (guard → middle → exit), selected with
        // the same diversity rules real com traffic uses. Roles are assigned by
        // position: first hop = guard, last = exit, anything between = middle.
        let path_specs = self.com_circuit_path(crate::circuit::MAX_HOPS).await;
        let n = path_specs.len();
        let path: Vec<_> = path_specs.iter().enumerate().map(|(i, h)| {
            let role = if n == 1 { "single" }
                else if i == 0 { "guard" }
                else if i == n - 1 { "exit" }
                else { "middle" };
            serde_json::json!({
                "role": role,
                "node_id": hex::encode(h.node_id),
                "host": h.host, "port": h.port,
            })
        }).collect();

        serde_json::json!({
            "node_id":    self.node_id_hex(),
            "static_pub": hex::encode(self.static_pub()),
            "path": path,
            "guards": guards.iter().map(|g| serde_json::json!({
                "node_id": g.node_id, "host": g.host, "port": g.port,
            })).collect::<Vec<_>>(),
            "relays": peers.iter().map(|p| serde_json::json!({
                "node_id": hex::encode(p.node_id), "host": p.host, "port": p.port,
            })).collect::<Vec<_>>(),
        })
    }

    /// Tor NEWNYM analog: retire all current guards, drop active circuits, and
    /// reselect guards from consensus — so subsequent traffic uses fresh relays.
    pub async fn new_identity(self: &Arc<Self>) {
        let empty = std::collections::HashSet::new();
        self.guard_mgr.retain_ids(&empty);
        self.guard_mgr.save_best_effort();
        self.guards.write().await.clear();
        *self.circuits.write().await = crate::circuit_mgr::CircuitManager::new();
        self.maintain_guards_from_consensus().await;
    }

    // ── com groups & channels ─────────────────────────────────────────

    /// Create a group (or channel) with us as the first member/admin.
    pub async fn com_create_group(self: &Arc<Self>, name: &str, is_channel: bool)
        -> crate::com::Group
    {
        let g = crate::com::Group::create(name, self.node_id(), self.com_sign_pub(), is_channel);
        self.com_groups.write().await.insert(g.group_id, g.clone());
        g
    }

    /// Invite a contact to a group by node id: add them as a member and
    /// send them the group key inside a sealed 1:1 invite.
    pub async fn com_invite_to_group(self: &Arc<Self>, group_id: [u8; 16],
                                     member_id: [u8; 32]) -> Result<()>
    {
        let group = {
            let mut groups = self.com_groups.write().await;
            let g = groups.get_mut(&group_id)
                .ok_or_else(|| Error::Handshake("com: unknown group".into()))?;
            if !g.members.contains(&member_id) { g.members.push(member_id); }
            g.clone()
        };
        let invite = crate::com::encode_invite(&group);
        self.com_send_to(member_id, &invite).await.map(|_| ())
    }

    /// Send a message to a group/channel: seal under the group key,
    /// record our copy, and gossip it to the group's blinded address.
    pub async fn com_send_group(self: &Arc<Self>, group_id: [u8; 16], body: &str)
        -> Result<[u8; 16]>
    {
        let group = self.com_groups.read().await.get(&group_id).cloned()
            .ok_or_else(|| Error::Handshake("com: unknown group".into()))?;
        let ts    = crate::com::now_secs();
        let epoch = crate::com::current_epoch();
        let env = crate::com::seal_group(&group, self.node_id(), &self.com_signer(), epoch, ts, body.as_bytes());
        let msg_id: [u8; 16] = hex::decode(&env.msg_id).ok()
            .and_then(|v| v.try_into().ok()).unwrap_or([0u8; 16]);
        self.com_inbox.write().await.record(crate::com::StoredMessage {
            msg_id, peer_id: Self::group_thread_id(&group_id), outgoing: true,
            timestamp: ts, body: body.to_string(),
        });
        let peers = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::ComGroupStore(env.clone())).await;
        }
        Ok(msg_id)
    }

    /// List groups/channels we're in as `(group_id, name, is_channel,
    /// thread_id)`.
    pub async fn com_groups_list(&self) -> Vec<([u8; 16], String, bool, [u8; 32])> {
        self.com_groups.read().await.values()
            .map(|g| (g.group_id, g.name.clone(), g.is_channel,
                      Self::group_thread_id(&g.group_id)))
            .collect()
    }

    /// Conversation thread with `peer` as `(outgoing, timestamp, body)`,
    /// chronological. Works for both 1:1 peers and group thread ids.
    pub async fn com_conversation(&self, peer: &[u8; 32]) -> Vec<(bool, u64, String, String)> {
        self.com_inbox.read().await.conversation(peer).into_iter()
            .map(|m| (m.outgoing, m.timestamp, m.body.clone(), hex::encode(m.msg_id))).collect()
    }

    /// Node ids of all 1:1 conversation threads, most-recently-active first.
    pub async fn com_threads(&self) -> Vec<[u8; 32]> {
        self.com_inbox.read().await.threads()
    }

    /// Pull our mail from connected peers and evict expired mailbox
    /// entries on a fixed cadence. This is what delivers messages sent
    /// while we were offline: as soon as we reconnect and this loop
    /// fires, we ask peers for anything held for us.
    async fn com_maintenance_loop(self: Arc<Self>) {
        // Pull promptly on startup, then on an interval.
        time::sleep(Duration::from_secs(3)).await;
        loop {
            self.com_pull().await;
            self.com_mailbox.write().await.evict_expired(crate::com::now_secs());
            time::sleep(Duration::from_secs(30)).await;
        }
    }

    // ── Onion ─────────────────────────────────────────────────────────

    async fn handle_onion(&self, msg: Onion) {
        match onion::peel(&msg.cell, &self.keypair.secret, &self.host, self.port) {
            Ok((Some(nh), Some(np), inner)) => {
                let cell = Message::Onion(Onion { cell: hex::encode(&inner) });
                let peers = self.peers.read().await;
                for p in peers.values() {
                    if p.info.host == nh && p.info.port == np {
                        let _ = p.send_msg(&cell).await;
                        return;
                    }
                }
            }
            Ok((None, _, payload)) => {
                if let Ok(inner) = serde_json::from_slice::<Message>(&payload) {
                    if let Message::BoardPost(p) = inner {
                        self.board.post(&p.channel, &p.text, None);
                    }
                }
            }
            Ok(_) => {} // partial Some/None — malformed cell, discard
            Err(e) => debug!("onion peel: {}", e),
        }
    }

    // ── Circuit cell dispatch ─────────────────────────────────────────

    /// Send a 512-byte cell to a specific peer by its node_id. Used
    /// both by the manager's forwarding logic and by origin-circuit
    /// construction. Returns Err if the peer is no longer connected.
    pub async fn send_circuit_cell(
        &self,
        peer_id: &[u8; 32],
        cell_bytes: &[u8; crate::circuit::CELL_SIZE],
    ) -> Result<()> {
        let peers = self.peers.read().await;
        let peer = peers.get(peer_id)
            .ok_or_else(|| Error::Handshake("peer not connected".into()))?;
        // The circuit id is the first four bytes of the cell (little-endian);
        // the scheduler needs it to know whose queue this belongs in.
        let cid = u32::from_le_bytes(cell_bytes[0..4].try_into().unwrap());
        peer.send_circuit_msg(cid, Message::CircuitCell(crate::wire::CircuitCellMsg {
            data: hex::encode(cell_bytes),
        }))
    }

    /// Dispatch an incoming CircuitCell from `src`. Decodes, consults
    /// the CircuitManager for the appropriate action, and forwards or
    /// handles terminally.
    async fn handle_circuit_cell(
        self: Arc<Self>,
        msg: crate::wire::CircuitCellMsg,
        src: &Arc<PeerConn>,
    ) {
        use crate::circuit::{Cell, CellCommand, CELL_SIZE, CircuitId};
        use crate::circuit_mgr::RelayAction;

        let raw = match hex::decode(&msg.data) {
            Ok(r) if r.len() == CELL_SIZE => r,
            _ => { debug!("circuit: malformed cell"); return; }
        };
        let mut cell_bytes = [0u8; CELL_SIZE];
        cell_bytes.copy_from_slice(&raw);
        let cell = match Cell::from_bytes(&cell_bytes) {
            Ok(c) => c,
            Err(e) => { debug!("circuit: parse: {}", e); return; }
        };
        let from_peer = src.info.node_id;

        match cell.command {
            CellCommand::Create => {
                // Peer is starting a circuit with us as guard-hop.
                //
                // Check the limit *first*. Everything after this line is an
                // ntor handshake — real elliptic-curve work, done because an
                // unauthenticated stranger asked. That asymmetry is the whole
                // attack: cheap to send, expensive to answer. Refusing after
                // the handshake would cost us exactly as much as complying.
                {
                    let ip = self.peers.read().await
                        .get(&from_peer).and_then(|p| p.remote_ip);
                    if let Some(ip) = ip {
                        if !self.dos.lock().unwrap().allow_circuit(ip) {
                            debug!("refusing CREATE from {} — circuit rate exceeded", ip);
                            return;
                        }
                    }
                }
                let client_msg_bytes = &cell.payload[..crate::ntor::CLIENT_HANDSHAKE_LEN];
                let mut cmsg = [0u8; crate::ntor::CLIENT_HANDSHAKE_LEN];
                cmsg.copy_from_slice(client_msg_bytes);

                let mut mgr = self.circuits.write().await;
                let my_id  = self.node_id();
                let my_pub = self.keypair.public_bytes();
                match mgr.handle_create(
                    from_peer, cell.circ_id,
                    &my_id, &my_pub, &self.keypair.secret,
                    &cmsg,
                ) {
                    Ok(reply_bytes) => {
                        drop(mgr);
                        let _ = self.send_circuit_cell(&from_peer, &reply_bytes).await;
                    }
                    Err(e) => warn!(
                        "handle_create from {}: {} — dropping (no CREATED sent). \
                         Usually means the client's ntor used a static key that \
                         doesn't match ours: check that the consensus entry for \
                         this relay carries our current static_pub.",
                        hex::encode(&from_peer[..6]), e),
                }
            }

            CellCommand::Created => {
                // Reply to a circuit we originated (we are client).
                // If instead this is for a circuit we're extending on
                // behalf of another client, wrap as EXTENDED2 and send
                // back on the previous hop.
                let server_reply_bytes = &cell.payload[..crate::ntor::SERVER_HANDSHAKE_LEN];
                let mut reply = [0u8; crate::ntor::SERVER_HANDSHAKE_LEN];
                reply.copy_from_slice(server_reply_bytes);

                let mut mgr = self.circuits.write().await;
                // Check: is this circuit one we originated directly?
                if mgr.origins.contains_key(&cell.circ_id) {
                    if let Err(e) = mgr.handle_created(cell.circ_id, &reply) {
                        debug!("handle_created (origin): {}", e);
                    }
                    return;
                }
                // Otherwise: maybe we're extending on behalf of a client.
                match mgr.handle_created_from_next(from_peer, cell.circ_id, &reply) {
                    Ok((prev_peer, bytes)) => {
                        drop(mgr);
                        let _ = self.send_circuit_cell(&prev_peer, &bytes).await;
                    }
                    Err(e) => debug!("handle_created_from_next: {}", e),
                }
            }

            CellCommand::Relay | CellCommand::RelayEarly => {
                // Forward direction from client OR backward direction
                // from next hop. Disambiguate by which table the
                // circuit is in.
                let mgr_read = self.circuits.read().await;
                let is_origin   = mgr_read.origins.contains_key(&cell.circ_id);
                let is_relay_fw = mgr_read.relays.contains_key(&(from_peer, cell.circ_id));
                let is_relay_bw = mgr_read.relay_by_next
                    .contains_key(&(from_peer, cell.circ_id));
                drop(mgr_read);

                if is_origin {
                    let mut mgr = self.circuits.write().await;
                    match mgr.handle_origin_relay(cell.circ_id, &cell.payload) {
                        Ok(None) => {} // EXTENDED2 consumed
                        Ok(Some((_hop, rc))) => {
                            use crate::circuit::RelayCommand;
                            // `_hop` is usize::MAX when the cell was
                            // recognized at the end-to-end layer (an HS
                            // rendezvous circuit), vs. a real hop index
                            // for ordinary relay-originated backward
                            // cells. The Data/End arms use this to route
                            // e2e traffic to the HS-serve / client-collect
                            // paths.
                            match rc.command {
                                // HS side: intro relay confirmed our ESTABLISH_INTRO
                                RelayCommand::IntroEstablished => {
                                    debug!("intro point confirmed on circ {:?}", cell.circ_id);
                                }
                                // Client side: RP confirmed our ESTABLISH_RENDEZVOUS
                                RelayCommand::RendezvousEstablished => {
                                    debug!("rendezvous established on circ {:?}", cell.circ_id);
                                }
                                // HS side: INTRODUCE2 received on our intro circuit
                                RelayCommand::Introduce2 => {
                                    drop(mgr);
                                    self.handle_introduce2(cell.circ_id, &rc.data).await;
                                }
                                // Client side: RP delivered RENDEZVOUS2 with HS's reply
                                RelayCommand::Rendezvous2 => {
                                    drop(mgr);
                                    self.handle_rendezvous2(cell.circ_id, &rc.data).await;
                                }
                                // Client side: intro acknowledged delivery
                                RelayCommand::IntroduceAck => {
                                    debug!("introduce1 delivered on circ {:?}", cell.circ_id);
                                }

                                // Stream-layer cells: route to the per-circuit
                                // StreamMux. Each stream_id within a circuit
                                // identifies one application-level connection.
                                RelayCommand::Connected => {
                                    let streams = mgr.origins.get(&cell.circ_id)
                                        .map(|c| Arc::clone(&c.streams));
                                    drop(mgr);
                                    if let Some(m) = streams {
                                        let _ = m.with_stream(rc.stream_id, |s| {
                                            if let Err(e) = s.on_connected() {
                                                debug!("connected: {}", e);
                                            }
                                        }).await;
                                    }
                                }
                                RelayCommand::Data => {
                                    // End-to-end HS traffic path. On a
                                    // rendezvous circuit the cell was
                                    // recognized at the e2e layer
                                    // (hop_idx == usize::MAX). Two roles:
                                    //   * we are the CLIENT and have a
                                    //     response collector registered →
                                    //     push the chunk to hs_fetch.
                                    //   * we are the HS (e2e keys but no
                                    //     collector) → treat the DATA as
                                    //     a request and serve it.
                                    let is_e2e = _hop == usize::MAX;
                                    if is_e2e {
                                        let collector = self.hs_response_collectors
                                            .read().await
                                            .get(&cell.circ_id).cloned();
                                        drop(mgr);
                                        if let Some(tx) = collector {
                                            // Client role: deliver to hs_fetch.
                                            let _ = tx.send(rc.data.clone());
                                        } else {
                                            // HS role: serve the request.
                                            Arc::clone(&self).serve_hs_request(
                                                cell.circ_id, rc.data.clone()).await;
                                        }
                                        return;
                                    }
                                    let streams = mgr.origins.get(&cell.circ_id)
                                        .map(|c| Arc::clone(&c.streams));
                                    // We also need to bump the
                                    // circuit-level delivered count.
                                    // Grab write access first so we
                                    // can check in the same critical
                                    // section — avoids a race where
                                    // two threads both think they
                                    // need to emit the sendme.
                                    let circ_sendme_due = mgr.origins
                                        .get_mut(&cell.circ_id)
                                        .map(|oc| {
                                            let due = oc.note_circ_delivered();
                                            if due { oc.reset_circ_delivered(); }
                                            due
                                        })
                                        .unwrap_or(false);
                                    drop(mgr);
                                    if let Some(m) = streams {
                                        // Per-stream delivery and
                                        // SENDME emission.
                                        let result = m.with_stream(rc.stream_id, |s| {
                                            s.on_data(&rc.data)
                                        }).await;
                                        if let Some(Ok(true)) = result {
                                            let _ = self.send_origin_relay(
                                                cell.circ_id,
                                                RelayCommand::SendMe,
                                                Vec::new(),
                                            ).await;
                                        }
                                    }
                                    // Circuit-level SENDME. Uses
                                    // stream_id = 0 as the
                                    // circuit-level convention
                                    // (which is what send_origin_relay
                                    // stamps by default).
                                    if circ_sendme_due {
                                        let _ = self.send_origin_relay(
                                            cell.circ_id,
                                            RelayCommand::SendMe,
                                            Vec::new(),
                                        ).await;
                                    }
                                }
                                RelayCommand::SendMe => {
                                    // stream_id == 0 is a circuit-
                                    // level SENDME, refilling the
                                    // circuit's outbound window.
                                    // stream_id != 0 refills a single
                                    // stream's window.
                                    if rc.stream_id == 0 {
                                        if let Some(oc) = mgr.origins
                                            .get_mut(&cell.circ_id)
                                        {
                                            oc.on_circ_sendme();
                                        }
                                        drop(mgr);
                                    } else {
                                        let streams = mgr.origins.get(&cell.circ_id)
                                            .map(|c| Arc::clone(&c.streams));
                                        drop(mgr);
                                        if let Some(m) = streams {
                                            m.with_stream(rc.stream_id, |s| s.on_sendme()).await;
                                        }
                                    }
                                }
                                RelayCommand::End => {
                                    // e2e End on a rendezvous circuit:
                                    // the HS finished its response. Drop
                                    // the client collector so hs_fetch
                                    // sees the channel close.
                                    if _hop == usize::MAX {
                                        drop(mgr);
                                        self.hs_response_collectors
                                            .write().await
                                            .remove(&cell.circ_id);
                                        return;
                                    }
                                    let reason = rc.data.first().copied().unwrap_or(0);
                                    let streams = mgr.origins.get(&cell.circ_id)
                                        .map(|c| Arc::clone(&c.streams));
                                    drop(mgr);
                                    if let Some(m) = streams {
                                        m.with_stream(rc.stream_id, |s| {
                                            s.close(crate::stream::EndReason::from_byte(reason));
                                        }).await;
                                        // After both directions acked, clean up.
                                        // (For now, close on first END.)
                                        m.remove(rc.stream_id).await;
                                    }
                                }

                                _ => {
                                    if rc.command == RelayCommand::Drop {
                                        // Padding cell from a relay. Just
                                        // discard it. Notify the scheduler
                                        // that something arrived (it
                                        // counts as cell activity from
                                        // its perspective, even though
                                        // we generated it as padding).
                                        if let Some(oc) = mgr.origins.get(&cell.circ_id) {
                                            oc.padding_scheduler.on_padding_cell(
                                                std::time::Instant::now());
                                        }
                                        return;
                                    }
                                    debug!("origin cell cmd={:?} stream={}",
                                           rc.command, rc.stream_id);
                                }
                            }
                        }
                        Err(e) => debug!("origin relay: {}", e),
                    }
                    return;
                }

                if is_relay_bw {
                    // Backward cell: wrap and forward to previous peer.
                    let mut mgr = self.circuits.write().await;
                    if let Some((prev_peer, bytes)) = mgr.handle_backward_relay(
                        from_peer, cell.circ_id, cell.clone()
                    ) {
                        drop(mgr);
                        let _ = self.send_circuit_cell(&prev_peer, &bytes).await;
                    }
                    return;
                }

                if is_relay_fw {
                    let mut mgr = self.circuits.write().await;
                    let action  = mgr.handle_forward_relay(
                        from_peer, cell.circ_id, cell.clone(),
                    );
                    match action {
                        RelayAction::Handle(relay) => {
                            use crate::circuit::RelayCommand;
                            match relay.command {
                                RelayCommand::Extend2 => {
                                    let next = match crate::circuit::parse_extend2(&relay.data) {
                                        Ok((ls, _)) => ls,
                                        Err(e) => { debug!("parse extend2: {}", e); return; }
                                    };
                                    let next_cid = CircuitId(
                                        rand_u32() | 0x8000_0000
                                    );
                                    match mgr.begin_extend(
                                        from_peer, cell.circ_id,
                                        next.node_id, next_cid, &relay.data,
                                    ) {
                                        Ok(bytes) => {
                                            drop(mgr);
                                            // Dial the next hop if we aren't
                                            // linked to it. This is what makes
                                            // hop-by-hop extension real: the
                                            // client only ever connects to its
                                            // guard, and each relay opens the
                                            // link to the one after it. The
                                            // EXTEND2 cell carries the address,
                                            // so we have what we need.
                                            // Bind the check: a temporary
                                            // guard from an `if` condition
                                            // lives to the end of the whole
                                            // statement, so reading it inline
                                            // would hold the lock across the
                                            // dial below.
                                            let linked = self.peers.read().await
                                                .contains_key(&next.node_id);
                                            if !linked {
                                                let host = next.host.clone();
                                                let port = next.port;
                                                // connect_boxed, not connect:
                                                // dialling from inside a cell
                                                // handler closes a type cycle
                                                // the compiler can't resolve.
                                                if let Err(e) = Arc::clone(&self)
                                                    .connect_boxed(host.clone(), port).await
                                                {
                                                    warn!("extend: dial {}:{} failed: {} \
                                                           — dropping (client will time out)",
                                                          host, port, e);
                                                    return;
                                                }
                                                let ok = self.peers.read().await
                                                    .contains_key(&next.node_id);
                                                if !ok {
                                                    warn!("extend: {}:{} answered with a \
                                                           different identity than the \
                                                           circuit asked for — dropping",
                                                          host, port);
                                                    return;
                                                }
                                            }
                                            let _ = self.send_circuit_cell(
                                                &next.node_id, &bytes).await;
                                        }
                                        Err(e) => warn!("begin_extend to {}: {}",
                                                        hex::encode(&next.node_id[..6]), e),
                                    }
                                }

                                // Someone's HS is declaring this circuit as its
                                // intro point. Record the auth key so we know
                                // how to forward INTRODUCE1 cells later.
                                RelayCommand::EstablishIntro => {
                                    match crate::rendezvous::EstablishIntro::decode(&relay.data) {
                                        Ok(msg) => {
                                            mgr.register_intro_relay(
                                                from_peer, cell.circ_id, msg.auth_key_pub);
                                            drop(mgr);
                                            self.send_intro_established(from_peer, cell.circ_id).await;
                                        }
                                        Err(e) => debug!("establish_intro: {}", e),
                                    }
                                }

                                // Client is asking us (as an RP) to hold their
                                // cookie and splice when HS arrives.
                                RelayCommand::EstablishRendezvous => {
                                    match crate::rendezvous::EstablishRendezvous::decode(&relay.data) {
                                        Ok(msg) => {
                                            mgr.register_rendezvous_cookie(
                                                msg.cookie, from_peer, cell.circ_id);
                                            drop(mgr);
                                            self.send_rendezvous_established(from_peer, cell.circ_id).await;
                                        }
                                        Err(e) => debug!("establish_rendezvous: {}", e),
                                    }
                                }

                                // Client sent INTRODUCE1 to us as intro relay.
                                // Look up which HS circuit this auth_key maps to
                                // and forward the blob as INTRODUCE2.
                                RelayCommand::Introduce1 => {
                                    match crate::rendezvous::Introduce::decode(&relay.data) {
                                        Ok(intro_msg) => {
                                            let target = mgr.find_intro_target(&intro_msg.auth_key_pub);
                                            drop(mgr);
                                            match target {
                                                Some((hs_peer, hs_cid)) => {
                                                    self.forward_introduce2(
                                                        hs_peer, hs_cid, &relay.data).await;
                                                    // ACK back to client on THEIR circuit
                                                    self.send_introduce_ack(from_peer, cell.circ_id).await;
                                                }
                                                None => {
                                                    // No separate HS circuit registered
                                                    // for this auth key. If the auth key is
                                                    // *our own* node static key, then we are
                                                    // the HS and the client's intro circuit
                                                    // terminates directly at us — handle the
                                                    // INTRODUCE1 as our own INTRODUCE2.
                                                    if intro_msg.auth_key_pub == self.keypair.public_bytes() {
                                                        self.handle_introduce2(cell.circ_id, &relay.data).await;
                                                        self.send_introduce_ack(from_peer, cell.circ_id).await;
                                                    } else {
                                                        debug!("introduce1: no matching intro for auth_key");
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => debug!("introduce1 decode: {}", e),
                                    }
                                }

                                // HS sent RENDEZVOUS1 to us as RP. Look up cookie,
                                // splice to the client's circuit as RENDEZVOUS2,
                                // then establish a durable data bridge so
                                // subsequent end-to-end DATA cells flow both ways.
                                RelayCommand::Rendezvous1 => {
                                    match crate::rendezvous::Rendezvous1::decode(&relay.data) {
                                        Ok(r1) => {
                                            let hs_leg = (from_peer, cell.circ_id);
                                            let target = mgr.consume_rendezvous_cookie(&r1.cookie);
                                            if let Some(client_leg) = target {
                                                // Pair the legs while we still hold
                                                // the write lock, before any DATA
                                                // can arrive.
                                                mgr.bridge_rendezvous(client_leg, hs_leg);
                                            }
                                            drop(mgr);
                                            match target {
                                                Some((client_peer, client_cid)) => {
                                                    self.splice_rendezvous2(
                                                        client_peer, client_cid,
                                                        &r1.server_y, &r1.auth).await;
                                                }
                                                None => {
                                                    debug!("rendezvous1: unknown cookie");
                                                }
                                            }
                                        }
                                        Err(e) => debug!("rendezvous1 decode: {}", e),
                                    }
                                }

                                // Exit side: a client injected a sealed
                                // com envelope through a circuit. We push
                                // it into the store-and-forward gossip as
                                // if it originated here — so the client's
                                // own guard never sees it emit com traffic.
                                RelayCommand::ComInject => {
                                    drop(mgr);
                                    match crate::com::ComEnvelope::from_compact(&relay.data) {
                                        Some(env) => self.inject_com_store(env).await,
                                        None => debug!("com inject: bad compact envelope"),
                                    }
                                }

                                // Exit side: client asked us to open a
                                // TCP connection to the named target. We
                                // parse the target, open TCP, record a
                                // stream in the relay-circuit mux, and
                                // kick off a forwarding task that pumps
                                // bytes between TCP and circuit.
                                RelayCommand::Begin => {
                                    drop(mgr);
                                    Arc::clone(&self).handle_exit_begin(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                        &relay.data,
                                    ).await;
                                }

                                // Exit side: DATA from client on an open
                                // stream — write to the TCP socket.
                                RelayCommand::Data => {
                                    drop(mgr);
                                    self.handle_exit_data(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                        &relay.data,
                                    ).await;
                                }

                                // Exit side: client closed a stream.
                                RelayCommand::End => {
                                    drop(mgr);
                                    self.handle_exit_end(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                    ).await;
                                }

                                // Exit side: client acknowledged our DATA.
                                RelayCommand::SendMe => {
                                    drop(mgr);
                                    self.handle_exit_sendme(
                                        from_peer, cell.circ_id,
                                        relay.stream_id,
                                    ).await;
                                }

                                other => {
                                    if other == RelayCommand::Drop {
                                        // Padding cell terminating at us.
                                        // Discard silently — that's the
                                        // whole point.
                                        return;
                                    }
                                    debug!("relay handle: unexpected cmd {:?}", other);
                                }
                            }
                        }
                        RelayAction::Forward(next_peer, bytes) => {
                            drop(mgr);
                            let _ = self.send_circuit_cell(&next_peer, &bytes).await;
                        }
                        RelayAction::Drop => {}
                    }
                    return;
                }

                debug!("relay cell on unknown circuit id={:?}", cell.circ_id);
            }

            CellCommand::Destroy => {
                let mut mgr = self.circuits.write().await;
                // If this circuit is a bridged rendezvous leg, propagate
                // the teardown to its partner so the other side doesn't
                // linger with a half-open bridge.
                let partner = mgr.bridge_partner((from_peer, cell.circ_id));
                mgr.destroy(from_peer, cell.circ_id);
                drop(mgr);
                if let Some((pp, pc)) = partner {
                    use crate::circuit::{Cell, CellCommand as CC};
                    if let Ok(dcell) = Cell::with_payload(pc, CC::Destroy, &[0]) {
                        let _ = self.send_circuit_cell(&pp, &dcell.to_bytes()).await;
                    }
                }
            }

            _ => {
                debug!("circuit cell: unsupported cmd {:?}", cell.command);
            }
        }
    }

    // ── Rendezvous helpers ────────────────────────────────────────────
    //
    // These send single relay cells toward specific peers and circuits.
    // They share a pattern:
    //   1. Build a RelayCell with the desired command and data
    //   2. Stamp the backward digest at our hop state
    //   3. Layered-encrypt backward to the target
    //   4. Send the enclosing Cell over the peer connection

    /// Send RELAY_INTRO_ESTABLISHED backward on a relay circuit to
    /// confirm to the HS that we've registered as its intro point.
    async fn send_intro_established(&self, to_peer: [u8; 32], cid: crate::circuit::CircuitId) {
        self.send_backward_relay(
            to_peer, cid,
            crate::circuit::RelayCommand::IntroEstablished,
            Vec::new(),
        ).await;
    }

    /// Send RELAY_RENDEZVOUS_ESTABLISHED backward on a relay circuit
    /// to confirm to the client we've registered their cookie.
    async fn send_rendezvous_established(&self, to_peer: [u8; 32], cid: crate::circuit::CircuitId) {
        self.send_backward_relay(
            to_peer, cid,
            crate::circuit::RelayCommand::RendezvousEstablished,
            Vec::new(),
        ).await;
    }

    /// Send RELAY_INTRODUCE_ACK backward to a client after forwarding
    /// their INTRODUCE1 as INTRODUCE2 to the HS.
    async fn send_introduce_ack(&self, to_peer: [u8; 32], cid: crate::circuit::CircuitId) {
        self.send_backward_relay(
            to_peer, cid,
            crate::circuit::RelayCommand::IntroduceAck,
            Vec::new(),
        ).await;
    }

    /// Forward an INTRODUCE1 body as INTRODUCE2 on the HS-facing
    /// circuit. We're acting as intro relay; the HS established the
    /// circuit ending at us and is now expecting INTRODUCE2 cells
    /// backward.
    async fn forward_introduce2(
        &self,
        hs_peer: [u8; 32],
        hs_cid: crate::circuit::CircuitId,
        data: &[u8],
    ) {
        self.send_backward_relay(
            hs_peer, hs_cid,
            crate::circuit::RelayCommand::Introduce2,
            data.to_vec(),
        ).await;
    }

    /// Splice: send RELAY_RENDEZVOUS2(Y, AUTH) backward on the client's
    /// circuit. We're acting as RP; client built circuit to us and is
    /// blocked waiting for this cell.
    async fn splice_rendezvous2(
        &self,
        client_peer: [u8; 32],
        client_cid: crate::circuit::CircuitId,
        server_y: &[u8; 32],
        auth: &[u8; crate::rendezvous::HS_AUTH_LEN],
    ) {
        let r2 = crate::rendezvous::Rendezvous2 {
            server_y: *server_y,
            auth:     *auth,
        };
        self.send_backward_relay(
            client_peer, client_cid,
            crate::circuit::RelayCommand::Rendezvous2,
            r2.encode(),
        ).await;
    }

    /// Internal: build a backward-direction relay cell on a relay
    /// circuit (we are mid-hop), stamp digest, encrypt our backward
    /// layer, wrap in a Cell, and send to the previous peer.
    async fn send_backward_relay(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        data: Vec<u8>,
    ) {
        use crate::circuit::{Cell, CellCommand, RelayCell, onion_encrypt_backward};
        let relay = match RelayCell::new(cmd, 0, data) {
            Ok(r) => r,
            Err(e) => { debug!("send_backward_relay: build: {}", e); return; }
        };

        let mut mgr = self.circuits.write().await;
        let Some(rc) = mgr.relays.get_mut(&(to_peer, cid)) else {
            debug!("send_backward_relay: no relay circuit for {:?}", cid);
            return;
        };

        let mut relay = relay;
        relay.stamp_digest(&mut rc.hop.backward_digest);
        let mut payload = relay.to_payload();
        onion_encrypt_backward(&mut rc.hop, &mut payload);
        let prev_peer    = rc.prev_peer;
        let prev_cid     = rc.prev_circ_id;
        drop(mgr);

        let out_cell = Cell { circ_id: prev_cid, command: CellCommand::Relay, payload };
        let _ = self.send_circuit_cell(&prev_peer, &out_cell.to_bytes()).await;
    }

    /// Internal: same as send_backward_relay but preserves a stream_id
    /// on the relay cell. Used for exit-side responses (CONNECTED,
    /// DATA backward, END) that must carry the client's original
    /// stream_id so the origin can route to the right Stream.
    async fn send_backward_relay_stream(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        stream_id: u16,
        data: Vec<u8>,
    ) {
        use crate::circuit::{Cell, CellCommand, RelayCell, onion_encrypt_backward};
        let relay = match RelayCell::new(cmd, stream_id, data) {
            Ok(r) => r,
            Err(e) => { debug!("send_backward_relay_stream: build: {}", e); return; }
        };

        let mut mgr = self.circuits.write().await;
        let Some(rc) = mgr.relays.get_mut(&(to_peer, cid)) else {
            debug!("send_backward_relay_stream: no relay circuit");
            return;
        };

        let mut relay = relay;
        relay.stamp_digest(&mut rc.hop.backward_digest);
        let mut payload = relay.to_payload();
        onion_encrypt_backward(&mut rc.hop, &mut payload);
        let prev_peer = rc.prev_peer;
        let prev_cid  = rc.prev_circ_id;
        drop(mgr);

        let out = Cell { circ_id: prev_cid, command: CellCommand::Relay, payload };
        let _ = self.send_circuit_cell(&prev_peer, &out.to_bytes()).await;
    }

    // ── Exit-side stream handlers ─────────────────────────────────────

    /// Exit handler: client sent RELAY_BEGIN("host:port\0") on a new
    /// stream. We parse the target, open a TCP connection, register
    /// the stream in the relay circuit's mux, reply with RELAY_CONNECTED,
    /// and spawn a bidirectional pump task that bridges the TCP socket
    /// to the circuit.
    ///
    /// On failure (bad target, connection refused, etc.) we send back
    /// RELAY_END with an appropriate reason.
    async fn handle_exit_begin(
        self: Arc<Self>,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        data: &[u8],
    ) {
        // Parse null-terminated "host:port" target
        let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
        let target = match std::str::from_utf8(&data[..end]) {
            Ok(s) => s.to_string(),
            Err(_) => {
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::Internal).await;
                return;
            }
        };

        // ── bw-test: intercept ────────────────────────────────────
        // Sentinel target used by the bandwidth scanner. Format:
        // "bw-test:<bytes>" e.g. "bw-test:1048576". The exit relay
        // generates that many bytes *locally* (no network egress)
        // and streams them back through the circuit. This produces
        // a clean throughput measurement of the circuit itself —
        // dominated by the slowest hop, by design — without
        // depending on an external server.
        //
        // Why this is safe to expose unconditionally:
        //   - The bytes generated are pseudorandom from a per-stream
        //     keyed PRF; no information about the relay leaks
        //   - The size is capped at MAX_BW_TEST_BYTES so a malicious
        //     client can't request 1 TB and OOM the relay
        //   - Generation is local — the exit policy doesn't need to
        //     evaluate it. Even non-EXIT relays can serve bw-test.
        if let Some(rest) = target.strip_prefix("bw-test:") {
            let bytes: usize = rest.parse().unwrap_or(0);
            const MAX_BW_TEST_BYTES: usize = 4 * 1024 * 1024;  // 4 MB cap
            let bytes = bytes.min(MAX_BW_TEST_BYTES);
            self.serve_bw_test(from_peer, cid, stream_id, bytes).await;
            return;
        }

        // Policy: pre-resolve check for IP literals + port blocklist.
        if self.exit_policy.read().unwrap().check_pre_resolve(&target) ==
            crate::exit_policy::Decision::Reject
        {
            debug!("exit policy rejected: {}", target);
            self.send_exit_end(from_peer, cid, stream_id,
                crate::stream::EndReason::ExitPolicy).await;
            return;
        }

        // Try to connect
        let tcp = match tokio::time::timeout(
            Duration::from_secs(15),
            tokio::net::TcpStream::connect(&target),
        ).await {
            Ok(Ok(t))  => t,
            Ok(Err(e)) => {
                debug!("exit begin: connect {}: {}", target, e);
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::Unreachable).await;
                return;
            }
            Err(_) => {
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::Timeout).await;
                return;
            }
        };

        // Post-resolve check: DNS might have returned a private IP.
        if let Ok(peer) = tcp.peer_addr() {
            if self.exit_policy.read().unwrap().check_post_resolve(&peer) ==
                crate::exit_policy::Decision::Reject
            {
                debug!("exit policy rejected after resolve: {} -> {}",
                       target, peer);
                self.send_exit_end(from_peer, cid, stream_id,
                    crate::stream::EndReason::ExitPolicy).await;
                return;
            }
        }

        info!("exit: stream {} opened to {}", stream_id, target);

        // Register stream in the relay circuit's mux
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.relays.get(&(from_peer, cid))
                .map(|rc| Arc::clone(&rc.exit_streams))
        };
        let Some(streams) = streams else {
            debug!("exit begin: relay circuit vanished");
            return;
        };
        let _rx = streams.accept_stream(stream_id, target).await;

        // Reply CONNECTED upstream
        self.send_exit_relay(
            from_peer, cid, crate::circuit::RelayCommand::Connected,
            stream_id, Vec::new(),
        ).await;

        // Split the TCP stream into read/write halves and spawn a pump.
        let (mut tcp_read, tcp_write) = tokio::io::split(tcp);
        let tcp_write = Arc::new(Mutex::new(tcp_write));

        // Store the write half on the node so handle_exit_data can reach it.
        self.exit_writers.write().await
            .insert((cid, stream_id), Arc::clone(&tcp_write));

        // Spawn reader task: TCP -> circuit (as DATA cells backward).
        let node = Arc::clone(&self);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; crate::circuit::RELAY_DATA_MAX];
            loop {
                let n = match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        // EOF from target — close stream
                        node.send_exit_end(from_peer, cid, stream_id,
                            crate::stream::EndReason::Done).await;
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        node.send_exit_end(from_peer, cid, stream_id,
                            crate::stream::EndReason::Unreachable).await;
                        break;
                    }
                };
                // Consume the relay circuit's backward-direction
                // window slot. If exhausted, the exit stalls on this
                // iteration until the client sends a circuit SENDME
                // (which we handle in handle_exit_sendme). We don't
                // block the TCP read — we just poll periodically until
                // a slot frees up. This means a slow client can
                // backpressure the exit's TCP reads, which is exactly
                // what flow control should do.
                loop {
                    let ok = {
                        let mut mgr = node.circuits.write().await;
                        mgr.relays.get_mut(&(from_peer, cid))
                            .map(|rc| rc.try_consume_circ_window())
                    };
                    match ok {
                        Some(Ok(())) => break,
                        Some(Err(_)) => {
                            // Window exhausted; wait briefly for a SENDME.
                            tokio::time::sleep(
                                std::time::Duration::from_millis(10)
                            ).await;
                        }
                        None => {
                            // Circuit went away underneath us.
                            return;
                        }
                    }
                }
                node.send_exit_relay(
                    from_peer, cid, crate::circuit::RelayCommand::Data,
                    stream_id, buf[..n].to_vec(),
                ).await;
            }
            // Clean up writer entry on exit
            node.exit_writers.write().await.remove(&(cid, stream_id));
        });
    }

    /// Serve a bw-test stream: emit `bytes` of pseudorandom data
    /// back through the circuit. Mirrors the structure of the
    /// regular exit-stream forward path (CONNECTED reply, then DATA
    /// chunks honoring circuit-window flow control), but the bytes
    /// come from a local PRF instead of a TCP socket.
    ///
    /// The bytes are pseudorandom (chacha-style stream from a
    /// per-stream key) rather than zeros so the throughput
    /// measurement isn't artificially boosted by compression
    /// anywhere in the path. It's *not* secret-quality randomness;
    /// callers should treat the data as "filler that happens to
    /// look like noise."
    async fn serve_bw_test(
        self: Arc<Self>,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        bytes: usize,
    ) {
        // Register stream so DATA cells get demuxed correctly even
        // if the client sends one (we don't expect them to but the
        // circuit machinery wants the registration).
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.relays.get(&(from_peer, cid))
                .map(|rc| Arc::clone(&rc.exit_streams))
        };
        let Some(streams) = streams else {
            debug!("bw-test: relay circuit vanished");
            return;
        };
        let _rx = streams.accept_stream(stream_id, "bw-test".into()).await;

        // Reply CONNECTED upstream so the client's stream transitions
        // from Connecting → Open and the ready-oneshot fires.
        self.send_exit_relay(
            from_peer, cid, crate::circuit::RelayCommand::Connected,
            stream_id, Vec::new(),
        ).await;

        // Spawn a generator task: emits chunks of pseudorandom data
        // until `bytes` are sent, then closes the stream cleanly.
        let node = Arc::clone(&self);
        tokio::spawn(async move {
            // Per-stream PRF state. We use a simple xorshift64 seeded
            // from (stream_id, cid bits, current time) — fine for
            // throughput measurement, not a cryptographic primitive.
            let seed = (stream_id as u64).wrapping_mul(0x9E3779B97F4A7C15)
                ^ (cid.0 as u64).wrapping_mul(0xBF58476D1CE4E5B9)
                ^ std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
            let mut state = if seed == 0 { 1 } else { seed };

            let mut sent = 0usize;
            let chunk_size = crate::circuit::RELAY_DATA_MAX;

            while sent < bytes {
                let want = (bytes - sent).min(chunk_size);
                let mut buf = vec![0u8; want];
                // xorshift64 fill
                for i in 0..want {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    buf[i] = state as u8;
                }

                // Honor circuit window — same backpressure pattern as
                // the TCP forwarder. If the client doesn't drain, we
                // block here and the measurement reflects that
                // (correctly slow throughput).
                loop {
                    let ok = {
                        let mut mgr = node.circuits.write().await;
                        mgr.relays.get_mut(&(from_peer, cid))
                            .map(|rc| rc.try_consume_circ_window())
                    };
                    match ok {
                        Some(Ok(())) => break,
                        Some(Err(_)) => {
                            tokio::time::sleep(
                                std::time::Duration::from_millis(10)
                            ).await;
                        }
                        None => {
                            // Circuit destroyed; stop generating
                            return;
                        }
                    }
                }

                node.send_exit_relay(
                    from_peer, cid,
                    crate::circuit::RelayCommand::Data,
                    stream_id, buf,
                ).await;

                sent += want;
            }

            // All bytes sent; close stream cleanly so the client knows
            // we're done and can compute the final throughput.
            node.send_exit_end(from_peer, cid, stream_id,
                crate::stream::EndReason::Done).await;
        });
    }

    async fn handle_exit_data(
        &self,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        data: &[u8],
    ) {
        use tokio::io::AsyncWriteExt;
        let writer = self.exit_writers.read().await
            .get(&(cid, stream_id)).cloned();
        if let Some(w) = writer {
            let mut w = w.lock().await;
            if let Err(e) = w.write_all(data).await {
                debug!("exit data: write: {}", e);
            }
        }

        // Bump the relay circuit's delivered counter. When it crosses
        // the Prop-324 SENDME increment (congestion::CC_SENDME_INC),
        // emit a circuit-level SENDME back toward the client so its
        // Vegas controller frees a window of in-flight cells and folds
        // in the RTT sample. Without this the client's congestion
        // window would fill and `try_consume_circ_window` would stall.
        let circ_sendme_due = {
            let mut mgr = self.circuits.write().await;
            mgr.relays.get_mut(&(from_peer, cid))
                .map(|rc| {
                    let due = rc.note_circ_delivered();
                    if due { rc.reset_circ_delivered(); }
                    due
                })
                .unwrap_or(false)
        };
        if circ_sendme_due {
            // stream_id = 0 → circuit-level SENDME
            self.send_backward_relay_stream(
                from_peer, cid,
                crate::circuit::RelayCommand::SendMe,
                0,              // stream_id = 0 for circuit-level
                Vec::new(),
            ).await;
        }
    }

    async fn handle_exit_end(
        &self,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
    ) {
        // Drop the TCP write half — the reader task will see the
        // half-close and exit.
        self.exit_writers.write().await.remove(&(cid, stream_id));
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.relays.get(&(from_peer, cid))
                .map(|rc| Arc::clone(&rc.exit_streams))
        };
        if let Some(m) = streams {
            m.remove(stream_id).await;
        }
    }

    async fn handle_exit_sendme(
        &self,
        from_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
    ) {
        // stream_id = 0 is a circuit-level SENDME, refilling the
        // relay circuit's backward (exit→client) window. stream_id
        // != 0 refills the stream's own window.
        if stream_id == 0 {
            let mut mgr = self.circuits.write().await;
            if let Some(rc) = mgr.relays.get_mut(&(from_peer, cid)) {
                rc.on_circ_sendme();
            }
        } else {
            let streams = {
                let mgr = self.circuits.read().await;
                mgr.relays.get(&(from_peer, cid))
                    .map(|rc| Arc::clone(&rc.exit_streams))
            };
            if let Some(m) = streams {
                m.with_stream(stream_id, |s| s.on_sendme()).await;
            }
        }
    }

    /// Shorthand for sending a single relay cell backward from the
    /// exit with a specified stream_id.
    async fn send_exit_relay(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        stream_id: u16,
        data: Vec<u8>,
    ) {
        self.send_backward_relay_stream(to_peer, cid, cmd, stream_id, data).await;
    }

    /// Send RELAY_END backward with the given reason byte.
    async fn send_exit_end(
        &self,
        to_peer: [u8; 32],
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        reason: crate::stream::EndReason,
    ) {
        self.send_backward_relay_stream(
            to_peer, cid,
            crate::circuit::RelayCommand::End,
            stream_id,
            vec![reason as u8],
        ).await;
    }

    /// HS side: we received INTRODUCE2 on one of our intro circuits.
    /// Decrypt the payload using our static HS key, extract the RP
    /// info, cookie, and client ephemeral X. Build a 3-hop circuit to
    /// the RP, run the e2e handshake, and send RENDEZVOUS1 carrying
    /// (cookie, Y, AUTH) through the RP circuit.
    ///
    /// If we don't yet have a connection to the RP, we note the
    /// intent and log — a real deployment would consult the consensus
    /// for path selection and pre-connect; here we rely on the HS
    /// operator to have pre-connected to candidate RPs.
    /// HS side: we received INTRODUCE2 on one of our intro circuits.
    /// Decrypt the payload using our static HS key, extract the RP
    /// info, cookie, and client ephemeral X. Run the e2e handshake to
    /// obtain Y and AUTH, then enqueue an `HsRendezvousIntent` for the
    /// background drainer to act on (build RP circuit, send RENDEZVOUS1).
    ///
    /// We enqueue rather than acting inline to avoid an async-recursion
    /// cycle (`build_circuit` requires `Arc<Self>`). The drainer runs
    /// from `run()` with a fresh Arc captured at startup.
    async fn handle_introduce2(&self, _intro_cid: crate::circuit::CircuitId, data: &[u8]) {
        let intro = match crate::rendezvous::Introduce::decode(data) {
            Ok(i) => i,
            Err(e) => { debug!("introduce2 decode: {}", e); return; }
        };

        // HS static keys = the node's connection-level identity keys.
        let hs_b_sec = self.keypair.secret.clone();
        let hs_b_pub = self.keypair.public_bytes();

        let plain = match intro.open_at_hs(&hs_b_sec, &hs_b_pub) {
            Ok(p) => p,
            Err(e) => { debug!("introduce2 open (MAC/decrypt): {}", e); return; }
        };

        info!("HS: accepted INTRODUCE2, RP={}:{} cookie={}",
              plain.rp_host, plain.rp_port,
              hex::encode(&plain.cookie[..6]));

        let (e2e_keys, y_pub, auth) = crate::rendezvous::hs_finalize(
            &hs_b_sec, &hs_b_pub, &intro.client_ntor_x);

        let intent = HsRendezvousIntent {
            rp_node_id: plain.rp_node_id,
            rp_host:    plain.rp_host,
            rp_port:    plain.rp_port,
            cookie:     plain.cookie,
            server_y:   y_pub,
            auth,
            e2e_keys,
        };

        // Cap the queue so an adversarial intro relay can't flood us.
        let mut q = self.hs_pending_rendezvous.write().await;
        if q.len() >= 64 {
            debug!("HS: rendezvous queue full, dropping intent");
            return;
        }
        q.push_back(intent);
    }

    /// Background loop: drain the HS pending-rendezvous queue. For
    /// each queued intent, build a circuit to the RP and send
    /// RENDEZVOUS1. On success, install the e2e keys on the built
    /// circuit.
    ///
    /// This is the owner of `Arc<Self>` that `build_circuit` needs
    /// — which is why we decouple it from the cell-dispatch path.
    ///
    /// Runs every 100 ms while the queue has entries, otherwise
    /// sleeps 1 s. Each intent gets one attempt; failure logs and
    /// drops. For production, add a retry counter and exponential
    /// backoff; for now a failed RP just means the client's cookie
    /// goes stale and they retry with a different RP.
    async fn hs_rendezvous_drain_loop(self: Arc<Self>) {
        loop {
            let intent = {
                let mut q = self.hs_pending_rendezvous.write().await;
                q.pop_front()
            };
            let Some(intent) = intent else {
                time::sleep(Duration::from_secs(1)).await;
                continue;
            };

            let rp_connected = self.peers.read().await
                .contains_key(&intent.rp_node_id);
            if !rp_connected {
                // Try to open a connection to the RP. In production this
                // would go through a circuit; here we need a direct
                // control-plane link so we can originate a 1-hop circuit.
                let node = Arc::clone(&self);
                let host = intent.rp_host.clone();
                let port = intent.rp_port;
                if let Err(e) = node.connect(&host, port).await {
                    debug!("hs drain: connect RP {}:{}: {}", host, port, e);
                    time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                // Wait a beat for handshake to complete
                time::sleep(Duration::from_millis(500)).await;
                if !self.peers.read().await.contains_key(&intent.rp_node_id) {
                    debug!("hs drain: RP connection didn't register");
                    continue;
                }
            }

            // Build a 1-hop circuit to the RP. (3-hop path selection
            // via consensus is future work.) We need the RP's x25519
            // static public key to form the ntor handshake; look it
            // up in the peer table.
            let rp_static_pub: [u8; 32] = {
                let peers = self.peers.read().await;
                let Some(peer) = peers.get(&intent.rp_node_id) else {
                    debug!("hs drain: RP peer vanished");
                    continue;
                };
                match hex::decode(&peer.info.static_pub)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                {
                    Some(b) => b,
                    None => {
                        debug!("hs drain: RP static_pub invalid");
                        continue;
                    }
                }
            };
            let rp_link = crate::circuit::LinkSpec {
                host:       intent.rp_host.clone(),
                port:       intent.rp_port,
                node_id:    intent.rp_node_id,
                static_pub: rp_static_pub,
            };
            let node = Arc::clone(&self);
            // HS-side rendezvous circuit. We use `build_hs_circuit`
            // even though it's currently a 1-hop circuit (HS → RP) —
            // for 1-hop paths the function falls through to regular
            // `build_circuit`, but if the design ever evolves to
            // include intermediate hops between HS and RP (e.g. for
            // additional anonymity), vanguards will kick in
            // automatically. Padding scheduler is also installed on
            // every HS-side circuit at the operator-configured rate
            // (or NoPadding if not configured).
            let scheduler: Arc<dyn crate::padding::PaddingScheduler> =
                self.hs_padding_scheduler.read().await.clone()
                    .unwrap_or_else(|| Arc::new(crate::padding::NoPadding));
            let rp_cid = match Arc::clone(&node)
                .build_hs_circuit(vec![rp_link]).await
            {
                Ok(c) => {
                    // Install the padding scheduler now that the
                    // circuit's built. Scheduler swap-in is safe
                    // because the pump rechecks every 5s by default.
                    let mut mgr = self.circuits.write().await;
                    let _ = mgr.set_padding_scheduler(c, scheduler);
                    c
                }
                Err(e) => {
                    debug!("hs drain: build RP circuit: {}", e);
                    continue;
                }
            };

            // Send RENDEZVOUS1 through the circuit
            let r1 = crate::rendezvous::Rendezvous1 {
                cookie:   intent.cookie,
                server_y: intent.server_y,
                auth:     intent.auth,
            };
            if let Err(e) = self.send_origin_relay(
                rp_cid,
                crate::circuit::RelayCommand::Rendezvous1,
                r1.encode(),
            ).await {
                debug!("hs drain: send RENDEZVOUS1: {}", e);
                continue;
            }

            // Install e2e keys — future app-level cells on this circuit
            // use these keys end-to-end with the client.
            {
                let mut mgr = self.circuits.write().await;
                if let Some(oc) = mgr.origins.get_mut(&rp_cid) {
                    oc.e2e = Some(crate::circuit::HopState::from_e2e_keys(
                        &intent.e2e_keys, false));
                }
                mgr.e2e_keys.insert(rp_cid, intent.e2e_keys);
            }
            info!("HS: rendezvous completed, e2e keys installed on circ {:?}", rp_cid);
        }
    }

    /// Open a multiplexed stream on an existing circuit to `target`
    /// (host:port). Sends RELAY_BEGIN through the circuit and returns:
    ///   * `stream_id` — for subsequent `stream_write` / `stream_close` calls
    ///   * `rx` — channel that yields data received on this stream.
    ///     An empty yield (`rx.recv() -> None`) signals the stream closed.
    ///   * `ready` — oneshot that completes when RELAY_CONNECTED arrives
    ///     from the exit and the stream transitions to Open. Callers
    ///     must await this before calling `stream_write`, or writes
    ///     will fail with `"send in state Connecting"`.
    pub async fn stream_open(
        &self,
        cid: crate::circuit::CircuitId,
        target: &str,
    ) -> Result<(u16, tokio::sync::mpsc::Receiver<Vec<u8>>, tokio::sync::oneshot::Receiver<()>)> {
        let streams = {
            let mgr = self.circuits.read().await;
            mgr.origins.get(&cid)
                .map(|c| Arc::clone(&c.streams))
                .ok_or_else(|| Error::Handshake("stream_open: no circuit".into()))?
        };

        let (id, rx, ready) = streams.open_stream(target.to_string()).await;

        // BEGIN payload is a nul-terminated address string in ASCII.
        let mut begin_data = target.as_bytes().to_vec();
        begin_data.push(0);

        // Construct the relay cell manually to set stream_id.
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        let mut relay = RelayCell::new(RelayCommand::Begin, id, begin_data)?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("stream_open: no circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("stream_open: circuit has no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let target_hop = hops_len - 1;

        let oc      = mgr.origins.get_mut(&cid).unwrap();
        relay.stamp_digest(&mut oc.hops[target_hop].forward_digest);
        let mut payload = relay.to_payload();
        for i in (0..=target_hop).rev() {
            crate::circuit::onion_encrypt_forward(&mut oc.hops[i], &mut payload);
        }
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await?;

        Ok((id, rx, ready))
    }

    /// Send DATA on an open stream. Enforces the per-stream send
    /// window; returns an error if the window is exhausted (caller
    /// should wait for a SENDME to arrive).
    pub async fn stream_write(
        &self,
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        data: &[u8],
    ) -> Result<()> {
        use crate::circuit::{RELAY_DATA_MAX, RelayCommand};

        // Split into cell-sized chunks.
        for chunk in data.chunks(RELAY_DATA_MAX) {
            let streams = {
                let mgr = self.circuits.read().await;
                mgr.origins.get(&cid)
                    .map(|c| Arc::clone(&c.streams))
                    .ok_or_else(|| Error::Handshake("stream_write: no circuit".into()))?
            };

            // First consume a stream-level window slot. This fails
            // fast if the per-stream budget is exhausted.
            let ok = streams.with_stream(stream_id, |s| s.try_consume_window()).await;
            match ok {
                Some(Ok(())) => {}
                Some(Err(e)) => return Err(e),
                None => return Err(Error::Handshake("stream_write: unknown stream".into())),
            }

            // Then consume a circuit-level window slot. A depleted
            // circuit window means the circuit as a whole is
            // congested, not just this stream, so all sibling streams
            // are equally blocked. This prevents one greedy stream
            // from monopolizing the circuit's downstream capacity.
            {
                let mut mgr = self.circuits.write().await;
                let oc = mgr.origins.get_mut(&cid)
                    .ok_or_else(|| Error::Handshake("stream_write: circuit gone".into()))?;
                oc.try_consume_circ_window()?;
            }

            self.send_stream_relay(cid, stream_id, RelayCommand::Data, chunk.to_vec()).await?;
        }
        Ok(())
    }

    /// Close a stream with the given reason.
    pub async fn stream_close(
        &self,
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        reason: crate::stream::EndReason,
    ) -> Result<()> {
        use crate::circuit::RelayCommand;
        let reason_byte = reason as u8;
        self.send_stream_relay(cid, stream_id, RelayCommand::End, vec![reason_byte]).await?;

        let streams = {
            let mgr = self.circuits.read().await;
            mgr.origins.get(&cid).map(|c| Arc::clone(&c.streams))
        };
        if let Some(m) = streams {
            m.with_stream(stream_id, |s| s.close(reason)).await;
            m.remove(stream_id).await;
        }
        Ok(())
    }

    /// Internal: send a stream-scoped relay cell (carries stream_id).
    async fn send_stream_relay(
        &self,
        cid: crate::circuit::CircuitId,
        stream_id: u16,
        cmd: crate::circuit::RelayCommand,
        data: Vec<u8>,
    ) -> Result<()> {
        use crate::circuit::{RelayCell, Cell, CellCommand, onion_encrypt_forward};

        let mut relay = RelayCell::new(cmd, stream_id, data)?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("send_stream_relay: no circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("send_stream_relay: no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let target_hop = hops_len - 1;

        let oc = mgr.origins.get_mut(&cid).unwrap();
        relay.stamp_digest(&mut oc.hops[target_hop].forward_digest);
        let mut payload = relay.to_payload();
        for i in (0..=target_hop).rev() {
            onion_encrypt_forward(&mut oc.hops[i], &mut payload);
        }
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Send an application-level relay cell along an origin circuit.
    /// Encrypts the cell through all hops and dispatches it over the
    /// connection to our guard peer.
    pub async fn send_origin_relay(
        &self,
        cid: crate::circuit::CircuitId,
        cmd: crate::circuit::RelayCommand,
        data: Vec<u8>,
    ) -> Result<()> {
        use crate::circuit::{RelayCell, Cell, CellCommand};
        let relay = RelayCell::new(cmd, 0, data)?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("send_origin_relay: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("send_origin_relay: no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Client side: we received RENDEZVOUS2 on our RP circuit. Match
    /// the cookie to the pending_rendezvous entry, verify the AUTH
    /// tag using the HS static key stashed at registration, and
    /// install the end-to-end keys for this circuit.
    ///
    /// This is the cryptographic moment at which the client becomes
    /// authenticated with the HS. A tampered or forged RENDEZVOUS2
    /// is rejected: the cookie is consumed (preventing retry) but no
    /// keys are installed, and the caller should tear down the circuit.
    async fn handle_rendezvous2(&self, rp_cid: crate::circuit::CircuitId, data: &[u8]) {
        let r2 = match crate::rendezvous::Rendezvous2::decode(data) {
            Ok(r) => r,
            Err(e) => { debug!("rendezvous2 decode: {}", e); return; }
        };

        // Find pending entry by rp_cid (RENDEZVOUS2 carries no cookie
        // itself — the RP used it for splicing and stripped it).
        let mut mgr = self.circuits.write().await;
        let cookie = mgr.pending_rendezvous.iter()
            .find(|(_, (cid, _, _, _))| *cid == rp_cid)
            .map(|(c, _)| *c);
        let Some(cookie) = cookie else {
            debug!("rendezvous2: no pending entry for cid {:?}", rp_cid);
            return;
        };

        // complete_rendezvous uses the HS static key stored at
        // register_pending_rendezvous time. On AUTH failure the cookie
        // is still consumed (see the implementation); no keys installed.
        match mgr.complete_rendezvous(&cookie, &r2.server_y, &r2.auth) {
            Ok(cid) => {
                info!("HS rendezvous completed on circ {:?} (e2e keys installed)", cid);
                drop(mgr);
                // Signal any orchestrator (e.g. hs_fetch) awaiting this
                // circuit that the e2e keys are installed and the
                // circuit is ready for application traffic. Keyed by
                // the RP circuit id — the same id the waiter registered
                // under before sending INTRODUCE1.
                self.signal_rendezvous(cid, Ok(())).await;
            }
            Err(e) => {
                debug!("rendezvous2: auth verification failed: {}", e);
                // Tear down the circuit — the RP may be adversarial.
                let guard = mgr.origins.get(&rp_cid).map(|c| c.peer);
                mgr.origins.remove(&rp_cid);
                mgr.e2e_keys.remove(&rp_cid);
                drop(mgr);
                if let Some(g) = guard {
                    use crate::circuit::{Cell, CellCommand};
                    if let Ok(dcell) = Cell::with_payload(rp_cid, CellCommand::Destroy, &[0]) {
                        let _ = self.send_circuit_cell(&g, &dcell.to_bytes()).await;
                    }
                }
                // Wake the orchestrator with the failure so it doesn't
                // block until timeout. The cookie has already been
                // consumed inside complete_rendezvous, so no retry.
                self.signal_rendezvous(rp_cid, Err(Error::Handshake(
                    format!("rendezvous auth verification failed: {e}")))).await;
            }
        }
    }

    /// HS role: serve an end-to-end request that arrived on one of our
    /// rendezvous circuits. The request is a single line
    /// `"<METHOD> <path>"` (e.g. "GET /") sent by the client over the
    /// e2e DATA channel. We resolve which hidden service this circuit
    /// belongs to, look the path up in the local site store, and reply
    /// over the same e2e channel with a DATA cell carrying the response
    /// (a minimal `status\n\ncontent-type\n\n<body>` framing) followed
    /// by an END to signal completion.
    ///
    /// The reply travels back through `send_origin_relay`, which applies
    /// the installed e2e layer automatically, so the RP forwards it
    /// blindly and the client recovers it at its own e2e layer.
    async fn serve_hs_request(
        self: Arc<Self>,
        rp_cid: crate::circuit::CircuitId,
        request: Vec<u8>,
    ) {
        use crate::circuit::RelayCommand;

        // Only serve if this circuit actually has e2e keys (it's one of
        // our rendezvous circuits). Otherwise ignore.
        {
            let mgr = self.circuits.read().await;
            if !mgr.e2e_keys.contains_key(&rp_cid) {
                debug!("serve_hs_request: circ {:?} has no e2e keys", rp_cid);
                return;
            }
        }

        let line = String::from_utf8_lossy(&request);
        let mut parts = line.split_whitespace();
        let _method = parts.next().unwrap_or("GET");
        let path    = parts.next().unwrap_or("/").to_string();

        // Determine which hidden service this rendezvous circuit serves.
        // We host possibly several; the store is keyed by hs_id. We
        // don't currently record hs_id per RP circuit, so serve from the
        // first (typically only) locally-hosted service. This is fine
        // for the common single-service node; a multi-service node would
        // thread the hs_id from handle_introduce2 into the intent and on
        // into the circuit. See note below.
        let hs_id = {
            let svcs = self.store.list_services().await;
            svcs.into_iter().next().map(|m| m.hs_id)
        };

        let (status, ctype, body): (u16, String, Vec<u8>) = match hs_id {
            Some(id) => match self.store.get_file(&id, &path).await {
                Some((s, ct, b)) => (s, ct, b),
                None => (404, "text/html".into(), b"<h1>Not found</h1>".to_vec()),
            },
            None => (503, "text/html".into(),
                     b"<h1>No hidden service hosted here</h1>".to_vec()),
        };

        // Frame: "<status>\n<content-type>\n\n<body-bytes>". Kept simple
        // and self-delimiting; the client splits on the blank line.
        let mut framed = format!("{status}\n{ctype}\n\n").into_bytes();
        framed.extend_from_slice(&body);

        // A single relay cell carries at most RELAY_DATA_MAX bytes, so
        // chunk the framed response across as many DATA cells as needed.
        // The client collector concatenates chunks until END, so any
        // split point is fine. Leave headroom below the hard limit for
        // safety.
        const CHUNK: usize = crate::circuit::RELAY_DATA_MAX;
        for piece in framed.chunks(CHUNK) {
            if let Err(e) = self.send_origin_relay(
                rp_cid, RelayCommand::Data, piece.to_vec()).await
            {
                debug!("serve_hs_request: send chunk: {}", e);
                return;
            }
        }
        let _ = self.send_origin_relay(
            rp_cid, RelayCommand::End,
            vec![crate::stream::EndReason::Done as u8]).await;
    }

    /// Fire the completion waiter registered for `rp_cid`, if any.
    /// Called from `handle_rendezvous2` on both the success and
    /// failure paths. Sending on a dropped receiver (orchestrator gave
    /// up / timed out) is a no-op. Removing the entry means a second,
    /// duplicate RENDEZVOUS2 for the same circuit can't re-fire a
    /// stale sender.
    async fn signal_rendezvous(
        &self,
        rp_cid: crate::circuit::CircuitId,
        result: Result<()>,
    ) {
        if let Some(tx) = self.rendezvous_waiters.write().await.remove(&rp_cid) {
            let _ = tx.send(result);
        }
    }

    /// Register a completion waiter for the RP circuit `rp_cid` and
    /// return the receiver to await. Must be called *before* sending
    /// INTRODUCE1 so there's no window in which RENDEZVOUS2 could
    /// arrive and find no waiter registered. Any prior waiter for the
    /// same circuit is dropped (its receiver resolves to a canceled
    /// error), which is fine — only one fetch drives a given circuit.
    async fn await_rendezvous(
        &self,
        rp_cid: crate::circuit::CircuitId,
    ) -> tokio::sync::oneshot::Receiver<Result<()>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.rendezvous_waiters.write().await.insert(rp_cid, tx);
        rx
    }

    // ── DHT ───────────────────────────────────────────────────────────

    async fn handle_dht_find(&self, msg: DhtFind, src: &Arc<PeerConn>) {
        let target: [u8; 32] = hex::decode(&msg.target)
            .ok().and_then(|b| b.try_into().ok()).unwrap_or([0u8; 32]);
        let nodes = self.routing.closest(&target, crate::dht::K)
            .into_iter().map(|p| DhtPeerInfo {
                node_id:    p.node_id_hex(),
                host:       p.host,
                port:       p.port,
                cert:       p.cert,
                static_pub: p.static_pub,
            }).collect();
        let _ = src.send_msg(&Message::DhtFound(DhtFound {
            req_id: msg.req_id,
            target: msg.target,
            nodes,
        })).await;
    }

    fn handle_dht_found(&self, msg: DhtFound) {
        for n in msg.nodes {
            if let Ok(b) = hex::decode(&n.node_id) {
                if let Ok(id) = b.try_into() {
                    self.routing.add_peer(PeerInfo {
                        node_id: id, host: n.host, port: n.port,
                        cert: n.cert, static_pub: n.static_pub,
                    });
                }
            }
        }
    }

    async fn handle_dht_fetch(&self, msg: crate::wire::DhtFetch, src: &Arc<PeerConn>) {
        let value = self.dht.get(&msg.key);
        let _ = src.send_msg(&Message::DhtValue(DhtValue {
            req_id: msg.req_id, key: msg.key, value,
        })).await;
    }

    // ── Hidden services ───────────────────────────────────────────────

    async fn handle_hs_lookup(&self, msg: HsLookup, src: &Arc<PeerConn>) {
        let descriptor = self.dht.get_hs(&msg.hs_id);
        info!("hs lookup request {}: have_descriptor={}",
              &msg.hs_id[..12.min(msg.hs_id.len())], descriptor.is_some());
        let puzzle = if let Some(hs) = self.hs_mgr.get(&msg.hs_id).await {
            Some(hs.issue_puzzle())
        } else { None };
        let _ = src.send_msg(&Message::HsFound(HsFound {
            req_id: msg.req_id, hs_id: msg.hs_id, descriptor, puzzle,
        })).await;
    }

    /// Client side: a peer answered our HsLookup. Cache any descriptor it
    /// carried and wake the waiting `lookup_hs_descriptor` call.
    async fn handle_hs_found(&self, msg: HsFound) {
        info!("hs found {}: has_descriptor={}",
              &msg.hs_id[..12.min(msg.hs_id.len())], msg.descriptor.is_some());
        // Only a descriptor-bearing answer resolves the lookup. Peers that
        // don't have it reply with `None`; ignore those so they can't
        // preempt a peer that does (or the timeout).
        if let Some(desc) = msg.descriptor {
            self.dht.put_hs(&desc);
            if let Some(tx) = self.hs_lookup_waiters.write().await.remove(&msg.req_id) {
                let _ = tx.send(Some(desc));
            }
        }
    }

    /// Actively resolve an HS descriptor from the network. Checks the local
    /// DHT cache first; on a miss, broadcasts an HsLookup to all connected
    /// peers and awaits the first HsFound that carries a descriptor (up to
    /// `timeout`). The result is cached, so subsequent fetches are local.
    pub async fn lookup_hs_descriptor(&self, hs_id: &str)
        -> Option<crate::wire::HsDescriptor>
    {
        // 1. local cache hit — no network needed.
        if let Some(d) = self.dht.get_hs(hs_id) { return Some(d); }

        // 2. register a waiter, then broadcast the query.
        let req_id = hex::encode(rand::random::<[u8; 16]>());
        let rx = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.hs_lookup_waiters.write().await.insert(req_id.clone(), tx);
            rx
        };
        // Ask the relays the ring says should have it. Broadcasting instead
        // wakes the whole network to find one record, and tells every relay
        // which services are being visited.
        let responsible = self.responsible_hsdirs_for(hs_id).await;
        {
            let peers = self.peers.read().await;
            if peers.is_empty() {
                warn!("hs lookup {}: no peers connected", &hs_id[..12.min(hs_id.len())]);
                self.hs_lookup_waiters.write().await.remove(&req_id);
                return None;
            }
            let targets: Vec<_> = match &responsible {
                Some(dirs) if !dirs.is_empty() => {
                    let want: Vec<_> = peers.iter()
                        .filter(|(id, _)| dirs.contains(&hex::encode(id)))
                        .map(|(_, p)| Arc::clone(p))
                        .collect();
                    // We may not be linked to the responsible relays; better a
                    // broadcast that works than a targeted query that reaches
                    // nobody.
                    if want.is_empty() {
                        debug!("hs lookup {}: not linked to any responsible HSDir, \
                                asking everyone", &hs_id[..12.min(hs_id.len())]);
                        peers.values().map(Arc::clone).collect()
                    } else {
                        info!("hs lookup {}: asking {} responsible HSDir(s)",
                              &hs_id[..12.min(hs_id.len())], want.len());
                        want
                    }
                }
                _ => {
                    debug!("hs lookup {}: no consensus ring, asking all {} peer(s)",
                           &hs_id[..12.min(hs_id.len())], peers.len());
                    peers.values().map(Arc::clone).collect()
                }
            };
            for p in targets {
                let _ = p.send_msg(&Message::HsLookup(HsLookup {
                    req_id:          req_id.clone(),
                    hs_id:           hs_id.to_string(),
                    puzzle_solution: None,
                })).await;
            }
        }

        // 3. await the first descriptor-bearing answer (bounded wait).
        let res = time::timeout(Duration::from_secs(10), rx).await;
        self.hs_lookup_waiters.write().await.remove(&req_id);
        match res {
            Ok(Ok(Some(desc))) => {
                info!("hs lookup {}: resolved descriptor", &hs_id[..12.min(hs_id.len())]);
                Some(desc)
            }
            _ => {
                warn!("hs lookup {}: no descriptor from any peer (timeout/miss)",
                      &hs_id[..12.min(hs_id.len())]);
                self.dht.get_hs(hs_id) // late arrival may have cached it
            }
        }
    }

    // ── Board ─────────────────────────────────────────────────────────

    async fn handle_board_post(&self, msg: BoardPost, src: &Arc<PeerConn>) {
        if self.board.merge(&msg) {
            let peers = self.peers.read().await;
            for p in peers.values() {
                if p.info.node_id != src.info.node_id {
                    let _ = p.send_msg(&Message::BoardPost(msg.clone())).await;
                }
            }
        }
    }

    async fn handle_board_fetch(&self, msg: BoardFetch, src: &Arc<PeerConn>) {
        let posts = self.board.get(&msg.channel, msg.limit as usize);
        let _ = src.send_msg(&Message::BoardPosts(BoardPosts {
            req_id: msg.req_id, channel: msg.channel, posts,
        })).await;
    }

    // ── Public API ────────────────────────────────────────────────────

    pub async fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().map(|p| p.info.clone()).collect()
    }

    pub async fn post_to_board(&self, channel: &str, text: &str) {
        let cluster = self.cert.read().unwrap().cluster_id();
        let post    = self.board.post(channel, text, Some(cluster));
        let peers   = self.peers.read().await;
        for p in peers.values() {
            let _ = p.send_msg(&Message::BoardPost(post.clone())).await;
        }
    }

    pub async fn register_hs(&self, name: &str) -> Arc<crate::hidden_service::HiddenService> {
        let cert = self.cert.read().unwrap().clone();
        self.hs_mgr.register(&cert, name).await
    }

    // ── Circuit API ───────────────────────────────────────────────────

    /// Build a multi-hop circuit through the given path. Each entry in
    /// `path` must correspond to a peer this node is already connected
    /// to (use [`PhiNode::connect`] first). The first entry is the
    /// guard; subsequent entries are reached via RELAY_EXTEND2.
    ///
    /// Returns the originating [`CircuitId`] once all hops are built.
    /// The caller can then send application-level relay cells through
    /// the circuit using APIs not yet exposed (stream layer).
    /// Build one clean circuit for the pool.
    ///
    /// Uses exactly the same machinery as an on-demand build — weighted path
    /// selection, guard, layer-2 vanguard substitution via `build_hs_circuit`
    /// — because a pooled circuit that cut corners would be a quietly weaker
    /// circuit, and the caller can't tell the difference.
    async fn build_pool_circuit(
        self: &Arc<Self>,
        consensus: &crate::directory::ConsensusDocument,
        avoid_terminal_hex: Option<&str>,
    ) -> Result<crate::circuit_pool::PooledCircuit> {
        use crate::path_select::{select_path, PathError};
        let self_id = hex::encode(self.node_id());
        let path = {
            let mut rng = rand::thread_rng();
            // Redraw rather than exclude: a rendezvous point on the service's
            // own relay means rendezvousing with itself, but on a small
            // network that relay is in *every* path — only the draws that
            // don't place it last are unusable. Excluding it outright would
            // leave nothing to pick from.
            let mut chosen = None;
            for _ in 0..24 {
                let p = select_path(&mut rng, consensus, &[self_id.clone()], None)
                    .map_err(|PathError::InsufficientRelays(s)| Error::Handshake(
                        format!("circuit pool: {s}")))?;
                let ok = match avoid_terminal_hex {
                    None => true,
                    Some(bad) => p.hops.last().map(|h| h.node_id_hex != bad).unwrap_or(false),
                };
                if ok { chosen = Some(p); break; }
            }
            match chosen {
                Some(p) => p,
                None => return Err(Error::Handshake(
                    "circuit pool: every draw put the terminal hop on the \
                     service's own relay — the network needs more relays".into())),
            }
        };
        let specs = path.to_link_specs()
            .map_err(|e| Error::Handshake(format!("circuit pool: link specs: {e:?}")))?;
        let cid = Arc::clone(self).build_hs_circuit(specs.clone()).await?;
        Ok(crate::circuit_pool::PooledCircuit {
            cid, path: specs, built_at: std::time::Instant::now(),
        })
    }

    /// Keep a couple of circuits warm, and retire ones that have gone stale.
    ///
    /// This is the whole point of the pool: the handshakes happen while the
    /// user is reading, not while they're waiting.
    pub async fn circuit_pool_loop(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = time::sleep(Duration::from_secs(10)) => {}
                _ = self.shutdown.notified() => break,
            }
            if self.is_shutting_down() { break; }

            // Retire stale circuits first, so the rebuild below refills with
            // paths drawn from the current consensus.
            let stale = {
                let mut p = self.pool.lock().unwrap();
                p.drain_stale(std::time::Instant::now())
            };
            for c in stale {
                debug!("circuit pool: retiring stale circuit {:?}", c.cid);
                let _ = self.destroy_circuit(c.cid).await;
            }

            loop {
                let want = {
                    let p = self.pool.lock().unwrap();
                    p.wants_more(std::time::Instant::now())
                };
                if !want || self.is_shutting_down() { break; }

                let consensus = {
                    let g = self.cached_consensus.read().await;
                    match g.as_ref() { Some(d) => d.clone(), None => {
                        debug!("circuit pool: no consensus yet, waiting");
                        break;
                    }}
                };
                match self.build_pool_circuit(&consensus, None).await {
                    Ok(c) => {
                        debug!("circuit pool: warm circuit {:?} ready ({} hop)",
                               c.cid, c.path.len());
                        self.pool.lock().unwrap().push(c);
                    }
                    Err(e) => {
                        // Expected on a cold start or a small network; don't
                        // spin on it.
                        debug!("circuit pool: build failed ({}), backing off", e);
                        self.pool.lock().unwrap().note_failure(std::time::Instant::now());
                        break;
                    }
                }
            }
        }
        // Don't leave circuits open on the relays behind us.
        let left = self.pool.lock().unwrap().take_all();
        for c in left { let _ = self.destroy_circuit(c.cid).await; }
        debug!("circuit_pool_loop: shutting down");
    }

    /// A rendezvous circuit: warm if one is available, freshly built if not.
    ///
    /// Returns the circuit id and its terminal hop (the rendezvous point).
    /// `avoid_hex` is the service's own relay — a rendezvous point there
    /// would mean rendezvousing with itself.
    async fn rp_circuit(
        self: &Arc<Self>,
        consensus: &crate::directory::ConsensusDocument,
        avoid_hex: &str,
    ) -> Result<(crate::circuit::CircuitId, Vec<crate::circuit::LinkSpec>)> {
        if let Some(c) = {
            let mut p = self.pool.lock().unwrap();
            p.take(std::time::Instant::now(), Some(avoid_hex))
        } {
            if !c.path.is_empty() {
                info!("hs_fetch: using a warm circuit ({:?}) — no build wait", c.cid);
                return Ok((c.cid, c.path));
            }
        }
        debug!("hs_fetch: no warm circuit available, building one now");
        let c = self.build_pool_circuit(consensus, Some(avoid_hex)).await?;
        if c.path.is_empty() {
            return Err(Error::Handshake("hs_fetch: empty RP path".into()));
        }
        Ok((c.cid, c.path))
    }

    /// Which relays should hold this service's descriptor this period.
    ///
    /// Both the publisher and the client compute this, which is what lets a
    /// lookup ask specific relays instead of shouting at the whole network.
    /// Falls back to `None` when we have no consensus to draw a ring from —
    /// the caller then uses every peer it knows, which is what the old
    /// broadcast did.
    pub async fn responsible_hsdirs_for(&self, hs_id: &str) -> Option<Vec<String>> {
        use crate::directory::PeerFlags;
        let doc = self.cached_consensus.read().await.as_ref()?.clone();
        let relays: Vec<String> = doc.peers.iter()
            .filter(|p| PeerFlags::from_bits_truncate(p.flags).contains(PeerFlags::RUNNING))
            .map(|p| p.node_id_hex.clone())
            .collect();
        if relays.is_empty() { return None; }
        // Salt with the period's shared random value, so next period's ring
        // can't be computed today and ground against. If the authorities
        // didn't agree one, fall back to the network id and accept that the
        // ring is predictable — a predictable ring still beats a broadcast,
        // and pretending otherwise would be worse than saying so.
        let salt = if doc.shared_random.is_empty() {
            debug!("consensus carries no shared random value — HSDir ring \
                    positions are predictable this period. The authorities \
                    need two consecutive vote cycles to agree one.");
            doc.network_id.clone()
        } else {
            doc.shared_random.clone()
        };
        let period = crate::hs_identity::current_epoch();

        // Index by the blinded key, not the identity. A directory then holds
        // a descriptor it cannot attribute to a service, and cannot link to
        // the same service next period. Clients derive the same blinded key
        // from the address they typed, so they still know exactly who to ask.
        let ring_key = match hex::decode(hs_id).ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .and_then(|pk| crate::hs_blind::blind_public(&pk, period, &salt))
        {
            Some(b) => hex::encode(b),
            // Not a valid key — nothing will resolve anyway, but fall back to
            // the raw id rather than silently returning no directories.
            None => hs_id.to_string(),
        };
        Some(crate::hsdir_ring::responsible_hsdirs(
            &ring_key, &relays, period, &salt))
    }

    /// Load the sampled guard set from disk, or start one.
    ///
    /// The set is only a bound on how many guards ever learn our address if
    /// it survives restarts — an in-memory sample would be redrawn on every
    /// launch, which is the churn attack, self-inflicted.
    pub fn load_guard_sample(&self, path: std::path::PathBuf) {
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(s) = serde_json::from_slice::<crate::guard_sample::SampledSet>(&bytes) {
                info!("guard sample: {} guard(s) remembered", s.len());
                *self.guard_sample.write().unwrap() = s;
            }
        }
        *self.guard_sample_path.write().unwrap() = Some(path);
    }

    fn save_guard_sample(&self) {
        let path = match self.guard_sample_path.read().unwrap().clone() {
            Some(p) => p,
            None => return,
        };
        let s = self.guard_sample.read().unwrap().clone();
        if let Ok(j) = serde_json::to_vec_pretty(&s) {
            let _ = std::fs::write(&path, j);
        }
    }

    /// Note that a circuit completed through this guard.
    pub fn confirm_guard(&self, node_id_hex: &str) {
        {
            let mut s = self.guard_sample.write().unwrap();
            s.confirm(node_id_hex, crate::com::now_secs());
        }
        self.save_guard_sample();
    }

    /// Give this relay the key it signs its descriptor with.
    pub fn set_signing_key(&self, k: ed25519_dalek::SigningKey) {
        *self.signing_key.write().unwrap() = Some(k);
    }

    /// This relay's own descriptor, signed — or `None` if no signing key was
    /// configured (a client, or an older identity).
    pub fn my_descriptor(&self) -> Option<crate::relay_desc::RelayDescriptor> {
        let g = self.signing_key.read().unwrap();
        let k = g.as_ref()?;
        Some(crate::relay_desc::build(
            k,
            self.node_id_hex(),
            self.host.clone(),
            self.port,
            hex::encode(self.keypair.public_bytes()),
            self.family(),
            "default".to_string(),
            crate::com::now_secs(),
        ))
    }

    /// Pin a peer's signing key, learned over a link the ΦNET handshake has
    /// already authenticated.
    ///
    /// This is the only place a key becomes attributable to a node id. The
    /// handshake proved the peer holds the cert and static key for that id —
    /// only the real node can do that — so the signing key it presents here
    /// is genuinely its own. Everything afterwards is checked against this.
    ///
    /// A node that presents a *different* key later is refused rather than
    /// re-pinned: silently accepting a new key would make the pin decorative,
    /// since impersonation is exactly what it exists to catch.
    pub fn pin_signing_key(&self, node_id: [u8; 32], signing_pub_hex: String) -> bool {
        let mut m = self.pinned_keys.write().unwrap();
        match m.get(&node_id) {
            Some(existing) if *existing != signing_pub_hex => {
                warn!("node {} presented a different signing key than the one \
                       pinned for it — refusing. Either it rotated keys (which \
                       it may not do unilaterally) or something is impersonating it.",
                      &hex::encode(node_id)[..12]);
                false
            }
            Some(_) => true,
            None => { m.insert(node_id, signing_pub_hex); true }
        }
    }

    pub fn pinned_signing_key(&self, node_id: &[u8; 32]) -> Option<String> {
        self.pinned_keys.read().unwrap().get(node_id).cloned()
    }

    /// Accept a descriptor if it verifies against the key we pinned.
    pub fn accept_descriptor(&self, d: crate::relay_desc::RelayDescriptor) -> bool {
        let node_id: [u8; 32] = match hex::decode(&d.node_id_hex).ok()
            .and_then(|v| v.try_into().ok()) {
            Some(n) => n,
            None => return false,
        };
        let pinned = self.pinned_signing_key(&node_id);
        match crate::relay_desc::verify(&d, pinned.as_deref(), crate::com::now_secs()) {
            Ok(()) => {
                self.descriptors.write().unwrap().insert(d.node_id_hex.clone(), d);
                true
            }
            Err(e) => {
                debug!("rejecting descriptor for {}: {:?}",
                       &d.node_id_hex[..12.min(d.node_id_hex.len())], e);
                false
            }
        }
    }

    /// Every descriptor we hold, for the bandwidth scanner's vote.
    pub fn known_descriptors(&self) -> Vec<crate::relay_desc::RelayDescriptor> {
        self.descriptors.read().unwrap().values().cloned().collect()
    }

    /// Turn per-address rate limiting on. Off by default — a limiter that
    /// enables itself is a good way to break someone's testnet.
    pub fn set_dos_protection(&self, on: bool) {
        self.dos.lock().unwrap().set_enabled(on);
    }

    pub fn dos_enabled(&self) -> bool { self.dos.lock().unwrap().is_enabled() }

    /// Addresses currently being refused, worst first.
    pub fn dos_offenders(&self) -> Vec<(std::net::IpAddr, u64)> {
        self.dos.lock().unwrap().offenders()
    }

    /// Guards whose circuits fail far more often than the rest — possibly a
    /// guard steering us onto paths it controls, possibly just a bad relay.
    pub fn suspicious_guards(&self) -> Vec<(String, crate::path_bias::GuardStats)> {
        self.path_bias.lock().unwrap().suspicious()
    }

    /// Every guard's circuit success record, worst first.
    pub fn guard_stats(&self) -> Vec<(String, crate::path_bias::GuardStats)> {
        self.path_bias.lock().unwrap().all()
    }

    /// How long to wait for a circuit, learned from how long circuits
    /// actually take on this client's view of the network.
    pub fn circuit_timeout(&self) -> Duration {
        self.build_times.lock().unwrap().timeout()
    }

    /// Declare which operator family this relay belongs to.
    ///
    /// Set it to the same string on every relay you run. Clients then refuse
    /// to build a circuit through two of them, because two relays with one
    /// operator provide one relay's worth of anonymity while looking like
    /// two.
    pub fn set_family(&self, f: String) {
        *self.family.write().unwrap() = f;
    }

    pub fn family(&self) -> String {
        self.family.read().unwrap().clone()
    }

    /// Dial a peer, with the future's type erased.
    ///
    /// `connect` spawns the peer read loop, which handles cells, which (for
    /// EXTEND2) dials the next hop — a genuine cycle. Every link in it is an
    /// `async fn` with an opaque return type, so the compiler chases the cycle
    /// forever ("cycle detected when computing type of opaque ..."). Declaring
    /// a concrete boxed type here breaks the chain.
    fn connect_boxed(self: Arc<Self>, host: String, port: u16)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
    {
        Box::pin(async move { self.connect(&host, port).await })
    }

    pub async fn build_circuit(
        self: Arc<Self>,
        path: Vec<crate::circuit::LinkSpec>,
    ) -> Result<crate::circuit::CircuitId> {
        use crate::circuit::{MAX_HOPS, CELL_SIZE};

        if path.is_empty() || path.len() > MAX_HOPS {
            return Err(Error::Handshake(format!(
                "build_circuit: path length {} out of range [1,{}]",
                path.len(), MAX_HOPS
            )));
        }
        // Link to the guard, and *only* the guard.
        //
        // This node used to open a direct connection to every hop, including
        // its own exit — which handed the exit operator the client's address
        // alongside the traffic it was carrying, the one pairing onion
        // routing exists to prevent. It also made guard pinning pointless:
        // guards limit who ever sees your address, which means nothing if you
        // dial every relay you route through.
        //
        // Now the client links to path[0] and extends through the circuit:
        // the guard dials the middle, the middle dials the exit (see the
        // Extend2 handler). Nobody past the guard learns who we are.
        {
            let ls = &path[0];
            let linked = self.peers.read().await.contains_key(&ls.node_id);
            if !linked {
                let host = ls.host.clone();
                let port = ls.port;
                debug!("build_circuit: dialling guard {}:{}", host, port);
                if let Err(e) = Arc::clone(&self).connect(&host, port).await {
                    return Err(Error::Handshake(format!(
                        "build_circuit: dial guard {}:{} failed: {}", host, port, e
                    )));
                }
            }
            let ok = self.peers.read().await.contains_key(&ls.node_id);
            if !ok {
                return Err(Error::Handshake(format!(
                    "build_circuit: guard {} ({}:{}) answered with a different identity",
                    hex::encode(&ls.node_id[..6]), ls.host, ls.port
                )));
            }
        }
        {
            let peers = self.peers.read().await;
            // Only the guard needs a link — the rest of the path is reached
            // by extending through the circuit, which is the entire point.
            let ls = &path[0];
            if !peers.contains_key(&ls.node_id) {
                return Err(Error::Handshake(format!(
                    "build_circuit: guard ({}) not connected",
                    hex::encode(&ls.node_id[..6])
                )));
            }
        }

        // 1. CREATE to guard. The `guard_b` arg is the guard's x25519
        //    static public key — NOT its node_id. The receiver's
        //    server_handshake validates that the B in the message
        //    matches its own static public key.
        let guard = &path[0];
        let (cid, create_bytes) = {
            let mut mgr = self.circuits.write().await;
            mgr.start_circuit(guard.node_id, &guard.node_id, &guard.static_pub)?
        };
        self.send_circuit_cell(&guard.node_id, &create_bytes).await?;

        // 2. Wait for CREATED — we poll the origin state until the first
        //    hop appears. In practice the dispatch task installs it.
        //
        // The wait is learned rather than fixed: fifteen seconds is far too
        // long on a fast network (a dead guard costs the user the whole
        // fifteen) and too short on a slow one (we abandon circuits that were
        // about to complete, and rebuild them, making it slower still).
        let timeout = self.circuit_timeout();
        let build_started = std::time::Instant::now();
        // Counted from here: the guard has taken the circuit, so what happens
        // next is something it had a hand in. An unreachable guard is a
        // different failure and doesn't belong in this statistic.
        let guard_hex = hex::encode(guard.node_id);
        self.path_bias.lock().unwrap().note_attempt(&guard_hex);
        let start = std::time::Instant::now();
        loop {
            {
                let mgr = self.circuits.read().await;
                if let Some(oc) = mgr.origins.get(&cid) {
                    if oc.hops.len() >= 1 { break; }
                }
            }
            if start.elapsed() > timeout {
                return Err(Error::Handshake("circuit: CREATE timed out".into()));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 3. Extend through remaining hops one at a time
        for (i, next) in path.iter().enumerate().skip(1) {
            let extend_bytes: [u8; CELL_SIZE] = {
                let mut mgr = self.circuits.write().await;
                mgr.extend_circuit(cid, next.clone())?
            };
            self.send_circuit_cell(&guard.node_id, &extend_bytes).await?;

            let need_hops = i + 1;
            let start = std::time::Instant::now();
            loop {
                {
                    let mgr = self.circuits.read().await;
                    if let Some(oc) = mgr.origins.get(&cid) {
                        if oc.hops.len() >= need_hops { break; }
                    }
                }
                if start.elapsed() > timeout {
                    return Err(Error::Handshake(format!(
                        "circuit: EXTEND to hop {} timed out", i
                    )));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        // ── Padding pump ─────────────────────────────────────────
        //
        // Each circuit gets a per-circuit padding scheduler. By
        // default this is `NoPadding` (no traffic generated); set
        // a different scheduler via `CircuitManager::set_padding_scheduler`
        // before/during construction to enable padding.
        //
        // This task polls the scheduler at most every 50ms and
        // emits RELAY_DROP cells through the guard hop on the
        // scheduler's say-so. The DROP cells are recognized and
        // discarded by the receiving relay (see
        // `RelayCommand::Drop` handling in node.rs::dispatch).
        //
        // The task exits when the circuit is destroyed (origin
        // record removed from the manager).
        let pad_node = Arc::clone(&self);
        let pad_cid = cid;
        tokio::spawn(async move {
            pad_node.padding_pump_loop(pad_cid).await;
        });

        // Only successful builds are recorded. A timeout says how long we
        // were willing to wait, not how long circuits take — feeding it back
        // would drag the timeout down towards itself until nothing ever
        // completed.
        self.build_times.lock().unwrap().record(build_started.elapsed());
        self.path_bias.lock().unwrap().note_success(&guard_hex);
        // A guard that has actually carried a circuit outranks one that
        // merely looks reachable, and keeps that seniority.
        self.confirm_guard(&guard_hex);

        Ok(cid)
    }

    /// Per-circuit padding pump. Runs until the circuit is destroyed
    /// or the scheduler indicates `Never`. Polls at most every 50ms;
    /// when the scheduler says `Now`, emits a RELAY_DROP cell. When
    /// it says `SleepFor(d)`, sleeps for `d` (capped at 5s so the
    /// task is responsive to circuit teardown).
    async fn padding_pump_loop(self: Arc<Self>, cid: crate::circuit::CircuitId) {
        use crate::circuit::{RelayCell, RelayCommand};
        use crate::padding::PadDecision;
        use std::time::Instant;

        const MAX_SLEEP: Duration = Duration::from_secs(5);
        const MIN_SLEEP: Duration = Duration::from_millis(50);

        loop {
            // Snapshot what we need from the circuit and drop the lock
            // before sleeping or emitting (lock contention would
            // otherwise stall the dispatch path).
            let (scheduler, _guard_peer, scheduler_name) = {
                let mgr = self.circuits.read().await;
                let Some(oc) = mgr.origins.get(&cid) else {
                    // Circuit gone → exit task.
                    return;
                };
                (Arc::clone(&oc.padding_scheduler), oc.peer, oc.padding_scheduler.name().to_string())
            };

            // For NoPadding we still want a low-frequency wake-up
            // so the pump can pick up a scheduler that's swapped in
            // later via set_padding_scheduler. Sleep ~5s and re-check.
            if scheduler_name == "none" {
                tokio::time::sleep(MAX_SLEEP).await;
                continue;
            }

            let now = Instant::now();
            match scheduler.should_pad_now(now) {
                PadDecision::Never => return,
                PadDecision::SleepFor(d) => {
                    let dur = d.clamp(MIN_SLEEP, MAX_SLEEP);
                    tokio::time::sleep(dur).await;
                    continue;
                }
                PadDecision::Now => {
                    // Build a DROP cell. Payload bytes are random so
                    // the cell isn't distinguishable from real DATA
                    // traffic by ciphertext alone.
                    let mut payload = vec![0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut payload);
                    // Validate it round-trips cleanly before sending.
                    if RelayCell::new(
                        RelayCommand::Drop, 0, payload.clone(),
                    ).is_err() {
                        return;
                    }

                    // Onion-encrypt and send via the guard. We use
                    // send_stream_relay which handles the layered
                    // encryption; if it fails (circuit destroyed),
                    // exit the task.
                    if let Err(_) = self.send_stream_relay(
                        cid, 0, RelayCommand::Drop, payload,
                    ).await {
                        return;
                    }

                    scheduler.on_padding_cell(now);
                    // After emitting, give the scheduler a chance to
                    // re-evaluate; loop back to should_pad_now.
                    tokio::time::sleep(MIN_SLEEP).await;
                }
            }
        }
    }

    /// Build a circuit with a specific padding scheduler attached.
    ///
    /// Equivalent to calling `build_circuit` and then immediately
    /// `set_padding_scheduler`, except: this version installs the
    /// scheduler *before* spawning the padding pump, so the pump
    /// immediately uses the requested scheduler instead of cycling
    /// through one wakeup with `NoPadding` before being replaced.
    ///
    /// Pass an `Arc<NoPadding>` (the default) to disable padding
    /// for this circuit even if the operator sets a network-wide
    /// default later — useful for circuits where padding overhead
    /// matters more than fingerprinting resistance (e.g. internal
    /// bandwidth scans).
    pub async fn build_circuit_with_padding(
        self: Arc<Self>,
        path: Vec<crate::circuit::LinkSpec>,
        scheduler: Arc<dyn crate::padding::PaddingScheduler>,
    ) -> Result<crate::circuit::CircuitId> {
        let cid = Arc::clone(&self).build_circuit(path).await?;
        // Install scheduler before the next padding pump iteration
        // wakes up. There's a small race window where the pump may
        // sample the default `NoPadding` once; we accept that — the
        // worst case is one missed pad cycle (~50ms), which is
        // operationally insignificant.
        let mut mgr = self.circuits.write().await;
        mgr.set_padding_scheduler(cid, scheduler);
        Ok(cid)
    }

    /// Build an HS-related circuit using layer-2 vanguards for hop 2.
    ///
    /// HS-related circuits include:
    /// - introduction circuits (HS → IP)
    /// - rendezvous circuits (HS → RP, client → RP)
    ///
    /// For these circuits, the second hop is selected from a small
    /// rotating set of "vanguards" — long-lived (~10 day) helper
    /// relays. This defends against guard-discovery attacks where
    /// an adversary forces the HS to build many circuits and waits
    /// to be selected as the random second hop, then probes from
    /// there to find the actual guard.
    ///
    /// `candidate_paths` is a list of paths the daemon would
    /// otherwise have built. The first hop is taken from
    /// `candidate_paths[0]` (caller's guard choice). The second hop
    /// is replaced with a layer-2 vanguard when available; if no
    /// vanguards are populated yet, the original second hop is
    /// used and added to the vanguard set for next time.
    /// Subsequent hops (if any) come from the original path.
    ///
    /// Returns the cid of the built circuit.
    pub async fn build_hs_circuit(
        self: Arc<Self>,
        candidate_path: Vec<crate::circuit::LinkSpec>,
    ) -> Result<crate::circuit::CircuitId> {
        if candidate_path.len() < 2 {
            // Vanguards only matter for ≥2-hop circuits. Fall through
            // to regular build for trivial cases.
            return Arc::clone(&self).build_circuit(candidate_path).await;
        }

        let mut path = candidate_path.clone();

        // Try to substitute hop 2 with a layer-2 vanguard. If we
        // have one, use it. If not, populate the vanguard set with
        // hop 2 (the originally-selected relay) so next time we have
        // a vanguard to pick from.
        if let Some(vg) = self.vanguards.pick_layer2() {
            // Convert vanguard entry into LinkSpec
            let vg_node_id: [u8; 32] = match hex::decode(&vg.node_id_hex)
                .ok().and_then(|v| v.try_into().ok())
            {
                Some(b) => b,
                None => {
                    tracing::warn!("vanguard has malformed node_id, falling back to candidate");
                    // Fall through to populating with the candidate
                    self.populate_vanguard(&path[1]);
                    return Arc::clone(&self).build_circuit(path).await;
                }
            };
            let vg_static_pub: [u8; 32] = match hex::decode(&vg.static_pub_hex)
                .ok().and_then(|v| v.try_into().ok())
            {
                Some(b) => b,
                None => {
                    self.populate_vanguard(&path[1]);
                    return Arc::clone(&self).build_circuit(path).await;
                }
            };

            // Verify the vanguard is reachable as a peer. If not,
            // mark it unreachable and fall back.
            let connected = self.peers.read().await.contains_key(&vg_node_id);
            if !connected {
                tracing::debug!("vanguard {} not connected, marking unreachable",
                    &vg.node_id_hex[..8]);
                self.vanguards.mark_unreachable(&vg.node_id_hex);
                self.populate_vanguard(&path[1]);
                return Arc::clone(&self).build_circuit(path).await;
            }

            tracing::debug!("HS circuit using vanguard {} for hop 2",
                &vg.node_id_hex[..8]);
            path[1] = crate::circuit::LinkSpec {
                host:       vg.host.clone(),
                port:       vg.port,
                node_id:    vg_node_id,
                static_pub: vg_static_pub,
            };

            // Build, then mark vanguard as used on success
            let result = Arc::clone(&self).build_circuit(path).await;
            if result.is_ok() {
                self.vanguards.mark_used(&vg.node_id_hex);
            } else {
                self.vanguards.mark_unreachable(&vg.node_id_hex);
            }
            return result;
        }

        // No vanguards populated yet — use candidate path as-is and
        // populate the vanguard set with hop 2 for next time.
        self.populate_vanguard(&path[1]);
        Arc::clone(&self).build_circuit(path).await
    }

    fn populate_vanguard(&self, hop: &crate::circuit::LinkSpec) {
        let added = self.vanguards.add_candidate(
            &hex::encode(hop.node_id),
            &hop.host,
            hop.port,
            &hex::encode(hop.static_pub),
        );
        if added {
            tracing::debug!("vanguard set: added {} ({}:{})",
                &hex::encode(&hop.node_id[..6]), hop.host, hop.port);
        }
    }

    /// Set the padding scheduler used for HS-side circuits.
    ///
    /// Applies to circuits built by the HS rendezvous drain. Pass
    /// `None` to disable padding (default behavior). Pass an
    /// `Arc<ConstantRate>` or `Arc<AdaptiveBurst>` to enable
    /// per-circuit padding for every HS rendezvous circuit this
    /// node builds going forward.
    ///
    /// Existing circuits aren't retroactively updated — their
    /// schedulers were captured at build time. Only new circuits
    /// pick up this change.
    pub async fn set_hs_padding_scheduler(
        &self,
        scheduler: Option<Arc<dyn crate::padding::PaddingScheduler>>,
    ) {
        *self.hs_padding_scheduler.write().await = scheduler;
    }

    /// Resolve an HS descriptor to a usable intro point.
    ///
    /// Two cases:
    ///
    /// **Public service** (`descriptor.client_auth.is_none()`):
    /// returns `descriptor.intro_pub` parsed as `[u8; 32]`. This is
    /// what every client could already do; the helper just centralizes
    /// the parsing.
    ///
    /// **Client-authorized service** (`descriptor.client_auth.is_some()`):
    /// the plaintext intro fields are blank. The function tries each
    /// of `client_secrets` in turn against the descriptor's
    /// `ClientAuthBlock`. The first secret that successfully decrypts
    /// a wrapped key (and thus the intro details) wins; we return the
    /// recovered (intro_pub, intro_host, intro_port).
    ///
    /// Returns `Ok(None)` if the descriptor is client-authorized and
    /// none of the supplied secrets are authorized — i.e. this client
    /// can't reach this hidden service. Caller should treat this as
    /// "not authorized," not as a transient error.
    ///
    /// Returns `Err(...)` if the descriptor signature doesn't verify,
    /// the public intro_pub is malformed, or the AEAD decrypt of an
    /// authorized entry fails (which shouldn't happen — that would
    /// indicate corruption).
    pub fn resolve_hs_descriptor(
        descriptor: &crate::wire::HsDescriptor,
        client_secrets: &[x25519_dalek::StaticSecret],
    ) -> Result<Option<ResolvedIntro>> {
        // Step 1: signature must verify regardless of auth model
        crate::hs_identity::verify_descriptor(descriptor)?;

        // Step 2: dispatch on auth model
        match &descriptor.client_auth {
            None => {
                // Public service — parse the plaintext intro_pub
                let intro_pub_bytes: [u8; 32] = hex::decode(&descriptor.intro_pub)
                    .map_err(|e| Error::Crypto(format!("intro_pub hex: {e}")))?
                    .try_into()
                    .map_err(|_| Error::Crypto("intro_pub size".into()))?;
                Ok(Some(ResolvedIntro {
                    intro_pub:  intro_pub_bytes,
                    intro_host: descriptor.intro_host.clone(),
                    intro_port: descriptor.intro_port,
                    intro_node_id: hex::decode(&descriptor.intro_node_id)
                        .ok().and_then(|v| v.try_into().ok())
                        .unwrap_or([0u8; 32]),
                }))
            }
            Some(block) => {
                // Client-authorized — try each provided secret. We
                // don't short-circuit on first error; a malformed
                // entry should be skipped silently (already done by
                // decrypt_intro_with_client_secret).
                for sec in client_secrets {
                    match crate::client_auth::decrypt_intro_with_client_secret(
                        block, sec,
                    )? {
                        Some(intro_secret) => {
                            // Successfully recovered the intro point
                            let intro_pub_bytes: [u8; 32] = hex::decode(&intro_secret.intro_pub)
                                .map_err(|e| Error::Crypto(
                                    format!("recovered intro_pub hex: {e}")))?
                                .try_into()
                                .map_err(|_| Error::Crypto(
                                    "recovered intro_pub size".into()))?;
                            return Ok(Some(ResolvedIntro {
                                intro_pub:  intro_pub_bytes,
                                intro_host: intro_secret.intro_host,
                                intro_port: intro_secret.intro_port,
                                intro_node_id: hex::decode(&intro_secret.intro_node_id)
                                    .ok().and_then(|v| v.try_into().ok())
                                    .unwrap_or([0u8; 32]),
                            }));
                        }
                        None => continue, // try next secret
                    }
                }
                // No supplied secret was authorized
                Ok(None)
            }
        }
    }

    /// Report on existing circuits. Returns `(origin_count,
    /// relay_count)` — how many circuits this node originated vs.
    /// how many it participates in as a middle/exit hop.
    pub async fn circuit_status(&self) -> (usize, usize) {
        let mgr = self.circuits.read().await;
        (mgr.origins.len(), mgr.relays.len())
    }

    /// Tear down an origin circuit. Sends DESTROY upstream and removes
    /// local state.
    pub async fn destroy_circuit(&self, cid: crate::circuit::CircuitId) -> Result<()> {
        use crate::circuit::{Cell, CellCommand};

        let guard_peer = {
            let mgr = self.circuits.read().await;
            mgr.origins.get(&cid).map(|c| c.peer)
        };
        let Some(guard) = guard_peer else { return Ok(()); };

        let cell  = Cell::with_payload(cid, CellCommand::Destroy, &[0u8])?;
        let bytes = cell.to_bytes();
        let _ = self.send_circuit_cell(&guard, &bytes).await;

        let mut mgr = self.circuits.write().await;
        mgr.destroy(guard, cid);
        Ok(())
    }

    // ── Hidden service / rendezvous API ───────────────────────────────

    /// Send ESTABLISH_INTRO as a hidden service operator on an already
    /// built circuit. The circuit's terminal hop becomes an intro
    /// point for this HS. Returns the auth_key_pub the HS will publish
    /// in its descriptor for clients to reference.
    pub async fn establish_intro_on(
        &self,
        cid: crate::circuit::CircuitId,
        auth_key_pub: [u8; 32],
    ) -> Result<()> {
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        use crate::rendezvous::EstablishIntro;

        let msg = EstablishIntro {
            auth_key_pub,
            // Empty sig for now: in production the HS signs the circuit
            // digest with its long-term HS identity key.
            sig: [0u8; 32],
        };
        let relay = RelayCell::new(
            RelayCommand::EstablishIntro, 0, msg.encode())?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("establish_intro: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("establish_intro: circuit has no hops".into()));
        }

        let guard_peer = mgr.origins[&cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        // Remember this circuit is now an intro for us
        mgr.register_intro_circuit(cid, auth_key_pub);
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Client: send ESTABLISH_RENDEZVOUS on an existing built circuit
    /// to an RP. The cookie is generated fresh; a StaticSecret is
    /// created for the e2e handshake. `hs_static_pub` comes from the
    /// HS descriptor and is stored so `handle_rendezvous2` can verify
    /// AUTH when the HS's reply arrives.
    pub async fn establish_rendezvous_on(
        &self,
        cid: crate::circuit::CircuitId,
        hs_static_pub: [u8; 32],
    ) -> Result<[u8; 20]> {
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        use crate::rendezvous::{EstablishRendezvous, fresh_cookie};
        use x25519_dalek::StaticSecret;

        let cookie = fresh_cookie();

        let client_sk = StaticSecret::random_from_rng(OsRng);
        let client_x  = *PublicKey::from(&client_sk).as_bytes();

        let relay = RelayCell::new(
            RelayCommand::EstablishRendezvous, 0,
            EstablishRendezvous { cookie }.encode())?;

        let mut mgr = self.circuits.write().await;
        let hops_len   = mgr.origins.get(&cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("establish_rendezvous: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("establish_rendezvous: no hops".into()));
        }
        let guard_peer = mgr.origins[&cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        mgr.register_pending_rendezvous(cookie, cid, client_sk, client_x, hs_static_pub);
        drop(mgr);

        let cell = Cell { circ_id: cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await?;
        Ok(cookie)
    }

    /// Client: send INTRODUCE1 to the HS via an intro circuit we've
    /// built. `intro_cid` is the circuit whose terminal hop is the
    /// intro point. The plaintext contains our RP selection.
    pub async fn send_introduce1(
        &self,
        intro_cid: crate::circuit::CircuitId,
        hs_static_pub: &[u8; 32],
        auth_key_pub:  &[u8; 32],
        rp_node_id:    [u8; 32],
        rp_host:       String,
        rp_port:       u16,
        cookie:        [u8; 20],
    ) -> Result<()> {
        use crate::circuit::{RelayCell, RelayCommand, Cell, CellCommand};
        use crate::rendezvous::{Introduce, IntroducePlaintext};

        let plaintext = IntroducePlaintext { rp_node_id, rp_host, rp_port, cookie };

        // CRITICAL: use the same client ephemeral stashed in
        // pending_rendezvous — the one we'll later use to verify
        // AUTH in handle_rendezvous2. Generating a fresh ephemeral
        // here would cause the HS's AUTH (computed over the X
        // embedded in INTRODUCE) to not match what the client
        // recomputes (from its stashed X).
        let client_sk = {
            let mgr = self.circuits.read().await;
            let entry = mgr.pending_rendezvous.get(&cookie)
                .ok_or_else(|| Error::Handshake(
                    "send_introduce1: no pending_rendezvous for this cookie \
                     — call establish_rendezvous_on first".into()))?;
            entry.1.clone()
        };

        let (intro, _client_sk) = Introduce::build_for_hs_with_ephemeral(
            hs_static_pub, auth_key_pub, &plaintext, client_sk);

        let relay = RelayCell::new(
            RelayCommand::Introduce1, 0, intro.encode())?;

        let mut mgr = self.circuits.write().await;
        let hops_len = mgr.origins.get(&intro_cid)
            .map(|c| c.hops.len())
            .ok_or_else(|| Error::Handshake("introduce1: unknown circuit".into()))?;
        if hops_len == 0 {
            return Err(Error::Handshake("introduce1: no hops".into()));
        }
        let guard_peer = mgr.origins[&intro_cid].peer;
        let payload    = {
            let oc = mgr.origins.get_mut(&intro_cid).unwrap();
            oc.encrypt_outbound(hops_len - 1, relay)?
        };
        drop(mgr);

        let cell = Cell { circ_id: intro_cid, command: CellCommand::Relay, payload };
        self.send_circuit_cell(&guard_peer, &cell.to_bytes()).await
    }

    /// Client: drive a full rendezvous to a hidden service and return
    /// the RP origin-circuit id with end-to-end keys installed, ready
    /// for the stream layer to carry application traffic.
    ///
    /// This is the orchestration that ties the three low-level
    /// primitives together:
    ///
    ///   1. **Resolve** the descriptor to an intro point
    ///      (`resolve_hs_descriptor`) — handles both public and
    ///      client-authorized services. Returns `NotAuthorized` if the
    ///      service is client-auth and none of `client_secrets` match.
    ///   2. **Build the RP circuit** — a normal 3-hop circuit selected
    ///      from `consensus`. Its terminal hop is the rendezvous point.
    ///   3. **Build the intro circuit** — a second, node-disjoint 3-hop
    ///      circuit whose terminal hop we extend to the intro point.
    ///   4. `establish_rendezvous_on(rp_cid, hs_static_pub)` — send
    ///      ESTABLISH_RENDEZVOUS on the RP circuit, stashing the client
    ///      ephemeral + HS static key so the reply can be verified.
    ///      Returns the cookie.
    ///   5. **Register a completion waiter** for `rp_cid` *before*
    ///      introducing, closing the race where RENDEZVOUS2 could beat
    ///      the waiter into the map.
    ///   6. `send_introduce1(...)` on the intro circuit — tells the HS
    ///      our chosen RP + cookie. The HS then builds its own circuit
    ///      to the RP and sends RENDEZVOUS1, which the RP splices into
    ///      RENDEZVOUS2 back to us.
    ///   7. **Await completion** — the handle loop processes the
    ///      inbound RENDEZVOUS2, `handle_rendezvous2` installs the e2e
    ///      keys and fires the waiter. We time out if the HS never
    ///      answers (offline, unreachable RP, or authorization
    ///      mismatch on its side).
    ///
    /// On success the caller can `stream_open`/`stream_write` on the
    /// returned circuit; those cells travel end-to-end under the
    /// installed `e2e_keys`. On any failure the RP circuit is torn
    /// down before returning.
    ///
    /// `rp_static_pub` for the RP hop is taken from the RP circuit's
    /// terminal LinkSpec — the same relay the HS will dial — so the HS
    /// can complete its half of the ntor with the RP.
    pub async fn hs_fetch(
        self: Arc<Self>,
        descriptor: &crate::wire::HsDescriptor,
        client_secrets: &[x25519_dalek::StaticSecret],
        consensus: &crate::directory::ConsensusDocument,
        path: &str,
    ) -> Result<HsFetchResponse> {
        use crate::path_select::{select_path, SelectedPath};

        // ── 1. Resolve descriptor → intro point ───────────────────────
        let resolved = Self::resolve_hs_descriptor(descriptor, client_secrets)?
            .ok_or_else(|| Error::Handshake(
                "hs_fetch: not authorized for this client-auth service".into()))?;

        // HS static X25519 key: what the client uses to (a) encrypt
        // INTRODUCE1 to the HS and (b) verify the HS's AUTH tag on
        // RENDEZVOUS2 (see `client_finalize` via `complete_rendezvous`).
        //
        // NOTE on the key model: `handle_introduce2` on the HS side
        // opens INTRODUCE2 and runs `hs_finalize` using the *node's
        // connection static key* (`self.keypair`), NOT the descriptor's
        // Ed25519 `hs_id` and NOT the per-HS `intro_pub`. So the value
        // the client must supply here is the X25519 static_pub of the
        // relay that terminates the intro circuit — i.e. the node
        // hosting the intro point. In the current single-tier design
        // that relay is the HS node itself. We therefore take it from
        // the resolved intro point (`intro_pub`), which for a
        // public/self-hosted service equals that node's static key.
        //
        // If the descriptor model is ever split so `intro_pub` is a
        // dedicated per-intro key distinct from the HS node's static
        // key, this is the single line that must change (the descriptor
        // would need to publish the HS node static key separately, and
        // `handle_introduce2` keyed to match).
        let hs_static_pub: [u8; 32] = resolved.intro_pub;

        let self_id = hex::encode(self.node_id());
        let mut rng = OsRng;
        let hs_hex = hex::encode(resolved.intro_node_id);

        // ── 2. Build the RP circuit ───────────────────────────────────
        // The terminal hop becomes the rendezvous point; remember its
        // identity so we can name it in INTRODUCE1.
        //
        // The RP must not be the service's own node: the HS would then be
        // asked to rendezvous with itself and the handshake never
        // completes (it surfaces as "timed out waiting for RENDEZVOUS2").
        // Excluding it outright can't work on a network this small — with
        // three relays, dropping one leaves too few for a three-hop path —
        // so redraw until the terminal lands elsewhere. Selection is
        // in-memory, so rerolling here is far cheaper than discovering the
        // collision after a 15s wire timeout.
        // A rendezvous circuit is generic — the rendezvous point is our own
        // choice — so it may already be built and waiting. That's the
        // difference between a fetch that starts now and one that starts
        // after three handshakes across the internet.
        let (rp_cid, rp_hops) = self.rp_circuit(consensus, &hs_hex).await
            .map_err(|e| Error::Handshake(format!("hs_fetch: build RP circuit: {e}")))?;
        let rp_terminal = rp_hops.last().cloned()
            .ok_or_else(|| Error::Handshake("hs_fetch: empty RP path".into()))?;

        // From here on any early return must tear down the RP circuit.
        let teardown = |node: Arc<Self>, cid| async move {
            let _ = node.destroy_circuit(cid).await;
        };

        // ── 3. Build the intro circuit ────────────────────────────────
        // Prefer node-disjointness: a relay serving as both the RP and our
        // intro-circuit guard could correlate both ends of the rendezvous.
        // That needs two full disjoint paths (6 distinct relays for 3 hops
        // each). On a small network there aren't enough, so rather than
        // failing outright we retry allowing overlap — the rendezvous still
        // works, but a relay appearing in both circuits weakens the
        // unlinkability this design aims for. The real fix is more relays.
        // The intro circuit's terminal hop is replaced below with the HS
        // node itself, so the hops leading up to it must not *be* that node
        // — a relay asked to extend to itself just times out ("EXTEND to
        // hop 2 timed out"). `ok` enforces that, and is also why we redraw
        // rather than exclude: on a three-relay network the HS is in every
        // possible path, and only the draws that place it last are usable.
        let mut excluded = vec![self_id.clone()];
        excluded.extend(rp_hops.iter().map(|h| hex::encode(h.node_id)));
        let ok = |p: &SelectedPath| {
            let n = p.hops.len();
            n > 0 && p.hops[..n - 1].iter().all(|h| h.node_id_hex != hs_hex)
        };
        let disjoint = (0..24)
            .filter_map(|_| select_path(&mut rng, consensus, &excluded, None).ok())
            .find(|p| ok(p));
        let intro_path = match disjoint {
            Some(p) => p,
            None => {
                warn!("hs_fetch: not enough relays for a node-disjoint intro \
                       circuit ({} in consensus); falling back to an \
                       overlapping path — RP and intro circuits may share a \
                       relay, which weakens correlation resistance",
                      consensus.peers.len());
                let overlapping = (0..24)
                    .filter_map(|_| select_path(&mut rng, consensus, &[self_id.clone()], None).ok())
                    .find(|p| ok(p));
                match overlapping {
                    Some(p) => p,
                    None => {
                        teardown(Arc::clone(&self), rp_cid).await;
                        return Err(Error::Handshake(
                            "hs_fetch: intro path selection: no path avoids \
                             routing through the service's own relay — the \
                             network needs more relays".into()));
                    }
                }
            }
        };
        let mut intro_specs = match intro_path.to_link_specs() {
            Ok(s) => s,
            Err(e) => {
                teardown(Arc::clone(&self), rp_cid).await;
                return Err(Error::Handshake(format!("hs_fetch: intro link specs: {e:?}")));
            }
        };
        // The intro circuit must terminate *at the HS's intro point*
        // (the HS node itself, in the single-tier design). Replace the
        // selected terminal hop with a LinkSpec fully describing that
        // node: its real node_id (needed to route the ntor extend), its
        // static key (== intro_pub, what we encrypt INTRODUCE1 to and
        // what the extend's ntor validates), and its host/port. Without
        // a node_id we can't build the hop, so require it.
        if resolved.intro_node_id == [0u8; 32] {
            teardown(Arc::clone(&self), rp_cid).await;
            return Err(Error::Handshake(
                "hs_fetch: descriptor lacks intro_node_id; cannot target HS".into()));
        }
        let intro_host = resolved.intro_host.clone()
            .unwrap_or_else(|| intro_specs.last().map(|l| l.host.clone()).unwrap_or_default());
        let intro_port = resolved.intro_port
            .unwrap_or_else(|| intro_specs.last().map(|l| l.port).unwrap_or(0));
        if let Some(last) = intro_specs.last_mut() {
            last.node_id    = resolved.intro_node_id;
            last.static_pub = resolved.intro_pub;
            last.host       = intro_host;
            last.port       = intro_port;
        }
        let intro_cid = match Arc::clone(&self).build_hs_circuit(intro_specs).await {
            Ok(c) => c,
            Err(e) => {
                teardown(Arc::clone(&self), rp_cid).await;
                return Err(Error::Handshake(format!("hs_fetch: build intro circuit: {e}")));
            }
        };

        // ── 4. ESTABLISH_RENDEZVOUS on the RP circuit ─────────────────
        let cookie = match self.establish_rendezvous_on(rp_cid, hs_static_pub).await {
            Ok(c) => c,
            Err(e) => {
                teardown(Arc::clone(&self), intro_cid).await;
                teardown(Arc::clone(&self), rp_cid).await;
                return Err(Error::Handshake(format!("hs_fetch: establish_rendezvous: {e}")));
            }
        };

        // ── 5. Register the completion waiter BEFORE introducing ──────
        // Must precede send_introduce1: once the HS has the cookie it
        // can drive RENDEZVOUS1 → RENDEZVOUS2 arbitrarily fast, and the
        // handle loop's handle_rendezvous2 must find a waiter to fire.
        let ready = self.await_rendezvous(rp_cid).await;

        // ── 6. INTRODUCE1 on the intro circuit ────────────────────────
        // auth_key_pub is the per-intro key the HS published; for a
        // public descriptor it's the same as the resolved intro_pub.
        let auth_key_pub = resolved.intro_pub;
        if let Err(e) = self.send_introduce1(
            intro_cid,
            &hs_static_pub,
            &auth_key_pub,
            rp_terminal.node_id,
            rp_terminal.host.clone(),
            rp_terminal.port,
            cookie,
        ).await {
            // Drop the waiter we just registered so it can't leak.
            self.rendezvous_waiters.write().await.remove(&rp_cid);
            teardown(Arc::clone(&self), intro_cid).await;
            teardown(Arc::clone(&self), rp_cid).await;
            return Err(Error::Handshake(format!("hs_fetch: send_introduce1: {e}")));
        }

        // The intro circuit's job is done the moment INTRODUCE1 is
        // acknowledged; the actual data path is the RP circuit. Tear
        // the intro circuit down to avoid leaving it lingering as a
        // correlation handle. (Do this after the send so the ACK can
        // still be matched; a best-effort destroy is fine.)
        teardown(Arc::clone(&self), intro_cid).await;

        // ── 7. Await RENDEZVOUS2 completion (with timeout) ────────────
        const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);
        match time::timeout(RENDEZVOUS_TIMEOUT, ready).await {
            Ok(Ok(Ok(()))) => {
                // e2e keys installed on rp_cid by handle_rendezvous2.
                info!("hs_fetch: rendezvous complete, circuit {:?} ready", rp_cid);
                // ── 8. Send request + collect the e2e response ────────
                Arc::clone(&self).hs_fetch_request(rp_cid, path).await
                    .map_err(|e| {
                        // Best-effort teardown on request failure.
                        let n = Arc::clone(&self);
                        tokio::spawn(async move { let _ = n.destroy_circuit(rp_cid).await; });
                        e
                    })
            }
            Ok(Ok(Err(e))) => {
                // handle_rendezvous2 already tore down rp_cid on the
                // auth-failure path; don't double-destroy.
                Err(e)
            }
            Ok(Err(_canceled)) => {
                // Sender dropped without sending — should not happen,
                // but treat as failure and clean up.
                teardown(Arc::clone(&self), rp_cid).await;
                Err(Error::Handshake("hs_fetch: rendezvous waiter canceled".into()))
            }
            Err(_elapsed) => {
                // Timed out: HS never answered. Remove the waiter and
                // tear the RP circuit down.
                self.rendezvous_waiters.write().await.remove(&rp_cid);
                teardown(Arc::clone(&self), rp_cid).await;
                Err(Error::Handshake(
                    "hs_fetch: timed out waiting for RENDEZVOUS2".into()))
            }
        }
    }

    /// Client side: over an already-established rendezvous circuit
    /// (e2e keys installed), send a request line and collect the HS's
    /// response. Registers a collector for `rp_cid`, sends
    /// `"GET <path>"` as an e2e DATA cell, then reads response chunks
    /// until the HS sends END (collector channel closes) or a timeout
    /// elapses. Parses the minimal `status\ncontent-type\n\n<body>`
    /// framing produced by `serve_hs_request`.
    async fn hs_fetch_request(
        self: Arc<Self>,
        rp_cid: crate::circuit::CircuitId,
        path: &str,
    ) -> Result<HsFetchResponse> {
        use crate::circuit::RelayCommand;

        // Register the response collector before sending, so no chunk
        // can race ahead of the collector being in place.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        self.hs_response_collectors.write().await.insert(rp_cid, tx);

        // Send the request line over the e2e channel.
        let req = format!("GET {path}");
        if let Err(e) = self.send_origin_relay(
            rp_cid, RelayCommand::Data, req.into_bytes()).await
        {
            self.hs_response_collectors.write().await.remove(&rp_cid);
            return Err(Error::Handshake(format!("hs_fetch_request: send: {e}")));
        }

        // Collect chunks until the channel closes (END) or we time out.
        const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
        let mut buf = Vec::new();
        let collect = async {
            while let Some(chunk) = rx.recv().await {
                buf.extend_from_slice(&chunk);
            }
            buf
        };
        let body_bytes = match time::timeout(RESPONSE_TIMEOUT, collect).await {
            Ok(b) => b,
            Err(_elapsed) => {
                self.hs_response_collectors.write().await.remove(&rp_cid);
                return Err(Error::Handshake(
                    "hs_fetch_request: timed out reading response".into()));
            }
        };
        // Collector is removed by the END handler; ensure it's gone.
        self.hs_response_collectors.write().await.remove(&rp_cid);

        // Parse "status\ncontent-type\n\n<body>".
        parse_hs_response(&body_bytes)
            .ok_or_else(|| Error::Handshake(
                "hs_fetch_request: malformed HS response framing".into()))
    }

    /// Broadcast a hidden-service descriptor to all connected peers and store in DHT.
    /// Sign and publish an HS descriptor. The descriptor is signed
    /// under the given HS identity's epoch-blinded subkey before
    /// being cached locally and broadcast to peers via HsRegister.
    /// Peers verify the signature before caching (see HsRegister
    /// dispatch in `handle`), so an attacker can't forge descriptors
    /// for an hs_id they don't control.
    pub async fn broadcast_hs(
        &self,
        descriptor: crate::wire::HsDescriptor,
        identity:   &crate::hs_identity::HsIdentity,
    ) {
        // Stash the endpoint that was published so the periodic
        // republishing loop can reconstruct it next epoch without
        // the operator having to re-invoke hs_register.
        if let Some(hs) = self.hs_mgr.get(&descriptor.hs_id).await {
            let host = descriptor.intro_host.clone().unwrap_or_default();
            let port = descriptor.intro_port.unwrap_or(0);
            *hs.published_endpoint.write().await = Some((host, port));
        }

        let epoch = crate::hs_identity::current_epoch();
        let signed = crate::hs_identity::sign_descriptor(identity, descriptor, epoch);
        self.dht.put_hs(&signed);

        // Publish to the relays the ring makes responsible, not to everyone.
        // Handing every relay every descriptor is O(network) per republish,
        // and it tells each of them the complete list of services that exist
        // — a census, published by the thing whose job is hiding who talks to
        // whom.
        let hs_id = signed.hs_id.clone();
        let responsible = self.responsible_hsdirs_for(&hs_id).await;
        let peers = self.peers.read().await;
        let targets: Vec<_> = match &responsible {
            Some(dirs) if !dirs.is_empty() => {
                let want: Vec<_> = peers.iter()
                    .filter(|(id, _)| dirs.contains(&hex::encode(id)))
                    .map(|(_, p)| Arc::clone(p))
                    .collect();
                // A descriptor nobody holds is a site nobody can reach, so if
                // we aren't linked to any responsible relay, publish widely
                // rather than publish into the void.
                if want.is_empty() {
                    debug!("hs publish {}: not linked to a responsible HSDir, \
                            publishing to all peers", &hs_id[..12.min(hs_id.len())]);
                    peers.values().map(Arc::clone).collect()
                } else {
                    debug!("hs publish {}: to {} responsible HSDir(s)",
                           &hs_id[..12.min(hs_id.len())], want.len());
                    want
                }
            }
            _ => peers.values().map(Arc::clone).collect(),
        };
        for p in targets {
            let _ = p.send_msg(&Message::HsRegister(crate::wire::HsRegister {
                descriptor: signed.clone(),
            })).await;
        }
    }

    /// Periodically re-sign and re-publish descriptors for every HS
    /// this node hosts. Descriptors are signed for the current epoch
    /// and clients accept signatures within ±1 epoch of their local
    /// clock, so a republish every ~12 hours keeps every HS
    /// reachable indefinitely. Without this loop, a hidden service
    /// stops being reachable ~48 hours after the daemon starts as
    /// the originally-signed descriptor falls outside the acceptance
    /// window.
    ///
    /// Runs forever. Spawned from `run()`. Never panics: all errors
    /// are logged and ignored.
    async fn hs_republish_loop(self: Arc<Self>) {
        // Two clocks constrain this, and the shorter one wins:
        //
        //  * descriptors are *signed* per epoch, so they must be reissued
        //    within half an epoch to stay inside clients' ±1 window;
        //  * descriptors are *stored* in the DHT under DHT_VALUE_TTL, which
        //    is far shorter — an hour against a day.
        //
        // Only honouring the epoch meant every hidden service dropped out of
        // the DHT one hour after it registered and stayed unreachable for the
        // remaining eleven, which looked exactly like "the site randomly
        // stops existing". Refresh at a third of the TTL so a couple of
        // missed passes still can't let an entry lapse.
        let interval = std::cmp::min(
            Duration::from_secs(crate::hs_identity::EPOCH_SECS / 2),
            crate::dht::DHT_VALUE_TTL / 3,
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.shutdown.notified() => break,
            }
            if self.is_shutting_down() { break; }
            self.republish_all_hs_once().await;
        }
        debug!("hs_republish_loop: shutting down");
    }

    /// Iterate every registered HS and re-sign + re-broadcast its
    /// descriptor (using the last-published endpoint). Public so
    /// tests can invoke a single republish pass directly instead of
    /// waiting 12 hours for the loop to fire.
    ///
    /// Skips services that have never been published (no endpoint
    /// stashed), since without an intro endpoint we'd publish a
    /// useless descriptor pointing nowhere.
    pub async fn republish_all_hs_once(&self) {
        let hs_ids = self.hs_mgr.list().await;
        for hs_id in hs_ids {
            let Some(hs) = self.hs_mgr.get(&hs_id).await else { continue };
            let endpoint = hs.published_endpoint.read().await.clone();
            let Some((host, port)) = endpoint else {
                debug!("hs republish: skip {} (never published)", hs_id);
                continue;
            };
            let host_opt = if host.is_empty() { None } else { Some(host.as_str()) };
            let port_opt = if port == 0       { None } else { Some(port)   };

            // Honor the per-service authorized client list. If
            // populated, build a client-auth descriptor; if empty,
            // build a public one. Mirrors the daemon's hs_register
            // logic so ongoing republishes don't accidentally
            // downgrade an authed service to public.
            let clients_hex = self.store.list_authorized_clients(&hs_id).await;
            let descriptor = if clients_hex.is_empty() {
                hs.descriptor(host_opt, port_opt)
            } else {
                let mut client_pubs: Vec<[u8; 32]> = Vec::new();
                let mut bad = false;
                for h in &clients_hex {
                    match hex::decode(h).ok().and_then(|v| v.try_into().ok()) {
                        Some(b) => client_pubs.push(b),
                        None => {
                            warn!("hs republish: malformed client pubkey {} for {}, \
                                   skipping republish for safety", h, hs_id);
                            bad = true;
                            break;
                        }
                    }
                }
                if bad { continue; }
                match hs.descriptor_with_client_auth(host_opt, port_opt, &client_pubs) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("hs republish: descriptor_with_client_auth({}): {}",
                              hs_id, e);
                        continue;
                    }
                }
            };

            // The intro point is this node, and clients need both halves of
            // that to target it. `descriptor()` doesn't fill them in — only
            // the register path did — so every republish used to overwrite a
            // working descriptor with one that clients reject ("descriptor
            // lacks intro_node_id"), taking the site offline until someone
            // re-registered it by hand.
            let mut descriptor = descriptor;
            descriptor.intro_pub     = hex::encode(self.static_pub());
            descriptor.intro_node_id = hex::encode(self.node_id());

            debug!("hs republish: re-signing descriptor for {} (epoch {}, clients={})",
                   hs_id, crate::hs_identity::current_epoch(), clients_hex.len());
            self.broadcast_hs(descriptor, &hs.identity).await;
        }
    }

    pub async fn bootstrap(self: Arc<Self>, peers: Vec<(String, u16)>) {
        for (host, port) in peers {
            let node = Arc::clone(&self);
            let h    = host.clone();
            tokio::spawn(async move {
                info!("Bootstrap {}:{}", h, port);
                if let Err(e) = Arc::clone(&node).connect(&h, port).await {
                    warn!("Bootstrap {}:{}: {}", h, port, e);
                } else {
                    let my_id = node.node_id_hex();
                    let peers = node.peers.read().await;
                    for p in peers.values() {
                        let _ = p.send_msg(&Message::DhtFind(DhtFind {
                            req_id: hex::encode(rand_bytes(8)),
                            target: my_id.clone(),
                        })).await;
                    }
                }
            });
        }
    }

    // ── Background loops ──────────────────────────────────────────────

    /// Evict peers silent (no cell, not even padding) for more than
    /// `STALE_PEER_SECS` as of `now`. Returns the evicted node ids.
    /// Removing them from the peer table + routing is what stops a
    /// vanished node from being snapshotted into the consensus as a
    /// ghost. Called on a timer; also directly unit-tested.
    pub async fn reap_dead_peers(&self, now: u64) -> Vec<[u8; 32]> {
        let dead: Vec<[u8; 32]> = {
            let peers = self.peers.read().await;
            peers.iter()
                .filter(|(_, p)| p.idle_secs(now) > STALE_PEER_SECS)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in &dead {
            self.peers.write().await.remove(id);
            self.routing.remove_peer(id);
            self.guard_mgr.mark_failure(id);
            info!("Peer {}… reaped (silent >{}s)",
                  &hex::encode(id)[..12], STALE_PEER_SECS);
        }
        dead
    }

    async fn guard_refresh_loop(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = time::sleep(Duration::from_secs(60)) => {}
                _ = self.shutdown.notified() => break,
            }
            if self.is_shutting_down() { break; }

            // Consensus-driven guard maintenance: pin a persistent guard
            // set drawn from the *consensus* (not just peers we already
            // know) and actively dial guards we aren't linked to. This is
            // what turns a bootstrap star into a consensus-driven
            // topology — every node learns all relays from the consensus
            // and maintains links to its sticky guards, instead of only
            // knowing whoever it happened to bootstrap against.
            self.maintain_guards_from_consensus().await;

            // Guards aren't enough. `build_circuit` needs a live link to
            // *every* hop, and lookups broadcast to whatever is in `peers`,
            // so a client whose middle/exit links have dropped can neither
            // build a path nor find a hidden service — it just reports
            // "not connected" and "not found" while the consensus insists
            // those relays are running. Redial anything in the consensus
            // we've lost. On a small network that's a handful of links; a
            // large one should narrow this to relays we actually intend to
            // use.
            self.maintain_links_from_consensus().await;

            // Keep the exemption list current: a relay's normal work — many
            // circuits, constantly — is indistinguishable from the flood we're
            // defending against, so rate-limiting our own peers would break
            // the network to protect it. Refreshed from the consensus so a
            // relay that joins stops being limited without a restart.
            {
                let exempt: Vec<std::net::IpAddr> = match self.cached_consensus.read().await.as_ref() {
                    Some(doc) => doc.peers.iter()
                        .filter_map(|p| p.host.parse::<std::net::IpAddr>().ok())
                        .collect(),
                    None => Vec::new(),
                };
                let mut g = self.dos.lock().unwrap();
                g.set_exempt(exempt);
                g.cleanup();
                if g.is_enabled() {
                    for (ip, n) in g.offenders().into_iter().take(3) {
                        warn!("rate limiting {}: {} request(s) refused", ip, n);
                    }
                }
            }

            // A guard that fails almost every circuit may be steering us onto
            // paths it controls — the failures look like an unreliable
            // network, and retrying is exactly what the attack wants. Say so
            // rather than acting: dropping guards automatically hands an
            // attacker a lever to make us go shopping for new ones.
            for (g, st) in self.suspicious_guards() {
                warn!("guard {} has completed {}/{} circuits ({:.0}%). That is far \
                       worse than a healthy relay and may mean it is failing \
                       circuits it can't observe, to push you onto ones it can. \
                       Consider replacing it.",
                      &g[..12.min(g.len())], st.successes, st.attempts,
                      st.success_rate() * 100.0);
            }

            // Keep the in-memory guard set (used by circuit path
            // selection) fresh from whatever we're now linked to.
            let peers  = self.routing.all_peers();
            let guards = onion::select_guards(&peers, 3, &[])
                .into_iter().cloned().collect();
            *self.guards.write().await = guards;
        }
    }

    /// Feed the current consensus into the persistent guard manager and
    /// dial any pinned guard we're not currently connected to. Guards are
    /// sticky (persisted across restarts by `GuardManager`), reachability
    /// is tracked per-guard, and unreachable guards are eventually
    /// dropped and replaced — the Tor guard discipline.
    /// Re-dial consensus relays we've lost a link to.
    ///
    /// Bootstrap only runs at startup, and guard maintenance only redials
    /// guards — so a dropped link to a middle or exit was never restored.
    /// Circuits through it then failed permanently ("hop N not connected")
    /// even though the relay was up and in the consensus, and a client that
    /// lost every link went quiet: nothing to send an HsLookup to, so every
    /// address resolved to "not found".
    async fn maintain_links_from_consensus(self: &Arc<Self>) {
        let me = self.node_id();
        let entries = match self.cached_consensus.read().await.as_ref() {
            Some(doc) => doc.peers.clone(),
            None => return,
        };
        for p in &entries {
            let nid = match hex::decode(&p.node_id_hex).ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                Some(n) => n,
                None => continue,
            };
            if nid == me { continue; }
            if self.peers.read().await.contains_key(&nid) { continue; }
            let node = Arc::clone(self);
            let host = p.host.clone();
            let port = p.port;
            tokio::spawn(async move {
                match node.connect(&host, port).await {
                    Ok(_)  => info!("relinked to {}:{}", host, port),
                    Err(e) => debug!("relink {}:{} failed: {}", host, port, e),
                }
            });
        }
    }

    async fn maintain_guards_from_consensus(self: &Arc<Self>) {        let me = self.node_id();

        // 1. Offer every consensus relay (except us) as a guard
        //    candidate. GuardManager caps the set at MAX_GUARDS and
        //    ignores duplicates, so this pins a stable set.
        let entries = {
            match self.cached_consensus.read().await.as_ref() {
                Some(doc) => doc.peers.clone(),
                None => return, // no consensus yet — nothing to do
            }
        };
        // Build the set of node_ids currently in the consensus, and
        // retire any pinned guard no longer in it (a stale ghost whose
        // identity no longer exists). Doing this first frees slots so the
        // current relays can be pinned.
        let consensus_ids: std::collections::HashSet<[u8; 32]> = entries.iter()
            .filter_map(|p| hex::decode(&p.node_id_hex).ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok()))
            .filter(|id| *id != me)
            .collect();
        let pruned = self.guard_mgr.retain_ids(&consensus_ids);
        if pruned > 0 {
            info!("guard: retired {} stale guard(s) not in the consensus", pruned);
        }

        // Only guards from the sample are ever offered as candidates.
        //
        // Previously every relay in the consensus was a candidate, and
        // whenever a guard slot freed — retirement, a day of unreachability —
        // the next relay in consensus order filled it. That put no bound on
        // how many distinct guards a client would try over its life, and each
        // one it tries learns its address. An adversary didn't need luck,
        // only patience: cause churn, wait for the client to draw again.
        //
        // The sample decides once which guards we are ever willing to use.
        // Churn now rotates us within that set instead of introducing us to
        // the network.
        let me_hex = hex::encode(me);
        let candidates: Vec<String> = entries.iter()
            .filter(|p| p.node_id_hex != me_hex)
            .map(|p| p.node_id_hex.clone())
            .collect();
        let live = candidates.clone();   // entries are already RUNNING-filtered
        let added = {
            let mut smp = self.guard_sample.write().unwrap();
            let mut rng = rand::thread_rng();
            smp.maybe_extend(&mut rng, &candidates, &live, crate::com::now_secs())
        };
        if added > 0 {
            info!("guard sample: added {} guard(s) (sample is the bound on how \
                   many relays ever learn this client's address)", added);
            self.save_guard_sample();
        }

        let primary = self.guard_sample.read().unwrap().primary(&live);
        for p in &entries {
            if !primary.contains(&p.node_id_hex) { continue; }
            let nid = match hex::decode(&p.node_id_hex).ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                Some(n) => n,
                None => continue,
            };
            if nid == me { continue; }
            self.guard_mgr.add_candidate(&nid, &p.host, p.port);
        }

        // 2. Dial guards we're not linked to (respecting retry backoff).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0);
        let connected: std::collections::HashSet<[u8; 32]> =
            self.peers.read().await.keys().copied().collect();

        for g in self.guard_mgr.list() {
            let nid = match g.node_id_bytes() { Ok(n) => n, Err(_) => continue };
            if connected.contains(&nid) {
                self.guard_mgr.mark_success(&nid);   // still linked — refresh liveness
                continue;
            }
            if !g.should_try(now) { continue; }      // backoff not elapsed
            // Bounded dial so an unreachable (e.g. NAT'd) guard can't
            // stall the loop.
            let dial = tokio::time::timeout(
                Duration::from_secs(10),
                Arc::clone(self).connect(&g.host, g.port),
            ).await;
            match dial {
                Ok(Ok(())) => {
                    self.guard_mgr.mark_success(&nid);
                    info!("guard: connected to {} @{}:{}",
                          &g.node_id[..12.min(g.node_id.len())], g.host, g.port);
                }
                Ok(Err(e)) => {
                    self.guard_mgr.mark_failure(&nid);
                    debug!("guard: dial {} failed: {}",
                           &g.node_id[..12.min(g.node_id.len())], e);
                }
                Err(_) => {
                    self.guard_mgr.mark_failure(&nid);
                    debug!("guard: dial {} timed out", &g.node_id[..12.min(g.node_id.len())]);
                }
            }
        }
        self.guard_mgr.save_best_effort();
    }

    /// Verify and apply an incoming CertRotate announcement.
    ///
    /// Checks performed (in order, all must pass):
    /// 1. `old_node_id` matches an existing peer in our table.
    /// 2. `seq` strictly exceeds any previously-seen seq for that id.
    /// 3. `link_sig` matches the HMAC computed from the peer's
    ///    rotation_link_key — proves the announcer holds the session
    ///    key shared with the claimed old identity.
    /// 4. The new cert passes `PhiCert::verify()` (math is sound).
    /// 5. `new_node_id` matches the new cert's node_id.
    ///
    /// On success, updates the peer entry: key (HashMap index) moves
    /// from old_id to new_id, PeerInfo.node_id is updated, and the
    /// routing table is rebalanced. Session keys and the open TCP
    /// connection are preserved — rotation is purely a credential
    /// refresh, not a new handshake.
    async fn handle_cert_rotate(&self, msg: crate::wire::CertRotate, src: &Arc<PeerConn>) {
        // Parse hex IDs
        let old_id_vec = match hex::decode(&msg.old_node_id) {
            Ok(v) if v.len() == 32 => v,
            _ => { debug!("cert rotate: bad old_node_id hex"); return; }
        };
        let new_id_vec = match hex::decode(&msg.new_node_id) {
            Ok(v) if v.len() == 32 => v,
            _ => { debug!("cert rotate: bad new_node_id hex"); return; }
        };
        let mut old_id = [0u8; 32]; old_id.copy_from_slice(&old_id_vec);
        let mut new_id = [0u8; 32]; new_id.copy_from_slice(&new_id_vec);

        // Defensive: the sender must actually be the one rotating.
        // Otherwise peer A could broadcast a rotation for peer B.
        if src.info.node_id != old_id {
            debug!("cert rotate: src {} claims to rotate {}",
                   hex::encode(&src.info.node_id[..6]),
                   hex::encode(&old_id[..6]));
            return;
        }

        // (1) Peer must exist in our table under old_id.
        let peer_arc = match self.peers.read().await.get(&old_id) {
            Some(p) => Arc::clone(p),
            None    => { debug!("cert rotate: unknown old peer"); return; }
        };

        // (2) Replay / stale check.
        {
            let mut seen = self.seen_rotation_seqs.write().await;
            let prev = seen.get(&old_id).copied().unwrap_or(0);
            if msg.seq <= prev {
                debug!("cert rotate: stale seq {} ≤ {} for {}",
                       msg.seq, prev, hex::encode(&old_id[..6]));
                return;
            }
            // Speculatively mark seen so a concurrent replay of the same
            // announcement is rejected even before (3) and (4) run.
            seen.insert(old_id, msg.seq);
        }

        // (3)-(5) Pure-function verification chain: HMAC, cert math,
        //         node_id binding.
        let link_key = peer_arc.session.rotation_link_key();
        if let Err(e) = verify_rotation(&link_key, &msg) {
            debug!("cert rotate: verification failed: {}", e);
            return;
        }
        // We need the WireCert for the peer entry update below.
        let wire_cert: crate::cert::WireCert = match serde_json::from_str(&msg.new_cert_json) {
            Ok(w) => w,
            Err(e) => { debug!("cert rotate: json re-parse: {}", e); return; }
        };

        // All checks passed — re-key the peer entry.
        {
            let mut peers = self.peers.write().await;
            let peer = match peers.remove(&old_id) {
                Some(p) => p,
                None    => {
                    debug!("cert rotate: peer vanished during rotation");
                    return;
                }
            };
            // Update the shared PeerInfo's node_id. peer.info is a value;
            // the stored Arc<PeerConn> already captures it. We can't
            // mutate through Arc safely without interior mutability, so
            // we rebuild the PeerConn Arc with the new info. Keep the
            // original session (it's wrapped in Arc already).
            let new_info = crate::dht::PeerInfo {
                node_id:    new_id,
                host:       peer.info.host.clone(),
                port:       peer.info.port,
                cert:       wire_cert.clone(),
                static_pub: peer.info.static_pub.clone(),
            };
            let updated = Arc::new(PeerConn {
                info:    new_info.clone(),
                sender:  peer.sender.clone(),
                session: Arc::clone(&peer.session),
                last_seen: AtomicU64::new(crate::com::now_secs()),
                remote_ip: peer.remote_ip,
                // Same link, same pending cells — a rename mustn't drop
                // traffic already queued for it.
                queues: Arc::clone(&peer.queues),
            });
            peers.insert(new_id, updated);
            drop(peers);

            // Routing table: drop old, add new.
            self.routing.remove_peer(&old_id);
            self.routing.add_peer(new_info);
        }

        // Also migrate the guard manager entry if present.
        if self.guard_mgr.is_guard(&old_id) {
            // Re-add under new id; list() retains old until prune.
            let entry_host = src.info.host.clone();
            let entry_port = src.info.port;
            self.guard_mgr.add_candidate(&new_id, &entry_host, entry_port);
            self.guard_mgr.mark_success(&new_id);
            self.guard_mgr.save_best_effort();
        }

        info!("Peer rotated: {} → {}",
              hex::encode(&old_id[..6]),
              hex::encode(&new_id[..6]));

        // Suppress unused lint on vecs we already copied.
        let _ = (old_id_vec, new_id_vec);
    }

    async fn rotation_loop(self: Arc<Self>) {
        loop {
            time::sleep(ROTATE_INTERVAL).await;
            info!("Rotating cert…");
            let old_cert = self.cert.read().unwrap().clone();
            let new_cert = match old_cert.rotate() {
                Ok(c)  => c,
                Err(e) => { warn!("Cert rotation: {}", e); continue; }
            };

            let old_id = old_cert.node_id();
            let new_id = new_cert.node_id();
            let new_wire = new_cert.to_wire();
            let new_json = match serde_json::to_string(&new_wire) {
                Ok(s) => s,
                Err(e) => { warn!("rotate: serialize: {}", e); continue; }
            };

            let seq = self.rotation_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let ts  = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);

            // Install the new cert locally first so self.node_id() changes.
            *self.cert.write().unwrap() = new_cert;

            // Broadcast to each connected peer, signed per-session.
            let peers = self.peers.read().await;
            for (pid, peer) in peers.iter() {
                let link_key = peer.session.rotation_link_key();
                let sig      = compute_rotation_sig(
                    &link_key, &old_id, &new_id, &new_json, seq, ts);
                let msg = crate::wire::CertRotate {
                    old_node_id:   hex::encode(old_id),
                    new_node_id:   hex::encode(new_id),
                    new_cert_json: new_json.clone(),
                    seq,
                    ts,
                    link_sig:      hex::encode(sig),
                };
                if let Err(e) = peer.send_msg(&Message::CertRotate(msg)).await {
                    debug!("rotate: peer {}: {}", hex::encode(&pid[..6]), e);
                }
            }
        }
    }
}

/// Compute the HMAC-SHA256 tag binding a CertRotate announcement to
/// the (old, new) identity transition. Both sides of a peer session
/// derive the same `link_key` via `Session::rotation_link_key`, so
/// the receiver can recompute this tag and compare byte-for-byte.
/// Returns exactly 32 bytes; no truncation.
fn compute_rotation_sig(
    link_key: &[u8; 32],
    old_node_id: &[u8; 32],
    new_node_id: &[u8; 32],
    new_cert_json: &str,
    seq: u64,
    ts: u64,
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(link_key)
        .expect("hmac key");
    mac.update(b"phinet-cert-rotate-v1:");
    mac.update(old_node_id);
    mac.update(new_node_id);
    mac.update(new_cert_json.as_bytes());
    mac.update(&seq.to_be_bytes());
    mac.update(&ts.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Pure-function rotation verification. Returns the parsed new cert
/// on success or an error describing which check failed. Used by
/// `handle_cert_rotate` and directly by unit tests.
///
/// Checks performed (all must pass):
/// 1. HMAC `link_sig` matches `compute_rotation_sig` under `link_key`.
/// 2. New cert JSON parses and `PhiCert::verify()` returns true.
/// 3. Derived node_id matches claimed `new_node_id`.
pub(crate) fn verify_rotation(
    link_key: &[u8; 32],
    msg: &crate::wire::CertRotate,
) -> Result<crate::cert::PhiCert> {
    // Parse IDs
    let old_id_vec = hex::decode(&msg.old_node_id)
        .map_err(|_| Error::Crypto("cert rotate: bad old_node_id hex".into()))?;
    if old_id_vec.len() != 32 {
        return Err(Error::Crypto("cert rotate: old_node_id not 32 bytes".into()));
    }
    let mut old_id = [0u8; 32]; old_id.copy_from_slice(&old_id_vec);

    let new_id_vec = hex::decode(&msg.new_node_id)
        .map_err(|_| Error::Crypto("cert rotate: bad new_node_id hex".into()))?;
    if new_id_vec.len() != 32 {
        return Err(Error::Crypto("cert rotate: new_node_id not 32 bytes".into()));
    }
    let mut new_id = [0u8; 32]; new_id.copy_from_slice(&new_id_vec);

    // HMAC
    let sig_vec = hex::decode(&msg.link_sig)
        .map_err(|_| Error::Crypto("cert rotate: bad sig hex".into()))?;
    if sig_vec.len() != 32 {
        return Err(Error::Crypto("cert rotate: sig not 32 bytes".into()));
    }
    let mut sig = [0u8; 32]; sig.copy_from_slice(&sig_vec);

    let expect = compute_rotation_sig(
        link_key, &old_id, &new_id, &msg.new_cert_json, msg.seq, msg.ts);
    if !ct_eq_32(&sig, &expect) {
        return Err(Error::AuthFailed);
    }

    // Cert JSON + math
    let wire_cert: crate::cert::WireCert = serde_json::from_str(&msg.new_cert_json)
        .map_err(|e| Error::Crypto(format!("cert rotate: json: {e}")))?;
    let new_cert = crate::cert::PhiCert::from_wire(&wire_cert)?;
    if !new_cert.verify() {
        return Err(Error::Crypto("cert rotate: math failed".into()));
    }

    // Binding: new_id must be the derived node_id of the new cert
    let derived = new_cert.node_id();
    if derived != new_id {
        return Err(Error::Crypto("cert rotate: node_id binding mismatch".into()));
    }

    Ok(new_cert)
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    OsRng.fill_bytes(&mut b);
    u32::from_le_bytes(b)
}

use crate::timing::ct_eq_32;

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::cert::{PhiCert, CertBits};
    use crate::wire::CertRotate;

    /// Build a small valid cert for testing. Uses smallest available
    /// bit size to keep test runtime reasonable.
    fn small_cert() -> PhiCert {
        PhiCert::generate(CertBits::B256).expect("gen cert")
    }

    fn make_rotation(
        old_cert: &PhiCert,
        new_cert: &PhiCert,
        link_key: &[u8; 32],
        seq: u64,
        ts: u64,
    ) -> CertRotate {
        let old_id = old_cert.node_id();
        let new_id = new_cert.node_id();
        let wire   = new_cert.to_wire();
        let json   = serde_json::to_string(&wire).unwrap();
        let sig    = compute_rotation_sig(link_key, &old_id, &new_id, &json, seq, ts);
        CertRotate {
            old_node_id:   hex::encode(old_id),
            new_node_id:   hex::encode(new_id),
            new_cert_json: json,
            seq,
            ts,
            link_sig:      hex::encode(sig),
        }
    }

    #[test]
    fn valid_rotation_accepted() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let msg      = make_rotation(&old_cert, &new_cert, &key, 1, 1700000000);

        let verified = verify_rotation(&key, &msg).expect("should verify");
        assert_eq!(verified.node_id(), new_cert.node_id());
    }

    #[test]
    fn tampered_hmac_rejected() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let mut msg  = make_rotation(&old_cert, &new_cert, &key, 1, 1700000000);

        // Flip one bit in the hex sig
        let mut bytes = hex::decode(&msg.link_sig).unwrap();
        bytes[17] ^= 1;
        msg.link_sig = hex::encode(bytes);

        assert!(matches!(verify_rotation(&key, &msg), Err(Error::AuthFailed)));
    }

    #[test]
    fn wrong_link_key_rejected() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let msg      = make_rotation(&old_cert, &new_cert, &key, 1, 1700000000);

        // Different key — an attacker who doesn't share our session
        let wrong_key = [0x43u8; 32];
        assert!(matches!(verify_rotation(&wrong_key, &msg), Err(Error::AuthFailed)));
    }

    #[test]
    fn node_id_binding_enforced() {
        // Attacker signs a rotation pointing to cert X but claims
        // new_node_id is from cert Y. Verifier must catch the mismatch.
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let decoy    = small_cert();
        let key      = [0x42u8; 32];

        let old_id   = old_cert.node_id();
        let fake_id  = decoy.node_id();     // doesn't match the embedded cert
        let real_id  = new_cert.node_id();
        assert_ne!(fake_id, real_id);

        let wire = new_cert.to_wire();
        let json = serde_json::to_string(&wire).unwrap();
        let sig  = compute_rotation_sig(&key, &old_id, &fake_id, &json, 1, 0);
        let msg  = CertRotate {
            old_node_id:   hex::encode(old_id),
            new_node_id:   hex::encode(fake_id),    // LIE
            new_cert_json: json,
            seq:           1,
            ts:            0,
            link_sig:      hex::encode(sig),
        };
        // HMAC passes (we signed the lie), but binding check fails.
        let err = verify_rotation(&key, &msg);
        assert!(err.is_err());
        let err_str = format!("{:?}", err.unwrap_err());
        assert!(err_str.contains("binding") || err_str.contains("node_id"),
                "expected binding error, got: {}", err_str);
    }

    #[test]
    fn corrupt_cert_json_rejected() {
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let mut msg  = make_rotation(&old_cert, &new_cert, &key, 1, 0);

        // Mangle the JSON — HMAC will fail first since the sig was
        // computed over the original text.
        msg.new_cert_json = "{not valid json".to_string();
        // The HMAC was computed over the *original* json, so mangling
        // the field invalidates it. verify_rotation hits HMAC check first.
        assert!(verify_rotation(&key, &msg).is_err());
    }

    #[test]
    fn sig_binds_to_seq_and_ts() {
        // If attacker replays a valid rotation but changes seq/ts,
        // the sig should no longer verify.
        let old_cert = small_cert();
        let new_cert = old_cert.rotate().unwrap();
        let key      = [0x42u8; 32];
        let mut msg  = make_rotation(&old_cert, &new_cert, &key, 5, 1700000000);

        msg.seq = 6; // attacker tries to replay with higher seq
        assert!(matches!(verify_rotation(&key, &msg), Err(Error::AuthFailed)));

        let mut msg2 = make_rotation(&old_cert, &new_cert, &key, 5, 1700000000);
        msg2.ts = 1700001000;
        assert!(matches!(verify_rotation(&key, &msg2), Err(Error::AuthFailed)));
    }

    #[test]
    fn compute_rotation_sig_is_deterministic() {
        let key    = [0x11u8; 32];
        let old_id = [0xAAu8; 32];
        let new_id = [0xBBu8; 32];
        let json   = r#"{"fake":"cert"}"#;

        let s1 = compute_rotation_sig(&key, &old_id, &new_id, json, 42, 1000);
        let s2 = compute_rotation_sig(&key, &old_id, &new_id, json, 42, 1000);
        assert_eq!(s1, s2);

        // Changing any field produces a different sig
        let s_diff_key = compute_rotation_sig(&[0x12u8; 32], &old_id, &new_id, json, 42, 1000);
        assert_ne!(s1, s_diff_key);
        let s_diff_seq = compute_rotation_sig(&key, &old_id, &new_id, json, 43, 1000);
        assert_ne!(s1, s_diff_seq);
    }

    // ── ResolvedIntro / resolve_hs_descriptor ──────────────────────

    use crate::hidden_service::HiddenService;
    use crate::hs_identity::{current_epoch, sign_descriptor};
    use x25519_dalek::{StaticSecret, PublicKey as XPub};

    #[test]
    fn resolve_public_descriptor_returns_plaintext_intro() {
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        let hs = HiddenService::new(&cert, "svc-pub");
        let unsigned = hs.descriptor(Some("intro.host"), Some(7700));
        let signed = sign_descriptor(&hs.identity, unsigned, current_epoch());

        // No client secrets needed for a public descriptor
        let resolved = PhiNode::resolve_hs_descriptor(&signed, &[])
            .expect("resolve should succeed")
            .expect("public descriptor should resolve");
        assert_eq!(resolved.intro_host.as_deref(), Some("intro.host"));
        assert_eq!(resolved.intro_port, Some(7700));
        // intro_pub should match the HS's intro key
        let expected: [u8; 32] = *hs.intro_pub.as_bytes();
        assert_eq!(resolved.intro_pub, expected);
    }

    #[test]
    fn resolve_authed_descriptor_with_correct_secret() {
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        let hs = HiddenService::new(&cert, "svc-priv");

        let alice_sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_pub = *XPub::from(&alice_sec).as_bytes();

        let unsigned = hs.descriptor_with_client_auth(
            Some("intro.host"), Some(8800),
            &[alice_pub],
        ).expect("build authed");
        let signed = sign_descriptor(&hs.identity, unsigned, current_epoch());

        let resolved = PhiNode::resolve_hs_descriptor(&signed, &[alice_sec])
            .expect("resolve")
            .expect("alice should be authorized");
        assert_eq!(resolved.intro_host.as_deref(), Some("intro.host"));
        assert_eq!(resolved.intro_port, Some(8800));
        let expected: [u8; 32] = *hs.intro_pub.as_bytes();
        assert_eq!(resolved.intro_pub, expected);
    }

    #[test]
    fn resolve_authed_descriptor_unauthorized_client() {
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        let hs = HiddenService::new(&cert, "svc-priv");

        let alice_sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_pub = *XPub::from(&alice_sec).as_bytes();
        let eve_sec = StaticSecret::random_from_rng(rand::rngs::OsRng);

        let unsigned = hs.descriptor_with_client_auth(
            Some("intro.host"), Some(8800),
            &[alice_pub],   // only alice authorized
        ).unwrap();
        let signed = sign_descriptor(&hs.identity, unsigned, current_epoch());

        // Eve tries her own secret — must get None (not error)
        let r = PhiNode::resolve_hs_descriptor(&signed, &[eve_sec])
            .expect("resolve should not error on unauthorized");
        assert!(r.is_none(),
            "unauthorized client should get None, not an error");
    }

    #[test]
    fn resolve_authed_descriptor_tries_multiple_secrets() {
        // Caller might have several authorized-client identities (e.g.
        // for different hidden services). resolve_hs_descriptor tries
        // each in turn; only one needs to match.
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        let hs = HiddenService::new(&cert, "svc-priv");

        // Three secrets — only the third is authorized
        let unrelated_a = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let unrelated_b = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_pub = *XPub::from(&alice_sec).as_bytes();

        let unsigned = hs.descriptor_with_client_auth(
            Some("intro.host"), Some(8800),
            &[alice_pub],
        ).unwrap();
        let signed = sign_descriptor(&hs.identity, unsigned, current_epoch());

        let resolved = PhiNode::resolve_hs_descriptor(
            &signed, &[unrelated_a, unrelated_b, alice_sec],
        ).expect("resolve").expect("alice authorized");
        // Successfully recovered intro_pub
        assert_eq!(resolved.intro_pub, *hs.intro_pub.as_bytes());
    }

    #[test]
    fn resolve_rejects_unsigned_descriptor() {
        // Resolve must verify signature first regardless of auth model.
        // A descriptor with no signature must be rejected.
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        let hs = HiddenService::new(&cert, "svc");
        let unsigned = hs.descriptor(Some("h"), Some(1));
        // Don't sign it — sig field stays empty

        let r = PhiNode::resolve_hs_descriptor(&unsigned, &[]);
        assert!(r.is_err(),
            "unsigned descriptor must fail signature check");
    }

    #[test]
    fn resolve_rejects_tampered_descriptor() {
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        let hs = HiddenService::new(&cert, "svc");
        let unsigned = hs.descriptor(Some("h"), Some(1));
        let mut signed = sign_descriptor(&hs.identity, unsigned, current_epoch());

        // Tamper: change intro_host. Sig was over original.
        signed.intro_host = Some("attacker.example".into());

        let r = PhiNode::resolve_hs_descriptor(&signed, &[]);
        assert!(r.is_err(),
            "tampered descriptor must fail signature");
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use crate::cert::{CertBits, PhiCert};
    use crate::store::SiteStore;
    use std::sync::Arc;

    fn node(port: u16) -> Arc<PhiNode> {
        let cert = PhiCert::generate(CertBits::B256).expect("gen cert");
        PhiNode::new("127.0.0.1", port, cert, Arc::new(SiteStore::new_test()))
    }

    /// Two real nodes complete the ephemeral-DH-then-encrypted-cert
    /// handshake over a loopback TCP connection and register each other
    /// as peers. Registration only happens after each side successfully
    /// decrypts the other's encrypted HANDSHAKE / HANDSHAKE_ACK, so this
    /// passing proves the cert exchange is carried (and correctly
    /// round-tripped) under the session key rather than in the clear.
    #[tokio::test]
    async fn encrypted_handshake_two_nodes_register_each_other() {
        let a = node(7001);
        let b = node(7002);
        let a_id = a.node_id();
        let b_id = b.node_id();
        assert_ne!(a_id, b_id);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let baddr = listener.local_addr().unwrap();

        let b_srv = Arc::clone(&b);
        let accept = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            b_srv.handle_incoming(stream, addr).await
        });

        Arc::clone(&a)
            .connect(&baddr.ip().to_string(), baddr.port())
            .await
            .expect("initiator handshake should succeed");
        accept.await.unwrap().expect("responder handshake should succeed");

        // Let the spawned reader/writer tasks settle.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(a.peers.read().await.contains_key(&b_id),
            "initiator should have registered the responder");
        assert!(b.peers.read().await.contains_key(&a_id),
            "responder should have registered the initiator");
    }

    /// End-to-end: A connects to B, then sends B an encrypted com
    /// message. B's inbox should contain the decrypted body attributed
    /// to A, and A's own outgoing thread should mirror it.
    #[tokio::test]
    async fn com_message_delivers_over_phinet_link() {
        let a = node(7011);
        let b = node(7012);
        let a_id = a.node_id();
        let b_id = b.node_id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let baddr = listener.local_addr().unwrap();
        let b_srv = Arc::clone(&b);
        let accept = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            b_srv.handle_incoming(stream, addr).await
        });
        Arc::clone(&a).connect(&baddr.ip().to_string(), baddr.port()).await.unwrap();
        accept.await.unwrap().unwrap();

        // A → B.
        Arc::clone(&a).com_send_to(b_id, "hello over phinet").await
            .expect("send should succeed");

        // Wait for B's reader task to dispatch + store.
        let mut got = None;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let conv = b.com_conversation(&a_id).await;
            if let Some(m) = conv.first() { got = Some(m.clone()); break; }
        }
        let (outgoing, _ts, body, _mid) = got.expect("B should have received the message");
        assert!(!outgoing, "B's copy is incoming");
        assert_eq!(body, "hello over phinet");

        // A's own thread mirrors the sent message.
        let a_conv = a.com_conversation(&b_id).await;
        assert_eq!(a_conv.len(), 1);
        assert!(a_conv[0].0, "A's copy is outgoing");
        assert_eq!(a_conv[0].2, "hello over phinet");
    }

    /// Connect `a` (initiator) to `b` (responder) over loopback and
    /// return once both have registered each other.
    async fn link(a: &Arc<PhiNode>, b: &Arc<PhiNode>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let baddr = listener.local_addr().unwrap();
        let b_srv = Arc::clone(b);
        let accept = tokio::spawn(async move {
            let (s, addr) = listener.accept().await.unwrap();
            b_srv.handle_incoming(s, addr).await
        });
        Arc::clone(a).connect(&baddr.ip().to_string(), baddr.port()).await.unwrap();
        accept.await.unwrap().unwrap();
    }

    /// Offline delivery: A sends to B while B is offline. A relay R holds
    /// the sealed mail; when B connects to R and pulls, it arrives.
    #[tokio::test]
    async fn com_offline_delivery_via_mailbox() {
        let a = node(7021); // sender
        let r = node(7022); // relay / mailbox
        let b = node(7023); // recipient, initially offline
        let a_id  = a.node_id();
        let b_id  = b.node_id();
        let b_pub = b.static_pub();

        // A ↔ R only. B is not connected to anything yet.
        link(&a, &r).await;

        // A sends to (offline) B; the ComStore gossip lands in R's mailbox.
        Arc::clone(&a).com_send(b_id, b_pub, "offline hi").await.unwrap();

        let mut held = 0;
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            held = r.com_mailbox.read().await.len();
            if held > 0 { break; }
        }
        assert!(held >= 1, "relay should hold mail for offline B");

        // B comes online, connects to R, and pulls its mail.
        link(&b, &r).await;
        Arc::clone(&b).com_pull().await;

        let mut got = None;
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let conv = b.com_conversation(&a_id).await;
            if let Some(m) = conv.first() { got = Some(m.clone()); break; }
        }
        let (outgoing, _ts, body, _mid) = got.expect("B should receive offline mail");
        assert!(!outgoing, "B's copy is incoming");
        assert_eq!(body, "offline hi");
    }

    /// Groups: A creates a group, invites B (key delivered inside a
    /// sealed 1:1 invite), then posts to the group; B — now a member —
    /// receives and decrypts the group message.
    #[tokio::test]
    async fn com_group_message_reaches_invited_member() {
        let a = node(7031);
        let b = node(7032);
        let b_id = b.node_id();
        link(&a, &b).await;
        // A learns B's key from the link (contacts), so it can invite.

        let g = Arc::clone(&a).com_create_group("crew", false).await;
        let gid = g.group_id;
        let thread = PhiNode::group_thread_id(&gid);

        Arc::clone(&a).com_invite_to_group(gid, b_id).await
            .expect("invite should send");

        // Wait for B to join the group (invite arrives via gossip).
        let mut joined = false;
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            if b.com_groups.read().await.contains_key(&gid) { joined = true; break; }
        }
        assert!(joined, "B should have joined the group from the invite");

        // A posts to the group.
        Arc::clone(&a).com_send_group(gid, "hello crew").await.unwrap();

        // B receives + decrypts it in the group thread.
        let mut got = None;
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let conv = b.com_conversation(&thread).await;
            if let Some(m) = conv.first() { got = Some(m.clone()); break; }
        }
        let (_out, _ts, body, _mid) = got.expect("B should receive the group message");
        assert_eq!(body, "hello crew");
    }

    /// Circuit-injected (sender-anonymous) delivery: A builds a circuit
    /// to B and injects a sealed envelope for C at the exit. We drive the
    /// circuit path directly (not the gossip fallback) to prove the exit
    /// injects it into store-and-forward.
    #[tokio::test]
    async fn com_circuit_injection_reaches_exit() {
        use crate::circuit::RelayCommand;
        let a = node(7041); // origin
        let b = node(7042); // relay / exit
        let c = node(7043); // recipient (only its key is needed here)
        let c_pub = c.static_pub();
        link(&a, &b).await;

        let ts    = crate::com::now_secs();
        let epoch = crate::com::current_epoch();
        let env = crate::com::seal(&a.keypair.secret, a.node_id(), a.static_pub(),
                                   c_pub, epoch, ts, b"anon hi");
        let compact = env.to_compact().expect("compact");
        assert!(compact.len() <= crate::circuit::RELAY_DATA_MAX);

        // Build a real 1-hop circuit A→B and inject over it.
        let path = a.com_circuit_path(1).await;
        assert_eq!(path.len(), 1, "A should have exactly B as a peer");
        let cid = Arc::clone(&a).build_circuit(path).await.expect("circuit build");
        a.send_origin_relay(cid, RelayCommand::ComInject, compact).await
            .expect("circuit inject");

        // The exit (B) should have injected the envelope into its mailbox
        // under C's blinded address — proving delivery entered the network
        // at B, not from A's own link as a ComStore.
        let addr = crate::com::blinded_addr(&c_pub, epoch);
        let mut held = 0;
        for _ in 0..80 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            held = b.com_mailbox.read().await.peek(&addr).len();
            if held > 0 { break; }
        }
        assert!(held >= 1, "exit should have injected the envelope into its mailbox");
    }

    /// Consensus-driven topology: a node that has a consensus listing a
    /// relay it never bootstrapped to should *dial that relay itself* as
    /// a guard. This is the piece that turns a bootstrap star into a
    /// mesh — nodes connect to relays learned from the consensus, not
    /// only whoever they were hand-pointed at.
    #[tokio::test]
    async fn dials_a_guard_from_the_consensus() {
        use crate::directory::{ConsensusDocument, PeerEntry};
        // Start from a clean guard file so add_candidate has room.
        if let Some(h) = dirs::home_dir() {
            let _ = std::fs::remove_file(h.join(".phinet/guards.json"));
        }
        let a = node(7051);   // has the consensus, will dial
        let b = node(7052);   // the relay listed in it

        // B listens persistently.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let baddr = listener.local_addr().unwrap();
        let b_srv = Arc::clone(&b);
        tokio::spawn(async move {
            loop {
                let (s, addr) = match listener.accept().await { Ok(x) => x, Err(_) => break };
                let b2 = Arc::clone(&b_srv);
                tokio::spawn(async move { let _ = b2.handle_incoming(s, addr).await; });
            }
        });

        // A's consensus lists B — but A never bootstrapped to it.
        let doc = ConsensusDocument {
            network_id:  "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1,
            valid_until: 4_102_444_800,
            peers: vec![PeerEntry {
                node_id_hex:    hex::encode(b.node_id()),
                host:           baddr.ip().to_string(),
                port:           baddr.port(),
                static_pub_hex: hex::encode(b.static_pub()),
                flags: 0, bandwidth_kbs: 1000, exit_policy_summary: "default".into(),
 family: String::new(),
            }],
            signatures: vec![],
        };
        *a.cached_consensus.write().await = Some(doc);
        assert!(a.peers.read().await.is_empty(), "A starts with no peers");

        // Run guard maintenance — A should dial B from the consensus.
        a.maintain_guards_from_consensus().await;

        let b_id = b.node_id();
        let mut linked = false;
        for _ in 0..40 {
            if a.peers.read().await.contains_key(&b_id) { linked = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(linked, "A should have dialed its consensus guard B and linked");
        assert!(a.guard_mgr.is_guard(&b_id), "B should be pinned as a guard");
    }

    /// Anonymity-preserving contact model: you can only message someone
    /// whose address you were given. A node NOT in peers/contacts does
    /// not resolve — even if it's in the consensus — until you add it by
    /// address.
    #[tokio::test]
    async fn com_messages_only_known_contacts() {
        let a = node(7061);
        let b = node(7062);
        let b_id  = b.node_id();
        let b_pub = b.static_pub();

        // Unknown recipient: no resolution, no roster to fall back to.
        assert_eq!(a.com_resolve_pub(&b_id).await, None,
                   "an unknown node must not resolve");

        // B shares its address out of band; A adds it.
        let addr = b.com_my_address();
        let (nid, spk) = crate::com::address_decode(&addr).expect("valid address");
        assert_eq!(nid, b_id);
        assert_eq!(spk, b_pub);
        a.com_add_contact(nid, spk).await;

        // Now — and only now — A can resolve B.
        assert_eq!(a.com_resolve_pub(&b_id).await, Some(b_pub),
                   "after adding by address, the contact resolves");
    }

    /// A peer that goes silent (its 1 Hz padding stops) is reaped from
    /// the peer table + routing, so a vanished node can't linger as a
    /// consensus ghost.
    #[tokio::test]
    async fn reaps_a_silent_peer() {
        let a = node(7071);
        let b = node(7072);
        link(&a, &b).await;
        let b_id = b.node_id();
        assert!(a.peers.read().await.contains_key(&b_id), "linked");

        // Freshly linked → not stale → kept.
        let now = crate::com::now_secs();
        assert!(a.reap_dead_peers(now).await.is_empty());
        assert!(a.peers.read().await.contains_key(&b_id), "fresh peer kept");

        // Past the stale window → silent → reaped.
        let evicted = a.reap_dead_peers(now + STALE_PEER_SECS + 100).await;
        assert!(evicted.contains(&b_id), "silent peer reaped");
        assert!(!a.peers.read().await.contains_key(&b_id), "removed from peer table");
        assert!(a.routing.all_peers().iter().all(|p| p.node_id != b_id),
                "removed from routing");
    }

    /// A pinned guard that has fallen out of the consensus is retired,
    /// so a node stops forever redialing a relay whose identity no
    /// longer exists (the stale-guards.json ghost).
    #[tokio::test]
    async fn retires_guards_not_in_consensus() {
        use crate::directory::{ConsensusDocument, PeerEntry};
        if let Some(h) = dirs::home_dir() {
            let _ = std::fs::remove_file(h.join(".phinet/guards.json"));
        }
        let a = node(7081);
        // A stale guard from a "previous session" — unreachable, fast-refused.
        let ghost = [0xABu8; 32];
        a.guard_mgr.add_candidate(&ghost, "127.0.0.1", 1);
        assert!(a.guard_mgr.is_guard(&ghost), "ghost pinned");

        // Current consensus lists a different node (also fast-refused).
        let real = [0xCDu8; 32];
        let doc = ConsensusDocument {
            network_id: "phinet-mainnet".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1, valid_until: 4_102_444_800,
            peers: vec![PeerEntry {
                node_id_hex:    hex::encode(real),
                host:           "127.0.0.1".into(),
                port:           1,
                static_pub_hex: hex::encode([9u8; 32]),
                flags: 0, bandwidth_kbs: 1000, exit_policy_summary: "default".into(),
 family: String::new(),
            }],
            signatures: vec![],
        };
        *a.cached_consensus.write().await = Some(doc);

        a.maintain_guards_from_consensus().await;

        assert!(!a.guard_mgr.is_guard(&ghost),
                "stale guard not in consensus should be retired");
    }

    // ── Full end-to-end hidden-service GET over rendezvous ────────────

    /// Mesh every node in `nodes` with every other over loopback, so
    /// any node can serve as any hop of a circuit (build_hs_circuit
    /// requires all hops to be pre-connected peers).
    async fn full_mesh(nodes: &[Arc<PhiNode>]) {
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                link(&nodes[i], &nodes[j]).await;
            }
        }
    }

    /// Build a consensus document listing the given relay nodes, all
    /// flagged usable for every hop position so path selection has a
    /// full set to choose from.
    fn consensus_of(relays: &[Arc<PhiNode>]) -> crate::directory::ConsensusDocument {
        use crate::directory::{ConsensusDocument, PeerEntry, PeerFlags};
        let flags = (PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::GUARD
                     | PeerFlags::EXIT | PeerFlags::RUNNING | PeerFlags::VALID).bits();
        // Path selection prefers relays in distinct /16 subnets, so give
        // each consensus entry a cosmetically-distinct host. Circuit
        // building routes by node_id via the peer table (not by this
        // host), so distinct IPs here only affect diversity scoring, not
        // actual connectivity — the nodes are still reached over their
        // real loopback links.
        let peers = relays.iter().enumerate().map(|(i, n)| PeerEntry {
            node_id_hex:    hex::encode(n.node_id()),
            host:           format!("10.{}.0.1", i),
            port:           n.port,
            static_pub_hex: hex::encode(n.static_pub()),
            flags,
            bandwidth_kbs:  1000,
            exit_policy_summary: String::new(),
            family: String::new(),
        }).collect();
        ConsensusDocument {
            network_id: "phinet-test".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 0,
            valid_until: u64::MAX,
            peers,
            signatures: Vec::new(),
        }
    }

    /// The whole pipeline: an HS hosts a one-page site; a client with no
    /// prior knowledge but the signed descriptor runs `hs_fetch`, which
    /// resolves the intro point, builds RP + intro circuits through a
    /// relay mesh, completes the rendezvous handshake, bridges the two
    /// legs at the RP, sends a GET over the end-to-end channel, and
    /// recovers the exact bytes the HS served. Exercises every piece
    /// added in this work: e2e layer, RP data bridge, HS serve path,
    /// and client collect path.
    #[tokio::test]
    async fn hs_fetch_end_to_end_get() {
        // 6 relays give two node-disjoint 3-hop paths (RP + intro) with
        // room to spare; the intro path's terminal hop is then swapped
        // for the HS node itself.
        let client = node(7200);
        let hs     = node(7201);
        let relays: Vec<Arc<PhiNode>> = (0..6).map(|i| node(7210 + i)).collect();

        // Mesh everyone: client, hs, and all relays.
        let mut all = vec![Arc::clone(&client), Arc::clone(&hs)];
        all.extend(relays.iter().cloned());
        full_mesh(&all).await;

        // Spawn the HS rendezvous drain loop (normally started by run()).
        {
            let n = Arc::clone(&hs);
            tokio::spawn(async move { n.hs_rendezvous_drain_loop().await });
        }

        // HS hosts a site with one page.
        let svc = hs.register_hs("testsite").await;
        let hs_id = svc.hs_id.clone();
        hs.store.create_service(&hs_id, "testsite", "00").await.unwrap();
        hs.store.put_file(&hs_id, "/index.html", b"hello from phinet HS").await.unwrap();

        // Build the descriptor the way the daemon does: advertise the
        // HS *node* static key as intro_pub and the HS node id so the
        // client can target the terminal intro hop at the HS.
        let mut desc = svc.descriptor(Some(&hs.host), Some(hs.port));
        desc.intro_pub     = hex::encode(hs.static_pub());
        desc.intro_node_id = hex::encode(hs.node_id());
        let desc = crate::hs_identity::sign_descriptor(
            &svc.identity, desc, crate::hs_identity::current_epoch());

        // Publish it into the client's DHT (in production this arrives
        // via HsRegister gossip; here we inject directly for determinism).
        client.dht.put_hs(&desc);

        // Client resolves + fetches "/".
        let consensus = consensus_of(&relays);
        let resp = Arc::clone(&client)
            .hs_fetch(&desc, &[], &consensus, "/")
            .await
            .expect("hs_fetch should complete end-to-end");

        assert_eq!(resp.status, 200, "expected 200 OK from HS");
        assert_eq!(resp.body, b"hello from phinet HS",
            "client must recover the exact bytes the HS served");
    }

    /// A response larger than a single relay cell (RELAY_DATA_MAX = 496
    /// bytes) must be chunked by the HS and reassembled by the client.
    /// We serve a body well over that limit and check every byte comes
    /// back intact — exercising the multi-cell path that a one-cell GET
    /// doesn't.
    #[tokio::test]
    async fn hs_fetch_end_to_end_large_body_chunked() {
        let client = node(7240);
        let hs     = node(7241);
        let relays: Vec<Arc<PhiNode>> = (0..6).map(|i| node(7250 + i)).collect();

        let mut all = vec![Arc::clone(&client), Arc::clone(&hs)];
        all.extend(relays.iter().cloned());
        full_mesh(&all).await;

        {
            let n = Arc::clone(&hs);
            tokio::spawn(async move { n.hs_rendezvous_drain_loop().await });
        }

        let svc = hs.register_hs("bigsite").await;
        let hs_id = svc.hs_id.clone();
        hs.store.create_service(&hs_id, "bigsite", "00").await.unwrap();
        // ~5 KB body → spans ~11 relay cells after framing.
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        hs.store.put_file(&hs_id, "/big.bin", &big).await.unwrap();

        let mut desc = svc.descriptor(Some(&hs.host), Some(hs.port));
        desc.intro_pub     = hex::encode(hs.static_pub());
        desc.intro_node_id = hex::encode(hs.node_id());
        let desc = crate::hs_identity::sign_descriptor(
            &svc.identity, desc, crate::hs_identity::current_epoch());
        client.dht.put_hs(&desc);

        let consensus = consensus_of(&relays);
        let resp = match Arc::clone(&client)
            .hs_fetch(&desc, &[], &consensus, "/big.bin")
            .await {
            Ok(r) => r,
            Err(e) => panic!("hs_fetch(large) failed: {e}"),
        };

        assert_eq!(resp.status, 200, "large fetch should be 200");
        assert_eq!(resp.body.len(), big.len(),
            "reassembled body length must match ({} vs {})", resp.body.len(), big.len());
        assert_eq!(resp.body, big,
            "every chunk must reassemble in order, byte-for-byte");
    }
}
