// phinet-core/src/circuit_mgr.rs
//! Circuit manager: builds multi-hop circuits, routes cells across them.
//!
//! There are two kinds of circuit state tracked here:
//!
//! * **Origin circuit** — this node initiated the circuit. Holds
//!   `HopState` entries for each hop, in build order (guard first).
//! * **Relay circuit** — this node sits in the middle of someone else's
//!   circuit. Holds exactly one `HopState` (the keys it shares with the
//!   originating client) plus two routing endpoints: the previous peer
//!   (toward client) and the next peer (toward terminal hop).
//!
//! The manager is keyed by `(peer_id, CircuitId)` because circuit IDs
//! are local to a single TCP connection — different connections can
//! reuse the same numeric ID for unrelated circuits.
//!
//! # State machine
//!
//! Origin side, building a 3-hop circuit [G, M, E]:
//!
//! ```text
//!   start_circuit(G)  →  CREATE to G, circuit state = Building(vec![],
//!                        pending_ntor[G])
//!   recv CREATED      →  ntor_finish, hops = [G], pending = None
//!
//!   extend(M)         →  ntor_start(M), build EXTEND2, layered-encrypt
//!                        for G, send as RelayEarly; pending = ntor[M]
//!   recv RELAY cell   →  decrypt layer-by-layer; recognized at G-digest
//!                        means it's a RELAY_EXTENDED2 for our extend.
//!                        ntor_finish(M), hops = [G, M], pending = None
//!
//!   extend(E)         →  same as above, one more wrapping layer.
//!                        RELAY_EXTENDED2 returns recognized at M-digest
//!                        after peeling G and M layers.
//! ```
//!
//! Relay side, forwarding a cell from G toward M (we are G in this
//! scenario, circuit originated by a client):
//!
//! ```text
//!   recv CREATE (from client)  →  ntor_server, reply CREATED, register
//!                                 `Pending(client_conn, client_circ_id)`
//!                                 — we do not yet know the next hop.
//!
//!   recv RELAY (from client)   →  decrypt_forward with our key.
//!                                 If recognized and cmd == EXTEND2:
//!                                   parse next hop, open/find conn,
//!                                   allocate circ_id_for_next,
//!                                   send CREATE to next. Remember
//!                                   which origin RELAY cell this was
//!                                   so we can return EXTENDED2.
//!                                 If not recognized:
//!                                   look up next hop, forward cell
//!                                   with our circ_id rewritten.
//!
//!   recv CREATED (from next)   →  wrap ntor reply in RELAY_EXTENDED2,
//!                                 encrypt_backward with our key,
//!                                 send to client.
//! ```

use crate::{
    circuit::{
        build_extend2, build_extended2, onion_decrypt_backward, onion_decrypt_forward,
        onion_encrypt_backward, onion_encrypt_forward, parse_extend2, parse_extended2,
        Cell, CellCommand, CircuitId, HopState, LinkSpec, RelayCell, RelayCommand,
        CELL_PAYLOAD, MAX_HOPS,
    },
    ntor::{self, ClientHandshake, CLIENT_HANDSHAKE_LEN, SERVER_HANDSHAKE_LEN},
    Error, Result,
};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Opaque peer identifier. In node.rs this is the peer's 32-byte node_id;
/// here we abstract over it so the manager can be tested independently.
pub type PeerId = [u8; 32];

// ── Circuit state ─────────────────────────────────────────────────────

/// Client-originated circuit. Hops are in build order: `hops[0]` is
/// the guard (the peer we have a direct TCP connection to).
pub struct OriginCircuit {
    pub id:   CircuitId,
    pub peer: PeerId,             // the guard peer
    pub hops: Vec<HopState>,
    /// When we've just sent a CREATE or EXTEND2 and are waiting for the
    /// reply, we stash the in-flight ntor handshake here.
    pub pending: Option<ClientHandshake>,
    /// Number of RELAY_EARLY cells emitted so far. Must not exceed
    /// `MAX_RELAY_EARLY` or a compromised hop could silently extend.
    pub relay_early_used: u32,
    /// Multiplexed stream table: many application streams per circuit.
    /// Each tracks its own flow-control window and state.
    pub streams: std::sync::Arc<crate::stream::StreamMux>,
    /// Circuit-level outbound congestion controller (Tor Proposal 324,
    /// Vegas). Replaces the legacy fixed send-window: `can_send()`
    /// gates each outbound DATA cell, `on_send` accounts it, and
    /// `on_sendme` (called from `on_circ_sendme`) folds in the RTT
    /// sample and re-sizes the congestion window. This is what lets a
    /// circuit's throughput track the actual path capacity instead of
    /// being pinned at a fixed 1000-cell window.
    pub cc: crate::congestion::Vegas,
    /// Circuit-level inbound DATA count. Increments on each DATA cell
    /// delivered up the circuit; we emit a SENDME every
    /// `CC_SENDME_INC` cells to refill the peer's window. The cadence
    /// must match `CC_SENDME_INC` so the far end's controller frees
    /// exactly one window's worth of in-flight cells per SENDME.
    pub circ_delivered_since_sendme: i32,
    /// Instant of the most recent activity on this circuit (cell sent
    /// or received in either direction). Used by the idle-eviction
    /// loop to drop circuits that haven't been used in
    /// `CIRCUIT_IDLE_TIMEOUT`. Without this, a long-running daemon
    /// accumulates dead circuits forever — each one holds memory for
    /// key state, stream muxes, hop keys, etc.
    pub last_activity: std::time::Instant,
    /// Per-circuit padding scheduler. The padding pump task polls
    /// `should_pad_now()` and emits RELAY_DROP cells via the guard
    /// hop on its decisions. Set via
    /// `CircuitManager::set_padding_scheduler` after construction or
    /// left as `NoPadding` (the default — circuits don't pad unless
    /// the operator opted in).
    pub padding_scheduler: std::sync::Arc<dyn crate::padding::PaddingScheduler>,
    /// Innermost end-to-end layer, present only on rendezvous circuits
    /// after a successful client↔HS handshake. When `Some`, outbound
    /// relay cells get one extra encryption layer applied *inside* all
    /// hop layers (so no path relay can read them), and inbound cells
    /// are peeled with it *after* all hop layers. `None` for ordinary
    /// exit circuits, where the terminal hop is the endpoint.
    pub e2e: Option<HopState>,
}

impl OriginCircuit {
    pub fn new(id: CircuitId, peer: PeerId) -> Self {
        Self {
            id,
            peer,
            hops: Vec::with_capacity(MAX_HOPS),
            pending: None,
            relay_early_used: 0,
            streams: std::sync::Arc::new(crate::stream::StreamMux::new()),
            cc: crate::congestion::Vegas::new(),
            circ_delivered_since_sendme: 0,
            last_activity: std::time::Instant::now(),
            padding_scheduler: std::sync::Arc::new(crate::padding::NoPadding),
            e2e: None,
        }
    }

    /// Refresh the last-activity timestamp. Called on every cell sent
    /// or received on this circuit, so the idle-eviction loop treats
    /// the circuit as live.
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    /// Attempt to consume one slot from the circuit's outbound DATA
    /// window. Returns `Ok(())` if there was budget, or an error if
    /// the window is exhausted — callers should wait for a circuit
    /// SENDME to refill before retrying. Unlike stream windows, a
    /// depleted circuit window means the circuit as a whole is
    /// congested, not just one stream.
    pub fn try_consume_circ_window(&mut self) -> Result<()> {
        if !self.cc.can_send() {
            return Err(Error::Handshake(format!(
                "circuit {:?}: congestion window full (cwnd={}, inflight={})",
                self.id, self.cc.cwnd(), self.cc.inflight()
            )));
        }
        self.cc.on_send(std::time::Instant::now());
        Ok(())
    }

    /// Called when a circuit-level SENDME arrives from the far end.
    /// Frees one SENDME-increment of in-flight cells, folds the RTT
    /// sample into the Vegas estimator, and re-sizes the congestion
    /// window. Unlike the legacy fixed window there is no artificial
    /// 2× cap: the window is bounded by the Vegas queue estimate and
    /// [`crate::congestion::CC_CWND_MAX`], so a peer cannot inflate it
    /// by flooding SENDMEs — extra SENDMEs just free already-acked
    /// window and the queue estimate pulls `cwnd` back down.
    pub fn on_circ_sendme(&mut self) {
        self.cc.on_sendme(std::time::Instant::now());
    }

    /// Count a DATA cell delivered up the circuit. Returns `true` if
    /// it's now time to emit a circuit SENDME (i.e. the delivered
    /// count reached [`crate::congestion::CC_SENDME_INC`]), else
    /// `false`. Caller resets the counter via `reset_circ_delivered`
    /// after emitting the SENDME. The cadence matches the sender's
    /// controller increment so each SENDME frees exactly one window.
    pub fn note_circ_delivered(&mut self) -> bool {
        self.circ_delivered_since_sendme += 1;
        self.circ_delivered_since_sendme >= crate::congestion::CC_SENDME_INC as i32
    }

    /// Reset the delivered-since-last-sendme counter. Call after
    /// emitting a circuit SENDME cell.
    pub fn reset_circ_delivered(&mut self) {
        self.circ_delivered_since_sendme = 0;
    }

    /// Layered-encrypt a plaintext relay-cell payload through the
    /// first N hops (innermost = last, outermost = first). Stamps the
    /// digest at the terminal hop before encrypting.
    pub fn encrypt_outbound(
        &mut self,
        target_hop: usize,
        mut relay: RelayCell,
    ) -> Result<[u8; CELL_PAYLOAD]> {
        if target_hop >= self.hops.len() {
            return Err(Error::Crypto(format!(
                "encrypt_outbound: target_hop {target_hop} >= hops.len() {}",
                self.hops.len()
            )));
        }
        // If this is a rendezvous circuit with an installed e2e layer,
        // the cell is addressed end-to-end to the HS, not to any path
        // hop. Stamp the recognition digest with the e2e forward digest
        // and apply the e2e encryption layer first (innermost). The
        // path hops then wrap it without being able to read it — to
        // them it's opaque bytes forwarded toward the RP, which splices
        // it onto the HS circuit. When there's no e2e layer (ordinary
        // exit circuit) we stamp at the terminal hop as before.
        let mut payload = if let Some(e2e) = self.e2e.as_mut() {
            relay.stamp_digest(&mut e2e.forward_digest);
            let mut p = relay.to_payload();
            onion_encrypt_forward(e2e, &mut p);
            p
        } else {
            relay.stamp_digest(&mut self.hops[target_hop].forward_digest);
            relay.to_payload()
        };
        // Encrypt innermost-first: target_hop down to 0
        for i in (0..=target_hop).rev() {
            onion_encrypt_forward(&mut self.hops[i], &mut payload);
        }
        self.last_activity = std::time::Instant::now();
        Ok(payload)
    }

    /// Peel layers off an incoming backward cell. Returns the
    /// `(hop_index, relay_cell)` that recognized it, or `None` if no
    /// hop recognized it (likely means the cell was corrupted and the
    /// circuit should be destroyed).
    pub fn decrypt_inbound(
        &mut self,
        cell_payload: &[u8; CELL_PAYLOAD],
    ) -> Option<(usize, RelayCell)> {
        // Peel each hop's backward layer in turn. After peeling hop i,
        // the cell may be recognized *at* hop i (an ordinary relay-
        // originated backward cell, e.g. SENDME/EXTENDED2/END). We must
        // check recognition progressively because each hop's layer has
        // to come off before the next, and a cell addressed to hop i is
        // still wrapped in hops 0..i only.
        //
        // Nonce/digest state advances exactly once per layer here; we do
        // NOT re-peel for the e2e check (doing so previously double-
        // advanced the hop nonces and corrupted the e2e attempt).
        let mut payload = *cell_payload;
        for i in 0..self.hops.len() {
            onion_decrypt_backward(&mut self.hops[i], &mut payload);
            if let Ok(rc) = RelayCell::from_payload(&payload) {
                if rc.is_recognized_at(&payload, &self.hops[i].backward_digest) {
                    let mut tmp = payload;
                    tmp[5] = 0; tmp[6] = 0; tmp[7] = 0; tmp[8] = 0;
                    self.hops[i].backward_digest.update(&tmp);
                    self.last_activity = std::time::Instant::now();
                    return Some((i, rc));
                }
            }
        }
        // All hop layers are now stripped and none recognized the cell.
        // On a rendezvous circuit this is the expected path for an
        // end-to-end cell from the HS: peel the single innermost e2e
        // backward layer and recognize with the e2e backward digest.
        if let Some(e2e) = self.e2e.as_mut() {
            onion_decrypt_backward(e2e, &mut payload);
            if let Ok(rc) = RelayCell::from_payload(&payload) {
                if rc.is_recognized_at(&payload, &e2e.backward_digest) {
                    let mut tmp = payload;
                    tmp[5] = 0; tmp[6] = 0; tmp[7] = 0; tmp[8] = 0;
                    e2e.backward_digest.update(&tmp);
                    self.last_activity = std::time::Instant::now();
                    // Sentinel usize::MAX = "recognized at the e2e layer,
                    // not a path hop" — callers treat it as the endpoint.
                    return Some((usize::MAX, rc));
                }
            }
        }
        None
    }
}

/// Middle-hop circuit: we forward between previous and next peers.
/// We never know what the cells actually carry; we just peel/add our
/// one layer and route.
pub struct RelayCircuit {
    pub prev_peer:    PeerId,
    pub prev_circ_id: CircuitId,
    pub next_peer:    Option<PeerId>,
    pub next_circ_id: Option<CircuitId>,
    pub hop:          HopState,
    /// Set when we're mid-EXTEND on behalf of the client: we've sent
    /// CREATE to the next hop and are waiting for CREATED back, at
    /// which point we wrap the reply as RELAY_EXTENDED2 for the client.
    pub awaiting_extended: bool,
    /// Exit-side stream table. Only populated when we act as an exit
    /// for clients; intermediate relays just forward cells and never
    /// touch this.
    pub exit_streams: std::sync::Arc<crate::stream::StreamMux>,
    /// Exit-side outbound congestion controller (Prop 324, Vegas).
    /// Same role as `OriginCircuit.cc` but governs the data the exit
    /// sends back toward the client. `can_send()` gates each backward
    /// DATA cell; circuit SENDMEs from the client drive `on_sendme`.
    pub cc: crate::congestion::Vegas,
    /// Exit-side inbound DATA count for circuit SENDME emission.
    pub circ_delivered_since_sendme: i32,
    /// Instant of the most recent cell activity on this relay circuit.
    /// Used by idle-eviction — a relay that hasn't forwarded anything
    /// in CIRCUIT_IDLE_TIMEOUT is torn down to free middle-hop state.
    pub last_activity: std::time::Instant,
}

impl RelayCircuit {
    /// Try to consume one slot from the circuit's outbound (backward-
    /// facing) DATA window. Same semantics as
    /// `OriginCircuit::try_consume_circ_window` but on the exit side.
    pub fn try_consume_circ_window(&mut self) -> Result<()> {
        if !self.cc.can_send() {
            return Err(Error::Handshake(format!(
                "relay circuit ({:?},{:?}): congestion window full \
                 (cwnd={}, inflight={})",
                self.prev_peer, self.prev_circ_id,
                self.cc.cwnd(), self.cc.inflight()
            )));
        }
        self.cc.on_send(std::time::Instant::now());
        Ok(())
    }

    pub fn on_circ_sendme(&mut self) {
        self.cc.on_sendme(std::time::Instant::now());
    }

    pub fn note_circ_delivered(&mut self) -> bool {
        self.circ_delivered_since_sendme += 1;
        self.circ_delivered_since_sendme >= crate::congestion::CC_SENDME_INC as i32
    }

    pub fn reset_circ_delivered(&mut self) {
        self.circ_delivered_since_sendme = 0;
    }

    /// Refresh last-activity timestamp. Called on each cell forwarded
    /// through this middle hop so idle eviction treats it as live.
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
}

// ── Manager ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct CircuitManager {
    pub origins: HashMap<CircuitId, OriginCircuit>,
    pub relays:  HashMap<(PeerId, CircuitId), RelayCircuit>,
    /// Inverse: given next-peer side of a relay circuit, find the pair.
    /// Used when a CREATED or backward RELAY cell arrives from the far side.
    pub relay_by_next: HashMap<(PeerId, CircuitId), (PeerId, CircuitId)>,
    /// Monotonic allocator for circuit IDs we originate.
    next_origin_id: AtomicU32,

    // ── Rendezvous state ──────────────────────────────────────────────

    /// Intro points we host (as a hidden service operator). Key is the
    /// auth_key_pub published in our descriptor. Value is the
    /// origin-side circuit_id that terminates at the intro point.
    /// When an INTRODUCE2 arrives on that circuit, we know which HS
    /// it's for (this map might have multiple entries if we host
    /// multiple hidden services).
    pub intro_circuits: HashMap<[u8; 32], CircuitId>,

    /// Intro points we serve for other hidden services (as a relay).
    /// Key is (from_peer, circ_id) of the HS-facing circuit. Value is
    /// the registered auth_key_pub the HS advertised for matching.
    pub intro_registered: HashMap<(PeerId, CircuitId), [u8; 32]>,

    /// Rendezvous cookies we hold (as an RP). Key is cookie. Value is
    /// (client_peer, client_circ_id) — where to splice HS→client.
    pub rendezvous_cookies: HashMap<[u8; 20], (PeerId, CircuitId)>,

    /// Active RP data bridges. Once RENDEZVOUS1 arrives and we've
    /// spliced RENDEZVOUS2 back to the client, we retain a durable
    /// bidirectional link between the client leg and the HS leg so
    /// subsequent end-to-end DATA cells can be forwarded in both
    /// directions. Key is one leg's (peer, circ_id); value is the
    /// paired leg's (peer, circ_id). Both directions are inserted, so a
    /// cell arriving on either leg finds its partner with one lookup.
    /// The e2e-encrypted inner payload is opaque to us — we only peel
    /// our own hop layer and re-wrap onto the partner leg.
    pub rendezvous_bridges: HashMap<(PeerId, CircuitId), (PeerId, CircuitId)>,

    /// Pending rendezvous state on the client side: circuit we built
    /// to the RP that's awaiting RENDEZVOUS2. Key is the cookie.
    /// Value is (circ_id, client ephemeral secret, client ephemeral pub,
    /// HS static pub from descriptor). The last field is what lets us
    /// verify the HS-side AUTH tag when RENDEZVOUS2 arrives.
    pub pending_rendezvous: HashMap<[u8; 20], (CircuitId, x25519_dalek::StaticSecret, [u8; 32], [u8; 32])>,

    /// End-to-end keys installed after successful rendezvous. Keyed
    /// by the origin CircuitId. Separate from the per-hop HopState
    /// because these keys are shared directly with the HS and don't
    /// fit the hop-onion layering.
    pub e2e_keys: HashMap<CircuitId, crate::rendezvous::E2EKeys>,
}

impl CircuitManager {
    pub fn new() -> Self {
        Self {
            origins:        HashMap::new(),
            relays:         HashMap::new(),
            relay_by_next:  HashMap::new(),
            next_origin_id: AtomicU32::new(0x80_00_00_00), // high bit set = originator
            intro_circuits:      HashMap::new(),
            intro_registered:    HashMap::new(),
            rendezvous_cookies:  HashMap::new(),
            rendezvous_bridges:  HashMap::new(),
            pending_rendezvous:  HashMap::new(),
            e2e_keys:            HashMap::new(),
        }
    }

    fn fresh_origin_id(&self) -> CircuitId {
        CircuitId(self.next_origin_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Install a padding scheduler on an existing origin circuit.
    /// Returns true if the circuit was found, false otherwise.
    ///
    /// Typical use: after `build_circuit` returns the cid, daemon
    /// code optionally calls this to enable padding. The scheduler
    /// is shared via Arc so the same instance can be used across
    /// many circuits if desired (e.g. one ConstantRate scheduler
    /// per HS-related circuit family).
    ///
    /// **Note**: the `padding_pump_loop` task that polls schedulers
    /// already spawned in `build_circuit`. If the previous scheduler
    /// was `NoPadding`, that task already exited; this method
    /// doesn't restart it. To enable padding, call this *before*
    /// invoking `build_circuit`, or via the `build_circuit_with_padding`
    /// convenience on PhiNode.
    pub fn set_padding_scheduler(
        &mut self,
        cid: CircuitId,
        scheduler: std::sync::Arc<dyn crate::padding::PaddingScheduler>,
    ) -> bool {
        if let Some(oc) = self.origins.get_mut(&cid) {
            oc.padding_scheduler = scheduler;
            true
        } else {
            false
        }
    }

    /// Drop circuits that haven't seen activity in
    /// `CIRCUIT_IDLE_TIMEOUT`. Returns the count evicted, for logging.
    ///
    /// Evicts both origin circuits and relay circuits independently —
    /// each type has its own `last_activity` timestamp. Stream state
    /// attached to evicted circuits is dropped along with the circuit
    /// (Arc<StreamMux> drops to zero refcount). Any pending handshakes
    /// (`OriginCircuit.pending`) are also dropped, which is the right
    /// semantics: if an ntor reply didn't arrive in 1 hour, the peer
    /// is unreachable.
    ///
    /// Also cleans up associated rendezvous state for the evicted
    /// circuits (pending_rendezvous, intro_circuits) so adversaries
    /// can't exhaust the server by spraying half-built circuits.
    pub fn evict_idle_circuits(&mut self) -> (usize, usize) {
        let now = std::time::Instant::now();
        let timeout = crate::circuit::CIRCUIT_IDLE_TIMEOUT;

        let dead_origins: Vec<CircuitId> = self.origins.iter()
            .filter(|(_, c)| now.duration_since(c.last_activity) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for cid in &dead_origins {
            self.origins.remove(cid);
            // Clean up rendezvous state keyed by this cid
            self.intro_circuits.retain(|_, v| v != cid);
            self.pending_rendezvous.retain(|_, (rp_cid, _, _, _)| rp_cid != cid);
            self.e2e_keys.remove(cid);
        }

        let dead_relays: Vec<(PeerId, CircuitId)> = self.relays.iter()
            .filter(|(_, rc)| now.duration_since(rc.last_activity) > timeout)
            .map(|(key, _)| *key)
            .collect();

        for key in &dead_relays {
            if let Some(rc) = self.relays.remove(key) {
                if let (Some(np), Some(nc)) = (rc.next_peer, rc.next_circ_id) {
                    self.relay_by_next.remove(&(np, nc));
                }
            }
            // Also clear intro_registered pointing at this relay circuit
            self.intro_registered.retain(|(p, c), _| (*p, *c) != *key);
            // Rendezvous cookies that point at this (peer, cid) are stale
            self.rendezvous_cookies.retain(|_, (p, c)| (*p, *c) != *key);
            // Tear down any rendezvous bridge this leg was part of.
            self.unbridge_rendezvous(*key);
        }

        (dead_origins.len(), dead_relays.len())
    }

    // ── Origin side ───────────────────────────────────────────────────

    /// Begin a new circuit to `guard`. Returns the allocated circ_id
    /// and the 512-byte CREATE cell to send over the connection to guard.
    pub fn start_circuit(
        &mut self,
        guard_peer: PeerId,
        guard_id:   &[u8; 32],
        guard_b:    &[u8; 32],
    ) -> Result<(CircuitId, [u8; crate::circuit::CELL_SIZE])> {
        let cid = self.fresh_origin_id();
        let mut c = OriginCircuit::new(cid, guard_peer);

        let (hs, client_msg) = ntor::client_handshake_start(guard_id, guard_b);
        c.pending = Some(hs);
        self.origins.insert(cid, c);

        let cell = Cell::with_payload(cid, CellCommand::Create, &client_msg)?;
        Ok((cid, cell.to_bytes()))
    }

    /// Handle a CREATED cell arriving from the guard (for the circuit
    /// we just started). Installs the hop state.
    pub fn handle_created(
        &mut self,
        cid:           CircuitId,
        server_reply:  &[u8; SERVER_HANDSHAKE_LEN],
    ) -> Result<()> {
        let c = self.origins.get_mut(&cid)
            .ok_or_else(|| Error::Handshake(format!("unknown origin circ {cid:?}")))?;
        let hs = c.pending.take()
            .ok_or_else(|| Error::Handshake("no pending handshake".into()))?;

        let keys = ntor::client_handshake_finish(hs, server_reply)?;
        c.hops.push(HopState::from_ntor(&keys));
        Ok(())
    }

    /// Build a RELAY_EARLY cell that extends the given circuit to the
    /// next hop. Caller sends the returned bytes over the guard connection.
    pub fn extend_circuit(
        &mut self,
        cid:       CircuitId,
        next:      LinkSpec,
    ) -> Result<[u8; crate::circuit::CELL_SIZE]> {
        let c = self.origins.get_mut(&cid)
            .ok_or_else(|| Error::Handshake("extend: unknown circ".into()))?;
        if c.hops.is_empty() {
            return Err(Error::Handshake("extend: circuit has no hops".into()));
        }
        if c.relay_early_used >= crate::circuit::MAX_RELAY_EARLY {
            return Err(Error::Handshake("extend: RELAY_EARLY budget exhausted".into()));
        }

        // Start ntor handshake aimed at `next`. The third arg is the
        // x25519 static public key of the target hop — receiver
        // validates B against its own static pub.
        let (hs, client_msg) = ntor::client_handshake_start(&next.node_id, &next.static_pub);
        c.pending = Some(hs);

        let terminal = c.hops.len() - 1; // innermost hop for encryption
        let extend2  = build_extend2(&next, &client_msg);
        let relay    = RelayCell::new(RelayCommand::Extend2, 0, extend2)?;

        let payload  = c.encrypt_outbound(terminal, relay)?;
        c.relay_early_used += 1;

        let cell = Cell { circ_id: cid, command: CellCommand::RelayEarly, payload };
        Ok(cell.to_bytes())
    }

    /// Handle any RELAY or RELAY_EARLY cell arriving on an origin
    /// circuit. Unwinds layered encryption, identifies which hop
    /// originated the cell, and returns the parsed relay cell plus the
    /// hop index. If the cell is a RELAY_EXTENDED2, this call
    /// automatically finishes the pending ntor handshake and appends
    /// the new hop; in that case it returns `None`.
    pub fn handle_origin_relay(
        &mut self,
        cid:     CircuitId,
        payload: &[u8; CELL_PAYLOAD],
    ) -> Result<Option<(usize, RelayCell)>> {
        let c = self.origins.get_mut(&cid)
            .ok_or_else(|| Error::Handshake("relay: unknown circ".into()))?;

        let (hop_idx, rc) = c.decrypt_inbound(payload)
            .ok_or_else(|| Error::AuthFailed)?;

        if rc.command == RelayCommand::Extended2 {
            let reply_bytes = parse_extended2(&rc.data)?;
            if reply_bytes.len() != SERVER_HANDSHAKE_LEN {
                return Err(Error::Handshake("extended2: wrong reply length".into()));
            }
            let hs = c.pending.take()
                .ok_or_else(|| Error::Handshake("extended2: no pending ntor".into()))?;
            let mut reply = [0u8; SERVER_HANDSHAKE_LEN];
            reply.copy_from_slice(&reply_bytes);
            let keys = ntor::client_handshake_finish(hs, &reply)?;
            c.hops.push(HopState::from_ntor(&keys));
            return Ok(None);
        }

        Ok(Some((hop_idx, rc)))
    }

    // ── Relay side ────────────────────────────────────────────────────

    /// A peer sent us a CREATE cell. Run ntor server-side and return
    /// the CREATED reply cell to send back. We now own one end of a
    /// new relay circuit, but we don't know where it extends yet —
    /// that comes in a subsequent EXTEND2.
    pub fn handle_create(
        &mut self,
        from_peer:       PeerId,
        cid:             CircuitId,
        my_id:           &[u8; 32],
        my_b_pub:        &[u8; 32],
        my_b_sec:        &x25519_dalek::StaticSecret,
        client_msg:      &[u8; CLIENT_HANDSHAKE_LEN],
    ) -> Result<[u8; crate::circuit::CELL_SIZE]> {
        let (keys, reply) = ntor::server_handshake(my_id, my_b_pub, my_b_sec, client_msg)?;
        let hop = HopState::from_ntor(&keys);

        let rc = RelayCircuit {
            prev_peer:         from_peer,
            prev_circ_id:      cid,
            next_peer:         None,
            next_circ_id:      None,
            hop,
            awaiting_extended: false,
            exit_streams:      std::sync::Arc::new(crate::stream::StreamMux::new()),
            cc:                          crate::congestion::Vegas::new(),
            circ_delivered_since_sendme: 0,
            last_activity:               std::time::Instant::now(),
        };
        self.relays.insert((from_peer, cid), rc);

        let cell = Cell::with_payload(cid, CellCommand::Created, &reply)?;
        Ok(cell.to_bytes())
    }

    /// A forward RELAY cell arrived from the previous hop. Peel our
    /// layer and decide what to do.
    ///
    /// Returns one of:
    /// * `RelayAction::Handle(RelayCell)` — recognized at us; caller
    ///   handles it (usually EXTEND2).
    /// * `RelayAction::ForwardForward(next_peer, next_cid, cell_bytes)`
    ///   — pass to next hop (layer already peeled).
    /// * `RelayAction::Drop` — couldn't decrypt or no next hop; drop silently.
    pub fn handle_forward_relay(
        &mut self,
        from_peer: PeerId,
        cid:       CircuitId,
        cell:      Cell,
    ) -> RelayAction {
        let key = (from_peer, cid);
        let rc = match self.relays.get_mut(&key) {
            Some(r) => r,
            None    => return RelayAction::Drop,
        };

        let mut payload = cell.payload;
        onion_decrypt_forward(&mut rc.hop, &mut payload);
        rc.last_activity = std::time::Instant::now();

        if let Ok(relay) = RelayCell::from_payload(&payload) {
            if relay.is_recognized_at(&payload, &rc.hop.forward_digest) {
                // Advance the digest state.
                let mut tmp = payload;
                tmp[5] = 0; tmp[6] = 0; tmp[7] = 0; tmp[8] = 0;
                rc.hop.forward_digest.update(&tmp);
                return RelayAction::Handle(relay);
            }
        }

        // Not for us — forward to next hop, if we have one.
        match (rc.next_peer, rc.next_circ_id) {
            (Some(np), Some(ncid)) => {
                let fwd = Cell { circ_id: ncid, command: cell.command, payload };
                RelayAction::Forward(np, fwd.to_bytes())
            }
            _ => {
                // No onward hop. If this circuit is one leg of a
                // rendezvous bridge, the (now hop-peeled but still
                // e2e-encrypted) payload is an end-to-end cell destined
                // for the partner leg. Re-wrap it with the partner leg's
                // backward layer and forward toward that leg's origin.
                // `payload` here has already had our forward layer peeled
                // exactly once by the code above — so we must NOT peel
                // again (doing so was a bug that corrupted the cell).
                let arriving = (from_peer, cid);
                if let Some(partner) = self.rendezvous_bridges.get(&arriving).copied() {
                    if let Some(prc) = self.relays.get_mut(&partner) {
                        onion_encrypt_backward(&mut prc.hop, &mut payload);
                        prc.last_activity = std::time::Instant::now();
                        let out = Cell {
                            circ_id: prc.prev_circ_id,
                            command: cell.command,
                            payload,
                        };
                        return RelayAction::Forward(prc.prev_peer, out.to_bytes());
                    }
                }
                RelayAction::Drop
            }
        }
    }

    /// Invoked by the caller once `handle_forward_relay` returned
    /// `Handle(cell)` and the cell is an EXTEND2. The caller supplies
    /// the next-hop peer connection (after opening it if needed) and
    /// a fresh circuit ID to use on that connection. Returns the
    /// CREATE cell bytes to send to the next hop.
    pub fn begin_extend(
        &mut self,
        from_peer:    PeerId,
        prev_cid:     CircuitId,
        next_peer:    PeerId,
        next_cid:     CircuitId,
        extend_data:  &[u8],
    ) -> Result<[u8; crate::circuit::CELL_SIZE]> {
        let key = (from_peer, prev_cid);
        let rc = self.relays.get_mut(&key)
            .ok_or_else(|| Error::Handshake("begin_extend: unknown circ".into()))?;
        if rc.next_peer.is_some() {
            return Err(Error::Handshake("begin_extend: already extended".into()));
        }

        let (_link, client_msg) = parse_extend2(extend_data)?;
        if client_msg.len() != CLIENT_HANDSHAKE_LEN {
            return Err(Error::Handshake("extend2: wrong hdata length".into()));
        }

        rc.next_peer         = Some(next_peer);
        rc.next_circ_id      = Some(next_cid);
        rc.awaiting_extended = true;
        self.relay_by_next.insert((next_peer, next_cid), key);

        let cell = Cell::with_payload(next_cid, CellCommand::Create, &client_msg)?;
        Ok(cell.to_bytes())
    }

    /// Called when a CREATED arrives from the next hop on a circuit
    /// we're extending. Wraps the reply as RELAY_EXTENDED2 and sends
    /// it back toward the originator.
    pub fn handle_created_from_next(
        &mut self,
        from_next: PeerId,
        next_cid:  CircuitId,
        reply:     &[u8; SERVER_HANDSHAKE_LEN],
    ) -> Result<(PeerId, [u8; crate::circuit::CELL_SIZE])> {
        let prev_key = *self.relay_by_next.get(&(from_next, next_cid))
            .ok_or_else(|| Error::Handshake("created_from_next: no matching relay".into()))?;
        let rc = self.relays.get_mut(&prev_key)
            .ok_or_else(|| Error::Handshake("created_from_next: gone".into()))?;
        if !rc.awaiting_extended {
            return Err(Error::Handshake("created_from_next: not expecting".into()));
        }
        rc.awaiting_extended = false;

        let extended_data = build_extended2(reply);
        let mut relay     = RelayCell::new(RelayCommand::Extended2, 0, extended_data)?;
        relay.stamp_digest(&mut rc.hop.backward_digest);
        let mut payload   = relay.to_payload();
        onion_encrypt_backward(&mut rc.hop, &mut payload);

        let cell = Cell { circ_id: rc.prev_circ_id, command: CellCommand::Relay, payload };
        Ok((rc.prev_peer, cell.to_bytes()))
    }

    /// Backward RELAY cell from next hop. Add our backward layer and
    /// forward toward the client.
    pub fn handle_backward_relay(
        &mut self,
        from_next: PeerId,
        next_cid:  CircuitId,
        cell:      Cell,
    ) -> Option<(PeerId, [u8; crate::circuit::CELL_SIZE])> {
        let prev_key = *self.relay_by_next.get(&(from_next, next_cid))?;
        let rc       = self.relays.get_mut(&prev_key)?;
        let mut payload = cell.payload;
        onion_encrypt_backward(&mut rc.hop, &mut payload);
        let fwd = Cell { circ_id: rc.prev_circ_id, command: cell.command, payload };
        Some((rc.prev_peer, fwd.to_bytes()))
    }

    pub fn destroy(&mut self, from_peer: PeerId, cid: CircuitId) {
        if let Some(rc) = self.relays.remove(&(from_peer, cid)) {
            if let (Some(np), Some(ncid)) = (rc.next_peer, rc.next_circ_id) {
                self.relay_by_next.remove(&(np, ncid));
            }
        }
        // Remove any rendezvous bridge this leg participated in. The
        // partner is left registered as an origin/relay; the caller
        // (node dispatch) is responsible for forwarding a DESTROY to it.
        self.unbridge_rendezvous((from_peer, cid));
        self.origins.remove(&cid);
        self.e2e_keys.remove(&cid);
        self.intro_circuits.retain(|_, c| *c != cid);
        self.intro_registered.remove(&(from_peer, cid));
    }

    // ── Rendezvous: HS side ───────────────────────────────────────────

    /// Register an existing origin circuit as an introduction point
    /// for a hidden service we operate. The `auth_key_pub` is what we
    /// publish in our descriptor; clients reference it in INTRODUCE1.
    pub fn register_intro_circuit(&mut self, cid: CircuitId, auth_key_pub: [u8; 32]) {
        self.intro_circuits.insert(auth_key_pub, cid);
    }

    /// When we (as an intro relay) receive ESTABLISH_INTRO on a relay
    /// circuit, we record the auth_key so we can match later
    /// INTRODUCE1s and forward them to the HS on this same circuit.
    pub fn register_intro_relay(
        &mut self,
        from_peer: PeerId,
        cid: CircuitId,
        auth_key_pub: [u8; 32],
    ) {
        self.intro_registered.insert((from_peer, cid), auth_key_pub);
    }

    /// When an INTRODUCE1 arrives at an intro-relay, look up where to
    /// forward it. Returns the circuit that leads to the HS (the
    /// circuit the HS originally used to ESTABLISH_INTRO with us).
    pub fn find_intro_target(&self, auth_key_pub: &[u8; 32]) -> Option<(PeerId, CircuitId)> {
        // Scan registered intros for a matching auth key
        self.intro_registered.iter()
            .find(|(_, k)| *k == auth_key_pub)
            .map(|(key, _)| *key)
    }

    // ── Rendezvous: RP side ───────────────────────────────────────────

    /// Store a cookie for future splicing. Called when
    /// ESTABLISH_RENDEZVOUS arrives on a client-built relay circuit.
    pub fn register_rendezvous_cookie(
        &mut self,
        cookie: [u8; 20],
        client_peer: PeerId,
        client_cid: CircuitId,
    ) {
        self.rendezvous_cookies.insert(cookie, (client_peer, client_cid));
    }

    /// When RENDEZVOUS1 arrives, look up the cookie and return the
    /// client circuit to splice to. Cookie is consumed (removed from
    /// the map) — each cookie is single-use.
    pub fn consume_rendezvous_cookie(
        &mut self,
        cookie: &[u8; 20],
    ) -> Option<(PeerId, CircuitId)> {
        self.rendezvous_cookies.remove(cookie)
    }

    /// Establish a durable bidirectional data bridge between the client
    /// leg and the HS leg at this RP. Called right after RENDEZVOUS1 is
    /// matched to a cookie: we've already spliced RENDEZVOUS2 back to
    /// the client, and from here on both sides send end-to-end DATA
    /// cells that we forward blindly. Inserting both directions lets a
    /// cell arriving on either leg find its partner in one lookup.
    ///
    /// `client_leg` is the (client_peer, client_cid) recovered from the
    /// cookie; `hs_leg` is the (hs_peer, hs_cid) the RENDEZVOUS1 arrived
    /// on. Idempotent: re-bridging the same pair just overwrites.
    pub fn bridge_rendezvous(
        &mut self,
        client_leg: (PeerId, CircuitId),
        hs_leg:     (PeerId, CircuitId),
    ) {
        self.rendezvous_bridges.insert(client_leg, hs_leg);
        self.rendezvous_bridges.insert(hs_leg, client_leg);
    }

    /// Is `(peer, cid)` one leg of an active rendezvous bridge? Used by
    /// the dispatch loop to decide, when a forward relay cell isn't
    /// recognized at our hop, whether to blind-forward it across the
    /// bridge rather than dropping it.
    pub fn bridge_partner(
        &self,
        leg: (PeerId, CircuitId),
    ) -> Option<(PeerId, CircuitId)> {
        self.rendezvous_bridges.get(&leg).copied()
    }

    /// Tear down a rendezvous bridge, removing both directions. Called
    /// when either leg is destroyed or the RP circuit is reaped, so a
    /// DESTROY on one side propagates to freeing the pairing (the
    /// caller is responsible for forwarding DESTROY to the partner if
    /// desired). Returns the partner leg that was bridged, if any, so
    /// the caller can propagate teardown.
    pub fn unbridge_rendezvous(
        &mut self,
        leg: (PeerId, CircuitId),
    ) -> Option<(PeerId, CircuitId)> {
        if let Some(partner) = self.rendezvous_bridges.remove(&leg) {
            self.rendezvous_bridges.remove(&partner);
            Some(partner)
        } else {
            None
        }
    }

    // ── Rendezvous: Client side ───────────────────────────────────────

    /// Client side: register a built rendezvous circuit waiting for
    /// RENDEZVOUS2 to arrive with the HS's ephemeral Y and AUTH.
    /// `hs_static_pub` comes from the descriptor the client fetched;
    /// it's needed to verify the AUTH tag when RENDEZVOUS2 arrives.
    pub fn register_pending_rendezvous(
        &mut self,
        cookie: [u8; 20],
        cid: CircuitId,
        client_sk: x25519_dalek::StaticSecret,
        client_x_pub: [u8; 32],
        hs_static_pub: [u8; 32],
    ) {
        self.pending_rendezvous.insert(cookie, (cid, client_sk, client_x_pub, hs_static_pub));
    }

    /// Client side: on RENDEZVOUS2 arrival, complete the e2e handshake.
    /// Uses the HS static key stashed at registration time to verify
    /// AUTH; installs e2e keys on success and returns the circ_id.
    /// The cookie is always consumed regardless of success, preventing
    /// any retry-based attack by the RP.
    pub fn complete_rendezvous(
        &mut self,
        cookie: &[u8; 20],
        server_y: &[u8; 32],
        auth: &[u8; crate::rendezvous::HS_AUTH_LEN],
    ) -> Result<CircuitId> {
        let (cid, client_sk, client_x_pub, hs_b_pub) = self.pending_rendezvous.remove(cookie)
            .ok_or_else(|| Error::Handshake("no pending rendezvous for cookie".into()))?;

        let keys = crate::rendezvous::client_finalize(
            &client_sk, &client_x_pub, &hs_b_pub, server_y, auth)?;
        // Materialize the innermost e2e layer onto the RP origin circuit
        // (client orientation) so stream cells encrypt end-to-end to the
        // HS. Keep the keys in the map too for lookup/back-compat.
        if let Some(oc) = self.origins.get_mut(&cid) {
            oc.e2e = Some(crate::circuit::HopState::from_e2e_keys(&keys, true));
        }
        self.e2e_keys.insert(cid, keys);
        Ok(cid)
    }
}

/// Return value of `handle_forward_relay`.
pub enum RelayAction {
    Handle(RelayCell),
    Forward(PeerId, [u8; crate::circuit::CELL_SIZE]),
    Drop,
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;

    fn server_keys() -> ([u8; 32], [u8; 32], StaticSecret) {
        let sec = StaticSecret::random_from_rng(OsRng);
        let pub_ = *PublicKey::from(&sec).as_bytes();
        (pub_, pub_, sec)
    }

    /// Two nodes: client (A) + guard (B). A builds 1-hop circuit to B
    /// via CREATE/CREATED, and the derived keys match on both sides.
    #[test]
    fn two_peers_create_created() {
        let mut client = CircuitManager::new();
        let mut guard  = CircuitManager::new();

        let (b_id, b_pub, b_sec) = server_keys();
        let peer_a: PeerId = [0xAAu8; 32];
        let peer_b: PeerId = b_id;

        // A: start circuit to B
        let (cid, create_bytes) = client.start_circuit(peer_b, &b_id, &b_pub).unwrap();
        let create_cell         = Cell::from_bytes(&create_bytes).unwrap();
        assert_eq!(create_cell.command, CellCommand::Create);
        assert_eq!(create_cell.circ_id, cid);

        // B: handle CREATE
        let mut cmsg = [0u8; CLIENT_HANDSHAKE_LEN];
        cmsg.copy_from_slice(&create_cell.payload[..CLIENT_HANDSHAKE_LEN]);
        let created_bytes = guard
            .handle_create(peer_a, cid, &b_id, &b_pub, &b_sec, &cmsg)
            .unwrap();
        let created_cell  = Cell::from_bytes(&created_bytes).unwrap();
        assert_eq!(created_cell.command, CellCommand::Created);

        // A: finish
        let mut reply = [0u8; SERVER_HANDSHAKE_LEN];
        reply.copy_from_slice(&created_cell.payload[..SERVER_HANDSHAKE_LEN]);
        client.handle_created(cid, &reply).unwrap();

        // Both sides should have matching keys
        let a_hop = &client.origins[&cid].hops[0];
        let b_hop = &guard.relays[&(peer_a, cid)].hop;
        assert_eq!(a_hop.forward_key,  b_hop.forward_key);
        assert_eq!(a_hop.backward_key, b_hop.backward_key);
    }

    /// Three-peer flow: A builds a 2-hop circuit through B to C by
    /// sending RELAY_EXTEND2 via B. Then A uses the circuit to send
    /// an onion-encrypted cell that decrypts correctly at C.
    #[test]
    fn three_peers_extend2() {
        let mut ca = CircuitManager::new();
        let mut cb = CircuitManager::new();
        let mut cc = CircuitManager::new();

        let (b_id, b_pub, b_sec) = server_keys();
        let (c_id, c_pub, c_sec) = server_keys();
        let peer_a: PeerId = [0xAAu8; 32];

        // ── Step 1: A ⇄ B create ──────────────────────────────────────
        let (cid_ab, bytes) = ca.start_circuit(b_id, &b_id, &b_pub).unwrap();
        let create          = Cell::from_bytes(&bytes).unwrap();

        let mut cmsg = [0u8; CLIENT_HANDSHAKE_LEN];
        cmsg.copy_from_slice(&create.payload[..CLIENT_HANDSHAKE_LEN]);
        let created_bytes = cb.handle_create(peer_a, cid_ab, &b_id, &b_pub, &b_sec, &cmsg).unwrap();
        let created       = Cell::from_bytes(&created_bytes).unwrap();

        let mut reply = [0u8; SERVER_HANDSHAKE_LEN];
        reply.copy_from_slice(&created.payload[..SERVER_HANDSHAKE_LEN]);
        ca.handle_created(cid_ab, &reply).unwrap();

        // ── Step 2: A sends EXTEND2 via B to C ────────────────────────
        let next = LinkSpec {
            host:       "127.0.0.1".into(),
            port:       7700,
            node_id:    c_id,
            static_pub: c_pub,
        };
        let extend_cell_bytes = ca.extend_circuit(cid_ab, next.clone()).unwrap();
        let extend_cell       = Cell::from_bytes(&extend_cell_bytes).unwrap();
        assert_eq!(extend_cell.command, CellCommand::RelayEarly);

        // B: peel forward layer on cell
        let action = cb.handle_forward_relay(peer_a, cid_ab, extend_cell);
        let relay = match action {
            RelayAction::Handle(rc) => rc,
            _ => panic!("expected EXTEND2 recognized at B"),
        };
        assert_eq!(relay.command, RelayCommand::Extend2);

        // B: begin_extend to C with a new circ_id on its B↔C connection
        let cid_bc = CircuitId(0xDEAD_BEEF);
        let create_bc_bytes = cb.begin_extend(peer_a, cid_ab, c_id, cid_bc, &relay.data).unwrap();
        let create_bc       = Cell::from_bytes(&create_bc_bytes).unwrap();
        assert_eq!(create_bc.command, CellCommand::Create);
        assert_eq!(create_bc.circ_id, cid_bc);

        // C: handle CREATE from B
        let mut cmsg_c = [0u8; CLIENT_HANDSHAKE_LEN];
        cmsg_c.copy_from_slice(&create_bc.payload[..CLIENT_HANDSHAKE_LEN]);
        let created_bc_bytes = cc.handle_create(b_id, cid_bc, &c_id, &c_pub, &c_sec, &cmsg_c).unwrap();
        let created_bc       = Cell::from_bytes(&created_bc_bytes).unwrap();

        // B: receives CREATED from C, wraps as RELAY_EXTENDED2 for A
        let mut reply_bc = [0u8; SERVER_HANDSHAKE_LEN];
        reply_bc.copy_from_slice(&created_bc.payload[..SERVER_HANDSHAKE_LEN]);
        let (target_a, extended_bytes) = cb.handle_created_from_next(c_id, cid_bc, &reply_bc).unwrap();
        assert_eq!(target_a, peer_a);

        // A: parse RELAY_EXTENDED2 — this internally finishes ntor
        let extended = Cell::from_bytes(&extended_bytes).unwrap();
        let res      = ca.handle_origin_relay(cid_ab, &extended.payload).unwrap();
        assert!(res.is_none(), "EXTEND flow consumed internally");

        // Now A has 2 hops
        assert_eq!(ca.origins[&cid_ab].hops.len(), 2);

        // Both sides should have matching keys at hop 1 (the C hop)
        let a_hop_c = &ca.origins[&cid_ab].hops[1];
        let c_hop   = &cc.relays[&(b_id, cid_bc)].hop;
        assert_eq!(a_hop_c.forward_key,  c_hop.forward_key);
        assert_eq!(a_hop_c.backward_key, c_hop.backward_key);
    }

    // ── Rendezvous state-machine tests ────────────────────────────────

    #[test]
    fn rp_cookie_register_and_consume() {
        let mut mgr = CircuitManager::new();
        let cookie = [0xAAu8; 20];
        let client_peer = [0xBBu8; 32];
        let client_cid  = CircuitId(42);

        mgr.register_rendezvous_cookie(cookie, client_peer, client_cid);
        assert_eq!(mgr.rendezvous_cookies.len(), 1);

        // First consume succeeds
        let got = mgr.consume_rendezvous_cookie(&cookie);
        assert_eq!(got, Some((client_peer, client_cid)));

        // Second consume returns None (single-use)
        assert_eq!(mgr.consume_rendezvous_cookie(&cookie), None);
        assert_eq!(mgr.rendezvous_cookies.len(), 0);
    }

    #[test]
    fn intro_registration_lookup() {
        let mut mgr = CircuitManager::new();
        let auth_key = [0xCCu8; 32];
        let from_peer = [0xDDu8; 32];
        let cid = CircuitId(99);

        mgr.register_intro_relay(from_peer, cid, auth_key);
        let found = mgr.find_intro_target(&auth_key);
        assert_eq!(found, Some((from_peer, cid)));

        let missing = mgr.find_intro_target(&[0xEEu8; 32]);
        assert_eq!(missing, None);
    }

    #[test]
    fn client_rendezvous_completion() {
        use crate::rendezvous;
        use x25519_dalek::{PublicKey, StaticSecret};
        use rand::rngs::OsRng;

        // HS identity
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();

        // Client side: build a rendezvous circuit (simulated), register cookie
        let mut mgr = CircuitManager::new();
        let cid = CircuitId(0x1234);
        let cookie = rendezvous::fresh_cookie();

        // Client builds its own ephemeral for the e2e handshake
        let client_sk = StaticSecret::random_from_rng(OsRng);
        let client_pub = *PublicKey::from(&client_sk).as_bytes();

        mgr.register_pending_rendezvous(cookie, cid, client_sk, client_pub, hs_pub);
        assert_eq!(mgr.pending_rendezvous.len(), 1);

        // HS side: run finalize with same client_pub
        let (_hs_keys, y_pub, auth) = rendezvous::hs_finalize(
            &hs_sec, &hs_pub, &client_pub);

        // Client completes via CircuitManager
        let completed_cid = mgr.complete_rendezvous(&cookie, &y_pub, &auth).unwrap();
        assert_eq!(completed_cid, cid);

        // Keys installed
        assert!(mgr.e2e_keys.contains_key(&cid));
        // Cookie consumed
        assert!(!mgr.pending_rendezvous.contains_key(&cookie));
    }

    /// End-to-end layer round-trip: a DATA cell the client encrypts for
    /// the HS (one path hop + innermost e2e layer) must be recovered by
    /// the HS after it peels the hop layer and the e2e layer, and the
    /// reverse direction must work too. This proves the orientation
    /// logic in `HopState::from_e2e_keys` and the innermost layering in
    /// `encrypt_outbound`/`decrypt_inbound` — independent of the RP
    /// forwarding path, which is exercised at the node level.
    #[test]
    fn e2e_layer_roundtrip_through_one_hop() {
        use crate::rendezvous;
        use crate::circuit::{HopState, RelayCell, RelayCommand,
            onion_decrypt_forward, onion_encrypt_backward};
        use crate::ntor::NtorKeys;
        use x25519_dalek::{PublicKey, StaticSecret};
        use rand::rngs::OsRng;
        use zeroize::Zeroizing;

        // ── Matching e2e keys on both ends (as after a real rendezvous) ──
        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();
        let client_sk = StaticSecret::random_from_rng(OsRng);
        let client_x  = *PublicKey::from(&client_sk).as_bytes();
        let (hs_keys, y_pub, auth) = rendezvous::hs_finalize(&hs_sec, &hs_pub, &client_x);
        let client_keys = rendezvous::client_finalize(
            &client_sk, &client_x, &hs_pub, &y_pub, &auth).unwrap();

        // ── One shared path hop (the RP, from the client's view). Both
        //    ends share the same symmetric hop key; the RP just relays. ──
        let hop_keys = NtorKeys {
            forward_digest_seed:  [7u8; 20],
            backward_digest_seed: [9u8; 20],
            forward_key:          Zeroizing::new([3u8; 32]),
            backward_key:         Zeroizing::new([5u8; 32]),
        };

        // Client origin circuit: 1 hop + client-oriented e2e layer.
        let mut client_oc = OriginCircuit::new(CircuitId(1), [0xAA; 32]);
        client_oc.hops.push(HopState::from_ntor(&hop_keys));
        client_oc.e2e = Some(HopState::from_e2e_keys(&client_keys, true));

        // HS side: its own HS-oriented e2e layer.
        let mut hs_e2e = HopState::from_e2e_keys(&hs_keys, false);
        // The RP holds its *own* hop state (independent nonce counters
        // from the client's copy). It uses the forward counter to peel
        // client→HS cells and the backward counter to wrap HS→client
        // cells. Model it separately so we don't accidentally advance
        // the client's hop nonce here.
        let mut rp_hop = HopState::from_ntor(&hop_keys);

        // ── Forward: client → HS ──────────────────────────────────────
        let msg = b"GET / HTTP/1.1\r\nHost: hs\r\n\r\n".to_vec();
        let relay = RelayCell::new(RelayCommand::Data, 0, msg.clone()).unwrap();
        let cell = client_oc.encrypt_outbound(0, relay).unwrap();

        // RP peels its single forward layer and forwards the opaque
        // remainder to the HS. The HS *receives* on client→HS, which in
        // its relative HopState naming is the e2e BACKWARD direction
        // (forward = "what the HS sends" = hs→client). So it peels with
        // the e2e backward layer and recognizes with the backward digest.
        let mut p = cell;
        onion_decrypt_forward(&mut rp_hop, &mut p);   // RP's hop layer (its own copy)
        crate::circuit::onion_decrypt_backward(&mut hs_e2e, &mut p); // e2e recv at HS
        let recovered = RelayCell::from_payload(&p).unwrap();
        assert!(recovered.is_recognized_at(&p, &hs_e2e.backward_digest),
            "HS must recognize the client's e2e DATA cell");
        assert_eq!(recovered.command, RelayCommand::Data);
        assert_eq!(recovered.data, msg);
        // Advance HS e2e backward digest to mirror consumption.
        { let mut t = p; t[5]=0; t[6]=0; t[7]=0; t[8]=0; hs_e2e.backward_digest.update(&t); }

        // ── Backward: HS → client ─────────────────────────────────────
        // The HS *sends* on hs→client = its e2e FORWARD direction; the
        // client peels that as its e2e BACKWARD (via decrypt_inbound).
        let reply = b"HTTP/1.1 200 OK\r\n\r\nhi".to_vec();
        let mut br = RelayCell::new(RelayCommand::Data, 0, reply.clone()).unwrap();
        br.stamp_digest(&mut hs_e2e.forward_digest);
        let mut bp = br.to_payload();
        crate::circuit::onion_encrypt_forward(&mut hs_e2e, &mut bp); // e2e send at HS
        onion_encrypt_backward(&mut rp_hop, &mut bp);                // RP wraps (its copy)

        // Client peels: hop backward (no recognition) then e2e backward.
        let out = client_oc.decrypt_inbound(&bp);
        let (idx, rc) = out.expect("client must recover HS reply via e2e layer");
        assert_eq!(idx, usize::MAX, "recognized at the e2e layer, not a path hop");
        assert_eq!(rc.command, RelayCommand::Data);
        assert_eq!(rc.data, reply);
    }

    #[test]
    fn rendezvous_auth_tamper_rejected() {
        use crate::rendezvous;
        use x25519_dalek::{PublicKey, StaticSecret};
        use rand::rngs::OsRng;

        let hs_sec = StaticSecret::random_from_rng(OsRng);
        let hs_pub = *PublicKey::from(&hs_sec).as_bytes();

        let mut mgr = CircuitManager::new();
        let cid = CircuitId(0xABCD);
        let cookie = rendezvous::fresh_cookie();
        let client_sk = StaticSecret::random_from_rng(OsRng);
        let client_pub = *PublicKey::from(&client_sk).as_bytes();
        mgr.register_pending_rendezvous(cookie, cid, client_sk, client_pub, hs_pub);

        let (_hs_keys, y_pub, mut auth) = rendezvous::hs_finalize(
            &hs_sec, &hs_pub, &client_pub);
        auth[0] ^= 0x01; // tamper

        let res = mgr.complete_rendezvous(&cookie, &y_pub, &auth);
        assert!(res.is_err(), "tampered AUTH must be rejected");
        // Cookie still consumed (prevents retry attack)
        assert!(!mgr.pending_rendezvous.contains_key(&cookie));
    }

    #[test]
    fn destroy_cleans_rendezvous_state() {
        let mut mgr = CircuitManager::new();
        let cid = CircuitId(0xFF);
        let peer = [0x42u8; 32];

        mgr.register_intro_relay(peer, cid, [0xAA; 32]);
        mgr.register_intro_circuit(cid, [0xBB; 32]);
        assert_eq!(mgr.intro_registered.len(), 1);
        assert_eq!(mgr.intro_circuits.len(), 1);

        mgr.destroy(peer, cid);
        assert_eq!(mgr.intro_registered.len(), 0);
        assert_eq!(mgr.intro_circuits.len(), 0);
    }

    // ── Circuit-level flow control ───────────────────────────────────

    #[test]
    fn origin_circuit_starts_at_init_cwnd() {
        let c = OriginCircuit::new(CircuitId(1), [0u8; 32]);
        assert_eq!(c.cc.cwnd(), crate::congestion::CC_CWND_INIT);
        assert_eq!(c.cc.inflight(), 0);
        assert_eq!(c.circ_delivered_since_sendme, 0);
    }

    #[test]
    fn circ_window_drains_with_each_cell() {
        let mut c = OriginCircuit::new(CircuitId(1), [0u8; 32]);
        for _ in 0..5 {
            c.try_consume_circ_window().unwrap();
        }
        // Each consumed cell is now in flight against the cwnd.
        assert_eq!(c.cc.inflight(), 5);
    }

    #[test]
    fn circ_window_errors_when_cwnd_full() {
        let mut c = OriginCircuit::new(CircuitId(1), [0u8; 32]);
        // Fill exactly the initial congestion window.
        for _ in 0..crate::congestion::CC_CWND_INIT {
            c.try_consume_circ_window().unwrap();
        }
        // The next send exceeds cwnd with no SENDME yet → blocked.
        assert!(c.try_consume_circ_window().is_err());
    }

    #[test]
    fn circ_sendme_frees_inflight() {
        let mut c = OriginCircuit::new(CircuitId(1), [0u8; 32]);
        // Send one SENDME-increment worth of cells, then ack them.
        for _ in 0..crate::congestion::CC_SENDME_INC {
            c.try_consume_circ_window().unwrap();
        }
        assert_eq!(c.cc.inflight(), crate::congestion::CC_SENDME_INC);
        c.on_circ_sendme();
        assert_eq!(c.cc.inflight(), 0);
    }

    #[test]
    fn cwnd_is_bounded_not_inflatable_by_sendme_flood() {
        // A peer flooding SENDMEs cannot push cwnd past CC_CWND_MAX, and
        // with no matching sends the queue estimate keeps it in check —
        // the old "2× start" cap is replaced by the Vegas bound.
        let mut c = OriginCircuit::new(CircuitId(1), [0u8; 32]);
        for _ in 0..10_000 {
            c.on_circ_sendme();
        }
        assert!(c.cc.cwnd() <= crate::congestion::CC_CWND_MAX);
    }

    #[test]
    fn circ_delivered_counter_triggers_sendme_at_cc_increment() {
        let mut c = OriginCircuit::new(CircuitId(1), [0u8; 32]);
        // One below the increment: no SENDME due yet.
        for _ in 0..(crate::congestion::CC_SENDME_INC as i32 - 1) {
            assert!(!c.note_circ_delivered());
        }
        // The increment-th delivered cell triggers the SENDME signal.
        assert!(c.note_circ_delivered());

        // After reset, counter starts over.
        c.reset_circ_delivered();
        assert!(!c.note_circ_delivered());
    }

    #[test]
    fn relay_circuit_also_runs_congestion_control() {
        // Exit side gets its own independent controller.
        let hop = HopState::from_ntor(&ntor::NtorKeys {
            forward_key:  [0u8; 32].into(),
            backward_key: [0u8; 32].into(),
            forward_digest_seed:  [0u8; 20],
            backward_digest_seed: [0u8; 20],
        });
        let mut rc = RelayCircuit {
            prev_peer: [0u8; 32],
            prev_circ_id: CircuitId(1),
            next_peer: None,
            next_circ_id: None,
            hop,
            awaiting_extended: false,
            exit_streams: std::sync::Arc::new(crate::stream::StreamMux::new()),
            cc:                          crate::congestion::Vegas::new(),
            circ_delivered_since_sendme: 0,
            last_activity:               std::time::Instant::now(),
        };
        assert_eq!(rc.cc.inflight(), 0);
        rc.try_consume_circ_window().unwrap();
        assert_eq!(rc.cc.inflight(), 1);
    }

    #[test]
    fn init_cwnd_exceeds_stream_window_increment() {
        // Design property preserved under Prop 324: the circuit-level
        // controller must admit more than one stream-SENDME increment
        // of cells, so a single stream's own window is the first
        // bottleneck rather than the circuit controller.
        assert!(crate::congestion::CC_CWND_INIT as i32
                > crate::stream::STREAM_SENDME_INC,
                "initial cwnd must exceed one stream SENDME increment");
    }

    // ── Idle eviction ─────────────────────────────────────────────────

    #[test]
    fn evict_idle_circuits_keeps_fresh_ones() {
        // A freshly-touched circuit must survive an eviction pass.
        let mut mgr = CircuitManager::new();
        mgr.origins.insert(CircuitId(1), OriginCircuit::new(CircuitId(1), [0u8;32]));
        assert_eq!(mgr.origins.len(), 1);
        let (o, r) = mgr.evict_idle_circuits();
        assert_eq!(o, 0, "fresh origin must not be evicted");
        assert_eq!(r, 0);
        assert_eq!(mgr.origins.len(), 1);
    }

    #[test]
    fn evict_idle_circuits_reaps_stale_ones() {
        // Manually backdate last_activity past the timeout and verify
        // the eviction sweep removes the circuit.
        let mut mgr = CircuitManager::new();
        let mut c = OriginCircuit::new(CircuitId(42), [0u8;32]);
        c.last_activity = std::time::Instant::now()
            - crate::circuit::CIRCUIT_IDLE_TIMEOUT
            - std::time::Duration::from_secs(1);
        mgr.origins.insert(CircuitId(42), c);

        let (o, _r) = mgr.evict_idle_circuits();
        assert_eq!(o, 1, "stale origin circuit must be evicted");
        assert!(mgr.origins.is_empty());
    }

    #[test]
    fn eviction_cleans_up_rendezvous_state_for_dead_circuits() {
        // Rendezvous tables keyed by (or pointing at) an evicted
        // circuit id must not retain stale entries — otherwise a
        // long-running node's rendezvous state grows forever.
        let mut mgr = CircuitManager::new();
        let cid  = CircuitId(99);
        let peer = [0x42u8; 32];

        let mut c = OriginCircuit::new(cid, peer);
        c.last_activity = std::time::Instant::now()
            - crate::circuit::CIRCUIT_IDLE_TIMEOUT
            - std::time::Duration::from_secs(1);
        mgr.origins.insert(cid, c);
        mgr.intro_circuits.insert([0xAA; 32], cid);

        assert_eq!(mgr.intro_circuits.len(), 1);
        let (o, _r) = mgr.evict_idle_circuits();
        assert_eq!(o, 1);
        assert!(mgr.intro_circuits.is_empty(),
            "intro_circuits entry pointing at dead cid must be cleaned up");
    }

    #[test]
    fn touch_prevents_eviction() {
        // A circuit whose last_activity is stale is evicted by default.
        // After .touch() bumps it to now, eviction leaves it alone.
        let mut mgr = CircuitManager::new();
        let cid = CircuitId(7);
        let mut c = OriginCircuit::new(cid, [0u8;32]);
        c.last_activity = std::time::Instant::now()
            - crate::circuit::CIRCUIT_IDLE_TIMEOUT
            - std::time::Duration::from_secs(1);
        c.touch();  // refresh
        mgr.origins.insert(cid, c);

        let (o, _r) = mgr.evict_idle_circuits();
        assert_eq!(o, 0, "touched circuit must survive eviction");
    }
}
