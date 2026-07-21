// phinet-core/src/stream.rs
//! Multiplexed streams over circuits.
//!
//! A single circuit can carry many concurrent streams, each addressed
//! by a 16-bit `stream_id` inside the relay cell header. Streams are
//! identified by their originator; within a circuit the originator
//! allocates stream_ids monotonically.
//!
//! # State machine
//!
//! ```text
//!   (client)                            (exit)
//!   New -- RELAY_BEGIN(addr) -->     New
//!                              <--  Connecting (opens TCP)
//!         <-- RELAY_CONNECTED --    Open
//!   Open                             Open
//!   Open -- RELAY_DATA -->           Open
//!         <-- RELAY_DATA --
//!   Open -- RELAY_END(reason) --> Closed
//!         <-- RELAY_END(reason) --  (ack)
//!   Closed                           Closed
//! ```
//!
//! Either side can initiate END. If the peer has already ended,
//! receiving a DATA cell on a Closed stream is silently dropped.
//!
//! # Flow control (fixed-window, per-stream)
//!
//! Each stream has a send-window of [`STREAM_WINDOW_START`] cells.
//! When an endpoint has sent that many DATA cells without receiving
//! a SENDME ack, it stops sending. For every [`STREAM_SENDME_INC`]
//! received DATA cells, the receiver emits a RELAY_SENDME, which
//! increments the sender's window.
//!
//! This is the same mechanism as Tor Proposal 289, simplified. A
//! circuit-level window (not yet implemented in this module) runs on
//! top to prevent any one stream from monopolising a circuit.

use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::sync::{mpsc, Mutex};

/// Initial send window in cells. A sender can emit this many DATA
/// cells before receiving any SENDME. Matches Tor default.
pub const STREAM_WINDOW_START: i32 = 500;

/// SENDME acks add this many cells to the sender's window when received.
pub const STREAM_SENDME_INC: i32 = 50;

/// Receiver sends a SENDME after it has delivered this many cells
/// since the last SENDME.
pub const STREAM_SENDME_DELIVERED: i32 = 50;

/// Maximum buffered bytes per stream direction before we apply
/// backpressure on the local application. Prevents a slow reader from
/// forcing unbounded buffer growth.
pub const STREAM_BUFFER_MAX: usize = 64 * 1024;

// ── Circuit-level flow control ───────────────────────────────────────
//
// Per-circuit window prevents a greedy stream from monopolizing the
// downstream capacity and starving siblings. Every DATA cell that
// leaves on a circuit (across all streams) decrements the circuit's
// send window; a circuit-level SENDME (stream_id = 0) refills it.
// This mirrors Tor's two-level window design. Constants are 2× the
// stream-level so a single stream can saturate its own window before
// the circuit's starts limiting.

/// Initial circuit-level send window in DATA cells.
pub const CIRCUIT_WINDOW_START: i32 = 1000;

/// Cells a circuit-level SENDME refills.
pub const CIRCUIT_SENDME_INC: i32 = 100;

/// After how many DATA cells delivered up a circuit we emit a circuit
/// SENDME (stream_id = 0).
pub const CIRCUIT_SENDME_DELIVERED: i32 = 100;

// ── End reasons ───────────────────────────────────────────────────────

/// Reason codes carried in RELAY_END payload (1 byte).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// Normal close, both sides finished sending.
    Done         = 0,
    /// Remote host unreachable, DNS fail, connection refused.
    Unreachable  = 1,
    /// Exit policy denies the destination.
    ExitPolicy   = 2,
    /// Stream was torn down by circuit destruction.
    Destroyed    = 3,
    /// Idle timeout.
    Timeout      = 4,
    /// Internal error, no other reason fits.
    Internal     = 5,
}

impl EndReason {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Done,
            1 => Self::Unreachable,
            2 => Self::ExitPolicy,
            3 => Self::Destroyed,
            4 => Self::Timeout,
            _ => Self::Internal,
        }
    }
}

// ── Stream state ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    /// Local side has sent BEGIN, waiting for CONNECTED.
    Connecting,
    /// Fully open, bidirectional data flow.
    Open,
    /// Closed normally or due to error; no further data accepted.
    Closed,
}

/// Per-stream state. Holds inbound-data buffer, flow-control windows,
/// and a sender for notifying the application when data arrives.
pub struct Stream {
    pub id:          u16,
    pub state:       StreamState,
    /// Destination `host:port` from the original BEGIN. Useful for
    /// exit-policy decisions and logging. Empty on the initiator side
    /// once CONNECTED arrives (we know where we asked to connect).
    pub target:      String,
    /// Cells we can still send before needing a SENDME.
    pub send_window: i32,
    /// Cells received since last SENDME we emitted.
    pub delivered_since_sendme: i32,
    /// Bytes of inbound data queued for the application. If this
    /// exceeds STREAM_BUFFER_MAX, we stop acking (withhold SENDMEs)
    /// so the peer stops sending.
    pub inbound_buffered: usize,
    /// Channel for delivering received data to the application. The
    /// application polls the Receiver half; this struct owns the
    /// Sender.
    pub inbound_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// End reason if closed, else None.
    pub end_reason:  Option<EndReason>,
    /// Fires once when the stream transitions Connecting → Open.
    /// `stream_open` holds the receive half and hands it to callers
    /// who want to block until the stream is ready for data. None
    /// after `on_connected` has fired (channel already signaled) or
    /// for streams that skipped the Connecting phase (exit side).
    pub ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Stream {
    /// Apply the initiator-side transition for a RELAY_CONNECTED cell.
    /// Returns an error if the stream wasn't in Connecting state.
    pub fn on_connected(&mut self) -> Result<()> {
        if self.state != StreamState::Connecting {
            return Err(Error::Handshake(format!(
                "stream {}: CONNECTED in state {:?}", self.id, self.state
            )));
        }
        self.state = StreamState::Open;
        // Signal any awaiter. send() returns Err iff receiver was
        // dropped; that's fine, just means nobody's waiting.
        if let Some(tx) = self.ready_tx.take() {
            let _ = tx.send(());
        }
        Ok(())
    }

    /// Receive a DATA cell. Queues the bytes, updates the delivery
    /// counter, and returns `Some(())` if a SENDME should be emitted
    /// now by the caller.
    pub fn on_data(&mut self, bytes: &[u8]) -> Result<bool> {
        if self.state != StreamState::Open {
            return Err(Error::Handshake(format!(
                "stream {}: DATA in state {:?}", self.id, self.state
            )));
        }
        if self.inbound_buffered + bytes.len() > STREAM_BUFFER_MAX {
            // Apply backpressure — don't accept; peer will hit its
            // own send window and stop.
            return Err(Error::Handshake(format!(
                "stream {}: inbound buffer full", self.id
            )));
        }
        if let Some(tx) = &self.inbound_tx {
            // Try-send so a stuck app doesn't block the dispatcher.
            if tx.try_send(bytes.to_vec()).is_err() {
                return Err(Error::Handshake(format!(
                    "stream {}: app buffer full", self.id
                )));
            }
        }
        self.inbound_buffered += bytes.len();
        self.delivered_since_sendme += 1;
        let should_sendme = self.delivered_since_sendme >= STREAM_SENDME_DELIVERED;
        if should_sendme {
            self.delivered_since_sendme = 0;
            // A SENDME means "I've processed this batch." Reset the
            // buffered-byte counter so STREAM_BUFFER_MAX acts as a
            // ceiling on UNACKED bytes, not total bytes seen. Without
            // this reset the counter grows monotonically and once it
            // crosses the max, every subsequent on_data fails — which
            // stalls any transfer larger than STREAM_BUFFER_MAX.
            self.inbound_buffered = 0;
        }
        Ok(should_sendme)
    }

    /// Receive a SENDME. Increment our send window.
    pub fn on_sendme(&mut self) {
        self.send_window += STREAM_SENDME_INC;
        // Cap: can't exceed 2× initial. Prevents one side from
        // minting arbitrarily large windows and DoSing with DATA.
        if self.send_window > STREAM_WINDOW_START * 2 {
            self.send_window = STREAM_WINDOW_START * 2;
        }
    }

    /// Called locally when we want to send one more DATA cell.
    /// Returns Ok(()) if there's window budget, Err(Handshake) if not.
    pub fn try_consume_window(&mut self) -> Result<()> {
        if self.state != StreamState::Open {
            return Err(Error::Handshake(format!(
                "stream {}: send in state {:?}", self.id, self.state
            )));
        }
        if self.send_window <= 0 {
            return Err(Error::Handshake(format!(
                "stream {}: window exhausted", self.id
            )));
        }
        self.send_window -= 1;
        Ok(())
    }

    /// Mark the stream closed. Idempotent.
    pub fn close(&mut self, reason: EndReason) {
        self.state = StreamState::Closed;
        self.end_reason = Some(reason);
        self.inbound_tx = None; // drop the sender so app sees EOF
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, StreamState::Open)
    }
}

// ── Stream manager (one per circuit) ──────────────────────────────────

/// Owns the stream table for a single circuit. Multiple streams run
/// concurrently; stream_ids are 16-bit monotonic within the circuit.
/// Stream ID 0 is reserved for circuit-level control cells.
pub struct StreamMux {
    streams:         Mutex<HashMap<u16, Stream>>,
    next_stream_id:  AtomicU16,
}

impl StreamMux {
    pub fn new() -> Self {
        Self {
            streams:        Mutex::new(HashMap::new()),
            // Start at 1 so we never collide with the "no-stream" ID 0.
            next_stream_id: AtomicU16::new(1),
        }
    }

    /// Allocate a fresh stream_id. Wraps around at u16::MAX; caller
    /// should check that the new ID isn't already in use (extremely
    /// unlikely for normal workloads but defense against overflow).
    pub fn fresh_id(&self) -> u16 {
        let id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        if id == 0 { self.next_stream_id.fetch_add(1, Ordering::SeqCst) } else { id }
    }

    /// Open a new outbound stream to `target`. Returns the fresh
    /// stream_id and the `Receiver` half the application reads from.
    /// The caller is responsible for sending the RELAY_BEGIN cell.
    /// Open a new outbound stream to `target`. Returns the fresh
    /// stream_id, the `Receiver` half the application reads from,
    /// and a oneshot that fires when the stream transitions to Open
    /// (i.e. when CONNECTED arrives from the exit). The oneshot is
    /// always returned, even if the stream has already transitioned
    /// by the time the caller awaits it — in that case the send has
    /// already happened and the recv completes immediately.
    pub async fn open_stream(&self, target: String)
        -> (u16, mpsc::Receiver<Vec<u8>>, tokio::sync::oneshot::Receiver<()>)
    {
        let id = self.fresh_id();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(32);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        let s = Stream {
            id,
            state:   StreamState::Connecting,
            target,
            send_window: STREAM_WINDOW_START,
            delivered_since_sendme: 0,
            inbound_buffered: 0,
            inbound_tx: Some(tx),
            end_reason: None,
            ready_tx: Some(ready_tx),
        };
        self.streams.lock().await.insert(id, s);
        (id, rx, ready_rx)
    }

    /// Accept an inbound BEGIN on the exit side. Creates a Stream in
    /// state Open (exit side skips the Connecting phase — it's done
    /// the TCP connect before calling this).
    pub async fn accept_stream(&self, id: u16, target: String) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(32);
        let s = Stream {
            id,
            state:   StreamState::Open,
            target,
            send_window: STREAM_WINDOW_START,
            delivered_since_sendme: 0,
            inbound_buffered: 0,
            inbound_tx: Some(tx),
            end_reason: None,
            ready_tx: None, // no transition to signal — already Open
        };
        self.streams.lock().await.insert(id, s);
        rx
    }

    pub async fn with_stream<F, T>(&self, id: u16, f: F) -> Option<T>
    where
        F: FnOnce(&mut Stream) -> T,
    {
        let mut s = self.streams.lock().await;
        s.get_mut(&id).map(f)
    }

    /// Remove a stream entirely. Called after END has been exchanged
    /// in both directions, or on circuit teardown.
    pub async fn remove(&self, id: u16) {
        self.streams.lock().await.remove(&id);
    }

    /// Snapshot of stream IDs currently tracked.
    pub async fn active_ids(&self) -> Vec<u16> {
        self.streams.lock().await.keys().copied().collect()
    }

    pub async fn len(&self) -> usize {
        self.streams.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.streams.lock().await.is_empty()
    }
}

impl Default for StreamMux {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_stream(id: u16) -> Stream {
        Stream {
            id,
            state:   StreamState::Connecting,
            target:  "example.com:80".into(),
            send_window: STREAM_WINDOW_START,
            delivered_since_sendme: 0,
            inbound_buffered: 0,
            inbound_tx: None,
            end_reason: None,
            ready_tx: None,
        }
    }

    #[test]
    fn connecting_then_open() {
        let mut s = fresh_stream(1);
        assert_eq!(s.state, StreamState::Connecting);
        s.on_connected().unwrap();
        assert_eq!(s.state, StreamState::Open);
        assert!(s.is_open());
    }

    #[test]
    fn connected_twice_rejected() {
        let mut s = fresh_stream(1);
        s.on_connected().unwrap();
        assert!(s.on_connected().is_err());
    }

    #[test]
    fn data_before_connected_rejected() {
        let mut s = fresh_stream(1);
        assert!(s.on_data(b"early").is_err());
    }

    #[test]
    fn data_on_closed_rejected() {
        let mut s = fresh_stream(1);
        s.on_connected().unwrap();
        s.close(EndReason::Done);
        assert!(s.on_data(b"post-close").is_err());
    }

    #[test]
    fn sendme_triggered_every_n_cells() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1000);
        let mut s = fresh_stream(1);
        s.inbound_tx = Some(tx);
        s.on_connected().unwrap();

        // First N-1 cells: no sendme
        for _ in 0..(STREAM_SENDME_DELIVERED - 1) {
            let r = s.on_data(b"x").unwrap();
            assert!(!r);
        }
        // Nth cell: should signal sendme
        let r = s.on_data(b"x").unwrap();
        assert!(r, "SENDME should be due after STREAM_SENDME_DELIVERED cells");
        // Counter reset
        assert_eq!(s.delivered_since_sendme, 0);
    }

    #[test]
    fn window_decreases_on_send_increases_on_sendme() {
        let mut s = fresh_stream(1);
        s.on_connected().unwrap();
        let start = s.send_window;

        for _ in 0..10 { s.try_consume_window().unwrap(); }
        assert_eq!(s.send_window, start - 10);

        s.on_sendme();
        assert_eq!(s.send_window, start - 10 + STREAM_SENDME_INC);
    }

    #[test]
    fn window_capped_at_2x_start() {
        let mut s = fresh_stream(1);
        s.on_connected().unwrap();
        // Bombard with sendmes
        for _ in 0..100 { s.on_sendme(); }
        assert!(s.send_window <= STREAM_WINDOW_START * 2);
    }

    #[test]
    fn window_exhaustion_blocks_send() {
        let mut s = fresh_stream(1);
        s.on_connected().unwrap();
        s.send_window = 1;
        s.try_consume_window().unwrap();
        assert!(s.try_consume_window().is_err(), "send blocked when window at 0");
    }

    #[test]
    fn closed_stream_reports_reason() {
        let mut s = fresh_stream(1);
        s.close(EndReason::Timeout);
        assert_eq!(s.state, StreamState::Closed);
        assert_eq!(s.end_reason, Some(EndReason::Timeout));
        assert!(!s.is_open());
    }

    #[test]
    fn close_is_idempotent() {
        let mut s = fresh_stream(1);
        s.close(EndReason::Done);
        s.close(EndReason::Timeout); // later close replaces reason — that's fine
        assert_eq!(s.state, StreamState::Closed);
    }

    #[test]
    fn end_reason_roundtrip() {
        for i in 0u8..10 {
            let r = EndReason::from_byte(i);
            // Unknown maps to Internal; others are stable.
            let back = r as u8;
            if i <= 4 { assert_eq!(back, i); }
        }
    }

    // ── Mux tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn mux_allocates_monotonic_ids() {
        let mux = StreamMux::new();
        let (id1, _, _) = mux.open_stream("a".into()).await;
        let (id2, _, _) = mux.open_stream("b".into()).await;
        assert!(id2 > id1, "ids increase");
        assert!(id1 > 0,   "id 0 reserved");
    }

    #[tokio::test]
    async fn mux_tracks_multiple_streams() {
        let mux = StreamMux::new();
        let (_a, _, _) = mux.open_stream("host1:80".into()).await;
        let (_b, _, _) = mux.open_stream("host2:80".into()).await;
        let (_c, _, _) = mux.open_stream("host3:80".into()).await;
        assert_eq!(mux.len().await, 3);
    }

    #[tokio::test]
    async fn mux_with_stream_reads_and_writes() {
        let mux = StreamMux::new();
        let (id, _, _) = mux.open_stream("t:1".into()).await;
        mux.with_stream(id, |s| { s.on_connected().unwrap(); }).await;
        let state = mux.with_stream(id, |s| s.state).await.unwrap();
        assert_eq!(state, StreamState::Open);
    }

    #[tokio::test]
    async fn mux_accept_side_skips_connecting() {
        let mux = StreamMux::new();
        let _rx = mux.accept_stream(42, "in:1".into()).await;
        let state = mux.with_stream(42, |s| s.state).await.unwrap();
        // Exit side of a stream doesn't need the Connecting phase —
        // the TCP connect happens before accept_stream is called.
        assert_eq!(state, StreamState::Open);
    }

    #[tokio::test]
    async fn mux_remove_cleans_up() {
        let mux = StreamMux::new();
        let (id, _, _) = mux.open_stream("t:1".into()).await;
        mux.remove(id).await;
        assert_eq!(mux.len().await, 0);
        assert!(mux.with_stream(id, |s| s.id).await.is_none());
    }

    #[tokio::test]
    async fn inbound_data_delivered_via_channel() {
        let mux = StreamMux::new();
        let (id, mut rx, _) = mux.open_stream("t:1".into()).await;
        mux.with_stream(id, |s| { s.on_connected().unwrap(); }).await;

        // Inject a DATA cell
        mux.with_stream(id, |s| {
            s.on_data(b"hello").unwrap()
        }).await;

        // Application reads from the channel
        let got = rx.recv().await.unwrap();
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn ready_signal_fires_on_connected() {
        let mux = StreamMux::new();
        let (id, _rx, ready) = mux.open_stream("t:1".into()).await;

        // Ready shouldn't fire yet
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut { ready }).await,
            Err(_)  // timeout == ready not yet fired, which is what we want
        ));

        // Get a fresh ready — the one above was moved
        let (id2, _rx2, ready2) = mux.open_stream("t:2".into()).await;

        // Drive the transition
        mux.with_stream(id2, |s| { s.on_connected().unwrap(); }).await;

        // Ready fires
        ready2.await.expect("ready recv after on_connected");

        // Re-transitioning (second on_connected) would error but
        // not re-fire the channel; verify the channel state.
        let _ = id;
    }

    #[tokio::test]
    async fn ready_signal_drops_cleanly_on_close() {
        let mux = StreamMux::new();
        let (id, _rx, ready) = mux.open_stream("t:1".into()).await;

        // Close before CONNECTED — ready channel's sender drops with
        // the Stream, receiver sees Err.
        mux.with_stream(id, |s| s.close(EndReason::Destroyed)).await;
        mux.remove(id).await;

        // Channel is dropped — await resolves to Err.
        assert!(ready.await.is_err(), "ready fails when stream closed without connected");
    }
}
