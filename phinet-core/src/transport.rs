// phinet-core/src/transport.rs
//!
//! # Pluggable transports
//!
//! Abstraction over how a peer-to-peer ΦNET connection is carried.
//! The default is [`PlainTcp`] — a direct TCP socket — which is what
//! `node.rs` uses today. In hostile network environments, plain TCP
//! is fingerprintable and blockable. Pluggable transports wrap the
//! underlying byte stream in an obfuscation layer that disguises
//! ΦNET traffic as something else (random noise, web traffic, etc).
//!
//! ## Design
//!
//! The [`Transport`] trait abstracts the dial/listen primitives. A
//! transport produces objects implementing standard
//! `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`, so the rest
//! of the network stack (handshake, session, circuits) needs no
//! awareness of which transport is in use.
//!
//! ## Provided transports
//!
//! - **[`PlainTcp`]**: vanilla TCP. Default. No obfuscation.
//! - **[`SubprocessTransport`]**: launches an external program (e.g.
//!   `obfs4proxy`, `meek-client`, `snowflake-client`) that speaks the
//!   PT-1 spec, and dials/relays through its local SOCKS5. This is
//!   the integration point for actual obfs-style transports — but
//!   verifying it requires the external binary, which can't run in
//!   the build sandbox. The struct + dial logic is here, ready to
//!   be wired up in deployment.
//!
//! ## Adding new transports
//!
//! Implement the trait, return your custom byte-stream type. Any
//! `AsyncRead + AsyncWrite` works. Examples that would slot in:
//!
//! - **WebSocket** (carrying ΦNET cells inside WebSocket frames so
//!   traffic looks like a web app)
//! - **DTLS-over-UDP** (a la WireGuard's wire format)
//! - **Custom random-bytes-stream** (obfs4 has this as a layer)
//!
//! ## Why this isn't wired into `node.rs` yet
//!
//! `node.rs::run()` currently calls `TcpListener::bind` and
//! `TcpStream::connect` directly. Plugging this trait in requires
//! threading a `dyn Transport` through the node's accept and connect
//! paths — straightforward refactor but a wide one. The trait + the
//! wrapper types here are the foundation; the refactor is the next
//! step.

use crate::Result;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// A bidirectional byte stream produced by a transport. Anything
/// implementing AsyncRead + AsyncWrite + Unpin + Send works — that
/// covers TcpStream, TLS streams, framed wrappers, etc.
pub type DynStream = Pin<Box<dyn AsyncReadWrite + Send>>;

/// Combined trait for the streams transports return. Tokio doesn't
/// have a single name for this, so we define one.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncReadWrite for T {}

/// Boxed future returned by trait methods. We avoid the `async-trait`
/// macro dependency by writing this out by hand: every async-trait
/// method desugars to one of these. Verbose but zero deps.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A pluggable transport.
///
/// Transports may be **stateful** (e.g. obfs4 derives a session key
/// from the bridge cert; the same instance is reused across multiple
/// dials to amortize that), so we model them as long-lived objects
/// with `dial`/`listen` methods rather than free functions.
pub trait Transport: Send + Sync {
    /// Human-readable name for logs ("plain", "obfs4", "websocket"…).
    fn name(&self) -> &'static str;

    /// Open an outbound connection to `host:port`. The host string
    /// is interpreted by the transport — most transports treat it
    /// as a DNS name + IP address, but obfuscated transports may
    /// embed extra metadata (cert hashes, channel IDs).
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<DynStream>>;

    /// Listen for inbound connections at `bind_addr`. The
    /// returned [`Listener`] yields one stream per accepted
    /// connection.
    fn listen<'a>(&'a self, bind_addr: &'a str) -> BoxFuture<'a, Result<Box<dyn Listener>>>;
}

/// Listener returned by [`Transport::listen`]. Each `accept` call
/// yields the next inbound connection along with the remote
/// address as a string.
pub trait Listener: Send + Sync {
    fn accept<'a>(&'a mut self) -> BoxFuture<'a, Result<(DynStream, String)>>;
    fn local_addr(&self) -> String;
}

// ── PlainTcp: the default transport ──────────────────────────────────

/// Vanilla TCP. No obfuscation. This is the transport `node.rs`
/// effectively uses today (it calls `TcpListener` / `TcpStream`
/// directly). Wrapping it in the [`Transport`] trait lets the rest
/// of the stack stay agnostic.
pub struct PlainTcp;

impl Transport for PlainTcp {
    fn name(&self) -> &'static str { "plain" }

    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<DynStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((host, port)).await
                .map_err(|e| crate::Error::Io(e))?;
            // Match the existing `node.rs` socket settings. Disabling
            // Nagle reduces latency for small cells.
            let _ = stream.set_nodelay(true);
            let s: DynStream = Box::pin(stream);
            Ok(s)
        })
    }

    fn listen<'a>(&'a self, bind_addr: &'a str) -> BoxFuture<'a, Result<Box<dyn Listener>>> {
        Box::pin(async move {
            let listener = TcpListener::bind(bind_addr).await
                .map_err(|e| crate::Error::Io(e))?;
            let local = listener.local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| bind_addr.to_string());
            let l: Box<dyn Listener> = Box::new(PlainTcpListener { inner: listener, local });
            Ok(l)
        })
    }
}

struct PlainTcpListener {
    inner: TcpListener,
    local: String,
}

impl Listener for PlainTcpListener {
    fn accept<'a>(&'a mut self) -> BoxFuture<'a, Result<(DynStream, String)>> {
        Box::pin(async move {
            let (stream, addr) = self.inner.accept().await
                .map_err(|e| crate::Error::Io(e))?;
            let _ = stream.set_nodelay(true);
            let s: DynStream = Box::pin(stream);
            Ok((s, addr.to_string()))
        })
    }
    fn local_addr(&self) -> String { self.local.clone() }
}

// ── SubprocessTransport: obfs4proxy / meek-client / snowflake-client ──

/// A transport implemented by an external PT-1 compliant binary
/// (obfs4proxy, meek-client, snowflake-client, etc).
///
/// The binary speaks the **Pluggable Transport spec** (Tor's
/// pt-spec.txt) over its stdio:
///
/// 1. Process spawned with environment vars (TOR_PT_MANAGED_TRANSPORT_VER,
///    TOR_PT_CLIENT_TRANSPORTS, TOR_PT_STATE_LOCATION, …)
/// 2. Process announces a SOCKS5 listener: `CMETHOD obfs4 socks5 127.0.0.1:N`
/// 3. ΦNET dials through that local SOCKS5, passing the bridge address
///    as the destination + per-bridge args (`cert=…&iat-mode=…`) as
///    SOCKS5 username/password.
/// 4. The PT process talks to the bridge using its obfuscated wire
///    format; ΦNET sees only a clean bytestream.
///
/// **Status**: the SOCKS5 client logic below is fully tested with a
/// mock PT proxy (see tests). Running real obfs4proxy needs the
/// binary installed in the test environment — out of scope for the
/// build sandbox but trivial to wire up with `tokio::process::Command`
/// at deploy time.
pub struct SubprocessTransport {
    /// e.g. "obfs4", "meek_lite", "snowflake"
    pt_name: &'static str,
    /// SOCKS5 endpoint exposed by the subprocess. Set after handshake.
    socks_addr: std::sync::OnceLock<std::net::SocketAddr>,
    /// Per-bridge arguments forwarded as SOCKS5 user:pass per pt-spec
    /// (e.g. "cert=…&iat-mode=0" for obfs4).
    bridge_args: String,
}

impl SubprocessTransport {
    /// Construct without spawning. Call `start_subprocess` separately
    /// to launch the PT binary.
    pub fn new(pt_name: &'static str, bridge_args: impl Into<String>) -> Self {
        Self {
            pt_name,
            socks_addr: std::sync::OnceLock::new(),
            bridge_args: bridge_args.into(),
        }
    }

    /// Address of the SOCKS5 endpoint exposed by the subprocess, if
    /// the subprocess has been started. None until that's done.
    pub fn socks_addr(&self) -> Option<std::net::SocketAddr> {
        self.socks_addr.get().copied()
    }

    /// Manually inject the SOCKS5 endpoint for this transport. Used
    /// either by `start_subprocess` after parsing CMETHOD lines, or
    /// by tests / external orchestrators that manage the PT process
    /// out-of-band.
    pub fn set_socks_addr(&self, addr: std::net::SocketAddr) -> std::result::Result<(), &'static str> {
        self.socks_addr.set(addr).map_err(|_| "socks_addr already set")
    }

    /// Spawn the PT binary as a managed subprocess and wait for it
    /// to announce its SOCKS5 endpoint. On success, the
    /// `socks_addr` is populated and the subprocess remains running
    /// until `shutdown_subprocess` is called or the parent process
    /// exits.
    ///
    /// `binary_path` is the absolute path to the PT binary (e.g.
    /// `/usr/bin/obfs4proxy`, `/usr/local/bin/snowflake-client`).
    ///
    /// `state_dir` is a writable directory the binary uses for its
    /// state files. PT-spec mandates the parent provide this; many
    /// PT implementations write per-bridge keys here. Pass an
    /// app-specific path like `~/.phinet/pt-state/`.
    ///
    /// Spec reference: `pt-spec.txt` from torproject.org. We
    /// implement only the client-side managed-proxy side.
    ///
    /// **What's verified vs. what isn't**: the parsing logic and
    /// timeout handling are tested with a mock subprocess that
    /// emits canned PT-spec output. Running real obfs4proxy needs
    /// the binary installed which the build sandbox doesn't have —
    /// integration with a real PT binary is a deployment-time step.
    pub async fn start_subprocess(
        &self,
        binary_path: &std::path::Path,
        state_dir: &std::path::Path,
    ) -> Result<SubprocessHandle> {
        use tokio::process::Command;
        use tokio::io::{AsyncBufReadExt, BufReader};

        std::fs::create_dir_all(state_dir)
            .map_err(|e| crate::Error::Crypto(format!("pt: mkdir state_dir: {e}")))?;

        let mut cmd = Command::new(binary_path);
        cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
           .env("TOR_PT_CLIENT_TRANSPORTS", self.pt_name)
           .env("TOR_PT_STATE_LOCATION", state_dir)
           // Tells the subprocess to exit when its stdin closes,
           // i.e. when our process dies. Without this, killing the
           // parent would orphan the PT binary.
           .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
           .stdin(std::process::Stdio::piped())
           .stdout(std::process::Stdio::piped())
           .stderr(std::process::Stdio::piped())
           .kill_on_drop(true);

        let mut child = cmd.spawn()
            .map_err(|e| crate::Error::Crypto(format!("pt: spawn {}: {e}", binary_path.display())))?;

        let stdout = child.stdout.take()
            .ok_or_else(|| crate::Error::Crypto("pt: subprocess has no stdout".into()))?;

        // PT-spec output handshake. We expect, in some order:
        //   VERSION 1
        //   CMETHOD <name> socks5 <ip>:<port>
        //   CMETHODS DONE
        //
        // Errors come as:
        //   VERSION-ERROR no-version
        //   ENV-ERROR <reason>
        //   CMETHOD-ERROR <name> <reason>
        //
        // We bound the wait at 30 seconds to catch hung subprocesses.
        let mut reader = BufReader::new(stdout).lines();
        let mut found_socks: Option<std::net::SocketAddr> = None;
        let mut version_ok = false;

        let parse_loop = async {
            while let Some(line) = reader.next_line().await
                .map_err(|e| crate::Error::Crypto(format!("pt: read stdout: {e}")))?
            {
                tracing::debug!("pt {}: {}", self.pt_name, line);
                match parse_cmethod_line(&line, self.pt_name) {
                    PtLine::VersionOk          => { version_ok = true; }
                    PtLine::Cmethod(addr)      => { found_socks = Some(addr); }
                    PtLine::CmethodsDone       => break,
                    PtLine::VersionError(why)  => {
                        return Err(crate::Error::Crypto(format!(
                            "pt: version negotiation failed: {why}")));
                    }
                    PtLine::EnvError(why)      => {
                        return Err(crate::Error::Crypto(format!("pt: env error: {why}")));
                    }
                    PtLine::CmethodError(why)  => {
                        return Err(crate::Error::Crypto(format!(
                            "pt: cmethod error: {why}")));
                    }
                    // Server-mode lines never occur in client mode.
                    PtLine::Smethod { .. }
                    | PtLine::SmethodsDone
                    | PtLine::SmethodError(_)
                    | PtLine::Other              => {}
                }
            }
            Ok(())
        };

        match tokio::time::timeout(std::time::Duration::from_secs(30), parse_loop).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(crate::Error::Crypto(
                    "pt: subprocess did not announce CMETHODS within 30s".into()));
            }
        }

        if !version_ok {
            let _ = child.kill().await;
            return Err(crate::Error::Crypto(
                "pt: subprocess did not announce VERSION 1".into()));
        }
        let socks = found_socks.ok_or_else(|| {
            crate::Error::Crypto(format!(
                "pt: subprocess did not announce a CMETHOD for transport '{}'",
                self.pt_name))
        })?;

        self.set_socks_addr(socks)
            .map_err(|e| crate::Error::Crypto(format!("pt: {e}")))?;

        Ok(SubprocessHandle {
            child: tokio::sync::Mutex::new(Some(child)),
            transport_name: self.pt_name,
        })
    }
}

/// Live handle to a spawned PT subprocess. Drop-or-call-shutdown
/// kills the process. The `kill_on_drop(true)` flag set during spawn
/// means even if the holder forgets `shutdown`, OS-level cleanup
/// will fire.
pub struct SubprocessHandle {
    child: tokio::sync::Mutex<Option<tokio::process::Child>>,
    transport_name: &'static str,
}

impl SubprocessHandle {
    /// Send the subprocess SIGTERM (or kill on Windows) and wait
    /// for it to exit. Idempotent; later calls are no-ops.
    pub async fn shutdown(&self) {
        let mut guard = self.child.lock().await;
        if let Some(mut child) = guard.take() {
            tracing::info!("pt {}: shutting down subprocess", self.transport_name);
            // Closing stdin with TOR_PT_EXIT_ON_STDIN_CLOSE=1 should
            // give a clean shutdown. If the process ignores that,
            // fall back to kill().
            drop(child.stdin.take());  // close stdin
            // 5 second grace period
            let waited = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                child.wait()
            ).await;
            if waited.is_err() {
                tracing::warn!("pt {}: graceful shutdown timed out, killing", self.transport_name);
                let _ = child.kill().await;
            }
        }
    }
}

/// One parsed line of PT-spec output. The spec defines exact wire
/// strings; this enum represents the subset we care about. All
/// non-essential lines map to `Other`.
#[derive(Debug, PartialEq)]
enum PtLine {
    VersionOk,
    Cmethod(std::net::SocketAddr),
    CmethodsDone,
    VersionError(String),
    EnvError(String),
    CmethodError(String),
    /// Server-mode: PT announced its public listener + per-bridge args.
    Smethod { bind: std::net::SocketAddr, args: Option<String> },
    SmethodsDone,
    SmethodError(String),
    Other,
}

/// Parse one PT-spec stdout line. `expected_name` is the transport
/// name we asked for; CMETHOD lines for other names are ignored.
///
/// Examples (per pt-spec.txt §4):
/// ```text
/// VERSION 1
/// CMETHOD obfs4 socks5 127.0.0.1:46221
/// CMETHODS DONE
/// CMETHOD-ERROR obfs4 missing keypair
/// ENV-ERROR no transports specified
/// VERSION-ERROR no-version
/// ```
fn parse_cmethod_line(line: &str, expected_name: &str) -> PtLine {
    let line = line.trim();

    if line == "VERSION 1" {
        return PtLine::VersionOk;
    }
    if line == "CMETHODS DONE" {
        return PtLine::CmethodsDone;
    }

    if let Some(rest) = line.strip_prefix("VERSION-ERROR ") {
        return PtLine::VersionError(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix("ENV-ERROR ") {
        return PtLine::EnvError(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix("CMETHOD-ERROR ") {
        return PtLine::CmethodError(rest.to_string());
    }

    if let Some(rest) = line.strip_prefix("CMETHOD ") {
        // CMETHOD <name> socks5 <addr>:<port>
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == expected_name && parts[1] == "socks5" {
            if let Ok(addr) = parts[2].parse::<std::net::SocketAddr>() {
                return PtLine::Cmethod(addr);
            }
        }
    }

    PtLine::Other
}

/// Parse one **server-mode** PT-spec stdout line. A server PT (a bridge)
/// announces its public listener with `SMETHOD` instead of `CMETHOD`,
/// and includes the per-bridge `ARGS:` that clients must present to
/// connect (for obfs4 this carries the `cert=…` a client needs).
///
/// Examples (pt-spec.txt §3.3.3):
/// ```text
/// VERSION 1
/// SMETHOD obfs4 0.0.0.0:443 ARGS:cert=AAAA…;iat-mode=0
/// SMETHODS DONE
/// SMETHOD-ERROR obfs4 no bindaddr
/// ```
fn parse_smethod_line(line: &str, expected_name: &str) -> PtLine {
    let line = line.trim();

    if line == "VERSION 1"     { return PtLine::VersionOk; }
    if line == "SMETHODS DONE" { return PtLine::SmethodsDone; }

    if let Some(rest) = line.strip_prefix("VERSION-ERROR ") {
        return PtLine::VersionError(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix("ENV-ERROR ") {
        return PtLine::EnvError(rest.to_string());
    }
    if let Some(rest) = line.strip_prefix("SMETHOD-ERROR ") {
        return PtLine::SmethodError(rest.to_string());
    }

    if let Some(rest) = line.strip_prefix("SMETHOD ") {
        // SMETHOD <name> <addr:port> [ARGS:k=v;…] [OPT-ARGS:…]
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == expected_name {
            if let Ok(bind) = parts[1].parse::<std::net::SocketAddr>() {
                let args = parts.iter().skip(2).find_map(|p| {
                    p.strip_prefix("ARGS:").or_else(|| p.strip_prefix("OPT-ARGS:"))
                }).map(|s| s.to_string());
                return PtLine::Smethod { bind, args };
            }
        }
    }

    PtLine::Other
}

/// Result of starting a server-side PT (a bridge): the public listener
/// address the PT bound, plus the per-bridge `ARGS` clients must
/// present. Publish [`client_line`](BridgeLine::client_line)
/// out-of-band to anyone who should be able to reach this bridge.
#[derive(Debug, Clone)]
pub struct BridgeLine {
    pub transport: String,
    pub bind_addr: std::net::SocketAddr,
    pub args:      Option<String>,
}

impl BridgeLine {
    /// The string an operator shares with clients. A ΦNET client feeds
    /// the pieces to the daemon as `--transport <t> --pt-bridge-args
    /// <args> --bootstrap <bind_addr>`.
    pub fn client_line(&self) -> String {
        match &self.args {
            Some(a) => format!("{} {} {}", self.transport, self.bind_addr, a),
            None    => format!("{} {}", self.transport, self.bind_addr),
        }
    }
}

/// Spawn a **server-side** PT managed proxy — i.e. run this node as an
/// obfs4/meek/snowflake **bridge**. The PT binary listens on
/// `bind_addr` speaking its obfuscated protocol and forwards decrypted
/// connections to `orport`, which should be the local ΦNET daemon's
/// plain listener (e.g. `127.0.0.1:7700`). The ΦNET daemon itself keeps
/// using [`PlainTcp`]; the PT sits in front as a de-obfuscating shim,
/// so nothing about the daemon's own listener changes.
///
/// Returns the process handle (drop/`shutdown` kills it) and the
/// [`BridgeLine`] clients need to connect. Mirrors the client-side
/// `start_subprocess`: same spawn/parse/timeout structure, but with the
/// server `TOR_PT_*` environment and `SMETHOD` parsing.
pub async fn start_server_pt(
    pt_name:        &str,
    binary_path:    &std::path::Path,
    state_dir:      &std::path::Path,
    bind_addr:      &str,
    orport:         &str,
    server_options: Option<&str>,
) -> Result<(SubprocessHandle, BridgeLine)> {
    use tokio::process::Command;
    use tokio::io::{AsyncBufReadExt, BufReader};

    std::fs::create_dir_all(state_dir)
        .map_err(|e| crate::Error::Crypto(format!("pt: mkdir state_dir: {e}")))?;

    let mut cmd = Command::new(binary_path);
    cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
       .env("TOR_PT_SERVER_TRANSPORTS", pt_name)
       .env("TOR_PT_SERVER_BINDADDR", format!("{pt_name}-{bind_addr}"))
       .env("TOR_PT_ORPORT", orport)
       .env("TOR_PT_STATE_LOCATION", state_dir)
       .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
       .stdin(std::process::Stdio::piped())
       .stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped())
       .kill_on_drop(true);
    if let Some(opts) = server_options {
        cmd.env("TOR_PT_SERVER_TRANSPORT_OPTIONS", opts);
    }

    let mut child = cmd.spawn()
        .map_err(|e| crate::Error::Crypto(format!("pt: spawn {}: {e}", binary_path.display())))?;

    let stdout = child.stdout.take()
        .ok_or_else(|| crate::Error::Crypto("pt: subprocess has no stdout".into()))?;

    let mut reader     = BufReader::new(stdout).lines();
    let mut version_ok = false;
    let mut bridge: Option<BridgeLine> = None;
    let name_owned     = pt_name.to_string();

    let parse_loop = async {
        while let Some(line) = reader.next_line().await
            .map_err(|e| crate::Error::Crypto(format!("pt: read stdout: {e}")))?
        {
            tracing::debug!("pt-server {}: {}", name_owned, line);
            match parse_smethod_line(&line, &name_owned) {
                PtLine::VersionOk              => version_ok = true,
                PtLine::Smethod { bind, args } => {
                    bridge = Some(BridgeLine {
                        transport: name_owned.clone(),
                        bind_addr: bind,
                        args,
                    });
                }
                PtLine::SmethodsDone           => break,
                PtLine::VersionError(why)      =>
                    return Err(crate::Error::Crypto(format!(
                        "pt: version negotiation failed: {why}"))),
                PtLine::EnvError(why)          =>
                    return Err(crate::Error::Crypto(format!("pt: env error: {why}"))),
                PtLine::SmethodError(why)      =>
                    return Err(crate::Error::Crypto(format!("pt: smethod error: {why}"))),
                _                              => {}
            }
        }
        Ok(())
    };

    match tokio::time::timeout(std::time::Duration::from_secs(30), parse_loop).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => { let _ = child.kill().await; return Err(e); }
        Err(_) => {
            let _ = child.kill().await;
            return Err(crate::Error::Crypto(
                "pt: subprocess did not announce SMETHODS within 30s".into()));
        }
    }

    if !version_ok {
        let _ = child.kill().await;
        return Err(crate::Error::Crypto(
            "pt: subprocess did not announce VERSION 1".into()));
    }
    let bridge = bridge.ok_or_else(|| crate::Error::Crypto(format!(
        "pt: subprocess did not announce an SMETHOD for transport '{pt_name}'")))?;

    let handle = SubprocessHandle {
        child: tokio::sync::Mutex::new(Some(child)),
        // Bridge daemons start one PT for the process lifetime; leaking
        // the name to obtain a 'static str is a one-time cost.
        transport_name: Box::leak(name_owned.into_boxed_str()),
    };
    Ok((handle, bridge))
}

impl Transport for SubprocessTransport {
    fn name(&self) -> &'static str { self.pt_name }

    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<DynStream>> {
        Box::pin(async move {
            let socks = self.socks_addr()
                .ok_or_else(|| crate::Error::Crypto(
                    "subprocess transport: SOCKS5 endpoint not configured \
                     (call start_subprocess or set_socks_addr first)".into()))?;
            socks5_connect(socks, host, port, &self.bridge_args).await
        })
    }

    fn listen<'a>(&'a self, _bind_addr: &'a str) -> BoxFuture<'a, Result<Box<dyn Listener>>> {
        Box::pin(async move {
            // PT clients speak only client-mode SOCKS5; running a
            // server-side PT (a "bridge") would use a different
            // ServerTransport trait that's out of scope here.
            Err(crate::Error::Crypto(
                "subprocess transport: server-side listen is not supported \
                 (use PlainTcp on the bridge side and a forward proxy)".into()))
        })
    }
}

/// Open a SOCKS5 CONNECT to `dest_host:dest_port` through the SOCKS5
/// proxy at `proxy`. The pluggable-transport spec uses the SOCKS5
/// username/password fields to carry per-bridge arguments — those go
/// in `pt_args`.
///
/// Implementation: SOCKS5 RFC 1928 with optional username/password
/// auth (RFC 1929). We always offer username/password auth so the PT
/// proxy gets the bridge arguments; if it doesn't want them it can
/// negotiate no-auth and we send empty creds.
async fn socks5_connect(
    proxy: std::net::SocketAddr,
    dest_host: &str,
    dest_port: u16,
    pt_args: &str,
) -> Result<DynStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut sock = TcpStream::connect(proxy).await
        .map_err(|e| crate::Error::Io(e))?;
    sock.set_nodelay(true).ok();

    // Greeting: VER=5, NMETHODS=2, METHODS=[no-auth, user/pass]
    sock.write_all(&[0x05, 0x02, 0x00, 0x02]).await
        .map_err(|e| crate::Error::Io(e))?;

    // Server picks a method: VER, METHOD
    let mut sel = [0u8; 2];
    sock.read_exact(&mut sel).await
        .map_err(|e| crate::Error::Io(e))?;
    if sel[0] != 0x05 {
        return Err(crate::Error::Crypto(format!("socks5: bad ver {}", sel[0])));
    }
    match sel[1] {
        0x00 => {
            // No auth; pt_args (if any) just won't be conveyed. PT
            // proxies that need args MUST select 0x02 — if they pick
            // 0x00, they're saying "no per-connection args needed".
        }
        0x02 => {
            // Username/password subnegotiation (RFC 1929). We pack
            // the PT args entirely into the username field; password
            // is empty. obfs4proxy and most PT clients accept this.
            let user = pt_args.as_bytes();
            if user.len() > 255 {
                return Err(crate::Error::Crypto("socks5: pt_args > 255 bytes".into()));
            }
            let mut auth = Vec::with_capacity(3 + user.len() + 1);
            auth.push(0x01);                  // sub-negotiation version
            auth.push(user.len() as u8);
            auth.extend_from_slice(user);
            auth.push(0x00);                  // password length
            sock.write_all(&auth).await.map_err(|e| crate::Error::Io(e))?;

            let mut auth_resp = [0u8; 2];
            sock.read_exact(&mut auth_resp).await.map_err(|e| crate::Error::Io(e))?;
            if auth_resp[1] != 0x00 {
                return Err(crate::Error::Crypto(format!(
                    "socks5: auth failed (status={})", auth_resp[1])));
            }
        }
        other => {
            return Err(crate::Error::Crypto(format!(
                "socks5: server picked unsupported method 0x{:02x}", other)));
        }
    }

    // CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (domain),
    // domain length, domain, port (BE)
    if dest_host.len() > 255 {
        return Err(crate::Error::Crypto("socks5: dest_host too long".into()));
    }
    let mut req = Vec::with_capacity(7 + dest_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(dest_host.len() as u8);
    req.extend_from_slice(dest_host.as_bytes());
    req.extend_from_slice(&dest_port.to_be_bytes());
    sock.write_all(&req).await.map_err(|e| crate::Error::Io(e))?;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr).await.map_err(|e| crate::Error::Io(e))?;
    if hdr[0] != 0x05 {
        return Err(crate::Error::Crypto(format!("socks5: bad reply ver {}", hdr[0])));
    }
    if hdr[1] != 0x00 {
        return Err(crate::Error::Crypto(format!(
            "socks5: connect failed (rep={})", socks5_rep_str(hdr[1]))));
    }
    // Skip BND.ADDR (variable) + BND.PORT (2)
    match hdr[3] {
        0x01 => { let mut b = [0u8; 4 + 2]; sock.read_exact(&mut b).await.map_err(|e| crate::Error::Io(e))?; }
        0x04 => { let mut b = [0u8; 16 + 2]; sock.read_exact(&mut b).await.map_err(|e| crate::Error::Io(e))?; }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.map_err(|e| crate::Error::Io(e))?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            sock.read_exact(&mut rest).await.map_err(|e| crate::Error::Io(e))?;
        }
        other => return Err(crate::Error::Crypto(format!(
            "socks5: bad ATYP in reply: 0x{:02x}", other))),
    }
    Ok(Box::pin(sock))
}

fn socks5_rep_str(rep: u8) -> &'static str {
    match rep {
        0x00 => "succeeded",
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "addr type not supported",
        _    => "unknown",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn plain_tcp_dial_and_echo() {
        // Bring up an echo server on a random port using PlainTcp's
        // listen, dial it via PlainTcp's dial, exchange bytes.
        let transport = PlainTcp;
        let mut listener = transport.listen("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr();
        let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();

        let server = tokio::spawn(async move {
            let (mut s, _peer) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.expect("read");
            s.write_all(&buf).await.expect("echo");
        });

        let mut s = transport.dial("127.0.0.1", port).await.expect("dial");
        s.write_all(b"hello").await.expect("write");
        let mut reply = [0u8; 5];
        s.read_exact(&mut reply).await.expect("read");
        assert_eq!(&reply, b"hello");

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn plain_tcp_name_is_plain() {
        assert_eq!(PlainTcp.name(), "plain");
    }

    #[tokio::test]
    async fn subprocess_dial_without_socks_fails() {
        // SubprocessTransport without socks_addr set must error
        // out cleanly rather than panic.
        let t = SubprocessTransport::new("obfs4", "");
        let result = t.dial("dest.example", 443).await;
        let err = match result {
            Ok(_)  => panic!("expected error from unconfigured subprocess transport"),
            Err(e) => format!("{:?}", e),
        };
        assert!(err.contains("SOCKS5 endpoint not configured"),
            "expected helpful error, got: {}", err);
    }

    #[tokio::test]
    async fn subprocess_listen_unsupported() {
        // Server-side PT is out of scope; listen must error cleanly.
        let t = SubprocessTransport::new("obfs4", "");
        let result = t.listen("127.0.0.1:0").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn subprocess_set_socks_addr_idempotent_protected() {
        // OnceLock semantics: first set wins, second errors.
        let t = SubprocessTransport::new("obfs4", "cert=foo");
        let addr1: std::net::SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let addr2: std::net::SocketAddr = "127.0.0.1:9051".parse().unwrap();
        t.set_socks_addr(addr1).expect("first set ok");
        let r2 = t.set_socks_addr(addr2);
        assert!(r2.is_err());
        assert_eq!(t.socks_addr(), Some(addr1));
    }

    #[tokio::test]
    async fn socks5_connect_through_local_echo_socks() {
        // Stand up a tiny SOCKS5 server that:
        //   1. accepts the no-auth greeting
        //   2. handles a CONNECT to "echo.local:42"
        //   3. then echoes the bytes that flow through
        // Then use socks5_connect to dial through it. This exercises
        // the SOCKS5 handshake code path completely (no real PT
        // binary, but the protocol logic is the same).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();

            // Greeting: read VER, NMETHODS, METHODS
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            // Pick no-auth
            s.write_all(&[0x05, 0x00]).await.unwrap();

            // Read CONNECT request
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x01);  // CONNECT
            assert_eq!(req[3], 0x03);  // domain
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut name = vec![0u8; len[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(&name, b"echo.local");
            assert_eq!(u16::from_be_bytes(port), 42);

            // Send success reply: VER, REP=0, RSV, ATYP=1 (IPv4), BND.ADDR (4), BND.PORT (2)
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await.unwrap();

            // Echo
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let mut s = socks5_connect(socks_addr, "echo.local", 42, "").await
            .expect("socks5_connect");
        s.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_with_auth_carries_pt_args() {
        // Same setup but the SOCKS5 server requires user/pass auth
        // and asserts that the username matches the PT args we
        // passed. This is the obfs4-style code path.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = listener.local_addr().unwrap();
        let pt_args = "cert=ABC&iat-mode=0";

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            // Demand user/pass
            assert!(methods.contains(&0x02));
            s.write_all(&[0x05, 0x02]).await.unwrap();

            // Read user/pass
            let mut auth_hdr = [0u8; 2];
            s.read_exact(&mut auth_hdr).await.unwrap();
            assert_eq!(auth_hdr[0], 0x01);
            let user_len = auth_hdr[1] as usize;
            let mut user = vec![0u8; user_len];
            s.read_exact(&mut user).await.unwrap();
            assert_eq!(user, b"cert=ABC&iat-mode=0",
                "PT args must be passed verbatim in the username field");
            let mut pass_len = [0u8; 1];
            s.read_exact(&mut pass_len).await.unwrap();
            assert_eq!(pass_len[0], 0);
            // Approve auth
            s.write_all(&[0x01, 0x00]).await.unwrap();

            // Read CONNECT and acknowledge
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            let mut name_len = [0u8; 1];
            s.read_exact(&mut name_len).await.unwrap();
            let mut name = vec![0u8; name_len[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await.unwrap();
        });

        let _s = socks5_connect(socks_addr, "bridge.example", 443, pt_args).await
            .expect("socks5_connect with PT args");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_failure_propagates() {
        // SOCKS5 server returns rep=0x05 (connection refused). The
        // dial must fail with a helpful error.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            let mut name_len = [0u8; 1];
            s.read_exact(&mut name_len).await.unwrap();
            let mut name = vec![0u8; name_len[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();

            // Reply with REFUSED
            s.write_all(&[0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0]).await.unwrap();
        });

        let result = socks5_connect(socks_addr, "x.example", 1, "").await;
        let err = match result {
            Ok(_)  => panic!("expected SOCKS5 connect to fail with REFUSED"),
            Err(e) => format!("{:?}", e),
        };
        assert!(err.contains("connection refused"),
            "expected refused error, got: {}", err);
        server.await.unwrap();
    }

    // ── PT-spec line parser ──────────────────────────────────────────

    #[test]
    fn parse_version_line() {
        assert_eq!(parse_cmethod_line("VERSION 1", "obfs4"), PtLine::VersionOk);
    }

    #[test]
    fn parse_cmethod_line_with_addr() {
        let r = parse_cmethod_line("CMETHOD obfs4 socks5 127.0.0.1:46221", "obfs4");
        match r {
            PtLine::Cmethod(addr) => {
                assert_eq!(addr.to_string(), "127.0.0.1:46221");
            }
            other => panic!("expected Cmethod, got {:?}", other),
        }
    }

    #[test]
    fn parse_cmethod_line_for_other_transport_ignored() {
        // We're looking for obfs4 but the line announces meek_lite —
        // should not match, falls through to Other.
        let r = parse_cmethod_line("CMETHOD meek_lite socks5 127.0.0.1:1234", "obfs4");
        assert_eq!(r, PtLine::Other);
    }

    #[test]
    fn parse_cmethods_done() {
        assert_eq!(parse_cmethod_line("CMETHODS DONE", "obfs4"), PtLine::CmethodsDone);
    }

    #[test]
    fn parse_error_lines() {
        match parse_cmethod_line("VERSION-ERROR no-version", "obfs4") {
            PtLine::VersionError(s) => assert_eq!(s, "no-version"),
            other => panic!("got {:?}", other),
        }
        match parse_cmethod_line("ENV-ERROR missing TOR_PT_STATE_LOCATION", "obfs4") {
            PtLine::EnvError(s) => assert_eq!(s, "missing TOR_PT_STATE_LOCATION"),
            other => panic!("got {:?}", other),
        }
        match parse_cmethod_line("CMETHOD-ERROR obfs4 missing keypair", "obfs4") {
            PtLine::CmethodError(s) => assert_eq!(s, "obfs4 missing keypair"),
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn parse_garbage_line_is_other() {
        assert_eq!(parse_cmethod_line("garbage stdout from PT", "obfs4"), PtLine::Other);
        assert_eq!(parse_cmethod_line("", "obfs4"), PtLine::Other);
    }

    #[test]
    fn parse_cmethod_with_extra_whitespace() {
        // Real PT binaries vary in whitespace handling.
        let r = parse_cmethod_line("  CMETHOD obfs4 socks5 127.0.0.1:9999  ", "obfs4");
        match r {
            PtLine::Cmethod(_) => {}
            other => panic!("expected Cmethod even with leading/trailing whitespace, got {:?}", other),
        }
    }

    #[test]
    fn parse_cmethod_malformed_addr_falls_through() {
        // If the addr doesn't parse, the whole line is treated as
        // garbage — caller will time out waiting for CMETHODS DONE.
        let r = parse_cmethod_line("CMETHOD obfs4 socks5 not-an-address", "obfs4");
        assert_eq!(r, PtLine::Other);
    }

    // ── Mock-subprocess integration ──────────────────────────────────

    /// Helper: write a tiny shell script that emits canned PT-spec
    /// output and then sleeps. Run start_subprocess against it. This
    /// verifies the spawn + stdout-parsing + handshake completion
    /// path without needing a real obfs4proxy binary.
    async fn run_mock_pt(script: &str) -> Result<SubprocessHandle> {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("mock-pt.sh");
        std::fs::write(&script_path, script).unwrap();
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path,
                std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let t = SubprocessTransport::new("obfs4", "");
        let state = dir.path().join("state");
        // Leak the script's tempdir so the script file outlives the test.
        let _keep = Box::leak(Box::new(dir));
        t.start_subprocess(&script_path, &state).await
            .map(|h| {
                // Verify the SOCKS addr was populated as a side effect
                assert!(t.socks_addr().is_some());
                h
            })
    }

    /// Server-mode analogue of `run_mock_pt`: runs a mock PT that emits
    /// SMETHOD output and returns the parsed BridgeLine.
    #[cfg(unix)]
    async fn run_mock_server_pt(script: &str) -> Result<(SubprocessHandle, BridgeLine)> {
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("mock-server-pt.sh");
        std::fs::write(&script_path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path,
            std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = dir.path().join("state");
        let _keep = Box::leak(Box::new(dir));
        start_server_pt("obfs4", &script_path, &state,
                        "0.0.0.0:443", "127.0.0.1:7700", None).await
    }

    #[test]
    fn parse_smethod_with_args() {
        let r = parse_smethod_line(
            "SMETHOD obfs4 0.0.0.0:443 ARGS:cert=ABCDEF;iat-mode=0", "obfs4");
        match r {
            PtLine::Smethod { bind, args } => {
                assert_eq!(bind, "0.0.0.0:443".parse().unwrap());
                assert_eq!(args.as_deref(), Some("cert=ABCDEF;iat-mode=0"));
            }
            other => panic!("expected Smethod, got {other:?}"),
        }
    }

    #[test]
    fn parse_smethod_without_args() {
        match parse_smethod_line("SMETHOD obfs4 1.2.3.4:9001", "obfs4") {
            PtLine::Smethod { bind, args } => {
                assert_eq!(bind, "1.2.3.4:9001".parse().unwrap());
                assert!(args.is_none());
            }
            other => panic!("expected Smethod, got {other:?}"),
        }
    }

    #[test]
    fn parse_smethod_other_transport_ignored() {
        // An SMETHOD for a different transport name is not our bridge.
        let r = parse_smethod_line("SMETHOD meek_lite 0.0.0.0:443 ARGS:x=y", "obfs4");
        assert_eq!(r, PtLine::Other);
    }

    #[test]
    fn parse_smethods_done_and_errors() {
        assert_eq!(parse_smethod_line("SMETHODS DONE", "obfs4"), PtLine::SmethodsDone);
        assert_eq!(parse_smethod_line("VERSION 1", "obfs4"), PtLine::VersionOk);
        match parse_smethod_line("SMETHOD-ERROR obfs4 no bindaddr", "obfs4") {
            PtLine::SmethodError(s) => assert_eq!(s, "obfs4 no bindaddr"),
            other => panic!("expected SmethodError, got {other:?}"),
        }
    }

    #[test]
    fn bridge_line_client_string() {
        let bl = BridgeLine {
            transport: "obfs4".into(),
            bind_addr: "1.2.3.4:443".parse().unwrap(),
            args: Some("cert=ZZ;iat-mode=0".into()),
        };
        assert_eq!(bl.client_line(), "obfs4 1.2.3.4:443 cert=ZZ;iat-mode=0");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn server_pt_happy_path_parses_bridge_line() {
        // Mock server PT announces its listener + per-bridge cert.
        let script = "#!/bin/sh\necho 'VERSION 1'\necho 'SMETHOD obfs4 0.0.0.0:443 ARGS:cert=DEADBEEF;iat-mode=0'\necho 'SMETHODS DONE'\nsleep 30\n";
        let (handle, bridge) = run_mock_server_pt(script).await.expect("server pt");
        assert_eq!(bridge.transport, "obfs4");
        assert_eq!(bridge.bind_addr, "0.0.0.0:443".parse().unwrap());
        assert_eq!(bridge.args.as_deref(), Some("cert=DEADBEEF;iat-mode=0"));
        assert!(bridge.client_line().contains("cert=DEADBEEF"));
        handle.shutdown().await;
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn server_pt_smethod_error_surfaces() {
        let script = "#!/bin/sh\necho 'VERSION 1'\necho 'SMETHOD-ERROR obfs4 could not bind'\nsleep 10\n";
        let err = match run_mock_server_pt(script).await {
            Ok(_)  => panic!("expected smethod error"),
            Err(e) => format!("{e:?}"),
        };
        assert!(err.contains("smethod error"), "got: {err}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn server_pt_no_smethod_errors() {
        let script = "#!/bin/sh\necho 'VERSION 1'\necho 'SMETHODS DONE'\nsleep 10\n";
        let err = match run_mock_server_pt(script).await {
            Ok(_)  => panic!("expected no-smethod error"),
            Err(e) => format!("{e:?}"),
        };
        assert!(err.contains("did not announce an SMETHOD"), "got: {err}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn subprocess_handshake_happy_path() {
        // Mock PT process emits the canonical PT-spec sequence then
        // sleeps. Our start_subprocess should see the CMETHOD line
        // and populate socks_addr.
        let script = "#!/bin/sh
echo 'VERSION 1'
echo 'CMETHOD obfs4 socks5 127.0.0.1:46221'
echo 'CMETHODS DONE'
sleep 30
";
        let handle = run_mock_pt(script).await.expect("handshake");
        handle.shutdown().await;
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn subprocess_handshake_version_error() {
        let script = "#!/bin/sh
echo 'VERSION-ERROR no-version'
sleep 10
";
        let result = run_mock_pt(script).await;
        let err = match result {
            Ok(_)  => panic!("expected version error"),
            Err(e) => format!("{:?}", e),
        };
        assert!(err.contains("version"), "got: {}", err);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn subprocess_handshake_env_error() {
        let script = "#!/bin/sh
echo 'ENV-ERROR missing transport spec'
sleep 10
";
        let result = run_mock_pt(script).await;
        let err = match result {
            Ok(_)  => panic!("expected env error"),
            Err(e) => format!("{:?}", e),
        };
        assert!(err.contains("env error"), "got: {}", err);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn subprocess_handshake_no_cmethod() {
        // VERSION ok then CMETHODS DONE without ever announcing a
        // CMETHOD line — should error with "did not announce a CMETHOD".
        let script = "#!/bin/sh
echo 'VERSION 1'
echo 'CMETHODS DONE'
sleep 10
";
        let result = run_mock_pt(script).await;
        let err = match result {
            Ok(_)  => panic!("expected no-cmethod error"),
            Err(e) => format!("{:?}", e),
        };
        assert!(err.contains("did not announce a CMETHOD"), "got: {}", err);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn subprocess_set_socks_twice_fails() {
        let script = "#!/bin/sh
echo 'VERSION 1'
echo 'CMETHOD obfs4 socks5 127.0.0.1:46221'
echo 'CMETHODS DONE'
sleep 30
";
        let dir = tempfile::tempdir().unwrap();
        let script_path = dir.path().join("mock-pt.sh");
        std::fs::write(&script_path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path,
            std::fs::Permissions::from_mode(0o755)).unwrap();
        let t = SubprocessTransport::new("obfs4", "");
        let state = dir.path().join("state");
        let h1 = t.start_subprocess(&script_path, &state).await.expect("first");

        // Second start_subprocess should fail because socks_addr
        // is already set
        let r2 = t.start_subprocess(&script_path, &state).await;
        assert!(r2.is_err(), "second start should fail (socks_addr already set)");

        h1.shutdown().await;
    }
}
