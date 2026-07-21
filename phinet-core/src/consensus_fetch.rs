// phinet-core/src/consensus_fetch.rs
//!
//! # Consensus refresh loops
//!
//! Two ways to keep the daemon's `cached_consensus` field up to date:
//!
//! - **`refresh_loop_url`** — periodically fetches a consensus from
//!   an HTTPS URL (typically an authority's public mirror). Verifies
//!   the signature against `node.trusted_authorities` before swapping
//!   it in. If the fetch fails or verification fails, the previous
//!   consensus stays in place.
//!
//! - **`refresh_loop_path`** — periodically reads a consensus from a
//!   local file path. Same verification logic; the file is treated
//!   as untrusted input. Useful for testnets where the operator drops
//!   the consensus on disk via scp / shared filesystem.
//!
//! ## Why we don't trust the URL
//!
//! Even if the URL is HTTPS, the integrity guarantee is "TLS
//! certificate of auth.example.com vouches for the bytes." That
//! does not protect against a compromised authority machine
//! serving a malicious consensus signed by a different key. The
//! verification we do here is the *real* trust check: we verify
//! the consensus's authority signatures against the hardcoded
//! pubkey set in `node.trusted_authorities`.
//!
//! ## Refresh interval
//!
//! Consensuses typically have a 1-hour validity window. We refresh
//! every 15 minutes so a stale consensus is replaced well before it
//! expires. If a fetch fails we retry every 5 minutes until the
//! next regular interval.

use crate::directory::{verify_consensus, threshold_for, ConsensusDocument};
use crate::node::PhiNode;
use std::sync::Arc;
use std::time::Duration;

/// How often to attempt a fresh consensus fetch under normal
/// conditions.
const REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// How long to wait before retrying after a fetch/verify failure.
const RETRY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How long to wait before retrying when we have *no* consensus at all.
///
/// A node without a consensus has no path table: it can't build a circuit,
/// can't look up a hidden service, and answers every fetch with "not found".
/// It is, functionally, off the network.
///
/// So the wait after a failed load is not the same problem as the wait
/// between healthy refreshes. Sleeping the full refresh interval before the
/// first retry means a node that boots during a brief consensus problem — an
/// authority mid-vote, a half-published file — stays dead for fifteen minutes
/// after the network is fine again, with nothing in the log to explain it.
/// Retry quickly until we have *something*, then settle into the normal
/// rhythm.
const COLD_RETRY_INTERVAL: Duration = Duration::from_secs(20);

/// Back off the cold retry up to this, so a genuinely broken authority isn't
/// hammered every 20s forever.
const COLD_RETRY_MAX: Duration = Duration::from_secs(5 * 60);

/// Periodically fetch a consensus over HTTP from `url` and update
/// `node.cached_consensus` after verification.
///
/// ## TLS model
///
/// This fetcher speaks **plain HTTP**, not HTTPS. The reason is
/// architectural rather than security: the security guarantee
/// here comes from the consensus's threshold-signed authority
/// signatures, not from transport encryption. A network attacker
/// who tampers with the bytes flips signature verification
/// failures, not silent compromise.
///
/// For confidentiality and to satisfy operational expectations,
/// authorities should put the daemon's `serve_consensus` endpoint
/// behind a TLS-terminating reverse proxy (nginx, Caddy, Apache).
/// The proxy listens on 443 with a Let's Encrypt cert and forwards
/// to `127.0.0.1:<port>` where the daemon serves plain consensus
/// bytes. This is the same pattern Tor uses for directory mirror
/// HTTP endpoints — TLS is operator concern, not protocol concern.
///
/// Clients fetching from the proxy use HTTPS at the URL level; the
/// daemon does the HTTP request internally to whatever URL it's
/// configured with. Both `http://` and `https://` URLs are accepted
/// here, but the daemon only handles HTTP — operators who configure
/// `https://` need the URL to point at a port that does plain HTTP
/// (e.g. `https://localhost:8080` is invalid, `http://auth1.example.com/consensus.json`
/// is valid; production setups typically use `http://127.0.0.1:8080`
/// when the daemon is co-located with the proxy).
///
/// If you need real HTTPS in the daemon itself (e.g. fetching
/// directly from authorities without a local proxy), add a
/// `tls = ["rustls", "tokio-rustls", "webpki-roots"]` feature
/// flag to phinet-core's Cargo.toml — the dependencies are well-
/// behaved and the integration is mechanical. Deferred so the
/// default daemon binary stays as small as possible.
/// Try each URL in turn, returning the first that fetches *and verifies*.
///
/// One consensus host is one machine whose failure stops the whole network:
/// a node that can't get a consensus has no path table, so it can't build a
/// circuit, so it isn't on the network at all. That's a strange dependency
/// for a system whose point is not having a centre — and it isn't only about
/// outages. A single host is also a single place to lean on: serve one client
/// a different consensus and you've chosen its relays for it.
///
/// The signature is what makes multiple sources safe. Any host can serve the
/// bytes; only the authorities can sign them. A mirror that lies produces a
/// document that fails verification, and we move to the next — so mirrors
/// need no trust at all, which means anyone can run one.
async fn try_fetch_any(node: &Arc<PhiNode>, urls: &[String]) -> Result<(bool, String), String> {
    let mut last_err = String::from("no consensus sources configured");
    for url in urls {
        match try_fetch_url(node, url).await {
            Ok(updated) => return Ok((updated, url.clone())),
            Err(e) => {
                tracing::debug!("consensus source {} unusable: {}", url, e);
                last_err = format!("{url}: {e}");
            }
        }
    }
    Err(last_err)
}

pub async fn refresh_loop_url(node: Arc<PhiNode>, url: String) {
    refresh_loop_urls(node, vec![url]).await
}

/// Refresh from any of several sources, preferring the earlier ones.
pub async fn refresh_loop_urls(node: Arc<PhiNode>, urls: Vec<String>) {
    let url = urls.join(", ");

    // Initial fetch, then keep trying *quickly* until one lands. Until it
    // does this node can't build a circuit at all, so the normal 15-minute
    // rhythm is the wrong clock entirely.
    // Log success, not just failure. A daemon that says nothing on a good
    // load forces the operator to infer health from the absence of a warning
    // — which is indistinguishable from the log line never being reached.
    match try_fetch_url(&node, &url).await {
        Ok(_) => {
            let n = node.cached_consensus.read().await
                .as_ref().map(|d| d.peers.len()).unwrap_or(0);
            tracing::info!("consensus loaded from {}: {} relay(s)", url, n);
        }
        Err(e) => {
        tracing::warn!("initial consensus fetch from {}: {}", url, e);
        let mut backoff = COLD_RETRY_INTERVAL;
        loop {
            if node.is_shutting_down() { return; }
            tokio::time::sleep(backoff).await;
            if node.is_shutting_down() { return; }
            match try_fetch_any(&node, &urls).await {
                Ok((_, src)) => {
                    tracing::info!("consensus acquired from {} — node is usable", src);
                    break;
                }
                Err(e) => {
                    tracing::warn!("no consensus source is usable yet ({}); \
                                    retrying in {:?} — this node cannot build \
                                    circuits until it has one", e, backoff);
                    backoff = (backoff * 2).min(COLD_RETRY_MAX);
                }
            }
        }
        }
    }

    loop {
        if node.is_shutting_down() {
            return;
        }
        tokio::time::sleep(REFRESH_INTERVAL).await;
        if node.is_shutting_down() {
            return;
        }
        match try_fetch_any(&node, &urls).await {
            Ok((updated, src)) => {
                if updated {
                    tracing::info!("consensus refreshed from {}", src);
                }
            }
            Err(e) => {
                tracing::warn!("consensus refresh failed on every source: {}", e);
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// One-shot fetch + verify + swap. Returns Ok(true) if a new
/// consensus was installed, Ok(false) if the bytes match what's
/// already cached, Err on fetch/parse/verify failure.
async fn try_fetch_url(node: &Arc<PhiNode>, url: &str) -> Result<bool, String> {
    let bytes = http_get(url).await?;
    let consensus: ConsensusDocument = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse: {}", e))?;
    install_consensus(node, consensus).await
}

/// Minimal HTTP/1.1 GET client. Plain-text only (see refresh_loop_url
/// for the TLS-termination pattern). Bounded body size, bounded
/// timeout, follows up to 3 redirects.
///
/// Returns the body bytes on 2xx response. Errors otherwise.
///
/// Why hand-rolled instead of `reqwest`: keeps the daemon's
/// dependency tree minimal. The protocol surface we need is tiny
/// (one GET request, parse status line + headers, read body) and
/// the alternative (reqwest + its hyper + tower stack) would add
/// dozens of crates for a feature that's rarely on the hot path.
async fn http_get(url: &str) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    const MAX_BODY: usize = 16 * 1024 * 1024;     // 16 MB
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    const MAX_REDIRECTS: usize = 3;

    let mut current_url = url.to_string();
    for redirect in 0..=MAX_REDIRECTS {
        // Strip scheme. We accept both http:// and https:// in the
        // URL string for operator convenience but only do plain HTTP
        // on the wire — see the comment at refresh_loop_url. If
        // someone passes an https:// URL pointing at a port that
        // doesn't speak plain HTTP, the read fails with a parse
        // error and they get a clear log message.
        let rest = current_url
            .strip_prefix("http://")
            .or_else(|| current_url.strip_prefix("https://"))
            .ok_or_else(|| format!(
                "url must start with http:// or https://, got {}", current_url))?;

        // Split host[:port]/path
        let (host_part, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None    => (rest, "/"),
        };
        let (host, port) = match host_part.rfind(':') {
            Some(i) => {
                let p: u16 = host_part[i+1..].parse()
                    .map_err(|e| format!("port: {}", e))?;
                (&host_part[..i], p)
            }
            None => {
                // Default by scheme. https:// implies operator wants
                // 443 (where the TLS proxy lives); http:// implies 80.
                let p = if current_url.starts_with("https://") { 443 } else { 80 };
                (host_part, p)
            }
        };

        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let mut stream = TcpStream::connect((host, port)).await
                .map_err(|e| format!("connect {}:{}: {}", host, port, e))?;

            // Send minimal HTTP/1.1 request. Connection: close so we
            // don't have to deal with keep-alive accounting; one
            // request per fetch, the connection cost is amortized
            // across the 15-min refresh interval.
            let req = format!(
                "GET {} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: phinet-daemon/0.1\r\n\
                 Accept: application/json\r\n\
                 Connection: close\r\n\r\n",
                path, host);
            stream.write_all(req.as_bytes()).await
                .map_err(|e| format!("write request: {}", e))?;

            let mut reader = BufReader::new(stream);

            // Status line
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await
                .map_err(|e| format!("read status: {}", e))?;
            let status: u16 = status_line.split_whitespace().nth(1)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("malformed status: {:?}", status_line))?;

            // Headers — collect Content-Length and Location, ignore rest
            let mut content_length: Option<usize> = None;
            let mut location: Option<String> = None;
            let mut chunked = false;
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await
                    .map_err(|e| format!("read header: {}", e))?;
                if n == 0 { break; }
                let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                if trimmed.is_empty() { break; }
                if let Some(colon) = trimmed.find(':') {
                    let name  = trimmed[..colon].trim().to_ascii_lowercase();
                    let value = trimmed[colon+1..].trim();
                    match name.as_str() {
                        "content-length" => {
                            content_length = value.parse().ok();
                        }
                        "location" => {
                            location = Some(value.to_string());
                        }
                        "transfer-encoding" => {
                            if value.to_ascii_lowercase().contains("chunked") {
                                chunked = true;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Handle redirects
            if (300..400).contains(&status) {
                if let Some(loc) = location {
                    return Ok::<RedirectOrBody, String>(RedirectOrBody::Redirect(loc));
                }
                return Err(format!("redirect status {} without Location", status));
            }
            if !(200..300).contains(&status) {
                return Err(format!("HTTP {}", status));
            }

            // Read body
            let body = if chunked {
                read_chunked(&mut reader, MAX_BODY).await?
            } else if let Some(len) = content_length {
                if len > MAX_BODY {
                    return Err(format!("body length {} exceeds cap {}", len, MAX_BODY));
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await
                    .map_err(|e| format!("read body: {}", e))?;
                buf
            } else {
                // No content-length, no chunked — read until EOF
                let mut buf = Vec::new();
                let mut total = 0usize;
                let mut chunk = [0u8; 8192];
                loop {
                    let n = reader.read(&mut chunk).await
                        .map_err(|e| format!("read body: {}", e))?;
                    if n == 0 { break; }
                    total += n;
                    if total > MAX_BODY {
                        return Err(format!("body exceeds cap {}", MAX_BODY));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                buf
            };

            Ok(RedirectOrBody::Body(body))
        }).await
            .map_err(|_| "request timed out".to_string())??;

        match result {
            RedirectOrBody::Body(b) => return Ok(b),
            RedirectOrBody::Redirect(loc) => {
                if redirect == MAX_REDIRECTS {
                    return Err(format!("too many redirects (last: {})", loc));
                }
                tracing::debug!("redirect: {} → {}", current_url, loc);
                // Resolve relative redirect target
                current_url = if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc
                } else if loc.starts_with('/') {
                    // Relative-to-host: keep scheme + host from
                    // current_url, replace path
                    let scheme_end = current_url.find("://")
                        .ok_or_else(|| "current url missing scheme".to_string())?;
                    let rest = &current_url[scheme_end + 3..];
                    let host_end = rest.find('/').unwrap_or(rest.len());
                    format!("{}{}", &current_url[..scheme_end + 3 + host_end], loc)
                } else {
                    return Err(format!("unsupported redirect target: {}", loc));
                };
            }
        }
    }
    Err("redirect loop exited unexpectedly".into())
}

enum RedirectOrBody {
    Body(Vec<u8>),
    Redirect(String),
}

/// Read a chunked-transfer-encoding body up to `cap` bytes total.
async fn read_chunked<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut buf = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await
            .map_err(|e| format!("read chunk size: {}", e))?;
        let size_hex = size_line.trim_end_matches(&['\r', '\n'][..])
            .split(';').next().unwrap_or("0").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| format!("chunk size {:?}: {}", size_hex, e))?;
        if size == 0 {
            // Read trailing CRLF after final 0-size chunk
            let mut tail = String::new();
            let _ = reader.read_line(&mut tail).await;
            break;
        }
        if buf.len() + size > cap {
            return Err(format!("body exceeds cap {} (chunked)", cap));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await
            .map_err(|e| format!("read chunk body: {}", e))?;
        buf.extend_from_slice(&chunk);
        // Trailing CRLF after each chunk
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await
            .map_err(|e| format!("read chunk crlf: {}", e))?;
    }
    Ok(buf)
}

/// Periodically read `path` from disk, verify, swap in.
pub async fn refresh_loop_path(node: Arc<PhiNode>, path: String) {
    tracing::info!("consensus refresh: file mode, path={}", path);

    // Initial load, then keep retrying quickly until one lands — see
    // COLD_RETRY_INTERVAL. In file mode this is the common case during a
    // re-vote: the daemon restarts while the operator is still assembling
    // signatures, and without this it sits useless for fifteen minutes after
    // the file becomes valid.
    match try_load_path(&node, &path).await {
        Ok(_) => {
            let n = node.cached_consensus.read().await
                .as_ref().map(|d| d.peers.len()).unwrap_or(0);
            tracing::info!("consensus loaded from {}: {} relay(s)", path, n);
        }
        Err(e) => {
        tracing::warn!("initial consensus load from {}: {}", path, e);
        let mut backoff = COLD_RETRY_INTERVAL;
        loop {
            if node.is_shutting_down() { return; }
            tokio::time::sleep(backoff).await;
            if node.is_shutting_down() { return; }
            match try_load_path(&node, &path).await {
                Ok(_) => {
                    tracing::info!("consensus acquired from {} — node is usable", path);
                    break;
                }
                Err(e) => {
                    tracing::warn!("consensus not yet valid at {} ({}); retrying in \
                                    {:?} — this node cannot build circuits until it \
                                    has one", path, e, backoff);
                    backoff = (backoff * 2).min(COLD_RETRY_MAX);
                }
            }
        }
        }
    }

    loop {
        if node.is_shutting_down() {
            return;
        }
        tokio::time::sleep(REFRESH_INTERVAL).await;
        if node.is_shutting_down() {
            return;
        }
        match try_load_path(&node, &path).await {
            Ok(updated) => {
                if updated {
                    tracing::info!("consensus refreshed from {}", path);
                }
            }
            Err(e) => {
                tracing::warn!("consensus refresh from {}: {}", path, e);
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// One-shot load + verify + swap. Returns `Ok(true)` if a new
/// consensus was installed (different from cached), `Ok(false)` if
/// the consensus on disk matches what we already have, or `Err`
/// on parse/verify failure.
async fn try_load_path(node: &Arc<PhiNode>, path: &str) -> Result<bool, String> {
    let bytes = tokio::fs::read_to_string(path).await
        .map_err(|e| format!("read {}: {}", path, e))?;
    let consensus: ConsensusDocument = serde_json::from_str(&bytes)
        .map_err(|e| format!("parse {}: {}", path, e))?;
    install_consensus(node, consensus).await
}

/// Verify and install a consensus into `node.cached_consensus`.
/// Public so it can be invoked from a control-port command too
/// (the daemon's `consensus_load` command uses this).
pub async fn install_consensus(
    node: &Arc<PhiNode>,
    consensus: ConsensusDocument,
) -> Result<bool, String> {
    let trusted = node.trusted_authorities.read().await.clone();
    if trusted.is_empty() {
        return Err("no trusted authorities configured \
                    (use --trusted-authority on daemon startup)".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let min_sigs = threshold_for(trusted.len());
    verify_consensus(&consensus, &trusted, min_sigs, now)
        .map_err(|e| format!("verify: {}", e))?;

    // Compare hash with existing — only swap if different. Saves
    // a write lock on every refresh tick.
    let new_hash = crate::directory::consensus_hash(&consensus);
    {
        let cur = node.cached_consensus.read().await;
        if let Some(c) = cur.as_ref() {
            if crate::directory::consensus_hash(c) == new_hash {
                return Ok(false);
            }
        }
    }
    let mut guard = node.cached_consensus.write().await;
    *guard = Some(consensus);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{CertBits, PhiCert};
    use crate::directory::{
        ConsensusDocument, DirectoryAuthority, PeerEntry, PeerFlags,
    };
    use crate::store::SiteStore;

    struct HomeGuard {
        _tmp: tempfile::TempDir,
        old:  Option<String>,
    }
    impl HomeGuard {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let old = std::env::var("HOME").ok();
            std::env::set_var("HOME", tmp.path());
            Self { _tmp: tmp, old }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => std::env::set_var("HOME", v),
                None    => std::env::remove_var("HOME"),
            }
        }
    }

    fn build_node() -> Arc<PhiNode> {
        let _g    = HomeGuard::new();
        let cert  = PhiCert::generate(CertBits::B256).expect("gen");
        let store = Arc::new(SiteStore::new());
        PhiNode::new("127.0.0.1", 0, cert, store)
    }

    fn fake_peer(id: &str) -> PeerEntry {
        PeerEntry {
            node_id_hex: id.into(),
            host: "10.0.0.1".into(),
            port: 7700,
            static_pub_hex: format!("{:0<64}", id),
            flags: PeerFlags::all().bits(),
            bandwidth_kbs: 1000,
            exit_policy_summary: String::new(),
            family: String::new(),
        }
    }

    #[tokio::test]
    async fn install_consensus_with_no_trusted_authorities_fails() {
        let node = build_node();
        let auth = DirectoryAuthority::generate("net");
        let mut consensus = ConsensusDocument {
            network_id: "net".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 0,
            valid_until: u64::MAX,
            peers: vec![fake_peer("aa")],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut consensus);
        let r = install_consensus(&node, consensus).await;
        assert!(r.is_err());
        assert!(format!("{:?}", r).contains("no trusted authorities"));
    }

    #[tokio::test]
    async fn install_consensus_with_trusted_authority_succeeds() {
        let node = build_node();
        let auth = DirectoryAuthority::generate("net");
        let auth_pub: [u8; 32] = {
            let v = hex::decode(auth.pub_hex()).unwrap();
            let mut a = [0u8; 32]; a.copy_from_slice(&v); a
        };
        *node.trusted_authorities.write().await = vec![auth_pub];

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut consensus = ConsensusDocument {
            network_id: "net".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: now,
            valid_until: now + 3600,
            peers: vec![fake_peer("aa"), fake_peer("bb"), fake_peer("cc")],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut consensus);

        let r = install_consensus(&node, consensus.clone()).await;
        assert!(r.is_ok(), "install: {:?}", r);
        assert_eq!(r.unwrap(), true, "first install reports updated=true");

        // Second install of same content should report no update.
        let r2 = install_consensus(&node, consensus).await;
        assert_eq!(r2.unwrap(), false);

        // cached_consensus is populated
        assert!(node.cached_consensus.read().await.is_some());
    }

    #[tokio::test]
    async fn install_consensus_with_invalid_sig_rejected() {
        let node = build_node();
        let real_auth     = DirectoryAuthority::generate("net");
        let imposter_auth = DirectoryAuthority::generate("net");
        let real_pub: [u8; 32] = {
            let v = hex::decode(real_auth.pub_hex()).unwrap();
            let mut a = [0u8; 32]; a.copy_from_slice(&v); a
        };
        *node.trusted_authorities.write().await = vec![real_pub];

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut consensus = ConsensusDocument {
            network_id: "net".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: now,
            valid_until: now + 3600,
            peers: vec![fake_peer("aa")],
            signatures: Vec::new(),
        };
        // Imposter signs but isn't trusted; consensus has 0 valid sigs
        // from trusted authorities → rejected.
        imposter_auth.sign_consensus(&mut consensus);

        let r = install_consensus(&node, consensus).await;
        assert!(r.is_err());
        assert!(format!("{:?}", r).contains("verify"));
    }

    #[tokio::test]
    async fn install_consensus_expired_rejected() {
        let node = build_node();
        let auth = DirectoryAuthority::generate("net");
        let auth_pub: [u8; 32] = {
            let v = hex::decode(auth.pub_hex()).unwrap();
            let mut a = [0u8; 32]; a.copy_from_slice(&v); a
        };
        *node.trusted_authorities.write().await = vec![auth_pub];

        // Far in the past
        let mut consensus = ConsensusDocument {
            network_id: "net".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: 1000,
            valid_until: 2000,
            peers: vec![fake_peer("aa")],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut consensus);

        let r = install_consensus(&node, consensus).await;
        assert!(r.is_err());
        assert!(format!("{:?}", r).contains("expired"));
    }

    // ── HTTP fetch ───────────────────────────────────────────────────

    /// Stand up a minimal mock HTTP/1.1 server on a random port,
    /// returning a fixed body. Used to test http_get without
    /// depending on external services.
    async fn mock_http_server(
        body: Vec<u8>,
        content_type: &'static str,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let task = tokio::spawn(async move {
            // Accept just one connection; tests need only one fetch
            if let Ok((conn, _)) = listener.accept().await {
                let (rd, mut wr) = conn.into_split();
                let mut reader = BufReader::new(rd);

                // Drain request
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;
                loop {
                    let mut h = String::new();
                    let n = reader.read_line(&mut h).await.unwrap_or(0);
                    if n == 0 { break; }
                    if h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
                }

                let head = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: {}\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    content_type, body.len());
                let _ = wr.write_all(head.as_bytes()).await;
                let _ = wr.write_all(&body).await;
                let _ = wr.shutdown().await;
            }
        });
        (port, task)
    }

    #[tokio::test]
    async fn http_get_fetches_body_correctly() {
        let body = br#"{"hello":"world"}"#.to_vec();
        let (port, task) = mock_http_server(body.clone(), "application/json").await;
        let url = format!("http://127.0.0.1:{}/consensus.json", port);

        let got = super::http_get(&url).await.expect("http_get");
        assert_eq!(got, body);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn http_get_rejects_4xx_status() {
        // Mock that returns 404
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            if let Ok((conn, _)) = listener.accept().await {
                let (rd, mut wr) = conn.into_split();
                let mut reader = BufReader::new(rd);
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;
                loop {
                    let mut h = String::new();
                    let n = reader.read_line(&mut h).await.unwrap_or(0);
                    if n == 0 { break; }
                    if h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
                }
                let _ = wr.write_all(
                    b"HTTP/1.1 404 Not Found\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n"
                ).await;
                let _ = wr.shutdown().await;
            }
        });
        let url = format!("http://127.0.0.1:{}/", port);
        let r = super::http_get(&url).await;
        assert!(r.is_err());
        assert!(format!("{:?}", r).contains("404"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_get_rejects_oversized_body() {
        // Server claims 100 MB content-length; http_get caps at 16 MB.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            if let Ok((conn, _)) = listener.accept().await {
                let (rd, mut wr) = conn.into_split();
                let mut reader = BufReader::new(rd);
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;
                loop {
                    let mut h = String::new();
                    let n = reader.read_line(&mut h).await.unwrap_or(0);
                    if n == 0 { break; }
                    if h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
                }
                let _ = wr.write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Length: 104857600\r\n\
                      Connection: close\r\n\r\n"
                ).await;
                let _ = wr.shutdown().await;
            }
        });
        let url = format!("http://127.0.0.1:{}/", port);
        let r = super::http_get(&url).await;
        assert!(r.is_err());
        assert!(format!("{:?}", r).contains("exceeds cap"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_get_chunked_body() {
        // Mock that uses chunked transfer encoding.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            if let Ok((conn, _)) = listener.accept().await {
                let (rd, mut wr) = conn.into_split();
                let mut reader = BufReader::new(rd);
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;
                loop {
                    let mut h = String::new();
                    let n = reader.read_line(&mut h).await.unwrap_or(0);
                    if n == 0 { break; }
                    if h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
                }
                // Two chunks: "Hello, " then "World!" then 0
                let _ = wr.write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Transfer-Encoding: chunked\r\n\
                      Connection: close\r\n\r\n\
                      7\r\nHello, \r\n\
                      6\r\nWorld!\r\n\
                      0\r\n\r\n"
                ).await;
                let _ = wr.shutdown().await;
            }
        });
        let url = format!("http://127.0.0.1:{}/", port);
        let r = super::http_get(&url).await.expect("chunked");
        assert_eq!(r, b"Hello, World!");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn try_fetch_url_installs_signed_consensus() {
        // End-to-end: serve a signed consensus over HTTP, fetch it,
        // verify it gets installed into cached_consensus.
        let node = build_node();
        let auth = DirectoryAuthority::generate("net");
        let auth_pub: [u8; 32] = {
            let v = hex::decode(auth.pub_hex()).unwrap();
            let mut a = [0u8; 32]; a.copy_from_slice(&v); a
        };
        *node.trusted_authorities.write().await = vec![auth_pub];

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut consensus = ConsensusDocument {
            network_id: "net".into(),
            shared_random: String::new(),
            srv_commitments: Vec::new(),
            valid_after: now,
            valid_until: now + 3600,
            peers: vec![fake_peer("aa")],
            signatures: Vec::new(),
        };
        auth.sign_consensus(&mut consensus);
        let body = serde_json::to_vec(&consensus).unwrap();

        let (port, task) = mock_http_server(body, "application/json").await;
        let url = format!("http://127.0.0.1:{}/consensus.json", port);

        let updated = super::try_fetch_url(&node, &url).await.expect("fetch");
        assert!(updated, "first fetch should report updated=true");
        assert!(node.cached_consensus.read().await.is_some());
        task.await.unwrap();
    }
}
