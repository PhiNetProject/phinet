// phinet-daemon/src/main.rs
//! ΦNET Daemon — network node + JSON control socket on 127.0.0.1:7799

use anyhow::{Context, Result};
use phinet_core::{
    cert::{CertBits, PhiCert, WireCert},
    crypto::StaticKeypair,
    node::PhiNode,
    store::{identity_path, sites_dir, SiteStore},
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time,
};
use tracing::{info, warn};

// ── Identity ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    cert: WireCert,
    /// Hex x25519 static secret. The consensus publishes the matching
    /// public key as this relay's `B`; if we regenerated it on each start
    /// our own consensus entry would be wrong and every client CREATE
    /// would fail the ntor handshake. Optional so identities written by
    /// older builds still load (they get a fresh key, once).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    static_secret: Option<String>,
    /// Hex Ed25519 secret, for signing this relay's descriptor.
    ///
    /// Separate from the x25519 static key because they do different jobs:
    /// x25519 agrees keys with one peer on one link, Ed25519 signs statements
    /// anyone can check later. The relay had no way to make a checkable
    /// statement before this existed, which is why `--family` only worked for
    /// operators who also ran an authority.
    ///
    /// Optional so identities from older builds still load — they mint one
    /// once. Minting is safe: it doesn't touch the cert, so the node id and
    /// every consensus entry stay exactly as they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_secret: Option<String>,
}

/// Load or mint the relay's Ed25519 signing key, persisting it alongside the
/// identity. Returns `None` only if the identity file can't be written.
fn load_or_create_signing_key() -> Option<ed25519_dalek::SigningKey> {
    use ed25519_dalek::SigningKey;
    let path = identity_path();
    let json = std::fs::read_to_string(&path).ok()?;
    let mut saved: SavedIdentity = serde_json::from_str(&json).ok()?;

    if let Some(k) = saved.signing_secret.as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        return Some(SigningKey::from_bytes(&k));
    }

    // First run on this build: mint and save. Doing this once and persisting
    // it matters — a signing key that changed each restart would invalidate
    // every pin other relays hold, and they'd read it as impersonation.
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    saved.signing_secret = Some(hex::encode(sk.to_bytes()));
    if let Ok(out) = serde_json::to_string_pretty(&saved) {
        let _ = std::fs::write(&path, out);
        info!("Minted this relay's descriptor signing key (one-time; node id unchanged)");
    }
    Some(sk)
}

fn load_or_create(bits: CertBits, reset: bool) -> Result<(PhiCert, StaticKeypair)> {
    let path = identity_path();
    std::fs::create_dir_all(path.parent().unwrap())?;

    if !reset && path.exists() {
        if let Ok(json) = std::fs::read_to_string(&path) {
            if let Ok(saved) = serde_json::from_str::<SavedIdentity>(&json) {
                if let Ok(cert) = PhiCert::from_wire(&saved.cert) {
                    if cert.verify() {
                        let kp = saved.static_secret.as_deref()
                            .and_then(|h| hex::decode(h).ok())
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(|b| StaticKeypair::from_secret_bytes(&b));
                        match kp {
                            Some(kp) => {
                                info!("Loaded identity from {}", path.display());
                                return Ok((cert, kp));
                            }
                            None => {
                                // Pre-upgrade identity: mint a static key and
                                // persist it so this is a one-time event. The
                                // relay's consensus entry must be regenerated
                                // (gen-genesis) to carry the new key.
                                let kp = StaticKeypair::generate();
                                warn!("Identity has no saved static key (older \
                                       build) — generated one and saved it. \
                                       Regenerate the consensus so this relay's \
                                       static_pub is correct.");
                                let saved = serde_json::to_string_pretty(&SavedIdentity {
                                    cert: cert.to_wire(),
                                    static_secret: Some(hex::encode(kp.secret_bytes())),
                                    // Minted lazily on first use, so an
                                    // upgrade doesn't rewrite a working
                                    // identity file more than it must.
                                    signing_secret: None,
                                })?;
                                std::fs::write(&path, saved)?;
                                return Ok((cert, kp));
                            }
                        }
                    }
                }
            }
        }
        warn!("Saved identity invalid — regenerating");
    }

    info!("Generating {}-bit ΦNET identity…", bits.bits());
    let cert  = PhiCert::generate(bits).context("cert generation failed")?;
    let kp    = StaticKeypair::generate();
    let saved = serde_json::to_string_pretty(&SavedIdentity {
        cert: cert.to_wire(),
        static_secret: Some(hex::encode(kp.secret_bytes())),
        signing_secret: None,
    })?;
    std::fs::write(&path, saved)?;

    // Restrict permissions so only the owner can read/write — this file
    // now holds the node's private x25519 static key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path,
            std::fs::Permissions::from_mode(0o600));
    }

    info!("Identity saved to {}", path.display());
    Ok((cert, kp))
}

// ── Control socket ────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct Req {
    cmd:      String,
    /// Hex control cookie. Every command except `ping` must carry it.
    cookie:   Option<String>,
    hs_id:    Option<String>,
    path:     Option<String>,
    method:   Option<String>,
    name:     Option<String>,
    channel:  Option<String>,
    text:     Option<String>,
    node_id_hex: Option<String>,
    group_id:    Option<String>,
    is_channel:  Option<bool>,
    address:     Option<String>,
    msg_id:      Option<String>,
}

#[derive(Serialize)]
struct Resp {
    ok:    bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(flatten)]
    data:  serde_json::Value,
}

impl Resp {
    fn ok(data: serde_json::Value) -> Self { Self { ok: true,  error: None,               data } }
    fn err(msg: &str)              -> Self { Self { ok: false, error: Some(msg.to_string()), data: serde_json::Value::Null } }
}

async fn run_ctl(node: Arc<PhiNode>, port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let srv  = TcpListener::bind(&addr).await?;
    info!("Control socket on {}", addr);
    loop {
        let (conn, _) = srv.accept().await?;
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = handle_ctl(conn, n).await { tracing::debug!("ctl: {}", e); }
        });
    }
}

/// Serve the cached consensus over plain HTTP/1.1.
///
/// **Bind address: 127.0.0.1**. The endpoint is intended to be
/// fronted by a TLS-terminating reverse proxy (nginx/Caddy/Apache)
/// that handles the HTTPS cert and forwards to this. We don't bind
/// 0.0.0.0 because that would publish raw HTTP on the public
/// internet — operationally legitimate but easy to misconfigure.
/// If you want public exposure, set up the reverse proxy. If you
/// want to bypass it, change the bind address yourself; the model
/// is documented in `phinet-core/src/consensus_fetch.rs`.
///
/// Endpoints:
///   - `GET /consensus.json` → JSON-serialized cached consensus
///   - `GET /consensus.hash` → hex SHA-256 of canonical consensus bytes
///                              (cheap diff-check for clients)
///   - other paths → 404
///
/// Returns 503 if no consensus is cached yet (authority hasn't run
/// merge-votes). Clients should retry later.
/// Serve the **com** messenger UI + a small JSON API over localhost
/// HTTP. Bound to 127.0.0.1 only. The bundled single-file UI (`GET /`)
/// talks to `/api/*` on the same origin. This is the "com app" — the
/// messaging analogue of the ΦNET browser, but served as a static page
/// so no separate build/toolchain is needed.
async fn serve_com_http(node: Arc<PhiNode>, port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let srv  = TcpListener::bind(&addr).await
        .with_context(|| format!("bind com HTTP on {}", addr))?;
    info!("com UI on http://{}", addr);
    loop {
        let (conn, _) = srv.accept().await?;
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = handle_com_http(conn, n).await {
                tracing::debug!("com http: {}", e);
            }
        });
    }
}

/// Percent-decode a query-string value (enough of it for message text).
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                let h = |c: u8| (c as char).to_digit(16);
                match (h(b[i+1]), h(b[i+2])) {
                    (Some(a), Some(c)) => { out.push((a * 16 + c) as u8); i += 3; }
                    _ => { out.push(b'%'); i += 1; }
                }
            }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `k=v&k2=v2` into a lookup.
fn query_params(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&').filter_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        Some((k.to_string(), url_decode(v)))
    }).collect()
}

async fn handle_com_http(stream: TcpStream, node: Arc<PhiNode>) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut req_line = String::new();
    reader.read_line(&mut req_line).await?;
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = wr.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
        return Ok(());
    }
    let method = parts[0].to_string();
    let target = parts[1].to_string();
    // Read headers. Host and Origin decide whether this request is allowed
    // at all, so they can't be drained unread.
    let mut host_hdr   = String::new();
    let mut origin_hdr = String::new();
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h).await?;
        if n == 0 || h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
        let (k, v) = match h.split_once(':') { Some(kv) => kv, None => continue };
        match k.trim().to_ascii_lowercase().as_str() {
            "host"   => host_hdr   = v.trim().to_string(),
            "origin" => origin_hdr = v.trim().to_string(),
            _ => {}
        }
    }

    // Anti DNS-rebinding: a name that resolves to 127.0.0.1 lets a remote page
    // address this server as if it were its own origin. Only accept the
    // literal loopback host we bind to.
    let host_ok = host_hdr.is_empty()
        || host_hdr.starts_with("127.0.0.1:")
        || host_hdr.starts_with("localhost:")
        || host_hdr == "127.0.0.1" || host_hdr == "localhost";
    // Anti CSRF: the bundled UI is same-origin and sends no Origin. A browser
    // attaches Origin to cross-site requests, so any Origin at all means some
    // *other* page is driving this API, and it doesn't get to.
    let origin_ok = origin_hdr.is_empty()
        || origin_hdr.starts_with("http://127.0.0.1:")
        || origin_hdr.starts_with("http://localhost:");
    if !host_ok || !origin_ok {
        warn!("com UI: rejected request (host={:?} origin={:?}) — a page on \
               another site tried to drive this node's messenger",
              host_hdr, origin_hdr);
        let _ = wr.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
        return Ok(());
    }

    // Helper to send a JSON body with permissive localhost CORS.
    async fn send_json<W: tokio::io::AsyncWrite + Unpin>(
        wr: &mut W, code: &str, body: &[u8],
    ) -> Result<()> {
        // No Access-Control-Allow-Origin. It used to be `*`, which invited
        // every site the user visits to read this node's com threads and
        // address: the browser makes the request and the wildcard tells it to
        // hand over the reply. The bundled UI is same-origin and needs no CORS
        // at all, so the safe value is no header.
        let head = format!(
            "HTTP/1.1 {code}\r\nContent-Type: application/json\r\n\
             X-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n", body.len());
        wr.write_all(head.as_bytes()).await?;
        wr.write_all(body).await?;
        Ok(())
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let params = query_params(&query);

    if method == "OPTIONS" {
        // The preflight used to answer "any origin, any header" — which is a
        // standing invitation for other sites to call this API. Same-origin
        // requests don't preflight, so grant nothing.
        let _ = wr.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        return Ok(());
    }

    match path.as_str() {
        "/" | "/index.html" => {
            let body = include_str!("com_ui.html").as_bytes();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            wr.write_all(head.as_bytes()).await?;
            if method == "GET" { wr.write_all(body).await?; }
        }
        "/api/whoami" => {
            let body = serde_json::to_vec(&serde_json::json!({
                "node_id":    node.node_id_hex(),
                "static_pub": hex::encode(node.static_pub()),
            }))?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/peers" => {
            let peers = node.peers_snapshot().await;
            let body = serde_json::to_vec(&serde_json::json!({
                "peers": peers.iter().map(|p| serde_json::json!({
                    "node_id":    hex::encode(p.node_id),
                    "static_pub": p.static_pub,
                    "host":       p.host,
                    "port":       p.port,
                })).collect::<Vec<_>>(),
            }))?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/delete" => {
            let peer = params.get("peer").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8;32]>::try_from(v).ok());
            let mid  = params.get("msg_id").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8;16]>::try_from(v).ok());
            match (peer, mid) {
                (Some(p), Some(m)) => {
                    let _ = node.com_delete(p, m).await;
                    send_json(&mut wr, "200 OK", br#"{"ok":true}"#).await?;
                }
                _ => send_json(&mut wr, "400 Bad Request",
                    br#"{"error":"need peer and msg_id"}"#).await?,
            }
        }
        "/api/circuit" => {
            let body = serde_json::to_vec(&node.circuit_info().await)?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/new_identity" => {
            node.new_identity().await;
            send_json(&mut wr, "200 OK", br#"{"ok":true}"#).await?;
        }
        "/api/my_address" => {
            let body = serde_json::to_vec(&serde_json::json!({
                "address": node.com_my_address(),
            }))?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/add_contact" => {
            // Add a contact from an out-of-band address (phi:<128 hex>).
            match params.get("address").and_then(|a| phinet_core::com::address_decode(a)) {
                Some((nid, spk)) => {
                    node.com_add_contact(nid, spk).await;
                    let body = serde_json::to_vec(&serde_json::json!({
                        "ok": true, "node_id": hex::encode(nid) }))?;
                    send_json(&mut wr, "200 OK", &body).await?;
                }
                None => send_json(&mut wr, "400 Bad Request",
                    br#"{"error":"invalid address (expected phi:<128 hex>)"}"#).await?,
            }
        }
        "/api/threads" => {
            let threads = node.com_threads().await;
            let body = serde_json::to_vec(&serde_json::json!({
                "threads": threads.iter().map(hex::encode).collect::<Vec<_>>(),
            }))?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/thread" => {
            let peer = params.get("peer").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok());
            match peer {
                Some(pid) => {
                    let conv = node.com_conversation(&pid).await;
                    let body = serde_json::to_vec(&serde_json::json!({
                        "messages": conv.iter().map(|(out, ts, b, mid)| serde_json::json!({
                            "outgoing": out, "timestamp": ts, "body": b, "msg_id": mid })).collect::<Vec<_>>(),
                    }))?;
                    send_json(&mut wr, "200 OK", &body).await?;
                }
                None => send_json(&mut wr, "400 Bad Request",
                    br#"{"error":"bad or missing peer"}"#).await?,
            }
        }
        "/api/send" => {
            let peer = params.get("peer").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok());
            let text = params.get("text").cloned().unwrap_or_default();
            match peer {
                Some(pid) if !text.is_empty() => match node.com_send_to(pid, &text).await {
                    Ok(mid) => {
                        let body = serde_json::to_vec(&serde_json::json!({
                            "ok": true, "msg_id": hex::encode(mid) }))?;
                        send_json(&mut wr, "200 OK", &body).await?;
                    }
                    Err(e) => {
                        let body = serde_json::to_vec(&serde_json::json!({
                            "error": format!("{e}") }))?;
                        send_json(&mut wr, "200 OK", &body).await?;
                    }
                },
                _ => send_json(&mut wr, "400 Bad Request",
                    br#"{"error":"need peer and text"}"#).await?,
            }
        }
        "/api/groups" => {
            let groups = node.com_groups_list().await;
            let body = serde_json::to_vec(&serde_json::json!({
                "groups": groups.iter().map(|(gid, name, ch, tid)| serde_json::json!({
                    "group_id": hex::encode(gid), "name": name,
                    "is_channel": ch, "thread_id": hex::encode(tid),
                })).collect::<Vec<_>>(),
            }))?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/create_group" => {
            let name = params.get("name").cloned().unwrap_or_else(|| "group".into());
            let is_channel = params.get("channel").map(|v| v == "1" || v == "true")
                .unwrap_or(false);
            let g = node.com_create_group(&name, is_channel).await;
            let body = serde_json::to_vec(&serde_json::json!({
                "group_id": hex::encode(g.group_id),
                "thread_id": hex::encode(PhiNode::group_thread_id(&g.group_id)),
                "name": g.name, "is_channel": g.is_channel,
            }))?;
            send_json(&mut wr, "200 OK", &body).await?;
        }
        "/api/invite" => {
            let gid = params.get("group").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 16]>::try_from(v).ok());
            let mid = params.get("peer").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok());
            match (gid, mid) {
                (Some(g), Some(m)) => {
                    let r = node.com_invite_to_group(g, m).await;
                    let body = match r {
                        Ok(())  => serde_json::to_vec(&serde_json::json!({ "ok": true }))?,
                        Err(e)  => serde_json::to_vec(&serde_json::json!({ "error": format!("{e}") }))?,
                    };
                    send_json(&mut wr, "200 OK", &body).await?;
                }
                _ => send_json(&mut wr, "400 Bad Request",
                    br#"{"error":"need group and peer"}"#).await?,
            }
        }
        "/api/send_group" => {
            let gid = params.get("group").and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 16]>::try_from(v).ok());
            let text = params.get("text").cloned().unwrap_or_default();
            match gid {
                Some(g) if !text.is_empty() => match node.com_send_group(g, &text).await {
                    Ok(mid) => {
                        let body = serde_json::to_vec(&serde_json::json!({
                            "ok": true, "msg_id": hex::encode(mid) }))?;
                        send_json(&mut wr, "200 OK", &body).await?;
                    }
                    Err(e) => {
                        let body = serde_json::to_vec(&serde_json::json!({ "error": format!("{e}") }))?;
                        send_json(&mut wr, "200 OK", &body).await?;
                    }
                },
                _ => send_json(&mut wr, "400 Bad Request",
                    br#"{"error":"need group and text"}"#).await?,
            }
        }
        _ => {
            let _ = wr.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        }
    }
    let _ = wr.shutdown().await;
    Ok(())
}

async fn serve_consensus_http(node: Arc<PhiNode>, port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let srv  = TcpListener::bind(&addr).await
        .with_context(|| format!("bind consensus HTTP on {}", addr))?;
    info!("Consensus HTTP on {}", addr);

    loop {
        let (conn, _) = srv.accept().await?;
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = handle_consensus_http(conn, n).await {
                tracing::debug!("consensus http: {}", e);
            }
        });
    }
}

async fn handle_consensus_http(stream: TcpStream, node: Arc<PhiNode>) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    // Parse request line: METHOD PATH HTTP/1.1
    let mut req_line = String::new();
    reader.read_line(&mut req_line).await?;
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = wr.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
        return Ok(());
    }
    let method = parts[0];
    let path   = parts[1];

    // Drain headers (we don't care about them but must consume to
    // avoid a half-closed read leaving bytes in the socket).
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h).await?;
        if n == 0 { break; }
        if h.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
    }

    if method != "GET" && method != "HEAD" {
        let _ = wr.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\
                              Allow: GET, HEAD\r\n\
                              Content-Length: 0\r\n\r\n").await;
        return Ok(());
    }

    let cached = node.cached_consensus.read().await;
    let consensus = match cached.as_ref() {
        Some(c) => c.clone(),
        None => {
            let _ = wr.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 31\r\n\r\n\
                  no consensus cached on this host"
            ).await;
            return Ok(());
        }
    };
    drop(cached);

    match path {
        "/consensus.json" => {
            let body = serde_json::to_vec_pretty(&consensus)?;
            let head = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: max-age=300\r\n\
                 Connection: close\r\n\r\n",
                body.len());
            wr.write_all(head.as_bytes()).await?;
            if method == "GET" {
                wr.write_all(&body).await?;
            }
        }
        "/consensus.hash" => {
            let hash = phinet_core::directory::consensus_hash(&consensus);
            let body = format!("{}\n", hex::encode(hash));
            let head = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len());
            wr.write_all(head.as_bytes()).await?;
            if method == "GET" {
                wr.write_all(body.as_bytes()).await?;
            }
        }
        _ => {
            let _ = wr.write_all(
                b"HTTP/1.1 404 Not Found\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 9\r\n\r\n\
                  not found"
            ).await;
        }
    }
    let _ = wr.shutdown().await;
    Ok(())
}


// ── Control-socket authentication ─────────────────────────────────────
//
// The control socket can read com threads, send messages as this node, and
// reveal its address — so "it's only bound to localhost" is not a boundary.
// On Android every installed app can reach 127.0.0.1; on a desktop every
// local process can. Tor gates its control port behind a cookie file for
// exactly this reason, and so do we: the cookie sits in the node's own data
// directory at mode 0600, so the barrier is filesystem permissions rather
// than a hope that nothing else is listening.

static COOKIE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn control_cookie_path() -> std::path::PathBuf {
    identity_path().parent().unwrap().join("control.cookie")
}

/// Load the cookie, creating one on first run.
fn load_or_create_cookie() -> Result<String> {
    let path = control_cookie_path();
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if s.len() == 64 { return Ok(s); }
    }
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let hex = hex::encode(raw);
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, &hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    info!("Control cookie written to {}", path.display());
    Ok(hex)
}

/// Constant-time compare so a wrong cookie can't be recovered by timing the
/// rejection.
fn cookie_ok(given: Option<&str>, want: &str) -> bool {
    let g = match given { Some(g) => g.as_bytes(), None => return false };
    let w = want.as_bytes();
    if g.len() != w.len() { return false; }
    let mut diff = 0u8;
    for i in 0..w.len() { diff |= g[i] ^ w[i]; }
    diff == 0
}

async fn handle_ctl(stream: TcpStream, node: Arc<PhiNode>) -> Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    while let Some(line) = lines.next_line().await? {
        let resp = match serde_json::from_str::<Req>(&line) {
            Err(e)  => Resp::err(&format!("parse: {}", e)),
            Ok(req) => {
                // `ping` stays open so a client can check whether a daemon is
                // up without holding the cookie; it discloses nothing else.
                let cookie = COOKIE.get().map(|s| s.as_str()).unwrap_or("");
                if req.cmd != "ping" && !cookie_ok(req.cookie.as_deref(), cookie) {
                    Resp::err("unauthorized: control cookie missing or wrong \
                               (read it from .phinet/control.cookie)")
                } else {
                    dispatch(&req, &node).await
                }
            }
        };
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        wr.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

async fn dispatch(req: &Req, node: &Arc<PhiNode>) -> Resp {
    match req.cmd.as_str() {
        "ping" => Resp::ok(serde_json::json!({ "version": 2 })),

        "whoami" => {
            let cert = node.cert.read().unwrap().clone();
            Resp::ok(serde_json::json!({
                "node_id":   cert.node_id_hex(),
                "static_pub": hex::encode(node.static_pub()),
                "cert_bits": cert.bits.bits(),
                "dr":        cert.dr,
                "mu":        cert.mu,
                "sg":        cert.sg,
                "cluster_id": cert.cluster_id_hex(),
                "peers":     node.routing.peer_count(),
                "dht_keys":  node.dht.keys().len(),
                "listen":    format!("{}:{}", node.host, node.port),
                "family":    node.family(),
                "circuit_timeout_ms": node.circuit_timeout().as_millis() as u64,
                "descriptors": node.known_descriptors().iter().map(|d| serde_json::json!({
                    "node_id": d.node_id_hex,
                    "family":  d.family,
                    "exit_policy_summary": d.exit_policy_summary,
                    "host":    d.host,
                    "port":    d.port,
                })).collect::<Vec<_>>(),
                "guards":    node.guard_stats().iter().map(|(g, st)| serde_json::json!({
                    "guard":     g,
                    "attempts":  st.attempts,
                    "successes": st.successes,
                    "suspicious": st.is_suspicious(),
                })).collect::<Vec<_>>(),
            }))
        }

        "peers" => {
            let peers = node.all_peers().await;
            Resp::ok(serde_json::json!({
                "count": peers.len(),
                "peers": peers.iter().map(|p| serde_json::json!({
                    "node_id": p.node_id_hex(),
                    "host":    p.host,
                    "port":    p.port,
                    "static_pub": p.static_pub,
                })).collect::<Vec<_>>(),
            }))
        }

        // Like "peers", but each peer is verified by dialing its advertised
        // address and confirming the answering identity matches — so NAT'd
        // clients and stale ghosts are excluded. Used by gen-genesis.
        "verified_relays" => {
            let peers = node.verified_relays().await;
            Resp::ok(serde_json::json!({
                "count": peers.len(),
                "peers": peers.iter().map(|p| serde_json::json!({
                    "node_id": p.node_id_hex(),
                    "host":    p.host,
                    "port":    p.port,
                    "static_pub": p.static_pub,
                })).collect::<Vec<_>>(),
            }))
        }

        "hs_fetch" => {
            let hs_id = req.hs_id.as_deref().unwrap_or("");
            let path  = req.path.as_deref().unwrap_or("/");
            match node.store.get_file(hs_id, path).await {
                Some((status, ct, body)) => Resp::ok(serde_json::json!({
                    "status":   status,
                    "headers":  { "Content-Type": ct },
                    "body_b64": hex::encode(&body),
                })),
                None => {
                    // Not served locally. Actively resolve the descriptor
                    // from the network (local cache first, then broadcast an
                    // HsLookup to peers), then drive a full client rendezvous
                    // via node.hs_fetch — the handshake plus an end-to-end
                    // fetch of the requested path over the rendezvous circuit.
                    let Some(desc) = node.lookup_hs_descriptor(hs_id).await else {
                        return Resp::ok(serde_json::json!({
                            "status":   404,
                            "headers":  { "Content-Type": "text/html" },
                            "body_b64": hex::encode(b"<h1>Not found</h1>"),
                        }));
                    };

                    // Prefer the verified cached consensus; fall back to
                    // an ad-hoc one built from connected peers (matches
                    // the auto_circuit idiom for small private networks).
                    use phinet_core::directory::{ConsensusDocument, PeerEntry, PeerFlags};
                    let consensus = match node.cached_consensus.read().await.clone() {
                        Some(c) => c,
                        None => {
                            let peers = node.peers_snapshot().await;
                            if peers.len() < 3 {
                                return Resp::ok(serde_json::json!({
                                    "status":  503,
                                    "headers": { "Content-Type": "text/html" },
                                    "body_b64": hex::encode(format!(
                                        "<h1>No consensus and only {} peer(s)</h1>\
                                         <p>Need \u{2265}3 relays to build rendezvous circuits.</p>",
                                        peers.len()).as_bytes()),
                                }));
                            }
                            let entries: Vec<PeerEntry> = peers.iter().map(|p| PeerEntry {
                                // The peer table doesn't carry family; only
                                // an operator's own authority can declare it.
                                family:         String::new(),
                                node_id_hex:    hex::encode(p.node_id),
                                host:           p.host.clone(),
                                port:           p.port,
                                static_pub_hex: p.static_pub.clone(),
                                flags: (PeerFlags::STABLE | PeerFlags::FAST
                                        | PeerFlags::GUARD | PeerFlags::EXIT
                                        | PeerFlags::RUNNING | PeerFlags::VALID).bits(),
                                bandwidth_kbs: 1000,
                                exit_policy_summary: String::new(),
                            }).collect();
                            ConsensusDocument {
                                network_id: "phinet-local".to_string(),
                                shared_random: String::new(),
                                srv_commitments: Vec::new(),
                                valid_after: 0,
                                valid_until: u64::MAX,
                                peers: entries,
                                signatures: Vec::new(),
                            }
                        }
                    };

                    // Public services need no client secrets. Client-auth
                    // services would require the operator's authorized
                    // X25519 secret(s) here; that store isn't plumbed
                    // through this control path yet, so resolve_hs_descriptor
                    // will return NotAuthorized for them and hs_fetch
                    // surfaces that as an error below.
                    let client_secrets: Vec<phinet_core::x25519_dalek::StaticSecret> = Vec::new();

                    let node = Arc::clone(node);
                    // Each attempt reselects its RP and intro paths at random.
                    // On a small network the draw can collide with the service
                    // itself — the RP landing on the HS's own node (so it must
                    // rendezvous with itself), or the intro circuit's middle
                    // hop being the HS node it then has to extend to (a
                    // self-extend that just times out). Both are unlucky draws
                    // rather than permanent faults, so reroll a few times
                    // before giving up. More relays makes collisions rare.
                    const HS_FETCH_ATTEMPTS: u32 = 4;
                    let mut last_err = None;
                    let mut fetched  = None;
                    for attempt in 1..=HS_FETCH_ATTEMPTS {
                        let n = Arc::clone(&node);
                        match n.hs_fetch(&desc, &client_secrets, &consensus, path).await {
                            Ok(r) => { fetched = Some(r); break; }
                            Err(e) => {
                                warn!("hs_fetch attempt {}/{}: {}",
                                      attempt, HS_FETCH_ATTEMPTS, e);
                                last_err = Some(e);
                            }
                        }
                    }
                    match fetched {
                        Some(resp) => Resp::ok(serde_json::json!({
                            "status":   resp.status,
                            "headers":  { "Content-Type": resp.content_type },
                            "body_b64": hex::encode(&resp.body),
                        })),
                        None => {
                            let e = last_err.map(|e| e.to_string())
                                .unwrap_or_else(|| "unknown".into());
                            Resp::ok(serde_json::json!({
                                "status":  502,
                                "headers": { "Content-Type": "text/html" },
                                "body_b64": hex::encode(format!(
                                    "<h1>Rendezvous failed</h1><p>after {} attempts: {}</p>\
                                     <p>intro: {:?}:{:?}</p>",
                                    HS_FETCH_ATTEMPTS, e,
                                    desc.intro_host, desc.intro_port).as_bytes()),
                            }))
                        }
                    }
                }
            }
        }

        "hs_register" => {
            let name = req.name.as_deref().unwrap_or("").to_string();
            let hs   = node.register_hs(&name).await;

            // Check the per-service authorized client list. If empty,
            // publish a public descriptor (anyone can resolve). If
            // populated, encrypt the intro point to those clients.
            let host = detect_ip();
            // The intro point IS this node — clients extend their intro
            // circuit to us and we answer INTRODUCE2 on our normal listener.
            // Advertising port+1 pointed the terminal EXTEND at a port
            // nothing binds, so the hop timed out unless the chosen middle
            // relay happened to already hold a connection to us.
            let port = node.port;

            let clients_hex = node.store.list_authorized_clients(&hs.hs_id).await;
            let desc = if clients_hex.is_empty() {
                let mut d = hs.descriptor(Some(&host), Some(port));
                // The client encrypts INTRODUCE1 to the key advertised
                // as `intro_pub`, and the HS decrypts INTRODUCE2 with its
                // *node* static key (see handle_introduce2). So the
                // descriptor must advertise the node static key here, not
                // the HS's dedicated intro_secret pubkey — otherwise the
                // handshake's ntor would never agree. We also advertise
                // the HS node id so the client can build the terminal
                // intro hop toward this node.
                d.intro_pub = hex::encode(node.static_pub());
                d.intro_node_id = hex::encode(node.node_id());
                d
            } else {
                // Parse hex pubkeys to [u8; 32]
                let mut client_pubs: Vec<[u8; 32]> = Vec::new();
                for h in &clients_hex {
                    match hex::decode(h).ok().and_then(|v| v.try_into().ok()) {
                        Some(b) => client_pubs.push(b),
                        None => {
                            return Resp::err(&format!(
                                "hs_register: malformed client pubkey in store: {}", h));
                        }
                    }
                }
                match hs.descriptor_with_client_auth(
                    Some(&host), Some(port), &client_pubs,
                ) {
                    Ok(d) => {
                        info!("hs_register: publishing {} with client-auth ({} clients)",
                            &hs.hs_id[..16], client_pubs.len());
                        d
                    }
                    Err(e) => return Resp::err(&format!(
                        "hs_register: descriptor_with_client_auth: {}", e)),
                }
            };
            node.broadcast_hs(desc, &hs.identity).await;
            Resp::ok(serde_json::json!({
                "hs_id":     hs.hs_id,
                "name":      hs.name,
                "intro_pub": hex::encode(hs.intro_pub.as_bytes()),
                "client_auth_clients": clients_hex.len(),
            }))
        }

        "board_post" => {
            let ch   = req.channel.as_deref().unwrap_or("general");
            let text = req.text.as_deref().unwrap_or("");
            node.post_to_board(ch, text).await;
            Resp::ok(serde_json::json!({ "posted": true }))
        }

        "board_read" => {
            let ch    = req.channel.as_deref().unwrap_or("general");
            let posts = node.board.get(ch, 50);
            Resp::ok(serde_json::json!({ "posts": posts }))
        }

        "status" => {
            let svcs = node.store.list_services().await;
            Resp::ok(serde_json::json!({
                "local_services": svcs.len(),
                "peers":          node.routing.peer_count(),
                "dht_keys":       node.dht.keys().len(),
            }))
        }

        "connect" => {
            // Connect to a bootstrap peer: {"cmd":"connect","host":"1.2.3.4","port":7700}
            let host = req.name.as_deref().unwrap_or("").to_string();
            let port = req.path.as_deref()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(7700);
            if host.is_empty() {
                Resp::err("missing host (use 'name' field)")
            } else {
                let node = Arc::clone(node);
                tokio::spawn(async move {
                    node.bootstrap(vec![(host, port)]).await;
                });
                Resp::ok(serde_json::json!({ "connecting": true }))
            }
        }

        "circuit_status" => {
            let (origins, relays) = node.circuit_status().await;
            Resp::ok(serde_json::json!({
                "origins": origins,
                "relays":  relays,
            }))
        }

        "build_circuit" => {
            // Path is a comma-separated list of "node_id_hex@host:port"
            // Example: {"cmd":"build_circuit","path":"ab..@1.2.3.4:7700,cd..@5.6.7.8:7700"}
            let path_str = req.text.as_deref().unwrap_or("").trim();
            if path_str.is_empty() {
                return Resp::err("missing 'text' field with comma-separated path");
            }

            let mut path = Vec::new();
            for entry in path_str.split(',') {
                let entry = entry.trim();
                let Some((id_hex, addr)) = entry.split_once('@') else {
                    return Resp::err(&format!("malformed hop: {entry} (want id@host:port)"));
                };
                let Ok(id_vec) = hex::decode(id_hex) else {
                    return Resp::err(&format!("bad hex in node_id: {id_hex}"));
                };
                if id_vec.len() != 32 {
                    return Resp::err(&format!("node_id must be 32 bytes, got {}", id_vec.len()));
                }
                let Some((host, port_str)) = addr.rsplit_once(':') else {
                    return Resp::err(&format!("malformed addr: {addr}"));
                };
                let Ok(port) = port_str.parse::<u16>() else {
                    return Resp::err(&format!("bad port: {port_str}"));
                };
                let mut id = [0u8; 32];
                id.copy_from_slice(&id_vec);

                // Look up the peer's x25519 static public key from the
                // node's peer table. Without it, the ntor handshake
                // can't be addressed to this hop, so the circuit-build
                // would time out. The hop must already be a connected
                // peer for this to work.
                let static_pub: [u8; 32] = {
                    let peers = node.peers_snapshot().await;
                    let Some(peer) = peers.iter().find(|p| p.node_id == id) else {
                        return Resp::err(&format!(
                            "hop {} not a connected peer — phi peer connect first",
                            hex::encode(&id[..6])
                        ));
                    };
                    match hex::decode(&peer.static_pub)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                    {
                        Some(b) => b,
                        None => return Resp::err(
                            "peer's static_pub is corrupted in peer table"),
                    }
                };

                path.push(phinet_core::circuit::LinkSpec {
                    host:       host.to_string(),
                    port,
                    node_id:    id,
                    static_pub,
                });
            }

            let node = Arc::clone(node);
            match node.build_circuit(path).await {
                Ok(cid) => Resp::ok(serde_json::json!({
                    "circ_id": cid.0,
                    "hops":    path_str.split(',').count(),
                })),
                Err(e) => Resp::err(&format!("build_circuit: {e}")),
            }
        }

        "auto_circuit" => {
            // Build a circuit using consensus-weighted path selection.
            //
            // Request: {"cmd":"auto_circuit"}
            //   Optionally provide "consensus_path" pointing at a JSON
            //   ConsensusDocument file. Otherwise we construct an
            //   ad-hoc consensus from currently-connected peers (fine
            //   for a small private network, not what production
            //   would use).
            //
            // The selector picks 3 hops weighted by bandwidth, with
            // /16 subnet diversity, GUARD/EXIT flag constraints, and
            // self-exclusion. Returns the constructed circuit ID.
            use phinet_core::directory::{ConsensusDocument, PeerEntry, PeerFlags};
            use phinet_core::path_select::{select_path, PathError};

            let consensus = if let Some(path) = req.text.as_deref() {
                // Operator passed a consensus file path.
                match std::fs::read_to_string(path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<ConsensusDocument>(&s).ok())
                {
                    Some(c) => c,
                    None => return Resp::err(
                        &format!("could not load/parse consensus from {path}")),
                }
            } else {
                // Construct an ad-hoc consensus from connected peers.
                // Every peer gets STABLE+FAST+GUARD+EXIT+RUNNING+VALID
                // because in a small private network every peer is
                // expected to do everything. Bandwidth is set to 1000
                // for all peers (uniform random selection).
                let peers = node.peers_snapshot().await;
                if peers.len() < 3 {
                    return Resp::err(&format!(
                        "auto_circuit: need ≥3 connected peers, have {}",
                        peers.len()));
                }
                let entries: Vec<PeerEntry> = peers.iter().map(|p| {
                    PeerEntry {
                        family:         String::new(),
                        node_id_hex:    hex::encode(p.node_id),
                        host:           p.host.clone(),
                        port:           p.port,
                        static_pub_hex: p.static_pub.clone(),
                        flags: (PeerFlags::STABLE | PeerFlags::FAST
                                | PeerFlags::GUARD | PeerFlags::EXIT
                                | PeerFlags::RUNNING | PeerFlags::VALID).bits(),
                        bandwidth_kbs: 1000,
                        exit_policy_summary: String::new(),
                    }
                }).collect();
                ConsensusDocument {
                    network_id: "phinet-local".to_string(),
                    shared_random: String::new(),
                    srv_commitments: Vec::new(),
                    valid_after: 0,
                    valid_until: u64::MAX,
                    peers: entries,
                    signatures: Vec::new(),
                }
            };

            // Exclude our own node_id so we don't pick ourselves.
            let self_id = hex::encode(node.node_id());
            // OsRng is Send (unlike thread_rng which has thread-local
            // state) so the future containing it can cross threads.
            let mut rng = rand::rngs::OsRng;
            let path = match select_path(&mut rng, &consensus, &[self_id], None) {
                Ok(p) => p,
                Err(PathError::InsufficientRelays(s)) => {
                    return Resp::err(&format!("path selection: {s}"));
                }
            };

            let specs = match path.to_link_specs() {
                Ok(s) => s,
                Err(e) => return Resp::err(&format!("link spec conversion: {e}")),
            };
            let hop_summary: Vec<String> = path.hops.iter()
                .map(|h| format!("{}…@{}:{}", &h.node_id_hex[..8], h.host, h.port))
                .collect();

            let node = Arc::clone(node);
            match node.build_circuit(specs).await {
                Ok(cid) => Resp::ok(serde_json::json!({
                    "circ_id": cid.0,
                    "hops":    hop_summary,
                    "method":  "auto_select",
                })),
                Err(e) => Resp::err(&format!("auto_circuit build: {e}")),
            }
        }

        "bw_measure" => {
            // Measure throughput through a target relay by building
            // a 2-hop circuit (target → helper) and timing how fast
            // bytes flow back. Used by the bandwidth scanner.
            //
            // Request:
            //   {"cmd":"bw_measure",
            //    "hs_id":"<target relay node_id_hex>",
            //    "text":"<helper relay node_id_hex>",   // optional
            //    "method":"<bytes>" }                   // optional, default 1MB
            //
            // The "method" field carries the payload byte count
            // (sloppy but the Req struct is fixed and we don't have
            // a free numeric field).
            //
            // Returns: { bw_kbs, rtt_ms, bytes_received, success }
            //
            // Caveat: this needs at least one helper relay connected
            // to the target. In a small network this is the case
            // because everyone connects to everyone; in production
            // the scanner would specify the helper explicitly.
            use phinet_core::circuit::LinkSpec;

            let target_hex = match req.hs_id.as_deref() {
                Some(s) => s,
                None    => return Resp::err("bw_measure: missing hs_id (target node_id)"),
            };
            let target_id = match hex::decode(target_hex) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                }
                _ => return Resp::err("bw_measure: bad target node_id_hex"),
            };

            let payload_bytes: usize = req.method.as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024 * 1024);

            let peers = node.peers_snapshot().await;
            let target_peer = peers.iter().find(|p| p.node_id == target_id);
            let target_peer = match target_peer {
                Some(p) => p,
                None    => return Resp::err(&format!(
                    "bw_measure: target {} is not in peer table — connect to it first",
                    &target_hex[..16])),
            };

            // Pick a helper: either explicit from req.text, or the
            // first peer that isn't us and isn't the target.
            let self_id = node.node_id();
            let helper_peer = if let Some(htxt) = req.text.as_deref() {
                let h = match hex::decode(htxt) {
                    Ok(v) if v.len() == 32 => {
                        let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                    }
                    _ => return Resp::err("bw_measure: bad helper node_id_hex"),
                };
                peers.iter().find(|p| p.node_id == h)
            } else {
                peers.iter().find(|p|
                    p.node_id != self_id && p.node_id != target_id)
            };
            let helper_peer = match helper_peer {
                Some(p) => p,
                None    => return Resp::err(
                    "bw_measure: no helper available (need ≥2 connected peers)"),
            };

            let target_pub = match hex::decode(&target_peer.static_pub) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                }
                _ => return Resp::err("bw_measure: target static_pub bad hex"),
            };
            let helper_pub = match hex::decode(&helper_peer.static_pub) {
                Ok(v) if v.len() == 32 => {
                    let mut a = [0u8; 32]; a.copy_from_slice(&v); a
                }
                _ => return Resp::err("bw_measure: helper static_pub bad hex"),
            };

            let specs = vec![
                LinkSpec {
                    host:       target_peer.host.clone(),
                    port:       target_peer.port,
                    node_id:    target_id,
                    static_pub: target_pub,
                },
                LinkSpec {
                    host:       helper_peer.host.clone(),
                    port:       helper_peer.port,
                    node_id:    helper_peer.node_id,
                    static_pub: helper_pub,
                },
            ];

            let t_build_start = std::time::Instant::now();
            let cid = match Arc::clone(node).build_circuit(specs).await {
                Ok(c) => c,
                Err(e) => return Resp::err(&format!("bw_measure: circuit build: {e}")),
            };
            let build_ms = t_build_start.elapsed().as_millis() as u32;

            // Open a bw-test:<N> stream to the helper (last hop).
            // The helper's BEGIN handler intercepts the sentinel
            // target and emits N pseudorandom bytes locally — no
            // network egress, no exit-policy involvement. We time
            // first-byte and total arrival to compute throughput.
            let target_str = format!("bw-test:{}", payload_bytes);
            let (stream_id, mut rx, ready) =
                match node.stream_open(cid, &target_str).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = node.destroy_circuit(cid).await;
                        return Resp::err(&format!("bw_measure: stream_open: {e}"));
                    }
                };

            // Wait for CONNECTED to fire so the timer doesn't include
            // RELAY_BEGIN dispatch latency. Bound the wait.
            if let Err(_) = tokio::time::timeout(
                std::time::Duration::from_secs(15), ready
            ).await {
                let _ = node.stream_close(cid, stream_id,
                    phinet_core::stream::EndReason::Internal).await;
                let _ = node.destroy_circuit(cid).await;
                return Resp::err("bw_measure: stream did not reach Open within 15s");
            }

            let t_first_byte: Option<std::time::Instant>;
            let mut received: usize = 0;
            let t_recv_start = std::time::Instant::now();

            // First byte: wait up to 30s
            let first_chunk = tokio::time::timeout(
                std::time::Duration::from_secs(30), rx.recv()
            ).await;
            t_first_byte = Some(std::time::Instant::now());
            match first_chunk {
                Ok(Some(buf)) => received += buf.len(),
                Ok(None) => {
                    let _ = node.destroy_circuit(cid).await;
                    return Resp::err("bw_measure: stream closed before any data");
                }
                Err(_) => {
                    let _ = node.destroy_circuit(cid).await;
                    return Resp::err("bw_measure: no data within 30s of stream open");
                }
            }

            // Drain remaining chunks until EOF or full payload.
            while received < payload_bytes {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(60), rx.recv()
                ).await {
                    Ok(Some(buf)) => received += buf.len(),
                    Ok(None) => break, // helper closed stream
                    Err(_)   => break, // timeout — accept what we got
                }
            }

            let t_done = std::time::Instant::now();
            let transfer_ms = t_first_byte
                .map(|t| t_done.duration_since(t).as_millis().max(1) as u64)
                .unwrap_or(1);
            let total_ms = t_recv_start.elapsed().as_millis().max(1) as u64;

            // bw_kbs = bytes / (transfer_secs) / 1024 (kibibytes).
            // We use the post-first-byte window so circuit-build and
            // queue-warmup don't depress the number; it's the
            // steady-state throughput.
            let bw_kbs = ((received as u64) * 1000 / transfer_ms / 1024) as u32;

            // rtt_ms reports the time to first byte after stream
            // open: this is the round-trip across the 2 hops, a
            // useful auxiliary signal for "is this relay overloaded?"
            let rtt_ms = t_first_byte
                .map(|t| t.duration_since(t_recv_start).as_millis() as u32)
                .unwrap_or(0);

            // Tear down stream and circuit
            let _ = node.stream_close(cid, stream_id,
                phinet_core::stream::EndReason::Done).await;
            let _ = node.destroy_circuit(cid).await;

            Resp::ok(serde_json::json!({
                "bw_kbs":         bw_kbs,
                "rtt_ms":         rtt_ms,
                "bytes_received": received,
                "bytes_requested": payload_bytes,
                "transfer_ms":    transfer_ms,
                "total_ms":       total_ms,
                "build_ms":       build_ms,
                "success":        received > 0,
                "circuit_method": "2hop_target_then_helper_bw_test",
            }))
        }

        "consensus_load" => {
            // Load a consensus document from disk and install it
            // into cached_consensus after verification.
            //
            // Request: {"cmd":"consensus_load","text":"/path/to/consensus.json"}
            let path = match req.text.as_deref() {
                Some(p) => p,
                None    => return Resp::err("consensus_load: missing text (path)"),
            };
            let bytes = match std::fs::read_to_string(path) {
                Ok(b) => b,
                Err(e) => return Resp::err(&format!("read {}: {}", path, e)),
            };
            let consensus: phinet_core::directory::ConsensusDocument =
                match serde_json::from_str(&bytes) {
                    Ok(c) => c,
                    Err(e) => return Resp::err(&format!("parse: {}", e)),
                };
            match phinet_core::consensus_fetch::install_consensus(node, consensus).await {
                Ok(updated) => Resp::ok(serde_json::json!({"updated": updated})),
                Err(e)      => Resp::err(&e),
            }
        }

        // ── Vanguard management ─────────────────────────────────
        // List entries: { "cmd": "vanguards_list" }
        // Returns: [{ node_id_hex, host, port, added_at, last_used,
        //             unreachable_since }, ...]
        "vanguards_list" => {
            let entries = node.vanguards.list();
            Resp::ok(serde_json::json!({
                "entries": entries.iter().map(|e| serde_json::json!({
                    "node_id_hex":       e.node_id_hex,
                    "host":              e.host,
                    "port":              e.port,
                    "added_at":          e.added_at,
                    "last_used":         e.last_used,
                    "unreachable_since": e.unreachable_since,
                })).collect::<Vec<_>>(),
                "active_count": node.vanguards.active_count(),
            }))
        }
        // Forget a single vanguard: { "cmd": "vanguards_forget",
        //                             "node_id_hex": "abcd..." }
        "vanguards_forget" => {
            let id = req.node_id_hex.as_deref().unwrap_or("");
            if id.is_empty() {
                return Resp::err("vanguards_forget: missing node_id_hex");
            }
            // Mark unreachable so it ages out via maintain. We don't
            // expose a synchronous removal because that could cause
            // anti-churn bypass — operators who *really* want to
            // start fresh should use vanguards_clear.
            node.vanguards.mark_unreachable(id);
            Resp::ok(serde_json::json!({"marked_unreachable": id}))
        }
        // Clear all vanguards: { "cmd": "vanguards_clear" }
        // Forces a fresh set on next HS-circuit build. Use sparingly:
        // disrupts the layered-guard property until enough new builds
        // have repopulated the set.
        "vanguards_clear" => {
            // No public clear method on Vanguards (intentional —
            // implementing it requires holding the file lock briefly).
            // Mark every entry unreachable, then call maintain() to
            // remove the long-unreachable ones. New entries will
            // populate on next build_hs_circuit.
            let entries = node.vanguards.list();
            for e in &entries {
                node.vanguards.mark_unreachable(&e.node_id_hex);
            }
            // We don't immediately remove — anti-churn protection
            // keeps entries for LAYER2_MIN_LIFETIME (24h). But marking
            // them all unreachable means they won't be picked.
            Resp::ok(serde_json::json!({
                "marked": entries.len(),
                "note": "entries persist for 24h (anti-churn). pick_layer2 will return None until then or until new entries are added.",
            }))
        }

        // ── Hidden-service client-auth helpers ─────────────────
        // Generate a client keypair (operator gives the pubkey to a
        // client out-of-band). Doesn't involve the daemon's identity;
        // pure local key generation.
        // { "cmd": "hs_auth_gen_client" }
        "hs_auth_gen_client" => {
            use rand::rngs::OsRng;
            let sec = phinet_core::x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let pubk = phinet_core::x25519_dalek::PublicKey::from(&sec);
            Resp::ok(serde_json::json!({
                "secret_hex": hex::encode(sec.to_bytes()),
                "public_hex": hex::encode(pubk.as_bytes()),
                "note": "save the secret somewhere safe; share only the public key with the HS operator",
            }))
        }

        // Authorize a client to access a hidden service.
        // { "cmd": "hs_auth_add_client", "hs_id": "...", "text": "<pubkey-hex>" }
        // After adding the first client, subsequent hs_register calls
        // will publish a client-auth descriptor instead of a public one.
        "hs_auth_add_client" => {
            let hs_id = match req.hs_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return Resp::err("hs_auth_add_client: missing hs_id"),
            };
            let pubk = match req.text.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return Resp::err("hs_auth_add_client: missing client pubkey (in 'text' field)"),
            };
            match node.store.add_authorized_client(hs_id, pubk).await {
                Ok(true)  => Resp::ok(serde_json::json!({
                    "added": true, "hs_id": hs_id,
                    "client_pub": pubk.trim().to_lowercase(),
                })),
                Ok(false) => Resp::ok(serde_json::json!({
                    "added": false, "reason": "already authorized",
                })),
                Err(e) => Resp::err(&format!("hs_auth_add_client: {}", e)),
            }
        }

        // Remove an authorized client.
        // { "cmd": "hs_auth_remove_client", "hs_id": "...", "text": "<pubkey-hex>" }
        // If the resulting list is empty, the file is removed and the
        // service publishes as public on next hs_register.
        "hs_auth_remove_client" => {
            let hs_id = match req.hs_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return Resp::err("hs_auth_remove_client: missing hs_id"),
            };
            let pubk = match req.text.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return Resp::err("hs_auth_remove_client: missing client pubkey"),
            };
            match node.store.remove_authorized_client(hs_id, pubk).await {
                Ok(true)  => Resp::ok(serde_json::json!({
                    "removed": true,
                    "remaining": node.store.list_authorized_clients(hs_id).await.len(),
                })),
                Ok(false) => Resp::ok(serde_json::json!({
                    "removed": false, "reason": "not in list",
                })),
                Err(e) => Resp::err(&format!("hs_auth_remove_client: {}", e)),
            }
        }

        // List authorized clients.
        // { "cmd": "hs_auth_list_clients", "hs_id": "..." }
        "hs_auth_list_clients" => {
            let hs_id = match req.hs_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return Resp::err("hs_auth_list_clients: missing hs_id"),
            };
            let clients = node.store.list_authorized_clients(hs_id).await;
            let count = clients.len();
            Resp::ok(serde_json::json!({
                "hs_id":   hs_id,
                "clients": clients,
                "count":   count,
                "mode":    if count == 0 { "public" } else { "client-auth" },
            }))
        }

        // ── com (end-to-end messaging) ──────────────────────────────
        // {"cmd":"com_send","node_id_hex":"<recipient>","text":"hi"}
        "com_send" => {
            match (req.node_id_hex.as_deref(), req.text.as_deref()) {
                (Some(rid_hex), Some(body)) => {
                    match hex::decode(rid_hex).ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    {
                        Some(rid) => match node.com_send_to(rid, body).await {
                            Ok(mid) => Resp::ok(serde_json::json!({
                                "msg_id": hex::encode(mid) })),
                            Err(e)  => Resp::err(&format!("com_send: {e}")),
                        },
                        None => Resp::err("com_send: bad node_id_hex"),
                    }
                }
                _ => Resp::err("com_send needs node_id_hex and text"),
            }
        }

        // List conversation threads (peer node ids), most-recent first.
        "com_threads" => {
            let threads = node.com_threads().await;
            Resp::ok(serde_json::json!({
                "threads": threads.iter().map(hex::encode).collect::<Vec<_>>(),
            }))
        }

        // {"cmd":"com_thread","node_id_hex":"<peer>"} → messages.
        "com_thread" => {
            match req.node_id_hex.as_deref().and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
            {
                Some(pid) => {
                    let conv = node.com_conversation(&pid).await;
                    Resp::ok(serde_json::json!({
                        "messages": conv.iter().map(|(out, ts, body, mid)| serde_json::json!({
                            "outgoing":  out,
                            "timestamp": ts,
                            "body":      body,
                            "msg_id":    mid,
                        })).collect::<Vec<_>>(),
                    }))
                }
                None => Resp::err("com_thread needs node_id_hex"),
            }
        }

        // ── com groups & channels ───────────────────────────────────
        "com_create_group" => {
            let name = req.name.clone().unwrap_or_else(|| "group".into());
            let is_channel = req.is_channel.unwrap_or(false);
            let g = node.com_create_group(&name, is_channel).await;
            Resp::ok(serde_json::json!({
                "group_id":  hex::encode(g.group_id),
                "thread_id": hex::encode(PhiNode::group_thread_id(&g.group_id)),
                "name":      g.name,
                "is_channel": g.is_channel,
            }))
        }
        "com_delete" => {
            let peer = req.node_id_hex.as_deref().and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8;32]>::try_from(v).ok());
            let mid  = req.msg_id.as_deref().and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8;16]>::try_from(v).ok());
            match (peer, mid) {
                (Some(p), Some(m)) => { let _ = node.com_delete(p, m).await;
                    Resp::ok(serde_json::json!({ "ok": true })) }
                _ => Resp::err("com_delete: need node_id_hex and msg_id"),
            }
        }
        "circuit_info" => { Resp::ok(node.circuit_info().await) }
        "new_identity" => { node.new_identity().await; Resp::ok(serde_json::json!({"ok":true})) }
        "com_my_address" => {
            Resp::ok(serde_json::json!({ "address": node.com_my_address() }))
        }
        "com_add_contact" => {
            match req.address.as_deref().and_then(phinet_core::com::address_decode) {
                Some((nid, spk)) => {
                    node.com_add_contact(nid, spk).await;
                    Resp::ok(serde_json::json!({ "node_id": hex::encode(nid) }))
                }
                None => Resp::err("com_add_contact: invalid address (expected phi:<128 hex>)"),
            }
        }
        "com_groups" => {
            let groups = node.com_groups_list().await;
            Resp::ok(serde_json::json!({
                "groups": groups.iter().map(|(gid, name, ch, tid)| serde_json::json!({
                    "group_id":   hex::encode(gid),
                    "name":       name,
                    "is_channel": ch,
                    "thread_id":  hex::encode(tid),
                })).collect::<Vec<_>>(),
            }))
        }
        "com_invite" => {
            match (req.group_id.as_deref().and_then(|h| hex::decode(h).ok())
                       .and_then(|v| <[u8; 16]>::try_from(v).ok()),
                   req.node_id_hex.as_deref().and_then(|h| hex::decode(h).ok())
                       .and_then(|v| <[u8; 32]>::try_from(v).ok()))
            {
                (Some(gid), Some(mid)) => match node.com_invite_to_group(gid, mid).await {
                    Ok(())  => Resp::ok(serde_json::json!({ "ok": true })),
                    Err(e)  => Resp::err(&format!("com_invite: {e}")),
                },
                _ => Resp::err("com_invite needs group_id and node_id_hex"),
            }
        }
        "com_send_group" => {
            match (req.group_id.as_deref().and_then(|h| hex::decode(h).ok())
                       .and_then(|v| <[u8; 16]>::try_from(v).ok()),
                   req.text.as_deref())
            {
                (Some(gid), Some(body)) => match node.com_send_group(gid, body).await {
                    Ok(mid) => Resp::ok(serde_json::json!({ "msg_id": hex::encode(mid) })),
                    Err(e)  => Resp::err(&format!("com_send_group: {e}")),
                },
                _ => Resp::err("com_send_group needs group_id and text"),
            }
        }

        other => Resp::err(&format!("unknown command: {}", other)),
    }
}

// ── Main ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut port          = 7700u16;
    let mut host          = "0.0.0.0".to_string();
    let mut bootstrap     = Vec::<(String, u16)>::new();
    let mut cert_bits     = CertBits::B256;
    let mut ctl_port       = 7799u16;
    let mut consensus_port: Option<u16> = None;
    let mut reset         = false;
    let mut _high_sec      = false;
    let mut verbose       = false;
    let mut client_only   = false;
    let mut trusted_auths = Vec::<[u8; 32]>::new();
    let mut family: String = String::new();
    let mut dos_protection = false;
    let mut consensus_urls: Vec<String> = Vec::new();
    let mut consensus_path: Option<String> = None;
    // Pluggable transport (obfs4 / meek / snowflake) options.
    let mut pt_transport:   Option<String> = None;
    let mut pt_binary:      Option<String> = None;
    let mut pt_bridge_args: String         = String::new();
    let mut pt_state_dir:   Option<String> = None;
    // Server-side PT (run this node as an obfs4/meek/snowflake bridge).
    let mut bridge_transport: Option<String> = None;
    let mut bridge_bind:      Option<String> = None;
    let mut bridge_options:   Option<String> = None;
    let mut i             = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--port"            => { port     = args.get(i+1).and_then(|s| s.parse().ok()).unwrap_or(7700); i += 1; }
            "--host"            => { host     = args.get(i+1).cloned().unwrap_or_else(|| "0.0.0.0".into()); i += 1; }
            "--ctl-port"        => { ctl_port = args.get(i+1).and_then(|s| s.parse().ok()).unwrap_or(7799); i += 1; }
            "--consensus-port"  => { consensus_port = args.get(i+1).and_then(|s| s.parse().ok()); i += 1; }
            "--cert-bits"       => {
                cert_bits = match args.get(i+1).map(|s| s.as_str()) {
                    Some("512")  => CertBits::B512,
                    Some("1024") => CertBits::B1024,
                    Some("2048") => CertBits::B2048,
                    _            => CertBits::B256,
                };
                i += 1;
            }
            "--bootstrap"       => {
                if let Some(s) = args.get(i+1) {
                    if let Some((h, p)) = s.rsplit_once(':') {
                        if let Ok(p) = p.parse::<u16>() {
                            let h = h.to_string();
                            // Skip obviously wrong values
                            if !h.is_empty() && h != "0.0.0.0" {
                                bootstrap.push((h, p));
                            } else {
                                eprintln!("Warning: ignoring --bootstrap {} (use a real remote IP, e.g. 1.2.3.4:7700)", s);
                            }
                        }
                    } else {
                        // No port specified — try with default port 7700
                        let h = s.trim().to_string();
                        if !h.is_empty() && h != "0.0.0.0" {
                            bootstrap.push((h, 7700));
                        } else {
                            eprintln!("Usage: --bootstrap <host>:<port>  e.g. --bootstrap 1.2.3.4:7700");
                        }
                    }
                } else {
                    eprintln!("Usage: --bootstrap <host>:<port>  e.g. --bootstrap 1.2.3.4:7700");
                }
                i += 1;
            }
            "--reset-identity"  => reset    = true,
            "--high-security"   => _high_sec = true,
            "--verbose" | "-v"  => verbose  = true,

            // Client-only mode: don't bind a listener. Outbound
            // circuits and HS fetch still work; this node just
            // doesn't accept inbound connections.
            "--client-only"     => client_only = true,

            // Add a trusted directory authority by hex-encoded
            // Ed25519 public key (32 bytes = 64 hex chars). Repeat
            // the flag to add multiple. Without these, consensus
            // verification will reject every consensus.
            "--trusted-authority" => {
                if let Some(s) = args.get(i+1) {
                    match hex::decode(s.trim()) {
                        Ok(v) if v.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            trusted_auths.push(arr);
                        }
                        _ => eprintln!("Warning: --trusted-authority {} is not 32-byte hex; ignored", s),
                    }
                } else {
                    eprintln!("Usage: --trusted-authority <64-hex-char Ed25519 pubkey>");
                }
                i += 1;
            }

            // URL of an HTTPS-served consensus document. The daemon
            // periodically fetches this, verifies the signatures
            // Turn on per-address rate limiting. Recommended for any relay
            // reachable from the internet; off by default so a testnet
            // doesn't silently throttle itself.
            "--dos-protection" => {
                dos_protection = true;
            }

            // Operator family label. Set the same value on every relay you
            // run: clients then refuse to put two of them in one circuit,
            // because two relays under one operator are one relay for
            // correlation purposes. Leave unset if this is your only relay.
            "--family" => {
                if let Some(s) = args.get(i+1) {
                    family = s.clone();
                } else {
                    eprintln!("Usage: --family <label shared by all your relays>");
                }
                i += 1;
            }

            // against --trusted-authority, and uses it for path
            // selection. Mutually exclusive with --consensus-path.
            // Repeatable. Each is tried in order until one fetches *and*
            // verifies, so a mirror going down (or lying) costs a round trip
            // rather than the node's ability to build circuits at all. The
            // signature is what makes this safe: any host can serve the
            // bytes, only the authorities can sign them, so a mirror needs no
            // trust and anyone can run one.
            "--consensus-url" => {
                if let Some(s) = args.get(i+1) {
                    consensus_urls.push(s.clone());
                } else {
                    eprintln!("Usage: --consensus-url <https://auth.example.com/consensus.json> \
                               [--consensus-url <mirror> ...]");
                }
                i += 1;
            }

            // Local file path to a consensus document. Useful for
            // testnets where the operator places the consensus on
            // disk rather than serving it over HTTPS. Mutually
            // exclusive with --consensus-url.
            "--consensus-path" => {
                if let Some(s) = args.get(i+1) {
                    consensus_path = Some(s.clone());
                } else {
                    eprintln!("Usage: --consensus-path </path/to/consensus.json>");
                }
                i += 1;
            }

            // Pluggable transport: route all outbound peer dials through
            // an external PT managed proxy (obfs4proxy, snowflake-client,
            // meek-client) for censorship circumvention. --transport is
            // the PT name; --pt-binary is the executable; --pt-bridge-args
            // are the per-bridge parameters (e.g. "cert=…;iat-mode=0").
            "--transport" => {
                pt_transport = args.get(i+1).cloned();
                i += 1;
            }
            "--pt-binary" => {
                pt_binary = args.get(i+1).cloned();
                i += 1;
            }
            "--pt-bridge-args" => {
                pt_bridge_args = args.get(i+1).cloned().unwrap_or_default();
                i += 1;
            }
            "--pt-state-dir" => {
                pt_state_dir = args.get(i+1).cloned();
                i += 1;
            }

            // Run this node as a PT bridge: spawn a server-side PT that
            // listens on --bridge-bind speaking the obfuscated protocol
            // and forwards decrypted traffic to the local ΦNET listener.
            "--bridge-transport" => {
                bridge_transport = args.get(i+1).cloned();
                i += 1;
            }
            "--bridge-bind" => {
                bridge_bind = args.get(i+1).cloned();
                i += 1;
            }
            "--bridge-options" => {
                bridge_options = args.get(i+1).cloned();
                i += 1;
            }

            _                   => {}
        }
        i += 1;
    }

    tracing_subscriber::fmt()
        .with_env_filter(if verbose { "debug" } else { "info" })
        .init();

    let (cert, keypair) = load_or_create(cert_bits, reset)?;
    let _ = COOKIE.set(load_or_create_cookie()?);
    let store = Arc::new(SiteStore::new());
    let mut node  = PhiNode::new_with_keypair(&host, port, cert, store, keypair);
    if !family.is_empty() {
        info!("Operator family: {} — clients won't put two of your relays in one circuit", family);
        node.set_family(family.clone());
    }
    // Remember which guards we're willing to use, across restarts. A sample
    // that resets each launch is no bound at all.
    if let Some(dir) = identity_path().parent() {
        node.load_guard_sample(dir.join("guard_sample.json"));
    }

    // Give the node its descriptor signing key. Without it the relay can't
    // make a claim anyone can check, and `--family` goes back to only working
    // for people who run an authority.
    if let Some(sk) = load_or_create_signing_key() {
        node.set_signing_key(sk);
    } else {
        warn!("could not load or mint a descriptor signing key — this relay \
               won't be able to declare its family to other authorities");
    }
    if dos_protection {
        info!("DoS protection on: max {} circuits/min and {} connections per address \
               (consensus relays and loopback exempt)",
              phinet_core::dos::MAX_CIRCUITS_PER_MIN, phinet_core::dos::MAX_CONNS_PER_IP);
        node.set_dos_protection(true);
    }

    // Pluggable transport: if requested, spawn the PT managed proxy and
    // route all outbound dials through its SOCKS5 endpoint. This must
    // happen before the node Arc is cloned/shared, so Arc::get_mut can
    // swap the transport in place. The handle is held for the process
    // lifetime; dropping it (kill_on_drop) tears the subprocess down.
    let mut _pt_handle = None;
    if let Some(pt_name) = pt_transport.clone() {
        let binary = pt_binary.clone().ok_or_else(|| {
            anyhow::anyhow!("--transport requires --pt-binary </path/to/obfs4proxy>")
        })?;
        let state_dir = pt_state_dir.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            format!("{home}/.phinet/pt-state")
        });
        // SubprocessTransport::new needs a 'static name; the daemon runs
        // for the process lifetime, so leaking the CLI string is fine.
        let name_static: &'static str = Box::leak(pt_name.clone().into_boxed_str());
        let pt = Arc::new(phinet_core::transport::SubprocessTransport::new(
            name_static, pt_bridge_args.clone()));
        info!("Starting pluggable transport '{}' via {}", pt_name, binary);
        let handle = pt.start_subprocess(
            std::path::Path::new(&binary),
            std::path::Path::new(&state_dir),
        ).await.map_err(|e| anyhow::anyhow!("pt start failed: {e}"))?;
        info!("PT '{}' ready; SOCKS5 at {:?}", pt_name, pt.socks_addr());
        _pt_handle = Some(handle);
        match Arc::get_mut(&mut node) {
            Some(n) => n.transport = pt,
            None    => anyhow::bail!("internal: node Arc already shared before PT setup"),
        }
    }

    // Server-side PT: run this node as a bridge. The PT binary listens
    // on the public --bridge-bind and forwards decrypted connections to
    // our local ΦNET listener (ORPORT). We print the resulting bridge
    // line for the operator to share with clients. Held for the process
    // lifetime; kill_on_drop tears the subprocess down on exit.
    let mut _bridge_handle = None;
    if let Some(bt_name) = bridge_transport.clone() {
        let binary = pt_binary.clone().ok_or_else(|| {
            anyhow::anyhow!("--bridge-transport requires --pt-binary </path/to/obfs4proxy>")
        })?;
        let bind = bridge_bind.clone().ok_or_else(|| {
            anyhow::anyhow!("--bridge-transport requires --bridge-bind <addr:port> \
                             (the PUBLIC address the bridge listens on, e.g. 0.0.0.0:443)")
        })?;
        let state_dir = pt_state_dir.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            format!("{home}/.phinet/pt-state")
        });
        // Forward decrypted traffic to our own local listener.
        let orport = format!("127.0.0.1:{port}");
        info!("Starting PT bridge '{}' on {} → {}", bt_name, bind, orport);
        let (handle, bridge) = phinet_core::transport::start_server_pt(
            &bt_name,
            std::path::Path::new(&binary),
            std::path::Path::new(&state_dir),
            &bind,
            &orport,
            bridge_options.as_deref(),
        ).await.map_err(|e| anyhow::anyhow!("bridge start failed: {e}"))?;
        _bridge_handle = Some(handle);
        info!("──────────────────────────────────────────────────────────");
        info!("PT BRIDGE READY. Share this bridge line with clients:");
        info!("    {}", bridge.client_line());
        info!("Clients connect with:");
        match &bridge.args {
            Some(a) => info!("    phinet-daemon --transport {} --pt-binary <obfs4proxy> \
                              --pt-bridge-args \"{}\" --bootstrap <this-host>:{}",
                              bridge.transport, a, bridge.bind_addr.port()),
            None    => info!("    phinet-daemon --transport {} --pt-binary <obfs4proxy> \
                              --bootstrap <this-host>:{}",
                              bridge.transport, bridge.bind_addr.port()),
        }
        info!("──────────────────────────────────────────────────────────");
    }

    // Apply --client-only flag.
    if client_only {
        node.client_only.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // Populate trusted directory authorities. Without at least one,
    // consensus verification rejects every consensus, which means
    // path selection has no consensus to consult.
    if !trusted_auths.is_empty() {
        let mut guard = node.trusted_authorities.write().await;
        *guard = trusted_auths.clone();
        info!("Trusted authorities: {}", trusted_auths.len());
    } else if client_only {
        warn!("--client-only without --trusted-authority; consensus verification will fail");
    }

    // Mutual exclusion between consensus-url and consensus-path.
    if !consensus_urls.is_empty() && consensus_path.is_some() {
        anyhow::bail!("--consensus-url and --consensus-path are mutually exclusive");
    }

    // Background loop: periodically refresh the consensus.
    if !consensus_urls.is_empty() {
        if consensus_urls.len() > 1 {
            info!("Consensus sources ({}, tried in order): {}",
                  consensus_urls.len(), consensus_urls.join(", "));
        }
        let n = Arc::clone(&node);
        let urls = consensus_urls.clone();
        tokio::spawn(async move {
            phinet_core::consensus_fetch::refresh_loop_urls(n, urls).await;
        });
    } else if let Some(path) = consensus_path.clone() {
        let n = Arc::clone(&node);
        tokio::spawn(async move {
            phinet_core::consensus_fetch::refresh_loop_path(n, path).await;
        });
    }

    // high_security cannot be set after Arc creation — use a wrapper or re-init
    // For now, high_security is false by default (can be toggled via ctl later)

    print_banner(&node, ctl_port);

    // Control socket
    let ctl_node = Arc::clone(&node);
    tokio::spawn(async move {
        if let Err(e) = run_ctl(ctl_node, ctl_port).await {
            warn!("Control: {}", e);
        }
    });

    // Startup re-registration of hosted hidden services.
    //
    // A descriptor lives in the DHT, not on disk, so every daemon restart used
    // to silently un-publish every site this node hosts — the files were still
    // there, but no client could resolve the address until someone manually ran
    // `phi register`. The periodic republish loop doesn't cover this either: it
    // sleeps half an epoch before its first pass and skips services that have
    // never published an endpoint (that state is in-memory, so it's empty after
    // a restart). Re-registering here makes hosted sites durable across
    // restarts.
    {
        let hs_node = Arc::clone(&node);
        tokio::spawn(async move {
            // Give bootstrap time to connect peers — publishing needs a circuit.
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            let services = hs_node.store.list_services().await;
            if services.is_empty() { return; }
            info!("startup: re-registering {} hosted service(s)", services.len());
            for meta in services {
                let hs   = hs_node.register_hs(&meta.name).await;
                if hs.hs_id != meta.hs_id {
                    warn!("startup: service '{}' on disk is {} but its identity \
                           derives {} — created by an older `phi new`; recreate \
                           it so the files and the descriptor share one id",
                          meta.name, &meta.hs_id[..12.min(meta.hs_id.len())],
                          &hs.hs_id[..12.min(hs.hs_id.len())]);
                    continue;
                }
                let host = detect_ip();
                let port = hs_node.port;   // intro point is this node's listener
                let clients_hex = hs_node.store.list_authorized_clients(&hs.hs_id).await;
                let desc = if clients_hex.is_empty() {
                    let mut d = hs.descriptor(Some(&host), Some(port));
                    d.intro_pub     = hex::encode(hs_node.static_pub());
                    d.intro_node_id = hex::encode(hs_node.node_id());
                    d
                } else {
                    let mut pubs: Vec<[u8; 32]> = Vec::new();
                    for h in &clients_hex {
                        if let Some(b) = hex::decode(h).ok().and_then(|v| v.try_into().ok()) {
                            pubs.push(b);
                        }
                    }
                    match hs.descriptor_with_client_auth(Some(&host), Some(port), &pubs) {
                        Ok(d)  => d,
                        Err(e) => { warn!("startup: {} client-auth descriptor: {}",
                                          &hs.hs_id[..12], e); continue; }
                    }
                };
                hs_node.broadcast_hs(desc, &hs.identity).await;
                info!("startup: republished {}.phinet", &hs.hs_id[..12.min(hs.hs_id.len())]);
            }
        });
    }

    // Consensus HTTP endpoint (default ctl_port + 1 = 7800).
    // Serves the cached_consensus as JSON to anyone who GETs
    // /consensus.json. This is the *publish* side — clients fetching
    // from a URL hit either this directly or (recommended) hit a
    // TLS-terminating reverse proxy that forwards here.
    //
    // Skip in client-only mode: a client doesn't publish a consensus.
    if !client_only {
        let cons_node = Arc::clone(&node);
        let cons_port = consensus_port.unwrap_or_else(|| ctl_port.wrapping_add(1));
        tokio::spawn(async move {
            if let Err(e) = serve_consensus_http(cons_node, cons_port).await {
                warn!("Consensus serve: {}", e);
            }
        });
    }

    // com messenger UI (localhost, default ctl_port + 2 = 7801).
    {
        let com_node = Arc::clone(&node);
        let com_port = ctl_port.wrapping_add(2);
        tokio::spawn(async move {
            if let Err(e) = serve_com_http(com_node, com_port).await {
                warn!("com UI serve: {}", e);
            }
        });
    }

    // Bootstrap
    if !bootstrap.is_empty() {
        let bn = Arc::clone(&node);
        let bp = bootstrap.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            bn.bootstrap(bp).await;
        });
    }

    // Wire SIGINT/SIGTERM to a graceful shutdown. Without this the
    // daemon can only be stopped with SIGKILL, which drops in-flight
    // state (replay-cache writes, guard persistence, board flushes).
    // With this wiring, Ctrl-C / systemd stop triggers the same
    // idempotent shutdown path that integration tests use, giving
    // background loops a chance to finish cleanly.
    {
        let sn = Arc::clone(&node);
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                // Set up both handlers; race them against each other
                // so whichever fires first triggers shutdown.
                let mut sigint  = match signal(SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("signal handler setup failed: {e}");
                        return;
                    }
                };
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("signal handler setup failed: {e}");
                        return;
                    }
                };
                tokio::select! {
                    _ = sigint.recv()  => tracing::info!("SIGINT received"),
                    _ = sigterm.recv() => tracing::info!("SIGTERM received"),
                }
            }
            #[cfg(not(unix))]
            {
                // Windows: just ctrl_c. SIGTERM isn't a Windows concept.
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::warn!("ctrl_c handler: {e}");
                    return;
                }
                tracing::info!("ctrl_c received");
            }
            tracing::info!("shutting down gracefully…");
            sn.shutdown();
        });
    }

    node.run().await?;
    tracing::info!("daemon exited cleanly");
    Ok(())
}

fn print_banner(node: &Arc<PhiNode>, ctl_port: u16) {
    let cert = node.cert.read().unwrap();
    println!(r"
  ┌────────────────────────────────────────────────┐
  │              ΦNET Daemon v2                    │
  └────────────────────────────────────────────────┘

  Node ID:  {}…
  Cert:     {}-bit  dr={}  mu={}  sg={}
  Listen:   {}:{}
  Control:  127.0.0.1:{}
  Sites:    {}
",
        &cert.node_id_hex()[..16],
        cert.bits.bits(), cert.dr, cert.mu, cert.sg,
        node.host, node.port,
        ctl_port,
        sites_dir().display(),
    );
}

fn detect_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0").ok()
        .and_then(|s| { s.connect("8.8.8.8:80").ok()?; s.local_addr().ok() })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}
