// phinet-browser/src-tauri/src/main.rs
//! com — the ΦNET end-to-end encrypted messenger, as a native Tauri
//! desktop app. The UI (React) calls these commands; each one bridges
//! to the running ΦNET daemon's control socket (127.0.0.1:7799) with a
//! single line-delimited JSON request, exactly like the ΦNET browser.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;
mod daemon;

use serde_json::{json, Value};
use tauri::Manager;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

/// Control-socket port the daemon listens on (its default `--ctl-port`).
const CTL_ADDR: &str = "127.0.0.1:7799";

/// Send one control request and read one JSON response line.
/// Read the daemon's control cookie from its data directory. The daemon
/// refuses every command but `ping` without it, so a stray process on the
/// machine can't read this node's messages or speak as it.
fn control_cookie() -> Option<String> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))?;
    let path = std::path::Path::new(&home).join(".phinet").join("control.cookie");
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

async fn ctl(req: Value) -> Option<Value> {
    let mut req = req;
    if let (Some(obj), Some(c)) = (req.as_object_mut(), control_cookie()) {
        obj.insert("cookie".into(), Value::String(c));
    }
    let stream = TcpStream::connect(CTL_ADDR).await.ok()?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut line = req.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.ok()?;
    writer.flush().await.ok()?;
    let resp = lines.next_line().await.ok()??;
    serde_json::from_str(&resp).ok()
}

fn offline() -> Value { json!({ "ok": false, "error": "daemon offline" }) }

#[tauri::command]
async fn whoami() -> Value {
    ctl(json!({ "cmd": "whoami" })).await.unwrap_or_else(offline)
}

/// Connected peers, usable as contacts (node_id + static_pub + addr).
#[tauri::command]
async fn peers() -> Value {
    ctl(json!({ "cmd": "peers" })).await.unwrap_or_else(offline)
}

/// Conversation thread peer ids, most-recent first.
#[tauri::command]
async fn com_threads() -> Value {
    ctl(json!({ "cmd": "com_threads" })).await.unwrap_or_else(offline)
}

/// Messages in the conversation with `peer` (hex node id).
#[tauri::command]
async fn com_thread(peer: String) -> Value {
    ctl(json!({ "cmd": "com_thread", "node_id_hex": peer })).await
        .unwrap_or_else(offline)
}

/// Send an end-to-end-encrypted message to `peer`. Works whether the
/// recipient is online (direct) or offline (store-and-forward), as long
/// as the daemon has learned the recipient's key.
#[tauri::command]
async fn com_send(peer: String, text: String) -> Value {
    ctl(json!({ "cmd": "com_send", "node_id_hex": peer, "text": text })).await
        .unwrap_or_else(offline)
}

/// Groups & channels.
#[tauri::command]
async fn com_groups() -> Value {
    ctl(json!({ "cmd": "com_groups" })).await.unwrap_or_else(offline)
}

#[tauri::command]
async fn com_create_group(name: String, is_channel: bool) -> Value {
    ctl(json!({ "cmd": "com_create_group", "name": name, "is_channel": is_channel }))
        .await.unwrap_or_else(offline)
}

#[tauri::command]
async fn com_invite(group_id: String, peer: String) -> Value {
    ctl(json!({ "cmd": "com_invite", "group_id": group_id, "node_id_hex": peer }))
        .await.unwrap_or_else(offline)
}

#[tauri::command]
async fn com_send_group(group_id: String, text: String) -> Value {
    ctl(json!({ "cmd": "com_send_group", "group_id": group_id, "text": text }))
        .await.unwrap_or_else(offline)
}

/// This node's shareable com address (phi:<128 hex>). Hand it out so
/// others can add you — there is no public roster.
#[tauri::command]
async fn com_my_address() -> Value {
    ctl(json!({ "cmd": "com_my_address" })).await.unwrap_or_else(offline)
}

/// Add a contact from an address someone shared with you out of band.
#[tauri::command]
async fn com_add_contact(address: String) -> Value {
    ctl(json!({ "cmd": "com_add_contact", "address": address })).await
        .unwrap_or_else(offline)
}


/// Unsend a message (removes it here and asks the peer to remove it).
#[tauri::command]
async fn com_delete(peer: String, msg_id: String) -> Value {
    ctl(json!({ "cmd": "com_delete", "node_id_hex": peer, "msg_id": msg_id })).await
        .unwrap_or_else(offline)
}

/// Fetch a `.phinet` hidden site through the local node. `hs_id` is the
/// site id (without the .phinet suffix); returns { ok, status, body_b64 }.
#[tauri::command]
async fn browser_fetch(hs_id: String, path: String) -> Value {
    ctl(json!({ "cmd": "hs_fetch", "hs_id": hs_id, "path": path, "method": "GET" })).await
        .unwrap_or_else(offline)
}

/// Open a clearnet URL in a real webview window. An iframe can't show most
/// sites (X-Frame-Options / CSP frame-ancestors block embedding → white
/// screen); a top-level webview navigation isn't subject to that. Note:
/// clearnet traffic is a DIRECT connection, not routed through ΦNET.
#[tauri::command]
async fn open_web(app: tauri::AppHandle, url: String) -> Value {
    use tauri::{WebviewUrl, WebviewWindowBuilder};
    let parsed: url::Url = match url.parse() {
        Ok(u) => u,
        Err(e) => return json!({ "ok": false, "error": format!("bad url: {e}") }),
    };
    // Only ever open the web. Not `file:` (reads the user's disk), not
    // `javascript:` (runs in the window we're about to reuse, via the eval
    // below), not `data:`/`blob:`. This matters because the URL isn't always
    // the user's own: a vault link item can arrive from a contact over com,
    // so "open this link" is an instruction from an untrusted party.
    if !matches!(parsed.scheme(), "http" | "https") {
        return json!({
            "ok": false,
            "error": format!("refusing to open a {} link — only http and https", parsed.scheme()),
        });
    }
    // Hand the parsed URL to the webview rather than splicing the raw string
    // into JavaScript.
    let href = parsed.to_string();
    if let Some(w) = app.get_webview_window("web") {
        let _ = w.eval(&format!("window.location.replace({})",
                                serde_json::to_string(&href).unwrap_or_else(|_| "\"about:blank\"".into())));
        let _ = w.set_focus();
        return json!({ "ok": true });
    }
    match WebviewWindowBuilder::new(&app, "web", WebviewUrl::External(parsed))
        .title("Web")
        .inner_size(1100.0, 800.0)
        .build()
    {
        Ok(_)  => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// Tor-style circuit + identity view.
#[tauri::command]
async fn circuit_info() -> Value {
    ctl(json!({ "cmd": "circuit_info" })).await.unwrap_or_else(offline)
}

/// Rotate to a new identity (retire guards, drop circuits, reselect).
#[tauri::command]
async fn new_identity() -> Value {
    ctl(json!({ "cmd": "new_identity" })).await.unwrap_or_else(offline)
}

/// Serve vault items to the webview over `vault://<id>`.
///
/// The alternative — handing whole files to the frontend as hex through a
/// command — costs several times the file's size in RAM and can't seek, which
/// is why the viewer was capped at 16 MB and couldn't show video at all. A
/// protocol handler streams instead: the webview asks for byte ranges the way
/// it would from any HTTP server, so `<video>`, `<audio>` and PDF viewers work
/// on files of any size, and the plaintext never touches the disk the way
/// `vault_reveal` requires.
fn vault_protocol(
    app: &tauri::AppHandle,
    req: tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    use tauri::http::{header, Response, StatusCode};
    use tauri::Manager;

    let deny = |code: StatusCode| Response::builder()
        .status(code).body(Vec::new()).unwrap();

    // vault://localhost/<id> on Windows, vault://<id> elsewhere — take the
    // last non-empty path segment either way.
    let uri = req.uri().clone();
    let id = uri.path().trim_matches('/').rsplit('/').next().unwrap_or("").to_string();
    if id.is_empty() { return deny(StatusCode::BAD_REQUEST); }

    let state = app.state::<vault::VaultState>();
    let (mime, total) = match vault::item_meta(&state, &id) {
        Some(m) => m,
        None => return deny(StatusCode::NOT_FOUND),   // locked, or no such item
    };

    // Parse `Range: bytes=start-end`. Media elements rely on this to seek;
    // without it a browser will refuse to scrub a video.
    let range = req.headers().get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
        .map(|v| {
            let (a, b) = v.split_once('-').unwrap_or((v, ""));
            let start: u64 = a.parse().unwrap_or(0);
            let end: u64 = b.parse().unwrap_or(total.saturating_sub(1));
            (start, end.min(total.saturating_sub(1)))
        });

    // Cap each ranged response. A `<video>` opens with `Range: bytes=0-`,
    // meaning "from here to the end" — honouring that literally decrypts the
    // whole file into memory and hands the webview a gigabyte in one lump,
    // which is exactly the one-shot load the protocol exists to avoid. It
    // stalls, and the player gives up and shows a broken-media icon.
    //
    // Returning fewer bytes than asked for is normal and expected: the player
    // sees the Content-Range, takes the slice, and asks for the next one. That
    // back-and-forth *is* streaming.
    //
    // A request with no Range at all (an <img>, a PDF) still gets the whole
    // file — those need it in one piece, and they're bounded by the import
    // size in practice.
    const MAX_RANGE_RESPONSE: u64 = 4 * 1024 * 1024;
    let (start, end) = match range {
        Some((s, e)) => (s, e.min(s.saturating_add(MAX_RANGE_RESPONSE - 1))),
        None => (0, total.saturating_sub(1)),
    };
    if start > end || start >= total { return deny(StatusCode::RANGE_NOT_SATISFIABLE); }

    let bytes = match vault::read_range(&state, &id, start, end) {
        Ok(b) => b,
        Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut b = Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        // The bytes came out of the vault; don't let anything cache them.
        .header(header::CACHE_CONTROL, "no-store");
    if range.is_some() {
        b = b.status(StatusCode::PARTIAL_CONTENT)
             .header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, total));
    }
    b.body(bytes).unwrap()
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .try_init();

    tauri::Builder::default()
        .register_uri_scheme_protocol("vault", |ctx, req| vault_protocol(ctx.app_handle(), req))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(vault::VaultState::default())
        .manage(daemon::DaemonGuard::default())
        .setup(|app| {
            // Auto-bootstrap: make sure a local node is running + joining the
            // network the moment the app opens.
            let guard = app.state::<daemon::DaemonGuard>();
            let status = daemon::ensure_running(guard.inner());
            eprintln!("[phinet] {status}");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            whoami,
            peers,
            com_threads,
            com_thread,
            com_send,
            com_delete,
            com_groups,
            com_create_group,
            com_invite,
            com_send_group,
            com_my_address,
            com_add_contact,
            browser_fetch,
            open_web,
            circuit_info,
            new_identity,
            daemon::daemon_status,
            vault::vault_exists,
            vault::vault_status,
            vault::vault_create,
            vault::vault_unlock,
            vault::vault_lock,
            vault::vault_list,
            vault::vault_add,
            vault::vault_delete,
            vault::vault_import,
            vault::vault_reveal,
            vault::vault_read,
            vault::vault_add_file_b64,
            vault::vault_share_body,
        ])
        .build(tauri::generate_context!())
        .expect("error while building com")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                    daemon::shutdown(app.state::<daemon::DaemonGuard>().inner());
            }
        });
}
