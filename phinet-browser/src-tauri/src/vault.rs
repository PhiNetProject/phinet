// phinet-browser/src-tauri/src/vault.rs
//! Desktop vault — pure-Rust crypto so it builds identically on Linux,
//! Windows, and macOS with no C cross-compile. Same primitives as the
//! Android Lockr vault: Argon2id derives the master key from a passphrase,
//! XChaCha20-Poly1305 seals the data.
//!
//! Layout under <app-data>/phinet-vault/:
//!   vault.salt   — Argon2 salt (not secret)
//!   index.enc    — sealed JSON list of items (small text items inline)
//!   blobs/<id>   — sealed file contents (one AEAD blob each)
//!
//! The master key lives only in memory (VaultState) while unlocked.

use argon2::{Argon2, Algorithm, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, sync::Mutex};

const AAD_SALT: &str = "phinet_vault_v1";

/// Chunked blob format for file contents.
///
/// The original format sealed a whole file as one AEAD message, which needs
/// the entire plaintext *and* the entire ciphertext resident at once — a few
/// hundred MB of video meant a gigabyte of allocation, on the UI thread, and
/// the app looked hung. This streams instead: constant memory regardless of
/// file size.
///
///   "PHV2" | nonce_prefix(16) | [ u32be ct_len | ct ]...
///
/// Each chunk's nonce is prefix ‖ counter(8, big-endian), so no nonce repeats
/// under one key. The counter is part of the nonce rather than the AAD so a
/// reordered or dropped chunk fails to decrypt rather than silently
/// reassembling wrong. Legacy blobs (no magic) still read via `open`.
const BLOB_MAGIC: &[u8; 4] = b"PHV2";
const BLOB_CHUNK: usize = 1024 * 1024;   // 1 MiB plaintext per chunk

fn seal_stream(key: &[u8; 32], src: &std::path::Path, dst: &std::path::Path)
    -> Result<u64, String>
{
    use std::io::{BufReader, BufWriter, Read, Write};
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut prefix = [0u8; 16];
    OsRng.fill_bytes(&mut prefix);

    let fin = fs::File::open(src).map_err(|e| e.to_string())?;
    let fout = fs::File::create(dst).map_err(|e| e.to_string())?;
    let mut r = BufReader::with_capacity(BLOB_CHUNK, fin);
    let mut w = BufWriter::new(fout);

    w.write_all(BLOB_MAGIC).map_err(|e| e.to_string())?;
    w.write_all(&prefix).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; BLOB_CHUNK];
    let mut counter: u64 = 0;
    let mut plain_len: u64 = 0;
    loop {
        let mut filled = 0;
        while filled < BLOB_CHUNK {
            match r.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(e.to_string()),
            }
        }
        if filled == 0 { break; }
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&prefix);
        nonce[16..].copy_from_slice(&counter.to_be_bytes());
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), &buf[..filled])
            .map_err(|_| "encrypt failed".to_string())?;
        w.write_all(&(ct.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
        w.write_all(&ct).map_err(|e| e.to_string())?;
        plain_len += filled as u64;
        counter += 1;
        if filled < BLOB_CHUNK { break; }
    }
    w.flush().map_err(|e| e.to_string())?;
    Ok(plain_len)
}

/// Decrypt a chunked blob to `dst`, streaming. Returns plaintext length.
fn open_stream(key: &[u8; 32], src: &std::path::Path, dst: &std::path::Path)
    -> Result<u64, String>
{
    use std::io::{BufReader, BufWriter, Read, Write};
    let cipher = XChaCha20Poly1305::new(key.into());
    let fin = fs::File::open(src).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(fin);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != BLOB_MAGIC {
        // Legacy one-shot blob: read it whole (these predate streaming, and
        // are small enough that it was tolerable).
        let all = fs::read(src).map_err(|e| e.to_string())?;
        let plain = open(key, &all)?;
        fs::write(dst, &plain).map_err(|e| e.to_string())?;
        return Ok(plain.len() as u64);
    }
    let mut prefix = [0u8; 16];
    r.read_exact(&mut prefix).map_err(|e| e.to_string())?;

    let fout = fs::File::create(dst).map_err(|e| e.to_string())?;
    let mut w = BufWriter::new(fout);
    let mut counter: u64 = 0;
    let mut plain_len: u64 = 0;
    loop {
        let mut lenb = [0u8; 4];
        match r.read_exact(&mut lenb) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        let n = u32::from_be_bytes(lenb) as usize;
        let mut ct = vec![0u8; n];
        r.read_exact(&mut ct).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&prefix);
        nonce[16..].copy_from_slice(&counter.to_be_bytes());
        let plain = cipher.decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| "decrypt failed (wrong key or corrupt blob)".to_string())?;
        w.write_all(&plain).map_err(|e| e.to_string())?;
        plain_len += plain.len() as u64;
        counter += 1;
    }
    w.flush().map_err(|e| e.to_string())?;
    Ok(plain_len)
}

/// How long the vault stays unlocked without use. An unlocked vault is a
/// decryption key sitting in RAM: leave it there all day and "encrypted at
/// rest" stops describing anything real.
const IDLE_LOCK: std::time::Duration = std::time::Duration::from_secs(15 * 60);

#[derive(Default)]
pub struct VaultState {
    pub master: Mutex<Option<[u8; 32]>>,
    pub last_use: Mutex<Option<std::time::Instant>>,
}

/// Overwrite a key before dropping it.
///
/// `= None` just drops the array: the bytes stay in freed memory until
/// something reuses the page, which means a swap file or a core dump can
/// still contain the vault key long after locking. `write_volatile` can't be
/// optimised away the way a plain assignment can.
fn wipe(k: &mut [u8; 32]) {
    for b in k.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl VaultState {
    /// Fetch the master key, enforcing the idle timeout. Returns None if the
    /// vault is locked or has just been auto-locked.
    pub fn key(&self) -> Option<[u8; 32]> {
        let mut last = self.last_use.lock().unwrap();
        let mut g = self.master.lock().unwrap();
        if let Some(t) = *last {
            if t.elapsed() > IDLE_LOCK {
                if let Some(mut k) = g.take() { wipe(&mut k); }
                *last = None;
                return None;
            }
        }
        let k = (*g)?;
        *last = Some(std::time::Instant::now());
        Some(k)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultItem {
    pub id: String,
    pub kind: String,           // "link" | "note" | "secret" | "file"
    pub title: String,
    #[serde(default)]
    pub content: String,        // small text items
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub mime: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Index {
    items: Vec<VaultItem>,
}

fn dir() -> PathBuf {
    let mut d = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    d.push("phinet-vault");
    d
}
fn salt_path() -> PathBuf { dir().join("vault.salt") }
fn index_path() -> PathBuf { dir().join("index.enc") }
fn blob_path(id: &str) -> PathBuf { dir().join("blobs").join(id) }

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 3, 2, Some(32)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// nonce(24) || ciphertext+tag
fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| "encrypt failed".to_string())?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}
fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 24 { return Err("blob too short".into()); }
    let cipher = XChaCha20Poly1305::new(key.into());
    let (nonce, ct) = data.split_at(24);
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| "wrong passphrase or corrupt data".to_string())
}

fn read_index(key: &[u8; 32]) -> Index {
    let p = index_path();
    if !p.exists() { return Index::default(); }
    match fs::read(&p).ok().and_then(|b| open(key, &b).ok()) {
        Some(plain) => serde_json::from_slice(&plain).unwrap_or_default(),
        None => Index::default(),
    }
}
fn write_index(key: &[u8; 32], idx: &Index) -> Result<(), String> {
    fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let plain = serde_json::to_vec(idx).map_err(|e| e.to_string())?;
    fs::write(index_path(), seal(key, &plain)?).map_err(|e| e.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

// ── Tauri commands ──────────────────────────────────────────────

#[tauri::command]
pub fn vault_exists() -> bool { salt_path().exists() }

#[tauri::command]
pub fn vault_status(state: tauri::State<VaultState>) -> Value {
    json!({ "exists": salt_path().exists(), "unlocked": state.key().is_some() })
}

#[tauri::command]
pub fn vault_create(passphrase: String, state: tauri::State<VaultState>) -> Value {
    if passphrase.len() < 6 { return json!({ "ok": false, "error": "use at least 6 characters" }); }
    if let Err(e) = fs::create_dir_all(dir().join("blobs")) { return json!({ "ok": false, "error": e.to_string() }); }
    let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
    if let Err(e) = fs::write(salt_path(), salt) { return json!({ "ok": false, "error": e.to_string() }); }
    match derive(&passphrase, &salt) {
        Ok(key) => {
            if let Err(e) = write_index(&key, &Index::default()) { return json!({ "ok": false, "error": e }); }
            *state.master.lock().unwrap() = Some(key);
    *state.last_use.lock().unwrap() = Some(std::time::Instant::now());
            *state.last_use.lock().unwrap() = Some(std::time::Instant::now());
            json!({ "ok": true })
        }
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

#[tauri::command]
pub fn vault_unlock(passphrase: String, state: tauri::State<VaultState>) -> Value {
    let salt = match fs::read(salt_path()) { Ok(s) => s, Err(_) => return json!({ "ok": false, "error": "no vault yet" }) };
    let key = match derive(&passphrase, &salt) { Ok(k) => k, Err(e) => return json!({ "ok": false, "error": e }) };
    // verify by decrypting the index
    let p = index_path();
    if p.exists() {
        match fs::read(&p).ok().and_then(|b| open(&key, &b).ok()) {
            Some(_) => {}
            None => return json!({ "ok": false, "error": "wrong passphrase" }),
        }
    }
    *state.master.lock().unwrap() = Some(key);
    *state.last_use.lock().unwrap() = Some(std::time::Instant::now());
    json!({ "ok": true })
}

#[tauri::command]
pub fn vault_lock(state: tauri::State<VaultState>) {
    let mut g = state.master.lock().unwrap();
    if let Some(mut k) = g.take() { wipe(&mut k); }
    *state.last_use.lock().unwrap() = None;
}

#[tauri::command]
pub fn vault_list(state: tauri::State<VaultState>) -> Value {
    match state.key() {
        Some(key) => json!({ "ok": true, "items": read_index(&key).items }),
        None => json!({ "ok": false, "error": "locked" }),
    }
}

#[tauri::command]
pub fn vault_add(kind: String, title: String, content: String, state: tauri::State<VaultState>) -> Value {
    let key_owned = match state.key() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let key = &key_owned;
    let mut idx = read_index(key);
    idx.items.insert(0, VaultItem {
        id: uuid::Uuid::new_v4().to_string(), kind, title, content,
        file_name: String::new(), mime: String::new(), size: 0, created_at: now(),
    });
    match write_index(key, &idx) { Ok(_) => json!({ "ok": true, "items": idx.items }), Err(e) => json!({ "ok": false, "error": e }) }
}

#[tauri::command]
pub fn vault_delete(id: String, state: tauri::State<VaultState>) -> Value {
    let key_owned = match state.key() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let key = &key_owned;
    let mut idx = read_index(key);
    idx.items.retain(|i| i.id != id);
    let _ = fs::remove_file(blob_path(&id));
    match write_index(key, &idx) { Ok(_) => json!({ "ok": true, "items": idx.items }), Err(e) => json!({ "ok": false, "error": e }) }
}

/// Import a file from disk: stream → seal → store as a FILE item.
///
/// `async` matters here: a sync command runs on the UI thread, so importing a
/// large file froze the whole window. The heavy work goes to a blocking
/// thread and the encryption streams, so memory stays flat whether the file
/// is 2 KB or 2 GB.
#[tauri::command]
pub async fn vault_import(path: String, state: tauri::State<'_, VaultState>) -> Result<Value, ()> {
    let key = match state.key() {
        Some(k) => k,
        None => return Ok(json!({ "ok": false, "error": "locked" })),
    };
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<(String, String, u64), String> {
        let src = std::path::Path::new(&path);
        let name = src.file_name().and_then(|s| s.to_str()).unwrap_or("file").to_string();
        let id = uuid::Uuid::new_v4().to_string();
        fs::create_dir_all(dir().join("blobs")).map_err(|e| e.to_string())?;
        let size = seal_stream(&key, src, &blob_path(&id))?;
        Ok((id, name, size))
    }).await;

    let (id, name, size) = match res {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Ok(json!({ "ok": false, "error": e })),
        Err(e)     => return Ok(json!({ "ok": false, "error": e.to_string() })),
    };
    let mime = mime_for(&name);
    let mut idx = read_index(&key);
    idx.items.insert(0, VaultItem {
        id, kind: "file".into(), title: name.clone(), content: String::new(),
        file_name: name, mime, size, created_at: now(),
    });
    Ok(match write_index(&key, &idx) {
        Ok(_)  => json!({ "ok": true, "items": idx.items }),
        Err(e) => json!({ "ok": false, "error": e }),
    })
}

/// Store a file that arrived over com (chunked, reassembled by the UI) as a
/// sealed FILE item. The bytes go straight from the message into the vault —
/// a file fetched over an anonymous circuit shouldn't be written to the
/// filesystem in the clear just to get it into the vault.
#[tauri::command]
pub fn vault_add_file_b64(name: String, mime: String, b64: String,
                          state: tauri::State<VaultState>) -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let key_owned = match state.key() { Some(k) => k, None => return json!({ "ok": false, "error": "locked" }) };
    let key = &key_owned;
    let bytes = match STANDARD.decode(b64.as_bytes()) {
        Ok(b) => b, Err(e) => return json!({ "ok": false, "error": e.to_string() })
    };
    let size = bytes.len() as u64;
    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = fs::create_dir_all(dir().join("blobs")) { return json!({ "ok": false, "error": e.to_string() }); }
    // Write the bytes to a scratch file and seal it with the same chunked
    // writer used for imports, so every blob in the vault has one format.
    let tmp = std::env::temp_dir().join(format!("phinet-recv-{}", &id[..8]));
    if let Err(e) = fs::write(&tmp, &bytes) { return json!({ "ok": false, "error": e.to_string() }); }
    let sealed = seal_stream(key, &tmp, &blob_path(&id));
    let _ = fs::remove_file(&tmp);
    if let Err(e) = sealed { return json!({ "ok": false, "error": e }); }
    let mime = if mime.is_empty() { mime_for(&name) } else { mime };
    let mut idx = read_index(key);
    idx.items.insert(0, VaultItem {
        id, kind: "file".into(), title: name.clone(), content: String::new(),
        file_name: name, mime, size, created_at: now(),
    });
    match write_index(key, &idx) { Ok(_) => json!({ "ok": true, "items": idx.items }), Err(e) => json!({ "ok": false, "error": e }) }
}

/// Mime and plaintext length for a file item, if the vault is unlocked.
/// Used by the `vault://` protocol handler before it serves any bytes.
pub fn item_meta(state: &VaultState, id: &str) -> Option<(String, u64)> {
    let key = state.key()?;
    let idx = read_index(&key);
    idx.items.iter().find(|i| i.id == id).map(|i| (i.mime.clone(), i.size))
}

/// Decrypt and return the plaintext bytes in `[start, end]`.
///
/// Only the chunks covering the range are decrypted — the blob's chunk
/// framing makes that possible, so seeking to the middle of a video doesn't
/// decrypt everything before it. The scan reads each chunk's length header
/// and skips the ciphertext until it reaches the first chunk we need, which
/// is cheap relative to decrypting.
pub fn read_range(state: &VaultState, id: &str, start: u64, end: u64) -> Result<Vec<u8>, String> {
    use std::io::{BufReader, Read, Seek, SeekFrom};
    let key = state.key().ok_or("locked")?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let f = fs::File::open(blob_path(id)).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(f);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != BLOB_MAGIC {
        // Legacy one-shot blob: no framing to seek through, so decrypt it
        // whole and slice. These are small by construction (they predate
        // streaming) so the cost is bounded.
        let all = fs::read(blob_path(id)).map_err(|e| e.to_string())?;
        let plain = open(&key, &all)?;
        let s = (start as usize).min(plain.len());
        let e = ((end as usize) + 1).min(plain.len());
        return Ok(plain[s..e].to_vec());
    }
    let mut prefix = [0u8; 16];
    r.read_exact(&mut prefix).map_err(|e| e.to_string())?;

    let first = start / BLOB_CHUNK as u64;         // chunk holding `start`
    let mut counter: u64 = 0;

    // Skip whole chunks we don't need, reading only their length headers.
    while counter < first {
        let mut lenb = [0u8; 4];
        r.read_exact(&mut lenb).map_err(|e| e.to_string())?;
        let n = u32::from_be_bytes(lenb) as i64;
        r.seek(SeekFrom::Current(n)).map_err(|e| e.to_string())?;
        counter += 1;
    }

    let mut out = Vec::new();
    let mut pos = counter * BLOB_CHUNK as u64;     // plaintext offset of `counter`
    loop {
        if pos > end { break; }
        let mut lenb = [0u8; 4];
        match r.read_exact(&mut lenb) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        let n = u32::from_be_bytes(lenb) as usize;
        let mut ct = vec![0u8; n];
        r.read_exact(&mut ct).map_err(|e| e.to_string())?;

        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&prefix);
        nonce[16..].copy_from_slice(&counter.to_be_bytes());
        let plain = cipher.decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| "decrypt failed (wrong key or corrupt blob)".to_string())?;

        // Trim this chunk to the requested window.
        let chunk_start = pos;
        let chunk_end = pos + plain.len() as u64;   // exclusive
        let from = start.saturating_sub(chunk_start).min(plain.len() as u64) as usize;
        let to = ((end + 1).saturating_sub(chunk_start)).min(plain.len() as u64) as usize;
        if to > from { out.extend_from_slice(&plain[from..to]); }

        pos = chunk_end;
        counter += 1;
    }
    Ok(out)
}

/// Decrypt a file item **in memory** for viewing inside the app. Unlike
/// `vault_reveal` this never writes plaintext to disk — the whole point of a
/// vault is undermined if every look at a file leaves a decrypted copy in
/// /tmp for anything on the machine to read. Body is hex; the UI decodes it.
#[tauri::command]
pub async fn vault_read(id: String, state: tauri::State<'_, VaultState>) -> Result<Value, ()> {
    // Hard cap: this hands the bytes to the webview as hex, which costs ~2x
    // the file size in the JSON message and again as a JS string. Fine for a
    // note or a photo; catastrophic for a video. Anything larger is opened
    // through vault_reveal instead, which streams to a temp file.
    const MAX_INLINE: u64 = 16 * 1024 * 1024;

    let key = match state.key() {
        Some(k) => k,
        None => return Ok(json!({ "ok": false, "error": "locked" })),
    };
    let idx = read_index(&key);
    let item = match idx.items.iter().find(|i| i.id == id) {
        Some(i) => i.clone(),
        None => return Ok(json!({ "ok": false, "error": "not found" })),
    };
    if item.size > MAX_INLINE {
        return Ok(json!({
            "ok": false, "too_large": true, "mime": item.mime, "size": item.size,
            "error": "too large to preview in-app",
        }));
    }
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<(String, String, String, u64), String> {
        let tmp = std::env::temp_dir().join(format!("phinet-read-{}", &id[..8]));
        let n = open_stream(&key, &blob_path(&id), &tmp)?;
        let bytes = fs::read(&tmp).map_err(|e| e.to_string())?;
        // The temp file is a decryption scratchpad, not a deliverable —
        // remove it so viewing a vault item doesn't leave plaintext behind.
        let _ = fs::remove_file(&tmp);
        Ok((hex::encode(&bytes), item.mime.clone(), item.file_name.clone(), n))
    }).await;

    Ok(match res {
        Ok(Ok((hex, mime, name, size))) =>
            json!({ "ok": true, "hex": hex, "mime": mime, "name": name, "size": size }),
        Ok(Err(e)) => json!({ "ok": false, "error": e }),
        Err(e)     => json!({ "ok": false, "error": e.to_string() }),
    })
}

/// Decrypt a file item to a temp path for viewing/opening. Returns the path;
/// the caller can open it with the OS. (Temp file is the OS temp dir.)
#[tauri::command]
pub async fn vault_reveal(id: String, state: tauri::State<'_, VaultState>) -> Result<Value, ()> {
    let key = match state.key() {
        Some(k) => k,
        None => return Ok(json!({ "ok": false, "error": "locked" })),
    };
    let idx = read_index(&key);
    let item = match idx.items.iter().find(|i| i.id == id) {
        Some(i) => i.clone(),
        None => return Ok(json!({ "ok": false, "error": "not found" })),
    };
    let mime = item.mime.clone();
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("phinet-{}-{}", &id[..8], item.file_name));
        open_stream(&key, &blob_path(&id), &tmp)?;
        Ok(tmp.to_string_lossy().to_string())
    }).await;
    Ok(match res {
        Ok(Ok(path)) => json!({ "ok": true, "path": path, "mime": mime }),
        Ok(Err(e))   => json!({ "ok": false, "error": e }),
        Err(e)       => json!({ "ok": false, "error": e.to_string() }),
    })
}

/// Encode a small (non-file) item as a shareable payload the recipient's
/// client renders as a vault card (same tagged prefix as Android).
#[tauri::command]
pub fn vault_share_body(kind: String, title: String, content: String) -> Value {
    let payload = json!({ "id": "shared", "kind": kind, "title": title, "content": content });
    json!({ "ok": true, "body": format!("\u{1}phinet-vault\u{1}{}", payload) })
}

/// Guess a content type from the file name. The viewer dispatches on this, so
/// an unknown type is the difference between a video playing and a "no preview
/// for this" message.
fn mime_for(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        // images
        "png" => "image/png", "jpg" | "jpeg" => "image/jpeg", "gif" => "image/gif",
        "webp" => "image/webp", "svg" => "image/svg+xml", "bmp" => "image/bmp",
        "ico" => "image/x-icon", "avif" => "image/avif", "heic" => "image/heic",
        // video
        "mp4" | "m4v" => "video/mp4", "webm" => "video/webm", "ogv" => "video/ogg",
        "mov" => "video/quicktime", "mkv" => "video/x-matroska", "avi" => "video/x-msvideo",
        // audio
        "mp3" => "audio/mpeg", "m4a" => "audio/mp4", "aac" => "audio/aac",
        "ogg" | "oga" => "audio/ogg", "wav" => "audio/wav", "flac" => "audio/flac",
        "opus" => "audio/opus",
        // documents
        "pdf" => "application/pdf",
        "txt" | "log" | "csv" => "text/plain", "md" => "text/markdown",
        "html" | "htm" => "text/html", "css" => "text/css",
        "json" => "application/json", "xml" => "application/xml",
        "js" => "text/javascript", "rs" => "text/plain", "py" => "text/plain",
        "toml" | "yaml" | "yml" | "ini" | "conf" => "text/plain",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "epub" => "application/epub+zip",
        // archives
        "zip" => "application/zip", "gz" => "application/gzip",
        "tar" => "application/x-tar", "7z" => "application/x-7z-compressed",
        _ => "application/octet-stream",
    }.to_string()
}

// Keep AAD constant referenced (documents intent; folded into future framing).
#[allow(dead_code)]
fn _aad() -> &'static str { AAD_SALT }
