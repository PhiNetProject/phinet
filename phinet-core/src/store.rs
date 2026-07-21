// phinet-core/src/store.rs
//! Persistent site store at ~/.phinet/sites/

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

pub fn phinet_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".phinet")
}

pub fn sites_dir() -> PathBuf { phinet_dir().join("sites") }
pub fn identity_path() -> PathBuf { phinet_dir().join("identity.json") }

/// Path to a hidden service's persistent identity file. The operator
/// picks a human-readable `service_name` (e.g. "blog"); the file at
/// `~/.phinet/hs_identity_<sanitized_name>.json` holds the Ed25519
/// identity keypair so the hs_id stays stable across daemon restarts.
///
/// Service names are sanitized to filename-safe characters: anything
/// not in `[A-Za-z0-9._-]` becomes `_`. This is defense-in-depth
/// against path traversal; the caller controls the name but should
/// not assume any sanitization upstream.
pub fn hs_identity_path(service_name: &str) -> PathBuf {
    let sanitized: String = service_name.chars().map(|c| {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            c
        } else {
            '_'
        }
    }).collect();
    phinet_dir().join(format!("hs_identity_{}.json", sanitized))
}

// ── Site metadata ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMeta {
    pub name:      String,
    pub hs_id:     String,
    pub nonce_hex: String,
    pub created:   u64,
}

// ── Store ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SiteStore {
    root: PathBuf,
}

impl SiteStore {
    pub fn new() -> Self { Self { root: sites_dir() } }

    pub fn new_test() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        // Include the process PID in the path so tempdirs from prior
        // cargo-test runs can't collide with this run's counter values.
        // Otherwise stale files from a previous run (which aren't
        // cleaned up since new_test has no Drop impl) would make
        // list_services report stale entries.
        let pid  = std::process::id();
        let root = std::env::temp_dir().join(format!(
            "phinet_test_{}_{}",
            pid,
            CTR.fetch_add(1, Ordering::SeqCst),
        ));
        // Always start from an empty dir — if this path happens to
        // exist (extremely unlikely given PID+counter), blow it away.
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).ok();
        Self { root }
    }

    fn site_dir(&self, hs_id: &str) -> PathBuf { self.root.join(hs_id) }
    fn meta_path(&self, hs_id: &str) -> PathBuf { self.site_dir(hs_id).join("_meta.json") }
    fn www_dir(&self,  hs_id: &str) -> PathBuf { self.site_dir(hs_id).join("www") }
    /// Per-service authorized client list. Each line in this file
    /// is one X25519 public key (hex). When this file exists and is
    /// non-empty, the daemon publishes the descriptor with
    /// client-auth (only listed clients can resolve the intro point).
    /// When absent or empty, the descriptor is published without
    /// auth (everyone can resolve).
    fn clients_path(&self, hs_id: &str) -> PathBuf {
        self.site_dir(hs_id).join("authorized_clients.txt")
    }

    /// Add an authorized client public key for this service. The
    /// pubkey must be 32 bytes hex-encoded (64 hex chars). Returns
    /// `Ok(true)` if added, `Ok(false)` if already present.
    pub async fn add_authorized_client(
        &self,
        hs_id: &str,
        client_pub_hex: &str,
    ) -> Result<bool> {
        if !self.site_dir(hs_id).exists() {
            return Err(Error::NotFound(format!("service {}", hs_id)));
        }
        let normalized = client_pub_hex.trim().to_lowercase();
        if normalized.len() != 64 ||
           !normalized.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::Crypto(
                "client pubkey must be 64 hex chars (32 bytes)".into()));
        }
        let mut current = self.list_authorized_clients(hs_id).await;
        if current.iter().any(|p| p == &normalized) {
            return Ok(false);
        }
        current.push(normalized);
        let body = format!(
            "# ΦNET authorized clients for service {}\n\
             # one X25519 pubkey (hex) per line; lines starting with # are comments\n\
             {}\n",
            hs_id,
            current.join("\n"),
        );
        fs::write(self.clients_path(hs_id), body).await?;
        Ok(true)
    }

    /// Remove an authorized client. Returns `Ok(true)` if found and
    /// removed, `Ok(false)` if not in the list.
    pub async fn remove_authorized_client(
        &self,
        hs_id: &str,
        client_pub_hex: &str,
    ) -> Result<bool> {
        if !self.site_dir(hs_id).exists() {
            return Err(Error::NotFound(format!("service {}", hs_id)));
        }
        let normalized = client_pub_hex.trim().to_lowercase();
        let current = self.list_authorized_clients(hs_id).await;
        if !current.iter().any(|p| p == &normalized) {
            return Ok(false);
        }
        let remaining: Vec<String> = current.into_iter()
            .filter(|p| p != &normalized).collect();
        if remaining.is_empty() {
            // Empty list = remove the file entirely so the descriptor
            // publishes without client-auth (rather than with an
            // empty list, which would lock everyone out).
            let _ = fs::remove_file(self.clients_path(hs_id)).await;
        } else {
            let body = format!(
                "# ΦNET authorized clients for service {}\n\
                 # one X25519 pubkey (hex) per line; lines starting with # are comments\n\
                 {}\n",
                hs_id,
                remaining.join("\n"),
            );
            fs::write(self.clients_path(hs_id), body).await?;
        }
        Ok(true)
    }

    /// List authorized client pubkeys for a service. Returns empty
    /// vec when the file is absent or contains no non-comment lines.
    pub async fn list_authorized_clients(&self, hs_id: &str) -> Vec<String> {
        let path = self.clients_path(hs_id);
        let content = match fs::read_to_string(&path).await {
            Ok(s)  => s,
            Err(_) => return Vec::new(),
        };
        content.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_lowercase())
            .filter(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
            .collect()
    }

    // ── Writes ────────────────────────────────────────────────────────

    pub async fn create_service(&self, hs_id: &str, name: &str, nonce_hex: &str) -> Result<SiteMeta> {
        fs::create_dir_all(self.www_dir(hs_id)).await?;
        let meta = SiteMeta {
            name:      name.to_string(),
            hs_id:     hs_id.to_string(),
            nonce_hex: nonce_hex.to_string(),
            created:   unix_now(),
        };
        fs::write(self.meta_path(hs_id), serde_json::to_string_pretty(&meta)?).await?;
        fs::write(self.www_dir(hs_id).join("index.html"), default_index_html(name, hs_id)).await?;
        Ok(meta)
    }

    pub async fn put_file(&self, hs_id: &str, url_path: &str, body: &[u8]) -> Result<()> {
        if !self.site_dir(hs_id).exists() {
            return Err(Error::NotFound(format!("service {}", hs_id)));
        }
        let dest = self.resolve(hs_id, url_path);
        if let Some(p) = dest.parent() { fs::create_dir_all(p).await?; }
        fs::write(dest, body).await?;
        Ok(())
    }

    pub async fn deploy_directory(&self, hs_id: &str, local: &std::path::Path) -> Result<Vec<String>> {
        let mut deployed = Vec::new();
        self.walk(hs_id, local, local, &mut deployed).await?;
        Ok(deployed)
    }

    fn walk<'a>(
        &'a self, hs_id: &'a str, base: &'a std::path::Path, dir: &'a std::path::Path,
        out: &'a mut Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut rd = fs::read_dir(dir).await?;
            while let Some(e) = rd.next_entry().await? {
                let p = e.path();
                let n = p.file_name().unwrap_or_default().to_string_lossy();
                if n.starts_with('.') || n.ends_with(".pyc") { continue; }
                if p.is_dir() {
                    self.walk(hs_id, base, &p, out).await?;
                } else {
                    let rel = p.strip_prefix(base).unwrap_or(&p);
                    let url = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
                    let body = fs::read(&p).await?;
                    self.put_file(hs_id, &url, &body).await?;
                    out.push(url);
                }
            }
            Ok(())
        })
    }

    pub async fn delete_service(&self, hs_id: &str) -> Result<()> {
        let d = self.site_dir(hs_id);
        if d.exists() { fs::remove_dir_all(d).await?; }
        Ok(())
    }

    pub async fn delete_file(&self, hs_id: &str, url_path: &str) -> Result<()> {
        let p = self.resolve(hs_id, url_path);
        if p.exists() { fs::remove_file(p).await?; }
        Ok(())
    }

    // ── Reads ─────────────────────────────────────────────────────────

    /// Returns (status, content-type, body) or None if service unknown.
    pub async fn get_file(&self, hs_id: &str, url_path: &str) -> Option<(u16, String, Vec<u8>)> {
        if !self.site_dir(hs_id).exists() { return None; }
        let www = self.www_dir(hs_id);
        if !www.exists() {
            return Some((404, "text/html".into(), not_found_html(url_path)));
        }
        let clean = url_path.trim_end_matches('/');
        let clean = if clean.is_empty() { "/" } else { clean };
        let candidates = [
            www.join(clean.trim_start_matches('/')),
            www.join(format!("{}/index.html", clean.trim_start_matches('/'))),
            www.join(format!("{}.html", clean.trim_start_matches('/'))),
            www.join("index.html"),
        ];
        for c in &candidates {
            if c.is_file() {
                if let Ok(body) = fs::read(c).await {
                    return Some((200, guess_mime(c), body));
                }
            }
        }
        Some((404, "text/html; charset=utf-8".into(), not_found_html(url_path)))
    }

    pub async fn get_service(&self, hs_id: &str) -> Option<SiteMeta> {
        serde_json::from_str(&fs::read_to_string(self.meta_path(hs_id)).await.ok()?).ok()
    }

    pub async fn list_services(&self) -> Vec<SiteMeta> {
        let mut out = Vec::new();
        let Ok(mut rd) = fs::read_dir(&self.root).await else { return out };
        while let Ok(Some(e)) = rd.next_entry().await {
            let id = e.file_name().to_string_lossy().to_string();
            if let Some(m) = self.get_service(&id).await { out.push(m); }
        }
        out.sort_by(|a, b| b.created.cmp(&a.created));
        out
    }

    pub async fn list_files(&self, hs_id: &str) -> Vec<String> {
        let www   = self.www_dir(hs_id);
        let mut v = Vec::new();
        collect_files(&www, &www, &mut v).await;
        v
    }

    // ── Path resolution ───────────────────────────────────────────────

    fn resolve(&self, hs_id: &str, url_path: &str) -> PathBuf {
        let www = self.www_dir(hs_id);
        let rel = url_path.trim_start_matches('/');
        let rel = if rel.is_empty() { "index.html" } else { rel };
        let parts: Vec<&str> = rel.split('/')
            .filter(|p| !p.is_empty() && *p != "..").collect();
        let mut path = www;
        for part in parts { path = path.join(part); }
        path
    }
}

impl Default for SiteStore {
    fn default() -> Self { Self::new() }
}

// ── Recursive file collector ──────────────────────────────────────────

fn collect_files<'a>(
    base: &'a std::path::Path,
    dir:  &'a std::path::Path,
    out:  &'a mut Vec<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        let Ok(mut rd) = fs::read_dir(dir).await else { return };
        while let Ok(Some(e)) = rd.next_entry().await {
            let p = e.path();
            if p.is_file() {
                let rel = p.strip_prefix(base).unwrap_or(&p);
                out.push(format!("/{}", rel.to_string_lossy()));
            } else if p.is_dir() {
                collect_files(base, &p, out).await;
            }
        }
    })
}

// ── MIME detection ────────────────────────────────────────────────────

fn guess_mime(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html"|"htm" => "text/html; charset=utf-8",
        "css"        => "text/css; charset=utf-8",
        "js"|"mjs"   => "application/javascript",
        "json"       => "application/json",
        "svg"        => "image/svg+xml",
        "png"        => "image/png",
        "jpg"|"jpeg" => "image/jpeg",
        "gif"        => "image/gif",
        "webp"       => "image/webp",
        "woff"       => "font/woff",
        "woff2"      => "font/woff2",
        "ico"        => "image/x-icon",
        "txt"        => "text/plain; charset=utf-8",
        "wasm"       => "application/wasm",
        _            => "application/octet-stream",
    }.to_string()
}

// ── Built-in pages ────────────────────────────────────────────────────

pub fn default_index_html(name: &str, hs_id: &str) -> Vec<u8> {
    let s = site_style();
    format!(
"<!DOCTYPE html><html lang=\"en\"><head>\
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{name}</title><style>{s}</style></head>\
<body>\
<header><nav><span class=\"logo\">&#x2B21; {name}</span></nav></header>\
<main>\
<div class=\"hero\">\
<div class=\"badge\">Hidden Service</div>\
<h1>{name}</h1>\
<p class=\"tagline\">Live on the anonymous network</p>\
<div class=\"addr\">{hs_id}.phinet</div>\
</div>\
<div class=\"card\">\
<h2>Deploy your content</h2>\
<p>Your hidden service is registered. Deploy a site:</p>\
<p><code>phi init \"{name}\" ./site/</code></p>\
<p><code>phi deploy {hs_id} ./site/</code></p>\
</div>\
</main>\
<footer><p>PHINET &middot; anonymous &middot; encrypted &middot; no tracking</p></footer>\
</body></html>",
        name = name, hs_id = hs_id, s = s
    ).into_bytes()
}

pub fn not_found_html(path: &str) -> Vec<u8> {
    let s = site_style();
    format!(
"<!DOCTYPE html><html><head>\
<meta charset=\"utf-8\"><title>404</title><style>{s}</style></head>\
<body>\
<main style=\"padding-top:4rem\">\
<div class=\"card\">\
<h2 style=\"color:#f87171\">404 &mdash; Not Found</h2>\
<p>The path <code>{path}</code> was not found on this hidden service.</p>\
<p><a href=\"/\">Back to home &rarr;</a></p>\
</div>\
</main>\
<footer><p>PHINET</p></footer>\
</body></html>",
        path = path, s = s
    ).into_bytes()
}

fn site_style() -> &'static str {
"*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\
:root{\
--bg:#0a0a14;--surface:#12121e;--card:#17172a;\
--border:rgba(90,110,200,.18);\
--accent:#4a7ef0;--accent2:#7aa8ff;\
--text:#d8e4f8;--muted:#8898bb;--max-w:860px}\
body{font-family:Inter,'Segoe UI',system-ui,sans-serif;\
background:var(--bg);color:var(--text);\
line-height:1.7;min-height:100vh;display:flex;flex-direction:column}\
a{color:var(--accent2);text-decoration:none}\
a:hover{text-decoration:underline}\
header{background:rgba(10,10,20,.9);\
border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}\
nav{max-width:var(--max-w);margin:0 auto;padding:1rem 2rem;\
display:flex;align-items:center;justify-content:space-between}\
.logo{font-weight:700;font-size:1.05rem;color:var(--accent2)}\
.nav-links{display:flex;gap:1.5rem}\
.nav-links a{color:var(--muted);font-size:.9rem;transition:color .15s}\
.nav-links a:hover{color:var(--text);text-decoration:none}\
main{flex:1;max-width:var(--max-w);width:100%;margin:0 auto;padding:3rem 2rem 4rem}\
.hero{text-align:center;padding:4rem 2rem 3rem}\
.badge{display:inline-block;background:rgba(74,126,240,.12);\
border:1px solid rgba(74,126,240,.3);color:var(--accent2);\
font-size:.72rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;\
padding:.3rem .9rem;border-radius:99px;margin-bottom:1.5rem}\
h1{font-size:clamp(2rem,6vw,3rem);font-weight:800;letter-spacing:-.02em;\
color:var(--accent2);margin-bottom:.5rem;line-height:1.15}\
.tagline{color:var(--muted);font-size:1.05rem;margin-bottom:1.5rem}\
.addr{display:inline-block;font-family:monospace;font-size:.75rem;\
background:var(--surface);border:1px solid var(--border);\
border-radius:8px;padding:.5rem 1.1rem;\
color:var(--accent2);word-break:break-all;max-width:100%}\
.card{background:var(--card);border:1px solid var(--border);\
border-radius:16px;padding:2rem;margin-bottom:2rem}\
.card h2,.card > h2{font-size:1.2rem;font-weight:700;\
color:var(--text);margin-bottom:.75rem}\
.card p{color:var(--muted);margin-bottom:.75rem}\
.card p:last-child{margin-bottom:0}\
section{background:var(--card);border:1px solid var(--border);\
border-radius:16px;padding:2rem;margin-bottom:2rem}\
section h2{font-size:1.2rem;font-weight:700;color:var(--text);margin-bottom:.75rem}\
section p{color:var(--muted);margin-bottom:.75rem}\
section p:last-child{margin-bottom:0}\
code{font-family:monospace;background:rgba(74,126,240,.1);\
border:1px solid rgba(74,126,240,.2);border-radius:5px;\
padding:2px 7px;font-size:.85em;color:var(--accent2)}\
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}\
.feature{background:var(--card);border:1px solid var(--border);\
border-radius:12px;padding:1.25rem 1rem;\
text-align:center;font-size:.8rem;color:var(--muted);line-height:1.4}\
.feature .icon{font-size:1.4rem;margin-bottom:.4rem}\
@media(max-width:600px){\
.features{grid-template-columns:repeat(2,1fr)}\
main{padding:2rem 1rem 3rem}\
nav{padding:.8rem 1rem}}\
footer{text-align:center;padding:1.5rem;\
border-top:1px solid var(--border);\
font-size:.78rem;color:var(--muted);font-family:monospace}"
}

pub async fn generate_starter_site(store: &SiteStore, hs_id: &str, name: &str) -> Result<Vec<String>> {
    let mut deployed = Vec::new();
    for (path, body) in starter_site_files(name, hs_id) {
        store.put_file(hs_id, path, body.as_bytes()).await?;
        deployed.push(path.to_string());
    }
    Ok(deployed)
}

fn starter_site_files(name: &str, hs_id: &str) -> Vec<(&'static str, String)> {
    let index = format!(
"<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
<title>{name}</title>\n\
<link rel=\"stylesheet\" href=\"/style.css\">\n\
</head>\n\
<body>\n\
<header><nav>\n\
  <a href=\"/\" class=\"logo\">&#x2B21; {name}</a>\n\
  <div class=\"nav-links\">\n\
    <a href=\"/\">Home</a>\n\
    <a href=\"/about.html\">About</a>\n\
  </div>\n\
</nav></header>\n\
<main>\n\
  <div class=\"hero\">\n\
    <div class=\"badge\">PHINET Hidden Service</div>\n\
    <h1>{name}</h1>\n\
    <p class=\"tagline\">Your anonymous home on PHINET</p>\n\
    <div class=\"addr\">{hs_id}.phinet</div>\n\
  </div>\n\
  <div class=\"card\">\n\
    <h2>Welcome</h2>\n\
    <p>Edit this page to make it your own. This site is hosted anonymously\n\
    on PHINET — no server knows your IP, no CA signed your certificate,\n\
    no registrar owns your address.</p>\n\
    <p>Re-deploy with: <code>phi deploy {hs_id} ./site/</code></p>\n\
  </div>\n\
  <div class=\"features\">\n\
    <div class=\"feature\"><div class=\"icon\">&#x1F512;</div>E2E Encrypted</div>\n\
    <div class=\"feature\"><div class=\"icon\">&#x1F9C5;</div>3-Hop Onion</div>\n\
    <div class=\"feature\"><div class=\"icon\">&#x1F6AB;</div>No Tracking</div>\n\
    <div class=\"feature\"><div class=\"icon\">&#x26AB;</div>No IP Exposed</div>\n\
  </div>\n\
</main>\n\
<footer><p>Hosted on PHINET &middot; anonymous &middot; encrypted &middot; no tracking</p></footer>\n\
<script src=\"/app.js\"></script>\n\
</body>\n\
</html>",
        name = name, hs_id = hs_id
    );

    let about = format!(
"<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
<title>About &mdash; {name}</title>\n\
<link rel=\"stylesheet\" href=\"/style.css\">\n\
</head>\n\
<body>\n\
<header><nav>\n\
  <a href=\"/\" class=\"logo\">&#x2B21; {name}</a>\n\
  <div class=\"nav-links\">\n\
    <a href=\"/\">Home</a>\n\
    <a href=\"/about.html\">About</a>\n\
  </div>\n\
</nav></header>\n\
<main>\n\
  <div class=\"card\">\n\
    <h2>About</h2>\n\
    <p>Published anonymously via PHINET. No accounts, no email, no tracking, no central servers.</p>\n\
    <p>Address: <code>{hs_id}.phinet</code></p>\n\
  </div>\n\
</main>\n\
<footer><p>PHINET &middot; anonymous &middot; encrypted</p></footer>\n\
</body>\n\
</html>",
        name = name, hs_id = hs_id
    );

    let js = "\
document.addEventListener('DOMContentLoaded',()=>{\n  \
  const els=document.querySelectorAll('.hero,.card,.feature');\n  \
  els.forEach((el,i)=>{\n    \
    el.style.cssText='opacity:0;transform:translateY(16px);transition:opacity .4s ease,transform .4s ease';\n    \
    setTimeout(()=>{el.style.opacity='1';el.style.transform='none';},80*i);\n  \
  });\n\
});".to_string();

    vec![
        ("/index.html", index),
        ("/about.html", about),
        ("/style.css",  site_style().to_string()),
        ("/app.js",     js),
    ]
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_read() {
        let s = SiteStore::new_test();
        s.create_service("aaaa0000bbbb1111cccc", "test", "ff").await.unwrap();
        let m = s.get_service("aaaa0000bbbb1111cccc").await.unwrap();
        assert_eq!(m.name, "test");
    }

    #[tokio::test]
    async fn put_and_get_file() {
        let s = SiteStore::new_test();
        s.create_service("1111222233334444aaaa", "s", "00").await.unwrap();
        s.put_file("1111222233334444aaaa", "/hello.txt", b"world").await.unwrap();
        let (status, ct, body) = s.get_file("1111222233334444aaaa", "/hello.txt").await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"world");
        assert!(ct.contains("plain"));
    }

    // ── Authorized client list ────────────────────────────────────────

    fn fake_pub_hex(seed: u8) -> String {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_add(99);
        hex::encode(bytes)
    }

    #[tokio::test]
    async fn authorized_clients_empty_by_default() {
        let s = SiteStore::new_test();
        s.create_service("svc1aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let clients = s.list_authorized_clients("svc1aaaaaaaaaaaaaaaa").await;
        assert!(clients.is_empty(),
            "newly-created service must have no authorized clients (= public)");
    }

    #[tokio::test]
    async fn add_authorized_client_succeeds() {
        let s = SiteStore::new_test();
        s.create_service("svc2aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let pubk = fake_pub_hex(1);
        assert!(s.add_authorized_client("svc2aaaaaaaaaaaaaaaa", &pubk).await.unwrap());
        let clients = s.list_authorized_clients("svc2aaaaaaaaaaaaaaaa").await;
        assert_eq!(clients, vec![pubk]);
    }

    #[tokio::test]
    async fn add_duplicate_returns_false() {
        let s = SiteStore::new_test();
        s.create_service("svc3aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let pubk = fake_pub_hex(2);
        assert!(s.add_authorized_client("svc3aaaaaaaaaaaaaaaa", &pubk).await.unwrap());
        assert!(!s.add_authorized_client("svc3aaaaaaaaaaaaaaaa", &pubk).await.unwrap());
        let clients = s.list_authorized_clients("svc3aaaaaaaaaaaaaaaa").await;
        assert_eq!(clients.len(), 1, "duplicate must not be re-added");
    }

    #[tokio::test]
    async fn malformed_pubkey_rejected() {
        let s = SiteStore::new_test();
        s.create_service("svc4aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        // Wrong length
        assert!(s.add_authorized_client("svc4aaaaaaaaaaaaaaaa", "deadbeef")
            .await.is_err());
        // Non-hex
        let bad = "g".repeat(64);
        assert!(s.add_authorized_client("svc4aaaaaaaaaaaaaaaa", &bad)
            .await.is_err());
    }

    #[tokio::test]
    async fn remove_authorized_client_works() {
        let s = SiteStore::new_test();
        s.create_service("svc5aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let p1 = fake_pub_hex(1);
        let p2 = fake_pub_hex(2);
        s.add_authorized_client("svc5aaaaaaaaaaaaaaaa", &p1).await.unwrap();
        s.add_authorized_client("svc5aaaaaaaaaaaaaaaa", &p2).await.unwrap();
        assert!(s.remove_authorized_client("svc5aaaaaaaaaaaaaaaa", &p1).await.unwrap());
        let remaining = s.list_authorized_clients("svc5aaaaaaaaaaaaaaaa").await;
        assert_eq!(remaining, vec![p2]);
    }

    #[tokio::test]
    async fn remove_nonexistent_returns_false() {
        let s = SiteStore::new_test();
        s.create_service("svc6aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let p = fake_pub_hex(1);
        assert!(!s.remove_authorized_client("svc6aaaaaaaaaaaaaaaa", &p).await.unwrap());
    }

    #[tokio::test]
    async fn removing_last_client_clears_file() {
        // After removing the last entry, the file should be gone so
        // the descriptor reverts to "public" (no client-auth) rather
        // than "auth with empty list" (which would lock everyone out).
        let s = SiteStore::new_test();
        s.create_service("svc7aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let p = fake_pub_hex(1);
        s.add_authorized_client("svc7aaaaaaaaaaaaaaaa", &p).await.unwrap();
        s.remove_authorized_client("svc7aaaaaaaaaaaaaaaa", &p).await.unwrap();
        assert!(s.list_authorized_clients("svc7aaaaaaaaaaaaaaaa").await.is_empty());
    }

    #[tokio::test]
    async fn comments_and_blanks_are_skipped() {
        // Manually write a file with comments and blanks; verify
        // list_authorized_clients filters them out.
        let s = SiteStore::new_test();
        s.create_service("svc8aaaaaaaaaaaaaaaa", "s", "00").await.unwrap();
        let p = fake_pub_hex(1);
        let body = format!("# alice's key\n\n{}\n# trailing\n", p);
        fs::write(s.clients_path("svc8aaaaaaaaaaaaaaaa"), body).await.unwrap();
        let listed = s.list_authorized_clients("svc8aaaaaaaaaaaaaaaa").await;
        assert_eq!(listed, vec![p]);
    }

    #[tokio::test]
    async fn index_fallback() {
        let s = SiteStore::new_test();
        s.create_service("bbbb2222cccc3333dddd", "s", "00").await.unwrap();
        let (status, ct, body) = s.get_file("bbbb2222cccc3333dddd", "/").await.unwrap();
        assert_eq!(status, 200);
        assert!(ct.contains("html"));
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn unknown_service_none() {
        let s = SiteStore::new_test();
        assert!(s.get_file("0000000000000000dead", "/").await.is_none());
    }

    #[tokio::test]
    async fn path_traversal_blocked() {
        let s   = SiteStore::new_test();
        s.create_service("ffff0000aaaa1111bbbb", "s", "00").await.unwrap();
        let p   = s.resolve("ffff0000aaaa1111bbbb", "/../../../etc/passwd");
        let www = s.www_dir("ffff0000aaaa1111bbbb");
        assert!(p.starts_with(&www), "resolved path escaped www_dir: {:?}", p);
    }

    #[tokio::test]
    async fn list_services() {
        let s = SiteStore::new_test();
        s.create_service("aaaa1111bbbb2222cccc", "a", "00").await.unwrap();
        s.create_service("bbbb2222cccc3333dddd", "b", "00").await.unwrap();
        assert_eq!(s.list_services().await.len(), 2);
    }
}
