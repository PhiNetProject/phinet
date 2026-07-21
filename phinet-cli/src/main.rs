// phinet-cli/src/main.rs
//! phi — ΦNET hidden service CLI

use anyhow::{bail, Context, Result};
use phinet_core::{
    hs_identity::HsIdentity,
    store::{hs_identity_path, identity_path, sites_dir, SiteStore},
};
use rand::{rngs::OsRng, RngCore};
use std::path::PathBuf;
use tokio::fs;

// ── Colour helpers ────────────────────────────────────────────────────

fn tty() -> bool { std::env::var("TERM").is_ok() }
fn green(s: &str) -> String { if tty() { format!("\x1b[32m{s}\x1b[0m") } else { s.into() } }
fn cyan(s:  &str) -> String { if tty() { format!("\x1b[36m{s}\x1b[0m") } else { s.into() } }
fn bold(s:  &str) -> String { if tty() { format!("\x1b[1m{s}\x1b[0m")  } else { s.into() } }
fn dim(s:   &str) -> String { if tty() { format!("\x1b[2m{s}\x1b[0m")  } else { s.into() } }
fn red(s:   &str) -> String { if tty() { format!("\x1b[31m{s}\x1b[0m") } else { s.into() } }

// ── Daemon control ────────────────────────────────────────────────────

/// The daemon's control cookie, read from its data directory. Anything that
/// can read this file can drive the node — which is the point: the boundary
/// is filesystem permissions (0600), not the fiction that localhost is
/// private. The CLI and daemon must therefore share $HOME.
fn control_cookie() -> Option<String> {
    let path = identity_path().parent()?.join("control.cookie");
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

async fn ctl(req: serde_json::Value) -> Option<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    // Attach the cookie to every request; the daemon rejects anything but
    // `ping` without it.
    let mut req = req;
    if let (Some(obj), Some(c)) = (req.as_object_mut(), control_cookie()) {
        obj.insert("cookie".into(), serde_json::Value::String(c));
    }
    let stream = TcpStream::connect("127.0.0.1:7799").await.ok()?;
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    wr.write_all(format!("{}\n", req).as_bytes()).await.ok()?;
    wr.flush().await.ok()?;
    serde_json::from_str(&lines.next_line().await.ok()??).ok()
}

fn daemon_online() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:7799".parse().unwrap(),
        std::time::Duration::from_millis(200),
    ).is_ok()
}

// ── ID resolution ─────────────────────────────────────────────────────

async fn resolve_id(store: &SiteStore, s: &str) -> Result<String> {
    let s = s.trim_end_matches(".phinet").to_lowercase();
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(s);
    }
    let svcs = store.list_services().await;
    let matches: Vec<_> = svcs.iter().filter(|m| {
        m.hs_id.starts_with(&s) || m.name.to_lowercase().contains(&s)
    }).collect();
    match matches.len() {
        0 => bail!("no service matching '{}'", s),
        1 => Ok(matches[0].hs_id.clone()),
        _ => bail!("ambiguous prefix '{}'", s),
    }
}

// ── Commands ──────────────────────────────────────────────────────────

async fn cmd_new(args: &[String]) -> Result<()> {
    let name  = args.first().context("Usage: phi new <name>")?;
    let store = SiteStore::new();

    // The hs_id MUST come from the same HsIdentity the daemon will load when
    // it registers this service (keyed by name at `hs_identity_path`).
    // Previously the CLI invented its own id, so the site directory and the
    // published descriptor referred to two different services: the descriptor
    // pointed at a keypair-derived id with no files, and the files sat under an
    // id nobody could resolve. Deriving from the identity keeps them identical.
    let id_path  = hs_identity_path(name);
    let identity = if id_path.exists() {
        HsIdentity::load(&id_path)
            .with_context(|| format!("unreadable HS identity at {}", id_path.display()))?
    } else {
        let id = HsIdentity::generate();
        id.save(&id_path)
            .with_context(|| format!("saving HS identity to {}", id_path.display()))?;
        id
    };
    let hs_id = identity.hs_id();
    store.create_service(&hs_id, name, &hex_rand(8)).await?;

    println!();
    println!("  {}  Hidden service created", green("✓"));
    println!();
    println!("  {}    {}", bold("Name"),    name);
    println!("  {}      {}", bold("ID"),    cyan(&hs_id));
    println!("  {} {}", bold("Address"),    cyan(&format!("{}.phinet", hs_id)));
    println!("  {}   {}", bold("Stored"),   dim(&sites_dir().join(&hs_id).display().to_string()));
    println!();

    if daemon_online() {
        println!("  Registering on live network…");
        if let Some(r) = ctl(serde_json::json!({"cmd":"hs_register","hs_id":hs_id,"name":name})).await {
            if r["ok"] == true { println!("  {}  Registered in DHT", green("✓")); }
        }
    } else {
        println!("  {}  Start daemon to publish on live network:", dim("ℹ"));
        println!("    phinet-daemon --port 7700");
    }
    println!();
    Ok(())
}

async fn cmd_init(args: &[String]) -> Result<()> {
    let name    = args.first().context("Usage: phi init <n> [dir]")?;
    let out_dir = args.get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(name.replace(' ', "-")));

    fs::create_dir_all(&out_dir).await?;



    let index = format!("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>{name}</title>\n<link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n<body>\n<header><nav>\n  <a href=\"/\" class=\"logo\">&#x2B21; {name}</a>\n  <div class=\"nav-links\"><a href=\"/\">Home</a><a href=\"/about.html\">About</a></div>\n</nav></header>\n<main>\n  <div class=\"hero\">\n    <div class=\"badge\">PHINET Hidden Service</div>\n    <h1>{name}</h1>\n    <p class=\"tagline\">Your anonymous home on PHINET</p>\n  </div>\n  <div class=\"card\">\n    <h2>Welcome</h2>\n    <p>Edit this page to make it your own. This site is hosted anonymously\n    on PHINET &mdash; no server knows your IP, no CA signed your certificate.</p>\n    <p>After editing, deploy with: <code>phi deploy &lt;hs_id&gt; {}/</code></p>\n  </div>\n</main>\n<footer><p>Hosted on PHINET &middot; anonymous &middot; encrypted &middot; no tracking</p></footer>\n<script src=\"/app.js\"></script>\n</body>\n</html>", out_dir.display());

    let css = "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}:root{--bg:#0a0a14;--surface:#12121e;--card:#17172a;--border:rgba(90,110,200,.18);--accent:#4a7ef0;--accent2:#7aa8ff;--text:#d8e4f8;--muted:#8898bb;--max-w:860px}body{font-family:Inter,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.7;min-height:100vh;display:flex;flex-direction:column}a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}header{background:rgba(10,10,20,.9);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}nav{max-width:var(--max-w);margin:0 auto;padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}.logo{font-weight:700;font-size:1.05rem;color:var(--accent2)}.nav-links{display:flex;gap:1.5rem}.nav-links a{color:var(--muted);font-size:.9rem;transition:color .15s}.nav-links a:hover{color:var(--text);text-decoration:none}main{flex:1;max-width:var(--max-w);width:100%;margin:0 auto;padding:3rem 2rem 4rem}.hero{text-align:center;padding:4rem 2rem 3rem}.badge{display:inline-block;background:rgba(74,126,240,.12);border:1px solid rgba(74,126,240,.3);color:var(--accent2);font-size:.72rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;padding:.3rem .9rem;border-radius:99px;margin-bottom:1.5rem}h1{font-size:clamp(2rem,6vw,3rem);font-weight:800;letter-spacing:-.02em;color:var(--accent2);margin-bottom:.5rem;line-height:1.15}.tagline{color:var(--muted);font-size:1.05rem;margin-bottom:1.5rem}.addr{display:inline-block;font-family:monospace;font-size:.75rem;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.5rem 1.1rem;color:var(--accent2);word-break:break-all;max-width:100%}.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;margin-bottom:2rem}.card h2{font-size:1.2rem;font-weight:700;color:var(--text);margin-bottom:.75rem}.card p{color:var(--muted);margin-bottom:.75rem}.card p:last-child{margin-bottom:0}section{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;margin-bottom:2rem}section h2{font-size:1.2rem;font-weight:700;color:var(--text);margin-bottom:.75rem}section p{color:var(--muted);margin-bottom:.75rem}section p:last-child{margin-bottom:0}code{font-family:monospace;background:rgba(74,126,240,.1);border:1px solid rgba(74,126,240,.2);border-radius:5px;padding:2px 7px;font-size:.85em;color:var(--accent2)}.features{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}.feature{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem 1rem;text-align:center;font-size:.8rem;color:var(--muted);line-height:1.4}.feature .icon{font-size:1.4rem;margin-bottom:.4rem}@media(max-width:600px){.features{grid-template-columns:repeat(2,1fr)}main{padding:2rem 1rem 3rem}nav{padding:.8rem 1rem}}footer{text-align:center;padding:1.5rem;border-top:1px solid var(--border);font-size:.78rem;color:var(--muted);font-family:monospace}";

    let js = "document.addEventListener('DOMContentLoaded',()=>{\n  const els=document.querySelectorAll('.hero,.card,.feature,section');\n  els.forEach((el,i)=>{\n    el.style.cssText='opacity:0;transform:translateY(16px);transition:opacity .4s ease,transform .4s ease';\n    setTimeout(()=>{el.style.opacity='1';el.style.transform='none';},80*i);\n  });\n});";

    fs::write(out_dir.join("index.html"), index.as_bytes()).await?;
    fs::write(out_dir.join("style.css"),  css.as_bytes()).await?;
    fs::write(out_dir.join("app.js"),     js.as_bytes()).await?;

    println!();
    println!("  {}  Starter site written to {}", green("✓"), bold(&out_dir.display().to_string()));
    println!();
    println!("  Files:  index.html  style.css  app.js");
    println!();
    println!("  Next:");
    println!("    phi new \"{}\"", name);
    println!("    # edit files");
    println!("    phi deploy <hs_id> {}/", out_dir.display());
    println!();
    Ok(())
}

async fn cmd_deploy(args: &[String]) -> Result<()> {
    let id_raw = args.first().context("Usage: phi deploy <hs_id> <dir>")?;
    let dir_s  = args.get(1).context("missing directory")?;
    let store  = SiteStore::new();
    let hs_id  = resolve_id(&store, id_raw).await?;
    let dir    = PathBuf::from(dir_s);
    if !dir.is_dir() { bail!("not a directory: {}", dir.display()); }
    store.get_service(&hs_id).await.context(format!("service not found: {}", hs_id))?;

    println!();
    println!("  Deploying {}  →  {}", bold(dir_s), cyan(&format!("{}.phinet", &hs_id[..16])));
    println!();

    let deployed = store.deploy_directory(&hs_id, &dir).await?;
    for p in &deployed {
        println!("  {}  {}", green("✓"), p);
    }
    println!();
    println!("  {}  {} files deployed", green("✓"), deployed.len());
    println!();
    println!("  Open in browser:  http://{}.phinet/", hs_id);
    println!();
    Ok(())
}

async fn cmd_put(args: &[String]) -> Result<()> {
    let id_raw = args.first().context("Usage: phi put <hs_id> <path> <file>")?;
    let path   = args.get(1).context("missing URL path")?;
    let file   = args.get(2).context("missing file")?;
    let store  = SiteStore::new();
    let hs_id  = resolve_id(&store, id_raw).await?;
    let url    = if path.starts_with('/') { path.clone() } else { format!("/{}", path) };
    let body   = fs::read(file).await.context(format!("cannot read {}", file))?;
    store.put_file(&hs_id, &url, &body).await?;
    println!("  {}  {} ({} B)", green("✓"), url, body.len());
    Ok(())
}

async fn cmd_list(_args: &[String]) -> Result<()> {
    let store = SiteStore::new();
    let svcs  = store.list_services().await;
    if svcs.is_empty() {
        println!("\n  No hidden services yet.\n  Create: phi new \"my-site\"\n");
        return Ok(());
    }
    println!();
    for s in &svcs {
        println!("  {}  {}  {}",
                 cyan(&format!("{}…{}", &s.hs_id[..12], &s.hs_id[36..])),
                 bold(&s.name),
                 dim(&format!("{}.phinet", &s.hs_id)));
    }
    println!("\n  {} service(s)\n", svcs.len());
    Ok(())
}

async fn cmd_info(args: &[String]) -> Result<()> {
    let id_raw = args.first().context("Usage: phi info <hs_id>")?;
    let store  = SiteStore::new();
    let hs_id  = resolve_id(&store, id_raw).await?;
    let meta   = store.get_service(&hs_id).await.context("service not found")?;
    let files  = store.list_files(&hs_id).await;
    println!();
    println!("  {}  ·  {}", bold(&meta.name), cyan(&format!("{}.phinet", hs_id)));
    println!("  {}", dim(&"─".repeat(60)));
    for f in &files { println!("    {}", f); }
    println!("\n  {} file(s)\n", files.len());
    Ok(())
}

async fn cmd_delete(args: &[String]) -> Result<()> {
    let id_raw = args.first().context("Usage: phi delete <hs_id>")?;
    let store  = SiteStore::new();
    let hs_id  = resolve_id(&store, id_raw).await?;
    let meta   = store.get_service(&hs_id).await.context("service not found")?;
    print!("  Delete '{}' ({})? [y/N] ", meta.name, &hs_id[..12]);
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim().to_lowercase() == "y" {
        store.delete_service(&hs_id).await?;
        println!("  {}  Deleted.", green("✓"));
    } else {
        println!("  Cancelled.");
    }
    Ok(())
}

async fn cmd_register(args: &[String]) -> Result<()> {
    let id_raw = args.first().context("Usage: phi register <hs_id>")?;
    let store  = SiteStore::new();
    let hs_id  = resolve_id(&store, id_raw).await?;
    let meta   = store.get_service(&hs_id).await.context("service not found")?;
    if !daemon_online() { bail!("daemon not running — start: phinet-daemon"); }
    let resp = ctl(serde_json::json!({"cmd":"hs_register","hs_id":hs_id,"name":meta.name}))
        .await.context("control socket error")?;
    if resp["ok"] == true {
        println!("  {}  Registered {}.phinet", green("✓"), &hs_id[..12]);
    } else {
        bail!("register failed: {:?}", resp["error"]);
    }
    Ok(())
}

async fn cmd_peers(_: &[String]) -> Result<()> {
    if !daemon_online() { bail!("daemon not running"); }
    let resp = ctl(serde_json::json!({"cmd":"peers"})).await.context("ctl error")?;
    println!("\n  {} peer(s)", resp["count"].as_u64().unwrap_or(0));
    if let Some(peers) = resp["peers"].as_array() {
        for p in peers {
            println!("    {}…  {}:{}", &p["node_id"].as_str().unwrap_or("?")[..12],
                     p["host"].as_str().unwrap_or("?"), p["port"].as_u64().unwrap_or(0));
        }
    }
    println!();
    Ok(())
}

async fn cmd_board_post(args: &[String]) -> Result<()> {
    let channel = args.first().context("Usage: phi board post <channel> <message>")?;
    let text    = args.get(1..).map(|a| a.join(" ")).filter(|s| !s.is_empty())
        .context("Usage: phi board post <channel> <message>")?;
    if !daemon_online() { bail!("daemon not running — start: phinet-daemon"); }
    let resp = ctl(serde_json::json!({"cmd":"board_post","channel":channel,"text":text}))
        .await.context("ctl error")?;
    if resp["ok"] == true {
        println!("  {}  Posted to #{}", green("✓"), channel);
    } else {
        bail!("post failed: {:?}", resp["error"]);
    }
    Ok(())
}

async fn cmd_board_read(args: &[String]) -> Result<()> {
    let channel = args.first().map(|s| s.as_str()).unwrap_or("general");
    if !daemon_online() { bail!("daemon not running — start: phinet-daemon"); }
    let resp = ctl(serde_json::json!({"cmd":"board_read","channel":channel}))
        .await.context("ctl error")?;
    let posts = resp["posts"].as_array().cloned().unwrap_or_default();
    println!();
    println!("  #{}", bold(channel));
    println!("  {}", dim(&"─".repeat(60)));
    if posts.is_empty() {
        println!("  {}", dim("No posts yet."));
    } else {
        for p in &posts {
            let ts   = p["ts"].as_u64().unwrap_or(0);
            let text = p["text"].as_str().unwrap_or("");
            let ep   = p["ephem_pub"].as_str().unwrap_or("?");
            let time = format_ts(ts);
            println!("  {}  {}  {}", dim(&time), dim(&format!("{}…", &ep[..8])), text);
        }
    }
    println!();
    println!("  {} message(s)", posts.len());
    println!();
    Ok(())
}

async fn cmd_board_channels(_: &[String]) -> Result<()> {
    if !daemon_online() { bail!("daemon not running — start: phinet-daemon"); }
    // Read a few common channels to discover active ones
    let channels = ["general", "announce", "random", "phinet"];
    println!();
    for ch in channels {
        let resp = ctl(serde_json::json!({"cmd":"board_read","channel":ch})).await;
        if let Some(r) = resp {
            let count = r["posts"].as_array().map(|a| a.len()).unwrap_or(0);
            if count > 0 {
                println!("  #{:<16}  {} message(s)", ch, count);
            }
        }
    }
    println!();
    Ok(())
}

fn format_ts(ts: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let diff = now.saturating_sub(ts);
    if diff < 60        { format!("{}s ago", diff) }
    else if diff < 3600 { format!("{}m ago", diff / 60) }
    else if diff < 86400{ format!("{}h ago", diff / 3600) }
    else                { format!("{}d ago", diff / 86400) }
}

async fn cmd_circuit_status(_: &[String]) -> Result<()> {
    if !daemon_online() { bail!("daemon not running"); }
    let resp = ctl(serde_json::json!({"cmd":"circuit_status"}))
        .await.context("ctl error")?;
    let origins = resp["origins"].as_u64().unwrap_or(0);
    let relays  = resp["relays"].as_u64().unwrap_or(0);
    println!();
    println!("  Circuits:");
    println!("    Originated (we built):       {}", origins);
    println!("    Relaying (others built):     {}", relays);
    println!();
    Ok(())
}

async fn cmd_circuit_build(args: &[String]) -> Result<()> {
    let path = args.first()
        .context("Usage: phi circuit build <node_id@host:port,node_id@host:port,...>")?
        .clone();
    if !daemon_online() { bail!("daemon not running"); }
    println!();
    println!("  Building circuit through:");
    for (i, hop) in path.split(',').enumerate() {
        let hop   = hop.trim();
        let label = match i { 0 => "guard", 1 => "middle", _ => "exit" };
        println!("    {}. {:<7}  {}", i + 1, label, hop);
    }
    println!();
    let resp = ctl(serde_json::json!({
        "cmd":  "build_circuit",
        "text": path,
    })).await.context("ctl error")?;
    if resp["ok"] == true {
        let cid = resp["circ_id"].as_u64().unwrap_or(0);
        println!("  {}  Circuit {} established", green("✓"), cid);
    } else {
        bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    println!();
    Ok(())
}

async fn cmd_status(_: &[String]) -> Result<()> {
    let store = SiteStore::new();
    let svcs  = store.list_services().await;
    println!();
    println!("  {} local service(s)", svcs.len());
    if daemon_online() {
        if let Some(r) = ctl(serde_json::json!({"cmd":"whoami"})).await {
            println!("  Daemon: {}", green("online"));
            println!("  Node:   {}…", &r["node_id"].as_str().unwrap_or("?")[..16]);
            println!("  Peers:  {}", r["peers"].as_u64().unwrap_or(0));
        }
    } else {
        println!("  Daemon: {}", red("offline"));
        println!("  Start:  phinet-daemon");
    }
    println!();
    Ok(())
}

// ── Vanguards subcommands ────────────────────────────────────────────

async fn cmd_vanguards_list(_args: &[String]) -> Result<()> {
    if !daemon_online() { bail!("daemon not running on 127.0.0.1:7799"); }
    let r = ctl(serde_json::json!({"cmd": "vanguards_list"})).await
        .ok_or_else(|| anyhow::anyhow!("daemon did not respond"))?;
    if r["ok"] != true {
        bail!("vanguards_list: {}", r["error"].as_str().unwrap_or("unknown"));
    }
    let entries = r["entries"].as_array().cloned().unwrap_or_default();
    let active  = r["active_count"].as_u64().unwrap_or(0);

    println!();
    if entries.is_empty() {
        println!("  {} no vanguards yet", dim("(empty)"));
        println!("  {}", dim("vanguards populate automatically on the first build_hs_circuit call"));
    } else {
        println!("  {}", bold(&format!("{} entries ({} active)", entries.len(), active)));
        println!();
        for e in &entries {
            let id    = e["node_id_hex"].as_str().unwrap_or("?");
            let host  = e["host"].as_str().unwrap_or("?");
            let port  = e["port"].as_u64().unwrap_or(0);
            let added = e["added_at"].as_u64().unwrap_or(0);
            let used  = e["last_used"].as_u64().unwrap_or(0);
            let unreach = e["unreachable_since"].as_u64().unwrap_or(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let age_h = (now.saturating_sub(added)) / 3600;
            let used_str = if used == 0 {
                dim("never used")
            } else {
                let h = (now.saturating_sub(used)) / 3600;
                dim(&format!("last used {}h ago", h))
            };
            let status = if unreach > 0 { red(" UNREACHABLE") } else { String::new() };
            println!("  {} {}:{}",
                cyan(&id[..16]), host, port);
            println!("    {} added {}h ago, {}{}",
                dim("•"), age_h, used_str, status);
        }
    }
    println!();
    Ok(())
}

async fn cmd_vanguards_forget(args: &[String]) -> Result<()> {
    let id = args.first()
        .context("Usage: phi vanguards forget <node_id_hex>")?;
    if !daemon_online() { bail!("daemon not running"); }
    let r = ctl(serde_json::json!({
        "cmd": "vanguards_forget",
        "node_id_hex": id,
    })).await.ok_or_else(|| anyhow::anyhow!("daemon did not respond"))?;
    if r["ok"] == true {
        println!("  {} marked {} unreachable", green("✓"), &id[..id.len().min(16)]);
        println!("  {}", dim("entry will be removed from the active set immediately;"));
        println!("  {}", dim("full removal happens after 24h anti-churn window"));
    } else {
        bail!("vanguards_forget: {}", r["error"].as_str().unwrap_or("unknown"));
    }
    Ok(())
}

async fn cmd_vanguards_clear(_args: &[String]) -> Result<()> {
    if !daemon_online() { bail!("daemon not running"); }
    let r = ctl(serde_json::json!({"cmd": "vanguards_clear"})).await
        .ok_or_else(|| anyhow::anyhow!("daemon did not respond"))?;
    if r["ok"] == true {
        let n = r["marked"].as_u64().unwrap_or(0);
        println!("  {} marked {} vanguard(s) unreachable", green("✓"), n);
        if n > 0 {
            println!("  {}", dim("entries persist for 24h (anti-churn) but won't be picked"));
            println!("  {}", dim("new vanguards will populate on next HS circuit build"));
        }
    } else {
        bail!("vanguards_clear: {}", r["error"].as_str().unwrap_or("unknown"));
    }
    Ok(())
}

// ── Hidden-service auth subcommands ──────────────────────────────────

async fn cmd_auth_gen_client(_args: &[String]) -> Result<()> {
    // Pure local key generation — doesn't need the daemon.
    // X25519 keypairs are independent of network state; we just
    // need an OS RNG. Falling back to in-process generation when
    // the daemon isn't running matches operator expectations
    // (you should be able to generate a client identity offline,
    // hand it to a friend, and have them run a node later).
    let (secret, public) = if daemon_online() {
        // Prefer the daemon path so the generated key shows up in
        // any audit logs the daemon keeps.
        let r = ctl(serde_json::json!({"cmd": "hs_auth_gen_client"})).await
            .ok_or_else(|| anyhow::anyhow!("daemon did not respond"))?;
        if r["ok"] != true {
            bail!("hs_auth_gen_client: {}", r["error"].as_str().unwrap_or("unknown"));
        }
        (r["secret_hex"].as_str().unwrap_or("").to_string(),
         r["public_hex"].as_str().unwrap_or("").to_string())
    } else {
        // Local fallback. Same primitives as the daemon would use.
        use phinet_core::x25519_dalek::{StaticSecret, PublicKey};
        let sec = StaticSecret::random_from_rng(OsRng);
        let pubk = PublicKey::from(&sec);
        (hex::encode(sec.to_bytes()), hex::encode(pubk.as_bytes()))
    };

    println!();
    println!("  {} client keypair generated", green("✓"));
    println!();
    println!("  {} {}", bold("Secret"), cyan(&secret));
    println!("    {}", dim("⚠ keep this private — anyone with the secret can reach services that authorized your public key"));
    println!();
    println!("  {} {}", bold("Public"), cyan(&public));
    println!("    {}", dim("share this with HS operators who should grant you access"));
    println!();
    println!("  {}", dim("HS operators add the public key to their authorized_clients list"));
    println!("  {}", dim("when publishing the descriptor, then anyone with the matching"));
    println!("  {}", dim("secret can decrypt and reach the hidden service."));
    println!();
    Ok(())
}

async fn cmd_auth_add_client(args: &[String]) -> Result<()> {
    let id_or_name = args.first()
        .context("Usage: phi auth add-client <hs_id> <client_pub_hex>")?;
    let pubk = args.get(1)
        .context("Usage: phi auth add-client <hs_id> <client_pub_hex>")?;
    let store = SiteStore::new();
    let hs_id = resolve_id(&store, id_or_name).await?;

    match store.add_authorized_client(&hs_id, pubk).await {
        Ok(true) => {
            println!();
            println!("  {} added authorized client", green("✓"));
            println!("    Service: {}", cyan(&hs_id));
            println!("    Client:  {}", cyan(pubk));
            let total = store.list_authorized_clients(&hs_id).await.len();
            println!("    {} authorized clients now", dim(&total.to_string()));
            println!();
            println!("  {} re-publish the descriptor with `phi register {}`",
                dim("→"), &hs_id[..hs_id.len().min(16)]);
            println!("    {} for the change to take effect on the network", dim(""));
            println!();
        }
        Ok(false) => {
            println!("  {} client already authorized; no change", dim("•"));
        }
        Err(e) => bail!("add_authorized_client: {}", e),
    }
    Ok(())
}

async fn cmd_auth_list_clients(args: &[String]) -> Result<()> {
    let id_or_name = args.first()
        .context("Usage: phi auth list-clients <hs_id>")?;
    let store = SiteStore::new();
    let hs_id = resolve_id(&store, id_or_name).await?;

    let clients = store.list_authorized_clients(&hs_id).await;
    println!();
    println!("  {} {}", bold("Service"), cyan(&hs_id));
    if clients.is_empty() {
        println!("  {} no authorized clients", dim("(empty)"));
        println!("  {}", dim("descriptor publishes as public — anyone can resolve"));
    } else {
        println!("  {}", bold(&format!("{} authorized client(s):", clients.len())));
        for (i, p) in clients.iter().enumerate() {
            println!("    {}. {}", i + 1, cyan(p));
        }
        println!();
        println!("  {}", dim("descriptor publishes with client-auth — only listed clients can resolve"));
    }
    println!();
    Ok(())
}

async fn cmd_auth_remove_client(args: &[String]) -> Result<()> {
    let id_or_name = args.first()
        .context("Usage: phi auth remove-client <hs_id> <client_pub_hex>")?;
    let pubk = args.get(1)
        .context("Usage: phi auth remove-client <hs_id> <client_pub_hex>")?;
    let store = SiteStore::new();
    let hs_id = resolve_id(&store, id_or_name).await?;

    match store.remove_authorized_client(&hs_id, pubk).await {
        Ok(true) => {
            println!();
            println!("  {} removed authorized client", green("✓"));
            println!("    Service: {}", cyan(&hs_id));
            println!("    Client:  {}", cyan(pubk));
            let total = store.list_authorized_clients(&hs_id).await.len();
            if total == 0 {
                println!("  {}", dim("→ descriptor will publish as public on next register"));
            } else {
                println!("  {} authorized clients remaining", dim(&total.to_string()));
            }
            println!();
        }
        Ok(false) => {
            println!("  {} client was not in the list; no change", dim("•"));
        }
        Err(e) => bail!("remove_authorized_client: {}", e),
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { usage(); return Ok(()); }
    match args[1].as_str() {
        "new"      => cmd_new(&args[2..]).await?,
        "init"     => cmd_init(&args[2..]).await?,
        "deploy"   => cmd_deploy(&args[2..]).await?,
        "put"      => cmd_put(&args[2..]).await?,
        "list"|"ls"             => cmd_list(&args[2..]).await?,
        "info"                  => cmd_info(&args[2..]).await?,
        "delete"|"rm"           => cmd_delete(&args[2..]).await?,
        "register"              => cmd_register(&args[2..]).await?,
        "peers"                 => cmd_peers(&args[2..]).await?,
        "status"                => cmd_status(&args[2..]).await?,
        "board"                 => {
            match args.get(2).map(|s| s.as_str()) {
                Some("post")     => cmd_board_post(&args[3..]).await?,
                Some("read")     => cmd_board_read(&args[3..]).await?,
                Some("channels") => cmd_board_channels(&args[3..]).await?,
                _ => { eprintln!("Usage: phi board post|read|channels"); }
            }
        }
        "circuit"               => {
            match args.get(2).map(|s| s.as_str()) {
                Some("status") => cmd_circuit_status(&args[3..]).await?,
                Some("build")  => cmd_circuit_build(&args[3..]).await?,
                _ => { eprintln!("Usage: phi circuit status|build"); }
            }
        }
        "vanguards" => {
            match args.get(2).map(|s| s.as_str()) {
                Some("list")   => cmd_vanguards_list(&args[3..]).await?,
                Some("forget") => cmd_vanguards_forget(&args[3..]).await?,
                Some("clear")  => cmd_vanguards_clear(&args[3..]).await?,
                _ => { eprintln!("Usage: phi vanguards list|forget <node_id_hex>|clear"); }
            }
        }
        "auth" => {
            match args.get(2).map(|s| s.as_str()) {
                Some("gen-client")    => cmd_auth_gen_client(&args[3..]).await?,
                Some("add-client")    => cmd_auth_add_client(&args[3..]).await?,
                Some("list-clients")  => cmd_auth_list_clients(&args[3..]).await?,
                Some("remove-client") => cmd_auth_remove_client(&args[3..]).await?,
                _ => { eprintln!("Usage: phi auth gen-client|add-client|list-clients|remove-client"); }
            }
        }
        "help"|"--help"|"-h" => usage(),
        other      => { eprintln!("Unknown command: {}\n", other); usage(); }
    }
    Ok(())
}

fn usage() {
    println!("\n  phi -- PHINET hidden service CLI\n\n  Sites:\n    phi new <n>                Create a hidden service\n    phi init <n> [dir]         Generate starter site files\n    phi deploy <hs_id> <dir>   Deploy a directory\n    phi put <hs_id> <url> <f>  Upload a single file\n    phi list                   List all services\n    phi info <hs_id>           Show service files\n    phi delete <hs_id>         Delete a service\n    phi register <hs_id>       Publish to live network\n\n  Board (anonymous messaging):\n    phi board post <ch> <msg>  Post to a channel\n    phi board read [ch]        Read a channel  [default: general]\n    phi board channels         Show channels with posts\n\n  Circuits (onion routing):\n    phi circuit status         Show origin/relay counts\n    phi circuit build <path>   Build a multi-hop circuit\n                               path = id@host:port,id@host:port,...\n\n  Vanguards (HS guard-discovery defense):\n    phi vanguards list                 Show layer-2 vanguard set\n    phi vanguards forget <node_id_hex> Mark one vanguard unreachable\n    phi vanguards clear                Mark all vanguards unreachable\n\n  HS client auth (private hidden services):\n    phi auth gen-client                Generate a client keypair\n    phi auth add-client <hs> <pub>     Authorize a client for a service\n    phi auth list-clients <hs>         Show authorized clients for a service\n    phi auth remove-client <hs> <pub>  Revoke a client's access\n\n  Network:\n    phi peers                  Show connected peers\n    phi status                 Show daemon status\n");
}

// ── Helpers ───────────────────────────────────────────────────────────

fn hex_rand(n: usize) -> String {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    hex::encode(v)
}
