// phinet-browser/src-tauri/src/daemon.rs
//! Auto-bootstrap: when the app starts, make sure a local ΦNET daemon is
//! running and connected to the network. If one is already listening on the
//! control port (the user ran it themselves), we leave it alone. Otherwise we
//! spawn one with the network's bootstrap + authority config, so opening the
//! app is all it takes to join the network.

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command},
    sync::Mutex,
    time::Duration,
};

// ── Network parameters (mirror the Android NodeConfig) ──────────────
const CTL_PORT: u16 = 7799;
const LINK_PORT: u16 = 7700;
const CONSENSUS_URL: &str = "http://phinetproject.com/phinet/consensus.json";
const BOOTSTRAP: &[&str] = &[
    "phinetproject.com:7700",
    "lobarcs.com:7700",
    "libraryofaletheia.com:7700",
];
const TRUSTED_AUTHORITIES: &[&str] = &[
    "af1aebff73f4bc25cb593481c78ca0b80f4c016237a1c896eff3656995f2cf3c", // lobarcs
    "7c30f0d91e8cb9263d13425e662f646fe50beaebceb84e1f3cc0fa525a6dc512", // libraryofaletheia
    "901e2740560270bb128b5c4d0cb8666a2cc525f87a9b75fb31bc8d94f2332ce8", // phinetproject
];

/// Holds the spawned daemon so it's killed when the app exits.
#[derive(Default)]
pub struct DaemonGuard(pub Mutex<Option<Child>>);

fn ctl_is_up() -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{CTL_PORT}").parse().unwrap(),
        Duration::from_millis(400),
    )
    .is_ok()
}

/// Locate the phinet-daemon binary. Order:
///   1. $PHINET_DAEMON (explicit override)
///   2. next to this app executable
///   3. `phinet-daemon` on PATH (resolved by the OS when we spawn by name)
fn find_daemon() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PHINET_DAEMON") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let name = if cfg!(windows) { "phinet-daemon.exe" } else { "phinet-daemon" };
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    // Fall back to bare name; Command will resolve it via PATH.
    Some(PathBuf::from(if cfg!(windows) { "phinet-daemon.exe" } else { "phinet-daemon" }))
}

/// Ensure a daemon is running. Returns a short status string for logging.
pub fn ensure_running(guard: &DaemonGuard) -> String {
    if ctl_is_up() {
        return "daemon already running — attached".into();
    }
    let bin = match find_daemon() {
        Some(b) => b,
        None => return "phinet-daemon binary not found".into(),
    };

    // Data/identity lives under the OS home so the node keeps a stable
    // identity across launches (the daemon persists $HOME/.phinet/identity.json).
    let mut cmd = Command::new(&bin);
    cmd.arg("--host").arg("127.0.0.1")
        .arg("--port").arg(LINK_PORT.to_string())
        .arg("--ctl-port").arg(CTL_PORT.to_string())
        .arg("--consensus-url").arg(CONSENSUS_URL)
        .arg("--consensus-http-version").arg("1.1");
    for b in BOOTSTRAP {
        cmd.arg("--bootstrap").arg(b);
    }
    for a in TRUSTED_AUTHORITIES {
        cmd.arg("--trusted-authority").arg(a);
    }
    // Detach stdio so the child keeps running independently.
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());

    match cmd.spawn() {
        Ok(child) => {
            *guard.0.lock().unwrap() = Some(child);
            // Give it a moment to open the control socket.
            for _ in 0..20 {
                if ctl_is_up() {
                    return format!("spawned daemon ({})", bin.display());
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            "daemon spawned; still starting up".into()
        }
        Err(e) => format!("failed to spawn daemon ({}): {e}", bin.display()),
    }
}

/// Kill the daemon we spawned (no-op if we attached to an existing one).
pub fn shutdown(guard: &DaemonGuard) {
    if let Some(mut child) = guard.0.lock().unwrap().take() {
        let _ = child.kill();
    }
}

/// Tauri command: the frontend can call this to (re)check/kick the daemon.
#[tauri::command]
pub fn daemon_status(guard: tauri::State<DaemonGuard>) -> serde_json::Value {
    let up = ctl_is_up();
    if !up {
        let msg = ensure_running(guard.inner());
        return serde_json::json!({ "up": ctl_is_up(), "msg": msg });
    }
    serde_json::json!({ "up": true, "msg": "connected" })
}
