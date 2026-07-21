# ΦNET Desktop (Tauri)

The ΦNET desktop app — **Com · Browser · Vault** in one window, the desktop
counterpart to the Android app. It's a thin UI over the same `phinet-daemon`
control socket, so it runs on Linux, Windows, and macOS with no cross-compile.

## Prerequisites

- **A running ΦNET daemon** on the same machine (it provides the network).
  Start your node first — the app talks to it on `127.0.0.1:7799` (ctl) and
  shows "daemon offline" until it's up.
- Rust toolchain, Node 18+, and the Tauri 2 system deps for your OS
  (see https://tauri.app for the per-OS webview/build packages).

## Run in development

```bash
cd phinet-browser
npm install
npm run tauri dev
```

## Build installers (all three OSes)

Build on each target OS (Tauri bundles per-platform):

```bash
npm install
npm run tauri build
# → src-tauri/target/release/bundle/  (.deb/.AppImage, .msi/.exe, .dmg/.app)
```

## What's inside

- **Com** — the existing end-to-end encrypted messenger (threads, groups,
  add-by-address), now with unsend wired to the daemon.
- **Browser** — a search homepage, open-web pages, and `.phinet` hidden sites
  fetched through the local node, plus a Tor-style circuit panel with
  "New identity."
- **Vault** — an encrypted store (links / notes / secrets / files) using
  **pure-Rust XChaCha20-Poly1305 + Argon2id** in the Tauri backend. The master
  key is derived from your passphrase and held only in memory while unlocked.
  Vault data lives under the OS app-data dir (`phinet-vault/`).


## Bundling the daemon (sidecar) for a distributable

The app spawns a local `phinet-daemon`. For a shippable build, bundle it inside
the app so users need nothing installed. It's wired as a Tauri **sidecar**
(`bundle.externalBin`), which places the daemon next to the app executable — where
the app already looks for it.

Per OS you build on:

```bash
# 1. build the daemon for THIS platform
cargo build --release -p phinet-daemon        # in the phinet-main workspace

# 2. drop it into the sidecar slot for this platform's target triple
cd phinet-browser
./sync-sidecar.sh /path/to/phinet-main/target/release/phinet-daemon

# 3. build the app — the daemon is now bundled inside it
npm run tauri build
```

`sync-sidecar.sh` names the file `binaries/phinet-daemon-<target-triple>` as Tauri
requires. Do this on each of Linux/macOS/Windows with that platform's daemon build.
In `npm run tauri dev` (no bundling), set `PHINET_DAEMON=/path/to/phinet-daemon`
or put it on `PATH` instead.

## Known limits (v1)

- **Open-web pages load in an iframe**, so sites that forbid framing
  (`X-Frame-Options`/`frame-ancestors`, e.g. Google) won't render. `.phinet`
  sites and framing-friendly sites work. A future version can swap to a real
  Tauri webview window to remove this limit.
- Vault file encryption is whole-file (fine for typical files; very large
  media would benefit from the chunked-streaming approach used elsewhere).
- **Auto-bootstrap:** on launch the app starts a local ΦNET daemon (bootstrapping
  to phinetproject.com + the backbone relays, trusting all three authorities) and
  stops it on exit. If a daemon is already listening on 127.0.0.1:7799, the app
  attaches to that one instead. The app finds the daemon binary via, in order:
  `$PHINET_DAEMON`, a `phinet-daemon` next to the app executable, or `phinet-daemon`
  on `PATH`. For a distributable build, bundle `phinet-daemon` beside the app (or as
  a Tauri sidecar).
