# Building ΦNET release bundles

Tor-Browser-style distributables: one archive per platform containing the
browser GUI, the node daemon, the `phi` site tool, and helper scripts. Because
native binaries and the Tauri app must be compiled on each target OS, run the
bundler **on each platform you ship** (Linux, Windows, macOS) — same as Tor
Browser is built per-platform.

## Prerequisites (per build machine)

- Rust toolchain (`rustup`, stable)
- Node + npm (only if building the browser GUI)
- Tauri build deps for that OS (webview2 on Windows, webkit2gtk on Linux, Xcode
  CLT on macOS) — see https://tauri.app prerequisites
- `zip` (Windows/macOS archive) or `tar` (Linux/macOS)

## Build

```bash
# full bundle (browser GUI + tools) for the current platform:
./release/build-bundle.sh

# tools only (daemon + phi + helpers), no GUI toolchain needed:
./release/build-bundle.sh --no-gui
```

Output lands in `dist/phinet-bundle-<os>-<arch>.{tar.gz,zip}`.

## What the bundler does

1. Compiles `phinet-daemon`, `phi`, and `phinet-bwscanner` in release mode.
2. For the GUI: runs `phinet-browser/sync-sidecar.sh` to embed the freshly-built
   daemon as the browser's sidecar, then `npm run tauri build`, and collects the
   OS-native app artifacts (`.AppImage`/`.deb`, `.dmg`, `.msi`/`.exe`).
3. Stages `bin/`, the platform helper scripts (`.sh` or `.bat`), and the
   user-facing `README.md`.
4. Archives everything.

## Per-platform notes

- **Linux** → `.tar.gz`; GUI ships as `.AppImage` and/or `.deb`.
- **Windows** → `.zip`; GUI ships as `.msi`/`.exe`. Users open port 7700 inbound
  to run a relay.
- **macOS** → `.tar.gz`; GUI ships as `.dmg`. Unsigned builds need a
  right-click-open the first time (or notarize for distribution).

## Cross-compiling (advanced)

The daemon/CLI can cross-compile with the appropriate Rust target + linker
(e.g. `cross`), but the **Tauri GUI generally cannot be cross-compiled** — build
it natively on each OS. For CI, use a matrix of Linux/Windows/macOS runners each
invoking `build-bundle.sh`.
