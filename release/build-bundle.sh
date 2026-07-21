#!/usr/bin/env bash
# build-bundle.sh — assemble a Tor-Browser-style ΦNET distributable for THIS
# platform: the browser (GUI), the node daemon, the `phi` site tool, and helper
# scripts to run a relay or publish a .phinet site. Run once per OS you ship on.
#
#   ./release/build-bundle.sh            # full bundle (browser + tools)
#   ./release/build-bundle.sh --no-gui   # tools only (daemon + phi + helpers)
#
# Output:  dist/phinet-bundle-<os>-<arch>[.tar.gz|.zip]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
NO_GUI=0; [ "${1:-}" = "--no-gui" ] && NO_GUI=1

# ── platform detection ──────────────────────────────────────────────
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
  Linux)  PLAT=linux;   EXE="";     ARCHIVE=tar.gz ;;
  Darwin) PLAT=macos;   EXE="";     ARCHIVE=tar.gz ;;
  MINGW*|MSYS*|CYGWIN*) PLAT=windows; EXE=".exe"; ARCHIVE=zip ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac
STAGE="dist/phinet-bundle-$PLAT-$ARCH"
echo "▸ building ΦNET bundle for $PLAT-$ARCH"

# ── 1. build the Rust binaries ──────────────────────────────────────
echo "▸ compiling daemon + phi + bwscanner (release)…"
cargo build --release -p phinet-daemon -p phinet-cli -p phinet-bwscanner

# ── 2. stage layout ─────────────────────────────────────────────────
rm -rf "$STAGE"; mkdir -p "$STAGE/bin"
cp "target/release/phinet-daemon$EXE"    "$STAGE/bin/"
cp "target/release/phi$EXE"              "$STAGE/bin/"
cp "target/release/phinet-bwscanner$EXE" "$STAGE/bin/"

# helper scripts (shell + windows batch)
if [ "$PLAT" = "windows" ]; then
  cp release/helpers/*.bat "$STAGE/"
else
  cp release/helpers/*.sh "$STAGE/"; chmod +x "$STAGE"/*.sh
fi
cp release/BUNDLE_README.md "$STAGE/README.md"

# ── 3. build + stage the browser GUI (optional) ─────────────────────
if [ "$NO_GUI" -eq 0 ]; then
  if command -v npm >/dev/null 2>&1; then
    echo "▸ building phinet-browser (Tauri)…"
    # bundle the freshly-built daemon as the browser's sidecar so the GUI
    # auto-spawns a node with no separate install
    ( cd phinet-browser && ./sync-sidecar.sh "$ROOT/target/release/phinet-daemon$EXE" \
        && npm install --silent && npm run tauri build )
    # collect the built app artifacts (location varies by OS/bundler)
    mkdir -p "$STAGE/browser"
    find phinet-browser/src-tauri/target/release/bundle -maxdepth 2 \
      \( -name "*.AppImage" -o -name "*.deb" -o -name "*.dmg" -o -name "*.msi" -o -name "*.exe" \) \
      -exec cp {} "$STAGE/browser/" \; 2>/dev/null || true
    echo "  browser artifacts → $STAGE/browser/"
  else
    echo "  ! npm not found — skipping GUI (use --no-gui to silence)."
  fi
fi

# ── 4. archive ──────────────────────────────────────────────────────
mkdir -p dist
if [ "$ARCHIVE" = "zip" ]; then
  ( cd dist && zip -rq "$(basename "$STAGE").zip" "$(basename "$STAGE")" )
  OUT="$STAGE.zip"
else
  tar -C dist -czf "$STAGE.tar.gz" "$(basename "$STAGE")"
  OUT="$STAGE.tar.gz"
fi

echo "✓ bundle ready: $OUT"
echo
echo "Contents:"
echo "  bin/phinet-daemon    the ΦNET node"
echo "  bin/phi              create + deploy .phinet sites"
echo "  bin/phinet-bwscanner directory-authority scanner (relay operators)"
echo "  run-relay.*          start a relay in one command"
echo "  create-site.*        publish a .phinet site in one command"
[ "$NO_GUI" -eq 0 ] && echo "  browser/             the ΦNET browser app"
