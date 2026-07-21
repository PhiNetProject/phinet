#!/usr/bin/env bash
# sync-sidecar.sh — place a built phinet-daemon into the Tauri sidecar slot
# for THIS platform, so `npm run tauri build` bundles it inside the app.
#
# Tauri's externalBin expects  src-tauri/binaries/phinet-daemon-<target-triple>
# (with .exe on Windows). Run this once per OS you build on, pointing at that
# OS's freshly-built daemon.
#
# Usage:  ./sync-sidecar.sh /path/to/phinet-daemon
set -euo pipefail

SRC="${1:?usage: ./sync-sidecar.sh <path-to-phinet-daemon>}"
[ -f "$SRC" ] || { echo "not found: $SRC" >&2; exit 1; }

# Host target triple, e.g. x86_64-unknown-linux-gnu / aarch64-apple-darwin /
# x86_64-pc-windows-msvc
TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
[ -n "$TRIPLE" ] || { echo "couldn't determine target triple (is rustc installed?)" >&2; exit 1; }

EXT=""
case "$TRIPLE" in *windows*) EXT=".exe";; esac

DEST_DIR="$(cd "$(dirname "$0")" && pwd)/src-tauri/binaries"
mkdir -p "$DEST_DIR"
DEST="$DEST_DIR/phinet-daemon-$TRIPLE$EXT"

cp "$SRC" "$DEST"
chmod +x "$DEST"
echo "sidecar installed:"
echo "  $DEST"
echo "Now: cd $(dirname "$0") && npm run tauri build"
