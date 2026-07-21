#!/usr/bin/env bash
# create-site.sh — publish a .phinet hidden-service site.
#
#   ./create-site.sh <name> <folder>
#
# Example:
#   ./create-site.sh myblog ./my-site-files
#
# Requires a running local node (the browser app runs one automatically, or
# start ./run-relay.sh, or run bin/phinet-daemon yourself). The node needs a
# working circuit to publish the descriptor, so give it ~20s after startup.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PHI="$HERE/bin/phi"

NAME="${1:-}"; DIR="${2:-}"
if [ -z "$NAME" ] || [ -z "$DIR" ]; then
  echo "usage: $0 <name> <folder-with-index.html>" >&2; exit 1
fi
[ -d "$DIR" ] || { echo "not a folder: $DIR" >&2; exit 1; }
[ -f "$DIR/index.html" ] || echo "  ! note: no index.html in $DIR — '/' will 404"

# Use the same data dir as the local node so CLI + daemon share one store.
export HOME="${PHINET_HOME:-$HOME/.phinet}"; mkdir -p "$HOME"

echo "▸ creating hidden service '$NAME'…"
OUT="$("$PHI" new "$NAME")"; echo "$OUT"
HS_ID="$(printf '%s\n' "$OUT" | grep -oE '[0-9a-f]{40}' | head -1)"
[ -n "$HS_ID" ] || { echo "couldn't parse hs_id from 'phi new' output" >&2; exit 1; }

echo "▸ deploying $DIR → $HS_ID.phinet"
"$PHI" deploy "$HS_ID" "$DIR"

echo
echo "✓ your site is live at:"
echo "    $HS_ID.phinet"
echo "  open it in the ΦNET browser. Keep this node online so the site stays"
echo "  reachable — it republishes its descriptor periodically."
