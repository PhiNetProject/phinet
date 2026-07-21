#!/usr/bin/env bash
# run-relay.sh — start a ΦNET relay. A relay forwards encrypted traffic for
# others; the more independent relays exist, the stronger everyone's anonymity.
#
# Needs a machine that accepts inbound connections on the relay port (7700).
# Open that port in your firewall / router first.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DAEMON="$HERE/bin/phinet-daemon"

PORT="${PHINET_PORT:-7700}"
DATA="${PHINET_HOME:-$HOME/.phinet}"
mkdir -p "$DATA"

# The public bootstrap + directory authorities of the main network.
BOOTSTRAP=(phinetproject.com:7700 lobarcs.com:7700 libraryofaletheia.com:7700)
CONSENSUS_URL="http://phinetproject.com/phinet/consensus.json"
AUTHS=(
  af1aebff73f4bc25cb593481c78ca0b80f4c016237a1c896eff3656995f2cf3c
  7c30f0d91e8cb9263d13425e662f646fe50beaebceb84e1f3cc0fa525a6dc512
  901e2740560270bb128b5c4d0cb8666a2cc525f87a9b75fb31bc8d94f2332ce8
)

args=(--host 0.0.0.0 --port "$PORT"
      --identity "$DATA/.phinet/identity.json"
      --consensus-url "$CONSENSUS_URL" --consensus-http-version 1.1)
for b in "${BOOTSTRAP[@]}"; do args+=(--bootstrap "$b"); done
for a in "${AUTHS[@]}";     do args+=(--trusted-authority "$a"); done

echo "▸ starting ΦNET relay on port $PORT (data: $DATA)"
echo "  a stable, reachable relay is verified by the network before it enters"
echo "  the consensus — keep it online and give it a fixed address."
HOME="$DATA" exec "$DAEMON" "${args[@]}"
