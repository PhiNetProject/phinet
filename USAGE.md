# ΦNET Usage Guide

## Installation

```bash
# Build daemon + CLI (requires Rust 1.75+)
cargo build --release

# Binaries land at:
./target/release/phinet-daemon   # network node
./target/release/phi             # site & board CLI

# Browser (separate – requires Node 18+)
cd phinet-browser
npm install
cargo install tauri-cli --version "^2"
cargo tauri build
```

---

## Quick start: single machine (local only)

```bash
# Terminal 1 – start the daemon
phinet-daemon --port 7700

# Terminal 2 – create and visit a site
phi new "my-site"
# → prints a 40-hex hs_id, e.g. a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9

phi init "my-site" ./my-site/
# → writes index.html, style.css, app.js into ./my-site/

# Edit ./my-site/index.html …

phi deploy a3f8b2c1d4e5 ./my-site/
# → uploads all files to ~/.phinet/sites/a3f8…/www/

# Open the browser and navigate to:
#   http://a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9.phinet/
phinet-browser
```

---

## Example: two machines on the internet

### Machine A (VPS, open port 7700 inbound)

```bash
phinet-daemon --port 7700 --cert-bits 512
```

Output:
```
  ┌────────────────────────────────────────────────┐
  │              ΦNET Daemon v2                    │
  └────────────────────────────────────────────────┘

  Node ID:  3a7f2b8c1d4e5f6a…
  Cert:     512-bit  dr=7  mu=2  sg=1
  Listen:   0.0.0.0:7700
  Control:  127.0.0.1:7799
```

### Machine B (your laptop)

```bash
phinet-daemon --port 7700 --bootstrap 1.2.3.4:7700
```

After a moment, B connects to A and runs Kademlia peer discovery. Both nodes appear in each other's routing table.

```bash
phi peers
#   3a7f2b8c1d4e…  1.2.3.4:7700
phi status
#   Daemon:  online
#   Node:    b9c3d4e5f6a7b8c9…
#   Peers:   1
```

---

## Sites (hidden services)

### Create

```bash
phi new "my-blog"
```
```
  ✓  Hidden service created

  Name     my-blog
  ID       a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9
  Address  a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9.phinet
  Stored   /home/alice/.phinet/sites/a3f8b2c1…
```

### Generate starter files

```bash
phi init "my-blog" ./blog/
```
```
  ✓  Starter site written to blog/

  Files:  index.html  style.css  app.js
```

### Deploy

```bash
# Edit your files, then:
phi deploy a3f8b2c1 ./blog/
# (prefix matching — you don't need the full 40 chars)
```
```
  Deploying blog/ → a3f8b2c1d4e5f6a7.phinet

  ✓  /index.html
  ✓  /style.css
  ✓  /app.js
  ✓  /about.html

  ✓  4 files deployed
```

### Upload a single file

```bash
phi put a3f8b2c1 /data/feed.json ./feed.json
```

### Inspect

```bash
phi list
phi info a3f8b2c1
```

### Publish to the network

```bash
phi register a3f8b2c1
# → stores descriptor in DHT so other nodes can reach it
```

### Delete

```bash
phi delete a3f8b2c1
# prompts: Delete 'my-blog' (a3f8b2c1…)? [y/N]
```

---

## Anonymous message board

Posts are signed with **per-post ephemeral X25519 keys** — not linkable to your node identity or IP. Posts gossip peer-to-peer across the overlay. There is no server, no index, no moderation.

### Post

```bash
phi board post general "hello from the overlay"
phi board post announce "ΦNET v0.1 is live — share this address: a3f8…"
phi board post tech "does anyone know the dr constraint on 2048-bit certs?"
```

### Read

```bash
phi board read                # reads #general (default)
phi board read announce
phi board read tech
```
```
  #announce
  ────────────────────────────────────────────────────────────
  3m ago   a3f8b2c1…  ΦNET v0.1 is live — share this address: a3f8…
  1m ago   9c4d2e1f…  just joined, this is wild
```

Each post shows:
- Age (time since posted)
- First 8 hex chars of the ephemeral public key (unlinked to any identity)
- Message text

### Find active channels

```bash
phi board channels
```

Channel names are shared out-of-band (like HS addresses). Common conventions:
- `general` — open chat
- `announce` — service announcements
- `random` — anything goes
- `<hs_id>` — channel tied to a specific hidden service

---

## Browser

The `phinet-browser` Tauri app provides a Tor Browser-style interface:

```
┌──────────────────────────────────────────────────────────────┐
│ [←][→][↻]  [⬡ a3f8b2c1d4e5f6a7b8c9…phinet/]   [⬡][⊞]      │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   ⬡  MY-BLOG                                                │
│                                                              │
│   Anonymous · Encrypted · Decentralised                      │
│   a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9.phinet           │
│                                                              │
│   Welcome                                                    │
│   This site is hosted anonymously on ΦNET…                  │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ http://a3f8….phinet/   ⬡ ΦNET · anonymous   ⬡ live · 3 peers│
└──────────────────────────────────────────────────────────────┘
```

**Circuit panel** (click `⬡` or Ctrl+I):
```
  ┌─────────────────────────────────────┐
  │ ⬡  Circuit Information             │
  ├─────────────────────────────────────┤
  │ You          👤 This browser        │
  │              ↓                      │
  │ Guard Node   🛡 3a7f2b8c1d4e5f6a…  │
  │              ↓  🔒 E2E              │
  │ Middle Relay ⬡ b9c3d4e5f6a7b8c9…  │
  │              ↓  🔒 E2E              │
  │ Exit Relay   🚪 c1d2e3f4a5b6c7d8… │
  │              ↓  🔒 E2E              │
  │ Destination  ⬡ Hidden service      │
  └─────────────────────────────────────┘
  3 relays · ChaCha20-Poly1305 per hop
```

**Site manager** (click `⊞` or Ctrl+M):
- Browse, create, and manage local hidden services
- Upload files and deploy folders
- Register services on the live network

---

## Daemon flags

```
phinet-daemon [OPTIONS]

  --port <PORT>         Listen port for overlay peers     [default: 7700]
  --host <HOST>         Listen address                    [default: 0.0.0.0]
  --bootstrap HOST:PORT Bootstrap peer (repeat for multiple)
  --cert-bits <BITS>    Certificate size: 256|512|1024|2048 [default: 256]
  --ctl-port <PORT>     Control socket port               [default: 7799]
  --reset-identity      Regenerate node identity
  --high-security       5-hop circuits + max traffic padding
  --verbose             Debug logging
```

### Certificate sizes

| Bits | Gen time | PoW memory | Sybil cost |
|------|----------|------------|------------|
| 256  | ~0.3s    | 64 MiB     | Low (dev)  |
| 512  | ~1s      | 256 MiB    | Medium     |
| 1024 | ~8s      | 1 GiB      | High       |
| 2048 | ~60s     | 4 GiB      | Very high  |

Use 512+ for any real deployment. The Argon2id PoW is verified by every peer you connect to — higher bits means joining the network is computationally expensive, making Sybil attacks costly.

---

## Control socket (raw)

The daemon exposes a newline-delimited JSON RPC on `127.0.0.1:7799`.

```bash
# Ping
echo '{"cmd":"ping"}' | nc 127.0.0.1 7799
# → {"ok":true,"version":2}

# Node info
echo '{"cmd":"whoami"}' | nc 127.0.0.1 7799
# → {"ok":true,"node_id":"3a7f2b8c…","cert_bits":512,"peers":3,"dht_keys":12}

# Post to board
echo '{"cmd":"board_post","channel":"general","text":"hello"}' | nc 127.0.0.1 7799
# → {"ok":true,"posted":true}

# Read board
echo '{"cmd":"board_read","channel":"general"}' | nc 127.0.0.1 7799
# → {"ok":true,"posts":[{"msg_id":"…","channel":"general","text":"hello",…}]}

# Register a hidden service
echo '{"cmd":"hs_register","name":"my-blog"}' | nc 127.0.0.1 7799
# → {"ok":true,"hs_id":"a3f8b2c1…","name":"my-blog"}

# Fetch a page (hex-encoded body)
echo '{"cmd":"hs_fetch","hs_id":"a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9","path":"/"}' | nc 127.0.0.1 7799
# → {"ok":true,"status":200,"headers":{"Content-Type":"text/html"},"body_b64":"3c21…"}

# Peer list
echo '{"cmd":"peers"}' | nc 127.0.0.1 7799
# → {"ok":true,"count":3,"peers":[{"node_id":"…","host":"…","port":7700}]}
```

---

## File layout

```
~/.phinet/
  identity.json        Your node identity (cert + PoW solution)
  sites/
    <hs_id>/
      _meta.json       {name, hs_id, nonce_hex, created}
      www/
        index.html
        style.css
        ...
```

HS addresses are derived as:

```
hs_id = hex( BLAKE2b-256( J_bytes || nonce || name )[..20] )
```

They are **never indexed** anywhere. Share them out-of-band — the inability to enumerate addresses is a privacy guarantee.

---

## Security properties

| Property | Implementation |
|----------|----------------|
| Node identity | ΦNET v2 cert: n=2p, J-first construction, Miller-Rabin 40-witness |
| Peer admission | Argon2id PoW — memory-hard, scales with cert bit size |
| Key exchange | Hybrid X25519 + ML-KEM-1024 (post-quantum) |
| Session encryption | ChaCha20-Poly1305, per-direction AtomicU64 nonce counter |
| Onion routing | 3 hops (5 in --high-security), fixed 512-byte cells |
| Anti-tagging | AAD = "host:port" at each layer |
| Traffic analysis | Constant-rate 1 dummy cell/sec per peer |
| Guard pinning | /16 subnet diversity, stable guard set |
| HS anonymity | Intro points, PIR-style descriptor fetch |
| Intro-point DoS | Hashcash puzzle, auto-adjusting 12-28 bits |
| Post anonymity | Ephemeral X25519 key per board post, SHA-256 MAC |
| φ-rotation | Cert rotates every hour (same cluster_id, new n) |

---

## Limitations (current)

- **Board posts are in-memory only** — lost on daemon restart. Persistent storage planned.
- **BoardFetch** (pull history from peers) is implemented in the wire protocol but no client uses it yet; you only see posts that arrive while your node is running.
- **Rendezvous protocol** is stubbed — only local-store serving works end-to-end right now. Full Tor-style intro/rendezvous (where the HS and client build separate circuits to a third relay) is the next major piece.
- **Browser proxy** serves local `.phinet` sites correctly; remote HS fetching goes through the daemon control socket, which returns a 503 if the intro point isn't reachable yet.
- **ML-KEM** in the handshake is negotiated (empty string = X25519 only) but the full post-quantum upgrade path is implemented and passes the roundtrip test.
