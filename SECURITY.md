# Security

## Reporting a vulnerability

Please **don't** open a public issue for a security bug. ΦNET is used to hide
who is talking to whom; a public report is a working attack until it's fixed.

Report privately through GitHub's *Report a vulnerability* button (Security tab).
Include what you found, how to reproduce it, and what you think it lets an
attacker learn. You'll get an acknowledgement within a few days.

## Threat model, stated honestly

ΦNET aims to hide **metadata**: who is talking to whom, when, from where, and
how often. It does this with layered encryption, multi-hop circuits, a signed
consensus, sealed-sender messaging, and hidden services.

**What it does not currently protect against:**

- **A small network.** Anonymity is a function of how many *unrelated* people
  run relays. A network of a handful of relays run by one person protects you
  from nobody — that operator sees every hop. The protocol being correct and
  you being anonymous are different claims, and only the first is true today.
- **A global passive adversary.** Someone who can watch every link can
  correlate traffic by timing regardless of encryption. This is an unsolved
  problem for low-latency networks; Tor has it too.
- **Anything above the network.** If a hidden service asks for your name, or
  you log into an account, ΦNET can't help.

## What runs where, and who can talk to it

- **The control socket** (127.0.0.1:7799) can read messages, send as this node,
  and reveal its address. It requires the cookie from `.phinet/control.cookie`
  (mode 0600). Localhost is not a trust boundary — on Android any installed app
  can reach it, and on a desktop any local process can.
- **The com UI** (127.0.0.1:7801) validates `Host` and rejects cross-origin
  requests, so a web page you visit can't drive it.
- **`identity.json`** holds this node's private x25519 static key, and
  `hs_identity_*.json` hold hidden-service private keys. Whoever has them can
  impersonate the node or the site. They're mode 0600 and gitignored — don't
  commit them, don't copy them between machines.

## Known limitations

- Clearnet browsing in the ΦNET browser is a **direct connection** and is not
  anonymous. The address bar says so.
- Rust builds aren't bit-reproducible, so release checksums prove provenance
  (built in public CI from public source), not reproducibility.
