# ΦNET

A metadata-private overlay network. This bundle contains everything you need to
browse `.phinet` sites, publish your own, and help run the network — no install,
no clearnet account, no tracking.

## What's in here

```
browser/            The ΦNET browser (GUI). Launches a node automatically.
bin/phinet-daemon   The node — joins the network, builds anonymous circuits.
bin/phi             Create and deploy .phinet hidden-service sites.
bin/phinet-bwscanner Directory-authority scanner (only relay/authority operators need this).
run-relay.*         Start a relay in one command.
create-site.*       Publish a .phinet site in one command.
```

## Just want to browse?

Open the app in `browser/`. It starts its own node in the background and
connects to the network. Type a `.phinet` address and go. That's it.

Clearnet sites open in a normal web window — note that **clearnet traffic is a
direct connection, not routed through ΦNET.** Only `.phinet` sites travel the
anonymous network.

## Publish a .phinet site

1. Put your site in a folder with an `index.html`.
2. Make sure a node is running (the browser app runs one; or run `./run-relay.sh`).
3. Publish:

   ```
   ./create-site.sh myblog ./my-site-folder     # Linux/macOS
   create-site.bat  myblog  .\my-site-folder     # Windows
   ```

   It prints your `<id>.phinet` address. Keep the node online so the site stays
   reachable.

## Run a relay (help the network)

Anonymity is a numbers game — every independent relay makes the whole network
harder to watch. If you have a machine with a reachable address, run one:

```
./run-relay.sh        # Linux/macOS
run-relay.bat         # Windows
```

Open port **7700** inbound in your firewall/router. A stable, reachable relay is
verified by the network before it joins the consensus, so give it a fixed
address and keep it online. The authorities measure it over time and clients
begin routing through it.

## Honest note on privacy

The mechanism here is real — signed consensus, diverse multi-hop circuits,
hidden services, sealed-sender messaging. But anonymity's *strength* depends on
many independent relay operators. A small network proves the protocol; it
doesn't yet hide you from a patient, well-resourced adversary. The most useful
thing you can do is run a relay, and ask others to.

## Data & privacy

Your node's identity and any sites you host live under `~/.phinet` (Linux/macOS)
or `%USERPROFILE%\.phinet` (Windows). Nothing is sent anywhere except encrypted
traffic through the network.
