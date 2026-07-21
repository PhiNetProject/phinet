// phinet-bwscanner/src/main.rs
//!
//! # phinet-bwscanner
//!
//! CLI driver around the bandwidth-scanner library. Reads a
//! consensus, runs measurements, writes a signed authority vote.
//!
//! Operators run this on a schedule (cron, systemd-timer) every
//! ~hour. The output votes are then exchanged with other authorities
//! out-of-band and merged into the next consensus.
//!
//! ## Usage
//!
//! ```bash
//! # Generate a fresh authority identity
//! phinet-bwscanner gen-identity --out ~/.phinet/auth.json
//!
//! # Run a scan against a consensus, writing a signed vote
//! phinet-bwscanner scan \
//!     --identity ~/.phinet/auth.json \
//!     --consensus /var/phinet/consensus.json \
//!     --output /var/phinet/votes/vote-$(date +%s).json \
//!     --network-id phinet-mainnet \
//!     --daemon-control 127.0.0.1:7799
//! ```
//!
//! In current form the scanner uses a **simulation transport** — it
//! doesn't drive real ΦNET circuit-build measurements. Wiring it
//! up to the daemon's control port for real measurements is one
//! integration step away (the trait is stable; just need a
//! `DaemonMeasurementTransport` implementation that talks to the
//! daemon over JSON-RPC). The scanner pipeline itself, vote
//! signing, and median aggregation are all production-ready.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use phinet_bwscanner::{
    BoxFuture, MeasurementTransport, RelayMeasurement, ScanConfig, Scanner,
};
use phinet_core::{
    directory::{ConsensusDocument, DirectoryAuthority, PeerEntry},
    hs_identity::HsIdentity,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "phinet-bwscanner",
          version = "0.2.0-srv-quantized",
          about = "Bandwidth scanner producing signed authority votes")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new directory-authority identity (long-term Ed25519).
    /// The resulting file is the root of trust for any consensus this
    /// authority signs. Keep it offline-secure.
    GenIdentity {
        #[arg(long)]
        out: PathBuf,
    },

    /// Build a genesis consensus by asking the local daemon for its own
    /// identity and its connected peers, then writing them out as relay
    /// entries. This seeds the very first consensus (the scanner only
    /// *re-measures* relays already listed, so the first one must be
    /// authored). Feed the result to `scan --simulate` then `merge-votes`.
    GenGenesis {
        /// Local daemon control socket.
        #[arg(long, default_value = "127.0.0.1:7799")]
        daemon_control: String,
        /// This node's *public* hostname/IP to advertise for itself
        /// (the daemon binds 0.0.0.0 and doesn't know its own name).
        #[arg(long)]
        advertise_host: String,
        /// Network id to stamp into the genesis.
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,
        /// Where to write the genesis consensus JSON.
        #[arg(long)]
        out: PathBuf,
        /// Skip the reachability+identity probe and list ALL connected peers.
        /// Only for bootstrapping a brand-new network where relays aren't yet
        /// mutually reachable. Default (off) verifies each peer is a reachable
        /// relay answering with its advertised identity — excluding NAT'd
        /// clients and stale ghosts.
        #[arg(long, default_value_t = false)]
        no_verify: bool,
    },

    /// Run one full scan pass and write a signed vote.
    Scan {
        /// Path to the authority identity file (from gen-identity).
        #[arg(long)]
        identity: PathBuf,

        /// Path to the consensus document to scan against.
        #[arg(long)]
        consensus: PathBuf,

        /// Where to write the signed vote (JSON).
        #[arg(long)]
        output: PathBuf,

        /// Network identifier — must match the one in the consensus.
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,

        /// Number of measurement passes per relay (median is reported).
        #[arg(long, default_value = "3")]
        passes: u32,

        /// Per-relay measurement timeout in seconds.
        #[arg(long, default_value = "60")]
        timeout_secs: u64,

        /// How long the resulting vote/consensus stays valid, in seconds.
        /// The daemon rejects an expired consensus, so this is also how
        /// often you must refresh. Default 24h so a hand-built consensus
        /// doesn't lapse mid-setup; drop it lower once a refresh timer
        /// runs.
        #[arg(long, default_value = "86400")]
        vote_window_secs: u64,

        /// Use the simulation transport — generates random plausible
        /// bandwidth values instead of doing real measurements.
        /// Useful for testing the scanner pipeline end-to-end without
        /// a live network.
        #[arg(long)]
        simulate: bool,

        /// Control-port address of the phinet-daemon to use for
        /// real measurements. Ignored when --simulate is set.
        /// The daemon must already be connected to every relay
        /// being measured.
        #[arg(long, default_value = "127.0.0.1:7799")]
        daemon_control: String,
    },

    /// Print the public key of an authority identity. Operators
    /// publish this so clients can add it to their trusted-authority
    /// set.
    PubKey {
        #[arg(long)]
        identity: PathBuf,
    },

    /// Append this authority's signature to an existing consensus
    /// document (signing its canonical bytes). This is how a follower
    /// authority co-signs the leader's *exact* consensus without having
    /// to rebuild an identical one — avoiding the timing/randomness races
    /// of independent builds. No-op if we've already signed it.
    SignConsensus {
        /// This authority's identity (private signing key).
        #[arg(long)]
        identity: PathBuf,
        /// Network id (must match the consensus).
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,
        /// Consensus file to co-sign.
        #[arg(long = "in")]
        in_file: PathBuf,
        /// Where to write the co-signed consensus.
        #[arg(long)]
        out: PathBuf,
    },

    /// Combine several single-signature consensus documents (produced
    /// independently by each authority from the *same* vote set, so
    /// their canonical bytes match) into one multi-signature consensus.
    /// This is how a multi-authority net assembles the signed consensus
    /// unattended: each authority merges + signs locally and publishes
    /// its copy; a collector unions the signatures.
    CombineConsensus {
        /// Network id (must match every input).
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,
        /// Where to write the combined consensus.
        #[arg(long)]
        out: PathBuf,
        /// Input consensus files (each single-signature, same peers).
        inputs: Vec<PathBuf>,
    },

    /// Merge a set of votes from peer authorities into a signed
    /// consensus document. Each authority runs this independently
    /// after collecting votes; they should all produce byte-identical
    /// pre-signature canonical bytes (deterministic merge), so the
    /// signatures attached afterwards are interoperable.
    ///
    /// Usage:
    ///   phinet-bwscanner merge-votes \
    ///     --identity ~/.phinet/auth.json \
    ///     --network-id phinet-mainnet \
    ///     --output /var/phinet/consensus.json \
    ///     /var/phinet/votes/auth1.json \
    ///     /var/phinet/votes/auth2.json \
    ///     /var/phinet/votes/auth3.json
    ///
    /// The output document carries this authority's signature.
    /// Other authorities run the same command on their machines
    /// and the operator collects all the signed copies — any one
    /// of them that has ≥threshold valid sigs is publishable.
    MergeVotes {
        /// Path to this authority's identity file.
        #[arg(long)]
        identity: PathBuf,
        /// Network ID — must match what's in every vote.
        #[arg(long, default_value = "phinet-mainnet")]
        network_id: String,
        /// Path to write the signed consensus.
        #[arg(long)]
        output: PathBuf,
        /// Skip per-vote signature verification. Useful only for
        /// debugging — never use in production.
        #[arg(long)]
        skip_verify: bool,
        /// Last period's consensus, whose commitments this period's reveals
        /// are checked against.
        ///
        /// Defaults to `$HOME/.phinet/consensus.json`. Pass it explicitly if
        /// your publish step overwrites that file before merging — a merge
        /// that reads the consensus it is about to replace checks this
        /// period's reveals against this period's commitments, which never
        /// match, and silently produces no shared random value.
        #[arg(long)]
        prev_consensus: Option<PathBuf>,
        /// Vote JSON files (one per authority).
        votes: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("phinet_bwscanner=info"))
        )
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    match cli.cmd {
        Cmd::GenIdentity { out } => {
            let id = HsIdentity::generate();
            id.save(&out).with_context(|| format!("save identity to {}", out.display()))?;
            println!("Generated authority identity at {}", out.display());
            println!("Public key: {}", hex::encode(id.public_key()));
            println!("\nDistribute this public key to clients and other authorities.");
        }

        Cmd::PubKey { identity } => {
            let id = HsIdentity::load(&identity)
                .with_context(|| format!("load identity from {}", identity.display()))?;
            println!("{}", hex::encode(id.public_key()));
        }

        Cmd::Scan { identity, consensus, output, network_id, passes, timeout_secs, vote_window_secs, simulate, daemon_control } => {
            rt.block_on(async {
                run_scan(RunScanArgs {
                    identity,
                    consensus,
                    output,
                    network_id,
                    passes,
                    timeout_secs,
                    vote_window_secs,
                    simulate,
                    daemon_control,
                }).await
            })?;
        }

        Cmd::MergeVotes { identity, network_id, output, skip_verify, prev_consensus, votes } => {
            run_merge(MergeArgs {
                identity, network_id, output, skip_verify, prev_consensus, votes,
            })?;
        }

        Cmd::GenGenesis { daemon_control, advertise_host, network_id, out, no_verify } => {
            rt.block_on(run_gen_genesis(daemon_control, advertise_host, network_id, out, no_verify))?;
        }

        Cmd::CombineConsensus { network_id, out, inputs } => {
            run_combine(network_id, out, inputs)?;
        }

        Cmd::SignConsensus { identity, network_id, in_file, out } => {
            run_sign_consensus(identity, network_id, in_file, out)?;
        }
    }

    Ok(())
}

struct MergeArgs {
    identity:    PathBuf,
    network_id:  String,
    output:      PathBuf,
    skip_verify: bool,
    prev_consensus: Option<PathBuf>,
    votes:       Vec<PathBuf>,
}

/// Send one JSON request to the daemon control socket and return the
/// parsed response.
/// The daemon's control cookie, from its data directory.
///
/// The scanner must run as the same user as the daemon (and with the same
/// HOME), because that's the only thing that distinguishes it from any other
/// process on the box — which is the point of the cookie.
fn control_cookie() -> Option<String> {
    let path = phinet_core::store::identity_path().parent()?.join("control.cookie");
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

async fn ctl_request(addr: &str, req: serde_json::Value) -> Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    // The control socket is cookie-gated; without this every command comes
    // back "unauthorized".
    let mut req = req;
    match (req.as_object_mut(), control_cookie()) {
        (Some(obj), Some(c)) => { obj.insert("cookie".into(), serde_json::Value::String(c)); }
        (_, None) => anyhow::bail!(
            "no control cookie found at $HOME/.phinet/control.cookie — run this as the \
             same user as the daemon, with the same HOME (e.g. sudo -u phinet env \
             HOME=/var/lib/phinet ...)"),
        _ => {}
    }
    let stream = TcpStream::connect(addr).await
        .with_context(|| format!("connect daemon control {addr}"))?;
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    w.write_all(format!("{}\n", req).as_bytes()).await?;
    let _ = w.shutdown().await;
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let resp: serde_json::Value = serde_json::from_str(&line)
        .context("parse daemon response")?;
    if resp["ok"].as_bool() != Some(true) {
        anyhow::bail!("daemon error: {}", resp["error"].as_str().unwrap_or("unknown"));
    }
    Ok(resp)
}

/// Build a genesis consensus from the local daemon's own identity plus
/// its connected peers.
async fn run_gen_genesis(daemon_control: String, advertise_host: String,
                         network_id: String, out: PathBuf, no_verify: bool) -> Result<()> {
    use phinet_core::directory::{ConsensusDocument, PeerEntry};

    let me = ctl_request(&daemon_control, serde_json::json!({ "cmd": "whoami" })).await?;
    // Default: ask the daemon for peers it has verified are reachable relays
    // answering with their advertised identity (excludes NAT'd clients and
    // ghosts). `--no-verify` falls back to the raw peer list for bootstrapping.
    let peers_cmd = if no_verify { "peers" } else { "verified_relays" };
    if !no_verify {
        eprintln!("verifying peers are reachable relays (probing advertised addresses)…");
    }
    let peers = ctl_request(&daemon_control, serde_json::json!({ "cmd": peers_cmd })).await?;

    let self_node = me["node_id"].as_str().unwrap_or_default().to_string();
    let self_pub  = me["static_pub"].as_str().unwrap_or_default().to_string();
    if self_pub.is_empty() {
        anyhow::bail!("daemon whoami returned no static_pub — is the daemon on this build?");
    }
    // Self advertised port comes from the daemon's listen address.
    let self_port: u16 = me["listen"].as_str()
        .and_then(|l| l.rsplit(':').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(7700);

    let mut entries: Vec<PeerEntry> = Vec::new();
    let entry = |node_id: String, host: String, port: u16, static_pub: String, family: String|
        PeerEntry {
            node_id_hex: node_id, host, port, static_pub_hex: static_pub,
            flags: 0, bandwidth_kbs: 1000, exit_policy_summary: "default".into(),
            family,
        };
    // Families now come from signed descriptors, which relays publish
    // themselves and gossip onward. So this authority no longer has to be the
    // operator to know a relay's family — it reads what the relay signed.
    // That's the difference between `--family` working for everyone and
    // working only for people who run an authority.
    let descs: std::collections::HashMap<String, String> = me["descriptors"]
        .as_array().cloned().unwrap_or_default().iter()
        .filter_map(|d| Some((
            d["node_id"].as_str()?.to_string(),
            d["family"].as_str().unwrap_or_default().to_string(),
        )))
        .collect();
    let self_family = me["family"].as_str().unwrap_or_default().to_string();
    entries.push(entry(self_node.clone(), advertise_host, self_port, self_pub, self_family));

    for p in peers["peers"].as_array().cloned().unwrap_or_default() {
        let node_id = p["node_id"].as_str().unwrap_or_default().to_string();
        let host    = p["host"].as_str().unwrap_or_default().to_string();
        let port    = p["port"].as_u64().unwrap_or(7700) as u16;
        let sp      = p["static_pub"].as_str().unwrap_or_default().to_string();
        if node_id.is_empty() || sp.is_empty() {
            eprintln!("warning: skipping peer with missing node_id/static_pub ({host}:{port})");
            continue;
        }
        // A relay's own signed claim, if we've received its descriptor.
        let fam = descs.get(&node_id).cloned().unwrap_or_default();
        entries.push(entry(node_id, host, port, sp, fam));
    }
    entries.sort_by(|a, b| a.node_id_hex.cmp(&b.node_id_hex));
    entries.dedup_by(|a, b| a.node_id_hex == b.node_id_hex);

    let doc = ConsensusDocument {
        network_id,
        shared_random: String::new(),
        srv_commitments: Vec::new(),
        valid_after: 1,
        valid_until: 4_102_444_800, // year 2100; genesis timing is nominal
        peers: entries,
        signatures: Vec::new(),
    };
    let json = serde_json::to_string_pretty(&doc).context("serialize genesis")?;
    std::fs::write(&out, json).with_context(|| format!("write {}", out.display()))?;
    println!("Wrote genesis with {} relay(s) to {}", doc.peers.len(), out.display());
    println!("Next: run `scan --simulate --consensus {}` on each authority, then merge-votes.",
             out.display());
    Ok(())
}

/// Append this authority's signature to an existing consensus.
fn run_sign_consensus(identity: PathBuf, network_id: String,
                      in_file: PathBuf, out: PathBuf) -> Result<()> {
    use phinet_core::directory::{ConsensusDocument, DirectoryAuthority};
    let id = HsIdentity::load(&identity)
        .with_context(|| format!("load identity from {}", identity.display()))?;
    let auth = DirectoryAuthority::new(id, &network_id);

    let bytes = std::fs::read_to_string(&in_file)
        .with_context(|| format!("read {}", in_file.display()))?;
    let mut doc: ConsensusDocument = serde_json::from_str(&bytes)
        .with_context(|| format!("parse {}", in_file.display()))?;
    if doc.network_id != network_id {
        anyhow::bail!("{} has network_id={} (expected {})",
            in_file.display(), doc.network_id, network_id);
    }

    let me = auth.pub_hex();
    if doc.signatures.iter().any(|s| s.authority_pub_hex == me) {
        println!("already signed by this authority; nothing to do");
    } else {
        auth.sign_consensus(&mut doc); // appends our signature over the canonical
    }
    std::fs::write(&out, serde_json::to_string_pretty(&doc)?)
        .with_context(|| format!("write {}", out.display()))?;
    println!("Wrote {} with {} peer(s) and {} signature(s)",
             out.display(), doc.peers.len(), doc.signatures.len());
    Ok(())
}

/// Union the signatures of several single-signature consensus documents
/// that share identical canonical bytes (same peers, times, network).
fn run_combine(network_id: String, out: PathBuf, inputs: Vec<PathBuf>) -> Result<()> {
    use phinet_core::directory::{AuthoritySignature, ConsensusDocument};
    if inputs.is_empty() {
        anyhow::bail!("combine-consensus: provide at least one consensus file");
    }
    let mut base: Option<ConsensusDocument> = None;
    let mut sigs: Vec<AuthoritySignature> = Vec::new();

    for path in &inputs {
        let bytes = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let doc: ConsensusDocument = serde_json::from_str(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;
        if doc.network_id != network_id {
            anyhow::bail!("{} has network_id={} (expected {})",
                path.display(), doc.network_id, network_id);
        }
        // Compare canonical form (everything except signatures).
        let mut bare = doc.clone();
        bare.signatures.clear();
        match &base {
            None => base = Some(bare),
            Some(b) => {
                if serde_json::to_string(b)? != serde_json::to_string(&bare)? {
                    anyhow::bail!(
                        "{} differs from the first input (different vote set or \
                         timing) — re-run each authority's merge over the same \
                         votes before combining", path.display());
                }
            }
        }
        for s in doc.signatures {
            if !sigs.iter().any(|x| x.authority_pub_hex == s.authority_pub_hex) {
                sigs.push(s);
            }
        }
    }

    let mut doc = base.unwrap();
    doc.signatures = sigs;
    std::fs::write(&out, serde_json::to_string_pretty(&doc)?)
        .with_context(|| format!("write {}", out.display()))?;
    println!("Combined into {} with {} peer(s) and {} signature(s)",
             out.display(), doc.peers.len(), doc.signatures.len());
    Ok(())
}

fn run_merge(args: MergeArgs) -> Result<()> {
    use phinet_core::directory::{
        verify_vote, AuthorityVote, DirectoryAuthority,
    };

    if args.votes.is_empty() {
        anyhow::bail!("merge-votes: provide at least one vote file");
    }

    let id = HsIdentity::load(&args.identity)
        .with_context(|| format!("load identity from {}", args.identity.display()))?;
    let auth = DirectoryAuthority::new(id, &args.network_id);

    let mut votes: Vec<AuthorityVote> = Vec::with_capacity(args.votes.len());
    for path in &args.votes {
        let bytes = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let vote: AuthorityVote = serde_json::from_str(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;

        if !args.skip_verify {
            verify_vote(&vote)
                .map_err(|e| anyhow::anyhow!("vote {} self-verify failed: {:?}",
                    path.display(), e))?;
        }
        if vote.network_id != args.network_id {
            anyhow::bail!("vote {} has network_id={} but expected {}",
                path.display(), vote.network_id, args.network_id);
        }
        votes.push(vote);
    }

    tracing::info!("merging {} votes for network {}", votes.len(), args.network_id);

    // Last period's consensus holds the commitments this period's reveals are
    // checked against. Without it the reveals prove nothing, so we'd publish
    // no shared random value rather than one nobody vouched for.
    let prev_path = args.prev_consensus.clone().or_else(|| {
        phinet_core::store::identity_path().parent().map(|d| d.join("consensus.json"))
    });
    let prev: Option<ConsensusDocument> = prev_path.as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok());
    let period = phinet_bwscanner::current_period();

    // Guard against the self-clobber trap: if `prev` is *this* period's own
    // consensus rather than last period's, its commitments were made for
    // period+1, not for the reveals we're about to check (which are for
    // `period`). Merging against it silently produces no value — the reveals
    // can't match commitments made for a different period. This is what
    // happens when the publish step overwrites consensus.json before the
    // next period's merge reads it, then the merge is re-run.
    //
    // A consensus made in period P has valid_after within P. So prev is
    // usable only if its period is exactly period-1.
    let prev_ok = match &prev {
        Some(p) => {
            let prev_period = p.valid_after / phinet_core::hs_identity::EPOCH_SECS;
            if prev_period == period.saturating_sub(1) {
                true
            } else if prev_period >= period {
                tracing::error!(
                    "previous consensus at {} is from period {} but we are in \
                     period {} — its commitments are for the wrong period and no \
                     reveal can match them. This usually means the publish step \
                     overwrote consensus.json before this merge ran. Refusing to \
                     use it; snapshot last period's consensus before publishing.",
                    prev_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
                    prev_period, period);
                false
            } else {
                tracing::warn!(
                    "previous consensus is from period {} but we are in {} — a gap \
                     of {} period(s). Reveals for skipped periods can't be checked; \
                     no shared random value this period.",
                    prev_period, period, period - prev_period);
                false
            }
        }
        None => {
            tracing::warn!(
                "no previous consensus — no shared random value this period \
                 (expected on a first run).");
            false
        }
    };
    let prev = if prev_ok { prev } else { None };
    if let (Some(p), Some(path)) = (&prev, &prev_path) {
        tracing::info!("checking reveals against {} commitment(s) from {}",
                       p.srv_commitments.len(), path.display());
    }

    let mut consensus = phinet_core::directory::build_consensus_with_srv(
        &args.network_id, &votes, prev.as_ref(), period);
    if consensus.shared_random.is_empty() {
        tracing::warn!("no shared random value agreed this period ({} commitment(s) \
                        carried forward for next period)", consensus.srv_commitments.len());
    } else {
        tracing::info!("shared random value agreed: {}…",
                       &consensus.shared_random[..16.min(consensus.shared_random.len())]);
    }
    auth.sign_consensus(&mut consensus);

    tracing::info!("consensus has {} peers, {} signatures",
        consensus.peers.len(), consensus.signatures.len());

    let json = serde_json::to_string_pretty(&consensus)
        .context("serialize consensus")?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&args.output, json)
        .with_context(|| format!("write {}", args.output.display()))?;

    tracing::info!("wrote signed consensus to {}", args.output.display());
    println!("{}", hex::encode(phinet_core::directory::consensus_hash(&consensus)));
    Ok(())
}

struct RunScanArgs {
    identity: PathBuf,
    consensus: PathBuf,
    output: PathBuf,
    network_id: String,
    passes: u32,
    timeout_secs: u64,
    vote_window_secs: u64,
    simulate: bool,
    daemon_control: String,
}

async fn run_scan(args: RunScanArgs) -> Result<()> {
    let id = HsIdentity::load(&args.identity)
        .with_context(|| format!("load identity from {}", args.identity.display()))?;
    let auth = DirectoryAuthority::new(id, &args.network_id);

    let cons_bytes = std::fs::read_to_string(&args.consensus)
        .with_context(|| format!("read consensus from {}", args.consensus.display()))?;
    let consensus: ConsensusDocument = serde_json::from_str(&cons_bytes)
        .context("parse consensus JSON")?;

    if consensus.network_id != args.network_id {
        anyhow::bail!(
            "consensus network_id ({}) doesn't match --network-id ({})",
            consensus.network_id, args.network_id);
    }

    tracing::info!("scanning {} relays in network {}",
        consensus.peers.len(), consensus.network_id);

    let config = ScanConfig {
        passes: args.passes,
        per_relay_timeout: Duration::from_secs(args.timeout_secs),
        vote_window_secs: args.vote_window_secs,
        ..Default::default()
    };

    let transport: Box<dyn MeasurementTransport> = if args.simulate {
        tracing::warn!("using simulation transport — output is NOT real measurements");
        Box::new(SimulationTransport)
    } else {
        // Real-network mode: talk to a running phinet-daemon's
        // control port. The daemon must already be connected to
        // the relays we're measuring (see "scanner daemon"
        // discussion in OPERATING.md).
        let addr: std::net::SocketAddr = args.daemon_control.parse()
            .with_context(|| format!(
                "parse --daemon-control {}", args.daemon_control))?;
        tracing::info!("using daemon measurement transport at {}", addr);
        Box::new(DaemonMeasurementTransport::new(addr))
    };

    let scanner = Scanner::new(transport, config);
    let vote = scanner.run(&consensus.peers, &auth).await;

    // Verify before writing — defensive check that our own
    // signing produced a valid vote. If this fails, the
    // identity-load path is broken.
    phinet_core::directory::verify_vote(&vote)
        .context("our own vote failed self-verification")?;

    let json = serde_json::to_string_pretty(&vote).context("serialize vote")?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&args.output, json)
        .with_context(|| format!("write vote to {}", args.output.display()))?;

    tracing::info!("wrote signed vote to {}", args.output.display());
    let running = vote.peers.iter()
        .filter(|p| p.flags & phinet_core::directory::PeerFlags::RUNNING.bits() != 0)
        .count();
    tracing::info!("  {}/{} relays measured as RUNNING",
        running, vote.peers.len());

    Ok(())
}

/// Simulation transport: produces deterministic-but-plausible
/// bandwidth values based on the relay's node_id. Used for
/// pipeline testing without a live network.
///
/// Each relay's bandwidth is hash(node_id) % 5000 + 100 kBs, so
/// values range from 100 kBs to 5100 kBs. Stable across runs for
/// a given relay so consensus tests are reproducible.
struct SimulationTransport;

impl MeasurementTransport for SimulationTransport {
    fn measure<'a>(
        &'a self,
        relay: &'a PeerEntry,
        _config: &'a ScanConfig,
    ) -> BoxFuture<'a, RelayMeasurement> {
        Box::pin(async move {
            // Tiny artificial delay so timeouts can be tested if
            // someone really wants to. In real scans the per-relay
            // measurement takes seconds; we don't need to simulate
            // that exactly.
            tokio::time::sleep(Duration::from_millis(5)).await;

            // Hash the node_id to derive a stable bandwidth value
            let mut h: u64 = 0xcbf29ce484222325;
            for b in relay.node_id_hex.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            let bw_kbs = ((h % 5000) + 100) as u32;

            RelayMeasurement {
                node_id_hex: relay.node_id_hex.clone(),
                bw_kbs,
                rtt_ms: 50 + ((h % 100) as u32),
                success: true,
                error: None,
            }
        })
    }
}

/// Real-network measurement transport. Connects to a running
/// `phinet-daemon`'s control port (default 127.0.0.1:7799) and
/// invokes `bw_measure` for each relay, returning the daemon's
/// observed throughput.
///
/// The daemon must:
///   - Be already connected to the target relay (the bw_measure
///     command requires the target in its peer table)
///   - Have ≥1 other peer that can serve as a 2-hop helper
///
/// In a deployment, the authority operates a "scanner daemon" that
/// connects to every relay in the consensus and runs measurements.
/// This crate's responsibility ends at the control-port boundary;
/// the scanner daemon's bootstrap connectivity is operator concern.
struct DaemonMeasurementTransport {
    control_addr: std::net::SocketAddr,
}

impl DaemonMeasurementTransport {
    fn new(control_addr: std::net::SocketAddr) -> Self {
        Self { control_addr }
    }
}

impl MeasurementTransport for DaemonMeasurementTransport {
    fn measure<'a>(
        &'a self,
        relay: &'a phinet_core::directory::PeerEntry,
        config: &'a ScanConfig,
    ) -> BoxFuture<'a, RelayMeasurement> {
        Box::pin(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            use tokio::net::TcpStream;

            // Build the JSON-RPC request the daemon's handle_ctl expects.
            let req = serde_json::json!({
                "cmd":    "bw_measure",
                "hs_id":  relay.node_id_hex,
                "method": config.payload_bytes.to_string(),
            });
            let req_str = match serde_json::to_string(&req) {
                Ok(s) => s,
                Err(e) => return failed(&relay.node_id_hex,
                    format!("serialize req: {e}")),
            };

            // Connect, send, read line.
            let stream = match TcpStream::connect(self.control_addr).await {
                Ok(s) => s,
                Err(e) => return failed(&relay.node_id_hex,
                    format!("connect daemon ctl {}: {e}", self.control_addr)),
            };

            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);

            if let Err(e) = w.write_all(format!("{}\n", req_str).as_bytes()).await {
                return failed(&relay.node_id_hex, format!("write: {e}"));
            }
            // Best effort flush + half-close
            let _ = w.shutdown().await;

            let mut line = String::new();
            if let Err(e) = reader.read_line(&mut line).await {
                return failed(&relay.node_id_hex, format!("read: {e}"));
            }

            let resp: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => return failed(&relay.node_id_hex,
                    format!("parse resp: {e}")),
            };

            if resp["ok"].as_bool() != Some(true) {
                let err = resp["error"].as_str().unwrap_or("unknown");
                return failed(&relay.node_id_hex, format!("daemon: {err}"));
            }

            let bw_kbs = resp["bw_kbs"].as_u64().unwrap_or(0) as u32;
            let rtt_ms = resp["rtt_ms"].as_u64().unwrap_or(0) as u32;

            RelayMeasurement {
                node_id_hex: relay.node_id_hex.clone(),
                bw_kbs,
                rtt_ms,
                success: bw_kbs > 0,
                error: if bw_kbs == 0 {
                    Some("daemon reported 0 kbs".into())
                } else { None },
            }
        })
    }
}

fn failed(node_id_hex: &str, why: String) -> RelayMeasurement {
    RelayMeasurement {
        node_id_hex: node_id_hex.into(),
        bw_kbs: 0, rtt_ms: 0, success: false,
        error: Some(why),
    }
}
