// phinet-bwscanner/src/lib.rs
//!
//! # Bandwidth scanner
//!
//! Measures the throughput of every relay in the consensus and
//! produces a signed [`AuthorityVote`] containing the observed
//! bandwidths. Authorities run this binary on a schedule (every
//! ~hour) and feed votes into the consensus-building pipeline.
//!
//! ## How measurements work
//!
//! For each candidate relay R:
//!   1. Build a 2-hop circuit through R as the first hop.
//!   2. Open a stream to a measurement endpoint that emits a
//!      known-size payload.
//!   3. Time the byte arrival rate, record `bw_kbs`.
//!
//! ## Why measurements are third-party attestations
//!
//! Relays can lie about their capacity. Scanners produce
//! attestations from a *third party* (the authority running the
//! scanner) so the consensus doesn't depend on relay self-reports.

use phinet_core::directory::{AuthorityVote, DirectoryAuthority, PeerEntry, PeerFlags};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Configuration for a scan run.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub payload_bytes: usize,
    pub per_relay_timeout: Duration,
    pub passes: u32,
    pub vote_window_secs: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            payload_bytes: 1024 * 1024,
            per_relay_timeout: Duration::from_secs(60),
            passes: 3,
            vote_window_secs: 3600,
        }
    }
}

/// Result of one relay measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayMeasurement {
    pub node_id_hex: String,
    /// Observed throughput in kilobytes/sec. 0 means failure.
    pub bw_kbs: u32,
    pub rtt_ms: u32,
    pub success: bool,
    pub error: Option<String>,
}

/// Boxed-future return type. Same pattern as `transport.rs` —
/// gives us trait-objects without an `async-trait` proc-macro dep.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for the actual transport layer that does the measurement.
pub trait MeasurementTransport: Send + Sync {
    fn measure<'a>(
        &'a self,
        relay: &'a PeerEntry,
        config: &'a ScanConfig,
    ) -> BoxFuture<'a, RelayMeasurement>;
}

/// The period the shared random protocol is on. Same clock as the hidden
/// service directory ring, since that's what consumes the value.
pub fn current_period() -> u64 { phinet_core::hs_identity::current_epoch() }

/// Where this authority keeps the value it has committed to but not yet
/// revealed.
fn srv_state_path() -> std::path::PathBuf {
    phinet_core::store::identity_path()
        .parent().map(|d| d.join("srv_pending.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("srv_pending.json"))
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct SrvPending {
    /// Period `next_value` is committed for — always the reveal period plus
    /// one.
    period: u64,
    /// The value committed for `period`, revealed once the clock reaches it.
    value: String,
    /// The value committed for the period *after* `period`. Kept so that the
    /// reveal of `value` and the commitment of the next value are separate
    /// facts, not two halves of one destructive step.
    #[serde(default)]
    next_value: String,
}

/// Produce this authority's `(commitment, reveal)` for a vote.
///
/// **Idempotent within a period.** Running it five times in period P reveals
/// the same value five times and commits the same next value — it does not
/// consume anything. The earlier version rolled the state forward on every
/// call, so a second vote in the same period revealed nothing and silently
/// discarded the value that matched this period's published commitment. That
/// turned "run the cycle twice" — an ordinary thing to do — into "lose the
/// shared random value for this period", with no error to show for it.
///
/// The state holds two values: the one to reveal now, and the one already
/// committed for next period. A run reveals the first and re-publishes the
/// commitment for the second. It only *advances* — turning next period's
/// value into this period's — when the clock has actually moved on.
fn srv_contribution(authority_pub_hex: &str, period: u64) -> (String, String) {
    use phinet_core::shared_random as srv;

    let path = srv_state_path();
    let mut st: SrvPending = std::fs::read_to_string(&path).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Advance the state to the current period, if the clock has moved since
    // the last run. This is the *only* place the state rolls forward, and it
    // rolls by whole periods — so re-running within a period is a no-op here.
    if period > st.period {
        // One period on: what we'd committed for `period` becomes the value
        // to reveal now. More than one period on: the reveal window we were
        // holding a value for has passed unused, so there's nothing to
        // reveal and we start fresh.
        if period == st.period + 1 && !st.next_value.is_empty() {
            st.value = st.next_value.clone();
        } else {
            st.value = String::new();
        }
        st.next_value = String::new();
        st.period = period;
    }

    // Reveal the value committed for this exact period, if we have one.
    let reveal = if st.period == period && !st.value.is_empty() {
        st.value.clone()
    } else {
        String::new()
    };

    // Commit to next period's value — reusing the one we already committed if
    // this isn't the first run in the period, so the published commitment
    // stays stable no matter how many times the cycle runs.
    if st.next_value.is_empty() {
        st.next_value = hex::encode(srv::fresh_contribution());
    }
    let next_bytes: [u8; 32] = hex::decode(&st.next_value).ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0u8; 32]);
    let commitment = srv::commit(authority_pub_hex, &next_bytes, period + 1);

    if let Ok(j) = serde_json::to_string_pretty(&st) {
        let _ = std::fs::write(&path, j);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Anyone who reads this before the reveal knows the value early,
            // which is exactly the advantage the protocol denies everyone.
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    (commitment, reveal)
}

pub struct Scanner {
    transport: Box<dyn MeasurementTransport>,
    config: ScanConfig,
}

impl Scanner {
    pub fn new(transport: Box<dyn MeasurementTransport>, config: ScanConfig) -> Self {
        Self { transport, config }
    }

    pub async fn run(
        &self,
        relays: &[PeerEntry],
        authority: &DirectoryAuthority,
    ) -> AuthorityVote {
        let measurements = self.measure_all(relays).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Quantize validity to the epoch boundary rather than using the raw
        // clock. Every authority merges independently, seconds apart, and
        // combine requires the merged consensuses to be byte-identical apart
        // from signatures. A raw `now` differs per box and combine rejects
        // the set; the epoch boundary is a value all three compute
        // identically from the same clock, so their consensuses line up. It
        // also matches the period the shared-random value and HSDir ring are
        // keyed to — validity and SRV then advance together instead of
        // drifting.
        let epoch = phinet_core::hs_identity::EPOCH_SECS;
        let valid_after = (now / epoch) * epoch;
        let valid_until = valid_after + epoch + self.config.vote_window_secs;

        let mut peers: Vec<PeerEntry> = relays.iter().map(|p| {
            let m = measurements.get(&p.node_id_hex);
            let measured_bw = m.map(|m| m.bw_kbs).unwrap_or(0);

            // A reachable, measured relay *earns* its flags. Previously this
            // only toggled RUNNING, so a consensus that had degraded to
            // RUNNING-only stayed that way forever (the vote scans the served
            // consensus, re-adds only RUNNING, and re-emits the minimal set) —
            // leaving no GUARD/EXIT-eligible relay and breaking circuit build.
            let mut flags = PeerFlags::from_bits_truncate(p.flags);
            match m {
                Some(m) if m.success => {
                    // Reachable with a real bandwidth measurement → grant the
                    // core relay flags. EXIT is granted too: in this network
                    // every operator relay is willing to serve as an exit.
                    flags |= PeerFlags::RUNNING | PeerFlags::VALID
                           | PeerFlags::STABLE  | PeerFlags::FAST
                           | PeerFlags::GUARD   | PeerFlags::EXIT;
                }
                _ => {
                    // Unreachable → not RUNNING, and not usable as a hop.
                    flags.remove(PeerFlags::RUNNING);
                    flags.remove(PeerFlags::GUARD);
                    flags.remove(PeerFlags::EXIT);
                }
            }

            PeerEntry {
                node_id_hex:    p.node_id_hex.clone(),
                host:           p.host.clone(),
                port:           p.port,
                static_pub_hex: p.static_pub_hex.clone(),
                flags:          flags.bits(),
                bandwidth_kbs:  measured_bw,
                exit_policy_summary: p.exit_policy_summary.clone(),
                // Carried through from what the relay reports about itself.
                family:         p.family.clone(),
            }
        }).collect();

        peers.sort_by(|a, b| a.node_id_hex.cmp(&b.node_id_hex));

        // Contribute to the shared random value: reveal the value we
        // committed to last period, and commit to one for next period.
        //
        // The value has to outlive this process. A commitment we can't later
        // honour is worse than not committing — the reveal fails its check,
        // we're dropped from the computation, and to everyone else that looks
        // exactly like cheating.
        let (commit, reveal) = srv_contribution(&authority.pub_hex(), current_period());
        authority.vote_with_srv(valid_after, valid_until, peers, commit, reveal)
    }

    async fn measure_all(&self, relays: &[PeerEntry]) -> HashMap<String, RelayMeasurement> {
        let mut out = HashMap::with_capacity(relays.len());
        for relay in relays {
            let id = relay.node_id_hex.clone();
            tracing::info!("measuring {}…", &id[..16.min(id.len())]);
            let m = self.measure_one_with_passes(relay).await;
            tracing::info!("  → bw_kbs={} success={}", m.bw_kbs, m.success);
            out.insert(id, m);
        }
        out
    }

    async fn measure_one_with_passes(&self, relay: &PeerEntry) -> RelayMeasurement {
        let mut samples: Vec<RelayMeasurement> = Vec::with_capacity(self.config.passes as usize);
        for _pass in 0..self.config.passes {
            let m = tokio::time::timeout(
                self.config.per_relay_timeout,
                self.transport.measure(relay, &self.config),
            ).await.unwrap_or_else(|_| RelayMeasurement {
                node_id_hex: relay.node_id_hex.clone(),
                bw_kbs: 0, rtt_ms: 0, success: false,
                error: Some(format!("measurement timed out after {:?}",
                    self.config.per_relay_timeout)),
            });
            samples.push(m);
        }
        median_measurement(samples, &relay.node_id_hex)
    }
}

fn median_measurement(samples: Vec<RelayMeasurement>, node_id: &str) -> RelayMeasurement {
    if samples.is_empty() {
        return RelayMeasurement {
            node_id_hex: node_id.into(),
            bw_kbs: 0, rtt_ms: 0, success: false,
            error: Some("no samples".into()),
        };
    }
    if samples.iter().any(|s| !s.success) {
        let err = samples.iter().find_map(|s| s.error.clone());
        return RelayMeasurement {
            node_id_hex: node_id.into(),
            bw_kbs: 0, rtt_ms: 0, success: false,
            error: err.or_else(|| Some("at least one sample failed".into())),
        };
    }
    let mut sorted = samples;
    sorted.sort_by_key(|s| s.bw_kbs);
    let n = sorted.len();
    let mid = &sorted[n / 2];
    RelayMeasurement {
        node_id_hex: node_id.into(),
        bw_kbs: mid.bw_kbs,
        rtt_ms: mid.rtt_ms,
        success: true,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::collections::HashSet;

    struct MockTransport {
        observations: HashMap<String, u32>,
        unreachable: HashSet<String>,
        calls: Arc<AtomicUsize>,
    }

    impl MeasurementTransport for MockTransport {
        fn measure<'a>(
            &'a self,
            relay: &'a PeerEntry,
            _config: &'a ScanConfig,
        ) -> BoxFuture<'a, RelayMeasurement> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let id = &relay.node_id_hex;
                if self.unreachable.contains(id) {
                    return RelayMeasurement {
                        node_id_hex: id.clone(),
                        bw_kbs: 0, rtt_ms: 0, success: false,
                        error: Some("mock: unreachable".into()),
                    };
                }
                let bw = self.observations.get(id).copied().unwrap_or(0);
                RelayMeasurement {
                    node_id_hex: id.clone(),
                    bw_kbs: bw, rtt_ms: 50, success: true, error: None,
                }
            })
        }
    }

    fn peer(id: &str) -> PeerEntry {
        PeerEntry {
            node_id_hex: id.into(),
            host: "10.0.0.1".into(),
            port: 7700,
            static_pub_hex: format!("{:0<64}", id),
            flags: (PeerFlags::STABLE | PeerFlags::FAST | PeerFlags::RUNNING
                    | PeerFlags::VALID).bits(),
            bandwidth_kbs: 0,
            exit_policy_summary: String::new(),
            family: String::new(),
        }
    }

    #[tokio::test]
    async fn scan_produces_signed_vote_with_measured_bandwidths() {
        let mut obs = HashMap::new();
        obs.insert("aaaa".into(), 1500);
        obs.insert("bbbb".into(), 2500);
        let transport = MockTransport {
            observations: obs, unreachable: HashSet::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 1, ..Default::default()
        });
        let relays = vec![peer("aaaa"), peer("bbbb")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;

        phinet_core::directory::verify_vote(&vote).expect("vote must self-verify");
        let aaaa = vote.peers.iter().find(|p| p.node_id_hex == "aaaa").unwrap();
        let bbbb = vote.peers.iter().find(|p| p.node_id_hex == "bbbb").unwrap();
        assert_eq!(aaaa.bandwidth_kbs, 1500);
        assert_eq!(bbbb.bandwidth_kbs, 2500);
    }

    #[tokio::test]
    async fn unreachable_relays_get_zero_bw_and_lose_running_flag() {
        let mut obs = HashMap::new();
        obs.insert("aaaa".into(), 1000);
        let mut unreachable = HashSet::new();
        unreachable.insert("bbbb".into());
        let transport = MockTransport {
            observations: obs, unreachable,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 1, ..Default::default()
        });
        let relays = vec![peer("aaaa"), peer("bbbb")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;
        let bbbb = vote.peers.iter().find(|p| p.node_id_hex == "bbbb").unwrap();
        assert_eq!(bbbb.bandwidth_kbs, 0);
        assert!(bbbb.flags & PeerFlags::RUNNING.bits() == 0);
    }

    #[tokio::test]
    async fn vote_peers_sorted_canonically() {
        let mut obs = HashMap::new();
        obs.insert("ccc".into(), 100);
        obs.insert("aaa".into(), 100);
        obs.insert("bbb".into(), 100);
        let transport = MockTransport {
            observations: obs, unreachable: HashSet::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 1, ..Default::default()
        });
        let relays = vec![peer("ccc"), peer("aaa"), peer("bbb")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;
        let ids: Vec<&str> = vote.peers.iter()
            .map(|p| p.node_id_hex.as_str()).collect();
        assert_eq!(ids, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn median_returns_middle_of_three_successful_samples() {
        let samples = vec![
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 100, rtt_ms: 0, success: true, error: None },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 500, rtt_ms: 0, success: true, error: None },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 200, rtt_ms: 0, success: true, error: None },
        ];
        let m = median_measurement(samples, "x");
        assert!(m.success);
        assert_eq!(m.bw_kbs, 200);
    }

    #[test]
    fn median_fails_if_any_sample_failed() {
        let samples = vec![
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 100, rtt_ms: 0, success: true, error: None },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 0, rtt_ms: 0, success: false, error: Some("oops".into()) },
            RelayMeasurement { node_id_hex: "x".into(), bw_kbs: 200, rtt_ms: 0, success: true, error: None },
        ];
        let m = median_measurement(samples, "x");
        assert!(!m.success);
        assert_eq!(m.bw_kbs, 0);
    }

    #[test]
    fn median_of_empty_is_failure() {
        let m = median_measurement(vec![], "x");
        assert!(!m.success);
    }

    #[tokio::test]
    async fn passes_call_transport_n_times() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut obs = HashMap::new();
        obs.insert("aaaa".into(), 1000);
        let transport = MockTransport {
            observations: obs, unreachable: HashSet::new(),
            calls: calls.clone(),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig {
            passes: 5, ..Default::default()
        });
        let relays = vec![peer("aaaa")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let _vote = scanner.run(&relays, &auth).await;
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn timeout_yields_failed_measurement() {
        struct SlowTransport;
        impl MeasurementTransport for SlowTransport {
            fn measure<'a>(
                &'a self,
                relay: &'a PeerEntry,
                _config: &'a ScanConfig,
            ) -> BoxFuture<'a, RelayMeasurement> {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    RelayMeasurement {
                        node_id_hex: relay.node_id_hex.clone(),
                        bw_kbs: 9999, rtt_ms: 0, success: true, error: None,
                    }
                })
            }
        }
        let scanner = Scanner::new(Box::new(SlowTransport), ScanConfig {
            passes: 1,
            per_relay_timeout: Duration::from_millis(50),
            ..Default::default()
        });
        let relays = vec![peer("aaaa")];
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&relays, &auth).await;
        let p = vote.peers.iter().find(|p| p.node_id_hex == "aaaa").unwrap();
        assert_eq!(p.bandwidth_kbs, 0);
    }

    #[tokio::test]
    async fn empty_relay_list_produces_empty_vote() {
        let transport = MockTransport {
            observations: HashMap::new(),
            unreachable: HashSet::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let scanner = Scanner::new(Box::new(transport), ScanConfig::default());
        let auth = DirectoryAuthority::generate("phinet-test");
        let vote = scanner.run(&[], &auth).await;
        assert!(vote.peers.is_empty());
        phinet_core::directory::verify_vote(&vote).expect("empty vote must verify");
    }
}

#[cfg(test)]
mod srv_idempotency_tests {
    use super::*;
    use phinet_core::shared_random as srv;

    // Drive srv_contribution against a temp state file, simulating the clock.
    fn run(dir: &std::path::Path, auth: &str, period: u64) -> (String, String) {
        // srv_state_path() derives from identity_path(); point HOME at dir.
        std::env::set_var("HOME", dir);
        srv_contribution(auth, period)
    }

    #[test]
    fn revealing_is_idempotent_within_a_period() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".phinet")).unwrap();
        let auth = "aa".repeat(32);

        // Period 100: commit only, nothing to reveal.
        let (c100_a, r100) = run(dir.path(), &auth, 100);
        assert!(r100.is_empty(), "nothing committed for 100 yet");
        // Re-run in 100: same commitment, still no reveal.
        let (c100_b, _) = run(dir.path(), &auth, 100);
        assert_eq!(c100_a, c100_b, "commitment must be stable across re-runs");

        // Period 101: reveal what was committed for 101.
        let (_, r101_a) = run(dir.path(), &auth, 101);
        assert!(!r101_a.is_empty(), "must reveal the value committed for 101");
        // The reveal must verify against the commitment published in 100.
        let val: [u8; 32] = hex::decode(&r101_a).unwrap().try_into().unwrap();
        assert!(srv::check_reveal(&auth, &val, 101, &c100_a),
                "revealed value must match the commitment made for it");

        // Re-run in 101 (the exact bug that lost tonight's value): must reveal
        // the SAME value, not blank it.
        let (_, r101_b) = run(dir.path(), &auth, 101);
        assert_eq!(r101_a, r101_b,
                   "running the cycle twice in a period must not consume the reveal");
    }

    #[test]
    fn a_skipped_period_does_not_reveal_a_stale_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".phinet")).unwrap();
        let auth = "bb".repeat(32);
        run(dir.path(), &auth, 100);            // commit for 101
        // Jump straight to 103 — the 101 reveal window passed unused.
        let (_, r) = run(dir.path(), &auth, 103);
        assert!(r.is_empty(), "a value committed for 101 must not be revealed in 103");
    }
}
