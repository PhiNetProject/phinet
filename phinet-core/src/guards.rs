// phinet-core/src/guards.rs
//! Persistent guard node selection.
//!
//! # Why this matters
//!
//! Without persistence, an attacker can force clients to cycle through
//! guards by keeping them offline. Eventually the client picks an
//! attacker-controlled guard, and at that point the attacker can
//! observe all entry traffic from that client. Tor calls this the
//! "first-hop attack" and solves it the same way we do: persist a
//! small set of guards (3-5) and stick with them for 60-120 days.
//!
//! # Storage
//!
//! `~/.phinet/guards.json` — atomically-replaced JSON array of entries:
//!
//! ```json
//! [
//!   {
//!     "node_id":          "ab12…",
//!     "host":             "1.2.3.4",
//!     "port":             7700,
//!     "first_seen":       1700000000,
//!     "last_tried":       1700003600,
//!     "last_connected":   1700003600,
//!     "unreachable_since": null,
//!     "confirmed":        true
//!   },
//!   ...
//! ]
//! ```
//!
//! # Semantics
//!
//! * We pick up to [`MAX_GUARDS`] guards. New guards are added only
//!   when existing guards are exhausted or expire.
//! * A guard is "confirmed" after the first successful connection.
//!   Before then it's tentative and can be replaced freely.
//! * A guard that fails to connect is marked `unreachable_since`. If
//!   that window stays open for [`GUARD_UNREACHABLE_BEFORE_DROP`],
//!   we drop it and pick a replacement.
//! * A guard older than [`GUARD_LIFETIME`] is retired even if healthy.
//!   This bounds the damage from a guard that's silently been
//!   compromised.
//!
//! # What this module is NOT
//!
//! This is just the data + persistence. The actual peer-connection
//! logic (picking a new guard, trying to connect, promoting on
//! success) lives in `node.rs` and consults `GuardManager` for state.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum simultaneous guards we maintain. 3 is the Tor default.
/// Never more than this or we become vulnerable to Sybil rotation.
pub const MAX_GUARDS: usize = 3;

/// Time in seconds before a guard is retired for age (60 days).
pub const GUARD_LIFETIME: u64 = 60 * 24 * 3600;

/// Time a guard can remain unreachable before we replace it (24h).
/// Short enough to recover from a dead guard, long enough that a
/// temporary network outage doesn't lose us our guards.
pub const GUARD_UNREACHABLE_BEFORE_DROP: u64 = 24 * 3600;

/// Minimum interval between retry attempts to an unreachable guard (5m).
pub const GUARD_RETRY_INTERVAL: u64 = 300;

// ── Entry ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardEntry {
    /// Hex-encoded 32-byte node_id.
    pub node_id: String,
    pub host:    String,
    pub port:    u16,
    /// First time we selected this peer as a candidate guard.
    pub first_seen: u64,
    /// Last time we attempted to connect (whether successful or not).
    pub last_tried: u64,
    /// Last time we successfully connected.
    pub last_connected: u64,
    /// Timestamp of the first failure in the current unreachable streak;
    /// `None` means the guard is currently reachable (or never tried).
    pub unreachable_since: Option<u64>,
    /// True after the first successful connection. Unconfirmed guards
    /// can be swapped out liberally.
    pub confirmed: bool,
}

impl GuardEntry {
    pub fn node_id_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.node_id)
            .map_err(|e| Error::Crypto(format!("guards: bad hex: {e}")))?;
        if v.len() != 32 {
            return Err(Error::Crypto(format!("guards: node_id is {} bytes, want 32", v.len())));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&v);
        Ok(id)
    }

    /// True if we should drop this guard from the set entirely.
    pub fn should_retire(&self, now: u64) -> bool {
        // Aged out
        if now.saturating_sub(self.first_seen) >= GUARD_LIFETIME {
            return true;
        }
        // Unreachable for too long
        if let Some(since) = self.unreachable_since {
            if now.saturating_sub(since) >= GUARD_UNREACHABLE_BEFORE_DROP {
                return true;
            }
        }
        false
    }

    /// True if we're willing to retry connecting to this guard right now.
    pub fn should_try(&self, now: u64) -> bool {
        if self.should_retire(now) { return false; }
        if self.unreachable_since.is_some() {
            // Rate-limit retries
            now.saturating_sub(self.last_tried) >= GUARD_RETRY_INTERVAL
        } else {
            true
        }
    }
}

// ── Manager ───────────────────────────────────────────────────────────

pub struct GuardManager {
    path:    PathBuf,
    entries: Mutex<Vec<GuardEntry>>,
}

impl GuardManager {
    /// Open or create the guard store at the given path. Missing file
    /// is treated as empty (no guards yet).
    pub fn open(path: PathBuf) -> Result<Self> {
        let entries = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => match serde_json::from_slice::<Vec<GuardEntry>>(&bytes) {
                    Ok(v) => v,
                    Err(_) => Vec::new(), // corrupted file — start fresh
                },
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    /// In-memory-only manager for tests.
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self {
            path: PathBuf::from("/tmp/phinet_test_guards_ignored.json"),
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Return the current list of guards (a snapshot).
    pub fn list(&self) -> Vec<GuardEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// True if this peer is currently in our guard set.
    pub fn is_guard(&self, node_id: &[u8; 32]) -> bool {
        let hex = hex::encode(node_id);
        self.entries.lock().unwrap().iter().any(|g| g.node_id == hex)
    }

    /// How many non-retired guards we currently have.
    pub fn active_count(&self) -> usize {
        let now = now_unix();
        self.entries.lock().unwrap()
            .iter()
            .filter(|g| !g.should_retire(now))
            .count()
    }

    /// Add a fresh guard candidate. No-op if already present or if the
    /// set is full. Returns true if added.
    pub fn add_candidate(&self, node_id: &[u8; 32], host: &str, port: u16) -> bool {
        let hex = hex::encode(node_id);
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();

        // Already have this one?
        if g.iter().any(|e| e.node_id == hex) {
            return false;
        }

        // Prune retired entries first (frees space for replacements)
        g.retain(|e| !e.should_retire(now));

        if g.len() >= MAX_GUARDS {
            return false;
        }

        g.push(GuardEntry {
            node_id:          hex,
            host:             host.to_string(),
            port,
            first_seen:       now,
            last_tried:       0,
            last_connected:   0,
            unreachable_since: None,
            confirmed:        false,
        });
        true
    }

    /// Drop any guard whose node_id is not in `keep`. Used to retire
    /// guards that have fallen out of the consensus so we stop dialing
    /// relays whose identity no longer exists (the classic stale-guard
    /// ghost). Returns how many were removed.
    pub fn retain_ids(&self, keep: &std::collections::HashSet<[u8; 32]>) -> usize {
        let mut g = self.entries.lock().unwrap();
        let before = g.len();
        g.retain(|e| {
            hex::decode(&e.node_id).ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .map(|id| keep.contains(&id))
                .unwrap_or(false)
        });
        before - g.len()
    }

    /// Record a successful connection to a guard.
    pub fn mark_success(&self, node_id: &[u8; 32]) {
        let hex = hex::encode(node_id);
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();
        if let Some(e) = g.iter_mut().find(|e| e.node_id == hex) {
            e.last_tried        = now;
            e.last_connected    = now;
            e.unreachable_since = None;
            e.confirmed         = true;
        }
    }

    /// Record a failed connection attempt to a guard.
    pub fn mark_failure(&self, node_id: &[u8; 32]) {
        let hex = hex::encode(node_id);
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();
        if let Some(e) = g.iter_mut().find(|e| e.node_id == hex) {
            e.last_tried = now;
            if e.unreachable_since.is_none() {
                e.unreachable_since = Some(now);
            }
        }
    }

    /// Remove expired guards. Returns how many were dropped.
    pub fn prune(&self) -> usize {
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();
        let before = g.len();
        g.retain(|e| !e.should_retire(now));
        before - g.len()
    }

    /// Atomically write the current state to disk. Uses write-to-temp
    /// + rename to avoid corruption on crash mid-write.
    pub fn save(&self) -> Result<()> {
        let g = self.entries.lock().unwrap().clone();
        let json = serde_json::to_vec_pretty(&g)
            .map_err(|e| Error::Crypto(format!("guards: serialize: {e}")))?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Crypto(format!("guards: mkdir: {e}")))?;
        }

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| Error::Crypto(format!("guards: write tmp: {e}")))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| Error::Crypto(format!("guards: rename: {e}")))?;
        crate::secure_permissions(&self.path);
        Ok(())
    }

    /// Convenience: save without propagating error, just log. Useful
    /// inside periodic tasks where we don't want to abort on disk flaps.
    pub fn save_best_effort(&self) {
        if let Err(e) = self.save() {
            tracing::warn!("guards: save failed: {}", e);
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_node_id(b: u8) -> [u8; 32] { [b; 32] }

    #[test]
    fn add_then_list() {
        let mgr = GuardManager::new_test();
        assert!(mgr.add_candidate(&test_node_id(0x11), "1.1.1.1", 7700));
        assert_eq!(mgr.list().len(), 1);
        assert_eq!(mgr.list()[0].host, "1.1.1.1");
    }

    #[test]
    fn duplicate_rejected() {
        let mgr = GuardManager::new_test();
        assert!(mgr.add_candidate(&test_node_id(0x22), "2.2.2.2", 7700));
        assert!(!mgr.add_candidate(&test_node_id(0x22), "2.2.2.2", 7700));
        assert_eq!(mgr.list().len(), 1);
    }

    #[test]
    fn enforces_max_guards() {
        let mgr = GuardManager::new_test();
        for i in 0..MAX_GUARDS { assert!(mgr.add_candidate(&test_node_id(i as u8), "x", 1)); }
        // Next one rejected
        assert!(!mgr.add_candidate(&test_node_id(0xEF), "x", 1));
        assert_eq!(mgr.list().len(), MAX_GUARDS);
    }

    #[test]
    fn mark_success_promotes() {
        let mgr = GuardManager::new_test();
        mgr.add_candidate(&test_node_id(0x33), "3.3.3.3", 7700);
        mgr.mark_success(&test_node_id(0x33));
        let g = mgr.list();
        assert!(g[0].confirmed);
        assert!(g[0].last_connected > 0);
        assert!(g[0].unreachable_since.is_none());
    }

    #[test]
    fn mark_failure_sets_unreachable() {
        let mgr = GuardManager::new_test();
        mgr.add_candidate(&test_node_id(0x44), "4.4.4.4", 7700);
        mgr.mark_failure(&test_node_id(0x44));
        let g = mgr.list();
        assert!(g[0].unreachable_since.is_some());
        assert!(!g[0].confirmed);
    }

    #[test]
    fn retire_after_unreachable_window() {
        let mut entry = GuardEntry {
            node_id:          "ab".repeat(16),
            host:             "x".into(),
            port:             1,
            first_seen:       now_unix(),
            last_tried:       now_unix(),
            last_connected:   0,
            unreachable_since: Some(now_unix() - GUARD_UNREACHABLE_BEFORE_DROP - 10),
            confirmed:        false,
        };
        assert!(entry.should_retire(now_unix()));

        entry.unreachable_since = Some(now_unix() - 60);
        assert!(!entry.should_retire(now_unix()));
    }

    #[test]
    fn retire_after_lifetime() {
        let entry = GuardEntry {
            node_id: "ff".repeat(16),
            host: "x".into(),
            port: 1,
            first_seen: now_unix() - GUARD_LIFETIME - 10,
            last_tried: 0, last_connected: 0,
            unreachable_since: None, confirmed: true,
        };
        assert!(entry.should_retire(now_unix()));
    }

    #[test]
    fn should_try_rate_limits_retries() {
        let now = now_unix();
        let mut entry = GuardEntry {
            node_id: "aa".repeat(16),
            host: "x".into(), port: 1,
            first_seen: now, last_tried: now,
            last_connected: 0,
            unreachable_since: Some(now),
            confirmed: false,
        };
        // Just tried, too soon to retry
        assert!(!entry.should_try(now));
        // After the interval, OK to retry
        entry.last_tried = now - GUARD_RETRY_INTERVAL - 1;
        assert!(entry.should_try(now));
    }

    #[test]
    fn persists_across_reopen() {
        let dir  = tempdir().unwrap();
        let path = dir.path().join("guards.json");

        {
            let mgr = GuardManager::open(path.clone()).unwrap();
            mgr.add_candidate(&test_node_id(0x55), "5.5.5.5", 7700);
            mgr.mark_success(&test_node_id(0x55));
            mgr.save().unwrap();
        }

        let mgr2 = GuardManager::open(path).unwrap();
        let g = mgr2.list();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].host, "5.5.5.5");
        assert!(g[0].confirmed);
    }

    #[test]
    fn prune_drops_retired() {
        let mgr = GuardManager::new_test();
        mgr.add_candidate(&test_node_id(0x66), "6.6.6.6", 7700);
        // Inject an aged-out entry directly (after add_candidate, which self-prunes)
        mgr.entries.lock().unwrap().push(GuardEntry {
            node_id: "aa".repeat(16),
            host: "x".into(), port: 1,
            first_seen: now_unix() - GUARD_LIFETIME - 100,
            last_tried: 0, last_connected: 0,
            unreachable_since: None, confirmed: true,
        });
        assert_eq!(mgr.list().len(), 2);
        let dropped = mgr.prune();
        assert_eq!(dropped, 1);
        assert_eq!(mgr.list().len(), 1);
    }

    #[test]
    fn corrupted_file_starts_fresh() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("guards.json");
        std::fs::write(&path, b"this is not valid JSON").unwrap();
        let mgr = GuardManager::open(path).unwrap();
        assert_eq!(mgr.list().len(), 0);
    }
}
