// phinet-core/src/vanguards.rs
//!
//! # Vanguards (layered guards for HS-related circuits)
//!
//! ΦNET, like Tor, uses *guards* — a small set of trusted relays a
//! client always uses as the first hop. Without guards, an attacker
//! who runs many relays will eventually be selected as the first hop
//! by chance and observe the client's IP. With guards, the client
//! commits to a small persistent set; the attacker has to compromise
//! one of those specific relays.
//!
//! For hidden-service circuits, this isn't enough. An attacker who
//! repeatedly causes a hidden service to extend new circuits (e.g.
//! by running a flood of introduction attempts) can probe the
//! service's guard relay over time and eventually compromise it.
//! This is the **guard-discovery attack** documented in the Tor
//! research literature (e.g., Kwon et al. 2015).
//!
//! **Vanguards** add a second guard layer that the HS uses as hop 2
//! of HS-related circuits. The attacker still has to compromise the
//! layer-1 guard to see the service's IP, but doing so only reveals
//! the layer-2 vanguard, not the service. Compromising both layers
//! requires much more work, and the layer-2 set rotates more slowly
//! than regular circuits, so the attacker's compromise is short-lived.
//!
//! ## What this module provides
//!
//! - `Vanguards`: persistent set of layer-2 vanguards with longer
//!   rotation periods than regular guards
//! - `pick_layer2()`: select a layer-2 vanguard for HS circuit hop 2
//! - Integration with path selection via the `excluded_node_ids` and
//!   `pinned_guard` knobs that path_select already supports
//!
//! ## What this module does NOT do
//!
//! - **Full Tor "vanguards-lite" three-layer scheme.** Tor's spec
//!   defines layer-1 (regular guards), layer-2 (10-day rotation),
//!   layer-3 (1-day rotation). ΦNET ships only the layer-2 idea.
//!   Adding layer-3 is mechanical given this module's structure.
//! - **HS-specific circuit construction logic.** Daemon code calling
//!   `auto_circuit` for HS purposes needs to consult this module
//!   when picking the second hop. This module exposes the API; the
//!   daemon-side wiring is operator integration work, documented in
//!   `OPERATING.md` under "Vanguards setup".
//!
//! ## Configuration
//!
//! - `MAX_LAYER2`: 4 vanguards in the active set (Tor's value).
//!   Selected when a slot opens up; rotated when the slot expires.
//! - `LAYER2_LIFETIME`: 10 days. Longer than regular guard lifetime
//!   (60 days) is wrong — guards stay longer than vanguards because
//!   guards see real client traffic that we're committed to anyway,
//!   while vanguards only matter for HS circuits and rotating them
//!   limits the attack window.
//! - `LAYER2_MIN_LIFETIME`: 24 hours. Even a vanguard that turns
//!   out to be unreachable stays in the set this long, to prevent
//!   adversarial churn ("force the client to keep picking new
//!   vanguards by killing each one").

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;

/// Maximum number of layer-2 vanguards in the active set. Tor's
/// vanguards-lite uses 4. More than this means too much state to
/// maintain; less than this means insufficient diversity.
pub const MAX_LAYER2: usize = 4;

/// How long a layer-2 vanguard stays in the set, in seconds. After
/// this, we rotate. 10 days = 864000 seconds. Tor uses 10 days.
pub const LAYER2_LIFETIME: u64 = 10 * 24 * 60 * 60;

/// Minimum lifetime even for unreachable vanguards. Prevents
/// adversarial churn where an attacker DoS's vanguards to force
/// the client to keep trying new ones (and eventually picking an
/// attacker-controlled relay). 1 day = 86400 seconds.
pub const LAYER2_MIN_LIFETIME: u64 = 24 * 60 * 60;

/// One layer-2 vanguard entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VanguardEntry {
    pub node_id_hex: String,
    pub host:        String,
    pub port:        u16,
    pub static_pub_hex: String,
    /// When we first added this vanguard (unix seconds).
    pub added_at: u64,
    /// Last time we successfully built a circuit through it.
    /// 0 means never used yet.
    pub last_used: u64,
    /// Last time we tried and failed to use it. 0 means no failures.
    pub unreachable_since: u64,
}

impl VanguardEntry {
    /// True if this entry has aged past `LAYER2_LIFETIME` and should
    /// be rotated out.
    pub fn should_rotate(&self, now: u64) -> bool {
        now.saturating_sub(self.added_at) >= LAYER2_LIFETIME
    }

    /// True if this entry is unreachable AND has been in the set
    /// long enough that we don't have to keep it for anti-churn.
    pub fn should_remove_unreachable(&self, now: u64) -> bool {
        if self.unreachable_since == 0 { return false; }
        let age = now.saturating_sub(self.added_at);
        let unreachable_for = now.saturating_sub(self.unreachable_since);
        // Past min-lifetime AND unreachable for >1h: drop it
        age >= LAYER2_MIN_LIFETIME && unreachable_for >= 3600
    }
}

/// Persistent set of layer-2 vanguards. Backed by a JSON file on
/// disk so the set survives daemon restarts.
pub struct Vanguards {
    path:    PathBuf,
    entries: Mutex<Vec<VanguardEntry>>,
}

impl Vanguards {
    /// Open or create a vanguards store at the given path.
    pub fn open(path: PathBuf) -> Result<Self> {
        let entries = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => serde_json::from_slice::<Vec<VanguardEntry>>(&bytes)
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        Ok(Self { path, entries: Mutex::new(entries) })
    }

    /// In-memory-only manager for tests.
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self {
            path:    PathBuf::from("/tmp/phinet_test_vanguards_ignored.json"),
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of the current vanguard set.
    pub fn list(&self) -> Vec<VanguardEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Number of currently-active (not-rotated, not-unreachable) entries.
    pub fn active_count(&self) -> usize {
        let now = now_unix();
        self.entries.lock().unwrap().iter()
            .filter(|e| !e.should_rotate(now) && e.unreachable_since == 0)
            .count()
    }

    /// Add a fresh candidate. Returns true if added (i.e. there was
    /// a free slot and the candidate isn't already in the set).
    pub fn add_candidate(
        &self,
        node_id_hex: &str,
        host: &str,
        port: u16,
        static_pub_hex: &str,
    ) -> bool {
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();

        // Already present?
        if g.iter().any(|e| e.node_id_hex == node_id_hex) {
            return false;
        }

        // Prune rotated + unreachable entries to free slots
        g.retain(|e| !e.should_rotate(now) && !e.should_remove_unreachable(now));

        if g.len() >= MAX_LAYER2 {
            return false;
        }

        g.push(VanguardEntry {
            node_id_hex:    node_id_hex.to_string(),
            host:           host.to_string(),
            port,
            static_pub_hex: static_pub_hex.to_string(),
            added_at:       now,
            last_used:      0,
            unreachable_since: 0,
        });
        let _ = self.persist(&g);
        true
    }

    /// Pick a layer-2 vanguard for an HS-related circuit's second hop.
    /// Returns `None` if no vanguards are currently usable.
    ///
    /// Selection: prefer vanguards that have been used recently (i.e.
    /// known-working) over ones that are stale. Avoids vanguards
    /// currently flagged unreachable.
    pub fn pick_layer2(&self) -> Option<VanguardEntry> {
        let now = now_unix();
        let g = self.entries.lock().unwrap();
        let active: Vec<&VanguardEntry> = g.iter()
            .filter(|e| !e.should_rotate(now) && e.unreachable_since == 0)
            .collect();
        if active.is_empty() { return None; }
        // Prefer most-recently-used; fall back to first.
        active.iter()
            .max_by_key(|e| e.last_used)
            .copied()
            .cloned()
    }

    /// Record that we successfully built a circuit through this vanguard.
    pub fn mark_used(&self, node_id_hex: &str) {
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();
        for e in g.iter_mut() {
            if e.node_id_hex == node_id_hex {
                e.last_used = now;
                e.unreachable_since = 0;
                let _ = self.persist(&g);
                return;
            }
        }
    }

    /// Record that this vanguard is currently unreachable. After
    /// `LAYER2_MIN_LIFETIME` it becomes eligible for removal.
    pub fn mark_unreachable(&self, node_id_hex: &str) {
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();
        for e in g.iter_mut() {
            if e.node_id_hex == node_id_hex && e.unreachable_since == 0 {
                e.unreachable_since = now;
                let _ = self.persist(&g);
                return;
            }
        }
    }

    /// Run periodic maintenance: drop rotated entries, drop
    /// long-unreachable entries. Call this on a timer (e.g. once
    /// per hour) in a background task.
    pub fn maintain(&self) -> usize {
        let now = now_unix();
        let mut g = self.entries.lock().unwrap();
        let before = g.len();
        g.retain(|e| !e.should_rotate(now) && !e.should_remove_unreachable(now));
        let removed = before - g.len();
        if removed > 0 {
            let _ = self.persist(&g);
        }
        removed
    }

    fn persist(&self, entries: &[VanguardEntry]) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&self.path, bytes)
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> (String, String, u16, String) {
        (id.to_string(), format!("host-{id}"), 7700, format!("{:0<64}", id))
    }

    #[test]
    fn add_until_full() {
        let v = Vanguards::new_test();
        for i in 0..MAX_LAYER2 {
            let (id, h, p, sp) = entry(&format!("aa{:02}", i));
            assert!(v.add_candidate(&id, &h, p, &sp));
        }
        // Next one rejected
        let (id, h, p, sp) = entry("ff");
        assert!(!v.add_candidate(&id, &h, p, &sp));
        assert_eq!(v.active_count(), MAX_LAYER2);
    }

    #[test]
    fn add_duplicate_rejected() {
        let v = Vanguards::new_test();
        let (id, h, p, sp) = entry("aa");
        assert!(v.add_candidate(&id, &h, p, &sp));
        assert!(!v.add_candidate(&id, &h, p, &sp), "duplicate must be rejected");
    }

    #[test]
    fn pick_returns_none_when_empty() {
        let v = Vanguards::new_test();
        assert!(v.pick_layer2().is_none());
    }

    #[test]
    fn pick_returns_active_entry() {
        let v = Vanguards::new_test();
        let (id, h, p, sp) = entry("aa");
        v.add_candidate(&id, &h, p, &sp);
        let picked = v.pick_layer2().expect("should pick");
        assert_eq!(picked.node_id_hex, id);
    }

    #[test]
    fn pick_skips_unreachable() {
        let v = Vanguards::new_test();
        let (id_a, h_a, p_a, sp_a) = entry("aa");
        let (id_b, h_b, p_b, sp_b) = entry("bb");
        v.add_candidate(&id_a, &h_a, p_a, &sp_a);
        v.add_candidate(&id_b, &h_b, p_b, &sp_b);

        // Mark aa unreachable
        v.mark_unreachable(&id_a);

        // Pick must return bb, not aa
        let picked = v.pick_layer2().expect("at least one available");
        assert_eq!(picked.node_id_hex, id_b);
    }

    #[test]
    fn pick_prefers_recently_used() {
        let v = Vanguards::new_test();
        for tag in ["aa", "bb", "cc"] {
            let (id, h, p, sp) = entry(tag);
            v.add_candidate(&id, &h, p, &sp);
        }
        // Mark bb as recently used
        v.mark_used("bb");
        let picked = v.pick_layer2().expect("pick");
        assert_eq!(picked.node_id_hex, "bb",
            "pick should prefer recently-used vanguard");
    }

    #[test]
    fn mark_used_clears_unreachable_flag() {
        let v = Vanguards::new_test();
        let (id, h, p, sp) = entry("aa");
        v.add_candidate(&id, &h, p, &sp);
        v.mark_unreachable(&id);
        assert_eq!(v.active_count(), 0);

        // Used successfully — flag should clear
        v.mark_used(&id);
        assert_eq!(v.active_count(), 1);
    }

    #[test]
    fn rotation_eligibility() {
        let now = now_unix();
        let fresh = VanguardEntry {
            node_id_hex: "x".into(), host: "h".into(), port: 1,
            static_pub_hex: "p".into(),
            added_at: now, last_used: 0, unreachable_since: 0,
        };
        assert!(!fresh.should_rotate(now));
        assert!(!fresh.should_remove_unreachable(now));

        // Past LAYER2_LIFETIME → rotate
        let aged = VanguardEntry {
            added_at: now.saturating_sub(LAYER2_LIFETIME + 1),
            ..fresh.clone()
        };
        assert!(aged.should_rotate(now));

        // Unreachable but within MIN_LIFETIME → keep
        let recent_unreach = VanguardEntry {
            added_at: now.saturating_sub(LAYER2_MIN_LIFETIME / 2),
            unreachable_since: now.saturating_sub(7200),
            ..fresh.clone()
        };
        assert!(!recent_unreach.should_remove_unreachable(now));

        // Old AND long-unreachable → remove
        let stale_unreach = VanguardEntry {
            added_at: now.saturating_sub(LAYER2_MIN_LIFETIME + 100),
            unreachable_since: now.saturating_sub(7200),
            ..fresh.clone()
        };
        assert!(stale_unreach.should_remove_unreachable(now));
    }

    #[test]
    fn persistence_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vanguards.json");

        let v1 = Vanguards::open(path.clone()).unwrap();
        let (id, h, p, sp) = entry("aa");
        assert!(v1.add_candidate(&id, &h, p, &sp));
        v1.mark_used(&id);
        drop(v1);

        // Reopen — entry should still be there with last_used set
        let v2 = Vanguards::open(path).unwrap();
        let entries = v2.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].node_id_hex, id);
        assert!(entries[0].last_used > 0);
    }

    #[test]
    fn maintain_drops_rotated_entries() {
        let v = Vanguards::new_test();
        // Insert two entries. Age the first one beyond LAYER2_LIFETIME.
        let (id1, h1, p1, sp1) = entry("old");
        v.add_candidate(&id1, &h1, p1, &sp1);
        let (id2, h2, p2, sp2) = entry("new");
        v.add_candidate(&id2, &h2, p2, &sp2);
        {
            let mut g = v.entries.lock().unwrap();
            // Age the first entry by direct mutation (test-only).
            g[0].added_at = now_unix().saturating_sub(LAYER2_LIFETIME + 100);
        }

        // Now maintain() should drop the aged entry.
        let removed = v.maintain();
        assert_eq!(removed, 1, "should remove the aged entry");
        let remaining = v.list();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].node_id_hex, "new");
    }
}
