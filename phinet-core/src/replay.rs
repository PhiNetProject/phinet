// phinet-core/src/replay.rs
//! Persistent replay cache.
//!
//! Tracks message IDs we've already processed, across daemon restarts,
//! so an attacker replaying old signed/MACed ciphertext can't cause
//! us to re-emit or re-accept the same message.
//!
//! # Scope
//!
//! This is NOT for session AEAD replay — the session layer already
//! handles that with monotonic counters. This IS for:
//!   * DHT store records (replayed descriptor/value pushes)
//!   * HS descriptors (replayed old descriptors pointing at rotated-out
//!     intro points)
//!   * Board posts (belt-and-suspenders over the board's own dedup)
//!   * Any other broadcast/gossip message that should be processed
//!     once across the lifetime of a node
//!
//! # Storage
//!
//! `~/.phinet/replay.log` — append-only newline-JSON entries:
//!
//! ```text
//! {"id":"abc…","exp":1700099999}
//! ```
//!
//! On startup we load the file, evict entries past expiry, and rewrite
//! a compact copy. During normal operation we append new entries.
//!
//! # Properties
//!
//! * **Bounded size** — entries are time-bounded. A replay cache that
//!   grows forever is a DoS vector.
//! * **Fail-open on disk failure** — in-memory cache stays authoritative;
//!   we log but don't crash if the file is unwritable.
//! * **Crash-safe** — append-only means a crash mid-write loses at
//!   most the last line. Compaction uses write-temp-then-rename.
//!
//! # Usage
//!
//! ```ignore
//! let cache = ReplayCache::open(path, 3600)?; // 1-hour TTL
//!
//! let msg_id = "abc...";
//! if cache.seen(msg_id) {
//!     return; // already processed
//! }
//! cache.mark(msg_id);
//! // ... process the message ...
//! ```

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum size of the in-memory replay set. Prevents an attacker
/// flooding us with fake IDs from exhausting RAM. When we hit this
/// limit, a forced prune runs — oldest-expiry entries go first.
pub const REPLAY_MAX_ENTRIES: usize = 100_000;

/// Threshold for automatic compaction (append-only log size in lines).
/// Real entries live in memory; the file accumulates stale entries
/// from prior runs. When file size gets this large, we rewrite.
pub const REPLAY_COMPACT_LINES: usize = 50_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    id:  String,
    exp: u64,
}

pub struct ReplayCache {
    path:     Option<PathBuf>,
    default_ttl: u64,
    /// id → expiry_unix_secs
    entries:  Mutex<HashMap<String, u64>>,
    log_file: Mutex<Option<std::fs::File>>,
    /// Approximate count of append-only log entries (including stale).
    /// Reset on compaction.
    log_lines: Mutex<usize>,
}

impl ReplayCache {
    /// Open or create a persistent replay cache. `default_ttl` is
    /// seconds from `mark()` until auto-eviction.
    pub fn open(path: PathBuf, default_ttl: u64) -> Result<Self> {
        let cache = Self {
            path:       Some(path.clone()),
            default_ttl,
            entries:    Mutex::new(HashMap::new()),
            log_file:   Mutex::new(None),
            log_lines:  Mutex::new(0),
        };

        if path.exists() {
            cache.load_from_disk()?;
        } else if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Crypto(format!("replay: mkdir: {e}")))?;
        }

        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::Crypto(format!("replay: open: {e}")))?;
        *cache.log_file.lock().unwrap() = Some(f);

        // If the on-disk log is already large, compact to keep appends fast.
        if *cache.log_lines.lock().unwrap() > REPLAY_COMPACT_LINES {
            let _ = cache.compact();
        }
        Ok(cache)
    }

    /// In-memory-only cache for tests.
    #[cfg(test)]
    pub fn new_test(ttl: u64) -> Self {
        Self {
            path:       None,
            default_ttl: ttl,
            entries:    Mutex::new(HashMap::new()),
            log_file:   Mutex::new(None),
            log_lines:  Mutex::new(0),
        }
    }

    fn load_from_disk(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()); };
        let f = std::fs::File::open(path)
            .map_err(|e| Error::Crypto(format!("replay: load: {e}")))?;
        let reader = BufReader::new(f);
        let now = now_unix();
        let mut entries = self.entries.lock().unwrap();
        let mut count   = 0usize;
        let mut kept    = 0usize;

        for line in reader.lines().map_while(|r| r.ok()) {
            let line = line.trim();
            if line.is_empty() { continue; }
            count += 1;
            let Ok(e) = serde_json::from_str::<Entry>(line) else { continue; };
            if e.exp <= now { continue; } // already expired
            entries.insert(e.id, e.exp);
            kept += 1;
        }
        *self.log_lines.lock().unwrap() = count;
        tracing::debug!("replay: loaded {} live / {} total entries", kept, count);
        Ok(())
    }

    /// True if `id` has been marked recently and is not yet expired.
    pub fn seen(&self, id: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        let now = now_unix();
        match entries.get(id) {
            Some(&exp) if exp > now => true,
            _ => false,
        }
    }

    /// Record `id` as seen with the default TTL.
    /// Returns `true` if this was a new insertion (safe to process),
    /// `false` if the id was already present and not yet expired
    /// (caller should drop the message as a replay).
    pub fn mark(&self, id: &str) -> bool {
        self.mark_with_ttl(id, self.default_ttl)
    }

    /// Record `id` with a specific TTL in seconds.
    pub fn mark_with_ttl(&self, id: &str, ttl: u64) -> bool {
        let exp = now_unix().saturating_add(ttl);

        let was_new = {
            let mut entries = self.entries.lock().unwrap();
            let now = now_unix();

            // Bound cache size — evict if full.
            if entries.len() >= REPLAY_MAX_ENTRIES {
                let to_drop: Vec<String> = entries.iter()
                    .filter(|(_, &e)| e <= now)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in to_drop { entries.remove(&k); }
                if entries.len() >= REPLAY_MAX_ENTRIES {
                    // Still full — drop the soonest-to-expire 10% to make room.
                    let mut pairs: Vec<(String, u64)> =
                        entries.iter().map(|(k,v)|(k.clone(),*v)).collect();
                    pairs.sort_by_key(|(_,e)| *e);
                    let to_drop = REPLAY_MAX_ENTRIES / 10;
                    for (k, _) in pairs.into_iter().take(to_drop) {
                        entries.remove(&k);
                    }
                }
            }

            match entries.get(id) {
                Some(&prev) if prev > now => false,
                _ => { entries.insert(id.to_string(), exp); true }
            }
        };

        if was_new {
            self.append_to_log(&Entry { id: id.to_string(), exp });
        }
        was_new
    }

    fn append_to_log(&self, e: &Entry) {
        let mut guard = self.log_file.lock().unwrap();
        let Some(f) = guard.as_mut() else { return; };
        let Ok(line) = serde_json::to_string(e) else { return; };
        if let Err(err) = writeln!(f, "{line}") {
            tracing::warn!("replay: log append: {}", err);
            return;
        }
        let _ = f.flush();
        *self.log_lines.lock().unwrap() += 1;
    }

    /// Drop entries past expiry. Returns how many were evicted.
    /// Called periodically by a background task or on size pressure.
    pub fn evict_expired(&self) -> usize {
        let now = now_unix();
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, &mut e| e > now);
        before - entries.len()
    }

    /// Rewrite the log file, keeping only non-expired entries. This
    /// shrinks storage when many entries have expired. Called from
    /// `open()` on startup if the file was large, and can be called
    /// periodically.
    pub fn compact(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()); };
        let entries = self.entries.lock().unwrap().clone();
        let tmp = path.with_extension("log.tmp");

        // Drop the current file handle so Windows doesn't complain
        // about the rename below. Reopen in append mode after rename.
        *self.log_file.lock().unwrap() = None;

        {
            let mut tmp_f = std::fs::File::create(&tmp)
                .map_err(|e| Error::Crypto(format!("replay: compact create: {e}")))?;
            for (id, exp) in entries.iter() {
                let line = serde_json::to_string(&Entry { id: id.clone(), exp: *exp })
                    .map_err(|e| Error::Crypto(format!("replay: compact ser: {e}")))?;
                writeln!(tmp_f, "{line}")
                    .map_err(|e| Error::Crypto(format!("replay: compact write: {e}")))?;
            }
        }

        std::fs::rename(&tmp, path)
            .map_err(|e| Error::Crypto(format!("replay: compact rename: {e}")))?;

        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Error::Crypto(format!("replay: reopen: {e}")))?;
        *self.log_file.lock().unwrap() = Some(f);
        *self.log_lines.lock().unwrap() = entries.len();
        tracing::debug!("replay: compacted to {} entries", entries.len());
        Ok(())
    }

    /// Current number of live (non-expired) entries.
    pub fn len(&self) -> usize {
        let now = now_unix();
        self.entries.lock().unwrap().values()
            .filter(|&&e| e > now)
            .count()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_then_seen() {
        let c = ReplayCache::new_test(60);
        assert!(!c.seen("abc"));
        assert!(c.mark("abc"));
        assert!(c.seen("abc"));
    }

    #[test]
    fn repeated_mark_returns_false() {
        let c = ReplayCache::new_test(60);
        assert!(c.mark("x"));
        assert!(!c.mark("x"), "second mark of same id must return false");
        assert!(!c.mark("x"));
    }

    #[test]
    fn distinct_ids_independent() {
        let c = ReplayCache::new_test(60);
        assert!(c.mark("a"));
        assert!(c.mark("b"));
        assert!(c.mark("c"));
        assert!(c.seen("a"));
        assert!(c.seen("b"));
        assert!(c.seen("c"));
        assert!(!c.seen("d"));
    }

    #[test]
    fn zero_ttl_acts_as_expired() {
        let c = ReplayCache::new_test(0);
        // mark_with_ttl(id, 0) expires immediately (exp = now).
        c.mark_with_ttl("e", 0);
        assert!(!c.seen("e"), "0-ttl entries should not appear as seen");
    }

    #[test]
    fn evict_expired_drops_old_entries() {
        let c = ReplayCache::new_test(1);
        c.mark_with_ttl("old", 0);   // already expired
        c.mark_with_ttl("fresh", 3600);
        // Sanity: both are in the entries map
        assert_eq!(c.entries.lock().unwrap().len(), 2);
        let dropped = c.evict_expired();
        assert_eq!(dropped, 1);
        assert!(c.seen("fresh"));
        assert!(!c.seen("old"));
    }

    #[test]
    fn persists_across_reopen() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.log");
        {
            let c = ReplayCache::open(path.clone(), 3600).unwrap();
            c.mark("id-1");
            c.mark("id-2");
        }
        let c2 = ReplayCache::open(path, 3600).unwrap();
        assert!(c2.seen("id-1"));
        assert!(c2.seen("id-2"));
        assert!(!c2.seen("id-3"));
    }

    #[test]
    fn expired_entries_dropped_on_reload() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.log");
        {
            let c = ReplayCache::open(path.clone(), 3600).unwrap();
            c.mark_with_ttl("live",    3600);
            c.mark_with_ttl("expired", 0);    // expires immediately
        }
        let c2 = ReplayCache::open(path, 3600).unwrap();
        assert!(c2.seen("live"));
        assert!(!c2.seen("expired"));
    }

    #[test]
    fn corrupted_log_starts_fresh_for_bad_lines() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.log");
        std::fs::write(&path,
            b"{\"id\":\"good\",\"exp\":9999999999}\n\
              not valid json\n\
              {\"also\":\"not our schema\"}\n\
              {\"id\":\"good2\",\"exp\":9999999999}\n")
            .unwrap();
        let c = ReplayCache::open(path, 3600).unwrap();
        assert!(c.seen("good"));
        assert!(c.seen("good2"));
    }

    #[test]
    fn compact_keeps_live_entries() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.log");
        {
            let c = ReplayCache::open(path.clone(), 3600).unwrap();
            c.mark("a"); c.mark("b"); c.mark("c");
        }
        // Manually append garbage to bloat the file
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            for i in 0..100 {
                writeln!(f, "{{\"id\":\"noise-{}\",\"exp\":1}}", i).unwrap();
            }
        }
        {
            let c = ReplayCache::open(path.clone(), 3600).unwrap();
            c.compact().unwrap();
        }
        let c = ReplayCache::open(path, 3600).unwrap();
        assert!(c.seen("a"));
        assert!(c.seen("b"));
        assert!(c.seen("c"));
        assert!(!c.seen("noise-0"));
    }

    #[test]
    fn mark_returns_correct_boolean_for_replay_detection() {
        // This is how production code will use the API:
        // drop the message if mark returns false.
        let c = ReplayCache::new_test(60);
        let msg_id = "unique-msg-id-v1";
        let is_new = c.mark(msg_id);
        assert!(is_new, "first mark: is_new");
        let is_new_again = c.mark(msg_id);
        assert!(!is_new_again, "replay: mark returns false");
    }

    #[test]
    fn len_counts_live_only() {
        let c = ReplayCache::new_test(3600);
        c.mark("a");
        c.mark("b");
        c.mark_with_ttl("expires-now", 0);
        assert_eq!(c.len(), 2, "expired entry must not count");
    }
}
