// phinet-core/src/board.rs
//! Anonymous distributed message board.
//!
//! Posts use per-post ephemeral X25519 keys — not linkable to node identity.
//! Channels are arbitrary strings or φ-cluster IDs.
//! Gossip deduplication by msg_id = SHA-256(ephem_pub ‖ channel ‖ text ‖ ts).

use crate::{crypto::sha256, wire::BoardPost, Error, Result};
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

pub const BOARD_MAX_POSTS: usize = 1000;

pub struct MessageBoard {
    channels: RwLock<HashMap<String, VecDeque<BoardPost>>>,
    seen:     RwLock<HashSet<String>>,
    /// Append-only log for durability. `None` = in-memory only.
    /// Protected by Mutex since file appends must be serialized; the
    /// critical section is fast (one write call).
    log_path: Option<PathBuf>,
    log_file: Mutex<Option<std::fs::File>>,
}

impl MessageBoard {
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
            seen:     RwLock::new(HashSet::new()),
            log_path: None,
            log_file: Mutex::new(None),
        }
    }

    /// Open or create a persistent board. The file is an append-only
    /// JSON-lines log: one `BoardPost` per line. On load, posts are
    /// replayed and MAC-verified; corrupted or invalid lines are
    /// silently skipped. The file is opened in append mode, so a crash
    /// mid-write loses at most the partial last line.
    ///
    /// If the file doesn't exist it's created. If it exists and is
    /// larger than [`BOARD_MAX_POSTS`]·10 lines, a compaction pass
    /// runs: the most recent [`BOARD_MAX_POSTS`] entries per channel
    /// are rewritten into a fresh file, and the old one is replaced.
    pub fn open(path: PathBuf) -> Result<Self> {
        let board = Self {
            channels: RwLock::new(HashMap::new()),
            seen:     RwLock::new(HashSet::new()),
            log_path: Some(path.clone()),
            log_file: Mutex::new(None),
        };

        if path.exists() {
            board.load_from_disk()?;
            board.maybe_compact()?;
        } else if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Crypto(format!("board: mkdir: {e}")))?;
        }

        // Open file for appending.
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::Crypto(format!("board: open log: {e}")))?;
        *board.log_file.lock().unwrap() = Some(f);

        Ok(board)
    }

    fn load_from_disk(&self) -> Result<()> {
        let Some(path) = &self.log_path else { return Ok(()); };
        let f = std::fs::File::open(path)
            .map_err(|e| Error::Crypto(format!("board: load: {e}")))?;
        let reader = BufReader::new(f);
        let mut loaded = 0usize;
        let mut bad    = 0usize;
        for line in reader.lines() {
            let Ok(line) = line else { bad += 1; continue; };
            let line = line.trim();
            if line.is_empty() { continue; }
            let Ok(post) = serde_json::from_str::<BoardPost>(line) else {
                bad += 1; continue;
            };
            // Silently drop posts with invalid MAC (may be
            // adversarially-crafted or corrupted storage).
            if !Self::verify(&post) { bad += 1; continue; }
            self.insert_mem(&post, &post.msg_id.clone());
            loaded += 1;
        }
        tracing::debug!("board: loaded {} posts from disk ({} skipped)", loaded, bad);
        Ok(())
    }

    /// Compact the log if it's grown far beyond what we'd display.
    /// Rewrites just the retained window (BOARD_MAX_POSTS per channel).
    fn maybe_compact(&self) -> Result<()> {
        let Some(path) = &self.log_path else { return Ok(()); };
        let Ok(meta)   = std::fs::metadata(path) else { return Ok(()); };
        // Heuristic: each post ~300 bytes typical. Compact if > 1 MB.
        if meta.len() < 1_000_000 { return Ok(()); }

        // Serialize all in-memory posts to a fresh temp file, then rename.
        let tmp = path.with_extension("log.tmp");
        let mut tmp_file = std::fs::File::create(&tmp)
            .map_err(|e| Error::Crypto(format!("board: compact create: {e}")))?;

        let channels = self.channels.read().unwrap();
        for posts in channels.values() {
            for post in posts.iter() {
                let line = serde_json::to_string(post)
                    .map_err(|e| Error::Crypto(format!("board: serialize: {e}")))?;
                writeln!(tmp_file, "{line}")
                    .map_err(|e| Error::Crypto(format!("board: compact write: {e}")))?;
            }
        }
        drop(tmp_file);
        drop(channels);

        std::fs::rename(&tmp, path)
            .map_err(|e| Error::Crypto(format!("board: compact rename: {e}")))?;
        tracing::debug!("board: compacted log");
        Ok(())
    }

    /// Create and store a new post. Returns the post.
    pub fn post(
        &self,
        channel: &str,
        text:    &str,
        cluster: Option<[u8; 32]>,
    ) -> BoardPost {
        // Ephemeral key — not linked to node identity
        let ephem_secret = StaticSecret::random_from_rng(OsRng);
        let ephem_pub    = PublicKey::from(&ephem_secret);
        let ephem_bytes  = ephem_pub.as_bytes();

        let ts = unix_now();

        // msg_id = SHA-256(ephem_pub ‖ channel ‖ text ‖ ts_le)
        let mut id_input = Vec::new();
        id_input.extend_from_slice(ephem_bytes);
        id_input.extend_from_slice(channel.as_bytes());
        id_input.extend_from_slice(text.as_bytes());
        id_input.extend_from_slice(&ts.to_le_bytes());
        let msg_id = hex::encode(sha256(&id_input));

        // MAC = SHA-256(ephem_pub ‖ "channel:text:ts")
        let mac_data = format!("{}:{}:{}", channel, text, ts);
        let mut mac_input = ephem_bytes.to_vec();
        mac_input.extend_from_slice(mac_data.as_bytes());
        let mac = hex::encode(sha256(&mac_input));

        let post = BoardPost {
            msg_id:    msg_id.clone(),
            channel:   channel.to_string(),
            text:      text.to_string(),
            ts,
            ephem_pub: hex::encode(ephem_bytes),
            mac,
            cluster:   cluster.map(|c| hex::encode(c)),
        };

        self.insert(&post, &msg_id);
        post
    }

    /// Merge an incoming post. Returns `true` if it was new (gossip it).
    pub fn merge(&self, post: &BoardPost) -> bool {
        if self.seen.read().unwrap().contains(&post.msg_id) {
            return false;
        }
        self.insert(post, &post.msg_id);
        true
    }

    fn insert(&self, post: &BoardPost, msg_id: &str) {
        // If already in seen set, don't write or re-insert.
        if self.seen.read().unwrap().contains(msg_id) { return; }
        self.insert_mem(post, msg_id);
        self.append_to_log(post);
    }

    /// In-memory insert. Used both for fresh posts and for replay on
    /// startup. Skips if the msg_id has already been seen in this
    /// process — this is what makes reload-after-duplicate-file-write
    /// safe.
    fn insert_mem(&self, post: &BoardPost, msg_id: &str) {
        {
            let mut seen = self.seen.write().unwrap();
            if !seen.insert(msg_id.to_string()) {
                return; // already present
            }
            if seen.len() > BOARD_MAX_POSTS * 10 {
                // Keep the newest half
                let v: Vec<_> = seen.iter().skip(seen.len() / 2).cloned().collect();
                *seen = v.into_iter().collect();
            }
        }
        let mut ch = self.channels.write().unwrap();
        let board  = ch.entry(post.channel.clone()).or_default();
        board.push_back(post.clone());
        if board.len() > BOARD_MAX_POSTS {
            board.pop_front();
        }
    }

    fn append_to_log(&self, post: &BoardPost) {
        let mut guard = self.log_file.lock().unwrap();
        let Some(f) = guard.as_mut() else { return; };
        let Ok(line) = serde_json::to_string(post) else { return; };
        // Best-effort: log but don't fail the insert if disk I/O breaks.
        if let Err(e) = writeln!(f, "{line}") {
            tracing::warn!("board: log append failed: {}", e);
        }
        // Flush to ensure crash-durability of the previous line.
        let _ = f.flush();
    }

    pub fn get(&self, channel: &str, limit: usize) -> Vec<BoardPost> {
        let ch = self.channels.read().unwrap();
        ch.get(channel).map(|b| {
            let skip = b.len().saturating_sub(limit);
            b.iter().skip(skip).cloned().collect()
        }).unwrap_or_default()
    }

    pub fn all_channels(&self) -> Vec<String> {
        self.channels.read().unwrap().keys().cloned().collect()
    }

    /// Verify the MAC on a post in constant time.
    ///
    /// Uses `timing::ct_eq_bytes` so an attacker cannot correlate
    /// response timing with which byte of the expected MAC first
    /// differs. Even though MACs on gossiped posts aren't strictly
    /// keyed, treating them as secret-comparable is defense-in-depth:
    /// an attacker who knows `ephem_pub` can try crafted forgeries
    /// against a verifier and learn via timing which bytes of the
    /// SHA-256 output land where.
    pub fn verify(post: &BoardPost) -> bool {
        let Ok(eb) = hex::decode(&post.ephem_pub) else { return false };
        let mac_data = format!("{}:{}:{}", post.channel, post.text, post.ts);
        let mut input = eb;
        input.extend_from_slice(mac_data.as_bytes());
        let expected = hex::encode(sha256(&input));
        crate::timing::ct_eq_bytes(expected.as_bytes(), post.mac.as_bytes())
    }
}

impl Default for MessageBoard {
    fn default() -> Self { Self::new() }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_and_get() {
        let b = MessageBoard::new();
        let p = b.post("general", "hello", None);
        assert_eq!(p.msg_id.len(), 64);
        let posts = b.get("general", 10);
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].text, "hello");
    }

    #[test]
    fn verify_mac() {
        let b = MessageBoard::new();
        let p = b.post("t", "msg", None);
        assert!(MessageBoard::verify(&p));
        let mut bad = p.clone(); bad.text = "tampered".into();
        assert!(!MessageBoard::verify(&bad));
    }

    #[test]
    fn dedup() {
        let b = MessageBoard::new();
        let p = b.post("c", "x", None);
        assert!(!b.merge(&p));
        assert_eq!(b.get("c", 100).len(), 1);
    }

    #[test]
    fn merge_new() {
        let b1 = MessageBoard::new();
        let b2 = MessageBoard::new();
        let p  = b2.post("news", "item", None);
        assert!(b1.merge(&p));
        assert_eq!(b1.get("news", 10).len(), 1);
    }

    #[test]
    fn cap() {
        let b = MessageBoard::new();
        for i in 0..BOARD_MAX_POSTS + 5 { b.post("s", &format!("{}", i), None); }
        assert_eq!(b.get("s", BOARD_MAX_POSTS + 100).len(), BOARD_MAX_POSTS);
    }

    // ── Persistence ───────────────────────────────────────────────────

    #[test]
    fn persists_posts_across_reopen() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.log");
        {
            let b = MessageBoard::open(path.clone()).unwrap();
            b.post("news", "alpha", None);
            b.post("news", "beta",  None);
            b.post("chat", "hi",    None);
        }
        let b2 = MessageBoard::open(path).unwrap();
        let news = b2.get("news", 100);
        let chat = b2.get("chat", 100);
        assert_eq!(news.len(), 2);
        assert_eq!(chat.len(), 1);
        assert_eq!(news[0].text, "alpha");
        assert_eq!(news[1].text, "beta");
        assert_eq!(chat[0].text, "hi");
    }

    #[test]
    fn persistence_dedups_on_reload() {
        // Manually write the same post twice — loader should dedupe.
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.log");

        // Produce a post with valid MAC
        let b = MessageBoard::new();
        let p = b.post("c", "once", None);
        let line = serde_json::to_string(&p).unwrap();

        std::fs::write(&path, format!("{line}\n{line}\n")).unwrap();

        let b2 = MessageBoard::open(path).unwrap();
        assert_eq!(b2.get("c", 100).len(), 1, "duplicate msg_ids must be deduped");
    }

    #[test]
    fn persistence_rejects_bad_mac() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.log");

        let b = MessageBoard::new();
        let mut tampered = b.post("c", "real", None);
        tampered.text = "forged".into(); // MAC no longer matches

        let line = serde_json::to_string(&tampered).unwrap();
        std::fs::write(&path, format!("{line}\n")).unwrap();

        let b2 = MessageBoard::open(path).unwrap();
        assert_eq!(b2.get("c", 100).len(), 0, "bad MAC must be rejected on load");
    }

    #[test]
    fn persistence_survives_garbage_lines() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.log");

        let b = MessageBoard::new();
        let p = b.post("c", "good", None);
        let good_line = serde_json::to_string(&p).unwrap();

        let content = format!(
            "not json\n\
             {good_line}\n\
             {{\"truncated\":\
             \nalso not json\n\
             {good_line}\n"
        );
        std::fs::write(&path, content).unwrap();

        let b2 = MessageBoard::open(path).unwrap();
        // Garbage ignored, one good post loaded (dupe suppressed)
        assert_eq!(b2.get("c", 100).len(), 1);
    }

    #[test]
    fn persistence_appends_new_posts() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.log");

        {
            let b = MessageBoard::open(path.clone()).unwrap();
            b.post("c", "first", None);
        }
        {
            let b = MessageBoard::open(path.clone()).unwrap();
            b.post("c", "second", None);
        }
        let b = MessageBoard::open(path).unwrap();
        let posts = b.get("c", 100);
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].text, "first");
        assert_eq!(posts[1].text, "second");
    }

    #[test]
    fn in_memory_mode_still_works() {
        // No log_path = no persistence
        let b = MessageBoard::new();
        let p = b.post("c", "x", None);
        assert!(MessageBoard::verify(&p));
        assert_eq!(b.get("c", 10).len(), 1);
    }
}
