// phinet-core/src/dht.rs
//! Kademlia-style DHT — 256-bit XOR metric, 256 k-buckets, K=8.

use crate::wire::HsDescriptor;
use crate::cert::WireCert;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::RwLock,
    time::{Duration, Instant},
};

pub const K:              usize    = 8;
pub const ALPHA:          usize    = 3;
pub const NODE_ID_BITS:   usize    = 256;
pub const DHT_VALUE_TTL:  Duration = Duration::from_secs(3600);

// ── Peer info ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id:    [u8; 32],
    pub host:       String,
    pub port:       u16,
    pub cert:       WireCert,
    pub static_pub: String,
}

impl Default for PeerInfo {
    fn default() -> Self {
        PeerInfo {
            node_id:    [0u8; 32],
            host:       String::new(),
            port:       0,
            cert:       WireCert::default(),
            static_pub: String::new(),
        }
    }
}

impl PeerInfo {
    pub fn addr(&self) -> String { format!("{}:{}", self.host, self.port) }
    pub fn node_id_hex(&self) -> String { hex::encode(self.node_id) }
}

// ── K-bucket ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct KBucket {
    nodes: VecDeque<PeerInfo>,
}

impl KBucket {
    fn add(&mut self, peer: PeerInfo) {
        // Move to tail if already present (most-recently-seen)
        if let Some(pos) = self.nodes.iter().position(|p| p.node_id == peer.node_id) {
            self.nodes.remove(pos);
        }
        if self.nodes.len() >= K {
            self.nodes.pop_front(); // evict least-recently-seen
        }
        self.nodes.push_back(peer);
    }

    fn all(&self) -> Vec<PeerInfo> {
        self.nodes.iter().cloned().collect()
    }

    fn remove(&mut self, id: &[u8; 32]) -> bool {
        if let Some(pos) = self.nodes.iter().position(|p| p.node_id == *id) {
            self.nodes.remove(pos);
            true
        } else {
            false
        }
    }
}

// ── Routing table ─────────────────────────────────────────────────────

pub struct RoutingTable {
    own_id:  [u8; 32],
    buckets: Vec<RwLock<KBucket>>,
}

impl RoutingTable {
    pub fn new(own_id: [u8; 32]) -> Self {
        let buckets = (0..NODE_ID_BITS)
            .map(|_| RwLock::new(KBucket::default()))
            .collect();
        Self { own_id, buckets }
    }

    fn bucket_idx(&self, id: &[u8; 32]) -> usize {
        let xor = xor_dist(&self.own_id, id);
        for (i, &b) in xor.iter().enumerate() {
            if b != 0 {
                return NODE_ID_BITS - 1 - (i * 8 + b.leading_zeros() as usize);
            }
        }
        NODE_ID_BITS - 1
    }

    pub fn add_peer(&self, peer: PeerInfo) {
        if peer.node_id == self.own_id { return; }
        let idx = self.bucket_idx(&peer.node_id);
        self.buckets[idx].write().unwrap().add(peer);
    }

    pub fn remove_peer(&self, id: &[u8; 32]) -> bool {
        if *id == self.own_id { return false; }
        let idx = self.bucket_idx(id);
        self.buckets[idx].write().unwrap().remove(id)
    }

    pub fn closest(&self, target: &[u8; 32], k: usize) -> Vec<PeerInfo> {
        let mut all: Vec<PeerInfo> = self.buckets.iter()
            .flat_map(|b| b.read().unwrap().all())
            .collect();
        all.sort_by_key(|p| xor_dist(target, &p.node_id));
        all.truncate(k);
        all
    }

    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.buckets.iter()
            .flat_map(|b| b.read().unwrap().all())
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(|b| b.read().unwrap().nodes.len()).sum()
    }
}

fn xor_dist(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = a[i] ^ b[i]; }
    out
}

// ── DHT key-value store ───────────────────────────────────────────────

struct Entry {
    value:   serde_json::Value,
    stored:  Instant,
}

#[derive(Default)]
pub struct DhtStore {
    data: RwLock<HashMap<String, Entry>>,
}

impl DhtStore {
    pub fn new() -> Self { Self::default() }

    pub fn put(&self, key: String, value: serde_json::Value) {
        self.data.write().unwrap()
            .insert(key, Entry { value, stored: Instant::now() });
    }

    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.data.read().unwrap().get(key).and_then(|e| {
            if e.stored.elapsed() < DHT_VALUE_TTL { Some(e.value.clone()) }
            else { None }
        })
    }

    pub fn keys(&self) -> Vec<String> {
        self.data.read().unwrap().keys().cloned().collect()
    }

    pub fn evict_expired(&self) {
        self.data.write().unwrap()
            .retain(|_, e| e.stored.elapsed() < DHT_VALUE_TTL);
    }

    pub fn put_hs(&self, desc: &HsDescriptor) {
        self.put(
            format!("hs:{}", desc.hs_id),
            serde_json::to_value(desc).unwrap_or_default(),
        );
    }

    pub fn get_hs(&self, hs_id: &str) -> Option<HsDescriptor> {
        self.get(&format!("hs:{}", hs_id))
            .and_then(|v| serde_json::from_value(v).ok())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8, host: &str, port: u16) -> PeerInfo {
        let mut id = [0u8; 32];
        id[0] = b;
        PeerInfo { node_id: id, host: host.into(), port, ..Default::default() }
    }

    #[test]
    fn routing_add_and_closest() {
        let rt = RoutingTable::new([0u8; 32]);
        rt.add_peer(peer(1, "10.0.0.1", 7700));
        rt.add_peer(peer(2, "10.0.0.2", 7701));
        rt.add_peer(peer(0x80, "10.0.0.3", 7702));
        assert_eq!(rt.peer_count(), 3);
        let mut t = [0u8; 32]; t[0] = 1;
        let c = rt.closest(&t, 1);
        assert_eq!(c[0].node_id[0], 1);
    }

    #[test]
    fn dht_store_put_get() {
        let s = DhtStore::new();
        s.put("k".into(), serde_json::json!(42));
        assert_eq!(s.get("k").unwrap(), 42);
        assert!(s.get("nope").is_none());
    }

    #[test]
    fn dht_hs_roundtrip() {
        let s = DhtStore::new();
        let d = HsDescriptor {
            hs_id: "ab12345678901234abcd".into(),
            name: "test".into(),
            intro_pub: "deadbeef".into(),
            intro_host: Some("1.2.3.4".into()),
            intro_port: Some(8080),
            intro_node_id: String::new(),
            identity_pub: String::new(),
            epoch: 0,
            sig: String::new(),
            blinded_pub: String::new(),
            client_auth: None,
        };
        s.put_hs(&d);
        let got = s.get_hs("ab12345678901234abcd").unwrap();
        assert_eq!(got.name, "test");
    }
}
