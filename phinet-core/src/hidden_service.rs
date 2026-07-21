// phinet-core/src/hidden_service.rs
//! ΦNET Hidden Services

use crate::{
    cert::PhiCert,
    crypto::blake2b_256,
    pow::{IntroPuzzle, IntroPuzzleSolution, PuzzleController},
    store::SiteStore,
    wire::HsDescriptor,
    Result,
};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Hidden service ────────────────────────────────────────────────────

pub struct HiddenService {
    pub hs_id:     String,
    pub name:      String,
    pub nonce:     [u8; 16],
    intro_secret:  StaticSecret,
    pub intro_pub: PublicKey,
    puzzle_ctl:    Mutex<PuzzleController>,
    rendezvous:    RwLock<HashMap<[u8; 32], RendezvousSlot>>,
    /// Long-term Ed25519 identity key for signing descriptors. Kept
    /// alongside the service; the `hs_id` field is derived from this
    /// identity so the two stay consistent.
    pub identity:  crate::hs_identity::HsIdentity,
    /// The (host, port) last published in a descriptor. Used by the
    /// periodic republishing loop to sign a fresh descriptor for the
    /// current epoch. `None` until the service has been published at
    /// least once.
    pub published_endpoint: RwLock<Option<(String, u16)>>,
}

#[allow(dead_code)]
struct RendezvousSlot {
    pub rend_host: String,
    pub rend_port: u16,
    pub created:   std::time::Instant,
}

impl HiddenService {
    pub fn new(_cert: &PhiCert, name: &str) -> Self {
        let intro_secret = StaticSecret::random_from_rng(OsRng);
        let intro_pub    = PublicKey::from(&intro_secret);
        let mut nonce    = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        // Generate a fresh HS identity; `hs_id` is derived from it,
        // not from (cert, nonce, name). Operators who want a stable
        // identity across restarts should use `from_identity` below
        // with a previously-saved HsIdentity.
        let identity = crate::hs_identity::HsIdentity::generate();
        let hs_id    = identity.hs_id();

        HiddenService {
            hs_id,
            name:        name.to_string(),
            nonce,
            intro_secret,
            intro_pub,
            puzzle_ctl:  Mutex::new(PuzzleController::new(5.0)),
            rendezvous:  RwLock::new(HashMap::new()),
            identity,
            published_endpoint: RwLock::new(None),
        }
    }

    /// Construct from a pre-existing HS identity (e.g. loaded from
    /// disk by an operator who wants a persistent hs_id).
    pub fn from_identity(
        identity: crate::hs_identity::HsIdentity,
        name: &str,
    ) -> Self {
        let intro_secret = StaticSecret::random_from_rng(OsRng);
        let intro_pub    = PublicKey::from(&intro_secret);
        let mut nonce    = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let hs_id = identity.hs_id();
        HiddenService {
            hs_id,
            name:        name.to_string(),
            nonce,
            intro_secret,
            intro_pub,
            puzzle_ctl:  Mutex::new(PuzzleController::new(5.0)),
            rendezvous:  RwLock::new(HashMap::new()),
            identity,
            published_endpoint: RwLock::new(None),
        }
    }

    pub fn descriptor(&self, intro_host: Option<&str>, intro_port: Option<u16>) -> HsDescriptor {
        HsDescriptor {
            hs_id:      self.hs_id.clone(),
            name:       self.name.clone(),
            intro_pub:  hex::encode(self.intro_pub.as_bytes()),
            intro_host: intro_host.map(|s| s.to_string()),
            intro_port,
            intro_node_id: String::new(),
            identity_pub: String::new(),
            epoch:        0,
            sig:          String::new(),
            blinded_pub:  String::new(),
            client_auth:  None,
        }
    }

    /// Build a client-authorized descriptor.
    ///
    /// The intro point fields (intro_pub, intro_host, intro_port)
    /// are encrypted to the set of authorized clients via
    /// `client_auth::encrypt_intro_for_clients`. The plaintext
    /// fields are left empty in the resulting descriptor — only
    /// authorized clients can recover them.
    ///
    /// `client_pubs` is the list of authorized clients' X25519
    /// public keys (32 bytes each). The descriptor will fail to
    /// build if this list is empty (would result in a permanently
    /// inaccessible service).
    ///
    /// The returned descriptor is unsigned; pass to `sign_descriptor`
    /// to produce a publishable copy.
    pub fn descriptor_with_client_auth(
        &self,
        intro_host: Option<&str>,
        intro_port: Option<u16>,
        client_pubs: &[[u8; 32]],
    ) -> Result<HsDescriptor> {
        use crate::client_auth::{encrypt_intro_for_clients, IntroPointSecret};

        let intro = IntroPointSecret {
            intro_pub:  hex::encode(self.intro_pub.as_bytes()),
            intro_host: intro_host.map(|s| s.to_string()),
            intro_port,
            intro_node_id: String::new(),
        };
        let block = encrypt_intro_for_clients(&intro, client_pubs)?;

        Ok(HsDescriptor {
            hs_id:        self.hs_id.clone(),
            name:         self.name.clone(),
            intro_pub:    String::new(),       // hidden behind client_auth
            intro_host:   None,
            intro_port:   None,
            intro_node_id: String::new(),      // hidden behind client_auth
            identity_pub: String::new(),
            epoch:        0,
            sig:          String::new(),
            blinded_pub:  String::new(),
            client_auth:  Some(block),
        })
    }

    pub fn issue_puzzle(&self) -> IntroPuzzle {
        let d = self.puzzle_ctl.lock().unwrap().record_request();
        IntroPuzzle::generate(d)
    }

    pub fn verify_puzzle(&self, puzzle: &IntroPuzzle, sol: &IntroPuzzleSolution) -> bool {
        puzzle.is_fresh() && puzzle.verify(sol)
    }

    pub fn rotate_intro_key(&mut self) {
        self.intro_secret = StaticSecret::random_from_rng(OsRng);
        self.intro_pub    = PublicKey::from(&self.intro_secret);
    }

    pub async fn evict_old_rendezvous(&self) {
        self.rendezvous.write().await
            .retain(|_, s| s.created.elapsed() < std::time::Duration::from_secs(600));
    }
}

/// Derive hs_id = hex(BLAKE2b-256(J ‖ nonce ‖ name)[..20]).
pub fn derive_hs_id(j_bytes: &[u8], nonce: &[u8; 16], name: &str) -> String {
    let mut input = Vec::with_capacity(j_bytes.len() + 16 + name.len());
    input.extend_from_slice(j_bytes);
    input.extend_from_slice(nonce);
    input.extend_from_slice(name.as_bytes());
    hex::encode(&blake2b_256(&input)[..20])
}

// ── HS manager ────────────────────────────────────────────────────────

pub struct HsManager {
    services: RwLock<HashMap<String, Arc<HiddenService>>>,
    store:    Arc<SiteStore>,
}

impl HsManager {
    pub fn new(store: Arc<SiteStore>) -> Self {
        Self { services: RwLock::new(HashMap::new()), store }
    }

    pub async fn register(&self, cert: &PhiCert, name: &str) -> Arc<HiddenService> {
        // Load an existing HS identity from disk if present, else
        // generate a fresh one and save it. This keeps the hs_id
        // stable across daemon restarts — without persistence, every
        // restart would produce a new hs_id and all previously-
        // published links would break.
        let path = crate::store::hs_identity_path(name);
        let identity = if path.exists() {
            match crate::hs_identity::HsIdentity::load(&path) {
                Ok(id) => {
                    tracing::info!(
                        "HS identity loaded from {} (hs_id={})",
                        path.display(), id.hs_id()
                    );
                    id
                }
                Err(e) => {
                    // If the file is corrupt, fall back to generating
                    // a fresh identity rather than failing the whole
                    // registration. The operator should investigate,
                    // but a broken file shouldn't prevent serving.
                    tracing::warn!(
                        "HS identity at {} is unreadable ({}); generating fresh",
                        path.display(), e
                    );
                    let id = crate::hs_identity::HsIdentity::generate();
                    if let Err(se) = id.save(&path) {
                        tracing::warn!("HS identity save failed: {}", se);
                    }
                    id
                }
            }
        } else {
            let id = crate::hs_identity::HsIdentity::generate();
            if let Err(e) = id.save(&path) {
                tracing::warn!("HS identity save failed for {}: {}",
                               path.display(), e);
            } else {
                tracing::info!(
                    "HS identity generated and saved to {} (hs_id={})",
                    path.display(), id.hs_id()
                );
            }
            id
        };

        // Discard the unused cert param (legacy signature compat);
        // from_identity uses the loaded/generated HsIdentity directly.
        let _ = cert;

        let hs = Arc::new(HiddenService::from_identity(identity, name));
        self.services.write().await.insert(hs.hs_id.clone(), Arc::clone(&hs));
        tracing::info!("HS registered: {} ({})", hs.hs_id, name);
        hs
    }

    pub async fn get(&self, hs_id: &str) -> Option<Arc<HiddenService>> {
        self.services.read().await.get(hs_id).cloned()
    }

    pub async fn list(&self) -> Vec<String> {
        self.services.read().await.keys().cloned().collect()
    }

    /// Serve an HTTP request from the local disk store.
    pub async fn serve_http(&self, hs_id: &str, path: &str) -> Option<(u16, String, Vec<u8>)> {
        self.store.get_file(hs_id, path).await
    }
}

// ── PIR-style oblivious lookup ────────────────────────────────────────

/// Return a shuffled batch of DHT keys that hides which hs_id we want.
pub fn pir_query_keys(hs_id: &str, noise: usize) -> Vec<String> {
    let mut keys = vec![format!("hs:{}", hs_id)];
    for _ in 0..noise {
        let mut rnd = [0u8; 10];
        OsRng.fill_bytes(&mut rnd);
        keys.push(format!("hs:{}", hex::encode(rnd)));
    }
    keys.shuffle(&mut OsRng);
    keys
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{CertBits, PhiCert};

    fn cert() -> PhiCert { PhiCert::generate(CertBits::B256).unwrap() }

    #[test]
    fn hs_id_is_64_hex() {
        // hs_id is now derived from the HS's Ed25519 identity key:
        // SHA-256(tag || pub) → 32 bytes → 64 hex chars. Previously
        // this was BLAKE2b(cert ‖ nonce ‖ name)[..20] → 40 hex.
        let c  = cert();
        let hs = HiddenService::new(&c, "site");
        assert_eq!(hs.hs_id.len(), 64);
        assert!(hs.hs_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hs_id_matches_derived_from_identity() {
        let c  = cert();
        let hs = HiddenService::new(&c, "site");
        // The hs_id must equal what the identity module would derive
        // from the HS's identity pub. This is what clients use to
        // verify descriptors.
        assert_eq!(
            hs.hs_id,
            crate::hs_identity::derive_hs_id(&hs.identity.public_key())
        );
    }

    #[test]
    fn hs_id_deterministic() {
        let j = b"jbytes";
        let n = [0u8; 16];
        assert_eq!(derive_hs_id(j, &n, "a"), derive_hs_id(j, &n, "a"));
        assert_ne!(derive_hs_id(j, &n, "a"), derive_hs_id(j, &n, "b"));
    }

    #[test]
    fn puzzle_roundtrip() {
        let c      = cert();
        let hs     = HiddenService::new(&c, "t");
        let puzzle = hs.issue_puzzle();
        let sol    = puzzle.solve().unwrap();
        assert!(hs.verify_puzzle(&puzzle, &sol));
    }

    #[test]
    fn pir_contains_real_key() {
        let keys = pir_query_keys("aabbccdd1122334455aa", 7);
        assert_eq!(keys.len(), 8);
        assert!(keys.contains(&"hs:aabbccdd1122334455aa".to_string()));
    }

    #[tokio::test]
    async fn manager_register_get() {
        let store = Arc::new(SiteStore::new_test());
        let mgr   = HsManager::new(store);
        let c     = cert();
        let hs    = mgr.register(&c, "svc").await;
        assert_eq!(mgr.get(&hs.hs_id).await.unwrap().name, "svc");
    }

    /// Helper: run a test inside a fresh HOME so the stable-hs_id test
    /// doesn't collide with other tests' HS files or the user's real
    /// ~/.phinet directory.
    fn with_home<F, R>(f: F) -> R
    where F: FnOnce() -> R,
    {
        let tmp = tempfile::tempdir().unwrap();
        let old = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());
        let r = f();
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None    => std::env::remove_var("HOME"),
        }
        drop(tmp);
        r
    }

    // These two tests share HOME mutation, so they must serialize.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn hs_id_is_stable_across_re_register() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_home(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let store = Arc::new(SiteStore::new_test());
                let mgr1  = HsManager::new(Arc::clone(&store));
                let c     = cert();

                // First registration — generates identity, saves to disk
                let hs1 = mgr1.register(&c, "blog").await;
                let id1 = hs1.hs_id.clone();

                // Second registration (e.g. daemon restart, new manager)
                // — should LOAD the saved identity, not generate fresh
                let mgr2 = HsManager::new(store);
                let hs2  = mgr2.register(&c, "blog").await;

                assert_eq!(hs1.hs_id, hs2.hs_id,
                    "hs_id must be stable across re-registrations — \
                     otherwise previously-published links break on restart");
                assert_eq!(id1, hs2.hs_id);
            });
        });
    }

    #[test]
    fn different_service_names_have_different_persistent_ids() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_home(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let store = Arc::new(SiteStore::new_test());
                let mgr   = HsManager::new(store);
                let c     = cert();

                let hs_a = mgr.register(&c, "blog").await;
                let hs_b = mgr.register(&c, "shop").await;
                assert_ne!(hs_a.hs_id, hs_b.hs_id,
                    "different service names must get different identities");
            });
        });
    }

    #[test]
    fn hs_identity_path_sanitizes_dangerous_chars() {
        let p = crate::store::hs_identity_path("../../../etc/passwd");
        let s = p.to_string_lossy();
        // Path traversal must be neutralized
        assert!(!s.contains("/etc/"),
            "path traversal must be blocked: got {}", s);
        // Spaces / slashes normalize to _
        let p2 = crate::store::hs_identity_path("my svc/with slash");
        assert!(p2.file_name().unwrap().to_string_lossy()
                .starts_with("hs_identity_my_svc_with_slash"));
    }
}
