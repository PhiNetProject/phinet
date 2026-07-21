// phinet-core/src/lib.rs
//! ΦNET Core Library
//!
//! All cryptographic primitives, certificate logic, onion routing,
//! DHT, hidden services, and message board for the ΦNET overlay network.

pub mod cert;
pub mod crypto;
pub mod ntor;
pub mod pow;
pub mod session;
pub mod shared_random;
pub mod wire;
pub mod onion;
pub mod circuit;
pub mod circuit_mgr;
pub mod circuit_pool;
pub mod circuit_sched;
pub mod circuit_timing;
pub mod rendezvous;
pub mod hs_identity;
pub mod hs_blind;
pub mod hsdir_ring;
pub mod guard_sample;
pub mod guards;
pub mod relay_desc;
pub mod replay;
pub mod timing;
pub mod stream;
pub mod congestion;
pub mod com;
pub mod exit_policy;
pub mod dht;
pub mod dos;
pub mod hidden_service;
pub mod board;
pub mod node;
pub mod directory;
pub mod transport;
pub mod path_bias;
pub mod path_select;
pub mod consensus_fetch;
pub mod padding;
pub mod client_auth;
pub mod vanguards;
pub mod store;
pub mod error;

pub use error::{Error, Result};

/// Re-export x25519_dalek so downstream crates can use the same
/// version without taking a direct dependency. Used by the daemon's
/// `hs_auth_gen_client` control command.
pub use x25519_dalek;

/// Restrict a file to owner-only read/write on Unix (0o600). No-op
/// on non-Unix. Best-effort: logs but doesn't fail if the chmod fails.
pub fn secure_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(
            path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!("chmod 600 {}: {}", path.display(), e);
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}
