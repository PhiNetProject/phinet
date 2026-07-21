// phinet-core/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid certificate: {0}")]
    InvalidCert(String),

    #[error("proof-of-work failed: {0}")]
    PowFailed(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("authentication failure")]
    AuthFailed,

    #[error("handshake error: {0}")]
    Handshake(String),

    #[error("onion routing error: {0}")]
    Onion(String),

    #[error("DHT error: {0}")]
    Dht(String),

    #[error("hidden service error: {0}")]
    HiddenService(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("connection closed")]
    Closed,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("rate limited")]
    RateLimited,

    #[error("puzzle required")]
    PuzzleRequired,
}

pub type Result<T> = std::result::Result<T, Error>;
