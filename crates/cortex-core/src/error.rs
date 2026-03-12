use thiserror::Error;

#[derive(Error, Debug)]
pub enum CortexError {
    #[error("JIS access denied: required level {required}, got {actual}")]
    JisAccessDenied { required: u8, actual: u8 },

    #[error("JIS claim expired at {expired_at}")]
    JisClaimExpired { expired_at: String },

    #[error("JIS claim dimension mismatch: {dimension}")]
    JisDimensionMismatch { dimension: String },

    #[error("Airlock violation: {0}")]
    AirlockViolation(String),

    #[error("Airlock already sealed")]
    AirlockSealed,

    #[error("TIBET integrity check failed: expected {expected}, got {actual}")]
    TibetIntegrityFailed { expected: String, actual: String },

    #[error("TIBET chain broken at token {token_id}")]
    TibetChainBroken { token_id: String },

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("Envelope corrupted: {0}")]
    EnvelopeCorrupted(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type CortexResult<T> = Result<T, CortexError>;
