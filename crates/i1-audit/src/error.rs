//! Error types for the audit system.

use thiserror::Error;

/// Result type alias for audit operations.
pub type Result<T> = std::result::Result<T, AuditError>;

/// Errors that can occur during audit operations.
#[derive(Error, Debug)]
pub enum AuditError {
    /// File I/O error
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    /// Failed to hash a file
    #[error("hashing failed for {path}: {reason}")]
    Hash { path: String, reason: String },

    /// Process discovery error
    #[error("process discovery error: {0}")]
    Process(String),

    /// Certificate parsing error
    #[error("certificate parse error in {path}: {reason}")]
    CertParse { path: String, reason: String },

    /// PEM decoding error
    #[error("PEM decode error in {path}: {reason}")]
    PemDecode { path: String, reason: String },

    /// DNS consensus query failed
    #[error("DNS consensus query failed: {0}")]
    DnsQuery(String),

    /// Encoding error
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Walk directory error
    #[error("directory walk error: {0}")]
    Walk(String),

    /// procfs error (Linux only)
    #[cfg(target_os = "linux")]
    #[error("procfs error: {0}")]
    Procfs(String),
}

impl AuditError {
    /// Create an I/O error with path context.
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
