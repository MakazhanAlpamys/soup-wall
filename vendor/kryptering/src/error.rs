/// Errors produced by kryptering cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("{backend} does not support {operation:?} ({algorithm})")]
    UnsupportedAlgorithm {
        backend: crate::backend::BackendId,
        operation: crate::backend::Operation,
        algorithm: String,
    },

    #[error("cryptographic backend {backend} has not been explicitly initialized")]
    BackendNotInitialized { backend: crate::backend::BackendId },

    #[error("failed to initialize cryptographic backend {backend}: {message}")]
    BackendInitialization {
        backend: crate::backend::BackendId,
        message: String,
    },

    #[error("FIPS mode is unavailable for {backend}: {message}")]
    FipsUnavailable {
        backend: crate::backend::BackendId,
        message: String,
    },

    #[error("key error: {0}")]
    Key(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(all(feature = "pkcs11", not(target_arch = "wasm32")))]
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),
}

impl Error {
    /// Construct a deterministic unsupported-operation error for the selected provider.
    pub fn unsupported(operation: crate::backend::Operation, algorithm: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm {
            backend: crate::backend::selected_backend(),
            operation,
            algorithm: algorithm.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
