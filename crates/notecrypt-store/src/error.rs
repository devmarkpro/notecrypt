use std::io;

/// Stable failures returned by the encrypted storage boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("the filesystem cannot provide the required durability guarantee")]
    UnsupportedDurability,
    #[error("a filesystem object does not satisfy the vault safety policy")]
    FilesystemObjectRejected,
    #[error("an immutable object already exists with different bytes")]
    ImmutableObjectConflict,
    #[error("the unlocked vault session is locked")]
    Locked,
    #[error("local trusted state authentication failed")]
    LocalStateAuthenticationFailed,
    #[error("vault rollback was detected")]
    RollbackDetected,
    #[error("an authentication check failed")]
    AuthenticationFailed,
    #[error("an operation exceeded its configured resource limit")]
    LimitExceeded,
    #[error("the operation was cancelled")]
    Cancelled,
    #[error("the operation timed out")]
    TimedOut,
    #[error("a one-time capability was stale, mismatched, or already consumed")]
    InvalidCapability,
    #[error("another process owns the vault mutation lock")]
    Busy,
    #[error("the filesystem mutation took effect but still requires directory synchronization")]
    DurabilityPending,
    #[cfg(feature = "test-support")]
    #[error("test-only simulated process crash")]
    SimulatedCrash,
    #[error("the requested object was not found")]
    NotFound,
    #[error("the encrypted object is malformed or unsupported")]
    MalformedObject,
    #[error("the operating-system random source failed")]
    RandomSource,
    #[error("fresh identity generation exhausted its collision retry budget")]
    IdentityCollision,
    #[error("the session generation counter is exhausted")]
    SessionGenerationExhausted,
    #[error("operation failed and owned staging cleanup also failed")]
    CleanupAfterFailure {
        primary: Box<StoreError>,
        cleanup: io::Error,
    },
    #[error("the storage operation failed")]
    Io(#[source] io::Error),
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<notecrypt_format::FormatError> for StoreError {
    fn from(_: notecrypt_format::FormatError) -> Self {
        Self::MalformedObject
    }
}

impl From<notecrypt_crypto::CryptoError> for StoreError {
    fn from(_: notecrypt_crypto::CryptoError) -> Self {
        Self::AuthenticationFailed
    }
}
