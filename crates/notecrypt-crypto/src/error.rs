use thiserror::Error;

/// Stable, non-sensitive failures from cryptographic operations.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("the secure random source failed")]
    RandomSource,
    #[error("the recovery passphrase does not meet policy")]
    PassphrasePolicy,
    #[error("the key derivation parameters are outside the supported profile")]
    InvalidKdfParameters,
    #[error("the operation was cancelled at a safe boundary")]
    Cancelled,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("secure key-derivation memory could not be allocated")]
    Allocation,
    #[error("the requested key-derivation calibration could not be reached safely")]
    CalibrationFailed,
    #[error("the public cryptographic envelope is invalid")]
    InvalidEnvelope,
    #[error("authentication failed")]
    Authentication,
    #[error("the protected value exceeds its profile limit")]
    PlaintextTooLarge,
    #[error("the protected value has the wrong length")]
    InvalidPlaintextLength,
}
