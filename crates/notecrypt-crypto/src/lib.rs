//! Cryptographic composition for Notecrypt.

mod aead;
mod error;
mod kdf;
mod keys;
mod recovery;
mod secret;
mod stream;

pub use aead::*;
pub use error::CryptoError;
pub use kdf::{
    Argon2idParameters, ValidatedArgon2idParameters, calibrate_argon2id,
    derive_recovery_wrapping_key,
};
pub use keys::{VaultKeys, derive_vault_keys};
pub use recovery::{
    CustomPassphrasePolicy, OFFLINE_VERIFIER_DISCLOSURE, RecoveryPhrase, generate_recovery_phrase,
    validate_custom_passphrase,
};
pub use secret::{
    ChunkFingerprintKey, ContentWrappingKey, DeviceWrappingKey, LocalVerificationKey, MetadataKey,
    RecoveryPassphrase, RecoveryWrappingKey, SnapshotAuthenticationKey, VaultRootKey,
};
pub use stream::*;

/// Fallible cryptographically secure randomness used at atomic construction boundaries.
pub trait SecureRandom: Send {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError>;
}

/// Operating-system randomness for production composition roots.
pub struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(destination).map_err(|_| CryptoError::RandomSource)
    }
}
