use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::{CryptoError, SecureRandom};

/// A user-supplied recovery credential whose bytes are preserved exactly.
pub struct RecoveryPassphrase(SecretString);

impl RecoveryPassphrase {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value.into())
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    pub(crate) fn from_secret(value: SecretString) -> Self {
        Self(value)
    }
}

macro_rules! secret_key {
    ($name:ident) => {
        pub struct $name(SecretBox<[u8; 32]>);

        impl $name {
            pub(crate) fn from_boxed_bytes(bytes: Box<[u8; 32]>) -> Self {
                Self(SecretBox::new(bytes))
            }

            #[allow(dead_code)]
            pub(crate) fn expose_secret(&self) -> &[u8; 32] {
                self.0.expose_secret()
            }
        }
    };
}

secret_key!(VaultRootKey);
secret_key!(RecoveryWrappingKey);
secret_key!(MetadataKey);
secret_key!(SnapshotAuthenticationKey);
secret_key!(ChunkFingerprintKey);
secret_key!(ContentWrappingKey);
secret_key!(LocalVerificationKey);
secret_key!(DeviceWrappingKey);

impl VaultRootKey {
    pub fn generate(random: &mut dyn SecureRandom) -> Result<Self, CryptoError> {
        let mut bytes = Box::new([0_u8; 32]);
        if let Err(error) = random.fill(bytes.as_mut()) {
            zeroize::Zeroize::zeroize(bytes.as_mut());
            return Err(error);
        }
        Ok(Self::from_boxed_bytes(bytes))
    }
}

impl DeviceWrappingKey {
    pub fn try_from_protected_bytes(mut bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            zeroize::Zeroize::zeroize(&mut bytes);
            return Err(CryptoError::InvalidPlaintextLength);
        }
        let mut key = Box::new([0_u8; 32]);
        key.copy_from_slice(&bytes);
        zeroize::Zeroize::zeroize(&mut bytes);
        Ok(Self::from_boxed_bytes(key))
    }
}
