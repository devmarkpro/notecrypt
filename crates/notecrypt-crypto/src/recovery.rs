use bip39::{Language, Mnemonic};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::{CryptoError, RecoveryPassphrase, SecureRandom};

pub const OFFLINE_VERIFIER_DISCLOSURE: &str = "The public vault bootstrap permits offline recovery-credential guesses. Argon2id slows guesses but cannot make a weak custom passphrase strong.";

/// A generated BIP39 English recovery phrase held in zeroizing storage.
pub struct RecoveryPhrase(SecretString);

impl RecoveryPhrase {
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.0.expose_secret().split_whitespace().count()
    }

    /// Consumes the phrase at the one-time presentation boundary.
    pub fn present_once<E>(self, presenter: impl FnOnce(&str) -> Result<(), E>) -> Result<(), E> {
        presenter(self.0.expose_secret())
    }

    #[must_use]
    pub fn into_passphrase(self) -> RecoveryPassphrase {
        let Self(secret) = self;
        RecoveryPassphrase::from_secret(secret)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CustomPassphrasePolicy {
    V1,
}

pub fn generate_recovery_phrase(
    random: &mut dyn SecureRandom,
) -> Result<RecoveryPhrase, CryptoError> {
    let mut entropy = Zeroizing::new([0_u8; 16]);
    random.fill(entropy.as_mut())?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
        .map_err(|_| CryptoError::RandomSource)?;
    Ok(RecoveryPhrase(mnemonic.to_string().into()))
}

pub fn validate_custom_passphrase(
    passphrase: RecoveryPassphrase,
    policy: CustomPassphrasePolicy,
) -> Result<RecoveryPassphrase, CryptoError> {
    match policy {
        CustomPassphrasePolicy::V1 => validate_v1(passphrase),
    }
}

fn validate_v1(passphrase: RecoveryPassphrase) -> Result<RecoveryPassphrase, CryptoError> {
    validate_recovery_passphrase(&passphrase)?;
    Ok(passphrase)
}

pub(crate) fn validate_recovery_passphrase(
    passphrase: &RecoveryPassphrase,
) -> Result<(), CryptoError> {
    let value = passphrase.expose_secret();
    if !(20..=1_024).contains(&value.len())
        || value.contains('\0')
        || value.split_whitespace().count() < 5
    {
        return Err(CryptoError::PassphrasePolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bip39::{Language, Mnemonic};

    use super::{CustomPassphrasePolicy, generate_recovery_phrase, validate_custom_passphrase};
    use crate::{CryptoError, RecoveryPassphrase, SecureRandom};

    #[test]
    fn custom_policy_preserves_unicode_bytes_without_normalization() {
        let composed = validate_custom_passphrase(
            RecoveryPassphrase::new("alpha beta gamma delta café".to_owned()),
            CustomPassphrasePolicy::V1,
        )
        .unwrap();
        let decomposed = validate_custom_passphrase(
            RecoveryPassphrase::new("alpha beta gamma delta cafe\u{301}".to_owned()),
            CustomPassphrasePolicy::V1,
        )
        .unwrap();

        assert_ne!(composed.expose_secret(), decomposed.expose_secret());
    }

    #[test]
    fn all_zero_entropy_matches_the_official_twelve_word_vector() {
        struct ZeroRandom;
        impl SecureRandom for ZeroRandom {
            fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
                destination.fill(0);
                Ok(())
            }
        }

        let phrase = generate_recovery_phrase(&mut ZeroRandom).unwrap();
        phrase
            .present_once(|words| {
                assert_eq!(
                    words,
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                );
                let decoded = Mnemonic::parse_in_normalized(Language::English, words).unwrap();
                assert_eq!(decoded.to_entropy(), [0_u8; 16]);
                let corrupted = words.replace("about", "abandon");
                assert!(Mnemonic::parse_in_normalized(Language::English, &corrupted).is_err());
                Ok::<(), ()>(())
            })
            .unwrap();
    }
}
