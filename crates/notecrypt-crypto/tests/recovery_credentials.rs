use std::sync::atomic::AtomicBool;

use notecrypt_crypto::{
    Argon2idParameters, AuthenticatedHeadContext, CryptoError, CustomPassphrasePolicy,
    OFFLINE_VERIFIER_DISCLOSURE, PublicEnvelopeIdentity, RecoveryPassphrase, RecoverySlotContext,
    RecoverySlotPlaintext, SecureRandom, ValidatedArgon2idParameters, VaultRootKey,
    authenticate_head, decrypt_recovery_slot, derive_recovery_wrapping_key, derive_vault_keys,
    encrypt_recovery_slot, generate_recovery_phrase, validate_custom_passphrase,
};

struct FixedRandom {
    bytes: Vec<u8>,
    calls: usize,
}

impl FixedRandom {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, calls: 0 }
    }
}

impl SecureRandom for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        self.calls += 1;
        assert_eq!(destination.len(), self.bytes.len());
        destination.copy_from_slice(&self.bytes);
        Ok(())
    }
}

struct FailingRandom;

impl SecureRandom for FailingRandom {
    fn fill(&mut self, _destination: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::RandomSource)
    }
}

fn error_of<T>(result: Result<T, CryptoError>) -> CryptoError {
    match result {
        Ok(_) => panic!("expected a crypto error"),
        Err(error) => error,
    }
}

#[test]
fn generated_phrase_uses_exactly_128_bits_and_has_a_valid_checksum() {
    let mut random = FixedRandom::new(vec![0; 16]);

    let phrase = generate_recovery_phrase(&mut random).unwrap();

    assert_eq!(random.calls, 1);
    assert_eq!(phrase.word_count(), 12);
    phrase.present_once(|_| Ok::<(), ()>(())).unwrap();
}

#[test]
fn random_failure_returns_no_recovery_phrase() {
    assert_eq!(
        error_of(generate_recovery_phrase(&mut FailingRandom)),
        CryptoError::RandomSource,
    );
}

#[test]
fn custom_passphrase_policy_is_byte_preserving_and_bounded() {
    let accepted = "alpha beta gamma delta café";
    let passphrase = RecoveryPassphrase::new(accepted.to_owned());
    assert!(validate_custom_passphrase(passphrase, CustomPassphrasePolicy::V1).is_ok());

    for rejected in [
        "one two three four",
        "one two three four five\0",
        "a b c d e",
        &"x".repeat(1_025),
    ] {
        assert_eq!(
            error_of(validate_custom_passphrase(
                RecoveryPassphrase::new(rejected.to_owned()),
                CustomPassphrasePolicy::V1,
            )),
            CryptoError::PassphrasePolicy,
        );
    }
}

#[test]
fn custom_passphrase_policy_accepts_exact_byte_boundaries() {
    let minimum = "aaa aaa aaa aaa aaaa";
    let maximum = format!("a b c d {}", "x".repeat(1_016));
    assert_eq!(minimum.len(), 20);
    assert_eq!(maximum.len(), 1_024);

    for value in [minimum.to_owned(), maximum] {
        assert!(
            validate_custom_passphrase(RecoveryPassphrase::new(value), CustomPassphrasePolicy::V1,)
                .is_ok()
        );
    }
}

#[test]
fn argon2_profile_rejects_every_out_of_range_field() {
    let floor = Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };
    let ceiling = Argon2idParameters {
        memory_kib: 1_048_576,
        iterations: 10,
        parallelism: 16,
    };
    assert!(ValidatedArgon2idParameters::try_from(floor).is_ok());
    assert!(ValidatedArgon2idParameters::try_from(ceiling).is_ok());

    for invalid in [
        Argon2idParameters {
            memory_kib: 0,
            ..floor
        },
        Argon2idParameters {
            memory_kib: 65_535,
            ..floor
        },
        Argon2idParameters {
            memory_kib: 1_048_577,
            ..floor
        },
        Argon2idParameters {
            memory_kib: u32::MAX,
            ..floor
        },
        Argon2idParameters {
            iterations: 0,
            ..floor
        },
        Argon2idParameters {
            iterations: 2,
            ..floor
        },
        Argon2idParameters {
            iterations: 11,
            ..floor
        },
        Argon2idParameters {
            iterations: u32::MAX,
            ..floor
        },
        Argon2idParameters {
            parallelism: 0,
            ..floor
        },
        Argon2idParameters {
            parallelism: 17,
            ..floor
        },
        Argon2idParameters {
            parallelism: u32::MAX,
            ..floor
        },
    ] {
        assert_eq!(
            error_of(ValidatedArgon2idParameters::try_from(invalid)),
            CryptoError::InvalidKdfParameters,
        );
    }
}

#[test]
fn cancellation_is_checked_before_argon2() {
    let cancelled = AtomicBool::new(true);
    let parameters = ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap();

    let result = notecrypt_crypto::derive_recovery_wrapping_key(
        &RecoveryPassphrase::new("alpha beta gamma delta epsilon".to_owned()),
        &[7; 16],
        parameters,
        &cancelled,
    );

    assert_eq!(error_of(result), CryptoError::Cancelled);
}

#[test]
fn direct_invalid_recovery_input_cannot_reach_argon2() {
    let parameters = ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap();

    let result = derive_recovery_wrapping_key(
        &RecoveryPassphrase::new("weak".to_owned()),
        &[7; 16],
        parameters,
        &AtomicBool::new(false),
    );

    assert!(matches!(result, Err(CryptoError::PassphrasePolicy)));
}

#[test]
fn recovery_slot_round_trips_and_wrong_credentials_fail() {
    let parameters = || {
        ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        })
        .unwrap()
    };
    let cancelled = AtomicBool::new(false);
    let correct = RecoveryPassphrase::new("alpha beta gamma delta epsilon".to_owned());
    let wrong = RecoveryPassphrase::new("wrong beta gamma delta epsilon".to_owned());
    let correct_key =
        derive_recovery_wrapping_key(&correct, &[7; 16], parameters(), &cancelled).unwrap();
    let wrong_key =
        derive_recovery_wrapping_key(&wrong, &[7; 16], parameters(), &cancelled).unwrap();
    let changed_salt_key =
        derive_recovery_wrapping_key(&correct, &[8; 16], parameters(), &cancelled).unwrap();

    let mut root_random = FixedRandom::new(vec![11; 32]);
    let root = VaultRootKey::generate(&mut root_random).unwrap();
    let slot_context = RecoverySlotContext::try_new(PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [1; 16],
        object_kind: RecoverySlotContext::OBJECT_KIND,
        format_version: 1,
        object_id: [2; 32],
    })
    .unwrap();
    let mut nonce_random = FixedRandom::new(vec![3; 24]);
    let slot = encrypt_recovery_slot(
        &slot_context,
        RecoverySlotPlaintext::from_root_key(&root),
        &correct_key,
        &mut nonce_random,
    )
    .unwrap();
    let recovered = decrypt_recovery_slot(&slot_context, &slot, &correct_key)
        .unwrap()
        .into_root_key();

    let head_context = AuthenticatedHeadContext::try_new(PublicEnvelopeIdentity {
        object_kind: AuthenticatedHeadContext::OBJECT_KIND,
        ..*slot_context.identity()
    })
    .unwrap();
    let original_mac = authenticate_head(
        &head_context,
        b"canonical head",
        &derive_vault_keys(&root).unwrap().snapshot_authentication,
    )
    .unwrap();
    let recovered_mac = authenticate_head(
        &head_context,
        b"canonical head",
        &derive_vault_keys(&recovered)
            .unwrap()
            .snapshot_authentication,
    )
    .unwrap();
    assert_eq!(original_mac.as_bytes(), recovered_mac.as_bytes());

    for rejected_key in [&wrong_key, &changed_salt_key] {
        assert!(matches!(
            decrypt_recovery_slot(&slot_context, &slot, rejected_key),
            Err(CryptoError::Authentication),
        ));
    }
}

#[test]
fn offline_verifier_disclosure_is_explicit() {
    assert!(OFFLINE_VERIFIER_DISCLOSURE.contains("offline"));
    assert!(OFFLINE_VERIFIER_DISCLOSURE.contains("weak custom passphrase"));
}

#[test]
fn partial_random_failure_returns_no_root_key() {
    struct PartialFailure;
    impl SecureRandom for PartialFailure {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            let midpoint = destination.len() / 2;
            destination[..midpoint].fill(99);
            Err(CryptoError::RandomSource)
        }
    }

    assert!(matches!(
        VaultRootKey::generate(&mut PartialFailure),
        Err(CryptoError::RandomSource),
    ));
}
