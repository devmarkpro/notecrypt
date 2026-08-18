use notecrypt_crypto::{
    AeadEnvelopeParts, AuthenticatedHeadContext, CryptoError, DeviceSlotContext,
    DeviceSlotEnvelope, DeviceSlotPlaintext, DeviceWrappingKey, HeadAuthenticator,
    LocalStateAuthenticator, LocalStateContext, ManifestContext, ManifestEnvelope,
    ManifestPlaintext, MetadataContext, MetadataEnvelope, MetadataPlaintext,
    PublicEnvelopeIdentity, RecoverySlotContext, RecoverySlotEnvelope, SecureRandom,
    SnapshotContext, SnapshotEnvelope, SnapshotPlaintext, TreeContext, TreeEnvelope, TreePlaintext,
    TypedAeadEnvelope, VaultRootKey, authenticate_head, authenticate_local_state,
    decrypt_device_slot, decrypt_manifest, decrypt_metadata, decrypt_snapshot, decrypt_tree,
    derive_vault_keys, encrypt_device_slot, encrypt_manifest, encrypt_metadata, encrypt_snapshot,
    encrypt_tree, verify_head, verify_local_state,
};

fn identity(kind: u8) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [1; 16],
        object_kind: kind,
        format_version: 1,
        object_id: [2; 32],
    }
}

fn parts(kind: u8, ciphertext_len: usize) -> AeadEnvelopeParts {
    AeadEnvelopeParts::try_new(identity(kind), &[3; 24], vec![4; ciphertext_len], &[5; 16]).unwrap()
}

#[test]
fn checked_parts_round_trip_without_exposing_private_fields() {
    macro_rules! assert_typed_round_trip {
        ($envelope:ty, $kind:expr, $length:expr) => {{
            let envelope = <$envelope>::try_from_parts(parts($kind, $length)).unwrap();
            assert_eq!(envelope.parts().identity().vault_id, [1; 16]);
            assert_eq!(envelope.parts().nonce(), &[3; 24]);
            assert_eq!(envelope.parts().ciphertext(), &[4; $length]);
            assert_eq!(envelope.parts().tag(), &[5; 16]);
            let recovered = envelope.into_parts();
            assert_eq!(recovered.identity().object_id, [2; 32]);
        }};
    }

    assert_typed_round_trip!(RecoverySlotEnvelope, RecoverySlotContext::OBJECT_KIND, 32);
    assert_typed_round_trip!(DeviceSlotEnvelope, DeviceSlotContext::OBJECT_KIND, 32);
    assert_typed_round_trip!(MetadataEnvelope, MetadataContext::OBJECT_KIND, 7);
    assert_typed_round_trip!(TreeEnvelope, TreeContext::OBJECT_KIND, 8);
    assert_typed_round_trip!(ManifestEnvelope, ManifestContext::OBJECT_KIND, 9);

    let snapshot =
        SnapshotEnvelope::try_new(parts(SnapshotContext::OBJECT_KIND, 10), &[6; 32]).unwrap();
    assert_eq!(snapshot.encrypted_parts().identity().object_id, [2; 32]);
    assert_eq!(snapshot.outer_authenticator(), &[6; 32]);
    let (snapshot_parts, snapshot_authenticator) = snapshot.into_parts();
    assert_eq!(snapshot_parts.ciphertext(), &[4; 10]);
    assert_eq!(snapshot_authenticator, [6; 32]);

    let head = HeadAuthenticator::try_from_bytes(&[7; 32]).unwrap();
    let local = LocalStateAuthenticator::try_from_bytes(&[8; 32]).unwrap();
    assert_eq!(head.as_bytes(), &[7; 32]);
    assert_eq!(local.as_bytes(), &[8; 32]);
}

#[test]
fn typed_envelopes_reject_wrong_kinds_and_lengths_without_large_allocations() {
    macro_rules! assert_wrong_kind {
        ($envelope:ty, $kind:expr, $length:expr) => {{
            let wrong_kind = if $kind == RecoverySlotContext::OBJECT_KIND {
                MetadataContext::OBJECT_KIND
            } else {
                RecoverySlotContext::OBJECT_KIND
            };
            assert!(matches!(
                <$envelope>::try_from_parts(parts(wrong_kind, $length)),
                Err(CryptoError::InvalidEnvelope),
            ));
        }};
    }

    assert_wrong_kind!(RecoverySlotEnvelope, RecoverySlotContext::OBJECT_KIND, 32);
    assert_wrong_kind!(DeviceSlotEnvelope, DeviceSlotContext::OBJECT_KIND, 32);
    assert_wrong_kind!(MetadataEnvelope, MetadataContext::OBJECT_KIND, 0);
    assert_wrong_kind!(TreeEnvelope, TreeContext::OBJECT_KIND, 0);
    assert_wrong_kind!(ManifestEnvelope, ManifestContext::OBJECT_KIND, 0);
    assert!(matches!(
        SnapshotEnvelope::try_new(parts(MetadataContext::OBJECT_KIND, 0), &[0; 32]),
        Err(CryptoError::InvalidEnvelope),
    ));

    assert!(matches!(
        RecoverySlotEnvelope::try_from_parts(parts(RecoverySlotContext::OBJECT_KIND, 31)),
        Err(CryptoError::InvalidPlaintextLength),
    ));
    assert!(notecrypt_crypto::DeviceSlotEnvelope::validate_ciphertext_len(32).is_ok());
    assert!(notecrypt_crypto::DeviceSlotEnvelope::validate_ciphertext_len(31).is_err());
    assert!(MetadataEnvelope::validate_ciphertext_len(1_048_576).is_ok());
    assert!(MetadataEnvelope::validate_ciphertext_len(1_048_577).is_err());
    assert!(TreeEnvelope::validate_ciphertext_len(268_435_456).is_ok());
    assert!(TreeEnvelope::validate_ciphertext_len(268_435_457).is_err());
    assert!(ManifestEnvelope::validate_ciphertext_len(67_108_864).is_ok());
    assert!(ManifestEnvelope::validate_ciphertext_len(67_108_865).is_err());
    assert!(SnapshotEnvelope::validate_ciphertext_len(1_048_576).is_ok());
    assert!(SnapshotEnvelope::validate_ciphertext_len(1_048_577).is_err());
}

#[test]
fn parts_and_authenticators_reject_wrong_fixed_lengths() {
    assert!(matches!(
        AeadEnvelopeParts::try_new(
            identity(MetadataContext::OBJECT_KIND),
            &[0; 23],
            vec![],
            &[0; 16]
        ),
        Err(CryptoError::InvalidEnvelope),
    ));
    assert!(matches!(
        AeadEnvelopeParts::try_new(
            identity(MetadataContext::OBJECT_KIND),
            &[0; 24],
            vec![],
            &[0; 15]
        ),
        Err(CryptoError::InvalidEnvelope),
    ));
    assert!(matches!(
        HeadAuthenticator::try_from_bytes(&[0; 31]),
        Err(CryptoError::InvalidEnvelope),
    ));
    assert!(matches!(
        LocalStateAuthenticator::try_from_bytes(&[0; 31]),
        Err(CryptoError::InvalidEnvelope),
    ));
    assert!(matches!(
        SnapshotEnvelope::try_new(parts(SnapshotContext::OBJECT_KIND, 32), &[0; 31]),
        Err(CryptoError::InvalidEnvelope),
    ));
}

#[test]
fn contexts_reject_wrong_profile_kind_and_format_version() {
    macro_rules! assert_checked_context {
        ($context:ty, $kind:expr) => {{
            assert!(<$context>::try_new(identity($kind)).is_ok());
            assert!(matches!(
                <$context>::try_new(PublicEnvelopeIdentity {
                    profile_id: 2,
                    ..identity($kind)
                }),
                Err(CryptoError::InvalidEnvelope),
            ));
            let wrong_kind = if $kind == RecoverySlotContext::OBJECT_KIND {
                MetadataContext::OBJECT_KIND
            } else {
                RecoverySlotContext::OBJECT_KIND
            };
            assert!(matches!(
                <$context>::try_new(PublicEnvelopeIdentity {
                    object_kind: wrong_kind,
                    ..identity($kind)
                }),
                Err(CryptoError::InvalidEnvelope),
            ));
            assert!(matches!(
                <$context>::try_new(PublicEnvelopeIdentity {
                    format_version: 2,
                    ..identity($kind)
                }),
                Err(CryptoError::InvalidEnvelope),
            ));
        }};
    }

    assert_checked_context!(RecoverySlotContext, RecoverySlotContext::OBJECT_KIND);
    assert_checked_context!(DeviceSlotContext, DeviceSlotContext::OBJECT_KIND);
    assert_checked_context!(MetadataContext, MetadataContext::OBJECT_KIND);
    assert_checked_context!(TreeContext, TreeContext::OBJECT_KIND);
    assert_checked_context!(ManifestContext, ManifestContext::OBJECT_KIND);
    assert_checked_context!(SnapshotContext, SnapshotContext::OBJECT_KIND);
    assert_checked_context!(
        AuthenticatedHeadContext,
        AuthenticatedHeadContext::OBJECT_KIND
    );
    assert_checked_context!(LocalStateContext, LocalStateContext::OBJECT_KIND);

    for kind in [
        RecoverySlotContext::OBJECT_KIND,
        DeviceSlotContext::OBJECT_KIND,
        MetadataContext::OBJECT_KIND,
        TreeContext::OBJECT_KIND,
        ManifestContext::OBJECT_KIND,
        SnapshotContext::OBJECT_KIND,
    ] {
        assert!(matches!(
            AeadEnvelopeParts::try_new(
                PublicEnvelopeIdentity {
                    profile_id: 2,
                    ..identity(kind)
                },
                &[0; 24],
                Vec::new(),
                &[0; 16],
            ),
            Err(CryptoError::InvalidEnvelope),
        ));
    }
}

struct ByteRandom(u8);

impl SecureRandom for ByteRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

#[test]
fn every_non_recovery_task_three_operation_round_trips() {
    let mut random = ByteRandom(20);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();

    let device_context =
        DeviceSlotContext::try_new(identity(DeviceSlotContext::OBJECT_KIND)).unwrap();
    let device_key = DeviceWrappingKey::try_from_protected_bytes(vec![21; 32]).unwrap();
    let device = encrypt_device_slot(
        &device_context,
        DeviceSlotPlaintext::from_root_key(&root),
        &device_key,
        &mut random,
    )
    .unwrap();
    let recovered_root = decrypt_device_slot(&device_context, &device, &device_key)
        .unwrap()
        .into_root_key();
    let recovered_keys = derive_vault_keys(&recovered_root).unwrap();

    let metadata_context =
        MetadataContext::try_new(identity(MetadataContext::OBJECT_KIND)).unwrap();
    let metadata = encrypt_metadata(
        &metadata_context,
        MetadataPlaintext::try_new(b"metadata".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    decrypt_metadata(&metadata_context, &metadata, &keys.metadata)
        .unwrap()
        .into_protected_bytes()
        .consume(|bytes| assert_eq!(bytes, b"metadata"));

    let tree_context = TreeContext::try_new(identity(TreeContext::OBJECT_KIND)).unwrap();
    let tree = encrypt_tree(
        &tree_context,
        TreePlaintext::try_new(b"tree".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    decrypt_tree(&tree_context, &tree, &keys.metadata)
        .unwrap()
        .into_protected_bytes()
        .consume(|bytes| assert_eq!(bytes, b"tree"));

    let manifest_context =
        ManifestContext::try_new(identity(ManifestContext::OBJECT_KIND)).unwrap();
    let manifest = encrypt_manifest(
        &manifest_context,
        ManifestPlaintext::try_new(b"manifest".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    decrypt_manifest(&manifest_context, &manifest, &keys.metadata)
        .unwrap()
        .into_protected_bytes()
        .consume(|bytes| assert_eq!(bytes, b"manifest"));

    let snapshot_context =
        SnapshotContext::try_new(identity(SnapshotContext::OBJECT_KIND)).unwrap();
    let snapshot = encrypt_snapshot(
        &snapshot_context,
        SnapshotPlaintext::try_new(b"snapshot".to_vec()).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut random,
    )
    .unwrap();
    decrypt_snapshot(
        &snapshot_context,
        &snapshot,
        &keys.metadata,
        &keys.snapshot_authentication,
    )
    .unwrap()
    .into_protected_bytes()
    .consume(|bytes| assert_eq!(bytes, b"snapshot"));

    let head_context =
        AuthenticatedHeadContext::try_new(identity(AuthenticatedHeadContext::OBJECT_KIND)).unwrap();
    let head = authenticate_head(
        &head_context,
        b"head",
        &recovered_keys.snapshot_authentication,
    )
    .unwrap();
    assert!(matches!(
        authenticate_head(
            &head_context,
            &vec![0; 65_537],
            &keys.snapshot_authentication,
        ),
        Err(CryptoError::PlaintextTooLarge),
    ));
    verify_head(&head_context, b"head", &head, &keys.snapshot_authentication).unwrap();
    assert!(matches!(
        verify_head(
            &head_context,
            b"changed head",
            &head,
            &keys.snapshot_authentication,
        ),
        Err(CryptoError::Authentication),
    ));
    let mut changed_head_bytes = *head.as_bytes();
    changed_head_bytes[0] ^= 1;
    let changed_head = HeadAuthenticator::try_from_bytes(&changed_head_bytes).unwrap();
    assert!(matches!(
        verify_head(
            &head_context,
            b"head",
            &changed_head,
            &keys.snapshot_authentication,
        ),
        Err(CryptoError::Authentication),
    ));

    let local_context =
        LocalStateContext::try_new(identity(LocalStateContext::OBJECT_KIND)).unwrap();
    let local =
        authenticate_local_state(&local_context, b"local", &keys.local_verification).unwrap();
    assert!(matches!(
        authenticate_local_state(&local_context, &vec![0; 65_537], &keys.local_verification,),
        Err(CryptoError::PlaintextTooLarge),
    ));
    verify_local_state(&local_context, b"local", &local, &keys.local_verification).unwrap();
    assert!(matches!(
        verify_local_state(
            &local_context,
            b"changed local",
            &local,
            &keys.local_verification,
        ),
        Err(CryptoError::Authentication),
    ));
    let mut changed_local_bytes = *local.as_bytes();
    changed_local_bytes[0] ^= 1;
    let changed_local = LocalStateAuthenticator::try_from_bytes(&changed_local_bytes).unwrap();
    assert!(matches!(
        verify_local_state(
            &local_context,
            b"local",
            &changed_local,
            &keys.local_verification,
        ),
        Err(CryptoError::Authentication),
    ));
}

#[test]
fn snapshot_outer_authenticator_mutation_is_rejected_before_plaintext() {
    let mut random = ByteRandom(30);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let context = SnapshotContext::try_new(identity(SnapshotContext::OBJECT_KIND)).unwrap();
    let envelope = encrypt_snapshot(
        &context,
        SnapshotPlaintext::try_new(b"snapshot".to_vec()).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut random,
    )
    .unwrap();
    let (encrypted, mut authenticator) = envelope.into_parts();
    authenticator[0] ^= 1;
    let changed = SnapshotEnvelope::try_new(encrypted, &authenticator).unwrap();

    assert!(matches!(
        decrypt_snapshot(
            &context,
            &changed,
            &keys.metadata,
            &keys.snapshot_authentication,
        ),
        Err(CryptoError::Authentication),
    ));
}
