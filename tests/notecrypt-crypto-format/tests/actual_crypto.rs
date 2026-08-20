use std::sync::atomic::AtomicBool;

use notecrypt_crypto::*;
use notecrypt_format::*;

struct FixedRandom(u8);
impl SecureRandom for FixedRandom {
    fn fill(&mut self, d: &mut [u8]) -> Result<(), CryptoError> {
        d.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
fn identity(kind: u8, object: u8) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [1; 16],
        object_kind: kind,
        format_version: 1,
        object_id: [object; 32],
    }
}
fn ordinary_kind(kind: u8) -> OrdinaryAeadKind {
    match kind {
        RECOVERY_SLOT_OBJECT_KIND => OrdinaryAeadKind::RecoverySlot,
        DEVICE_SLOT_OBJECT_KIND => OrdinaryAeadKind::DeviceSlot,
        METADATA_OBJECT_KIND => OrdinaryAeadKind::Metadata,
        TREE_OBJECT_KIND => OrdinaryAeadKind::Tree,
        MANIFEST_OBJECT_KIND => OrdinaryAeadKind::Manifest,
        _ => panic!(),
    }
}
fn wire(parts: AeadEnvelopeParts) -> AeadObject {
    let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
    AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        identity.vault_id,
        ordinary_kind(identity.object_kind),
        FormatVersion::v1(),
        identity.object_id,
        &nonce,
        ciphertext,
        &tag,
        &DecodeLimits::PHASE_1,
    )
    .unwrap()
}
fn parts(value: AeadObject) -> AeadEnvelopeParts {
    let (profile, _algorithm, vault, kind, version, object, nonce, ciphertext, tag) =
        value.into_parts().into_components();
    AeadEnvelopeParts::try_new(
        PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: vault,
            object_kind: kind.object_kind().get(),
            format_version: version.get(),
            object_id: object,
        },
        &nonce,
        ciphertext,
        &tag,
    )
    .unwrap()
}
fn borrowed_parts(value: &AeadObject) -> AeadEnvelopeParts {
    AeadEnvelopeParts::try_new(
        PublicEnvelopeIdentity {
            profile_id: value.profile_id().get(),
            vault_id: *value.vault_id(),
            object_kind: value.kind().object_kind().get(),
            format_version: value.format_version().get(),
            object_id: *value.object_id(),
        },
        value.nonce(),
        value.ciphertext().to_vec(),
        value.tag(),
    )
    .unwrap()
}
fn canonical_round_trip<E: TypedAeadEnvelope>(value: E) -> E {
    let bytes = encode_aead_object(&wire(value.into_parts())).unwrap();
    E::try_from_parts(parts(
        decode_aead_object(&bytes, &DecodeLimits::PHASE_1).unwrap(),
    ))
    .ok()
    .unwrap()
}

#[test]
fn every_profile_row_crosses_real_crypto_and_wire_boundaries() {
    let mut random = FixedRandom(1);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let recovery_key = derive_recovery_wrapping_key(
        &RecoveryPassphrase::new("alpha bravo charlie delta echo foxtrot".into()),
        &[9; 16],
        ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        })
        .unwrap(),
        &AtomicBool::new(false),
    )
    .unwrap();
    let recovery_context =
        RecoverySlotContext::try_new(identity(RECOVERY_SLOT_OBJECT_KIND, 2)).unwrap();
    let recovery = encrypt_recovery_slot(
        &recovery_context,
        RecoverySlotPlaintext::from_root_key(&root),
        &recovery_key,
        &mut random,
    )
    .unwrap();
    decrypt_recovery_slot(
        &recovery_context,
        &canonical_round_trip(recovery),
        &recovery_key,
    )
    .unwrap();
    let device_key = DeviceWrappingKey::try_from_protected_bytes(vec![7; 32]).unwrap();
    let device_context = DeviceSlotContext::try_new(identity(DEVICE_SLOT_OBJECT_KIND, 3)).unwrap();
    let device = encrypt_device_slot(
        &device_context,
        DeviceSlotPlaintext::from_root_key(&root),
        &device_key,
        &mut random,
    )
    .unwrap();
    decrypt_device_slot(&device_context, &canonical_round_trip(device), &device_key).unwrap();
    let metadata_context = MetadataContext::try_new(identity(METADATA_OBJECT_KIND, 4)).unwrap();
    let metadata = encrypt_metadata(
        &metadata_context,
        MetadataPlaintext::try_new(b"metadata".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    decrypt_metadata(
        &metadata_context,
        &canonical_round_trip(metadata),
        &keys.metadata,
    )
    .unwrap();
    let tree_context = TreeContext::try_new(identity(TREE_OBJECT_KIND, 5)).unwrap();
    let tree = encrypt_tree(
        &tree_context,
        TreePlaintext::try_new(b"tree".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    decrypt_tree(&tree_context, &canonical_round_trip(tree), &keys.metadata).unwrap();
    let manifest_context = ManifestContext::try_new(identity(MANIFEST_OBJECT_KIND, 6)).unwrap();
    let manifest = encrypt_manifest(
        &manifest_context,
        ManifestPlaintext::try_new(b"manifest".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    decrypt_manifest(
        &manifest_context,
        &canonical_round_trip(manifest),
        &keys.metadata,
    )
    .unwrap();
    let snapshot_context = SnapshotContext::try_new(identity(SNAPSHOT_OBJECT_KIND, 7)).unwrap();
    let snapshot = encrypt_snapshot(
        &snapshot_context,
        SnapshotPlaintext::try_new(b"snapshot".to_vec()).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut random,
    )
    .unwrap();
    let (p, outer_authenticator) = snapshot.into_parts();
    let (snapshot_identity, snapshot_nonce, snapshot_ciphertext, snapshot_tag) =
        p.into_public_parts().into_components();
    let sw = SnapshotObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        snapshot_identity.vault_id,
        FormatVersion::v1(),
        snapshot_identity.object_id,
        &snapshot_nonce,
        snapshot_ciphertext,
        &snapshot_tag,
        &outer_authenticator,
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let sw = decode_snapshot_object(
        &encode_snapshot_object(&sw).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let (_profile, _aead, _auth, vault, version, object, nonce, ciphertext, tag, outer) =
        sw.into_parts().into_components();
    let rebuilt_parts = AeadEnvelopeParts::try_new(
        PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: vault,
            object_kind: SNAPSHOT_OBJECT_KIND,
            format_version: version.get(),
            object_id: object,
        },
        &nonce,
        ciphertext,
        &tag,
    )
    .unwrap();
    let rebuilt = SnapshotEnvelope::try_new(rebuilt_parts, &outer).unwrap();
    decrypt_snapshot(
        &snapshot_context,
        &rebuilt,
        &keys.metadata,
        &keys.snapshot_authentication,
    )
    .unwrap();
    let head_payload = HeadPayload::new([10; 32], [11; 32], [12; 32]);
    let canonical = encode_head_payload(&head_payload).unwrap();
    let head_context =
        AuthenticatedHeadContext::try_new(identity(AUTHENTICATED_HEAD_OBJECT_KIND, 8)).unwrap();
    let auth = authenticate_head(&head_context, &canonical, &keys.snapshot_authentication).unwrap();
    let record = HeadRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [8; 32],
        head_payload,
        auth.as_bytes(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let decoded = decode_head(&encode_head(&record).unwrap(), &DecodeLimits::PHASE_1).unwrap();
    verify_head(
        &head_context,
        decoded.untrusted_payload_bytes(),
        &HeadAuthenticator::try_from_bytes(decoded.authenticator()).unwrap(),
        &keys.snapshot_authentication,
    )
    .unwrap();
    let verified_head = notecrypt_format::decode_head_payload(
        decoded.untrusted_payload_bytes(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    assert_eq!(verified_head.snapshot_id(), &[10; 32]);
    let local_payload = LocalStatePayload::try_new(
        LocalRecordType::Cleanup,
        [13; 32],
        b"cleanup".to_vec(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let canonical = encode_local_state_payload(&local_payload).unwrap();
    let local_context = LocalStateContext::try_new(identity(LOCAL_STATE_OBJECT_KIND, 9)).unwrap();
    let auth =
        authenticate_local_state(&local_context, &canonical, &keys.local_verification).unwrap();
    let record = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [9; 32],
        local_payload,
        auth.as_bytes(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let decoded = decode_local_state(
        &encode_local_state(&record).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    verify_local_state(
        &local_context,
        decoded.untrusted_payload_bytes(),
        &LocalStateAuthenticator::try_from_bytes(decoded.authenticator()).unwrap(),
        &keys.local_verification,
    )
    .unwrap();
    let verified_local = notecrypt_format::decode_local_state_payload(
        decoded.untrusted_payload_bytes(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    assert!(verified_local.into_parts().0 == LocalRecordType::Cleanup);
    let content_context =
        ContentChunkContext::try_new(identity(CONTENT_CHUNK_OBJECT_KIND, 10)).unwrap();
    let wrap_context = ChunkKeyWrapContext::try_new(identity(CHUNK_KEY_OBJECT_KIND, 10)).unwrap();
    let chunk_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let content = encrypt_content_chunk(
        &content_context,
        ContentChunkPlaintext::try_new(b"chunk".to_vec()).unwrap(),
        &chunk_key,
        &mut random,
    )
    .unwrap();
    let wrapped = wrap_chunk_key(
        &wrap_context,
        chunk_key,
        &keys.content_wrapping,
        &mut random,
    )
    .unwrap();
    let cp = content.into_parts();
    let wp = wrapped.into_parts();
    let (content_identity, content_nonce, content_ciphertext, content_tag) =
        cp.into_public_parts().into_components();
    let (wrap_identity, wrap_nonce, wrap_ciphertext, wrap_tag) =
        wp.into_public_parts().into_components();
    let object = ContentChunkObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        FormatVersion::v1(),
        [10; 32],
        &content_nonce,
        CompactChunkKey::try_new(
            AeadAlgorithmId::xchacha20_poly1305(),
            &wrap_nonce,
            wrap_ciphertext,
            &wrap_tag,
        )
        .unwrap(),
        content_ciphertext,
        &content_tag,
    )
    .unwrap();
    let decoded = decode_content_chunk(
        &encode_content_chunk(&object).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    assert_eq!(content_identity.object_id, wrap_identity.object_id);
    let (_profile, _algorithm, vault, version, object_id, nonce, wrapper, ciphertext, tag) =
        decoded.into_parts().into_components();
    let wrapped = ChunkKeyEnvelope::try_from_parts(
        AeadEnvelopeParts::try_new(
            PublicEnvelopeIdentity {
                profile_id: 1,
                vault_id: vault,
                object_kind: CHUNK_KEY_OBJECT_KIND,
                format_version: version.get(),
                object_id,
            },
            wrapper.nonce(),
            wrapper.ciphertext().to_vec(),
            wrapper.tag(),
        )
        .unwrap(),
    )
    .unwrap();
    let key = unwrap_chunk_key(&wrap_context, &wrapped, &keys.content_wrapping).unwrap();
    let content = ContentChunkEnvelope::try_from_parts(
        AeadEnvelopeParts::try_new(
            PublicEnvelopeIdentity {
                profile_id: 1,
                vault_id: vault,
                object_kind: CONTENT_CHUNK_OBJECT_KIND,
                format_version: version.get(),
                object_id,
            },
            &nonce,
            ciphertext,
            &tag,
        )
        .unwrap(),
    )
    .unwrap();
    decrypt_content_chunk(&content_context, &content, &key).unwrap();
    let mut semantics = vec![14; 16];
    semantics.extend_from_slice(&0_u64.to_be_bytes());
    let fingerprint = fingerprint_chunk(
        &ChunkFingerprintContext::profile_one(),
        &semantics,
        b"chunk",
        &keys.chunk_fingerprint,
    )
    .unwrap();
    verify_chunk_fingerprint(
        &ChunkFingerprintContext::profile_one(),
        &semantics,
        b"chunk",
        &fingerprint,
        &keys.chunk_fingerprint,
    )
    .unwrap();
    let protected = fingerprint.into_protected_bytes();
    ChunkFingerprint::try_from_protected_bytes(&protected).unwrap();
}

#[test]
fn identity_ciphertext_tag_and_algorithm_mutations_fail_closed() {
    let mut random = FixedRandom(40);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let context = MetadataContext::try_new(identity(METADATA_OBJECT_KIND, 4)).unwrap();
    let encrypted = encrypt_metadata(
        &context,
        MetadataPlaintext::try_new(b"private".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let original = wire(encrypted.into_parts());
    let attempt =
        |vault: [u8; 16], object: [u8; 32], nonce: [u8; 24], ciphertext: Vec<u8>, tag: [u8; 16]| {
            let changed = AeadObject::try_new(
                CryptoProfileId::profile_one(),
                AeadAlgorithmId::xchacha20_poly1305(),
                vault,
                OrdinaryAeadKind::Metadata,
                FormatVersion::v1(),
                object,
                &nonce,
                ciphertext,
                &tag,
                &DecodeLimits::PHASE_1,
            )
            .unwrap();
            let envelope = MetadataEnvelope::try_from_parts(borrowed_parts(&changed)).unwrap();
            decrypt_metadata(&context, &envelope, &keys.metadata).is_err()
        };
    assert!(attempt(
        [2; 16],
        [4; 32],
        *original.nonce(),
        original.ciphertext().to_vec(),
        *original.tag()
    ));
    assert!(attempt(
        [1; 16],
        [5; 32],
        *original.nonce(),
        original.ciphertext().to_vec(),
        *original.tag()
    ));
    let mut nonce = *original.nonce();
    nonce[0] ^= 1;
    assert!(attempt(
        [1; 16],
        [4; 32],
        nonce,
        original.ciphertext().to_vec(),
        *original.tag()
    ));
    let mut cipher = original.ciphertext().to_vec();
    cipher[0] ^= 1;
    assert!(attempt(
        [1; 16],
        [4; 32],
        *original.nonce(),
        cipher,
        *original.tag()
    ));
    let mut tag = *original.tag();
    tag[0] ^= 1;
    assert!(attempt(
        [1; 16],
        [4; 32],
        *original.nonce(),
        original.ciphertext().to_vec(),
        tag
    ));
    let mut bytes = encode_aead_object(&original).unwrap();
    bytes[2] = 2;
    assert!(decode_aead_object(&bytes, &DecodeLimits::PHASE_1).is_err());
    let mut bytes = encode_aead_object(&original).unwrap();
    bytes[1] = 2;
    assert!(decode_aead_object(&bytes, &DecodeLimits::PHASE_1).is_err());
    let mut bytes = encode_aead_object(&original).unwrap();
    bytes[21] = 2;
    assert!(decode_aead_object(&bytes, &DecodeLimits::PHASE_1).is_err());
}

#[test]
fn cross_kind_slot_authenticator_and_fingerprint_mutations_fail_closed() {
    let mut random = FixedRandom(80);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let metadata_context = MetadataContext::try_new(identity(METADATA_OBJECT_KIND, 1)).unwrap();
    let metadata = encrypt_metadata(
        &metadata_context,
        MetadataPlaintext::try_new(b"kind".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let p = metadata.parts();
    let crossed = AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        OrdinaryAeadKind::Tree,
        FormatVersion::v1(),
        [1; 32],
        p.nonce(),
        p.ciphertext().to_vec(),
        p.tag(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let tree = TreeEnvelope::try_from_parts(parts(crossed)).unwrap();
    let tree_context = TreeContext::try_new(identity(TREE_OBJECT_KIND, 1)).unwrap();
    assert!(decrypt_tree(&tree_context, &tree, &keys.metadata).is_err());
    assert!(
        AeadObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            [1; 16],
            OrdinaryAeadKind::RecoverySlot,
            FormatVersion::v1(),
            [1; 32],
            &[2; 24],
            vec![3; 31],
            &[4; 16],
            &DecodeLimits::PHASE_1
        )
        .is_err()
    );
    let device_context = DeviceSlotContext::try_new(identity(DEVICE_SLOT_OBJECT_KIND, 2)).unwrap();
    let key = DeviceWrappingKey::try_from_protected_bytes(vec![5; 32]).unwrap();
    let wrong = DeviceWrappingKey::try_from_protected_bytes(vec![6; 32]).unwrap();
    let slot = encrypt_device_slot(
        &device_context,
        DeviceSlotPlaintext::from_root_key(&root),
        &key,
        &mut random,
    )
    .unwrap();
    assert!(decrypt_device_slot(&device_context, &slot, &wrong).is_err());
    let snapshot_context = SnapshotContext::try_new(identity(SNAPSHOT_OBJECT_KIND, 3)).unwrap();
    let snapshot = encrypt_snapshot(
        &snapshot_context,
        SnapshotPlaintext::try_new(b"snapshot".to_vec()).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut random,
    )
    .unwrap();
    let mut outer = *snapshot.outer_authenticator();
    outer[0] ^= 1;
    let altered = SnapshotEnvelope::try_new(
        AeadEnvelopeParts::try_new(
            identity(SNAPSHOT_OBJECT_KIND, 3),
            snapshot.encrypted_parts().nonce(),
            snapshot.encrypted_parts().ciphertext().to_vec(),
            snapshot.encrypted_parts().tag(),
        )
        .unwrap(),
        &outer,
    )
    .unwrap();
    assert!(
        decrypt_snapshot(
            &snapshot_context,
            &altered,
            &keys.metadata,
            &keys.snapshot_authentication
        )
        .is_err()
    );
    let head_context =
        AuthenticatedHeadContext::try_new(identity(AUTHENTICATED_HEAD_OBJECT_KIND, 4)).unwrap();
    let payload = b"head";
    let auth = authenticate_head(&head_context, payload, &keys.snapshot_authentication).unwrap();
    let mut changed = *auth.as_bytes();
    changed[0] ^= 1;
    assert!(
        verify_head(
            &head_context,
            payload,
            &HeadAuthenticator::try_from_bytes(&changed).unwrap(),
            &keys.snapshot_authentication
        )
        .is_err()
    );
    let local_context = LocalStateContext::try_new(identity(LOCAL_STATE_OBJECT_KIND, 5)).unwrap();
    let auth =
        authenticate_local_state(&local_context, b"local", &keys.local_verification).unwrap();
    let mut changed = *auth.as_bytes();
    changed[0] ^= 1;
    assert!(
        verify_local_state(
            &local_context,
            b"local",
            &LocalStateAuthenticator::try_from_bytes(&changed).unwrap(),
            &keys.local_verification
        )
        .is_err()
    );
    let wrap_context = ChunkKeyWrapContext::try_new(identity(CHUNK_KEY_OBJECT_KIND, 6)).unwrap();
    let chunk_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let wrapped = wrap_chunk_key(
        &wrap_context,
        chunk_key,
        &keys.content_wrapping,
        &mut random,
    )
    .unwrap();
    let wrong_context = ChunkKeyWrapContext::try_new(identity(CHUNK_KEY_OBJECT_KIND, 7)).unwrap();
    assert!(unwrap_chunk_key(&wrong_context, &wrapped, &keys.content_wrapping).is_err());
    let mut semantics = vec![8; 16];
    semantics.extend_from_slice(&0_u64.to_be_bytes());
    let fingerprint = fingerprint_chunk(
        &ChunkFingerprintContext::profile_one(),
        &semantics,
        b"fingerprint",
        &keys.chunk_fingerprint,
    )
    .unwrap();
    let mut changed = fingerprint.into_protected_bytes();
    changed[0] ^= 1;
    let changed = ChunkFingerprint::try_from_protected_bytes(&changed).unwrap();
    assert!(
        verify_chunk_fingerprint(
            &ChunkFingerprintContext::profile_one(),
            &semantics,
            b"fingerprint",
            &changed,
            &keys.chunk_fingerprint
        )
        .is_err()
    );
}

#[test]
fn revision_and_parent_object_locator_substitutions_fail_authentication() {
    let mut root_random = FixedRandom(0x31);
    let root = VaultRootKey::generate(&mut root_random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let limits = DecodeLimits::PHASE_1;

    let tree_context = TreeContext::try_new(identity(TREE_OBJECT_KIND, 0x41)).unwrap();
    let tree_bytes = |manifest_object_id| {
        encode_tree(
            &LogicalTree::try_new(
                [1; 16],
                vec![
                    TreeEntry::root([1; 16]),
                    TreeEntry::file(
                        [2; 16],
                        [1; 16],
                        "note.md",
                        RevisionLocator::new([3; 32], manifest_object_id),
                        &limits,
                    )
                    .unwrap(),
                ],
                &limits,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let mut first_random = FixedRandom(0x51);
    let first_tree = encrypt_tree(
        &tree_context,
        TreePlaintext::try_new(tree_bytes([4; 32])).unwrap(),
        &keys.metadata,
        &mut first_random,
    )
    .unwrap();
    let mut second_random = FixedRandom(0x51);
    let second_tree = encrypt_tree(
        &tree_context,
        TreePlaintext::try_new(tree_bytes([5; 32])).unwrap(),
        &keys.metadata,
        &mut second_random,
    )
    .unwrap();
    let substituted_tree = TreeEnvelope::try_from_parts(
        AeadEnvelopeParts::try_new(
            identity(TREE_OBJECT_KIND, 0x41),
            first_tree.parts().nonce(),
            second_tree.parts().ciphertext().to_vec(),
            first_tree.parts().tag(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(decrypt_tree(&tree_context, &substituted_tree, &keys.metadata).is_err());

    let snapshot_context = SnapshotContext::try_new(identity(SNAPSHOT_OBJECT_KIND, 0x42)).unwrap();
    let snapshot_bytes = |parent_object_id| {
        encode_snapshot_payload(
            &SnapshotPayload::try_new(
                [6; 32],
                vec![SnapshotParentLocator::new([7; 32], parent_object_id)],
                [8; 32],
                [9; 16],
                "device",
                &limits,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let mut first_random = FixedRandom(0x61);
    let first_snapshot = encrypt_snapshot(
        &snapshot_context,
        SnapshotPlaintext::try_new(snapshot_bytes([10; 32])).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut first_random,
    )
    .unwrap();
    let mut second_random = FixedRandom(0x61);
    let second_snapshot = encrypt_snapshot(
        &snapshot_context,
        SnapshotPlaintext::try_new(snapshot_bytes([11; 32])).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut second_random,
    )
    .unwrap();
    let substituted_snapshot = SnapshotEnvelope::try_new(
        AeadEnvelopeParts::try_new(
            identity(SNAPSHOT_OBJECT_KIND, 0x42),
            first_snapshot.encrypted_parts().nonce(),
            second_snapshot.encrypted_parts().ciphertext().to_vec(),
            first_snapshot.encrypted_parts().tag(),
        )
        .unwrap(),
        first_snapshot.outer_authenticator(),
    )
    .unwrap();
    assert!(
        decrypt_snapshot(
            &snapshot_context,
            &substituted_snapshot,
            &keys.metadata,
            &keys.snapshot_authentication,
        )
        .is_err()
    );
}

#[test]
fn journal_local_record_type_is_covered_by_authentication() {
    let mut random = FixedRandom(91);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let context = LocalStateContext::try_new(identity(LOCAL_STATE_OBJECT_KIND, 9)).unwrap();
    let payload = LocalStatePayload::try_new(
        LocalRecordType::Journal,
        [9; 32],
        b"journal".to_vec(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let canonical = encode_local_state_payload(&payload).unwrap();
    let authenticator =
        authenticate_local_state(&context, &canonical, &keys.local_verification).unwrap();
    let mut crossed = canonical;
    crossed[2] = LocalRecordType::Cleanup as u8;
    assert!(
        verify_local_state(&context, &crossed, &authenticator, &keys.local_verification).is_err()
    );
}

#[test]
fn vault_availability_local_record_type_is_covered_by_authentication() {
    let mut random = FixedRandom(92);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let context = LocalStateContext::try_new(identity(LOCAL_STATE_OBJECT_KIND, 10)).unwrap();
    let payload = LocalStatePayload::try_new(
        LocalRecordType::VaultAvailability,
        [10; 32],
        b"vault-availability".to_vec(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let canonical = encode_local_state_payload(&payload).unwrap();
    let authenticator =
        authenticate_local_state(&context, &canonical, &keys.local_verification).unwrap();
    let mut crossed = canonical;
    crossed[2] = LocalRecordType::BackendCopy as u8;
    assert!(
        verify_local_state(&context, &crossed, &authenticator, &keys.local_verification).is_err()
    );
}
