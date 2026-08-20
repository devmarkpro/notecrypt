use notecrypt_crypto::{
    AUTHENTICATED_HEAD_OBJECT_KIND, AeadEnvelopeParts, CHUNK_KEY_OBJECT_KIND,
    CONTENT_CHUNK_OBJECT_KIND, DEVICE_SLOT_OBJECT_KIND, HeadAuthenticator, LOCAL_STATE_OBJECT_KIND,
    LocalStateAuthenticator, MANIFEST_OBJECT_KIND, METADATA_OBJECT_KIND, ManifestEnvelope,
    MetadataEnvelope, RECOVERY_SLOT_OBJECT_KIND, RecoverySlotEnvelope, SNAPSHOT_OBJECT_KIND,
    SnapshotEnvelope, TREE_OBJECT_KIND, TreeEnvelope, TypedAeadEnvelope,
};
use notecrypt_format::{
    AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CompactChunkKey, ContentChunkObject,
    CryptoProfileId, DecodeLimits, FormatVersion, ObjectKind, OrdinaryAeadKind, SnapshotObject,
    decode_aead_object, decode_content_chunk, decode_snapshot_object, encode_aead_object,
    encode_content_chunk, encode_snapshot_object,
};

fn crypto_parts(kind: u8, length: usize) -> AeadEnvelopeParts {
    AeadEnvelopeParts::try_new(
        notecrypt_crypto::PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: [1; 16],
            object_kind: kind,
            format_version: 1,
            object_id: [2; 32],
        },
        &[3; 24],
        vec![4; length],
        &[5; 16],
    )
    .unwrap()
}
fn format_kind(kind: u8) -> OrdinaryAeadKind {
    match kind {
        RECOVERY_SLOT_OBJECT_KIND => OrdinaryAeadKind::RecoverySlot,
        DEVICE_SLOT_OBJECT_KIND => OrdinaryAeadKind::DeviceSlot,
        METADATA_OBJECT_KIND => OrdinaryAeadKind::Metadata,
        TREE_OBJECT_KIND => OrdinaryAeadKind::Tree,
        MANIFEST_OBJECT_KIND => OrdinaryAeadKind::Manifest,
        _ => panic!("ordinary kind"),
    }
}
fn wire_from_parts(parts: AeadEnvelopeParts) -> AeadObject {
    let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
    AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        identity.vault_id,
        format_kind(identity.object_kind),
        FormatVersion::v1(),
        identity.object_id,
        &nonce,
        ciphertext,
        &tag,
        &DecodeLimits::PHASE_1,
    )
    .unwrap()
}
fn parts_from_wire(wire: AeadObject) -> AeadEnvelopeParts {
    let (profile, _algorithm, vault, kind, version, object, nonce, ciphertext, tag) =
        wire.into_parts().into_components();
    AeadEnvelopeParts::try_new(
        notecrypt_crypto::PublicEnvelopeIdentity {
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

#[test]
fn format_kind_mapping_exactly_matches_crypto_profile() {
    let rows = [
        (ObjectKind::RecoverySlot, RECOVERY_SLOT_OBJECT_KIND),
        (ObjectKind::DeviceSlot, DEVICE_SLOT_OBJECT_KIND),
        (ObjectKind::Metadata, METADATA_OBJECT_KIND),
        (ObjectKind::Tree, TREE_OBJECT_KIND),
        (ObjectKind::Manifest, MANIFEST_OBJECT_KIND),
        (ObjectKind::Snapshot, SNAPSHOT_OBJECT_KIND),
        (
            ObjectKind::AuthenticatedHead,
            AUTHENTICATED_HEAD_OBJECT_KIND,
        ),
        (ObjectKind::LocalState, LOCAL_STATE_OBJECT_KIND),
        (ObjectKind::ChunkKey, CHUNK_KEY_OBJECT_KIND),
        (ObjectKind::ContentChunk, CONTENT_CHUNK_OBJECT_KIND),
    ];
    for (kind, crypto) in rows {
        assert_eq!(kind.get(), crypto)
    }
}

#[test]
fn every_ordinary_crypto_envelope_round_trips_through_canonical_wire() {
    macro_rules! row {
        ($ty:ty,$kind:expr,$len:expr) => {{
            let typed = <$ty>::try_from_parts(crypto_parts($kind, $len)).unwrap();
            let bytes = encode_aead_object(&wire_from_parts(typed.into_parts())).unwrap();
            let decoded = decode_aead_object(&bytes, &DecodeLimits::PHASE_1).unwrap();
            let rebuilt = <$ty>::try_from_parts(parts_from_wire(decoded)).unwrap();
            assert_eq!(rebuilt.parts().ciphertext(), &[4; $len]);
        }};
    }
    row!(RecoverySlotEnvelope, RECOVERY_SLOT_OBJECT_KIND, 32);
    row!(
        notecrypt_crypto::DeviceSlotEnvelope,
        DEVICE_SLOT_OBJECT_KIND,
        32
    );
    row!(MetadataEnvelope, METADATA_OBJECT_KIND, 17);
    row!(TreeEnvelope, TREE_OBJECT_KIND, 19);
    row!(ManifestEnvelope, MANIFEST_OBJECT_KIND, 23);
}

#[test]
fn snapshot_chunk_authenticator_and_fingerprint_checked_surfaces_integrate() {
    let crypto =
        SnapshotEnvelope::try_new(crypto_parts(SNAPSHOT_OBJECT_KIND, 21), &[6; 32]).unwrap();
    let (p, outer_authenticator) = crypto.into_parts();
    let (identity, nonce, ciphertext, tag) = p.into_public_parts().into_components();
    let wire = SnapshotObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        identity.vault_id,
        FormatVersion::v1(),
        identity.object_id,
        &nonce,
        ciphertext,
        &tag,
        &outer_authenticator,
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let decoded = decode_snapshot_object(
        &encode_snapshot_object(&wire).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let (profile, _aead, _auth, vault, version, object, nonce, ciphertext, tag, outer) =
        decoded.into_parts().into_components();
    let rebuilt = SnapshotEnvelope::try_new(
        AeadEnvelopeParts::try_new(
            notecrypt_crypto::PublicEnvelopeIdentity {
                profile_id: profile.get(),
                vault_id: vault,
                object_kind: SNAPSHOT_OBJECT_KIND,
                format_version: version.get(),
                object_id: object,
            },
            &nonce,
            ciphertext,
            &tag,
        )
        .unwrap(),
        &outer,
    )
    .unwrap();
    assert_eq!(rebuilt.outer_authenticator(), &[6; 32]);
    HeadAuthenticator::try_from_bytes(&[7; 32]).unwrap();
    LocalStateAuthenticator::try_from_bytes(&[8; 32]).unwrap();
    let wrapper_parts = crypto_parts(CHUNK_KEY_OBJECT_KIND, 32);
    let content_parts = crypto_parts(CONTENT_CHUNK_OBJECT_KIND, 41);
    let (_wrapper_identity, wrapper_nonce, wrapper_ciphertext, wrapper_tag) =
        wrapper_parts.into_public_parts().into_components();
    let (content_identity, content_nonce, content_ciphertext, content_tag) =
        content_parts.into_public_parts().into_components();
    let compact = CompactChunkKey::try_new(
        AeadAlgorithmId::xchacha20_poly1305(),
        &wrapper_nonce,
        wrapper_ciphertext,
        &wrapper_tag,
    )
    .unwrap();
    let chunk = ContentChunkObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        content_identity.vault_id,
        FormatVersion::v1(),
        content_identity.object_id,
        &content_nonce,
        compact,
        content_ciphertext,
        &content_tag,
    )
    .unwrap();
    let decoded = decode_content_chunk(
        &encode_content_chunk(&chunk).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    assert_eq!(decoded.wrapper().ciphertext(), &[4; 32]);
    let _ = notecrypt_crypto::ChunkFingerprint::try_from_protected_bytes(&[9; 32])
        .unwrap()
        .into_protected_bytes();
}

#[test]
fn modified_wire_algorithm_is_rejected_before_crypto_construction() {
    let wire = wire_from_parts(crypto_parts(METADATA_OBJECT_KIND, 4));
    let mut bytes = encode_aead_object(&wire).unwrap();
    assert_eq!(&bytes[..3], &[0x8a, 0x01, 0x01]);
    bytes[2] = 0x02;
    assert!(decode_aead_object(&bytes, &DecodeLimits::PHASE_1).is_err());
}
