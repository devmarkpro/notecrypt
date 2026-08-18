use notecrypt_crypto::{
    AeadEnvelopeParts, CHUNK_KEY_OBJECT_KIND, CONTENT_CHUNK_OBJECT_KIND, ChunkFingerprint,
    ChunkFingerprintContext, ChunkKeyEnvelope, ChunkKeyWrapContext, ContentChunkContext,
    ContentChunkEnvelope, ContentChunkPlaintext, CryptoError, PublicEnvelopeIdentity,
    TypedAeadEnvelope,
};

const MIB: usize = 1_048_576;

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
fn chunk_envelopes_round_trip_through_checked_parts() {
    let wrapped = ChunkKeyEnvelope::try_from_parts(parts(CHUNK_KEY_OBJECT_KIND, 32)).unwrap();
    assert_eq!(wrapped.parts().identity().object_kind, 0x09);
    assert_eq!(wrapped.parts().nonce(), &[3; 24]);
    assert_eq!(wrapped.parts().ciphertext(), &[4; 32]);
    assert_eq!(wrapped.parts().tag(), &[5; 16]);
    assert_eq!(wrapped.into_parts().identity().object_id, [2; 32]);

    let content =
        ContentChunkEnvelope::try_from_parts(parts(CONTENT_CHUNK_OBJECT_KIND, 4 * MIB)).unwrap();
    assert_eq!(content.parts().identity().object_kind, 0x0a);
    assert_eq!(content.into_parts().ciphertext().len(), 4 * MIB);
}

#[test]
fn chunk_envelopes_reject_wrong_kinds_and_lengths() {
    assert!(matches!(
        ChunkKeyEnvelope::try_from_parts(parts(CONTENT_CHUNK_OBJECT_KIND, 32)),
        Err(CryptoError::InvalidEnvelope),
    ));
    assert!(matches!(
        ContentChunkEnvelope::try_from_parts(parts(CHUNK_KEY_OBJECT_KIND, 32)),
        Err(CryptoError::InvalidEnvelope),
    ));
    for length in [0, 31, 33] {
        assert!(matches!(
            ChunkKeyEnvelope::try_from_parts(parts(CHUNK_KEY_OBJECT_KIND, length)),
            Err(CryptoError::InvalidPlaintextLength),
        ));
    }
    assert!(ContentChunkEnvelope::validate_ciphertext_len(4 * MIB).is_ok());
    assert!(matches!(
        ContentChunkEnvelope::validate_ciphertext_len(4 * MIB + 1),
        Err(CryptoError::PlaintextTooLarge),
    ));
}

#[test]
fn chunk_contexts_check_profile_format_and_exact_reserved_kind() {
    assert_eq!(ChunkKeyWrapContext::OBJECT_KIND, 0x09);
    assert_eq!(ContentChunkContext::OBJECT_KIND, 0x0a);
    assert!(ChunkKeyWrapContext::try_new(identity(CHUNK_KEY_OBJECT_KIND)).is_ok());
    assert!(ContentChunkContext::try_new(identity(CONTENT_CHUNK_OBJECT_KIND)).is_ok());

    for invalid in [
        PublicEnvelopeIdentity {
            profile_id: 2,
            ..identity(CHUNK_KEY_OBJECT_KIND)
        },
        PublicEnvelopeIdentity {
            format_version: 2,
            ..identity(CHUNK_KEY_OBJECT_KIND)
        },
        identity(CONTENT_CHUNK_OBJECT_KIND),
    ] {
        assert!(matches!(
            ChunkKeyWrapContext::try_new(invalid),
            Err(CryptoError::InvalidEnvelope),
        ));
    }
}

#[test]
fn chunk_plaintext_and_fingerprint_checked_constructors_enforce_bounds() {
    assert!(ContentChunkPlaintext::try_new(vec![0; 4 * MIB]).is_ok());
    assert!(matches!(
        ContentChunkPlaintext::try_new(vec![0; 4 * MIB + 1]),
        Err(CryptoError::PlaintextTooLarge),
    ));
    let _context = ChunkFingerprintContext::profile_one();

    let fingerprint = ChunkFingerprint::try_from_protected_bytes(&[7; 32]).unwrap();
    assert_eq!(fingerprint.into_protected_bytes(), [7; 32]);
    for invalid in [&[0_u8; 31][..], &[0_u8; 33][..]] {
        assert!(matches!(
            ChunkFingerprint::try_from_protected_bytes(invalid),
            Err(CryptoError::InvalidPlaintextLength),
        ));
    }
}
