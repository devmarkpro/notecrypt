use notecrypt_format::{
    AeadAlgorithmId, AuthenticationAlgorithmId, CryptoProfileId, DerivationProfileId,
    FingerprintAlgorithmId, KdfProfileId, ObjectKind,
};

#[test]
fn profile_one_identifiers_are_checked_and_stable() {
    assert_eq!(CryptoProfileId::profile_one().get(), 0x0001);
    assert_eq!(AeadAlgorithmId::xchacha20_poly1305().get(), 0x0001);
    assert_eq!(AuthenticationAlgorithmId::keyed_blake3_256().get(), 0x0002);
    assert_eq!(FingerprintAlgorithmId::keyed_blake3_256().get(), 0x0003);
    assert_eq!(KdfProfileId::argon2id_v1().get(), 0x0001);
    assert_eq!(DerivationProfileId::hkdf_sha256_v1().get(), 0x0001);

    assert!(CryptoProfileId::try_from(2).is_err());
    assert!(AeadAlgorithmId::try_from(2).is_err());
    assert!(AuthenticationAlgorithmId::try_from(1).is_err());
    assert!(FingerprintAlgorithmId::try_from(2).is_err());
    assert!(KdfProfileId::try_from(2).is_err());
    assert!(DerivationProfileId::try_from(2).is_err());
}

#[test]
fn every_phase_one_object_kind_has_one_checked_value() {
    let expected = [
        (ObjectKind::RecoverySlot, 0x01),
        (ObjectKind::DeviceSlot, 0x02),
        (ObjectKind::Metadata, 0x03),
        (ObjectKind::Tree, 0x04),
        (ObjectKind::Manifest, 0x05),
        (ObjectKind::Snapshot, 0x06),
        (ObjectKind::AuthenticatedHead, 0x07),
        (ObjectKind::LocalState, 0x08),
        (ObjectKind::ChunkKey, 0x09),
        (ObjectKind::ContentChunk, 0x0a),
    ];

    for (kind, value) in expected {
        assert_eq!(kind.get(), value);
        assert_eq!(ObjectKind::try_from(value).unwrap(), kind);
    }
    assert!(ObjectKind::try_from(0).is_err());
    assert!(ObjectKind::try_from(0x0b).is_err());
}
