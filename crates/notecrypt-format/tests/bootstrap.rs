use notecrypt_format::{
    AeadAlgorithmId, AeadObject, BootstrapHeader, CryptoProfileId, CryptoSuite, DecodeLimits,
    FormatVersion, KdfParameters, KdfProfileId, OrdinaryAeadKind, RecoverySlot, decode_bootstrap,
    encode_bootstrap,
};

fn recovery_slot(seed: u8) -> RecoverySlot {
    let envelope = AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        OrdinaryAeadKind::RecoverySlot,
        FormatVersion::v1(),
        [seed; 32],
        &[seed.wrapping_add(1); 24],
        vec![seed.wrapping_add(2); 32],
        &[seed.wrapping_add(3); 16],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    RecoverySlot::try_new(envelope).unwrap()
}

#[test]
fn bootstrap_round_trip_is_canonical_and_bounded() {
    let kdf = KdfParameters::try_new(KdfProfileId::argon2id_v1(), 65_536, 3, 1, &[9; 16]).unwrap();
    let header = BootstrapHeader::try_new(
        FormatVersion::v1(),
        CryptoSuite::profile_one(),
        [1; 16],
        kdf,
        vec![recovery_slot(4)],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let encoded = encode_bootstrap(&header).unwrap();
    let decoded = decode_bootstrap(&encoded, &DecodeLimits::PHASE_1).unwrap();
    assert_eq!(encode_bootstrap(&decoded).unwrap(), encoded);
    assert_eq!(decoded.recovery_slots().len(), 1);
}

#[test]
fn bootstrap_rejects_kdf_bounds_and_slot_cross_context() {
    assert!(KdfParameters::try_new(KdfProfileId::argon2id_v1(), 65_535, 3, 1, &[0; 16]).is_err());
    assert!(KdfParameters::try_new(KdfProfileId::argon2id_v1(), 65_536, 11, 1, &[0; 16]).is_err());
    let wrong = AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        OrdinaryAeadKind::DeviceSlot,
        FormatVersion::v1(),
        [2; 32],
        &[3; 24],
        vec![4; 32],
        &[5; 16],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    assert!(RecoverySlot::try_new(wrong).is_err());
}
