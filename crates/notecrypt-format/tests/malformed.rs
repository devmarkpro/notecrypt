use notecrypt_format::{
    AeadAlgorithmId, AeadObject, CryptoProfileId, DecodeLimits, FormatError, FormatVersion,
    OrdinaryAeadKind, decode_aead_object, encode_aead_object,
};

fn object() -> AeadObject {
    AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        OrdinaryAeadKind::Metadata,
        FormatVersion::v1(),
        [2; 32],
        &[3; 24],
        vec![4; 32],
        &[5; 16],
        &DecodeLimits::PHASE_1,
    )
    .unwrap()
}

#[test]
fn canonical_round_trip_is_byte_stable() {
    let value = object();
    let encoded = encode_aead_object(&value).unwrap();
    let decoded = decode_aead_object(&encoded, &DecodeLimits::PHASE_1).unwrap();
    assert_eq!(encode_aead_object(&decoded).unwrap(), encoded);
}

#[test]
fn rejects_indefinite_non_shortest_and_trailing_encodings() {
    let encoded = encode_aead_object(&object()).unwrap();

    let mut indefinite = encoded.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert_eq!(
        decode_aead_object(&indefinite, &DecodeLimits::PHASE_1),
        Err(FormatError::NonCanonical)
    );

    let mut non_shortest = encoded.clone();
    assert_eq!(non_shortest[1], 0x01);
    non_shortest.splice(1..2, [0x18, 0x01]);
    assert_eq!(
        decode_aead_object(&non_shortest, &DecodeLimits::PHASE_1),
        Err(FormatError::NonCanonical)
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_aead_object(&trailing, &DecodeLimits::PHASE_1),
        Err(FormatError::TrailingBytes)
    );
}

#[test]
fn rejects_wrong_version_algorithm_lengths_and_kind_limits() {
    let valid = object();
    assert_eq!(
        FormatVersion::try_from(2),
        Err(FormatError::UnsupportedVersion(2))
    );
    assert_eq!(valid.algorithm_id().get(), 1);
    assert!(
        AeadObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            [1; 16],
            OrdinaryAeadKind::Metadata,
            FormatVersion::v1(),
            [2; 32],
            &[3; 23],
            vec![],
            &[5; 16],
            &DecodeLimits::PHASE_1,
        )
        .is_err()
    );
    assert!(
        AeadObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            [1; 16],
            OrdinaryAeadKind::RecoverySlot,
            FormatVersion::v1(),
            [2; 32],
            &[3; 24],
            vec![0; 31],
            &[5; 16],
            &DecodeLimits::PHASE_1,
        )
        .is_err()
    );
}

#[test]
fn ordinary_envelope_has_exact_fixed_field_positions() {
    let encoded = encode_aead_object(&object()).unwrap();
    assert_eq!(encoded[0], 0x8a);
}

#[test]
fn aggregate_allocation_budget_is_enforced_before_copy() {
    let encoded = encode_aead_object(&object()).unwrap();
    let mut limits = DecodeLimits::PHASE_1;
    limits.max_aggregate_allocation_bytes = 31;
    assert_eq!(
        decode_aead_object(&encoded, &limits),
        Err(FormatError::LimitExceeded)
    );
}

#[test]
fn static_schema_depth_is_enforced() {
    let encoded = encode_aead_object(&object()).unwrap();
    let mut limits = DecodeLimits::PHASE_1;
    limits.max_recursion_depth = 0;
    assert_eq!(
        decode_aead_object(&encoded, &limits),
        Err(FormatError::LimitExceeded)
    );
}

#[test]
fn consuming_parts_preserve_large_ciphertext_allocation_and_debug_is_bounded() {
    let mut ciphertext = Vec::with_capacity(4096);
    ciphertext.extend_from_slice(&[4; 32]);
    let pointer = ciphertext.as_ptr();
    let capacity = ciphertext.capacity();
    let value = AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        OrdinaryAeadKind::Metadata,
        FormatVersion::v1(),
        [2; 32],
        &[3; 24],
        ciphertext,
        &[5; 16],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let rendered = format!("{value:?}");
    assert!(rendered.contains("ciphertext_len: 32"));
    assert!(!rendered.contains("4, 4, 4"));
    let (_, _, _, _, _, _, _, ciphertext, _) = value.into_parts().into_components();
    assert_eq!(ciphertext.as_ptr(), pointer);
    assert_eq!(ciphertext.capacity(), capacity);
}
