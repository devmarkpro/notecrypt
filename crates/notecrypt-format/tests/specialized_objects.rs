use minicbor::Encoder;
use notecrypt_format::{
    AeadAlgorithmId, AuthenticationAlgorithmId, CompactChunkKey, ContentChunkObject,
    CryptoProfileId, DecodeLimits, FormatError, FormatVersion, HeadPayload, HeadRecord,
    LocalRecordType, LocalStatePayload, LocalStateRecord, SnapshotObject, decode_content_chunk,
    decode_head, decode_head_payload, decode_local_state, decode_local_state_payload,
    decode_snapshot_object, encode_content_chunk, encode_head, encode_local_state,
    encode_snapshot_object,
};

#[test]
fn snapshot_and_mac_records_use_distinct_canonical_schemas() {
    let snapshot = SnapshotObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [2; 32],
        &[3; 24],
        vec![4; 20],
        &[5; 16],
        &[6; 32],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_snapshot_object(&snapshot).unwrap();
    assert_eq!(bytes[0], 0x8c);
    assert_eq!(
        encode_snapshot_object(&decode_snapshot_object(&bytes, &DecodeLimits::PHASE_1).unwrap())
            .unwrap(),
        bytes
    );

    let head = HeadRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [2; 32],
        HeadPayload::new([7; 32], [8; 32], [9; 32]),
        &[8; 32],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let head_bytes = encode_head(&head).unwrap();
    assert_eq!(
        encode_head(&decode_head(&head_bytes, &DecodeLimits::PHASE_1).unwrap()).unwrap(),
        head_bytes
    );

    let local = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [3; 32],
        LocalStatePayload::try_new(
            LocalRecordType::Cleanup,
            [9; 32],
            vec![9; 12],
            &DecodeLimits::PHASE_1,
        )
        .unwrap(),
        &[10; 32],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let local_bytes = encode_local_state(&local).unwrap();
    assert_eq!(
        encode_local_state(&decode_local_state(&local_bytes, &DecodeLimits::PHASE_1).unwrap())
            .unwrap(),
        local_bytes
    );
}

#[test]
fn unverified_mac_records_expose_only_authenticator_covered_untrusted_bytes() {
    let head = HeadRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [2; 32],
        HeadPayload::new([7; 32], [8; 32], [9; 32]),
        &[8; 32],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let mut head_bytes = encode_head(&head).unwrap();
    let payload_start = head_bytes
        .windows(3)
        .position(|window| window == [0x84, 0x01, 0x58])
        .unwrap();
    head_bytes[payload_start] = 0x80;
    let unverified = decode_head(&head_bytes, &DecodeLimits::PHASE_1).unwrap();
    assert!(
        decode_head_payload(unverified.untrusted_payload_bytes(), &DecodeLimits::PHASE_1).is_err()
    );

    let local = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [3; 32],
        LocalStatePayload::try_new(
            LocalRecordType::Cleanup,
            [9; 32],
            vec![9; 12],
            &DecodeLimits::PHASE_1,
        )
        .unwrap(),
        &[10; 32],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let mut local_bytes = encode_local_state(&local).unwrap();
    let payload_start = local_bytes
        .windows(3)
        .position(|window| window == [0x85, 0x01, 0x04])
        .unwrap();
    local_bytes[payload_start] = 0x80;
    let unverified = decode_local_state(&local_bytes, &DecodeLimits::PHASE_1).unwrap();
    assert!(
        decode_local_state_payload(unverified.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)
            .is_err()
    );
}

#[test]
fn content_chunk_uses_compact_inherited_identity_wrapper() {
    let wrapper = CompactChunkKey::try_new(
        AeadAlgorithmId::xchacha20_poly1305(),
        &[4; 24],
        vec![5; 32],
        &[6; 16],
    )
    .unwrap();
    assert!(wrapper.encoded_len().unwrap() <= 128);
    let content = ContentChunkObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        [1; 16],
        FormatVersion::v1(),
        [2; 32],
        &[3; 24],
        wrapper,
        vec![7; 1024],
        &[8; 16],
    )
    .unwrap();
    let bytes = encode_content_chunk(&content).unwrap();
    let decoded = decode_content_chunk(&bytes, &DecodeLimits::PHASE_1).unwrap();
    assert_eq!(encode_content_chunk(&decoded).unwrap(), bytes);
    assert_eq!(decoded.object_id(), &[2; 32]);
}

#[test]
fn oversized_compact_wrapper_ciphertext_rejects_before_copy() {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(11)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .u8(10)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[2; 32])
        .unwrap()
        .bytes(&[3; 24])
        .unwrap()
        .u64(1)
        .unwrap()
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .u8(9)
        .unwrap()
        .bytes(&[4; 24])
        .unwrap()
        .u64(32)
        .unwrap()
        .bytes(&[5; 33])
        .unwrap()
        .bytes(&[6; 16])
        .unwrap()
        .bytes(&[7])
        .unwrap()
        .bytes(&[8; 16])
        .unwrap();
    let mut limits = DecodeLimits::PHASE_1;
    limits.max_aggregate_allocation_bytes = 0;
    assert!(matches!(
        decode_content_chunk(&encoder.into_writer(), &limits),
        Err(FormatError::InvalidLength)
    ));
}

#[test]
fn whole_mac_record_limit_includes_framing_and_authenticator() {
    let mut limits = DecodeLimits::PHASE_1;
    limits.max_head_bytes = 100;
    assert!(
        HeadRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            [1; 16],
            FormatVersion::v1(),
            [2; 32],
            HeadPayload::new([0; 32], [0; 32], [0; 32]),
            &[3; 32],
            &DecodeLimits::PHASE_1,
        )
        .is_ok()
    );
    let bytes = encode_head(
        &HeadRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            [1; 16],
            FormatVersion::v1(),
            [2; 32],
            HeadPayload::new([0; 32], [0; 32], [0; 32]),
            &[3; 32],
            &DecodeLimits::PHASE_1,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(decode_head(&bytes, &limits).is_err());
}
