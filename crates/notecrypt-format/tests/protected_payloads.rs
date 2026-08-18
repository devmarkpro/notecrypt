use minicbor::Encoder;
use notecrypt_format::{
    ChunkDescriptor, ContentPayload, DecodeLimits, FormatError, HeadPayload, LocalRecordType,
    LocalStatePayload, LogicalTree, RevisionManifest, SnapshotPayload, TreeEntry,
    decode_content_payload, decode_head_payload, decode_local_state_payload, decode_manifest,
    decode_snapshot_payload, decode_tree, encode_content_payload, encode_head_payload,
    encode_local_state_payload, encode_manifest, encode_snapshot_payload, encode_tree,
};

#[test]
fn manifest_content_and_totals_are_canonical() {
    let content = ContentPayload::try_new([1; 16], 7, vec![2; 1_048_576]).unwrap();
    let bytes = encode_content_payload(&content).unwrap();
    assert_eq!(
        encode_content_payload(&decode_content_payload(&bytes, &DecodeLimits::PHASE_1).unwrap())
            .unwrap(),
        bytes
    );

    let descriptor = ChunkDescriptor::try_new([3; 32], &[4; 32], 1_048_576).unwrap();
    let manifest = RevisionManifest::try_new(
        [1; 16],
        [5; 32],
        vec![descriptor],
        1_048_576,
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_manifest(&manifest).unwrap();
    assert_eq!(
        encode_manifest(&decode_manifest(&bytes, &DecodeLimits::PHASE_1).unwrap()).unwrap(),
        bytes
    );
    assert!(
        RevisionManifest::try_new([1; 16], [5; 32], vec![], 1, &DecodeLimits::PHASE_1).is_err()
    );
}

#[test]
fn tree_decoder_rejects_attacker_order_instead_of_sorting() {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(3)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .array(3)
        .unwrap()
        .array(2)
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .array(4)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(&[2; 16])
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .str("later")
        .unwrap()
        .array(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[0; 16])
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .str("earlier")
        .unwrap()
        .bytes(&[3; 32])
        .unwrap();
    assert!(matches!(
        decode_tree(&encoder.into_writer(), &DecodeLimits::PHASE_1),
        Err(FormatError::NonCanonical)
    ));
}

#[test]
fn tree_snapshot_head_and_local_payloads_are_canonical() {
    let entries = vec![
        TreeEntry::root([1; 16]),
        TreeEntry::file([2; 16], [1; 16], "note.md", [3; 32], &DecodeLimits::PHASE_1).unwrap(),
    ];
    let tree = LogicalTree::try_new([1; 16], entries, &DecodeLimits::PHASE_1).unwrap();
    let bytes = encode_tree(&tree).unwrap();
    assert_eq!(
        encode_tree(&decode_tree(&bytes, &DecodeLimits::PHASE_1).unwrap()).unwrap(),
        bytes
    );

    let snapshot = SnapshotPayload::try_new(
        [4; 32],
        vec![[5; 32], [6; 32]],
        [7; 32],
        [8; 16],
        "device",
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_snapshot_payload(&snapshot).unwrap();
    assert_eq!(
        encode_snapshot_payload(&decode_snapshot_payload(&bytes, &DecodeLimits::PHASE_1).unwrap())
            .unwrap(),
        bytes
    );

    let head = HeadPayload::new([4; 32], [9; 32], [7; 32]);
    let bytes = encode_head_payload(&head).unwrap();
    assert_eq!(
        encode_head_payload(&decode_head_payload(&bytes, &DecodeLimits::PHASE_1).unwrap()).unwrap(),
        bytes
    );

    let local = LocalStatePayload::try_new(
        LocalRecordType::TrustedHead,
        [10; 32],
        vec![11; 32],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_local_state_payload(&local).unwrap();
    assert_eq!(
        encode_local_state_payload(
            &decode_local_state_payload(&bytes, &DecodeLimits::PHASE_1).unwrap()
        )
        .unwrap(),
        bytes
    );
}

#[test]
fn collection_and_name_bounds_are_enforced() {
    let mut limits = DecodeLimits::PHASE_1;
    limits.max_tree_entries = 1;
    assert!(
        LogicalTree::try_new(
            [1; 16],
            vec![
                TreeEntry::root([1; 16]),
                TreeEntry::directory([2; 16], [1; 16], "d", &limits).unwrap()
            ],
            &limits
        )
        .is_err()
    );
    assert!(
        TreeEntry::directory([2; 16], [1; 16], &"x".repeat(1_025), &DecodeLimits::PHASE_1).is_err()
    );
}
