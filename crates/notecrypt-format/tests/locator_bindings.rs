use std::{fs, path::PathBuf};

use minicbor::Encoder;
use notecrypt_format::{
    DecodeLimits, FormatError, LogicalTree, PriorEntryKind, RevisionLocator, SnapshotParentLocator,
    SnapshotPayload, TreeEntry, decode_snapshot_payload, decode_tree, encode_snapshot_payload,
    encode_tree,
};

#[test]
fn tree_locators_bind_logical_revisions_to_manifest_objects() {
    let locator = RevisionLocator::new([3; 32], [4; 32]);
    let tree = LogicalTree::try_new(
        [1; 16],
        vec![
            TreeEntry::root([1; 16]),
            TreeEntry::file([2; 16], [1; 16], "note.md", locator, &DecodeLimits::PHASE_1).unwrap(),
        ],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_tree(&tree).unwrap();
    let decoded = decode_tree(&bytes, &DecodeLimits::PHASE_1).unwrap();
    let TreeEntry::File { locator, .. } = &decoded.entries()[1] else {
        panic!("expected file entry");
    };
    assert_eq!(locator.revision_id(), &[3; 32]);
    assert_eq!(locator.manifest_object_id(), &[4; 32]);
}

#[test]
fn old_draft_flat_tree_revision_is_rejected() {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(3)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .array(2)
        .unwrap()
        .array(2)
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .array(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&[2; 16])
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .str("note.md")
        .unwrap()
        .bytes(&[3; 32])
        .unwrap();
    assert!(matches!(
        decode_tree(&encoder.into_writer(), &DecodeLimits::PHASE_1),
        Err(FormatError::Malformed | FormatError::NonCanonical)
    ));
}

#[test]
fn tombstone_last_revision_uses_the_same_nested_locator_shape() {
    let tree = LogicalTree::try_new(
        [1; 16],
        vec![
            TreeEntry::root([1; 16]),
            TreeEntry::tombstone(
                [2; 16],
                [1; 16],
                "removed.md",
                [5; 32],
                PriorEntryKind::File,
                Some(RevisionLocator::new([3; 32], [4; 32])),
                &DecodeLimits::PHASE_1,
            )
            .unwrap(),
        ],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let encoded = encode_tree(&tree).unwrap();
    assert_eq!(
        encode_tree(&decode_tree(&encoded, &DecodeLimits::PHASE_1).unwrap()).unwrap(),
        encoded
    );
}

#[test]
fn old_draft_flat_tombstone_revision_is_rejected() {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(3)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .array(2)
        .unwrap()
        .array(2)
        .unwrap()
        .u8(0)
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .array(7)
        .unwrap()
        .u8(3)
        .unwrap()
        .bytes(&[2; 16])
        .unwrap()
        .bytes(&[1; 16])
        .unwrap()
        .str("removed.md")
        .unwrap()
        .bytes(&[5; 32])
        .unwrap()
        .u8(PriorEntryKind::File as u8)
        .unwrap()
        .bytes(&[3; 32])
        .unwrap();
    assert!(matches!(
        decode_tree(&encoder.into_writer(), &DecodeLimits::PHASE_1),
        Err(FormatError::Malformed | FormatError::NonCanonical)
    ));
}

#[test]
fn snapshot_parent_locators_reject_duplicate_logical_or_object_identity() {
    let limits = DecodeLimits::PHASE_1;
    assert!(matches!(
        SnapshotPayload::try_new(
            [1; 32],
            vec![
                SnapshotParentLocator::new([2; 32], [3; 32]),
                SnapshotParentLocator::new([2; 32], [4; 32]),
            ],
            [5; 32],
            [6; 16],
            "device",
            &limits,
        ),
        Err(FormatError::Malformed)
    ));
    assert!(matches!(
        SnapshotPayload::try_new(
            [1; 32],
            vec![
                SnapshotParentLocator::new([2; 32], [4; 32]),
                SnapshotParentLocator::new([3; 32], [4; 32]),
            ],
            [5; 32],
            [6; 16],
            "device",
            &limits,
        ),
        Err(FormatError::Malformed)
    ));
}

#[test]
fn snapshot_parent_pairs_are_canonical_and_old_flat_parent_is_rejected() {
    let payload = SnapshotPayload::try_new(
        [1; 32],
        vec![
            SnapshotParentLocator::new([3; 32], [5; 32]),
            SnapshotParentLocator::new([2; 32], [4; 32]),
        ],
        [6; 32],
        [7; 16],
        "device",
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_snapshot_payload(&payload).unwrap();
    assert_eq!(
        encode_snapshot_payload(&decode_snapshot_payload(&bytes, &DecodeLimits::PHASE_1).unwrap())
            .unwrap(),
        bytes
    );

    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[1; 32])
        .unwrap()
        .array(1)
        .unwrap()
        .bytes(&[2; 32])
        .unwrap()
        .bytes(&[6; 32])
        .unwrap()
        .bytes(&[7; 16])
        .unwrap()
        .str("device")
        .unwrap();
    assert!(matches!(
        decode_snapshot_payload(&encoder.into_writer(), &DecodeLimits::PHASE_1),
        Err(FormatError::Malformed | FormatError::NonCanonical)
    ));
}

#[test]
fn raw_locator_fuzz_seeds_are_valid_canonical_payloads() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/format/seeds");
    let tree = fs::read(root.join("decode_tree/locator-v1.cbor")).unwrap();
    assert_eq!(
        encode_tree(&decode_tree(&tree, &DecodeLimits::PHASE_1).unwrap()).unwrap(),
        tree
    );
    let snapshot = fs::read(root.join("decode_snapshot/locator-v1.cbor")).unwrap();
    assert_eq!(
        encode_snapshot_payload(
            &decode_snapshot_payload(&snapshot, &DecodeLimits::PHASE_1).unwrap()
        )
        .unwrap(),
        snapshot
    );
}
