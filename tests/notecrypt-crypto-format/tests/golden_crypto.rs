use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

use notecrypt_crypto::*;
use notecrypt_format::*;

struct FixedRandom(u8);
impl SecureRandom for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

fn identity(kind: u8, object_id: [u8; 32]) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [1; 16],
        object_kind: kind,
        format_version: 1,
        object_id,
    }
}

fn ordinary_kind(kind: u8) -> OrdinaryAeadKind {
    match kind {
        RECOVERY_SLOT_OBJECT_KIND => OrdinaryAeadKind::RecoverySlot,
        DEVICE_SLOT_OBJECT_KIND => OrdinaryAeadKind::DeviceSlot,
        METADATA_OBJECT_KIND => OrdinaryAeadKind::Metadata,
        TREE_OBJECT_KIND => OrdinaryAeadKind::Tree,
        MANIFEST_OBJECT_KIND => OrdinaryAeadKind::Manifest,
        _ => panic!("ordinary fixture kind"),
    }
}

fn ordinary_wire(parts: AeadEnvelopeParts) -> AeadObject {
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

fn protected_cases(fingerprint: [u8; 32]) -> Vec<(&'static str, Vec<u8>)> {
    let content = ContentPayload::try_new([14; 16], 0, b"fixture-content".to_vec()).unwrap();
    let manifest = RevisionManifest::try_new(
        [14; 16],
        [15; 32],
        vec![ChunkDescriptor::try_new([10; 32], &fingerprint, 15).unwrap()],
        15,
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let tree = LogicalTree::try_new(
        [16; 16],
        vec![
            TreeEntry::root([16; 16]),
            TreeEntry::file(
                [17; 16],
                [16; 16],
                "fixture.md",
                [15; 32],
                &DecodeLimits::PHASE_1,
            )
            .unwrap(),
        ],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let snapshot = SnapshotPayload::try_new(
        [18; 32],
        vec![[19; 32]],
        [5; 32],
        [20; 16],
        "fixture-device",
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let head = HeadPayload::new([18; 32], [7; 32], [5; 32]);
    let local = LocalStatePayload::try_new(
        LocalRecordType::TrustedHead,
        [21; 32],
        b"fixture-local".to_vec(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    vec![
        ("content_payload", encode_content_payload(&content).unwrap()),
        ("manifest_payload", encode_manifest(&manifest).unwrap()),
        ("tree_payload", encode_tree(&tree).unwrap()),
        (
            "snapshot_payload",
            encode_snapshot_payload(&snapshot).unwrap(),
        ),
        ("head_payload", encode_head_payload(&head).unwrap()),
        ("local_payload", encode_local_state_payload(&local).unwrap()),
    ]
}

fn crypto_cases() -> Vec<(&'static str, Vec<u8>)> {
    let mut random = FixedRandom(1);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let mut fingerprint_semantics = Vec::from([14; 16]);
    fingerprint_semantics.extend_from_slice(&0_u64.to_be_bytes());
    let fingerprint = fingerprint_chunk(
        &ChunkFingerprintContext::profile_one(),
        &fingerprint_semantics,
        b"fixture-content",
        &keys.chunk_fingerprint,
    )
    .unwrap()
    .into_protected_bytes();
    let protected = protected_cases(fingerprint);
    let fixture = |name: &str| {
        protected
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .unwrap()
            .1
            .clone()
    };

    let recovery_key = derive_recovery_wrapping_key(
        &RecoveryPassphrase::new("alpha bravo charlie delta echo foxtrot".into()),
        &[22; 16],
        ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        })
        .unwrap(),
        &AtomicBool::new(false),
    )
    .unwrap();
    let recovery = encrypt_recovery_slot(
        &RecoverySlotContext::try_new(identity(RECOVERY_SLOT_OBJECT_KIND, [2; 32])).unwrap(),
        RecoverySlotPlaintext::from_root_key(&root),
        &recovery_key,
        &mut random,
    )
    .unwrap();
    let recovery = encode_aead_object(&ordinary_wire(recovery.into_parts())).unwrap();
    let header = BootstrapHeader::try_new(
        FormatVersion::v1(),
        CryptoSuite::profile_one(),
        [1; 16],
        KdfParameters::try_new(KdfProfileId::argon2id_v1(), 65_536, 3, 1, &[22; 16]).unwrap(),
        vec![
            RecoverySlot::try_new(decode_aead_object(&recovery, &DecodeLimits::PHASE_1).unwrap())
                .unwrap(),
        ],
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let device_key = DeviceWrappingKey::try_from_protected_bytes(vec![23; 32]).unwrap();
    let device = encrypt_device_slot(
        &DeviceSlotContext::try_new(identity(DEVICE_SLOT_OBJECT_KIND, [3; 32])).unwrap(),
        DeviceSlotPlaintext::from_root_key(&root),
        &device_key,
        &mut random,
    )
    .unwrap();
    let metadata = encrypt_metadata(
        &MetadataContext::try_new(identity(METADATA_OBJECT_KIND, [4; 32])).unwrap(),
        MetadataPlaintext::try_new(b"fixture-metadata".to_vec()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let tree = encrypt_tree(
        &TreeContext::try_new(identity(TREE_OBJECT_KIND, [5; 32])).unwrap(),
        TreePlaintext::try_new(fixture("tree_payload")).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let manifest = encrypt_manifest(
        &ManifestContext::try_new(identity(MANIFEST_OBJECT_KIND, [6; 32])).unwrap(),
        ManifestPlaintext::try_new(fixture("manifest_payload")).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let snapshot = encrypt_snapshot(
        &SnapshotContext::try_new(identity(SNAPSHOT_OBJECT_KIND, [7; 32])).unwrap(),
        SnapshotPlaintext::try_new(fixture("snapshot_payload")).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut random,
    )
    .unwrap();
    let (snapshot_parts, snapshot_authenticator) = snapshot.into_parts();
    let (snapshot_identity, snapshot_nonce, snapshot_ciphertext, snapshot_tag) =
        snapshot_parts.into_public_parts().into_components();
    let snapshot = SnapshotObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        snapshot_identity.vault_id,
        FormatVersion::v1(),
        snapshot_identity.object_id,
        &snapshot_nonce,
        snapshot_ciphertext,
        &snapshot_tag,
        &snapshot_authenticator,
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let head_payload =
        decode_head_payload(&fixture("head_payload"), &DecodeLimits::PHASE_1).unwrap();
    let head_authenticator = authenticate_head(
        &AuthenticatedHeadContext::try_new(identity(AUTHENTICATED_HEAD_OBJECT_KIND, [8; 32]))
            .unwrap(),
        &fixture("head_payload"),
        &keys.snapshot_authentication,
    )
    .unwrap();
    let head = HeadRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [8; 32],
        head_payload,
        head_authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let local_payload =
        decode_local_state_payload(&fixture("local_payload"), &DecodeLimits::PHASE_1).unwrap();
    let local_authenticator = authenticate_local_state(
        &LocalStateContext::try_new(identity(LOCAL_STATE_OBJECT_KIND, [9; 32])).unwrap(),
        &fixture("local_payload"),
        &keys.local_verification,
    )
    .unwrap();
    let local = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        [1; 16],
        FormatVersion::v1(),
        [9; 32],
        local_payload,
        local_authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let chunk_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let content = encrypt_content_chunk(
        &ContentChunkContext::try_new(identity(CONTENT_CHUNK_OBJECT_KIND, [10; 32])).unwrap(),
        ContentChunkPlaintext::try_new(fixture("content_payload")).unwrap(),
        &chunk_key,
        &mut random,
    )
    .unwrap();
    let wrapper = wrap_chunk_key(
        &ChunkKeyWrapContext::try_new(identity(CHUNK_KEY_OBJECT_KIND, [10; 32])).unwrap(),
        chunk_key,
        &keys.content_wrapping,
        &mut random,
    )
    .unwrap();
    let (content_identity, content_nonce, content_ciphertext, content_tag) =
        content.into_parts().into_public_parts().into_components();
    let (wrapper_identity, wrapper_nonce, wrapper_ciphertext, wrapper_tag) =
        wrapper.into_parts().into_public_parts().into_components();
    assert_eq!(wrapper_identity.profile_id, content_identity.profile_id);
    assert_eq!(wrapper_identity.vault_id, content_identity.vault_id);
    assert_eq!(
        wrapper_identity.format_version,
        content_identity.format_version
    );
    assert_eq!(wrapper_identity.object_id, content_identity.object_id);
    assert_eq!(wrapper_identity.object_kind, CHUNK_KEY_OBJECT_KIND);
    assert_eq!(content_identity.object_kind, CONTENT_CHUNK_OBJECT_KIND);
    let content = ContentChunkObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        content_identity.vault_id,
        FormatVersion::v1(),
        content_identity.object_id,
        &content_nonce,
        CompactChunkKey::try_new(
            AeadAlgorithmId::xchacha20_poly1305(),
            &wrapper_nonce,
            wrapper_ciphertext,
            &wrapper_tag,
        )
        .unwrap(),
        content_ciphertext,
        &content_tag,
    )
    .unwrap();

    let mut cases = vec![
        ("bootstrap", encode_bootstrap(&header).unwrap()),
        ("recovery", recovery),
        (
            "device",
            encode_aead_object(&ordinary_wire(device.into_parts())).unwrap(),
        ),
        (
            "metadata",
            encode_aead_object(&ordinary_wire(metadata.into_parts())).unwrap(),
        ),
        (
            "tree_object",
            encode_aead_object(&ordinary_wire(tree.into_parts())).unwrap(),
        ),
        (
            "manifest_object",
            encode_aead_object(&ordinary_wire(manifest.into_parts())).unwrap(),
        ),
        (
            "snapshot_object",
            encode_snapshot_object(&snapshot).unwrap(),
        ),
        ("head", encode_head(&head).unwrap()),
        ("local", encode_local_state(&local).unwrap()),
        ("content_chunk", encode_content_chunk(&content).unwrap()),
    ];
    cases.extend(protected);
    cases
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn fixed_crypto_profile_reproduces_every_public_fixture() {
    let cases = crypto_cases();
    if std::env::var_os("NOTECRYPT_PRINT_FIXTURES").is_some() {
        for (name, bytes) in cases {
            println!("{name}|{}|{}", blake3::hash(&bytes).to_hex(), hex(&bytes));
        }
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/notecrypt-format/tests/fixtures/v1");
    for (name, bytes) in cases {
        let fixture = fs::read_to_string(root.join(format!("{name}.hex"))).unwrap();
        assert_eq!(
            unhex(fixture.trim()),
            bytes,
            "profile fixture replacement requires a format-version decision: {name}"
        );
    }
}
