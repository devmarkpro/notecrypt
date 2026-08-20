use notecrypt_crypto::{
    ChunkKeyPlaintext, ChunkKeyWrapContext, ContentChunkContext, ContentChunkPlaintext,
    ManifestContext, ManifestPlaintext, MetadataContext, MetadataPlaintext, PublicEnvelopeIdentity,
    SecureRandom, SnapshotContext, SnapshotPlaintext, TreeContext, TreePlaintext,
    TypedAeadEnvelope, VaultRootKey, derive_vault_keys, encrypt_content_chunk, encrypt_manifest,
    encrypt_metadata, encrypt_snapshot, encrypt_tree, wrap_chunk_key,
};
use notecrypt_format::{
    AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, ChunkDescriptor, CompactChunkKey,
    ContentChunkObject, ContentPayload, CryptoProfileId, DecodeLimits, FormatVersion, LogicalTree,
    OrdinaryAeadKind, RevisionLocator, RevisionManifest, SnapshotObject, SnapshotParentLocator,
    SnapshotPayload, TreeEntry, encode_aead_object, encode_content_chunk, encode_content_payload,
    encode_manifest, encode_snapshot_object, encode_snapshot_payload, encode_tree,
};

struct FixedRandom(u8);
impl SecureRandom for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), notecrypt_crypto::CryptoError> {
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

fn assert_absent(public: &[u8], canaries: &[&[u8]]) {
    for canary in canaries {
        assert!(!public.windows(canary.len()).any(|window| window == *canary));
    }
}

#[test]
fn every_public_object_hides_graph_counts_lengths_and_sequence() {
    let limits = DecodeLimits::PHASE_1;
    let mut random = FixedRandom(60);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let vault = [61; 16];

    let tree_name = b"tree-name-canary";
    let tree = LogicalTree::try_new(
        [0xa1; 16],
        vec![
            TreeEntry::root([0xa1; 16]),
            TreeEntry::file(
                [0xa2; 16],
                [0xa1; 16],
                std::str::from_utf8(tree_name).unwrap(),
                RevisionLocator::new([0xa3; 32], [0xa4; 32]),
                &limits,
            )
            .unwrap(),
        ],
        &limits,
    )
    .unwrap();
    let id = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: vault,
        object_kind: TreeContext::OBJECT_KIND,
        format_version: 1,
        object_id: [1; 32],
    };
    let encrypted = encrypt_tree(
        &TreeContext::try_new(id).unwrap(),
        TreePlaintext::try_new(encode_tree(&tree).unwrap()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let p = encrypted.parts();
    let public = encode_aead_object(
        &AeadObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            vault,
            OrdinaryAeadKind::Tree,
            FormatVersion::v1(),
            [1; 32],
            p.nonce(),
            p.ciphertext().to_vec(),
            p.tag(),
            &limits,
        )
        .unwrap(),
    )
    .unwrap();
    assert_absent(
        &public,
        &[
            tree_name,
            &[0xa1; 16],
            &[0xa2; 16],
            &[0xa3; 32],
            &[0xa4; 32],
        ],
    );

    let manifest = RevisionManifest::try_new(
        [0xb1; 16],
        [0xb2; 32],
        vec![ChunkDescriptor::try_new([0xb3; 32], &[0xb4; 32], 17).unwrap()],
        17,
        &limits,
    )
    .unwrap();
    let id = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: vault,
        object_kind: ManifestContext::OBJECT_KIND,
        format_version: 1,
        object_id: [2; 32],
    };
    let encrypted = encrypt_manifest(
        &ManifestContext::try_new(id).unwrap(),
        ManifestPlaintext::try_new(encode_manifest(&manifest).unwrap()).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let p = encrypted.parts();
    let public = encode_aead_object(
        &AeadObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            vault,
            OrdinaryAeadKind::Manifest,
            FormatVersion::v1(),
            [2; 32],
            p.nonce(),
            p.ciphertext().to_vec(),
            p.tag(),
            &limits,
        )
        .unwrap(),
    )
    .unwrap();
    assert_absent(
        &public,
        &[&[0xb1; 16], &[0xb2; 32], &[0xb3; 32], &[0xb4; 32]],
    );

    let snapshot = SnapshotPayload::try_new(
        [0xc1; 32],
        vec![
            SnapshotParentLocator::new([0xc2; 32], [0xc6; 32]),
            SnapshotParentLocator::new([0xc3; 32], [0xc7; 32]),
        ],
        [0xc4; 32],
        [0xc5; 16],
        "device-label-canary",
        &limits,
    )
    .unwrap();
    let id = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: vault,
        object_kind: SnapshotContext::OBJECT_KIND,
        format_version: 1,
        object_id: [3; 32],
    };
    let encrypted = encrypt_snapshot(
        &SnapshotContext::try_new(id).unwrap(),
        SnapshotPlaintext::try_new(encode_snapshot_payload(&snapshot).unwrap()).unwrap(),
        &keys.metadata,
        &keys.snapshot_authentication,
        &mut random,
    )
    .unwrap();
    let p = encrypted.encrypted_parts();
    let public = encode_snapshot_object(
        &SnapshotObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            vault,
            FormatVersion::v1(),
            [3; 32],
            p.nonce(),
            p.ciphertext().to_vec(),
            p.tag(),
            encrypted.outer_authenticator(),
            &limits,
        )
        .unwrap(),
    )
    .unwrap();
    assert_absent(
        &public,
        &[
            &[0xc1; 32],
            &[0xc2; 32],
            &[0xc3; 32],
            &[0xc4; 32],
            &[0xc6; 32],
            &[0xc7; 32],
            &[0xc5; 16],
            b"device-label-canary",
        ],
    );

    let content_plain = encode_content_payload(
        &ContentPayload::try_new(
            [0xd1; 16],
            0x0102_0304_0506_0708,
            b"content-canary".to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    let content_id = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: vault,
        object_kind: ContentChunkContext::OBJECT_KIND,
        format_version: 1,
        object_id: [4; 32],
    };
    let wrap_id = PublicEnvelopeIdentity {
        object_kind: ChunkKeyWrapContext::OBJECT_KIND,
        ..content_id
    };
    let content_context = ContentChunkContext::try_new(content_id).unwrap();
    let wrap_context = ChunkKeyWrapContext::try_new(wrap_id).unwrap();
    let key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let content = encrypt_content_chunk(
        &content_context,
        ContentChunkPlaintext::try_new(content_plain).unwrap(),
        &key,
        &mut random,
    )
    .unwrap();
    let wrapped = wrap_chunk_key(&wrap_context, key, &keys.content_wrapping, &mut random).unwrap();
    let cp = content.parts();
    let wp = wrapped.parts();
    let public = encode_content_chunk(
        &ContentChunkObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            vault,
            FormatVersion::v1(),
            [4; 32],
            cp.nonce(),
            CompactChunkKey::try_new(
                AeadAlgorithmId::xchacha20_poly1305(),
                wp.nonce(),
                wp.ciphertext().to_vec(),
                wp.tag(),
            )
            .unwrap(),
            cp.ciphertext().to_vec(),
            cp.tag(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_absent(
        &public,
        &[
            &[0xd1; 16],
            &0x0102_0304_0506_0708_u64.to_be_bytes(),
            b"content-canary",
        ],
    );
}

#[test]
fn encrypted_public_wire_excludes_protected_semantic_canaries() {
    let canaries = [
        b"logical-file-id-canary".as_slice(),
        b"revision-id-canary".as_slice(),
        b"snapshot-parent-canary".as_slice(),
        b"device-label-canary".as_slice(),
        b"chunk-count-canary".as_slice(),
        b"total-length-canary".as_slice(),
        b"sequence-canary".as_slice(),
    ];
    let mut plaintext = Vec::new();
    for canary in canaries {
        plaintext.extend_from_slice(canary);
        plaintext.push(0);
    }
    let mut random = FixedRandom(1);
    let root = VaultRootKey::generate(&mut random).unwrap();
    let keys = derive_vault_keys(&root).unwrap();
    let identity = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [2; 16],
        object_kind: MetadataContext::OBJECT_KIND,
        format_version: 1,
        object_id: [3; 32],
    };
    let context = MetadataContext::try_new(identity).unwrap();
    let encrypted = encrypt_metadata(
        &context,
        MetadataPlaintext::try_new(plaintext).unwrap(),
        &keys.metadata,
        &mut random,
    )
    .unwrap();
    let parts = encrypted.parts();
    let wire = AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        identity.vault_id,
        OrdinaryAeadKind::Metadata,
        FormatVersion::v1(),
        identity.object_id,
        parts.nonce(),
        parts.ciphertext().to_vec(),
        parts.tag(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let bytes = encode_aead_object(&wire).unwrap();
    for canary in canaries {
        assert!(!bytes.windows(canary.len()).any(|window| window == canary));
    }
}
