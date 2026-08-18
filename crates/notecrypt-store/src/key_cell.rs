use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};

use notecrypt_core::{ObjectId, VaultId};
use notecrypt_crypto::{
    AUTHENTICATED_HEAD_OBJECT_KIND, AeadEnvelopeParts, AuthenticatedHeadContext, ChunkFingerprint,
    ChunkFingerprintContext, ChunkKeyEnvelope, ChunkKeyPlaintext, ChunkKeyWrapContext,
    ContentChunkContext, ContentChunkEnvelope, ContentChunkPlaintext, CryptoError,
    DeviceSlotContext, DeviceSlotEnvelope, DeviceSlotPlaintext, DeviceWrappingKey,
    HeadAuthenticator, LocalStateAuthenticator, LocalStateContext, ManifestContext,
    ManifestEnvelope, ManifestPlaintext, PublicEnvelopeIdentity, SecureRandom, SnapshotContext,
    SnapshotEnvelope, SnapshotPlaintext, TreeContext, TreeEnvelope, TreePlaintext,
    TypedAeadEnvelope, VaultKeys, VaultRootKey, authenticate_head, authenticate_local_state,
    decrypt_content_chunk, decrypt_manifest, decrypt_snapshot, decrypt_tree, derive_vault_keys,
    encrypt_content_chunk, encrypt_device_slot, encrypt_manifest, encrypt_snapshot, encrypt_tree,
    fingerprint_chunk, unwrap_chunk_key, verify_chunk_fingerprint, verify_head, verify_local_state,
    wrap_chunk_key,
};
use notecrypt_format::{
    AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CompactChunkKey, ContentChunkObject,
    CryptoProfileId, DecodeLimits, FormatVersion, HeadPayload, HeadRecord, LogicalTree,
    OrdinaryAeadKind, RevisionManifest, SnapshotObject, SnapshotPayload, TreeEntry,
    decode_aead_object, decode_content_chunk, decode_content_payload, decode_manifest,
    decode_snapshot_object, decode_snapshot_payload, decode_tree, encode_aead_object,
    encode_content_chunk, encode_head, encode_head_payload, encode_snapshot_object,
};
use notecrypt_platform_fs::FileCapability;
use zeroize::Zeroizing;

use crate::StoreError;
use crate::replication::{
    AuthenticatedObjectSemantics, AuthenticatedRevisionLocator, AuthenticatedSnapshotParent,
    ImportedObjectKind, ImportedObjectMetadata, ReplicationLimits, authenticated_object_id,
};

pub(crate) struct KeyCell {
    closing: AtomicBool,
    close_fenced: AtomicBool,
    generation: AtomicU64,
    publication: Mutex<()>,
    material: RwLock<Option<KeyMaterial>>,
    #[cfg(feature = "test-support")]
    local_chunk_authentications: AtomicU64,
}

struct KeyMaterial {
    _root: VaultRootKey,
    derived: VaultKeys,
}

impl KeyCell {
    pub(crate) fn new(root: VaultRootKey) -> Result<Self, StoreError> {
        let derived = derive_vault_keys(&root)?;
        Ok(Self {
            closing: AtomicBool::new(false),
            close_fenced: AtomicBool::new(false),
            generation: AtomicU64::new(1),
            publication: Mutex::new(()),
            material: RwLock::new(Some(KeyMaterial {
                _root: root,
                derived,
            })),
            #[cfg(feature = "test-support")]
            local_chunk_authentications: AtomicU64::new(0),
        })
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn validate_generation(&self, expected_generation: u64) -> Result<(), StoreError> {
        self.validate(expected_generation)
    }

    pub(crate) fn authenticate_local(
        &self,
        expected_generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
    ) -> Result<LocalStateAuthenticator, StoreError> {
        self.with_key_boundary(expected_generation, |keys| {
            Ok(authenticate_local_state(
                context,
                canonical,
                &keys.local_verification,
            )?)
        })
    }

    pub(crate) fn verify_local(
        &self,
        expected_generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
        authenticator: &LocalStateAuthenticator,
    ) -> Result<(), StoreError> {
        self.with_key_boundary(expected_generation, |keys| {
            verify_local_state(context, canonical, authenticator, &keys.local_verification)?;
            Ok(())
        })
    }

    pub(crate) fn verify_authenticated_head(
        &self,
        expected_generation: u64,
        context: &AuthenticatedHeadContext,
        canonical: &[u8],
        authenticator: &HeadAuthenticator,
    ) -> Result<(), StoreError> {
        self.with_key_boundary(expected_generation, |keys| {
            verify_head(
                context,
                canonical,
                authenticator,
                &keys.snapshot_authentication,
            )?;
            Ok(())
        })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn verify_tree_file(
        &self,
        expected_generation: u64,
        expected_id: &ObjectId,
        file: &mut FileCapability,
    ) -> Result<(), StoreError> {
        let maximum = u64::from(DecodeLimits::PHASE_1.max_tree_bytes)
            .checked_add(256)
            .ok_or(StoreError::LimitExceeded)?;
        let bytes = read_file_bounded_exact(file, maximum, |_| Ok(()), |_| Ok(()))?;
        let object = decode_aead_object(&bytes, &DecodeLimits::PHASE_1)?;
        if object.object_id() != expected_id.as_bytes()
            || object.kind() != notecrypt_format::OrdinaryAeadKind::Tree
        {
            return Err(StoreError::AuthenticationFailed);
        }
        let (profile, _algorithm, vault, kind, version, object_id, nonce, ciphertext, tag) =
            object.into_parts().into_components();
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: vault,
            object_kind: kind.object_kind().get(),
            format_version: version.get(),
            object_id,
        };
        let context = TreeContext::try_new(identity)?;
        let envelope = TreeEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            identity, &nonce, ciphertext, &tag,
        )?)?;
        self.with_key_boundary(expected_generation, |keys| {
            let plaintext = decrypt_tree(&context, &envelope, &keys.metadata)?;
            drop(plaintext);
            Ok(())
        })
    }

    pub(crate) fn authenticate_imported_object(
        &self,
        expected_generation: u64,
        vault: VaultId,
        expected_id: ObjectId,
        kind: ImportedObjectKind,
        file: &mut FileCapability,
        mut observe: impl FnMut(ImportAuthenticationBoundary) -> Result<(), StoreError>,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        let maximum = ReplicationLimits::PHASE_1.maximum_for_kind(kind);
        let bytes = read_file_bounded_exact(
            file,
            maximum,
            |_| Ok(()),
            |_| observe(ImportAuthenticationBoundary::ReadPageComplete),
        )?;
        let encoded_length = u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?;
        match kind {
            ImportedObjectKind::Tree => self.authenticate_tree_object(
                expected_generation,
                vault,
                expected_id,
                encoded_length,
                bytes,
                &mut observe,
            ),
            ImportedObjectKind::Manifest => self.authenticate_manifest_object(
                expected_generation,
                vault,
                expected_id,
                encoded_length,
                bytes,
                &mut observe,
            ),
            ImportedObjectKind::Snapshot => self.authenticate_snapshot_object(
                expected_generation,
                vault,
                expected_id,
                encoded_length,
                bytes,
                &mut observe,
            ),
            ImportedObjectKind::Chunk => self.authenticate_chunk_object(
                expected_generation,
                vault,
                expected_id,
                encoded_length,
                bytes,
                &mut observe,
            ),
        }
    }

    fn authenticate_tree_object(
        &self,
        generation: u64,
        vault: VaultId,
        expected: ObjectId,
        encoded_length: u64,
        bytes: Vec<u8>,
        observe: &mut dyn FnMut(ImportAuthenticationBoundary) -> Result<(), StoreError>,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        let object = decode_aead_object(&bytes, &DecodeLimits::PHASE_1)?;
        if object.kind() != OrdinaryAeadKind::Tree
            || object.vault_id() != vault.as_bytes()
            || object.object_id() != expected.as_bytes()
        {
            return Err(StoreError::AuthenticationFailed);
        }
        let (profile, _algorithm, wire_vault, wire_kind, version, object_id, nonce, cipher, tag) =
            object.into_parts().into_components();
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: wire_vault,
            object_kind: wire_kind.object_kind().get(),
            format_version: version.get(),
            object_id,
        };
        let context = TreeContext::try_new(identity)?;
        let envelope = TreeEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            identity, &nonce, cipher, &tag,
        )?)?;
        self.with_key_boundary(generation, |keys| {
            observe(ImportAuthenticationBoundary::BeforeCrypto)?;
            let plaintext = decrypt_tree(&context, &envelope, &keys.metadata)?;
            observe(ImportAuthenticationBoundary::AfterCrypto)?;
            let tree = plaintext
                .into_protected_bytes()
                .consume(|plain| decode_tree(plain, &DecodeLimits::PHASE_1))?;
            observe(ImportAuthenticationBoundary::AfterProtectedDecode)?;
            let mut revisions = Vec::new();
            revisions
                .try_reserve_exact(tree.entries().len())
                .map_err(|_| StoreError::LimitExceeded)?;
            let mut references = Vec::new();
            references
                .try_reserve_exact(tree.entries().len())
                .map_err(|_| StoreError::LimitExceeded)?;
            for entry in tree.entries() {
                match entry {
                    TreeEntry::File { id, locator, .. } => {
                        let manifest = authenticated_object_id(*locator.manifest_object_id());
                        references.push(manifest);
                        revisions.push(AuthenticatedRevisionLocator {
                            file_id: *id,
                            revision_id: *locator.revision_id(),
                            manifest_object_id: manifest,
                        });
                    }
                    TreeEntry::Tombstone {
                        id,
                        last_revision: Some(locator),
                        ..
                    } => {
                        let manifest = authenticated_object_id(*locator.manifest_object_id());
                        references.push(manifest);
                        revisions.push(AuthenticatedRevisionLocator {
                            file_id: *id,
                            revision_id: *locator.revision_id(),
                            manifest_object_id: manifest,
                        });
                    }
                    _ => {}
                }
            }
            observe(ImportAuthenticationBoundary::BeforeAcceptReferences)?;
            Ok(ImportedObjectMetadata::authenticated(
                expected,
                ImportedObjectKind::Tree,
                encoded_length,
                references,
                AuthenticatedObjectSemantics::Tree { revisions },
            ))
        })
    }

    fn authenticate_manifest_object(
        &self,
        generation: u64,
        vault: VaultId,
        expected: ObjectId,
        encoded_length: u64,
        bytes: Vec<u8>,
        observe: &mut dyn FnMut(ImportAuthenticationBoundary) -> Result<(), StoreError>,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        let object = decode_aead_object(&bytes, &DecodeLimits::PHASE_1)?;
        if object.kind() != OrdinaryAeadKind::Manifest
            || object.vault_id() != vault.as_bytes()
            || object.object_id() != expected.as_bytes()
        {
            return Err(StoreError::AuthenticationFailed);
        }
        let (profile, _algorithm, wire_vault, wire_kind, version, object_id, nonce, cipher, tag) =
            object.into_parts().into_components();
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: wire_vault,
            object_kind: wire_kind.object_kind().get(),
            format_version: version.get(),
            object_id,
        };
        let context = ManifestContext::try_new(identity)?;
        let envelope = ManifestEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            identity, &nonce, cipher, &tag,
        )?)?;
        self.with_key_boundary(generation, |keys| {
            observe(ImportAuthenticationBoundary::BeforeCrypto)?;
            let plaintext = decrypt_manifest(&context, &envelope, &keys.metadata)?;
            observe(ImportAuthenticationBoundary::AfterCrypto)?;
            let manifest = plaintext
                .into_protected_bytes()
                .consume(|plain| decode_manifest(plain, &DecodeLimits::PHASE_1))?;
            observe(ImportAuthenticationBoundary::AfterProtectedDecode)?;
            let mut references = Vec::new();
            references
                .try_reserve_exact(manifest.chunks().len())
                .map_err(|_| StoreError::LimitExceeded)?;
            let mut chunks = Vec::new();
            chunks
                .try_reserve_exact(manifest.chunks().len())
                .map_err(|_| StoreError::LimitExceeded)?;
            for (position, chunk) in manifest.chunks().iter().enumerate() {
                let object_id = authenticated_object_id(*chunk.object_id());
                references.push(object_id);
                chunks.push(crate::replication::AuthenticatedChunkReference {
                    object_id,
                    position: u64::try_from(position).map_err(|_| StoreError::LimitExceeded)?,
                });
            }
            observe(ImportAuthenticationBoundary::BeforeAcceptReferences)?;
            Ok(ImportedObjectMetadata::authenticated(
                expected,
                ImportedObjectKind::Manifest,
                encoded_length,
                references,
                AuthenticatedObjectSemantics::Manifest {
                    file_id: *manifest.file_id(),
                    revision_id: *manifest.revision_id(),
                    chunks,
                },
            ))
        })
    }

    fn authenticate_snapshot_object(
        &self,
        generation: u64,
        vault: VaultId,
        expected: ObjectId,
        encoded_length: u64,
        bytes: Vec<u8>,
        observe: &mut dyn FnMut(ImportAuthenticationBoundary) -> Result<(), StoreError>,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        let object = decode_snapshot_object(&bytes, &DecodeLimits::PHASE_1)?;
        let (profile, _aead, _auth, wire_vault, version, object_id, nonce, cipher, tag, outer) =
            object.into_parts().into_components();
        if wire_vault != *vault.as_bytes() || object_id != *expected.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: wire_vault,
            object_kind: SnapshotContext::OBJECT_KIND,
            format_version: version.get(),
            object_id,
        };
        let context = SnapshotContext::try_new(identity)?;
        let envelope = SnapshotEnvelope::try_new(
            AeadEnvelopeParts::try_new(identity, &nonce, cipher, &tag)?,
            &outer,
        )?;
        self.with_key_boundary(generation, |keys| {
            observe(ImportAuthenticationBoundary::BeforeCrypto)?;
            let plaintext = decrypt_snapshot(
                &context,
                &envelope,
                &keys.metadata,
                &keys.snapshot_authentication,
            )?;
            observe(ImportAuthenticationBoundary::AfterCrypto)?;
            let snapshot = plaintext
                .into_protected_bytes()
                .consume(|plain| decode_snapshot_payload(plain, &DecodeLimits::PHASE_1))?;
            observe(ImportAuthenticationBoundary::AfterProtectedDecode)?;
            let tree_object_id = authenticated_object_id(*snapshot.tree_object_id());
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(snapshot.parents().len())
                .map_err(|_| StoreError::LimitExceeded)?;
            let mut references = Vec::new();
            references
                .try_reserve_exact(snapshot.parents().len().saturating_add(1))
                .map_err(|_| StoreError::LimitExceeded)?;
            references.push(tree_object_id);
            for parent in snapshot.parents() {
                let object_id = authenticated_object_id(*parent.snapshot_object_id());
                references.push(object_id);
                parents.push(AuthenticatedSnapshotParent {
                    snapshot_id: *parent.snapshot_id(),
                    snapshot_object_id: object_id,
                });
            }
            observe(ImportAuthenticationBoundary::BeforeAcceptReferences)?;
            Ok(ImportedObjectMetadata::authenticated(
                expected,
                ImportedObjectKind::Snapshot,
                encoded_length,
                references,
                AuthenticatedObjectSemantics::Snapshot {
                    snapshot_id: *snapshot.snapshot_id(),
                    parents,
                    tree_object_id,
                },
            ))
        })
    }

    fn authenticate_chunk_object(
        &self,
        generation: u64,
        vault: VaultId,
        expected: ObjectId,
        encoded_length: u64,
        bytes: Vec<u8>,
        observe: &mut dyn FnMut(ImportAuthenticationBoundary) -> Result<(), StoreError>,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        let object = decode_content_chunk(&bytes, &DecodeLimits::PHASE_1)?;
        if object.vault_id() != vault.as_bytes() || object.object_id() != expected.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let (_profile, _algorithm, wire_vault, version, object_id, nonce, wrapper, cipher, tag) =
            object.into_parts().into_components();
        let wrap_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: wire_vault,
            object_kind: ChunkKeyWrapContext::OBJECT_KIND,
            format_version: version.get(),
            object_id,
        };
        let content_identity = PublicEnvelopeIdentity {
            object_kind: ContentChunkContext::OBJECT_KIND,
            ..wrap_identity
        };
        let wrap_context = ChunkKeyWrapContext::try_new(wrap_identity)?;
        let content_context = ContentChunkContext::try_new(content_identity)?;
        let wrapped = ChunkKeyEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            wrap_identity,
            wrapper.nonce(),
            wrapper.ciphertext().to_vec(),
            wrapper.tag(),
        )?)?;
        let content = ContentChunkEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            content_identity,
            &nonce,
            cipher,
            &tag,
        )?)?;
        self.with_key_boundary(generation, |keys| {
            observe(ImportAuthenticationBoundary::BeforeCrypto)?;
            let key = unwrap_chunk_key(&wrap_context, &wrapped, &keys.content_wrapping)?;
            observe(ImportAuthenticationBoundary::AfterCrypto)?;
            observe(ImportAuthenticationBoundary::BeforeCrypto)?;
            let plaintext = decrypt_content_chunk(&content_context, &content, &key)?;
            observe(ImportAuthenticationBoundary::AfterCrypto)?;
            let payload = plaintext
                .into_protected_bytes()
                .consume(|plain| decode_content_payload(plain, &DecodeLimits::PHASE_1))?;
            observe(ImportAuthenticationBoundary::AfterProtectedDecode)?;
            observe(ImportAuthenticationBoundary::BeforeAcceptReferences)?;
            Ok(ImportedObjectMetadata::authenticated(
                expected,
                ImportedObjectKind::Chunk,
                encoded_length,
                Vec::new(),
                AuthenticatedObjectSemantics::Chunk {
                    file_id: *payload.file_id(),
                    position: payload.position(),
                },
            ))
        })
    }

    pub(crate) fn fingerprint_local_chunk(
        &self,
        generation: u64,
        file_id: [u8; 16],
        position: u64,
        plaintext: &[u8],
    ) -> Result<[u8; 32], StoreError> {
        let semantics = chunk_semantics(file_id, position);
        self.with_key_boundary(generation, |keys| {
            Ok(fingerprint_chunk(
                &ChunkFingerprintContext::profile_one(),
                &semantics,
                plaintext,
                &keys.chunk_fingerprint,
            )?
            .into_protected_bytes())
        })
    }

    pub(crate) fn local_chunk_matches(
        &self,
        generation: u64,
        file_id: [u8; 16],
        position: u64,
        plaintext: &[u8],
        expected: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let semantics = chunk_semantics(file_id, position);
        self.with_key_boundary(generation, |keys| {
            let expected = ChunkFingerprint::try_from_protected_bytes(expected)?;
            Ok(verify_chunk_fingerprint(
                &ChunkFingerprintContext::profile_one(),
                &semantics,
                plaintext,
                &expected,
                &keys.chunk_fingerprint,
            )
            .is_ok())
        })
    }

    pub(crate) fn encrypt_local_chunk(
        &self,
        generation: u64,
        vault: VaultId,
        object: ObjectId,
        protected_payload: Vec<u8>,
        random: &mut dyn SecureRandom,
    ) -> Result<Vec<u8>, StoreError> {
        let identity = public_identity(vault, object, ContentChunkContext::OBJECT_KIND);
        let content_context = ContentChunkContext::try_new(identity)?;
        let wrapping_context = ChunkKeyWrapContext::try_new(PublicEnvelopeIdentity {
            object_kind: ChunkKeyWrapContext::OBJECT_KIND,
            ..identity
        })?;
        self.with_key_boundary(generation, |keys| {
            let chunk_key = ChunkKeyPlaintext::generate(random).map_err(map_crypto)?;
            let content = encrypt_content_chunk(
                &content_context,
                ContentChunkPlaintext::try_new(protected_payload).map_err(map_crypto)?,
                &chunk_key,
                random,
            )
            .map_err(map_crypto)?;
            let wrapped =
                wrap_chunk_key(&wrapping_context, chunk_key, &keys.content_wrapping, random)
                    .map_err(map_crypto)?;
            let (content_identity, nonce, ciphertext, tag) =
                content.into_parts().into_public_parts().into_components();
            let (_wrapping_identity, wrap_nonce, wrap_ciphertext, wrap_tag) =
                wrapped.into_parts().into_public_parts().into_components();
            let wire = ContentChunkObject::try_new(
                CryptoProfileId::profile_one(),
                AeadAlgorithmId::xchacha20_poly1305(),
                content_identity.vault_id,
                FormatVersion::v1(),
                content_identity.object_id,
                &nonce,
                CompactChunkKey::try_new(
                    AeadAlgorithmId::xchacha20_poly1305(),
                    &wrap_nonce,
                    wrap_ciphertext,
                    &wrap_tag,
                )?,
                ciphertext,
                &tag,
            )?;
            Ok(encode_content_chunk(&wire)?)
        })
    }

    pub(crate) fn encrypt_local_manifest(
        &self,
        generation: u64,
        vault: VaultId,
        object: ObjectId,
        canonical: Vec<u8>,
        random: &mut dyn SecureRandom,
    ) -> Result<Vec<u8>, StoreError> {
        self.encrypt_ordinary_metadata(
            generation,
            vault,
            object,
            OrdinaryAeadKind::Manifest,
            canonical,
            random,
        )
    }

    pub(crate) fn encrypt_local_tree(
        &self,
        generation: u64,
        vault: VaultId,
        object: ObjectId,
        canonical: Vec<u8>,
        random: &mut dyn SecureRandom,
    ) -> Result<Vec<u8>, StoreError> {
        self.encrypt_ordinary_metadata(
            generation,
            vault,
            object,
            OrdinaryAeadKind::Tree,
            canonical,
            random,
        )
    }

    fn encrypt_ordinary_metadata(
        &self,
        generation: u64,
        vault: VaultId,
        object: ObjectId,
        kind: OrdinaryAeadKind,
        canonical: Vec<u8>,
        random: &mut dyn SecureRandom,
    ) -> Result<Vec<u8>, StoreError> {
        let identity = public_identity(vault, object, kind.object_kind().get());
        self.with_key_boundary(generation, |keys| {
            let parts = match kind {
                OrdinaryAeadKind::Tree => encrypt_tree(
                    &TreeContext::try_new(identity)?,
                    TreePlaintext::try_new(canonical).map_err(map_crypto)?,
                    &keys.metadata,
                    random,
                )
                .map_err(map_crypto)?
                .into_parts(),
                OrdinaryAeadKind::Manifest => encrypt_manifest(
                    &ManifestContext::try_new(identity)?,
                    ManifestPlaintext::try_new(canonical).map_err(map_crypto)?,
                    &keys.metadata,
                    random,
                )
                .map_err(map_crypto)?
                .into_parts(),
                _ => return Err(StoreError::AuthenticationFailed),
            };
            let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
            let wire = AeadObject::try_new(
                CryptoProfileId::profile_one(),
                AeadAlgorithmId::xchacha20_poly1305(),
                identity.vault_id,
                kind,
                FormatVersion::v1(),
                identity.object_id,
                &nonce,
                ciphertext,
                &tag,
                &DecodeLimits::PHASE_1,
            )?;
            Ok(encode_aead_object(&wire)?)
        })
    }

    pub(crate) fn encrypt_local_snapshot(
        &self,
        generation: u64,
        vault: VaultId,
        object: ObjectId,
        canonical: Vec<u8>,
        random: &mut dyn SecureRandom,
    ) -> Result<Vec<u8>, StoreError> {
        let identity = public_identity(vault, object, SnapshotContext::OBJECT_KIND);
        self.with_key_boundary(generation, |keys| {
            let envelope = encrypt_snapshot(
                &SnapshotContext::try_new(identity)?,
                SnapshotPlaintext::try_new(canonical).map_err(map_crypto)?,
                &keys.metadata,
                &keys.snapshot_authentication,
                random,
            )
            .map_err(map_crypto)?;
            let (parts, outer) = envelope.into_parts();
            let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
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
                &outer,
                &DecodeLimits::PHASE_1,
            )?;
            Ok(encode_snapshot_object(&wire)?)
        })
    }

    pub(crate) fn build_local_head(
        &self,
        generation: u64,
        vault: VaultId,
        record_id: ObjectId,
        payload: HeadPayload,
    ) -> Result<Vec<u8>, StoreError> {
        let canonical = encode_head_payload(&payload)?;
        let identity = public_identity(vault, record_id, AUTHENTICATED_HEAD_OBJECT_KIND);
        self.with_key_boundary(generation, |keys| {
            let authenticator = authenticate_head(
                &AuthenticatedHeadContext::try_new(identity)?,
                &canonical,
                &keys.snapshot_authentication,
            )?;
            Ok(encode_head(&HeadRecord::try_new(
                CryptoProfileId::profile_one(),
                AuthenticationAlgorithmId::keyed_blake3_256(),
                *vault.as_bytes(),
                FormatVersion::v1(),
                *record_id.as_bytes(),
                payload,
                authenticator.as_bytes(),
                &DecodeLimits::PHASE_1,
            )?)?)
        })
    }

    pub(crate) fn decrypt_local_tree(
        &self,
        generation: u64,
        expected: ObjectId,
        file: &mut FileCapability,
    ) -> Result<LogicalTree, StoreError> {
        let bytes = read_file_bounded_exact(
            file,
            u64::from(DecodeLimits::PHASE_1.max_tree_bytes) + 256,
            |_| Ok(()),
            |_| Ok(()),
        )?;
        let object = decode_aead_object(&bytes, &DecodeLimits::PHASE_1)?;
        if object.kind() != OrdinaryAeadKind::Tree || object.object_id() != expected.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let (profile, _algorithm, vault, kind, version, object_id, nonce, ciphertext, tag) =
            object.into_parts().into_components();
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: vault,
            object_kind: kind.object_kind().get(),
            format_version: version.get(),
            object_id,
        };
        let envelope = TreeEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            identity, &nonce, ciphertext, &tag,
        )?)?;
        self.with_key_boundary(generation, |keys| {
            decrypt_tree(&TreeContext::try_new(identity)?, &envelope, &keys.metadata)?
                .into_protected_bytes()
                .consume(|plain| Ok(decode_tree(plain, &DecodeLimits::PHASE_1)?))
        })
    }

    pub(crate) fn decrypt_local_manifest(
        &self,
        generation: u64,
        expected: ObjectId,
        file: &mut FileCapability,
    ) -> Result<RevisionManifest, StoreError> {
        let bytes = read_file_bounded_exact(
            file,
            u64::from(DecodeLimits::PHASE_1.max_manifest_bytes) + 256,
            |_| Ok(()),
            |_| Ok(()),
        )?;
        let object = decode_aead_object(&bytes, &DecodeLimits::PHASE_1)?;
        if object.kind() != OrdinaryAeadKind::Manifest || object.object_id() != expected.as_bytes()
        {
            return Err(StoreError::AuthenticationFailed);
        }
        let (profile, _algorithm, vault, kind, version, object_id, nonce, ciphertext, tag) =
            object.into_parts().into_components();
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: vault,
            object_kind: kind.object_kind().get(),
            format_version: version.get(),
            object_id,
        };
        let envelope = ManifestEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            identity, &nonce, ciphertext, &tag,
        )?)?;
        self.with_key_boundary(generation, |keys| {
            decrypt_manifest(
                &ManifestContext::try_new(identity)?,
                &envelope,
                &keys.metadata,
            )?
            .into_protected_bytes()
            .consume(|plain| Ok(decode_manifest(plain, &DecodeLimits::PHASE_1)?))
        })
    }

    pub(crate) fn decrypt_local_snapshot(
        &self,
        generation: u64,
        expected: ObjectId,
        file: &mut FileCapability,
    ) -> Result<SnapshotPayload, StoreError> {
        let bytes = read_file_bounded_exact(
            file,
            u64::from(DecodeLimits::PHASE_1.max_snapshot_bytes) + 256,
            |_| Ok(()),
            |_| Ok(()),
        )?;
        let object = decode_snapshot_object(&bytes, &DecodeLimits::PHASE_1)?;
        let (profile, _aead, _auth, vault, version, object_id, nonce, ciphertext, tag, outer) =
            object.into_parts().into_components();
        if object_id != *expected.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let identity = PublicEnvelopeIdentity {
            profile_id: profile.get(),
            vault_id: vault,
            object_kind: SnapshotContext::OBJECT_KIND,
            format_version: version.get(),
            object_id,
        };
        let envelope = SnapshotEnvelope::try_new(
            AeadEnvelopeParts::try_new(identity, &nonce, ciphertext, &tag)?,
            &outer,
        )?;
        self.with_key_boundary(generation, |keys| {
            decrypt_snapshot(
                &SnapshotContext::try_new(identity)?,
                &envelope,
                &keys.metadata,
                &keys.snapshot_authentication,
            )?
            .into_protected_bytes()
            .consume(|plain| Ok(decode_snapshot_payload(plain, &DecodeLimits::PHASE_1)?))
        })
    }

    pub(crate) fn export_local_chunk(
        &self,
        generation: u64,
        expected: ObjectId,
        expected_file: [u8; 16],
        expected_position: u64,
        file: &mut FileCapability,
        output: &mut dyn Write,
    ) -> Result<u64, StoreError> {
        #[cfg(feature = "test-support")]
        self.local_chunk_authentications
            .fetch_add(1, Ordering::Relaxed);
        let bytes = read_file_bounded_exact(file, (4 << 20) + (4 << 10), |_| Ok(()), |_| Ok(()))?;
        let object = decode_content_chunk(&bytes, &DecodeLimits::PHASE_1)?;
        if object.object_id() != expected.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let (_profile, _algorithm, vault, version, object_id, nonce, wrapper, ciphertext, tag) =
            object.into_parts().into_components();
        let wrapping_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: vault,
            object_kind: ChunkKeyWrapContext::OBJECT_KIND,
            format_version: version.get(),
            object_id,
        };
        let content_identity = PublicEnvelopeIdentity {
            object_kind: ContentChunkContext::OBJECT_KIND,
            ..wrapping_identity
        };
        let wrapped = ChunkKeyEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            wrapping_identity,
            wrapper.nonce(),
            wrapper.ciphertext().to_vec(),
            wrapper.tag(),
        )?)?;
        let content = ContentChunkEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
            content_identity,
            &nonce,
            ciphertext,
            &tag,
        )?)?;
        let plaintext = self.with_key_boundary(generation, |keys| {
            let chunk_key = unwrap_chunk_key(
                &ChunkKeyWrapContext::try_new(wrapping_identity)?,
                &wrapped,
                &keys.content_wrapping,
            )?;
            let plaintext = decrypt_content_chunk(
                &ContentChunkContext::try_new(content_identity)?,
                &content,
                &chunk_key,
            )?;
            plaintext.into_protected_bytes().consume(|plain| {
                let payload = decode_content_payload(plain, &DecodeLimits::PHASE_1)?;
                if payload.file_id() != &expected_file || payload.position() != expected_position {
                    return Err(StoreError::AuthenticationFailed);
                }
                payload.consume(|bytes| {
                    let mut owned = Vec::new();
                    owned
                        .try_reserve_exact(bytes.len())
                        .map_err(|_| StoreError::LimitExceeded)?;
                    owned.extend_from_slice(bytes);
                    Ok(Zeroizing::new(owned))
                })
            })
        })?;
        let length = u64::try_from(plaintext.len()).map_err(|_| StoreError::LimitExceeded)?;
        output.write_all(&plaintext)?;
        self.validate(generation)?;
        Ok(length)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn local_chunk_authentication_count(&self) -> u64 {
        self.local_chunk_authentications.load(Ordering::Relaxed)
    }

    pub(crate) fn wrap_root_for_device(
        &self,
        expected_generation: u64,
        context: &DeviceSlotContext,
        key: &DeviceWrappingKey,
        random: &mut dyn SecureRandom,
    ) -> Result<DeviceSlotEnvelope, StoreError> {
        self.validate(expected_generation)?;
        let guard = self.material.read().map_err(|_| StoreError::Locked)?;
        self.validate(expected_generation)?;
        let material = guard.as_ref().ok_or(StoreError::Locked)?;
        let result = encrypt_device_slot(
            context,
            DeviceSlotPlaintext::from_root_key(&material._root),
            key,
            random,
        );
        drop(guard);
        self.validate(expected_generation)?;
        match result {
            Ok(envelope) => Ok(envelope),
            Err(CryptoError::RandomSource) => Err(StoreError::RandomSource),
            Err(_) => Err(StoreError::AuthenticationFailed),
        }
    }

    fn with_key_boundary<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(&VaultKeys) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.validate(expected_generation)?;
        let guard = self.material.read().map_err(|_| StoreError::Locked)?;
        self.validate(expected_generation)?;
        let keys = &guard.as_ref().ok_or(StoreError::Locked)?.derived;
        let output = operation(keys)?;
        drop(guard);
        if let Err(error) = self.validate(expected_generation) {
            drop(output);
            return Err(error);
        }
        Ok(output)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_boundary<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(&VaultKeys) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.with_key_boundary(expected_generation, operation)
    }

    pub(crate) fn begin_close(&self) -> Result<(), StoreError> {
        self.begin_close_observed(|| {})
    }

    pub(crate) fn revoke(&self) {
        self.closing.store(true, Ordering::Release);
    }

    pub(crate) fn begin_close_observed(
        &self,
        closing_observed: impl FnOnce(),
    ) -> Result<(), StoreError> {
        let first_revoke = self
            .closing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if first_revoke {
            closing_observed();
        }
        if self.close_fenced.load(Ordering::Acquire) {
            return Ok(());
        }
        let _publication = self.publication.lock().map_err(|_| StoreError::Locked)?;
        if self
            .close_fenced
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        self.generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map(|_| ())
            .map_err(|_| StoreError::SessionGenerationExhausted)
    }

    pub(crate) fn authorize_publication(
        &self,
        expected_generation: u64,
    ) -> Result<PublicationAuthorization<'_>, StoreError> {
        self.validate(expected_generation)?;
        let guard = self.publication.lock().map_err(|_| StoreError::Locked)?;
        self.validate(expected_generation)?;
        Ok(PublicationAuthorization {
            _guard: guard,
            generation: expected_generation,
        })
    }

    pub(crate) fn close(&self) -> Result<(), StoreError> {
        self.begin_close()?;
        let mut guard = match self.material.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        drop(guard.take());
        Ok(())
    }

    fn validate(&self, expected_generation: u64) -> Result<(), StoreError> {
        if self.closing.load(Ordering::Acquire)
            || self.generation.load(Ordering::Acquire) != expected_generation
        {
            Err(StoreError::Locked)
        } else {
            Ok(())
        }
    }
}

fn public_identity(vault: VaultId, object: ObjectId, object_kind: u8) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: *vault.as_bytes(),
        object_kind,
        format_version: 1,
        object_id: *object.as_bytes(),
    }
}

fn chunk_semantics(file_id: [u8; 16], position: u64) -> [u8; 24] {
    let mut semantics = [0_u8; 24];
    semantics[..16].copy_from_slice(&file_id);
    semantics[16..].copy_from_slice(&position.to_be_bytes());
    semantics
}

fn map_crypto(error: CryptoError) -> StoreError {
    if matches!(error, CryptoError::RandomSource) {
        StoreError::RandomSource
    } else {
        StoreError::AuthenticationFailed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportAuthenticationBoundary {
    ReadPageComplete,
    BeforeCrypto,
    AfterCrypto,
    AfterProtectedDecode,
    BeforeAcceptReferences,
}

fn read_file_bounded_exact(
    file: &mut FileCapability,
    maximum: u64,
    after_preflight: impl FnOnce(&mut FileCapability) -> Result<(), StoreError>,
    mut page_complete: impl FnMut(usize) -> Result<(), StoreError>,
) -> Result<Vec<u8>, StoreError> {
    let preflight = file.len()?;
    if preflight > maximum {
        return Err(StoreError::LimitExceeded);
    }
    let capacity = usize::try_from(preflight.checked_add(1).ok_or(StoreError::LimitExceeded)?)
        .map_err(|_| StoreError::LimitExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| StoreError::LimitExceeded)?;
    after_preflight(file)?;
    file.seek(SeekFrom::Start(0))?;
    let maximum_with_sentinel = maximum.checked_add(1).ok_or(StoreError::LimitExceeded)?;
    let mut remaining = maximum_with_sentinel;
    let mut page = [0_u8; 64 * 1024];
    while remaining != 0 {
        let bounded = usize::try_from(remaining.min(page.len() as u64))
            .map_err(|_| StoreError::LimitExceeded)?;
        let read = file.read(&mut page[..bounded])?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&page[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| StoreError::LimitExceeded)?)
            .ok_or(StoreError::LimitExceeded)?;
        page_complete(read)?;
    }
    let actual = u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?;
    if actual > maximum {
        return Err(StoreError::LimitExceeded);
    }
    if actual != preflight {
        return Err(StoreError::MalformedObject);
    }
    Ok(bytes)
}

pub(crate) struct PublicationAuthorization<'a> {
    _guard: MutexGuard<'a, ()>,
    generation: u64,
}

impl PublicationAuthorization<'_> {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use notecrypt_crypto::{CryptoError, SecureRandom};

    use super::*;

    pub struct ScriptedKeyCell {
        cell: KeyCell,
        generation: u64,
    }

    impl ScriptedKeyCell {
        pub fn new() -> Result<Self, StoreError> {
            struct FixedRandom;
            impl SecureRandom for FixedRandom {
                fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
                    output.fill(0x51);
                    Ok(())
                }
            }
            let cell = KeyCell::new(VaultRootKey::generate(&mut FixedRandom)?)?;
            let generation = cell.generation();
            Ok(Self { cell, generation })
        }

        pub fn bounded_step(&self, hook: impl FnOnce()) -> Result<(), StoreError> {
            self.cell.test_boundary(self.generation, |_| {
                hook();
                Ok(())
            })
        }

        pub fn validate_publication(&self) -> Result<(), StoreError> {
            self.cell.validate_generation(self.generation)
        }

        pub fn begin_close(&self) -> Result<(), StoreError> {
            self.cell.begin_close()
        }

        pub fn close(&self) -> Result<(), StoreError> {
            self.cell.close()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use notecrypt_crypto::{CryptoError, SecureRandom};
    use notecrypt_format::{ContentPayload, encode_content_payload};
    use notecrypt_platform_fs::{Directory, PhysicalComponent};
    use tempfile::TempDir;

    use super::*;

    struct FixedRandom;
    impl SecureRandom for FixedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
            output.fill(7);
            Ok(())
        }
    }

    fn cell() -> Arc<KeyCell> {
        Arc::new(KeyCell::new(VaultRootKey::generate(&mut FixedRandom).unwrap()).unwrap())
    }

    #[test]
    fn concurrent_bounded_operations_share_read_access() {
        let cell = cell();
        let generation = cell.generation();
        let entered = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let cell = Arc::clone(&cell);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            workers.push(thread::spawn(move || {
                cell.test_boundary(generation, |_| {
                    entered.wait();
                    release.wait();
                    Ok(())
                })
            }));
        }
        entered.wait();
        release.wait();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
    }

    #[test]
    fn revoke_rejects_new_boundaries_while_close_fences_prior_publication() {
        let cell = cell();
        let generation = cell.generation();
        let publication = cell.authorize_publication(generation).unwrap();
        cell.revoke();
        assert!(matches!(
            cell.test_boundary(generation, |_| Ok(())),
            Err(StoreError::Locked)
        ));

        let closing = Arc::clone(&cell);
        let (completed_tx, completed_rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("notecrypt-key-close-publication-fence-eze".to_owned())
            .spawn(move || {
                let result = closing.close();
                completed_tx.send(result).unwrap();
            })
            .unwrap();
        assert!(matches!(
            completed_rx.recv_timeout(Duration::from_millis(25)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(publication);
        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(matches!(
            cell.test_boundary(generation, |_| Ok(())),
            Err(StoreError::Locked)
        ));
    }

    #[test]
    fn close_rejects_new_work_immediately_and_discards_crossing_output() {
        let cell = cell();
        let generation = cell.generation();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker = {
            let cell = Arc::clone(&cell);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            thread::spawn(move || {
                cell.test_boundary(generation, |_| {
                    entered.wait();
                    release.wait();
                    Ok(vec![9_u8; 32])
                })
            })
        };
        entered.wait();
        cell.begin_close().unwrap();
        assert!(matches!(
            cell.test_boundary(generation, |_| Ok(())),
            Err(StoreError::Locked)
        ));
        release.wait();
        assert!(matches!(worker.join().unwrap(), Err(StoreError::Locked)));
        cell.close().unwrap();
        assert!(matches!(
            cell.test_boundary(cell.generation(), |_| Ok(())),
            Err(StoreError::Locked)
        ));
    }

    #[test]
    fn bounded_file_read_rejects_growth_after_length_preflight() {
        let root = TempDir::new().unwrap();
        let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
        let name = PhysicalComponent::try_new("object").unwrap();
        let mut file = directory.create_file_new(&name).unwrap();
        file.write_all(b"four").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let result = read_file_bounded_exact(
            &mut file,
            4,
            |file| {
                file.seek(SeekFrom::End(0))?;
                file.write_all(b"growth")?;
                Ok(())
            },
            |_| Ok(()),
        );

        assert!(matches!(result, Err(StoreError::LimitExceeded)));
    }

    #[test]
    fn blocked_export_writer_does_not_delay_key_zeroization() {
        struct BlockingWriter {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
        }

        impl Write for BlockingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.entered.wait();
                self.release.wait();
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let root = TempDir::new().unwrap();
        let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
        let name = PhysicalComponent::try_new("chunk").unwrap();
        let cell = cell();
        let generation = cell.generation();
        let vault = VaultId::from_bytes([3; 16]);
        let object = ObjectId::from_bytes([4; 32]);
        let file_id = [5; 16];
        let protected = encode_content_payload(
            &ContentPayload::try_new(file_id, 0, b"protected export".to_vec()).unwrap(),
        )
        .unwrap();
        let encoded = cell
            .encrypt_local_chunk(generation, vault, object, protected, &mut FixedRandom)
            .unwrap();
        let mut file = directory.create_file_new(&name).unwrap();
        file.write_all(&encoded).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker = {
            let cell = Arc::clone(&cell);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            thread::spawn(move || {
                let mut output = BlockingWriter { entered, release };
                cell.export_local_chunk(generation, object, file_id, 0, &mut file, &mut output)
            })
        };
        entered.wait();
        cell.begin_close().unwrap();
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || closed_tx.send(cell.close()).unwrap())
        };
        let closed = closed_rx.recv_timeout(Duration::from_secs(1));
        release.wait();
        assert!(closed.unwrap().is_ok());
        closer.join().unwrap();
        assert!(matches!(worker.join().unwrap(), Err(StoreError::Locked)));
    }
}
