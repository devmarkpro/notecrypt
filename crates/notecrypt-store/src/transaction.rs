use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};

use notecrypt_core::{ObjectId, SnapshotId};
use notecrypt_crypto::{
    AUTHENTICATED_HEAD_OBJECT_KIND, AuthenticatedHeadContext, HeadAuthenticator,
    PublicEnvelopeIdentity,
};
use notecrypt_format::{DecodeLimits, decode_head, decode_head_payload, encode_local_state};

use crate::StoreError;
#[cfg(test)]
use crate::batch::BatchMetrics;
use crate::batch::{BatchBoundary, DurableBatch};
use crate::journal::{
    JournalPhase, JournalTransition, build_authenticated_journal,
    verify_authenticated_journal_with_cell,
};
use crate::key_cell::KeyCell;
use crate::layout::{StoreLayout, component};
use crate::local_io::{read_optional, replace_durable};
use crate::trusted_state::{
    TrustedHead, build_authenticated_trusted_head, verify_authenticated_trusted_head,
};

const JOURNAL_FILE: &str = "active";
const TRUSTED_FILE: &str = "head";
const HEAD_FILE: &str = "head";

/// A final pre-publication safety check supplied by the owning service operation.
pub trait PublicationGuard: Send {
    fn validate(&mut self) -> Result<(), StoreError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionBoundary {
    AuthenticateCurrent,
    StageObjects,
    FlushStaged,
    AuthenticateStaged,
    PublishObjects,
    WriteJournal,
    ReplaceHead,
    FlushHeadDirectory,
    UpdateTrustedState,
    CompleteJournal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryMoment {
    Before,
    After,
}

pub(crate) trait TransactionObserver {
    fn at(
        &mut self,
        boundary: TransactionBoundary,
        moment: BoundaryMoment,
    ) -> Result<(), StoreError>;
}

struct NoObserver;

impl TransactionObserver for NoObserver {
    fn at(
        &mut self,
        _boundary: TransactionBoundary,
        _moment: BoundaryMoment,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

pub(crate) struct TransactionObject<'a> {
    pub(crate) id: ObjectId,
    pub(crate) source: &'a mut dyn Read,
    pub(crate) declared_length: u64,
}

pub(crate) struct TransactionRequest<'a> {
    pub(crate) objects: Vec<TransactionObject<'a>>,
    pub(crate) intended_head: Vec<u8>,
    pub(crate) expected_base: Option<SnapshotId>,
}

pub(crate) struct TransactionResult {
    pub(crate) snapshot: SnapshotId,
    #[cfg(test)]
    pub(crate) metrics: BatchMetrics,
}

pub(crate) fn commit(
    layout: &StoreLayout,
    batch: DurableBatch<'_>,
    keys: &KeyCell,
    request: TransactionRequest<'_>,
    authenticate_object: impl FnMut(
        &ObjectId,
        &mut notecrypt_platform_fs::FileCapability,
    ) -> Result<(), StoreError>,
    guard: &mut dyn PublicationGuard,
    cancel: &AtomicBool,
) -> Result<TransactionResult, StoreError> {
    commit_observed(
        layout,
        batch,
        keys,
        request,
        authenticate_object,
        guard,
        cancel,
        &mut NoObserver,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_observed(
    layout: &StoreLayout,
    mut batch: DurableBatch<'_>,
    keys: &KeyCell,
    mut request: TransactionRequest<'_>,
    authenticate_object: impl FnMut(
        &ObjectId,
        &mut notecrypt_platform_fs::FileCapability,
    ) -> Result<(), StoreError>,
    guard: &mut dyn PublicationGuard,
    cancel: &AtomicBool,
    observer: &mut dyn TransactionObserver,
) -> Result<TransactionResult, StoreError> {
    let generation = keys.generation();
    check_boundary(keys, generation, cancel)?;
    observe_batch(
        observer,
        TransactionBoundary::AuthenticateCurrent,
        BoundaryMoment::Before,
        &mut batch,
    )?;
    let current = read_and_authenticate_current(layout, keys, generation)?;
    match (&current, request.expected_base) {
        (Some(trusted), Some(expected)) if trusted.snapshot() == expected => {}
        (None, None) => {}
        _ => return Err(StoreError::RollbackDetected),
    }

    let intended = authenticate_head(&request.intended_head, keys, generation)?;
    if intended.vault != layout.vault {
        return Err(StoreError::AuthenticationFailed);
    }
    observe_batch(
        observer,
        TransactionBoundary::AuthenticateCurrent,
        BoundaryMoment::After,
        &mut batch,
    )?;
    observe_batch(
        observer,
        TransactionBoundary::StageObjects,
        BoundaryMoment::Before,
        &mut batch,
    )?;
    for object in &mut request.objects {
        check_boundary(keys, generation, cancel)?;
        batch.stage(object.id, object.source, object.declared_length)?;
    }
    observe_batch(
        observer,
        TransactionBoundary::StageObjects,
        BoundaryMoment::After,
        &mut batch,
    )?;
    let mut published = batch.authenticate_and_publish_observed(
        authenticate_object,
        |boundary, before| match (boundary, before) {
            (BatchBoundary::Flushed, moment) => observer.at(
                TransactionBoundary::FlushStaged,
                if moment {
                    BoundaryMoment::Before
                } else {
                    BoundaryMoment::After
                },
            ),
            (BatchBoundary::Authenticated, moment) => observer.at(
                TransactionBoundary::AuthenticateStaged,
                if moment {
                    BoundaryMoment::Before
                } else {
                    BoundaryMoment::After
                },
            ),
            (BatchBoundary::PublishedNames, true) => {
                observer.at(TransactionBoundary::PublishObjects, BoundaryMoment::Before)
            }
            (BatchBoundary::DirectoriesSynced, false) => {
                observer.at(TransactionBoundary::PublishObjects, BoundaryMoment::After)
            }
            (BatchBoundary::PublishedNames, false) | (BatchBoundary::DirectoriesSynced, true) => {
                Ok(())
            }
        },
    )?;
    check_boundary(keys, generation, cancel)?;

    let head_stage = component("head-stage")?;
    published.stage_replacement(
        head_stage.clone(),
        &mut Cursor::new(&request.intended_head),
        u64::try_from(request.intended_head.len()).map_err(|_| StoreError::LimitExceeded)?,
    )?;
    let mut transaction_id = [0_u8; 16];
    getrandom::fill(&mut transaction_id).map_err(|_| StoreError::RandomSource)?;
    let prior_commitment = current
        .as_ref()
        .map_or(*blake3::hash(&[]).as_bytes(), |trusted| {
            *trusted.head_commitment()
        });
    let transition = JournalTransition::try_new(
        transaction_id,
        layout.vault,
        generation,
        prior_commitment,
        request.intended_head,
        JournalPhase::Intended,
    )?;
    let prepared_journal = prepare_journal(&transition, keys, generation)?;

    guard.validate()?;
    let authorization = keys.authorize_publication(generation)?;
    if cancel.load(Ordering::Acquire) {
        return Err(StoreError::Cancelled);
    }
    observe_published(
        observer,
        TransactionBoundary::WriteJournal,
        BoundaryMoment::Before,
        &mut published,
    )?;
    write_prepared_journal(layout, &prepared_journal, keys, authorization.generation())?;
    observe_published(
        observer,
        TransactionBoundary::WriteJournal,
        BoundaryMoment::After,
        &mut published,
    )?;
    observe_published(
        observer,
        TransactionBoundary::ReplaceHead,
        BoundaryMoment::Before,
        &mut published,
    )?;
    published.publish_replacement_unsynced(&head_stage, &component(HEAD_FILE)?)?;
    observe_published(
        observer,
        TransactionBoundary::ReplaceHead,
        BoundaryMoment::After,
        &mut published,
    )?;
    observe_published(
        observer,
        TransactionBoundary::FlushHeadDirectory,
        BoundaryMoment::Before,
        &mut published,
    )?;
    published.sync_replacement_directories()?;
    let written_head =
        read_optional(&layout.repository, &component(HEAD_FILE)?)?.ok_or(StoreError::NotFound)?;
    let authenticated = authenticate_head(&written_head, keys, generation)?;
    if authenticated.snapshot != intended.snapshot
        || authenticated.commitment != intended.commitment
    {
        return Err(StoreError::AuthenticationFailed);
    }
    observe_published(
        observer,
        TransactionBoundary::FlushHeadDirectory,
        BoundaryMoment::After,
        &mut published,
    )?;
    drop(authorization);

    let trusted = TrustedHead::new(layout.vault, intended.snapshot, intended.commitment);
    observe_published(
        observer,
        TransactionBoundary::UpdateTrustedState,
        BoundaryMoment::Before,
        &mut published,
    )?;
    write_trusted(layout, &trusted, keys, generation)?;
    observe_published(
        observer,
        TransactionBoundary::UpdateTrustedState,
        BoundaryMoment::After,
        &mut published,
    )?;
    let complete = transition.with_phase(JournalPhase::Complete)?;
    observe_published(
        observer,
        TransactionBoundary::CompleteJournal,
        BoundaryMoment::Before,
        &mut published,
    )?;
    write_journal(layout, &complete, keys, generation)?;
    observe_published(
        observer,
        TransactionBoundary::CompleteJournal,
        BoundaryMoment::After,
        &mut published,
    )?;
    #[cfg(test)]
    let metrics = published.finish()?;
    #[cfg(not(test))]
    published.finish()?;
    Ok(TransactionResult {
        snapshot: intended.snapshot,
        #[cfg(test)]
        metrics,
    })
}

fn observe_batch(
    observer: &mut dyn TransactionObserver,
    boundary: TransactionBoundary,
    moment: BoundaryMoment,
    _batch: &mut DurableBatch<'_>,
) -> Result<(), StoreError> {
    let result = observer.at(boundary, moment);
    #[cfg(feature = "test-support")]
    if matches!(result, Err(StoreError::SimulatedCrash)) {
        _batch.preserve_for_simulated_crash();
    }
    result
}

fn observe_published(
    observer: &mut dyn TransactionObserver,
    boundary: TransactionBoundary,
    moment: BoundaryMoment,
    _published: &mut crate::batch::PublishedBatch<'_>,
) -> Result<(), StoreError> {
    let result = observer.at(boundary, moment);
    #[cfg(feature = "test-support")]
    if matches!(result, Err(StoreError::SimulatedCrash)) {
        _published.preserve_for_simulated_crash();
    }
    result
}

pub struct AuthenticatedHead {
    pub(crate) vault: notecrypt_core::VaultId,
    pub(crate) snapshot: SnapshotId,
    pub(crate) commitment: [u8; 32],
    pub(crate) snapshot_object: ObjectId,
    pub(crate) tree_object: ObjectId,
}

pub(crate) fn authenticate_head(
    bytes: &[u8],
    keys: &KeyCell,
    generation: u64,
) -> Result<AuthenticatedHead, StoreError> {
    let record = decode_head(bytes, &DecodeLimits::PHASE_1)?;
    let context = AuthenticatedHeadContext::try_new(PublicEnvelopeIdentity {
        profile_id: record.profile_id().get(),
        vault_id: *record.vault_id(),
        object_kind: AUTHENTICATED_HEAD_OBJECT_KIND,
        format_version: record.version().get(),
        object_id: *record.object_id(),
    })?;
    let authenticator = HeadAuthenticator::try_from_bytes(record.authenticator())?;
    keys.verify_authenticated_head(
        generation,
        &context,
        record.untrusted_payload_bytes(),
        &authenticator,
    )?;
    let payload = decode_head_payload(record.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)?;
    Ok(AuthenticatedHead {
        vault: notecrypt_core::VaultId::from_bytes(*record.vault_id()),
        snapshot: SnapshotId::from_bytes(*payload.snapshot_id()),
        commitment: *blake3::hash(bytes).as_bytes(),
        snapshot_object: ObjectId::from_bytes(*payload.snapshot_object_id()),
        tree_object: ObjectId::from_bytes(*payload.tree_object_id()),
    })
}

pub(crate) fn read_and_authenticate_current(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<Option<TrustedHead>, StoreError> {
    Ok(
        read_and_authenticate_current_parts(layout, keys, generation)?
            .map(|(trusted, _head)| trusted),
    )
}

pub(crate) fn read_and_authenticate_current_head(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<Option<AuthenticatedHead>, StoreError> {
    Ok(read_and_authenticate_current_parts(layout, keys, generation)?.map(|(_trusted, head)| head))
}

fn read_and_authenticate_current_parts(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<Option<(TrustedHead, AuthenticatedHead)>, StoreError> {
    let trusted_name = component(TRUSTED_FILE)?;
    let trusted_bytes = read_optional(&layout.trusted, &trusted_name)?;
    let Some(trusted_bytes) = trusted_bytes else {
        if read_optional(&layout.repository, &component(HEAD_FILE)?)?.is_some() {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        return Ok(None);
    };
    let record = notecrypt_format::decode_local_state(&trusted_bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    let trusted = verify_authenticated_trusted_head(&record, keys, generation)?;
    let head_bytes = read_optional(&layout.repository, &component(HEAD_FILE)?)?
        .ok_or(StoreError::RollbackDetected)?;
    let head = authenticate_head(&head_bytes, keys, generation)?;
    crate::rollback::require_exact_trusted_head(layout.vault, &trusted, &head)?;
    Ok(Some((trusted, head)))
}

pub(crate) fn write_journal(
    layout: &StoreLayout,
    transition: &JournalTransition,
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    let bytes = prepare_journal(transition, keys, generation)?;
    write_prepared_journal(layout, &bytes, keys, generation)
}

fn prepare_journal(
    transition: &JournalTransition,
    keys: &KeyCell,
    generation: u64,
) -> Result<Vec<u8>, StoreError> {
    let record = build_authenticated_journal(transition, keys, generation)?;
    Ok(encode_local_state(&record)?)
}

fn write_prepared_journal(
    layout: &StoreLayout,
    bytes: &[u8],
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    replace_durable(&layout.journal, &component(JOURNAL_FILE)?, bytes)?;
    let readback =
        read_optional(&layout.journal, &component(JOURNAL_FILE)?)?.ok_or(StoreError::NotFound)?;
    let record = notecrypt_format::decode_local_state(&readback, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    verify_authenticated_journal_with_cell(&record, keys, generation)?;
    Ok(())
}

pub(crate) fn write_trusted(
    layout: &StoreLayout,
    trusted: &TrustedHead,
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    let record = build_authenticated_trusted_head(trusted, keys, generation)?;
    let bytes = encode_local_state(&record)?;
    replace_durable(&layout.trusted, &component(TRUSTED_FILE)?, &bytes)?;
    let readback =
        read_optional(&layout.trusted, &component(TRUSTED_FILE)?)?.ok_or(StoreError::NotFound)?;
    let record = notecrypt_format::decode_local_state(&readback, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    verify_authenticated_trusted_head(&record, keys, generation)?;
    Ok(())
}

fn check_boundary(keys: &KeyCell, generation: u64, cancel: &AtomicBool) -> Result<(), StoreError> {
    if cancel.load(Ordering::Acquire) {
        return Err(StoreError::Cancelled);
    }
    keys.validate_generation(generation)
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use notecrypt_core::{ObjectId, VaultId};
    use notecrypt_crypto::{
        AUTHENTICATED_HEAD_OBJECT_KIND, CryptoError, PublicEnvelopeIdentity, SecureRandom,
        TREE_OBJECT_KIND, TreeContext, TreePlaintext, TypedAeadEnvelope, VaultRootKey,
        authenticate_head as create_head_authenticator, derive_vault_keys, encrypt_tree,
    };
    use notecrypt_format::{
        AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CryptoProfileId, FormatVersion,
        HeadPayload, HeadRecord, OrdinaryAeadKind, encode_aead_object, encode_head,
    };

    use super::*;
    use crate::VaultStore;
    use crate::recovery::{RecoveryOutcome, recover};

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
            output.fill(0x35);
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RecoveredSnapshot {
        Old,
        New,
    }

    pub struct FaultResult {
        pub first: RecoveredSnapshot,
        pub second: RecoveredSnapshot,
        pub transient_entries: usize,
        pub authenticated_objects: usize,
    }

    pub fn create_empty_layout(
        repository_root: &Path,
        local_root: &Path,
        vault: [u8; 16],
    ) -> Result<(), StoreError> {
        VaultStore::create_empty(repository_root, local_root, VaultId::from_bytes(vault))?;
        Ok(())
    }

    pub fn exercise_fault(
        repository_root: &Path,
        local_root: &Path,
        fault_boundary: TransactionBoundary,
        fault_moment: BoundaryMoment,
    ) -> Result<FaultResult, StoreError> {
        struct Allow;
        impl PublicationGuard for Allow {
            fn validate(&mut self) -> Result<(), StoreError> {
                Ok(())
            }
        }
        struct Fault {
            boundary: TransactionBoundary,
            moment: BoundaryMoment,
        }
        impl TransactionObserver for Fault {
            fn at(
                &mut self,
                boundary: TransactionBoundary,
                moment: BoundaryMoment,
            ) -> Result<(), StoreError> {
                if boundary == self.boundary && moment == self.moment {
                    Err(StoreError::SimulatedCrash)
                } else {
                    Ok(())
                }
            }
        }

        let vault = VaultId::from_bytes([0x61; 16]);
        let store = VaultStore::create_empty(repository_root, local_root, vault)?;
        let root = VaultRootKey::generate(&mut FixedRandom)?;
        let old_head = make_head(vault, &root, [1; 32]);
        let new_head = make_head(vault, &root, [2; 32]);
        let (tree_id, tree_bytes) = make_tree(vault, &root)?;
        let keys = KeyCell::new(root)?;
        let mut old_tree = Cursor::new(tree_bytes.clone());
        commit(
            &store.layout,
            store.begin_durable_batch()?,
            &keys,
            TransactionRequest {
                objects: vec![TransactionObject {
                    id: tree_id,
                    source: &mut old_tree,
                    declared_length: u64::try_from(tree_bytes.len())
                        .map_err(|_| StoreError::LimitExceeded)?,
                }],
                intended_head: old_head,
                expected_base: None,
            },
            |id, file| keys.verify_tree_file(keys.generation(), id, file),
            &mut Allow,
            &AtomicBool::new(false),
        )?;
        let authenticated_objects = Arc::new(AtomicUsize::new(0));
        let mut new_tree = Cursor::new(tree_bytes);
        let new_tree_length =
            u64::try_from(new_tree.get_ref().len()).map_err(|_| StoreError::LimitExceeded)?;
        let counter = Arc::clone(&authenticated_objects);
        let fault_result = commit_observed(
            &store.layout,
            store.begin_durable_batch()?,
            &keys,
            TransactionRequest {
                objects: vec![TransactionObject {
                    id: tree_id,
                    source: &mut new_tree,
                    declared_length: new_tree_length,
                }],
                intended_head: new_head,
                expected_base: Some(SnapshotId::from_bytes([1; 32])),
            },
            |id, file| {
                counter.fetch_add(1, Ordering::Relaxed);
                keys.verify_tree_file(keys.generation(), id, file)
            },
            &mut Allow,
            &AtomicBool::new(false),
            &mut Fault {
                boundary: fault_boundary,
                moment: fault_moment,
            },
        );
        if !matches!(fault_result, Err(StoreError::SimulatedCrash)) {
            return Err(StoreError::InvalidCapability);
        }
        drop(keys);
        drop(store);

        let first_store = VaultStore::create_empty(repository_root, local_root, vault)?;
        let first_keys = KeyCell::new(VaultRootKey::generate(&mut FixedRandom)?)?;
        let first = recover(
            &first_store.layout,
            first_store.begin_durable_batch()?,
            &first_keys,
            |id, file| first_keys.verify_tree_file(first_keys.generation(), id, file),
            |head_bytes| verify_reachable_tree(&first_store, &first_keys, head_bytes),
        )?;
        drop(first_keys);
        drop(first_store);

        let second_store = VaultStore::create_empty(repository_root, local_root, vault)?;
        let second_keys = KeyCell::new(VaultRootKey::generate(&mut FixedRandom)?)?;
        let second = recover(
            &second_store.layout,
            second_store.begin_durable_batch()?,
            &second_keys,
            |id, file| second_keys.verify_tree_file(second_keys.generation(), id, file),
            |head_bytes| verify_reachable_tree(&second_store, &second_keys, head_bytes),
        )?;
        let transient_entries = std::fs::read_dir(repository_root.join(".notecrypt-txn"))
            .map_err(StoreError::from)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .count();
        Ok(FaultResult {
            first: classify(first)?,
            second: classify(second)?,
            transient_entries,
            authenticated_objects: authenticated_objects.load(Ordering::Relaxed),
        })
    }

    fn verify_reachable_tree(
        store: &VaultStore,
        keys: &KeyCell,
        head_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let head = authenticate_head(head_bytes, keys, keys.generation())?;
        let encoded = crate::layout::encode_hex(head.tree_object.as_bytes());
        let shard = store
            .layout
            .objects
            .open_dir_nofollow(&component(&encoded[..2])?)?;
        let mut file = shard.open_file_nofollow(&component(&encoded[2..])?)?;
        keys.verify_tree_file(keys.generation(), &head.tree_object, &mut file)
    }

    fn classify(outcome: RecoveryOutcome) -> Result<RecoveredSnapshot, StoreError> {
        let snapshot = match outcome {
            RecoveryOutcome::Current(snapshot) | RecoveryOutcome::Completed(snapshot) => snapshot,
            RecoveryOutcome::Empty => return Err(StoreError::InvalidCapability),
        };
        if snapshot == SnapshotId::from_bytes([1; 32]) {
            Ok(RecoveredSnapshot::Old)
        } else if snapshot == SnapshotId::from_bytes([2; 32]) {
            Ok(RecoveredSnapshot::New)
        } else {
            Err(StoreError::InvalidCapability)
        }
    }

    fn make_head(vault: VaultId, root: &VaultRootKey, snapshot: [u8; 32]) -> Vec<u8> {
        let keys = derive_vault_keys(root).expect("fixed test root derives");
        let object_id = snapshot;
        let payload = HeadPayload::new(snapshot, [6; 32], [7; 32]);
        let canonical = notecrypt_format::encode_head_payload(&payload)
            .expect("fixed test head payload encodes");
        let context = AuthenticatedHeadContext::try_new(PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: AUTHENTICATED_HEAD_OBJECT_KIND,
            format_version: 1,
            object_id,
        })
        .expect("fixed test head context is valid");
        let authenticator =
            create_head_authenticator(&context, &canonical, &keys.snapshot_authentication)
                .expect("fixed test head authenticates");
        let record = HeadRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            *vault.as_bytes(),
            FormatVersion::v1(),
            object_id,
            payload,
            authenticator.as_bytes(),
            &DecodeLimits::PHASE_1,
        )
        .expect("fixed test head record is valid");
        encode_head(&record).expect("fixed test head encodes")
    }

    fn make_tree(vault: VaultId, root: &VaultRootKey) -> Result<(ObjectId, Vec<u8>), StoreError> {
        let id = ObjectId::from_bytes([7; 32]);
        let identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: TREE_OBJECT_KIND,
            format_version: 1,
            object_id: *id.as_bytes(),
        };
        let context = TreeContext::try_new(identity)?;
        let keys = derive_vault_keys(root)?;
        let envelope = encrypt_tree(
            &context,
            TreePlaintext::try_new(b"canonical-tree".to_vec())?,
            &keys.metadata,
            &mut FixedRandom,
        )?;
        let (identity, nonce, ciphertext, tag) =
            envelope.into_parts().into_public_parts().into_components();
        let object = AeadObject::try_new(
            CryptoProfileId::profile_one(),
            AeadAlgorithmId::xchacha20_poly1305(),
            identity.vault_id,
            OrdinaryAeadKind::Tree,
            FormatVersion::v1(),
            identity.object_id,
            &nonce,
            ciphertext,
            &tag,
            &DecodeLimits::PHASE_1,
        )?;
        Ok((id, encode_aead_object(&object)?))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use notecrypt_core::VaultId;
    use notecrypt_crypto::{
        AUTHENTICATED_HEAD_OBJECT_KIND, CryptoError, PublicEnvelopeIdentity, SecureRandom,
        VaultRootKey, authenticate_head as create_head_authenticator, derive_vault_keys,
    };
    use notecrypt_format::{
        AuthenticationAlgorithmId, CryptoProfileId, FormatVersion, HeadPayload, HeadRecord,
        encode_head,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::VaultStore;

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
            output.fill(7);
            Ok(())
        }
    }

    struct Allow;

    impl PublicationGuard for Allow {
        fn validate(&mut self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn transaction_publishes_head_trusted_state_and_completed_journal() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([3; 16]);
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            vault,
        )
        .unwrap();
        let root = VaultRootKey::generate(&mut FixedRandom).unwrap();
        let head = head(vault, &root, [4; 32]);
        let keys = KeyCell::new(root).unwrap();
        let result = commit(
            &store.layout,
            store.begin_durable_batch().unwrap(),
            &keys,
            TransactionRequest {
                objects: Vec::new(),
                intended_head: head.clone(),
                expected_base: None,
            },
            |_, _| Ok(()),
            &mut Allow,
            &AtomicBool::new(false),
        )
        .unwrap();

        assert_eq!(result.snapshot, SnapshotId::from_bytes([4; 32]));
        assert_eq!(result.metrics.immutable_renames, 0);
        assert_eq!(std::fs::read(repository.path().join("head")).unwrap(), head);
        let local_vault = local.path().join("03030303030303030303030303030303");
        assert!(local_vault.join("trusted/head").is_file());
        assert!(local_vault.join("journal/active").is_file());
        assert_eq!(
            std::fs::read_dir(repository.path().join(".notecrypt-txn"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                .count(),
            0
        );
    }

    #[test]
    fn close_after_service_validation_prevents_journal_and_head_publication() {
        struct BlockingGuard {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
        }
        impl PublicationGuard for BlockingGuard {
            fn validate(&mut self) -> Result<(), StoreError> {
                self.entered.wait();
                self.release.wait();
                Ok(())
            }
        }

        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let repository_path = repository.path().canonicalize().unwrap();
        let local_path = local.path().canonicalize().unwrap();
        let vault = VaultId::from_bytes([9; 16]);
        let store =
            Arc::new(VaultStore::create_empty(&repository_path, &local_path, vault).unwrap());
        let root = VaultRootKey::generate(&mut FixedRandom).unwrap();
        let head = head(vault, &root, [8; 32]);
        let keys = Arc::new(KeyCell::new(root).unwrap());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker = {
            let store = Arc::clone(&store);
            let keys = Arc::clone(&keys);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            thread::spawn(move || {
                commit(
                    &store.layout,
                    store.begin_durable_batch().unwrap(),
                    &keys,
                    TransactionRequest {
                        objects: Vec::new(),
                        intended_head: head,
                        expected_base: None,
                    },
                    |_, _| Ok(()),
                    &mut BlockingGuard { entered, release },
                    &AtomicBool::new(false),
                )
            })
        };
        entered.wait();
        keys.begin_close().unwrap();
        release.wait();
        assert!(matches!(worker.join().unwrap(), Err(StoreError::Locked)));
        assert!(!repository_path.join("head").exists());
        let local_vault = local_path.join("09090909090909090909090909090909");
        assert!(!local_vault.join("journal/active").exists());
        assert!(!local_vault.join("trusted/head").exists());
    }

    #[test]
    fn close_after_publication_authorization_waits_for_durable_head_boundary() {
        struct BlockAfterJournal {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
        }

        impl TransactionObserver for BlockAfterJournal {
            fn at(
                &mut self,
                boundary: TransactionBoundary,
                moment: BoundaryMoment,
            ) -> Result<(), StoreError> {
                if boundary == TransactionBoundary::WriteJournal && moment == BoundaryMoment::After
                {
                    self.entered.wait();
                    self.release.wait();
                }
                Ok(())
            }
        }

        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let repository_path = repository.path().canonicalize().unwrap();
        let local_path = local.path().canonicalize().unwrap();
        let vault = VaultId::from_bytes([0x0a; 16]);
        let store =
            Arc::new(VaultStore::create_empty(&repository_path, &local_path, vault).unwrap());
        let root = VaultRootKey::generate(&mut FixedRandom).unwrap();
        let intended = head(vault, &root, [0x0b; 32]);
        let keys = Arc::new(KeyCell::new(root).unwrap());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let commit_worker = {
            let store = Arc::clone(&store);
            let keys = Arc::clone(&keys);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            thread::spawn(move || {
                commit_observed(
                    &store.layout,
                    store.begin_durable_batch().unwrap(),
                    &keys,
                    TransactionRequest {
                        objects: Vec::new(),
                        intended_head: intended,
                        expected_base: None,
                    },
                    |_, _| Ok(()),
                    &mut Allow,
                    &AtomicBool::new(false),
                    &mut BlockAfterJournal { entered, release },
                )
            })
        };

        entered.wait();
        let close_started = Arc::new(Barrier::new(2));
        let close_returned = Arc::new(AtomicBool::new(false));
        let close_worker = {
            let keys = Arc::clone(&keys);
            let close_started = Arc::clone(&close_started);
            let close_returned = Arc::clone(&close_returned);
            thread::spawn(move || {
                let result = keys.begin_close_observed(|| {
                    close_started.wait();
                });
                close_returned.store(true, Ordering::Release);
                result
            })
        };
        close_started.wait();
        assert!(!close_returned.load(Ordering::Acquire));
        release.wait();

        assert!(matches!(
            commit_worker.join().unwrap(),
            Err(StoreError::Locked)
        ));
        close_worker.join().unwrap().unwrap();
        assert!(close_returned.load(Ordering::Acquire));
        drop(keys);
        drop(store);

        let recovered_store =
            VaultStore::create_empty(&repository_path, &local_path, vault).unwrap();
        let recovered_root = VaultRootKey::generate(&mut FixedRandom).unwrap();
        let recovered_keys = KeyCell::new(recovered_root).unwrap();
        let outcome = crate::recovery::recover(
            &recovered_store.layout,
            recovered_store.begin_durable_batch().unwrap(),
            &recovered_keys,
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            outcome,
            crate::recovery::RecoveryOutcome::Completed(SnapshotId::from_bytes([0x0b; 32]))
        );
    }

    fn head(vault: VaultId, root: &VaultRootKey, snapshot: [u8; 32]) -> Vec<u8> {
        let keys = derive_vault_keys(root).unwrap();
        let object_id = [5; 32];
        let payload = HeadPayload::new(snapshot, [6; 32], [7; 32]);
        let canonical = notecrypt_format::encode_head_payload(&payload).unwrap();
        let context = AuthenticatedHeadContext::try_new(PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: AUTHENTICATED_HEAD_OBJECT_KIND,
            format_version: 1,
            object_id,
        })
        .unwrap();
        let authenticator =
            create_head_authenticator(&context, &canonical, &keys.snapshot_authentication).unwrap();
        let record = HeadRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            *vault.as_bytes(),
            FormatVersion::v1(),
            object_id,
            payload,
            authenticator.as_bytes(),
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        encode_head(&record).unwrap()
    }
}
