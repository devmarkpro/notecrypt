use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use notecrypt_core::{CoreError, EntryName, FileId, ObjectId, RevisionId, SnapshotId, VaultId};
use notecrypt_crypto::{
    AeadEnvelopeParts, Argon2idParameters, OsRandom, PublicEnvelopeIdentity,
    RECOVERY_SLOT_OBJECT_KIND, RecoveryPassphrase, RecoverySlotContext, RecoverySlotEnvelope,
    RecoverySlotPlaintext, RecoveryWrappingKey, SecureRandom, TypedAeadEnvelope,
    ValidatedArgon2idParameters, VaultRootKey, decrypt_recovery_slot, derive_recovery_wrapping_key,
    encrypt_recovery_slot,
};
use notecrypt_format::{
    AeadAlgorithmId, AeadObject, BootstrapHeader, ChunkDescriptor, ContentPayload, CryptoProfileId,
    CryptoSuite, DecodeLimits, FormatVersion, HeadPayload, KdfParameters, KdfProfileId,
    LogicalTree, OrdinaryAeadKind, PriorEntryKind, RecoverySlot, RevisionLocator, RevisionManifest,
    SnapshotParentLocator, SnapshotPayload, TreeEntry, decode_aead_object, decode_bootstrap,
    decode_content_chunk, decode_snapshot_object, encode_bootstrap, encode_content_payload,
    encode_manifest, encode_snapshot_payload, encode_tree,
};
use notecrypt_platform_fs::{FileCapability, FileStamp};
use zeroize::{Zeroize, Zeroizing};

use crate::StoreError;
use crate::availability::VaultAvailability;
use crate::batch::DurableBatch;
use crate::compromise::{
    CompromiseRekeySource, PendingVaultTarget, RepositoryCompromiseSource,
    RepositoryPendingVaultTarget,
};
use crate::device::DeviceSlotRegistry;
use crate::key_cell::KeyCell;
use crate::layout::component;
use crate::local_io::read_optional;
use crate::recovery::recover;
use crate::repository::{
    FilesystemCleanupPersistence, FilesystemDeviceSlotPersistence, UnlockedVault, VaultStore,
};
use crate::transaction::{
    PublicationGuard, TransactionObject, TransactionRequest, authenticate_head,
    commit as commit_transaction, read_and_authenticate_current_head, write_trusted,
};
use crate::trusted_state::TrustedHead;

const BOOTSTRAP_FILE: &str = ".notecrypt-vault";
const PENDING_ACTIVATION_FILE: &str = ".notecrypt-pending";
const IDENTITY_RETRIES: usize = 16;
const READ_PAGE_BYTES: usize = 64 * 1024;

pub struct RepositoryEntry {
    file_id: FileId,
    revision_id: RevisionId,
    name: String,
}

impl RepositoryEntry {
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    #[must_use]
    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for RepositoryEntry {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

pub struct RepositorySnapshot {
    snapshot_id: SnapshotId,
    file_id: FileId,
    revision_id: RevisionId,
}

pub enum VaultRepairAction {
    RebuildTrustedHead,
}

pub struct VaultRepair {
    store: Arc<VaultStore>,
    keys: Arc<KeyCell>,
    generation: u64,
    authorized_head: crate::transaction::AuthenticatedHead,
}

impl VaultRepair {
    pub fn apply(self, action: VaultRepairAction, cancel: &AtomicBool) -> Result<(), StoreError> {
        self.apply_observed(action, cancel, None)
    }

    fn apply_observed(
        self,
        action: VaultRepairAction,
        cancel: &AtomicBool,
        after_authenticated_snapshot: Option<&dyn Fn()>,
    ) -> Result<(), StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let _mutation = self.store.begin_store_mutation()?;
        let current =
            authenticate_repository_head(self.store.as_ref(), self.keys.as_ref(), self.generation)?;
        if current.commitment != self.authorized_head.commitment
            || current.snapshot != self.authorized_head.snapshot
            || current.snapshot_object != self.authorized_head.snapshot_object
            || current.tree_object != self.authorized_head.tree_object
        {
            return Err(StoreError::RollbackDetected);
        }
        verify_complete_head_record_observed(
            self.store.as_ref(),
            self.keys.as_ref(),
            self.generation,
            &current,
            Some(cancel),
            after_authenticated_snapshot,
        )?;
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        match action {
            VaultRepairAction::RebuildTrustedHead => write_trusted(
                &self.store.layout,
                &TrustedHead::new(
                    self.store.layout.vault,
                    current.snapshot,
                    current.commitment,
                ),
                self.keys.as_ref(),
                self.generation,
            ),
        }
    }
}

impl Drop for VaultRepair {
    fn drop(&mut self) {
        let _ = self.keys.begin_close();
        let _ = self.keys.close();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepositoryEntryId([u8; 16]);

impl RepositoryEntryId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<FileId> for RepositoryEntryId {
    fn from(value: FileId) -> Self {
        Self(*value.as_bytes())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RepositoryEntryKind {
    File,
    Directory,
    Tombstone,
}

pub struct RepositoryListedEntry {
    id: RepositoryEntryId,
    parent: RepositoryEntryId,
    name: String,
    kind: RepositoryEntryKind,
    revision: Option<RevisionId>,
}

impl RepositoryListedEntry {
    #[must_use]
    pub const fn id(&self) -> RepositoryEntryId {
        self.id
    }

    #[must_use]
    pub const fn parent_id(&self) -> RepositoryEntryId {
        self.parent
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> RepositoryEntryKind {
        self.kind
    }

    #[must_use]
    pub const fn revision_id(&self) -> Option<RevisionId> {
        self.revision
    }

    #[must_use]
    pub fn into_parts(
        mut self,
    ) -> (
        RepositoryEntryId,
        RepositoryEntryId,
        String,
        RepositoryEntryKind,
        Option<RevisionId>,
    ) {
        (
            self.id,
            self.parent,
            std::mem::take(&mut self.name),
            self.kind,
            self.revision,
        )
    }
}

impl Drop for RepositoryListedEntry {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

/// One coherent authenticated observation of the current logical vault tree.
pub struct RepositoryAuthenticatedView {
    snapshot: SnapshotId,
    root: RepositoryEntryId,
    entries: Vec<RepositoryListedEntry>,
}

/// Fixed-size projection of one authenticated current head and logical tree.
pub struct RepositoryAuthenticatedStatus {
    snapshot: SnapshotId,
    root: RepositoryEntryId,
    entry_count: usize,
}

impl RepositoryAuthenticatedStatus {
    #[must_use]
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot
    }

    #[must_use]
    pub fn root_entry_id(&self) -> RepositoryEntryId {
        self.root
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

impl RepositoryAuthenticatedView {
    #[must_use]
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot
    }

    #[must_use]
    pub fn root_entry_id(&self) -> RepositoryEntryId {
        self.root
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn into_entries(self) -> Vec<RepositoryListedEntry> {
        self.entries
    }
}

pub struct RepositoryMutation {
    expected_snapshot: SnapshotId,
    operation: RepositoryMutationOperation,
}

enum RepositoryMutationOperation {
    CreateDirectory {
        parent: RepositoryEntryId,
        name: String,
    },
    Rename {
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: String,
        new_parent: RepositoryEntryId,
        new_name: String,
    },
    Delete {
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: String,
        expected_revision: Option<RevisionId>,
        expected_kind: RepositoryEntryKind,
    },
}

impl RepositoryMutation {
    #[must_use]
    pub fn create_directory(
        expected_snapshot: SnapshotId,
        parent: RepositoryEntryId,
        name: &str,
    ) -> Self {
        Self::create_directory_owned(expected_snapshot, parent, name.to_owned())
    }

    #[must_use]
    pub fn create_directory_owned(
        expected_snapshot: SnapshotId,
        parent: RepositoryEntryId,
        name: String,
    ) -> Self {
        Self {
            expected_snapshot,
            operation: RepositoryMutationOperation::CreateDirectory { parent, name },
        }
    }

    #[must_use]
    pub fn rename(
        expected_snapshot: SnapshotId,
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: &str,
        new_parent: RepositoryEntryId,
        new_name: &str,
    ) -> Self {
        Self::rename_owned(
            expected_snapshot,
            entry,
            expected_parent,
            expected_name.to_owned(),
            new_parent,
            new_name.to_owned(),
        )
    }

    #[must_use]
    pub fn rename_owned(
        expected_snapshot: SnapshotId,
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: String,
        new_parent: RepositoryEntryId,
        new_name: String,
    ) -> Self {
        Self {
            expected_snapshot,
            operation: RepositoryMutationOperation::Rename {
                entry,
                expected_parent,
                expected_name,
                new_parent,
                new_name,
            },
        }
    }

    #[must_use]
    pub fn delete_file(
        expected_snapshot: SnapshotId,
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: &str,
        expected_revision: RevisionId,
    ) -> Self {
        Self::delete_file_owned(
            expected_snapshot,
            entry,
            expected_parent,
            expected_name.to_owned(),
            expected_revision,
        )
    }

    #[must_use]
    pub fn delete_file_owned(
        expected_snapshot: SnapshotId,
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: String,
        expected_revision: RevisionId,
    ) -> Self {
        Self {
            expected_snapshot,
            operation: RepositoryMutationOperation::Delete {
                entry,
                expected_parent,
                expected_name,
                expected_revision: Some(expected_revision),
                expected_kind: RepositoryEntryKind::File,
            },
        }
    }

    #[must_use]
    pub fn delete_directory(
        expected_snapshot: SnapshotId,
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: &str,
    ) -> Self {
        Self::delete_directory_owned(
            expected_snapshot,
            entry,
            expected_parent,
            expected_name.to_owned(),
        )
    }

    #[must_use]
    pub fn delete_directory_owned(
        expected_snapshot: SnapshotId,
        entry: RepositoryEntryId,
        expected_parent: RepositoryEntryId,
        expected_name: String,
    ) -> Self {
        Self {
            expected_snapshot,
            operation: RepositoryMutationOperation::Delete {
                entry,
                expected_parent,
                expected_name,
                expected_revision: None,
                expected_kind: RepositoryEntryKind::Directory,
            },
        }
    }
}

impl Drop for RepositoryMutation {
    fn drop(&mut self) {
        match &mut self.operation {
            RepositoryMutationOperation::CreateDirectory { name, .. } => name.zeroize(),
            RepositoryMutationOperation::Rename {
                expected_name,
                new_name,
                ..
            } => {
                expected_name.zeroize();
                new_name.zeroize();
            }
            RepositoryMutationOperation::Delete { expected_name, .. } => expected_name.zeroize(),
        }
    }
}

pub struct RepositoryMutationResult {
    snapshot_id: SnapshotId,
    entry_id: RepositoryEntryId,
}

pub struct StreamRevisionRequest {
    expected_snapshot: SnapshotId,
    file_id: Option<FileId>,
    parent: Option<RepositoryEntryId>,
    expected_revision: Option<RevisionId>,
    name: String,
}

impl StreamRevisionRequest {
    #[must_use]
    pub fn create(expected_snapshot: SnapshotId, name: &str) -> Self {
        Self::create_owned(expected_snapshot, name.to_owned())
    }

    #[must_use]
    pub fn create_owned(expected_snapshot: SnapshotId, name: String) -> Self {
        Self {
            expected_snapshot,
            file_id: None,
            parent: None,
            expected_revision: None,
            name,
        }
    }

    #[must_use]
    pub fn create_in_parent(
        expected_snapshot: SnapshotId,
        parent: RepositoryEntryId,
        name: &str,
    ) -> Self {
        Self::create_in_parent_owned(expected_snapshot, parent, name.to_owned())
    }

    #[must_use]
    pub fn create_in_parent_owned(
        expected_snapshot: SnapshotId,
        parent: RepositoryEntryId,
        name: String,
    ) -> Self {
        Self {
            expected_snapshot,
            file_id: None,
            parent: Some(parent),
            expected_revision: None,
            name,
        }
    }

    #[must_use]
    pub fn replace(
        expected_snapshot: SnapshotId,
        file_id: FileId,
        expected_revision: RevisionId,
        name: &str,
    ) -> Self {
        Self::replace_owned(
            expected_snapshot,
            file_id,
            expected_revision,
            name.to_owned(),
        )
    }

    #[must_use]
    pub fn replace_owned(
        expected_snapshot: SnapshotId,
        file_id: FileId,
        expected_revision: RevisionId,
        name: String,
    ) -> Self {
        Self {
            expected_snapshot,
            file_id: Some(file_id),
            parent: None,
            expected_revision: Some(expected_revision),
            name,
        }
    }
}

impl Drop for StreamRevisionRequest {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

impl RepositoryMutationResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn entry_id(&self) -> RepositoryEntryId {
        self.entry_id
    }
}

impl RepositorySnapshot {
    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    #[must_use]
    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }
}

pub struct UnlockedVaultLease {
    store: Arc<VaultStore>,
    keys: Arc<KeyCell>,
    generation: u64,
    verified_chunks: Arc<Mutex<HashMap<ObjectId, VerifiedChunkStamp>>>,
    stamp_cache_policy: Arc<StampCachePolicy>,
}

pub(crate) struct StampCachePolicy {
    enabled: AtomicBool,
}

impl StampCachePolicy {
    pub(crate) const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
        }
    }

    fn accepts(&self, stamp: FileStamp) -> bool {
        self.enabled.load(Ordering::Acquire) && stamp.is_cacheable()
    }

    #[cfg(feature = "test-support")]
    fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedChunkStamp {
    vault: VaultId,
    generation: u64,
    object: ObjectId,
    kind: crate::ImportedObjectKind,
    stamp: FileStamp,
}

impl VerifiedChunkStamp {
    const fn new(vault: VaultId, generation: u64, object: ObjectId, stamp: FileStamp) -> Self {
        Self {
            vault,
            generation,
            object,
            kind: crate::ImportedObjectKind::Chunk,
            stamp,
        }
    }

    fn matches_binding(self, vault: VaultId, generation: u64, object: ObjectId) -> bool {
        self.vault == vault
            && self.generation == generation
            && self.object == object
            && self.kind == crate::ImportedObjectKind::Chunk
    }
}

pub(crate) struct SourceHeadCommitment {
    snapshot: SnapshotId,
    snapshot_object: ObjectId,
    tree_object: ObjectId,
    head_commitment: [u8; 32],
}

impl VaultStore {
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.layout.vault
    }

    pub fn initialize(
        repository_root: &Path,
        local_state_root: &Path,
        passphrase: RecoveryPassphrase,
        parameters: ValidatedArgon2idParameters,
        device_label: &str,
        cancel: &AtomicBool,
    ) -> Result<Arc<Self>, StoreError> {
        let (store, unlocked) = initialize_new_target(
            repository_root,
            local_state_root,
            passphrase,
            parameters,
            device_label,
            cancel,
            None,
        )?;
        match unlocked.close() {
            Ok(()) => Ok(store),
            Err(primary) => {
                let cleanup = crate::repository::open_root(local_state_root).and_then(|local| {
                    crate::compromise::cleanup_owned_target(
                        &store.layout.repository,
                        &local,
                        store.layout.vault,
                    )
                });
                match cleanup {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                        primary: Box::new(primary),
                        cleanup: std::io::Error::other(cleanup.to_string()),
                    }),
                }
            }
        }
    }

    pub fn open(repository_root: &Path, local_state_root: &Path) -> Result<Arc<Self>, StoreError> {
        let repository = crate::repository::open_root(repository_root)?;
        let pending_marker = match repository.entry_kind(&component(PENDING_ACTIVATION_FILE)?) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Ok(notecrypt_platform_fs::EntryKind::File) => true,
            Ok(_) => return Err(StoreError::FilesystemObjectRejected),
            Err(error) => return Err(StoreError::from(error)),
        };
        let bytes =
            read_optional(&repository, &component(BOOTSTRAP_FILE)?)?.ok_or(StoreError::NotFound)?;
        let bootstrap = decode_bootstrap(&bytes, &DecodeLimits::PHASE_1)?;
        let store = Arc::new(Self::open_existing(
            repository_root,
            local_state_root,
            VaultId::from_bytes(*bootstrap.vault_id()),
        )?);
        if pending_marker
            && !matches!(
                crate::availability::untrusted_state(&store.layout)?,
                Some(VaultAvailability::Activating | VaultAvailability::Active)
            )
        {
            return Err(StoreError::InvalidCapability);
        }
        Ok(store)
    }

    pub fn unlock_recovery(
        self: &Arc<Self>,
        passphrase: RecoveryPassphrase,
        cancel: &AtomicBool,
    ) -> Result<UnlockedVault, StoreError> {
        #[cfg(feature = "test-support")]
        test_support::run_before_recovery_unlock_hook(self.layout.vault);
        let (keys, bootstrap_bytes) = self.recovery_keys(passphrase, cancel)?;
        unlock_with_keys(self, keys, Some(bootstrap_bytes), Some(cancel))
    }

    pub fn authorize_repair(
        self: &Arc<Self>,
        passphrase: RecoveryPassphrase,
        cancel: &AtomicBool,
    ) -> Result<VaultRepair, StoreError> {
        self.authorize_repair_observed(passphrase, cancel, None)
    }

    fn authorize_repair_observed(
        self: &Arc<Self>,
        passphrase: RecoveryPassphrase,
        cancel: &AtomicBool,
        after_authenticated_snapshot: Option<&dyn Fn()>,
    ) -> Result<VaultRepair, StoreError> {
        let (keys, _) = self.recovery_keys(passphrase, cancel)?;
        let generation = keys.generation();
        let authorized = authenticate_repository_head(self.as_ref(), keys.as_ref(), generation)
            .and_then(|head| {
                verify_complete_head_record_observed(
                    self.as_ref(),
                    keys.as_ref(),
                    generation,
                    &head,
                    Some(cancel),
                    after_authenticated_snapshot,
                )?;
                Ok(head)
            });
        match authorized {
            Ok(authorized_head) => Ok(VaultRepair {
                store: Arc::clone(self),
                keys,
                generation,
                authorized_head,
            }),
            Err(error) => {
                let _ = keys.begin_close();
                let _ = keys.close();
                Err(error)
            }
        }
    }

    fn recovery_keys(
        &self,
        passphrase: RecoveryPassphrase,
        cancel: &AtomicBool,
    ) -> Result<(Arc<KeyCell>, Arc<[u8]>), StoreError> {
        let mut bootstrap_file = self
            .layout
            .repository
            .open_file_nofollow(&component(BOOTSTRAP_FILE)?)?;
        let bootstrap_identity = bootstrap_file.identity()?;
        let bootstrap_bytes = read_exact_bounded(&mut bootstrap_file, 1 << 20)?;
        let bootstrap = decode_bootstrap(&bootstrap_bytes, &DecodeLimits::PHASE_1)
            .map_err(|_| StoreError::AuthenticationFailed)?;
        if bootstrap.vault_id() != self.layout.vault.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let kdf = bootstrap.kdf();
        let parameters = ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: kdf.memory_kib(),
            iterations: kdf.iterations(),
            parallelism: kdf.lanes(),
        })
        .map_err(|_| StoreError::AuthenticationFailed)?;
        let recovery_key =
            derive_recovery_wrapping_key(&passphrase, kdf.salt(), parameters, cancel)
                .map_err(map_unlock_crypto)?;
        let reread = read_exact_bounded(&mut bootstrap_file, 1 << 20)?;
        let named = self
            .layout
            .repository
            .open_file_nofollow(&component(BOOTSTRAP_FILE)?)?;
        if reread != bootstrap_bytes || !named.matches_identity(&bootstrap_identity)? {
            return Err(StoreError::AuthenticationFailed);
        }
        let root = decrypt_bootstrap_root(&bootstrap, &recovery_key)?;
        let keys = Arc::new(KeyCell::new(root)?);
        Ok((keys, Arc::from(bootstrap_bytes)))
    }
}

fn authenticate_repository_head(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
) -> Result<crate::transaction::AuthenticatedHead, StoreError> {
    let bytes = read_optional(&store.layout.repository, &component("head")?)?
        .ok_or(StoreError::NotFound)?;
    let head = authenticate_head(&bytes, keys, generation)?;
    if head.vault != store.layout.vault {
        return Err(StoreError::AuthenticationFailed);
    }
    Ok(head)
}

pub(crate) fn initialize_compromise_target(
    repository_root: &Path,
    local_state_root: &Path,
    passphrase: RecoveryPassphrase,
    parameters: ValidatedArgon2idParameters,
    device_label: &str,
    cancel: &AtomicBool,
    forbidden_vault: VaultId,
) -> Result<(Arc<VaultStore>, UnlockedVault), StoreError> {
    initialize_new_target(
        repository_root,
        local_state_root,
        passphrase,
        parameters,
        device_label,
        cancel,
        Some(forbidden_vault),
    )
}

#[allow(clippy::too_many_arguments)]
fn initialize_new_target(
    repository_root: &Path,
    local_state_root: &Path,
    passphrase: RecoveryPassphrase,
    parameters: ValidatedArgon2idParameters,
    device_label: &str,
    cancel: &AtomicBool,
    forbidden_vault: Option<VaultId>,
) -> Result<(Arc<VaultStore>, UnlockedVault), StoreError> {
    let mut random = OsRandom;
    let availability = if forbidden_vault.is_some() {
        VaultAvailability::Inactive
    } else {
        VaultAvailability::Active
    };
    #[cfg(feature = "test-support")]
    test_support::check_initialization_entropy(
        test_support::InitializationEntropyStage::VaultIdentity,
    )?;
    let vault = generate_vault_id(&mut random, forbidden_vault)?;
    let salt = generate_random_16(&mut random)?;
    let selected = parameters.parameters();
    let kdf = KdfParameters::try_new(
        KdfProfileId::argon2id_v1(),
        selected.memory_kib,
        selected.iterations,
        selected.parallelism,
        &salt,
    )?;
    #[cfg(feature = "test-support")]
    test_support::check_initialization_kdf(
        test_support::InitializationKdfFaultPoint::BeforeStart,
        cancel,
    );
    let recovery_key =
        derive_recovery_wrapping_key(&passphrase, &salt, parameters, cancel).map_err(map_random)?;
    #[cfg(feature = "test-support")]
    test_support::check_initialization_kdf(
        test_support::InitializationKdfFaultPoint::AfterComputation,
        cancel,
    );
    if cancel.load(Ordering::Acquire) {
        return Err(StoreError::Cancelled);
    }
    let store = Arc::new(VaultStore::create_new(
        repository_root,
        local_state_root,
        vault,
    )?);
    let initialized = (|| {
        if read_optional(&store.layout.repository, &component(BOOTSTRAP_FILE)?)?.is_some() {
            return Err(StoreError::ImmutableObjectConflict);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(StoreError::Cancelled);
        }
        let root = VaultRootKey::generate(&mut random).map_err(map_random)?;
        #[cfg(feature = "test-support")]
        test_support::check_initialization_entropy(
            test_support::InitializationEntropyStage::RecoverySlotIdentity,
        )?;
        let bootstrap = build_bootstrap(vault, kdf, &root, &recovery_key, &mut random)?;
        write_bootstrap(&store, &bootstrap)?;
        if cancel.load(Ordering::Acquire) {
            return Err(StoreError::Cancelled);
        }
        let authenticated_bootstrap: Arc<[u8]> = Arc::from(bootstrap);
        let keys = initialize_empty_graph(&store, root, device_label, &mut random, cancel)?;
        #[cfg(feature = "test-support")]
        test_support::run_before_initial_availability_hook();
        #[cfg(feature = "test-support")]
        test_support::run_before_initial_availability_send_hook();
        if cancel.load(Ordering::Acquire) {
            let _ = keys.close();
            return Err(StoreError::Cancelled);
        }
        let generation = keys.generation();
        crate::availability::write_initial(&store.layout, &keys, generation, availability)?;
        #[cfg(feature = "test-support")]
        test_support::run_after_initial_availability_hook();
        if availability == VaultAvailability::Inactive {
            write_pending_activation_marker(&store)?;
        }
        Ok(UnlockedVault {
            store: Arc::clone(&store),
            keys,
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: Some(authenticated_bootstrap),
        })
    })();
    match initialized {
        Ok(unlocked) => Ok((store, unlocked)),
        Err(primary) => {
            let cleanup = crate::repository::open_root(local_state_root).and_then(|local| {
                crate::compromise::cleanup_owned_target(&store.layout.repository, &local, vault)
            });
            match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(primary),
                    cleanup: std::io::Error::other(cleanup.to_string()),
                }),
            }
        }
    }
}

pub(crate) fn unlock_with_keys(
    store: &Arc<VaultStore>,
    keys: Arc<KeyCell>,
    authenticated_bootstrap: Option<Arc<[u8]>>,
    cancel: Option<&AtomicBool>,
) -> Result<UnlockedVault, StoreError> {
    let generation = keys.generation();
    let unlock_result = (|| {
        check_graph_boundary(&keys, generation, cancel)?;
        #[cfg(feature = "test-support")]
        test_support::run_after_recovery_keys_hook(store.layout.vault);
        let batch = store.begin_durable_batch()?;
        recover(
            &store.layout,
            batch,
            &keys,
            |id, file| {
                check_graph_boundary(&keys, generation, cancel)?;
                let result =
                    authenticate_any_object(&keys, generation, store.layout.vault, *id, file);
                check_graph_boundary(&keys, generation, cancel)?;
                result
            },
            |head| verify_complete_head(store, &keys, generation, head, cancel).map(|_| ()),
            cancel,
        )?;
        check_graph_boundary(&keys, generation, cancel)?;
        crate::trusted_remote::authenticate_trusted_remote_if_present(
            &store.layout,
            &keys,
            generation,
        )?;
        check_graph_boundary(&keys, generation, cancel)?;
        let mut cleanup = crate::cleanup::CleanupRegistry::new(
            store.layout.vault,
            generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &store.layout.cleanup_registry,
                &store.layout.cleanup_staging,
            ),
        )?;
        cleanup.authenticated_records(keys.as_ref())?;
        check_graph_boundary(&keys, generation, cancel)?;
        let mut devices = DeviceSlotRegistry::new(
            store.layout.vault,
            generation,
            OsRandom,
            FilesystemDeviceSlotPersistence::new(&store.layout),
        )?;
        devices.authenticate_existing(&keys)?;
        check_graph_boundary(&keys, generation, cancel)?;
        devices.authenticate_all_local_records(&keys)?;
        check_graph_boundary(&keys, generation, cancel)?;
        recover_or_require_active(store, &keys, generation)?;
        check_graph_boundary(&keys, generation, cancel)?;
        let verified_chunks = if let Some(head) =
            read_and_authenticate_current_head(&store.layout, &keys, generation)?
        {
            verify_complete_head_record_observed(store, &keys, generation, &head, cancel, None)?
        } else {
            HashMap::new()
        };
        Ok::<HashMap<ObjectId, VerifiedChunkStamp>, StoreError>(verified_chunks)
    })();
    let verified_chunks = match unlock_result {
        Ok(verified_chunks) => verified_chunks,
        Err(error) => {
            let _ = keys.begin_close();
            let _ = keys.close();
            return Err(error);
        }
    };
    Ok(UnlockedVault {
        store: Arc::clone(store),
        keys,
        generation,
        workspace_absence_authority: None,
        verified_chunks: Arc::new(Mutex::new(verified_chunks)),
        stamp_cache_policy: Arc::new(StampCachePolicy::new()),
        authenticated_bootstrap,
    })
}

impl UnlockedVault {
    pub fn acquire_lease(&self) -> Result<UnlockedVaultLease, StoreError> {
        self.keys.validate_generation(self.generation)?;
        Ok(UnlockedVaultLease {
            store: Arc::clone(&self.store),
            keys: Arc::clone(&self.keys),
            generation: self.generation,
            verified_chunks: Arc::clone(&self.verified_chunks),
            stamp_cache_policy: Arc::clone(&self.stamp_cache_policy),
        })
    }

    pub fn acquire_compromise_rekey_source(
        &self,
    ) -> Result<Box<dyn CompromiseRekeySource>, StoreError> {
        Ok(Box::new(RepositoryCompromiseSource::acquire(
            self.acquire_lease()?,
        )?))
    }

    pub(crate) fn begin_compromise_activation(
        &self,
        cancel: &AtomicBool,
        commit_attempt: impl FnOnce(),
    ) -> Result<(), StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _authorization = self.keys.authorize_publication(self.generation)?;
        #[cfg(feature = "test-support")]
        test_support::run_before_compromise_activation_hook();
        if cancel.load(Ordering::Acquire) {
            return Err(StoreError::Cancelled);
        }
        commit_attempt();
        crate::availability::begin_activation(&self.store.layout, &self.keys, self.generation)
    }

    pub(crate) fn complete_compromise_activation_record(&self) -> Result<(), StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _authorization = self.keys.authorize_publication(self.generation)?;
        crate::availability::complete_activation(&self.store.layout, &self.keys, self.generation)
    }

    pub(crate) fn finalize_compromise_activation(&self) -> Result<(), StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _authorization = self.keys.authorize_publication(self.generation)?;
        remove_pending_activation_marker(self.store.as_ref())
    }
}

fn recover_or_require_active(
    store: &Arc<VaultStore>,
    keys: &Arc<KeyCell>,
    generation: u64,
) -> Result<(), StoreError> {
    match crate::availability::authenticated_state(&store.layout, keys, generation)? {
        VaultAvailability::Inactive => Err(StoreError::InvalidCapability),
        VaultAvailability::Activating => {
            let _mutation = store.begin_store_mutation()?;
            let _authorization = keys.authorize_publication(generation)?;
            crate::availability::complete_activation(&store.layout, keys, generation)?;
            remove_pending_activation_marker(store)?;
            crate::availability::require_active(&store.layout, keys, generation)
        }
        VaultAvailability::Active => {
            if store
                .layout
                .repository
                .entry_kind(&component(PENDING_ACTIVATION_FILE)?)
                .is_ok()
            {
                let _mutation = store.begin_store_mutation()?;
                let _authorization = keys.authorize_publication(generation)?;
                remove_pending_activation_marker(store)?;
            }
            crate::availability::require_active(&store.layout, keys, generation)
        }
    }
}

impl VaultStore {
    #[allow(clippy::too_many_arguments)]
    pub fn begin_pending_target(
        &self,
        repository_root: &Path,
        local_state_root: &Path,
        passphrase: RecoveryPassphrase,
        parameters: ValidatedArgon2idParameters,
        device_label: &str,
        cancel: &AtomicBool,
    ) -> Result<Box<dyn PendingVaultTarget>, StoreError> {
        Ok(Box::new(RepositoryPendingVaultTarget::begin(
            self,
            repository_root,
            local_state_root,
            passphrase,
            parameters,
            device_label,
            cancel,
        )?))
    }
}

impl UnlockedVaultLease {
    #[cfg(feature = "test-support")]
    pub(crate) fn vault_id(&self) -> VaultId {
        self.store.layout.vault
    }

    pub(crate) fn validate_generation(&self) -> Result<(), StoreError> {
        self.keys.validate_generation(self.generation)
    }

    pub(crate) fn capture_current_head_commitment(
        &mut self,
    ) -> Result<SourceHeadCommitment, StoreError> {
        self.validate_generation()?;
        let (head, _tree) = self.current_tree()?;
        self.validate_generation()?;
        Ok(SourceHeadCommitment {
            snapshot: head.snapshot,
            snapshot_object: head.snapshot_object,
            tree_object: head.tree_object,
            head_commitment: head.commitment,
        })
    }

    pub(crate) fn validate_current_head_commitment(
        &mut self,
        expected: &SourceHeadCommitment,
    ) -> Result<(), StoreError> {
        self.validate_generation()?;
        let head = read_and_authenticate_current_head(
            &self.store.layout,
            self.keys.as_ref(),
            self.generation,
        )?
        .ok_or(StoreError::NotFound)?;
        if head.snapshot != expected.snapshot
            || head.snapshot_object != expected.snapshot_object
            || head.tree_object != expected.tree_object
            || head.commitment != expected.head_commitment
        {
            return Err(StoreError::RollbackDetected);
        }
        self.validate_generation()
    }

    pub fn list(&mut self) -> Result<Vec<RepositoryEntry>, StoreError> {
        self.keys.validate_generation(self.generation)?;
        let (_head, tree) = self.current_tree()?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(tree.entries().len())
            .map_err(|_| StoreError::AllocationFailed)?;
        for entry in tree.entries() {
            if let TreeEntry::File {
                id, name, locator, ..
            } = entry
            {
                let mut owned_name = String::new();
                owned_name
                    .try_reserve_exact(name.len())
                    .map_err(|_| StoreError::AllocationFailed)?;
                owned_name.push_str(name);
                output.push(RepositoryEntry {
                    file_id: FileId::from_bytes(*id),
                    revision_id: RevisionId::from_bytes(*locator.revision_id()),
                    name: owned_name,
                });
            }
        }
        self.keys.validate_generation(self.generation)?;
        Ok(output)
    }

    pub fn root_entry_id(&mut self) -> Result<RepositoryEntryId, StoreError> {
        self.keys.validate_generation(self.generation)?;
        let (_head, tree) = self.current_tree()?;
        self.keys.validate_generation(self.generation)?;
        Ok(RepositoryEntryId(*tree.root()))
    }

    pub fn current_snapshot_id(&mut self) -> Result<SnapshotId, StoreError> {
        self.keys.validate_generation(self.generation)?;
        let (head, _tree) = self.current_tree()?;
        self.keys.validate_generation(self.generation)?;
        Ok(head.snapshot)
    }

    pub fn list_entries(&mut self) -> Result<Vec<RepositoryListedEntry>, StoreError> {
        self.authenticated_view(usize::MAX, &AtomicBool::new(false))
            .map(RepositoryAuthenticatedView::into_entries)
    }

    pub fn authenticated_view(
        &mut self,
        max_entries: usize,
        cancel: &AtomicBool,
    ) -> Result<RepositoryAuthenticatedView, StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        #[cfg(feature = "test-support")]
        test_support::check_authenticated_read_fault(
            self.store.layout.vault,
            test_support::AuthenticatedReadFault::ViewAllocation,
        )?;
        let (head, tree) = self.current_tree_with_cancel(cancel)?;
        let entry_count = tree.entries().len().saturating_sub(1);
        if entry_count > max_entries {
            return Err(StoreError::LimitExceeded);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(entry_count)
            .map_err(|_| StoreError::AllocationFailed)?;
        for entry in tree.entries() {
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
            let listed = match entry {
                TreeEntry::Root { .. } => continue,
                TreeEntry::File {
                    id,
                    parent,
                    name,
                    locator,
                } => RepositoryListedEntry {
                    id: RepositoryEntryId(*id),
                    parent: RepositoryEntryId(*parent),
                    name: copy_string(name)?,
                    kind: RepositoryEntryKind::File,
                    revision: Some(RevisionId::from_bytes(*locator.revision_id())),
                },
                TreeEntry::Directory { id, parent, name } => RepositoryListedEntry {
                    id: RepositoryEntryId(*id),
                    parent: RepositoryEntryId(*parent),
                    name: copy_string(name)?,
                    kind: RepositoryEntryKind::Directory,
                    revision: None,
                },
                TreeEntry::Tombstone {
                    id,
                    parent,
                    name,
                    last_revision,
                    ..
                } => RepositoryListedEntry {
                    id: RepositoryEntryId(*id),
                    parent: RepositoryEntryId(*parent),
                    name: copy_string(name)?,
                    kind: RepositoryEntryKind::Tombstone,
                    revision: last_revision
                        .as_ref()
                        .map(|locator| RevisionId::from_bytes(*locator.revision_id())),
                },
            };
            output.push(listed);
        }
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        Ok(RepositoryAuthenticatedView {
            snapshot: head.snapshot,
            root: RepositoryEntryId(*tree.root()),
            entries: output,
        })
    }

    pub fn validate_entry_binding(
        &mut self,
        entry: RepositoryEntryId,
        parent: RepositoryEntryId,
        name: &str,
        kind: RepositoryEntryKind,
        revision: Option<RevisionId>,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let (_, tree) = self.current_tree_with_cancel(cancel)?;
        for candidate in tree.entries() {
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
            if entry_matches_binding(candidate, entry, parent, name, kind, revision) {
                return Ok(());
            }
        }
        Err(StoreError::InvalidCapability)
    }

    pub fn validate_export_binding(
        &mut self,
        entry: RepositoryEntryId,
        revision: RevisionId,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let (_, tree) = self.current_tree_with_cancel(cancel)?;
        for candidate in tree.entries() {
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
            if entry_matches_export(candidate, entry, revision) {
                return Ok(());
            }
        }
        Err(StoreError::InvalidCapability)
    }

    pub fn authenticated_status(
        &mut self,
        max_entries: usize,
        cancel: &AtomicBool,
    ) -> Result<RepositoryAuthenticatedStatus, StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        #[cfg(feature = "test-support")]
        test_support::check_authenticated_read_fault(
            self.store.layout.vault,
            test_support::AuthenticatedReadFault::StatusAllocation,
        )?;
        let (head, tree) = self.current_tree_with_cancel(cancel)?;
        let entry_count = tree.entries().len().saturating_sub(1);
        if entry_count > max_entries {
            return Err(StoreError::LimitExceeded);
        }
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        Ok(RepositoryAuthenticatedStatus {
            snapshot: head.snapshot,
            root: RepositoryEntryId(*tree.root()),
            entry_count,
        })
    }

    pub fn apply(
        &mut self,
        mutation: RepositoryMutation,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
    ) -> Result<RepositoryMutationResult, StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let mut random = OsRandom;
        let mut batch = self.store.begin_durable_batch()?;
        let mut staged_kinds = HashMap::new();
        let (current, tree) = self.current_tree()?;
        verify_current_head_record(
            self.store.as_ref(),
            self.keys.as_ref(),
            self.generation,
            &current,
            cancel,
            &self.verified_chunks,
            self.stamp_cache_policy.as_ref(),
        )?;
        if current.snapshot != mutation.expected_snapshot {
            return Err(StoreError::RollbackDetected);
        }
        let root = *tree.root();
        let mut entries = tree.into_parts().1;
        let snapshot = generate_snapshot_id(&mut random)?;
        let affected = apply_repository_mutation(
            &mutation.operation,
            root,
            snapshot,
            &mut entries,
            &mut random,
        )?;
        let tree_object = generate_unique_object(self.store.as_ref(), &mut random)?;
        let tree = LogicalTree::try_new(root, entries, &DecodeLimits::PHASE_1)?;
        let tree_wire = self.keys.encrypt_local_tree(
            self.generation,
            self.store.layout.vault,
            tree_object,
            encode_tree(&tree)?,
            &mut random,
        )?;
        stage_local_wire(
            &mut batch,
            tree_object,
            &tree_wire,
            self.keys.as_ref(),
            self.generation,
            cancel,
        )?;
        remember_staged_kind(
            &mut staged_kinds,
            tree_object,
            crate::ImportedObjectKind::Tree,
        )?;
        let snapshot_object = generate_unique_object(self.store.as_ref(), &mut random)?;
        let snapshot_payload = SnapshotPayload::try_new(
            *snapshot.as_bytes(),
            vec![SnapshotParentLocator::new(
                *current.snapshot.as_bytes(),
                *current.snapshot_object.as_bytes(),
            )],
            *tree_object.as_bytes(),
            generate_random_16(&mut random)?,
            "local-mutation",
            &DecodeLimits::PHASE_1,
        )?;
        let snapshot_wire = self.keys.encrypt_local_snapshot(
            self.generation,
            self.store.layout.vault,
            snapshot_object,
            encode_snapshot_payload(&snapshot_payload)?,
            &mut random,
        )?;
        stage_local_wire(
            &mut batch,
            snapshot_object,
            &snapshot_wire,
            self.keys.as_ref(),
            self.generation,
            cancel,
        )?;
        remember_staged_kind(
            &mut staged_kinds,
            snapshot_object,
            crate::ImportedObjectKind::Snapshot,
        )?;
        let head_id = generate_unique_object(self.store.as_ref(), &mut random)?;
        let intended_head = self.keys.build_local_head(
            self.generation,
            self.store.layout.vault,
            head_id,
            HeadPayload::new(
                *snapshot.as_bytes(),
                *snapshot_object.as_bytes(),
                *tree_object.as_bytes(),
            ),
        )?;
        let result = commit_transaction(
            &self.store.layout,
            batch,
            self.keys.as_ref(),
            TransactionRequest {
                objects: Vec::new(),
                intended_head,
                expected_base: Some(current.snapshot),
            },
            |id, file| {
                authenticate_known_object(
                    self.keys.as_ref(),
                    self.generation,
                    self.store.layout.vault,
                    *id,
                    file,
                    &staged_kinds,
                )
            },
            publication_guard,
            cancel,
        )?;
        Ok(RepositoryMutationResult {
            snapshot_id: result.snapshot,
            entry_id: affected,
        })
    }

    pub fn export(
        &mut self,
        file_id: FileId,
        expected_revision: RevisionId,
        output: &mut dyn Write,
        cancel: &AtomicBool,
    ) -> Result<u64, StoreError> {
        self.export_checked(file_id, Some(expected_revision), output, cancel)
    }

    pub(crate) fn export_exact(
        &mut self,
        file_id: FileId,
        expected_revision: RevisionId,
        output: &mut dyn Write,
        cancel: &AtomicBool,
    ) -> Result<u64, StoreError> {
        self.export_checked(file_id, Some(expected_revision), output, cancel)
    }

    fn export_checked(
        &mut self,
        file_id: FileId,
        expected_revision: Option<RevisionId>,
        output: &mut dyn Write,
        cancel: &AtomicBool,
    ) -> Result<u64, StoreError> {
        let (_head, tree) = self.current_tree()?;
        let locator = tree
            .entries()
            .iter()
            .find_map(|entry| match entry {
                TreeEntry::File { id, locator, .. } if id == file_id.as_bytes() => Some(locator),
                _ => None,
            })
            .ok_or(StoreError::NotFound)?;
        if expected_revision.is_some_and(|revision| revision.as_bytes() != locator.revision_id()) {
            return Err(StoreError::InvalidCapability);
        }
        let manifest_id = ObjectId::from_bytes(*locator.manifest_object_id());
        let mut manifest_file = self.store.open_object(&manifest_id)?;
        let manifest =
            self.keys
                .decrypt_local_manifest(self.generation, manifest_id, &mut manifest_file)?;
        if manifest.file_id() != file_id.as_bytes()
            || manifest.revision_id() != locator.revision_id()
        {
            return Err(StoreError::AuthenticationFailed);
        }
        let mut spool = self.store.begin_durable_batch()?;
        for descriptor in manifest.chunks() {
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
            let object = ObjectId::from_bytes(*descriptor.object_id());
            let mut chunk = self.store.open_object(&object)?;
            let encrypted_bytes = chunk.len()?;
            spool.stage_checked(object, &mut chunk, encrypted_bytes, |_| {
                check_boundary(self.keys.as_ref(), self.generation, cancel)
            })?;
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        }
        let mut authenticated_bytes = 0_u64;
        for (position, descriptor) in manifest.chunks().iter().enumerate() {
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
            let object = ObjectId::from_bytes(*descriptor.object_id());
            let mut chunk = spool.open_staged(&object)?;
            authenticated_bytes = authenticated_bytes
                .checked_add(self.keys.export_local_chunk(
                    self.generation,
                    object,
                    *file_id.as_bytes(),
                    u64::try_from(position).map_err(|_| StoreError::LimitExceeded)?,
                    &mut chunk,
                    &mut std::io::sink(),
                )?)
                .ok_or(StoreError::LimitExceeded)?;
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        }
        if authenticated_bytes != manifest.total_plaintext_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let mut written = 0_u64;
        for (position, descriptor) in manifest.chunks().iter().enumerate() {
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
            let object = ObjectId::from_bytes(*descriptor.object_id());
            let mut chunk = spool.open_staged(&object)?;
            written = written
                .checked_add(self.keys.export_local_chunk(
                    self.generation,
                    object,
                    *file_id.as_bytes(),
                    u64::try_from(position).map_err(|_| StoreError::LimitExceeded)?,
                    &mut chunk,
                    output,
                )?)
                .ok_or(StoreError::LimitExceeded)?;
            check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        }
        if written != authenticated_bytes {
            return Err(StoreError::AuthenticationFailed);
        }
        spool.discard()?;
        Ok(written)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn commit_streamed_revision_internal(
        &mut self,
        file_id: Option<FileId>,
        name: &str,
        source: &mut dyn Read,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
    ) -> Result<RepositorySnapshot, StoreError> {
        self.commit_streamed_revision_with_random(
            file_id,
            None,
            name,
            None,
            None,
            source,
            publication_guard,
            cancel,
            notecrypt_format::DecodeLimits::PHASE_1.max_chunks_per_file,
            &mut OsRandom,
        )
    }

    #[allow(clippy::too_many_lines)]
    pub fn commit_streamed_revision(
        &mut self,
        request: StreamRevisionRequest,
        source: &mut dyn Read,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
    ) -> Result<RepositorySnapshot, StoreError> {
        self.commit_streamed_revision_with_random(
            request.file_id,
            request.parent,
            &request.name,
            Some(request.expected_snapshot),
            request.expected_revision,
            source,
            publication_guard,
            cancel,
            DecodeLimits::PHASE_1.max_chunks_per_file,
            &mut OsRandom,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn commit_streamed_revision_with_random(
        &mut self,
        file_id: Option<FileId>,
        requested_parent: Option<RepositoryEntryId>,
        name: &str,
        expected_snapshot: Option<SnapshotId>,
        expected_revision: Option<RevisionId>,
        source: &mut dyn Read,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
        maximum_chunks: u32,
        random: &mut dyn SecureRandom,
    ) -> Result<RepositorySnapshot, StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let mut batch = self.store.begin_durable_batch()?;
        let mut staged_kinds = HashMap::new();
        let (current, tree) = self.current_tree()?;
        verify_current_head_record(
            self.store.as_ref(),
            self.keys.as_ref(),
            self.generation,
            &current,
            cancel,
            &self.verified_chunks,
            self.stamp_cache_policy.as_ref(),
        )?;
        if expected_snapshot.is_some_and(|expected| expected != current.snapshot) {
            return Err(StoreError::RollbackDetected);
        }
        let root = *tree.root();
        let mut entries = tree.into_parts().1;
        if file_id.is_some() && requested_parent.is_some() {
            return Err(StoreError::InvalidCapability);
        }
        let file = file_id.unwrap_or(generate_file_id(random)?);
        let existing_index = entries
            .iter()
            .position(|entry| entry.id() == file.as_bytes());
        if let Some(expected) = expected_revision {
            let Some(index) = existing_index else {
                return Err(StoreError::InvalidCapability);
            };
            match &entries[index] {
                TreeEntry::File { locator, .. } if locator.revision_id() == expected.as_bytes() => {
                }
                _ => return Err(StoreError::InvalidCapability),
            }
        } else if expected_snapshot.is_some() && file_id.is_some() {
            return Err(StoreError::InvalidCapability);
        }
        if existing_index.is_none() {
            let parent = requested_parent.unwrap_or(RepositoryEntryId(root));
            require_directory(&entries, root, parent)?;
            require_name_available(&entries, parent, name, None)?;
        }

        let previous = if let Some(index) = existing_index {
            let manifest_id = match &entries[index] {
                TreeEntry::File { locator, .. } => {
                    ObjectId::from_bytes(*locator.manifest_object_id())
                }
                _ => return Err(StoreError::InvalidCapability),
            };
            let mut manifest_file = self.store.open_object(&manifest_id)?;
            Some(self.keys.decrypt_local_manifest(
                self.generation,
                manifest_id,
                &mut manifest_file,
            )?)
        } else {
            None
        };
        let previous_chunks = previous
            .as_ref()
            .map(RevisionManifest::chunks)
            .unwrap_or(&[]);

        let mut descriptors = Vec::new();
        let maximum_chunks =
            usize::try_from(maximum_chunks).map_err(|_| StoreError::LimitExceeded)?;
        let mut total = 0_u64;
        let mut position = 0_u64;
        loop {
            if descriptors.len() == maximum_chunks {
                let mut sentinel = [0_u8; 1];
                let read = loop {
                    check_boundary(self.keys.as_ref(), self.generation, cancel)?;
                    match source.read(&mut sentinel) {
                        Ok(read) => break read,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(StoreError::from(error)),
                    }
                };
                check_boundary(self.keys.as_ref(), self.generation, cancel)?;
                if read == 0 {
                    break;
                }
                return Err(StoreError::LimitExceeded);
            }
            let mut plaintext = read_chunk(source, self.keys.as_ref(), self.generation, cancel)?;
            if plaintext.is_empty() {
                break;
            }
            descriptors
                .try_reserve(1)
                .map_err(|_| StoreError::LimitExceeded)?;
            let plain_len =
                u32::try_from(plaintext.len()).map_err(|_| StoreError::LimitExceeded)?;
            total = total
                .checked_add(u64::from(plain_len))
                .ok_or(StoreError::LimitExceeded)?;
            let reused = if let Some(previous) = usize::try_from(position)
                .ok()
                .and_then(|index| previous_chunks.get(index))
            {
                if previous.plaintext_bytes() == plain_len
                    && self.keys.local_chunk_matches(
                        self.generation,
                        *file.as_bytes(),
                        position,
                        &plaintext,
                        previous.fingerprint(),
                    )?
                {
                    Some((
                        ObjectId::from_bytes(*previous.object_id()),
                        *previous.fingerprint(),
                    ))
                } else {
                    None
                }
            } else {
                None
            };
            let (object_id, fingerprint) = if let Some(reused) = reused {
                reused
            } else {
                let object_id = generate_unique_object(self.store.as_ref(), random)?;
                let fingerprint = self.keys.fingerprint_local_chunk(
                    self.generation,
                    *file.as_bytes(),
                    position,
                    &plaintext,
                )?;
                let payload = encode_content_payload(&ContentPayload::try_new(
                    *file.as_bytes(),
                    position,
                    std::mem::take(&mut plaintext),
                )?)?;
                let wire = self.keys.encrypt_local_chunk(
                    self.generation,
                    self.store.layout.vault,
                    object_id,
                    payload,
                    random,
                )?;
                stage_local_wire(
                    &mut batch,
                    object_id,
                    &wire,
                    self.keys.as_ref(),
                    self.generation,
                    cancel,
                )?;
                remember_staged_kind(
                    &mut staged_kinds,
                    object_id,
                    crate::ImportedObjectKind::Chunk,
                )?;
                (object_id, fingerprint)
            };
            descriptors.push(ChunkDescriptor::try_new(
                *object_id.as_bytes(),
                &fingerprint,
                plain_len,
            )?);
            position = position.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        }

        let revision = generate_revision_id(random)?;
        let manifest_object = generate_unique_object(self.store.as_ref(), random)?;
        let manifest = RevisionManifest::try_new(
            *file.as_bytes(),
            *revision.as_bytes(),
            descriptors,
            total,
            &DecodeLimits::PHASE_1,
        )?;
        let manifest_wire = self.keys.encrypt_local_manifest(
            self.generation,
            self.store.layout.vault,
            manifest_object,
            encode_manifest(&manifest)?,
            random,
        )?;
        stage_local_wire(
            &mut batch,
            manifest_object,
            &manifest_wire,
            self.keys.as_ref(),
            self.generation,
            cancel,
        )?;
        remember_staged_kind(
            &mut staged_kinds,
            manifest_object,
            crate::ImportedObjectKind::Manifest,
        )?;

        let parent = match existing_index {
            Some(index) => match &entries[index] {
                TreeEntry::File { parent, .. } => *parent,
                _ => return Err(StoreError::InvalidCapability),
            },
            None => *requested_parent
                .unwrap_or(RepositoryEntryId(root))
                .as_bytes(),
        };
        let replacement = TreeEntry::file(
            *file.as_bytes(),
            parent,
            name,
            RevisionLocator::new(*revision.as_bytes(), *manifest_object.as_bytes()),
            &DecodeLimits::PHASE_1,
        )?;
        match existing_index {
            Some(index) => entries[index] = replacement,
            None => entries.push(replacement),
        }
        let tree_object = generate_unique_object(self.store.as_ref(), random)?;
        let tree = LogicalTree::try_new(root, entries, &DecodeLimits::PHASE_1)?;
        let tree_wire = self.keys.encrypt_local_tree(
            self.generation,
            self.store.layout.vault,
            tree_object,
            encode_tree(&tree)?,
            random,
        )?;
        stage_local_wire(
            &mut batch,
            tree_object,
            &tree_wire,
            self.keys.as_ref(),
            self.generation,
            cancel,
        )?;
        remember_staged_kind(
            &mut staged_kinds,
            tree_object,
            crate::ImportedObjectKind::Tree,
        )?;

        let snapshot = generate_snapshot_id(random)?;
        let snapshot_object = generate_unique_object(self.store.as_ref(), random)?;
        let parents = vec![SnapshotParentLocator::new(
            *current.snapshot.as_bytes(),
            *current.snapshot_object.as_bytes(),
        )];
        let snapshot_payload = SnapshotPayload::try_new(
            *snapshot.as_bytes(),
            parents,
            *tree_object.as_bytes(),
            generate_random_16(random)?,
            "local",
            &DecodeLimits::PHASE_1,
        )?;
        let snapshot_wire = self.keys.encrypt_local_snapshot(
            self.generation,
            self.store.layout.vault,
            snapshot_object,
            encode_snapshot_payload(&snapshot_payload)?,
            random,
        )?;
        stage_local_wire(
            &mut batch,
            snapshot_object,
            &snapshot_wire,
            self.keys.as_ref(),
            self.generation,
            cancel,
        )?;
        remember_staged_kind(
            &mut staged_kinds,
            snapshot_object,
            crate::ImportedObjectKind::Snapshot,
        )?;
        let head_id = generate_unique_object(self.store.as_ref(), random)?;
        let intended_head = self.keys.build_local_head(
            self.generation,
            self.store.layout.vault,
            head_id,
            HeadPayload::new(
                *snapshot.as_bytes(),
                *snapshot_object.as_bytes(),
                *tree_object.as_bytes(),
            ),
        )?;
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;

        let result = commit_transaction(
            &self.store.layout,
            batch,
            self.keys.as_ref(),
            TransactionRequest {
                objects: Vec::new(),
                intended_head,
                expected_base: Some(current.snapshot),
            },
            |id, file| {
                authenticate_known_object(
                    self.keys.as_ref(),
                    self.generation,
                    self.store.layout.vault,
                    *id,
                    file,
                    &staged_kinds,
                )
            },
            publication_guard,
            cancel,
        )?;
        cache_published_chunks(
            self.store.as_ref(),
            self.store.layout.vault,
            self.generation,
            &staged_kinds,
            &self.verified_chunks,
            self.stamp_cache_policy.as_ref(),
        );
        Ok(RepositorySnapshot {
            snapshot_id: result.snapshot,
            file_id: file,
            revision_id: revision,
        })
    }

    fn current_tree(
        &self,
    ) -> Result<(crate::transaction::AuthenticatedHead, LogicalTree), StoreError> {
        let head = read_and_authenticate_current_head(
            &self.store.layout,
            self.keys.as_ref(),
            self.generation,
        )?
        .ok_or(StoreError::NotFound)?;
        let mut tree_file = self.store.open_object(&head.tree_object)?;
        let tree =
            self.keys
                .decrypt_local_tree(self.generation, head.tree_object, &mut tree_file)?;
        Ok((head, tree))
    }

    fn current_tree_with_cancel(
        &self,
        cancel: &AtomicBool,
    ) -> Result<(crate::transaction::AuthenticatedHead, LogicalTree), StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let head = read_and_authenticate_current_head(
            &self.store.layout,
            self.keys.as_ref(),
            self.generation,
        )?
        .ok_or(StoreError::NotFound)?;
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let mut tree_file = self.store.open_object(&head.tree_object)?;
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let tree =
            self.keys
                .decrypt_local_tree(self.generation, head.tree_object, &mut tree_file)?;
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        Ok((head, tree))
    }

    pub(crate) fn commit_parentless_current_state(
        &mut self,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
    ) -> Result<Vec<ObjectId>, StoreError> {
        check_boundary(self.keys.as_ref(), self.generation, cancel)?;
        let (current, tree) = self.current_tree()?;
        let mut random = OsRandom;
        let snapshot = generate_snapshot_id(&mut random)?;
        let snapshot_object = generate_unique_object(self.store.as_ref(), &mut random)?;
        let payload = SnapshotPayload::try_new(
            *snapshot.as_bytes(),
            Vec::new(),
            *current.tree_object.as_bytes(),
            generate_random_16(&mut random)?,
            "compromise-rekey",
            &DecodeLimits::PHASE_1,
        )?;
        let wire = self.keys.encrypt_local_snapshot(
            self.generation,
            self.store.layout.vault,
            snapshot_object,
            encode_snapshot_payload(&payload)?,
            &mut random,
        )?;
        let head_id = generate_unique_object(self.store.as_ref(), &mut random)?;
        let head = self.keys.build_local_head(
            self.generation,
            self.store.layout.vault,
            head_id,
            HeadPayload::new(
                *snapshot.as_bytes(),
                *snapshot_object.as_bytes(),
                *current.tree_object.as_bytes(),
            ),
        )?;
        let mut cursor = Cursor::new(wire.as_slice());
        commit_transaction(
            &self.store.layout,
            self.store.begin_durable_batch()?,
            self.keys.as_ref(),
            TransactionRequest {
                objects: vec![TransactionObject {
                    id: snapshot_object,
                    declared_length: wire.len() as u64,
                    source: &mut cursor,
                }],
                intended_head: head,
                expected_base: Some(current.snapshot),
            },
            |id, file| {
                authenticate_any_object(
                    self.keys.as_ref(),
                    self.generation,
                    self.store.layout.vault,
                    *id,
                    file,
                )
            },
            publication_guard,
            cancel,
        )?;
        let authenticated = read_and_authenticate_current_head(
            &self.store.layout,
            self.keys.as_ref(),
            self.generation,
        )?
        .ok_or(StoreError::NotFound)?;
        verify_complete_head_record(
            self.store.as_ref(),
            self.keys.as_ref(),
            self.generation,
            &authenticated,
        )?;
        collect_reachable_objects(
            self.store.as_ref(),
            self.keys.as_ref(),
            self.generation,
            snapshot_object,
            current.tree_object,
            &tree,
        )
    }
}

fn stage_local_wire(
    batch: &mut DurableBatch<'_>,
    id: ObjectId,
    wire: &[u8],
    keys: &KeyCell,
    generation: u64,
    cancel: &AtomicBool,
) -> Result<(), StoreError> {
    let declared_length = u64::try_from(wire.len()).map_err(|_| StoreError::LimitExceeded)?;
    batch.stage_checked(id, &mut Cursor::new(wire), declared_length, |_| {
        check_boundary(keys, generation, cancel)
    })
}

fn remember_staged_kind(
    kinds: &mut HashMap<ObjectId, crate::ImportedObjectKind>,
    id: ObjectId,
    kind: crate::ImportedObjectKind,
) -> Result<(), StoreError> {
    kinds
        .try_reserve(1)
        .map_err(|_| StoreError::LimitExceeded)?;
    if kinds.insert(id, kind).is_some() {
        return Err(StoreError::ImmutableObjectConflict);
    }
    Ok(())
}

fn authenticate_known_object(
    keys: &KeyCell,
    generation: u64,
    vault: VaultId,
    id: ObjectId,
    file: &mut FileCapability,
    kinds: &HashMap<ObjectId, crate::ImportedObjectKind>,
) -> Result<(), StoreError> {
    let kind = kinds
        .get(&id)
        .copied()
        .ok_or(StoreError::InvalidCapability)?;
    keys.authenticate_imported_object(generation, vault, id, kind, file, |_| Ok(()))?;
    Ok(())
}

fn apply_repository_mutation(
    operation: &RepositoryMutationOperation,
    root: [u8; 16],
    deleted_in: SnapshotId,
    entries: &mut Vec<TreeEntry>,
    random: &mut dyn SecureRandom,
) -> Result<RepositoryEntryId, StoreError> {
    match operation {
        RepositoryMutationOperation::CreateDirectory { parent, name } => {
            require_directory(entries, root, *parent)?;
            require_name_available(entries, *parent, name, None)?;
            let id = generate_unique_entry_id(entries, random)?;
            entries.push(TreeEntry::directory(
                *id.as_bytes(),
                *parent.as_bytes(),
                name,
                &DecodeLimits::PHASE_1,
            )?);
            Ok(id)
        }
        RepositoryMutationOperation::Rename {
            entry,
            expected_parent,
            expected_name,
            new_parent,
            new_name,
        } => {
            require_directory(entries, root, *new_parent)?;
            let index = find_entry(entries, *entry)?;
            require_expected_location(&entries[index], *expected_parent, expected_name)?;
            require_name_available(entries, *new_parent, new_name, Some(*entry))?;
            if matches!(entries[index], TreeEntry::Directory { .. }) {
                require_not_descendant(entries, root, *entry, *new_parent)?;
            }
            let replacement = match &entries[index] {
                TreeEntry::File { id, locator, .. } => TreeEntry::file(
                    *id,
                    *new_parent.as_bytes(),
                    new_name,
                    RevisionLocator::new(*locator.revision_id(), *locator.manifest_object_id()),
                    &DecodeLimits::PHASE_1,
                )?,
                TreeEntry::Directory { id, .. } => TreeEntry::directory(
                    *id,
                    *new_parent.as_bytes(),
                    new_name,
                    &DecodeLimits::PHASE_1,
                )?,
                TreeEntry::Root { .. } | TreeEntry::Tombstone { .. } => {
                    return Err(StoreError::InvalidCapability);
                }
            };
            entries[index] = replacement;
            Ok(*entry)
        }
        RepositoryMutationOperation::Delete {
            entry,
            expected_parent,
            expected_name,
            expected_revision,
            expected_kind,
        } => {
            let index = find_entry(entries, *entry)?;
            require_expected_location(&entries[index], *expected_parent, expected_name)?;
            let replacement = match &entries[index] {
                TreeEntry::File { id, locator, .. }
                    if *expected_kind == RepositoryEntryKind::File
                        && expected_revision.as_ref().map(RevisionId::as_bytes)
                            == Some(locator.revision_id()) =>
                {
                    TreeEntry::tombstone(
                        *id,
                        *expected_parent.as_bytes(),
                        expected_name,
                        *deleted_in.as_bytes(),
                        PriorEntryKind::File,
                        Some(RevisionLocator::new(
                            *locator.revision_id(),
                            *locator.manifest_object_id(),
                        )),
                        &DecodeLimits::PHASE_1,
                    )?
                }
                TreeEntry::Directory { id, .. }
                    if *expected_kind == RepositoryEntryKind::Directory
                        && expected_revision.is_none() =>
                {
                    if entries
                        .iter()
                        .any(|candidate| entry_parent(candidate) == Some(*entry.as_bytes()))
                    {
                        return Err(StoreError::InvalidCapability);
                    }
                    TreeEntry::tombstone(
                        *id,
                        *expected_parent.as_bytes(),
                        expected_name,
                        *deleted_in.as_bytes(),
                        PriorEntryKind::Directory,
                        None,
                        &DecodeLimits::PHASE_1,
                    )?
                }
                _ => return Err(StoreError::InvalidCapability),
            };
            entries[index] = replacement;
            Ok(*entry)
        }
    }
}

fn find_entry(entries: &[TreeEntry], id: RepositoryEntryId) -> Result<usize, StoreError> {
    entries
        .iter()
        .position(|entry| entry.id() == id.as_bytes())
        .ok_or(StoreError::InvalidCapability)
}

fn require_directory(
    entries: &[TreeEntry],
    root: [u8; 16],
    id: RepositoryEntryId,
) -> Result<(), StoreError> {
    if id.as_bytes() == &root
        || entries.iter().any(|entry| {
            matches!(entry, TreeEntry::Directory { id: candidate, .. } if candidate == id.as_bytes())
        })
    {
        Ok(())
    } else {
        Err(StoreError::InvalidCapability)
    }
}

fn require_expected_location(
    entry: &TreeEntry,
    expected_parent: RepositoryEntryId,
    expected_name: &str,
) -> Result<(), StoreError> {
    match entry {
        TreeEntry::File { parent, name, .. } | TreeEntry::Directory { parent, name, .. }
            if parent == expected_parent.as_bytes() && name == expected_name =>
        {
            Ok(())
        }
        _ => Err(StoreError::InvalidCapability),
    }
}

fn require_name_available(
    entries: &[TreeEntry],
    parent: RepositoryEntryId,
    name: &str,
    except: Option<RepositoryEntryId>,
) -> Result<(), StoreError> {
    let maximum = usize::from(DecodeLimits::PHASE_1.max_name_bytes);
    let requested = EntryName::try_parse_bounded(name, maximum)
        .map_err(map_entry_name_error)?
        .try_collision_key(maximum)
        .map_err(map_entry_name_error)?;
    for entry in entries {
        if except
            .as_ref()
            .is_some_and(|id| id.as_bytes() == entry.id())
        {
            continue;
        }
        let candidate = match entry {
            TreeEntry::File {
                parent: candidate_parent,
                name: candidate_name,
                ..
            }
            | TreeEntry::Directory {
                parent: candidate_parent,
                name: candidate_name,
                ..
            } if candidate_parent == parent.as_bytes() => candidate_name,
            _ => continue,
        };
        let collision = EntryName::try_parse_bounded(candidate, maximum)
            .map_err(map_entry_name_error)?
            .try_collision_key(maximum)
            .map_err(map_entry_name_error)?;
        if collision == requested {
            return Err(StoreError::InvalidCapability);
        }
    }
    Ok(())
}

fn map_entry_name_error(error: CoreError) -> StoreError {
    match error {
        CoreError::AllocationFailed => StoreError::AllocationFailed,
        CoreError::CapacityExceeded => StoreError::LimitExceeded,
        _ => StoreError::InvalidInput,
    }
}

fn require_not_descendant(
    entries: &[TreeEntry],
    root: [u8; 16],
    moved: RepositoryEntryId,
    mut parent: RepositoryEntryId,
) -> Result<(), StoreError> {
    for _ in 0..=entries.len() {
        if parent == moved {
            return Err(StoreError::InvalidCapability);
        }
        if parent.as_bytes() == &root {
            return Ok(());
        }
        let index = find_entry(entries, parent)?;
        parent =
            RepositoryEntryId(entry_parent(&entries[index]).ok_or(StoreError::InvalidCapability)?);
    }
    Err(StoreError::InvalidCapability)
}

fn entry_parent(entry: &TreeEntry) -> Option<[u8; 16]> {
    match entry {
        TreeEntry::Root { .. } => None,
        TreeEntry::File { parent, .. }
        | TreeEntry::Directory { parent, .. }
        | TreeEntry::Tombstone { parent, .. } => Some(*parent),
    }
}

fn generate_unique_entry_id(
    entries: &[TreeEntry],
    random: &mut dyn SecureRandom,
) -> Result<RepositoryEntryId, StoreError> {
    for _ in 0..IDENTITY_RETRIES {
        let candidate = RepositoryEntryId(generate_random_16(random)?);
        if entries
            .iter()
            .all(|entry| entry.id() != candidate.as_bytes())
        {
            return Ok(candidate);
        }
    }
    Err(StoreError::IdentityCollision)
}

fn copy_string(value: &str) -> Result<String, StoreError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| StoreError::AllocationFailed)?;
    output.push_str(value);
    Ok(output)
}

fn collect_reachable_objects(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
    snapshot: ObjectId,
    tree_id: ObjectId,
    tree: &LogicalTree,
) -> Result<Vec<ObjectId>, StoreError> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for id in [snapshot, tree_id] {
        if !seen.insert(id) {
            return Err(StoreError::AuthenticationFailed);
        }
        output.push(id);
    }
    for entry in tree.entries() {
        let TreeEntry::File { locator, .. } = entry else {
            continue;
        };
        let manifest_id = ObjectId::from_bytes(*locator.manifest_object_id());
        if !seen.insert(manifest_id) {
            return Err(StoreError::AuthenticationFailed);
        }
        output.push(manifest_id);
        let mut file = store.open_object(&manifest_id)?;
        let manifest = keys.decrypt_local_manifest(generation, manifest_id, &mut file)?;
        for descriptor in manifest.chunks() {
            let chunk = ObjectId::from_bytes(*descriptor.object_id());
            if !seen.insert(chunk) {
                return Err(StoreError::AuthenticationFailed);
            }
            output.push(chunk);
        }
    }
    Ok(output)
}

fn build_bootstrap(
    vault: VaultId,
    kdf: KdfParameters,
    root: &VaultRootKey,
    recovery_key: &RecoveryWrappingKey,
    random: &mut dyn SecureRandom,
) -> Result<Vec<u8>, StoreError> {
    let recovery_id = generate_object_id(random)?;
    let identity = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: *vault.as_bytes(),
        object_kind: RECOVERY_SLOT_OBJECT_KIND,
        format_version: 1,
        object_id: *recovery_id.as_bytes(),
    };
    let envelope = encrypt_recovery_slot(
        &RecoverySlotContext::try_new(identity)?,
        RecoverySlotPlaintext::from_root_key(root),
        recovery_key,
        random,
    )
    .map_err(map_random)?;
    let (identity, nonce, ciphertext, tag) =
        envelope.into_parts().into_public_parts().into_components();
    let slot = RecoverySlot::try_new(AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        identity.vault_id,
        OrdinaryAeadKind::RecoverySlot,
        FormatVersion::v1(),
        identity.object_id,
        &nonce,
        ciphertext,
        &tag,
        &DecodeLimits::PHASE_1,
    )?)?;
    Ok(encode_bootstrap(&BootstrapHeader::try_new(
        FormatVersion::v1(),
        CryptoSuite::profile_one(),
        *vault.as_bytes(),
        kdf,
        vec![slot],
        &DecodeLimits::PHASE_1,
    )?)?)
}

fn decrypt_bootstrap_root(
    bootstrap: &BootstrapHeader,
    recovery_key: &RecoveryWrappingKey,
) -> Result<VaultRootKey, StoreError> {
    let slot = bootstrap
        .recovery_slots()
        .first()
        .ok_or(StoreError::AuthenticationFailed)?
        .envelope();
    let identity = PublicEnvelopeIdentity {
        profile_id: slot.profile_id().get(),
        vault_id: *slot.vault_id(),
        object_kind: RECOVERY_SLOT_OBJECT_KIND,
        format_version: slot.format_version().get(),
        object_id: *slot.object_id(),
    };
    let envelope = RecoverySlotEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
        identity,
        slot.nonce(),
        slot.ciphertext().to_vec(),
        slot.tag(),
    )?)?;
    decrypt_recovery_slot(
        &RecoverySlotContext::try_new(identity)?,
        &envelope,
        recovery_key,
    )
    .map(RecoverySlotPlaintext::into_root_key)
    .map_err(|_| StoreError::AuthenticationFailed)
}

fn write_bootstrap(store: &VaultStore, bytes: &[u8]) -> Result<(), StoreError> {
    let batch = store.begin_durable_batch()?;
    let mut published = batch.authenticate_and_publish(|_, _| Ok(()))?;
    let name = component("bootstrap-stage")?;
    published.stage_replacement(
        name.clone(),
        &mut Cursor::new(bytes),
        u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?,
    )?;
    published.publish_replacement(&name, &component(BOOTSTRAP_FILE)?)?;
    published.finish()?;
    let readback = read_optional(&store.layout.repository, &component(BOOTSTRAP_FILE)?)?
        .ok_or(StoreError::NotFound)?;
    if readback != bytes || decode_bootstrap(&readback, &DecodeLimits::PHASE_1).is_err() {
        return Err(StoreError::AuthenticationFailed);
    }
    Ok(())
}

fn write_pending_activation_marker(store: &VaultStore) -> Result<(), StoreError> {
    let name = component(PENDING_ACTIVATION_FILE)?;
    let file = store.layout.repository.create_private_file_new(&name)?;
    file.sync_all()?;
    store.layout.repository.sync()?;
    match store.layout.repository.entry_kind(&name) {
        Ok(notecrypt_platform_fs::EntryKind::File) => Ok(()),
        Ok(_) => Err(StoreError::FilesystemObjectRejected),
        Err(error) => Err(StoreError::from(error)),
    }
}

fn remove_pending_activation_marker(store: &VaultStore) -> Result<(), StoreError> {
    let name = component(PENDING_ACTIVATION_FILE)?;
    match store.layout.repository.remove_file(&name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(StoreError::from(error)),
    }
    store.layout.repository.sync()?;
    match store.layout.repository.entry_kind(&name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(StoreError::InvalidCapability),
        Err(error) => Err(StoreError::from(error)),
    }
}

pub(crate) fn initialize_empty_graph(
    store: &VaultStore,
    root: VaultRootKey,
    device_label: &str,
    random: &mut dyn SecureRandom,
    cancel: &AtomicBool,
) -> Result<Arc<KeyCell>, StoreError> {
    let keys = Arc::new(KeyCell::new(root)?);
    let generation = keys.generation();
    let logical_root = generate_random_16(random)?;
    #[cfg(feature = "test-support")]
    test_support::check_initialization_entropy(
        test_support::InitializationEntropyStage::ObjectIdentity,
    )?;
    let tree_object = generate_unique_object(store, random)?;
    let tree = LogicalTree::try_new(
        logical_root,
        vec![TreeEntry::root(logical_root)],
        &DecodeLimits::PHASE_1,
    )?;
    #[cfg(feature = "test-support")]
    test_support::check_initialization_entropy(test_support::InitializationEntropyStage::Nonce)?;
    let tree_wire = keys.encrypt_local_tree(
        generation,
        store.layout.vault,
        tree_object,
        encode_tree(&tree)?,
        random,
    )?;
    #[cfg(feature = "test-support")]
    test_support::check_initialization_entropy(
        test_support::InitializationEntropyStage::SnapshotIdentity,
    )?;
    let snapshot = generate_snapshot_id(random)?;
    let snapshot_object = generate_unique_object(store, random)?;
    let snapshot_payload = SnapshotPayload::try_new(
        *snapshot.as_bytes(),
        Vec::new(),
        *tree_object.as_bytes(),
        generate_random_16(random)?,
        device_label,
        &DecodeLimits::PHASE_1,
    )?;
    let snapshot_wire = keys.encrypt_local_snapshot(
        generation,
        store.layout.vault,
        snapshot_object,
        encode_snapshot_payload(&snapshot_payload)?,
        random,
    )?;
    let head_id = generate_unique_object(store, random)?;
    let head = keys.build_local_head(
        generation,
        store.layout.vault,
        head_id,
        HeadPayload::new(
            *snapshot.as_bytes(),
            *snapshot_object.as_bytes(),
            *tree_object.as_bytes(),
        ),
    )?;
    let mut tree_cursor = Cursor::new(tree_wire.as_slice());
    let mut snapshot_cursor = Cursor::new(snapshot_wire.as_slice());
    let result = commit_transaction(
        &store.layout,
        store.begin_durable_batch()?,
        keys.as_ref(),
        TransactionRequest {
            objects: vec![
                TransactionObject {
                    id: tree_object,
                    declared_length: tree_wire.len() as u64,
                    source: &mut tree_cursor,
                },
                TransactionObject {
                    id: snapshot_object,
                    declared_length: snapshot_wire.len() as u64,
                    source: &mut snapshot_cursor,
                },
            ],
            intended_head: head,
            expected_base: None,
        },
        |id, file| {
            authenticate_any_object(keys.as_ref(), generation, store.layout.vault, *id, file)
        },
        &mut InitializationGuard,
        cancel,
    );
    result?;
    Ok(keys)
}

struct InitializationGuard;

impl PublicationGuard for InitializationGuard {
    fn validate(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

fn authenticate_any_object(
    keys: &KeyCell,
    generation: u64,
    vault: VaultId,
    id: ObjectId,
    file: &mut FileCapability,
) -> Result<(), StoreError> {
    let kind = detect_object_kind(file)?;
    file.seek(SeekFrom::Start(0))?;
    keys.authenticate_imported_object(generation, vault, id, kind, file, |_| Ok(()))?;
    Ok(())
}

fn detect_object_kind(file: &mut FileCapability) -> Result<crate::ImportedObjectKind, StoreError> {
    let length = file.len()?;
    if length > ReplicationObjectMaximum::BYTES {
        return Err(StoreError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(length).map_err(|_| StoreError::LimitExceeded)?)
        .map_err(|_| StoreError::AllocationFailed)?;
    file.seek(SeekFrom::Start(0))?;
    file.take(length.checked_add(1).ok_or(StoreError::LimitExceeded)?)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)? != length {
        return Err(StoreError::MalformedObject);
    }
    if decode_content_chunk(&bytes, &DecodeLimits::PHASE_1).is_ok() {
        return Ok(crate::ImportedObjectKind::Chunk);
    }
    if decode_snapshot_object(&bytes, &DecodeLimits::PHASE_1).is_ok() {
        return Ok(crate::ImportedObjectKind::Snapshot);
    }
    let ordinary = decode_aead_object(&bytes, &DecodeLimits::PHASE_1)?;
    match ordinary.kind() {
        OrdinaryAeadKind::Tree => Ok(crate::ImportedObjectKind::Tree),
        OrdinaryAeadKind::Manifest => Ok(crate::ImportedObjectKind::Manifest),
        _ => Err(StoreError::MalformedObject),
    }
}

struct ReplicationObjectMaximum;

impl ReplicationObjectMaximum {
    const BYTES: u64 = 256 << 20;
}

fn verify_complete_head(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
    canonical_head: &[u8],
    cancel: Option<&AtomicBool>,
) -> Result<HashMap<ObjectId, VerifiedChunkStamp>, StoreError> {
    let head = authenticate_head(canonical_head, keys, generation)?;
    verify_complete_head_record_observed(store, keys, generation, &head, cancel, None)
}

fn verify_complete_head_record(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
    head: &crate::transaction::AuthenticatedHead,
) -> Result<HashMap<ObjectId, VerifiedChunkStamp>, StoreError> {
    verify_complete_head_record_observed(store, keys, generation, head, None, None)
}

fn verify_complete_head_record_observed(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
    head: &crate::transaction::AuthenticatedHead,
    cancel: Option<&AtomicBool>,
    after_authenticated_snapshot: Option<&dyn Fn()>,
) -> Result<HashMap<ObjectId, VerifiedChunkStamp>, StoreError> {
    verify_head_graph(
        store,
        keys,
        generation,
        head,
        GraphVerificationContext {
            follow_history: true,
            cancel,
            verified_chunks: None,
            stamp_cache_policy: None,
            after_authenticated_snapshot,
        },
    )
}

fn verify_current_head_record(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
    head: &crate::transaction::AuthenticatedHead,
    cancel: &AtomicBool,
    verified_chunks: &Mutex<HashMap<ObjectId, VerifiedChunkStamp>>,
    stamp_cache_policy: &StampCachePolicy,
) -> Result<(), StoreError> {
    verify_head_graph(
        store,
        keys,
        generation,
        head,
        GraphVerificationContext {
            follow_history: false,
            cancel: Some(cancel),
            verified_chunks: Some(verified_chunks),
            stamp_cache_policy: Some(stamp_cache_policy),
            after_authenticated_snapshot: None,
        },
    )
    .map(|_| ())
}

struct GraphVerificationContext<'a> {
    follow_history: bool,
    cancel: Option<&'a AtomicBool>,
    verified_chunks: Option<&'a Mutex<HashMap<ObjectId, VerifiedChunkStamp>>>,
    stamp_cache_policy: Option<&'a StampCachePolicy>,
    after_authenticated_snapshot: Option<&'a dyn Fn()>,
}

fn verify_head_graph(
    store: &VaultStore,
    keys: &KeyCell,
    generation: u64,
    head: &crate::transaction::AuthenticatedHead,
    context: GraphVerificationContext<'_>,
) -> Result<HashMap<ObjectId, VerifiedChunkStamp>, StoreError> {
    let GraphVerificationContext {
        follow_history,
        cancel,
        verified_chunks,
        stamp_cache_policy,
        after_authenticated_snapshot,
    } = context;
    let limits = crate::ReplicationLimits::PHASE_1;
    let mut budget = LocalGraphBudget::new(limits);
    let mut queue = VecDeque::new();
    queue
        .try_reserve(1)
        .map_err(|_| StoreError::LimitExceeded)?;
    queue.push_back((head.snapshot, head.snapshot_object, 0_u32));
    let mut processed_snapshots = HashSet::new();
    let mut snapshot_to_object = HashMap::new();
    let mut object_to_snapshot = HashMap::new();
    let mut revision_to_object = HashMap::new();
    let mut object_to_revision = HashMap::new();
    let mut authenticated_chunks = HashMap::new();

    while let Some((expected_snapshot, snapshot_object, depth)) = queue.pop_front() {
        check_graph_boundary(keys, generation, cancel)?;
        if depth > limits.max_graph_depth {
            return Err(StoreError::LimitExceeded);
        }
        bind_bijective(
            &mut snapshot_to_object,
            &mut object_to_snapshot,
            expected_snapshot,
            snapshot_object,
        )?;
        if !insert_fallible(
            &mut processed_snapshots,
            (expected_snapshot, snapshot_object),
        )? {
            continue;
        }
        let mut snapshot_file = store.open_object(&snapshot_object)?;
        budget.charge_object(snapshot_object, snapshot_file.len()?)?;
        let snapshot =
            keys.decrypt_local_snapshot(generation, snapshot_object, &mut snapshot_file)?;
        if let Some(after_authenticated_snapshot) = after_authenticated_snapshot {
            after_authenticated_snapshot();
        }
        check_graph_boundary(keys, generation, cancel)?;
        if snapshot.snapshot_id() != expected_snapshot.as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let tree_object = ObjectId::from_bytes(*snapshot.tree_object_id());
        if depth == 0 && tree_object != head.tree_object {
            return Err(StoreError::AuthenticationFailed);
        }
        budget.charge_edge()?;
        let mut tree_file = store.open_object(&tree_object)?;
        budget.charge_object(tree_object, tree_file.len()?)?;
        let tree = keys.decrypt_local_tree(generation, tree_object, &mut tree_file)?;
        verify_tree_structure(&tree)?;
        for entry in tree.entries() {
            check_graph_boundary(keys, generation, cancel)?;
            let (id, locator) = match entry {
                TreeEntry::File { id, locator, .. }
                | TreeEntry::Tombstone {
                    id,
                    last_revision: Some(locator),
                    ..
                } => (id, locator),
                TreeEntry::Root { .. }
                | TreeEntry::Directory { .. }
                | TreeEntry::Tombstone {
                    last_revision: None,
                    ..
                } => continue,
            };
            budget.charge_edge()?;
            let revision = RevisionId::from_bytes(*locator.revision_id());
            let manifest_id = ObjectId::from_bytes(*locator.manifest_object_id());
            bind_bijective(
                &mut revision_to_object,
                &mut object_to_revision,
                revision,
                manifest_id,
            )?;
            let mut manifest_file = store.open_object(&manifest_id)?;
            budget.charge_object(manifest_id, manifest_file.len()?)?;
            let manifest =
                keys.decrypt_local_manifest(generation, manifest_id, &mut manifest_file)?;
            if manifest.file_id() != id || manifest.revision_id() != locator.revision_id() {
                return Err(StoreError::AuthenticationFailed);
            }
            for (position, chunk) in manifest.chunks().iter().enumerate() {
                check_graph_boundary(keys, generation, cancel)?;
                budget.charge_edge()?;
                let position = u64::try_from(position).map_err(|_| StoreError::LimitExceeded)?;
                let object = ObjectId::from_bytes(*chunk.object_id());
                let mut chunk_file = store.open_object(&object)?;
                budget.charge_object(object, chunk_file.len()?)?;
                let stamp = chunk_file.stamp()?;
                let known_stamp = if let Some(verified_chunks) = verified_chunks {
                    verified_chunks
                        .lock()
                        .map_err(|_| StoreError::Locked)?
                        .get(&object)
                        .copied()
                        .filter(|known| {
                            known.matches_binding(store.layout.vault, generation, object)
                        })
                        .map(|known| known.stamp)
                } else {
                    None
                };
                let unchanged_authenticated_stamp =
                    stamp.is_cacheable() && known_stamp.is_some_and(|known| known == stamp);
                if follow_history || !unchanged_authenticated_stamp {
                    let written = keys.export_local_chunk(
                        generation,
                        object,
                        *id,
                        position,
                        &mut chunk_file,
                        &mut std::io::sink(),
                    )?;
                    if written != u64::from(chunk.plaintext_bytes()) {
                        return Err(StoreError::AuthenticationFailed);
                    }
                    if stamp.is_cacheable()
                        && stamp_cache_policy.is_none_or(|policy| policy.accepts(stamp))
                        && let Some(verified_chunks) = verified_chunks
                    {
                        let mut verified_chunks =
                            verified_chunks.lock().map_err(|_| StoreError::Locked)?;
                        insert_verified_chunk_best_effort(
                            &mut verified_chunks,
                            object,
                            VerifiedChunkStamp::new(store.layout.vault, generation, object, stamp),
                        );
                    }
                    if stamp.is_cacheable()
                        && stamp_cache_policy.is_none_or(|policy| policy.accepts(stamp))
                    {
                        insert_verified_chunk_best_effort(
                            &mut authenticated_chunks,
                            object,
                            VerifiedChunkStamp::new(store.layout.vault, generation, object, stamp),
                        );
                    }
                }
                check_graph_boundary(keys, generation, cancel)?;
            }
        }
        if !follow_history {
            continue;
        }
        let next_depth = depth.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        for parent in snapshot.parents() {
            budget.charge_edge()?;
            queue
                .try_reserve(1)
                .map_err(|_| StoreError::LimitExceeded)?;
            queue.push_back((
                SnapshotId::from_bytes(*parent.snapshot_id()),
                ObjectId::from_bytes(*parent.snapshot_object_id()),
                next_depth,
            ));
        }
    }
    Ok(authenticated_chunks)
}

fn check_graph_boundary(
    keys: &KeyCell,
    generation: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(), StoreError> {
    if cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire)) {
        return Err(StoreError::Cancelled);
    }
    keys.validate_generation(generation)
}

struct LocalGraphBudget {
    limits: crate::ReplicationLimits,
    objects: HashSet<ObjectId>,
    aggregate: u64,
    edges: u64,
}

impl LocalGraphBudget {
    fn new(limits: crate::ReplicationLimits) -> Self {
        Self {
            limits,
            objects: HashSet::new(),
            aggregate: 0,
            edges: 0,
        }
    }

    fn charge_object(&mut self, id: ObjectId, encoded_length: u64) -> Result<(), StoreError> {
        if insert_fallible(&mut self.objects, id)? {
            if u64::try_from(self.objects.len()).map_err(|_| StoreError::LimitExceeded)?
                > self.limits.max_object_count
            {
                return Err(StoreError::LimitExceeded);
            }
            self.aggregate = self
                .aggregate
                .checked_add(encoded_length)
                .ok_or(StoreError::LimitExceeded)?;
            if self.aggregate > self.limits.max_aggregate_bytes {
                return Err(StoreError::LimitExceeded);
            }
        }
        Ok(())
    }

    fn charge_edge(&mut self) -> Result<(), StoreError> {
        self.edges = self.edges.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        if self.edges > self.limits.max_graph_edges {
            Err(StoreError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

fn bind_bijective<K, V>(
    forward: &mut HashMap<K, V>,
    reverse: &mut HashMap<V, K>,
    key: K,
    value: V,
) -> Result<(), StoreError>
where
    K: Copy + Eq + std::hash::Hash,
    V: Copy + Eq + std::hash::Hash,
{
    if forward.get(&key).is_some_and(|existing| existing != &value)
        || reverse.get(&value).is_some_and(|existing| existing != &key)
    {
        return Err(StoreError::AuthenticationFailed);
    }
    if !forward.contains_key(&key) {
        forward
            .try_reserve(1)
            .map_err(|_| StoreError::AllocationFailed)?;
        forward.insert(key, value);
    }
    if !reverse.contains_key(&value) {
        reverse
            .try_reserve(1)
            .map_err(|_| StoreError::AllocationFailed)?;
        reverse.insert(value, key);
    }
    Ok(())
}

fn insert_fallible<T>(set: &mut HashSet<T>, value: T) -> Result<bool, StoreError>
where
    T: Eq + std::hash::Hash,
{
    if set.contains(&value) {
        return Ok(false);
    }
    set.try_reserve(1)
        .map_err(|_| StoreError::AllocationFailed)?;
    Ok(set.insert(value))
}

fn cache_published_chunks(
    store: &VaultStore,
    vault: VaultId,
    generation: u64,
    staged_kinds: &HashMap<ObjectId, crate::ImportedObjectKind>,
    verified_chunks: &Mutex<HashMap<ObjectId, VerifiedChunkStamp>>,
    stamp_cache_policy: &StampCachePolicy,
) {
    let Ok(mut cache) = verified_chunks.lock() else {
        return;
    };
    for (object, kind) in staged_kinds {
        if *kind != crate::ImportedObjectKind::Chunk {
            continue;
        }
        let Ok(file) = store.open_object(object) else {
            continue;
        };
        let Ok(stamp) = file.stamp() else {
            continue;
        };
        if stamp_cache_policy.accepts(stamp) {
            insert_verified_chunk_best_effort(
                &mut cache,
                *object,
                VerifiedChunkStamp::new(vault, generation, *object, stamp),
            );
        }
    }
}

fn insert_verified_chunk_best_effort(
    cache: &mut HashMap<ObjectId, VerifiedChunkStamp>,
    object: ObjectId,
    verified: VerifiedChunkStamp,
) {
    if !cache.contains_key(&object) && cache.try_reserve(1).is_err() {
        return;
    }
    cache.insert(object, verified);
}

fn verify_tree_structure(tree: &LogicalTree) -> Result<(), StoreError> {
    let root = *tree.root();
    let mut directories = HashSet::new();
    directories
        .try_reserve(tree.entries().len())
        .map_err(|_| StoreError::AllocationFailed)?;
    directories.insert(root);
    for entry in tree.entries() {
        if let TreeEntry::Directory { id, .. } = entry {
            directories.insert(*id);
        }
    }
    for entry in tree.entries() {
        let Some(parent) = entry_parent(entry) else {
            continue;
        };
        if !directories.contains(&parent) {
            return Err(StoreError::AuthenticationFailed);
        }
        let mut current = parent;
        for _ in 0..=tree.entries().len() {
            if current == root {
                break;
            }
            if current == *entry.id() {
                return Err(StoreError::AuthenticationFailed);
            }
            let parent_entry = tree
                .entries()
                .iter()
                .find(|candidate| candidate.id() == &current)
                .ok_or(StoreError::AuthenticationFailed)?;
            current = entry_parent(parent_entry).ok_or(StoreError::AuthenticationFailed)?;
        }
        if current != root {
            return Err(StoreError::AuthenticationFailed);
        }
    }
    Ok(())
}

fn read_chunk(
    source: &mut dyn Read,
    keys: &KeyCell,
    generation: u64,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, StoreError> {
    let maximum = 1_048_576_usize;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(maximum)
        .map_err(|_| StoreError::LimitExceeded)?;
    let mut page = [0_u8; READ_PAGE_BYTES];
    while output.len() < maximum {
        check_boundary(keys, generation, cancel)?;
        let remaining = maximum - output.len();
        let bounded = remaining.min(page.len());
        let read = match source.read(&mut page[..bounded]) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(StoreError::from(error)),
        };
        if read == 0 {
            break;
        }
        output.extend_from_slice(&page[..read]);
        check_boundary(keys, generation, cancel)?;
    }
    Ok(std::mem::take(&mut *output))
}

fn read_exact_bounded(file: &mut FileCapability, maximum: u64) -> Result<Vec<u8>, StoreError> {
    let preflight = file.len()?;
    if preflight > maximum {
        return Err(StoreError::LimitExceeded);
    }
    let capacity = usize::try_from(preflight.checked_add(1).ok_or(StoreError::LimitExceeded)?)
        .map_err(|_| StoreError::LimitExceeded)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| StoreError::AllocationFailed)?;
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = maximum.checked_add(1).ok_or(StoreError::LimitExceeded)?;
    let mut page = [0_u8; READ_PAGE_BYTES];
    while remaining != 0 {
        let bounded = usize::try_from(remaining.min(page.len() as u64))
            .map_err(|_| StoreError::LimitExceeded)?;
        let read = file.read(&mut page[..bounded])?;
        if read == 0 {
            break;
        }
        output.extend_from_slice(&page[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| StoreError::LimitExceeded)?)
            .ok_or(StoreError::LimitExceeded)?;
    }
    if output.len() as u64 != preflight || output.len() as u64 > maximum {
        return Err(StoreError::MalformedObject);
    }
    Ok(output)
}

fn check_boundary(keys: &KeyCell, generation: u64, cancel: &AtomicBool) -> Result<(), StoreError> {
    if cancel.load(Ordering::Acquire) {
        return Err(StoreError::Cancelled);
    }
    keys.validate_generation(generation)
}

pub(crate) fn generate_unique_object(
    store: &VaultStore,
    random: &mut dyn SecureRandom,
) -> Result<ObjectId, StoreError> {
    for _ in 0..IDENTITY_RETRIES {
        let id = generate_object_id(random)?;
        match store.open_object(&id) {
            Err(StoreError::NotFound) => return Ok(id),
            Ok(_) | Err(StoreError::ImmutableObjectConflict) => {}
            Err(error) => return Err(error),
        }
    }
    Err(StoreError::IdentityCollision)
}

fn generate_object_id(random: &mut dyn SecureRandom) -> Result<ObjectId, StoreError> {
    let mut bytes = [0_u8; 32];
    random.fill(&mut bytes).map_err(map_random)?;
    Ok(ObjectId::from_bytes(bytes))
}

fn generate_snapshot_id(random: &mut dyn SecureRandom) -> Result<SnapshotId, StoreError> {
    let mut bytes = [0_u8; 32];
    random.fill(&mut bytes).map_err(map_random)?;
    Ok(SnapshotId::from_bytes(bytes))
}

fn generate_revision_id(random: &mut dyn SecureRandom) -> Result<RevisionId, StoreError> {
    let mut bytes = [0_u8; 32];
    random.fill(&mut bytes).map_err(map_random)?;
    Ok(RevisionId::from_bytes(bytes))
}

fn generate_file_id(random: &mut dyn SecureRandom) -> Result<FileId, StoreError> {
    Ok(FileId::from_bytes(generate_random_16(random)?))
}

fn generate_vault_id(
    random: &mut dyn SecureRandom,
    forbidden: Option<VaultId>,
) -> Result<VaultId, StoreError> {
    for _ in 0..IDENTITY_RETRIES {
        let candidate = VaultId::from_bytes(generate_random_16(random)?);
        if forbidden.as_ref() != Some(&candidate) {
            return Ok(candidate);
        }
    }
    Err(StoreError::IdentityCollision)
}

fn generate_random_16(random: &mut dyn SecureRandom) -> Result<[u8; 16], StoreError> {
    let mut bytes = [0_u8; 16];
    random.fill(&mut bytes).map_err(map_random)?;
    Ok(bytes)
}

fn map_random(error: notecrypt_crypto::CryptoError) -> StoreError {
    match error {
        notecrypt_crypto::CryptoError::RandomSource => StoreError::RandomSource,
        notecrypt_crypto::CryptoError::Cancelled => StoreError::Cancelled,
        notecrypt_crypto::CryptoError::Allocation => StoreError::AllocationFailed,
        notecrypt_crypto::CryptoError::Authentication => StoreError::AuthenticationFailed,
        notecrypt_crypto::CryptoError::PassphrasePolicy
        | notecrypt_crypto::CryptoError::InvalidKdfParameters
        | notecrypt_crypto::CryptoError::KeyDerivation
        | notecrypt_crypto::CryptoError::CalibrationFailed
        | notecrypt_crypto::CryptoError::InvalidEnvelope
        | notecrypt_crypto::CryptoError::PlaintextTooLarge
        | notecrypt_crypto::CryptoError::InvalidPlaintextLength => StoreError::InvalidInput,
    }
}

fn map_unlock_crypto(error: notecrypt_crypto::CryptoError) -> StoreError {
    match error {
        notecrypt_crypto::CryptoError::RandomSource => StoreError::RandomSource,
        notecrypt_crypto::CryptoError::Cancelled => StoreError::Cancelled,
        notecrypt_crypto::CryptoError::Allocation => StoreError::AllocationFailed,
        notecrypt_crypto::CryptoError::Authentication
        | notecrypt_crypto::CryptoError::PassphrasePolicy
        | notecrypt_crypto::CryptoError::KeyDerivation => StoreError::AuthenticationFailed,
        notecrypt_crypto::CryptoError::InvalidKdfParameters
        | notecrypt_crypto::CryptoError::CalibrationFailed
        | notecrypt_crypto::CryptoError::InvalidEnvelope
        | notecrypt_crypto::CryptoError::PlaintextTooLarge
        | notecrypt_crypto::CryptoError::InvalidPlaintextLength => StoreError::InvalidInput,
    }
}

#[cfg(test)]
mod activation_tests {
    use std::sync::atomic::AtomicBool;

    use notecrypt_core::VaultId;
    use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
    use tempfile::TempDir;

    use super::*;

    fn passphrase() -> RecoveryPassphrase {
        RecoveryPassphrase::new("alpha beta gamma delta epsilon".to_owned())
    }

    fn parameters() -> ValidatedArgon2idParameters {
        ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        })
        .unwrap()
    }

    #[test]
    fn fresh_unlock_recovers_both_durable_compromise_activation_crash_windows() {
        for crash_after_active in [false, true] {
            let repository = TempDir::new().unwrap();
            let local = TempDir::new().unwrap();
            let repository_path = repository.path().canonicalize().unwrap();
            let local_path = local.path().canonicalize().unwrap();
            let cancel = AtomicBool::new(false);
            let (store, unlocked) = initialize_compromise_target(
                &repository_path,
                &local_path,
                passphrase(),
                parameters(),
                "target-device",
                &cancel,
                VaultId::from_bytes([0x91; 16]),
            )
            .unwrap();
            assert!(VaultStore::open(&repository_path, &local_path).is_err());

            unlocked
                .begin_compromise_activation(&cancel, || {})
                .unwrap();
            if crash_after_active {
                unlocked.complete_compromise_activation_record().unwrap();
            }
            unlocked.close().unwrap();
            drop(store);

            let reopened = VaultStore::open(&repository_path, &local_path).unwrap();
            let recovered = reopened.unlock_recovery(passphrase(), &cancel).unwrap();
            recovered.close().unwrap();
            assert!(!repository_path.join(PENDING_ACTIVATION_FILE).exists());

            let second = VaultStore::open(&repository_path, &local_path).unwrap();
            second
                .unlock_recovery(passphrase(), &cancel)
                .unwrap()
                .close()
                .unwrap();
        }
    }
}

fn entry_matches_binding(
    candidate: &TreeEntry,
    entry: RepositoryEntryId,
    parent: RepositoryEntryId,
    name: &str,
    kind: RepositoryEntryKind,
    revision: Option<RevisionId>,
) -> bool {
    match candidate {
        TreeEntry::Root { .. } => false,
        TreeEntry::File {
            id,
            parent: candidate_parent,
            name: candidate_name,
            locator,
        } => {
            kind == RepositoryEntryKind::File
                && *id == entry.0
                && *candidate_parent == parent.0
                && candidate_name == name
                && revision == Some(RevisionId::from_bytes(*locator.revision_id()))
        }
        TreeEntry::Directory {
            id,
            parent: candidate_parent,
            name: candidate_name,
        } => {
            kind == RepositoryEntryKind::Directory
                && *id == entry.0
                && *candidate_parent == parent.0
                && candidate_name == name
                && revision.is_none()
        }
        TreeEntry::Tombstone {
            id,
            parent: candidate_parent,
            name: candidate_name,
            last_revision,
            ..
        } => {
            kind == RepositoryEntryKind::Tombstone
                && *id == entry.0
                && *candidate_parent == parent.0
                && candidate_name == name
                && revision
                    == last_revision
                        .as_ref()
                        .map(|locator| RevisionId::from_bytes(*locator.revision_id()))
        }
    }
}

fn entry_matches_export(
    candidate: &TreeEntry,
    entry: RepositoryEntryId,
    revision: RevisionId,
) -> bool {
    matches!(
        candidate,
        TreeEntry::File { id, locator, .. }
            if *id == entry.0 && locator.revision_id() == revision.as_bytes()
    )
}

#[cfg(test)]
mod binding_scale_tests {
    use notecrypt_format::{DecodeLimits, TreeEntry};

    use super::{RepositoryEntryId, RepositoryEntryKind, entry_matches_binding};

    #[test]
    fn targeted_binding_scales_to_one_hundred_thousand_entries_without_result_materialization() {
        const COUNT: usize = 100_000;
        let root = [0x41; 16];
        let mut entries = Vec::new();
        entries.try_reserve_exact(COUNT).unwrap();
        for index in 0..COUNT {
            entries.push(
                TreeEntry::directory(
                    (index as u128).to_be_bytes(),
                    root,
                    "bounded",
                    &DecodeLimits::PHASE_1,
                )
                .unwrap(),
            );
        }
        let target = RepositoryEntryId::from_bytes(((COUNT - 1) as u128).to_be_bytes());

        assert!(entries.iter().any(|candidate| entry_matches_binding(
            candidate,
            target,
            RepositoryEntryId::from_bytes(root),
            "bounded",
            RepositoryEntryKind::Directory,
            None,
        )));
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::cell::RefCell;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use notecrypt_crypto::{CryptoError, OsRandom, RecoveryPassphrase, SecureRandom};

    use super::{
        PublicationGuard, RepositorySnapshot, StoreError, UnlockedVaultLease, VaultId, VaultRepair,
        VaultRepairAction, VaultStore,
    };

    thread_local! {
        static BEFORE_INITIAL_AVAILABILITY: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static BEFORE_COMPROMISE_ACTIVATION: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    type SendHook = Box<dyn FnOnce() + Send + 'static>;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum InitializationEntropyStage {
        VaultIdentity,
        RecoverySlotIdentity,
        SnapshotIdentity,
        ObjectIdentity,
        Nonce,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum InitializationKdfFault {
        CancelBeforeStart,
        CancelAfterComputation,
        PanicBeforeStart,
        PanicAfterComputation,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum InitializationKdfFaultPoint {
        BeforeStart,
        AfterComputation,
    }

    fn initialization_entropy_failure() -> &'static Mutex<Option<InitializationEntropyStage>> {
        static STAGE: OnceLock<Mutex<Option<InitializationEntropyStage>>> = OnceLock::new();
        STAGE.get_or_init(|| Mutex::new(None))
    }

    fn initialization_entropy_panic() -> &'static Mutex<Option<InitializationEntropyStage>> {
        static STAGE: OnceLock<Mutex<Option<InitializationEntropyStage>>> = OnceLock::new();
        STAGE.get_or_init(|| Mutex::new(None))
    }

    fn initialization_kdf_fault() -> &'static Mutex<Option<InitializationKdfFault>> {
        static FAULT: OnceLock<Mutex<Option<InitializationKdfFault>>> = OnceLock::new();
        FAULT.get_or_init(|| Mutex::new(None))
    }

    fn after_initial_availability() -> &'static Mutex<Option<SendHook>> {
        static HOOK: OnceLock<Mutex<Option<SendHook>>> = OnceLock::new();
        HOOK.get_or_init(|| Mutex::new(None))
    }

    fn before_initial_availability_send() -> &'static Mutex<Option<SendHook>> {
        static HOOK: OnceLock<Mutex<Option<SendHook>>> = OnceLock::new();
        HOOK.get_or_init(|| Mutex::new(None))
    }

    fn after_recovery_keys() -> &'static Mutex<Option<(VaultId, SendHook)>> {
        static HOOK: OnceLock<Mutex<Option<(VaultId, SendHook)>>> = OnceLock::new();
        HOOK.get_or_init(|| Mutex::new(None))
    }

    fn before_recovery_unlock() -> &'static Mutex<Option<(VaultId, SendHook)>> {
        static HOOK: OnceLock<Mutex<Option<(VaultId, SendHook)>>> = OnceLock::new();
        HOOK.get_or_init(|| Mutex::new(None))
    }

    fn authenticated_read_fault() -> &'static Mutex<Option<(VaultId, AuthenticatedReadFault)>> {
        static FAULT: OnceLock<Mutex<Option<(VaultId, AuthenticatedReadFault)>>> = OnceLock::new();
        FAULT.get_or_init(|| Mutex::new(None))
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AuthenticatedReadFault {
        ViewAllocation,
        StatusAllocation,
    }

    pub fn install_before_initial_availability_hook(hook: impl FnOnce() + 'static) {
        BEFORE_INITIAL_AVAILABILITY.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "initialization hook already installed"
            );
            *slot.borrow_mut() = Some(Box::new(hook));
        });
    }

    pub fn install_before_compromise_activation_hook(hook: impl FnOnce() + 'static) {
        BEFORE_COMPROMISE_ACTIVATION.with(|slot| {
            assert!(slot.borrow().is_none(), "activation hook already installed");
            *slot.borrow_mut() = Some(Box::new(hook));
        });
    }

    pub fn install_after_initial_availability_hook(hook: impl FnOnce() + Send + 'static) {
        let mut slot = after_initial_availability()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(slot.is_none(), "initialization hook already installed");
        *slot = Some(Box::new(hook));
    }

    pub fn install_before_initial_availability_send_hook(hook: impl FnOnce() + Send + 'static) {
        let mut slot = before_initial_availability_send()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(slot.is_none(), "initialization hook already installed");
        *slot = Some(Box::new(hook));
    }

    pub fn install_after_recovery_keys_hook(vault: VaultId, hook: impl FnOnce() + Send + 'static) {
        let mut slot = after_recovery_keys()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(slot.is_none(), "recovery unlock hook already installed");
        *slot = Some((vault, Box::new(hook)));
    }

    pub fn install_before_recovery_unlock_hook(
        vault: VaultId,
        hook: impl FnOnce() + Send + 'static,
    ) {
        let mut slot = before_recovery_unlock()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(slot.is_none(), "recovery unlock hook already installed");
        *slot = Some((vault, Box::new(hook)));
    }

    pub fn fail_authenticated_read_at(vault: VaultId, fault: AuthenticatedReadFault) {
        let mut selected = authenticated_read_fault()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(
            selected.is_none(),
            "authenticated read fault already installed"
        );
        *selected = Some((vault, fault));
    }

    pub fn fail_initialization_entropy_at(stage: InitializationEntropyStage) {
        let mut selected = initialization_entropy_failure()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(selected.is_none(), "entropy failure already installed");
        *selected = Some(stage);
    }

    pub fn panic_initialization_entropy_at(stage: InitializationEntropyStage) {
        let mut selected = initialization_entropy_panic()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(selected.is_none(), "entropy panic already installed");
        *selected = Some(stage);
    }

    pub fn fail_initialization_kdf_at(fault: InitializationKdfFault) {
        let mut selected = initialization_kdf_fault()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(selected.is_none(), "KDF fault already installed");
        *selected = Some(fault);
    }

    pub(crate) fn check_initialization_kdf(
        point: InitializationKdfFaultPoint,
        cancel: &AtomicBool,
    ) {
        let mut selected = initialization_kdf_fault()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let matches = matches!(
            (*selected, point),
            (
                Some(InitializationKdfFault::CancelBeforeStart)
                    | Some(InitializationKdfFault::PanicBeforeStart),
                InitializationKdfFaultPoint::BeforeStart,
            ) | (
                Some(InitializationKdfFault::CancelAfterComputation)
                    | Some(InitializationKdfFault::PanicAfterComputation),
                InitializationKdfFaultPoint::AfterComputation,
            )
        );
        if !matches {
            return;
        }
        let fault = selected.take().expect("matching KDF fault is present");
        drop(selected);
        match fault {
            InitializationKdfFault::CancelBeforeStart
            | InitializationKdfFault::CancelAfterComputation => {
                cancel.store(true, Ordering::Release);
            }
            InitializationKdfFault::PanicBeforeStart
            | InitializationKdfFault::PanicAfterComputation => {
                panic!("injected KDF boundary panic");
            }
        }
    }

    pub(crate) fn check_initialization_entropy(
        stage: InitializationEntropyStage,
    ) -> Result<(), StoreError> {
        let mut selected = initialization_entropy_failure()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *selected == Some(stage) {
            *selected = None;
            return Err(StoreError::RandomSource);
        }
        drop(selected);
        let mut panic_stage = initialization_entropy_panic()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *panic_stage == Some(stage) {
            *panic_stage = None;
            drop(panic_stage);
            panic!("injected initialization entropy panic");
        }
        Ok(())
    }

    pub(crate) fn run_before_initial_availability_hook() {
        BEFORE_INITIAL_AVAILABILITY.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
    }

    pub(crate) fn run_before_compromise_activation_hook() {
        BEFORE_COMPROMISE_ACTIVATION.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
    }

    pub(crate) fn run_after_initial_availability_hook() {
        let hook = after_initial_availability()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn run_before_initial_availability_send_hook() {
        let hook = before_initial_availability_send()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn run_after_recovery_keys_hook(vault: VaultId) {
        let hook = {
            let mut slot = after_recovery_keys()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match slot.as_ref() {
                Some((target, _)) if *target == vault => slot.take().map(|(_, hook)| hook),
                _ => None,
            }
        };
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn run_before_recovery_unlock_hook(vault: VaultId) {
        let hook = {
            let mut slot = before_recovery_unlock()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match slot.as_ref() {
                Some((target, _)) if *target == vault => slot.take().map(|(_, hook)| hook),
                _ => None,
            }
        };
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn check_authenticated_read_fault(
        vault: VaultId,
        fault: AuthenticatedReadFault,
    ) -> Result<(), StoreError> {
        let mut selected = authenticated_read_fault()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *selected == Some((vault, fault)) {
            *selected = None;
            Err(StoreError::AllocationFailed)
        } else {
            Ok(())
        }
    }

    pub fn authorize_repair_cancel_during_graph(
        store: &Arc<VaultStore>,
        passphrase: RecoveryPassphrase,
        cancel: &AtomicBool,
    ) -> Result<VaultRepair, StoreError> {
        store.authorize_repair_observed(
            passphrase,
            cancel,
            Some(&|| cancel.store(true, Ordering::Release)),
        )
    }

    pub fn apply_repair_cancel_during_graph(
        repair: VaultRepair,
        action: VaultRepairAction,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        repair.apply_observed(
            action,
            cancel,
            Some(&|| cancel.store(true, Ordering::Release)),
        )
    }

    pub fn local_chunk_authentication_count(lease: &UnlockedVaultLease) -> u64 {
        lease.keys.local_chunk_authentication_count()
    }

    pub fn simulate_unavailable_change_metadata(lease: &UnlockedVaultLease) {
        lease.stamp_cache_policy.disable();
        if let Ok(mut verified) = lease.verified_chunks.lock() {
            verified.clear();
        }
    }

    #[derive(Clone, Copy)]
    pub enum ChunkRandomFailure {
        ObjectIdentity,
        DataKey,
        ContentNonce,
        WrappingNonce,
    }

    impl ChunkRandomFailure {
        const fn fill_index(self) -> usize {
            match self {
                Self::ObjectIdentity => 2,
                Self::DataKey => 3,
                Self::ContentNonce => 4,
                Self::WrappingNonce => 5,
            }
        }
    }

    pub fn commit_with_partial_random_failure(
        lease: &mut UnlockedVaultLease,
        name: &str,
        source: &mut dyn Read,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
        failure: ChunkRandomFailure,
    ) -> Result<RepositorySnapshot, StoreError> {
        let mut random = PartialFailureRandom {
            inner: OsRandom,
            calls: 0,
            failure,
        };
        lease.commit_streamed_revision_with_random(
            None,
            None,
            name,
            None,
            None,
            source,
            publication_guard,
            cancel,
            notecrypt_format::DecodeLimits::PHASE_1.max_chunks_per_file,
            &mut random,
        )
    }

    pub fn commit_with_maximum_chunks(
        lease: &mut UnlockedVaultLease,
        name: &str,
        source: &mut dyn Read,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &AtomicBool,
        maximum_chunks: u32,
    ) -> Result<RepositorySnapshot, StoreError> {
        lease.commit_streamed_revision_with_random(
            None,
            None,
            name,
            None,
            None,
            source,
            publication_guard,
            cancel,
            maximum_chunks,
            &mut OsRandom,
        )
    }

    struct PartialFailureRandom {
        inner: OsRandom,
        calls: usize,
        failure: ChunkRandomFailure,
    }

    impl SecureRandom for PartialFailureRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            self.calls = self.calls.checked_add(1).ok_or(CryptoError::RandomSource)?;
            let expected_lengths = [16, 32, 32, 24, 24];
            let expected_length = expected_lengths
                .get(self.calls - 1)
                .copied()
                .ok_or(CryptoError::RandomSource)?;
            if destination.len() != expected_length {
                return Err(CryptoError::RandomSource);
            }
            if self.calls == self.failure.fill_index() {
                let partial = destination.len() / 2;
                destination[..partial].fill(0x5a);
                return Err(CryptoError::RandomSource);
            }
            self.inner.fill(destination)
        }
    }
}
