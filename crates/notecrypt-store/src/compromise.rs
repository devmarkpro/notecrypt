use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use notecrypt_core::{FileId, ObjectId, RevisionId, VaultId};
use notecrypt_crypto::{OsRandom, RecoveryPassphrase, SecureRandom, ValidatedArgon2idParameters};
use notecrypt_platform_fs::{Directory, EntryKind, PhysicalComponent};
use zeroize::Zeroize;

use crate::StoreError;
use crate::layout::{component, encode_hex};
use crate::local::{
    RepositoryEntryId, RepositoryEntryKind, RepositoryListedEntry, RepositoryMutation,
    SourceHeadCommitment, UnlockedVaultLease, initialize_compromise_target,
};
use crate::repository::{UnlockedVault, VaultStore, open_root, reject_related_roots};
use crate::transaction::PublicationGuard;

const COPY_PAGE_BYTES: usize = 64 * 1024;
const PIPE_PAGES: usize = 2;
const MAX_OBJECTS: usize = 10_000_000;
const MAX_OBJECT_SHARDS: usize = 256;
const MAX_LOCAL_ENTRIES: usize = 1_024;
const MAX_TRANSACTION_ENTRIES: usize = MAX_OBJECTS + 1;

mod sealed {
    pub trait CompromiseRekeySource {}
    pub trait PendingVaultTarget {}
}

/// One authenticated logical entry issued by a compromise-rekey source.
///
/// Its identity and source binding stay private so callers cannot inject an
/// old file, revision, object, parent, or history reference into a target.
pub struct AuthenticatedLogicalEntry {
    source_binding: [u8; 32],
    sequence: u64,
    total_entries: u64,
    source_root: RepositoryEntryId,
    source_id: RepositoryEntryId,
    source_parent: RepositoryEntryId,
    kind: AuthenticatedLogicalKind,
    name: String,
}

#[derive(Clone, Copy)]
enum AuthenticatedLogicalKind {
    Root,
    File { revision: RevisionId },
    Directory,
}

impl Drop for AuthenticatedLogicalEntry {
    fn drop(&mut self) {
        self.name.zeroize();
        self.source_binding.zeroize();
    }
}

pub trait CompromiseRekeySource: Send + sealed::CompromiseRekeySource {
    fn next_entry(&mut self) -> Result<Option<AuthenticatedLogicalEntry>, StoreError>;

    fn stream_plaintext(
        &mut self,
        entry: AuthenticatedLogicalEntry,
        output: &mut dyn Write,
        cancel: &AtomicBool,
    ) -> Result<u64, StoreError>;
}

pub trait PendingVaultTarget: Send + sealed::PendingVaultTarget {
    fn stage_entry(
        &mut self,
        source: &mut dyn CompromiseRekeySource,
        entry: AuthenticatedLogicalEntry,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError>;

    fn verify_complete(&mut self, cancel: &AtomicBool) -> Result<(), StoreError>;

    fn activate(self: Box<Self>, cancel: &AtomicBool) -> Result<ActivatedVaultTarget, StoreError>;

    fn abort(self: Box<Self>) -> Result<(), StoreError>;
}

pub struct ActivatedVaultTarget {
    vault: VaultId,
}

impl ActivatedVaultTarget {
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault
    }
}

pub(crate) struct RepositoryCompromiseSource {
    lease: UnlockedVaultLease,
    source_head: SourceHeadCommitment,
    source_binding: [u8; 32],
    entries: VecDeque<AuthenticatedLogicalEntry>,
}

impl RepositoryCompromiseSource {
    pub(crate) fn acquire(mut lease: UnlockedVaultLease) -> Result<Self, StoreError> {
        let source_binding = random_32(&mut OsRandom)?;
        let source_head = lease.capture_current_head_commitment()?;
        let source_root = lease.root_entry_id()?;
        let listed = order_live_entries(source_root, lease.list_entries()?)?;
        lease.validate_current_head_commitment(&source_head)?;
        let total_entries = u64::try_from(listed.len())
            .map_err(|_| StoreError::LimitExceeded)?
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?;
        let mut entries = VecDeque::new();
        entries
            .try_reserve_exact(listed.len().saturating_add(1))
            .map_err(|_| StoreError::LimitExceeded)?;
        entries.push_back(AuthenticatedLogicalEntry {
            source_binding,
            sequence: 0,
            total_entries,
            source_root,
            source_id: source_root,
            source_parent: source_root,
            kind: AuthenticatedLogicalKind::Root,
            name: String::new(),
        });
        for (index, entry) in listed.into_iter().enumerate() {
            let kind = match entry.kind() {
                RepositoryEntryKind::File => AuthenticatedLogicalKind::File {
                    revision: entry
                        .revision_id()
                        .ok_or(StoreError::AuthenticationFailed)?,
                },
                RepositoryEntryKind::Directory => AuthenticatedLogicalKind::Directory,
                RepositoryEntryKind::Tombstone => return Err(StoreError::AuthenticationFailed),
            };
            entries.push_back(AuthenticatedLogicalEntry {
                source_binding,
                sequence: u64::try_from(index)
                    .map_err(|_| StoreError::LimitExceeded)?
                    .checked_add(1)
                    .ok_or(StoreError::LimitExceeded)?,
                total_entries,
                source_root,
                source_id: entry.id(),
                source_parent: entry.parent_id(),
                kind,
                name: copy_string(entry.name())?,
            });
        }
        Ok(Self {
            lease,
            source_head,
            source_binding,
            entries,
        })
    }
}

impl CompromiseRekeySource for RepositoryCompromiseSource {
    fn next_entry(&mut self) -> Result<Option<AuthenticatedLogicalEntry>, StoreError> {
        self.lease
            .validate_current_head_commitment(&self.source_head)?;
        Ok(self.entries.pop_front())
    }

    fn stream_plaintext(
        &mut self,
        entry: AuthenticatedLogicalEntry,
        output: &mut dyn Write,
        cancel: &AtomicBool,
    ) -> Result<u64, StoreError> {
        if entry.source_binding != self.source_binding {
            return Err(StoreError::InvalidCapability);
        }
        self.lease
            .validate_current_head_commitment(&self.source_head)?;
        let result = match entry.kind {
            AuthenticatedLogicalKind::File { revision } => {
                #[cfg(feature = "test-support")]
                let output = &mut FirstPlaintextWriteHook {
                    inner: output,
                    vault: self.lease.vault_id(),
                    fired: false,
                } as &mut dyn Write;
                self.lease.export_exact(
                    FileId::from_bytes(*entry.source_id.as_bytes()),
                    revision,
                    output,
                    cancel,
                )
            }
            AuthenticatedLogicalKind::Root | AuthenticatedLogicalKind::Directory => {
                if cancel.load(Ordering::Acquire) {
                    return Err(StoreError::Cancelled);
                }
                Ok(0)
            }
        };
        self.lease
            .validate_current_head_commitment(&self.source_head)?;
        result
    }
}

impl sealed::CompromiseRekeySource for RepositoryCompromiseSource {}

#[cfg(feature = "test-support")]
struct FirstPlaintextWriteHook<'a> {
    inner: &'a mut dyn Write,
    vault: VaultId,
    fired: bool,
}

#[cfg(feature = "test-support")]
impl Write for FirstPlaintextWriteHook<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        if written != 0 && !self.fired {
            self.fired = true;
            test_support::run_after_first_plaintext_write_hook(self.vault);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::sync::Mutex;

    use notecrypt_core::VaultId;

    type Hook = Box<dyn FnOnce() + Send>;

    static AFTER_FIRST_PLAINTEXT_WRITE: Mutex<Vec<(VaultId, Hook)>> = Mutex::new(Vec::new());

    pub fn install_after_first_plaintext_write_hook(
        vault: VaultId,
        hook: impl FnOnce() + Send + 'static,
    ) {
        let mut hooks = AFTER_FIRST_PLAINTEXT_WRITE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            hooks.iter().all(|(installed, _)| *installed != vault),
            "plaintext-write hook was already installed for this vault"
        );
        hooks.push((vault, Box::new(hook)));
    }

    pub(super) fn run_after_first_plaintext_write_hook(vault: VaultId) {
        let hook = {
            let mut hooks = AFTER_FIRST_PLAINTEXT_WRITE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks
                .iter()
                .position(|(installed, _)| *installed == vault)
                .map(|index| hooks.swap_remove(index).1)
        };
        if let Some(hook) = hook {
            hook();
        }
    }
}

fn order_live_entries(
    source_root: RepositoryEntryId,
    listed: Vec<RepositoryListedEntry>,
) -> Result<Vec<RepositoryListedEntry>, StoreError> {
    let mut children: HashMap<RepositoryEntryId, VecDeque<RepositoryListedEntry>> = HashMap::new();
    children
        .try_reserve(listed.len())
        .map_err(|_| StoreError::LimitExceeded)?;
    let mut seen = HashSet::new();
    seen.try_reserve(listed.len().saturating_add(1))
        .map_err(|_| StoreError::LimitExceeded)?;
    seen.insert(source_root);
    let mut live_count = 0_usize;
    for entry in listed {
        if entry.kind() == RepositoryEntryKind::Tombstone {
            continue;
        }
        if !seen.insert(entry.id()) {
            return Err(StoreError::AuthenticationFailed);
        }
        live_count = live_count.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        children
            .entry(entry.parent_id())
            .or_default()
            .push_back(entry);
    }

    let mut parents = VecDeque::from([source_root]);
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(live_count)
        .map_err(|_| StoreError::LimitExceeded)?;
    while let Some(parent) = parents.pop_front() {
        let Some(mut direct_children) = children.remove(&parent) else {
            continue;
        };
        while let Some(entry) = direct_children.pop_front() {
            if entry.kind() == RepositoryEntryKind::Directory {
                parents.push_back(entry.id());
            }
            ordered.push(entry);
        }
    }
    if ordered.len() != live_count || !children.is_empty() {
        return Err(StoreError::AuthenticationFailed);
    }
    Ok(ordered)
}

struct StagedTargetEntry {
    id: RepositoryEntryId,
    parent: RepositoryEntryId,
    name: String,
    kind: RepositoryEntryKind,
    revision: Option<RevisionId>,
}

struct VerificationEntry {
    id: RepositoryEntryId,
    parent: RepositoryEntryId,
    name: String,
    kind: RepositoryEntryKind,
    revision: Option<RevisionId>,
}

impl VerificationEntry {
    fn from_listed(entry: &RepositoryListedEntry) -> Result<Self, StoreError> {
        Ok(Self {
            id: entry.id(),
            parent: entry.parent_id(),
            name: copy_string(entry.name())?,
            kind: entry.kind(),
            revision: entry.revision_id(),
        })
    }
}

impl Drop for VerificationEntry {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

impl Drop for StagedTargetEntry {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

fn verify_staged_entries(
    actual: &[VerificationEntry],
    expected: &[StagedTargetEntry],
) -> Result<usize, StoreError> {
    if actual.len() != expected.len() {
        return Err(StoreError::AuthenticationFailed);
    }
    let mut by_id = HashMap::new();
    by_id
        .try_reserve(actual.len())
        .map_err(|_| StoreError::LimitExceeded)?;
    let mut operations = 0_usize;
    for entry in actual {
        operations = operations.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        if by_id.insert(entry.id, entry).is_some() {
            return Err(StoreError::AuthenticationFailed);
        }
    }
    for staged in expected {
        operations = operations.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        let entry = by_id
            .remove(&staged.id)
            .ok_or(StoreError::AuthenticationFailed)?;
        if entry.parent != staged.parent
            || entry.name != staged.name
            || entry.kind != staged.kind
            || entry.revision != staged.revision
        {
            return Err(StoreError::AuthenticationFailed);
        }
    }
    if !by_id.is_empty() {
        return Err(StoreError::AuthenticationFailed);
    }
    Ok(operations)
}

pub(crate) struct RepositoryPendingVaultTarget {
    store: Option<Arc<VaultStore>>,
    unlocked: Option<UnlockedVault>,
    repository_root: Directory,
    local_root: Directory,
    vault: VaultId,
    source_objects: HashSet<ObjectId>,
    source_binding: Option<[u8; 32]>,
    expected_entries: Option<u64>,
    next_sequence: u64,
    staged_entries: Vec<StagedTargetEntry>,
    source_entry_ids: HashSet<RepositoryEntryId>,
    source_revision_ids: HashSet<RevisionId>,
    target_entry_ids: HashSet<RepositoryEntryId>,
    target_revision_ids: HashSet<RevisionId>,
    entry_map: HashMap<RepositoryEntryId, RepositoryEntryId>,
    poisoned: bool,
    verified: bool,
    cleanup_required: bool,
}

impl RepositoryPendingVaultTarget {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        source: &VaultStore,
        repository_path: &Path,
        local_path: &Path,
        passphrase: RecoveryPassphrase,
        parameters: ValidatedArgon2idParameters,
        device_label: &str,
        cancel: &AtomicBool,
    ) -> Result<Self, StoreError> {
        let repository_root = open_root(repository_path)?;
        let local_root = open_root(local_path)?;
        reject_related_roots(&repository_root, &local_root)?;
        reject_source_target_alias(source, &repository_root, &local_root)?;
        require_empty_root(&repository_root)?;
        let source_objects = enumerate_objects(&source.layout.objects)?;
        let initialized = initialize_compromise_target(
            repository_path,
            local_path,
            passphrase,
            parameters,
            device_label,
            cancel,
            source.layout.vault,
        );
        let store = match initialized {
            Ok(initialized) => initialized,
            Err(primary) => {
                cleanup_repository(&repository_root)?;
                return Err(primary);
            }
        };
        let (store, unlocked) = store;
        let vault = store.vault_id();
        if !repository_root.same_identity(&store.layout.repository)?
            || !local_root.is_same_or_ancestor_of(&store.layout.trusted)
        {
            drop(store);
            cleanup_owned_target(&repository_root, &local_root, vault)?;
            return Err(StoreError::FilesystemObjectRejected);
        }
        Ok(Self {
            store: Some(store),
            unlocked: Some(unlocked),
            repository_root,
            local_root,
            vault,
            source_objects,
            source_binding: None,
            expected_entries: None,
            next_sequence: 0,
            staged_entries: Vec::new(),
            source_entry_ids: HashSet::new(),
            source_revision_ids: HashSet::new(),
            target_entry_ids: HashSet::new(),
            target_revision_ids: HashSet::new(),
            entry_map: HashMap::new(),
            poisoned: false,
            verified: false,
            cleanup_required: true,
        })
    }

    fn stage_entry_inner(
        &mut self,
        source: &mut dyn CompromiseRekeySource,
        entry: AuthenticatedLogicalEntry,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        self.require_staging(cancel)?;
        self.bind_entry(&entry)?;
        match entry.kind {
            AuthenticatedLogicalKind::Root => self.stage_root(source, entry, cancel),
            AuthenticatedLogicalKind::File { revision } => {
                self.stage_file(source, entry, revision, cancel)
            }
            AuthenticatedLogicalKind::Directory => self.stage_directory(source, entry, cancel),
        }
    }

    fn stage_root(
        &mut self,
        source: &mut dyn CompromiseRekeySource,
        entry: AuthenticatedLogicalEntry,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        if source.stream_plaintext(entry, &mut io::sink(), cancel)? != 0 {
            return Err(StoreError::AuthenticationFailed);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?;
        Ok(())
    }

    fn stage_directory(
        &mut self,
        source: &mut dyn CompromiseRekeySource,
        entry: AuthenticatedLogicalEntry,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        let name = copy_string(&entry.name)?;
        let source_id = entry.source_id;
        let target_parent = self.target_parent(&entry)?;
        if source.stream_plaintext(entry, &mut io::sink(), cancel)? != 0 {
            return Err(StoreError::AuthenticationFailed);
        }
        let mut guard = CancelPublicationGuard { cancel };
        let created = self.with_target_lease(|lease| {
            let snapshot = lease.current_snapshot_id()?;
            lease.apply(
                RepositoryMutation::create_directory(snapshot, target_parent, &name),
                &mut guard,
                cancel,
            )
        })?;
        self.finish_entry(
            source_id,
            created.entry_id(),
            target_parent,
            name,
            RepositoryEntryKind::Directory,
            None,
        )
    }

    fn stage_file(
        &mut self,
        source: &mut dyn CompromiseRekeySource,
        entry: AuthenticatedLogicalEntry,
        old_revision: RevisionId,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        let name = copy_string(&entry.name)?;
        let source_id = entry.source_id;
        let target_parent = self.target_parent(&entry)?;
        let target_root = *self
            .entry_map
            .get(&entry.source_root)
            .ok_or(StoreError::InvalidCapability)?;
        if self.target_revision_ids.contains(&old_revision) {
            return Err(StoreError::IdentityCollision);
        }
        self.source_revision_ids
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        let commit_name = if target_parent == target_root {
            copy_string(&name)?
        } else {
            self.unique_staging_name(target_root)?
        };

        let source_completed = AtomicBool::new(false);
        let (sender, receiver) = sync_channel(PIPE_PAGES);
        let (target_result, source_result) = std::thread::scope(|scope| {
            let producer = scope.spawn(|| {
                let mut writer = BoundedPlaintextWriter { sender, cancel };
                let result = source.stream_plaintext(entry, &mut writer, cancel);
                if result.is_ok() {
                    source_completed.store(true, Ordering::Release);
                }
                result
            });
            let mut reader = BoundedPlaintextReader {
                receiver,
                current: None,
                offset: 0,
            };
            let mut guard = SourceCompletionGuard {
                source_completed: &source_completed,
                cancel,
            };
            let target_result = self.with_target_lease(|lease| {
                lease.commit_streamed_revision_internal(
                    None,
                    &commit_name,
                    &mut reader,
                    &mut guard,
                    cancel,
                )
            });
            drop(reader);
            let source_result = producer
                .join()
                .map_err(|_| StoreError::InvalidCapability)
                .and_then(|result| result);
            (target_result, source_result)
        });
        let snapshot = match (target_result, source_result) {
            (Ok(snapshot), Ok(_)) => snapshot,
            (Err(target_error), Ok(_)) => return Err(target_error),
            (Ok(_), Err(source_error)) | (Err(_), Err(source_error)) => {
                return Err(source_error);
            }
        };
        let target_id = RepositoryEntryId::from(snapshot.file_id());
        if snapshot.revision_id() == old_revision
            || self.source_entry_ids.contains(&target_id)
            || self.source_revision_ids.contains(&snapshot.revision_id())
        {
            return Err(StoreError::IdentityCollision);
        }
        if target_parent != target_root {
            let mut guard = CancelPublicationGuard { cancel };
            self.with_target_lease(|lease| {
                lease.apply(
                    RepositoryMutation::rename(
                        snapshot.snapshot_id(),
                        target_id,
                        target_root,
                        &commit_name,
                        target_parent,
                        &name,
                    ),
                    &mut guard,
                    cancel,
                )
            })?;
        }
        self.source_revision_ids.insert(old_revision);
        self.finish_entry(
            source_id,
            target_id,
            target_parent,
            name,
            RepositoryEntryKind::File,
            Some(snapshot.revision_id()),
        )
    }

    fn bind_entry(&mut self, entry: &AuthenticatedLogicalEntry) -> Result<(), StoreError> {
        match (self.source_binding, self.expected_entries) {
            (None, None) => {
                self.source_binding = Some(entry.source_binding);
                self.expected_entries = Some(entry.total_entries);
            }
            (Some(binding), Some(total))
                if binding == entry.source_binding && total == entry.total_entries => {}
            _ => return Err(StoreError::InvalidCapability),
        }
        if entry.sequence != self.next_sequence || entry.sequence >= entry.total_entries {
            return Err(StoreError::InvalidCapability);
        }
        if matches!(entry.kind, AuthenticatedLogicalKind::Root) {
            if !self.entry_map.is_empty()
                || entry.sequence != 0
                || entry.source_id != entry.source_root
                || entry.source_parent != entry.source_root
                || !entry.name.is_empty()
            {
                return Err(StoreError::InvalidCapability);
            }
            let target_root = self.with_target_lease(UnlockedVaultLease::root_entry_id)?;
            if target_root == entry.source_root {
                return Err(StoreError::IdentityCollision);
            }
            self.source_entry_ids
                .try_reserve(1)
                .map_err(|_| StoreError::LimitExceeded)?;
            self.target_entry_ids
                .try_reserve(1)
                .map_err(|_| StoreError::LimitExceeded)?;
            self.entry_map
                .try_reserve(1)
                .map_err(|_| StoreError::LimitExceeded)?;
            self.source_entry_ids.insert(entry.source_root);
            self.target_entry_ids.insert(target_root);
            self.entry_map.insert(entry.source_root, target_root);
            return Ok(());
        }
        if self.entry_map.is_empty()
            || !self.entry_map.contains_key(&entry.source_root)
            || entry.source_id == entry.source_root
            || !self.entry_map.contains_key(&entry.source_parent)
            || self.source_entry_ids.contains(&entry.source_id)
        {
            return Err(StoreError::InvalidCapability);
        }
        if self.target_entry_ids.contains(&entry.source_id) {
            return Err(StoreError::IdentityCollision);
        }
        self.source_entry_ids
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.source_entry_ids.insert(entry.source_id);
        Ok(())
    }

    fn target_parent(
        &self,
        entry: &AuthenticatedLogicalEntry,
    ) -> Result<RepositoryEntryId, StoreError> {
        self.entry_map
            .get(&entry.source_parent)
            .copied()
            .ok_or(StoreError::InvalidCapability)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_entry(
        &mut self,
        source_id: RepositoryEntryId,
        target_id: RepositoryEntryId,
        target_parent: RepositoryEntryId,
        name: String,
        kind: RepositoryEntryKind,
        revision: Option<RevisionId>,
    ) -> Result<(), StoreError> {
        if source_id == target_id
            || self.source_entry_ids.contains(&target_id)
            || self.target_entry_ids.contains(&target_id)
            || revision.is_some_and(|id| self.source_revision_ids.contains(&id))
        {
            return Err(StoreError::IdentityCollision);
        }
        self.target_entry_ids
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.target_revision_ids
            .try_reserve(usize::from(revision.is_some()))
            .map_err(|_| StoreError::LimitExceeded)?;
        self.entry_map
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.staged_entries
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.target_entry_ids.insert(target_id);
        if let Some(revision) = revision {
            self.target_revision_ids.insert(revision);
        }
        self.entry_map.insert(source_id, target_id);
        self.staged_entries.push(StagedTargetEntry {
            id: target_id,
            parent: target_parent,
            name,
            kind,
            revision,
        });
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?;
        Ok(())
    }

    fn unique_staging_name(&self, target_root: RepositoryEntryId) -> Result<String, StoreError> {
        let occupied = self.with_target_lease(|lease| lease.list_entries())?;
        for _ in 0..16 {
            let mut random = [0_u8; 16];
            OsRandom.fill(&mut random).map_err(map_random)?;
            let candidate = format!(".notecrypt-rekey-{}", encode_hex(&random));
            if !occupied
                .iter()
                .any(|entry| entry.parent_id() == target_root && entry.name() == candidate)
            {
                return Ok(candidate);
            }
        }
        Err(StoreError::IdentityCollision)
    }

    fn require_staging(&self, cancel: &AtomicBool) -> Result<(), StoreError> {
        if self.poisoned || self.verified {
            return Err(StoreError::InvalidCapability);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(StoreError::Cancelled);
        }
        Ok(())
    }

    fn with_target_lease<R>(
        &self,
        operation: impl FnOnce(&mut UnlockedVaultLease) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let unlocked = self
            .unlocked
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let mut lease = unlocked.acquire_lease()?;
        let result = operation(&mut lease);
        drop(lease);
        result
    }

    fn verify_complete_inner(&mut self, cancel: &AtomicBool) -> Result<(), StoreError> {
        self.require_staging(cancel)?;
        if self.expected_entries != Some(self.next_sequence) {
            return Err(StoreError::InvalidCapability);
        }
        let mut guard = CancelPublicationGuard { cancel };
        let reachable = self
            .with_target_lease(|lease| lease.commit_parentless_current_state(&mut guard, cancel))?;
        prune_unreachable_objects(
            &self
                .store
                .as_ref()
                .ok_or(StoreError::InvalidCapability)?
                .layout
                .objects,
            &reachable,
        )?;
        let target_objects = enumerate_objects(
            &self
                .store
                .as_ref()
                .ok_or(StoreError::InvalidCapability)?
                .layout
                .objects,
        )?;
        let mut reachable_set = HashSet::new();
        reachable_set
            .try_reserve(reachable.len())
            .map_err(|_| StoreError::LimitExceeded)?;
        reachable_set.extend(reachable);
        if target_objects != reachable_set || !target_objects.is_disjoint(&self.source_objects) {
            return Err(StoreError::AuthenticationFailed);
        }
        if !self.source_entry_ids.is_disjoint(&self.target_entry_ids)
            || !self
                .source_revision_ids
                .is_disjoint(&self.target_revision_ids)
        {
            return Err(StoreError::IdentityCollision);
        }
        let listed = self.with_target_lease(UnlockedVaultLease::list_entries)?;
        let mut actual = Vec::new();
        actual
            .try_reserve_exact(listed.len())
            .map_err(|_| StoreError::LimitExceeded)?;
        for entry in &listed {
            actual.push(VerificationEntry::from_listed(entry)?);
        }
        verify_staged_entries(&actual, &self.staged_entries)?;
        self.verified = true;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), StoreError> {
        if !self.cleanup_required {
            return Ok(());
        }
        let close_error = self
            .unlocked
            .take()
            .and_then(|unlocked| unlocked.close().err());
        drop(self.store.take());
        let cleanup = cleanup_owned_target(&self.repository_root, &self.local_root, self.vault);
        if cleanup.is_ok() {
            self.cleanup_required = false;
        }
        match (close_error, cleanup) {
            (None, Ok(())) => Ok(()),
            (Some(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    fn fail_before_activation(&mut self, primary: StoreError) -> StoreError {
        match self.cleanup() {
            Ok(()) => primary,
            Err(cleanup) => StoreError::CleanupAfterFailure {
                primary: Box::new(primary),
                cleanup: std::io::Error::other(cleanup.to_string()),
            },
        }
    }
}

impl PendingVaultTarget for RepositoryPendingVaultTarget {
    fn stage_entry(
        &mut self,
        source: &mut dyn CompromiseRekeySource,
        entry: AuthenticatedLogicalEntry,
        cancel: &AtomicBool,
    ) -> Result<(), StoreError> {
        let result = self.stage_entry_inner(source, entry, cancel);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn verify_complete(&mut self, cancel: &AtomicBool) -> Result<(), StoreError> {
        let result = self.verify_complete_inner(cancel);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn activate(
        mut self: Box<Self>,
        cancel: &AtomicBool,
    ) -> Result<ActivatedVaultTarget, StoreError> {
        if !self.verified || self.poisoned {
            return Err(self.fail_before_activation(StoreError::InvalidCapability));
        }
        if cancel.load(Ordering::Acquire) {
            return Err(self.fail_before_activation(StoreError::Cancelled));
        }
        let cleanup_required = &mut self.cleanup_required;
        let unlocked = self
            .unlocked
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let begin_result = unlocked.begin_compromise_activation(cancel, || {
            *cleanup_required = false;
        });
        if *cleanup_required {
            return match begin_result {
                Ok(()) => Err(self.fail_before_activation(StoreError::InvalidCapability)),
                Err(primary) => Err(self.fail_before_activation(primary)),
            };
        }
        // The Activating replacement may already be visible even when its
        // final directory sync fails. From the commit attempt onward recovery
        // owns completion, so pending cleanup must never delete this target.
        begin_result.map_err(|_| StoreError::DurabilityPending)?;
        unlocked
            .complete_compromise_activation_record()
            .and_then(|()| unlocked.finalize_compromise_activation())
            .map_err(|_| StoreError::DurabilityPending)?;
        if let Some(unlocked) = self.unlocked.take() {
            unlocked
                .close()
                .map_err(|_| StoreError::DurabilityPending)?;
        }
        Ok(ActivatedVaultTarget { vault: self.vault })
    }

    fn abort(mut self: Box<Self>) -> Result<(), StoreError> {
        self.cleanup()
    }
}

impl sealed::PendingVaultTarget for RepositoryPendingVaultTarget {}

impl Drop for RepositoryPendingVaultTarget {
    fn drop(&mut self) {
        let _ = self.cleanup();
        if let Some(binding) = &mut self.source_binding {
            binding.zeroize();
        }
    }
}

struct PlaintextPage(Vec<u8>);

impl Drop for PlaintextPage {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct BoundedPlaintextWriter<'a> {
    sender: SyncSender<PlaintextPage>,
    cancel: &'a AtomicBool,
}

impl Write for BoundedPlaintextWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "copy cancelled"));
        }
        for page in bytes.chunks(COPY_PAGE_BYTES) {
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(page.len())
                .map_err(|_| io::Error::other("plaintext page allocation failed"))?;
            owned.extend_from_slice(page);
            self.sender.send(PlaintextPage(owned)).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "plaintext receiver closed")
            })?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedPlaintextReader {
    receiver: Receiver<PlaintextPage>,
    current: Option<PlaintextPage>,
    offset: usize,
}

impl Read for BoundedPlaintextReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.current.is_none() {
            self.current = self.receiver.recv().ok();
            self.offset = 0;
        }
        let Some(current) = self.current.as_ref() else {
            return Ok(0);
        };
        let remaining = &current.0[self.offset..];
        let copied = remaining.len().min(output.len());
        output[..copied].copy_from_slice(&remaining[..copied]);
        self.offset += copied;
        if self.offset == current.0.len() {
            self.current = None;
            self.offset = 0;
        }
        Ok(copied)
    }
}

struct SourceCompletionGuard<'a> {
    source_completed: &'a AtomicBool,
    cancel: &'a AtomicBool,
}

impl PublicationGuard for SourceCompletionGuard<'_> {
    fn validate(&mut self) -> Result<(), StoreError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(StoreError::Cancelled);
        }
        if !self.source_completed.load(Ordering::Acquire) {
            return Err(StoreError::InvalidCapability);
        }
        Ok(())
    }
}

struct CancelPublicationGuard<'a> {
    cancel: &'a AtomicBool,
}

impl PublicationGuard for CancelPublicationGuard<'_> {
    fn validate(&mut self) -> Result<(), StoreError> {
        if self.cancel.load(Ordering::Acquire) {
            Err(StoreError::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn reject_source_target_alias(
    source: &VaultStore,
    repository: &Directory,
    local: &Directory,
) -> Result<(), StoreError> {
    if roots_overlap(&source.layout.repository, repository)
        || roots_overlap(&source.layout.repository, local)
    {
        return Err(StoreError::FilesystemObjectRejected);
    }
    let source_local_directories = [
        &source.layout.objects,
        &source.layout.transactions,
        &source.layout.journal,
        &source.layout.trusted,
        &source.layout.trusted_remote,
        &source.layout.cleanup_registry,
        &source.layout.cleanup_staging,
        &source.layout.device_slots,
        &source.layout.quarantine,
    ];
    if source_local_directories
        .iter()
        .any(|source_directory| roots_overlap(source_directory, repository))
    {
        return Err(StoreError::FilesystemObjectRejected);
    }
    Ok(())
}

fn roots_overlap(first: &Directory, second: &Directory) -> bool {
    first.is_same_or_ancestor_of(second) || second.is_same_or_ancestor_of(first)
}

fn require_empty_root(root: &Directory) -> Result<(), StoreError> {
    if root.entry_names_bounded(1)?.is_empty() {
        Ok(())
    } else {
        Err(StoreError::FilesystemObjectRejected)
    }
}

fn random_32(random: &mut dyn SecureRandom) -> Result<[u8; 32], StoreError> {
    let mut bytes = [0_u8; 32];
    random.fill(&mut bytes).map_err(map_random)?;
    Ok(bytes)
}

fn copy_string(value: &str) -> Result<String, StoreError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| StoreError::LimitExceeded)?;
    output.push_str(value);
    Ok(output)
}

fn map_random(error: notecrypt_crypto::CryptoError) -> StoreError {
    if matches!(error, notecrypt_crypto::CryptoError::RandomSource) {
        StoreError::RandomSource
    } else {
        StoreError::AuthenticationFailed
    }
}

fn enumerate_objects(objects: &Directory) -> Result<HashSet<ObjectId>, StoreError> {
    enumerate_objects_bounded(objects, MAX_OBJECTS, MAX_OBJECT_SHARDS)
}

fn enumerate_objects_bounded(
    objects: &Directory,
    maximum_objects: usize,
    maximum_shards: usize,
) -> Result<HashSet<ObjectId>, StoreError> {
    let shards = objects.entry_names_bounded(maximum_shards.saturating_add(1))?;
    if shards.len() > maximum_shards {
        return Err(StoreError::LimitExceeded);
    }
    let mut output = HashSet::new();
    for shard_name in shards {
        require_lower_hex(shard_name.as_str(), 2)?;
        if objects.entry_kind(&shard_name)? != EntryKind::Directory {
            return Err(StoreError::FilesystemObjectRejected);
        }
        let shard = objects.open_dir_nofollow(&shard_name)?;
        let remaining = maximum_objects
            .checked_sub(output.len())
            .ok_or(StoreError::LimitExceeded)?;
        for object_name in shard.entry_names_bounded(remaining.saturating_add(1))? {
            if output.len() >= maximum_objects {
                return Err(StoreError::LimitExceeded);
            }
            require_lower_hex(object_name.as_str(), 62)?;
            if shard.entry_kind(&object_name)? != EntryKind::File {
                return Err(StoreError::FilesystemObjectRejected);
            }
            let encoded = format!("{}{}", shard_name.as_str(), object_name.as_str());
            output
                .try_reserve(1)
                .map_err(|_| StoreError::LimitExceeded)?;
            output.insert(ObjectId::from_bytes(decode_hex_32(&encoded)?));
        }
    }
    Ok(output)
}

fn prune_unreachable_objects(
    objects: &Directory,
    reachable: &[ObjectId],
) -> Result<(), StoreError> {
    prune_unreachable_objects_bounded(objects, reachable, MAX_OBJECTS, MAX_OBJECT_SHARDS)
}

fn prune_unreachable_objects_bounded(
    objects: &Directory,
    reachable: &[ObjectId],
    maximum_objects: usize,
    maximum_shards: usize,
) -> Result<(), StoreError> {
    if reachable.len() > maximum_objects {
        return Err(StoreError::LimitExceeded);
    }
    let mut reachable_set = HashSet::new();
    reachable_set
        .try_reserve(reachable.len())
        .map_err(|_| StoreError::LimitExceeded)?;
    reachable_set.extend(reachable.iter().copied());
    let inventory = enumerate_objects_bounded(objects, maximum_objects, maximum_shards)?;
    for id in inventory.difference(&reachable_set) {
        let encoded = encode_hex(id.as_bytes());
        let shard = objects.open_dir_nofollow(&component(&encoded[..2])?)?;
        shard.remove_file(&component(&encoded[2..])?)?;
    }
    let shards = objects.entry_names_bounded(maximum_shards.saturating_add(1))?;
    if shards.len() > maximum_shards {
        return Err(StoreError::LimitExceeded);
    }
    for shard_name in shards {
        require_lower_hex(shard_name.as_str(), 2)?;
        let shard = objects.open_dir_nofollow(&shard_name)?;
        if shard
            .entry_names_bounded(maximum_objects.saturating_add(1))?
            .is_empty()
        {
            drop(shard);
            objects.remove_empty_dir(&shard_name)?;
        }
    }
    objects.sync()?;
    Ok(())
}

fn require_lower_hex(value: &str, length: usize) -> Result<(), StoreError> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(StoreError::FilesystemObjectRejected)
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], StoreError> {
    require_lower_hex(value, 64)?;
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn decode_nibble(value: u8) -> Result<u8, StoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StoreError::FilesystemObjectRejected),
    }
}

pub(crate) fn cleanup_owned_target(
    repository: &Directory,
    local: &Directory,
    vault: VaultId,
) -> Result<(), StoreError> {
    let repository_cleanup = cleanup_repository(repository);
    let local_cleanup = cleanup_local(local, vault);
    match (repository_cleanup, local_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn cleanup_repository(repository: &Directory) -> Result<(), StoreError> {
    for name in repository.entry_names_bounded(5)? {
        match name.as_str() {
            ".notecrypt-vault" | ".notecrypt-pending" | "head" => {
                repository.remove_file(&name)?;
            }
            "objects" => cleanup_objects_root(repository, &name)?,
            ".notecrypt-txn" => cleanup_transaction_root(repository, &name)?,
            _ => return Err(StoreError::FilesystemObjectRejected),
        }
    }
    repository.sync()?;
    Ok(())
}

fn cleanup_objects_root(
    repository: &Directory,
    objects_name: &PhysicalComponent,
) -> Result<(), StoreError> {
    let objects = repository.open_dir_nofollow(objects_name)?;
    for shard_name in objects.entry_names_bounded(MAX_OBJECT_SHARDS + 1)? {
        require_lower_hex(shard_name.as_str(), 2)?;
        let shard = objects.open_dir_nofollow(&shard_name)?;
        for object_name in shard.entry_names_bounded(MAX_OBJECTS.saturating_add(1))? {
            require_lower_hex(object_name.as_str(), 62)?;
            shard.remove_file(&object_name)?;
        }
        drop(shard);
        objects.remove_empty_dir(&shard_name)?;
    }
    drop(objects);
    repository.remove_empty_dir(objects_name)?;
    Ok(())
}

fn cleanup_transaction_root(
    repository: &Directory,
    transaction_name: &PhysicalComponent,
) -> Result<(), StoreError> {
    let transactions = repository.open_dir_nofollow(transaction_name)?;
    for entry in transactions.entry_names_bounded(MAX_TRANSACTION_ENTRIES)? {
        match transactions.entry_kind(&entry)? {
            EntryKind::File => transactions.remove_file(&entry)?,
            EntryKind::Directory => {
                transactions.remove_private_file_tree(&entry, MAX_OBJECTS)?;
            }
        }
    }
    drop(transactions);
    repository.remove_empty_dir(transaction_name)?;
    Ok(())
}

fn cleanup_local(local: &Directory, vault: VaultId) -> Result<(), StoreError> {
    let vault_name = component(&encode_hex(vault.as_bytes()))?;
    let vault_directory = match local.open_dir_nofollow(&vault_name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::from(error)),
    };
    for name in vault_directory.entry_names_bounded(8)? {
        match name.as_str() {
            "journal"
            | "trusted"
            | "trusted-remote"
            | "cleanup-registry"
            | "cleanup-staging"
            | "device-slots"
            | "replication-quarantine" => {
                cleanup_private_local_directory(&vault_directory, &name)?;
            }
            _ => return Err(StoreError::FilesystemObjectRejected),
        }
    }
    drop(vault_directory);
    local.remove_empty_dir(&vault_name)?;
    Ok(())
}

fn cleanup_private_local_directory(
    vault: &Directory,
    name: &PhysicalComponent,
) -> Result<(), StoreError> {
    let directory = vault.open_dir_nofollow(name)?;
    directory.verify_private()?;
    for entry in directory.entry_names_bounded(MAX_LOCAL_ENTRIES)? {
        match directory.entry_kind(&entry)? {
            EntryKind::File => directory.remove_file(&entry)?,
            EntryKind::Directory => directory.remove_private_file_tree(&entry, MAX_OBJECTS)?,
        }
    }
    drop(directory);
    vault.remove_empty_dir(name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_id(index: usize) -> RepositoryEntryId {
        let mut bytes = [0_u8; 16];
        bytes[8..].copy_from_slice(&(index as u64).to_be_bytes());
        RepositoryEntryId::from(FileId::from_bytes(bytes))
    }

    fn inventory_fixture(count: usize) -> (Vec<VerificationEntry>, Vec<StagedTargetEntry>) {
        let parent = entry_id(usize::MAX);
        let mut actual = Vec::with_capacity(count);
        let mut expected = Vec::with_capacity(count);
        for index in 0..count {
            let id = entry_id(index);
            let name = format!("entry-{index}");
            actual.push(VerificationEntry {
                id,
                parent,
                name: name.clone(),
                kind: RepositoryEntryKind::Directory,
                revision: None,
            });
            expected.push(StagedTargetEntry {
                id,
                parent,
                name,
                kind: RepositoryEntryKind::Directory,
                revision: None,
            });
        }
        (actual, expected)
    }

    #[test]
    fn verification_operations_scale_linearly_from_one_to_ten_thousand_entries() {
        for count in [1_000_usize, 10_000] {
            let (actual, expected) = inventory_fixture(count);
            assert_eq!(
                verify_staged_entries(&actual, &expected).unwrap(),
                count * 2
            );
        }
    }

    #[test]
    fn pruning_keeps_multiple_reachable_objects_in_one_shard() {
        let root = tempfile::TempDir::new().unwrap();
        let root = root.path().canonicalize().unwrap();
        let objects = Directory::open_ambient(&root).unwrap();
        let shard = objects.create_dir(&component("aa").unwrap()).unwrap();
        let first = ObjectId::from_bytes([0xaa; 32]);
        let mut second_bytes = [0xaa; 32];
        second_bytes[31] = 0xbb;
        let second = ObjectId::from_bytes(second_bytes);
        for id in [first, second] {
            let encoded = encode_hex(id.as_bytes());
            shard
                .create_private_file_new(&component(&encoded[2..]).unwrap())
                .unwrap();
        }

        prune_unreachable_objects(&objects, &[first, second]).unwrap();

        assert_eq!(shard.entry_names_bounded(3).unwrap().len(), 2);
    }

    #[test]
    fn prune_inventory_enforces_one_budget_across_all_256_shards_before_deletion() {
        let root = tempfile::TempDir::new().unwrap();
        let root = root.path().canonicalize().unwrap();
        let objects = Directory::open_ambient(&root).unwrap();
        for shard_byte in 0_u8..=u8::MAX {
            let encoded_shard = format!("{shard_byte:02x}");
            let shard = objects
                .create_dir(&component(&encoded_shard).unwrap())
                .unwrap();
            let mut id = [0_u8; 32];
            id[0] = shard_byte;
            let encoded = encode_hex(&id);
            shard
                .create_private_file_new(&component(&encoded[2..]).unwrap())
                .unwrap();
        }

        assert!(matches!(
            prune_unreachable_objects_bounded(&objects, &[], 255, 256),
            Err(StoreError::LimitExceeded)
        ));

        let mut remaining = 0_usize;
        for shard_name in objects.entry_names_bounded(257).unwrap() {
            let shard = objects.open_dir_nofollow(&shard_name).unwrap();
            remaining += shard.entry_names_bounded(2).unwrap().len();
        }
        assert_eq!(remaining, 256);
    }
}
