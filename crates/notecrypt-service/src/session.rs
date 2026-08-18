use std::collections::HashMap;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use notecrypt_core::{EntryName, FileId, ObjectId, RevisionId, SnapshotId, VaultId};
use notecrypt_crypto::{Argon2idParameters, ValidatedArgon2idParameters};
use notecrypt_store::{
    CompromiseRekeySource, ReplicationLimits, StoreError, UnlockedVault, VaultStore,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{RecoverySecretInput, ServiceError, WorkspaceProvider};

/// Maximum warning boundaries retained for one session policy.
pub const MAX_WARNING_OFFSETS: usize = 16;
/// Maximum time granted to one explicitly armed durable final save.
pub const MAX_FINAL_SAVE_GRACE: Duration = Duration::from_secs(30);

/// Validated monotonic session lifetime policy.
pub struct SessionPolicy {
    inactivity_timeout: Duration,
    absolute_timeout: Duration,
    warning_offsets: Vec<Duration>,
    final_save_grace: Duration,
}

impl SessionPolicy {
    pub fn try_new(
        inactivity_timeout: Duration,
        absolute_timeout: Duration,
        warning_offsets: Vec<Duration>,
        final_save_grace: Duration,
    ) -> Result<Self, ServiceError> {
        let effective = inactivity_timeout.min(absolute_timeout);
        if inactivity_timeout.is_zero()
            || absolute_timeout.is_zero()
            || warning_offsets.len() > MAX_WARNING_OFFSETS
            || final_save_grace > effective
            || final_save_grace > MAX_FINAL_SAVE_GRACE
        {
            return Err(ServiceError::InvalidConfiguration);
        }

        let mut previous = None;
        for offset in &warning_offsets {
            if offset.is_zero()
                || *offset >= effective
                || previous.is_some_and(|previous| previous <= *offset)
            {
                return Err(ServiceError::InvalidConfiguration);
            }
            previous = Some(*offset);
        }

        let mut retained = Vec::new();
        retained
            .try_reserve_exact(warning_offsets.len())
            .map_err(|_| ServiceError::AllocationFailed)?;
        retained.extend(warning_offsets);
        Ok(Self {
            inactivity_timeout,
            absolute_timeout,
            warning_offsets: retained,
            final_save_grace,
        })
    }

    pub const fn inactivity_timeout(&self) -> Duration {
        self.inactivity_timeout
    }

    pub const fn absolute_timeout(&self) -> Duration {
        self.absolute_timeout
    }

    pub fn warning_offsets(&self) -> &[Duration] {
        &self.warning_offsets
    }

    pub const fn final_save_grace(&self) -> Duration {
        self.final_save_grace
    }
}

/// Coherent state of the service-owned unlock capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    CleanupRequired,
}

/// Deadline whose warning boundary was crossed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDeadlineKind {
    Inactivity,
    Absolute,
}

/// Bounded non-secret session event for presentation layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    LockWarning {
        remaining: Duration,
        deadline: SessionDeadlineKind,
    },
}

/// Non-secret summary of one unlocked session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    vault_id: VaultId,
    generation: u64,
}

impl SessionSummary {
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Injected clock whose value is monotonic since service construction.
pub trait MonotonicClock: Send + Sync + 'static {
    fn elapsed(&self) -> Result<Duration, ServiceError>;
}

/// System monotonic clock used by production composition.
pub struct SystemMonotonicClock {
    started: Instant,
}

impl SystemMonotonicClock {
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        Ok(self.started.elapsed())
    }
}

/// Stable repository-boundary failures without store or crypto details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepositoryPortError {
    Unavailable,
    WrongSecret,
    Cancelled,
    Locked,
    Busy,
    CapacityExceeded,
    AllocationFailed,
    CleanupRequired,
    PlatformFailure,
    TimedOut,
    DurabilityPending,
    IntegrityFailed,
    NotFound,
    EntropyUnavailable,
    IdentifierExhausted,
    InvalidInput,
    StaleCapability,
}

/// Service-owned bounds for one replication operation.
#[derive(Clone, Copy)]
pub struct ReplicationLimitProfile {
    limits: ReplicationLimits,
}

impl ReplicationLimitProfile {
    pub const fn phase_one() -> Self {
        Self {
            limits: ReplicationLimits::PHASE_1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        max_bootstrap_bytes: u64,
        max_head_bytes: u64,
        max_chunk_object_bytes: u64,
        max_manifest_object_bytes: u64,
        max_tree_object_bytes: u64,
        max_snapshot_object_bytes: u64,
        max_aggregate_bytes: u64,
        max_object_count: u64,
        max_graph_edges: u64,
        max_graph_depth: u32,
        max_duration: Duration,
        progress_interval: Duration,
        max_quarantine_bytes: u64,
        free_space_reserve_bytes: u64,
    ) -> Result<Self, RepositoryPortError> {
        let limits = ReplicationLimits {
            max_bootstrap_bytes,
            max_head_bytes,
            max_chunk_object_bytes,
            max_manifest_object_bytes,
            max_tree_object_bytes,
            max_snapshot_object_bytes,
            max_aggregate_bytes,
            max_object_count,
            max_graph_edges,
            max_graph_depth,
            max_duration,
            progress_interval,
            max_quarantine_bytes,
            free_space_reserve_bytes,
        };
        let phase_one = ReplicationLimits::PHASE_1;
        if [
            max_bootstrap_bytes,
            max_head_bytes,
            max_chunk_object_bytes,
            max_manifest_object_bytes,
            max_tree_object_bytes,
            max_snapshot_object_bytes,
            max_aggregate_bytes,
            max_object_count,
            max_graph_edges,
            max_quarantine_bytes,
        ]
        .contains(&0)
            || max_graph_depth == 0
            || max_duration.is_zero()
            || progress_interval.is_zero()
            || progress_interval > max_duration
            || max_bootstrap_bytes > phase_one.max_bootstrap_bytes
            || max_head_bytes > phase_one.max_head_bytes
            || max_chunk_object_bytes > phase_one.max_chunk_object_bytes
            || max_manifest_object_bytes > phase_one.max_manifest_object_bytes
            || max_tree_object_bytes > phase_one.max_tree_object_bytes
            || max_snapshot_object_bytes > phase_one.max_snapshot_object_bytes
            || max_aggregate_bytes > phase_one.max_aggregate_bytes
            || max_object_count > phase_one.max_object_count
            || max_graph_edges > phase_one.max_graph_edges
            || max_graph_depth > phase_one.max_graph_depth
            || max_duration > phase_one.max_duration
            || progress_interval > phase_one.progress_interval
            || max_quarantine_bytes > phase_one.max_quarantine_bytes
            || free_space_reserve_bytes < phase_one.free_space_reserve_bytes
        {
            return Err(RepositoryPortError::InvalidInput);
        }
        Ok(Self { limits })
    }

    #[must_use]
    pub fn strictest(self, other: Self) -> Self {
        Self {
            limits: self.limits.strictest(other.limits),
        }
    }

    pub const fn max_bootstrap_bytes(self) -> u64 {
        self.limits.max_bootstrap_bytes
    }
    pub const fn max_head_bytes(self) -> u64 {
        self.limits.max_head_bytes
    }
    pub const fn max_chunk_object_bytes(self) -> u64 {
        self.limits.max_chunk_object_bytes
    }
    pub const fn max_manifest_object_bytes(self) -> u64 {
        self.limits.max_manifest_object_bytes
    }
    pub const fn max_tree_object_bytes(self) -> u64 {
        self.limits.max_tree_object_bytes
    }
    pub const fn max_snapshot_object_bytes(self) -> u64 {
        self.limits.max_snapshot_object_bytes
    }
    pub const fn max_aggregate_bytes(self) -> u64 {
        self.limits.max_aggregate_bytes
    }
    pub const fn max_object_count(self) -> u64 {
        self.limits.max_object_count
    }
    pub const fn max_graph_edges(self) -> u64 {
        self.limits.max_graph_edges
    }
    pub const fn max_graph_depth(self) -> u32 {
        self.limits.max_graph_depth
    }
    pub const fn max_duration(self) -> Duration {
        self.limits.max_duration
    }
    pub const fn progress_interval(self) -> Duration {
        self.limits.progress_interval
    }
    pub const fn max_quarantine_bytes(self) -> u64 {
        self.limits.max_quarantine_bytes
    }
    pub const fn free_space_reserve_bytes(self) -> u64 {
        self.limits.free_space_reserve_bytes
    }

    pub(crate) const fn into_store(self) -> ReplicationLimits {
        self.limits
    }
}

/// Service-owned guard evaluated at the final store publication boundary.
pub trait VaultPublicationGuard: Send {
    fn validate(&mut self) -> Result<(), RepositoryPortError>;
}

pub trait OperationCancellation: Send + Sync {
    fn cancel(&self);
}

struct StorePublicationGuard<'a>(&'a mut dyn VaultPublicationGuard);

impl notecrypt_store::PublicationGuard for StorePublicationGuard<'_> {
    fn validate(&mut self) -> Result<(), StoreError> {
        self.0.validate().map_err(map_repository_publication_error)
    }
}

/// Opaque local repository entry identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalEntryId(notecrypt_store::RepositoryEntryId);

impl LocalEntryId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(FileId::from_bytes(bytes).into())
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalEntryKind {
    File,
    Directory,
    Tombstone,
}

pub struct LocalListedEntry<'a>(&'a notecrypt_store::RepositoryListedEntry);

impl LocalListedEntry<'_> {
    pub fn id(&self) -> LocalEntryId {
        LocalEntryId(self.0.id())
    }

    pub fn parent_id(&self) -> LocalEntryId {
        LocalEntryId(self.0.parent_id())
    }

    pub fn name(&self) -> &str {
        self.0.name()
    }

    pub fn kind(&self) -> LocalEntryKind {
        match self.0.kind() {
            notecrypt_store::RepositoryEntryKind::File => LocalEntryKind::File,
            notecrypt_store::RepositoryEntryKind::Directory => LocalEntryKind::Directory,
            notecrypt_store::RepositoryEntryKind::Tombstone => LocalEntryKind::Tombstone,
        }
    }

    pub fn revision_id(&self) -> Option<RevisionId> {
        self.0.revision_id()
    }
}

pub struct LocalEntryList(Vec<notecrypt_store::RepositoryListedEntry>);

impl LocalEntryList {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<LocalListedEntry<'_>> {
        self.0.get(index).map(LocalListedEntry)
    }
}

struct LocalAuthenticatedEntry {
    id: LocalEntryId,
    parent: LocalEntryId,
    name: Zeroizing<String>,
    kind: LocalEntryKind,
    revision: Option<RevisionId>,
}

/// One bounded, generation-coherent authenticated observation of the local vault.
pub struct LocalAuthenticatedView {
    snapshot: SnapshotId,
    root: LocalEntryId,
    entries: Vec<LocalAuthenticatedEntry>,
}

/// Fixed-size coherent status projection for one authenticated generation.
pub struct LocalAuthenticatedStatus {
    snapshot: SnapshotId,
    root: LocalEntryId,
    entry_count: usize,
}

impl LocalAuthenticatedStatus {
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot
    }

    pub fn root_entry_id(&self) -> LocalEntryId {
        self.root
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

impl LocalAuthenticatedView {
    fn from_store(
        view: notecrypt_store::RepositoryAuthenticatedView,
    ) -> Result<Self, RepositoryPortError> {
        let snapshot = view.snapshot_id();
        let root = LocalEntryId(view.root_entry_id());
        let store_entries = view.into_entries();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(store_entries.len())
            .map_err(|_| RepositoryPortError::AllocationFailed)?;
        for entry in store_entries {
            let (id, parent, name, kind, revision) = entry.into_parts();
            entries.push(LocalAuthenticatedEntry {
                id: LocalEntryId(id),
                parent: LocalEntryId(parent),
                name: Zeroizing::new(name),
                kind: match kind {
                    notecrypt_store::RepositoryEntryKind::File => LocalEntryKind::File,
                    notecrypt_store::RepositoryEntryKind::Directory => LocalEntryKind::Directory,
                    notecrypt_store::RepositoryEntryKind::Tombstone => LocalEntryKind::Tombstone,
                },
                revision,
            });
        }
        Ok(Self {
            snapshot,
            root,
            entries,
        })
    }

    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot
    }

    pub fn root_entry_id(&self) -> LocalEntryId {
        self.root
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn into_entry_summaries(self) -> Result<crate::EntrySummaries, ServiceError> {
        crate::EntrySummaries::try_from_iter(self.entries.into_iter().map(|entry| {
            crate::EntrySummary::from_authenticated_parts(
                *entry.id.as_bytes(),
                *entry.parent.as_bytes(),
                entry.name,
                match entry.kind {
                    LocalEntryKind::File => crate::EntryKind::File,
                    LocalEntryKind::Directory => crate::EntryKind::Directory,
                    LocalEntryKind::Tombstone => crate::EntryKind::Tombstone,
                },
                entry.revision.map(|revision| *revision.as_bytes()),
            )
        }))
    }
}

pub struct LocalMutation(notecrypt_store::RepositoryMutation);

fn validated_entry_name(value: &str) -> Result<String, RepositoryPortError> {
    if value.len() > crate::MAX_LOGICAL_COMPONENT_BYTES {
        return Err(RepositoryPortError::CapacityExceeded);
    }
    let parsed = EntryName::try_parse_bounded(value, crate::MAX_LOGICAL_COMPONENT_BYTES)
        .map_err(map_core_repository_error)?;
    if parsed.as_str().len() > crate::MAX_LOGICAL_COMPONENT_BYTES {
        return Err(RepositoryPortError::CapacityExceeded);
    }
    Ok(parsed.into_string())
}

impl LocalMutation {
    pub fn try_create_directory(
        expected_snapshot: SnapshotId,
        parent: LocalEntryId,
        name: &str,
    ) -> Result<Self, RepositoryPortError> {
        let name = validated_entry_name(name)?;
        Ok(Self(
            notecrypt_store::RepositoryMutation::create_directory_owned(
                expected_snapshot,
                parent.0,
                name,
            ),
        ))
    }

    pub fn try_rename(
        expected_snapshot: SnapshotId,
        entry: LocalEntryId,
        expected_parent: LocalEntryId,
        expected_name: &str,
        new_parent: LocalEntryId,
        new_name: &str,
    ) -> Result<Self, RepositoryPortError> {
        let expected_name = validated_entry_name(expected_name)?;
        let new_name = validated_entry_name(new_name)?;
        Ok(Self(notecrypt_store::RepositoryMutation::rename_owned(
            expected_snapshot,
            entry.0,
            expected_parent.0,
            expected_name,
            new_parent.0,
            new_name,
        )))
    }

    pub fn try_delete_file(
        expected_snapshot: SnapshotId,
        entry: LocalEntryId,
        expected_parent: LocalEntryId,
        expected_name: &str,
        expected_revision: RevisionId,
    ) -> Result<Self, RepositoryPortError> {
        let expected_name = validated_entry_name(expected_name)?;
        Ok(Self(
            notecrypt_store::RepositoryMutation::delete_file_owned(
                expected_snapshot,
                entry.0,
                expected_parent.0,
                expected_name,
                expected_revision,
            ),
        ))
    }

    pub fn try_delete_directory(
        expected_snapshot: SnapshotId,
        entry: LocalEntryId,
        expected_parent: LocalEntryId,
        expected_name: &str,
    ) -> Result<Self, RepositoryPortError> {
        let expected_name = validated_entry_name(expected_name)?;
        Ok(Self(
            notecrypt_store::RepositoryMutation::delete_directory_owned(
                expected_snapshot,
                entry.0,
                expected_parent.0,
                expected_name,
            ),
        ))
    }
}

pub struct LocalMutationResult(notecrypt_store::RepositoryMutationResult);

impl LocalMutationResult {
    pub fn snapshot_id(&self) -> SnapshotId {
        self.0.snapshot_id()
    }

    pub fn entry_id(&self) -> LocalEntryId {
        LocalEntryId(self.0.entry_id())
    }
}

pub struct LocalStreamRevisionRequest(notecrypt_store::StreamRevisionRequest);

impl LocalStreamRevisionRequest {
    pub fn try_create_in_parent(
        expected_snapshot: SnapshotId,
        parent: LocalEntryId,
        name: &str,
    ) -> Result<Self, RepositoryPortError> {
        let name = validated_entry_name(name)?;
        Ok(Self(
            notecrypt_store::StreamRevisionRequest::create_in_parent_owned(
                expected_snapshot,
                parent.0,
                name,
            ),
        ))
    }

    pub fn try_create(
        expected_snapshot: SnapshotId,
        name: &str,
    ) -> Result<Self, RepositoryPortError> {
        let name = validated_entry_name(name)?;
        Ok(Self(notecrypt_store::StreamRevisionRequest::create_owned(
            expected_snapshot,
            name,
        )))
    }

    pub fn try_replace(
        expected_snapshot: SnapshotId,
        file_id: FileId,
        expected_revision: RevisionId,
        name: &str,
    ) -> Result<Self, RepositoryPortError> {
        let name = validated_entry_name(name)?;
        Ok(Self(notecrypt_store::StreamRevisionRequest::replace_owned(
            expected_snapshot,
            file_id,
            expected_revision,
            name,
        )))
    }
}

pub struct LocalSnapshot(notecrypt_store::RepositorySnapshot);

impl LocalSnapshot {
    pub fn snapshot_id(&self) -> SnapshotId {
        self.0.snapshot_id()
    }

    pub fn file_id(&self) -> FileId {
        self.0.file_id()
    }

    pub fn revision_id(&self) -> RevisionId {
        self.0.revision_id()
    }
}

/// Unforgeable stable-source commit assembled by the service workspace workflow.
pub struct StableRevisionCommit<'a> {
    request: LocalStreamRevisionRequest,
    source: &'a mut dyn Read,
    guard: &'a mut dyn VaultPublicationGuard,
}

impl<'a> StableRevisionCommit<'a> {
    fn new(
        request: LocalStreamRevisionRequest,
        source: &'a mut dyn Read,
        guard: &'a mut dyn VaultPublicationGuard,
    ) -> Self {
        Self {
            request,
            source,
            guard,
        }
    }

    pub fn execute<T>(
        self,
        action: impl FnOnce(
            LocalStreamRevisionRequest,
            &mut dyn Read,
            &mut dyn VaultPublicationGuard,
        ) -> Result<T, RepositoryPortError>,
    ) -> Result<T, RepositoryPortError> {
        action(self.request, self.source, self.guard)
    }
}

pub(crate) fn selected_revision_commit<'a>(
    request: LocalStreamRevisionRequest,
    source: &'a mut dyn Read,
    guard: &'a mut dyn VaultPublicationGuard,
) -> StableRevisionCommit<'a> {
    StableRevisionCommit::new(request, source, guard)
}

/// Bounded local operation lease backed by the exact Task 6 lease.
pub trait LocalVaultLease: Send {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation>;
    fn cancel(&self);
    fn list_entries(&mut self) -> Result<LocalEntryList, RepositoryPortError>;
    fn root_entry_id(&mut self) -> Result<LocalEntryId, RepositoryPortError>;
    fn current_snapshot_id(&mut self) -> Result<SnapshotId, RepositoryPortError>;
    fn authenticated_view(
        &mut self,
        max_entries: usize,
    ) -> Result<LocalAuthenticatedView, RepositoryPortError> {
        let root = self.root_entry_id()?;
        let snapshot = self.current_snapshot_id()?;
        let list = self.list_entries()?;
        if list.len() > max_entries {
            return Err(RepositoryPortError::CapacityExceeded);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(list.len())
            .map_err(|_| RepositoryPortError::AllocationFailed)?;
        for entry in list.0 {
            let (id, parent, name, kind, revision) = entry.into_parts();
            entries.push(LocalAuthenticatedEntry {
                id: LocalEntryId(id),
                parent: LocalEntryId(parent),
                name: Zeroizing::new(name),
                kind: match kind {
                    notecrypt_store::RepositoryEntryKind::File => LocalEntryKind::File,
                    notecrypt_store::RepositoryEntryKind::Directory => LocalEntryKind::Directory,
                    notecrypt_store::RepositoryEntryKind::Tombstone => LocalEntryKind::Tombstone,
                },
                revision,
            });
        }
        Ok(LocalAuthenticatedView {
            snapshot,
            root,
            entries,
        })
    }
    fn authenticated_status(
        &mut self,
        max_entries: usize,
    ) -> Result<LocalAuthenticatedStatus, RepositoryPortError> {
        let root = self.root_entry_id()?;
        let snapshot = self.current_snapshot_id()?;
        let entries = self.list_entries()?;
        if entries.len() > max_entries {
            return Err(RepositoryPortError::CapacityExceeded);
        }
        Ok(LocalAuthenticatedStatus {
            snapshot,
            root,
            entry_count: entries.len(),
        })
    }
    fn validate_entry_binding(
        &mut self,
        entry: LocalEntryId,
        parent: LocalEntryId,
        name: &str,
        kind: LocalEntryKind,
        revision: Option<RevisionId>,
    ) -> Result<(), RepositoryPortError>;
    fn validate_export_binding(
        &mut self,
        entry: LocalEntryId,
        revision: RevisionId,
    ) -> Result<(), RepositoryPortError>;
    fn apply(
        &mut self,
        mutation: LocalMutation,
        guard: &mut dyn VaultPublicationGuard,
    ) -> Result<LocalMutationResult, RepositoryPortError>;
    fn export(
        &mut self,
        file_id: FileId,
        expected_revision: RevisionId,
        output: &mut dyn Write,
    ) -> Result<u64, RepositoryPortError>;
    fn commit_stable_revision(
        &mut self,
        commit: StableRevisionCommit<'_>,
    ) -> Result<LocalSnapshot, RepositoryPortError>;
    fn finish(self: Box<Self>) -> Result<(), RepositoryPortError>;
}

pub struct ReplicationAuthenticatedHead(notecrypt_store::AuthenticatedHead);
pub struct ReplicationVerifiedHead(notecrypt_store::VerifiedReachableHead);
pub struct ReplicationPendingPublication(notecrypt_store::PendingRemotePublication);
pub struct ReplicationCommittedHead(notecrypt_store::CommittedReachableHead);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReplicationObjectKind {
    Chunk,
    Manifest,
    Tree,
    Snapshot,
}

impl ReplicationObjectKind {
    fn into_store(self) -> notecrypt_store::ImportedObjectKind {
        match self {
            Self::Chunk => notecrypt_store::ImportedObjectKind::Chunk,
            Self::Manifest => notecrypt_store::ImportedObjectKind::Manifest,
            Self::Tree => notecrypt_store::ImportedObjectKind::Tree,
            Self::Snapshot => notecrypt_store::ImportedObjectKind::Snapshot,
        }
    }
}

pub struct ReplicationImportedObject(notecrypt_store::ImportedObjectMetadata);

impl ReplicationImportedObject {
    pub fn id(&self) -> ObjectId {
        self.0.id()
    }

    pub fn encoded_length(&self) -> u64 {
        self.0.encoded_length()
    }

    pub fn references(&self) -> &[ObjectId] {
        self.0.references()
    }
}

pub struct ReplicationObservation(notecrypt_store::BackendObservationFingerprint);

impl ReplicationObservation {
    pub fn try_new(mut bytes: Vec<u8>) -> Result<Self, RepositoryPortError> {
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(RepositoryPortError::InvalidInput);
        }
        if bytes.len() > MAX_REPLICATION_OBSERVATION_BYTES {
            bytes.zeroize();
            return Err(RepositoryPortError::CapacityExceeded);
        }
        let bytes = crate::ports::try_rehome_bytes(&mut bytes, MAX_REPLICATION_OBSERVATION_BYTES)
            .map_err(map_host_repository_error)?;
        notecrypt_store::BackendObservationFingerprint::try_new(bytes)
            .map(Self)
            .map_err(map_store_error)
    }

    #[cfg(test)]
    fn retained_capacity_for_test(&self) -> usize {
        self.0.retained_capacity_for_test()
    }
}

pub struct ReplicationCommitRequest(notecrypt_store::CommitReplicatedSnapshot);

impl ReplicationCommitRequest {
    pub fn try_new(mut intended_head: Vec<u8>) -> Result<Self, RepositoryPortError> {
        if intended_head.is_empty() {
            intended_head.zeroize();
            return Err(RepositoryPortError::InvalidInput);
        }
        if intended_head.len() > MAX_REPLICATION_COMMIT_BYTES {
            intended_head.zeroize();
            return Err(RepositoryPortError::CapacityExceeded);
        }
        let intended_head =
            crate::ports::try_rehome_bytes(&mut intended_head, MAX_REPLICATION_COMMIT_BYTES)
                .map_err(map_host_repository_error)?;
        Ok(Self(notecrypt_store::CommitReplicatedSnapshot::new(
            intended_head,
        )))
    }

    #[cfg(test)]
    fn retained_capacity_for_test(&self) -> usize {
        self.0.retained_capacity_for_test()
    }
}

pub trait ReplicationImport: Write + Send {
    fn finish(self: Box<Self>) -> Result<ReplicationImportedObject, RepositoryPortError>;
}

/// Lifetime-free replication capability that mirrors the complete Task 6 lease.
pub trait ReplicationVaultLease: Send {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation>;
    fn cancel(&self);
    fn authenticate_bootstrap(&mut self, bytes: &[u8]) -> Result<(), RepositoryPortError>;
    fn authenticate_head(
        &mut self,
        bytes: &[u8],
    ) -> Result<ReplicationAuthenticatedHead, RepositoryPortError>;
    fn contains_object(&mut self, id: &ObjectId) -> Result<bool, RepositoryPortError>;
    fn begin_import(
        &mut self,
        expected_id: ObjectId,
        kind: ReplicationObjectKind,
        declared_length: u64,
    ) -> Result<Box<dyn ReplicationImport + '_>, RepositoryPortError>;
    fn verify_reachable(
        &mut self,
        head: ReplicationAuthenticatedHead,
        observation: ReplicationObservation,
    ) -> Result<ReplicationVerifiedHead, RepositoryPortError>;
    fn export_encrypted(
        &mut self,
        id: &ObjectId,
        output: &mut dyn Write,
    ) -> Result<u64, RepositoryPortError>;
    fn commit_replicated_snapshot(
        &mut self,
        verified: ReplicationVerifiedHead,
        request: ReplicationCommitRequest,
        guard: &mut dyn VaultPublicationGuard,
    ) -> Result<ReplicationCommittedHead, RepositoryPortError>;
    fn commit_reconciled_snapshot(
        &mut self,
        verified_remote: ReplicationVerifiedHead,
        request: ReplicationCommitRequest,
        guard: &mut dyn VaultPublicationGuard,
    ) -> Result<ReplicationPendingPublication, RepositoryPortError>;
    fn confirm_reconciled_publication(
        &mut self,
        pending: ReplicationPendingPublication,
        verified_readback: ReplicationVerifiedHead,
    ) -> Result<ReplicationCommittedHead, RepositoryPortError>;
    fn accept_current_verified(
        &mut self,
        verified: ReplicationVerifiedHead,
    ) -> Result<ReplicationCommittedHead, RepositoryPortError>;
    fn record_trusted_remote(
        &mut self,
        committed: ReplicationCommittedHead,
    ) -> Result<TrustedRemoteRecordOutcome, RepositoryPortError>;
    fn into_freshness_acknowledgement(
        self: Box<Self>,
    ) -> Result<Box<dyn PendingFreshnessAction>, RepositoryPortError>;
    fn finish(self: Box<Self>) -> Result<(), RepositoryPortError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedRemoteRecordOutcome {
    Recorded,
    FreshnessAcknowledgementRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverySecretPolicy {
    Generated,
    CustomV1,
}

pub struct OfflineGuessingRiskAcknowledgement {
    version: u8,
}

/// Versioned safe disclosure that must be consumed to accept custom-secret risk.
pub struct OfflineGuessingRiskDisclosure {
    version: u8,
}

impl OfflineGuessingRiskDisclosure {
    pub fn try_for_policy(version: u16) -> Result<Self, RepositoryPortError> {
        if version != 1 {
            return Err(RepositoryPortError::InvalidInput);
        }
        Ok(Self { version: 1 })
    }

    pub const fn warning(&self) -> &'static str {
        notecrypt_crypto::OFFLINE_VERIFIER_DISCLOSURE
    }

    pub const fn policy_version(&self) -> u16 {
        self.version as u16
    }

    pub const fn accept(self) -> OfflineGuessingRiskAcknowledgement {
        OfflineGuessingRiskAcknowledgement {
            version: self.version,
        }
    }
}

impl OfflineGuessingRiskAcknowledgement {
    pub const fn version(&self) -> u8 {
        self.version
    }
}

pub struct BeginRecoveryInitialization {
    policy: RecoverySecretPolicy,
    custom: Option<RecoverySecretInput>,
    risk: Option<OfflineGuessingRiskAcknowledgement>,
}

impl BeginRecoveryInitialization {
    pub const fn generated() -> Self {
        Self {
            policy: RecoverySecretPolicy::Generated,
            custom: None,
            risk: None,
        }
    }

    pub fn custom_v1(
        secret: RecoverySecretInput,
        acknowledgement: OfflineGuessingRiskAcknowledgement,
    ) -> Self {
        Self {
            policy: RecoverySecretPolicy::CustomV1,
            custom: Some(secret),
            risk: Some(acknowledgement),
        }
    }

    pub const fn policy(&self) -> RecoverySecretPolicy {
        self.policy
    }

    pub fn into_custom(self) -> Option<(RecoverySecretInput, OfflineGuessingRiskAcknowledgement)> {
        self.custom.zip(self.risk)
    }
}

pub struct BeginCompromiseRekey {
    target: [u8; 16],
    policy: RecoverySecretPolicy,
    risk: Option<OfflineGuessingRiskAcknowledgement>,
}

/// Linear recovery credential confirmation for a compromise rekey.
pub struct CompromiseRekeyConfirmation {
    first: RecoverySecretInput,
    matching: Option<RecoverySecretInput>,
}

impl CompromiseRekeyConfirmation {
    pub fn generated(confirmation: RecoverySecretInput) -> Self {
        Self {
            first: confirmation,
            matching: None,
        }
    }

    pub fn custom_v1(first: RecoverySecretInput, matching: RecoverySecretInput) -> Self {
        Self {
            first,
            matching: Some(matching),
        }
    }

    pub(crate) fn into_parts(self) -> (RecoverySecretInput, Option<RecoverySecretInput>) {
        (self.first, self.matching)
    }
}

impl BeginCompromiseRekey {
    pub fn try_generated(target: [u8; 16]) -> Result<Self, RepositoryPortError> {
        if target == [0; 16] {
            return Err(RepositoryPortError::InvalidInput);
        }
        Ok(Self {
            target,
            policy: RecoverySecretPolicy::Generated,
            risk: None,
        })
    }

    pub fn try_custom_v1(
        target: [u8; 16],
        acknowledgement: OfflineGuessingRiskAcknowledgement,
    ) -> Result<Self, RepositoryPortError> {
        if target == [0; 16] || acknowledgement.version != 1 {
            return Err(RepositoryPortError::InvalidInput);
        }
        Ok(Self {
            target,
            policy: RecoverySecretPolicy::CustomV1,
            risk: Some(acknowledgement),
        })
    }

    pub const fn target(&self) -> &[u8; 16] {
        &self.target
    }

    pub const fn policy(&self) -> RecoverySecretPolicy {
        self.policy
    }

    pub fn into_parts(
        self,
    ) -> (
        [u8; 16],
        RecoverySecretPolicy,
        Option<OfflineGuessingRiskAcknowledgement>,
    ) {
        (self.target, self.policy, self.risk)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultSummary {
    vault_id: VaultId,
}

impl VaultSummary {
    pub const fn new(vault_id: VaultId) -> Self {
        Self { vault_id }
    }

    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshnessAcknowledgementView {
    warning_code: &'static str,
    authenticated_snapshot: SnapshotId,
    consequence: &'static str,
}

impl FreshnessAcknowledgementView {
    pub(crate) const fn new(authenticated_snapshot: SnapshotId) -> Self {
        Self {
            warning_code: "freshness-unprovable",
            authenticated_snapshot,
            consequence: "records this authenticated remote as trusted without proving freshness",
        }
    }

    pub const fn warning_code(&self) -> &'static str {
        self.warning_code
    }

    pub const fn authenticated_snapshot(&self) -> SnapshotId {
        self.authenticated_snapshot
    }

    pub const fn consequence(&self) -> &'static str {
        self.consequence
    }
}

pub trait PendingRecoveryAction: Send {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation>;
    fn confirm(
        self: Box<Self>,
        confirmation: RecoverySecretInput,
        cancel: &RepositoryCancellation,
    ) -> Result<VaultSummary, RepositoryPortError>;
    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError>;
}

pub trait PendingCompromiseAction: Send {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation>;
    fn confirm(
        self: Box<Self>,
        confirmation: RecoverySecretInput,
        cancel: &RepositoryCancellation,
    ) -> Result<(), RepositoryPortError>;
    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError>;
}

pub trait PendingFreshnessAction: Send {
    fn operation_cancellation(&self) -> &RepositoryCancellation;
    fn view(&self) -> FreshnessAcknowledgementView;
    fn acknowledge(self: Box<Self>) -> Result<(), RepositoryPortError>;
    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError>;
}

pub struct PreparedRecoveryInitialization {
    pub(crate) secret: RecoverySecretInput,
    pub(crate) generated: bool,
    pub(crate) action: Box<dyn PendingRecoveryAction>,
}

impl PreparedRecoveryInitialization {
    pub fn new(secret: RecoverySecretInput, action: Box<dyn PendingRecoveryAction>) -> Self {
        Self {
            secret,
            generated: true,
            action,
        }
    }

    pub fn custom(secret: RecoverySecretInput, action: Box<dyn PendingRecoveryAction>) -> Self {
        Self {
            secret,
            generated: false,
            action,
        }
    }
}

pub struct PreparedCompromiseRekey {
    pub(crate) secret: Option<RecoverySecretInput>,
    pub(crate) action: Box<dyn PendingCompromiseAction>,
}

/// Read-only cancellation probe for repository calls owned by the service.
pub struct RepositoryCancellation {
    cancelled: Arc<AtomicBool>,
}

impl RepositoryCancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn as_atomic(&self) -> &AtomicBool {
        &self.cancelled
    }

    pub(crate) fn shared_atomic(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
}

pub trait RegisteredWorkspaceCapability: Send {
    fn workspace_id(&self) -> &crate::WorkspaceId;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

pub trait ActiveWorkspaceCapability: Send {
    fn workspace_id(&self) -> &crate::WorkspaceId;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

pub enum AuthenticatedWorkspaceCapability {
    Registered(Box<dyn RegisteredWorkspaceCapability>),
    Active(Box<dyn ActiveWorkspaceCapability>),
}

impl AuthenticatedWorkspaceCapability {
    pub fn workspace_id(&self) -> &crate::WorkspaceId {
        match self {
            Self::Registered(registered) => registered.workspace_id(),
            Self::Active(active) => active.workspace_id(),
        }
    }
}

impl PreparedCompromiseRekey {
    pub fn new(secret: RecoverySecretInput, action: Box<dyn PendingCompromiseAction>) -> Self {
        Self {
            secret: Some(secret),
            action,
        }
    }

    pub fn custom(action: Box<dyn PendingCompromiseAction>) -> Self {
        Self {
            secret: None,
            action,
        }
    }
}

/// Opaque unlocked capability retained only by the service session.
pub trait UnlockedVaultCapability: Send {
    fn revocation_handle(&self) -> Arc<dyn VaultRootRevocation>;
    fn acquire_local_lease(
        &self,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn LocalVaultLease>, RepositoryPortError>;
    fn acquire_replication_lease(
        &self,
        backend: ReplicationLimitProfile,
        operation: ReplicationLimitProfile,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn ReplicationVaultLease>, RepositoryPortError>;
    fn begin_compromise_rekey(
        &self,
        request: BeginCompromiseRekey,
        cancel: &RepositoryCancellation,
    ) -> Result<PreparedCompromiseRekey, RepositoryPortError>;
    fn register_workspace(
        &self,
    ) -> Result<Box<dyn RegisteredWorkspaceCapability>, RepositoryPortError>;
    fn activate_workspace(
        &self,
        registered: &mut dyn RegisteredWorkspaceCapability,
    ) -> Result<Box<dyn ActiveWorkspaceCapability>, RepositoryPortError>;
    fn authenticated_workspaces(
        &self,
    ) -> Result<Vec<AuthenticatedWorkspaceCapability>, RepositoryPortError>;
    fn unregister_absent_workspace(
        &self,
        active: &mut dyn ActiveWorkspaceCapability,
    ) -> Result<(), RepositoryPortError>;
    fn unregister_removed_workspace(
        &self,
        active: &mut dyn ActiveWorkspaceCapability,
        guard: Box<dyn crate::WorkspaceAbsenceGuard>,
    ) -> Result<(), RepositoryPortError>;
    fn close(self: Box<Self>) -> Result<(), RepositoryPortError>;
}

/// One-way root revocation detached from the consuming repository capability.
pub trait VaultRootRevocation: Send + Sync {
    fn revoke(&self);
}

/// Repository composition seam used by recovery unlock.
pub trait VaultRepository: Send + Sync + 'static {
    fn current_vault_id(&self) -> Result<Option<VaultId>, RepositoryPortError>;
    fn unlock_recovery(
        &self,
        secret: RecoverySecretInput,
        cancel: &RepositoryCancellation,
    ) -> Result<Box<dyn UnlockedVaultCapability>, RepositoryPortError>;
    fn begin_recovery_initialization(
        &self,
        request: BeginRecoveryInitialization,
        cancel: &RepositoryCancellation,
    ) -> Result<PreparedRecoveryInitialization, RepositoryPortError>;
}

/// Service-owned Argon2id profile without exposing the crypto crate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoveryKdfProfileV1 {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl RecoveryKdfProfileV1 {
    pub fn try_new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, RepositoryPortError> {
        let parameters = Argon2idParameters {
            memory_kib,
            iterations,
            parallelism,
        };
        ValidatedArgon2idParameters::try_from(parameters)
            .map_err(|_| RepositoryPortError::InvalidInput)?;
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    fn validated(self) -> Result<ValidatedArgon2idParameters, RepositoryPortError> {
        ValidatedArgon2idParameters::try_from(Argon2idParameters {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        })
        .map_err(|_| RepositoryPortError::InvalidInput)
    }
}

/// Validated owned target selected by a trusted composition adapter.
pub struct LocalVaultConfig {
    repository_root: std::path::PathBuf,
    local_state_root: std::path::PathBuf,
    profile: RecoveryKdfProfileV1,
    device_label: String,
}

impl LocalVaultConfig {
    pub fn try_new(
        repository_root: std::path::PathBuf,
        local_state_root: std::path::PathBuf,
        profile: RecoveryKdfProfileV1,
        device_label: String,
    ) -> Result<Self, RepositoryPortError> {
        if !crate::ports::valid_absolute_path(&repository_root)
            || !crate::ports::valid_absolute_path(&local_state_root)
            || repository_root == local_state_root
            || device_label.is_empty()
            || device_label.len() > 256
            || device_label.as_bytes().contains(&0)
        {
            return Err(RepositoryPortError::InvalidInput);
        }
        let repository_root =
            crate::ports::try_rehome_path(repository_root, crate::MAX_NATIVE_PATH_BYTES)
                .map_err(map_host_repository_error)?;
        let local_state_root =
            crate::ports::try_rehome_path(local_state_root, crate::MAX_NATIVE_PATH_BYTES)
                .map_err(map_host_repository_error)?;
        let device_label = crate::ports::try_rehome_string(device_label, 256)
            .map_err(map_host_repository_error)?;
        Ok(Self {
            repository_root,
            local_state_root,
            profile,
            device_label,
        })
    }

    fn validated_parameters(&self) -> Result<ValidatedArgon2idParameters, RepositoryPortError> {
        self.profile.validated()
    }
}

/// Resolves an opaque compromise target without putting paths in UI requests.
pub trait CompromiseTargetResolver: Send + Sync + 'static {
    fn resolve(&self, target: [u8; 16]) -> Result<LocalVaultConfig, RepositoryPortError>;
}

enum StoreRepositoryState {
    Vacant(Arc<LocalVaultConfig>),
    Existing(Arc<VaultStore>),
}

/// Production bridge that keeps store and crypto types out of UI contracts.
pub struct StoreVaultRepository {
    state: Arc<Mutex<StoreRepositoryState>>,
    workspace: Arc<dyn WorkspaceProvider>,
    targets: Arc<dyn CompromiseTargetResolver>,
}

impl StoreVaultRepository {
    pub(crate) fn existing(
        store: Arc<VaultStore>,
        workspace: Arc<dyn WorkspaceProvider>,
        targets: Arc<dyn CompromiseTargetResolver>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(StoreRepositoryState::Existing(store))),
            workspace,
            targets,
        }
    }

    pub fn open(
        target: LocalVaultConfig,
        workspace: Arc<dyn WorkspaceProvider>,
        targets: Arc<dyn CompromiseTargetResolver>,
    ) -> Result<Self, RepositoryPortError> {
        let store = VaultStore::open(&target.repository_root, &target.local_state_root)
            .map_err(map_store_error)?;
        Ok(Self::existing(store, workspace, targets))
    }

    pub fn vacant(
        target: LocalVaultConfig,
        workspace: Arc<dyn WorkspaceProvider>,
        targets: Arc<dyn CompromiseTargetResolver>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(StoreRepositoryState::Vacant(Arc::new(target)))),
            workspace,
            targets,
        }
    }
}

impl VaultRepository for StoreVaultRepository {
    fn current_vault_id(&self) -> Result<Option<VaultId>, RepositoryPortError> {
        Ok(
            match &*self.state.lock().unwrap_or_else(|error| error.into_inner()) {
                StoreRepositoryState::Vacant(_) => None,
                StoreRepositoryState::Existing(store) => Some(store.vault_id()),
            },
        )
    }

    fn unlock_recovery(
        &self,
        secret: RecoverySecretInput,
        cancel: &RepositoryCancellation,
    ) -> Result<Box<dyn UnlockedVaultCapability>, RepositoryPortError> {
        let verifier = Arc::new(StoreWorkspaceAbsenceVerifier::new(Arc::clone(
            &self.workspace,
        )));
        let store = match &*self.state.lock().unwrap_or_else(|error| error.into_inner()) {
            StoreRepositoryState::Existing(store) => Arc::clone(store),
            StoreRepositoryState::Vacant(_) => return Err(RepositoryPortError::NotFound),
        };
        store
            .unlock_recovery(secret.into_crypto_passphrase(), cancel.as_atomic())
            .map(|unlocked| {
                let authority =
                    notecrypt_store::WorkspaceAbsenceAuthority::new(Arc::clone(&verifier)
                        as Arc<dyn notecrypt_store::TrustedWorkspaceAbsenceVerifier>);
                Box::new(StoreUnlockedVault::new(
                    unlocked.with_workspace_absence_authority(authority),
                    verifier,
                    store,
                    Arc::clone(&self.targets),
                )) as Box<dyn UnlockedVaultCapability>
            })
            .map_err(map_unlock_error)
    }

    fn begin_recovery_initialization(
        &self,
        request: BeginRecoveryInitialization,
        cancel: &RepositoryCancellation,
    ) -> Result<PreparedRecoveryInitialization, RepositoryPortError> {
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        let target = match &*self.state.lock().unwrap_or_else(|error| error.into_inner()) {
            StoreRepositoryState::Vacant(target) => Arc::clone(target),
            StoreRepositoryState::Existing(_) => return Err(RepositoryPortError::InvalidInput),
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let custom = request.policy() == RecoverySecretPolicy::CustomV1;
        let action = Box::new(StorePendingRecoveryAction {
            state: Arc::clone(&self.state),
            target,
            cancellation,
            custom,
        });
        match request.policy() {
            RecoverySecretPolicy::Generated => Ok(PreparedRecoveryInitialization::new(
                generate_recovery_input()?,
                action,
            )),
            RecoverySecretPolicy::CustomV1 => {
                let (secret, risk) = request
                    .into_custom()
                    .ok_or(RepositoryPortError::InvalidInput)?;
                if risk.version() != 1 {
                    return Err(RepositoryPortError::InvalidInput);
                }
                Ok(PreparedRecoveryInitialization::custom(secret, action))
            }
        }
    }
}

fn generate_recovery_input() -> Result<RecoverySecretInput, RepositoryPortError> {
    let phrase = notecrypt_crypto::generate_recovery_phrase(&mut notecrypt_crypto::OsRandom)
        .map_err(|_| RepositoryPortError::EntropyUnavailable)?;
    let mut bytes = Zeroizing::new(Vec::new());
    phrase.present_once(|value| {
        if crate::ports::allocation_failure_injected_for_test() {
            return Err(RepositoryPortError::AllocationFailed);
        }
        bytes
            .try_reserve_exact(value.len())
            .map_err(|_| RepositoryPortError::AllocationFailed)?;
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    })?;
    RecoverySecretInput::from_zeroizing_bytes(bytes).map_err(map_host_repository_error)
}

struct StorePendingRecoveryAction {
    state: Arc<Mutex<StoreRepositoryState>>,
    target: Arc<LocalVaultConfig>,
    cancellation: Arc<AtomicBool>,
    custom: bool,
}

impl PendingRecoveryAction for StorePendingRecoveryAction {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation> {
        Arc::clone(&self.cancellation) as Arc<dyn OperationCancellation>
    }

    fn confirm(
        self: Box<Self>,
        confirmation: RecoverySecretInput,
        cancel: &RepositoryCancellation,
    ) -> Result<VaultSummary, RepositoryPortError> {
        if cancel.is_cancelled() || self.cancellation.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let passphrase = confirmation.into_crypto_passphrase();
        let passphrase = if self.custom {
            notecrypt_crypto::validate_custom_passphrase(
                passphrase,
                notecrypt_crypto::CustomPassphrasePolicy::V1,
            )
            .map_err(|_| RepositoryPortError::InvalidInput)?
        } else {
            passphrase
        };
        let store = VaultStore::initialize(
            &self.target.repository_root,
            &self.target.local_state_root,
            passphrase,
            self.target.validated_parameters()?,
            &self.target.device_label,
            cancel.as_atomic(),
        )
        .map_err(map_store_error)?;
        let vault_id = store.vault_id();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !matches!(*state, StoreRepositoryState::Vacant(_)) {
            return Err(RepositoryPortError::CleanupRequired);
        }
        *state = StoreRepositoryState::Existing(store);
        Ok(VaultSummary::new(vault_id))
    }

    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.cancellation.store(true, Ordering::Release);
        Ok(())
    }
}

struct StorePendingCompromiseAction {
    source_store: Arc<VaultStore>,
    source: Option<Box<dyn CompromiseRekeySource>>,
    target: LocalVaultConfig,
    cancellation: Arc<AtomicBool>,
}

impl PendingCompromiseAction for StorePendingCompromiseAction {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation> {
        Arc::clone(&self.cancellation) as Arc<dyn OperationCancellation>
    }

    fn confirm(
        mut self: Box<Self>,
        confirmation: RecoverySecretInput,
        cancel: &RepositoryCancellation,
    ) -> Result<(), RepositoryPortError> {
        if cancel.is_cancelled() || self.cancellation.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let mut source = self.source.take().ok_or(RepositoryPortError::Locked)?;
        let mut target = self
            .source_store
            .begin_pending_target(
                &self.target.repository_root,
                &self.target.local_state_root,
                confirmation.into_crypto_passphrase(),
                self.target.validated_parameters()?,
                &self.target.device_label,
                cancel.as_atomic(),
            )
            .map_err(map_store_error)?;
        let result = (|| {
            loop {
                if cancel.is_cancelled() || self.cancellation.load(Ordering::Acquire) {
                    return Err(RepositoryPortError::Cancelled);
                }
                let Some(entry) = source.next_entry().map_err(map_store_error)? else {
                    break;
                };
                target
                    .stage_entry(source.as_mut(), entry, cancel.as_atomic())
                    .map_err(map_store_error)?;
            }
            target
                .verify_complete(cancel.as_atomic())
                .map_err(map_store_error)?;
            Ok(())
        })();
        if let Err(primary) = result {
            return match target.abort().map_err(map_store_error) {
                Ok(()) => Err(primary),
                Err(_) => Err(RepositoryPortError::CleanupRequired),
            };
        }
        if cancel.is_cancelled() || self.cancellation.load(Ordering::Acquire) {
            return match target.abort().map_err(map_store_error) {
                Ok(()) => Err(RepositoryPortError::Cancelled),
                Err(_) => Err(RepositoryPortError::CleanupRequired),
            };
        }
        target
            .activate(cancel.as_atomic())
            .map_err(map_store_error)?;
        Ok(())
    }

    fn abort(mut self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.cancellation.store(true, Ordering::Release);
        self.source.take();
        Ok(())
    }
}

struct StoreUnlockedVault {
    accepting: AtomicBool,
    revocation: notecrypt_store::VaultRevocationHandle,
    state: Mutex<StoreUnlockedState>,
    absence: Arc<StoreWorkspaceAbsenceVerifier>,
    source_store: Arc<VaultStore>,
    targets: Arc<dyn CompromiseTargetResolver>,
}

struct StoreVaultRootRevocation(notecrypt_store::VaultRevocationHandle);

impl VaultRootRevocation for StoreVaultRootRevocation {
    fn revoke(&self) {
        self.0.revoke();
    }
}

struct StoreRegisteredWorkspace {
    id: crate::WorkspaceId,
    inner: notecrypt_store::RegisteredWorkspace,
}

impl RegisteredWorkspaceCapability for StoreRegisteredWorkspace {
    fn workspace_id(&self) -> &crate::WorkspaceId {
        &self.id
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

struct StoreActiveWorkspace {
    id: crate::WorkspaceId,
    inner: notecrypt_store::ActiveWorkspace,
}

impl ActiveWorkspaceCapability for StoreActiveWorkspace {
    fn workspace_id(&self) -> &crate::WorkspaceId {
        &self.id
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

struct StoreUnlockedState {
    unlocked: Option<UnlockedVault>,
}

impl StoreUnlockedVault {
    fn new(
        unlocked: UnlockedVault,
        absence: Arc<StoreWorkspaceAbsenceVerifier>,
        source_store: Arc<VaultStore>,
        targets: Arc<dyn CompromiseTargetResolver>,
    ) -> Self {
        let revocation = unlocked.revocation_handle();
        Self {
            accepting: AtomicBool::new(true),
            revocation,
            state: Mutex::new(StoreUnlockedState {
                unlocked: Some(unlocked),
            }),
            absence,
            source_store,
            targets,
        }
    }
}

struct StoreWorkspaceAbsenceVerifier {
    provider: Arc<dyn WorkspaceProvider>,
    held: Mutex<HashMap<String, Box<dyn crate::WorkspaceAbsenceGuard>>>,
}

impl StoreWorkspaceAbsenceVerifier {
    fn new(provider: Arc<dyn WorkspaceProvider>) -> Self {
        Self {
            provider,
            held: Mutex::new(HashMap::new()),
        }
    }

    fn stage(
        &self,
        id: &crate::WorkspaceId,
        guard: Box<dyn crate::WorkspaceAbsenceGuard>,
    ) -> Result<(), RepositoryPortError> {
        let mut held = self.held.lock().unwrap_or_else(|error| error.into_inner());
        if held.len() == 1_024 {
            return Err(RepositoryPortError::CapacityExceeded);
        }
        if held.contains_key(id.child_name()) {
            return Err(RepositoryPortError::Busy);
        }
        if crate::ports::allocation_failure_injected_for_test() {
            return Err(RepositoryPortError::AllocationFailed);
        }
        held.try_reserve(1)
            .map_err(|_| RepositoryPortError::AllocationFailed)?;
        let mut key = String::new();
        if crate::ports::allocation_failure_injected_for_test() {
            return Err(RepositoryPortError::AllocationFailed);
        }
        key.try_reserve_exact(id.child_name().len())
            .map_err(|_| RepositoryPortError::AllocationFailed)?;
        key.push_str(id.child_name());
        held.insert(key, guard);
        Ok(())
    }
}

struct StoreAbsenceGuard {
    _guard: Box<dyn crate::WorkspaceAbsenceGuard>,
}
impl notecrypt_store::WorkspaceAbsenceGuard for StoreAbsenceGuard {}

impl notecrypt_store::TrustedWorkspaceAbsenceVerifier for StoreWorkspaceAbsenceVerifier {
    fn acquire_verified_absence(
        &self,
        workspace: &notecrypt_store::CleanupWorkspaceId,
    ) -> Result<Box<dyn notecrypt_store::WorkspaceAbsenceGuard>, StoreError> {
        let id = crate::WorkspaceId::from_store(workspace).map_err(map_workspace_id_store_error)?;
        let staged = self
            .held
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(id.child_name());
        let guard = match staged {
            Some(guard) => guard,
            None => self
                .provider
                .acquire_verified_absence(&id)
                .map_err(|error| match error {
                    crate::HostPortError::LiveWorkspace => StoreError::Busy,
                    crate::HostPortError::CapacityExceeded => StoreError::LimitExceeded,
                    crate::HostPortError::AllocationFailed => StoreError::AllocationFailed,
                    _ => StoreError::InvalidCapability,
                })?,
        };
        Ok(Box::new(StoreAbsenceGuard { _guard: guard }))
    }
}

struct StoreLocalVaultLease {
    lease: Option<notecrypt_store::UnlockedVaultLease>,
    cancel: Arc<AtomicBool>,
}

impl OperationCancellation for AtomicBool {
    fn cancel(&self) {
        self.store(true, Ordering::Release);
    }
}

impl LocalVaultLease for StoreLocalVaultLease {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation> {
        Arc::clone(&self.cancel) as Arc<dyn OperationCancellation>
    }

    fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    fn list_entries(&mut self) -> Result<LocalEntryList, RepositoryPortError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let entries = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .list_entries()
            .map_err(map_store_error)?;
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let entries = try_rehome_repository_vec(entries, crate::MAX_WORKSPACE_PATHS)?;
        Ok(LocalEntryList(entries))
    }

    fn root_entry_id(&mut self) -> Result<LocalEntryId, RepositoryPortError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let result = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .root_entry_id()
            .map(LocalEntryId)
            .map_err(map_store_error)?;
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        Ok(result)
    }

    fn current_snapshot_id(&mut self) -> Result<SnapshotId, RepositoryPortError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let result = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .current_snapshot_id()
            .map_err(map_store_error)?;
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        Ok(result)
    }

    fn authenticated_view(
        &mut self,
        max_entries: usize,
    ) -> Result<LocalAuthenticatedView, RepositoryPortError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let view = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .authenticated_view(max_entries, &self.cancel)
            .map_err(map_store_error)?;
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        LocalAuthenticatedView::from_store(view)
    }

    fn authenticated_status(
        &mut self,
        max_entries: usize,
    ) -> Result<LocalAuthenticatedStatus, RepositoryPortError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let status = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .authenticated_status(max_entries, &self.cancel)
            .map_err(map_store_error)?;
        if self.cancel.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        Ok(LocalAuthenticatedStatus {
            snapshot: status.snapshot_id(),
            root: LocalEntryId(status.root_entry_id()),
            entry_count: status.entry_count(),
        })
    }

    fn validate_entry_binding(
        &mut self,
        entry: LocalEntryId,
        parent: LocalEntryId,
        name: &str,
        kind: LocalEntryKind,
        revision: Option<RevisionId>,
    ) -> Result<(), RepositoryPortError> {
        let kind = match kind {
            LocalEntryKind::File => notecrypt_store::RepositoryEntryKind::File,
            LocalEntryKind::Directory => notecrypt_store::RepositoryEntryKind::Directory,
            LocalEntryKind::Tombstone => notecrypt_store::RepositoryEntryKind::Tombstone,
        };
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .validate_entry_binding(
                notecrypt_store::RepositoryEntryId::from_bytes(*entry.as_bytes()),
                notecrypt_store::RepositoryEntryId::from_bytes(*parent.as_bytes()),
                name,
                kind,
                revision,
                &self.cancel,
            )
            .map_err(map_store_error)
    }

    fn validate_export_binding(
        &mut self,
        entry: LocalEntryId,
        revision: RevisionId,
    ) -> Result<(), RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .validate_export_binding(
                notecrypt_store::RepositoryEntryId::from_bytes(*entry.as_bytes()),
                revision,
                &self.cancel,
            )
            .map_err(map_store_error)
    }

    fn apply(
        &mut self,
        mutation: LocalMutation,
        guard: &mut dyn VaultPublicationGuard,
    ) -> Result<LocalMutationResult, RepositoryPortError> {
        let mut guard = StorePublicationGuard(guard);
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .apply(mutation.0, &mut guard, &self.cancel)
            .map(LocalMutationResult)
            .map_err(map_store_error)
    }

    fn export(
        &mut self,
        file_id: FileId,
        expected_revision: RevisionId,
        output: &mut dyn Write,
    ) -> Result<u64, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .export(file_id, expected_revision, output, &self.cancel)
            .map_err(map_store_error)
    }

    fn commit_stable_revision(
        &mut self,
        commit: StableRevisionCommit<'_>,
    ) -> Result<LocalSnapshot, RepositoryPortError> {
        commit.execute(|request, source, guard| {
            let mut guard = StorePublicationGuard(guard);
            self.lease
                .as_mut()
                .ok_or(RepositoryPortError::Locked)?
                .commit_streamed_revision(request.0, source, &mut guard, &self.cancel)
                .map(LocalSnapshot)
                .map_err(map_store_error)
        })
    }

    fn finish(mut self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.lease.take();
        Ok(())
    }
}

struct StoreReplicationVaultLease {
    lease: Option<Box<dyn notecrypt_store::ReplicationLease>>,
    cancellation: Arc<StoreReplicationCancellation>,
    operation_binding: Arc<RepositoryCancellation>,
    pending_freshness: Option<notecrypt_store::PendingUnprovableRemote>,
}

struct StoreReplicationCancellation(notecrypt_store::ReplicationCancellation);

struct StoreReplicationCancellationProbe(Arc<AtomicBool>);

impl notecrypt_store::ReplicationCancellationProbe for StoreReplicationCancellationProbe {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl OperationCancellation for StoreReplicationCancellation {
    fn cancel(&self) {
        self.0.cancel();
    }
}

impl Drop for StoreReplicationVaultLease {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.as_ref() {
            lease.cancel();
        }
    }
}

impl ReplicationVaultLease for StoreReplicationVaultLease {
    fn cancellation_handle(&self) -> Arc<dyn OperationCancellation> {
        Arc::clone(&self.cancellation) as Arc<dyn OperationCancellation>
    }

    fn cancel(&self) {
        if let Some(lease) = self.lease.as_ref() {
            lease.cancel();
        }
    }

    fn authenticate_bootstrap(&mut self, bytes: &[u8]) -> Result<(), RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .authenticate_bootstrap(bytes)
            .map_err(map_store_error)
    }

    fn authenticate_head(
        &mut self,
        bytes: &[u8],
    ) -> Result<ReplicationAuthenticatedHead, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .authenticate_head(bytes)
            .map(ReplicationAuthenticatedHead)
            .map_err(map_store_error)
    }

    fn contains_object(&mut self, id: &ObjectId) -> Result<bool, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .contains_object(id)
            .map_err(map_store_error)
    }

    fn begin_import(
        &mut self,
        expected_id: ObjectId,
        kind: ReplicationObjectKind,
        declared_length: u64,
    ) -> Result<Box<dyn ReplicationImport + '_>, RepositoryPortError> {
        let import = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .begin_import(expected_id, kind.into_store(), declared_length)
            .map_err(map_store_error)?;
        Ok(Box::new(StoreReplicationImport {
            import: Some(import),
        }))
    }

    fn verify_reachable(
        &mut self,
        head: ReplicationAuthenticatedHead,
        observation: ReplicationObservation,
    ) -> Result<ReplicationVerifiedHead, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .verify_reachable(head.0, observation.0)
            .map(ReplicationVerifiedHead)
            .map_err(map_store_error)
    }

    fn export_encrypted(
        &mut self,
        id: &ObjectId,
        output: &mut dyn Write,
    ) -> Result<u64, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .export_encrypted(id, output)
            .map_err(map_store_error)
    }

    fn commit_replicated_snapshot(
        &mut self,
        verified: ReplicationVerifiedHead,
        request: ReplicationCommitRequest,
        guard: &mut dyn VaultPublicationGuard,
    ) -> Result<ReplicationCommittedHead, RepositoryPortError> {
        let mut guard = StorePublicationGuard(guard);
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .commit_replicated_snapshot(verified.0, request.0, &mut guard)
            .map(ReplicationCommittedHead)
            .map_err(map_store_error)
    }

    fn commit_reconciled_snapshot(
        &mut self,
        verified_remote: ReplicationVerifiedHead,
        request: ReplicationCommitRequest,
        guard: &mut dyn VaultPublicationGuard,
    ) -> Result<ReplicationPendingPublication, RepositoryPortError> {
        let mut guard = StorePublicationGuard(guard);
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .commit_reconciled_snapshot(verified_remote.0, request.0, &mut guard)
            .map(ReplicationPendingPublication)
            .map_err(map_store_error)
    }

    fn confirm_reconciled_publication(
        &mut self,
        pending: ReplicationPendingPublication,
        verified_readback: ReplicationVerifiedHead,
    ) -> Result<ReplicationCommittedHead, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .confirm_reconciled_publication(pending.0, verified_readback.0)
            .map(ReplicationCommittedHead)
            .map_err(map_store_error)
    }

    fn accept_current_verified(
        &mut self,
        verified: ReplicationVerifiedHead,
    ) -> Result<ReplicationCommittedHead, RepositoryPortError> {
        self.lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .accept_current_verified(verified.0)
            .map(ReplicationCommittedHead)
            .map_err(map_store_error)
    }

    fn record_trusted_remote(
        &mut self,
        committed: ReplicationCommittedHead,
    ) -> Result<TrustedRemoteRecordOutcome, RepositoryPortError> {
        let pending = self
            .lease
            .as_mut()
            .ok_or(RepositoryPortError::Locked)?
            .record_trusted_remote(committed.0)
            .map_err(map_store_error)?;
        if let Some(pending) = pending {
            self.pending_freshness = Some(pending);
            Ok(TrustedRemoteRecordOutcome::FreshnessAcknowledgementRequired)
        } else {
            Ok(TrustedRemoteRecordOutcome::Recorded)
        }
    }

    fn into_freshness_acknowledgement(
        mut self: Box<Self>,
    ) -> Result<Box<dyn PendingFreshnessAction>, RepositoryPortError> {
        let pending = self
            .pending_freshness
            .take()
            .ok_or(RepositoryPortError::InvalidInput)?;
        let view = FreshnessAcknowledgementView::new(pending.authenticated_snapshot());
        let lease = self.lease.take().ok_or(RepositoryPortError::Locked)?;
        Ok(Box::new(StorePendingFreshnessAction {
            view,
            lease: Some(lease),
            pending: Some(pending),
            operation_binding: Arc::clone(&self.operation_binding),
        }))
    }

    fn finish(mut self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.lease
            .take()
            .ok_or(RepositoryPortError::Locked)?
            .finish()
            .map_err(map_store_error)
    }
}

struct StorePendingFreshnessAction {
    view: FreshnessAcknowledgementView,
    lease: Option<Box<dyn notecrypt_store::ReplicationLease>>,
    pending: Option<notecrypt_store::PendingUnprovableRemote>,
    operation_binding: Arc<RepositoryCancellation>,
}

#[cfg(test)]
pub(crate) fn production_freshness_action_for_test(
    fixture: notecrypt_store::replication_test_support::PendingFreshnessFixture,
    operation_binding: Arc<RepositoryCancellation>,
) -> (Box<dyn PendingFreshnessAction>, SnapshotId) {
    let (lease, pending, snapshot) = fixture.into_parts();
    let view = FreshnessAcknowledgementView::new(pending.authenticated_snapshot());
    (
        Box::new(StorePendingFreshnessAction {
            view,
            lease: Some(lease),
            pending: Some(pending),
            operation_binding,
        }),
        snapshot,
    )
}

impl PendingFreshnessAction for StorePendingFreshnessAction {
    fn operation_cancellation(&self) -> &RepositoryCancellation {
        &self.operation_binding
    }

    fn view(&self) -> FreshnessAcknowledgementView {
        self.view
    }

    fn acknowledge(mut self: Box<Self>) -> Result<(), RepositoryPortError> {
        let pending = self
            .pending
            .take()
            .ok_or(RepositoryPortError::InvalidInput)?;
        let mut lease = self.lease.take().ok_or(RepositoryPortError::Locked)?;
        match lease
            .acknowledge_unprovable_remote(pending)
            .map_err(map_store_error)
        {
            Ok(()) => lease.finish().map_err(map_store_error),
            Err(primary) => {
                lease.cancel();
                match lease.finish().map_err(map_store_error) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(cleanup),
                }
            }
        }
    }

    fn abort(mut self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.pending.take();
        if let Some(lease) = self.lease.take() {
            lease.cancel();
            return match lease.finish() {
                Ok(()) | Err(StoreError::Cancelled) => Ok(()),
                Err(error) => Err(map_store_error(error)),
            };
        }
        Ok(())
    }
}

struct StoreReplicationImport<'a> {
    import: Option<Box<dyn notecrypt_store::QuarantineImport + 'a>>,
}

impl Write for StoreReplicationImport<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.import
            .as_mut()
            .ok_or_else(|| std::io::Error::other("replication import is closed"))?
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.import
            .as_mut()
            .ok_or_else(|| std::io::Error::other("replication import is closed"))?
            .flush()
    }
}

impl ReplicationImport for StoreReplicationImport<'_> {
    fn finish(mut self: Box<Self>) -> Result<ReplicationImportedObject, RepositoryPortError> {
        self.import
            .take()
            .ok_or(RepositoryPortError::Locked)?
            .finish()
            .map(ReplicationImportedObject)
            .map_err(map_store_error)
    }
}

impl UnlockedVaultCapability for StoreUnlockedVault {
    fn revocation_handle(&self) -> Arc<dyn VaultRootRevocation> {
        Arc::new(StoreVaultRootRevocation(self.revocation.clone()))
    }

    fn acquire_local_lease(
        &self,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn LocalVaultLease>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let lease = state
            .unlocked
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .acquire_lease()
            .map_err(map_store_error)?;
        if !self.accepting.load(Ordering::Acquire) {
            drop(lease);
            return Err(RepositoryPortError::Locked);
        }
        Ok(Box::new(StoreLocalVaultLease {
            lease: Some(lease),
            cancel: cancellation.shared_atomic(),
        }))
    }

    fn acquire_replication_lease(
        &self,
        backend: ReplicationLimitProfile,
        operation: ReplicationLimitProfile,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn ReplicationVaultLease>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let lease = state
            .unlocked
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .acquire_replication_lease_with_cancellation(
                backend.into_store(),
                operation.into_store(),
                Some(Arc::new(StoreReplicationCancellationProbe(
                    cancellation.shared_atomic(),
                ))),
            )
            .map_err(map_store_error)?;
        if !self.accepting.load(Ordering::Acquire) {
            lease.cancel();
            let _ = lease.finish();
            return Err(RepositoryPortError::Locked);
        }
        let operation_binding = Arc::clone(&cancellation);
        let lease_cancellation =
            Arc::new(StoreReplicationCancellation(lease.cancellation_handle()));
        Ok(Box::new(StoreReplicationVaultLease {
            lease: Some(lease),
            cancellation: lease_cancellation,
            operation_binding,
            pending_freshness: None,
        }))
    }

    fn begin_compromise_rekey(
        &self,
        request: BeginCompromiseRekey,
        cancel: &RepositoryCancellation,
    ) -> Result<PreparedCompromiseRekey, RepositoryPortError> {
        if cancel.is_cancelled() || !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Cancelled);
        }
        let (target_id, policy, risk) = request.into_parts();
        if policy == RecoverySecretPolicy::CustomV1
            && risk.as_ref().is_none_or(|risk| risk.version() != 1)
        {
            return Err(RepositoryPortError::InvalidInput);
        }
        let target = self.targets.resolve(target_id)?;
        let source = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .unlocked
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .acquire_compromise_rekey_source()
            .map_err(map_store_error)?;
        if cancel.is_cancelled() || !self.accepting.load(Ordering::Acquire) {
            drop(source);
            return Err(RepositoryPortError::Cancelled);
        }
        let action = Box::new(StorePendingCompromiseAction {
            source_store: Arc::clone(&self.source_store),
            source: Some(source),
            target,
            cancellation: Arc::new(AtomicBool::new(false)),
        });
        match policy {
            RecoverySecretPolicy::Generated => Ok(PreparedCompromiseRekey::new(
                generate_recovery_input()?,
                action,
            )),
            RecoverySecretPolicy::CustomV1 => Ok(PreparedCompromiseRekey::custom(action)),
        }
    }

    fn register_workspace(
        &self,
    ) -> Result<Box<dyn RegisteredWorkspaceCapability>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let registered = state
            .unlocked
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .register_cleanup_workspace()
            .map_err(map_store_error)?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let id = crate::WorkspaceId::from_store(registered.workspace_id())
            .map_err(map_host_repository_error)?;
        Ok(Box::new(StoreRegisteredWorkspace {
            id,
            inner: registered,
        }))
    }

    fn activate_workspace(
        &self,
        registered: &mut dyn RegisteredWorkspaceCapability,
    ) -> Result<Box<dyn ActiveWorkspaceCapability>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let registered = registered
            .as_any_mut()
            .downcast_mut::<StoreRegisteredWorkspace>()
            .ok_or(RepositoryPortError::InvalidInput)?;
        let active = state
            .unlocked
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .activate_cleanup_workspace(&mut registered.inner)
            .map_err(map_store_error)?;
        let id = crate::WorkspaceId::from_store(active.workspace_id())
            .map_err(map_host_repository_error)?;
        Ok(Box::new(StoreActiveWorkspace { id, inner: active }))
    }

    fn authenticated_workspaces(
        &self,
    ) -> Result<Vec<AuthenticatedWorkspaceCapability>, RepositoryPortError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let records = state
            .unlocked
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .authenticated_cleanup_workspaces()
            .map_err(map_store_error)?;
        let mut bounded = try_reserve_repository_vec(records.len(), MAX_ACTIVE_WORKSPACES)?;
        for record in records {
            let capability = match record.state() {
                notecrypt_store::CleanupWorkspaceState::Registered => {
                    let registered = record.into_registered().map_err(map_store_error)?;
                    let id = crate::WorkspaceId::from_store(registered.workspace_id())
                        .map_err(map_host_repository_error)?;
                    AuthenticatedWorkspaceCapability::Registered(Box::new(
                        StoreRegisteredWorkspace {
                            id,
                            inner: registered,
                        },
                    ))
                }
                notecrypt_store::CleanupWorkspaceState::Active => {
                    let active = record.into_active().map_err(map_store_error)?;
                    let id = crate::WorkspaceId::from_store(active.workspace_id())
                        .map_err(map_host_repository_error)?;
                    AuthenticatedWorkspaceCapability::Active(Box::new(StoreActiveWorkspace {
                        id,
                        inner: active,
                    }))
                }
            };
            bounded.push(capability);
        }
        Ok(bounded)
    }

    fn unregister_absent_workspace(
        &self,
        active: &mut dyn ActiveWorkspaceCapability,
    ) -> Result<(), RepositoryPortError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let unlocked = state.unlocked.as_ref().ok_or(RepositoryPortError::Locked)?;
        let active = active
            .as_any_mut()
            .downcast_mut::<StoreActiveWorkspace>()
            .ok_or(RepositoryPortError::InvalidInput)?;
        let mut proof = unlocked
            .acquire_cleanup_workspace_absence(&active.inner)
            .map_err(map_store_error)?;
        unlocked
            .unregister_cleanup_workspace(&mut active.inner, &mut proof)
            .map_err(map_store_error)
    }

    fn unregister_removed_workspace(
        &self,
        active: &mut dyn ActiveWorkspaceCapability,
        guard: Box<dyn crate::WorkspaceAbsenceGuard>,
    ) -> Result<(), RepositoryPortError> {
        self.absence.stage(active.workspace_id(), guard)?;
        self.unregister_absent_workspace(active)
    }

    fn close(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.accepting.store(false, Ordering::Release);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let unlocked = state.unlocked.take().ok_or(RepositoryPortError::Locked)?;
        unlocked.begin_close().map_err(map_store_error)?;
        unlocked.close().map_err(map_store_error)
    }
}

fn map_store_error(error: StoreError) -> RepositoryPortError {
    match error {
        StoreError::AuthenticationFailed
        | StoreError::LocalStateAuthenticationFailed
        | StoreError::MalformedObject => RepositoryPortError::IntegrityFailed,
        StoreError::RollbackDetected => RepositoryPortError::StaleCapability,
        StoreError::Cancelled => RepositoryPortError::Cancelled,
        StoreError::Locked => RepositoryPortError::Locked,
        StoreError::InvalidCapability => RepositoryPortError::StaleCapability,
        StoreError::Busy => RepositoryPortError::Busy,
        StoreError::LimitExceeded => RepositoryPortError::CapacityExceeded,
        StoreError::AllocationFailed => RepositoryPortError::AllocationFailed,
        StoreError::CleanupAfterFailure { .. } => RepositoryPortError::CleanupRequired,
        StoreError::TimedOut => RepositoryPortError::TimedOut,
        StoreError::DurabilityPending => RepositoryPortError::DurabilityPending,
        StoreError::NotFound => RepositoryPortError::NotFound,
        StoreError::RandomSource => RepositoryPortError::EntropyUnavailable,
        StoreError::IdentityCollision | StoreError::SessionGenerationExhausted => {
            RepositoryPortError::IdentifierExhausted
        }
        StoreError::FilesystemObjectRejected | StoreError::ImmutableObjectConflict => {
            RepositoryPortError::InvalidInput
        }
        StoreError::InvalidInput => RepositoryPortError::InvalidInput,
        _ => RepositoryPortError::PlatformFailure,
    }
}

fn map_repository_publication_error(error: RepositoryPortError) -> StoreError {
    match error {
        RepositoryPortError::AllocationFailed => StoreError::AllocationFailed,
        RepositoryPortError::CapacityExceeded => StoreError::LimitExceeded,
        RepositoryPortError::Cancelled => StoreError::Cancelled,
        RepositoryPortError::Locked => StoreError::Locked,
        RepositoryPortError::Busy => StoreError::Busy,
        RepositoryPortError::TimedOut => StoreError::TimedOut,
        RepositoryPortError::PlatformFailure => {
            StoreError::Io(std::io::Error::other("external publication guard failed"))
        }
        _ => StoreError::InvalidCapability,
    }
}

fn map_workspace_id_store_error(error: crate::HostPortError) -> StoreError {
    match map_host_repository_error(error) {
        RepositoryPortError::AllocationFailed => StoreError::AllocationFailed,
        RepositoryPortError::CapacityExceeded => StoreError::LimitExceeded,
        _ => StoreError::InvalidCapability,
    }
}

fn map_core_repository_error(error: notecrypt_core::CoreError) -> RepositoryPortError {
    match error {
        notecrypt_core::CoreError::AllocationFailed => RepositoryPortError::AllocationFailed,
        notecrypt_core::CoreError::CapacityExceeded => RepositoryPortError::CapacityExceeded,
        _ => RepositoryPortError::InvalidInput,
    }
}

pub(crate) fn map_host_repository_error(error: crate::HostPortError) -> RepositoryPortError {
    match error {
        crate::HostPortError::AllocationFailed => RepositoryPortError::AllocationFailed,
        crate::HostPortError::CapacityExceeded => RepositoryPortError::CapacityExceeded,
        _ => RepositoryPortError::InvalidInput,
    }
}

fn map_unlock_error(error: StoreError) -> RepositoryPortError {
    match error {
        StoreError::AuthenticationFailed | StoreError::LocalStateAuthenticationFailed => {
            RepositoryPortError::WrongSecret
        }
        other => map_store_error(other),
    }
}

/// Dependencies needed to construct one unlock-aware service runtime.
pub struct SessionComponents {
    pub(crate) repository: Arc<dyn VaultRepository>,
    pub(crate) workspace: Arc<dyn WorkspaceProvider>,
    pub(crate) external_files: Arc<dyn crate::ExternalFileProvider>,
    pub(crate) clock: Arc<dyn MonotonicClock>,
    pub(crate) policy: SessionPolicy,
}

pub(crate) struct RootCapabilitySlot {
    accepting: AtomicBool,
    revocation: Arc<dyn VaultRootRevocation>,
    capability: Mutex<Option<Box<dyn UnlockedVaultCapability>>>,
}

impl RootCapabilitySlot {
    fn try_new(
        capability: Box<dyn UnlockedVaultCapability>,
    ) -> Result<Self, Box<dyn UnlockedVaultCapability>> {
        let revocation = match catch_unwind(AssertUnwindSafe(|| capability.revocation_handle())) {
            Ok(revocation) => revocation,
            Err(_) => return Err(capability),
        };
        Ok(Self {
            accepting: AtomicBool::new(true),
            revocation,
            capability: Mutex::new(Some(capability)),
        })
    }

    pub(crate) fn begin_close(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    pub(crate) fn begin_adapter_close(&self) {
        self.revocation.revoke();
    }

    pub(crate) fn close(&self) -> Result<(), RepositoryPortError> {
        let capability = self
            .capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or(RepositoryPortError::Locked)?;
        capability.close()
    }

    fn acquire_local(
        &self,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn LocalVaultLease>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let lease = self
            .capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .acquire_local_lease(cancellation)?;
        if !self.accepting.load(Ordering::Acquire) {
            lease.cancel();
            let _ = lease.finish();
            return Err(RepositoryPortError::Locked);
        }
        Ok(lease)
    }

    fn acquire_replication(
        &self,
        backend: ReplicationLimitProfile,
        operation: ReplicationLimitProfile,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn ReplicationVaultLease>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let lease = self
            .capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .acquire_replication_lease(backend, operation, cancellation)?;
        if !self.accepting.load(Ordering::Acquire) {
            lease.cancel();
            let _ = lease.finish();
            return Err(RepositoryPortError::Locked);
        }
        Ok(lease)
    }

    fn begin_compromise_rekey(
        &self,
        request: BeginCompromiseRekey,
        cancel: &RepositoryCancellation,
    ) -> Result<PreparedCompromiseRekey, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        self.capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .begin_compromise_rekey(request, cancel)
    }

    fn reconcile_authenticated_workspaces(&self) -> Result<(), RepositoryPortError> {
        let capability = self
            .capability
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let capability = capability.as_ref().ok_or(RepositoryPortError::Locked)?;
        let records = try_rehome_repository_vec(
            capability.authenticated_workspaces()?,
            MAX_ACTIVE_WORKSPACES,
        )?;
        for record in records {
            let mut active = match record {
                AuthenticatedWorkspaceCapability::Registered(registered) => {
                    let mut registered = registered;
                    let active = capability.activate_workspace(&mut *registered)?;
                    if active.workspace_id().child_name() != registered.workspace_id().child_name()
                    {
                        return Err(RepositoryPortError::IntegrityFailed);
                    }
                    active
                }
                AuthenticatedWorkspaceCapability::Active(active) => active,
            };
            match capability.unregister_absent_workspace(&mut *active) {
                Ok(()) | Err(RepositoryPortError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn register_workspace(
        &self,
    ) -> Result<Box<dyn RegisteredWorkspaceCapability>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let registered = self
            .capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .register_workspace()?;
        if !self.accepting.load(Ordering::Acquire) {
            drop(registered);
            return Err(RepositoryPortError::Locked);
        }
        Ok(registered)
    }

    fn activate_workspace(
        &self,
        registered: &mut dyn RegisteredWorkspaceCapability,
    ) -> Result<Box<dyn ActiveWorkspaceCapability>, RepositoryPortError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RepositoryPortError::Locked);
        }
        let active = self
            .capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .activate_workspace(registered)?;
        if !self.accepting.load(Ordering::Acquire) {
            drop(active);
            return Err(RepositoryPortError::Locked);
        }
        Ok(active)
    }

    fn unregister_removed_workspace(
        &self,
        active: &mut dyn ActiveWorkspaceCapability,
        guard: Box<dyn crate::WorkspaceAbsenceGuard>,
    ) -> Result<(), RepositoryPortError> {
        self.capability
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .ok_or(RepositoryPortError::Locked)?
            .unregister_removed_workspace(active, guard)
    }
}

impl SessionComponents {
    pub fn new(
        repository: Arc<dyn VaultRepository>,
        workspace: Arc<dyn WorkspaceProvider>,
        clock: Arc<dyn MonotonicClock>,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            repository,
            workspace,
            external_files: Arc::new(crate::ports::UnavailableExternalFiles),
            clock,
            policy,
        }
    }

    /// Installs the trusted adapter that opens explicit user-selected files.
    #[must_use]
    pub fn with_external_files(
        mut self,
        external_files: Arc<dyn crate::ExternalFileProvider>,
    ) -> Self {
        self.external_files = external_files;
        self
    }
}

struct SessionData {
    state: SessionState,
    epoch: u64,
    last_observed: Duration,
    inactivity_deadline: Option<Duration>,
    absolute_deadline: Option<Duration>,
    unlocked: Option<Arc<RootCapabilitySlot>>,
    provisional_unlock: Option<Arc<RootCapabilitySlot>>,
    unlock_attempt: Option<Arc<RepositoryCancellation>>,
    cleanup_owner: bool,
    inactivity_warnings: u32,
    absolute_warnings: u32,
    expired: bool,
    cleanup_required: bool,
}

pub(crate) struct SessionObservation {
    pub(crate) expired: bool,
    pub(crate) warnings: Vec<SessionEvent>,
    pub(crate) next_wait: Option<Duration>,
}

pub(crate) struct SessionManager {
    repository: Arc<dyn VaultRepository>,
    vault_id: Mutex<Option<VaultId>>,
    workspace: Arc<dyn WorkspaceProvider>,
    external_files: Arc<dyn crate::ExternalFileProvider>,
    clock: Arc<dyn MonotonicClock>,
    policy: SessionPolicy,
    data: Mutex<SessionData>,
    clock_sequence: AtomicUsize,
    clock_observed: Mutex<(usize, Duration)>,
    workspaces: Mutex<HashMap<String, Arc<TrackedWorkspace>>>,
    workspace_attempts: AtomicUsize,
    changed: Condvar,
}

const MAX_ACTIVE_WORKSPACES: usize = 1_024;
const MAX_REPLICATION_OBSERVATION_BYTES: usize = 64 * 1024;
const MAX_REPLICATION_COMMIT_BYTES: usize = 64 * 1024;

fn try_rehome_repository_vec<T>(
    source: Vec<T>,
    maximum: usize,
) -> Result<Vec<T>, RepositoryPortError> {
    if source.len() > maximum {
        return Err(RepositoryPortError::CapacityExceeded);
    }
    let mut retained = try_reserve_repository_vec(source.len(), maximum)?;
    retained.extend(source);
    Ok(retained)
}

fn try_reserve_repository_vec<T>(
    length: usize,
    maximum: usize,
) -> Result<Vec<T>, RepositoryPortError> {
    if length > maximum {
        return Err(RepositoryPortError::CapacityExceeded);
    }
    if crate::ports::allocation_failure_injected_for_test() {
        return Err(RepositoryPortError::AllocationFailed);
    }
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(length)
        .map_err(|_| RepositoryPortError::AllocationFailed)?;
    Ok(retained)
}

struct TrackedWorkspace {
    generation: u64,
    value: Mutex<Option<(crate::WorkspaceLease, Box<dyn ActiveWorkspaceCapability>)>>,
    paths: Mutex<crate::WorkspacePathRegistry>,
}

enum WorkspaceCreateRequest {
    Target(crate::TargetWorkspaceRequest),
    WholeVault(crate::VaultWorkspaceRequest),
}

/// Linear handle to one service-tracked plaintext workspace.
pub struct WorkspaceSession {
    manager: std::sync::Weak<SessionManager>,
    record: Arc<TrackedWorkspace>,
}

struct WorkspaceAttemptGuard<'a>(&'a AtomicUsize);

impl Drop for WorkspaceAttemptGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SessionManager {
    fn close_unwrapped_capability(unlocked: Box<dyn UnlockedVaultCapability>) -> bool {
        let revocation_failed =
            match catch_unwind(AssertUnwindSafe(|| unlocked.revocation_handle())) {
                Ok(revocation) => catch_unwind(AssertUnwindSafe(|| revocation.revoke())).is_err(),
                Err(_) => true,
            };
        let close_failed = !matches!(
            catch_unwind(AssertUnwindSafe(|| unlocked.close())),
            Ok(Ok(()))
        );
        revocation_failed || close_failed
    }

    fn begin_workspace_attempt(&self) -> Result<WorkspaceAttemptGuard<'_>, ServiceError> {
        self.workspace_attempts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |attempts| {
                (attempts < MAX_ACTIVE_WORKSPACES).then(|| attempts + 1)
            })
            .map_err(|_| ServiceError::CapacityExceeded)?;
        Ok(WorkspaceAttemptGuard(&self.workspace_attempts))
    }

    pub(crate) fn owns_workspace(&self, workspace: &WorkspaceSession, generation: u64) -> bool {
        workspace.record.generation == generation
            && workspace
                .manager
                .upgrade()
                .is_some_and(|manager| std::ptr::eq(manager.as_ref(), self))
    }

    pub(crate) fn commit_stable_revision(
        &self,
        workspace_session: &WorkspaceSession,
        relative_path: &crate::LogicalWorkspacePath,
        expected_generation: u64,
        lease: &mut dyn LocalVaultLease,
        request: LocalStreamRevisionRequest,
    ) -> Result<LocalSnapshot, ServiceError> {
        if self.current_generation() != Some(workspace_session.record.generation) {
            return Err(ServiceError::StaleCapability);
        }
        workspace_session
            .record
            .paths
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(relative_path)
            .map_err(map_host_error)?;
        let mut tracked = workspace_session
            .record
            .value
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (workspace, _) = tracked.as_mut().ok_or(ServiceError::StaleCapability)?;
        let opened = catch_unwind(AssertUnwindSafe(|| {
            self.workspace
                .open_stable_source(workspace, relative_path, expected_generation)
        }))
        .map_err(|_| ServiceError::ExecutorFailed)?
        .map_err(map_host_error)?;
        if self.current_generation() != Some(workspace_session.record.generation) {
            return Err(ServiceError::StaleCapability);
        }
        let (mut reader, token) = opened.into_parts();
        let mut guard =
            crate::StableSourcePublicationGuard::new(Arc::clone(&self.workspace), workspace, token);
        lease
            .commit_stable_revision(StableRevisionCommit::new(
                request,
                reader.as_mut(),
                &mut guard,
            ))
            .map_err(map_repository_error)
    }

    pub(crate) fn repository(&self) -> &Arc<dyn VaultRepository> {
        &self.repository
    }

    pub(crate) fn current_vault_id(&self) -> Option<VaultId> {
        *self
            .vault_id
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn begin_compromise_rekey(
        &self,
        generation: u64,
        request: BeginCompromiseRekey,
        cancel: &RepositoryCancellation,
    ) -> Result<PreparedCompromiseRekey, RepositoryPortError> {
        let root = {
            let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if data.state != SessionState::Unlocked || data.epoch != generation {
                return Err(RepositoryPortError::Locked);
            }
            Arc::clone(data.unlocked.as_ref().ok_or(RepositoryPortError::Locked)?)
        };
        root.begin_compromise_rekey(request, cancel)
    }

    pub(crate) const fn final_save_grace(&self) -> Duration {
        self.policy.final_save_grace
    }
    pub(crate) fn new(components: SessionComponents) -> Result<Arc<Self>, ServiceError> {
        let vault_id = catch_unwind(AssertUnwindSafe(|| {
            components.repository.current_vault_id()
        }))
        .map_err(|_| ServiceError::ExecutorFailed)?
        .map_err(map_repository_error)?;
        let now = catch_port_panic(|| components.clock.elapsed())?;
        let mut workspaces = HashMap::new();
        workspaces
            .try_reserve(MAX_ACTIVE_WORKSPACES)
            .map_err(|_| ServiceError::AllocationFailed)?;
        Ok(Arc::new(Self {
            repository: components.repository,
            vault_id: Mutex::new(vault_id),
            workspace: components.workspace,
            external_files: components.external_files,
            clock: components.clock,
            policy: components.policy,
            data: Mutex::new(SessionData {
                state: SessionState::Locked,
                epoch: 0,
                last_observed: now,
                inactivity_deadline: None,
                absolute_deadline: None,
                unlocked: None,
                provisional_unlock: None,
                unlock_attempt: None,
                cleanup_owner: false,
                inactivity_warnings: 0,
                absolute_warnings: 0,
                expired: false,
                cleanup_required: false,
            }),
            clock_sequence: AtomicUsize::new(0),
            clock_observed: Mutex::new((0, now)),
            workspaces: Mutex::new(workspaces),
            workspace_attempts: AtomicUsize::new(0),
            changed: Condvar::new(),
        }))
    }

    pub(crate) fn state(&self) -> SessionState {
        self.data
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .state
    }

    pub(crate) fn current_generation(&self) -> Option<u64> {
        let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        (data.state == SessionState::Unlocked).then_some(data.epoch)
    }

    pub(crate) fn binding_epoch(&self) -> u64 {
        self.data
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .epoch
    }

    pub(crate) fn mark_cleanup_required(&self) {
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        data.cleanup_required = true;
        if let Some(attempt) = &data.unlock_attempt {
            attempt.cancel();
        }
        if data.state != SessionState::Unlocked {
            data.state = SessionState::CleanupRequired;
        }
        self.changed.notify_all();
    }

    pub(crate) fn acquire_local(
        &self,
        generation: u64,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn LocalVaultLease>, ServiceError> {
        let slot = {
            let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if data.state != SessionState::Unlocked || data.epoch != generation {
                return Err(ServiceError::Locked);
            }
            Arc::clone(data.unlocked.as_ref().ok_or(ServiceError::Locked)?)
        };
        let lease = slot
            .acquire_local(cancellation)
            .map_err(map_repository_error)?;
        if self.current_generation() != Some(generation) {
            lease.cancel();
            let _ = lease.finish();
            return Err(ServiceError::Locked);
        }
        Ok(lease)
    }

    pub(crate) fn open_import(
        &self,
        selection: crate::ImportSelection,
    ) -> Result<crate::OpenedImport, ServiceError> {
        catch_unwind(AssertUnwindSafe(|| {
            self.external_files.open_import(selection)
        }))
        .map_err(|_| ServiceError::ExecutorFailed)?
        .map_err(map_external_host_error)
    }

    pub(crate) fn begin_export(
        &self,
        selection: crate::ExportSelection,
    ) -> Result<crate::OpenedExport, ServiceError> {
        catch_unwind(AssertUnwindSafe(|| {
            self.external_files.begin_export(selection)
        }))
        .map_err(|_| ServiceError::ExecutorFailed)?
        .map_err(map_external_host_error)
    }

    pub(crate) fn acquire_replication(
        &self,
        generation: u64,
        backend: ReplicationLimitProfile,
        operation: ReplicationLimitProfile,
        cancellation: Arc<RepositoryCancellation>,
    ) -> Result<Box<dyn ReplicationVaultLease>, ServiceError> {
        let slot = {
            let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if data.state != SessionState::Unlocked || data.epoch != generation {
                return Err(ServiceError::Locked);
            }
            Arc::clone(data.unlocked.as_ref().ok_or(ServiceError::Locked)?)
        };
        let lease = slot
            .acquire_replication(backend, operation, cancellation)
            .map_err(map_repository_error)?;
        if self.current_generation() != Some(generation) {
            lease.cancel();
            let _ = lease.finish();
            return Err(ServiceError::Locked);
        }
        Ok(lease)
    }

    pub(crate) fn create_workspace(
        self: &Arc<Self>,
        generation: u64,
        mode: crate::WorkspaceMode,
        repository_root: std::path::PathBuf,
    ) -> Result<WorkspaceSession, ServiceError> {
        let root = {
            let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if data.state != SessionState::Unlocked || data.epoch != generation {
                return Err(ServiceError::Locked);
            }
            Arc::clone(data.unlocked.as_ref().ok_or(ServiceError::Locked)?)
        };
        let vault_id = self
            .vault_id
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .ok_or(ServiceError::Locked)?;
        let _attempt = self.begin_workspace_attempt()?;
        let paths = crate::WorkspacePathRegistry::new(crate::MAX_WORKSPACE_PATHS)
            .map_err(map_host_error)?;
        {
            let workspaces = self
                .workspaces
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if workspaces.len() == MAX_ACTIVE_WORKSPACES {
                return Err(ServiceError::CapacityExceeded);
            }
        }
        let mut registered = root.register_workspace().map_err(map_repository_error)?;
        let id = match registered
            .workspace_id()
            .try_duplicate()
            .map_err(map_host_error)
        {
            Ok(id) => id,
            Err(_) => {
                self.mark_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        let key = match crate::ports::try_copy_str(id.child_name(), 32).map_err(map_host_error) {
            Ok(key) => key,
            Err(_) => {
                self.mark_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        let request_id = match id.try_duplicate().map_err(map_host_error) {
            Ok(id) => id,
            Err(_) => {
                self.mark_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        let request = match mode {
            crate::WorkspaceMode::Targeted => {
                crate::TargetWorkspaceRequest::new(request_id, vault_id, repository_root)
                    .map(WorkspaceCreateRequest::Target)
            }
            crate::WorkspaceMode::WholeVault => {
                crate::VaultWorkspaceRequest::new(request_id, vault_id, repository_root)
                    .map(WorkspaceCreateRequest::WholeVault)
            }
        };
        let request = match request {
            Ok(request) => request,
            Err(_) => {
                if self
                    .rollback_registered_workspace(&root, &mut *registered, &id, None)
                    .is_err()
                {
                    self.mark_cleanup_required();
                    return Err(ServiceError::CleanupRequired);
                }
                return Err(ServiceError::ExecutorFailed);
            }
        };
        let workspace = catch_unwind(AssertUnwindSafe(|| match request {
            WorkspaceCreateRequest::Target(request) => self.workspace.create_target(request),
            WorkspaceCreateRequest::WholeVault(request) => {
                self.workspace.create_whole_vault(request)
            }
        }))
        .map_err(|_| ServiceError::CleanupRequired)
        .and_then(|result| result.map_err(map_host_error));
        let workspace = match workspace {
            Ok(workspace) => workspace,
            Err(primary) => {
                if self
                    .rollback_registered_workspace(&root, &mut *registered, &id, None)
                    .is_err()
                {
                    self.mark_cleanup_required();
                    return Err(ServiceError::CleanupRequired);
                }
                return Err(primary);
            }
        };
        if workspace.id().child_name() != id.child_name() || workspace.mode() != mode {
            let removed_wrong_workspace = catch_unwind(AssertUnwindSafe(|| {
                self.workspace.remove_workspace(workspace)
            }))
            .is_ok_and(|result| result.is_ok());
            let rolled_back_registered = self
                .rollback_registered_workspace(&root, &mut *registered, &id, None)
                .is_ok();
            if !removed_wrong_workspace || !rolled_back_registered {
                self.mark_cleanup_required();
            }
            return Err(ServiceError::CleanupRequired);
        }
        if self.current_generation() != Some(generation) {
            if self
                .rollback_registered_workspace(&root, &mut *registered, &id, Some(workspace))
                .is_err()
            {
                self.mark_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
            return Err(ServiceError::Cancelled);
        }
        let active = match root.activate_workspace(&mut *registered) {
            Ok(active) => active,
            Err(_) => {
                if self
                    .rollback_registered_workspace(&root, &mut *registered, &id, Some(workspace))
                    .is_err()
                {
                    self.mark_cleanup_required();
                }
                return Err(ServiceError::CleanupRequired);
            }
        };
        if active.workspace_id().child_name() != id.child_name() {
            let removed = catch_unwind(AssertUnwindSafe(|| {
                self.workspace.remove_workspace(workspace)
            }))
            .is_ok_and(|result| result.is_ok());
            drop(active);
            self.mark_cleanup_required();
            let _ = removed;
            return Err(ServiceError::CleanupRequired);
        }
        let record = Arc::new(TrackedWorkspace {
            generation,
            value: Mutex::new(Some((workspace, active))),
            paths: Mutex::new(paths),
        });
        // Publish the active workspace while holding the same session lock that
        // begin_lock uses to close the generation. Lock cleanup can therefore
        // never scan an empty registry after activation and then miss a late
        // successful handoff.
        let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        let mut workspaces = self
            .workspaces
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if data.state != SessionState::Unlocked || data.epoch != generation {
            drop(workspaces);
            drop(data);
            if self.rollback_active_workspace(&root, &record).is_err() {
                self.mark_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
            return Err(ServiceError::Cancelled);
        }
        if workspaces.len() == MAX_ACTIVE_WORKSPACES || workspaces.contains_key(&key) {
            drop(workspaces);
            drop(data);
            self.remove_workspace_record(&record)?;
            return Err(ServiceError::Busy);
        }
        workspaces.insert(key, Arc::clone(&record));
        drop(workspaces);
        drop(data);
        Ok(WorkspaceSession {
            manager: Arc::downgrade(self),
            record,
        })
    }

    fn rollback_registered_workspace(
        &self,
        root: &Arc<RootCapabilitySlot>,
        registered: &mut dyn RegisteredWorkspaceCapability,
        id: &crate::WorkspaceId,
        workspace: Option<crate::WorkspaceLease>,
    ) -> Result<(), ServiceError> {
        let guard = match workspace {
            Some(workspace) => catch_unwind(AssertUnwindSafe(|| {
                self.workspace.remove_workspace(workspace)
            }))
            .map_err(|_| ServiceError::CleanupRequired)?
            .map_err(|_| ServiceError::CleanupRequired)?,
            None => catch_unwind(AssertUnwindSafe(|| {
                self.workspace.acquire_verified_absence(id)
            }))
            .map_err(|_| ServiceError::CleanupRequired)?
            .map_err(|_| ServiceError::CleanupRequired)?,
        };
        let mut active = root
            .activate_workspace(registered)
            .map_err(|_| ServiceError::CleanupRequired)?;
        if registered.workspace_id().child_name() != id.child_name()
            || active.workspace_id().child_name() != id.child_name()
        {
            return Err(ServiceError::CleanupRequired);
        }
        root.unregister_removed_workspace(&mut *active, guard)
            .map_err(|_| ServiceError::CleanupRequired)
    }

    fn rollback_active_workspace(
        &self,
        root: &Arc<RootCapabilitySlot>,
        record: &Arc<TrackedWorkspace>,
    ) -> Result<(), ServiceError> {
        let (workspace, mut active) = record
            .value
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or(ServiceError::CleanupRequired)?;
        let guard = catch_unwind(AssertUnwindSafe(|| {
            self.workspace.remove_workspace(workspace)
        }))
        .map_err(|_| ServiceError::CleanupRequired)?
        .map_err(|_| ServiceError::CleanupRequired)?;
        root.unregister_removed_workspace(&mut *active, guard)
            .map_err(|_| ServiceError::CleanupRequired)
    }

    pub(crate) fn remove_workspace(
        &self,
        workspace: WorkspaceSession,
        generation: u64,
    ) -> Result<(), ServiceError> {
        if !self.owns_workspace(&workspace, generation)
            || self.current_generation() != Some(generation)
        {
            return Err(ServiceError::StaleCapability);
        }
        let _attempt = self.begin_workspace_attempt()?;
        self.remove_workspace_record(&workspace.record)
    }

    fn remove_workspace_record(&self, record: &Arc<TrackedWorkspace>) -> Result<(), ServiceError> {
        let (workspace, mut active) = record
            .value
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or(ServiceError::StaleCapability)?;
        self.workspaces
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(workspace.id().child_name());
        let guard = catch_unwind(AssertUnwindSafe(|| {
            self.workspace.remove_workspace(workspace)
        }))
        .map_err(|_| {
            self.mark_cleanup_required();
            ServiceError::CleanupRequired
        })?
        .map_err(|error| {
            self.mark_cleanup_required();
            let _ = error;
            ServiceError::CleanupRequired
        })?;
        let root = {
            let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            data.unlocked
                .as_ref()
                .map(Arc::clone)
                .ok_or(ServiceError::Locked)?
        };
        root.unregister_removed_workspace(&mut *active, guard)
            .map_err(|error| {
                self.mark_cleanup_required();
                let _ = error;
                ServiceError::CleanupRequired
            })?;
        Ok(())
    }

    fn cleanup_tracked_workspaces(&self) -> bool {
        loop {
            let record = self
                .workspaces
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .values()
                .next()
                .cloned();
            let Some(record) = record else {
                return true;
            };
            let pair = record
                .value
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            let Some((workspace, active)) = pair else {
                return false;
            };
            self.workspaces
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(workspace.id().child_name());
            // Root revocation precedes host cleanup. Physical absence is the
            // security requirement here; the authenticated Active record is
            // intentionally retained and reconciled on the next unlock.
            let result = catch_unwind(AssertUnwindSafe(|| {
                self.workspace
                    .remove_workspace(workspace)
                    .map(drop)
                    .map_err(map_host_error)
            }));
            drop(active);
            if result.is_err() || result.is_ok_and(|result| result.is_err()) {
                return false;
            }
        }
    }

    pub(crate) fn sample_now(&self) -> Result<Duration, ServiceError> {
        let sequence = self
            .clock_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| ServiceError::ClockFailure)?
            .checked_add(1)
            .ok_or(ServiceError::ClockFailure)?;
        let now = catch_port_panic(|| self.clock.elapsed())?;
        let mut observed = self
            .clock_observed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if sequence < observed.0 {
            return Ok(observed.1.max(now));
        }
        if now < observed.1 {
            return Err(ServiceError::ClockFailure);
        }
        *observed = (sequence, now);
        Ok(now)
    }

    fn observe_sample(data: &mut SessionData, now: Duration) {
        data.last_observed = data.last_observed.max(now);
    }

    pub(crate) fn unlock(
        &self,
        secret: RecoverySecretInput,
    ) -> Result<SessionSummary, ServiceError> {
        {
            let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if data.state != SessionState::Locked || data.unlock_attempt.is_some() {
                return Err(ServiceError::Locked);
            }
            data.epoch = data
                .epoch
                .checked_add(1)
                .ok_or(ServiceError::IdentifierExhausted)?;
            data.unlock_attempt = Some(Arc::new(RepositoryCancellation::new()));
            data.cleanup_owner = true;
        }

        let cleanup = catch_port_panic(|| {
            self.workspace
                .cleanup_owned_base()
                .map_err(|_| ServiceError::CleanupRequired)
        });
        let (epoch, cancel) = {
            let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            let cancel = Arc::clone(
                data.unlock_attempt
                    .as_ref()
                    .ok_or(ServiceError::Cancelled)?,
            );
            if cleanup.is_err() {
                data.unlock_attempt = None;
                data.cleanup_owner = false;
                data.state = SessionState::CleanupRequired;
                self.changed.notify_all();
                return Err(ServiceError::CleanupRequired);
            }
            if cancel.is_cancelled() {
                data.unlock_attempt = None;
                let cleanup_required = data.cleanup_required;
                data.state = if cleanup_required {
                    SessionState::CleanupRequired
                } else {
                    SessionState::Locked
                };
                data.cleanup_owner = false;
                self.changed.notify_all();
                return Err(if cleanup_required {
                    ServiceError::CleanupRequired
                } else {
                    ServiceError::Cancelled
                });
            }
            data.state = SessionState::Unlocking;
            (data.epoch, cancel)
        };

        let (unlocked, unlock_panicked) = match catch_unwind(AssertUnwindSafe(|| {
            self.repository
                .unlock_recovery(secret, cancel.as_ref())
                .map_err(map_repository_error)
        })) {
            Ok(result) => (result, false),
            Err(_) => (Err(ServiceError::CleanupRequired), true),
        };

        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        let exact_attempt = data
            .unlock_attempt
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &cancel));
        let cleanup_latched = data.cleanup_required;
        if data.epoch != epoch || !exact_attempt || cancel.is_cancelled() || cleanup_latched {
            data.unlock_attempt = None;
            data.state = SessionState::Locking;
            drop(data);
            let mut close_failed = false;
            if let Ok(unlocked) = unlocked {
                close_failed = Self::close_unwrapped_capability(unlocked);
            }
            if close_failed {
                self.mark_cleanup_required();
            }
            self.finish_cancelled_unlock();
            return Err(if cleanup_latched {
                ServiceError::CleanupRequired
            } else {
                ServiceError::Cancelled
            });
        }
        if unlock_panicked {
            data.unlock_attempt = None;
            data.state = SessionState::Locking;
            drop(data);
            self.mark_cleanup_required();
            self.finish_cancelled_unlock();
            return Err(ServiceError::CleanupRequired);
        }

        match unlocked {
            Ok(unlocked) => {
                drop(data);
                let slot = match RootCapabilitySlot::try_new(unlocked) {
                    Ok(slot) => Arc::new(slot),
                    Err(unlocked) => {
                        let _ = Self::close_unwrapped_capability(unlocked);
                        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
                        data.unlock_attempt = None;
                        data.state = SessionState::Locking;
                        drop(data);
                        self.mark_cleanup_required();
                        self.finish_cancelled_unlock();
                        return Err(ServiceError::CleanupRequired);
                    }
                };
                {
                    let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
                    let exact_attempt = data
                        .unlock_attempt
                        .as_ref()
                        .is_some_and(|active| Arc::ptr_eq(active, &cancel));
                    if data.state != SessionState::Unlocking
                        || data.epoch != epoch
                        || !exact_attempt
                        || cancel.is_cancelled()
                        || data.cleanup_required
                    {
                        data.unlock_attempt = None;
                        data.state = SessionState::Locking;
                        drop(data);
                        let close_failed = catch_port_panic(|| {
                            slot.begin_close();
                            slot.begin_adapter_close();
                            slot.close().map_err(map_repository_error)
                        })
                        .is_err();
                        if close_failed {
                            self.mark_cleanup_required();
                        }
                        self.finish_cancelled_unlock();
                        return Err(ServiceError::Cancelled);
                    }
                    data.provisional_unlock = Some(Arc::clone(&slot));
                }
                let reconciliation = catch_port_panic(|| {
                    slot.reconcile_authenticated_workspaces()
                        .map_err(map_repository_error)
                });
                if reconciliation.is_err() {
                    let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
                    data.unlock_attempt = None;
                    let owns_slot = data
                        .provisional_unlock
                        .as_ref()
                        .is_some_and(|active| Arc::ptr_eq(active, &slot));
                    if owns_slot {
                        data.provisional_unlock = None;
                        data.state = SessionState::Locking;
                    }
                    drop(data);
                    if !owns_slot {
                        self.mark_cleanup_required();
                        return Err(ServiceError::CleanupRequired);
                    }
                    let close_failed = catch_port_panic(|| {
                        slot.begin_close();
                        slot.begin_adapter_close();
                        slot.close().map_err(map_repository_error)
                    })
                    .is_err();
                    if close_failed {
                        self.mark_cleanup_required();
                    }
                    self.mark_cleanup_required();
                    self.finish_cancelled_unlock();
                    return Err(ServiceError::CleanupRequired);
                }
                let vault_id = match catch_unwind(AssertUnwindSafe(|| {
                    self.repository.current_vault_id()
                })) {
                    Ok(Ok(Some(vault_id))) => vault_id,
                    _ => {
                        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
                        data.unlock_attempt = None;
                        let owns_slot = data
                            .provisional_unlock
                            .as_ref()
                            .is_some_and(|active| Arc::ptr_eq(active, &slot));
                        if owns_slot {
                            data.provisional_unlock = None;
                            data.state = SessionState::Locking;
                        }
                        drop(data);
                        if owns_slot {
                            let _ = catch_port_panic(|| {
                                slot.begin_close();
                                slot.begin_adapter_close();
                                slot.close().map_err(map_repository_error)
                            });
                        }
                        self.mark_cleanup_required();
                        if owns_slot {
                            self.finish_cancelled_unlock();
                        }
                        return Err(ServiceError::CleanupRequired);
                    }
                };
                let sampled = self.sample_now();
                data = self.data.lock().unwrap_or_else(|error| error.into_inner());
                let exact_attempt = data
                    .unlock_attempt
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, &cancel));
                let cleanup_latched = data.cleanup_required;
                if data.epoch != epoch || !exact_attempt || cancel.is_cancelled() || cleanup_latched
                {
                    data.unlock_attempt = None;
                    let owns_slot = data
                        .provisional_unlock
                        .as_ref()
                        .is_some_and(|active| Arc::ptr_eq(active, &slot));
                    if owns_slot {
                        data.provisional_unlock = None;
                        data.state = SessionState::Locking;
                    }
                    drop(data);
                    if !owns_slot {
                        return Err(if cleanup_latched {
                            ServiceError::CleanupRequired
                        } else {
                            ServiceError::Cancelled
                        });
                    }
                    let close_failed = catch_port_panic(|| {
                        slot.begin_close();
                        slot.begin_adapter_close();
                        slot.close().map_err(map_repository_error)
                    })
                    .is_err();
                    if close_failed {
                        self.mark_cleanup_required();
                    }
                    self.finish_cancelled_unlock();
                    return Err(if cleanup_latched {
                        ServiceError::CleanupRequired
                    } else {
                        ServiceError::Cancelled
                    });
                }
                let deadlines = sampled.and_then(|now| {
                    Self::observe_sample(&mut data, now);
                    let inactivity = now
                        .checked_add(self.policy.inactivity_timeout)
                        .ok_or(ServiceError::ClockFailure)?;
                    let absolute = now
                        .checked_add(self.policy.absolute_timeout)
                        .ok_or(ServiceError::ClockFailure)?;
                    Ok((inactivity, absolute))
                });
                let (inactivity, absolute) = match deadlines {
                    Ok(deadlines) => deadlines,
                    Err(error) => {
                        data.unlock_attempt = None;
                        let owns_slot = data
                            .provisional_unlock
                            .as_ref()
                            .is_some_and(|active| Arc::ptr_eq(active, &slot));
                        if owns_slot {
                            data.provisional_unlock = None;
                            data.state = SessionState::Locking;
                        }
                        drop(data);
                        if owns_slot {
                            let close_failed = catch_port_panic(|| {
                                slot.begin_close();
                                slot.begin_adapter_close();
                                slot.close().map_err(map_repository_error)
                            })
                            .is_err();
                            if close_failed {
                                self.mark_cleanup_required();
                            }
                            self.finish_cancelled_unlock();
                        }
                        return Err(error);
                    }
                };
                data.inactivity_deadline = Some(inactivity);
                data.absolute_deadline = Some(absolute);
                data.inactivity_warnings = 0;
                data.absolute_warnings = 0;
                data.expired = false;
                let provisional = data.provisional_unlock.take();
                if !provisional
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, &slot))
                {
                    data.unlock_attempt = None;
                    return Err(ServiceError::Cancelled);
                }
                data.unlocked = provisional;
                data.unlock_attempt = None;
                data.cleanup_owner = false;
                data.state = SessionState::Unlocked;
                *self
                    .vault_id
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(vault_id);
                self.changed.notify_all();
                Ok(SessionSummary {
                    vault_id,
                    generation: epoch,
                })
            }
            Err(error) => {
                data.unlock_attempt = None;
                let cleanup_required =
                    data.cleanup_required || matches!(error, ServiceError::CleanupRequired);
                data.cleanup_required = cleanup_required;
                data.state = if cleanup_required {
                    SessionState::CleanupRequired
                } else {
                    SessionState::Locked
                };
                data.cleanup_owner = false;
                self.changed.notify_all();
                Err(if cleanup_required {
                    ServiceError::CleanupRequired
                } else {
                    error
                })
            }
        }
    }

    pub(crate) fn record_trusted_activity_at(&self, now: Duration) -> Result<(), ServiceError> {
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        Self::observe_sample(&mut data, now);
        if data.state != SessionState::Unlocked {
            return Err(ServiceError::Locked);
        }
        let now = data.last_observed;
        if data.expired
            || data
                .inactivity_deadline
                .is_some_and(|deadline| now >= deadline)
            || data
                .absolute_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            data.expired = true;
            return Err(ServiceError::Locked);
        }
        data.inactivity_deadline = Some(
            now.checked_add(self.policy.inactivity_timeout)
                .ok_or(ServiceError::ClockFailure)?,
        );
        data.inactivity_warnings = 0;
        Ok(())
    }

    pub(crate) fn observe_at(&self, now: Duration) -> Result<SessionObservation, ServiceError> {
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        Self::observe_sample(&mut data, now);
        let now = data.last_observed;
        if data.state != SessionState::Unlocked {
            return Ok(SessionObservation {
                expired: false,
                warnings: Vec::new(),
                next_wait: None,
            });
        }
        let expired = data.expired
            || data
                .inactivity_deadline
                .is_some_and(|deadline| now >= deadline)
            || data
                .absolute_deadline
                .is_some_and(|deadline| now >= deadline);
        data.expired = expired;
        let mut due = Vec::new();
        due.try_reserve_exact(self.policy.warning_offsets.len().saturating_mul(2))
            .map_err(|_| ServiceError::AllocationFailed)?;
        if !expired {
            for (index, offset) in self.policy.warning_offsets.iter().copied().enumerate() {
                let bit = 1_u32
                    .checked_shl(u32::try_from(index).map_err(|_| ServiceError::CapacityExceeded)?)
                    .ok_or(ServiceError::CapacityExceeded)?;
                if data.inactivity_warnings & bit == 0
                    && data.inactivity_deadline.is_some_and(|deadline| {
                        deadline
                            .checked_sub(offset)
                            .is_some_and(|boundary| now >= boundary)
                    })
                {
                    data.inactivity_warnings |= bit;
                    let boundary = data
                        .inactivity_deadline
                        .and_then(|deadline| deadline.checked_sub(offset))
                        .ok_or(ServiceError::ClockFailure)?;
                    due.push((boundary, SessionDeadlineKind::Inactivity, offset));
                }
                if data.absolute_warnings & bit == 0
                    && data.absolute_deadline.is_some_and(|deadline| {
                        deadline
                            .checked_sub(offset)
                            .is_some_and(|boundary| now >= boundary)
                    })
                {
                    data.absolute_warnings |= bit;
                    let boundary = data
                        .absolute_deadline
                        .and_then(|deadline| deadline.checked_sub(offset))
                        .ok_or(ServiceError::ClockFailure)?;
                    due.push((boundary, SessionDeadlineKind::Absolute, offset));
                }
            }
        }
        due.sort_by_key(|(boundary, deadline, _)| {
            (*boundary, matches!(deadline, SessionDeadlineKind::Absolute))
        });
        let mut warnings = Vec::new();
        warnings
            .try_reserve_exact(due.len())
            .map_err(|_| ServiceError::AllocationFailed)?;
        for (_, deadline, remaining) in due {
            warnings.push(SessionEvent::LockWarning {
                remaining,
                deadline,
            });
        }
        let next_deadline =
            data.inactivity_deadline
                .into_iter()
                .chain(data.absolute_deadline)
                .chain(self.policy.warning_offsets.iter().enumerate().flat_map(
                    |(index, offset)| {
                        let bit = 1_u32.checked_shl(u32::try_from(index).unwrap_or(u32::MAX));
                        [
                            (bit.is_some_and(|bit| data.inactivity_warnings & bit == 0))
                                .then(|| data.inactivity_deadline?.checked_sub(*offset))
                                .flatten(),
                            (bit.is_some_and(|bit| data.absolute_warnings & bit == 0))
                                .then(|| data.absolute_deadline?.checked_sub(*offset))
                                .flatten(),
                        ]
                        .into_iter()
                        .flatten()
                    },
                ))
                .min();
        Ok(SessionObservation {
            expired,
            warnings,
            next_wait: next_deadline.map(|deadline| deadline.saturating_sub(now)),
        })
    }

    pub(crate) fn begin_lock(&self) -> Option<Arc<RootCapabilitySlot>> {
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(cancel) = &data.unlock_attempt {
            cancel.cancel();
        }
        match data.state {
            SessionState::Unlocked => {
                data.state = SessionState::Locking;
                data.cleanup_owner = true;
                data.inactivity_deadline = None;
                data.absolute_deadline = None;
                data.inactivity_warnings = 0;
                data.absolute_warnings = 0;
                data.expired = false;
                data.unlocked.take()
            }
            SessionState::Unlocking => {
                data.state = SessionState::Locking;
                data.cleanup_owner = true;
                data.provisional_unlock.take()
            }
            _ => None,
        }
    }

    pub(crate) fn close_root_for_lock(&self, unlocked: Option<&Arc<RootCapabilitySlot>>) -> bool {
        unlocked.is_some_and(|unlocked| {
            catch_port_panic(|| unlocked.close().map_err(map_repository_error)).is_err()
        })
    }

    pub(crate) fn finish_lock_after_close(&self, root_was_present: bool, close_failed: bool) {
        {
            let data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if !data.cleanup_owner || !root_was_present {
                return;
            }
        }
        let mut failed = close_failed;
        failed |= self.workspace_attempts.load(Ordering::Acquire) != 0;
        failed |= !self.cleanup_tracked_workspaces();
        failed |= catch_port_panic(|| {
            self.workspace
                .cleanup_owned_base()
                .map_err(|_| ServiceError::CleanupRequired)
        })
        .is_err();

        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        data.state = if failed || data.cleanup_required {
            SessionState::CleanupRequired
        } else {
            SessionState::Locked
        };
        data.cleanup_owner = false;
        self.changed.notify_all();
    }

    fn finish_cancelled_unlock(&self) {
        let failed = catch_port_panic(|| {
            self.workspace
                .cleanup_owned_base()
                .map_err(|_| ServiceError::CleanupRequired)
        })
        .is_err();
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        data.state = if failed || data.cleanup_required {
            SessionState::CleanupRequired
        } else {
            SessionState::Locked
        };
        data.cleanup_owner = false;
        self.changed.notify_all();
    }

    pub(crate) fn retry_cleanup(&self) -> Result<(), ServiceError> {
        {
            let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
            if data.state != SessionState::CleanupRequired {
                return Err(ServiceError::Locked);
            }
            if data.unlock_attempt.is_some() || data.cleanup_owner {
                return Err(ServiceError::Busy);
            }
            if self.workspace_attempts.load(Ordering::Acquire) != 0 {
                return Err(ServiceError::Busy);
            }
            data.state = SessionState::Locking;
            data.cleanup_owner = true;
        }
        let tracked_clean = self.cleanup_tracked_workspaces();
        let base_clean = catch_port_panic(|| {
            self.workspace
                .cleanup_owned_base()
                .map_err(|_| ServiceError::CleanupRequired)
        })
        .is_ok();
        let external_clean = catch_port_panic(|| {
            self.external_files
                .retry_cleanup()
                .map_err(|_| ServiceError::CleanupRequired)
        })
        .is_ok();
        let clean = tracked_clean && base_clean && external_clean;
        let mut data = self.data.lock().unwrap_or_else(|error| error.into_inner());
        data.state = if clean {
            SessionState::Locked
        } else {
            SessionState::CleanupRequired
        };
        if clean {
            data.cleanup_required = false;
        }
        data.cleanup_owner = false;
        self.changed.notify_all();
        clean
            .then_some(())
            .ok_or(ServiceError::CleanupRequired)
            .map(|_| ())
            .map_err(|_| ServiceError::CleanupRequired)
    }
}

fn map_external_host_error(error: crate::HostPortError) -> ServiceError {
    match error {
        crate::HostPortError::Cancelled => ServiceError::Cancelled,
        crate::HostPortError::CapacityExceeded => ServiceError::CapacityExceeded,
        crate::HostPortError::AllocationFailed => ServiceError::AllocationFailed,
        crate::HostPortError::InvalidInput
        | crate::HostPortError::Denied
        | crate::HostPortError::Permission => ServiceError::InvalidInput,
        crate::HostPortError::Unavailable => ServiceError::Unavailable,
        crate::HostPortError::DestinationExists => ServiceError::DestinationExists,
        crate::HostPortError::StaleCapability => ServiceError::StaleCapability,
        crate::HostPortError::DurabilityPending => ServiceError::DurabilityPending,
        crate::HostPortError::CleanupFailed => ServiceError::CleanupRequired,
        crate::HostPortError::LiveWorkspace => ServiceError::Busy,
        crate::HostPortError::DetachedEditor | crate::HostPortError::PlatformFailure => {
            ServiceError::ExecutorFailed
        }
    }
}

pub(crate) fn map_repository_error(error: RepositoryPortError) -> ServiceError {
    match error {
        RepositoryPortError::WrongSecret => ServiceError::AuthenticationFailed,
        RepositoryPortError::Cancelled => ServiceError::Cancelled,
        RepositoryPortError::Locked => ServiceError::Locked,
        RepositoryPortError::Busy => ServiceError::Busy,
        RepositoryPortError::CapacityExceeded => ServiceError::CapacityExceeded,
        RepositoryPortError::AllocationFailed => ServiceError::AllocationFailed,
        RepositoryPortError::CleanupRequired | RepositoryPortError::DurabilityPending => {
            ServiceError::CleanupRequired
        }
        RepositoryPortError::TimedOut => ServiceError::TimedOut,
        RepositoryPortError::IntegrityFailed => ServiceError::IntegrityFailed,
        RepositoryPortError::InvalidInput => ServiceError::InvalidInput,
        RepositoryPortError::NotFound => ServiceError::Unavailable,
        RepositoryPortError::EntropyUnavailable => ServiceError::EntropyUnavailable,
        RepositoryPortError::IdentifierExhausted => ServiceError::IdentifierExhausted,
        RepositoryPortError::StaleCapability => ServiceError::StaleCapability,
        RepositoryPortError::Unavailable => ServiceError::Unavailable,
        RepositoryPortError::PlatformFailure => ServiceError::ExecutorFailed,
    }
}

fn map_host_error(error: crate::HostPortError) -> ServiceError {
    match error {
        crate::HostPortError::Cancelled => ServiceError::Cancelled,
        crate::HostPortError::CapacityExceeded => ServiceError::CapacityExceeded,
        crate::HostPortError::AllocationFailed => ServiceError::AllocationFailed,
        crate::HostPortError::LiveWorkspace => ServiceError::Busy,
        crate::HostPortError::CleanupFailed => ServiceError::CleanupRequired,
        crate::HostPortError::DestinationExists => ServiceError::DestinationExists,
        crate::HostPortError::StaleCapability => ServiceError::StaleCapability,
        crate::HostPortError::DurabilityPending => ServiceError::DurabilityPending,
        crate::HostPortError::InvalidInput => ServiceError::InvalidConfiguration,
        crate::HostPortError::Unavailable
        | crate::HostPortError::Denied
        | crate::HostPortError::DetachedEditor
        | crate::HostPortError::Permission
        | crate::HostPortError::PlatformFailure => ServiceError::ExecutorFailed,
    }
}

fn catch_port_panic<T>(
    action: impl FnOnce() -> Result<T, ServiceError>,
) -> Result<T, ServiceError> {
    catch_unwind(AssertUnwindSafe(action)).map_err(|_| ServiceError::ExecutorFailed)?
}

#[cfg(test)]
mod production_transition_tests {
    use super::*;
    use tempfile::TempDir;

    struct UnavailableWorkspace;

    struct TestRegisteredWorkspace(crate::WorkspaceId);

    impl RegisteredWorkspaceCapability for TestRegisteredWorkspace {
        fn workspace_id(&self) -> &crate::WorkspaceId {
            &self.0
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    struct TestActiveWorkspace(crate::WorkspaceId);

    impl ActiveWorkspaceCapability for TestActiveWorkspace {
        fn workspace_id(&self) -> &crate::WorkspaceId {
            &self.0
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    struct NoopRevocation;

    impl VaultRootRevocation for NoopRevocation {
        fn revoke(&self) {}
    }

    struct FixedClock;

    impl MonotonicClock for FixedClock {
        fn elapsed(&self) -> Result<Duration, ServiceError> {
            Ok(Duration::ZERO)
        }
    }

    struct IdentityRepository(VaultId);

    impl VaultRepository for IdentityRepository {
        fn current_vault_id(&self) -> Result<Option<VaultId>, RepositoryPortError> {
            Ok(Some(self.0))
        }

        fn unlock_recovery(
            &self,
            _secret: RecoverySecretInput,
            _cancel: &RepositoryCancellation,
        ) -> Result<Box<dyn UnlockedVaultCapability>, RepositoryPortError> {
            Err(RepositoryPortError::Unavailable)
        }

        fn begin_recovery_initialization(
            &self,
            _request: BeginRecoveryInitialization,
            _cancel: &RepositoryCancellation,
        ) -> Result<PreparedRecoveryInitialization, RepositoryPortError> {
            Err(RepositoryPortError::Unavailable)
        }
    }

    struct TestOwnershipGuard;
    impl crate::WorkspaceOwnershipGuard for TestOwnershipGuard {}

    struct TestAbsenceGuard;
    impl crate::WorkspaceAbsenceGuard for TestAbsenceGuard {}

    struct WorkspaceBindingProvider {
        response_id: Option<crate::WorkspaceId>,
        removed: Arc<AtomicUsize>,
        acquired_absence: Arc<AtomicUsize>,
        fail_absence_allocation: bool,
    }

    impl crate::WorkspaceProvider for WorkspaceBindingProvider {
        fn cleanup_owned_base(&self) -> Result<crate::StartupCleanupReport, crate::HostPortError> {
            crate::StartupCleanupReport::try_new(0, 0)
        }

        fn create_target(
            &self,
            request: crate::TargetWorkspaceRequest,
        ) -> Result<crate::WorkspaceLease, crate::HostPortError> {
            let response_id = self
                .response_id
                .as_ref()
                .ok_or(crate::HostPortError::PlatformFailure)?
                .try_duplicate()?;
            let root = request
                .repository_root()
                .parent()
                .ok_or(crate::HostPortError::InvalidInput)?
                .join(response_id.child_name());
            let response = crate::TargetWorkspaceRequest::new(
                response_id,
                request.vault_id(),
                request.repository_root().to_path_buf(),
            )?;
            crate::WorkspaceLease::from_target_request(response, root, Box::new(TestOwnershipGuard))
        }

        fn create_whole_vault(
            &self,
            _request: crate::VaultWorkspaceRequest,
        ) -> Result<crate::WorkspaceLease, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn materialization_target(
            &self,
            _lease: &crate::WorkspaceLease,
            _relative_path: &crate::LogicalWorkspacePath,
        ) -> Result<crate::MaterializationTarget, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn publish_materialized(
            &self,
            _lease: &crate::WorkspaceLease,
            _target: crate::MaterializationTarget,
        ) -> Result<crate::PublishedGeneration, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn arm_published_path(
            &self,
            _lease: &crate::WorkspaceLease,
            _published: crate::PublishedGeneration,
        ) -> Result<(), crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn watch(
            &self,
            _lease: &crate::WorkspaceLease,
        ) -> Result<Box<dyn crate::WorkspaceWatch>, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn open_stable_source(
            &self,
            _lease: &crate::WorkspaceLease,
            _relative_path: &crate::LogicalWorkspacePath,
            _expected_generation: u64,
        ) -> Result<crate::OpenedStableSource, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn validate_stable_source(
            &self,
            _lease: &crate::WorkspaceLease,
            _token: &crate::StableSourceToken,
        ) -> Result<(), crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn remove_workspace(
            &self,
            _lease: crate::WorkspaceLease,
        ) -> Result<Box<dyn crate::WorkspaceAbsenceGuard>, crate::HostPortError> {
            self.removed.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(TestAbsenceGuard))
        }

        fn acquire_verified_absence(
            &self,
            _id: &crate::WorkspaceId,
        ) -> Result<Box<dyn crate::WorkspaceAbsenceGuard>, crate::HostPortError> {
            self.acquired_absence.fetch_add(1, Ordering::AcqRel);
            if self.fail_absence_allocation {
                return Err(crate::HostPortError::AllocationFailed);
            }
            Ok(Box::new(TestAbsenceGuard))
        }
    }

    struct WrongActiveWorkspaceCapability {
        registered_id: crate::WorkspaceId,
        authenticated_count: usize,
        active_id: crate::WorkspaceId,
        unregister_calls: Arc<AtomicUsize>,
    }

    impl UnlockedVaultCapability for WrongActiveWorkspaceCapability {
        fn revocation_handle(&self) -> Arc<dyn VaultRootRevocation> {
            Arc::new(NoopRevocation)
        }

        fn acquire_local_lease(
            &self,
            _cancellation: Arc<RepositoryCancellation>,
        ) -> Result<Box<dyn LocalVaultLease>, RepositoryPortError> {
            Err(RepositoryPortError::Unavailable)
        }

        fn acquire_replication_lease(
            &self,
            _backend: ReplicationLimitProfile,
            _operation: ReplicationLimitProfile,
            _cancellation: Arc<RepositoryCancellation>,
        ) -> Result<Box<dyn ReplicationVaultLease>, RepositoryPortError> {
            Err(RepositoryPortError::Unavailable)
        }

        fn begin_compromise_rekey(
            &self,
            _request: BeginCompromiseRekey,
            _cancel: &RepositoryCancellation,
        ) -> Result<PreparedCompromiseRekey, RepositoryPortError> {
            Err(RepositoryPortError::Unavailable)
        }

        fn register_workspace(
            &self,
        ) -> Result<Box<dyn RegisteredWorkspaceCapability>, RepositoryPortError> {
            Ok(Box::new(TestRegisteredWorkspace(
                self.registered_id
                    .try_duplicate()
                    .map_err(map_host_repository_error)?,
            )))
        }

        fn activate_workspace(
            &self,
            _registered: &mut dyn RegisteredWorkspaceCapability,
        ) -> Result<Box<dyn ActiveWorkspaceCapability>, RepositoryPortError> {
            let id = self
                .active_id
                .try_duplicate()
                .map_err(map_host_repository_error)?;
            Ok(Box::new(TestActiveWorkspace(id)))
        }

        fn authenticated_workspaces(
            &self,
        ) -> Result<Vec<AuthenticatedWorkspaceCapability>, RepositoryPortError> {
            let mut records = Vec::new();
            records
                .try_reserve_exact(self.authenticated_count)
                .map_err(|_| RepositoryPortError::AllocationFailed)?;
            for _ in 0..self.authenticated_count {
                records.push(AuthenticatedWorkspaceCapability::Registered(Box::new(
                    TestRegisteredWorkspace(
                        self.registered_id
                            .try_duplicate()
                            .map_err(map_host_repository_error)?,
                    ),
                )));
            }
            Ok(records)
        }

        fn unregister_absent_workspace(
            &self,
            _active: &mut dyn ActiveWorkspaceCapability,
        ) -> Result<(), RepositoryPortError> {
            self.unregister_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn unregister_removed_workspace(
            &self,
            _active: &mut dyn ActiveWorkspaceCapability,
            _guard: Box<dyn crate::WorkspaceAbsenceGuard>,
        ) -> Result<(), RepositoryPortError> {
            self.unregister_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn close(self: Box<Self>) -> Result<(), RepositoryPortError> {
            Ok(())
        }
    }

    impl crate::WorkspaceProvider for UnavailableWorkspace {
        fn cleanup_owned_base(&self) -> Result<crate::StartupCleanupReport, crate::HostPortError> {
            crate::StartupCleanupReport::try_new(0, 0)
        }

        fn create_target(
            &self,
            _request: crate::TargetWorkspaceRequest,
        ) -> Result<crate::WorkspaceLease, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn create_whole_vault(
            &self,
            _request: crate::VaultWorkspaceRequest,
        ) -> Result<crate::WorkspaceLease, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn materialization_target(
            &self,
            _lease: &crate::WorkspaceLease,
            _relative_path: &crate::LogicalWorkspacePath,
        ) -> Result<crate::MaterializationTarget, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn publish_materialized(
            &self,
            _lease: &crate::WorkspaceLease,
            _target: crate::MaterializationTarget,
        ) -> Result<crate::PublishedGeneration, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn arm_published_path(
            &self,
            _lease: &crate::WorkspaceLease,
            _published: crate::PublishedGeneration,
        ) -> Result<(), crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn watch(
            &self,
            _lease: &crate::WorkspaceLease,
        ) -> Result<Box<dyn crate::WorkspaceWatch>, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn open_stable_source(
            &self,
            _lease: &crate::WorkspaceLease,
            _relative_path: &crate::LogicalWorkspacePath,
            _expected_generation: u64,
        ) -> Result<crate::OpenedStableSource, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn validate_stable_source(
            &self,
            _lease: &crate::WorkspaceLease,
            _token: &crate::StableSourceToken,
        ) -> Result<(), crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn remove_workspace(
            &self,
            _lease: crate::WorkspaceLease,
        ) -> Result<Box<dyn crate::WorkspaceAbsenceGuard>, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }

        fn acquire_verified_absence(
            &self,
            _id: &crate::WorkspaceId,
        ) -> Result<Box<dyn crate::WorkspaceAbsenceGuard>, crate::HostPortError> {
            Err(crate::HostPortError::Unavailable)
        }
    }

    struct OneTargetResolver {
        id: [u8; 16],
        target: Mutex<Option<LocalVaultConfig>>,
    }

    impl CompromiseTargetResolver for OneTargetResolver {
        fn resolve(&self, target: [u8; 16]) -> Result<LocalVaultConfig, RepositoryPortError> {
            if target != self.id {
                return Err(RepositoryPortError::NotFound);
            }
            self.target
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .ok_or(RepositoryPortError::NotFound)
        }
    }

    fn parameters() -> RecoveryKdfProfileV1 {
        RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap()
    }

    fn target(repository: &TempDir, local: &TempDir, label: &str) -> LocalVaultConfig {
        LocalVaultConfig::try_new(
            repository.path().canonicalize().unwrap(),
            local.path().canonicalize().unwrap(),
            parameters(),
            label.to_owned(),
        )
        .unwrap()
    }

    fn secret(value: &[u8]) -> RecoverySecretInput {
        RecoverySecretInput::from_protected_bytes(value.to_vec()).unwrap()
    }

    fn root_is_empty(root: &TempDir) -> bool {
        std::fs::read_dir(root.path()).unwrap().next().is_none()
    }

    fn workspace_id(byte: u8) -> crate::WorkspaceId {
        crate::WorkspaceId::from_store(&notecrypt_store::cleanup_test_support::workspace_id(
            [byte; 16],
        ))
        .unwrap()
    }

    fn unlocked_workspace_manager(
        provider: Arc<dyn crate::WorkspaceProvider>,
        capability: WrongActiveWorkspaceCapability,
        vault_id: VaultId,
    ) -> Arc<SessionManager> {
        let manager = SessionManager::new(SessionComponents::new(
            Arc::new(IdentityRepository(vault_id)),
            provider,
            Arc::new(FixedClock),
            SessionPolicy::try_new(
                Duration::from_secs(60),
                Duration::from_secs(120),
                Vec::new(),
                Duration::ZERO,
            )
            .unwrap(),
        ))
        .unwrap();
        let slot = RootCapabilitySlot::try_new(Box::new(capability))
            .unwrap_or_else(|_| panic!("test capability must expose revocation"));
        let mut data = manager
            .data
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        data.state = SessionState::Unlocked;
        data.epoch = 1;
        data.unlocked = Some(Arc::new(slot));
        drop(data);
        manager
    }

    #[test]
    fn production_vacant_recovery_and_compromise_targets_commit_end_to_end() {
        let source_repository = TempDir::new().unwrap();
        let source_local = TempDir::new().unwrap();
        let target_repository = TempDir::new().unwrap();
        let target_local = TempDir::new().unwrap();
        let target_id = [0x5a; 16];
        let resolver = Arc::new(OneTargetResolver {
            id: target_id,
            target: Mutex::new(Some(target(
                &target_repository,
                &target_local,
                "replacement",
            ))),
        });
        let workspace = Arc::new(UnavailableWorkspace);
        let repository = StoreVaultRepository::vacant(
            target(&source_repository, &source_local, "source"),
            workspace,
            resolver,
        );
        let cancellation = RepositoryCancellation::new();

        let prepared = repository
            .begin_recovery_initialization(
                BeginRecoveryInitialization::custom_v1(
                    secret(b"alpha beta gamma delta epsilon"),
                    OfflineGuessingRiskDisclosure::try_for_policy(1)
                        .unwrap()
                        .accept(),
                ),
                &cancellation,
            )
            .unwrap();
        let summary = prepared
            .action
            .confirm(prepared.secret, &cancellation)
            .unwrap();
        assert_eq!(
            repository.current_vault_id().unwrap(),
            Some(summary.vault_id())
        );

        let source = repository
            .unlock_recovery(secret(b"alpha beta gamma delta epsilon"), &cancellation)
            .unwrap();
        let prepared = source
            .begin_compromise_rekey(
                BeginCompromiseRekey::try_custom_v1(
                    target_id,
                    OfflineGuessingRiskDisclosure::try_for_policy(1)
                        .unwrap()
                        .accept(),
                )
                .unwrap(),
                &cancellation,
            )
            .unwrap();
        assert!(prepared.secret.is_none());
        prepared
            .action
            .confirm(secret(b"one two three four five six"), &cancellation)
            .unwrap();
        source.revocation_handle().revoke();
        source.close().unwrap();

        let replacement = VaultStore::open(
            &target_repository.path().canonicalize().unwrap(),
            &target_local.path().canonicalize().unwrap(),
        )
        .unwrap();
        replacement
            .unlock_recovery(
                RecoverySecretInput::from_protected_bytes(b"one two three four five six".to_vec())
                    .unwrap()
                    .into_crypto_passphrase(),
                &AtomicBool::new(false),
            )
            .unwrap()
            .close()
            .unwrap();
    }

    #[test]
    fn production_recovery_cancellation_before_active_publication_cleans_owned_target() {
        let source_repository = TempDir::new().unwrap();
        let source_local = TempDir::new().unwrap();
        let unused_repository = TempDir::new().unwrap();
        let unused_local = TempDir::new().unwrap();
        let repository = StoreVaultRepository::vacant(
            target(&source_repository, &source_local, "source"),
            Arc::new(UnavailableWorkspace),
            Arc::new(OneTargetResolver {
                id: [0x61; 16],
                target: Mutex::new(Some(target(&unused_repository, &unused_local, "unused"))),
            }),
        );
        let cancellation = Arc::new(RepositoryCancellation::new());
        let prepared = repository
            .begin_recovery_initialization(
                BeginRecoveryInitialization::custom_v1(
                    secret(b"alpha beta gamma delta epsilon"),
                    OfflineGuessingRiskDisclosure::try_for_policy(1)
                        .unwrap()
                        .accept(),
                ),
                cancellation.as_ref(),
            )
            .unwrap();
        let cancel_at_commit = Arc::clone(&cancellation);
        notecrypt_store::local_test_support::install_before_initial_availability_hook(move || {
            cancel_at_commit.cancel();
        });

        assert_eq!(
            prepared
                .action
                .confirm(prepared.secret, cancellation.as_ref()),
            Err(RepositoryPortError::Cancelled)
        );
        assert_eq!(repository.current_vault_id().unwrap(), None);
        assert!(root_is_empty(&source_repository));
        assert!(root_is_empty(&source_local));
    }

    #[test]
    fn production_compromise_cancellation_before_activating_cleans_owned_target() {
        let source_repository = TempDir::new().unwrap();
        let source_local = TempDir::new().unwrap();
        let target_repository = TempDir::new().unwrap();
        let target_local = TempDir::new().unwrap();
        let target_id = [0x62; 16];
        let resolver = Arc::new(OneTargetResolver {
            id: target_id,
            target: Mutex::new(Some(target(
                &target_repository,
                &target_local,
                "replacement",
            ))),
        });
        let repository = StoreVaultRepository::vacant(
            target(&source_repository, &source_local, "source"),
            Arc::new(UnavailableWorkspace),
            resolver,
        );
        let setup_cancel = RepositoryCancellation::new();
        let prepared = repository
            .begin_recovery_initialization(
                BeginRecoveryInitialization::custom_v1(
                    secret(b"alpha beta gamma delta epsilon"),
                    OfflineGuessingRiskDisclosure::try_for_policy(1)
                        .unwrap()
                        .accept(),
                ),
                &setup_cancel,
            )
            .unwrap();
        prepared
            .action
            .confirm(prepared.secret, &setup_cancel)
            .unwrap();
        let source = repository
            .unlock_recovery(secret(b"alpha beta gamma delta epsilon"), &setup_cancel)
            .unwrap();
        let prepared = source
            .begin_compromise_rekey(
                BeginCompromiseRekey::try_custom_v1(
                    target_id,
                    OfflineGuessingRiskDisclosure::try_for_policy(1)
                        .unwrap()
                        .accept(),
                )
                .unwrap(),
                &setup_cancel,
            )
            .unwrap();
        let cancellation = Arc::new(RepositoryCancellation::new());
        let cancel_at_commit = Arc::clone(&cancellation);
        notecrypt_store::local_test_support::install_before_compromise_activation_hook(move || {
            cancel_at_commit.cancel();
        });

        assert_eq!(
            prepared.action.confirm(
                secret(b"one two three four five six"),
                cancellation.as_ref(),
            ),
            Err(RepositoryPortError::Cancelled)
        );
        assert!(root_is_empty(&target_repository));
        assert!(root_is_empty(&target_local));
        source.revocation_handle().revoke();
        source.close().unwrap();
    }

    #[test]
    fn authenticated_workspace_reconciliation_rejects_mismatched_active_identity() {
        let registered_id = crate::WorkspaceId::from_store(
            &notecrypt_store::cleanup_test_support::workspace_id([0x71; 16]),
        )
        .unwrap();
        let active_id = crate::WorkspaceId::from_store(
            &notecrypt_store::cleanup_test_support::workspace_id([0x72; 16]),
        )
        .unwrap();
        let unregister_calls = Arc::new(AtomicUsize::new(0));
        let capability = WrongActiveWorkspaceCapability {
            registered_id,
            authenticated_count: 1,
            active_id,
            unregister_calls: Arc::clone(&unregister_calls),
        };
        let slot = match RootCapabilitySlot::try_new(Box::new(capability)) {
            Ok(slot) => slot,
            Err(_) => panic!("test capability must expose a revocation handle"),
        };

        assert_eq!(
            slot.reconcile_authenticated_workspaces(),
            Err(RepositoryPortError::IntegrityFailed)
        );
        assert_eq!(unregister_calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn authenticated_workspace_reconciliation_rejects_unbounded_adapter_result() {
        let registered_id = crate::WorkspaceId::from_store(
            &notecrypt_store::cleanup_test_support::workspace_id([0x73; 16]),
        )
        .unwrap();
        let active_id = crate::WorkspaceId::from_store(
            &notecrypt_store::cleanup_test_support::workspace_id([0x74; 16]),
        )
        .unwrap();
        let unregister_calls = Arc::new(AtomicUsize::new(0));
        let capability = WrongActiveWorkspaceCapability {
            registered_id,
            authenticated_count: MAX_ACTIVE_WORKSPACES + 1,
            active_id,
            unregister_calls: Arc::clone(&unregister_calls),
        };
        let slot = match RootCapabilitySlot::try_new(Box::new(capability)) {
            Ok(slot) => slot,
            Err(_) => panic!("test capability must expose a revocation handle"),
        };

        assert_eq!(
            slot.reconcile_authenticated_workspaces(),
            Err(RepositoryPortError::CapacityExceeded)
        );
        assert_eq!(unregister_calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn create_workspace_rejects_a_provider_lease_for_another_registered_identity() {
        let registered_id = workspace_id(0x81);
        let response_id = workspace_id(0x82);
        let active_id = workspace_id(0x81);
        let removed = Arc::new(AtomicUsize::new(0));
        let acquired_absence = Arc::new(AtomicUsize::new(0));
        let unregister_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(WorkspaceBindingProvider {
            response_id: Some(response_id),
            removed: Arc::clone(&removed),
            acquired_absence: Arc::clone(&acquired_absence),
            fail_absence_allocation: false,
        });
        let manager = unlocked_workspace_manager(
            provider,
            WrongActiveWorkspaceCapability {
                registered_id,
                authenticated_count: 0,
                active_id,
                unregister_calls: Arc::clone(&unregister_calls),
            },
            VaultId::from_bytes([0x83; 16]),
        );
        let repository_root = TempDir::new().unwrap();

        assert!(matches!(
            manager.create_workspace(
                1,
                crate::WorkspaceMode::Targeted,
                repository_root.path().canonicalize().unwrap(),
            ),
            Err(ServiceError::CleanupRequired)
        ));
        assert_eq!(removed.load(Ordering::Acquire), 1);
        assert_eq!(acquired_absence.load(Ordering::Acquire), 1);
        assert_eq!(unregister_calls.load(Ordering::Acquire), 1);
        assert!(
            manager
                .workspaces
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn rollback_never_pairs_an_absence_guard_with_a_different_active_identity() {
        let registered_id = workspace_id(0x91);
        let active_id = workspace_id(0x92);
        let removed = Arc::new(AtomicUsize::new(0));
        let acquired_absence = Arc::new(AtomicUsize::new(0));
        let unregister_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(WorkspaceBindingProvider {
            response_id: None,
            removed: Arc::clone(&removed),
            acquired_absence: Arc::clone(&acquired_absence),
            fail_absence_allocation: false,
        });
        let manager = unlocked_workspace_manager(
            provider,
            WrongActiveWorkspaceCapability {
                registered_id,
                authenticated_count: 0,
                active_id,
                unregister_calls: Arc::clone(&unregister_calls),
            },
            VaultId::from_bytes([0x93; 16]),
        );
        let repository_root = TempDir::new().unwrap();

        assert!(matches!(
            manager.create_workspace(
                1,
                crate::WorkspaceMode::Targeted,
                repository_root.path().canonicalize().unwrap(),
            ),
            Err(ServiceError::CleanupRequired)
        ));
        assert_eq!(removed.load(Ordering::Acquire), 0);
        assert_eq!(acquired_absence.load(Ordering::Acquire), 1);
        assert_eq!(unregister_calls.load(Ordering::Acquire), 0);
        assert!(
            manager
                .workspaces
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn replication_requests_discard_source_spare_capacity_and_preserve_limit_errors() {
        let mut observation = Vec::with_capacity(1_000_000);
        observation.push(1);
        let observation = ReplicationObservation::try_new(observation).unwrap();
        assert!(observation.retained_capacity_for_test() <= MAX_REPLICATION_OBSERVATION_BYTES);

        let mut commit = Vec::with_capacity(1_000_000);
        commit.push(2);
        let commit = ReplicationCommitRequest::try_new(commit).unwrap();
        assert!(commit.retained_capacity_for_test() <= MAX_REPLICATION_COMMIT_BYTES);

        assert!(matches!(
            ReplicationObservation::try_new(vec![0; MAX_REPLICATION_OBSERVATION_BYTES + 1]),
            Err(RepositoryPortError::CapacityExceeded)
        ));
        assert!(matches!(
            ReplicationCommitRequest::try_new(vec![0; MAX_REPLICATION_COMMIT_BYTES + 1]),
            Err(RepositoryPortError::CapacityExceeded)
        ));
    }

    #[test]
    fn session_configuration_discards_nested_caller_spare_capacity() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let mut repository_root = std::path::PathBuf::with_capacity(1_000_000);
        repository_root.push(repository.path().canonicalize().unwrap());
        let mut local_state_root = std::path::PathBuf::with_capacity(1_000_000);
        local_state_root.push(local.path().canonicalize().unwrap());
        let mut label = String::with_capacity(1_000_000);
        label.push_str("device");

        let target =
            LocalVaultConfig::try_new(repository_root, local_state_root, parameters(), label)
                .unwrap();
        assert!(target.repository_root.capacity() <= crate::MAX_NATIVE_PATH_BYTES);
        assert!(target.local_state_root.capacity() <= crate::MAX_NATIVE_PATH_BYTES);
        assert!(target.device_label.capacity() <= 256);

        let mut warning_offsets = Vec::with_capacity(1_000_000);
        warning_offsets.push(Duration::from_secs(5));
        let policy = SessionPolicy::try_new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            warning_offsets,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(policy.warning_offsets.capacity() <= MAX_WARNING_OFFSETS);
    }

    #[test]
    fn adapter_owned_outer_vectors_are_rehomed_before_service_retention() {
        let mut source = Vec::with_capacity(1_000_000);
        source.push(7_u8);

        let retained = try_rehome_repository_vec(source, MAX_ACTIVE_WORKSPACES).unwrap();

        assert_eq!(retained, vec![7]);
        assert!(retained.capacity() <= MAX_ACTIVE_WORKSPACES);
    }

    #[test]
    fn repository_rehome_paths_preserve_injected_allocation_failure() {
        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            ReplicationObservation::try_new(vec![1]),
            Err(RepositoryPortError::AllocationFailed)
        ));

        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            ReplicationCommitRequest::try_new(vec![1]),
            Err(RepositoryPortError::AllocationFailed)
        ));

        for successful_reservations in 0..=2 {
            let repository = TempDir::new().unwrap();
            let local = TempDir::new().unwrap();
            crate::ports::inject_allocation_failure_after_for_test(successful_reservations);
            assert!(matches!(
                LocalVaultConfig::try_new(
                    repository.path().canonicalize().unwrap(),
                    local.path().canonicalize().unwrap(),
                    parameters(),
                    "device".to_owned(),
                ),
                Err(RepositoryPortError::AllocationFailed)
            ));
        }

        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            try_rehome_repository_vec(vec![1_u8], 1),
            Err(RepositoryPortError::AllocationFailed)
        ));

        let store_id = notecrypt_store::cleanup_test_support::workspace_id([0xa1; 16]);
        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            crate::WorkspaceId::from_store(&store_id),
            Err(crate::HostPortError::AllocationFailed)
        ));
        let id = crate::WorkspaceId::from_store(&store_id).unwrap();
        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            id.try_duplicate(),
            Err(crate::HostPortError::AllocationFailed)
        ));

        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            generate_recovery_input(),
            Err(RepositoryPortError::AllocationFailed)
        ));
        crate::ports::inject_allocation_failure_after_for_test(1);
        assert!(generate_recovery_input().is_ok());
        assert!(crate::ports::allocation_failure_injected_for_test());

        assert_eq!(
            map_core_repository_error(notecrypt_core::CoreError::AllocationFailed),
            RepositoryPortError::AllocationFailed
        );
        assert_eq!(
            map_repository_error(RepositoryPortError::AllocationFailed),
            ServiceError::AllocationFailed
        );
    }

    #[test]
    fn absence_and_publication_bridges_preserve_allocation_failure() {
        let provider = Arc::new(UnavailableWorkspace);
        let store_id = notecrypt_store::cleanup_test_support::workspace_id([0xa2; 16]);
        let id = crate::WorkspaceId::from_store(&store_id).unwrap();

        let verifier = StoreWorkspaceAbsenceVerifier::new(provider.clone());
        crate::ports::inject_allocation_failure_after_for_test(0);
        assert_eq!(
            verifier.stage(&id, Box::new(TestAbsenceGuard)),
            Err(RepositoryPortError::AllocationFailed)
        );

        let verifier = StoreWorkspaceAbsenceVerifier::new(provider);
        crate::ports::inject_allocation_failure_after_for_test(1);
        assert_eq!(
            verifier.stage(&id, Box::new(TestAbsenceGuard)),
            Err(RepositoryPortError::AllocationFailed)
        );

        let provider = Arc::new(WorkspaceBindingProvider {
            response_id: None,
            removed: Arc::new(AtomicUsize::new(0)),
            acquired_absence: Arc::new(AtomicUsize::new(0)),
            fail_absence_allocation: true,
        });
        let verifier = StoreWorkspaceAbsenceVerifier::new(provider);
        assert!(matches!(
            notecrypt_store::TrustedWorkspaceAbsenceVerifier::acquire_verified_absence(
                &verifier, &store_id
            ),
            Err(StoreError::AllocationFailed)
        ));

        let provider = Arc::new(UnavailableWorkspace);
        let verifier = StoreWorkspaceAbsenceVerifier::new(provider);
        crate::ports::inject_allocation_failure_after_for_test(0);
        assert!(matches!(
            notecrypt_store::TrustedWorkspaceAbsenceVerifier::acquire_verified_absence(
                &verifier, &store_id
            ),
            Err(StoreError::AllocationFailed)
        ));

        struct AllocationFailingPublication;
        impl VaultPublicationGuard for AllocationFailingPublication {
            fn validate(&mut self) -> Result<(), RepositoryPortError> {
                Err(RepositoryPortError::AllocationFailed)
            }
        }

        let mut service_guard = AllocationFailingPublication;
        let mut store_guard = StorePublicationGuard(&mut service_guard);
        let error = notecrypt_store::PublicationGuard::validate(&mut store_guard).unwrap_err();
        assert!(matches!(error, StoreError::AllocationFailed));
        assert_eq!(
            map_store_error(error),
            RepositoryPortError::AllocationFailed
        );
    }
}
