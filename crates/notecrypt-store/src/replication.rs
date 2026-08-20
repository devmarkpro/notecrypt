use std::cell::Cell;
use std::collections::HashMap;
use std::io::{self, Read, Seek, Write};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use notecrypt_core::{ObjectId, VaultId};
use notecrypt_crypto::{OsRandom, SecureRandom};
use notecrypt_format::{CryptoSuite, DecodeLimits, FormatVersion, decode_bootstrap};
use notecrypt_platform_fs::{
    Directory, ExclusiveFileLock, FileCapability, FilesystemIdentity, PhysicalComponent,
};

use crate::StoreError;
use crate::key_cell::{ImportAuthenticationBoundary, KeyCell};
use crate::layout::{component, encode_hex};
use crate::reachability::{
    AppliedReplicatedTransition, BackendObservationFingerprint, CommitContext,
    CommittedReachableHead, LocalHeadBinding, OperationRegistry, PendingRemotePublication,
    PendingUnprovableRemote, RecordContext, RemoteBaseline, VerificationContext,
    VerifiedReachableHead, accept_current_verified as accept_verified_current,
    acknowledge_unprovable_remote, commit_applied, commit_reconciled,
    confirm_reconciled_publication, observation_commitment,
    record_or_require_unprovable_acknowledgement, verified_target_locator, verify_reachable_graph,
};
use crate::repository::VaultStore;
use crate::transaction::{
    AuthenticatedHead, CancellationProbe as TransactionCancellationProbe, PublicationGuard,
    TransactionRequest, authenticate_head, commit as commit_transaction,
    read_and_authenticate_current_head,
};
use crate::trusted_remote::{
    TrustedRemoteProvenance, TrustedRemoteRecord, authenticate_trusted_remote_if_present,
    write_trusted_remote,
};

const GIB: u64 = 1 << 30;
const TIB: u64 = 1 << 40;
const OPERATION_ID_RETRIES: usize = 16;
const PROGRESS_PAGE_BYTES: u64 = 64 * 1024;
const MAX_STALE_QUARANTINES: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicationLimits {
    pub max_bootstrap_bytes: u64,
    pub max_head_bytes: u64,
    pub max_chunk_object_bytes: u64,
    pub max_manifest_object_bytes: u64,
    pub max_tree_object_bytes: u64,
    pub max_snapshot_object_bytes: u64,
    pub max_aggregate_bytes: u64,
    pub max_object_count: u64,
    pub max_graph_edges: u64,
    pub max_graph_depth: u32,
    pub max_duration: Duration,
    pub progress_interval: Duration,
    pub max_quarantine_bytes: u64,
    pub free_space_reserve_bytes: u64,
}

impl ReplicationLimits {
    pub const PHASE_1: Self = Self {
        max_bootstrap_bytes: 1 << 20,
        max_head_bytes: 64 << 10,
        max_chunk_object_bytes: (4 << 20) + (4 << 10),
        max_manifest_object_bytes: 64 << 20,
        max_tree_object_bytes: 256 << 20,
        max_snapshot_object_bytes: 1 << 20,
        max_aggregate_bytes: TIB,
        max_object_count: 10_000_000,
        max_graph_edges: 100_000,
        max_graph_depth: 100_000,
        max_duration: Duration::from_secs(30 * 60),
        progress_interval: Duration::from_secs(30),
        max_quarantine_bytes: TIB,
        free_space_reserve_bytes: GIB,
    };

    pub fn effective_quarantine_bytes(
        &self,
        backend_limit: u64,
        operation_limit: u64,
        starting_free: u64,
    ) -> Result<u64, StoreError> {
        let eighty_percent = (starting_free / 5)
            .checked_mul(4)
            .and_then(|whole| whole.checked_add((starting_free % 5) * 4 / 5))
            .ok_or(StoreError::LimitExceeded)?;
        let after_reserve = starting_free
            .checked_sub(self.free_space_reserve_bytes)
            .ok_or(StoreError::LimitExceeded)?;
        Ok(self
            .max_quarantine_bytes
            .min(self.max_aggregate_bytes)
            .min(backend_limit)
            .min(operation_limit)
            .min(eighty_percent)
            .min(after_reserve))
    }

    pub(crate) fn maximum_for_kind(self, kind: ImportedObjectKind) -> u64 {
        match kind {
            ImportedObjectKind::Chunk => self.max_chunk_object_bytes,
            ImportedObjectKind::Manifest => self.max_manifest_object_bytes,
            ImportedObjectKind::Tree => self.max_tree_object_bytes,
            ImportedObjectKind::Snapshot => self.max_snapshot_object_bytes,
        }
    }

    #[must_use]
    pub fn strictest(self, other: Self) -> Self {
        Self {
            max_bootstrap_bytes: self.max_bootstrap_bytes.min(other.max_bootstrap_bytes),
            max_head_bytes: self.max_head_bytes.min(other.max_head_bytes),
            max_chunk_object_bytes: self
                .max_chunk_object_bytes
                .min(other.max_chunk_object_bytes),
            max_manifest_object_bytes: self
                .max_manifest_object_bytes
                .min(other.max_manifest_object_bytes),
            max_tree_object_bytes: self.max_tree_object_bytes.min(other.max_tree_object_bytes),
            max_snapshot_object_bytes: self
                .max_snapshot_object_bytes
                .min(other.max_snapshot_object_bytes),
            max_aggregate_bytes: self.max_aggregate_bytes.min(other.max_aggregate_bytes),
            max_object_count: self.max_object_count.min(other.max_object_count),
            max_graph_edges: self.max_graph_edges.min(other.max_graph_edges),
            max_graph_depth: self.max_graph_depth.min(other.max_graph_depth),
            max_duration: self.max_duration.min(other.max_duration),
            progress_interval: self.progress_interval.min(other.progress_interval),
            max_quarantine_bytes: self.max_quarantine_bytes.min(other.max_quarantine_bytes),
            free_space_reserve_bytes: self
                .free_space_reserve_bytes
                .max(other.free_space_reserve_bytes),
        }
    }
}

pub struct ReplicationBudget {
    limits: ReplicationLimits,
    aggregate_bytes: u64,
    objects: u64,
    edges: u64,
}

impl ReplicationBudget {
    #[must_use]
    pub const fn new(limits: ReplicationLimits) -> Self {
        Self {
            limits,
            aggregate_bytes: 0,
            objects: 0,
            edges: 0,
        }
    }

    pub fn add_object(&mut self, bytes: u64) -> Result<(), StoreError> {
        let next_objects = self
            .objects
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?;
        let next_bytes = self
            .aggregate_bytes
            .checked_add(bytes)
            .ok_or(StoreError::LimitExceeded)?;
        if next_objects > self.limits.max_object_count
            || next_bytes > self.limits.max_aggregate_bytes
        {
            return Err(StoreError::LimitExceeded);
        }
        self.objects = next_objects;
        self.aggregate_bytes = next_bytes;
        Ok(())
    }

    pub fn add_edges(&mut self, count: u64) -> Result<(), StoreError> {
        let next = self
            .edges
            .checked_add(count)
            .ok_or(StoreError::LimitExceeded)?;
        if next > self.limits.max_graph_edges {
            return Err(StoreError::LimitExceeded);
        }
        self.edges = next;
        Ok(())
    }

    pub fn check_depth(&self, depth: u32) -> Result<(), StoreError> {
        if depth > self.limits.max_graph_depth {
            Err(StoreError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportedObjectKind {
    Chunk,
    Manifest,
    Tree,
    Snapshot,
}

pub struct ImportedObjectMetadata {
    id: ObjectId,
    kind: ImportedObjectKind,
    encoded_length: u64,
    references: Vec<ObjectId>,
    semantics: AuthenticatedObjectSemantics,
}

pub(crate) enum AuthenticatedObjectSemantics {
    Chunk {
        file_id: [u8; 16],
        position: u64,
    },
    Manifest {
        file_id: [u8; 16],
        revision_id: [u8; 32],
        chunks: Vec<AuthenticatedChunkReference>,
    },
    Tree {
        revisions: Vec<AuthenticatedRevisionLocator>,
    },
    Snapshot {
        snapshot_id: [u8; 32],
        parents: Vec<AuthenticatedSnapshotParent>,
        tree_object_id: ObjectId,
    },
}

pub(crate) struct AuthenticatedRevisionLocator {
    pub(crate) file_id: [u8; 16],
    pub(crate) revision_id: [u8; 32],
    pub(crate) manifest_object_id: ObjectId,
}

pub(crate) struct AuthenticatedSnapshotParent {
    pub(crate) snapshot_id: [u8; 32],
    pub(crate) snapshot_object_id: ObjectId,
}

pub(crate) struct AuthenticatedChunkReference {
    pub(crate) object_id: ObjectId,
    pub(crate) position: u64,
}

pub(crate) fn authenticated_object_id(bytes: [u8; 32]) -> ObjectId {
    ObjectId::from_bytes(bytes)
}

impl ImportedObjectMetadata {
    pub(crate) fn authenticated(
        id: ObjectId,
        kind: ImportedObjectKind,
        encoded_length: u64,
        references: Vec<ObjectId>,
        semantics: AuthenticatedObjectSemantics,
    ) -> Self {
        Self {
            id,
            kind,
            encoded_length,
            references,
            semantics,
        }
    }

    pub(crate) const fn semantics(&self) -> &AuthenticatedObjectSemantics {
        &self.semantics
    }

    #[must_use]
    pub const fn id(&self) -> ObjectId {
        self.id
    }

    #[must_use]
    pub const fn kind(&self) -> ImportedObjectKind {
        self.kind
    }

    #[must_use]
    pub const fn encoded_length(&self) -> u64 {
        self.encoded_length
    }

    #[must_use]
    pub fn references(&self) -> &[ObjectId] {
        &self.references
    }
}

/// A bounded, operation-owned quarantine sink.
///
/// Dropping it before `finish` removes its complete operation directory and
/// releases its global disk reservation.
pub trait QuarantineImport: Write + Send {
    fn finish(self: Box<Self>) -> Result<ImportedObjectMetadata, StoreError>;
}

pub trait ReplicationLease: Send {
    fn cancellation_handle(&self) -> ReplicationCancellation;

    fn cancel(&self);

    fn authenticate_bootstrap(&mut self, bytes: &[u8]) -> Result<(), StoreError>;

    fn authenticate_head(&mut self, bytes: &[u8]) -> Result<AuthenticatedHead, StoreError>;

    fn contains_object(&mut self, id: &ObjectId) -> Result<bool, StoreError>;

    fn begin_import(
        &mut self,
        expected_id: ObjectId,
        kind: ImportedObjectKind,
        declared_length: u64,
    ) -> Result<Box<dyn QuarantineImport + '_>, StoreError>;

    fn verify_reachable(
        &mut self,
        head: AuthenticatedHead,
        observation: BackendObservationFingerprint,
    ) -> Result<VerifiedReachableHead, StoreError>;

    fn export_encrypted(
        &mut self,
        id: &ObjectId,
        output: &mut dyn Write,
    ) -> Result<u64, StoreError>;

    fn commit_replicated_snapshot(
        &mut self,
        verified: VerifiedReachableHead,
        request: CommitReplicatedSnapshot,
        guard: &mut dyn PublicationGuard,
    ) -> Result<CommittedReachableHead, StoreError>;

    fn commit_reconciled_snapshot(
        &mut self,
        verified_remote: VerifiedReachableHead,
        request: CommitReplicatedSnapshot,
        guard: &mut dyn PublicationGuard,
    ) -> Result<PendingRemotePublication, StoreError>;

    fn confirm_reconciled_publication(
        &mut self,
        pending: PendingRemotePublication,
        verified_readback: VerifiedReachableHead,
    ) -> Result<CommittedReachableHead, StoreError>;

    fn accept_current_verified(
        &mut self,
        verified: VerifiedReachableHead,
    ) -> Result<CommittedReachableHead, StoreError>;

    fn record_trusted_remote(
        &mut self,
        committed: CommittedReachableHead,
    ) -> Result<Option<PendingUnprovableRemote>, StoreError>;

    fn acknowledge_unprovable_remote(
        &mut self,
        pending: PendingUnprovableRemote,
    ) -> Result<(), StoreError>;

    fn finish(self: Box<Self>) -> Result<(), StoreError>;
}

/// Opaque one-way cancellation handle bound to one replication operation.
#[derive(Clone)]
pub struct ReplicationCancellation {
    cancelled: Arc<AtomicBool>,
}

impl ReplicationCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// Read-only cancellation state checked at every bounded replication boundary.
pub trait ReplicationCancellationProbe: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

struct ReplicationTransactionCancellation<'a> {
    local: &'a AtomicBool,
    external: Option<&'a dyn ReplicationCancellationProbe>,
}

impl TransactionCancellationProbe for ReplicationTransactionCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.local.load(Ordering::Acquire)
            || self
                .external
                .is_some_and(ReplicationCancellationProbe::is_cancelled)
    }
}

pub struct CommitReplicatedSnapshot {
    intended_head: Vec<u8>,
}

impl CommitReplicatedSnapshot {
    #[must_use]
    pub fn new(intended_head: Vec<u8>) -> Self {
        Self { intended_head }
    }

    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn retained_capacity_for_test(&self) -> usize {
        self.intended_head.capacity()
    }
}

pub(crate) trait ReplicationClock: Send + Sync {
    fn elapsed(&self) -> Duration;
}

pub(crate) trait FreeSpaceProbe: Send + Sync {
    fn available_bytes(&self) -> Result<u64, StoreError>;
}

pub(crate) trait OperationStatusProbe: Send + Sync {
    fn check(&self) -> Result<(), StoreError>;
}

pub(crate) struct SystemClock {
    started: Instant,
}

enum ClockSource<'a> {
    System(SystemClock),
    #[allow(dead_code)]
    Injected(&'a dyn ReplicationClock),
}

impl ClockSource<'_> {
    fn elapsed(&self) -> Duration {
        match self {
            Self::System(clock) => clock.elapsed(),
            Self::Injected(clock) => clock.elapsed(),
        }
    }
}

enum SpaceSource<'a> {
    Directory,
    #[allow(dead_code)]
    Injected(&'a dyn FreeSpaceProbe),
}

impl SpaceSource<'_> {
    fn available_bytes(&self, directory: &Directory) -> Result<u64, StoreError> {
        match self {
            Self::Directory => directory.available_space().map_err(StoreError::from),
            Self::Injected(space) => space.available_bytes(),
        }
    }
}

enum Shared<'a, T: ?Sized> {
    #[cfg_attr(not(test), allow(dead_code))]
    Borrowed(&'a T),
    Owned(Arc<T>),
}

impl<T: ?Sized> Deref for Shared<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
        }
    }
}

enum StatusSource<'a> {
    Keys {
        keys: Shared<'a, KeyCell>,
        generation: u64,
    },
    #[allow(dead_code)]
    Injected(&'a dyn OperationStatusProbe),
}

impl StatusSource<'_> {
    fn check(&self) -> Result<(), StoreError> {
        match self {
            Self::Keys { keys, generation } => keys.validate_generation(*generation),
            Self::Injected(status) => status.check(),
        }
    }
}

impl SystemClock {
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl ReplicationClock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

pub(crate) struct QuarantineReservations {
    state: Mutex<ReservationState>,
}

static RESERVATIONS_BY_FILESYSTEM: OnceLock<
    Mutex<HashMap<FilesystemIdentity, Weak<QuarantineReservations>>>,
> = OnceLock::new();

pub(crate) fn reservations_for(
    directory: &Directory,
) -> Result<Arc<QuarantineReservations>, StoreError> {
    let identity = directory.filesystem_identity();
    let registry = RESERVATIONS_BY_FILESYSTEM.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().map_err(|_| StoreError::LimitExceeded)?;
    registry.retain(|_, reservations| reservations.strong_count() != 0);
    if let Some(reservations) = registry.get(&identity).and_then(Weak::upgrade) {
        return Ok(reservations);
    }
    let reservations = Arc::new(QuarantineReservations::default());
    registry.insert(identity, Arc::downgrade(&reservations));
    Ok(reservations)
}

#[derive(Default)]
struct ReservationState {
    reserved: u64,
    ceiling: Option<u64>,
    active: u64,
    orphaned: HashMap<([u8; 16], [u8; 16]), u64>,
}

impl Default for QuarantineReservations {
    fn default() -> Self {
        Self {
            state: Mutex::new(ReservationState::default()),
        }
    }
}

impl QuarantineReservations {
    fn reserve(&self, amount: u64, maximum_total: u64) -> Result<(), StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::LimitExceeded)?;
        let ceiling = state
            .ceiling
            .map_or(maximum_total, |current| current.min(maximum_total));
        let next = state
            .reserved
            .checked_add(amount)
            .filter(|next| *next <= ceiling)
            .ok_or(StoreError::LimitExceeded)?;
        state.reserved = next;
        state.ceiling = Some(ceiling);
        state.active = state
            .active
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?;
        Ok(())
    }

    fn release(&self, amount: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        debug_assert!(state.reserved >= amount, "quarantine reservation underflow");
        state.reserved = state.reserved.saturating_sub(amount);
        state.active = state.active.saturating_sub(1);
        if state.active == 0 {
            state.ceiling = None;
        }
    }

    fn retain_orphan(
        &self,
        vault: VaultId,
        operation: [u8; 16],
        amount: u64,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::LimitExceeded)?;
        state
            .orphaned
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        state
            .orphaned
            .insert((*vault.as_bytes(), operation), amount);
        Ok(())
    }

    fn reconcile_swept(&self, vault: VaultId, operations: &[[u8; 16]]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        for operation in operations {
            let Some(amount) = state.orphaned.remove(&(*vault.as_bytes(), *operation)) else {
                continue;
            };
            state.reserved = state.reserved.saturating_sub(amount);
            state.active = state.active.saturating_sub(1);
        }
        if state.active == 0 {
            state.ceiling = None;
        }
    }

    #[cfg(test)]
    fn reserved(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .reserved
    }
}

pub(crate) struct QuarantineLease<'a> {
    store: Shared<'a, VaultStore>,
    operation: Directory,
    operation_name: PhysicalComponent,
    operation_id: ReplicationOperationId,
    operation_registry: Arc<OperationRegistry>,
    limits: ReplicationLimits,
    store_limits: ReplicationLimits,
    effective_quarantine_bytes: u64,
    reservations: Shared<'a, QuarantineReservations>,
    clock: ClockSource<'a>,
    space: SpaceSource<'a>,
    revocation: StatusSource<'a>,
    authenticator: ImportAuthenticator<'a>,
    budget: ReplicationBudget,
    imported: HashMap<ObjectId, VerifiedQuarantineObject>,
    bootstrap_commitment: Option<[u8; 32]>,
    expected_bootstrap: Option<Shared<'a, [u8]>>,
    operation_state: Arc<AtomicU8>,
    verified_context: Option<VerifiedOperationContext>,
    imports_published: bool,
    cancelled: Arc<AtomicBool>,
    started: Duration,
    last_progress: Cell<Duration>,
    terminal: bool,
    cleaned: bool,
    reservation_owned: bool,
    external_cancellation: Option<Arc<dyn ReplicationCancellationProbe>>,
    _os_lock: ExclusiveFileLock,
}

struct VerifiedOperationContext {
    bootstrap_commitment: [u8; 32],
    head_commitment: [u8; 32],
    observation_commitment: [u8; 32],
    local_head: Option<LocalHeadBinding>,
    prior_remote: Option<RemoteBaseline>,
}

pub(crate) struct ReplicationOperationId([u8; 16]);

impl ReplicationOperationId {
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

struct VerifiedQuarantineObject {
    kind: ImportedObjectKind,
    encoded_length: u64,
    file: FileCapability,
}

#[cfg(test)]
type ScriptedAuthenticateImport<'a> = dyn Fn(
        ObjectId,
        ImportedObjectKind,
        &mut FileCapability,
    ) -> Result<ImportedObjectMetadata, StoreError>
    + Send
    + Sync
    + 'a;

enum ImportAuthenticator<'a> {
    Keys {
        keys: Shared<'a, KeyCell>,
        generation: u64,
        vault: VaultId,
    },
    #[cfg(test)]
    Scripted(&'a ScriptedAuthenticateImport<'a>),
}

impl ImportAuthenticator<'_> {
    fn authenticate(
        &self,
        expected: ObjectId,
        kind: ImportedObjectKind,
        file: &mut FileCapability,
        mut observe: impl FnMut(ImportAuthenticationBoundary) -> Result<(), StoreError>,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        match self {
            Self::Keys {
                keys,
                generation,
                vault,
            } => keys.authenticate_imported_object(
                *generation,
                *vault,
                expected,
                kind,
                file,
                &mut observe,
            ),
            #[cfg(test)]
            Self::Scripted(authenticate) => {
                observe(ImportAuthenticationBoundary::BeforeCrypto)?;
                let metadata = authenticate(expected, kind, file)?;
                observe(ImportAuthenticationBoundary::AfterCrypto)?;
                observe(ImportAuthenticationBoundary::AfterProtectedDecode)?;
                observe(ImportAuthenticationBoundary::BeforeAcceptReferences)?;
                Ok(metadata)
            }
        }
    }

    fn authenticate_head(&self, bytes: &[u8]) -> Result<AuthenticatedHead, StoreError> {
        match self {
            Self::Keys {
                keys, generation, ..
            } => authenticate_head(bytes, keys, *generation),
            #[cfg(test)]
            Self::Scripted(_) => Err(StoreError::InvalidCapability),
        }
    }
}

impl QuarantineLease<'static> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn acquire_authenticated(
        store: Arc<VaultStore>,
        limits: ReplicationLimits,
        backend_limits: ReplicationLimits,
        operation_limits: ReplicationLimits,
        keys: Arc<KeyCell>,
        generation: u64,
        vault: VaultId,
        expected_bootstrap: Arc<[u8]>,
        external_cancellation: Option<Arc<dyn ReplicationCancellationProbe>>,
    ) -> Result<Self, StoreError> {
        let mut random = OsRandom;
        let reservations = Arc::clone(&store.quarantine_reservations);
        Self::acquire_with_authenticator(
            Shared::Owned(store),
            limits,
            backend_limits,
            operation_limits,
            Shared::Owned(reservations),
            ClockSource::System(SystemClock::start()),
            SpaceSource::Directory,
            StatusSource::Keys {
                keys: Shared::Owned(Arc::clone(&keys)),
                generation,
            },
            ImportAuthenticator::Keys {
                keys: Shared::Owned(keys),
                generation,
                vault,
            },
            Some(Shared::Owned(expected_bootstrap)),
            external_cancellation,
            &mut random,
        )
    }
}

impl<'a> QuarantineLease<'a> {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn acquire_authenticated_borrowed(
        store: &'a VaultStore,
        limits: ReplicationLimits,
        backend_limits: ReplicationLimits,
        operation_limits: ReplicationLimits,
        keys: &'a KeyCell,
        generation: u64,
        vault: VaultId,
        expected_bootstrap: &'a [u8],
    ) -> Result<Self, StoreError> {
        let mut random = OsRandom;
        Self::acquire_with_authenticator(
            Shared::Borrowed(store),
            limits,
            backend_limits,
            operation_limits,
            Shared::Borrowed(&store.quarantine_reservations),
            ClockSource::System(SystemClock::start()),
            SpaceSource::Directory,
            StatusSource::Keys {
                keys: Shared::Borrowed(keys),
                generation,
            },
            ImportAuthenticator::Keys {
                keys: Shared::Borrowed(keys),
                generation,
                vault,
            },
            Some(Shared::Borrowed(expected_bootstrap)),
            None,
            &mut random,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn acquire(
        store: &'a VaultStore,
        limits: ReplicationLimits,
        backend_limits: ReplicationLimits,
        operation_limits: ReplicationLimits,
        reservations: &'a QuarantineReservations,
        clock: &'a dyn ReplicationClock,
        space: &'a dyn FreeSpaceProbe,
        revocation: &'a dyn OperationStatusProbe,
        authenticate: &'a ScriptedAuthenticateImport<'a>,
    ) -> Result<Self, StoreError> {
        let mut random = OsRandom;
        let mut lease = Self::acquire_with_authenticator(
            Shared::Borrowed(store),
            limits,
            backend_limits,
            operation_limits,
            Shared::Borrowed(reservations),
            ClockSource::Injected(clock),
            SpaceSource::Injected(space),
            StatusSource::Injected(revocation),
            ImportAuthenticator::Scripted(authenticate),
            None,
            None,
            &mut random,
        )?;
        // Import-focused unit tests start after the remote bootstrap has already
        // been authenticated. Tests for ordering clear this test-only binding.
        lease.bootstrap_commitment = Some([0x42; 32]);
        Ok(lease)
    }

    #[allow(clippy::too_many_arguments)]
    fn acquire_with_authenticator(
        store: Shared<'a, VaultStore>,
        limits: ReplicationLimits,
        backend_limits: ReplicationLimits,
        operation_limits: ReplicationLimits,
        reservations: Shared<'a, QuarantineReservations>,
        clock: ClockSource<'a>,
        space: SpaceSource<'a>,
        revocation: StatusSource<'a>,
        authenticator: ImportAuthenticator<'a>,
        expected_bootstrap: Option<Shared<'a, [u8]>>,
        external_cancellation: Option<Arc<dyn ReplicationCancellationProbe>>,
        random: &mut dyn SecureRandom,
    ) -> Result<Self, StoreError> {
        let root = &store.layout.quarantine;
        revocation.check()?;
        let os_lock = root
            .try_lock_exclusive(&component("replication-lock")?)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    StoreError::Busy
                } else {
                    StoreError::from(error)
                }
            })?;
        let swept = sweep_stale_quarantines(root)?;
        reservations.reconcile_swept(store.layout.vault, &swept);
        let store_limits = limits;
        let limits = store_limits
            .strictest(backend_limits)
            .strictest(operation_limits);
        let starting_free = space.available_bytes(root)?;
        let mut effective = limits.effective_quarantine_bytes(
            limits.max_quarantine_bytes,
            limits.max_quarantine_bytes,
            starting_free,
        )?;
        let mut global_policy = store_limits;
        global_policy.free_space_reserve_bytes = limits.free_space_reserve_bytes;
        let global_maximum =
            global_policy.effective_quarantine_bytes(u64::MAX, u64::MAX, starting_free)?;
        if std::ptr::eq(&*reservations, Arc::as_ptr(&store.repository_reservations)) {
            effective = effective.min(global_maximum / 2);
        }
        if effective == 0 {
            return Err(StoreError::LimitExceeded);
        }
        reservations.reserve(effective, global_maximum)?;
        let operation_registry = Arc::clone(&store.replication_operations);
        let (operation_id, operation_name, operation) =
            match create_registered_operation(root, random, &operation_registry) {
                Ok(operation) => operation,
                Err(failure) => {
                    if let Some(operation) = failure.residue {
                        reservations.retain_orphan(store.layout.vault, operation, effective)?;
                    } else {
                        reservations.release(effective);
                    }
                    return Err(failure.error);
                }
            };
        let started = clock.elapsed();
        Ok(Self {
            store,
            operation,
            operation_name,
            operation_id,
            operation_registry,
            limits,
            store_limits,
            effective_quarantine_bytes: effective,
            reservations,
            clock,
            space,
            revocation,
            authenticator,
            budget: ReplicationBudget::new(limits),
            imported: HashMap::new(),
            bootstrap_commitment: None,
            expected_bootstrap,
            operation_state: Arc::new(AtomicU8::new(0)),
            verified_context: None,
            imports_published: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            started,
            last_progress: Cell::new(started),
            terminal: false,
            cleaned: false,
            reservation_owned: true,
            external_cancellation,
            _os_lock: os_lock,
        })
    }

    fn check_boundary(&self, pending_bytes: u64) -> Result<Duration, StoreError> {
        if self.cancelled.load(Ordering::Acquire)
            || self
                .external_cancellation
                .as_ref()
                .is_some_and(|cancellation| cancellation.is_cancelled())
        {
            return Err(StoreError::Cancelled);
        }
        self.revocation.check()?;
        if self.terminal {
            return Err(StoreError::InvalidCapability);
        }
        let now = self.clock.elapsed();
        if now.saturating_sub(self.started) > self.limits.max_duration
            || now.saturating_sub(self.last_progress.get()) > self.limits.progress_interval
        {
            return Err(StoreError::TimedOut);
        }
        let available = self.space.available_bytes(&self.store.layout.quarantine)?;
        let needed = self
            .limits
            .free_space_reserve_bytes
            .checked_add(pending_bytes)
            .ok_or(StoreError::LimitExceeded)?;
        if available < needed {
            return Err(StoreError::LimitExceeded);
        }
        Ok(now)
    }

    fn check_repository_boundary(&self, pending_bytes: u64) -> Result<(), StoreError> {
        let available = self.store.layout.transactions.available_space()?;
        let needed = self
            .limits
            .free_space_reserve_bytes
            .checked_add(pending_bytes)
            .ok_or(StoreError::LimitExceeded)?;
        if available < needed {
            return Err(StoreError::LimitExceeded);
        }
        Ok(())
    }

    fn record_context(&self, generation: u64) -> Result<RecordContext, StoreError> {
        let verified = self
            .verified_context
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        Ok(RecordContext {
            vault: self.store.layout.vault,
            generation,
            bootstrap_commitment: verified.bootstrap_commitment,
            head_commitment: verified.head_commitment,
            limits: self.limits,
            observation_commitment: verified.observation_commitment,
            operation: *self.operation_id.as_bytes(),
            local_head: verified.local_head,
            prior_remote: verified.prior_remote,
            state: Arc::clone(&self.operation_state),
            registry: Arc::clone(&self.operation_registry),
        })
    }

    fn cleanup(&mut self) -> Result<(), StoreError> {
        if self.cleaned {
            return Ok(());
        }
        let maximum_files =
            usize::try_from(self.limits.max_object_count).map_err(|_| StoreError::LimitExceeded)?;
        self.store
            .layout
            .quarantine
            .remove_private_file_tree(&self.operation_name, maximum_files)?;
        self.cleaned = true;
        Ok(())
    }

    fn cleanup_terminal(&mut self) -> Result<(), StoreError> {
        match self.cleanup() {
            Ok(()) => {
                self.release_reservation_after_cleanup();
                Ok(())
            }
            Err(error) => {
                self.retain_owned_reservation_as_orphan()?;
                Err(error)
            }
        }
    }

    fn release_owned_reservation(&mut self) {
        if self.reservation_owned {
            self.reservations.release(self.effective_quarantine_bytes);
            self.reservation_owned = false;
        }
    }

    fn release_reservation_after_cleanup(&mut self) {
        if self.reservation_owned {
            self.release_owned_reservation();
        } else {
            self.reservations
                .reconcile_swept(self.store.layout.vault, &[*self.operation_id.as_bytes()]);
        }
    }

    fn retain_owned_reservation_as_orphan(&mut self) -> Result<(), StoreError> {
        if self.reservation_owned {
            self.reservations.retain_orphan(
                self.store.layout.vault,
                *self.operation_id.as_bytes(),
                self.effective_quarantine_bytes,
            )?;
            self.reservation_owned = false;
        }
        Ok(())
    }

    fn fail(&mut self, primary: StoreError) -> StoreError {
        self.terminal = true;
        match self.cleanup() {
            Ok(()) => {
                self.release_owned_reservation();
                primary
            }
            Err(StoreError::Io(cleanup)) => {
                if let Err(reservation) = self.retain_owned_reservation_as_orphan() {
                    return reservation;
                }
                StoreError::CleanupAfterFailure {
                    primary: Box::new(primary),
                    cleanup,
                }
            }
            Err(cleanup) => {
                if let Err(reservation) = self.retain_owned_reservation_as_orphan() {
                    return reservation;
                }
                cleanup
            }
        }
    }

    fn publish_verified_imports(&mut self) -> Result<(), StoreError> {
        if self.imports_published {
            return Ok(());
        }
        if self.imported.is_empty() {
            self.imports_published = true;
            return Ok(());
        }
        let mut identities = Vec::new();
        identities
            .try_reserve_exact(self.imported.len())
            .map_err(|_| StoreError::LimitExceeded)?;
        identities.extend(self.imported.keys().copied());
        identities.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        let publication_bytes = self.budget.aggregate_bytes;
        let repository_free = self.store.layout.transactions.available_space()?;
        let repository_maximum =
            self.store_limits
                .effective_quarantine_bytes(u64::MAX, u64::MAX, repository_free)?;
        self.store
            .repository_reservations
            .reserve(publication_bytes, repository_maximum)?;
        let publication = self.publish_verified_imports_reserved(&identities);
        self.store
            .repository_reservations
            .release(publication_bytes);
        if publication.is_ok() {
            self.imports_published = true;
        }
        publication
    }

    fn publish_verified_imports_reserved(
        &mut self,
        identities: &[ObjectId],
    ) -> Result<(), StoreError> {
        let mut batch = self.store.begin_durable_batch()?;
        for id in identities {
            self.check_boundary(0)?;
            let mut verified = self
                .imported
                .remove(id)
                .ok_or(StoreError::InvalidCapability)?;
            verified.file.seek(std::io::SeekFrom::Start(0))?;
            let stage = batch.stage_checked(
                *id,
                &mut verified.file,
                verified.encoded_length,
                |pending| {
                    self.check_boundary(0)?;
                    self.check_repository_boundary(pending)?;
                    if pending == 0 {
                        self.last_progress.set(self.clock.elapsed());
                    }
                    Ok(())
                },
            );
            self.imported.insert(*id, verified);
            stage?;
        }

        let _publication = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => Some(keys.authorize_publication(*generation)?),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => None,
        };
        let imported = &self.imported;
        let authenticator = &self.authenticator;
        let published = batch.authenticate_and_publish_checked(
            |id, file| {
                self.check_boundary(0)?;
                let verified = imported.get(id).ok_or(StoreError::InvalidCapability)?;
                let metadata =
                    authenticator.authenticate(*id, verified.kind, file, |boundary| {
                        self.check_boundary(0)?;
                        if boundary == ImportAuthenticationBoundary::ReadPageComplete {
                            self.last_progress.set(self.clock.elapsed());
                        }
                        Ok(())
                    })?;
                if metadata.id != *id
                    || metadata.kind != verified.kind
                    || metadata.encoded_length != verified.encoded_length
                {
                    return Err(StoreError::AuthenticationFailed);
                }
                self.check_boundary(0)?;
                self.last_progress.set(self.clock.elapsed());
                Ok(())
            },
            || self.check_boundary(0).map(|_| ()),
        )?;
        published.finish()?;
        self.check_boundary(0)?;
        Ok(())
    }
}

impl ReplicationLease for QuarantineLease<'_> {
    fn cancellation_handle(&self) -> ReplicationCancellation {
        ReplicationCancellation {
            cancelled: Arc::clone(&self.cancelled),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn authenticate_bootstrap(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        let encoded_length = match u64::try_from(bytes.len()) {
            Ok(length) => length,
            Err(_) => return Err(self.fail(StoreError::LimitExceeded)),
        };
        if encoded_length > self.limits.max_bootstrap_bytes {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        let bootstrap = match decode_bootstrap(bytes, &DecodeLimits::PHASE_1) {
            Ok(bootstrap) => bootstrap,
            Err(_) => return Err(self.fail(StoreError::AuthenticationFailed)),
        };
        if bootstrap.vault_id() != self.store.layout.vault.as_bytes()
            || bootstrap.version() != FormatVersion::v1()
            || bootstrap.suite() != CryptoSuite::profile_one()
        {
            return Err(self.fail(StoreError::AuthenticationFailed));
        }
        if self
            .expected_bootstrap
            .as_deref()
            .is_some_and(|expected| expected != bytes)
        {
            return Err(self.fail(StoreError::AuthenticationFailed));
        }
        self.bootstrap_commitment = Some(*blake3::hash(bytes).as_bytes());
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        self.last_progress.set(self.clock.elapsed());
        Ok(())
    }

    fn authenticate_head(&mut self, bytes: &[u8]) -> Result<AuthenticatedHead, StoreError> {
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        if u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?
            > self.limits.max_head_bytes
        {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        if self.bootstrap_commitment.is_none() {
            return Err(self.fail(StoreError::InvalidCapability));
        }
        let head = match self.authenticator.authenticate_head(bytes) {
            Ok(head) if head.vault == self.store.layout.vault => head,
            Ok(_) => return Err(self.fail(StoreError::AuthenticationFailed)),
            Err(error) => return Err(self.fail(error)),
        };
        self.check_boundary(0)?;
        self.last_progress.set(self.clock.elapsed());
        Ok(head)
    }

    fn contains_object(&mut self, id: &ObjectId) -> Result<bool, StoreError> {
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        let exists = self.imported.contains_key(id)
            || match self.store.open_object(id) {
                Ok(_) => true,
                Err(StoreError::NotFound) => false,
                Err(error) => return Err(self.fail(error)),
            };
        self.check_boundary(0)?;
        Ok(exists)
    }

    fn begin_import(
        &mut self,
        expected_id: ObjectId,
        kind: ImportedObjectKind,
        declared_length: u64,
    ) -> Result<Box<dyn QuarantineImport + '_>, StoreError> {
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        if self.bootstrap_commitment.is_none() {
            return Err(self.fail(StoreError::InvalidCapability));
        }
        if declared_length > self.limits.maximum_for_kind(kind)
            || declared_length > self.limits.max_aggregate_bytes
            || declared_length > self.effective_quarantine_bytes
        {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        if self.imported.contains_key(&expected_id) {
            return Err(self.fail(StoreError::ImmutableObjectConflict));
        }
        if self.budget.objects >= self.limits.max_object_count {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        if self.imported.try_reserve(1).is_err() {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        let file_name = component(&encode_hex(expected_id.as_bytes()))?;
        let file = match self.operation.create_private_file_new(&file_name) {
            Ok(file) => file,
            Err(primary) => {
                return Err(self.fail(StoreError::Io(primary)));
            }
        };
        Ok(Box::new(FilesystemQuarantineImport {
            lease: self,
            file_name,
            file: Some(file),
            expected_id,
            kind,
            declared_length,
            written: 0,
            bytes_since_progress: 0,
            terminal: None,
            finished: false,
        }))
    }

    fn verify_reachable(
        &mut self,
        head: AuthenticatedHead,
        observation: BackendObservationFingerprint,
    ) -> Result<VerifiedReachableHead, StoreError> {
        let bootstrap_commitment = match self.bootstrap_commitment {
            Some(commitment) => commitment,
            None => return Err(self.fail(StoreError::InvalidCapability)),
        };
        if let Err(primary) = self.publish_verified_imports() {
            return Err(self.fail(primary));
        }
        let (keys, generation) = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => (&**keys, *generation),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => return Err(StoreError::InvalidCapability),
        };
        let local_head = read_and_authenticate_current_head(&self.store.layout, keys, generation)?
            .map(|current| LocalHeadBinding {
                snapshot: current.snapshot,
                snapshot_object: current.snapshot_object,
                tree_object: current.tree_object,
                head_commitment: current.commitment,
            });
        let prior_remote =
            authenticate_trusted_remote_if_present(&self.store.layout, keys, generation)?.map(
                |trusted| RemoteBaseline {
                    snapshot: trusted.snapshot(),
                    snapshot_object: trusted.snapshot_object(),
                },
            );
        let context = VerificationContext {
            vault: self.store.layout.vault,
            generation,
            bootstrap_commitment,
            limits: self.limits,
            operation: *self.operation_id.as_bytes(),
            local_head,
            prior_remote,
            state: Arc::clone(&self.operation_state),
            registry: Arc::clone(&self.operation_registry),
        };
        let head_commitment = head.commitment;
        let observation_bound = observation_commitment(&observation);
        let result = verify_reachable_graph(
            context,
            head,
            observation,
            |id, kind| {
                self.check_boundary(0)?;
                let mut file = self.store.open_object(&id)?;
                let metadata =
                    self.authenticator
                        .authenticate(id, kind, &mut file, |boundary| {
                            self.check_boundary(0)?;
                            if boundary == ImportAuthenticationBoundary::ReadPageComplete {
                                self.last_progress.set(self.clock.elapsed());
                            }
                            Ok(())
                        })?;
                self.check_boundary(0)?;
                self.last_progress.set(self.clock.elapsed());
                Ok(metadata)
            },
            || self.check_boundary(0).map(|_| ()),
        );
        match result {
            Ok(verified) => {
                self.verified_context = Some(VerifiedOperationContext {
                    bootstrap_commitment,
                    head_commitment,
                    observation_commitment: observation_bound,
                    local_head,
                    prior_remote,
                });
                Ok(verified)
            }
            Err(primary) => Err(self.fail(primary)),
        }
    }

    fn export_encrypted(
        &mut self,
        id: &ObjectId,
        output: &mut dyn Write,
    ) -> Result<u64, StoreError> {
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        let result = (|| {
            let mut file = self.store.open_object(id)?;
            let declared = file.len()?;
            if declared > self.limits.max_tree_object_bytes {
                return Err(StoreError::LimitExceeded);
            }
            let mut copied = 0_u64;
            let mut buffer = [0_u8; PROGRESS_PAGE_BYTES as usize];
            loop {
                self.check_boundary(0)?;
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                output.write_all(&buffer[..read])?;
                copied = copied
                    .checked_add(u64::try_from(read).map_err(|_| StoreError::LimitExceeded)?)
                    .ok_or(StoreError::LimitExceeded)?;
                if copied > declared || copied > self.limits.max_aggregate_bytes {
                    return Err(StoreError::LimitExceeded);
                }
                self.check_boundary(0)?;
                self.last_progress.set(self.clock.elapsed());
            }
            if copied != declared {
                return Err(StoreError::MalformedObject);
            }
            Ok(copied)
        })();
        match result {
            Ok(copied) => Ok(copied),
            Err(primary) => Err(self.fail(primary)),
        }
    }

    fn commit_replicated_snapshot(
        &mut self,
        verified: VerifiedReachableHead,
        request: CommitReplicatedSnapshot,
        guard: &mut dyn PublicationGuard,
    ) -> Result<CommittedReachableHead, StoreError> {
        self.check_boundary(0)?;
        if u64::try_from(request.intended_head.len()).map_err(|_| StoreError::LimitExceeded)?
            > self.limits.max_head_bytes
        {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        let (keys, generation) = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => (&**keys, *generation),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => return Err(StoreError::InvalidCapability),
        };
        let intended = authenticate_head(&request.intended_head, keys, generation)?;
        let verified_context = self
            .verified_context
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        if intended.commitment != verified_context.head_commitment {
            return Err(self.fail(StoreError::InvalidCapability));
        }
        let context = CommitContext {
            vault: self.store.layout.vault,
            generation,
            bootstrap_commitment: verified_context.bootstrap_commitment,
            head_commitment: verified_context.head_commitment,
            limits: self.limits,
            observation_commitment: verified_context.observation_commitment,
            operation: *self.operation_id.as_bytes(),
            local_head: verified_context.local_head,
            prior_remote: verified_context.prior_remote,
            state: Arc::clone(&self.operation_state),
            registry: Arc::clone(&self.operation_registry),
        };
        let target = intended.snapshot;
        let expected_local_head = verified_context.local_head;
        let transaction = TransactionRequest {
            objects: Vec::new(),
            intended_head: request.intended_head,
            expected_base: verified_context.local_head.map(|local| local.snapshot),
        };
        let cancel = ReplicationTransactionCancellation {
            local: &self.cancelled,
            external: self.external_cancellation.as_deref(),
        };
        let result = commit_applied(
            verified,
            context,
            target,
            AppliedReplicatedTransition::FastForward,
            || {
                let batch = self.store.begin_durable_batch()?;
                let current =
                    read_and_authenticate_current_head(&self.store.layout, keys, generation)?.map(
                        |head| LocalHeadBinding {
                            snapshot: head.snapshot,
                            snapshot_object: head.snapshot_object,
                            tree_object: head.tree_object,
                            head_commitment: head.commitment,
                        },
                    );
                if current != expected_local_head {
                    return Err(StoreError::RollbackDetected);
                }
                let committed = commit_transaction(
                    &self.store.layout,
                    batch,
                    keys,
                    transaction,
                    |_id, _file| Ok(()),
                    guard,
                    &cancel,
                )?;
                if committed.snapshot != target {
                    return Err(StoreError::AuthenticationFailed);
                }
                Ok(())
            },
        );
        match result {
            Ok(committed) => Ok(committed),
            Err(primary) => Err(self.fail(primary)),
        }
    }

    fn accept_current_verified(
        &mut self,
        verified: VerifiedReachableHead,
    ) -> Result<CommittedReachableHead, StoreError> {
        self.check_boundary(0)?;
        let (keys, generation) = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => (&**keys, *generation),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => return Err(StoreError::InvalidCapability),
        };
        let verified_context = self
            .verified_context
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let context = CommitContext {
            vault: self.store.layout.vault,
            generation,
            bootstrap_commitment: verified_context.bootstrap_commitment,
            head_commitment: verified_context.head_commitment,
            limits: self.limits,
            observation_commitment: verified_context.observation_commitment,
            operation: *self.operation_id.as_bytes(),
            local_head: verified_context.local_head,
            prior_remote: verified_context.prior_remote,
            state: Arc::clone(&self.operation_state),
            registry: Arc::clone(&self.operation_registry),
        };
        let result = accept_verified_current(verified, context, |target| {
            let current = read_and_authenticate_current_head(&self.store.layout, keys, generation)?
                .ok_or(StoreError::RollbackDetected)?;
            if current.snapshot != target
                || verified_context.local_head.is_some_and(|local| {
                    local.snapshot != current.snapshot
                        || local.snapshot_object != current.snapshot_object
                        || local.tree_object != current.tree_object
                        || local.head_commitment != current.commitment
                })
            {
                return Err(StoreError::RollbackDetected);
            }
            Ok(())
        });
        match result {
            Ok(committed) => Ok(committed),
            Err(primary) => Err(self.fail(primary)),
        }
    }

    fn commit_reconciled_snapshot(
        &mut self,
        verified_remote: VerifiedReachableHead,
        request: CommitReplicatedSnapshot,
        guard: &mut dyn PublicationGuard,
    ) -> Result<PendingRemotePublication, StoreError> {
        self.check_boundary(0)?;
        if u64::try_from(request.intended_head.len()).map_err(|_| StoreError::LimitExceeded)?
            > self.limits.max_head_bytes
        {
            return Err(self.fail(StoreError::LimitExceeded));
        }
        if let Err(primary) = self.publish_verified_imports() {
            return Err(self.fail(primary));
        }
        let (keys, generation) = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => (&**keys, *generation),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => return Err(StoreError::InvalidCapability),
        };
        let intended = authenticate_head(&request.intended_head, keys, generation)?;
        let candidate_head = AuthenticatedHead {
            vault: intended.vault,
            snapshot: intended.snapshot,
            commitment: intended.commitment,
            snapshot_object: intended.snapshot_object,
            tree_object: intended.tree_object,
        };
        let intended_for_proof = AuthenticatedHead {
            vault: intended.vault,
            snapshot: intended.snapshot,
            commitment: intended.commitment,
            snapshot_object: intended.snapshot_object,
            tree_object: intended.tree_object,
        };
        let verified_context = self
            .verified_context
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let local = verified_context
            .local_head
            .ok_or(StoreError::RollbackDetected)?;
        let remote = verified_target_locator(&verified_remote);
        if remote == (local.snapshot, local.snapshot_object)
            || intended.snapshot == local.snapshot
            || intended.snapshot == remote.0
        {
            return Err(self.fail(StoreError::RollbackDetected));
        }

        let mut candidate_parents = None;
        let candidate_context = VerificationContext {
            vault: self.store.layout.vault,
            generation,
            bootstrap_commitment: verified_context.bootstrap_commitment,
            limits: self.limits,
            operation: *self.operation_id.as_bytes(),
            local_head: Some(local),
            prior_remote: verified_context.prior_remote,
            state: Arc::clone(&self.operation_state),
            registry: Arc::clone(&self.operation_registry),
        };
        let candidate_observation = BackendObservationFingerprint::try_new(
            b"notecrypt/reconciliation-candidate/v1".to_vec(),
        )?;
        let candidate_snapshot_object = intended.snapshot_object;
        let candidate_proof = verify_reachable_graph(
            candidate_context,
            candidate_head,
            candidate_observation,
            |id, kind| {
                self.check_boundary(0)?;
                let mut file = self.store.open_object(&id)?;
                let metadata =
                    self.authenticator
                        .authenticate(id, kind, &mut file, |boundary| {
                            self.check_boundary(0)?;
                            if boundary == ImportAuthenticationBoundary::ReadPageComplete {
                                self.last_progress.set(self.clock.elapsed());
                            }
                            Ok(())
                        })?;
                if id == candidate_snapshot_object {
                    let AuthenticatedObjectSemantics::Snapshot { parents, .. } =
                        metadata.semantics()
                    else {
                        return Err(StoreError::AuthenticationFailed);
                    };
                    if parents.len() != 2 {
                        return Err(StoreError::AuthenticationFailed);
                    }
                    candidate_parents = Some([
                        (parents[0].snapshot_id, parents[0].snapshot_object_id),
                        (parents[1].snapshot_id, parents[1].snapshot_object_id),
                    ]);
                }
                Ok(metadata)
            },
            || self.check_boundary(0).map(|_| ()),
        )?;
        drop(candidate_proof);
        validate_reconciliation_parents(
            candidate_parents.ok_or(StoreError::AuthenticationFailed)?,
            local,
            remote,
        )?;

        let context = CommitContext {
            vault: self.store.layout.vault,
            generation,
            bootstrap_commitment: verified_context.bootstrap_commitment,
            head_commitment: verified_context.head_commitment,
            limits: self.limits,
            observation_commitment: verified_context.observation_commitment,
            operation: *self.operation_id.as_bytes(),
            local_head: Some(local),
            prior_remote: verified_context.prior_remote,
            state: Arc::clone(&self.operation_state),
            registry: Arc::clone(&self.operation_registry),
        };
        let target = intended.snapshot;
        let transaction = TransactionRequest {
            objects: Vec::new(),
            intended_head: request.intended_head,
            expected_base: Some(local.snapshot),
        };
        let cancel = ReplicationTransactionCancellation {
            local: &self.cancelled,
            external: self.external_cancellation.as_deref(),
        };
        let result = commit_reconciled(verified_remote, context, intended_for_proof, || {
            let batch = self.store.begin_durable_batch()?;
            let current = read_and_authenticate_current_head(&self.store.layout, keys, generation)?
                .map(|head| LocalHeadBinding {
                    snapshot: head.snapshot,
                    snapshot_object: head.snapshot_object,
                    tree_object: head.tree_object,
                    head_commitment: head.commitment,
                });
            if current != Some(local) {
                return Err(StoreError::RollbackDetected);
            }
            let committed = commit_transaction(
                &self.store.layout,
                batch,
                keys,
                transaction,
                |_id, _file| Ok(()),
                guard,
                &cancel,
            )?;
            if committed.snapshot != target {
                return Err(StoreError::AuthenticationFailed);
            }
            Ok(())
        });
        match result {
            Ok(committed) => Ok(committed),
            Err(primary) => Err(self.fail(primary)),
        }
    }

    fn confirm_reconciled_publication(
        &mut self,
        pending: PendingRemotePublication,
        verified_readback: VerifiedReachableHead,
    ) -> Result<CommittedReachableHead, StoreError> {
        let observed = self.accept_current_verified(verified_readback)?;
        confirm_reconciled_publication(pending, observed)
    }

    fn record_trusted_remote(
        &mut self,
        committed: CommittedReachableHead,
    ) -> Result<Option<PendingUnprovableRemote>, StoreError> {
        self.check_boundary(0)?;
        let (keys, generation) = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => (&**keys, *generation),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => return Err(StoreError::InvalidCapability),
        };
        let context = self.record_context(generation)?;
        record_or_require_unprovable_acknowledgement(committed, &context, |observation| {
            let _mutation = self.store.begin_store_mutation()?;
            let _publication = keys.authorize_publication(generation)?;
            self.check_boundary(0)?;
            write_trusted_remote(
                &self.store.layout,
                &TrustedRemoteRecord::new(
                    self.store.layout.vault,
                    observation.snapshot,
                    observation.snapshot_object,
                    observation.head_commitment,
                    observation.observation_commitment,
                    observation.binding_commitment,
                    TrustedRemoteProvenance::FreshnessProven,
                ),
                keys,
                generation,
            )
        })
    }

    fn acknowledge_unprovable_remote(
        &mut self,
        pending: PendingUnprovableRemote,
    ) -> Result<(), StoreError> {
        self.check_boundary(0)?;
        let (keys, generation) = match &self.authenticator {
            ImportAuthenticator::Keys {
                keys, generation, ..
            } => (&**keys, *generation),
            #[cfg(test)]
            ImportAuthenticator::Scripted(_) => return Err(StoreError::InvalidCapability),
        };
        let context = self.record_context(generation)?;
        acknowledge_unprovable_remote(pending, &context, |observation| {
            let _mutation = self.store.begin_store_mutation()?;
            let _publication = keys.authorize_publication(generation)?;
            self.check_boundary(0)?;
            write_trusted_remote(
                &self.store.layout,
                &TrustedRemoteRecord::new(
                    self.store.layout.vault,
                    observation.snapshot,
                    observation.snapshot_object,
                    observation.head_commitment,
                    observation.observation_commitment,
                    observation.binding_commitment,
                    TrustedRemoteProvenance::FreshnessUnprovableAcknowledged,
                ),
                keys,
                generation,
            )
        })
    }

    fn finish(mut self: Box<Self>) -> Result<(), StoreError> {
        if let Err(primary) = self.check_boundary(0) {
            return Err(self.fail(primary));
        }
        if let Err(primary) = self.publish_verified_imports() {
            return Err(self.fail(primary));
        }
        self.terminal = true;
        self.cleanup_terminal()
    }
}

fn validate_reconciliation_parents(
    mut parents: [([u8; 32], ObjectId); 2],
    local: LocalHeadBinding,
    remote: (notecrypt_core::SnapshotId, ObjectId),
) -> Result<(), StoreError> {
    parents.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    let mut expected = [
        (*local.snapshot.as_bytes(), local.snapshot_object),
        (*remote.0.as_bytes(), remote.1),
    ];
    expected.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    if parents == expected {
        Ok(())
    } else {
        Err(StoreError::AuthenticationFailed)
    }
}

impl Drop for QuarantineLease<'_> {
    fn drop(&mut self) {
        self.operation_registry
            .finish(*self.operation_id.as_bytes());
        if !self.cleaned {
            if self.cleanup().is_ok() {
                self.release_reservation_after_cleanup();
            } else {
                let _ = self.retain_owned_reservation_as_orphan();
            }
        } else {
            self.release_reservation_after_cleanup();
        }
    }
}

struct FilesystemQuarantineImport<'lease, 'root> {
    lease: &'lease mut QuarantineLease<'root>,
    file_name: PhysicalComponent,
    file: Option<FileCapability>,
    expected_id: ObjectId,
    kind: ImportedObjectKind,
    declared_length: u64,
    written: u64,
    bytes_since_progress: u64,
    terminal: Option<StoreError>,
    finished: bool,
}

impl FilesystemQuarantineImport<'_, '_> {
    fn check_boundary(&self, pending: u64) -> Result<Duration, StoreError> {
        self.lease.check_boundary(pending)
    }

    fn mark_terminal(&mut self, failure: StoreError) -> io::Error {
        self.file.take();
        self.terminal = Some(self.lease.fail(failure));
        io::Error::other("quarantine import terminated")
    }

    fn fail(&mut self, primary: StoreError) -> StoreError {
        self.file.take();
        self.lease.fail(primary)
    }

    fn finish_inner(&mut self) -> Result<ImportedObjectMetadata, StoreError> {
        if let Some(failure) = self.terminal.take() {
            return Err(failure);
        }
        self.check_boundary(0)?;
        if self.written != self.declared_length {
            return Err(StoreError::MalformedObject);
        }
        let file = self.file.as_ref().ok_or(StoreError::InvalidCapability)?;
        file.sync_all()?;
        self.lease.operation.sync()?;
        self.check_boundary(0)?;
        let metadata = {
            let file = self.file.as_mut().ok_or(StoreError::InvalidCapability)?;
            file.seek(std::io::SeekFrom::Start(0))?;
            self.lease.authenticator.authenticate(
                self.expected_id,
                self.kind,
                file,
                |boundary| {
                    self.lease.check_boundary(0)?;
                    if boundary == ImportAuthenticationBoundary::ReadPageComplete {
                        self.lease.last_progress.set(self.lease.clock.elapsed());
                    }
                    Ok(())
                },
            )?
        };
        self.check_boundary(0)?;
        if metadata.id != self.expected_id
            || metadata.kind != self.kind
            || metadata.encoded_length != self.declared_length
        {
            return Err(StoreError::AuthenticationFailed);
        }
        let named = self.lease.operation.open_file_nofollow(&self.file_name)?;
        let authenticated = self.file.as_ref().ok_or(StoreError::InvalidCapability)?;
        if !named.matches_identity(&authenticated.identity()?)? {
            return Err(StoreError::FilesystemObjectRejected);
        }
        self.lease.revocation.check()?;
        let reference_count =
            u64::try_from(metadata.references.len()).map_err(|_| StoreError::LimitExceeded)?;
        self.lease.budget.add_edges(reference_count)?;
        self.lease.budget.add_object(self.declared_length)?;
        let file = self.file.take().ok_or(StoreError::InvalidCapability)?;
        self.lease.imported.insert(
            self.expected_id,
            VerifiedQuarantineObject {
                kind: self.kind,
                encoded_length: self.declared_length,
                file,
            },
        );
        self.lease.imports_published = false;
        self.lease.last_progress.set(self.lease.clock.elapsed());
        Ok(metadata)
    }
}

impl Write for FilesystemQuarantineImport<'_, '_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.terminal.is_some() {
            return Err(io::Error::other("quarantine import is terminal"));
        }
        let bounded_length = buffer.len().min(PROGRESS_PAGE_BYTES as usize);
        let length = match u64::try_from(bounded_length) {
            Ok(length) => length,
            Err(_) => return Err(self.mark_terminal(StoreError::LimitExceeded)),
        };
        let before = match self.check_boundary(length) {
            Ok(now) => now,
            Err(failure) => return Err(self.mark_terminal(failure)),
        };
        match self.written.checked_add(length) {
            Some(next)
                if next <= self.declared_length
                    && next <= self.lease.limits.max_aggregate_bytes
                    && self
                        .lease
                        .budget
                        .aggregate_bytes
                        .checked_add(next)
                        .is_some_and(|aggregate| {
                            aggregate <= self.lease.effective_quarantine_bytes
                        }) =>
            {
                next
            }
            _ => return Err(self.mark_terminal(StoreError::LimitExceeded)),
        };
        if buffer.is_empty() {
            return Ok(0);
        }
        let written = match self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("quarantine file is closed"))?
            .write(&buffer[..bounded_length])
        {
            Ok(0) => {
                return Err(self.mark_terminal(StoreError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "quarantine file made no write progress",
                ))));
            }
            Ok(written) => written,
            Err(error) => return Err(self.mark_terminal(StoreError::Io(error))),
        };
        let written =
            u64::try_from(written).map_err(|_| self.mark_terminal(StoreError::LimitExceeded))?;
        let next = self
            .written
            .checked_add(written)
            .ok_or_else(|| self.mark_terminal(StoreError::LimitExceeded))?;
        let after = self.lease.clock.elapsed();
        if after.saturating_sub(before) > self.lease.limits.progress_interval
            || after.saturating_sub(self.lease.started) > self.lease.limits.max_duration
        {
            return Err(self.mark_terminal(StoreError::TimedOut));
        }
        self.written = next;
        self.bytes_since_progress = match self.bytes_since_progress.checked_add(written) {
            Some(value) => value,
            None => return Err(self.mark_terminal(StoreError::LimitExceeded)),
        };
        if let Err(failure) = self.lease.check_boundary(0) {
            return Err(self.mark_terminal(failure));
        }
        if self.bytes_since_progress >= PROGRESS_PAGE_BYTES {
            self.bytes_since_progress %= PROGRESS_PAGE_BYTES;
            self.lease.last_progress.set(after);
        }
        Ok(usize::try_from(written).expect("write result originated as usize"))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.terminal.is_some() {
            return Err(io::Error::other("quarantine import is terminal"));
        }
        if let Err(failure) = self.check_boundary(0) {
            return Err(self.mark_terminal(failure));
        }
        let result = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("quarantine file is closed"))?
            .flush();
        if result.is_err() {
            return Err(self.mark_terminal(StoreError::Io(io::Error::other(
                "quarantine file flush failed",
            ))));
        }
        if let Err(failure) = self.check_boundary(0) {
            return Err(self.mark_terminal(failure));
        }
        Ok(())
    }
}

impl QuarantineImport for FilesystemQuarantineImport<'_, '_> {
    fn finish(mut self: Box<Self>) -> Result<ImportedObjectMetadata, StoreError> {
        match self.finish_inner() {
            Ok(metadata) => {
                self.finished = true;
                self.file.take();
                Ok(metadata)
            }
            Err(primary) => Err(self.fail(primary)),
        }
    }
}

impl Drop for FilesystemQuarantineImport<'_, '_> {
    fn drop(&mut self) {
        if !self.finished && !self.lease.terminal {
            let _ = self.fail(StoreError::Cancelled);
        }
    }
}

struct OperationCreationFailure {
    error: StoreError,
    residue: Option<[u8; 16]>,
}

fn create_registered_operation(
    root: &Directory,
    random: &mut dyn SecureRandom,
    registry: &OperationRegistry,
) -> Result<(ReplicationOperationId, PhysicalComponent, Directory), OperationCreationFailure> {
    for _ in 0..OPERATION_ID_RETRIES {
        let (operation_id, operation_name, operation) = create_operation_directory(root, random)?;
        match registry.register(*operation_id.as_bytes()) {
            Ok(true) => return Ok((operation_id, operation_name, operation)),
            Ok(false) => {}
            Err(primary) => {
                drop(operation);
                return Err(match root.remove_private_file_tree(&operation_name, 0) {
                    Ok(()) => OperationCreationFailure {
                        error: primary,
                        residue: None,
                    },
                    Err(cleanup) => OperationCreationFailure {
                        error: StoreError::CleanupAfterFailure {
                            primary: Box::new(primary),
                            cleanup,
                        },
                        residue: Some(*operation_id.as_bytes()),
                    },
                });
            }
        }
        drop(operation);
        if let Err(cleanup) = root.remove_private_file_tree(&operation_name, 0) {
            return Err(OperationCreationFailure {
                error: StoreError::CleanupAfterFailure {
                    primary: Box::new(StoreError::IdentityCollision),
                    cleanup,
                },
                residue: Some(*operation_id.as_bytes()),
            });
        }
    }
    Err(OperationCreationFailure {
        error: StoreError::IdentityCollision,
        residue: None,
    })
}

fn create_operation_directory(
    root: &Directory,
    random: &mut dyn SecureRandom,
) -> Result<(ReplicationOperationId, PhysicalComponent, Directory), OperationCreationFailure> {
    for _ in 0..OPERATION_ID_RETRIES {
        let mut id = [0_u8; 16];
        random.fill(&mut id).map_err(|_| OperationCreationFailure {
            error: StoreError::RandomSource,
            residue: None,
        })?;
        let name = component(&encode_hex(&id)).map_err(|error| OperationCreationFailure {
            error,
            residue: None,
        })?;
        match root.create_private_dir(&name) {
            Ok(operation) => {
                if let Err(primary) = root.sync() {
                    drop(operation);
                    return Err(match root.remove_private_file_tree(&name, 0) {
                        Ok(()) => OperationCreationFailure {
                            error: StoreError::Io(primary),
                            residue: None,
                        },
                        Err(cleanup) => OperationCreationFailure {
                            error: StoreError::CleanupAfterFailure {
                                primary: Box::new(StoreError::Io(primary)),
                                cleanup,
                            },
                            residue: Some(id),
                        },
                    });
                }
                return Ok((ReplicationOperationId(id), name, operation));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(OperationCreationFailure {
                    error: StoreError::from(error),
                    residue: None,
                });
            }
        }
    }
    Err(OperationCreationFailure {
        error: StoreError::IdentityCollision,
        residue: None,
    })
}

fn sweep_stale_quarantines(root: &Directory) -> Result<Vec<[u8; 16]>, StoreError> {
    let maximum_files = usize::try_from(ReplicationLimits::PHASE_1.max_object_count)
        .map_err(|_| StoreError::LimitExceeded)?;
    let mut swept = Vec::new();
    swept
        .try_reserve(MAX_STALE_QUARANTINES.min(64))
        .map_err(|_| StoreError::LimitExceeded)?;
    for operation in root.entry_names_bounded(
        MAX_STALE_QUARANTINES
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?,
    )? {
        if operation.as_str() == "replication-lock" {
            continue;
        }
        if operation.as_str().len() != 32
            || !operation
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(StoreError::FilesystemObjectRejected);
        }
        let mut operation_id = [0_u8; 16];
        for (index, pair) in operation.as_str().as_bytes().chunks_exact(2).enumerate() {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or(StoreError::FilesystemObjectRejected)?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or(StoreError::FilesystemObjectRejected)?;
            operation_id[index] = u8::try_from((high << 4) | low)
                .map_err(|_| StoreError::FilesystemObjectRejected)?;
        }
        root.remove_private_file_tree(&operation, maximum_files)?;
        swept
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        swept.push(operation_id);
    }
    Ok(swept)
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::io::Write;
    use std::sync::Arc;

    use notecrypt_core::{ObjectId, SnapshotId, VaultId};
    use notecrypt_crypto::{
        AUTHENTICATED_HEAD_OBJECT_KIND, AuthenticatedHeadContext, CryptoError,
        PublicEnvelopeIdentity, SNAPSHOT_OBJECT_KIND, SecureRandom, SnapshotContext,
        SnapshotPlaintext, TREE_OBJECT_KIND, TreeContext, TreePlaintext, TypedAeadEnvelope,
        VaultKeys, VaultRootKey, authenticate_head as authenticate_head_bytes, derive_vault_keys,
        encrypt_snapshot, encrypt_tree,
    };
    use notecrypt_format::{
        AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits,
        FormatVersion, HeadPayload, HeadRecord, LogicalTree, OrdinaryAeadKind, SnapshotObject,
        SnapshotPayload, TreeEntry, decode_local_state, encode_aead_object, encode_head,
        encode_head_payload, encode_snapshot_object, encode_snapshot_payload, encode_tree,
    };

    use super::{
        BackendObservationFingerprint, CommitReplicatedSnapshot, ImportedObjectKind, KeyCell,
        PendingUnprovableRemote, PublicationGuard, QuarantineLease, ReplicationLease,
        ReplicationLimits, StoreError, TrustedRemoteProvenance,
    };
    use crate::local_io::read_optional;
    use crate::repository::VaultStore;
    use crate::trusted_remote::verify_authenticated_trusted_remote;

    pub struct PendingFreshnessFixture {
        lease: Box<dyn ReplicationLease>,
        pending: PendingUnprovableRemote,
        snapshot: SnapshotId,
    }

    pub struct FreshnessReadback {
        store: Arc<VaultStore>,
        keys: Arc<KeyCell>,
        generation: u64,
    }

    impl PendingFreshnessFixture {
        pub fn into_parts(
            self,
        ) -> (
            Box<dyn ReplicationLease>,
            PendingUnprovableRemote,
            SnapshotId,
        ) {
            (self.lease, self.pending, self.snapshot)
        }
    }

    struct AllowPublication;

    impl PublicationGuard for AllowPublication {
        fn validate(&mut self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct FixedRandom(u8);

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    struct EmptyGraph {
        tree_id: ObjectId,
        tree: Vec<u8>,
        snapshot_id: ObjectId,
        snapshot: Vec<u8>,
        logical_snapshot: SnapshotId,
        head: Vec<u8>,
    }

    pub fn pending_unprovable_remote(
        repository_root: &std::path::Path,
        local_state_root: &std::path::Path,
        vault: VaultId,
        seed: u8,
    ) -> Result<(PendingFreshnessFixture, FreshnessReadback), StoreError> {
        let mut random = FixedRandom(seed);
        let root = VaultRootKey::generate(&mut random)?;
        let derived = derive_vault_keys(&root)?;
        let graph = build_empty_graph(vault, &derived, seed)?;
        let store = Arc::new(VaultStore::create_empty(
            repository_root,
            local_state_root,
            vault,
        )?);
        let keys = Arc::new(KeyCell::new(root)?);
        let generation = keys.generation();
        let mut limits = ReplicationLimits::PHASE_1;
        limits.max_aggregate_bytes = 1 << 20;
        limits.max_quarantine_bytes = 1 << 20;
        let mut lease = QuarantineLease::acquire_authenticated(
            Arc::clone(&store),
            ReplicationLimits::PHASE_1,
            limits,
            limits,
            Arc::clone(&keys),
            generation,
            vault,
            Arc::from(&b""[..]),
            None,
        )?;
        lease.bootstrap_commitment = Some([seed; 32]);
        for (id, kind, bytes) in [
            (graph.tree_id, ImportedObjectKind::Tree, graph.tree),
            (
                graph.snapshot_id,
                ImportedObjectKind::Snapshot,
                graph.snapshot,
            ),
        ] {
            let declared = u64::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?;
            let mut import = lease.begin_import(id, kind, declared)?;
            import.write_all(&bytes)?;
            import.finish()?;
        }
        let head = lease.authenticate_head(&graph.head)?;
        let verified =
            lease.verify_reachable(head, BackendObservationFingerprint::try_new(vec![seed])?)?;
        let committed = lease.commit_replicated_snapshot(
            verified,
            CommitReplicatedSnapshot::new(graph.head),
            &mut AllowPublication,
        )?;
        let pending = lease
            .record_trusted_remote(committed)?
            .ok_or(StoreError::InvalidCapability)?;
        Ok((
            PendingFreshnessFixture {
                lease: Box::new(lease),
                pending,
                snapshot: graph.logical_snapshot,
            },
            FreshnessReadback {
                store,
                keys,
                generation,
            },
        ))
    }

    pub fn freshness_unprovable_was_acknowledged(
        readback: &FreshnessReadback,
    ) -> Result<bool, StoreError> {
        let bytes = read_optional(
            &readback.store.layout.trusted_remote,
            &crate::layout::component("remote")?,
        )?;
        let Some(bytes) = bytes else {
            return Ok(false);
        };
        let record = decode_local_state(&bytes, &DecodeLimits::PHASE_1)?;
        let trusted = verify_authenticated_trusted_remote(
            &record,
            readback.keys.as_ref(),
            readback.generation,
        )?;
        Ok(matches!(
            trusted.provenance(),
            TrustedRemoteProvenance::FreshnessUnprovableAcknowledged
        ))
    }

    fn build_empty_graph(
        vault: notecrypt_core::VaultId,
        keys: &VaultKeys,
        seed: u8,
    ) -> Result<EmptyGraph, StoreError> {
        let mut random = FixedRandom(seed);
        let tree_id = ObjectId::from_bytes([seed.wrapping_add(1); 32]);
        let snapshot_id = ObjectId::from_bytes([seed.wrapping_add(2); 32]);
        let logical_snapshot = SnapshotId::from_bytes([seed.wrapping_add(3); 32]);
        let root_id = [seed.wrapping_add(4); 16];

        let tree = LogicalTree::try_new(
            root_id,
            vec![TreeEntry::root(root_id)],
            &DecodeLimits::PHASE_1,
        )?;
        let tree_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: TREE_OBJECT_KIND,
            format_version: 1,
            object_id: *tree_id.as_bytes(),
        };
        let tree_envelope = encrypt_tree(
            &TreeContext::try_new(tree_identity)?,
            TreePlaintext::try_new(encode_tree(&tree)?)?,
            &keys.metadata,
            &mut random,
        )?;
        let (identity, nonce, ciphertext, tag) = tree_envelope
            .into_parts()
            .into_public_parts()
            .into_components();
        let tree = encode_aead_object(&AeadObject::try_new(
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
        )?)?;

        let snapshot_payload = SnapshotPayload::try_new(
            *logical_snapshot.as_bytes(),
            Vec::new(),
            *tree_id.as_bytes(),
            [seed.wrapping_add(5); 16],
            "replication-service-eze",
            &DecodeLimits::PHASE_1,
        )?;
        let snapshot_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: SNAPSHOT_OBJECT_KIND,
            format_version: 1,
            object_id: *snapshot_id.as_bytes(),
        };
        let snapshot_envelope = encrypt_snapshot(
            &SnapshotContext::try_new(snapshot_identity)?,
            SnapshotPlaintext::try_new(encode_snapshot_payload(&snapshot_payload)?)?,
            &keys.metadata,
            &keys.snapshot_authentication,
            &mut random,
        )?;
        let (parts, outer) = snapshot_envelope.into_parts();
        let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
        let snapshot = encode_snapshot_object(&SnapshotObject::try_new(
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
        )?)?;

        let head_payload = HeadPayload::new(
            *logical_snapshot.as_bytes(),
            *snapshot_id.as_bytes(),
            *tree_id.as_bytes(),
        );
        let canonical_head = encode_head_payload(&head_payload)?;
        let head_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: AUTHENTICATED_HEAD_OBJECT_KIND,
            format_version: 1,
            object_id: [seed.wrapping_add(6); 32],
        };
        let authenticator = authenticate_head_bytes(
            &AuthenticatedHeadContext::try_new(head_identity)?,
            &canonical_head,
            &keys.snapshot_authentication,
        )?;
        let head = encode_head(&HeadRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            *vault.as_bytes(),
            FormatVersion::v1(),
            head_identity.object_id,
            head_payload,
            authenticator.as_bytes(),
            &DecodeLimits::PHASE_1,
        )?)?;

        Ok(EmptyGraph {
            tree_id,
            tree,
            snapshot_id,
            snapshot,
            logical_snapshot,
            head,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::{AtomicU64, Ordering};

    use notecrypt_core::VaultId;
    use notecrypt_crypto::{
        AUTHENTICATED_HEAD_OBJECT_KIND, AuthenticatedHeadContext, CryptoError,
        PublicEnvelopeIdentity, SNAPSHOT_OBJECT_KIND, SnapshotContext, SnapshotPlaintext,
        TREE_OBJECT_KIND, TreeContext, TreePlaintext, TypedAeadEnvelope, VaultKeys, VaultRootKey,
        authenticate_head as authenticate_head_bytes, derive_vault_keys, encrypt_snapshot,
        encrypt_tree,
    };
    use notecrypt_format::{
        AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CryptoProfileId, FormatVersion,
        HeadPayload, HeadRecord, LogicalTree, OrdinaryAeadKind, SnapshotObject,
        SnapshotParentLocator, SnapshotPayload, TreeEntry, decode_local_state, encode_aead_object,
        encode_head, encode_head_payload, encode_snapshot_object, encode_snapshot_payload,
        encode_tree,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::VaultStore;
    use crate::local_io::read_optional;
    use crate::trusted_remote::{TrustedRemoteProvenance, verify_authenticated_trusted_remote};

    struct FakeClock(AtomicU64);

    impl FakeClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::AcqRel);
        }
    }

    impl ReplicationClock for FakeClock {
        fn elapsed(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::Acquire))
        }
    }

    struct FakeSpace(AtomicU64);

    impl FreeSpaceProbe for FakeSpace {
        fn available_bytes(&self) -> Result<u64, StoreError> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    struct Revocation(AtomicU64);

    impl OperationStatusProbe for Revocation {
        fn check(&self) -> Result<(), StoreError> {
            match self.0.load(Ordering::Acquire) {
                0 => Ok(()),
                1 => Err(StoreError::Locked),
                _ => Err(StoreError::Cancelled),
            }
        }
    }

    struct PartialRandom;

    impl SecureRandom for PartialRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            let partial = destination.len() / 2;
            destination[..partial].fill(0x5a);
            Err(CryptoError::RandomSource)
        }
    }

    struct ZeroRandom;

    impl SecureRandom for ZeroRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0);
            Ok(())
        }
    }

    struct FixedRandom(u8);

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    fn actual_encrypted_tree(vault: VaultId, id: ObjectId) -> (KeyCell, Vec<u8>) {
        let mut random = FixedRandom(0x21);
        let root = VaultRootKey::generate(&mut random).unwrap();
        let derived = derive_vault_keys(&root).unwrap();
        let tree = LogicalTree::try_new(
            [1; 16],
            vec![TreeEntry::root([1; 16])],
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let plaintext = encode_tree(&tree).unwrap();
        let identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: TREE_OBJECT_KIND,
            format_version: 1,
            object_id: *id.as_bytes(),
        };
        let context = TreeContext::try_new(identity).unwrap();
        let envelope = encrypt_tree(
            &context,
            TreePlaintext::try_new(plaintext).unwrap(),
            &derived.metadata,
            &mut random,
        )
        .unwrap();
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
        )
        .unwrap();
        (
            KeyCell::new(root).unwrap(),
            encode_aead_object(&object).unwrap(),
        )
    }

    fn actual_empty_graph(
        vault: VaultId,
    ) -> (KeyCell, ObjectId, Vec<u8>, ObjectId, Vec<u8>, Vec<u8>) {
        let mut random = FixedRandom(0x41);
        let root = VaultRootKey::generate(&mut random).unwrap();
        let derived = derive_vault_keys(&root).unwrap();
        let tree_id = ObjectId::from_bytes([0x42; 32]);
        let snapshot_id = ObjectId::from_bytes([0x43; 32]);
        let logical_snapshot = [0x44; 32];

        let tree = LogicalTree::try_new(
            [0x45; 16],
            vec![TreeEntry::root([0x45; 16])],
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let tree_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: TREE_OBJECT_KIND,
            format_version: 1,
            object_id: *tree_id.as_bytes(),
        };
        let tree_envelope = encrypt_tree(
            &TreeContext::try_new(tree_identity).unwrap(),
            TreePlaintext::try_new(encode_tree(&tree).unwrap()).unwrap(),
            &derived.metadata,
            &mut random,
        )
        .unwrap();
        let (identity, nonce, ciphertext, tag) = tree_envelope
            .into_parts()
            .into_public_parts()
            .into_components();
        let tree_wire = encode_aead_object(
            &AeadObject::try_new(
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
            )
            .unwrap(),
        )
        .unwrap();

        let snapshot_payload = SnapshotPayload::try_new(
            logical_snapshot,
            Vec::new(),
            *tree_id.as_bytes(),
            [0x46; 16],
            "replication-eze",
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let snapshot_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: SNAPSHOT_OBJECT_KIND,
            format_version: 1,
            object_id: *snapshot_id.as_bytes(),
        };
        let snapshot_envelope = encrypt_snapshot(
            &SnapshotContext::try_new(snapshot_identity).unwrap(),
            SnapshotPlaintext::try_new(encode_snapshot_payload(&snapshot_payload).unwrap())
                .unwrap(),
            &derived.metadata,
            &derived.snapshot_authentication,
            &mut random,
        )
        .unwrap();
        let (parts, outer) = snapshot_envelope.into_parts();
        let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
        let snapshot_wire = encode_snapshot_object(
            &SnapshotObject::try_new(
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
            )
            .unwrap(),
        )
        .unwrap();

        let head_payload = HeadPayload::new(
            logical_snapshot,
            *snapshot_id.as_bytes(),
            *tree_id.as_bytes(),
        );
        let canonical_head = encode_head_payload(&head_payload).unwrap();
        let head_identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: AUTHENTICATED_HEAD_OBJECT_KIND,
            format_version: 1,
            object_id: [0x47; 32],
        };
        let head_authenticator = authenticate_head_bytes(
            &AuthenticatedHeadContext::try_new(head_identity).unwrap(),
            &canonical_head,
            &derived.snapshot_authentication,
        )
        .unwrap();
        let head_wire = encode_head(
            &HeadRecord::try_new(
                CryptoProfileId::profile_one(),
                AuthenticationAlgorithmId::keyed_blake3_256(),
                *vault.as_bytes(),
                FormatVersion::v1(),
                head_identity.object_id,
                head_payload,
                head_authenticator.as_bytes(),
                &DecodeLimits::PHASE_1,
            )
            .unwrap(),
        )
        .unwrap();
        (
            KeyCell::new(root).unwrap(),
            tree_id,
            tree_wire,
            snapshot_id,
            snapshot_wire,
            head_wire,
        )
    }

    fn encrypted_empty_tree(
        vault: VaultId,
        object_id: ObjectId,
        root_id: [u8; 16],
        keys: &VaultKeys,
        random: &mut dyn SecureRandom,
    ) -> Vec<u8> {
        let tree = LogicalTree::try_new(
            root_id,
            vec![TreeEntry::root(root_id)],
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: TREE_OBJECT_KIND,
            format_version: 1,
            object_id: *object_id.as_bytes(),
        };
        let envelope = encrypt_tree(
            &TreeContext::try_new(identity).unwrap(),
            TreePlaintext::try_new(encode_tree(&tree).unwrap()).unwrap(),
            &keys.metadata,
            random,
        )
        .unwrap();
        let (identity, nonce, ciphertext, tag) =
            envelope.into_parts().into_public_parts().into_components();
        encode_aead_object(
            &AeadObject::try_new(
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
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn encrypted_snapshot(
        vault: VaultId,
        object_id: ObjectId,
        logical_id: [u8; 32],
        parents: Vec<SnapshotParentLocator>,
        tree: ObjectId,
        keys: &VaultKeys,
        random: &mut dyn SecureRandom,
    ) -> Vec<u8> {
        let payload = SnapshotPayload::try_new(
            logical_id,
            parents,
            *tree.as_bytes(),
            [0x70; 16],
            "reconciliation-eze",
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: SNAPSHOT_OBJECT_KIND,
            format_version: 1,
            object_id: *object_id.as_bytes(),
        };
        let envelope = encrypt_snapshot(
            &SnapshotContext::try_new(identity).unwrap(),
            SnapshotPlaintext::try_new(encode_snapshot_payload(&payload).unwrap()).unwrap(),
            &keys.metadata,
            &keys.snapshot_authentication,
            random,
        )
        .unwrap();
        let (parts, outer) = envelope.into_parts();
        let (identity, nonce, ciphertext, tag) = parts.into_public_parts().into_components();
        encode_snapshot_object(
            &SnapshotObject::try_new(
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
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn authenticated_head_wire(
        vault: VaultId,
        logical_id: [u8; 32],
        snapshot: ObjectId,
        tree: ObjectId,
        record_id: [u8; 32],
        keys: &VaultKeys,
    ) -> Vec<u8> {
        let payload = HeadPayload::new(logical_id, *snapshot.as_bytes(), *tree.as_bytes());
        let canonical = encode_head_payload(&payload).unwrap();
        let identity = PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: AUTHENTICATED_HEAD_OBJECT_KIND,
            format_version: 1,
            object_id: record_id,
        };
        let authenticator = authenticate_head_bytes(
            &AuthenticatedHeadContext::try_new(identity).unwrap(),
            &canonical,
            &keys.snapshot_authentication,
        )
        .unwrap();
        encode_head(
            &HeadRecord::try_new(
                CryptoProfileId::profile_one(),
                AuthenticationAlgorithmId::keyed_blake3_256(),
                *vault.as_bytes(),
                FormatVersion::v1(),
                record_id,
                payload,
                authenticator.as_bytes(),
                &DecodeLimits::PHASE_1,
            )
            .unwrap(),
        )
        .unwrap()
    }

    struct Harness {
        _repository: TempDir,
        _local: TempDir,
        store: VaultStore,
        clock: FakeClock,
        space: FakeSpace,
        revoked: Revocation,
        reservations: QuarantineReservations,
    }

    impl Harness {
        fn new(free: u64) -> Self {
            let repository = TempDir::new().unwrap();
            let local = TempDir::new().unwrap();
            let store = VaultStore::create_empty(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                VaultId::from_bytes([0x31; 16]),
            )
            .unwrap();
            Self {
                _repository: repository,
                _local: local,
                store,
                clock: FakeClock(AtomicU64::new(0)),
                space: FakeSpace(AtomicU64::new(free)),
                revoked: Revocation(AtomicU64::new(0)),
                reservations: QuarantineReservations::default(),
            }
        }

        fn operation_count(&self) -> usize {
            self.store
                .layout
                .quarantine
                .entry_names_bounded(64)
                .unwrap()
                .into_iter()
                .filter(|name| name.as_str() != "replication-lock")
                .count()
        }
    }

    fn authenticate(
        expected: ObjectId,
        kind: ImportedObjectKind,
        file: &mut FileCapability,
    ) -> Result<ImportedObjectMetadata, StoreError> {
        let length = file.len()?;
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.take(length.checked_add(1).ok_or(StoreError::LimitExceeded)?)
            .read_to_end(&mut bytes)?;
        if bytes != b"authenticated" {
            return Err(StoreError::AuthenticationFailed);
        }
        Ok(ImportedObjectMetadata {
            id: expected,
            kind,
            encoded_length: length,
            references: Vec::new(),
            semantics: AuthenticatedObjectSemantics::Tree {
                revisions: Vec::new(),
            },
        })
    }

    #[test]
    fn malformed_or_missing_bootstrap_terminates_and_cleans_before_import() {
        let harness = Harness::new(10 * GIB);
        let mut malformed = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        malformed.bootstrap_commitment = None;
        assert!(matches!(
            malformed.authenticate_bootstrap(b"not canonical bootstrap"),
            Err(StoreError::AuthenticationFailed)
        ));
        assert_eq!(harness.operation_count(), 0);
        assert_eq!(harness.reservations.reserved(), 0);
        drop(malformed);

        let mut missing = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        missing.bootstrap_commitment = None;
        assert!(matches!(
            missing.begin_import(
                ObjectId::from_bytes([0x91; 32]),
                ImportedObjectKind::Tree,
                13,
            ),
            Err(StoreError::InvalidCapability)
        ));
        assert_eq!(harness.operation_count(), 0);
        assert_eq!(harness.reservations.reserved(), 0);
    }

    #[test]
    fn import_streams_authenticates_and_cleans_operation_directory() {
        let harness = Harness::new(10 * GIB);
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        let id = ObjectId::from_bytes([7; 32]);
        let mut import = lease
            .begin_import(id, ImportedObjectKind::Tree, 13)
            .unwrap();
        import.write_all(b"authenticated").unwrap();
        let metadata = import.finish().unwrap();
        assert_eq!(metadata.id(), id);
        assert_eq!(metadata.kind(), ImportedObjectKind::Tree);
        assert_eq!(metadata.encoded_length(), 13);
        assert!(metadata.references().is_empty());
        assert_eq!(harness.operation_count(), 1);
        Box::new(lease).finish().unwrap();
        assert_eq!(harness.operation_count(), 0);
        assert_eq!(harness.reservations.reserved(), 0);
        let encoded = encode_hex(id.as_bytes());
        assert!(
            harness
                ._repository
                .path()
                .join("objects")
                .join(&encoded[..2])
                .join(&encoded[2..])
                .is_file()
        );
    }

    #[test]
    fn timeout_revoke_oversize_and_drop_remove_exact_quarantine() {
        for failure in ["timeout", "revoke", "oversize", "drop", "auth"] {
            let harness = Harness::new(10 * GIB);
            let mut limits = ReplicationLimits::PHASE_1;
            limits.max_tree_object_bytes = 13;
            let mut lease = QuarantineLease::acquire(
                &harness.store,
                limits,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                &harness.reservations,
                &harness.clock,
                &harness.space,
                &harness.revoked,
                &authenticate,
            )
            .unwrap();
            if failure == "oversize" {
                assert!(matches!(
                    lease
                        .begin_import(ObjectId::from_bytes([8; 32]), ImportedObjectKind::Tree, 14,),
                    Err(StoreError::LimitExceeded)
                ));
                assert_eq!(harness.operation_count(), 0);
                drop(lease);
                continue;
            }
            let declared = if failure == "auth" { 3 } else { 13 };
            let mut import = Some(
                lease
                    .begin_import(
                        ObjectId::from_bytes([8; 32]),
                        ImportedObjectKind::Tree,
                        declared,
                    )
                    .unwrap(),
            );
            match failure {
                "timeout" => {
                    harness.clock.advance(31);
                    assert!(
                        import
                            .as_mut()
                            .unwrap()
                            .write_all(b"authenticated")
                            .is_err()
                    );
                }
                "revoke" => {
                    harness.revoked.0.store(1, Ordering::Release);
                    assert!(
                        import
                            .as_mut()
                            .unwrap()
                            .write_all(b"authenticated")
                            .is_err()
                    );
                }
                "drop" => drop(import.take()),
                "auth" => {
                    import.as_mut().unwrap().write_all(b"bad").unwrap();
                    assert!(matches!(
                        import.take().unwrap().finish(),
                        Err(StoreError::AuthenticationFailed)
                    ));
                }
                _ => unreachable!(),
            }
            drop(import);
            assert_eq!(harness.operation_count(), 0, "{failure}");
        }
    }

    #[test]
    fn global_reservation_and_free_space_shrink_fail_closed() {
        let harness = Harness::new(10 * GIB);
        let first = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        assert!(matches!(
            QuarantineLease::acquire(
                &harness.store,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                &harness.reservations,
                &harness.clock,
                &harness.space,
                &harness.revoked,
                &authenticate,
            ),
            Err(StoreError::LimitExceeded | StoreError::Busy)
        ));
        drop(first);

        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        let mut import = lease
            .begin_import(ObjectId::from_bytes([9; 32]), ImportedObjectKind::Tree, 13)
            .unwrap();
        harness.space.0.store(GIB - 1, Ordering::Release);
        assert!(import.write_all(b"authenticated").is_err());
        drop(import);
        assert_eq!(harness.operation_count(), 0);
    }

    #[test]
    fn reservation_registry_is_shared_by_distinct_vaults_on_one_filesystem() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let first = Directory::open_ambient(&first.path().canonicalize().unwrap()).unwrap();
        let second = Directory::open_ambient(&second.path().canonicalize().unwrap()).unwrap();

        let first_reservations = reservations_for(&first).unwrap();
        let second_reservations = reservations_for(&second).unwrap();

        assert!(Arc::ptr_eq(&first_reservations, &second_reservations));
    }

    #[test]
    fn failed_cleanup_reservation_is_released_only_after_durable_stale_sweep() {
        let reservations = QuarantineReservations::default();
        let vault = VaultId::from_bytes([0x93; 16]);
        let operation = [0x94; 16];
        reservations.reserve(128, 1_024).unwrap();
        reservations.retain_orphan(vault, operation, 128).unwrap();
        assert_eq!(reservations.reserved(), 128);

        reservations.reconcile_swept(vault, &[[0x95; 16]]);
        assert_eq!(reservations.reserved(), 128);
        reservations.reconcile_swept(vault, &[operation]);
        assert_eq!(reservations.reserved(), 0);
    }

    #[test]
    fn operation_identity_partial_rng_and_collision_exhaustion_publish_nothing() {
        let root = TempDir::new().unwrap();
        let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
        assert!(matches!(
            create_operation_directory(&directory, &mut PartialRandom),
            Err(OperationCreationFailure {
                error: StoreError::RandomSource,
                residue: None,
            })
        ));
        assert!(directory.entry_names_bounded(1).unwrap().is_empty());

        let collision_name = component(&"00".repeat(16)).unwrap();
        let _collision = directory.create_private_dir(&collision_name).unwrap();
        assert!(matches!(
            create_operation_directory(&directory, &mut ZeroRandom),
            Err(OperationCreationFailure {
                error: StoreError::IdentityCollision,
                residue: None,
            })
        ));
        assert_eq!(directory.entry_names_bounded(1).unwrap().len(), 1);
    }

    #[test]
    fn live_quarantine_is_never_swept_and_stale_residue_is_removed_under_lock() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let repository_path = repository.path().canonicalize().unwrap();
        let local_path = local.path().canonicalize().unwrap();
        let vault = VaultId::from_bytes([0x42; 16]);
        let first_store = VaultStore::create_empty(&repository_path, &local_path, vault).unwrap();
        let second_store = VaultStore::create_empty(&repository_path, &local_path, vault).unwrap();
        let clock = FakeClock(AtomicU64::new(0));
        let space = FakeSpace(AtomicU64::new(10 * GIB));
        let status = Revocation(AtomicU64::new(0));
        let reservations = QuarantineReservations::default();
        let first = QuarantineLease::acquire(
            &first_store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &reservations,
            &clock,
            &space,
            &status,
            &authenticate,
        )
        .unwrap();
        assert!(matches!(
            QuarantineLease::acquire(
                &second_store,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                &reservations,
                &clock,
                &space,
                &status,
                &authenticate,
            ),
            Err(StoreError::Busy)
        ));
        assert!(!first.cleaned);
        drop(first);

        let stale_name = component(&"ab".repeat(16)).unwrap();
        let stale = first_store
            .layout
            .quarantine
            .create_private_dir(&stale_name)
            .unwrap();
        stale
            .create_private_file_new(&component("ciphertext").unwrap())
            .unwrap()
            .write_all(b"stale")
            .unwrap();
        stale.sync().unwrap();
        first_store.layout.quarantine.sync().unwrap();

        let recovered = QuarantineLease::acquire(
            &second_store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &reservations,
            &clock,
            &space,
            &status,
            &authenticate,
        )
        .unwrap();
        assert!(
            first_store
                .layout
                .quarantine
                .open_dir_nofollow(&stale_name)
                .is_err()
        );
        drop(recovered);
    }

    #[test]
    fn every_kind_accepts_exact_limit_and_rejects_limit_plus_one_without_allocation() {
        let cases = [
            (
                ImportedObjectKind::Chunk,
                ReplicationLimits::PHASE_1.max_chunk_object_bytes,
            ),
            (
                ImportedObjectKind::Manifest,
                ReplicationLimits::PHASE_1.max_manifest_object_bytes,
            ),
            (
                ImportedObjectKind::Tree,
                ReplicationLimits::PHASE_1.max_tree_object_bytes,
            ),
            (
                ImportedObjectKind::Snapshot,
                ReplicationLimits::PHASE_1.max_snapshot_object_bytes,
            ),
        ];
        for (kind, maximum) in cases {
            let harness = Harness::new(TIB + (2 * GIB));
            let mut lease = QuarantineLease::acquire(
                &harness.store,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                &harness.reservations,
                &harness.clock,
                &harness.space,
                &harness.revoked,
                &authenticate,
            )
            .unwrap();
            let import = lease
                .begin_import(ObjectId::from_bytes([0x44; 32]), kind, maximum)
                .unwrap();
            drop(import);
            assert_eq!(harness.operation_count(), 0);
            drop(lease);

            let mut lease = QuarantineLease::acquire(
                &harness.store,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                ReplicationLimits::PHASE_1,
                &harness.reservations,
                &harness.clock,
                &harness.space,
                &harness.revoked,
                &authenticate,
            )
            .unwrap();
            assert!(matches!(
                lease.begin_import(
                    ObjectId::from_bytes([0x45; 32]),
                    kind,
                    maximum.checked_add(1).unwrap(),
                ),
                Err(StoreError::LimitExceeded)
            ));
        }
    }

    #[test]
    fn exact_deadlines_pass_and_first_tick_beyond_each_deadline_cleans() {
        let harness = Harness::new(10 * GIB);
        let mut limits = ReplicationLimits::PHASE_1;
        limits.max_duration = Duration::from_secs(60);
        limits.progress_interval = Duration::from_secs(30);
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            limits,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        let mut import = lease
            .begin_import(
                ObjectId::from_bytes([0x46; 32]),
                ImportedObjectKind::Tree,
                13,
            )
            .unwrap();
        harness.clock.advance(30);
        import.write_all(b"authenticated").unwrap();
        let metadata = import.finish().unwrap();
        assert_eq!(metadata.encoded_length(), 13);
        harness.clock.advance(31);
        assert!(matches!(
            Box::new(lease).finish(),
            Err(StoreError::TimedOut)
        ));
        assert_eq!(harness.operation_count(), 0);
    }

    #[test]
    fn blocking_authentication_and_export_steps_cannot_reset_an_expired_progress_deadline() {
        let harness = Harness::new(10 * GIB);
        let slow_auth = |id: ObjectId,
                         kind: ImportedObjectKind,
                         file: &mut FileCapability|
         -> Result<ImportedObjectMetadata, StoreError> {
            harness.clock.advance(31);
            authenticate(id, kind, file)
        };
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &slow_auth,
        )
        .unwrap();
        let mut import = lease
            .begin_import(
                ObjectId::from_bytes([0x91; 32]),
                ImportedObjectKind::Tree,
                13,
            )
            .unwrap();
        import.write_all(b"authenticated").unwrap();
        assert!(matches!(import.finish(), Err(StoreError::TimedOut)));
        assert_eq!(harness.operation_count(), 0);

        struct SlowSink<'a>(&'a FakeClock);
        impl Write for SlowSink<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.advance(31);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let export_harness = Harness::new(10 * GIB);
        let mut export_lease = QuarantineLease::acquire(
            &export_harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &export_harness.reservations,
            &export_harness.clock,
            &export_harness.space,
            &export_harness.revoked,
            &authenticate,
        )
        .unwrap();
        let id = ObjectId::from_bytes([0x92; 32]);
        let mut import = export_lease
            .begin_import(id, ImportedObjectKind::Tree, 13)
            .unwrap();
        import.write_all(b"authenticated").unwrap();
        import.finish().unwrap();
        export_lease.publish_verified_imports().unwrap();
        let mut sink = SlowSink(&export_harness.clock);
        assert!(matches!(
            export_lease.export_encrypted(&id, &mut sink),
            Err(StoreError::TimedOut)
        ));
        assert_eq!(export_harness.operation_count(), 0);
    }

    #[test]
    fn authenticated_metadata_mismatch_and_short_input_clean_complete_operation() {
        let harness = Harness::new(10 * GIB);
        let wrong_metadata = |_: ObjectId,
                              kind: ImportedObjectKind,
                              file: &mut FileCapability|
         -> Result<ImportedObjectMetadata, StoreError> {
            Ok(ImportedObjectMetadata {
                id: ObjectId::from_bytes([0xff; 32]),
                kind,
                encoded_length: file.len()?,
                references: Vec::new(),
                semantics: AuthenticatedObjectSemantics::Tree {
                    revisions: Vec::new(),
                },
            })
        };
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &wrong_metadata,
        )
        .unwrap();
        let mut import = lease
            .begin_import(
                ObjectId::from_bytes([0x47; 32]),
                ImportedObjectKind::Tree,
                13,
            )
            .unwrap();
        import.write_all(b"authenticated").unwrap();
        assert!(matches!(
            import.finish(),
            Err(StoreError::AuthenticationFailed)
        ));
        assert_eq!(harness.operation_count(), 0);
        drop(lease);

        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        let mut import = lease
            .begin_import(
                ObjectId::from_bytes([0x48; 32]),
                ImportedObjectKind::Tree,
                13,
            )
            .unwrap();
        import.write_all(b"short").unwrap();
        assert!(matches!(import.finish(), Err(StoreError::MalformedObject)));
        assert_eq!(harness.operation_count(), 0);
    }

    #[test]
    fn each_write_is_one_bounded_page_and_cancellation_is_checked_between_pages() {
        let harness = Harness::new(10 * GIB);
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        let mut import = lease
            .begin_import(
                ObjectId::from_bytes([0x49; 32]),
                ImportedObjectKind::Tree,
                PROGRESS_PAGE_BYTES * 2,
            )
            .unwrap();
        let bytes = vec![0_u8; (PROGRESS_PAGE_BYTES * 2) as usize];
        assert_eq!(import.write(&bytes).unwrap(), PROGRESS_PAGE_BYTES as usize);
        harness.revoked.0.store(2, Ordering::Release);
        assert!(
            import
                .write(&bytes[PROGRESS_PAGE_BYTES as usize..])
                .is_err()
        );
        drop(import);
        assert_eq!(harness.operation_count(), 0);
    }

    #[test]
    fn authentication_uses_the_exact_original_write_handle_after_name_swap() {
        let harness = Harness::new(10 * GIB);
        let root = &harness.store.layout.quarantine;
        let swap = |expected: ObjectId,
                    kind: ImportedObjectKind,
                    file: &mut FileCapability|
         -> Result<ImportedObjectMetadata, StoreError> {
            let operation_name = root
                .entry_names_bounded(2)?
                .into_iter()
                .find(|name| name.as_str() != "replication-lock")
                .ok_or(StoreError::NotFound)?;
            let operation = root.open_dir_nofollow(&operation_name)?;
            let object_name = component(&encode_hex(expected.as_bytes()))?;
            operation.remove_file_from_private_staging_unsynced(&object_name)?;
            let mut replacement = operation.create_file_new(&object_name)?;
            replacement.write_all(b"attacker-byte")?;
            replacement.sync_all()?;
            authenticate(expected, kind, file)
        };
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &swap,
        )
        .unwrap();
        let mut import = lease
            .begin_import(
                ObjectId::from_bytes([0x4a; 32]),
                ImportedObjectKind::Tree,
                13,
            )
            .unwrap();
        import.write_all(b"authenticated").unwrap();
        let swapped = import.finish();
        assert!(matches!(swapped, Err(StoreError::FilesystemObjectRejected)));
        assert_eq!(harness.operation_count(), 0);
        let encoded = encode_hex(&[0x4a; 32]);
        assert!(
            !harness
                ._repository
                .path()
                .join("objects")
                .join(&encoded[..2])
                .join(&encoded[2..])
                .exists()
        );
    }

    #[test]
    fn public_cancellation_is_terminal_before_the_next_bounded_operation() {
        let harness = Harness::new(10 * GIB);
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();

        ReplicationLease::cancel(&lease);
        assert!(matches!(
            lease.begin_import(
                ObjectId::from_bytes([0x4b; 32]),
                ImportedObjectKind::Tree,
                13,
            ),
            Err(StoreError::Cancelled)
        ));
        assert_eq!(harness.operation_count(), 0);
        assert_eq!(harness.reservations.reserved(), 0);
    }

    #[test]
    fn same_volume_reservation_keeps_capacity_for_the_repository_copy() {
        let harness = Harness::new(10 * GIB);
        assert!(Arc::ptr_eq(
            &harness.store.quarantine_reservations,
            &harness.store.repository_reservations,
        ));
        let mut lease = QuarantineLease::acquire(
            &harness.store,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            ReplicationLimits::PHASE_1,
            &harness.store.quarantine_reservations,
            &harness.clock,
            &harness.space,
            &harness.revoked,
            &authenticate,
        )
        .unwrap();
        assert_eq!(lease.effective_quarantine_bytes, 4 * GIB);

        let id = ObjectId::from_bytes([0x4c; 32]);
        let mut import = lease
            .begin_import(id, ImportedObjectKind::Tree, 13)
            .unwrap();
        import.write_all(b"authenticated").unwrap();
        import.finish().unwrap();
        Box::new(lease).finish().unwrap();

        assert!(harness.store.open_object(&id).is_ok());
    }

    #[test]
    fn production_key_cell_authentication_publishes_only_canonical_ciphertext() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0x5d; 16]);
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            vault,
        )
        .unwrap();
        let id = ObjectId::from_bytes([0x5e; 32]);
        let (keys, ciphertext) = actual_encrypted_tree(vault, id);
        let mut operation_limits = ReplicationLimits::PHASE_1;
        operation_limits.max_aggregate_bytes = 1 << 20;
        operation_limits.max_quarantine_bytes = 1 << 20;
        let mut lease = QuarantineLease::acquire_authenticated_borrowed(
            &store,
            ReplicationLimits::PHASE_1,
            operation_limits,
            operation_limits,
            &keys,
            keys.generation(),
            vault,
            b"",
        )
        .unwrap();
        lease.bootstrap_commitment = Some([0x62; 32]);
        let mut import = lease
            .begin_import(
                id,
                ImportedObjectKind::Tree,
                u64::try_from(ciphertext.len()).unwrap(),
            )
            .unwrap();
        import.write_all(&ciphertext).unwrap();
        let metadata = import.finish().unwrap();
        assert_eq!(metadata.id(), id);
        assert_eq!(metadata.kind(), ImportedObjectKind::Tree);
        Box::new(lease).finish().unwrap();

        let mut published = store.open_object(&id).unwrap();
        let reauthenticated = keys
            .authenticate_imported_object(
                keys.generation(),
                vault,
                id,
                ImportedObjectKind::Tree,
                &mut published,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(reauthenticated.id(), id);
        assert_eq!(reauthenticated.encoded_length(), ciphertext.len() as u64);
    }

    #[test]
    fn production_graph_commit_and_trusted_remote_acknowledgement_are_linear() {
        struct Allow;
        impl PublicationGuard for Allow {
            fn validate(&mut self) -> Result<(), StoreError> {
                Ok(())
            }
        }

        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0x61; 16]);
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            vault,
        )
        .unwrap();
        let (keys, tree_id, tree, snapshot_id, snapshot, head_bytes) = actual_empty_graph(vault);
        let mut limits = ReplicationLimits::PHASE_1;
        limits.max_aggregate_bytes = 1 << 20;
        limits.max_quarantine_bytes = 1 << 20;
        let mut lease = QuarantineLease::acquire_authenticated_borrowed(
            &store,
            ReplicationLimits::PHASE_1,
            limits,
            limits,
            &keys,
            keys.generation(),
            vault,
            b"",
        )
        .unwrap();
        lease.bootstrap_commitment = Some([0x62; 32]);
        for (id, kind, bytes) in [
            (tree_id, ImportedObjectKind::Tree, tree),
            (snapshot_id, ImportedObjectKind::Snapshot, snapshot),
        ] {
            let mut import = lease
                .begin_import(id, kind, u64::try_from(bytes.len()).unwrap())
                .unwrap();
            import.write_all(&bytes).unwrap();
            import.finish().unwrap();
        }
        let head = lease.authenticate_head(&head_bytes).unwrap();
        let verified = lease
            .verify_reachable(
                head,
                BackendObservationFingerprint::try_new(vec![0x63]).unwrap(),
            )
            .unwrap();
        let committed = lease
            .commit_replicated_snapshot(
                verified,
                CommitReplicatedSnapshot::new(head_bytes.clone()),
                &mut Allow,
            )
            .unwrap();
        let pending = lease.record_trusted_remote(committed).unwrap().unwrap();
        assert!(
            store
                .layout
                .trusted_remote
                .entry_names_bounded(1)
                .unwrap()
                .is_empty()
        );
        lease.acknowledge_unprovable_remote(pending).unwrap();
        let bytes = read_optional(&store.layout.trusted_remote, &component("remote").unwrap())
            .unwrap()
            .unwrap();
        let record = decode_local_state(&bytes, &DecodeLimits::PHASE_1).unwrap();
        let trusted =
            verify_authenticated_trusted_remote(&record, &keys, keys.generation()).unwrap();
        assert!(matches!(
            trusted.provenance(),
            TrustedRemoteProvenance::FreshnessUnprovableAcknowledged
        ));
        Box::new(lease).finish().unwrap();

        let mut continuity = QuarantineLease::acquire_authenticated_borrowed(
            &store,
            ReplicationLimits::PHASE_1,
            limits,
            limits,
            &keys,
            keys.generation(),
            vault,
            b"",
        )
        .unwrap();
        continuity.bootstrap_commitment = Some([0x62; 32]);
        let head = continuity.authenticate_head(&head_bytes).unwrap();
        let verified = continuity
            .verify_reachable(
                head,
                BackendObservationFingerprint::try_new(vec![0x64]).unwrap(),
            )
            .unwrap();
        let committed = continuity.accept_current_verified(verified).unwrap();
        assert!(
            continuity
                .record_trusted_remote(committed)
                .unwrap()
                .is_none()
        );
        let bytes = read_optional(&store.layout.trusted_remote, &component("remote").unwrap())
            .unwrap()
            .unwrap();
        let record = decode_local_state(&bytes, &DecodeLimits::PHASE_1).unwrap();
        let trusted =
            verify_authenticated_trusted_remote(&record, &keys, keys.generation()).unwrap();
        assert!(matches!(
            trusted.provenance(),
            TrustedRemoteProvenance::FreshnessProven
        ));
        Box::new(continuity).finish().unwrap();
    }

    #[test]
    fn reconciled_transition_requires_exact_authenticated_local_and_remote_parents() {
        struct Allow;
        impl PublicationGuard for Allow {
            fn validate(&mut self) -> Result<(), StoreError> {
                Ok(())
            }
        }

        let repository = TempDir::new().unwrap();
        let local_state = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0x71; 16]);
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local_state.path().canonicalize().unwrap(),
            vault,
        )
        .unwrap();
        let mut random = FixedRandom(0x72);
        let root = VaultRootKey::generate(&mut random).unwrap();
        let derived = derive_vault_keys(&root).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let local_logical = [0x73; 32];
        let local_tree_id = ObjectId::from_bytes([0x74; 32]);
        let local_snapshot_id = ObjectId::from_bytes([0x75; 32]);
        let remote_logical = [0x76; 32];
        let remote_tree_id = ObjectId::from_bytes([0x77; 32]);
        let remote_snapshot_id = ObjectId::from_bytes([0x78; 32]);
        let merged_logical = [0x79; 32];
        let merged_tree_id = ObjectId::from_bytes([0x7a; 32]);
        let merged_snapshot_id = ObjectId::from_bytes([0x7b; 32]);
        let local_tree =
            encrypted_empty_tree(vault, local_tree_id, [0x7c; 16], &derived, &mut random);
        let local_snapshot = encrypted_snapshot(
            vault,
            local_snapshot_id,
            local_logical,
            Vec::new(),
            local_tree_id,
            &derived,
            &mut random,
        );
        let local_head = authenticated_head_wire(
            vault,
            local_logical,
            local_snapshot_id,
            local_tree_id,
            [0x7d; 32],
            &derived,
        );
        let mut limits = ReplicationLimits::PHASE_1;
        limits.max_aggregate_bytes = 4 << 20;
        limits.max_quarantine_bytes = 4 << 20;

        let mut baseline = QuarantineLease::acquire_authenticated_borrowed(
            &store,
            ReplicationLimits::PHASE_1,
            limits,
            limits,
            &keys,
            keys.generation(),
            vault,
            b"",
        )
        .unwrap();
        baseline.bootstrap_commitment = Some([0x7e; 32]);
        for (id, kind, bytes) in [
            (local_tree_id, ImportedObjectKind::Tree, local_tree),
            (
                local_snapshot_id,
                ImportedObjectKind::Snapshot,
                local_snapshot,
            ),
        ] {
            let mut import = baseline
                .begin_import(id, kind, u64::try_from(bytes.len()).unwrap())
                .unwrap();
            import.write_all(&bytes).unwrap();
            import.finish().unwrap();
        }
        let head = baseline.authenticate_head(&local_head).unwrap();
        let verified = baseline
            .verify_reachable(
                head,
                BackendObservationFingerprint::try_new(vec![0x7f]).unwrap(),
            )
            .unwrap();
        let committed = baseline
            .commit_replicated_snapshot(
                verified,
                CommitReplicatedSnapshot::new(local_head),
                &mut Allow,
            )
            .unwrap();
        let pending = baseline.record_trusted_remote(committed).unwrap().unwrap();
        baseline.acknowledge_unprovable_remote(pending).unwrap();
        Box::new(baseline).finish().unwrap();

        let remote_tree =
            encrypted_empty_tree(vault, remote_tree_id, [0x80; 16], &derived, &mut random);
        let remote_snapshot = encrypted_snapshot(
            vault,
            remote_snapshot_id,
            remote_logical,
            vec![SnapshotParentLocator::new(
                local_logical,
                *local_snapshot_id.as_bytes(),
            )],
            remote_tree_id,
            &derived,
            &mut random,
        );
        let remote_head = authenticated_head_wire(
            vault,
            remote_logical,
            remote_snapshot_id,
            remote_tree_id,
            [0x81; 32],
            &derived,
        );
        let merged_tree =
            encrypted_empty_tree(vault, merged_tree_id, [0x82; 16], &derived, &mut random);
        let merged_snapshot = encrypted_snapshot(
            vault,
            merged_snapshot_id,
            merged_logical,
            vec![
                SnapshotParentLocator::new(local_logical, *local_snapshot_id.as_bytes()),
                SnapshotParentLocator::new(remote_logical, *remote_snapshot_id.as_bytes()),
            ],
            merged_tree_id,
            &derived,
            &mut random,
        );
        let merged_head = authenticated_head_wire(
            vault,
            merged_logical,
            merged_snapshot_id,
            merged_tree_id,
            [0x83; 32],
            &derived,
        );
        let merged_head_for_readback = merged_head.clone();

        let mut reconciliation = QuarantineLease::acquire_authenticated_borrowed(
            &store,
            ReplicationLimits::PHASE_1,
            limits,
            limits,
            &keys,
            keys.generation(),
            vault,
            b"",
        )
        .unwrap();
        reconciliation.bootstrap_commitment = Some([0x7e; 32]);
        for (id, kind, bytes) in [
            (remote_tree_id, ImportedObjectKind::Tree, remote_tree),
            (
                remote_snapshot_id,
                ImportedObjectKind::Snapshot,
                remote_snapshot,
            ),
        ] {
            let mut import = reconciliation
                .begin_import(id, kind, u64::try_from(bytes.len()).unwrap())
                .unwrap();
            import.write_all(&bytes).unwrap();
            import.finish().unwrap();
        }
        let remote = reconciliation.authenticate_head(&remote_head).unwrap();
        let verified_remote = reconciliation
            .verify_reachable(
                remote,
                BackendObservationFingerprint::try_new(vec![0x84]).unwrap(),
            )
            .unwrap();
        for (id, kind, bytes) in [
            (merged_tree_id, ImportedObjectKind::Tree, merged_tree),
            (
                merged_snapshot_id,
                ImportedObjectKind::Snapshot,
                merged_snapshot,
            ),
        ] {
            let mut import = reconciliation
                .begin_import(id, kind, u64::try_from(bytes.len()).unwrap())
                .unwrap();
            import.write_all(&bytes).unwrap();
            import.finish().unwrap();
        }
        let pending_publication = reconciliation
            .commit_reconciled_snapshot(
                verified_remote,
                CommitReplicatedSnapshot::new(merged_head),
                &mut Allow,
            )
            .unwrap();
        let current = read_and_authenticate_current_head(&store.layout, &keys, keys.generation())
            .unwrap()
            .unwrap();
        assert_eq!(
            current.snapshot,
            notecrypt_core::SnapshotId::from_bytes(merged_logical)
        );
        assert_eq!(current.snapshot_object, merged_snapshot_id);
        Box::new(reconciliation).finish().unwrap();

        let mut readback = QuarantineLease::acquire_authenticated_borrowed(
            &store,
            ReplicationLimits::PHASE_1,
            limits,
            limits,
            &keys,
            keys.generation(),
            vault,
            b"",
        )
        .unwrap();
        readback.bootstrap_commitment = Some([0x7e; 32]);
        let observed_head = readback
            .authenticate_head(&merged_head_for_readback)
            .unwrap();
        let verified_readback = readback
            .verify_reachable(
                observed_head,
                BackendObservationFingerprint::try_new(vec![0x85]).unwrap(),
            )
            .unwrap();
        let observed = readback
            .confirm_reconciled_publication(pending_publication, verified_readback)
            .unwrap();
        assert!(readback.record_trusted_remote(observed).unwrap().is_none());
        Box::new(readback).finish().unwrap();
    }

    #[test]
    fn reconciliation_rejects_a_parent_with_the_right_logical_id_but_wrong_object() {
        let local = LocalHeadBinding {
            snapshot: notecrypt_core::SnapshotId::from_bytes([1; 32]),
            snapshot_object: ObjectId::from_bytes([2; 32]),
            tree_object: ObjectId::from_bytes([3; 32]),
            head_commitment: [4; 32],
        };
        let remote = (
            notecrypt_core::SnapshotId::from_bytes([5; 32]),
            ObjectId::from_bytes([6; 32]),
        );
        let result = validate_reconciliation_parents(
            [
                ([1; 32], ObjectId::from_bytes([9; 32])),
                ([5; 32], ObjectId::from_bytes([6; 32])),
            ],
            local,
            remote,
        );
        assert!(matches!(result, Err(StoreError::AuthenticationFailed)));
    }
}
