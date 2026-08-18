use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use notecrypt_core::{ObjectId, SnapshotId, VaultId};

use crate::StoreError;
use crate::replication::{
    AuthenticatedObjectSemantics, ImportedObjectKind, ImportedObjectMetadata, ReplicationBudget,
    ReplicationLimits,
};
use crate::transaction::AuthenticatedHead;

const OPERATION_OPEN: u8 = 0;
const OPERATION_SPENT: u8 = 1;
const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
const MAX_OPERATION_HISTORY: usize = 100_000;

pub(crate) struct OperationRegistry {
    state: Mutex<OperationRegistryState>,
}

struct OperationRegistryState {
    active: HashSet<[u8; 16]>,
    spent: HashSet<[u8; 16]>,
}

impl OperationRegistry {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(OperationRegistryState {
                active: HashSet::new(),
                spent: HashSet::new(),
            }),
        }
    }

    pub(crate) fn register(&self, operation: [u8; 16]) -> Result<bool, StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Locked)?;
        if state.active.contains(&operation) || state.spent.contains(&operation) {
            return Ok(false);
        }
        if state.active.len().saturating_add(state.spent.len()) >= MAX_OPERATION_HISTORY {
            return Err(StoreError::LimitExceeded);
        }
        state
            .active
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        state.active.insert(operation);
        Ok(true)
    }

    pub(crate) fn spend(&self, operation: [u8; 16]) -> Result<(), StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Locked)?;
        if !state.active.contains(&operation) || state.spent.contains(&operation) {
            return Err(StoreError::InvalidCapability);
        }
        state
            .spent
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        state.active.remove(&operation);
        state.spent.insert(operation);
        Ok(())
    }

    fn is_active(&self, operation: [u8; 16]) -> Result<bool, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Locked)?;
        Ok(state.active.contains(&operation) && !state.spent.contains(&operation))
    }

    pub(crate) fn finish(&self, operation: [u8; 16]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.active.remove(&operation)
            && state.active.len().saturating_add(state.spent.len()) < MAX_OPERATION_HISTORY
        {
            state.spent.insert(operation);
        }
    }
}

pub struct BackendObservationFingerprint(Vec<u8>);

impl BackendObservationFingerprint {
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, StoreError> {
        if bytes.is_empty() || bytes.len() > MAX_OBSERVATION_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        Ok(Self(bytes))
    }

    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn retained_capacity_for_test(&self) -> usize {
        self.0.capacity()
    }
}

pub struct VerifiedReachableHead {
    binding: VerifiedReachableBinding,
}

pub struct CommittedReachableHead {
    binding: CommittedReachableBinding,
}

pub struct PendingUnprovableRemote {
    binding: CommittedReachableBinding,
}

impl PendingUnprovableRemote {
    /// Returns the authenticated snapshot already bound into this linear proof.
    #[must_use]
    pub const fn authenticated_snapshot(&self) -> SnapshotId {
        self.binding.verified.target_snapshot
    }
}

pub struct PendingRemotePublication {
    vault: VaultId,
    snapshot: SnapshotId,
    snapshot_object: ObjectId,
    tree_object: ObjectId,
    head_commitment: [u8; 32],
}

struct VerifiedReachableBinding {
    vault: VaultId,
    generation: u64,
    bootstrap: [u8; 32],
    head: [u8; 32],
    reached: [u8; 32],
    limits: [u8; 32],
    observation: [u8; 32],
    operation: [u8; 16],
    target_snapshot: SnapshotId,
    target_snapshot_object: ObjectId,
    target_tree_object: ObjectId,
    local_head_at_verification: Option<LocalHeadBinding>,
    prior_remote_at_verification: Option<RemoteBaseline>,
    fast_forward_proven: bool,
    remote_freshness_proven: bool,
    state: Arc<AtomicU8>,
    registry: Arc<OperationRegistry>,
}

struct CommittedReachableBinding {
    verified: VerifiedReachableBinding,
    local_snapshot: SnapshotId,
    transition: CommittedTransition,
}

enum CommittedTransition {
    FastForward,
    Reconciled,
    NoLocalCommit,
}

pub(crate) enum AppliedReplicatedTransition {
    FastForward,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalHeadBinding {
    pub(crate) snapshot: SnapshotId,
    pub(crate) snapshot_object: ObjectId,
    pub(crate) tree_object: ObjectId,
    pub(crate) head_commitment: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteBaseline {
    pub(crate) snapshot: SnapshotId,
    pub(crate) snapshot_object: ObjectId,
}

struct PendingNode {
    kind: ImportedObjectKind,
    id: ObjectId,
    depth: u32,
    expected: ExpectedSemantics,
}

enum ExpectedSemantics {
    Snapshot {
        logical_id: [u8; 32],
        tree_object_id: Option<ObjectId>,
    },
    Tree,
    Manifest {
        file_id: [u8; 16],
        revision_id: [u8; 32],
    },
    Chunk {
        file_id: [u8; 16],
        position: u64,
    },
}

#[derive(Clone, Copy)]
enum AuthenticatedIdentitySemantics {
    Snapshot {
        logical_id: [u8; 32],
        tree_object_id: ObjectId,
    },
    Tree,
    Manifest {
        file_id: [u8; 16],
        revision_id: [u8; 32],
    },
    Chunk {
        file_id: [u8; 16],
        position: u64,
    },
}

pub(crate) struct VerificationContext {
    pub(crate) vault: VaultId,
    pub(crate) generation: u64,
    pub(crate) bootstrap_commitment: [u8; 32],
    pub(crate) limits: ReplicationLimits,
    pub(crate) operation: [u8; 16],
    pub(crate) local_head: Option<LocalHeadBinding>,
    pub(crate) prior_remote: Option<RemoteBaseline>,
    pub(crate) state: Arc<AtomicU8>,
    pub(crate) registry: Arc<OperationRegistry>,
}

pub(crate) fn verify_reachable_graph(
    context: VerificationContext,
    head: AuthenticatedHead,
    observation: BackendObservationFingerprint,
    mut authenticate: impl FnMut(
        ObjectId,
        ImportedObjectKind,
    ) -> Result<ImportedObjectMetadata, StoreError>,
    mut check_boundary: impl FnMut() -> Result<(), StoreError>,
) -> Result<VerifiedReachableHead, StoreError> {
    if head.vault != context.vault
        || context.state.load(Ordering::Acquire) != OPERATION_OPEN
        || !context.registry.is_active(context.operation)?
    {
        return Err(StoreError::InvalidCapability);
    }
    let mut budget = ReplicationBudget::new(context.limits);
    let mut queue = VecDeque::new();
    queue
        .try_reserve(1)
        .map_err(|_| StoreError::LimitExceeded)?;
    queue.push_back(PendingNode {
        kind: ImportedObjectKind::Snapshot,
        id: head.snapshot_object,
        depth: 0,
        expected: ExpectedSemantics::Snapshot {
            logical_id: *head.snapshot.as_bytes(),
            tree_object_id: Some(head.tree_object),
        },
    });
    let mut visited =
        HashMap::<ObjectId, (ImportedObjectKind, AuthenticatedIdentitySemantics)>::new();
    let mut reached = Vec::new();
    let mut snapshot_by_logical = HashMap::<[u8; 32], ObjectId>::new();
    let mut snapshot_by_object = HashMap::<ObjectId, [u8; 32]>::new();
    let mut manifest_by_revision = HashMap::<[u8; 32], ObjectId>::new();
    let mut revision_by_manifest = HashMap::<ObjectId, [u8; 32]>::new();
    let mut chunk_by_position = HashMap::<([u8; 16], u64), ObjectId>::new();
    let mut position_by_chunk = HashMap::<ObjectId, ([u8; 16], u64)>::new();
    let mut local_head_seen = context.local_head.is_none();
    let mut prior_remote_seen = context.prior_remote.is_none();

    while let Some(node) = queue.pop_front() {
        check_boundary()?;
        budget.check_depth(node.depth)?;
        validate_expected_bijections(
            &node,
            &mut snapshot_by_logical,
            &mut snapshot_by_object,
            &mut manifest_by_revision,
            &mut revision_by_manifest,
            &mut chunk_by_position,
            &mut position_by_chunk,
        )?;
        if let Some((previous_kind, authenticated)) = visited.get(&node.id) {
            if *previous_kind != node.kind
                || validate_cached_semantics(&node.expected, authenticated).is_err()
            {
                return Err(StoreError::AuthenticationFailed);
            }
            continue;
        }
        visited
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        reached
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        let metadata = authenticate(node.id, node.kind)?;
        if metadata.id() != node.id || metadata.kind() != node.kind {
            return Err(StoreError::AuthenticationFailed);
        }
        validate_semantics(&node.expected, metadata.semantics())?;
        let authenticated = authenticated_identity(metadata.semantics());
        if let AuthenticatedIdentitySemantics::Snapshot {
            logical_id,
            tree_object_id,
        } = authenticated
            && context.local_head.is_some_and(|local| {
                local.snapshot.as_bytes() == &logical_id
                    && local.snapshot_object == node.id
                    && local.tree_object == tree_object_id
            })
        {
            local_head_seen = true;
        }
        if let AuthenticatedIdentitySemantics::Snapshot { logical_id, .. } = authenticated
            && context.prior_remote.is_some_and(|prior| {
                prior.snapshot.as_bytes() == &logical_id && prior.snapshot_object == node.id
            })
        {
            prior_remote_seen = true;
        }
        budget.add_object(metadata.encoded_length())?;
        budget.add_edges(
            u64::try_from(metadata.references().len()).map_err(|_| StoreError::LimitExceeded)?,
        )?;
        let next_depth = node.depth.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        enqueue_references(&metadata, next_depth, &mut queue)?;
        visited.insert(node.id, (node.kind, authenticated));
        reached.push((kind_tag(node.kind), *node.id.as_bytes()));
        check_boundary()?;
    }

    reached.sort_unstable();
    if reached.windows(2).any(|pair| pair[0].1 == pair[1].1) {
        return Err(StoreError::AuthenticationFailed);
    }
    if !prior_remote_seen {
        return Err(StoreError::RollbackDetected);
    }
    Ok(VerifiedReachableHead {
        binding: VerifiedReachableBinding {
            vault: context.vault,
            generation: context.generation,
            bootstrap: context.bootstrap_commitment,
            head: head.commitment,
            reached: commitment_of_reached(&reached),
            limits: commitment_of_limits(context.limits),
            observation: observation_commitment(&observation),
            operation: context.operation,
            target_snapshot: head.snapshot,
            target_snapshot_object: head.snapshot_object,
            target_tree_object: head.tree_object,
            local_head_at_verification: context.local_head,
            prior_remote_at_verification: context.prior_remote,
            fast_forward_proven: local_head_seen
                && context
                    .local_head
                    .is_none_or(|local| local.snapshot != head.snapshot),
            remote_freshness_proven: context.prior_remote.is_some() && prior_remote_seen,
            state: context.state,
            registry: context.registry,
        },
    })
}

fn validate_expected_bijections(
    node: &PendingNode,
    snapshot_by_logical: &mut HashMap<[u8; 32], ObjectId>,
    snapshot_by_object: &mut HashMap<ObjectId, [u8; 32]>,
    manifest_by_revision: &mut HashMap<[u8; 32], ObjectId>,
    revision_by_manifest: &mut HashMap<ObjectId, [u8; 32]>,
    chunk_by_position: &mut HashMap<([u8; 16], u64), ObjectId>,
    position_by_chunk: &mut HashMap<ObjectId, ([u8; 16], u64)>,
) -> Result<(), StoreError> {
    match node.expected {
        ExpectedSemantics::Snapshot { logical_id, .. } => {
            fallible_insert_bijection(snapshot_by_logical, logical_id, node.id)?;
            fallible_insert_bijection(snapshot_by_object, node.id, logical_id)
        }
        ExpectedSemantics::Manifest {
            file_id,
            revision_id,
        } => {
            let _ = file_id;
            fallible_insert_bijection(manifest_by_revision, revision_id, node.id)?;
            fallible_insert_bijection(revision_by_manifest, node.id, revision_id)
        }
        ExpectedSemantics::Chunk { file_id, position } => {
            fallible_insert_bijection(chunk_by_position, (file_id, position), node.id)?;
            fallible_insert_bijection(position_by_chunk, node.id, (file_id, position))
        }
        ExpectedSemantics::Tree => Ok(()),
    }
}

fn authenticated_identity(
    semantics: &AuthenticatedObjectSemantics,
) -> AuthenticatedIdentitySemantics {
    match semantics {
        AuthenticatedObjectSemantics::Snapshot {
            snapshot_id,
            tree_object_id,
            ..
        } => AuthenticatedIdentitySemantics::Snapshot {
            logical_id: *snapshot_id,
            tree_object_id: *tree_object_id,
        },
        AuthenticatedObjectSemantics::Tree { .. } => AuthenticatedIdentitySemantics::Tree,
        AuthenticatedObjectSemantics::Manifest {
            file_id,
            revision_id,
            ..
        } => AuthenticatedIdentitySemantics::Manifest {
            file_id: *file_id,
            revision_id: *revision_id,
        },
        AuthenticatedObjectSemantics::Chunk { file_id, position } => {
            AuthenticatedIdentitySemantics::Chunk {
                file_id: *file_id,
                position: *position,
            }
        }
    }
}

fn validate_cached_semantics(
    expected: &ExpectedSemantics,
    actual: &AuthenticatedIdentitySemantics,
) -> Result<(), StoreError> {
    match (expected, actual) {
        (
            ExpectedSemantics::Snapshot {
                logical_id,
                tree_object_id,
            },
            AuthenticatedIdentitySemantics::Snapshot {
                logical_id: actual_logical,
                tree_object_id: actual_tree,
            },
        ) if logical_id == actual_logical
            && tree_object_id.is_none_or(|expected_tree| expected_tree == *actual_tree) =>
        {
            Ok(())
        }
        (ExpectedSemantics::Tree, AuthenticatedIdentitySemantics::Tree) => Ok(()),
        (
            ExpectedSemantics::Manifest {
                file_id,
                revision_id,
            },
            AuthenticatedIdentitySemantics::Manifest {
                file_id: actual_file,
                revision_id: actual_revision,
            },
        ) if file_id == actual_file && revision_id == actual_revision => Ok(()),
        (
            ExpectedSemantics::Chunk { file_id, position },
            AuthenticatedIdentitySemantics::Chunk {
                file_id: actual_file,
                position: actual_position,
            },
        ) if file_id == actual_file && position == actual_position => Ok(()),
        _ => Err(StoreError::AuthenticationFailed),
    }
}

fn fallible_insert_bijection<K, V>(
    map: &mut HashMap<K, V>,
    key: K,
    value: V,
) -> Result<(), StoreError>
where
    K: Eq + std::hash::Hash,
    V: Eq,
{
    if let Some(existing) = map.get(&key) {
        if existing != &value {
            return Err(StoreError::AuthenticationFailed);
        }
        return Ok(());
    }
    map.try_reserve(1).map_err(|_| StoreError::LimitExceeded)?;
    map.insert(key, value);
    Ok(())
}

fn validate_semantics(
    expected: &ExpectedSemantics,
    actual: &AuthenticatedObjectSemantics,
) -> Result<(), StoreError> {
    match (expected, actual) {
        (
            ExpectedSemantics::Snapshot {
                logical_id,
                tree_object_id,
            },
            AuthenticatedObjectSemantics::Snapshot {
                snapshot_id,
                tree_object_id: actual_tree,
                ..
            },
        ) if logical_id == snapshot_id
            && tree_object_id.is_none_or(|expected_tree| expected_tree == *actual_tree) =>
        {
            Ok(())
        }
        (ExpectedSemantics::Tree, AuthenticatedObjectSemantics::Tree { .. }) => Ok(()),
        (
            ExpectedSemantics::Manifest {
                file_id,
                revision_id,
            },
            AuthenticatedObjectSemantics::Manifest {
                file_id: actual_file,
                revision_id: actual_revision,
                ..
            },
        ) if file_id == actual_file && revision_id == actual_revision => Ok(()),
        (
            ExpectedSemantics::Chunk { file_id, position },
            AuthenticatedObjectSemantics::Chunk {
                file_id: actual_file,
                position: actual_position,
            },
        ) if file_id == actual_file && position == actual_position => Ok(()),
        _ => Err(StoreError::AuthenticationFailed),
    }
}

fn enqueue_references(
    metadata: &ImportedObjectMetadata,
    depth: u32,
    queue: &mut VecDeque<PendingNode>,
) -> Result<(), StoreError> {
    queue
        .try_reserve(metadata.references().len())
        .map_err(|_| StoreError::LimitExceeded)?;
    match metadata.semantics() {
        AuthenticatedObjectSemantics::Chunk { .. } => {}
        AuthenticatedObjectSemantics::Manifest {
            file_id, chunks, ..
        } => {
            for chunk in chunks {
                queue.push_back(PendingNode {
                    kind: ImportedObjectKind::Chunk,
                    id: chunk.object_id,
                    depth,
                    expected: ExpectedSemantics::Chunk {
                        file_id: *file_id,
                        position: chunk.position,
                    },
                });
            }
        }
        AuthenticatedObjectSemantics::Tree { revisions } => {
            for locator in revisions {
                queue.push_back(PendingNode {
                    kind: ImportedObjectKind::Manifest,
                    id: locator.manifest_object_id,
                    depth,
                    expected: ExpectedSemantics::Manifest {
                        file_id: locator.file_id,
                        revision_id: locator.revision_id,
                    },
                });
            }
        }
        AuthenticatedObjectSemantics::Snapshot {
            parents,
            tree_object_id,
            ..
        } => {
            queue.push_back(PendingNode {
                kind: ImportedObjectKind::Tree,
                id: *tree_object_id,
                depth,
                expected: ExpectedSemantics::Tree,
            });
            for parent in parents {
                queue.push_back(PendingNode {
                    kind: ImportedObjectKind::Snapshot,
                    id: parent.snapshot_object_id,
                    depth,
                    expected: ExpectedSemantics::Snapshot {
                        logical_id: parent.snapshot_id,
                        tree_object_id: None,
                    },
                });
            }
        }
    }
    Ok(())
}

pub(crate) struct CommitContext {
    pub(crate) vault: VaultId,
    pub(crate) generation: u64,
    pub(crate) bootstrap_commitment: [u8; 32],
    pub(crate) head_commitment: [u8; 32],
    pub(crate) limits: ReplicationLimits,
    pub(crate) observation_commitment: [u8; 32],
    pub(crate) operation: [u8; 16],
    pub(crate) local_head: Option<LocalHeadBinding>,
    pub(crate) prior_remote: Option<RemoteBaseline>,
    pub(crate) state: Arc<AtomicU8>,
    pub(crate) registry: Arc<OperationRegistry>,
}

pub(crate) struct RecordContext {
    pub(crate) vault: VaultId,
    pub(crate) generation: u64,
    pub(crate) bootstrap_commitment: [u8; 32],
    pub(crate) head_commitment: [u8; 32],
    pub(crate) limits: ReplicationLimits,
    pub(crate) observation_commitment: [u8; 32],
    pub(crate) operation: [u8; 16],
    pub(crate) local_head: Option<LocalHeadBinding>,
    pub(crate) prior_remote: Option<RemoteBaseline>,
    pub(crate) state: Arc<AtomicU8>,
    pub(crate) registry: Arc<OperationRegistry>,
}

pub(crate) fn commit_applied(
    verified: VerifiedReachableHead,
    context: CommitContext,
    local_snapshot: SnapshotId,
    transition: AppliedReplicatedTransition,
    commit: impl FnOnce() -> Result<(), StoreError>,
) -> Result<CommittedReachableHead, StoreError> {
    let binding = consume_verified(verified, &context)?;
    if !binding.fast_forward_proven {
        return Err(StoreError::RollbackDetected);
    }
    commit()?;
    Ok(CommittedReachableHead {
        binding: CommittedReachableBinding {
            verified: binding,
            local_snapshot,
            transition: match transition {
                AppliedReplicatedTransition::FastForward => CommittedTransition::FastForward,
            },
        },
    })
}

pub(crate) fn commit_reconciled(
    verified: VerifiedReachableHead,
    context: CommitContext,
    intended: AuthenticatedHead,
    commit: impl FnOnce() -> Result<(), StoreError>,
) -> Result<PendingRemotePublication, StoreError> {
    let binding = consume_verified(verified, &context)?;
    commit()?;
    if intended.vault != context.vault {
        return Err(StoreError::InvalidCapability);
    }
    let _committed_binding = CommittedReachableBinding {
        verified: binding,
        local_snapshot: intended.snapshot,
        transition: CommittedTransition::Reconciled,
    };
    Ok(PendingRemotePublication {
        vault: intended.vault,
        snapshot: intended.snapshot,
        snapshot_object: intended.snapshot_object,
        tree_object: intended.tree_object,
        head_commitment: intended.commitment,
    })
}

pub(crate) fn confirm_reconciled_publication(
    pending: PendingRemotePublication,
    observed: CommittedReachableHead,
) -> Result<CommittedReachableHead, StoreError> {
    let binding = &observed.binding;
    let exact = matches!(binding.transition, CommittedTransition::NoLocalCommit)
        && binding.verified.vault == pending.vault
        && binding.verified.target_snapshot == pending.snapshot
        && binding.verified.target_snapshot_object == pending.snapshot_object
        && binding.verified.target_tree_object == pending.tree_object
        && binding.verified.head == pending.head_commitment
        && binding.local_snapshot == pending.snapshot;
    if exact {
        Ok(observed)
    } else {
        Err(StoreError::InvalidCapability)
    }
}

pub(crate) fn verified_target_locator(verified: &VerifiedReachableHead) -> (SnapshotId, ObjectId) {
    (
        verified.binding.target_snapshot,
        verified.binding.target_snapshot_object,
    )
}

pub(crate) fn accept_current_verified(
    verified: VerifiedReachableHead,
    context: CommitContext,
    prove_current: impl FnOnce(SnapshotId) -> Result<(), StoreError>,
) -> Result<CommittedReachableHead, StoreError> {
    let target = verified.binding.target_snapshot;
    let binding = consume_verified(verified, &context)?;
    prove_current(target)?;
    Ok(CommittedReachableHead {
        binding: CommittedReachableBinding {
            verified: binding,
            local_snapshot: target,
            transition: CommittedTransition::NoLocalCommit,
        },
    })
}

fn consume_verified(
    verified: VerifiedReachableHead,
    context: &CommitContext,
) -> Result<VerifiedReachableBinding, StoreError> {
    let binding = verified.binding;
    let exact = binding.vault == context.vault
        && binding.generation == context.generation
        && binding.bootstrap == context.bootstrap_commitment
        && binding.head == context.head_commitment
        && binding.limits == commitment_of_limits(context.limits)
        && binding.observation == context.observation_commitment
        && binding.operation == context.operation
        && binding.local_head_at_verification == context.local_head
        && binding.prior_remote_at_verification == context.prior_remote
        && Arc::ptr_eq(&binding.state, &context.state)
        && Arc::ptr_eq(&binding.registry, &context.registry);
    if !exact {
        return Err(StoreError::InvalidCapability);
    }
    binding.registry.spend(binding.operation)?;
    binding
        .state
        .compare_exchange(
            OPERATION_OPEN,
            OPERATION_SPENT,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| StoreError::InvalidCapability)?;
    Ok(binding)
}

pub(crate) fn record_or_require_unprovable_acknowledgement(
    committed: CommittedReachableHead,
    context: &RecordContext,
    record: impl FnOnce(RemoteObservationRecord) -> Result<(), StoreError>,
) -> Result<Option<PendingUnprovableRemote>, StoreError> {
    validate_record_context(&committed.binding, context)?;
    if committed
        .binding
        .verified
        .prior_remote_at_verification
        .is_none()
    {
        return Ok(Some(PendingUnprovableRemote {
            binding: committed.binding,
        }));
    }
    if !committed.binding.verified.remote_freshness_proven {
        return Err(StoreError::RollbackDetected);
    }
    record(remote_observation_record(&committed.binding))?;
    Ok(None)
}

pub(crate) fn acknowledge_unprovable_remote(
    pending: PendingUnprovableRemote,
    context: &RecordContext,
    record: impl FnOnce(RemoteObservationRecord) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    validate_record_context(&pending.binding, context)?;
    record(remote_observation_record(&pending.binding))
}

pub(crate) struct RemoteObservationRecord {
    pub(crate) snapshot: SnapshotId,
    pub(crate) snapshot_object: ObjectId,
    pub(crate) head_commitment: [u8; 32],
    pub(crate) observation_commitment: [u8; 32],
    pub(crate) binding_commitment: [u8; 32],
}

fn remote_observation_record(binding: &CommittedReachableBinding) -> RemoteObservationRecord {
    RemoteObservationRecord {
        snapshot: binding.verified.target_snapshot,
        snapshot_object: binding.verified.target_snapshot_object,
        head_commitment: binding.verified.head,
        observation_commitment: binding.verified.observation,
        binding_commitment: committed_binding_commitment(binding),
    }
}

fn validate_record_context(
    binding: &CommittedReachableBinding,
    context: &RecordContext,
) -> Result<(), StoreError> {
    let verified = &binding.verified;
    let exact = verified.vault == context.vault
        && verified.generation == context.generation
        && verified.bootstrap == context.bootstrap_commitment
        && verified.head == context.head_commitment
        && verified.limits == commitment_of_limits(context.limits)
        && verified.observation == context.observation_commitment
        && verified.operation == context.operation
        && verified.local_head_at_verification == context.local_head
        && verified.prior_remote_at_verification == context.prior_remote
        && Arc::ptr_eq(&verified.state, &context.state)
        && Arc::ptr_eq(&verified.registry, &context.registry);
    if exact {
        Ok(())
    } else {
        Err(StoreError::InvalidCapability)
    }
}

fn committed_binding_commitment(binding: &CommittedReachableBinding) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"notecrypt/committed-reachable/v1");
    hasher.update(binding.verified.vault.as_bytes());
    hasher.update(&binding.verified.generation.to_be_bytes());
    hasher.update(&binding.verified.bootstrap);
    hasher.update(&binding.verified.head);
    hasher.update(&binding.verified.reached);
    hasher.update(&binding.verified.limits);
    hasher.update(&binding.verified.observation);
    hasher.update(&binding.verified.operation);
    hasher.update(binding.verified.target_snapshot.as_bytes());
    hasher.update(binding.verified.target_snapshot_object.as_bytes());
    hasher.update(binding.verified.target_tree_object.as_bytes());
    match binding.verified.local_head_at_verification {
        Some(local) => {
            hasher.update(&[1]);
            hasher.update(local.snapshot.as_bytes());
            hasher.update(local.snapshot_object.as_bytes());
            hasher.update(local.tree_object.as_bytes());
            hasher.update(&local.head_commitment);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match binding.verified.prior_remote_at_verification {
        Some(prior) => {
            hasher.update(&[1]);
            hasher.update(prior.snapshot.as_bytes());
            hasher.update(prior.snapshot_object.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&[u8::from(binding.verified.fast_forward_proven)]);
    hasher.update(&[u8::from(binding.verified.remote_freshness_proven)]);
    hasher.update(binding.local_snapshot.as_bytes());
    hasher.update(&[match binding.transition {
        CommittedTransition::FastForward => 1,
        CommittedTransition::Reconciled => 2,
        CommittedTransition::NoLocalCommit => 3,
    }]);
    *hasher.finalize().as_bytes()
}

fn commitment_of_reached(reached: &[(u8, [u8; 32])]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"notecrypt/reachable-set/v1");
    for (kind, id) in reached {
        hasher.update(&[*kind]);
        hasher.update(id);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn observation_commitment(observation: &BackendObservationFingerprint) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"notecrypt/backend-observation/v1");
    hasher.update(&observation.0);
    *hasher.finalize().as_bytes()
}

fn commitment_of_limits(limits: ReplicationLimits) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"notecrypt/replication-limits/v1");
    for value in [
        limits.max_bootstrap_bytes,
        limits.max_head_bytes,
        limits.max_chunk_object_bytes,
        limits.max_manifest_object_bytes,
        limits.max_tree_object_bytes,
        limits.max_snapshot_object_bytes,
        limits.max_aggregate_bytes,
        limits.max_object_count,
        limits.max_graph_edges,
        u64::from(limits.max_graph_depth),
        limits
            .max_duration
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX),
        limits
            .progress_interval
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX),
        limits.max_quarantine_bytes,
        limits.free_space_reserve_bytes,
    ] {
        hasher.update(&value.to_be_bytes());
    }
    *hasher.finalize().as_bytes()
}

const fn kind_tag(kind: ImportedObjectKind) -> u8 {
    match kind {
        ImportedObjectKind::Chunk => 1,
        ImportedObjectKind::Manifest => 2,
        ImportedObjectKind::Tree => 3,
        ImportedObjectKind::Snapshot => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::{
        AuthenticatedChunkReference, AuthenticatedRevisionLocator, AuthenticatedSnapshotParent,
    };

    fn context(vault: VaultId) -> VerificationContext {
        let registry = Arc::new(OperationRegistry::new());
        registry.register([3; 16]).unwrap();
        VerificationContext {
            vault,
            generation: 1,
            bootstrap_commitment: [2; 32],
            limits: ReplicationLimits::PHASE_1,
            operation: [3; 16],
            local_head: None,
            prior_remote: None,
            state: Arc::new(AtomicU8::new(OPERATION_OPEN)),
            registry,
        }
    }

    fn head(vault: VaultId, snapshot: ObjectId, tree: ObjectId) -> AuthenticatedHead {
        AuthenticatedHead {
            vault,
            snapshot: SnapshotId::from_bytes([4; 32]),
            commitment: [5; 32],
            snapshot_object: snapshot,
            tree_object: tree,
        }
    }

    #[test]
    fn pending_remote_acknowledgement_is_bound_to_its_exact_lease_context() {
        let vault = VaultId::from_bytes([0x90; 16]);
        let registry_a = Arc::new(OperationRegistry::new());
        let registry_b = Arc::new(OperationRegistry::new());
        let state_a = Arc::new(AtomicU8::new(OPERATION_SPENT));
        let state_b = Arc::new(AtomicU8::new(OPERATION_SPENT));
        let binding = CommittedReachableBinding {
            verified: VerifiedReachableBinding {
                vault,
                generation: 1,
                bootstrap: [1; 32],
                head: [2; 32],
                reached: [3; 32],
                limits: commitment_of_limits(ReplicationLimits::PHASE_1),
                observation: [4; 32],
                operation: [5; 16],
                target_snapshot: SnapshotId::from_bytes([6; 32]),
                target_snapshot_object: ObjectId::from_bytes([7; 32]),
                target_tree_object: ObjectId::from_bytes([8; 32]),
                local_head_at_verification: None,
                prior_remote_at_verification: None,
                fast_forward_proven: false,
                remote_freshness_proven: false,
                state: Arc::clone(&state_a),
                registry: Arc::clone(&registry_a),
            },
            local_snapshot: SnapshotId::from_bytes([6; 32]),
            transition: CommittedTransition::NoLocalCommit,
        };
        let pending = PendingUnprovableRemote { binding };
        let wrong_lease = RecordContext {
            vault,
            generation: 1,
            bootstrap_commitment: [1; 32],
            head_commitment: [2; 32],
            limits: ReplicationLimits::PHASE_1,
            observation_commitment: [4; 32],
            operation: [5; 16],
            local_head: None,
            prior_remote: None,
            state: state_b,
            registry: registry_b,
        };
        let mut wrote = false;
        assert!(matches!(
            acknowledge_unprovable_remote(pending, &wrong_lease, |_| {
                wrote = true;
                Ok(())
            }),
            Err(StoreError::InvalidCapability)
        ));
        assert!(!wrote);
    }

    #[test]
    fn spent_operation_identity_cannot_be_registered_for_replay() {
        let registry = OperationRegistry::new();
        assert!(registry.register([0x55; 16]).unwrap());
        registry.spend([0x55; 16]).unwrap();
        assert!(!registry.register([0x55; 16]).unwrap());
        assert!(matches!(
            registry.spend([0x55; 16]),
            Err(StoreError::InvalidCapability)
        ));
    }

    #[test]
    fn fast_forward_requires_the_exact_local_snapshot_object_locator() {
        let vault = VaultId::from_bytes([1; 16]);
        let target_snapshot = ObjectId::from_bytes([10; 32]);
        let target_tree = ObjectId::from_bytes([11; 32]);
        let observed_parent = ObjectId::from_bytes([12; 32]);
        let parent_tree = ObjectId::from_bytes([13; 32]);
        let mut verification = context(vault);
        verification.local_head = Some(LocalHeadBinding {
            snapshot: SnapshotId::from_bytes([9; 32]),
            snapshot_object: ObjectId::from_bytes([14; 32]),
            tree_object: parent_tree,
            head_commitment: [15; 32],
        });
        let state = Arc::clone(&verification.state);
        let registry = Arc::clone(&verification.registry);
        let verified = verify_reachable_graph(
            verification,
            head(vault, target_snapshot, target_tree),
            BackendObservationFingerprint::try_new(vec![1]).unwrap(),
            |id, kind| {
                let semantics = if id == target_snapshot {
                    AuthenticatedObjectSemantics::Snapshot {
                        snapshot_id: [4; 32],
                        parents: vec![AuthenticatedSnapshotParent {
                            snapshot_id: [9; 32],
                            snapshot_object_id: observed_parent,
                        }],
                        tree_object_id: target_tree,
                    }
                } else if id == observed_parent {
                    AuthenticatedObjectSemantics::Snapshot {
                        snapshot_id: [9; 32],
                        parents: Vec::new(),
                        tree_object_id: parent_tree,
                    }
                } else {
                    AuthenticatedObjectSemantics::Tree {
                        revisions: Vec::new(),
                    }
                };
                let references = match &semantics {
                    AuthenticatedObjectSemantics::Snapshot {
                        parents,
                        tree_object_id,
                        ..
                    } => std::iter::once(*tree_object_id)
                        .chain(parents.iter().map(|parent| parent.snapshot_object_id))
                        .collect(),
                    _ => Vec::new(),
                };
                Ok(ImportedObjectMetadata::authenticated(
                    id, kind, 1, references, semantics,
                ))
            },
            || Ok(()),
        )
        .unwrap();
        let committed = commit_applied(
            verified,
            CommitContext {
                vault,
                generation: 1,
                bootstrap_commitment: [2; 32],
                head_commitment: [5; 32],
                limits: ReplicationLimits::PHASE_1,
                observation_commitment: observation_commitment(
                    &BackendObservationFingerprint::try_new(vec![1]).unwrap(),
                ),
                operation: [3; 16],
                local_head: Some(LocalHeadBinding {
                    snapshot: SnapshotId::from_bytes([9; 32]),
                    snapshot_object: ObjectId::from_bytes([14; 32]),
                    tree_object: parent_tree,
                    head_commitment: [15; 32],
                }),
                prior_remote: None,
                state,
                registry,
            },
            SnapshotId::from_bytes([4; 32]),
            AppliedReplicatedTransition::FastForward,
            || Ok(()),
        );
        assert!(matches!(committed, Err(StoreError::RollbackDetected)));
    }

    #[test]
    fn one_chunk_object_cannot_claim_two_protected_file_positions() {
        let vault = VaultId::from_bytes([1; 16]);
        let snapshot = ObjectId::from_bytes([10; 32]);
        let tree = ObjectId::from_bytes([11; 32]);
        let manifest = ObjectId::from_bytes([12; 32]);
        let chunk = ObjectId::from_bytes([13; 32]);
        let result = verify_reachable_graph(
            context(vault),
            head(vault, snapshot, tree),
            BackendObservationFingerprint::try_new(vec![1]).unwrap(),
            |id, kind| {
                let semantics = if id == snapshot {
                    AuthenticatedObjectSemantics::Snapshot {
                        snapshot_id: [4; 32],
                        parents: Vec::new(),
                        tree_object_id: tree,
                    }
                } else if id == tree {
                    AuthenticatedObjectSemantics::Tree {
                        revisions: vec![AuthenticatedRevisionLocator {
                            file_id: [6; 16],
                            revision_id: [7; 32],
                            manifest_object_id: manifest,
                        }],
                    }
                } else if id == manifest {
                    AuthenticatedObjectSemantics::Manifest {
                        file_id: [6; 16],
                        revision_id: [7; 32],
                        chunks: vec![
                            AuthenticatedChunkReference {
                                object_id: chunk,
                                position: 0,
                            },
                            AuthenticatedChunkReference {
                                object_id: chunk,
                                position: 1,
                            },
                        ],
                    }
                } else {
                    AuthenticatedObjectSemantics::Chunk {
                        file_id: [6; 16],
                        position: 0,
                    }
                };
                let references = match &semantics {
                    AuthenticatedObjectSemantics::Snapshot { tree_object_id, .. } => {
                        vec![*tree_object_id]
                    }
                    AuthenticatedObjectSemantics::Tree { revisions } => revisions
                        .iter()
                        .map(|locator| locator.manifest_object_id)
                        .collect(),
                    AuthenticatedObjectSemantics::Manifest { chunks, .. } => {
                        chunks.iter().map(|reference| reference.object_id).collect()
                    }
                    AuthenticatedObjectSemantics::Chunk { .. } => Vec::new(),
                };
                Ok(ImportedObjectMetadata::authenticated(
                    id, kind, 1, references, semantics,
                ))
            },
            || Ok(()),
        );
        assert!(matches!(result, Err(StoreError::AuthenticationFailed)));
    }

    #[test]
    fn one_revision_identity_cannot_map_to_two_manifest_objects() {
        let vault = VaultId::from_bytes([1; 16]);
        let snapshot = ObjectId::from_bytes([20; 32]);
        let tree = ObjectId::from_bytes([21; 32]);
        let first_manifest = ObjectId::from_bytes([22; 32]);
        let second_manifest = ObjectId::from_bytes([23; 32]);
        let result = verify_reachable_graph(
            context(vault),
            head(vault, snapshot, tree),
            BackendObservationFingerprint::try_new(vec![1]).unwrap(),
            |id, kind| {
                let semantics = if id == snapshot {
                    AuthenticatedObjectSemantics::Snapshot {
                        snapshot_id: [4; 32],
                        parents: Vec::new(),
                        tree_object_id: tree,
                    }
                } else if id == tree {
                    AuthenticatedObjectSemantics::Tree {
                        revisions: vec![
                            AuthenticatedRevisionLocator {
                                file_id: [6; 16],
                                revision_id: [7; 32],
                                manifest_object_id: first_manifest,
                            },
                            AuthenticatedRevisionLocator {
                                file_id: [8; 16],
                                revision_id: [7; 32],
                                manifest_object_id: second_manifest,
                            },
                        ],
                    }
                } else {
                    AuthenticatedObjectSemantics::Manifest {
                        file_id: if id == first_manifest {
                            [6; 16]
                        } else {
                            [8; 16]
                        },
                        revision_id: [7; 32],
                        chunks: Vec::new(),
                    }
                };
                let references = match &semantics {
                    AuthenticatedObjectSemantics::Snapshot { tree_object_id, .. } => {
                        vec![*tree_object_id]
                    }
                    AuthenticatedObjectSemantics::Tree { revisions } => revisions
                        .iter()
                        .map(|locator| locator.manifest_object_id)
                        .collect(),
                    _ => Vec::new(),
                };
                Ok(ImportedObjectMetadata::authenticated(
                    id, kind, 1, references, semantics,
                ))
            },
            || Ok(()),
        );
        assert!(matches!(result, Err(StoreError::AuthenticationFailed)));
    }
}
