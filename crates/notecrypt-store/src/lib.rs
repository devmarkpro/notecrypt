//! Transactional encrypted object storage for Notecrypt.

mod availability;
mod batch;
#[cfg(feature = "benchmark-support")]
mod benchmark_support;
mod cleanup;
mod compromise;
mod device;
mod error;
mod journal;
mod key_cell;
mod layout;
mod local;
mod local_io;
mod reachability;
mod recovery;
mod replication;
mod repository;
mod rollback;
mod transaction;
mod trusted_remote;
mod trusted_state;

#[cfg(feature = "benchmark-support")]
pub use benchmark_support::{PublicationBenchmark, PublicationBenchmarkMetrics};
#[cfg(feature = "test-support")]
pub use cleanup::test_support as cleanup_test_support;
pub use cleanup::{
    ActiveWorkspace, AuthenticatedCleanupRecord, CleanupWorkspaceId, CleanupWorkspaceState,
    RegisteredWorkspace, TrustedWorkspaceAbsenceVerifier, WorkspaceAbsenceAuthority,
    WorkspaceAbsenceGuard, WorkspaceAbsenceProof,
};
pub use compromise::{
    ActivatedVaultTarget, AuthenticatedLogicalEntry, CompromiseRekeySource, PendingVaultTarget,
};
#[cfg(feature = "test-support")]
pub use device::test_support as device_test_support;
pub use device::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};
pub use error::StoreError;
#[cfg(feature = "test-support")]
pub use key_cell::test_support as revocation_test_support;
#[cfg(feature = "test-support")]
pub use local::test_support as local_test_support;
pub use local::{
    RepositoryEntry, RepositoryEntryId, RepositoryEntryKind, RepositoryListedEntry,
    RepositoryMutation, RepositoryMutationResult, RepositorySnapshot, StreamRevisionRequest,
    UnlockedVaultLease, VaultRepair, VaultRepairAction,
};
pub use reachability::{
    BackendObservationFingerprint, CommittedReachableHead, PendingRemotePublication,
    PendingUnprovableRemote, VerifiedReachableHead,
};
pub use recovery::RecoveryOutcome;
#[cfg(feature = "test-support")]
pub use replication::test_support as replication_test_support;
pub use replication::{
    CommitReplicatedSnapshot, ImportedObjectKind, ImportedObjectMetadata, QuarantineImport,
    ReplicationBudget, ReplicationCancellation, ReplicationCancellationProbe, ReplicationLease,
    ReplicationLimits,
};
pub use repository::{UnlockedVault, VaultRevocationHandle, VaultStore};
#[cfg(feature = "test-support")]
pub use rollback::test_support as rollback_test_support;
pub use transaction::PublicationGuard;
#[cfg(feature = "test-support")]
pub use transaction::test_support as transaction_test_support;
pub use transaction::{AuthenticatedHead, BoundaryMoment, TransactionBoundary};
