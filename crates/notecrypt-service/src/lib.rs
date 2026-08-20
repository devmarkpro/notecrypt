//! Runtime-neutral application orchestration for Notecrypt.

mod command;
mod error;
mod event;
mod external_files;
mod local_use_cases;
mod operation;
mod ports;
mod service;
mod session;

pub use command::{
    BackupSummary, BackupVault, Command, CreateDirectory, CreateFile, DeleteEntry, EditFile,
    EntryId, EntryKind, EntrySummaries, EntrySummary, ExportFile, ExportSummary, ImportFile,
    ListEntries, MAX_RESULT_ENTRIES, MoveEntry, MutationSummary, OpenWholeVault, OperationResult,
    RenameEntry, RevisionVersion, SnapshotVersion, SyncSummary, SyncVault, VaultStatus,
    VaultStatusRequest, WorkspaceSummary,
};
pub use error::ServiceError;
pub use event::{
    ConflictSummary, DurabilitySummary, OperationEvent, OperationPhase, Progress, ProgressUnit,
    WarningCode,
};
pub use external_files::PlatformExternalFileProvider;
pub use operation::{
    FinalSaveGuard, OperationContext, OperationHandle, OperationId, SecurityTransitionHandle,
};
pub use ports::*;
pub use service::{
    Control, MAX_COMPLETED_CAPACITY, MAX_EVENT_CAPACITY, MAX_ID_RETRIES, MAX_QUEUE_CAPACITY,
    MAX_WORKERS, OperationExecutor, OperationIdRandom, OsOperationIdRandom, PendingCompromiseRekey,
    PendingFreshnessAcknowledgement, PendingRecoveryInitialization, ServiceConfig, ServiceHandle,
    ServiceSnapshot, TrustedActivityHandle,
};
pub use session::*;
