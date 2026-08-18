//! Runtime-neutral application orchestration for Notecrypt.

mod command;
mod error;
mod event;
mod operation;
mod ports;
mod service;
mod session;

pub use command::{
    BackupSummary, BackupVault, Command, CreateDirectory, CreateFile, DeleteEntry, EditFile,
    EntrySummaries, EntrySummary, ExportFile, ExportSummary, ImportFile, ListEntries,
    MAX_RESULT_ENTRIES, MoveEntry, OpenWholeVault, OperationResult, RenameEntry, SyncSummary,
    SyncVault, WorkspaceSummary,
};
pub use error::ServiceError;
pub use event::{
    ConflictSummary, DurabilitySummary, OperationEvent, OperationPhase, Progress, ProgressUnit,
    WarningCode,
};
pub use operation::{FinalSaveGuard, OperationContext, OperationHandle, OperationId};
pub use ports::*;
pub use service::{
    Control, MAX_COMPLETED_CAPACITY, MAX_EVENT_CAPACITY, MAX_ID_RETRIES, MAX_QUEUE_CAPACITY,
    MAX_WORKERS, OperationExecutor, OperationIdRandom, OsOperationIdRandom, PendingCompromiseRekey,
    PendingFreshnessAcknowledgement, PendingRecoveryInitialization, ServiceConfig, ServiceHandle,
    ServiceSnapshot, TrustedActivityHandle,
};
pub use session::*;
