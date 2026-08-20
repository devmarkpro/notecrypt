use crate::ServiceError;

/// One bounded phase in an ordinary operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationPhase {
    Preparing,
    Reading,
    Encrypting,
    Publishing,
    CleaningUp,
}

/// Replaceable bounded progress for one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    unit: ProgressUnit,
    completed: u64,
    total: Option<u64>,
}

/// Unit carried by one coalesced progress dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressUnit {
    Items,
    Bytes,
}

impl Progress {
    pub fn new(
        unit: ProgressUnit,
        completed: u64,
        total: Option<u64>,
    ) -> Result<Self, ServiceError> {
        if total.is_some_and(|total| completed > total) {
            return Err(ServiceError::InvalidProgress);
        }
        Ok(Self {
            unit,
            completed,
            total,
        })
    }

    pub fn items(completed: u64, total: Option<u64>) -> Result<Self, ServiceError> {
        Self::new(ProgressUnit::Items, completed, total)
    }

    pub fn bytes(completed: u64, total: Option<u64>) -> Result<Self, ServiceError> {
        Self::new(ProgressUnit::Bytes, completed, total)
    }

    pub const fn unit(&self) -> ProgressUnit {
        self.unit
    }

    pub const fn completed(&self) -> u64 {
        self.completed
    }

    pub const fn total(&self) -> Option<u64> {
        self.total
    }
}

/// Stable warning categories with no arbitrary backend or plaintext detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarningCode {
    CleanupRequired,
    DurabilityPending,
    FreshnessUnprovable,
}

/// Opaque bounded conflict summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConflictSummary([u8; 16]);

impl ConflictSummary {
    pub const fn new(opaque_id: [u8; 16]) -> Self {
        Self(opaque_id)
    }

    pub const fn opaque_id(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Opaque bounded durability summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurabilitySummary([u8; 16]);

impl DurabilitySummary {
    pub const fn new(opaque_id: [u8; 16]) -> Self {
        Self(opaque_id)
    }

    pub const fn opaque_id(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Ordered event emitted by one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationEvent {
    Started,
    PhaseChanged(OperationPhase),
    Progress(Progress),
    Warning(WarningCode),
    Conflict(ConflictSummary),
    RevisionDurable(DurabilitySummary),
    SaveDetected,
    SyncPublished,
    CleanupRequired,
    Cancelled,
    Completed,
    Failed(ServiceError),
}

impl OperationEvent {
    pub(crate) const fn replaceable(&self) -> bool {
        matches!(self, Self::Progress(_))
    }

    pub(crate) const fn terminal(&self) -> bool {
        matches!(self, Self::Cancelled | Self::Completed | Self::Failed(_))
    }
}
