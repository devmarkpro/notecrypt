/// Maximum number of entries returned by one bounded service result.
pub const MAX_RESULT_ENTRIES: usize = 4096;

macro_rules! request {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name;
    };
}

request!(ListEntries, "Requests one bounded logical entry listing.");
request!(CreateFile, "Requests creation of one logical file.");
request!(
    CreateDirectory,
    "Requests creation of one logical directory."
);
request!(ImportFile, "Requests one bounded streaming import.");
request!(ExportFile, "Requests one bounded streaming export.");
request!(EditFile, "Requests one targeted editor session.");
request!(RenameEntry, "Requests one logical entry rename.");
request!(MoveEntry, "Requests one logical entry move.");
request!(DeleteEntry, "Requests one logical entry deletion.");
request!(
    OpenWholeVault,
    "Requests one bounded whole-vault workspace."
);
request!(SyncVault, "Requests one synchronization.");
request!(BackupVault, "Requests one encrypted backup publication.");

/// One ordinary service operation.
///
/// Secret-bearing recovery, unlock, rekey, and freshness acknowledgement flows
/// intentionally use dedicated linear methods introduced by later tasks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    List(ListEntries),
    CreateFile(CreateFile),
    CreateDirectory(CreateDirectory),
    ImportFile(ImportFile),
    ExportFile(ExportFile),
    EditFile(EditFile),
    RenameEntry(RenameEntry),
    MoveEntry(MoveEntry),
    DeleteEntry(DeleteEntry),
    OpenVault(OpenWholeVault),
    Sync(SyncVault),
    Backup(BackupVault),
}

impl Command {
    pub(crate) const fn resets_inactivity(&self) -> bool {
        matches!(
            self,
            Self::CreateFile(_)
                | Self::CreateDirectory(_)
                | Self::ImportFile(_)
                | Self::EditFile(_)
                | Self::RenameEntry(_)
                | Self::MoveEntry(_)
                | Self::DeleteEntry(_)
        )
    }
}

/// Bounded opaque summary for one logical entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntrySummary {
    opaque_id: [u8; 16],
}

impl EntrySummary {
    pub const fn new(opaque_id: [u8; 16]) -> Self {
        Self { opaque_id }
    }

    pub const fn opaque_id(&self) -> &[u8; 16] {
        &self.opaque_id
    }
}

/// Intrinsically bounded collection returned by an entry-listing operation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EntrySummaries {
    entries: Vec<EntrySummary>,
}

impl EntrySummaries {
    /// Maximum number of entries in one result.
    pub const MAX_LEN: usize = MAX_RESULT_ENTRIES;

    /// Creates an empty result without allocating.
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Builds one bounded result with fallible service-owned growth.
    ///
    /// At most `MAX_LEN + 1` input values are consumed, even if the source is
    /// longer or does not report an upper bound.
    pub fn try_from_iter(
        entries: impl IntoIterator<Item = EntrySummary>,
    ) -> Result<Self, crate::ServiceError> {
        let mut source = entries.into_iter();
        let initial_capacity = source.size_hint().0.min(Self::MAX_LEN);
        let mut bounded = Vec::new();
        bounded
            .try_reserve_exact(initial_capacity)
            .map_err(|_| crate::ServiceError::AllocationFailed)?;
        for entry in &mut source {
            if bounded.len() == Self::MAX_LEN {
                return Err(crate::ServiceError::CapacityExceeded);
            }
            bounded
                .try_reserve(1)
                .map_err(|_| crate::ServiceError::AllocationFailed)?;
            bounded.push(entry);
        }
        Ok(Self { entries: bounded })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn as_slice(&self) -> &[EntrySummary] {
        &self.entries
    }

    pub fn iter(&self) -> std::slice::Iter<'_, EntrySummary> {
        self.entries.iter()
    }
}

macro_rules! fixed_summary {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name {
            opaque_id: [u8; 16],
        }

        impl $name {
            pub const fn new(opaque_id: [u8; 16]) -> Self {
                Self { opaque_id }
            }

            pub const fn opaque_id(&self) -> &[u8; 16] {
                &self.opaque_id
            }
        }
    };
}

fixed_summary!(ExportSummary, "Bounded summary of one completed export.");
fixed_summary!(WorkspaceSummary, "Bounded summary of one opened workspace.");
fixed_summary!(SyncSummary, "Bounded summary of one synchronization.");
fixed_summary!(BackupSummary, "Bounded summary of one backup publication.");

/// One terminal ordinary-operation result.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationResult {
    Entries(EntrySummaries),
    EntryChanged(EntrySummary),
    Exported(ExportSummary),
    WorkspaceOpened(WorkspaceSummary),
    Synchronized(SyncSummary),
    BackedUp(BackupSummary),
    SecurityTransitionCompleted,
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn entry_summaries_discard_source_vector_spare_capacity() {
        let mut source = Vec::with_capacity(1_000_000);
        source.push(EntrySummary::new([7; 16]));

        let summaries = EntrySummaries::try_from_iter(source).unwrap();

        assert_eq!(summaries.len(), 1);
        assert!(summaries.entries.capacity() <= EntrySummaries::MAX_LEN);
    }
}
