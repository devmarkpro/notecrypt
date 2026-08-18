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
request!(
    VaultStatusRequest,
    "Requests authenticated current-vault status."
);
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
    Status(VaultStatusRequest),
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
pub enum EntryKind {
    File,
    Directory,
    Tombstone,
}

/// Immutable authenticated logical entry metadata.
#[derive(PartialEq, Eq)]
pub struct EntrySummary {
    opaque_id: [u8; 16],
    parent_id: [u8; 16],
    name: zeroize::Zeroizing<String>,
    kind: EntryKind,
    revision_id: Option<[u8; 32]>,
}

impl EntrySummary {
    pub(crate) fn from_authenticated_parts(
        opaque_id: [u8; 16],
        parent_id: [u8; 16],
        name: zeroize::Zeroizing<String>,
        kind: EntryKind,
        revision_id: Option<[u8; 32]>,
    ) -> Self {
        Self {
            opaque_id,
            parent_id,
            name,
            kind,
            revision_id,
        }
    }

    pub const fn opaque_id(&self) -> &[u8; 16] {
        &self.opaque_id
    }

    pub const fn parent_id(&self) -> &[u8; 16] {
        &self.parent_id
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    pub const fn revision_id(&self) -> Option<&[u8; 32]> {
        self.revision_id.as_ref()
    }
}

impl std::fmt::Debug for EntrySummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EntrySummary")
            .field("opaque_id", &self.opaque_id)
            .field("parent_id", &self.parent_id)
            .field("name", &"<redacted>")
            .field("kind", &self.kind)
            .field("revision_id", &self.revision_id)
            .finish()
    }
}

/// Intrinsically bounded collection returned by an entry-listing operation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EntrySummaries {
    entries: Vec<EntrySummary>,
}

/// Fixed-size authenticated status for the current unlocked vault generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultStatus {
    vault_id: notecrypt_core::VaultId,
    generation: u64,
    root_entry_id: [u8; 16],
    snapshot_id: [u8; 32],
    entry_count: usize,
}

impl VaultStatus {
    pub(crate) const fn new(
        vault_id: notecrypt_core::VaultId,
        generation: u64,
        root_entry_id: [u8; 16],
        snapshot_id: [u8; 32],
        entry_count: usize,
    ) -> Self {
        Self {
            vault_id,
            generation,
            root_entry_id,
            snapshot_id,
            entry_count,
        }
    }

    pub const fn vault_id(&self) -> notecrypt_core::VaultId {
        self.vault_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn root_entry_id(&self) -> &[u8; 16] {
        &self.root_entry_id
    }

    pub const fn snapshot_id(&self) -> &[u8; 32] {
        &self.snapshot_id
    }

    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }
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
    Status(VaultStatus),
    EntryChanged(EntrySummary),
    Exported(ExportSummary),
    WorkspaceOpened(WorkspaceSummary),
    Synchronized(SyncSummary),
    BackedUp(BackupSummary),
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn entry_summaries_discard_source_vector_spare_capacity() {
        let mut source = Vec::with_capacity(1_000_000);
        source.push(EntrySummary::from_authenticated_parts(
            [7; 16],
            [8; 16],
            zeroize::Zeroizing::new("entry".to_owned()),
            EntryKind::File,
            None,
        ));

        let summaries = EntrySummaries::try_from_iter(source).unwrap();

        assert_eq!(summaries.len(), 1);
        assert!(summaries.entries.capacity() <= EntrySummaries::MAX_LEN);
    }

    #[test]
    fn entry_summary_bound_consumes_only_one_value_past_the_limit() {
        let consumed = std::cell::Cell::new(0_usize);
        let source = std::iter::from_fn(|| {
            consumed.set(consumed.get() + 1);
            Some(EntrySummary::from_authenticated_parts(
                [7; 16],
                [8; 16],
                zeroize::Zeroizing::new(String::new()),
                EntryKind::File,
                None,
            ))
        });
        assert!(matches!(
            EntrySummaries::try_from_iter(source),
            Err(crate::ServiceError::CapacityExceeded)
        ));
        assert_eq!(consumed.get(), MAX_RESULT_ENTRIES + 1);
    }
}
