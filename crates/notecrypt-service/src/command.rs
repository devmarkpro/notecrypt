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
request!(EditFile, "Requests one targeted editor session.");
request!(
    OpenWholeVault,
    "Requests one bounded whole-vault workspace."
);
request!(SyncVault, "Requests one synchronization.");
request!(BackupVault, "Requests one encrypted backup publication.");

/// Opaque service-owned logical entry identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EntryId([u8; 16]);

impl EntryId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Opaque authenticated snapshot version used for optimistic mutation binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SnapshotVersion([u8; 32]);

impl SnapshotVersion {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque authenticated revision version used for optimistic file binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevisionVersion([u8; 32]);

impl RevisionVersion {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn validated_name(value: &str) -> Result<zeroize::Zeroizing<String>, crate::ServiceError> {
    if value.len() > crate::MAX_LOGICAL_COMPONENT_BYTES {
        return Err(crate::ServiceError::CapacityExceeded);
    }
    let parsed =
        notecrypt_core::EntryName::try_parse_bounded(value, crate::MAX_LOGICAL_COMPONENT_BYTES)
            .map_err(|error| match error {
                notecrypt_core::CoreError::AllocationFailed => {
                    crate::ServiceError::AllocationFailed
                }
                notecrypt_core::CoreError::CapacityExceeded => {
                    crate::ServiceError::CapacityExceeded
                }
                _ => crate::ServiceError::InvalidInput,
            })?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(parsed.as_str().len())
        .map_err(|_| crate::ServiceError::AllocationFailed)?;
    owned.push_str(parsed.as_str());
    Ok(zeroize::Zeroizing::new(owned))
}

macro_rules! legacy_constant {
    ($name:ident) => {
        #[allow(non_upper_case_globals)]
        pub const $name: $name = $name { request: None };
    };
}

struct CreateRequest {
    expected_snapshot: SnapshotVersion,
    parent: EntryId,
    name: zeroize::Zeroizing<String>,
}

/// Validated creation of one empty logical file.
pub struct CreateFile {
    request: Option<CreateRequest>,
}

impl CreateFile {
    pub fn try_new(
        expected_snapshot: SnapshotVersion,
        parent: EntryId,
        name: &str,
    ) -> Result<Self, crate::ServiceError> {
        Ok(Self {
            request: Some(CreateRequest {
                expected_snapshot,
                parent,
                name: validated_name(name)?,
            }),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<(SnapshotVersion, EntryId, zeroize::Zeroizing<String>), crate::ServiceError> {
        let request = self.request.ok_or(crate::ServiceError::InvalidInput)?;
        Ok((request.expected_snapshot, request.parent, request.name))
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some()
    }
}

impl std::fmt::Debug for CreateFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CreateFile(<redacted>)")
    }
}

legacy_constant!(CreateFile);

/// Validated creation of one logical directory.
pub struct CreateDirectory {
    request: Option<CreateRequest>,
}

impl CreateDirectory {
    pub fn try_new(
        expected_snapshot: SnapshotVersion,
        parent: EntryId,
        name: &str,
    ) -> Result<Self, crate::ServiceError> {
        Ok(Self {
            request: Some(CreateRequest {
                expected_snapshot,
                parent,
                name: validated_name(name)?,
            }),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<(SnapshotVersion, EntryId, zeroize::Zeroizing<String>), crate::ServiceError> {
        let request = self.request.ok_or(crate::ServiceError::InvalidInput)?;
        Ok((request.expected_snapshot, request.parent, request.name))
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some()
    }
}

impl std::fmt::Debug for CreateDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CreateDirectory(<redacted>)")
    }
}

legacy_constant!(CreateDirectory);

/// A bounded import from one private explicit user-selected path.
pub struct ImportFile {
    request: Option<CreateRequest>,
    selection: Option<crate::ImportSelection>,
}

impl ImportFile {
    pub fn try_new(
        expected_snapshot: SnapshotVersion,
        parent: EntryId,
        name: &str,
        source: std::path::PathBuf,
    ) -> Result<Self, crate::ServiceError> {
        Ok(Self {
            request: Some(CreateRequest {
                expected_snapshot,
                parent,
                name: validated_name(name)?,
            }),
            selection: Some(crate::ImportSelection::try_new(source)?),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<
        (
            SnapshotVersion,
            EntryId,
            zeroize::Zeroizing<String>,
            crate::ImportSelection,
        ),
        crate::ServiceError,
    > {
        let request = self.request.ok_or(crate::ServiceError::InvalidInput)?;
        let selection = self.selection.ok_or(crate::ServiceError::InvalidInput)?;
        Ok((
            request.expected_snapshot,
            request.parent,
            request.name,
            selection,
        ))
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some() && self.selection.is_some()
    }
}

impl std::fmt::Debug for ImportFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ImportFile(<redacted>)")
    }
}

#[allow(non_upper_case_globals)]
pub const ImportFile: ImportFile = ImportFile {
    request: None,
    selection: None,
};

struct ExportRequest {
    expected_snapshot: SnapshotVersion,
    entry: EntryId,
    expected_revision: RevisionVersion,
    selection: crate::ExportSelection,
}

/// Validated exact-revision export to one explicit external destination.
pub struct ExportFile {
    request: Option<ExportRequest>,
}

impl ExportFile {
    pub fn try_new(
        expected_snapshot: SnapshotVersion,
        entry: EntryId,
        expected_revision: RevisionVersion,
        destination: std::path::PathBuf,
        overwrite: crate::ExportOverwriteConfirmation,
    ) -> Result<Self, crate::ServiceError> {
        Ok(Self {
            request: Some(ExportRequest {
                expected_snapshot,
                entry,
                expected_revision,
                selection: crate::ExportSelection::try_new(destination, overwrite)?,
            }),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<
        (
            SnapshotVersion,
            EntryId,
            RevisionVersion,
            crate::ExportSelection,
        ),
        crate::ServiceError,
    > {
        let request = self.request.ok_or(crate::ServiceError::InvalidInput)?;
        Ok((
            request.expected_snapshot,
            request.entry,
            request.expected_revision,
            request.selection,
        ))
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some()
    }
}

impl std::fmt::Debug for ExportFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExportFile(<redacted>)")
    }
}

legacy_constant!(ExportFile);

struct RelocateRequest {
    expected_snapshot: SnapshotVersion,
    entry: EntryId,
    expected_parent: EntryId,
    expected_name: zeroize::Zeroizing<String>,
    expected_kind: EntryKind,
    expected_revision: Option<RevisionVersion>,
    new_parent: EntryId,
    new_name: zeroize::Zeroizing<String>,
}

/// Validated rename that retains the authenticated parent.
pub struct RenameEntry {
    request: Option<RelocateRequest>,
}

impl RenameEntry {
    pub fn try_new(
        expected_snapshot: SnapshotVersion,
        entry: EntryId,
        expected_parent: EntryId,
        expected_name: &str,
        expected_kind: EntryKind,
        expected_revision: Option<RevisionVersion>,
        new_name: &str,
    ) -> Result<Self, crate::ServiceError> {
        validate_entry_binding(expected_kind, expected_revision)?;
        Ok(Self {
            request: Some(RelocateRequest {
                expected_snapshot,
                entry,
                expected_parent,
                expected_name: validated_name(expected_name)?,
                expected_kind,
                expected_revision,
                new_parent: expected_parent,
                new_name: validated_name(new_name)?,
            }),
        })
    }

    pub(crate) fn into_parts(self) -> Result<RelocateParts, crate::ServiceError> {
        self.request
            .map(RelocateRequest::into_parts)
            .ok_or(crate::ServiceError::InvalidInput)
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some()
    }
}

impl std::fmt::Debug for RenameEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RenameEntry(<redacted>)")
    }
}

legacy_constant!(RenameEntry);

/// Validated move that retains the authenticated logical name.
pub struct MoveEntry {
    request: Option<RelocateRequest>,
}

impl MoveEntry {
    pub fn try_new(
        expected_snapshot: SnapshotVersion,
        entry: EntryId,
        expected_parent: EntryId,
        expected_name: &str,
        expected_kind: EntryKind,
        expected_revision: Option<RevisionVersion>,
        new_parent: EntryId,
    ) -> Result<Self, crate::ServiceError> {
        validate_entry_binding(expected_kind, expected_revision)?;
        let expected_name = validated_name(expected_name)?;
        let mut copied = String::new();
        copied
            .try_reserve_exact(expected_name.len())
            .map_err(|_| crate::ServiceError::AllocationFailed)?;
        copied.push_str(&expected_name);
        Ok(Self {
            request: Some(RelocateRequest {
                expected_snapshot,
                entry,
                expected_parent,
                expected_name,
                expected_kind,
                expected_revision,
                new_parent,
                new_name: zeroize::Zeroizing::new(copied),
            }),
        })
    }

    pub(crate) fn into_parts(self) -> Result<RelocateParts, crate::ServiceError> {
        self.request
            .map(RelocateRequest::into_parts)
            .ok_or(crate::ServiceError::InvalidInput)
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some()
    }
}

impl std::fmt::Debug for MoveEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MoveEntry(<redacted>)")
    }
}

legacy_constant!(MoveEntry);

pub(crate) struct RelocateParts {
    pub(crate) expected_snapshot: SnapshotVersion,
    pub(crate) entry: EntryId,
    pub(crate) expected_parent: EntryId,
    pub(crate) expected_name: zeroize::Zeroizing<String>,
    pub(crate) expected_kind: EntryKind,
    pub(crate) expected_revision: Option<RevisionVersion>,
    pub(crate) new_parent: EntryId,
    pub(crate) new_name: zeroize::Zeroizing<String>,
}

impl RelocateRequest {
    fn into_parts(self) -> RelocateParts {
        RelocateParts {
            expected_snapshot: self.expected_snapshot,
            entry: self.entry,
            expected_parent: self.expected_parent,
            expected_name: self.expected_name,
            expected_kind: self.expected_kind,
            expected_revision: self.expected_revision,
            new_parent: self.new_parent,
            new_name: self.new_name,
        }
    }
}

fn validate_entry_binding(
    kind: EntryKind,
    revision: Option<RevisionVersion>,
) -> Result<(), crate::ServiceError> {
    match (kind, revision) {
        (EntryKind::File, Some(_)) | (EntryKind::Directory, None) => Ok(()),
        _ => Err(crate::ServiceError::InvalidInput),
    }
}

enum DeleteKind {
    File(RevisionVersion),
    Directory,
}

struct DeleteRequest {
    expected_snapshot: SnapshotVersion,
    entry: EntryId,
    expected_parent: EntryId,
    expected_name: zeroize::Zeroizing<String>,
    kind: DeleteKind,
}

/// Validated deletion with exact authenticated kind and revision binding.
pub struct DeleteEntry {
    request: Option<DeleteRequest>,
}

impl DeleteEntry {
    pub fn try_file(
        expected_snapshot: SnapshotVersion,
        entry: EntryId,
        expected_parent: EntryId,
        expected_name: &str,
        expected_revision: RevisionVersion,
    ) -> Result<Self, crate::ServiceError> {
        Ok(Self {
            request: Some(DeleteRequest {
                expected_snapshot,
                entry,
                expected_parent,
                expected_name: validated_name(expected_name)?,
                kind: DeleteKind::File(expected_revision),
            }),
        })
    }

    pub fn try_directory(
        expected_snapshot: SnapshotVersion,
        entry: EntryId,
        expected_parent: EntryId,
        expected_name: &str,
    ) -> Result<Self, crate::ServiceError> {
        Ok(Self {
            request: Some(DeleteRequest {
                expected_snapshot,
                entry,
                expected_parent,
                expected_name: validated_name(expected_name)?,
                kind: DeleteKind::Directory,
            }),
        })
    }

    pub(crate) fn into_parts(self) -> Result<DeleteParts, crate::ServiceError> {
        let request = self.request.ok_or(crate::ServiceError::InvalidInput)?;
        Ok(DeleteParts {
            expected_snapshot: request.expected_snapshot,
            entry: request.entry,
            expected_parent: request.expected_parent,
            expected_name: request.expected_name,
            expected_revision: match request.kind {
                DeleteKind::File(revision) => Some(revision),
                DeleteKind::Directory => None,
            },
        })
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.request.is_some()
    }
}

impl std::fmt::Debug for DeleteEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeleteEntry(<redacted>)")
    }
}

legacy_constant!(DeleteEntry);

pub(crate) struct DeleteParts {
    pub(crate) expected_snapshot: SnapshotVersion,
    pub(crate) entry: EntryId,
    pub(crate) expected_parent: EntryId,
    pub(crate) expected_name: zeroize::Zeroizing<String>,
    pub(crate) expected_revision: Option<RevisionVersion>,
}

/// One ordinary service operation.
///
/// Secret-bearing recovery, unlock, rekey, and freshness acknowledgement flows
/// intentionally use dedicated linear methods introduced by later tasks.
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

impl std::fmt::Debug for Command {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::List(_) => "Command::List",
            Self::Status(_) => "Command::Status",
            Self::CreateFile(_) => "Command::CreateFile(<redacted>)",
            Self::CreateDirectory(_) => "Command::CreateDirectory(<redacted>)",
            Self::ImportFile(_) => "Command::ImportFile(<redacted>)",
            Self::ExportFile(_) => "Command::ExportFile(<redacted>)",
            Self::EditFile(_) => "Command::EditFile",
            Self::RenameEntry(_) => "Command::RenameEntry(<redacted>)",
            Self::MoveEntry(_) => "Command::MoveEntry(<redacted>)",
            Self::DeleteEntry(_) => "Command::DeleteEntry(<redacted>)",
            Self::OpenVault(_) => "Command::OpenVault",
            Self::Sync(_) => "Command::Sync",
            Self::Backup(_) => "Command::Backup",
        })
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

/// Bounded result of one durably committed local mutation.
#[derive(PartialEq, Eq)]
pub struct MutationSummary {
    entry_id: EntryId,
    parent_id: EntryId,
    snapshot: SnapshotVersion,
    revision: Option<RevisionVersion>,
    name: zeroize::Zeroizing<String>,
    kind: EntryKind,
}

impl MutationSummary {
    pub(crate) fn new(
        entry_id: EntryId,
        parent_id: EntryId,
        snapshot: SnapshotVersion,
        revision: Option<RevisionVersion>,
        name: zeroize::Zeroizing<String>,
        kind: EntryKind,
    ) -> Self {
        Self {
            entry_id,
            parent_id,
            snapshot,
            revision,
            name,
            kind,
        }
    }

    pub const fn entry_id(&self) -> EntryId {
        self.entry_id
    }

    pub const fn parent_id(&self) -> EntryId {
        self.parent_id
    }

    pub const fn snapshot(&self) -> SnapshotVersion {
        self.snapshot
    }

    pub const fn revision(&self) -> Option<RevisionVersion> {
        self.revision
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub const fn kind(&self) -> EntryKind {
        self.kind
    }
}

impl std::fmt::Debug for MutationSummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MutationSummary")
            .field("entry_id", &self.entry_id)
            .field("parent_id", &self.parent_id)
            .field("snapshot", &self.snapshot)
            .field("revision", &self.revision)
            .field("name", &"<redacted>")
            .field("kind", &self.kind)
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
    EntryChanged(MutationSummary),
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
