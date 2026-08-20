//! Handle-relative filesystem capabilities for Notecrypt storage.

#[cfg(windows)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, ExitStatus, Stdio};

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::ambient_authority;
#[cfg(not(windows))]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, File, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, PermissionsExt};
use cap_std::time::SystemTime;

const MAX_CAPABILITY_PATH_BYTES: usize = 32 * 1024;
const MAX_CAPABILITY_COMPONENTS: usize = 256;
const MAX_CAPABILITY_IDENTITIES: usize = MAX_CAPABILITY_COMPONENTS + 1;

#[cfg(feature = "test-support")]
thread_local! {
    static WORKSPACE_PUBLICATION_FAULT: std::cell::Cell<Option<WorkspacePublicationFault>> =
        const { std::cell::Cell::new(None) };
    static WORKSPACE_CLEANUP_FAULT: std::cell::Cell<Option<WorkspaceCleanupFault>> =
        const { std::cell::Cell::new(None) };
    static WORKSPACE_DIRECTORY_FAULT: std::cell::Cell<Option<WorkspaceDirectoryFault>> =
        const { std::cell::Cell::new(None) };
    static WORKSPACE_FILE_SYNC_FAULT: std::cell::Cell<Option<WorkspaceFileSyncFault>> =
        const { std::cell::Cell::new(None) };
    static WORKSPACE_PARENT_SYNC_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    #[cfg(windows)]
    static PRIVATE_FILE_SYNC_ACCESS: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    #[cfg(windows)]
    static RENAME_TARGET_ACQUISITION_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static PRIVATE_TREE_FILE_CLEANUP_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    #[cfg(all(windows, feature = "test-support"))]
    static TRUSTED_EXECUTABLE_ACL_DIAGNOSTIC:
        std::cell::Cell<Option<trusted_executable_test_support::AclDiagnostic>> =
        const { std::cell::Cell::new(None) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static PROCESS_GROUP_SCAN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static PROCESS_GROUP_SCAN_ENTRY_BUDGET: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static PROCESS_GROUP_SCAN_WALL_DELAY: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    static PROCESS_GROUP_SCAN_WALL_BUDGET: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
    #[cfg(target_vendor = "apple")]
    static PROCESS_GROUP_PROBE_BUDGET: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy)]
pub enum WorkspacePublicationFault {
    #[cfg(unix)]
    PublishedWithRetainedStage,
    #[cfg(unix)]
    PublishedThenDestinationAbsent,
    #[cfg(windows)]
    PublishedAfterMove,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceCleanupFault {
    TreeRemoveBeforeEffect,
    TreeAbsenceReadbackAfterEffect,
    OwnerUnlinkBeforeEffect,
    StagingUnlinkBeforeEffect,
    StagingNamedReopen,
    StagingAbsenceReadbackAfterEffect,
    DirectorySyncAfterEffect,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDirectoryFault {
    MountBoundary,
    ParentSync,
    PrivateDirectoryAfterCreate,
    PrivateFileAfterCreate,
    #[cfg(windows)]
    RenameTargetIdentityMismatch,
    #[cfg(windows)]
    RenameTargetAfterCreate,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceFileSyncFault {
    BeforeEffect,
    AfterEffect,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum ProcessWaitFailureStage {
    LeaderWaitId,
    GroupIdentity,
    GroupEnumerationOpen,
    GroupEnumerationNext,
    MemberStatOpen,
    MemberStatRead,
    MemberStatParse,
    GroupScanDeadline,
    LeaderReap,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum ProcessWaitFailureReason {
    Io,
    InvalidGroupIdentity,
    CpuDeadline,
    WallDeadline,
    CpuAndWallDeadline,
    CpuDeadlineOverflow,
    WallDeadlineOverflow,
    EnumerationOverflow,
    EnumerationResultSize,
    EnumerationEntryBudget,
    EnumerationEntryBound,
    StatReadAttemptBound,
    StatReadInterruptionBound,
    StatReadOverflow,
    InvalidUtf8,
    MissingPid,
    InvalidPid,
    MismatchedPid,
    MissingCommand,
    MissingState,
    InvalidState,
    UnknownState,
    MissingParent,
    InvalidParent,
    MissingGroup,
    InvalidGroup,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ProcessWaitFailureDiagnostic {
    pub stage: ProcessWaitFailureStage,
    pub reason: ProcessWaitFailureReason,
    pub io_kind: io::ErrorKind,
    pub raw_os_error: Option<i32>,
}

#[cfg(all(feature = "test-support", unix))]
#[derive(Default)]
struct ProcessWaitFailureSlot(Option<ProcessWaitFailureDiagnostic>);

#[cfg(all(not(feature = "test-support"), unix))]
#[derive(Default)]
struct ProcessWaitFailureSlot;

#[cfg(unix)]
fn process_wait_failure_slot() -> ProcessWaitFailureSlot {
    #[cfg(feature = "test-support")]
    {
        ProcessWaitFailureSlot::default()
    }
    #[cfg(not(feature = "test-support"))]
    {
        ProcessWaitFailureSlot
    }
}

#[cfg(all(feature = "test-support", unix))]
impl ProcessWaitFailureSlot {
    fn clear(&mut self) {
        self.0 = None;
    }

    fn take(&mut self) -> Option<ProcessWaitFailureDiagnostic> {
        self.0.take()
    }
}

#[cfg(all(feature = "test-support", unix))]
fn record_process_wait_failure(
    slot: &mut ProcessWaitFailureSlot,
    stage: ProcessWaitFailureStage,
    reason: ProcessWaitFailureReason,
    error: &io::Error,
) {
    if slot.0.is_none() {
        slot.0 = Some(ProcessWaitFailureDiagnostic {
            stage,
            reason,
            io_kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        });
    }
}

#[cfg(unix)]
macro_rules! process_wait_error {
    ($slot:expr, $stage:ident, $reason:ident, $kind:expr, $message:literal) => {{
        let error = io::Error::new($kind, $message);
        #[cfg(feature = "test-support")]
        record_process_wait_failure(
            $slot,
            ProcessWaitFailureStage::$stage,
            ProcessWaitFailureReason::$reason,
            &error,
        );
        error
    }};
}

#[cfg(unix)]
macro_rules! process_wait_io_error {
    ($slot:expr, $stage:ident, $error:expr) => {{
        let error = $error;
        #[cfg(feature = "test-support")]
        record_process_wait_failure(
            $slot,
            ProcessWaitFailureStage::$stage,
            ProcessWaitFailureReason::Io,
            &error,
        );
        error
    }};
}

#[cfg(any(target_os = "linux", target_os = "android"))]
macro_rules! process_wait_deadline_error {
    ($slot:expr, $stage:ident, $state:expr, $message:literal) => {{
        let state = $state;
        let error = io::Error::new(io::ErrorKind::TimedOut, $message);
        #[cfg(feature = "test-support")]
        record_process_wait_failure(
            $slot,
            ProcessWaitFailureStage::$stage,
            match state {
                ProcessScanDeadlineState::Cpu => ProcessWaitFailureReason::CpuDeadline,
                ProcessScanDeadlineState::Wall => ProcessWaitFailureReason::WallDeadline,
                ProcessScanDeadlineState::CpuAndWall => {
                    ProcessWaitFailureReason::CpuAndWallDeadline
                }
                ProcessScanDeadlineState::Active => unreachable!("a wait deadline expired"),
            },
            &error,
        );
        error
    }};
}

#[cfg(any(target_os = "linux", target_os = "android"))]
macro_rules! process_wait_parse_error {
    ($slot:expr, $reason:ident, $message:literal) => {
        process_wait_error!(
            $slot,
            MemberStatParse,
            $reason,
            io::ErrorKind::InvalidData,
            $message
        )
    };
}

#[cfg(feature = "test-support")]
fn take_workspace_publication_fault() -> Option<WorkspacePublicationFault> {
    WORKSPACE_PUBLICATION_FAULT.take()
}

#[cfg(feature = "test-support")]
fn take_workspace_cleanup_fault(expected: WorkspaceCleanupFault) -> bool {
    WORKSPACE_CLEANUP_FAULT.with(|fault| {
        if fault.get() == Some(expected) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(feature = "test-support")]
fn take_workspace_directory_fault(expected: WorkspaceDirectoryFault) -> bool {
    WORKSPACE_DIRECTORY_FAULT.with(|fault| {
        if fault.get() == Some(expected) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(feature = "test-support")]
fn take_workspace_file_sync_fault(expected: WorkspaceFileSyncFault) -> bool {
    WORKSPACE_FILE_SYNC_FAULT.with(|fault| {
        if fault.get() == Some(expected) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(all(feature = "test-support", windows))]
fn run_rename_target_acquisition_hook() {
    if let Some(hook) = RENAME_TARGET_ACQUISITION_HOOK.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

#[cfg(feature = "test-support")]
fn run_private_tree_file_cleanup_hook() {
    if let Some(hook) = PRIVATE_TREE_FILE_CLEANUP_HOOK.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod workspace_test_support {
    pub use super::{
        WorkspaceCleanupFault, WorkspaceDirectoryFault, WorkspaceFileSyncFault,
        WorkspacePublicationFault,
    };

    pub fn inject_publication_fault(fault: WorkspacePublicationFault) {
        super::WORKSPACE_PUBLICATION_FAULT.set(Some(fault));
    }

    pub fn inject_cleanup_fault(fault: WorkspaceCleanupFault) {
        super::WORKSPACE_CLEANUP_FAULT.set(Some(fault));
    }

    pub fn inject_directory_fault(fault: WorkspaceDirectoryFault) {
        super::WORKSPACE_DIRECTORY_FAULT.set(Some(fault));
    }

    pub fn inject_file_sync_fault(fault: WorkspaceFileSyncFault) {
        super::WORKSPACE_FILE_SYNC_FAULT.set(Some(fault));
    }

    #[cfg(windows)]
    pub fn inject_rename_target_acquisition_hook(hook: impl FnOnce() + 'static) {
        super::RENAME_TARGET_ACQUISITION_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
    }

    pub fn inject_private_tree_file_cleanup_hook(hook: impl FnOnce() + 'static) {
        super::PRIVATE_TREE_FILE_CLEANUP_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
    }

    pub fn take_parent_sync_count() -> usize {
        super::WORKSPACE_PARENT_SYNC_COUNT.with(|count| count.replace(0))
    }

    #[cfg(windows)]
    pub fn make_directory_inheritable_for_test(
        parent: &super::Directory,
        name: &super::PhysicalComponent,
        expected: &super::Directory,
    ) -> std::io::Result<()> {
        super::windows::make_directory_inheritable_for_test(
            &parent.inner,
            name.as_path(),
            &expected.inner,
        )
    }

    #[cfg(windows)]
    pub fn make_file_permissive_for_test(
        parent: &super::Directory,
        name: &super::PhysicalComponent,
        expected: &super::FileCapability,
    ) -> std::io::Result<()> {
        super::windows::make_file_permissive_for_test(&parent.inner, name.as_path(), expected)
    }

    #[cfg(windows)]
    pub fn directory_is_mutation_local_durable(
        directory: &super::Directory,
    ) -> std::io::Result<bool> {
        super::windows::directory_is_write_through(&directory.inner)
    }

    #[cfg(windows)]
    pub fn file_is_mutation_local_durable(file: &super::FileCapability) -> std::io::Result<bool> {
        super::windows::file_is_write_through(&file.inner)
    }

    #[cfg(windows)]
    pub fn rename_target_access(directory: &super::Directory) -> std::io::Result<u32> {
        super::windows::rename_target_access(&directory.rename_target)
    }

    #[cfg(windows)]
    pub fn directory_primary_access(directory: &super::Directory) -> std::io::Result<u32> {
        super::windows::directory_primary_access(&directory.inner)
    }

    #[cfg(windows)]
    pub fn retained_directory_access() -> u32 {
        super::windows::retained_directory_access()
    }

    #[cfg(windows)]
    pub fn file_access(file: &super::FileCapability) -> std::io::Result<u32> {
        super::windows::file_access(&file.inner)
    }

    #[cfg(windows)]
    pub fn private_file_access() -> u32 {
        super::windows::private_file_access()
    }

    #[cfg(windows)]
    pub fn private_file_sync_access() -> u32 {
        super::windows::private_file_sync_access()
    }

    #[cfg(windows)]
    pub fn take_observed_private_file_sync_access() -> Option<u32> {
        super::PRIVATE_FILE_SYNC_ACCESS.take()
    }

    #[cfg(windows)]
    pub fn file_is_private(file: &super::FileCapability) -> bool {
        super::verify_private_file(file).is_ok()
    }

    #[cfg(windows)]
    pub fn count_directory_entries(directory: &super::Directory) -> std::io::Result<usize> {
        let entries = directory.inner.read_dir(".").map_err(|error| {
            super::windows::operation_stage_error("diagnostic directory enumeration open", error)
        })?;
        let mut count = 0_usize;
        for entry in entries {
            entry.map_err(|error| {
                super::windows::operation_stage_error(
                    "diagnostic directory enumeration next",
                    error,
                )
            })?;
            count = count
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("diagnostic entry count overflowed"))?;
        }
        Ok(count)
    }

    #[cfg(windows)]
    pub fn disposition_empty_tree_production_lifecycle(
        parent: &super::Directory,
        original: &super::Directory,
        name: &super::PhysicalComponent,
    ) -> std::io::Result<()> {
        let initial =
            super::windows::open_private_directory_for_cleanup(&parent.inner, name.as_path())
                .map_err(|error| {
                    super::windows::operation_stage_error(
                        "diagnostic lifecycle initial validation open",
                        error,
                    )
                })?;
        if super::identity(&initial)? != original.final_identity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "diagnostic lifecycle initial identity changed",
            ));
        }
        drop(initial);

        if count_directory_entries(original)? != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "diagnostic lifecycle fixture is not empty",
            ));
        }

        let cleanup =
            super::windows::open_private_directory_for_cleanup(&parent.inner, name.as_path())
                .map_err(|error| {
                    super::windows::operation_stage_error(
                        "diagnostic lifecycle final cleanup open",
                        error,
                    )
                })?;
        if super::identity(&cleanup)? != original.final_identity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "diagnostic lifecycle final identity changed",
            ));
        }
        super::windows::delete_exact_directory(&cleanup).map_err(|error| {
            super::windows::operation_stage_error("diagnostic lifecycle exact disposition", error)
        })?;
        drop(cleanup);
        Ok(())
    }

    #[cfg(windows)]
    pub fn rename_with_primary_target(
        source: &super::FileCapability,
        destination: &super::Directory,
        name: &std::path::Path,
        replace: bool,
    ) -> std::io::Result<()> {
        super::windows::rename_with_primary_target(source, &destination.inner, name, replace)
    }

    #[cfg(windows)]
    pub fn rename_with_retained_target(
        source: &super::FileCapability,
        destination: &super::Directory,
        name: &std::path::Path,
        replace: bool,
    ) -> std::io::Result<()> {
        super::windows::rename_by_handle(source, &destination.rename_target, name, replace)
    }

    #[cfg(windows)]
    pub fn rename_directory_with_retained_target(
        source_parent: &super::Directory,
        source_name: &super::PhysicalComponent,
        expected_source: &super::Directory,
        destination: &super::Directory,
        name: &std::path::Path,
        replace: bool,
    ) -> std::io::Result<()> {
        super::windows::rename_directory_with_retained_target(
            source_parent,
            source_name.as_path(),
            expected_source,
            destination,
            name,
            replace,
        )
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn take_process_group_scan_count() -> usize {
        super::PROCESS_GROUP_SCAN_COUNT.with(|count| count.replace(0))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn inject_process_group_scan_entry_budget(budget: usize) {
        super::PROCESS_GROUP_SCAN_ENTRY_BUDGET.set(Some(budget));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn inject_process_group_scan_wall_delay(delay: std::time::Duration) {
        super::PROCESS_GROUP_SCAN_WALL_DELAY.set(Some(delay));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn inject_process_group_scan_wall_budget(budget: std::time::Duration) {
        super::PROCESS_GROUP_SCAN_WALL_BUDGET.set(Some(budget));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn parse_process_group_stat(stat: &[u8], pid: i32) -> std::io::Result<i32> {
        super::parse_linux_process_group(stat, pid)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn process_group_stat_is_live(stat: &[u8], pid: i32) -> std::io::Result<bool> {
        let mut diagnostic = super::process_wait_failure_slot();
        super::parse_linux_process_identity(stat, pid, &mut diagnostic)
            .map(|identity| identity.live)
    }

    #[cfg(target_vendor = "apple")]
    pub fn inject_process_group_probe_budget(budget: usize) {
        super::PROCESS_GROUP_PROBE_BUDGET.set(Some(budget));
    }
}

#[cfg(all(feature = "test-support", windows))]
#[doc(hidden)]
pub mod trusted_executable_test_support {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AclChainStage {
        WindowsRoot,
        System32OrInstall,
        Executable,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SidClass {
        System,
        Administrators,
        TrustedInstaller,
        CreatorOwner,
        Users,
        AuthenticatedUsers,
        World,
        AppPackages,
        Other,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AclDiagnostic {
        pub stage: AclChainStage,
        pub ace_type: u8,
        pub ace_flags: u8,
        pub mask: u32,
        pub sid: SidClass,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TestAclPrincipal {
        System,
        CreatorOwner,
        Users,
    }

    pub fn take_acl_diagnostic() -> Option<AclDiagnostic> {
        super::TRUSTED_EXECUTABLE_ACL_DIAGNOSTIC.take()
    }

    pub fn verify_allowed_ace_for_current_object(
        principal: TestAclPrincipal,
        ace_flags: u32,
        mask: u32,
        directory: bool,
    ) -> std::io::Result<()> {
        super::windows::verify_test_allowed_ace(principal, ace_flags, mask, directory)
    }

    pub fn verify_unsupported_ace_fails_closed(ace_type: u8, ace_flags: u8) -> std::io::Result<()> {
        super::windows::verify_test_ace_disposition(ace_type, ace_flags)
    }

    pub const fn object_container_inherit_only_flags() -> u32 {
        windows_sys::Win32::Security::OBJECT_INHERIT_ACE
            | windows_sys::Win32::Security::CONTAINER_INHERIT_ACE
            | windows_sys::Win32::Security::INHERIT_ONLY_ACE
    }

    pub const fn generic_all_access() -> u32 {
        windows_sys::Win32::Foundation::GENERIC_ALL
    }

    pub const fn file_write_data_access() -> u32 {
        windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA
    }
}

fn allocation_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, message)
}

mod external;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod external_test_support {
    use crate::{ExportTransaction, ExternalFileSet};

    #[cfg(windows)]
    pub use crate::external::{ExportPayloadAttestation, StableImportObservation};

    pub fn inject_cleanup_failures(transaction: &mut ExportTransaction, failures: usize) {
        transaction.inject_cleanup_failures(failures);
    }

    pub fn inject_publish_panic(transaction: &mut ExportTransaction) {
        transaction.inject_publish_panic();
    }

    pub fn inject_final_staging_sync_failure(transaction: &mut ExportTransaction) {
        transaction.inject_final_staging_sync_failure();
    }

    pub fn cleanup_authority_storage_is_preallocated(transaction: &ExportTransaction) -> bool {
        transaction.cleanup_authority_storage_is_preallocated()
    }

    pub fn pending_cleanup_authority_storage_is_preallocated(
        pending: &crate::ExportCleanupPending,
    ) -> bool {
        pending.cleanup_authority_storage_is_preallocated()
    }

    pub fn inject_begin_failure(files: &ExternalFileSet, cleanup_failures: usize) {
        files.inject_begin_failure(cleanup_failures);
    }

    #[cfg(windows)]
    pub fn export_payload_attestation(
        transaction: &ExportTransaction,
    ) -> std::io::Result<ExportPayloadAttestation> {
        transaction.payload_attestation()
    }

    #[cfg(windows)]
    pub fn stable_import_observation(
        import: &crate::StableImport,
    ) -> std::io::Result<StableImportObservation> {
        import.observation()
    }

    #[cfg(windows)]
    pub fn stable_import_validator_with_current_stamp(
        import: &crate::StableImport,
    ) -> std::io::Result<crate::StableImportValidator> {
        import.validator_with_current_stamp()
    }
}

pub use external::{
    ExportBeginError, ExportCleanupPending, ExportOverwrite, ExportPublicationEffect,
    ExportPublishAttemptError, ExportPublishError, ExportTransaction, ExternalFileSet,
    StableImport, StableImportValidator,
};
#[cfg(feature = "test-support")]
pub use external::{ExportCleanupDiagnostic, ExportCleanupStage};

/// A validated single physical name accepted by capability-relative operations.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalComponent(Box<str>);

impl PhysicalComponent {
    pub fn try_new(value: &str) -> io::Result<Self> {
        let portable = value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        });
        let base = value.split('.').next().unwrap_or_default();
        let numbered_device = |prefix: &str| {
            base.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        };
        let reserved = matches!(base, "con" | "prn" | "aux" | "nul")
            || numbered_device("com")
            || numbered_device("lpt");
        if value.is_empty()
            || value.len() > 255
            || matches!(value, "." | "..")
            || value.ends_with('.')
            || !portable
            || reserved
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid physical component",
            ));
        }
        Ok(Self(value.into()))
    }

    fn as_path(&self) -> &Path {
        Path::new(&*self.0)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum InitialFileAbsence {
    RejectBeforeEffect,
    ReconcileAfterEffect,
}

/// Observable state after an attempted no-replace workspace publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspacePublicationEffect {
    NotPublished,
    PublishedUnverified,
}

/// A failed workspace publication together with its conservative visibility state.
pub struct WorkspacePublishAttemptError {
    primary: io::Error,
    effect: WorkspacePublicationEffect,
}

impl WorkspacePublishAttemptError {
    pub const fn effect(&self) -> WorkspacePublicationEffect {
        self.effect
    }

    pub fn error(&self) -> &io::Error {
        &self.primary
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub directory_sync: bool,
    pub atomic_replace: bool,
    pub no_replace_publication: bool,
}

/// An opened directory handle from which all later names are resolved.
pub struct Directory {
    inner: Dir,
    identity_chain: Vec<FileIdentity>,
    #[cfg(windows)]
    rename_target: windows::RenameTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactFileRemovalStage {
    NamedOpen,
    Identity,
    #[cfg(windows)]
    CleanupOpen,
    Disposition,
    Absence,
}

pub(crate) struct ExactFileRemovalFailure {
    pub(crate) stage: ExactFileRemovalStage,
    pub(crate) error: io::Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactDirectoryRemovalStage {
    #[cfg(windows)]
    CleanupOpen,
    Identity,
    Disposition,
    Absence,
}

pub(crate) struct ExactDirectoryRemovalFailure {
    pub(crate) stage: ExactDirectoryRemovalStage,
    pub(crate) error: io::Error,
}

fn new_directory(
    inner: Dir,
    identity_chain: Vec<FileIdentity>,
    #[cfg(windows)] rename_target: windows::RenameTarget,
) -> Directory {
    Directory {
        inner,
        identity_chain,
        #[cfg(windows)]
        rename_target,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    identity: FileIdentity,
    length: u64,
    modified: SystemTime,
    change: Option<FileChangeStamp>,
}

/// Exact opened executable identity after platform trust attestation.
pub struct TrustedExecutable {
    _private: (),
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(windows)]
    file: std::fs::File,
    #[cfg(unix)]
    identity: FileIdentity,
    #[cfg(windows)]
    identity: FileIdentity,
    #[cfg(unix)]
    production_trusted: bool,
    #[cfg(windows)]
    production_trusted: bool,
}

impl TrustedExecutable {
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let (file, identity) = open_unix_executable(path, true)?;
            Ok(Self {
                _private: (),
                file,
                identity,
                production_trusted: true,
            })
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                let (file, identity) = windows::open_trusted_executable(path, true)?;
                Ok(Self {
                    _private: (),
                    file,
                    identity,
                    production_trusted: true,
                })
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "trusted executable attestation is unavailable",
                ))
            }
        }
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn open_test_only(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let (file, identity) = open_unix_executable(path, false)?;
            Ok(Self {
                _private: (),
                file,
                identity,
                production_trusted: false,
            })
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                let (file, identity) = windows::open_trusted_executable(path, false)?;
                Ok(Self {
                    _private: (),
                    file,
                    identity,
                    production_trusted: false,
                })
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "test executable attestation is unavailable",
                ))
            }
        }
    }

    pub fn matches_named(&self, path: &Path) -> io::Result<bool> {
        #[cfg(unix)]
        {
            let (named, identity) = open_unix_executable(path, self.production_trusted)?;
            let retained = file_identity_from_metadata(&self.file.metadata()?);
            Ok(identity == self.identity
                && retained == self.identity
                && named.metadata()?.is_file())
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                let (named, identity) =
                    windows::open_trusted_executable(path, self.production_trusted)?;
                Ok(identity == self.identity
                    && windows::file_identity(&self.file)? == self.identity
                    && named.metadata()?.is_file())
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Ok(false)
            }
        }
    }

    pub fn try_clone_if_matches_named(&self, path: &Path) -> io::Result<Option<Self>> {
        #[cfg(unix)]
        {
            let (named, identity) = open_unix_executable(path, self.production_trusted)?;
            let retained = file_identity_from_metadata(&self.file.metadata()?);
            if identity != self.identity
                || retained != self.identity
                || !named.metadata()?.is_file()
            {
                return Ok(None);
            }
            Ok(Some(Self {
                _private: (),
                file: self.file.try_clone()?,
                identity: self.identity,
                production_trusted: self.production_trusted,
            }))
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                let (named, identity) =
                    windows::open_trusted_executable(path, self.production_trusted)?;
                if identity != self.identity || windows::file_identity(&self.file)? != self.identity
                {
                    return Ok(None);
                }
                Ok(Some(Self {
                    _private: (),
                    file: named,
                    identity,
                    production_trusted: self.production_trusted,
                }))
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Ok(None)
            }
        }
    }
}

#[cfg(windows)]
pub fn windows_system_editor_candidate(name: &OsStr) -> io::Result<PathBuf> {
    windows::system_editor_candidate(name)
}

#[cfg(unix)]
pub struct SupervisedProcess {
    child: std::process::Child,
    pid: rustix::process::Pid,
    observed: Option<ExitStatus>,
    wait_failure: ProcessWaitFailureSlot,
}

#[cfg(windows)]
pub struct SupervisedProcess {
    inner: windows::SupervisedProcess,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisedProcessState {
    Running,
    LeaderExitedTreeActive,
    Exited(Option<i32>),
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedProcessPoll {
    Running,
    NeedsGroupProof(i32),
}

#[cfg(windows)]
impl SupervisedProcess {
    pub fn spawn(
        executable: &std::ffi::OsStr,
        arguments: &[OsString],
        workspace_file: &Path,
        owned_tree: bool,
    ) -> io::Result<Self> {
        windows::SupervisedProcess::spawn(executable, arguments, workspace_file, owned_tree)
            .map(|inner| Self { inner })
    }

    pub fn poll(&mut self, owned_tree: bool) -> io::Result<SupervisedProcessState> {
        self.inner.poll(owned_tree)
    }

    pub fn leader_exited_unreaped(&self) -> io::Result<bool> {
        self.inner.leader_exited()
    }

    pub fn request_stop(&self) -> io::Result<()> {
        self.inner.request_stop()
    }

    pub fn force_stop(&self) -> io::Result<()> {
        self.inner.force_stop()
    }
}

#[cfg(unix)]
impl SupervisedProcess {
    pub fn spawn(
        executable: &std::ffi::OsStr,
        arguments: &[OsString],
        workspace_file: &Path,
        _owned_tree: bool,
    ) -> io::Result<Self> {
        use std::os::unix::process::CommandExt as _;

        let mut command = Command::new(executable);
        command
            .args(arguments)
            .arg(workspace_file)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .process_group(0);
        let child = command.spawn()?;
        let raw = i32::try_from(child.id())
            .map_err(|_| io::Error::other("editor process identifier overflowed"))?;
        let pid = rustix::process::Pid::from_raw(raw)
            .ok_or_else(|| io::Error::other("editor process identifier is invalid"))?;
        Ok(Self {
            child,
            pid,
            observed: None,
            wait_failure: process_wait_failure_slot(),
        })
    }

    pub fn poll(&mut self, owned_tree: bool) -> io::Result<SupervisedProcessState> {
        #[cfg(feature = "test-support")]
        self.wait_failure.clear();
        if !owned_tree {
            let status = rustix::process::waitid(
                rustix::process::WaitId::Pid(self.pid),
                rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT
                    | rustix::process::WaitIdOptions::EXITED,
            )
            .map_err(|source| {
                process_wait_io_error!(
                    &mut self.wait_failure,
                    LeaderWaitId,
                    io::Error::from(source)
                )
            })?;
            if status.is_none() {
                return Ok(SupervisedProcessState::Running);
            }
            #[cfg(feature = "test-support")]
            let status = self.child.wait().map_err(|error| {
                process_wait_io_error!(&mut self.wait_failure, LeaderReap, error)
            })?;
            #[cfg(not(feature = "test-support"))]
            let status = self.child.wait()?;
            return Ok(SupervisedProcessState::Exited(status.code()));
        }
        match self.prepare_owned_poll()? {
            OwnedProcessPoll::Running => Ok(SupervisedProcessState::Running),
            OwnedProcessPoll::NeedsGroupProof(group) => {
                let pid = rustix::process::Pid::from_raw(group).ok_or_else(|| {
                    let error = io::Error::other("process group identifier is invalid");
                    #[cfg(feature = "test-support")]
                    record_process_wait_failure(
                        &mut self.wait_failure,
                        ProcessWaitFailureStage::GroupIdentity,
                        ProcessWaitFailureReason::InvalidGroupIdentity,
                        &error,
                    );
                    error
                })?;
                let has_other_members =
                    process_group_has_other_members(pid, &mut self.wait_failure)?;
                self.finish_owned_poll(has_other_members)
            }
        }
    }

    pub fn prepare_owned_poll(&mut self) -> io::Result<OwnedProcessPoll> {
        #[cfg(feature = "test-support")]
        self.wait_failure.clear();
        if self.observed.is_none() {
            let status = rustix::process::waitid(
                rustix::process::WaitId::Pid(self.pid),
                rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT
                    | rustix::process::WaitIdOptions::EXITED,
            )
            .map_err(|source| {
                process_wait_io_error!(
                    &mut self.wait_failure,
                    LeaderWaitId,
                    io::Error::from(source)
                )
            })?;
            if status.is_none() {
                return Ok(OwnedProcessPoll::Running);
            }
            self.observed = Some(exit_status_from_waitid(status.expect("status is present")));
        }
        Ok(OwnedProcessPoll::NeedsGroupProof(
            self.pid.as_raw_nonzero().get(),
        ))
    }

    pub fn finish_owned_poll(
        &mut self,
        has_other_members: bool,
    ) -> io::Result<SupervisedProcessState> {
        if self.observed.is_none() {
            return Err(io::Error::other(
                "owned editor leader exit was not observed",
            ));
        }
        if has_other_members {
            Ok(SupervisedProcessState::LeaderExitedTreeActive)
        } else {
            #[cfg(feature = "test-support")]
            let status = self.child.wait().map_err(|error| {
                process_wait_io_error!(&mut self.wait_failure, LeaderReap, error)
            })?;
            #[cfg(not(feature = "test-support"))]
            let status = self.child.wait()?;
            Ok(SupervisedProcessState::Exited(status.code()))
        }
    }

    #[cfg(feature = "test-support")]
    pub fn take_wait_failure_diagnostic(&mut self) -> Option<ProcessWaitFailureDiagnostic> {
        self.wait_failure.take()
    }

    pub fn leader_exited_unreaped(&self) -> io::Result<bool> {
        rustix::process::waitid(
            rustix::process::WaitId::Pid(self.pid),
            rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT
                | rustix::process::WaitIdOptions::EXITED,
        )
        .map(|status| status.is_some())
        .map_err(io::Error::from)
    }

    pub fn request_stop(&self) -> io::Result<()> {
        signal_group(self.pid, rustix::process::Signal::TERM)
    }

    pub fn force_stop(&self) -> io::Result<()> {
        signal_group(self.pid, rustix::process::Signal::KILL)
    }
}

#[cfg(target_vendor = "apple")]
fn process_group_has_other_members(
    pid: rustix::process::Pid,
    diagnostic: &mut ProcessWaitFailureSlot,
) -> io::Result<bool> {
    #[cfg(not(feature = "test-support"))]
    let _ = diagnostic;
    const PROC_PGRP_ONLY: u32 = 2;
    const MAX_GROUP_MEMBERS: usize = 4_096;

    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn proc_listpids(
            process_type: u32,
            type_info: u32,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    let mut members = [0_i32; MAX_GROUP_MEMBERS];
    let byte_capacity = i32::try_from(std::mem::size_of_val(&members)).map_err(|_| {
        process_wait_error!(
            diagnostic,
            GroupEnumerationOpen,
            EnumerationOverflow,
            io::ErrorKind::Other,
            "process group buffer size overflowed"
        )
    })?;
    let raw_pid = pid.as_raw_nonzero().get();
    let raw_group = u32::try_from(raw_pid).map_err(|_| {
        process_wait_error!(
            diagnostic,
            GroupIdentity,
            InvalidGroupIdentity,
            io::ErrorKind::Other,
            "process group identifier overflowed"
        )
    })?;
    // SAFETY: `members` is writable for exactly `byte_capacity` bytes, and libproc writes
    // only process identifiers into the supplied fixed-size buffer.
    #[allow(unsafe_code)]
    let bytes = unsafe {
        proc_listpids(
            PROC_PGRP_ONLY,
            raw_group,
            members.as_mut_ptr().cast(),
            byte_capacity,
        )
    };
    if bytes < 0 {
        return Err(process_wait_io_error!(
            diagnostic,
            GroupEnumerationOpen,
            io::Error::last_os_error()
        ));
    }
    let count = usize::try_from(bytes)
        .ok()
        .and_then(|value| value.checked_div(std::mem::size_of::<i32>()))
        .ok_or_else(|| {
            process_wait_error!(
                diagnostic,
                GroupEnumerationNext,
                EnumerationResultSize,
                io::ErrorKind::Other,
                "process group result size is invalid"
            )
        })?;
    if count >= MAX_GROUP_MEMBERS {
        return Ok(true);
    }
    Ok(members[..count]
        .iter()
        .any(|member| *member > 0 && *member != raw_pid))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_group_has_other_members(
    pid: rustix::process::Pid,
    diagnostic: &mut ProcessWaitFailureSlot,
) -> io::Result<bool> {
    let groups = [pid.as_raw_nonzero().get()];
    let mut members = [false];
    process_groups_have_other_members_with_diagnostic(&groups, &mut members, diagnostic)?;
    Ok(members[0])
}

#[cfg(target_vendor = "apple")]
pub fn process_groups_have_other_members(groups: &[i32], members: &mut [bool]) -> io::Result<()> {
    use std::time::{Duration, Instant};

    const PROCESS_GROUP_PROBE_DEADLINE: Duration = Duration::from_millis(100);
    if groups.len() != members.len() || groups.len() > 1_024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process group batch is invalid",
        ));
    }
    let mut ordered = [0_i32; 1_024];
    ordered[..groups.len()].copy_from_slice(groups);
    let ordered = &mut ordered[..groups.len()];
    ordered.sort_unstable();
    if ordered.iter().any(|group| *group <= 0) || ordered.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process group batch contains an invalid identity",
        ));
    }
    let deadline = Instant::now() + PROCESS_GROUP_PROBE_DEADLINE;
    for (index, (group, has_members)) in groups.iter().copied().zip(members.iter_mut()).enumerate()
    {
        #[cfg(not(feature = "test-support"))]
        let _ = index;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process group probes exceeded their deadline",
            ));
        }
        #[cfg(feature = "test-support")]
        if PROCESS_GROUP_PROBE_BUDGET
            .with(|budget| budget.get().is_some_and(|maximum| index >= maximum))
        {
            PROCESS_GROUP_PROBE_BUDGET.set(None);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process group probes exceeded their entry budget",
            ));
        }
        let pid = rustix::process::Pid::from_raw(group)
            .ok_or_else(|| io::Error::other("process group identifier is invalid"))?;
        let mut diagnostic = process_wait_failure_slot();
        *has_members = process_group_has_other_members(pid, &mut diagnostic)?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessScanDeadlineState {
    Active,
    Cpu,
    Wall,
    CpuAndWall,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn process_groups_have_other_members(groups: &[i32], members: &mut [bool]) -> io::Result<()> {
    let mut diagnostic = process_wait_failure_slot();
    process_groups_have_other_members_with_diagnostic(groups, members, &mut diagnostic)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_groups_have_other_members_with_diagnostic(
    groups: &[i32],
    members: &mut [bool],
    diagnostic: &mut ProcessWaitFailureSlot,
) -> io::Result<()> {
    use rustix::time::{ClockId, Timespec, clock_gettime};
    use std::time::{Duration, Instant};

    const MAX_SUPERVISED_GROUPS: usize = 1_024;
    const PROCESS_SCAN_CPU_BUDGET: Timespec = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    // Keep one synchronous callback materially below the service's one-second force/reap grace,
    // leaving room for multiple exact retries while still bounding pathological procfs reads.
    const PROCESS_SCAN_WALL_BACKSTOP: Duration = Duration::from_millis(200);
    if groups.len() != members.len() || groups.len() > MAX_SUPERVISED_GROUPS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process group batch is invalid",
        ));
    }
    members.fill(false);
    let mut sorted = [(0_i32, 0_usize); MAX_SUPERVISED_GROUPS];
    for (index, group) in groups.iter().copied().enumerate() {
        if group <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process group identifier is invalid",
            ));
        }
        sorted[index] = (group, index);
    }
    let sorted = &mut sorted[..groups.len()];
    sorted.sort_unstable_by_key(|(group, _)| *group);
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process group batch contains a duplicate",
        ));
    }
    #[cfg(feature = "test-support")]
    PROCESS_GROUP_SCAN_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    let mut inspected = 0_usize;
    let deadline = clock_gettime(ClockId::ThreadCPUTime)
        .checked_add(PROCESS_SCAN_CPU_BUDGET)
        .ok_or_else(|| {
            process_wait_error!(
                diagnostic,
                GroupScanDeadline,
                CpuDeadlineOverflow,
                io::ErrorKind::Other,
                "process group scan deadline overflowed"
            )
        })?;
    #[cfg(feature = "test-support")]
    let wall_budget = PROCESS_GROUP_SCAN_WALL_BUDGET
        .take()
        .unwrap_or(PROCESS_SCAN_WALL_BACKSTOP);
    #[cfg(not(feature = "test-support"))]
    let wall_budget = PROCESS_SCAN_WALL_BACKSTOP;
    let wall_deadline = Instant::now().checked_add(wall_budget).ok_or_else(|| {
        process_wait_error!(
            diagnostic,
            GroupScanDeadline,
            WallDeadlineOverflow,
            io::ErrorKind::Other,
            "process group wall deadline overflowed"
        )
    })?;
    #[cfg(feature = "test-support")]
    if let Some(delay) = PROCESS_GROUP_SCAN_WALL_DELAY.take() {
        std::thread::sleep(delay);
    }
    let directory = match std::fs::read_dir("/proc") {
        Ok(directory) => directory,
        Err(error) => {
            return Err(process_wait_io_error!(
                diagnostic,
                GroupEnumerationOpen,
                error
            ));
        }
    };
    for entry in directory {
        let cpu_expired = clock_gettime(ClockId::ThreadCPUTime) >= deadline;
        let wall_expired = Instant::now() >= wall_deadline;
        if cpu_expired || wall_expired {
            let state = match (cpu_expired, wall_expired) {
                (true, true) => ProcessScanDeadlineState::CpuAndWall,
                (true, false) => ProcessScanDeadlineState::Cpu,
                (false, true) => ProcessScanDeadlineState::Wall,
                (false, false) => ProcessScanDeadlineState::Active,
            };
            return Err(process_wait_deadline_error!(
                diagnostic,
                GroupScanDeadline,
                state,
                "process group scan exceeded its deadline"
            ));
        }
        inspected = inspected.checked_add(1).ok_or_else(|| {
            process_wait_error!(
                diagnostic,
                GroupScanDeadline,
                EnumerationOverflow,
                io::ErrorKind::Other,
                "process enumeration overflowed"
            )
        })?;
        #[cfg(feature = "test-support")]
        if PROCESS_GROUP_SCAN_ENTRY_BUDGET
            .with(|budget| budget.get().is_some_and(|maximum| inspected > maximum))
        {
            PROCESS_GROUP_SCAN_ENTRY_BUDGET.set(None);
            return Err(process_wait_error!(
                diagnostic,
                GroupScanDeadline,
                EnumerationEntryBudget,
                io::ErrorKind::TimedOut,
                "process group scan exceeded its entry budget"
            ));
        }
        if inspected > 1_000_000 {
            return Err(process_wait_error!(
                diagnostic,
                GroupScanDeadline,
                EnumerationEntryBound,
                io::ErrorKind::TimedOut,
                "process group scan exceeded its entry bound"
            ));
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return Err(process_wait_io_error!(
                    diagnostic,
                    GroupEnumerationNext,
                    error
                ));
            }
        };
        let Some(member) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        let mut file = match std::fs::File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(process_wait_io_error!(diagnostic, MemberStatOpen, error));
            }
        };
        let mut stat = [0_u8; 4_096];
        let read = read_linux_process_stat(
            &mut file,
            &mut stat,
            || match (
                clock_gettime(ClockId::ThreadCPUTime) >= deadline,
                Instant::now() >= wall_deadline,
            ) {
                (false, false) => ProcessScanDeadlineState::Active,
                (true, false) => ProcessScanDeadlineState::Cpu,
                (false, true) => ProcessScanDeadlineState::Wall,
                (true, true) => ProcessScanDeadlineState::CpuAndWall,
            },
            diagnostic,
        )?;
        if read == stat.len() {
            members.fill(true);
            return Ok(());
        }
        let identity = parse_linux_process_identity(&stat[..read], member, diagnostic)?;
        if identity.live
            && member != identity.group
            && let Ok(position) = sorted.binary_search_by_key(&identity.group, |(group, _)| *group)
        {
            members[sorted[position].1] = true;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_linux_process_stat(
    reader: &mut impl Read,
    stat: &mut [u8],
    mut deadline_state: impl FnMut() -> ProcessScanDeadlineState,
    diagnostic: &mut ProcessWaitFailureSlot,
) -> io::Result<usize> {
    const MAX_INTERRUPTED_READS: usize = 64;
    let mut read = 0_usize;
    let mut attempts = 0_usize;
    let mut interrupted = 0_usize;
    let maximum_attempts = stat
        .len()
        .checked_add(MAX_INTERRUPTED_READS)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            process_wait_error!(
                diagnostic,
                MemberStatRead,
                StatReadOverflow,
                io::ErrorKind::Other,
                "process stat attempt bound overflowed"
            )
        })?;
    while read < stat.len() {
        let deadline_state = deadline_state();
        if deadline_state != ProcessScanDeadlineState::Active {
            return Err(process_wait_deadline_error!(
                diagnostic,
                MemberStatRead,
                deadline_state,
                "process stat read exceeded its deadline"
            ));
        }
        attempts = attempts
            .checked_add(1)
            .filter(|attempts| *attempts <= maximum_attempts)
            .ok_or_else(|| {
                process_wait_error!(
                    diagnostic,
                    MemberStatRead,
                    StatReadAttemptBound,
                    io::ErrorKind::TimedOut,
                    "process stat read exceeded its attempt bound"
                )
            })?;
        match reader.read(&mut stat[read..]) {
            Ok(0) => break,
            Ok(bytes) => {
                read = read
                    .checked_add(bytes)
                    .filter(|total| *total <= stat.len())
                    .ok_or_else(|| {
                        process_wait_error!(
                            diagnostic,
                            MemberStatRead,
                            StatReadOverflow,
                            io::ErrorKind::Other,
                            "process stat read exceeded its bound"
                        )
                    })?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupted = interrupted
                    .checked_add(1)
                    .filter(|interrupts| *interrupts <= MAX_INTERRUPTED_READS)
                    .ok_or_else(|| {
                        process_wait_error!(
                            diagnostic,
                            MemberStatRead,
                            StatReadInterruptionBound,
                            io::ErrorKind::TimedOut,
                            "process stat read exceeded its interruption bound"
                        )
                    })?;
            }
            Err(error) => {
                return Err(process_wait_io_error!(diagnostic, MemberStatRead, error));
            }
        }
    }
    Ok(read)
}

#[cfg(all(
    feature = "test-support",
    any(target_os = "linux", target_os = "android")
))]
fn parse_linux_process_group(stat: &[u8], expected_pid: i32) -> io::Result<i32> {
    let mut diagnostic = process_wait_failure_slot();
    parse_linux_process_identity(stat, expected_pid, &mut diagnostic).map(|identity| identity.group)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct LinuxProcessIdentity {
    group: i32,
    live: bool,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_linux_process_identity(
    stat: &[u8],
    expected_pid: i32,
    diagnostic: &mut ProcessWaitFailureSlot,
) -> io::Result<LinuxProcessIdentity> {
    let text = std::str::from_utf8(stat)
        .map_err(|_| process_wait_parse_error!(diagnostic, InvalidUtf8, "invalid process stat"))?;
    let (pid, after_pid) = text.split_once(' ').ok_or_else(|| {
        process_wait_parse_error!(diagnostic, MissingPid, "process stat lacks pid")
    })?;
    let pid = pid.parse::<i32>().map_err(|_| {
        process_wait_parse_error!(diagnostic, InvalidPid, "process stat pid is invalid")
    })?;
    if pid != expected_pid {
        return Err(process_wait_parse_error!(
            diagnostic,
            MismatchedPid,
            "process stat pid does not match its directory"
        ));
    }
    let after_name = after_pid
        .rsplit_once(") ")
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            process_wait_parse_error!(diagnostic, MissingCommand, "process stat lacks command")
        })?;
    let mut fields = after_name.split_ascii_whitespace();
    let state = fields.next().ok_or_else(|| {
        process_wait_parse_error!(diagnostic, MissingState, "process stat lacks state")
    })?;
    if state.len() != 1 {
        return Err(process_wait_parse_error!(
            diagnostic,
            InvalidState,
            "process stat state is invalid"
        ));
    }
    let live = match state.as_bytes()[0] {
        b'Z' | b'X' | b'x' => false,
        b'R' | b'S' | b'D' | b'T' | b't' | b'W' | b'K' | b'P' | b'I' => true,
        _ => {
            return Err(process_wait_parse_error!(
                diagnostic,
                UnknownState,
                "process stat state is unknown"
            ));
        }
    };
    let parent = fields.next().ok_or_else(|| {
        process_wait_parse_error!(diagnostic, MissingParent, "process stat lacks parent")
    })?;
    parent.parse::<i32>().map_err(|_| {
        process_wait_parse_error!(diagnostic, InvalidParent, "process stat parent is invalid")
    })?;
    let group = fields.next().ok_or_else(|| {
        process_wait_parse_error!(diagnostic, MissingGroup, "process stat lacks process group")
    })?;
    let group = group.parse::<i32>().map_err(|_| {
        process_wait_parse_error!(
            diagnostic,
            InvalidGroup,
            "process stat process group is invalid"
        )
    })?;
    if group < 0 {
        return Err(process_wait_parse_error!(
            diagnostic,
            InvalidGroup,
            "process stat process group is invalid"
        ));
    }
    Ok(LinuxProcessIdentity { group, live })
}

#[cfg(unix)]
fn signal_group(pid: rustix::process::Pid, signal: rustix::process::Signal) -> io::Result<()> {
    match rustix::process::kill_process_group(pid, signal) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
        Err(error) if error == rustix::io::Errno::PERM => {
            let mut diagnostic = process_wait_failure_slot();
            if !process_group_has_other_members(pid, &mut diagnostic)? {
                Ok(())
            } else {
                Err(io::Error::from(error))
            }
        }
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(all(
    unix,
    not(any(target_vendor = "apple", target_os = "linux", target_os = "android"))
))]
compile_error!("supervised editor process groups are not supported on this Unix target");

#[cfg(all(feature = "test-support", unix))]
#[allow(unsafe_code)]
pub mod test_support {
    use std::process::Command;

    pub fn ignore_termination() {
        // SAFETY: the helper installs the standard ignore disposition and no signal handler.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }

    pub fn configure_detached_child(command: &mut Command) {
        use std::os::unix::process::CommandExt as _;

        // SAFETY: the child hook calls only async-signal-safe `setsid` before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }

    pub fn terminate_self_by_signal() -> ! {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .expect("terminate test editor by signal");
        loop {
            std::thread::park();
        }
    }
}

#[cfg(unix)]
fn exit_status_from_waitid(status: rustix::process::WaitIdStatus) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;

    if let Some(code) = status.exit_status() {
        ExitStatus::from_raw(code << 8)
    } else {
        ExitStatus::from_raw(status.terminating_signal().unwrap_or(1))
    }
}

impl FileStamp {
    pub const fn is_cacheable(&self) -> bool {
        self.change.is_some()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileChangeStamp {
    seconds_or_ticks: i64,
    nanoseconds: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FilesystemIdentity(u64);

impl Directory {
    pub fn try_clone(&self) -> io::Result<Self> {
        let inner = self.inner.try_clone()?;
        let identity_chain = try_copy_identity_chain(&self.identity_chain)?;
        #[cfg(windows)]
        let rename_target = windows::clone_rename_target(&self.rename_target, &inner)?;
        Ok(new_directory(
            inner,
            identity_chain,
            #[cfg(windows)]
            rename_target,
        ))
    }

    /// Acquires the only ambient path authority in the crate.
    pub fn open_ambient(path: &Path) -> io::Result<Self> {
        let (platform_root, components) = split_absolute(path)?;
        let mut inner = Dir::open_ambient_dir(platform_root, ambient_authority())?;
        let mut identity_chain = Vec::new();
        identity_chain
            .try_reserve_exact(components.len().saturating_add(1))
            .map_err(|_| allocation_error("capability identity allocation failed"))?;
        try_push_identity(&mut identity_chain, identity(&inner)?)?;
        for component in components {
            inner = inner.open_dir_nofollow(Path::new(&component))?;
            try_push_identity(&mut identity_chain, identity(&inner)?)?;
        }
        #[cfg(windows)]
        let rename_target = windows::open_ambient_rename_target(&inner)?;
        Ok(new_directory(
            inner,
            identity_chain,
            #[cfg(windows)]
            rename_target,
        ))
    }

    pub fn create_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        #[cfg(windows)]
        {
            let rename_name = windows::prepare_rename_target_name(name.as_path())?;
            let mut identity_chain =
                try_copy_identity_chain_with_capacity(&self.identity_chain, 1)?;
            let rollback = windows::create_directory_rollback(&self.inner, name.as_path())?;
            let inner = match windows::open_directory(&self.inner, name.as_path()) {
                Ok(inner) => inner,
                Err(primary) => {
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            let rollback_identity = match identity(&rollback) {
                Ok(identity) => identity,
                Err(primary) => {
                    drop(inner);
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            let child_identity = match identity(&inner) {
                Ok(identity) => identity,
                Err(primary) => {
                    drop(inner);
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            if rollback_identity != child_identity {
                drop(inner);
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "created directory retained-primary identity changed",
                    ),
                );
            }
            if let Err(primary) = try_push_identity(&mut identity_chain, child_identity) {
                drop(inner);
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    primary,
                );
            }
            let rename_target = match windows::open_child_rename_target(
                &self.rename_target,
                &rename_name,
                &inner,
            ) {
                Ok(rename_target) => rename_target,
                Err(primary) => {
                    drop(inner);
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            #[cfg(feature = "test-support")]
            if take_workspace_directory_fault(WorkspaceDirectoryFault::RenameTargetAfterCreate) {
                drop(rename_target);
                drop(inner);
                let primary = io::Error::other("injected rename-target post-create failure");
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    primary,
                );
            }
            drop(rollback);
            Ok(new_directory(inner, identity_chain, rename_target))
        }
        #[cfg(not(windows))]
        {
            self.inner.create_dir(name.as_path())?;
            self.open_dir_nofollow(name)
        }
    }

    pub fn create_private_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        #[cfg(windows)]
        {
            let rename_name = windows::prepare_rename_target_name(name.as_path())?;
            let mut identity_chain =
                try_copy_identity_chain_with_capacity(&self.identity_chain, 1)?;
            let rollback = windows::create_private_directory_rollback(&self.inner, name.as_path())?;
            let inner = match windows::open_directory(&self.inner, name.as_path()) {
                Ok(inner) => inner,
                Err(primary) => {
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            let rollback_identity = match identity(&rollback) {
                Ok(identity) => identity,
                Err(primary) => {
                    drop(inner);
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            #[cfg(feature = "test-support")]
            if take_workspace_directory_fault(WorkspaceDirectoryFault::PrivateDirectoryAfterCreate)
            {
                drop(inner);
                let primary = io::Error::other("injected private-directory readback failure");
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    primary,
                );
            }
            let child_identity = match identity(&inner) {
                Ok(identity) => identity,
                Err(primary) => {
                    drop(inner);
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            if rollback_identity != child_identity {
                drop(inner);
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "created private-directory retained-primary identity changed",
                    ),
                );
            }
            if let Err(primary) = try_push_identity(&mut identity_chain, child_identity) {
                drop(inner);
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    primary,
                );
            }
            let rename_target = match windows::open_child_rename_target(
                &self.rename_target,
                &rename_name,
                &inner,
            ) {
                Ok(rename_target) => rename_target,
                Err(primary) => {
                    drop(inner);
                    return fail_windows_created_directory(
                        &self.inner,
                        rollback,
                        name.as_path(),
                        primary,
                    );
                }
            };
            #[cfg(feature = "test-support")]
            if take_workspace_directory_fault(WorkspaceDirectoryFault::RenameTargetAfterCreate) {
                drop(rename_target);
                drop(inner);
                let primary = io::Error::other("injected rename-target post-create failure");
                return fail_windows_created_directory(
                    &self.inner,
                    rollback,
                    name.as_path(),
                    primary,
                );
            }
            let directory = new_directory(inner, identity_chain, rename_target);
            match directory.verify_private() {
                Ok(()) => {
                    drop(rollback);
                    Ok(directory)
                }
                Err(primary) => {
                    drop(directory);
                    fail_windows_created_directory(&self.inner, rollback, name.as_path(), primary)
                }
            }
        }
        #[cfg(not(windows))]
        {
            #[allow(unused_mut)]
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            self.inner.create_dir_with(name.as_path(), &builder)?;
            let initialized = match self.open_dir_nofollow(name) {
                Ok(directory) => prepare_private_directory(&directory).map(|()| directory),
                Err(error) => Err(error),
            };
            match initialized {
                Ok(directory) => Ok(directory),
                Err(primary) => match self.inner.remove_dir(name.as_path()) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(io::Error::other(format!(
                        "private-directory initialization failed: {primary}; cleanup failed: {cleanup}"
                    ))),
                },
            }
        }
    }

    pub fn open_dir_nofollow(&self, name: &PhysicalComponent) -> io::Result<Self> {
        #[cfg(windows)]
        let rename_name = windows::prepare_rename_target_name(name.as_path())?;
        #[cfg(windows)]
        let inner = windows::open_directory(&self.inner, name.as_path())?;
        #[cfg(not(windows))]
        let inner = self.inner.open_dir_nofollow(name.as_path())?;
        let mut identity_chain = try_copy_identity_chain(&self.identity_chain)?;
        try_push_identity(&mut identity_chain, identity(&inner)?)?;
        #[cfg(windows)]
        let rename_target =
            windows::open_child_rename_target(&self.rename_target, &rename_name, &inner)?;
        Ok(new_directory(
            inner,
            identity_chain,
            #[cfg(windows)]
            rename_target,
        ))
    }

    pub fn open_private_dir_for_cleanup(&self, name: &PhysicalComponent) -> io::Result<Self> {
        #[cfg(windows)]
        let rename_name = windows::prepare_rename_target_name(name.as_path())?;
        #[cfg(windows)]
        let inner = windows::open_directory(&self.inner, name.as_path())?;
        #[cfg(not(windows))]
        let inner = self.inner.open_dir_nofollow(name.as_path())?;
        let mut identity_chain = try_copy_identity_chain_with_capacity(&self.identity_chain, 1)?;
        try_push_identity(&mut identity_chain, identity(&inner)?)?;
        #[cfg(windows)]
        let rename_target =
            windows::open_child_rename_target(&self.rename_target, &rename_name, &inner)?;
        let directory = new_directory(
            inner,
            identity_chain,
            #[cfg(windows)]
            rename_target,
        );
        if !same_mount_instance(&self.inner, &directory.inner)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private cleanup directory crosses a mount boundary",
            ));
        }
        directory.verify_private()?;
        Ok(directory)
    }

    pub fn open_or_create_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        match self.open_dir_nofollow(name) {
            Ok(directory) => Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.create_dir(name),
            Err(error) => Err(error),
        }
    }

    pub fn open_or_create_private_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        let directory = match self.open_dir_nofollow(name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.create_private_dir(name)?
            }
            Err(error) => return Err(error),
        };
        directory.verify_private()?;
        Ok(directory)
    }

    pub fn open_or_create_private_workspace_dir(&self, name: &Path) -> io::Result<Self> {
        validate_workspace_component(name)?;
        #[cfg(windows)]
        {
            let rename_name = windows::prepare_rename_target_name(name)?;
            let mut identity_chain =
                try_copy_identity_chain_with_capacity(&self.identity_chain, 1)?;
            let (inner, rollback) = match windows::open_directory(&self.inner, name) {
                Ok(inner) => (inner, None),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let rollback = windows::create_private_directory_rollback(&self.inner, name)?;
                    let inner = match windows::open_directory(&self.inner, name) {
                        Ok(inner) => inner,
                        Err(primary) => {
                            return fail_windows_created_directory(
                                &self.inner,
                                rollback,
                                name,
                                primary,
                            );
                        }
                    };
                    let rollback_identity = match identity(&rollback) {
                        Ok(identity) => identity,
                        Err(primary) => {
                            drop(inner);
                            return fail_windows_created_directory(
                                &self.inner,
                                rollback,
                                name,
                                primary,
                            );
                        }
                    };
                    let retained_identity = match identity(&inner) {
                        Ok(identity) => identity,
                        Err(primary) => {
                            drop(inner);
                            return fail_windows_created_directory(
                                &self.inner,
                                rollback,
                                name,
                                primary,
                            );
                        }
                    };
                    if rollback_identity != retained_identity {
                        drop(inner);
                        return fail_windows_created_directory(
                            &self.inner,
                            rollback,
                            name,
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "created workspace retained-primary identity changed",
                            ),
                        );
                    }
                    (inner, Some(rollback))
                }
                Err(error) => return Err(error),
            };
            let child_identity = match identity(&inner) {
                Ok(identity) => identity,
                Err(primary) => {
                    drop(inner);
                    return fail_optional_windows_created_directory(
                        &self.inner,
                        rollback,
                        name,
                        primary,
                    );
                }
            };
            if let Err(primary) = try_push_identity(&mut identity_chain, child_identity) {
                drop(inner);
                return fail_optional_windows_created_directory(
                    &self.inner,
                    rollback,
                    name,
                    primary,
                );
            }
            let rename_target = match windows::open_child_rename_target(
                &self.rename_target,
                &rename_name,
                &inner,
            ) {
                Ok(rename_target) => rename_target,
                Err(primary) => {
                    drop(inner);
                    return fail_optional_windows_created_directory(
                        &self.inner,
                        rollback,
                        name,
                        primary,
                    );
                }
            };
            #[cfg(feature = "test-support")]
            if rollback.is_some()
                && take_workspace_directory_fault(WorkspaceDirectoryFault::RenameTargetAfterCreate)
            {
                drop(rename_target);
                drop(inner);
                return fail_optional_windows_created_directory(
                    &self.inner,
                    rollback,
                    name,
                    io::Error::other("injected rename-target post-create failure"),
                );
            }
            let directory = new_directory(inner, identity_chain, rename_target);
            let same_mount = match same_mount_instance(&self.inner, &directory.inner) {
                Ok(same_mount) => same_mount,
                Err(primary) => {
                    return fail_optional_windows_created_directory_capability(
                        self, directory, rollback, name, primary,
                    );
                }
            };
            if !same_mount {
                return fail_optional_windows_created_directory_capability(
                    self,
                    directory,
                    rollback,
                    name,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "workspace directory crosses a mount boundary",
                    ),
                );
            }
            if let Err(primary) = directory.verify_private() {
                return fail_optional_windows_created_directory_capability(
                    self, directory, rollback, name, primary,
                );
            }
            if let Err(primary) = self.sync_workspace_parent_creation() {
                return fail_optional_windows_created_directory_capability(
                    self, directory, rollback, name, primary,
                );
            }
            drop(rollback);
            Ok(directory)
        }
        #[cfg(not(windows))]
        {
            let mut identity_chain =
                try_copy_identity_chain_with_capacity(&self.identity_chain, 1)?;
            let (inner, created) = match self.inner.open_dir_nofollow(name) {
                Ok(inner) => (inner, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    #[allow(unused_mut)]
                    let mut builder = DirBuilder::new();
                    #[cfg(unix)]
                    builder.mode(0o700);
                    self.inner.create_dir_with(name, &builder)?;
                    (self.inner.open_dir_nofollow(name)?, true)
                }
                Err(error) => return Err(error),
            };
            let child_identity = match identity(&inner) {
                Ok(identity) => identity,
                Err(primary) => {
                    return fail_created_private_directory(
                        &self.inner,
                        inner,
                        name,
                        created,
                        primary,
                    );
                }
            };
            if let Err(primary) = try_push_identity(&mut identity_chain, child_identity) {
                return fail_created_private_directory(&self.inner, inner, name, created, primary);
            }
            let directory = new_directory(inner, identity_chain);
            let same_mount = match same_mount_instance(&self.inner, &directory.inner) {
                Ok(same_mount) => same_mount,
                Err(primary) => {
                    return fail_created_private_directory_capability(
                        self, directory, name, created, primary,
                    );
                }
            };
            if !same_mount {
                return fail_created_private_directory_capability(
                    self,
                    directory,
                    name,
                    created,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "workspace directory crosses a mount boundary",
                    ),
                );
            }
            let prepared = if created {
                prepare_private_directory(&directory)
            } else {
                directory.verify_private()
            };
            if let Err(primary) = prepared {
                return fail_created_private_directory_capability(
                    self, directory, name, created, primary,
                );
            }
            self.sync_workspace_parent_creation()?;
            Ok(directory)
        }
    }

    pub fn open_private_workspace_dir(&self, name: &Path) -> io::Result<Self> {
        validate_workspace_component(name)?;
        #[cfg(windows)]
        let rename_name = windows::prepare_rename_target_name(name)?;
        #[cfg(windows)]
        let inner = windows::open_directory(&self.inner, name)?;
        #[cfg(not(windows))]
        let inner = self.inner.open_dir_nofollow(name)?;
        let mut identity_chain = try_copy_identity_chain(&self.identity_chain)?;
        try_push_identity(&mut identity_chain, identity(&inner)?)?;
        #[cfg(windows)]
        let rename_target =
            windows::open_child_rename_target(&self.rename_target, &rename_name, &inner)?;
        let directory = new_directory(
            inner,
            identity_chain,
            #[cfg(windows)]
            rename_target,
        );
        if !same_mount_instance(&self.inner, &directory.inner)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "workspace directory crosses a mount boundary",
            ));
        }
        directory.verify_private()?;
        Ok(directory)
    }

    pub fn create_file_new(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE,
            };
            options
                .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_WRITE_THROUGH);
        }
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        #[cfg(windows)]
        if let Err(primary) = file.require_single_regular_link() {
            return windows::discard_created_file(&self.inner, file.inner, name.as_path())
                .and_then(|()| Err(primary));
        }
        #[cfg(not(windows))]
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn create_private_file_new(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        #[cfg(windows)]
        let inner = windows::create_private_file(&self.inner, name.as_path())?;
        #[cfg(not(windows))]
        let inner = {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            self.inner.open_with(name.as_path(), &options)?
        };
        let file = FileCapability { inner };
        #[cfg(feature = "test-support")]
        {
            if take_workspace_directory_fault(WorkspaceDirectoryFault::PrivateFileAfterCreate) {
                let primary = io::Error::other("injected private-file initialization failure");
                #[cfg(windows)]
                return windows::discard_created_file(&self.inner, file.inner, name.as_path())
                    .and_then(|()| Err(primary));
                #[cfg(not(windows))]
                return Err(primary);
            }
        }
        #[cfg(windows)]
        if let Err(primary) = file
            .require_single_regular_link()
            .and_then(|()| prepare_private_file(&file))
        {
            return windows::discard_created_file(&self.inner, file.inner, name.as_path())
                .and_then(|()| Err(primary));
        }
        #[cfg(not(windows))]
        file.require_single_regular_link()
            .and_then(|()| prepare_private_file(&file))?;
        Ok(file)
    }

    pub fn create_private_workspace_file_new(&self, name: &Path) -> io::Result<FileCapability> {
        validate_workspace_component(name)?;
        #[cfg(windows)]
        let inner = windows::create_private_file(&self.inner, name)?;
        #[cfg(not(windows))]
        let inner = {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            self.inner.open_with(name, &options)?
        };
        let file = FileCapability { inner };
        #[cfg(windows)]
        if let Err(primary) = file
            .require_single_regular_link()
            .and_then(|()| prepare_private_file(&file))
        {
            return windows::discard_created_file(&self.inner, file.inner, name)
                .and_then(|()| Err(primary));
        }
        #[cfg(not(windows))]
        file.require_single_regular_link()
            .and_then(|()| prepare_private_file(&file))?;
        Ok(file)
    }

    pub fn open_private_workspace_file_nofollow(&self, name: &Path) -> io::Result<FileCapability> {
        validate_workspace_component(name)?;
        let file = self.open_file_nofollow_path(name)?;
        verify_private_file(&file)?;
        Ok(file)
    }

    /// Synchronizes one exact private workspace file without widening ordinary reopen authority.
    pub fn sync_private_workspace_file_if_matches(
        &self,
        name: &Path,
        expected: &FileCapability,
    ) -> io::Result<()> {
        validate_workspace_component(name)?;
        expected.require_single_regular_link()?;
        verify_private_file(expected)?;

        #[cfg(windows)]
        let sync = {
            let sync = FileCapability {
                inner: windows::open_private_file_for_sync(&self.inner, name)?,
            };
            sync.require_single_regular_link()?;
            verify_private_file(&sync)?;
            sync
        };
        #[cfg(not(windows))]
        let sync = self.open_private_workspace_file_nofollow(name)?;

        if !expected.same_file(&sync)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private workspace sync target identity changed",
            ));
        }
        #[cfg(feature = "test-support")]
        if take_workspace_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect) {
            return Err(io::Error::other(
                "injected private workspace file sync failure before effect",
            ));
        }
        #[cfg(windows)]
        sync.sync_all()?;
        #[cfg(not(windows))]
        expected.sync_all()?;
        #[cfg(feature = "test-support")]
        if take_workspace_file_sync_fault(WorkspaceFileSyncFault::AfterEffect) {
            return Err(io::Error::other(
                "injected private workspace file sync failure after effect",
            ));
        }
        Ok(())
    }

    pub fn open_private_workspace_relative_file_nofollow(
        &self,
        path: &Path,
    ) -> io::Result<FileCapability> {
        let mut directory = self.try_clone()?;
        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "workspace path contains a non-normal component",
                ));
            };
            validate_workspace_component(Path::new(name))?;
            if components.peek().is_none() {
                return directory.open_private_workspace_file_nofollow(Path::new(name));
            }
            #[cfg(windows)]
            let rename_name = windows::prepare_rename_target_name(Path::new(name))?;
            #[cfg(windows)]
            let child = windows::open_directory(&directory.inner, Path::new(name))?;
            #[cfg(not(windows))]
            let child = directory.inner.open_dir_nofollow(Path::new(name))?;
            let mut identity_chain = try_copy_identity_chain(&directory.identity_chain)?;
            try_push_identity(&mut identity_chain, identity(&child)?)?;
            #[cfg(windows)]
            let rename_target =
                windows::open_child_rename_target(&directory.rename_target, &rename_name, &child)?;
            directory = new_directory(
                child,
                identity_chain,
                #[cfg(windows)]
                rename_target,
            );
            if !same_mount_instance(&self.inner, &directory.inner)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "workspace path crosses a mount boundary",
                ));
            }
            directory.verify_private()?;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace file path is empty",
        ))
    }

    pub fn open_file_nofollow(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn open_file_for_sync_nofollow(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn open_file_for_rename_nofollow(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        #[cfg(windows)]
        configure_rename_file_open_options(&mut options);
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn try_lock_exclusive(&self, name: &PhysicalComponent) -> io::Result<ExclusiveFileLock> {
        let file = match self.create_lock_file_new(name) {
            Ok(file) => {
                file.sync_all()?;
                self.sync()?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                match self.open_lock_file_nofollow(name) {
                    Ok(file) => file,
                    Err(error) if lock_open_is_contended(&error) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "lock sidecar is held",
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if lock_open_is_contended(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "lock sidecar is held",
                ));
            }
            Err(error) => return Err(error),
        };
        lock_file_nonblocking(&file)?;
        let lock = ExclusiveFileLock { file };
        if !lock.validates_named_file(self, name)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lock sidecar identity changed during acquisition",
            ));
        }
        Ok(lock)
    }

    fn create_lock_file_new(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(windows)]
        configure_lock_file_open_options(&mut options);
        let file = FileCapability {
            inner: self.inner.open_with(name.as_path(), &options)?,
        };
        #[cfg(windows)]
        if let Err(primary) = file.require_single_regular_link() {
            return windows::discard_created_file(&self.inner, file.inner, name.as_path())
                .and_then(|()| Err(primary));
        }
        #[cfg(not(windows))]
        file.require_single_regular_link()?;
        Ok(file)
    }

    fn open_lock_file_nofollow(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        #[cfg(windows)]
        configure_lock_file_open_options(&mut options);
        let file = FileCapability {
            inner: self.inner.open_with(name.as_path(), &options)?,
        };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn entry_kind(&self, name: &PhysicalComponent) -> io::Result<EntryKind> {
        let metadata = self.inner.symlink_metadata(name.as_path())?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "symbolic links are rejected",
            ));
        }
        if file_type.is_file() {
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hard-linked files are rejected",
                ));
            }
            Ok(EntryKind::File)
        } else if file_type.is_dir() {
            Ok(EntryKind::Directory)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "special filesystem objects are rejected",
            ))
        }
    }

    pub fn entry_names_bounded(&self, maximum: usize) -> io::Result<Vec<PhysicalComponent>> {
        let mut names = Vec::new();
        names
            .try_reserve(maximum.min(64))
            .map_err(|_| allocation_error("directory enumeration allocation failed"))?;
        for entry in self.inner.read_dir(".")? {
            if names.len() >= maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry limit exceeded",
                ));
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 physical name")
            })?;
            names
                .try_reserve(1)
                .map_err(|_| allocation_error("directory enumeration allocation failed"))?;
            names.push(PhysicalComponent::try_new(name)?);
        }
        names.sort_unstable();
        Ok(names)
    }

    pub fn workspace_entry_names_bounded(&self, maximum: usize) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        names
            .try_reserve(maximum.min(64))
            .map_err(|_| allocation_error("directory enumeration allocation failed"))?;
        for entry in self.inner.read_dir(".")? {
            if names.len() >= maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry limit exceeded",
                ));
            }
            let name = entry?.file_name();
            validate_workspace_component(Path::new(&name))?;
            names
                .try_reserve(1)
                .map_err(|_| allocation_error("directory enumeration allocation failed"))?;
            names.push(name);
        }
        names.sort_unstable();
        Ok(names)
    }

    pub fn sync(&self) -> io::Result<()> {
        sync_directory_handle(&self.inner)
    }

    pub fn sync_workspace_cleanup_after_effect(&self) -> io::Result<()> {
        #[cfg(feature = "test-support")]
        if take_workspace_cleanup_fault(WorkspaceCleanupFault::DirectorySyncAfterEffect) {
            return Err(io::Error::other("injected directory sync failure"));
        }
        self.sync()
    }

    fn sync_workspace_parent_creation(&self) -> io::Result<()> {
        #[cfg(feature = "test-support")]
        WORKSPACE_PARENT_SYNC_COUNT.with(|count| count.set(count.get().saturating_add(1)));
        #[cfg(feature = "test-support")]
        if take_workspace_directory_fault(WorkspaceDirectoryFault::ParentSync) {
            return Err(io::Error::other("injected workspace parent sync failure"));
        }
        self.sync()
    }

    pub fn verify_private(&self) -> io::Result<()> {
        let metadata = self.inner.dir_metadata()?;
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0
            || cap_fs_ext::OsMetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is not private to the effective user",
            ));
        }
        #[cfg(windows)]
        windows::verify_private_directory(&self.inner)?;
        #[cfg(target_vendor = "apple")]
        apple_acl::verify_no_extended_acl_directory(&self.inner)?;
        #[cfg(not(unix))]
        let _ = metadata;
        Ok(())
    }

    pub fn same_identity(&self, other: &Self) -> io::Result<bool> {
        Ok(self.final_identity() == other.final_identity())
    }

    pub fn identity(&self) -> FileIdentity {
        self.final_identity()
    }

    pub fn filesystem_identity(&self) -> FilesystemIdentity {
        FilesystemIdentity(self.final_identity().device)
    }

    #[cfg(unix)]
    pub fn available_space(&self) -> io::Result<u64> {
        use std::os::fd::AsFd as _;

        let statistics = rustix::fs::fstatvfs(self.inner.as_fd())?;
        statistics
            .f_frsize
            .checked_mul(statistics.f_bavail)
            .ok_or_else(|| io::Error::other("available-space calculation overflowed"))
    }

    #[cfg(windows)]
    pub fn available_space(&self) -> io::Result<u64> {
        windows::available_space(&self.inner)
    }

    pub fn is_same_or_ancestor_of(&self, other: &Self) -> bool {
        other.identity_chain.contains(&self.final_identity())
    }

    pub fn same_filesystem(&self, other: &Self) -> io::Result<bool> {
        same_mount_instance(&self.inner, &other.inner)
    }

    fn final_identity(&self) -> FileIdentity {
        *self
            .identity_chain
            .last()
            .expect("every directory capability includes its platform root")
    }

    /// Renames a synced file from a held private staging directory.
    ///
    /// Unix callers batch directory synchronization after all renames. Windows completes the
    /// namespace mutation through the exact write-through source handle, then uses `sync` only as
    /// the compatibility and retained-identity validation barrier.
    pub fn rename_opened_no_replace_from_private_staging(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        rename_no_replace(
            source,
            &self.inner,
            staged.as_path(),
            destination_directory,
            destination.as_path(),
        )?;
        let published = match destination_directory.open_file_nofollow(destination) {
            Ok(file) => file,
            Err(error) => {
                #[cfg(windows)]
                if let Err(cleanup) = destination_directory.remove_opened_file_exact_windows(
                    source,
                    destination.as_path(),
                    false,
                    InitialFileAbsence::ReconcileAfterEffect,
                ) {
                    return Err(io::Error::other(format!(
                        "published file verification failed: {error}; exact rollback failed: {cleanup}"
                    )));
                }
                #[cfg(not(windows))]
                let _ = destination_directory
                    .inner
                    .remove_file(destination.as_path());
                destination_directory.sync()?;
                return Err(error);
            }
        };
        if !published_matches_exact_source(source, &published)? {
            #[cfg(windows)]
            destination_directory.remove_opened_file_exact_windows(
                source,
                destination.as_path(),
                false,
                InitialFileAbsence::ReconcileAfterEffect,
            )?;
            #[cfg(not(windows))]
            destination_directory
                .inner
                .remove_file(destination.as_path())?;
            destination_directory.sync()?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published file identity changed",
            ));
        }
        Ok(())
    }

    pub fn rename_opened_no_replace_to_workspace(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &Path,
    ) -> Result<FileCapability, WorkspacePublishAttemptError> {
        self.verify_private().map_err(workspace_not_published)?;
        validate_workspace_component(destination).map_err(workspace_not_published)?;
        rename_no_replace_observed(
            source,
            &self.inner,
            staged.as_path(),
            destination_directory,
            destination,
        )
        .map_err(|failure| WorkspacePublishAttemptError {
            primary: failure.primary,
            effect: if failure.destination_may_be_visible {
                WorkspacePublicationEffect::PublishedUnverified
            } else {
                WorkspacePublicationEffect::NotPublished
            },
        })?;
        let published = match destination_directory.open_file_nofollow_path(destination) {
            Ok(file) => file,
            Err(primary) => return Err(workspace_published_unverified(primary)),
        };
        verify_private_file(&published).map_err(workspace_published_unverified)?;
        if !published_matches_exact_source(source, &published)
            .map_err(workspace_published_unverified)?
        {
            return Err(workspace_published_unverified(io::Error::new(
                io::ErrorKind::InvalidData,
                "published workspace file identity changed",
            )));
        }
        Ok(published)
    }

    pub fn reconcile_opened_workspace_publication(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &Path,
    ) -> Result<FileCapability, WorkspacePublishAttemptError> {
        self.verify_private().map_err(workspace_not_published)?;
        destination_directory
            .verify_private()
            .map_err(workspace_not_published)?;
        validate_workspace_component(destination).map_err(workspace_not_published)?;

        let published = match destination_directory.open_regular_file_nofollow_path(destination) {
            Ok(published) => published,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return self.rename_opened_no_replace_to_workspace(
                    source,
                    staged,
                    destination_directory,
                    destination,
                );
            }
            Err(error) => return Err(workspace_published_unverified(error)),
        };
        verify_private_file(&published).map_err(workspace_published_unverified)?;
        if !published_matches_exact_source(source, &published)
            .map_err(workspace_published_unverified)?
        {
            return Err(workspace_published_unverified(io::Error::new(
                io::ErrorKind::InvalidData,
                "published workspace file does not match retained source",
            )));
        }

        match self.open_regular_file_nofollow_path(staged.as_path()) {
            Ok(named_source) => {
                if !source
                    .same_file(&named_source)
                    .map_err(workspace_published_unverified)?
                {
                    return Err(workspace_published_unverified(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "staged workspace file identity changed",
                    )));
                }
                #[cfg(windows)]
                self.remove_opened_file_exact_windows(
                    source,
                    staged.as_path(),
                    true,
                    InitialFileAbsence::RejectBeforeEffect,
                )
                .map_err(workspace_published_unverified)?;
                #[cfg(not(windows))]
                self.inner
                    .remove_file(staged.as_path())
                    .map_err(workspace_published_unverified)?;
                self.sync().map_err(workspace_published_unverified)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(workspace_published_unverified(error)),
        }

        let published = destination_directory
            .open_file_nofollow_path(destination)
            .map_err(workspace_published_unverified)?;
        verify_private_file(&published).map_err(workspace_published_unverified)?;
        if !published_matches_exact_source(source, &published)
            .map_err(workspace_published_unverified)?
        {
            return Err(workspace_published_unverified(io::Error::new(
                io::ErrorKind::InvalidData,
                "published workspace file changed during reconciliation",
            )));
        }
        Ok(published)
    }

    pub fn replace_atomic_from_private_staging(
        &self,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        let source = self.open_file_for_rename_nofollow(staged)?;
        source.sync_all()?;
        self.replace_opened_atomic_from_private_staging(
            &source,
            staged,
            destination_directory,
            destination,
        )?;
        destination_directory.sync()?;
        self.sync()
    }

    pub fn replace_opened_atomic_from_private_staging(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
    ) -> io::Result<()> {
        self.replace_opened_atomic_checked(
            source,
            staged.as_path(),
            destination_directory,
            destination.as_path(),
            None,
        )
    }

    pub fn replace_opened_atomic_from_workspace_staging(
        &self,
        source: &FileCapability,
        staged: &Path,
        destination_directory: &Self,
        destination: &Path,
    ) -> io::Result<()> {
        validate_workspace_component(staged)?;
        validate_workspace_component(destination)?;
        self.replace_opened_atomic_checked(source, staged, destination_directory, destination, None)
    }

    pub fn replace_opened_atomic_if_destination_matches(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
        expected_destination: &FileCapability,
    ) -> io::Result<()> {
        self.replace_opened_atomic_checked(
            source,
            staged.as_path(),
            destination_directory,
            destination.as_path(),
            Some(expected_destination),
        )
    }

    fn replace_opened_atomic_checked(
        &self,
        source: &FileCapability,
        staged: &Path,
        destination_directory: &Self,
        destination: &Path,
        expected_destination: Option<&FileCapability>,
    ) -> io::Result<()> {
        self.verify_private()?;
        // Unix has no portable atomic replace syscall that names an already-open
        // source descriptor. The source lives in an unpredictable 0700 directory
        // under the store's OS mutation lock. Reopen and compare immediately
        // before the atomic path replacement so no cooperative process can
        // substitute a different source entry.
        let named_source = self.open_file_for_rename_nofollow_path(staged)?;
        if !source.same_file(&named_source)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staged replacement identity changed before publication",
            ));
        }
        if let Some(expected) = expected_destination {
            let named_destination = destination_directory.open_file_nofollow_path(destination)?;
            if !expected.same_file(&named_destination)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "replacement destination identity changed before publication",
                ));
            }
        }
        rename_replace(
            source,
            &self.inner,
            staged,
            destination_directory,
            destination,
        )?;
        source.sync_all()?;
        let published = destination_directory.open_file_nofollow_path(destination)?;
        if !source.same_file(&published)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replaced file identity changed",
            ));
        }
        Ok(())
    }

    fn open_file_nofollow_path(&self, name: &Path) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name, &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    #[cfg(windows)]
    fn open_private_file_for_exact_removal(&self, name: &Path) -> io::Result<FileCapability> {
        validate_workspace_component(name)?;
        let inner = windows::open_private_file_for_cleanup(&self.inner, name, true)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        verify_private_file(&file)?;
        Ok(file)
    }

    fn open_regular_file_nofollow_path(&self, name: &Path) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name, &options)?;
        let file = FileCapability { inner };
        if !file.inner.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "workspace entry is not a regular file",
            ));
        }
        Ok(file)
    }

    pub fn opened_workspace_file_matches(
        &self,
        expected: &FileCapability,
        name: &Path,
    ) -> io::Result<bool> {
        validate_workspace_component(name)?;
        let named = self.open_file_nofollow_path(name)?;
        expected.same_file(&named)
    }

    fn open_file_for_rename_nofollow_path(&self, name: &Path) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        #[cfg(windows)]
        configure_rename_file_open_options(&mut options);
        let inner = self.inner.open_with(name, &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn remove_opened_file_if_matches(
        &self,
        expected: &FileCapability,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.remove_opened_file_if_matches_unsynced(expected, name)?;
        self.sync()
    }

    pub fn remove_opened_file_if_matches_unsynced(
        &self,
        expected: &FileCapability,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.remove_opened_file_if_matches_unsynced_observed(expected, name)
            .map_err(|failure| failure.error)
    }

    pub(crate) fn remove_opened_file_if_matches_unsynced_observed(
        &self,
        expected: &FileCapability,
        name: &PhysicalComponent,
    ) -> Result<(), ExactFileRemovalFailure> {
        #[cfg(feature = "test-support")]
        if take_workspace_cleanup_fault(WorkspaceCleanupFault::StagingNamedReopen) {
            return Err(ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::NamedOpen,
                error: io::Error::other("injected staging named reopen failure"),
            });
        }
        let named = match self.open_file_nofollow(name) {
            Ok(named) => named,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                verify_private_file(expected).map_err(|error| ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::Identity,
                    error,
                })?;
                return Ok(());
            }
            Err(error) => {
                return Err(ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::NamedOpen,
                    error,
                });
            }
        };
        if !expected
            .same_file(&named)
            .map_err(|error| ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::Identity,
                error,
            })?
        {
            return Err(ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::Identity,
                error: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "removal target identity changed before removal",
                ),
            });
        }
        drop(named);
        #[cfg(feature = "test-support")]
        {
            if take_workspace_cleanup_fault(WorkspaceCleanupFault::StagingUnlinkBeforeEffect) {
                return Err(ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::Disposition,
                    error: io::Error::other("injected staging unlink failure"),
                });
            }
        }
        #[cfg(windows)]
        {
            let cleanup = self
                .open_private_file_for_exact_removal(name.as_path())
                .map_err(|error| ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::CleanupOpen,
                    error,
                })?;
            if !expected
                .same_file(&cleanup)
                .map_err(|error| ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::Identity,
                    error,
                })?
            {
                return Err(ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::Identity,
                    error: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "removal target identity changed before exact disposition",
                    ),
                });
            }
            windows::delete_exact_file(&cleanup.inner).map_err(|error| {
                ExactFileRemovalFailure {
                    stage: ExactFileRemovalStage::Disposition,
                    error,
                }
            })?;
            drop(cleanup);
        }
        #[cfg(not(windows))]
        self.inner
            .remove_file(name.as_path())
            .map_err(|error| ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::Disposition,
                error,
            })?;
        #[cfg(feature = "test-support")]
        if take_workspace_cleanup_fault(WorkspaceCleanupFault::StagingAbsenceReadbackAfterEffect) {
            return Err(ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::Absence,
                error: io::Error::other("injected staging absence readback failure"),
            });
        }
        match self.open_file_nofollow(name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::Absence,
                error: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "removed file name remains reachable",
                ),
            }),
            Err(error) => Err(ExactFileRemovalFailure {
                stage: ExactFileRemovalStage::Absence,
                error,
            }),
        }
    }

    pub fn remove_file(&self, name: &PhysicalComponent) -> io::Result<()> {
        #[cfg(windows)]
        {
            let expected = self.open_file_nofollow(name)?;
            self.remove_opened_file_exact_windows(
                &expected,
                name.as_path(),
                false,
                InitialFileAbsence::RejectBeforeEffect,
            )?;
            self.sync()
        }
        #[cfg(not(windows))]
        {
            self.entry_kind(name)?;
            self.inner.remove_file(name.as_path())?;
            self.sync()
        }
    }

    pub fn remove_file_from_private_staging_unsynced(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        #[cfg(windows)]
        {
            let expected = self.open_file_nofollow(name)?;
            self.remove_opened_file_if_matches_unsynced(&expected, name)
        }
        #[cfg(not(windows))]
        {
            self.entry_kind(name)?;
            self.inner.remove_file(name.as_path())
        }
    }

    /// Removes an untrusted regular-file residue from an owned private staging directory.
    ///
    /// This authority is intentionally narrower than private-file cleanup: the parent must still
    /// be private, the selected name must resolve without following links to one exact regular
    /// file, and the parent namespace is synchronized before success is returned.
    /// It is for store-owned operation directories protected by their mutation lock, not for
    /// removing files from an editor workspace.
    pub fn remove_untrusted_file_from_private_staging(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.remove_untrusted_file_from_private_staging_unsynced(name)?;
        self.sync()
    }

    /// Removes one exact untrusted staging file without completing the parent barrier.
    ///
    /// The caller must synchronize this private parent before reporting durable cleanup.
    pub fn remove_untrusted_file_from_private_staging_unsynced(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        let expected = self.open_file_nofollow(name)?;
        #[cfg(windows)]
        self.remove_opened_file_exact_windows(
            &expected,
            name.as_path(),
            false,
            InitialFileAbsence::RejectBeforeEffect,
        )?;
        #[cfg(not(windows))]
        {
            let named = self.open_file_nofollow(name)?;
            if !expected.same_file(&named)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "untrusted staging cleanup target identity changed",
                ));
            }
            drop(named);
            self.inner.remove_file(name.as_path())?;
            match self.open_file_nofollow(name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "removed untrusted staging file remains reachable",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn remove_opened_file_exact_windows(
        &self,
        expected: &FileCapability,
        name: &Path,
        require_private: bool,
        initial_absence: InitialFileAbsence,
    ) -> io::Result<()> {
        validate_workspace_component(name)?;
        let named = match self.open_file_nofollow_path(name) {
            Ok(named) => named,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if initial_absence == InitialFileAbsence::RejectBeforeEffect {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "removal target name disappeared before exact cleanup",
                    ));
                }
                let metadata = expected.inner.metadata()?;
                if !metadata.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "retained cleanup authority is not a regular file",
                    ));
                }
                if require_private {
                    verify_private_file(expected)?;
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !expected.same_file(&named)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "removal target identity changed before cleanup open",
            ));
        }
        drop(named);
        let cleanup = FileCapability {
            inner: windows::open_private_file_for_cleanup(&self.inner, name, true)?,
        };
        cleanup.require_single_regular_link()?;
        if require_private {
            verify_private_file(&cleanup)?;
        }
        if !expected.same_file(&cleanup)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "removal target identity changed before exact disposition",
            ));
        }
        windows::delete_exact_file(&cleanup.inner)?;
        drop(cleanup);
        match self.open_file_nofollow_path(name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "removed file name remains reachable",
            )),
            Err(error) => Err(error),
        }
    }

    pub fn remove_empty_dir(&self, name: &PhysicalComponent) -> io::Result<()> {
        self.remove_empty_dir_observed(name)
            .map_err(|failure| failure.error)
    }

    pub(crate) fn remove_empty_dir_observed(
        &self,
        name: &PhysicalComponent,
    ) -> Result<(), ExactDirectoryRemovalFailure> {
        #[cfg(windows)]
        {
            let cleanup = windows::open_private_directory_for_cleanup(&self.inner, name.as_path())
                .map_err(|error| ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::CleanupOpen,
                    error,
                })?;
            windows::delete_exact_directory(&cleanup).map_err(|error| {
                ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Disposition,
                    error,
                }
            })?;
            drop(cleanup);
            match self.open_dir_nofollow(name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.sync().map_err(|error| ExactDirectoryRemovalFailure {
                        stage: ExactDirectoryRemovalStage::Absence,
                        error,
                    })
                }
                Ok(_) => Err(ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Absence,
                    error: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "removed directory name remains reachable",
                    ),
                }),
                Err(error) => Err(ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Absence,
                    error,
                }),
            }
        }
        #[cfg(not(windows))]
        {
            self.inner.remove_dir(name.as_path()).map_err(|error| {
                ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Disposition,
                    error,
                }
            })?;
            self.sync().map_err(|error| ExactDirectoryRemovalFailure {
                stage: ExactDirectoryRemovalStage::Absence,
                error,
            })
        }
    }

    pub(crate) fn remove_empty_dir_if_matches_observed(
        &self,
        expected: &Directory,
        name: &PhysicalComponent,
    ) -> Result<(), ExactDirectoryRemovalFailure> {
        #[cfg(windows)]
        {
            let cleanup =
                match windows::open_private_directory_for_cleanup(&self.inner, name.as_path()) {
                    Ok(cleanup) => cleanup,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        expected.verify_private().map_err(|error| {
                            ExactDirectoryRemovalFailure {
                                stage: ExactDirectoryRemovalStage::Identity,
                                error,
                            }
                        })?;
                        return self.sync().map_err(|error| ExactDirectoryRemovalFailure {
                            stage: ExactDirectoryRemovalStage::Absence,
                            error,
                        });
                    }
                    Err(error) => {
                        return Err(ExactDirectoryRemovalFailure {
                            stage: ExactDirectoryRemovalStage::CleanupOpen,
                            error,
                        });
                    }
                };
            let cleanup_identity =
                identity(&cleanup).map_err(|error| ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Identity,
                    error,
                })?;
            if cleanup_identity != expected.final_identity() {
                return Err(ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Identity,
                    error: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory removal target identity changed",
                    ),
                });
            }
            windows::delete_exact_directory(&cleanup).map_err(|error| {
                ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Disposition,
                    error,
                }
            })?;
            drop(cleanup);
            match self.open_dir_nofollow(name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.sync().map_err(|error| ExactDirectoryRemovalFailure {
                        stage: ExactDirectoryRemovalStage::Absence,
                        error,
                    })
                }
                Ok(_) => Err(ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Absence,
                    error: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "removed directory name remains reachable",
                    ),
                }),
                Err(error) => Err(ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Absence,
                    error,
                }),
            }
        }
        #[cfg(not(windows))]
        {
            let named = match self.open_dir_nofollow(name) {
                Ok(named) => named,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    expected
                        .verify_private()
                        .map_err(|error| ExactDirectoryRemovalFailure {
                            stage: ExactDirectoryRemovalStage::Identity,
                            error,
                        })?;
                    return self.sync().map_err(|error| ExactDirectoryRemovalFailure {
                        stage: ExactDirectoryRemovalStage::Absence,
                        error,
                    });
                }
                Err(error) => {
                    return Err(ExactDirectoryRemovalFailure {
                        stage: ExactDirectoryRemovalStage::Identity,
                        error,
                    });
                }
            };
            if !expected
                .same_identity(&named)
                .map_err(|error| ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Identity,
                    error,
                })?
            {
                return Err(ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Identity,
                    error: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory removal target identity changed",
                    ),
                });
            }
            drop(named);
            self.inner.remove_dir(name.as_path()).map_err(|error| {
                ExactDirectoryRemovalFailure {
                    stage: ExactDirectoryRemovalStage::Disposition,
                    error,
                }
            })?;
            self.sync().map_err(|error| ExactDirectoryRemovalFailure {
                stage: ExactDirectoryRemovalStage::Absence,
                error,
            })
        }
    }

    pub fn remove_private_file_tree(
        &self,
        name: &PhysicalComponent,
        maximum_files: usize,
    ) -> io::Result<()> {
        let child = self.open_dir_nofollow(name)?;
        child.verify_private()?;
        let mut count = 0_usize;
        for entry in child.inner.read_dir(".")? {
            if count >= maximum_files {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owned transaction file limit exceeded",
                ));
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("owned transaction count overflow"))?;
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 physical name")
            })?;
            let entry = PhysicalComponent::try_new(name)?;
            if child.entry_kind(&entry)? != EntryKind::File {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owned transaction tree contains a non-file entry",
                ));
            }
            child.remove_untrusted_file_from_private_staging_unsynced(&entry)?;
        }
        child.sync()?;
        drop(child);
        #[cfg(windows)]
        return self.remove_empty_dir(name);
        #[cfg(not(windows))]
        {
            self.inner.remove_dir(name.as_path())?;
            self.sync()
        }
    }

    pub fn remove_opened_private_tree(
        &self,
        expected: &Self,
        name: &PhysicalComponent,
        maximum_entries: usize,
        maximum_depth: usize,
    ) -> io::Result<()> {
        if maximum_entries == 0 || maximum_depth == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private tree bounds must be nonzero",
            ));
        }
        self.remove_opened_private_tree_unsynced(expected, name, maximum_entries, maximum_depth)?;
        self.sync()
    }

    pub fn remove_opened_private_tree_unsynced(
        &self,
        expected: &Self,
        name: &PhysicalComponent,
        maximum_entries: usize,
        maximum_depth: usize,
    ) -> io::Result<()> {
        #[cfg(feature = "test-support")]
        if take_workspace_cleanup_fault(WorkspaceCleanupFault::TreeRemoveBeforeEffect) {
            return Err(io::Error::other("injected tree removal failure"));
        }
        if maximum_entries == 0 || maximum_depth == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private tree bounds must be nonzero",
            ));
        }
        expected
            .verify_private()
            .map_err(|error| operation_stage_error("private-tree expected validation", error))?;
        #[cfg(windows)]
        {
            let named =
                match windows::open_private_directory_for_cleanup(&self.inner, name.as_path()) {
                    Ok(named) => named,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                    Err(error) => {
                        return Err(operation_stage_error(
                            "private-tree initial name validation",
                            error,
                        ));
                    }
                };
            if identity(&named)? != expected.final_identity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private tree identity changed before removal",
                ));
            }
            drop(named);
        }
        #[cfg(not(windows))]
        {
            let named = match self.open_dir_nofollow(name) {
                Ok(named) => named,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            if !named.same_identity(expected)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private tree identity changed before removal",
                ));
            }
            drop(named);
        }
        let mut remaining = maximum_entries;
        remove_directory_contents_bounded(expected, &mut remaining, maximum_depth)
            .map_err(|error| operation_stage_error("private-tree recursive cleanup", error))?;
        #[cfg(not(windows))]
        {
            let named = self.open_dir_nofollow(name)?;
            if !named.same_identity(expected)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private tree identity changed before final removal",
                ));
            }
            drop(named);
        }
        #[cfg(windows)]
        {
            let cleanup = windows::open_private_directory_for_cleanup(&self.inner, name.as_path())
                .map_err(|error| {
                    windows::operation_stage_error("private-tree final cleanup open", error)
                })?;
            if identity(&cleanup)? != expected.final_identity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private tree identity changed before exact disposition",
                ));
            }
            windows::delete_exact_directory(&cleanup).map_err(|error| {
                windows::operation_stage_error("private-tree final exact disposition", error)
            })?;
            drop(cleanup);
        }
        #[cfg(not(windows))]
        self.inner.remove_dir(name.as_path())?;
        #[cfg(feature = "test-support")]
        if take_workspace_cleanup_fault(WorkspaceCleanupFault::TreeAbsenceReadbackAfterEffect) {
            return Err(io::Error::other(
                "injected private-tree absence readback failure",
            ));
        }
        match self.open_dir_nofollow(name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "removed private-tree name remains reachable",
            )),
            Err(error) => Err(operation_stage_error(
                "private-tree absence readback",
                error,
            )),
        }
    }

    pub fn remove_named_lock_unsynced(
        &self,
        lock: &ExclusiveFileLock,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        #[cfg(feature = "test-support")]
        if take_workspace_cleanup_fault(WorkspaceCleanupFault::OwnerUnlinkBeforeEffect) {
            return Err(io::Error::other("injected lock unlink failure"));
        }
        if !lock.validates_named_file(self, name)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "lock sidecar identity changed before removal",
            ));
        }
        #[cfg(windows)]
        return windows::delete_lock_file(&lock.file);
        #[cfg(not(windows))]
        self.inner.remove_file(name.as_path())
    }

    pub fn probe_capabilities(&self) -> io::Result<Capabilities> {
        let probe_name = random_probe_component()?;
        let probe = self.create_private_dir(&probe_name)?;
        let source_name = PhysicalComponent::try_new("source")?;
        let destination_name = PhysicalComponent::try_new("destination")?;
        let source_directory = probe.create_private_dir(&source_name)?;
        let destination_directory = probe.create_private_dir(&destination_name)?;
        let source = PhysicalComponent::try_new("source")?;
        let replacement = PhysicalComponent::try_new("replacement")?;
        let destination = PhysicalComponent::try_new("destination")?;
        let result = (|| {
            source_directory.create_file_new(&source)?.sync_all()?;
            source_directory.sync()?;
            let opened = source_directory.open_file_for_rename_nofollow(&source)?;
            source_directory
                .rename_opened_no_replace_from_private_staging(
                    &opened,
                    &source,
                    &destination_directory,
                    &destination,
                )
                .map_err(|error| operation_stage_error("capability probe no-replace", error))?;
            drop(opened);
            destination_directory.sync()?;
            source_directory.create_file_new(&replacement)?.sync_all()?;
            source_directory
                .replace_atomic_from_private_staging(
                    &replacement,
                    &destination_directory,
                    &destination,
                )
                .map_err(|error| operation_stage_error("capability probe replace", error))?;
            Ok(Capabilities {
                directory_sync: true,
                atomic_replace: true,
                no_replace_publication: true,
            })
        })();
        let cleanup_source = [&source, &replacement].into_iter().try_for_each(|name| {
            match source_directory.remove_file(name) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        });
        let cleanup_destination = match destination_directory.remove_file(&destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        let cleanup_files = cleanup_source
            .and(cleanup_destination)
            .and_then(|()| source_directory.sync())
            .and_then(|()| destination_directory.sync());
        drop(source_directory);
        drop(destination_directory);
        let cleanup_directories = cleanup_files
            .and_then(|()| probe.remove_empty_dir(&source_name))
            .and_then(|()| probe.remove_empty_dir(&destination_name));
        drop(probe);
        let cleanup = cleanup_directories.and_then(|()| self.remove_empty_dir(&probe_name));
        cleanup?;
        result.map(|_| Capabilities {
            directory_sync: true,
            atomic_replace: true,
            no_replace_publication: true,
        })
    }
}

#[cfg(windows)]
fn lock_open_is_contended(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(32 | 33))
}

#[cfg(not(windows))]
fn lock_open_is_contended(_error: &io::Error) -> bool {
    false
}

fn operation_stage_error(stage: &'static str, error: io::Error) -> io::Error {
    #[cfg(windows)]
    return windows::operation_stage_error(stage, error);
    #[cfg(not(windows))]
    {
        let _ = stage;
        error
    }
}

fn remove_directory_contents_bounded(
    directory: &Directory,
    remaining: &mut usize,
    depth: usize,
) -> io::Result<()> {
    if depth == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private tree depth limit exceeded",
        ));
    }
    let entries = directory
        .inner
        .read_dir(".")
        .map_err(|error| operation_stage_error("private-tree enumeration open", error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| operation_stage_error("private-tree enumeration next", error))?;
        let name = entry.file_name();
        *remaining = remaining.checked_sub(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "private tree entry limit exceeded",
            )
        })?;
        let path = Path::new(&name);
        validate_workspace_component(path)?;
        let metadata = directory
            .inner
            .symlink_metadata(path)
            .map_err(|error| operation_stage_error("private-tree entry metadata", error))?;
        let kind = if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "symbolic links are rejected",
            ));
        } else if metadata.file_type().is_file() {
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hard-linked files are rejected",
                ));
            }
            EntryKind::File
        } else if metadata.file_type().is_dir() {
            EntryKind::Directory
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "special filesystem objects are rejected",
            ));
        };
        match kind {
            EntryKind::File => {
                let opened = directory.open_file_nofollow_path(path).map_err(|error| {
                    operation_stage_error("private-tree file retained open", error)
                })?;
                #[cfg(feature = "test-support")]
                run_private_tree_file_cleanup_hook();
                #[cfg(windows)]
                {
                    directory
                        .remove_opened_file_exact_windows(
                            &opened,
                            path,
                            false,
                            InitialFileAbsence::RejectBeforeEffect,
                        )
                        .map_err(|error| {
                            windows::operation_stage_error("private-tree file exact cleanup", error)
                        })?;
                    drop(opened);
                }
                #[cfg(not(windows))]
                {
                    let named = directory.open_file_nofollow_path(path).map_err(|error| {
                        operation_stage_error("private-tree file identity reopen", error)
                    })?;
                    if !opened.same_file(&named)? {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "file identity changed before removal",
                        ));
                    }
                    drop(named);
                    directory.inner.remove_file(path)?;
                    ensure_file_name_absent(directory, path)?;
                }
            }
            EntryKind::Directory => {
                #[cfg(windows)]
                let rename_name = windows::prepare_rename_target_name(path)?;
                #[cfg(windows)]
                let inner = windows::open_directory(&directory.inner, path).map_err(|error| {
                    windows::operation_stage_error("private-tree nested retained open", error)
                })?;
                #[cfg(not(windows))]
                let inner = directory.inner.open_dir_nofollow(path)?;
                let mut identity_chain = try_copy_identity_chain(&directory.identity_chain)
                    .map_err(|error| {
                        operation_stage_error("private-tree child identity reservation", error)
                    })?;
                let child_identity = identity(&inner).map_err(|error| {
                    operation_stage_error("private-tree child identity readback", error)
                })?;
                try_push_identity(&mut identity_chain, child_identity).map_err(|error| {
                    operation_stage_error("private-tree child identity append", error)
                })?;
                #[cfg(windows)]
                let rename_target = windows::open_child_rename_target(
                    &directory.rename_target,
                    &rename_name,
                    &inner,
                )
                .map_err(|error| {
                    windows::operation_stage_error("private-tree child rename-target open", error)
                })?;
                let child = new_directory(
                    inner,
                    identity_chain,
                    #[cfg(windows)]
                    rename_target,
                );
                if !directory.same_filesystem(&child).map_err(|error| {
                    operation_stage_error("private-tree child mount validation", error)
                })? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "private tree crosses a filesystem boundary",
                    ));
                }
                child.verify_private().map_err(|error| {
                    operation_stage_error("private-tree child private validation", error)
                })?;
                remove_directory_contents_bounded(&child, remaining, depth - 1).map_err(
                    |error| operation_stage_error("private-tree child recursion", error),
                )?;
                #[cfg(windows)]
                let named_inner =
                    windows::open_private_directory_for_cleanup(&directory.inner, path).map_err(
                        |error| {
                            windows::operation_stage_error(
                                "private-tree nested final name validation",
                                error,
                            )
                        },
                    )?;
                #[cfg(not(windows))]
                let named_inner = directory.inner.open_dir_nofollow(path)?;
                if identity(&named_inner)? != child.final_identity() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "nested directory identity changed before removal",
                    ));
                }
                drop(named_inner);
                #[cfg(windows)]
                {
                    drop(child);
                    let cleanup =
                        windows::open_private_directory_for_cleanup(&directory.inner, path)
                            .map_err(|error| {
                                windows::operation_stage_error(
                                    "private-tree nested exact cleanup open",
                                    error,
                                )
                            })?;
                    if identity(&cleanup)? != child_identity {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "nested directory identity changed before exact disposition",
                        ));
                    }
                    windows::delete_exact_directory(&cleanup).map_err(|error| {
                        windows::operation_stage_error(
                            "private-tree nested exact disposition",
                            error,
                        )
                    })?;
                    drop(cleanup);
                }
                #[cfg(not(windows))]
                directory.inner.remove_dir(path)?;
                ensure_directory_name_absent(directory, path)?;
            }
        }
    }
    directory.sync()
}

#[cfg(not(windows))]
fn ensure_file_name_absent(directory: &Directory, path: &Path) -> io::Result<()> {
    match directory.open_file_nofollow_path(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "removed file name remains reachable",
        )),
        Err(error) => Err(error),
    }
}

fn ensure_directory_name_absent(directory: &Directory, path: &Path) -> io::Result<()> {
    match directory.inner.open_dir_nofollow(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "removed directory name remains reachable",
        )),
        Err(error) => Err(error),
    }
}

fn validate_workspace_component(path: &Path) -> io::Result<()> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace name is not a normal component",
        ));
    };
    if components.next().is_some() || name.is_empty() || name.as_encoded_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace name is invalid",
        ));
    }
    #[cfg(windows)]
    {
        let text = name.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "workspace name is not UTF-8")
        })?;
        let trimmed = text.trim_end_matches(['.', ' ']);
        let base = trimmed.split('.').next().unwrap_or_default();
        let lower = base.to_ascii_lowercase();
        let numbered = |prefix: &str| {
            lower.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        };
        if trimmed != text
            || text.contains(':')
            || matches!(lower.as_str(), "con" | "prn" | "aux" | "nul")
            || numbered("com")
            || numbered("lpt")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace name is reserved",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_unix_executable(
    path: &Path,
    require_platform_trust: bool,
) -> io::Result<(std::fs::File, FileIdentity)> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable path is not absolute",
        ));
    }
    if require_platform_trust {
        for ancestor in path.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "executable ownership chain is not trusted",
                ));
            }
            let opened = std::fs::File::open(ancestor)?;
            verify_no_non_owner_acl(&opened)?;
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusted executable is not a regular executable file",
        ));
    }
    Ok((file, file_identity_from_metadata(&metadata)))
}

#[cfg(unix)]
fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: std::os::unix::fs::MetadataExt::dev(metadata),
        inode: std::os::unix::fs::MetadataExt::ino(metadata),
    }
}

#[cfg(target_vendor = "apple")]
fn verify_no_non_owner_acl(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    apple_acl::verify_no_extended_acl_raw(file.as_raw_fd())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
fn verify_no_non_owner_acl(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let mut names = [0_u8; 4_096];
    // SAFETY: names is writable for its exact fixed capacity and file owns a live descriptor.
    let length =
        unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::other("extended attribute length overflowed"))?;
    if length > names.len() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable extended attributes exceed the trust bound",
        ));
    }
    if names[..length].split(|byte| *byte == 0).any(|name| {
        matches!(
            name,
            b"system.posix_acl_access" | b"system.posix_acl_default"
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable ownership chain has an extended ACL",
        ));
    }
    Ok(())
}

fn identity(directory: &Dir) -> io::Result<FileIdentity> {
    let metadata = directory.dir_metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn same_mount_instance(left: &Dir, right: &Dir) -> io::Result<bool> {
    #[cfg(feature = "test-support")]
    if take_workspace_directory_fault(WorkspaceDirectoryFault::MountBoundary) {
        return Ok(false);
    }
    platform_same_mount_instance(left, right)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_same_mount_instance(left: &Dir, right: &Dir) -> io::Result<bool> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    let left = statx(left, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    let right = statx(right, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if left.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || right.stx_mask & StatxFlags::MNT_ID.bits() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mount identity is unavailable",
        ));
    }
    Ok(left.stx_mnt_id == right.stx_mnt_id)
}

#[cfg(target_vendor = "apple")]
fn platform_same_mount_instance(left: &Dir, right: &Dir) -> io::Result<bool> {
    let left = rustix::fs::fstatfs(left)?;
    let right = rustix::fs::fstatfs(right)?;
    Ok(left.f_mntonname == right.f_mntonname)
}

#[cfg(windows)]
fn platform_same_mount_instance(left: &Dir, right: &Dir) -> io::Result<bool> {
    if windows::directory_is_reparse(right)? {
        return Ok(false);
    }
    let left = identity(left)?;
    let right = identity(right)?;
    Ok(left.device == right.device)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
fn platform_same_mount_instance(_left: &Dir, _right: &Dir) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "mount identity is unavailable on this platform",
    ))
}

fn try_copy_identity_chain(source: &[FileIdentity]) -> io::Result<Vec<FileIdentity>> {
    try_copy_identity_chain_with_capacity(source, 0)
}

fn try_copy_identity_chain_with_capacity(
    source: &[FileIdentity],
    additional: usize,
) -> io::Result<Vec<FileIdentity>> {
    if source.len() > MAX_CAPABILITY_IDENTITIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability path depth exceeded",
        ));
    }
    let mut retained = Vec::new();
    let capacity = source
        .len()
        .checked_add(additional)
        .ok_or_else(|| io::Error::other("capability identity capacity overflowed"))?;
    if capacity > MAX_CAPABILITY_IDENTITIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability path depth exceeded",
        ));
    }
    retained
        .try_reserve_exact(capacity)
        .map_err(|_| allocation_error("capability identity allocation failed"))?;
    retained.extend_from_slice(source);
    Ok(retained)
}

fn try_push_identity(chain: &mut Vec<FileIdentity>, value: FileIdentity) -> io::Result<()> {
    if chain.len() == MAX_CAPABILITY_IDENTITIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability path depth exceeded",
        ));
    }
    chain
        .try_reserve(1)
        .map_err(|_| allocation_error("capability identity allocation failed"))?;
    chain.push(value);
    Ok(())
}

fn split_absolute(path: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > MAX_CAPABILITY_PATH_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem roots must be absolute",
        ));
    }
    let mut platform_root = PathBuf::new();
    let mut names = Vec::new();
    names
        .try_reserve(MAX_CAPABILITY_COMPONENTS)
        .map_err(|_| allocation_error("capability path allocation failed"))?;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if names.is_empty() => platform_root.push(prefix.as_os_str()),
            Component::RootDir if names.is_empty() => platform_root.push(component.as_os_str()),
            Component::Normal(name) if names.len() < MAX_CAPABILITY_COMPONENTS => {
                let mut retained = OsString::new();
                retained
                    .try_reserve_exact(name.as_encoded_bytes().len())
                    .map_err(|_| allocation_error("capability component allocation failed"))?;
                retained.push(name);
                names.push(retained);
            }
            Component::Normal(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "capability path depth exceeded",
                ));
            }
            Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_)
            | Component::RootDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "filesystem root contains a special component",
                ));
            }
        }
    }
    if platform_root.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem root has no platform root",
        ));
    }
    Ok((platform_root, names))
}

fn random_probe_component() -> io::Result<PhysicalComponent> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
    let mut value = String::new();
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(io::Error::other)?;
    }
    PhysicalComponent::try_new(&value)
}

struct NoReplaceFailure {
    primary: io::Error,
    destination_may_be_visible: bool,
}

#[cfg(all(feature = "test-support", unix))]
fn injected_workspace_publication_failure(
    destination_directory: &Dir,
    destination: &Path,
) -> Option<NoReplaceFailure> {
    match take_workspace_publication_fault()? {
        WorkspacePublicationFault::PublishedWithRetainedStage => Some(NoReplaceFailure {
            primary: io::Error::other("injected ambiguous publication with retained stage"),
            destination_may_be_visible: true,
        }),
        WorkspacePublicationFault::PublishedThenDestinationAbsent => {
            let _ = destination_directory.remove_file(destination);
            let _ = sync_directory_handle(destination_directory);
            Some(NoReplaceFailure {
                primary: io::Error::other("injected ambiguous publication with absent destination"),
                destination_may_be_visible: true,
            })
        }
    }
}

#[cfg(all(feature = "test-support", windows))]
fn injected_workspace_publication_failure_after_move() -> Option<NoReplaceFailure> {
    match take_workspace_publication_fault()? {
        WorkspacePublicationFault::PublishedAfterMove => Some(NoReplaceFailure {
            primary: io::Error::other("injected ambiguous publication after exact Windows move"),
            destination_may_be_visible: true,
        }),
    }
}

fn workspace_not_published(primary: io::Error) -> WorkspacePublishAttemptError {
    WorkspacePublishAttemptError {
        primary,
        effect: WorkspacePublicationEffect::NotPublished,
    }
}

fn workspace_published_unverified(primary: io::Error) -> WorkspacePublishAttemptError {
    WorkspacePublishAttemptError {
        primary,
        effect: WorkspacePublicationEffect::PublishedUnverified,
    }
}

#[cfg(unix)]
fn finish_linked_publication_after_source_remove_failure(
    primary: io::Error,
    rollback: io::Result<()>,
    rollback_sync: io::Result<()>,
) -> NoReplaceFailure {
    match (rollback, rollback_sync) {
        (Ok(()), Ok(())) => NoReplaceFailure {
            primary,
            destination_may_be_visible: false,
        },
        (Err(cleanup), _) | (_, Err(cleanup)) => NoReplaceFailure {
            primary: io::Error::other(format!(
                "publication failed and destination rollback is unproven: {primary}; {cleanup}"
            )),
            destination_may_be_visible: true,
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_no_replace_observed(
    source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> Result<(), NoReplaceFailure> {
    use std::os::fd::AsRawFd as _;

    // `AT_EMPTY_PATH` requires CAP_DAC_READ_SEARCH and therefore cannot be
    // used by an ordinary desktop process. Linking through procfs preserves
    // exact ownership of the already-authenticated descriptor without adding
    // that capability requirement. Initialization probes this exact operation
    // and fails closed when procfs or the target filesystem cannot provide it.
    let proc_file = PathBuf::from(format!("/proc/self/fd/{}", source_file.inner.as_raw_fd()));
    rustix::fs::linkat(
        rustix::fs::CWD,
        &proc_file,
        &destination_directory.inner,
        destination,
        rustix::fs::AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(io::Error::from)
    .map_err(|primary| NoReplaceFailure {
        primary,
        destination_may_be_visible: false,
    })?;
    #[cfg(feature = "test-support")]
    if let Some(failure) =
        injected_workspace_publication_failure(&destination_directory.inner, destination)
    {
        return Err(failure);
    }
    if let Err(primary) = source_directory.remove_file(source) {
        let rollback = destination_directory.inner.remove_file(destination);
        let rollback_sync = sync_directory_handle(&destination_directory.inner);
        return Err(finish_linked_publication_after_source_remove_failure(
            primary,
            rollback,
            rollback_sync,
        ));
    }
    Ok(())
}

#[cfg(not(target_vendor = "apple"))]
fn published_matches_exact_source(
    source: &FileCapability,
    published: &FileCapability,
) -> io::Result<bool> {
    source.same_file(published)
}

#[cfg(target_vendor = "apple")]
fn published_matches_exact_source(
    source: &FileCapability,
    published: &FileCapability,
) -> io::Result<bool> {
    let length = source.len()?;
    if length != published.len()? {
        return Ok(false);
    }
    let mut source = source.try_clone()?;
    let mut published = published.try_clone()?;
    source.rewind()?;
    published.rewind()?;
    let mut remaining = length;
    let mut source_buffer = [0_u8; 64 * 1024];
    let mut published_buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(source_buffer.len() as u64))
            .map_err(|_| io::Error::other("workspace comparison length overflowed"))?;
        source.read_exact(&mut source_buffer[..count])?;
        published.read_exact(&mut published_buffer[..count])?;
        if source_buffer[..count] != published_buffer[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    Ok(true)
}

#[cfg(target_vendor = "apple")]
fn rename_no_replace_observed(
    source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> Result<(), NoReplaceFailure> {
    rustix::fs::fclonefileat(
        &source_file.inner,
        &destination_directory.inner,
        destination,
        rustix::fs::CloneFlags::empty(),
    )
    .map_err(io::Error::from)
    .map_err(|primary| NoReplaceFailure {
        primary,
        destination_may_be_visible: false,
    })?;
    #[cfg(feature = "test-support")]
    if let Some(failure) =
        injected_workspace_publication_failure(&destination_directory.inner, destination)
    {
        return Err(failure);
    }
    if let Err(primary) = source_directory.remove_file(source) {
        let rollback = destination_directory.inner.remove_file(destination);
        let rollback_sync = sync_directory_handle(&destination_directory.inner);
        return Err(finish_linked_publication_after_source_remove_failure(
            primary,
            rollback,
            rollback_sync,
        ));
    }
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn rename_no_replace_observed(
    _source_file: &FileCapability,
    _source_directory: &Dir,
    _source: &Path,
    _destination_directory: &Directory,
    _destination: &Path,
) -> Result<(), NoReplaceFailure> {
    Err(NoReplaceFailure {
        primary: io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is unavailable",
        ),
        destination_may_be_visible: false,
    })
}

#[cfg(windows)]
fn rename_no_replace_observed(
    source_file: &FileCapability,
    _source_directory: &Dir,
    _source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> Result<(), NoReplaceFailure> {
    windows::rename_by_handle(
        source_file,
        &destination_directory.rename_target,
        destination,
        false,
    )
    .map_err(|primary| NoReplaceFailure {
        primary,
        destination_may_be_visible: false,
    })?;
    #[cfg(feature = "test-support")]
    if let Some(failure) = injected_workspace_publication_failure_after_move() {
        return Err(failure);
    }
    Ok(())
}

fn rename_no_replace(
    source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> io::Result<()> {
    rename_no_replace_observed(
        source_file,
        source_directory,
        source,
        destination_directory,
        destination,
    )
    .map_err(|failure| failure.primary)
}

#[cfg(windows)]
fn rename_replace(
    source_file: &FileCapability,
    _source_directory: &Dir,
    _source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> io::Result<()> {
    windows::rename_by_handle(
        source_file,
        &destination_directory.rename_target,
        destination,
        true,
    )
}

#[cfg(not(windows))]
fn rename_replace(
    _source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> io::Result<()> {
    source_directory.rename(source, &destination_directory.inner, destination)
}

#[cfg(not(windows))]
fn prepare_private_directory(directory: &Directory) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::fs::fchmod(
        &reopen_linux_directory(&directory.inner)?,
        rustix::fs::Mode::from_bits_retain(0o700),
    )?;
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    rustix::fs::fchmod(&directory.inner, rustix::fs::Mode::from_bits_retain(0o700))?;
    #[cfg(target_vendor = "apple")]
    apple_acl::clear_extended_acl_directory(&directory.inner)?;
    directory.verify_private()
}

#[cfg(windows)]
fn fail_windows_created_directory<T>(
    parent: &Dir,
    rollback: Dir,
    name: &Path,
    primary: io::Error,
) -> io::Result<T> {
    match windows::discard_created_directory(parent, rollback, name) {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(io::Error::other(format!(
            "directory initialization failed: {primary}; exact rollback failed: {cleanup}"
        ))),
    }
}

#[cfg(windows)]
fn fail_optional_windows_created_directory<T>(
    parent: &Dir,
    rollback: Option<Dir>,
    name: &Path,
    primary: io::Error,
) -> io::Result<T> {
    match rollback {
        Some(rollback) => fail_windows_created_directory(parent, rollback, name, primary),
        None => Err(primary),
    }
}

#[cfg(windows)]
fn fail_optional_windows_created_directory_capability<T>(
    parent: &Directory,
    directory: Directory,
    rollback: Option<Dir>,
    name: &Path,
    primary: io::Error,
) -> io::Result<T> {
    drop(directory);
    fail_optional_windows_created_directory(&parent.inner, rollback, name, primary)
}

#[cfg(not(windows))]
fn fail_created_private_directory<T>(
    parent: &Dir,
    directory: Dir,
    name: &Path,
    created: bool,
    primary: io::Error,
) -> io::Result<T> {
    let _ = (parent, directory, name, created);
    Err(primary)
}

#[cfg(not(windows))]
fn fail_created_private_directory_capability<T>(
    parent: &Directory,
    directory: Directory,
    name: &Path,
    created: bool,
    primary: io::Error,
) -> io::Result<T> {
    fail_created_private_directory(&parent.inner, directory.inner, name, created, primary)
}

fn sync_directory_handle(directory: &Dir) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        rustix::fs::fsync(&reopen_linux_directory(directory)?).map_err(io::Error::from)
    }
    #[cfg(windows)]
    {
        windows::sync_directory(directory)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    {
        directory.try_clone()?.into_std_file().sync_all()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn reopen_linux_directory(directory: &Dir) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsFd as _;

    rustix::fs::openat(
        directory.as_fd(),
        Path::new("."),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)
}

fn prepare_private_file(file: &FileCapability) -> io::Result<()> {
    #[cfg(unix)]
    {
        rustix::fs::fchmod(&file.inner, rustix::fs::Mode::from_bits_retain(0o600))?;
        #[cfg(target_vendor = "apple")]
        apple_acl::clear_extended_acl_file(&file.inner)?;
    }
    verify_private_file(file)
}

#[cfg(windows)]
fn configure_lock_file_open_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    options
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_WRITE_THROUGH);
}

#[cfg(windows)]
fn configure_rename_file_open_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    options
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_WRITE_THROUGH);
}

fn verify_private_file(file: &FileCapability) -> io::Result<()> {
    #[cfg(unix)]
    {
        let metadata = file.inner.metadata()?;
        if metadata.permissions().mode() & 0o077 != 0
            || cap_fs_ext::OsMetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not private to the effective user",
            ));
        }
        #[cfg(target_vendor = "apple")]
        apple_acl::verify_no_extended_acl_file(&file.inner)?;
    }
    #[cfg(windows)]
    windows::verify_private_file(file)?;
    Ok(())
}

#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod apple_acl {
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::os::fd::AsRawFd as _;

    use cap_std::fs::{Dir, File};

    type Acl = *mut c_void;
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;

    unsafe extern "C" {
        fn acl_init(count: c_int) -> Acl;
        fn acl_free(value: *mut c_void) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> Acl;
        fn acl_set_fd_np(fd: c_int, acl: Acl, acl_type: c_int) -> c_int;
        fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    }

    struct OwnedAcl(Acl);

    impl Drop for OwnedAcl {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this allocation was returned by an ACL API and this guard owns it.
                unsafe {
                    acl_free(self.0);
                }
            }
        }
    }

    pub(super) fn clear_extended_acl_directory(directory: &Dir) -> io::Result<()> {
        clear(directory.as_raw_fd())
    }

    pub(super) fn clear_extended_acl_file(file: &File) -> io::Result<()> {
        clear(file.as_raw_fd())
    }

    pub(super) fn verify_no_extended_acl_directory(directory: &Dir) -> io::Result<()> {
        verify_empty(directory.as_raw_fd())
    }

    pub(super) fn verify_no_extended_acl_file(file: &File) -> io::Result<()> {
        verify_empty(file.as_raw_fd())
    }

    pub(super) fn verify_no_extended_acl_raw(fd: c_int) -> io::Result<()> {
        verify_empty(fd)
    }

    fn clear(fd: c_int) -> io::Result<()> {
        // SAFETY: acl_init returns an owned ACL object or null and does not alias Rust memory.
        let acl = OwnedAcl(unsafe { acl_init(0) });
        if acl.0.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is live and acl is a valid empty extended ACL for the duration of the call.
        if unsafe { acl_set_fd_np(fd, acl.0, ACL_TYPE_EXTENDED) } != 0 {
            return Err(io::Error::last_os_error());
        }
        verify_empty(fd)
    }

    fn verify_empty(fd: c_int) -> io::Result<()> {
        // SAFETY: fd is live and the returned ACL is owned by the caller.
        let acl = OwnedAcl(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) });
        if acl.0.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(2) {
                return Ok(());
            }
            return Err(error);
        }
        let mut entry = std::ptr::null_mut();
        // SAFETY: acl is live and entry is a valid output pointer.
        match unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) } {
            0 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "extended ACL grants are not private",
            )),
            _ => {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(22) {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::ffi::c_void;
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::CommandExt as _;
    use std::process::{Child, Command, Stdio};

    use cap_fs_ext::{DirExt as _, OpenOptionsFollowExt as _};
    use cap_std::fs::{Dir, File};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_ACCESS_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_MODE_INFORMATION,
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
        FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_WRITE_THROUGH, FileAccessInformation, FileModeInformation, FileRenameInformation,
        FileRenameInformationEx, NtCreateFile, NtQueryInformationFile, NtSetInformationFile,
        RtlNtStatusToDosErrorNoTeb,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER,
        ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
        OBJ_CASE_INSENSITIVE, STATUS_SUCCESS, UNICODE_STRING,
    };
    #[cfg(feature = "test-support")]
    use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
        SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorLength, GetTokenInformation, INHERIT_ONLY_ACE,
        InitializeSecurityDescriptor, IsValidAcl, IsValidSecurityDescriptor, IsValidSid,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SE_DACL_PROTECTED, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    #[cfg(feature = "test-support")]
    use windows_sys::Win32::Security::{
        PROTECTED_DACL_SECURITY_INFORMATION, WinAuthenticatedUserSid, WinBuiltinAnyPackageSid,
        WinBuiltinUsersSid, WinCreatorOwnerSid, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DELETE_CHILD, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfoEx,
        GetDiskFreeSpaceExW, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        SYNCHRONIZE, SetFileInformationByHandle, UnlockFileEx, VOLUME_NAME_DOS, WRITE_DAC,
        WRITE_OWNER,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    #[cfg(feature = "benchmark-support")]
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    #[cfg(feature = "benchmark-support")]
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, GetCurrentProcess, GetProcessIdOfThread, OpenProcessToken, OpenThread,
        ResumeThread, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};

    use super::{FileCapability, FileIdentity, SupervisedProcessState, allocation_error};

    const ACCESS_ALLOWED_ACE_KIND: u8 = 0;
    const ACCESS_DENIED_ACE_KIND: u8 = 1;
    const SYSTEM_MANDATORY_LABEL_ACE_KIND: u8 = 17;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const RETAINED_DIRECTORY_ACCESS: u32 = READ_CONTROL_ACCESS
        | SYNCHRONIZE
        | FILE_LIST_DIRECTORY
        | FILE_ADD_FILE
        | FILE_ADD_SUBDIRECTORY
        | FILE_DELETE_CHILD
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | FILE_READ_EA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES;
    const PRIVATE_FILE_SYNC_ACCESS: u32 = FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES;

    #[derive(Clone, Copy)]
    enum TrustedExecutableAclStage {
        WindowsRoot,
        System32OrInstall,
        Executable,
    }

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was returned by a Windows API documented to require
                // `LocalFree`, and this guard owns the only cleanup of that allocation.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    struct KernelHandle(OwnedHandle);

    impl KernelHandle {
        fn from_raw(raw: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Self> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: callers pass a newly acquired successful Win32 handle exactly once. The
            // resulting OwnedHandle supplies both RAII cleanup and the required Send ownership.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw.cast()) }))
        }

        fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
            self.0.as_raw_handle().cast()
        }
    }

    pub(super) fn system_editor_candidate(
        name: &std::ffi::OsStr,
    ) -> io::Result<std::path::PathBuf> {
        let path = std::path::Path::new(name);
        if path.components().count() != 1 || name.as_encoded_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "system editor name is invalid",
            ));
        }
        let normalized = name.to_string_lossy().to_ascii_lowercase();
        let normalized = normalized.strip_suffix(".exe").unwrap_or(&normalized);
        match normalized {
            "notepad" => Ok(windows_directory()?.join("System32").join("notepad.exe")),
            "notepad++" => Ok(program_files_directory()?
                .join("Notepad++")
                .join("notepad++.exe")),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "editor has no protected Windows installation root",
            )),
        }
    }

    pub(super) fn open_trusted_executable(
        path: &std::path::Path,
        production_trusted: bool,
    ) -> io::Result<(std::fs::File, FileIdentity)> {
        #[cfg(feature = "test-support")]
        super::TRUSTED_EXECUTABLE_ACL_DIAGNOSTIC.set(None);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable path is not absolute",
            ));
        }
        if !production_trusted {
            let canonical = std::fs::canonicalize(path)?;
            let file = open_no_reparse(&canonical, false)?;
            return file_identity(&file).map(|identity| (file, identity));
        }

        let file_name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing executable"))?;
        let normalized = file_name.to_ascii_lowercase();
        let normalized = normalized.strip_suffix(".exe").unwrap_or(&normalized);
        let (root_path, installation_path, expected) = match normalized {
            "notepad" => {
                let root = windows_directory()?;
                let installation = root.join("System32");
                let expected = installation.join("notepad.exe");
                (root, installation, expected)
            }
            "notepad++" => {
                let root = program_files_directory()?;
                let installation = root.join("Notepad++");
                let expected = installation.join("notepad++.exe");
                (root, installation, expected)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "editor has no approved Windows profile root",
                ));
            }
        };
        if !paths_equal_case_insensitive(path, &expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable is outside the protected system editor root",
            ));
        }

        let root = open_no_reparse(&root_path, true)?;
        let installation = open_no_reparse(&installation_path, true)?;
        let file = open_no_reparse(path, false)?;
        for (opened, directory, stage) in [
            (&root, true, TrustedExecutableAclStage::WindowsRoot),
            (
                &installation,
                true,
                TrustedExecutableAclStage::System32OrInstall,
            ),
            (&file, false, TrustedExecutableAclStage::Executable),
        ] {
            verify_trusted_executable_acl(opened, directory, stage)?;
        }
        let root_final = final_path(&root)?;
        let installation_final = final_path(&installation)?;
        let file_final = final_path(&file)?;
        if !path_is_direct_child(&root_final, &installation_final)
            || !path_is_direct_child(&installation_final, &file_final)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable handle ancestry is outside the protected system root",
            ));
        }
        let identity = file_identity(&file)?;
        Ok((file, identity))
    }

    pub(super) fn file_identity(file: &std::fs::File) -> io::Result<FileIdentity> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns a live exact handle and information is a valid output structure.
        if unsafe {
            GetFileInformationByHandle(
                file.as_raw_handle().cast(),
                std::ptr::addr_of_mut!(information),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity {
            device: u64::from(information.dwVolumeSerialNumber),
            inode: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }

    fn windows_directory() -> io::Result<std::path::PathBuf> {
        const MAX_WINDOWS_PATH: usize = 32_768;
        let mut buffer = [0_u16; MAX_WINDOWS_PATH];
        // SAFETY: buffer is writable for its complete declared UTF-16 capacity.
        let written = unsafe {
            GetWindowsDirectoryW(
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len())
                    .map_err(|_| io::Error::other("Windows path capacity overflowed"))?,
            )
        };
        let written = usize::try_from(written)
            .map_err(|_| io::Error::other("Windows path length overflowed"))?;
        if written == 0 || written >= buffer.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            &buffer[..written],
        )))
    }

    fn program_files_directory() -> io::Result<std::path::PathBuf> {
        let mut path = std::ptr::null_mut();
        // SAFETY: the known-folder identifier is static, null token requests the current process
        // view, and path is a valid output pointer for the CoTaskMem-owned result.
        let folder_id = FOLDERID_ProgramFiles;
        let status = unsafe {
            SHGetKnownFolderPath(
                std::ptr::addr_of!(folder_id),
                0,
                std::ptr::null_mut(),
                &mut path,
            )
        };
        if status < 0 || path.is_null() {
            return Err(io::Error::from_raw_os_error(status));
        }
        struct KnownFolderPath(*mut u16);
        impl Drop for KnownFolderPath {
            fn drop(&mut self) {
                // SAFETY: this guard owns the path returned by SHGetKnownFolderPath.
                unsafe { CoTaskMemFree(self.0.cast()) };
            }
        }
        let path = KnownFolderPath(path);
        let mut length = 0_usize;
        while length < 32_768 {
            // SAFETY: SHGetKnownFolderPath returns a NUL-terminated live UTF-16 allocation.
            if unsafe { *path.0.add(length) } == 0 {
                break;
            }
            length += 1;
        }
        if length == 32_768 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Program Files path is not bounded",
            ));
        }
        // SAFETY: the scan proved length readable UTF-16 units before the terminator.
        let value = unsafe { std::slice::from_raw_parts(path.0, length) };
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            value,
        )))
    }

    fn open_no_reparse(path: &std::path::Path, directory: bool) -> io::Result<std::fs::File> {
        const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(READ_CONTROL_ACCESS | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            );
        let file = options.open(path)?;
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let bytes = u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
            .map_err(|_| io::Error::other("file attribute size overflowed"))?;
        // SAFETY: file owns a live handle and attributes is writable for its exact size.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FileAttributeTagInfo,
                std::ptr::addr_of_mut!(attributes).cast(),
                bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || file.metadata()?.is_dir() != directory
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted executable chain contains a reparse point or wrong object type",
            ));
        }
        Ok(file)
    }

    fn final_path(file: &std::fs::File) -> io::Result<std::path::PathBuf> {
        final_path_bounded(file, "final executable")
    }

    fn final_path_bounded(
        file: &std::fs::File,
        object_kind: &'static str,
    ) -> io::Result<std::path::PathBuf> {
        const MAX_WINDOWS_PATH_UTF16: usize = 32_768;
        let handle = file.as_raw_handle().cast();
        // SAFETY: handle is live and the null query is the documented size request.
        let required =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_DOS) };
        if required == 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "{object_kind} path size query failed: win32={}",
                    error.raw_os_error().unwrap_or_default()
                ),
            ));
        }
        let capacity = usize::try_from(required)
            .ok()
            .and_then(|value| value.checked_add(1))
            .filter(|capacity| *capacity <= MAX_WINDOWS_PATH_UTF16)
            .ok_or_else(|| io::Error::other(format!("{object_kind} path exceeds its bound")))?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| allocation_error("final handle path allocation failed"))?;
        buffer.resize(capacity, 0_u16);
        // SAFETY: buffer is writable for capacity UTF-16 units and handle remains live.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buffer.as_mut_ptr(),
                u32::try_from(capacity)
                    .map_err(|_| io::Error::other("final handle path capacity overflowed"))?,
                VOLUME_NAME_DOS,
            )
        };
        let written = usize::try_from(written)
            .map_err(|_| io::Error::other("final handle path length overflowed"))?;
        if written == 0 || written >= capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{object_kind} path changed during lookup"),
            ));
        }
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            &buffer[..written],
        )))
    }

    fn paths_equal_case_insensitive(left: &std::path::Path, right: &std::path::Path) -> bool {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }

    fn path_is_direct_child(parent: &std::path::Path, child: &std::path::Path) -> bool {
        child
            .parent()
            .is_some_and(|candidate| paths_equal_case_insensitive(parent, candidate))
    }

    fn verify_trusted_executable_acl(
        file: &std::fs::File,
        directory: bool,
        _stage: TrustedExecutableAclStage,
    ) -> io::Result<()> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: all outputs are valid and the exact file handle remains live for the call.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        let descriptor_guard = LocalAllocation(descriptor.cast());
        if owner.is_null() || acl.is_null() || descriptor.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted executable has no owner or DACL",
            ));
        }
        // SAFETY: descriptor is the complete live self-relative descriptor returned above.
        let descriptor_length = usize::try_from(unsafe { GetSecurityDescriptorLength(descriptor) })
            .map_err(|_| io::Error::other("security descriptor length overflowed"))?;
        let descriptor_start = descriptor as usize;
        let descriptor_end = descriptor_start
            .checked_add(descriptor_length)
            .ok_or_else(|| io::Error::other("security descriptor range overflowed"))?;
        let owner_start = owner as usize;
        if owner_start < descriptor_start || owner_start >= descriptor_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trusted executable owner is outside its descriptor",
            ));
        }
        validate_bounded_sid(
            owner,
            descriptor_end - owner_start,
            "trusted executable owner",
        )?;
        if !sid_is_trusted_principal(owner)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted executable owner is not an approved system principal",
            ));
        }
        // SAFETY: acl is part of the live descriptor allocation.
        if unsafe { IsValidAcl(acl) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted executable DACL is invalid",
            ));
        }
        let acl_start = acl as usize;
        if acl_start < descriptor_start || acl_start >= descriptor_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trusted executable DACL is outside its descriptor",
            ));
        }
        // SAFETY: IsValidAcl succeeded and the fixed ACL header is within the descriptor.
        let (ace_count, acl_size) = unsafe { ((*acl).AceCount, usize::from((*acl).AclSize)) };
        if acl_size > descriptor_end - acl_start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trusted executable DACL extends beyond its descriptor",
            ));
        }
        verify_trusted_executable_acl_entries(acl, ace_count, directory, _stage)?;
        drop(descriptor_guard);
        Ok(())
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TrustedExecutableAceDisposition {
        Skip,
        Evaluate,
    }

    fn trusted_executable_ace_disposition(
        ace_type: u8,
        ace_flags: u8,
    ) -> io::Result<TrustedExecutableAceDisposition> {
        if ace_type == ACCESS_DENIED_ACE_KIND || ace_type == SYSTEM_MANDATORY_LABEL_ACE_KIND {
            return Ok(TrustedExecutableAceDisposition::Skip);
        }
        if ace_type != ACCESS_ALLOWED_ACE_KIND {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted executable DACL contains an unsupported grant",
            ));
        }
        // An inherit-only allowed ACE is a template for descendants and grants no access to the
        // object whose DACL is being verified.
        if u32::from(ace_flags) & INHERIT_ONLY_ACE != 0 {
            return Ok(TrustedExecutableAceDisposition::Skip);
        }
        Ok(TrustedExecutableAceDisposition::Evaluate)
    }

    fn verify_trusted_executable_acl_entries(
        acl: *mut ACL,
        ace_count: u16,
        directory: bool,
        _stage: TrustedExecutableAclStage,
    ) -> io::Result<()> {
        for index in 0..u32::from(ace_count) {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: IsValidAcl succeeded, index is below AceCount, and ace is a valid output.
            if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
                return Err(io::Error::last_os_error());
            }
            let header = ace.cast::<ACE_HEADER>();
            // SAFETY: GetAce returned a complete ACE with a readable fixed header.
            let (ace_type, ace_flags, ace_size) = unsafe {
                (
                    (*header).AceType,
                    (*header).AceFlags,
                    usize::from((*header).AceSize),
                )
            };
            if trusted_executable_ace_disposition(ace_type, ace_flags)?
                == TrustedExecutableAceDisposition::Skip
            {
                continue;
            }
            let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if ace_size < sid_offset.saturating_add(8) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "trusted executable DACL contains a truncated grant",
                ));
            }
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: the ACE type and fixed extent were validated before reading mask and SID.
            let (mask, sid) = unsafe {
                (
                    (*allowed).Mask,
                    std::ptr::addr_of_mut!((*allowed).SidStart).cast(),
                )
            };
            validate_bounded_sid(
                sid,
                ace_size.saturating_sub(sid_offset),
                "trusted executable grant",
            )?;
            const WRITE_ACCESS: u32 = FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | GENERIC_WRITE
                | GENERIC_ALL;
            let write_access = WRITE_ACCESS | if directory { FILE_DELETE_CHILD } else { 0 };
            if mask & write_access != 0 && !sid_is_trusted_principal(sid)? {
                #[cfg(feature = "test-support")]
                record_trusted_executable_acl_diagnostic(_stage, ace_type, ace_flags, mask, sid);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "trusted executable is writable by an unapproved principal",
                ));
            }
        }
        Ok(())
    }

    fn sid_is_trusted_principal(sid: PSID) -> io::Result<bool> {
        for kind in [WinLocalSystemSid, WinBuiltinAdministratorsSid] {
            if sid_matches_well_known(sid, kind)? {
                return Ok(true);
            }
        }

        sid_matches_trusted_installer(sid)
    }

    fn sid_matches_well_known(sid: PSID, kind: i32) -> io::Result<bool> {
        let mut known = well_known_sid(kind)?;
        // SAFETY: both SIDs are complete and live for the comparison.
        Ok(unsafe { EqualSid(sid, known.as_sid()) } != 0)
    }

    struct WellKnownSid {
        storage: [u64; 16],
        bytes: usize,
    }

    impl WellKnownSid {
        fn as_sid(&mut self) -> PSID {
            self.storage.as_mut_ptr().cast()
        }
    }

    fn well_known_sid(kind: i32) -> io::Result<WellKnownSid> {
        let mut known = WellKnownSid {
            storage: [0_u64; 16],
            bytes: 0,
        };
        let mut bytes = u32::try_from(size_of_val(&known.storage))
            .map_err(|_| io::Error::other("well-known SID capacity overflowed"))?;
        // SAFETY: storage is aligned and writable for bytes, and the null domain is allowed.
        if unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                known.storage.as_mut_ptr().cast(),
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        known.bytes = usize::try_from(bytes)
            .map_err(|_| io::Error::other("well-known SID length overflowed"))?;
        validate_bounded_sid(known.as_sid(), known.bytes, "well-known SID")?;
        Ok(known)
    }

    fn sid_matches_trusted_installer(sid: PSID) -> io::Result<bool> {
        let trusted_installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\0";
        let wide = trusted_installer.encode_utf16().collect::<Vec<_>>();
        let mut parsed: PSID = std::ptr::null_mut();
        // SAFETY: wide is NUL-terminated and parsed is a valid output pointer.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut parsed) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let parsed_guard = LocalAllocation(parsed.cast());
        // SAFETY: both complete SIDs remain live for the comparison.
        let matches = unsafe { EqualSid(sid, parsed) } != 0;
        drop(parsed_guard);
        Ok(matches)
    }

    #[cfg(feature = "test-support")]
    fn record_trusted_executable_acl_diagnostic(
        stage: TrustedExecutableAclStage,
        ace_type: u8,
        ace_flags: u8,
        mask: u32,
        sid: PSID,
    ) {
        use super::trusted_executable_test_support::{AclChainStage, AclDiagnostic, SidClass};

        let stage = match stage {
            TrustedExecutableAclStage::WindowsRoot => AclChainStage::WindowsRoot,
            TrustedExecutableAclStage::System32OrInstall => AclChainStage::System32OrInstall,
            TrustedExecutableAclStage::Executable => AclChainStage::Executable,
        };
        let sid = [
            (WinLocalSystemSid, SidClass::System),
            (WinBuiltinAdministratorsSid, SidClass::Administrators),
            (WinCreatorOwnerSid, SidClass::CreatorOwner),
            (WinBuiltinUsersSid, SidClass::Users),
            (WinAuthenticatedUserSid, SidClass::AuthenticatedUsers),
            (WinWorldSid, SidClass::World),
            (WinBuiltinAnyPackageSid, SidClass::AppPackages),
        ]
        .into_iter()
        .find_map(|(kind, class)| {
            sid_matches_well_known(sid, kind)
                .ok()
                .filter(|matches| *matches)
                .map(|_| class)
        })
        .or_else(|| {
            sid_matches_trusted_installer(sid)
                .ok()
                .filter(|matches| *matches)
                .map(|_| SidClass::TrustedInstaller)
        })
        .unwrap_or(SidClass::Other);
        let diagnostic = AclDiagnostic {
            stage,
            ace_type,
            ace_flags,
            mask,
            sid,
        };
        super::TRUSTED_EXECUTABLE_ACL_DIAGNOSTIC.with(|slot| {
            if slot.get().is_none() {
                slot.set(Some(diagnostic));
            }
        });
    }

    #[cfg(feature = "test-support")]
    pub(super) fn verify_test_allowed_ace(
        principal: super::trusted_executable_test_support::TestAclPrincipal,
        ace_flags: u32,
        mask: u32,
        directory: bool,
    ) -> io::Result<()> {
        use super::trusted_executable_test_support::TestAclPrincipal;

        let kind = match principal {
            TestAclPrincipal::System => WinLocalSystemSid,
            TestAclPrincipal::CreatorOwner => WinCreatorOwnerSid,
            TestAclPrincipal::Users => WinBuiltinUsersSid,
        };
        let mut sid = well_known_sid(kind)?;
        let acl = single_allowed_acl(sid.as_sid(), ace_flags, mask)?;
        let acl_pointer = acl.0.cast::<ACL>();
        verify_trusted_executable_acl_entries(
            acl_pointer,
            1,
            directory,
            TrustedExecutableAclStage::Executable,
        )
    }

    #[cfg(feature = "test-support")]
    pub(super) fn verify_test_ace_disposition(ace_type: u8, ace_flags: u8) -> io::Result<()> {
        trusted_executable_ace_disposition(ace_type, ace_flags).map(|_| ())
    }

    pub(super) struct SupervisedProcess {
        child: Child,
        job: Option<KernelHandle>,
    }

    impl SupervisedProcess {
        pub(super) fn spawn(
            executable: &std::ffi::OsStr,
            arguments: &[std::ffi::OsString],
            workspace_file: &std::path::Path,
            owned_tree: bool,
        ) -> io::Result<Self> {
            let mut command = Command::new(executable);
            command
                .args(arguments)
                .arg(workspace_file)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            if !owned_tree {
                return command.spawn().map(|child| Self { child, job: None });
            }
            let job = create_kill_on_close_job()?;
            command.creation_flags(CREATE_SUSPENDED);
            let mut child = command.spawn()?;
            // SAFETY: both handles are live, and the suspended child cannot execute before it is
            // assigned to the no-breakaway kill-on-close Job.
            if unsafe { AssignProcessToJobObject(job.raw(), child.as_raw_handle().cast()) } == 0 {
                let error = io::Error::last_os_error();
                terminate_partial_child(&mut child, &job);
                return Err(error);
            }
            if let Err(error) = resume_only_suspended_thread(child.id()) {
                terminate_partial_child(&mut child, &job);
                return Err(error);
            }
            Ok(Self {
                child,
                job: Some(job),
            })
        }

        pub(super) fn poll(&mut self, owned_tree: bool) -> io::Result<SupervisedProcessState> {
            let leader = self.child.try_wait()?;
            if !owned_tree {
                return Ok(leader.map_or(SupervisedProcessState::Running, |status| {
                    SupervisedProcessState::Exited(status.code())
                }));
            }
            let job = self
                .job
                .as_ref()
                .ok_or_else(|| io::Error::other("owned process has no containment job"))?;
            let active = active_job_processes(job)?;
            if active != 0 {
                return Ok(if leader.is_some() {
                    SupervisedProcessState::LeaderExitedTreeActive
                } else {
                    SupervisedProcessState::Running
                });
            }
            let status = match leader {
                Some(status) => status,
                None => self.child.wait()?,
            };
            Ok(SupervisedProcessState::Exited(status.code()))
        }

        pub(super) fn leader_exited(&self) -> io::Result<bool> {
            use windows_sys::Win32::Foundation::STILL_ACTIVE;
            use windows_sys::Win32::System::Threading::GetExitCodeProcess;

            let mut code = 0_u32;
            // SAFETY: child owns a live process handle and `code` is a valid output pointer.
            if unsafe { GetExitCodeProcess(self.child.as_raw_handle().cast(), &mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(code != u32::try_from(STILL_ACTIVE).unwrap_or(u32::MAX))
        }

        pub(super) fn request_stop(&self) -> io::Result<()> {
            Ok(())
        }

        pub(super) fn force_stop(&self) -> io::Result<()> {
            let job = self
                .job
                .as_ref()
                .ok_or_else(|| io::Error::other("unowned editor cannot be force-stopped"))?;
            // SAFETY: job is a live exact Job handle retained for this process tree.
            if unsafe { TerminateJobObject(job.raw(), 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for SupervisedProcess {
        fn drop(&mut self) {
            let Some(job) = self.job.as_ref() else {
                return;
            };
            if active_job_processes(job).is_ok_and(|active| active != 0) {
                // SAFETY: this best-effort fail-closed Drop owns the live Job handle.
                unsafe {
                    TerminateJobObject(job.raw(), 1);
                }
            }
            let _ = self.child.wait();
        }
    }

    fn create_kill_on_close_job() -> io::Result<KernelHandle> {
        // SAFETY: null security attributes and name create one private unnamed Job.
        let raw = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        let job = KernelHandle::from_raw(raw)?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let bytes = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(|_| io::Error::other("job limit information size overflowed"))?;
        // SAFETY: job is live and limits is readable for the exact documented structure size.
        if unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn active_job_processes(job: &KernelHandle) -> io::Result<u32> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let bytes = u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
            .map_err(|_| io::Error::other("job accounting size overflowed"))?;
        // SAFETY: job is live and accounting is writable for its complete structure size.
        if unsafe {
            QueryInformationJobObject(
                job.raw(),
                JobObjectBasicAccountingInformation,
                std::ptr::addr_of_mut!(accounting).cast(),
                bytes,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(accounting.ActiveProcesses)
    }

    fn resume_only_suspended_thread(process_id: u32) -> io::Result<()> {
        use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;

        const MAX_THREAD_SNAPSHOT_ENTRIES: usize = 1_000_000;

        // SAFETY: this creates a read-only owned snapshot handle.
        let snapshot =
            KernelHandle::from_raw(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>())
                .map_err(|_| io::Error::other("thread entry size overflowed"))?,
            ..THREADENTRY32::default()
        };
        // SAFETY: snapshot is live and entry is writable for its declared size.
        if unsafe { Thread32First(snapshot.raw(), &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut thread_id = None;
        let mut reached_end = false;
        for _ in 0..MAX_THREAD_SNAPSHOT_ENTRIES {
            if entry.th32OwnerProcessID == process_id
                && thread_id.replace(entry.th32ThreadID).is_some()
            {
                return Err(io::Error::other(
                    "suspended editor unexpectedly has multiple threads",
                ));
            }
            // SAFETY: snapshot and entry remain live for the next bounded enumeration step.
            if unsafe { Thread32Next(snapshot.raw(), &mut entry) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != i32::try_from(ERROR_NO_MORE_FILES).ok() {
                    return Err(error);
                }
                reached_end = true;
                break;
            }
        }
        if !reached_end {
            return Err(io::Error::other("thread snapshot bound exceeded"));
        }
        let thread_id = thread_id.ok_or_else(|| io::Error::other("suspended thread not found"))?;
        // SAFETY: the thread ID came from the bounded snapshot and the returned handle is owned.
        let thread = KernelHandle::from_raw(unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                thread_id,
            )
        })?;
        // SAFETY: thread is a live handle with query access.
        let opened_owner = unsafe { GetProcessIdOfThread(thread.raw()) };
        if opened_owner == 0 {
            return Err(io::Error::last_os_error());
        }
        if opened_owner != process_id {
            return Err(io::Error::other(
                "suspended thread identity changed before resume",
            ));
        }
        // SAFETY: thread is a live handle with THREAD_SUSPEND_RESUME access.
        let previous_suspend_count = unsafe { ResumeThread(thread.raw()) };
        if previous_suspend_count == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if previous_suspend_count != 1 {
            return Err(io::Error::other(
                "editor primary thread had an unexpected suspend count",
            ));
        }
        Ok(())
    }

    fn terminate_partial_child(child: &mut Child, job: &KernelHandle) {
        // SAFETY: job may or may not contain the child; termination is idempotent cleanup.
        unsafe {
            TerminateJobObject(job.raw(), 1);
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    pub(super) fn create_private_directory_rollback(
        parent: &Dir,
        name: &std::path::Path,
    ) -> io::Result<Dir> {
        create_private_child(parent, name, true)
            .map(Dir::from_std_file)
            .map_err(|error| private_acl_stage_error("directory create", error))
    }

    pub(super) fn create_directory_rollback(
        parent: &Dir,
        name: &std::path::Path,
    ) -> io::Result<Dir> {
        create_or_open_directory(parent, name, true)
    }

    pub(super) fn open_directory(parent: &Dir, name: &std::path::Path) -> io::Result<Dir> {
        let directory = create_or_open_directory(parent, name, false)?;
        if directory_is_reparse(&directory)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory reparse points are rejected",
            ));
        }
        let access = query_file_access(directory.as_raw_handle().cast())?;
        if access != RETAINED_DIRECTORY_ACCESS {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "retained directory access is not exact: expected=0x{RETAINED_DIRECTORY_ACCESS:08X}, actual=0x{access:08X}"
                ),
            ));
        }
        Ok(directory)
    }

    fn create_or_open_directory(
        parent: &Dir,
        name: &std::path::Path,
        create: bool,
    ) -> io::Result<Dir> {
        let (wide, object_name) = relative_object_name(name, "directory")?;
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
                .map_err(|_| io::Error::other("object attributes size overflowed"))?,
            RootDirectory: parent.as_raw_handle().cast(),
            ObjectName: std::ptr::addr_of!(object_name),
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let desired_access = RETAINED_DIRECTORY_ACCESS | if create { DELETE } else { 0 };
        let mut handle = INVALID_HANDLE_VALUE;
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        let disposition = if create { FILE_CREATE } else { FILE_OPEN };
        let options = FILE_DIRECTORY_FILE
            | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_WRITE_THROUGH
            | if create { 0 } else { FILE_OPEN_REPARSE_POINT };
        // SAFETY: the exact parent, bounded UTF-16 name, and output structures remain live for
        // this synchronous write-through directory create or nofollow open. Any returned handle
        // is transferred exactly once below.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &object_attributes,
                &mut io_status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                options,
                std::ptr::null(),
                0,
            )
        };
        let handle = owned_nt_handle(handle);
        const FILE_OPENED_INFORMATION: usize = 1;
        const FILE_CREATED_INFORMATION: usize = 2;
        let expected_information = if create {
            FILE_CREATED_INFORMATION
        } else {
            FILE_OPENED_INFORMATION
        };
        if status != STATUS_SUCCESS || io_status.Information != expected_information {
            if status == STATUS_SUCCESS {
                if create && let Some(handle) = handle {
                    discard_created_nt_child(parent, handle, name, true)?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory create or open returned an unexpected effect",
                ));
            }
            drop(handle);
            return Err(native_status_error(
                if create {
                    "directory NtCreateFile create"
                } else {
                    "directory NtCreateFile open"
                },
                status,
            ));
        }
        let owned = handle.ok_or_else(|| {
            io::Error::other("directory create or open returned no usable exact handle")
        })?;
        drop(wide);
        Ok(Dir::from_std_file(std::fs::File::from(owned)))
    }

    pub(super) fn create_private_file(parent: &Dir, name: &std::path::Path) -> io::Result<File> {
        create_private_child(parent, name, false)
            .map(File::from_std)
            .map_err(|error| private_acl_stage_error("file create", error))
    }

    pub(super) fn open_private_directory_for_cleanup(
        parent: &Dir,
        name: &std::path::Path,
    ) -> io::Result<Dir> {
        open_private_child_for_cleanup(parent, name, true, true).map(Dir::from_std_file)
    }

    pub(super) fn open_private_file_for_cleanup(
        parent: &Dir,
        name: &std::path::Path,
        share_delete: bool,
    ) -> io::Result<File> {
        open_private_child_for_cleanup(parent, name, false, share_delete).map(File::from_std)
    }

    pub(super) fn open_private_file_for_sync(
        parent: &Dir,
        name: &std::path::Path,
    ) -> io::Result<File> {
        let file = File::from_std(open_child_for_exact_access(
            parent,
            name,
            false,
            true,
            PRIVATE_FILE_SYNC_ACCESS,
            "private workspace file sync",
        )?);
        if file_is_reparse(&file)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private workspace sync target is a reparse point",
            ));
        }
        let access = query_file_access(file.as_raw_handle().cast())?;
        #[cfg(feature = "test-support")]
        super::PRIVATE_FILE_SYNC_ACCESS.set(Some(access));
        if access != PRIVATE_FILE_SYNC_ACCESS {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private workspace sync access is not exact: expected=0x{PRIVATE_FILE_SYNC_ACCESS:08X}, actual=0x{access:08X}"
                ),
            ));
        }
        Ok(file)
    }

    pub(super) fn sync_directory(directory: &Dir) -> io::Result<()> {
        let expected = super::identity(directory)?;
        // Windows does not provide a general directory-handle flush usable by an ordinary
        // process. Every namespace mutator in this module therefore completes through an exact
        // FILE_WRITE_THROUGH file object before returning. This barrier validates that the
        // retained capability still names the same object after that mutation-local durability
        // boundary; it never promotes an unflushed path mutation.
        if super::identity(directory)? == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory identity changed during durability validation",
            ))
        }
    }

    fn create_private_child(
        parent: &Dir,
        name: &std::path::Path,
        directory: bool,
    ) -> io::Result<std::fs::File> {
        if !matches!(
            (name.components().next(), name.components().nth(1)),
            (Some(std::path::Component::Normal(_)), None)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private child name is not one normal component",
            ));
        }
        let mut wide = Vec::new();
        let encoded = name.as_os_str().encode_wide();
        wide.try_reserve_exact(encoded.clone().count())
            .map_err(|_| allocation_error("private child name allocation failed"))?;
        wide.extend(encoded);
        if wide.is_empty() || wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private child name is empty or contains NUL",
            ));
        }
        let byte_length = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| io::Error::other("private child name is too long"))?;
        let object_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: wide.as_mut_ptr(),
        };

        let user = effective_user()?;
        let sid = user.sid()?;
        let acl = owner_only_acl(
            sid,
            if directory {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                0
            },
        )?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: descriptor is writable for its complete documented structure size.
        if unsafe {
            InitializeSecurityDescriptor(
                std::ptr::addr_of_mut!(descriptor).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is initialized and sid remains live in user through NtCreateFile.
        if unsafe { SetSecurityDescriptorOwner(std::ptr::addr_of_mut!(descriptor).cast(), sid, 0) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is initialized and acl remains live through NtCreateFile.
        if unsafe {
            SetSecurityDescriptorDacl(
                std::ptr::addr_of_mut!(descriptor).cast(),
                1,
                acl.0.cast(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is initialized and this sets only the documented inheritance bit.
        if unsafe {
            SetSecurityDescriptorControl(
                std::ptr::addr_of_mut!(descriptor).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor and all referenced components remain live and fully initialized.
        if unsafe { IsValidSecurityDescriptor(std::ptr::addr_of_mut!(descriptor).cast()) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private child security descriptor is invalid",
            ));
        }

        let desired_access = READ_CONTROL_ACCESS
            | WRITE_DAC
            | DELETE
            | SYNCHRONIZE
            | if directory {
                FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_DELETE_CHILD
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | FILE_READ_EA
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
            } else {
                GENERIC_READ | GENERIC_WRITE
            };
        let share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let create_options = FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_WRITE_THROUGH
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
            };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
                .map_err(|_| io::Error::other("object attributes size overflowed"))?,
            RootDirectory: parent.as_raw_handle().cast(),
            ObjectName: std::ptr::addr_of!(object_name),
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::addr_of!(descriptor),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle = INVALID_HANDLE_VALUE;
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        // SAFETY: all input structures and their referenced SID, ACL, UTF-16 name, and parent
        // handle are live for this synchronous create. FILE_CREATE is exact no-replace, and the
        // returned handle is transferred exactly once into OwnedHandle below.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &object_attributes,
                &mut io_status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                share_access,
                FILE_CREATE,
                create_options,
                std::ptr::null(),
                0,
            )
        };
        let handle = owned_nt_handle(handle);
        const FILE_CREATED_INFORMATION: usize = 2;
        if status != STATUS_SUCCESS || io_status.Information != FILE_CREATED_INFORMATION {
            if status == STATUS_SUCCESS {
                if let Some(handle) = handle {
                    discard_created_nt_child(parent, handle, name, directory)?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private child create returned an unexpected effect",
                ));
            }
            drop(handle);
            // SAFETY: conversion accepts the exact NTSTATUS returned by NtCreateFile.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            return Err(win32_error(code));
        }
        let owned = handle
            .ok_or_else(|| io::Error::other("private child creation returned no usable handle"))?;
        Ok(std::fs::File::from(owned))
    }

    fn open_private_child_for_cleanup(
        parent: &Dir,
        name: &std::path::Path,
        directory: bool,
        share_delete: bool,
    ) -> io::Result<std::fs::File> {
        let desired_access = private_cleanup_access_mask(directory);
        open_child_for_exact_access(
            parent,
            name,
            directory,
            share_delete,
            desired_access,
            "private cleanup child",
        )
    }

    const fn private_cleanup_access_mask(directory: bool) -> u32 {
        READ_CONTROL_ACCESS
            | DELETE
            | SYNCHRONIZE
            | if directory {
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES
            } else {
                FILE_READ_ATTRIBUTES
            }
    }

    fn open_child_for_exact_access(
        parent: &Dir,
        name: &std::path::Path,
        directory: bool,
        share_delete: bool,
        desired_access: u32,
        stage: &str,
    ) -> io::Result<std::fs::File> {
        let (wide, object_name) = relative_object_name(name, stage)?;
        let create_options = FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_WRITE_THROUGH
            | FILE_OPEN_REPARSE_POINT
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
                .map_err(|_| io::Error::other("object attributes size overflowed"))?,
            RootDirectory: parent.as_raw_handle().cast(),
            ObjectName: std::ptr::addr_of!(object_name),
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle = INVALID_HANDLE_VALUE;
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        // SAFETY: the exact retained parent and the bounded one-component UTF-16 name remain
        // live for this synchronous handle-relative open. Any returned handle is transferred
        // exactly once into OwnedHandle before the outcome is inspected.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &object_attributes,
                &mut io_status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ
                    | FILE_SHARE_WRITE
                    | if share_delete { FILE_SHARE_DELETE } else { 0 },
                FILE_OPEN,
                create_options,
                std::ptr::null(),
                0,
            )
        };
        let handle = if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            // SAFETY: NtCreateFile returned this raw handle and it is transferred exactly once.
            Some(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
        };
        const FILE_OPENED_INFORMATION: usize = 1;
        if status != STATUS_SUCCESS || io_status.Information != FILE_OPENED_INFORMATION {
            drop(handle);
            if status == STATUS_SUCCESS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{stage} open returned an unexpected effect"),
                ));
            }
            // SAFETY: conversion accepts the exact NTSTATUS returned by NtCreateFile.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            return Err(win32_error(code));
        }
        let owned = handle
            .ok_or_else(|| io::Error::other(format!("{stage} open returned no usable handle")))?;
        drop(wide);
        Ok(std::fs::File::from(owned))
    }

    fn relative_object_name(
        name: &std::path::Path,
        object_kind: &str,
    ) -> io::Result<(Vec<u16>, UNICODE_STRING)> {
        if !matches!(
            (name.components().next(), name.components().nth(1)),
            (Some(std::path::Component::Normal(_)), None)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{object_kind} name is not one normal component"),
            ));
        }
        let encoded = name.as_os_str().encode_wide();
        let mut wide = Vec::new();
        wide.try_reserve_exact(encoded.clone().count())
            .map_err(|_| allocation_error("relative object name allocation failed"))?;
        wide.extend(encoded);
        if wide.is_empty() || wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{object_kind} name is empty or contains NUL"),
            ));
        }
        let byte_length = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| io::Error::other(format!("{object_kind} name is too long")))?;
        let object_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: wide.as_mut_ptr(),
        };
        Ok((wide, object_name))
    }

    fn owned_nt_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<OwnedHandle> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            // SAFETY: a successful native create/open returned this raw handle, and this helper
            // transfers it exactly once into the returned RAII owner.
            Some(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
        }
    }

    fn discard_created_nt_child(
        parent: &Dir,
        handle: OwnedHandle,
        name: &std::path::Path,
        directory: bool,
    ) -> io::Result<()> {
        let file = std::fs::File::from(handle);
        if directory {
            discard_created_directory(parent, Dir::from_std_file(file), name)
        } else {
            discard_created_file(parent, File::from_std(file), name)
        }
    }

    pub(super) fn discard_created_directory(
        parent: &Dir,
        directory: Dir,
        name: &std::path::Path,
    ) -> io::Result<()> {
        mark_handle_deleted(directory.as_raw_handle().cast())?;
        drop(directory);
        ensure_directory_absent(parent, name, "created directory rollback")
    }

    pub(super) fn discard_created_file(
        parent: &Dir,
        file: File,
        name: &std::path::Path,
    ) -> io::Result<()> {
        mark_handle_deleted(file.as_raw_handle().cast())?;
        drop(file);
        ensure_file_absent(parent, name, "created file rollback")
    }

    fn mark_handle_deleted(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<()> {
        if query_file_mode(handle)? & FILE_WRITE_THROUGH == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "delete handle is not mutation-local durable",
            ));
        }
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        let bytes = u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>())
            .map_err(|_| io::Error::other("file disposition size overflowed"))?;
        // SAFETY: the caller proved that handle is a live exact object handle with DELETE access,
        // and the disposition remains readable for the complete synchronous call.
        let deleted = unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfoEx,
                std::ptr::addr_of!(disposition).cast(),
                bytes,
            )
        };
        if deleted == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn delete_exact_directory(directory: &Dir) -> io::Result<()> {
        mark_handle_deleted(directory.as_raw_handle().cast())
    }

    pub(super) fn delete_exact_file(file: &File) -> io::Result<()> {
        mark_handle_deleted(file.as_raw_handle().cast())
    }

    fn ensure_directory_absent(
        parent: &Dir,
        name: &std::path::Path,
        stage: &str,
    ) -> io::Result<()> {
        match parent.open_dir_nofollow(name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{stage} left the directory name reachable"),
            )),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("{stage} absence readback failed: {error}"),
            )),
        }
    }

    fn ensure_file_absent(parent: &Dir, name: &std::path::Path, stage: &str) -> io::Result<()> {
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(cap_fs_ext::FollowSymlinks::No);
        match parent.open_with(name, &options) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{stage} left the file name reachable"),
            )),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("{stage} absence readback failed: {error}"),
            )),
        }
    }

    fn owner_only_acl(sid: PSID, inheritance: u32) -> io::Result<LocalAllocation> {
        single_allowed_acl(sid, inheritance, FILE_ALL_ACCESS)
    }

    fn single_allowed_acl(
        sid: PSID,
        inheritance: u32,
        access_permissions: u32,
    ) -> io::Result<LocalAllocation> {
        let access = explicit_allowed_access(sid, inheritance, access_permissions);
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: access and sid remain live, and acl is a valid output pointer.
        let status = unsafe { SetEntriesInAclW(1, &access, std::ptr::null(), &mut acl) };
        if status != ERROR_SUCCESS {
            Err(win32_error(status))
        } else if acl.is_null() {
            Err(io::Error::other(
                "owner-only ACL construction returned null",
            ))
        // SAFETY: SetEntriesInAclW returned this complete ACL allocation.
        } else if unsafe { IsValidAcl(acl) } == 0 {
            // SAFETY: acl is the successful LocalAlloc-compatible result we still own.
            unsafe { LocalFree(acl.cast()) };
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner-only ACL construction returned an invalid ACL",
            ))
        } else {
            Ok(LocalAllocation(acl.cast()))
        }
    }

    #[cfg(feature = "test-support")]
    pub(super) fn make_directory_inheritable_for_test(
        parent: &Dir,
        name: &std::path::Path,
        expected: &Dir,
    ) -> io::Result<()> {
        let desired_access = READ_CONTROL_ACCESS
            | WRITE_DAC
            | SYNCHRONIZE
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES;
        let directory = Dir::from_std_file(open_child_for_exact_access(
            parent,
            name,
            true,
            true,
            desired_access,
            "test ACL directory",
        )?);
        if directory_is_reparse(&directory)?
            || super::identity(&directory)? != super::identity(expected)?
            || query_file_access(directory.as_raw_handle().cast())? != desired_access
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test ACL capability does not match the expected directory",
            ));
        }
        verify_private_directory(&directory)?;
        make_handle_permissive_for_test(
            directory.as_raw_handle().cast(),
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )
    }

    #[cfg(feature = "test-support")]
    pub(super) fn make_file_permissive_for_test(
        parent: &Dir,
        name: &std::path::Path,
        expected: &FileCapability,
    ) -> io::Result<()> {
        let desired_access = READ_CONTROL_ACCESS | WRITE_DAC | SYNCHRONIZE | FILE_READ_ATTRIBUTES;
        let file = FileCapability {
            inner: File::from_std(open_child_for_exact_access(
                parent,
                name,
                false,
                true,
                desired_access,
                "test ACL file",
            )?),
        };
        if file_is_reparse(&file.inner)?
            || !file.same_identity(expected)?
            || query_file_access(file.inner.as_raw_handle().cast())? != desired_access
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test ACL capability does not match the expected file",
            ));
        }
        file.require_single_regular_link()?;
        verify_private_file(&file)?;
        make_handle_permissive_for_test(file.inner.as_raw_handle().cast(), 0)
    }

    #[cfg(feature = "test-support")]
    fn make_handle_permissive_for_test(
        handle: windows_sys::Win32::Foundation::HANDLE,
        inheritance: u32,
    ) -> io::Result<()> {
        let user = effective_user()?;
        let mut world_storage = [0_u64; 16];
        let mut world_bytes = u32::try_from(size_of_val(&world_storage))
            .map_err(|_| io::Error::other("world SID capacity overflowed"))?;
        // SAFETY: world_storage is aligned and writable for world_bytes, and no domain is needed.
        if unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                std::ptr::null_mut(),
                world_storage.as_mut_ptr().cast(),
                &mut world_bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let world_bytes = usize::try_from(world_bytes)
            .map_err(|_| io::Error::other("world SID length overflowed"))?;
        let world = world_storage.as_mut_ptr().cast();
        validate_bounded_sid(world, world_bytes, "world test principal")?;
        let accesses = [
            explicit_owner_access(user.sid()?, inheritance),
            explicit_owner_access(world, inheritance),
        ];
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: both complete SIDs and accesses remain live, and acl is a valid output.
        let status = unsafe {
            SetEntriesInAclW(
                u32::try_from(accesses.len())
                    .map_err(|_| io::Error::other("test ACL entry count overflowed"))?,
                accesses.as_ptr(),
                std::ptr::null(),
                &mut acl,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        if acl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test ACL construction returned null",
            ));
        }
        let acl = LocalAllocation(acl.cast());
        // SAFETY: handle is the exact private object with WRITE_DAC, and acl remains live.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.0.cast(),
                std::ptr::null(),
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32_error(status))
        }
    }

    #[cfg(feature = "test-support")]
    fn explicit_owner_access(sid: PSID, inheritance: u32) -> EXPLICIT_ACCESS_W {
        explicit_allowed_access(sid, inheritance, FILE_ALL_ACCESS)
    }

    fn explicit_allowed_access(
        sid: PSID,
        inheritance: u32,
        access_permissions: u32,
    ) -> EXPLICIT_ACCESS_W {
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: access_permissions,
            grfAccessMode: SET_ACCESS,
            grfInheritance: inheritance,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid.cast(),
            },
        }
    }

    pub(super) fn directory_is_reparse(directory: &Dir) -> io::Result<bool> {
        handle_is_reparse(directory.as_raw_handle().cast())
    }

    fn file_is_reparse(file: &File) -> io::Result<bool> {
        handle_is_reparse(file.as_raw_handle().cast())
    }

    fn handle_is_reparse(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<bool> {
        let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
        let bytes = u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>())
            .map_err(|_| io::Error::other("file attribute tag size overflowed"))?;
        // SAFETY: `handle` is live and `information` is writable for its complete documented size
        // during the synchronous query.
        if unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                std::ptr::addr_of_mut!(information).cast(),
                bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    fn private_acl_stage_error(stage: &'static str, error: io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            format!(
                "private ACL {stage} failed: kind={:?}, code={:?}",
                error.kind(),
                error.raw_os_error()
            ),
        )
    }

    pub(super) fn verify_private_directory(directory: &Dir) -> io::Result<()> {
        let handle = directory.as_raw_handle().cast();
        verify_private_acl(
            handle,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            "directory",
        )
    }

    pub(super) fn verify_private_file(file: &FileCapability) -> io::Result<()> {
        let handle = file.inner.as_raw_handle().cast();
        verify_private_acl(handle, 0, "file")
    }

    fn verify_private_acl(
        handle: windows_sys::Win32::Foundation::HANDLE,
        required_inheritance: u32,
        object_kind: &str,
    ) -> io::Result<()> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: all output pointers are valid and `handle` remains live for the call.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        let _descriptor = LocalAllocation(descriptor.cast());
        if owner.is_null() || acl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} has no owner-only DACL"),
            ));
        }
        // SAFETY: the ACL pointer is owned by the live security descriptor allocation.
        if unsafe { IsValidAcl(acl) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} has an invalid DACL"),
            ));
        }
        if !owner_matches_effective_user(owner)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} is not owned by the effective user"),
            ));
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `descriptor` remains live through `_descriptor`, and both outputs are valid.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} DACL inherits permissions"),
            ));
        }
        // SAFETY: `acl` is part of the live descriptor allocation.
        let ace_count = unsafe { (*acl).AceCount };
        if ace_count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} DACL is not owner-only"),
            ));
        }
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: the verified ACL contains one entry and `ace` is a valid output pointer.
        if unsafe { GetAce(acl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        let header = ace.cast::<ACE_HEADER>();
        // SAFETY: GetAce returned a non-null pointer to an ACE whose fixed header is readable.
        let (ace_type, ace_flags, ace_size) = unsafe {
            (
                (*header).AceType,
                u32::from((*header).AceFlags),
                usize::from((*header).AceSize),
            )
        };
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if ace_type != ACCESS_ALLOWED_ACE_KIND
            || ace_size < sid_offset.saturating_add(8)
            || ace_flags != required_inheritance
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} DACL is not owner-only"),
            ));
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: the ACE type and fixed-size extent were validated before reading the mask and
        // SID header. The pointer stays within the live descriptor allocation.
        let (mask, sid) = unsafe {
            (
                (*allowed).Mask,
                std::ptr::addr_of_mut!((*allowed).SidStart).cast(),
            )
        };
        validate_bounded_sid(sid, ace_size.saturating_sub(sid_offset), object_kind)?;
        // SAFETY: the complete SID is bounded by the ACE, and owner remains in the live descriptor.
        let same_owner = unsafe { EqualSid(sid, owner) } != 0;
        if mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS || !same_owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private {object_kind} DACL is not owner-only"),
            ));
        }
        Ok(())
    }

    fn owner_matches_effective_user(owner: PSID) -> io::Result<bool> {
        let user = effective_user()?;
        // SAFETY: both SIDs are complete and remain live for this comparison.
        Ok(unsafe { EqualSid(owner, user.sid()?) } != 0)
    }

    struct EffectiveUser {
        buffer: Vec<usize>,
        returned: usize,
    }

    impl EffectiveUser {
        fn sid(&self) -> io::Result<PSID> {
            if self.returned < size_of::<TOKEN_USER>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "token user response is truncated",
                ));
            }
            // SAFETY: returned proves a complete TOKEN_USER in this aligned live buffer.
            let user = unsafe { &*self.buffer.as_ptr().cast::<TOKEN_USER>() };
            if user.User.Sid.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "effective user token has no SID",
                ));
            }
            let start = self.buffer.as_ptr().cast::<u8>() as usize;
            let end = start
                .checked_add(self.returned)
                .ok_or_else(|| io::Error::other("token user response range overflowed"))?;
            let sid_start = user.User.Sid as usize;
            if sid_start < start || sid_start >= end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "effective user SID is outside the token response",
                ));
            }
            validate_bounded_sid(user.User.Sid, end - sid_start, "effective user")?;
            Ok(user.User.Sid)
        }
    }

    fn effective_user() -> io::Result<EffectiveUser> {
        let mut token = std::ptr::null_mut();
        // SAFETY: the current process pseudo-handle is valid and token is a valid output pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        struct TokenHandle(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for TokenHandle {
            fn drop(&mut self) {
                // SAFETY: this guard owns the token handle returned by OpenProcessToken.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let token = TokenHandle(token);
        let mut bytes = 0_u32;
        // SAFETY: a null buffer with zero length is the documented size query.
        if unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut bytes) }
            != 0
            || io::Error::last_os_error().raw_os_error()
                != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok()
        {
            return Err(io::Error::last_os_error());
        }
        let bytes = usize::try_from(bytes)
            .map_err(|_| io::Error::other("token user buffer length overflowed"))?;
        let words = bytes
            .checked_add(size_of::<usize>() - 1)
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or_else(|| io::Error::other("token user buffer length overflowed"))?;
        let mut buffer = Vec::<usize>::new();
        buffer
            .try_reserve_exact(words)
            .map_err(|_| allocation_error("token user allocation failed"))?;
        buffer.resize(words, 0);
        let mut returned = 0_u32;
        // SAFETY: the aligned buffer is writable for the queried byte count and all pointers are
        // valid for the duration of the call.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                u32::try_from(bytes)
                    .map_err(|_| io::Error::other("token user buffer length overflowed"))?,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let returned = usize::try_from(returned)
            .map_err(|_| io::Error::other("token user response length overflowed"))?;
        if returned > bytes || returned < size_of::<TOKEN_USER>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token user response is invalid",
            ));
        }
        let user = EffectiveUser { buffer, returned };
        user.sid()?;
        Ok(user)
    }

    fn validate_bounded_sid(sid: PSID, available: usize, object_kind: &str) -> io::Result<usize> {
        if sid.is_null() || available < 8 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{object_kind} SID header is truncated"),
            ));
        }
        // SAFETY: available covers the fixed eight-byte SID header, whose second byte is the
        // subauthority count.
        let subauthorities = usize::from(unsafe { *sid.cast::<u8>().add(1) });
        let expected = 8_usize
            .checked_add(
                subauthorities
                    .checked_mul(size_of::<u32>())
                    .ok_or_else(|| io::Error::other("SID length overflowed"))?,
            )
            .ok_or_else(|| io::Error::other("SID length overflowed"))?;
        if expected > available {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{object_kind} SID is truncated"),
            ));
        }
        // SAFETY: the complete SID extent derived from its header is within the live allocation.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{object_kind} SID is invalid"),
            ));
        }
        // SAFETY: IsValidSid succeeded and the complete SID remains live and bounded.
        let reported = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| io::Error::other("SID length overflowed"))?;
        if reported != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{object_kind} SID length is inconsistent"),
            ));
        }
        Ok(reported)
    }

    fn win32_error(status: u32) -> io::Error {
        io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
    }

    pub(super) fn change_time(file: &FileCapability) -> io::Result<i64> {
        let mut information = FILE_BASIC_INFO::default();
        let information_bytes = u32::try_from(size_of::<FILE_BASIC_INFO>())
            .map_err(|_| io::Error::other("file information size overflowed"))?;
        // SAFETY: `file` owns a valid handle and `information` is writable for the exact
        // FILE_BASIC_INFO size for the duration of the call.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                file.inner.as_raw_handle().cast(),
                FileBasicInfo,
                std::ptr::addr_of_mut!(information).cast(),
                information_bytes,
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(information.ChangeTime)
        }
    }

    pub(super) fn available_space(directory: &Dir) -> io::Result<u64> {
        let handle = directory.as_raw_handle().cast();
        // The first call intentionally supplies no buffer and returns the required UTF-16 size.
        // SAFETY: `handle` is valid for the call and a null buffer with zero capacity is the
        // documented size-query form of GetFinalPathNameByHandleW.
        let required =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_DOS) };
        if required == 0 {
            return Err(io::Error::last_os_error());
        }
        let capacity = required
            .checked_add(1)
            .ok_or_else(|| io::Error::other("final directory path length overflowed"))?;
        let mut path = vec![
            0_u16;
            usize::try_from(capacity).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "final directory path is too long",
                )
            })?
        ];
        // SAFETY: `path` is writable for `capacity` UTF-16 units and `handle` remains valid.
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), capacity, VOLUME_NAME_DOS)
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written >= capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "final directory path changed during lookup",
            ));
        }
        path.truncate(usize::try_from(written).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "final directory path is too long",
            )
        })?);
        path.push(0);
        let mut available = 0_u64;
        // SAFETY: `path` is NUL-terminated and remains live, while `available` is a valid output.
        let succeeded = unsafe {
            GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(available)
        }
    }

    fn rename_raw_handle_by_handle(
        source: windows_sys::Win32::Foundation::HANDLE,
        rename_target: &RenameTarget,
        destination: &std::path::Path,
        replace: bool,
    ) -> io::Result<()> {
        if query_file_mode(source)? & FILE_WRITE_THROUGH == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "rename source is not mutation-local durable",
            ));
        }
        let filename: Vec<u16> = destination.as_os_str().encode_wide().collect();
        if filename.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical component contains an embedded NUL",
            ));
        }
        let filename_bytes = filename
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let buffer_bytes = size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(filename_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let words = buffer_bytes.div_ceil(size_of::<usize>());
        let mut aligned = vec![0_usize; words];
        let info = aligned.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let filename_length = u32::try_from(filename_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let information_class = if replace {
            FileRenameInformationEx
        } else {
            FileRenameInformation
        };
        // SAFETY: `aligned` is pointer-aligned and sized for the fixed header plus all UTF-16
        // code units. Both borrowed handles remain valid for the duration of this call. POSIX
        // replacement permits an authenticated destination handle to remain open while its name
        // is atomically rebound to the exact source.
        unsafe {
            if replace {
                (*info).Anonymous.Flags =
                    FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
            } else {
                (*info).Anonymous.ReplaceIfExists = false;
            }
            (*info).RootDirectory = rename_target.0.as_raw_handle().cast();
            (*info).FileNameLength = filename_length;
            std::ptr::copy_nonoverlapping(
                filename.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                filename.len(),
            );
        }
        let length = u32::try_from(buffer_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        // NtSetInformationFile is the native contract for root-directory-relative rename. The
        // source handle carries DELETE, the destination handle is retained, and the complete
        // FILE_RENAME_INFORMATION buffer remains live for the synchronous call.
        // SAFETY: both exact handles and the aligned initialized buffer remain live, and io_status
        // is writable for its complete documented size.
        let status = unsafe {
            NtSetInformationFile(
                source,
                &mut io_status,
                info.cast(),
                length,
                information_class,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(native_status_error(
                "file NtSetInformationFile rename",
                status,
            ));
        }
        Ok(())
    }

    pub(super) fn rename_by_handle(
        source: &FileCapability,
        rename_target: &RenameTarget,
        destination: &std::path::Path,
        replace: bool,
    ) -> io::Result<()> {
        rename_raw_handle_by_handle(
            source.inner.as_raw_handle().cast(),
            rename_target,
            destination,
            replace,
        )
    }

    #[cfg(feature = "test-support")]
    pub(super) fn rename_with_primary_target(
        source: &FileCapability,
        destination: &Dir,
        name: &std::path::Path,
        replace: bool,
    ) -> io::Result<()> {
        let target = RenameTarget(destination.try_clone()?.into_std_file());
        rename_by_handle(source, &target, name, replace)
    }

    #[cfg(feature = "test-support")]
    pub(super) fn rename_directory_with_retained_target(
        source_parent: &super::Directory,
        source_name: &std::path::Path,
        expected_source: &super::Directory,
        destination: &super::Directory,
        name: &std::path::Path,
        replace: bool,
    ) -> io::Result<()> {
        let source = Dir::from_std_file(open_private_child_for_cleanup(
            &source_parent.inner,
            source_name,
            true,
            true,
        )?);
        if directory_is_reparse(&source)?
            || super::identity(&source)? != expected_source.final_identity()
            || query_file_access(source.as_raw_handle().cast())?
                != private_cleanup_access_mask(true)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "temporary rename source does not match the expected directory",
            ));
        }
        verify_private_directory(&source)?;
        rename_raw_handle_by_handle(
            source.as_raw_handle().cast(),
            &destination.rename_target,
            name,
            replace,
        )
    }

    pub(super) struct RenameTarget(std::fs::File);

    pub(super) struct PreparedRenameTargetName {
        wide: Vec<u16>,
        byte_length: u16,
    }

    pub(super) fn prepare_rename_target_name(
        name: &std::path::Path,
    ) -> io::Result<PreparedRenameTargetName> {
        let (wide, object_name) = relative_object_name(name, "rename target")?;
        Ok(PreparedRenameTargetName {
            wide,
            byte_length: object_name.Length,
        })
    }

    pub(super) fn open_ambient_rename_target(directory: &Dir) -> io::Result<RenameTarget> {
        let path = final_path_bounded(
            &directory.try_clone()?.into_std_file(),
            "ambient rename target",
        )?;
        let desired_access = rename_target_access_mask();
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(desired_access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let target = options.open(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "ambient rename-target acquisition failed: win32={}",
                    error.raw_os_error().unwrap_or_default()
                ),
            )
        })?;
        validate_rename_target(&target, directory)?;
        Ok(RenameTarget(target))
    }

    pub(super) fn open_child_rename_target(
        parent: &RenameTarget,
        name: &PreparedRenameTargetName,
        expected: &Dir,
    ) -> io::Result<RenameTarget> {
        let object_name = UNICODE_STRING {
            Length: name.byte_length,
            MaximumLength: name.byte_length,
            Buffer: name.wide.as_ptr().cast_mut(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
                .map_err(|_| io::Error::other("object attributes size overflowed"))?,
            RootDirectory: parent.0.as_raw_handle().cast(),
            ObjectName: std::ptr::addr_of!(object_name),
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut raw = INVALID_HANDLE_VALUE;
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        #[cfg(feature = "test-support")]
        super::run_rename_target_acquisition_hook();
        // SAFETY: the exact retained parent, bounded one-component name, object attributes, and
        // output structures remain live for this synchronous nofollow open. Any returned handle
        // is transferred exactly once below.
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                rename_target_access_mask(),
                &object_attributes,
                &mut io_status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        let owned = owned_nt_handle(raw);
        const FILE_OPENED_INFORMATION: usize = 1;
        if status != STATUS_SUCCESS || io_status.Information != FILE_OPENED_INFORMATION {
            drop(owned);
            if status == STATUS_SUCCESS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "child rename-target acquisition returned an unexpected effect",
                ));
            }
            return Err(native_status_error(
                "child rename-target NtCreateFile open",
                status,
            ));
        }
        let owned = owned.ok_or_else(|| {
            io::Error::other("child rename-target acquisition returned no usable exact handle")
        })?;
        let target = std::fs::File::from(owned);
        validate_rename_target(&target, expected)?;
        Ok(RenameTarget(target))
    }

    pub(super) fn clone_rename_target(
        source: &RenameTarget,
        expected: &Dir,
    ) -> io::Result<RenameTarget> {
        let mut raw = std::ptr::null_mut();
        // DuplicateHandle with SAME_ACCESS creates another reference to the already validated
        // pinned file object without a namespace lookup or authority change.
        // SAFETY: both process handles refer to the current process, the retained source handle is
        // live, raw is writable, and a successful result is transferred exactly once below.
        let duplicated = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                source.0.as_raw_handle().cast(),
                process,
                &mut raw,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        let owned = owned_nt_handle(raw);
        if duplicated == 0 {
            drop(owned);
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "rename target DuplicateHandle clone failed: win32={}",
                    error.raw_os_error().unwrap_or_default()
                ),
            ));
        }
        let owned = owned.ok_or_else(|| {
            io::Error::other("rename target clone returned no usable exact handle")
        })?;
        let target = std::fs::File::from(owned);
        validate_rename_target(&target, expected)?;
        Ok(RenameTarget(target))
    }

    fn validate_rename_target(target: &std::fs::File, expected: &Dir) -> io::Result<()> {
        #[cfg(feature = "test-support")]
        if super::take_workspace_directory_fault(
            super::WorkspaceDirectoryFault::RenameTargetIdentityMismatch,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "injected rename-target identity mismatch",
            ));
        }
        if file_identity(target)? != super::identity(expected)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rename target identity does not match its retained directory capability",
            ));
        }
        let target_directory = Dir::from_std_file(target.try_clone()?);
        if directory_is_reparse(&target_directory)? || !target.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "rename target is a reparse point or not a directory",
            ));
        }
        let granted = query_file_access(target.as_raw_handle().cast())?;
        if granted != rename_target_access_mask() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("rename target access is not exact: granted=0x{granted:08X}"),
            ));
        }
        Ok(())
    }

    const fn rename_target_access_mask() -> u32 {
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
    }

    fn query_file_mode(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<u32> {
        let mut information = FILE_MODE_INFORMATION::default();
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        let length = u32::try_from(size_of::<FILE_MODE_INFORMATION>())
            .map_err(|_| io::Error::other("file mode information size overflowed"))?;
        // SAFETY: handle is live and information/io_status are writable for their complete sizes.
        let status = unsafe {
            NtQueryInformationFile(
                handle,
                &mut io_status,
                std::ptr::addr_of_mut!(information).cast(),
                length,
                FileModeInformation,
            )
        };
        if status == STATUS_SUCCESS {
            Ok(information.Mode)
        } else {
            Err(native_status_error("file mode query", status))
        }
    }

    #[cfg(feature = "test-support")]
    pub(super) fn directory_is_write_through(directory: &Dir) -> io::Result<bool> {
        Ok(query_file_mode(directory.as_raw_handle().cast())? & FILE_WRITE_THROUGH != 0)
    }

    #[cfg(feature = "test-support")]
    pub(super) fn file_is_write_through(file: &File) -> io::Result<bool> {
        Ok(query_file_mode(file.as_raw_handle().cast())? & FILE_WRITE_THROUGH != 0)
    }

    #[cfg(feature = "test-support")]
    pub(super) fn rename_target_access(target: &RenameTarget) -> io::Result<u32> {
        query_file_access(target.0.as_raw_handle().cast())
    }

    #[cfg(feature = "test-support")]
    pub(super) fn directory_primary_access(directory: &Dir) -> io::Result<u32> {
        query_file_access(directory.as_raw_handle().cast())
    }

    #[cfg(feature = "test-support")]
    pub(super) fn retained_directory_access() -> u32 {
        RETAINED_DIRECTORY_ACCESS
    }

    #[cfg(feature = "test-support")]
    pub(super) fn file_access(file: &File) -> io::Result<u32> {
        query_file_access(file.as_raw_handle().cast())
    }

    #[cfg(feature = "test-support")]
    pub(super) const fn private_file_access() -> u32 {
        READ_CONTROL_ACCESS
            | WRITE_DAC
            | DELETE
            | SYNCHRONIZE
            | windows_sys::Win32::Storage::FileSystem::FILE_READ_DATA
            | FILE_READ_ATTRIBUTES
            | FILE_READ_EA
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_EA
    }

    #[cfg(feature = "test-support")]
    pub(super) const fn private_file_sync_access() -> u32 {
        PRIVATE_FILE_SYNC_ACCESS
    }

    fn query_file_access(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<u32> {
        let mut information = FILE_ACCESS_INFORMATION::default();
        let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
        let length = u32::try_from(size_of::<FILE_ACCESS_INFORMATION>())
            .map_err(|_| io::Error::other("file access information size overflowed"))?;
        // SAFETY: handle is live and information/io_status are writable for their complete sizes.
        let status = unsafe {
            NtQueryInformationFile(
                handle,
                &mut io_status,
                std::ptr::addr_of_mut!(information).cast(),
                length,
                FileAccessInformation,
            )
        };
        if status == STATUS_SUCCESS {
            Ok(information.AccessFlags)
        } else {
            Err(native_status_error("file access query", status))
        }
    }

    pub(super) fn operation_stage_error(stage: &'static str, error: io::Error) -> io::Error {
        let win32 = error
            .raw_os_error()
            .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
        io::Error::new(
            error.kind(),
            format!(
                "{stage} failed: {error}; kind={:?}, win32={win32}",
                error.kind(),
            ),
        )
    }

    fn native_status_error(stage: &'static str, status: i32) -> io::Error {
        // SAFETY: conversion accepts the exact NTSTATUS returned by the synchronous native call.
        let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
        let kind = win32_error(code).kind();
        io::Error::new(
            kind,
            format!(
                "{stage} failed: ntstatus=0x{:08X}, win32={code}",
                status as u32
            ),
        )
    }

    pub(super) fn delete_lock_file(file: &FileCapability) -> io::Result<()> {
        mark_handle_deleted(file.inner.as_raw_handle().cast())
    }

    pub(super) fn lock_file_nonblocking(file: &FileCapability) -> io::Result<()> {
        // SAFETY: `OVERLAPPED` is a C POD structure for which all-zero is the documented
        // synchronous byte-range origin.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: `file` owns a valid handle and `overlapped` remains live and exclusively
        // borrowed for this synchronous nonblocking lock call.
        let succeeded = unsafe {
            LockFileEx(
                file.inner.as_raw_handle().cast(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if succeeded == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(33) {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mutation lock is held",
                ))
            } else {
                Err(error)
            }
        } else {
            Ok(())
        }
    }

    pub(super) fn unlock_file(file: &FileCapability) -> io::Result<()> {
        // SAFETY: `OVERLAPPED` is a C POD structure for which all-zero is the documented
        // synchronous byte-range origin.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: `file` owns the handle used for the matching lock and `overlapped` remains live
        // and exclusively borrowed for the duration of this synchronous unlock call.
        let succeeded =
            unsafe { UnlockFileEx(file.inner.as_raw_handle().cast(), 0, 1, 0, &mut overlapped) };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "benchmark-support")]
    pub(super) fn mark_sparse_file(file: &std::fs::File) -> io::Result<()> {
        let mut bytes_returned = 0_u32;
        // SAFETY: `file` owns a valid handle for this call, and Microsoft documents null input
        // and output buffers for FSCTL_SET_SPARSE.
        let succeeded = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// An opened regular file with no path authority.
pub struct FileCapability {
    inner: File,
}

pub struct ExclusiveFileLock {
    file: FileCapability,
}

impl ExclusiveFileLock {
    pub fn validates_named_file(
        &self,
        directory: &Directory,
        name: &PhysicalComponent,
    ) -> io::Result<bool> {
        self.file.require_single_regular_link()?;
        let named = directory.open_file_for_sync_nofollow(name)?;
        self.file.same_file(&named)
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn lock_file_nonblocking(file: &FileCapability) -> io::Result<()> {
    rustix::fs::flock(
        &file.inner,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| {
        let error = io::Error::from(error);
        if matches!(error.kind(), io::ErrorKind::WouldBlock) {
            io::Error::new(io::ErrorKind::WouldBlock, "mutation lock is held")
        } else {
            error
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn unlock_file(file: &FileCapability) -> io::Result<()> {
    rustix::fs::flock(&file.inner, rustix::fs::FlockOperation::Unlock).map_err(io::Error::from)
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn lock_file_nonblocking(_file: &FileCapability) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "exclusive mutation locking is unavailable",
    ))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn unlock_file(_file: &FileCapability) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn lock_file_nonblocking(file: &FileCapability) -> io::Result<()> {
    windows::lock_file_nonblocking(file)
}

#[cfg(windows)]
fn unlock_file(file: &FileCapability) -> io::Result<()> {
    windows::unlock_file(file)
}

/// Marks a benchmark fixture sparse where the platform requires an explicit operation.
#[cfg(all(feature = "benchmark-support", not(windows)))]
pub fn mark_sparse_file(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

/// Marks a benchmark fixture sparse without exposing the Windows FFI boundary.
#[cfg(all(feature = "benchmark-support", windows))]
pub fn mark_sparse_file(file: &std::fs::File) -> io::Result<()> {
    windows::mark_sparse_file(file)
}

impl FileCapability {
    pub fn same_identity(&self, other: &Self) -> io::Result<bool> {
        self.same_file(other)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
        })
    }

    pub fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(self.inner.metadata()?.len())
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn identity(&self) -> io::Result<FileIdentity> {
        let metadata = self.inner.metadata()?;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub fn stamp(&self) -> io::Result<FileStamp> {
        let metadata = self.inner.metadata()?;
        #[cfg(unix)]
        let change = {
            use std::os::fd::AsFd as _;

            let status = rustix::fs::fstat(self.inner.as_fd())?;
            Some(FileChangeStamp {
                seconds_or_ticks: status.st_ctime,
                nanoseconds: checked_change_nanoseconds(status.st_ctime_nsec)?,
            })
        };
        #[cfg(windows)]
        let change = Some(FileChangeStamp {
            seconds_or_ticks: windows::change_time(self)?,
            nanoseconds: 0,
        });
        #[cfg(not(any(unix, windows)))]
        let change = None;
        Ok(FileStamp {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            length: metadata.len(),
            modified: metadata.modified()?,
            change,
        })
    }

    pub fn matches_identity(&self, expected: &FileIdentity) -> io::Result<bool> {
        Ok(self.identity()? == *expected)
    }

    fn require_single_regular_link(&self) -> io::Result<()> {
        let metadata = self.inner.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file is not a single-linked regular file",
            ));
        }
        Ok(())
    }

    fn same_file(&self, other: &Self) -> io::Result<bool> {
        let left = self.inner.metadata()?;
        let right = other.inner.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
}

#[cfg(unix)]
fn checked_change_nanoseconds<T>(value: T) -> io::Result<i64>
where
    T: TryInto<i64>,
{
    value
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "change timestamp overflowed"))
}

impl Read for FileCapability {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for FileCapability {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for FileCapability {
    fn seek(&mut self, position: std::io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::io::Read;
    use std::io::Write;
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;

    use tempfile::TempDir;

    #[cfg(unix)]
    use super::finish_linked_publication_after_source_remove_failure;
    use super::{Directory, FileIdentity, FileStamp, PhysicalComponent};

    #[cfg(target_os = "linux")]
    #[test]
    fn process_stat_read_completes_short_chunks_and_interrupted_reads() {
        struct Fragmented<'a> {
            remaining: &'a [u8],
            interrupt: bool,
        }

        impl Read for Fragmented<'_> {
            fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
                if self.interrupt {
                    self.interrupt = false;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let bytes = self.remaining.len().min(target.len()).min(3);
                target[..bytes].copy_from_slice(&self.remaining[..bytes]);
                self.remaining = &self.remaining[bytes..];
                Ok(bytes)
            }
        }

        let expected = b"123 (fragmented) S 1 456 0";
        let mut reader = Fragmented {
            remaining: expected,
            interrupt: true,
        };
        let mut buffer = [0_u8; 64];
        let mut diagnostic = super::process_wait_failure_slot();
        let read = super::read_linux_process_stat(
            &mut reader,
            &mut buffer,
            || super::ProcessScanDeadlineState::Active,
            &mut diagnostic,
        )
        .unwrap();

        assert_eq!(&buffer[..read], expected);
        assert_eq!(
            super::parse_linux_process_identity(&buffer[..read], 123, &mut diagnostic,)
                .unwrap()
                .group,
            456
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_stat_read_bounds_repeated_interruptions() {
        struct InterruptedReader(usize);

        impl Read for InterruptedReader {
            fn read(&mut self, _target: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    Ok(0)
                } else {
                    self.0 -= 1;
                    Err(std::io::ErrorKind::Interrupted.into())
                }
            }
        }

        let mut buffer = [0_u8; 64];
        let mut diagnostic = super::process_wait_failure_slot();
        assert_eq!(
            super::read_linux_process_stat(
                &mut InterruptedReader(64),
                &mut buffer,
                || super::ProcessScanDeadlineState::Active,
                &mut diagnostic,
            )
            .unwrap(),
            0
        );
        let mut diagnostic = super::process_wait_failure_slot();
        assert_eq!(
            super::read_linux_process_stat(
                &mut InterruptedReader(65),
                &mut buffer,
                || super::ProcessScanDeadlineState::Active,
                &mut diagnostic,
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[cfg(all(target_os = "linux", feature = "test-support"))]
    #[test]
    fn process_stat_diagnostic_distinguishes_invalid_numeric_fields() {
        use super::ProcessWaitFailureReason;

        for (stat, expected) in [
            (
                &b"invalid (name) S 1 456 0"[..],
                ProcessWaitFailureReason::InvalidPid,
            ),
            (
                &b"123 (name) S invalid 456 0"[..],
                ProcessWaitFailureReason::InvalidParent,
            ),
            (
                &b"123 (name) S 1 invalid 0"[..],
                ProcessWaitFailureReason::InvalidGroup,
            ),
            (
                &b"123 (name) S 1 -1 0"[..],
                ProcessWaitFailureReason::InvalidGroup,
            ),
        ] {
            let mut diagnostic = super::process_wait_failure_slot();
            let error = match super::parse_linux_process_identity(stat, 123, &mut diagnostic) {
                Ok(_) => panic!("malformed process stat unexpectedly parsed"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(diagnostic.take().unwrap().reason, expected);
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn extended_acl_is_rejected_and_cleared_before_private_creation() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inherited = "everyone allow read,list,search,file_inherit,directory_inherit";
        let status = Command::new("/bin/chmod")
            .arg("+a")
            .arg(inherited)
            .arg(&root_path)
            .status()
            .unwrap();
        assert!(status.success());

        let directory = Directory::open_ambient(&root_path).unwrap();
        assert!(directory.verify_private().is_err());

        let child_name = PhysicalComponent::try_new("child").unwrap();
        let child = directory.create_private_dir(&child_name).unwrap();
        child.verify_private().unwrap();
        let file_name = PhysicalComponent::try_new("payload").unwrap();
        let file = child.create_private_file_new(&file_name).unwrap();
        super::apple_acl::verify_no_extended_acl_file(&file.inner).unwrap();
        assert_eq!(
            std::fs::metadata(root_path.join("child/payload"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn no_replace_reports_visibility_when_source_unlink_and_rollback_fail() {
        let failure = finish_linked_publication_after_source_remove_failure(
            std::io::Error::other("injected source unlink failure"),
            Err(std::io::Error::other(
                "injected destination rollback failure",
            )),
            Ok(()),
        );

        assert!(failure.destination_may_be_visible);
        assert_eq!(failure.primary.kind(), std::io::ErrorKind::Other);
    }

    #[cfg(unix)]
    #[test]
    fn no_replace_reports_visibility_when_rollback_sync_fails() {
        let failure = finish_linked_publication_after_source_remove_failure(
            std::io::Error::other("injected source unlink failure"),
            Ok(()),
            Err(std::io::Error::other("injected rollback sync failure")),
        );

        assert!(failure.destination_may_be_visible);
    }

    #[cfg(unix)]
    #[test]
    fn no_replace_reports_not_published_only_after_durable_rollback() {
        let failure = finish_linked_publication_after_source_remove_failure(
            std::io::Error::other("injected source unlink failure"),
            Ok(()),
            Ok(()),
        );

        assert!(!failure.destination_may_be_visible);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_publication_reconcile_republishes_an_exact_retained_stage() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let root = TempDir::new().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
        let staged = PhysicalComponent::try_new("stage").unwrap();
        let mut source = directory.create_private_file_new(&staged).unwrap();
        source.write_all(b"exact plaintext").unwrap();
        source.sync_all().unwrap();

        let published = match directory.reconcile_opened_workspace_publication(
            &source,
            &staged,
            &directory,
            std::path::Path::new("note.txt"),
        ) {
            Ok(published) => published,
            Err(_) => panic!("exact retained staging publication did not reconcile"),
        };

        assert_eq!(published.len().unwrap(), 15);
        assert!(!root.path().join("stage").exists());
        assert_eq!(
            std::fs::read(root.path().join("note.txt")).unwrap(),
            b"exact plaintext"
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_publication_reconcile_removes_only_the_exact_extra_link() {
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = TempDir::new().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
        let staged = PhysicalComponent::try_new("stage").unwrap();
        let mut source = directory.create_private_file_new(&staged).unwrap();
        source.write_all(b"exact plaintext").unwrap();
        source.sync_all().unwrap();
        std::fs::hard_link(root.path().join("stage"), root.path().join("note.txt")).unwrap();
        assert_eq!(
            std::fs::metadata(root.path().join("note.txt"))
                .unwrap()
                .nlink(),
            2
        );

        let published = match directory.reconcile_opened_workspace_publication(
            &source,
            &staged,
            &directory,
            std::path::Path::new("note.txt"),
        ) {
            Ok(published) => published,
            Err(_) => panic!("exact two-link publication did not reconcile"),
        };

        assert!(published.same_identity(&source).unwrap());
        assert!(!root.path().join("stage").exists());
        assert_eq!(
            std::fs::metadata(root.path().join("note.txt"))
                .unwrap()
                .nlink(),
            1
        );
    }

    #[test]
    fn unavailable_change_metadata_is_not_cacheable() {
        let stamp = FileStamp {
            identity: FileIdentity {
                device: 1,
                inode: 2,
            },
            length: 3,
            modified: cap_std::time::SystemTime::from_std(std::time::SystemTime::UNIX_EPOCH),
            change: None,
        };
        assert!(!stamp.is_cacheable());
    }

    #[cfg(unix)]
    #[test]
    fn change_stamp_detects_equal_length_rewrite_after_mtime_restore() {
        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let name = PhysicalComponent::try_new("object").unwrap();
        let mut file = directory.create_file_new(&name).unwrap();
        file.write_all(b"authenticated").unwrap();
        file.sync_all().unwrap();
        let before = file.stamp().unwrap();
        let modified = std::fs::metadata(root_path.join("object"))
            .unwrap()
            .modified()
            .unwrap();

        let probe_name = PhysicalComponent::try_new("clock-probe").unwrap();
        let probe = directory.create_file_new(&probe_name).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut probe_length = 1_u64;
        while probe.stamp().unwrap().change == before.change {
            assert!(
                std::time::Instant::now() < deadline,
                "filesystem change time did not advance"
            );
            probe.inner.set_len(probe_length).unwrap();
            probe_length ^= 1;
            std::thread::yield_now();
        }

        std::fs::write(root_path.join("object"), b"compromised!!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(root_path.join("object"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();

        let after = directory
            .open_file_nofollow(&name)
            .unwrap()
            .stamp()
            .unwrap();
        assert!(before.is_cacheable());
        assert!(before != after);
    }

    #[test]
    fn source_name_swap_cannot_publish_an_unverified_file() {
        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging_name = PhysicalComponent::try_new("staging").unwrap();
        let staging = directory.create_private_dir(&staging_name).unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        staging
            .create_file_new(&source)
            .unwrap()
            .write_all(b"authenticated")
            .unwrap();
        std::fs::write(root_path.join("attacker"), b"attacker").unwrap();

        let opened = staging.open_file_for_rename_nofollow(&source).unwrap();
        std::fs::rename(
            root_path.join("staging/source"),
            root_path.join("staging/original"),
        )
        .unwrap();
        std::fs::rename(root_path.join("attacker"), root_path.join("staging/source")).unwrap();
        let result = staging.rename_opened_no_replace_from_private_staging(
            &opened,
            &source,
            &directory,
            &destination,
        );

        #[cfg(windows)]
        {
            result.unwrap();
            assert_eq!(
                std::fs::read(root_path.join("destination")).unwrap(),
                b"authenticated"
            );
            assert_eq!(
                std::fs::read(root_path.join("staging/source")).unwrap(),
                b"attacker"
            );
            assert_eq!(
                std::fs::read(root_path.join("staging/original"))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
        }

        #[cfg(not(windows))]
        {
            match result {
                Ok(()) => assert_eq!(
                    std::fs::read(root_path.join("destination")).unwrap(),
                    b"authenticated"
                ),
                Err(_) => assert!(!root_path.join("destination").exists()),
            }
            assert_eq!(
                std::fs::read(root_path.join("staging/original")).unwrap(),
                b"authenticated"
            );
        }
    }

    #[test]
    fn checked_replace_and_remove_reject_source_and_destination_swaps() {
        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging = directory
            .create_private_dir(&PhysicalComponent::try_new("staging").unwrap())
            .unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        let mut staged = staging.create_file_new(&source).unwrap();
        staged.write_all(b"replacement").unwrap();
        staged.sync_all().unwrap();
        let mut current = directory.create_file_new(&destination).unwrap();
        current.write_all(b"current").unwrap();
        current.sync_all().unwrap();
        let expected_source = staging.open_file_for_rename_nofollow(&source).unwrap();
        let expected_destination = directory.open_file_nofollow(&destination).unwrap();

        std::fs::rename(
            root_path.join("staging/source"),
            root_path.join("staging/original-source"),
        )
        .unwrap();
        std::fs::write(root_path.join("staging/source"), b"attacker-source").unwrap();
        assert!(
            staging
                .replace_opened_atomic_if_destination_matches(
                    &expected_source,
                    &source,
                    &directory,
                    &destination,
                    &expected_destination,
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"current"
        );

        std::fs::remove_file(root_path.join("staging/source")).unwrap();
        std::fs::rename(
            root_path.join("staging/original-source"),
            root_path.join("staging/source"),
        )
        .unwrap();
        std::fs::rename(
            root_path.join("destination"),
            root_path.join("original-destination"),
        )
        .unwrap();
        std::fs::write(root_path.join("destination"), b"attacker-destination").unwrap();
        assert!(
            staging
                .replace_opened_atomic_if_destination_matches(
                    &expected_source,
                    &source,
                    &directory,
                    &destination,
                    &expected_destination,
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"attacker-destination"
        );

        assert!(
            directory
                .remove_opened_file_if_matches(&expected_destination, &destination)
                .is_err()
        );
        assert!(root_path.join("destination").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reachable_reader_rejects_link_publication_until_staging_name_is_unlinked() {
        use std::os::fd::AsRawFd as _;

        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging = directory
            .create_private_dir(&PhysicalComponent::try_new("staging").unwrap())
            .unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        let mut file = staging.create_file_new(&source).unwrap();
        file.write_all(b"authenticated").unwrap();
        file.sync_all().unwrap();
        let opened = staging.open_file_for_rename_nofollow(&source).unwrap();

        let proc_file = PathBuf::from(format!("/proc/self/fd/{}", opened.inner.as_raw_fd()));
        rustix::fs::linkat(
            rustix::fs::CWD,
            &proc_file,
            &directory.inner,
            destination.as_path(),
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        )
        .unwrap();
        directory.sync().unwrap();
        assert!(directory.open_file_nofollow(&destination).is_err());

        staging.inner.remove_file(source.as_path()).unwrap();
        staging.sync().unwrap();
        let mut published = directory.open_file_nofollow(&destination).unwrap();
        let mut bytes = Vec::new();
        published.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"authenticated");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_child_process_publishes_from_the_exact_authenticated_descriptor() {
        const CHILD: &str = "NOTECRYPT_PLATFORM_FS_UNPRIVILEGED_CHILD";

        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("tests::ordinary_child_process_publishes_from_the_exact_authenticated_descriptor")
                .arg("--nocapture")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .map(|value| u64::from_str_radix(value, 16).unwrap())
            .unwrap();
        assert_eq!(
            effective & (1_u64 << 2),
            0,
            "child unexpectedly has CAP_DAC_READ_SEARCH"
        );

        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging = directory
            .create_private_dir(&PhysicalComponent::try_new("staging").unwrap())
            .unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        let mut file = staging.create_file_new(&source).unwrap();
        file.write_all(b"authenticated").unwrap();
        file.sync_all().unwrap();
        let opened = staging.open_file_for_rename_nofollow(&source).unwrap();

        staging
            .rename_opened_no_replace_from_private_staging(
                &opened,
                &source,
                &directory,
                &destination,
            )
            .unwrap();
        directory.sync().unwrap();
        staging.sync().unwrap();

        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"authenticated"
        );
        assert!(!root_path.join("staging/source").exists());
    }
}
