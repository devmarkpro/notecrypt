use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "test-support")]
use std::sync::Barrier;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notecrypt_platform_fs::{
    Directory, ExclusiveFileLock, FileCapability, FileIdentity, FileStamp, PhysicalComponent,
    WorkspacePublicationEffect,
};
use notecrypt_service::{
    HostPortError, LogicalWorkspacePath, MAX_WORKSPACE_PATHS, MAX_WORKSPACE_PHYSICAL_ENTRIES,
    MaterializationId, MaterializationPublication, MaterializationTarget, OpenedStableSource,
    PendingPublishedGeneration, PublishedGeneration, PublishedWorkspaceGuard, StableSourceToken,
    StartupCleanupReport, SuppressionToken, TargetWorkspaceRequest, VaultWorkspaceRequest,
    WorkspaceAbsenceGuard, WorkspaceLease, WorkspaceOwnershipGuard, WorkspaceProvider,
    WorkspaceWatch,
};

use crate::error::map_io;
use crate::permissions::verify_private;

const BASE_LOCK: &str = ".base-lock";
const OWNER_PREFIX: &str = "o-";
const STAGING_PREFIX: &str = "s-";
const INDEX_EXCLUSION_MARKER: &str = ".metadata_never_index";
const MAX_ACTIVE_WORKSPACES: usize = 1_024;
const MAX_MATERIALIZATIONS: usize = 1_024;
const MAX_TREE_ENTRIES: usize = MAX_WORKSPACE_PHYSICAL_ENTRIES;
const MAX_TREE_DEPTH: usize = 16;
const MAX_PATH_BYTES: usize = 32 * 1_024;
const MAX_BASE_ENTRIES: usize = MAX_ACTIVE_WORKSPACES * 2 + 2;
const INITIAL_PATH_BUDGET_CAPACITY: usize = 128;

#[cfg(feature = "test-support")]
static CREATE_BARRIER: Mutex<Option<CreateBarrier>> = Mutex::new(None);

#[cfg(feature = "test-support")]
thread_local! {
    static MATERIALIZATION_IO_FAULT: std::cell::Cell<Option<MaterializationIoFault>> =
        const { std::cell::Cell::new(None) };
    static MATERIALIZATION_ENTROPY_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static INDEX_EXCLUSION_FAILURE: std::cell::Cell<Option<IndexExclusionFailureDiagnostic>> =
        const { std::cell::Cell::new(None) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexExclusionFailureStage {
    ExistingOpen,
    Create,
    MarkerSync,
    NamedReopen,
    Identity,
    ParentSync,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexExclusionFailureDiagnostic {
    pub stage: IndexExclusionFailureStage,
    pub io_kind: io::ErrorKind,
    pub raw_os_error: Option<i32>,
}

#[cfg(feature = "test-support")]
pub(crate) fn take_index_exclusion_failure_diagnostic() -> Option<IndexExclusionFailureDiagnostic> {
    INDEX_EXCLUSION_FAILURE.take()
}

#[cfg(feature = "test-support")]
fn clear_index_exclusion_failure_diagnostic() {
    INDEX_EXCLUSION_FAILURE.set(None);
}

#[cfg(feature = "test-support")]
fn record_index_exclusion_failure(
    stage: IndexExclusionFailureStage,
    io_kind: io::ErrorKind,
    raw_os_error: Option<i32>,
) {
    INDEX_EXCLUSION_FAILURE.set(Some(IndexExclusionFailureDiagnostic {
        stage,
        io_kind,
        raw_os_error,
    }));
}

fn observe_index_exclusion_io(stage: IndexExclusionFailureStage, error: &io::Error) {
    #[cfg(feature = "test-support")]
    record_index_exclusion_failure(stage, error.kind(), error.raw_os_error());
    #[cfg(not(feature = "test-support"))]
    let _ = (stage, error);
}

fn map_index_exclusion_io(stage: IndexExclusionFailureStage, error: &io::Error) -> HostPortError {
    observe_index_exclusion_io(stage, error);
    map_io(error)
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MaterializationIoFault {
    ShortWrite,
    InterruptedWrite,
    ZeroProgress,
    Flush,
    FileSync,
}

#[cfg(feature = "test-support")]
pub(crate) fn inject_materialization_io_fault(fault: MaterializationIoFault) {
    MATERIALIZATION_IO_FAULT.set(Some(fault));
}

#[cfg(feature = "test-support")]
pub(crate) fn inject_materialization_entropy_failure() {
    MATERIALIZATION_ENTROPY_FAILURE.set(true);
}

#[cfg(feature = "test-support")]
fn take_materialization_io_fault(expected: MaterializationIoFault) -> bool {
    MATERIALIZATION_IO_FAULT.with(|fault| {
        if fault.get() == Some(expected) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(feature = "test-support")]
struct CreateBarrier {
    workspace: String,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(feature = "test-support")]
pub(crate) fn install_create_barrier(
    workspace: String,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
) {
    *CREATE_BARRIER
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(CreateBarrier {
        workspace,
        entered,
        release,
    });
}

#[cfg(feature = "test-support")]
fn wait_at_create_barrier(workspace: &str) {
    let barrier = {
        let mut slot = CREATE_BARRIER
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if slot
            .as_ref()
            .is_some_and(|barrier| barrier.workspace == workspace)
        {
            slot.take()
        } else {
            None
        }
    };
    if let Some(barrier) = barrier {
        barrier.entered.wait();
        barrier.release.wait();
    }
}

pub struct SecureWorkspaceProvider {
    inner: Arc<Inner>,
}

struct Inner {
    base_path: PathBuf,
    base: Directory,
    repository: Directory,
    local_state: Directory,
    state: Mutex<State>,
}

struct State {
    workspaces: HashMap<String, WorkspaceEntry>,
    materializations: HashMap<MaterializationId, MaterializationEntry>,
    generations: HashMap<String, u64>,
    armed: HashMap<PathBuf, ArmedPath>,
    path_budgets: HashMap<PathBuf, PathBudget>,
    durable_directories: HashMap<PathBuf, Option<FileIdentity>>,
}

struct ArmedPath {
    workspace: String,
    materialization: MaterializationId,
    relative_path: PathBuf,
    generation: u64,
    suppression: [u8; 16],
    baseline: FileStamp,
}

struct PathBudget {
    workspace: String,
    _components: usize,
}

struct WorkspaceEntry {
    lease_identity: Arc<()>,
    directory: Directory,
    ownership: ExclusiveFileLock,
    base_lock: Option<ExclusiveFileLock>,
    activated: bool,
    cleanup_pending: bool,
    tree_removed: bool,
    owner_unlinked: bool,
    active_attempts: usize,
    logical_paths: usize,
    physical_entries: usize,
}

struct MaterializationEntry {
    workspace: String,
    parent: Option<Directory>,
    staging: PhysicalComponent,
    destination: PathBuf,
    destination_absolute: PathBuf,
    suppression: [u8; 16],
    state: MaterializationState,
}

enum MaterializationState {
    Reserved,
    Staged(FileCapability),
    Publishing {
        file: FileCapability,
        generation: u64,
    },
    Cleaning,
    AwaitingArm {
        published: FileCapability,
        generation: u64,
    },
    PublishedUnverified {
        source: FileCapability,
        generation: u64,
    },
    Arming {
        generation: u64,
    },
}

struct LeaseOwnership {
    inner: Arc<Inner>,
    workspace: String,
    identity: Arc<()>,
}

pub(crate) struct WorkspaceAttempt {
    inner: Arc<Inner>,
    workspace: String,
}

impl Drop for WorkspaceAttempt {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = state.workspaces.get_mut(&self.workspace) {
            entry.active_attempts = entry.active_attempts.saturating_sub(1);
        }
    }
}

struct GuardedWriter {
    file: Option<FileCapability>,
    attempt: Option<WorkspaceAttempt>,
    materialization: MaterializationId,
}

impl Write for GuardedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("materialization writer is closed"))?;
        #[cfg(feature = "test-support")]
        {
            if take_materialization_io_fault(MaterializationIoFault::InterruptedWrite) {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if take_materialization_io_fault(MaterializationIoFault::ZeroProgress) {
                return Ok(0);
            }
            if take_materialization_io_fault(MaterializationIoFault::ShortWrite) && buffer.len() > 1
            {
                return file.write(&buffer[..buffer.len() - 1]);
            }
        }
        file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(feature = "test-support")]
        if take_materialization_io_fault(MaterializationIoFault::Flush) {
            return Err(io::Error::other("injected materialization flush failure"));
        }
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("materialization writer is closed"))?
            .flush()
    }
}

impl Drop for GuardedWriter {
    fn drop(&mut self) {
        self.file.take();
        if let Some(attempt) = self.attempt.as_ref() {
            cleanup_abandoned_materialization(&attempt.inner, self.materialization);
        }
        self.attempt.take();
    }
}

impl WorkspaceOwnershipGuard for LeaseOwnership {}
impl PublishedWorkspaceGuard for WorkspaceAttempt {}

impl Drop for LeaseOwnership {
    fn drop(&mut self) {
        let base_lock = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state
                .workspaces
                .get_mut(&self.workspace)
                .filter(|entry| Arc::ptr_eq(&entry.lease_identity, &self.identity))
                .and_then(|entry| {
                    entry.cleanup_pending = true;
                    entry.base_lock.take()
                })
        };
        drop(base_lock);
    }
}

struct HeldAbsence {
    inner: Arc<Inner>,
    base_lock: Option<ExclusiveFileLock>,
    ownership: Option<ExclusiveFileLock>,
    owner_name: PhysicalComponent,
    owner_unlinked: bool,
    finalized: bool,
}

impl WorkspaceAbsenceGuard for HeldAbsence {
    fn finalize(&mut self) -> Result<(), HostPortError> {
        if self.finalized {
            return Ok(());
        }
        let base_name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        let base_lock = self
            .base_lock
            .as_ref()
            .ok_or(HostPortError::StaleCapability)?;
        validate_named_lock(&self.inner.base, base_lock, &base_name)?;
        if !self.owner_unlinked {
            let ownership = self
                .ownership
                .as_ref()
                .ok_or(HostPortError::StaleCapability)?;
            self.inner
                .base
                .remove_named_lock_unsynced(ownership, &self.owner_name)
                .map_err(|_| HostPortError::CleanupFailed)?;
            self.owner_unlinked = true;
        }
        self.inner
            .base
            .sync_workspace_cleanup_after_effect()
            .map_err(|_| HostPortError::CleanupFailed)?;
        self.ownership.take();
        self.base_lock.take();
        self.finalized = true;
        Ok(())
    }
}

struct PendingWatch;

impl WorkspaceWatch for PendingWatch {
    fn next_event(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<notecrypt_service::WorkspaceEvent>, HostPortError> {
        Err(HostPortError::Unavailable)
    }
}

impl SecureWorkspaceProvider {
    #[cfg(feature = "test-support")]
    pub(crate) fn seed_workspace_budget(
        &self,
        lease: &WorkspaceLease,
        logical_paths: usize,
        physical_entries: usize,
    ) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .workspaces
            .get_mut(lease.id().child_name())
            .expect("test lease belongs to provider");
        entry.logical_paths = logical_paths;
        entry.physical_entries = physical_entries;
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn toggle_awaiting_arm_suppression(
        &self,
        published: &PublishedGeneration,
    ) -> Result<(), HostPortError> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .materializations
            .get_mut(&published.id())
            .ok_or(HostPortError::StaleCapability)?;
        if !matches!(
            entry.state,
            MaterializationState::AwaitingArm { generation, .. }
                if generation == published.generation()
        ) {
            return Err(HostPortError::StaleCapability);
        }
        entry.suppression[0] ^= 1;
        Ok(())
    }

    pub fn open(
        base_path: PathBuf,
        repository_root: PathBuf,
        local_state_root: PathBuf,
    ) -> Result<Self, HostPortError> {
        if !base_path.is_absolute() {
            return Err(HostPortError::InvalidInput);
        }
        let canonical_base = std::fs::canonicalize(&base_path).map_err(|error| map_io(&error))?;
        if canonical_base.as_os_str() != base_path.as_os_str()
            || base_path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(HostPortError::InvalidInput);
        }
        let base_path = try_copy_path(&base_path)?;
        let base = Directory::open_ambient(&base_path).map_err(|error| map_io(&error))?;
        let repository =
            Directory::open_ambient(&repository_root).map_err(|error| map_io(&error))?;
        let local_state =
            Directory::open_ambient(&local_state_root).map_err(|error| map_io(&error))?;
        verify_private(&base)?;
        reject_alias_or_nesting(&base, &repository)?;
        reject_alias_or_nesting(&base, &local_state)?;
        reject_alias_or_nesting(&repository, &local_state)?;
        ensure_indexing_exclusion(&base)?;
        let mut workspaces = HashMap::new();
        workspaces
            .try_reserve(MAX_ACTIVE_WORKSPACES)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let mut materializations = HashMap::new();
        materializations
            .try_reserve(MAX_MATERIALIZATIONS)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let mut generations = HashMap::new();
        generations
            .try_reserve(MAX_ACTIVE_WORKSPACES)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let mut armed = HashMap::new();
        armed
            .try_reserve(INITIAL_PATH_BUDGET_CAPACITY)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let mut path_budgets = HashMap::new();
        path_budgets
            .try_reserve(INITIAL_PATH_BUDGET_CAPACITY)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let mut durable_directories = HashMap::new();
        durable_directories
            .try_reserve(INITIAL_PATH_BUDGET_CAPACITY)
            .map_err(|_| HostPortError::AllocationFailed)?;
        Ok(Self {
            inner: Arc::new(Inner {
                base_path,
                base,
                repository,
                local_state,
                state: Mutex::new(State {
                    workspaces,
                    materializations,
                    generations,
                    armed,
                    path_budgets,
                    durable_directories,
                }),
            }),
        })
    }

    fn validate_repository(&self, root: &Path) -> Result<(), HostPortError> {
        let requested = Directory::open_ambient(root).map_err(|error| map_io(&error))?;
        if !self
            .inner
            .repository
            .same_identity(&requested)
            .map_err(|error| map_io(&error))?
        {
            return Err(HostPortError::Denied);
        }
        let _ = &self.inner.local_state;
        Ok(())
    }

    fn validate_named_base(&self) -> Result<Directory, HostPortError> {
        let named =
            Directory::open_ambient(&self.inner.base_path).map_err(|error| map_io(&error))?;
        if !self
            .inner
            .base
            .same_identity(&named)
            .map_err(|error| map_io(&error))?
        {
            return Err(HostPortError::StaleCapability);
        }
        Ok(named)
    }

    pub(crate) fn validate_editor_path(
        &self,
        workspace_id: &notecrypt_service::WorkspaceId,
        workspace_file: &Path,
    ) -> Result<(), HostPortError> {
        let (workspace, baseline, relative_path) = {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let workspace = state
                .workspaces
                .get(workspace_id.child_name())
                .ok_or(HostPortError::StaleCapability)?;
            if !workspace.activated || workspace.cleanup_pending {
                return Err(HostPortError::StaleCapability);
            }
            let armed = state
                .armed
                .get(workspace_file)
                .ok_or(HostPortError::StaleCapability)?;
            if armed.workspace != workspace_id.child_name() {
                return Err(HostPortError::StaleCapability);
            }
            if armed.generation == 0 || armed.suppression == [0_u8; 16] {
                return Err(HostPortError::StaleCapability);
            }
            let _materialization = armed.materialization;
            (
                workspace
                    .directory
                    .try_clone()
                    .map_err(|error| map_io(&error))?,
                armed.baseline,
                try_copy_relative_path(&armed.relative_path)?,
            )
        };
        let named_base =
            Directory::open_ambient(&self.inner.base_path).map_err(|error| map_io(&error))?;
        if !self
            .inner
            .base
            .same_identity(&named_base)
            .map_err(|error| map_io(&error))?
        {
            return Err(HostPortError::StaleCapability);
        }
        let child = PhysicalComponent::try_new(workspace_id.child_name())
            .map_err(|error| map_io(&error))?;
        let named_workspace = named_base
            .open_dir_nofollow(&child)
            .map_err(|error| map_io(&error))?;
        if !workspace
            .same_identity(&named_workspace)
            .map_err(|error| map_io(&error))?
        {
            return Err(HostPortError::StaleCapability);
        }
        let named_file = named_workspace
            .open_private_workspace_relative_file_nofollow(&relative_path)
            .map_err(|error| map_io(&error))?;
        if named_file.stamp().map_err(|error| map_io(&error))? != baseline {
            return Err(HostPortError::StaleCapability);
        }
        Ok(())
    }

    pub(crate) fn reserve_editor_attempt(
        &self,
        workspace_id: &notecrypt_service::WorkspaceId,
    ) -> Result<WorkspaceAttempt, HostPortError> {
        let workspace = copy_string(workspace_id.child_name())?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .workspaces
            .get_mut(&workspace)
            .ok_or(HostPortError::StaleCapability)?;
        if !entry.activated || entry.cleanup_pending {
            return Err(HostPortError::StaleCapability);
        }
        entry.active_attempts = entry
            .active_attempts
            .checked_add(1)
            .ok_or(HostPortError::CapacityExceeded)?;
        Ok(WorkspaceAttempt {
            inner: Arc::clone(&self.inner),
            workspace,
        })
    }

    fn create_workspace(
        &self,
        id: &notecrypt_service::WorkspaceId,
    ) -> Result<(PathBuf, Box<dyn WorkspaceOwnershipGuard>), HostPortError> {
        self.validate_named_base()?;
        let child = PhysicalComponent::try_new(id.child_name()).map_err(|error| map_io(&error))?;
        let owner_name = owner_component(id.child_name())?;
        let base_name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.workspaces.len() == MAX_ACTIVE_WORKSPACES
                || state.workspaces.contains_key(id.child_name())
            {
                return Err(HostPortError::CapacityExceeded);
            }
        }
        let root = try_join_child(&self.inner.base_path, id.child_name())?;
        let mut key = String::new();
        key.try_reserve_exact(id.child_name().len())
            .map_err(|_| HostPortError::AllocationFailed)?;
        key.push_str(id.child_name());
        let generation_key = copy_string(&key)?;
        let lease_key = copy_string(&key)?;
        let lease_identity = Arc::new(());
        let ownership_guard: Box<dyn WorkspaceOwnershipGuard> = Box::new(LeaseOwnership {
            inner: Arc::clone(&self.inner),
            workspace: lease_key,
            identity: Arc::clone(&lease_identity),
        });
        #[cfg(feature = "test-support")]
        wait_at_create_barrier(id.child_name());
        let base_lock = self.base_lock()?;
        let on_disk_entries = self
            .inner
            .base
            .workspace_entry_names_bounded(MAX_BASE_ENTRIES)
            .map_err(|error| map_io(&error))?;
        if on_disk_entries.len() > MAX_BASE_ENTRIES.saturating_sub(2) {
            return Err(HostPortError::CapacityExceeded);
        }
        match self.inner.base.entry_kind(&child) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(HostPortError::DestinationExists),
            Err(error) => return Err(map_io(&error)),
        }
        let ownership = self
            .inner
            .base
            .try_lock_exclusive(&owner_name)
            .map_err(|error| map_io(&error))?;
        validate_named_lock(&self.inner.base, &base_lock, &base_name)?;
        validate_named_lock(&self.inner.base, &ownership, &owner_name)?;
        let directory = self
            .inner
            .base
            .create_private_dir(&child)
            .map_err(|error| map_io(&error))?;
        verify_private(&directory)?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.workspaces.len() == MAX_ACTIVE_WORKSPACES || state.workspaces.contains_key(&key) {
            drop(state);
            let _ = self.inner.base.remove_opened_private_tree(
                &directory,
                &child,
                MAX_TREE_ENTRIES,
                MAX_TREE_DEPTH,
            );
            return Err(HostPortError::CapacityExceeded);
        }
        state.workspaces.insert(
            key,
            WorkspaceEntry {
                lease_identity,
                directory,
                ownership,
                base_lock: Some(base_lock),
                activated: false,
                cleanup_pending: false,
                tree_removed: false,
                owner_unlinked: false,
                active_attempts: 0,
                logical_paths: 0,
                physical_entries: 0,
            },
        );
        state.generations.insert(generation_key, 0);
        Ok((root, ownership_guard))
    }

    fn base_lock(&self) -> Result<ExclusiveFileLock, HostPortError> {
        let name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        let lock = self
            .inner
            .base
            .try_lock_exclusive(&name)
            .map_err(|error| map_io(&error))?;
        validate_named_lock(&self.inner.base, &lock, &name)?;
        Ok(lock)
    }

    fn restore_staged_publication(
        &self,
        id: MaterializationId,
        generation: u64,
    ) -> Result<(), HostPortError> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .materializations
            .get_mut(&id)
            .ok_or(HostPortError::StaleCapability)?;
        let retained = std::mem::replace(&mut entry.state, MaterializationState::Reserved);
        let MaterializationState::Publishing {
            file,
            generation: retained_generation,
        } = retained
        else {
            return Err(HostPortError::StaleCapability);
        };
        if retained_generation != generation {
            entry.state = MaterializationState::PublishedUnverified {
                source: file,
                generation: retained_generation,
            };
            return Err(HostPortError::StaleCapability);
        }
        entry.state = MaterializationState::Staged(file);
        Ok(())
    }

    fn begin_workspace_attempt(
        &self,
        lease: &WorkspaceLease,
    ) -> Result<(WorkspaceAttempt, Directory), HostPortError> {
        let workspace = copy_string(lease.id().child_name())?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .workspaces
            .get_mut(&workspace)
            .ok_or(HostPortError::StaleCapability)?;
        if !entry.activated || entry.cleanup_pending {
            return Err(HostPortError::StaleCapability);
        }
        entry.active_attempts = entry
            .active_attempts
            .checked_add(1)
            .ok_or(HostPortError::CapacityExceeded)?;
        let directory = match entry.directory.try_clone() {
            Ok(directory) => directory,
            Err(error) => {
                entry.active_attempts -= 1;
                return Err(map_io(&error));
            }
        };
        drop(state);
        Ok((
            WorkspaceAttempt {
                inner: Arc::clone(&self.inner),
                workspace,
            },
            directory,
        ))
    }

    fn drain_cleanup_pending(&self) -> Result<(usize, usize), HostPortError> {
        let pending = {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let count = state
                .workspaces
                .values()
                .filter(|entry| entry.cleanup_pending)
                .count();
            let mut pending = Vec::new();
            pending
                .try_reserve_exact(count)
                .map_err(|_| HostPortError::AllocationFailed)?;
            for (id, entry) in &state.workspaces {
                if entry.cleanup_pending {
                    pending.push(copy_string(id)?);
                }
            }
            pending
        };
        let mut removed = 0_usize;
        let mut skipped = 0_usize;
        let mut first_error = None;
        for id in pending {
            match self.drain_one_cleanup_pending(&id) {
                Ok(Some(true)) => {
                    removed = removed
                        .checked_add(1)
                        .ok_or(HostPortError::CapacityExceeded)?;
                }
                Ok(Some(false)) => {
                    skipped = skipped
                        .checked_add(1)
                        .ok_or(HostPortError::CapacityExceeded)?;
                }
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok((removed, skipped))
    }

    fn drain_one_cleanup_pending(&self, id: &str) -> Result<Option<bool>, HostPortError> {
        let child = PhysicalComponent::try_new(id).map_err(|error| map_io(&error))?;
        let owner = owner_component(id)?;
        let (directory, tree_removed, owner_unlinked, retained_base_lock) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(entry) = state.workspaces.get_mut(id) else {
                return Ok(None);
            };
            if !entry.cleanup_pending {
                return Ok(None);
            }
            if entry.active_attempts != 0 {
                return Ok(Some(false));
            }
            (
                entry
                    .directory
                    .try_clone()
                    .map_err(|error| map_io(&error))?,
                entry.tree_removed,
                entry.owner_unlinked,
                entry.base_lock.take(),
            )
        };
        let base_lock = match retained_base_lock {
            Some(base_lock) => base_lock,
            None => self.base_lock()?,
        };
        let base_name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        validate_named_lock(&self.inner.base, &base_lock, &base_name)?;
        if !owner_unlinked {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let ownership = &state
                .workspaces
                .get(id)
                .ok_or(HostPortError::CleanupFailed)?
                .ownership;
            validate_named_lock(&self.inner.base, ownership, &owner)?;
        }
        if !tree_removed {
            self.inner
                .base
                .remove_opened_private_tree_unsynced(
                    &directory,
                    &child,
                    MAX_TREE_ENTRIES,
                    MAX_TREE_DEPTH,
                )
                .map_err(|_| HostPortError::CleanupFailed)?;
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state
                .materializations
                .retain(|_, materialization| materialization.workspace != id);
            state.armed.retain(|_, armed| armed.workspace != id);
            state
                .path_budgets
                .retain(|_, budget| budget.workspace != id);
            state
                .durable_directories
                .retain(|path, _| !path_belongs_to_workspace(path, &self.inner.base_path, id));
            state.generations.remove(id);
            state
                .workspaces
                .get_mut(id)
                .ok_or(HostPortError::CleanupFailed)?
                .tree_removed = true;
        }
        self.inner
            .base
            .sync_workspace_cleanup_after_effect()
            .map_err(|_| HostPortError::CleanupFailed)?;
        if !owner_unlinked {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = state
                .workspaces
                .get_mut(id)
                .ok_or(HostPortError::CleanupFailed)?;
            self.inner
                .base
                .remove_named_lock_unsynced(&entry.ownership, &owner)
                .map_err(|_| HostPortError::CleanupFailed)?;
            entry.owner_unlinked = true;
        }
        self.inner
            .base
            .sync_workspace_cleanup_after_effect()
            .map_err(|_| HostPortError::CleanupFailed)?;
        self.inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .workspaces
            .remove(id)
            .ok_or(HostPortError::CleanupFailed)?;
        Ok(Some(true))
    }

    fn cleanup_disk_entry(
        &self,
        child_name: &OsString,
        base_lock: &ExclusiveFileLock,
        base_name: &PhysicalComponent,
    ) -> Result<Option<bool>, HostPortError> {
        let name = child_name.to_str().ok_or(HostPortError::CleanupFailed)?;
        if name == BASE_LOCK || name == INDEX_EXCLUSION_MARKER {
            return Ok(None);
        }
        if let Some(id) = name.strip_prefix(OWNER_PREFIX) {
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(HostPortError::CleanupFailed);
            }
            let child = PhysicalComponent::try_new(id).map_err(|error| map_io(&error))?;
            match self.inner.base.entry_kind(&child) {
                Ok(_) => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(map_io(&error)),
            }
            let owner = PhysicalComponent::try_new(name).map_err(|error| map_io(&error))?;
            let ownership = match self.inner.base.try_lock_exclusive(&owner) {
                Ok(ownership) => ownership,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(Some(false));
                }
                Err(error) => return Err(map_io(&error)),
            };
            validate_named_lock(&self.inner.base, base_lock, base_name)?;
            validate_named_lock(&self.inner.base, &ownership, &owner)?;
            self.inner
                .base
                .remove_named_lock_unsynced(&ownership, &owner)
                .map_err(|_| HostPortError::CleanupFailed)?;
            self.inner
                .base
                .sync_workspace_cleanup_after_effect()
                .map_err(|_| HostPortError::CleanupFailed)?;
            return Ok(None);
        }
        if name.len() != 32
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(HostPortError::CleanupFailed);
        }
        let child = PhysicalComponent::try_new(name).map_err(|error| map_io(&error))?;
        let owner = owner_component(name)?;
        let ownership = match self.inner.base.try_lock_exclusive(&owner) {
            Ok(guard) => guard,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(Some(false));
            }
            Err(error) => return Err(map_io(&error)),
        };
        validate_named_lock(&self.inner.base, base_lock, base_name)?;
        validate_named_lock(&self.inner.base, &ownership, &owner)?;
        let directory = self
            .inner
            .base
            .open_private_dir_for_cleanup(&child)
            .map_err(|error| map_io(&error))?;
        self.inner
            .base
            .remove_opened_private_tree_unsynced(
                &directory,
                &child,
                MAX_TREE_ENTRIES,
                MAX_TREE_DEPTH,
            )
            .map_err(|_| HostPortError::CleanupFailed)?;
        self.inner
            .base
            .sync_workspace_cleanup_after_effect()
            .map_err(|_| HostPortError::CleanupFailed)?;
        self.inner
            .base
            .remove_named_lock_unsynced(&ownership, &owner)
            .map_err(|_| HostPortError::CleanupFailed)?;
        self.inner
            .base
            .sync_workspace_cleanup_after_effect()
            .map_err(|_| HostPortError::CleanupFailed)?;
        Ok(Some(true))
    }
}

impl WorkspaceProvider for SecureWorkspaceProvider {
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError> {
        let (mut removed, mut skipped, mut first_error) = match self.drain_cleanup_pending() {
            Ok((removed, skipped)) => (removed, skipped, None),
            Err(error) => (0, 0, Some(error)),
        };
        let base_lock = self.base_lock()?;
        let base_name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        validate_named_lock(&self.inner.base, &base_lock, &base_name)?;
        let names = self
            .inner
            .base
            .workspace_entry_names_bounded(MAX_BASE_ENTRIES)
            .map_err(|error| map_io(&error))?;
        for child_name in names {
            match self.cleanup_disk_entry(&child_name, &base_lock, &base_name) {
                Ok(Some(true)) => {
                    removed = removed
                        .checked_add(1)
                        .ok_or(HostPortError::CapacityExceeded)?;
                }
                Ok(Some(false)) => {
                    skipped = skipped
                        .checked_add(1)
                        .ok_or(HostPortError::CapacityExceeded)?;
                }
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Err(error) = self.inner.base.sync_workspace_cleanup_after_effect() {
            first_error.get_or_insert(map_io(&error));
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        StartupCleanupReport::try_new(removed, skipped)
    }

    fn create_target(
        &self,
        request: TargetWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        self.validate_repository(request.repository_root())?;
        let (root, ownership) = self.create_workspace(request.id())?;
        WorkspaceLease::from_target_request(request, root, ownership)
    }

    fn create_whole_vault(
        &self,
        request: VaultWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        self.validate_repository(request.repository_root())?;
        let (root, ownership) = self.create_workspace(request.id())?;
        WorkspaceLease::from_vault_request(request, root, ownership)
    }

    fn confirm_activated(&self, lease: &WorkspaceLease) -> Result<(), HostPortError> {
        let named_base = self.validate_named_base()?;
        let expected = try_join_child(&self.inner.base_path, lease.id().child_name())?;
        if lease.root() != expected {
            return Err(HostPortError::StaleCapability);
        }
        let child =
            PhysicalComponent::try_new(lease.id().child_name()).map_err(|error| map_io(&error))?;
        let named_workspace = named_base
            .open_dir_nofollow(&child)
            .map_err(|error| map_io(&error))?;
        let base_lock = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = state
                .workspaces
                .get_mut(lease.id().child_name())
                .ok_or(HostPortError::StaleCapability)?;
            if entry.activated || entry.cleanup_pending {
                return Err(HostPortError::StaleCapability);
            }
            if !entry
                .directory
                .same_identity(&named_workspace)
                .map_err(|error| map_io(&error))?
            {
                return Err(HostPortError::StaleCapability);
            }
            let base_lock = entry
                .base_lock
                .take()
                .ok_or(HostPortError::StaleCapability)?;
            entry.activated = true;
            base_lock
        };
        drop(base_lock);
        Ok(())
    }

    fn materialization_target(
        &self,
        lease: &WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
    ) -> Result<MaterializationTarget, HostPortError> {
        self.validate_named_base()?;
        #[cfg(feature = "test-support")]
        if MATERIALIZATION_ENTROPY_FAILURE.with(|failure| failure.replace(false)) {
            return Err(HostPortError::Unavailable);
        }
        let (attempt, workspace) = self.begin_workspace_attempt(lease)?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| HostPortError::Unavailable)?;
        let id = MaterializationId::from_random_bytes(random);
        let staging = staging_component(&random)?;
        let mut suppression = [0_u8; 16];
        getrandom::fill(&mut suppression).map_err(|_| HostPortError::Unavailable)?;
        let destination_path = try_join_relative(lease.root(), relative_path.as_path())?;
        let staging_path = try_copy_path(
            destination_path
                .parent()
                .ok_or(HostPortError::InvalidInput)?,
        )?;
        let staging_path = try_join_child(&staging_path, staging.as_str())?;
        let workspace_key = copy_string(lease.id().child_name())?;
        let budget_workspace = copy_string(lease.id().child_name())?;
        let retained_destination = destination_path
            .file_name()
            .ok_or(HostPortError::InvalidInput)
            .map(Path::new)
            .and_then(try_copy_relative_path)?;
        let retained_absolute = try_copy_path(&destination_path)?;
        let budget_path = try_copy_path(&destination_path)?;
        let durable_prefixes = materialization_prefix_paths(lease.root(), relative_path.as_path())?;
        let charged_components = relative_path
            .as_path()
            .components()
            .count()
            .checked_add(1)
            .ok_or(HostPortError::CapacityExceeded)?;
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.materializations.len() == MAX_MATERIALIZATIONS
                || state.materializations.contains_key(&id)
            {
                return Err(HostPortError::CapacityExceeded);
            }
            if state.armed.contains_key(&destination_path)
                || state
                    .materializations
                    .values()
                    .any(|entry| entry.destination_absolute == destination_path)
            {
                return Err(HostPortError::DestinationExists);
            }
            let new_budget = !state.path_budgets.contains_key(&destination_path);
            if new_budget {
                let workspace_entry = state
                    .workspaces
                    .get(lease.id().child_name())
                    .ok_or(HostPortError::StaleCapability)?;
                if workspace_entry.logical_paths == MAX_WORKSPACE_PATHS
                    || workspace_entry
                        .physical_entries
                        .checked_add(charged_components)
                        .is_none_or(|total| total > MAX_WORKSPACE_PHYSICAL_ENTRIES)
                {
                    return Err(HostPortError::CapacityExceeded);
                }
                state
                    .path_budgets
                    .try_reserve(1)
                    .map_err(|_| HostPortError::AllocationFailed)?;
            }
            state
                .materializations
                .try_reserve(1)
                .map_err(|_| HostPortError::AllocationFailed)?;
            let pending_armed_slots = state
                .materializations
                .len()
                .checked_add(1)
                .ok_or(HostPortError::CapacityExceeded)?;
            state
                .armed
                .try_reserve(pending_armed_slots)
                .map_err(|_| HostPortError::AllocationFailed)?;
            let missing_durable_prefixes = durable_prefixes
                .iter()
                .filter(|prefix| !state.durable_directories.contains_key(*prefix))
                .count();
            state
                .durable_directories
                .try_reserve(missing_durable_prefixes)
                .map_err(|_| HostPortError::AllocationFailed)?;
            for prefix in &durable_prefixes {
                if !state.durable_directories.contains_key(prefix) {
                    state
                        .durable_directories
                        .insert(try_copy_path(prefix)?, None);
                }
            }
            if new_budget {
                let workspace_entry = state
                    .workspaces
                    .get_mut(lease.id().child_name())
                    .ok_or(HostPortError::StaleCapability)?;
                workspace_entry.logical_paths += 1;
                workspace_entry.physical_entries += charged_components;
                state.path_budgets.insert(
                    budget_path,
                    PathBudget {
                        workspace: budget_workspace,
                        _components: charged_components,
                    },
                );
            }
            state.materializations.insert(
                id,
                MaterializationEntry {
                    workspace: workspace_key,
                    parent: None,
                    staging: staging.clone(),
                    destination: retained_destination,
                    destination_absolute: retained_absolute,
                    suppression,
                    state: MaterializationState::Reserved,
                },
            );
        }
        let (parent, destination) = match open_materialization_parent(
            &self.inner,
            workspace,
            relative_path.as_path(),
            &durable_prefixes,
        ) {
            Ok(opened) => opened,
            Err(error) => {
                self.inner
                    .state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .materializations
                    .remove(&id);
                return Err(error);
            }
        };
        if destination.as_os_str()
            != destination_path
                .file_name()
                .ok_or(HostPortError::InvalidInput)?
        {
            return Err(HostPortError::StaleCapability);
        }
        let retained_parent = match parent.try_clone() {
            Ok(parent) => parent,
            Err(error) => {
                self.inner
                    .state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .materializations
                    .remove(&id);
                return Err(map_io(&error));
            }
        };
        self.inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .materializations
            .get_mut(&id)
            .ok_or(HostPortError::CleanupFailed)?
            .parent = Some(retained_parent);
        let file = match parent.create_private_file_new(&staging) {
            Ok(file) => file,
            Err(error) => {
                match parent.open_file_for_rename_nofollow(&staging) {
                    Ok(file) => {
                        let mut state = self
                            .inner
                            .state
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        if let Some(entry) = state.materializations.get_mut(&id) {
                            entry.state = MaterializationState::Staged(file);
                        }
                        drop(state);
                        cleanup_abandoned_materialization(&self.inner, id);
                    }
                    Err(open_error) if open_error.kind() == io::ErrorKind::NotFound => {
                        self.inner
                            .state
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .materializations
                            .remove(&id);
                    }
                    Err(_) => {}
                }
                return Err(map_io(&error));
            }
        };
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = state
                .materializations
                .get_mut(&id)
                .ok_or(HostPortError::CleanupFailed)?;
            entry.state = MaterializationState::Staged(file);
        }
        let writer = {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = state
                .materializations
                .get(&id)
                .ok_or(HostPortError::CleanupFailed)?;
            let MaterializationState::Staged(file) = &entry.state else {
                return Err(HostPortError::CleanupFailed);
            };
            file.try_clone().map_err(|error| map_io(&error))
        };
        let writer = match writer {
            Ok(writer) => writer,
            Err(error) => {
                cleanup_abandoned_materialization(&self.inner, id);
                return Err(error);
            }
        };
        let target = MaterializationTarget::new(
            lease,
            id,
            staging_path,
            destination_path,
            SuppressionToken::from_random_bytes(suppression),
            Box::new(GuardedWriter {
                file: Some(writer),
                attempt: Some(attempt),
                materialization: id,
            }),
        )?;
        Ok(target)
    }

    fn publish_materialized(
        &self,
        lease: &WorkspaceLease,
        mut target: MaterializationTarget,
    ) -> Result<MaterializationPublication, HostPortError> {
        self.validate_named_base()?;
        target.flush()?;
        let (publication_attempt, publication_directory) = self.begin_workspace_attempt(lease)?;
        drop(publication_directory);
        let publication_guard = Box::new(publication_attempt);
        let (file, parent, staging, destination, generation) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let workspace = state
                .workspaces
                .get(lease.id().child_name())
                .ok_or(HostPortError::StaleCapability)?;
            if !workspace.activated || workspace.cleanup_pending {
                return Err(HostPortError::StaleCapability);
            }
            let generation = state
                .generations
                .get_mut(lease.id().child_name())
                .ok_or(HostPortError::StaleCapability)?
                .checked_add(1)
                .ok_or(HostPortError::CapacityExceeded)?;
            *state
                .generations
                .get_mut(lease.id().child_name())
                .ok_or(HostPortError::StaleCapability)? = generation;
            let entry = state
                .materializations
                .get_mut(&target.id())
                .ok_or(HostPortError::StaleCapability)?;
            if entry.workspace != lease.id().child_name()
                || entry.suppression != *target.suppression().as_bytes()
                || entry.destination_absolute != target.destination()
            {
                return Err(HostPortError::StaleCapability);
            }
            let MaterializationState::Staged(file) = &entry.state else {
                return Err(HostPortError::StaleCapability);
            };
            let io_file = file.try_clone().map_err(|error| map_io(&error))?;
            let parent = entry
                .parent
                .as_ref()
                .ok_or(HostPortError::StaleCapability)?
                .try_clone()
                .map_err(|error| map_io(&error))?;
            let staging = PhysicalComponent::try_new(entry.staging.as_str())
                .map_err(|error| map_io(&error))?;
            let destination = try_copy_relative_path(&entry.destination)?;
            (io_file, parent, staging, destination, generation)
        };
        let mut pending = PendingPublishedGeneration::from_materialization(
            lease,
            &target,
            generation,
            publication_guard,
        )?;
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let workspace = state
                .workspaces
                .get(lease.id().child_name())
                .ok_or(HostPortError::StaleCapability)?;
            if !workspace.activated || workspace.cleanup_pending {
                return Err(HostPortError::StaleCapability);
            }
            let entry = state
                .materializations
                .get_mut(&target.id())
                .ok_or(HostPortError::StaleCapability)?;
            if entry.workspace != lease.id().child_name()
                || entry.suppression != *target.suppression().as_bytes()
                || entry.destination_absolute != target.destination()
            {
                return Err(HostPortError::StaleCapability);
            }
            let retained = std::mem::replace(&mut entry.state, MaterializationState::Reserved);
            let MaterializationState::Staged(file) = retained else {
                return Err(HostPortError::StaleCapability);
            };
            entry.state = MaterializationState::Publishing { file, generation };
        }
        drop(target);
        #[cfg(feature = "test-support")]
        let sync_result = if take_materialization_io_fault(MaterializationIoFault::FileSync) {
            Err(io::Error::other(
                "injected materialization file sync failure",
            ))
        } else {
            file.sync_all()
        };
        #[cfg(not(feature = "test-support"))]
        let sync_result = file.sync_all();
        if let Err(error) = sync_result {
            self.restore_staged_publication(pending.id(), generation)?;
            cleanup_abandoned_materialization(&self.inner, pending.id());
            return Err(map_io(&error));
        }
        let published = match parent.rename_opened_no_replace_to_workspace(
            &file,
            &staging,
            &parent,
            &destination,
        ) {
            Ok(published) => published,
            Err(error) => {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let entry = state
                    .materializations
                    .get_mut(&pending.id())
                    .ok_or(HostPortError::StaleCapability)?;
                if error.effect() == WorkspacePublicationEffect::PublishedUnverified {
                    let retained =
                        std::mem::replace(&mut entry.state, MaterializationState::Reserved);
                    let MaterializationState::Publishing {
                        file: source,
                        generation: retained_generation,
                    } = retained
                    else {
                        return Err(HostPortError::StaleCapability);
                    };
                    entry.state = MaterializationState::PublishedUnverified {
                        source,
                        generation: retained_generation,
                    };
                    return Ok(MaterializationPublication::DurabilityPending(pending));
                }
                let retained = std::mem::replace(&mut entry.state, MaterializationState::Reserved);
                let MaterializationState::Publishing {
                    file,
                    generation: retained_generation,
                } = retained
                else {
                    return Err(HostPortError::StaleCapability);
                };
                if retained_generation != generation {
                    entry.state = MaterializationState::PublishedUnverified {
                        source: file,
                        generation: retained_generation,
                    };
                    return Err(HostPortError::StaleCapability);
                }
                entry.state = MaterializationState::Staged(file);
                return Err(map_io(error.error()));
            }
        };
        let durability = parent.sync();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = state
            .materializations
            .get_mut(&pending.id())
            .ok_or(HostPortError::StaleCapability)?;
        if !matches!(
            entry.state,
            MaterializationState::Publishing {
                generation: retained,
                ..
            } if retained == generation
        ) {
            return Err(HostPortError::StaleCapability);
        }
        entry.state = MaterializationState::AwaitingArm {
            published,
            generation,
        };
        if durability.is_err() {
            return Ok(MaterializationPublication::DurabilityPending(pending));
        }
        drop(state);
        if self.validate_named_base().is_err() {
            return Ok(MaterializationPublication::DurabilityPending(pending));
        }
        pending
            .spend(lease)
            .map(MaterializationPublication::Durable)
    }

    fn confirm_materialized(
        &self,
        lease: &WorkspaceLease,
        pending: &mut PendingPublishedGeneration,
    ) -> Result<PublishedGeneration, HostPortError> {
        if pending.is_spent() {
            return Err(HostPortError::StaleCapability);
        }
        let (published, parent, staging, destination, generation, unverified) = {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = state
                .materializations
                .get(&pending.id())
                .ok_or(HostPortError::StaleCapability)?;
            if entry.workspace != lease.id().child_name()
                || entry.destination_absolute != pending.path()
                || entry.suppression != *pending.suppression().as_bytes()
            {
                return Err(HostPortError::StaleCapability);
            }
            let (published, generation, unverified) = match &entry.state {
                MaterializationState::AwaitingArm {
                    published,
                    generation,
                } => (
                    published.try_clone().map_err(|error| map_io(&error))?,
                    *generation,
                    false,
                ),
                MaterializationState::PublishedUnverified { source, generation } => (
                    source.try_clone().map_err(|error| map_io(&error))?,
                    *generation,
                    true,
                ),
                _ => return Err(HostPortError::StaleCapability),
            };
            (
                published,
                entry
                    .parent
                    .as_ref()
                    .ok_or(HostPortError::StaleCapability)?
                    .try_clone()
                    .map_err(|error| map_io(&error))?,
                PhysicalComponent::try_new(entry.staging.as_str())
                    .map_err(|error| map_io(&error))?,
                try_copy_relative_path(&entry.destination)?,
                generation,
                unverified,
            )
        };
        if generation != pending.generation() {
            return Err(HostPortError::StaleCapability);
        }
        let published = if unverified {
            match parent.reconcile_opened_workspace_publication(
                &published,
                &staging,
                &parent,
                &destination,
            ) {
                Ok(published) => published,
                Err(error) if error.effect() == WorkspacePublicationEffect::PublishedUnverified => {
                    return Err(HostPortError::DurabilityPending);
                }
                Err(error) => return Err(map_io(error.error())),
            }
        } else {
            match parent.opened_workspace_file_matches(&published, &destination) {
                Ok(true) => published,
                Ok(false) => return Err(HostPortError::CleanupFailed),
                Err(error) => return Err(map_io(&error)),
            }
        };
        parent.sync().map_err(|error| map_io(&error))?;
        self.validate_named_base()?;
        if unverified {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = state
                .materializations
                .get_mut(&pending.id())
                .ok_or(HostPortError::StaleCapability)?;
            if !matches!(
                entry.state,
                MaterializationState::PublishedUnverified {
                    generation: current,
                    ..
                } if current == generation
            ) {
                return Err(HostPortError::StaleCapability);
            }
            entry.state = MaterializationState::AwaitingArm {
                published,
                generation,
            };
        }
        pending.spend(lease)
    }

    fn arm_published_path(
        &self,
        lease: &WorkspaceLease,
        published: &mut PublishedGeneration,
    ) -> Result<(), HostPortError> {
        if published.is_armed() {
            return Err(HostPortError::StaleCapability);
        }
        self.validate_named_base()?;
        let path = try_copy_path(published.path())?;
        let relative_path = published
            .path()
            .strip_prefix(lease.root())
            .map_err(|_| HostPortError::StaleCapability)
            .and_then(try_copy_relative_path)?;
        let destination = published
            .path()
            .file_name()
            .ok_or(HostPortError::StaleCapability)
            .map(Path::new)
            .and_then(try_copy_relative_path)?;
        let workspace = copy_string(lease.id().child_name())?;
        let materialization = published.id();
        let generation = published.generation();
        let suppression = *published.suppression().as_bytes();
        let (parent, held) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.armed.contains_key(&path) {
                return Err(HostPortError::DestinationExists);
            }
            let entry = state
                .materializations
                .get_mut(&materialization)
                .ok_or(HostPortError::StaleCapability)?;
            if entry.workspace != workspace
                || entry.destination_absolute != published.path()
                || entry.suppression != suppression
            {
                return Err(HostPortError::StaleCapability);
            }
            let retained = std::mem::replace(
                &mut entry.state,
                MaterializationState::Arming { generation },
            );
            let MaterializationState::AwaitingArm {
                published: held,
                generation: retained_generation,
            } = retained
            else {
                return Err(HostPortError::StaleCapability);
            };
            if retained_generation != generation {
                entry.state = MaterializationState::AwaitingArm {
                    published: held,
                    generation: retained_generation,
                };
                return Err(HostPortError::StaleCapability);
            }
            let parent = entry.parent.take().ok_or(HostPortError::StaleCapability)?;
            (parent, held)
        };

        let armed_result = (|| {
            if !parent
                .opened_workspace_file_matches(&held, &destination)
                .map_err(|_| HostPortError::StaleCapability)?
            {
                return Err(HostPortError::StaleCapability);
            }
            let stamp = held.stamp().map_err(|_| HostPortError::StaleCapability)?;
            Ok(ArmedPath {
                workspace,
                materialization,
                relative_path,
                generation,
                suppression,
                baseline: stamp,
            })
        })();

        let armed = match armed_result {
            Ok(armed) => armed,
            Err(error) => {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(entry) = state.materializations.get_mut(&materialization)
                    && matches!(
                        entry.state,
                        MaterializationState::Arming { generation: current }
                            if current == generation
                    )
                {
                    entry.parent = Some(parent);
                    entry.state = MaterializationState::AwaitingArm {
                        published: held,
                        generation,
                    };
                }
                return Err(error);
            }
        };

        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let exact_arming = state
            .materializations
            .get(&materialization)
            .is_some_and(|entry| {
                entry.parent.is_none()
                    && matches!(
                        entry.state,
                        MaterializationState::Arming { generation: current }
                            if current == generation
                    )
            });
        if !exact_arming || state.armed.contains_key(&path) {
            if let Some(entry) = state.materializations.get_mut(&materialization)
                && exact_arming
            {
                entry.parent = Some(parent);
                entry.state = MaterializationState::AwaitingArm {
                    published: held,
                    generation,
                };
            }
            return Err(HostPortError::StaleCapability);
        }
        state.armed.insert(path, armed);
        state.materializations.remove(&materialization);
        drop(state);
        drop(parent);
        drop(held);
        published.mark_armed()
    }

    fn watch(&self, _lease: &WorkspaceLease) -> Result<Box<dyn WorkspaceWatch>, HostPortError> {
        Ok(Box::new(PendingWatch))
    }

    fn open_stable_source(
        &self,
        _lease: &WorkspaceLease,
        _relative_path: &LogicalWorkspacePath,
        _expected_generation: u64,
    ) -> Result<OpenedStableSource, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn validate_stable_source(
        &self,
        _lease: &WorkspaceLease,
        _token: &StableSourceToken,
    ) -> Result<(), HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn remove_workspace(
        &self,
        lease: &WorkspaceLease,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, HostPortError> {
        let id = copy_string(lease.id().child_name())?;
        let child = PhysicalComponent::try_new(&id).map_err(|error| map_io(&error))?;
        let owner_name = owner_component(&id)?;
        let mut absence = Box::new(HeldAbsence {
            inner: Arc::clone(&self.inner),
            base_lock: None,
            ownership: None,
            owner_name,
            owner_unlinked: false,
            finalized: false,
        });
        let (directory, tree_removed, base_lock) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let (directory, tree_removed, base_lock) = {
                let entry = state
                    .workspaces
                    .get_mut(&id)
                    .ok_or(HostPortError::StaleCapability)?;
                entry.cleanup_pending = true;
                if entry.active_attempts != 0 {
                    return Err(HostPortError::CleanupFailed);
                }
                (
                    entry
                        .directory
                        .try_clone()
                        .map_err(|error| map_io(&error))?,
                    entry.tree_removed,
                    entry.base_lock.take(),
                )
            };
            state
                .materializations
                .retain(|_, materialization| materialization.workspace != id);
            state
                .armed
                .retain(|path, _| !path.starts_with(lease.root()));
            state
                .path_budgets
                .retain(|_, budget| budget.workspace != id);
            state
                .durable_directories
                .retain(|path, _| !path.starts_with(lease.root()));
            (directory, tree_removed, base_lock)
        };
        let base_lock = match base_lock {
            Some(lock) => lock,
            None => self.base_lock()?,
        };
        let base_name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        validate_named_lock(&self.inner.base, &base_lock, &base_name)?;
        {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let ownership = &state
                .workspaces
                .get(&id)
                .ok_or(HostPortError::StaleCapability)?
                .ownership;
            validate_named_lock(&self.inner.base, ownership, &absence.owner_name)?;
        }
        if !tree_removed {
            self.inner
                .base
                .remove_opened_private_tree_unsynced(
                    &directory,
                    &child,
                    MAX_TREE_ENTRIES,
                    MAX_TREE_DEPTH,
                )
                .map_err(|_| HostPortError::CleanupFailed)?;
            self.inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .workspaces
                .get_mut(&id)
                .ok_or(HostPortError::CleanupFailed)?
                .tree_removed = true;
        }
        self.inner
            .base
            .sync_workspace_cleanup_after_effect()
            .map_err(|_| HostPortError::CleanupFailed)?;
        let entry = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .workspaces
            .remove(&id)
            .ok_or(HostPortError::CleanupFailed)?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.generations.remove(&id);
        drop(state);
        absence.base_lock = Some(base_lock);
        absence.ownership = Some(entry.ownership);
        Ok(absence)
    }

    fn acquire_verified_absence(
        &self,
        id: &notecrypt_service::WorkspaceId,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, HostPortError> {
        let owner_name = owner_component(id.child_name())?;
        let mut absence = Box::new(HeldAbsence {
            inner: Arc::clone(&self.inner),
            base_lock: None,
            ownership: None,
            owner_name,
            owner_unlinked: false,
            finalized: false,
        });
        let base_lock = self.base_lock()?;
        let child = PhysicalComponent::try_new(id.child_name()).map_err(|error| map_io(&error))?;
        match self.inner.base.entry_kind(&child) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(HostPortError::CleanupFailed),
            Err(error) => return Err(map_io(&error)),
        }
        let ownership = self
            .inner
            .base
            .try_lock_exclusive(&absence.owner_name)
            .map_err(|error| map_io(&error))?;
        let base_name = PhysicalComponent::try_new(BASE_LOCK).map_err(|error| map_io(&error))?;
        validate_named_lock(&self.inner.base, &base_lock, &base_name)?;
        validate_named_lock(&self.inner.base, &ownership, &absence.owner_name)?;
        absence.base_lock = Some(base_lock);
        absence.ownership = Some(ownership);
        Ok(absence)
    }
}

fn ensure_indexing_exclusion(base: &Directory) -> Result<(), HostPortError> {
    #[cfg(feature = "test-support")]
    clear_index_exclusion_failure_diagnostic();
    let name = Path::new(INDEX_EXCLUSION_MARKER);
    let marker = match base.open_private_workspace_file_nofollow(name) {
        Ok(marker) => marker,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match base.create_private_workspace_file_new(name) {
                Ok(marker) => marker,
                Err(create_error) => {
                    observe_index_exclusion_io(IndexExclusionFailureStage::Create, &create_error);
                    match base.open_private_workspace_file_nofollow(name) {
                        Ok(marker) => {
                            #[cfg(feature = "test-support")]
                            clear_index_exclusion_failure_diagnostic();
                            marker
                        }
                        Err(_) => return Err(map_io(&create_error)),
                    }
                }
            }
        }
        Err(error) => {
            return Err(map_index_exclusion_io(
                IndexExclusionFailureStage::ExistingOpen,
                &error,
            ));
        }
    };
    base.sync_private_workspace_file_if_matches(name, &marker)
        .map_err(|error| map_index_exclusion_io(IndexExclusionFailureStage::MarkerSync, &error))?;
    let named = base
        .open_private_workspace_file_nofollow(name)
        .map_err(|error| map_index_exclusion_io(IndexExclusionFailureStage::NamedReopen, &error))?;
    if !marker
        .same_identity(&named)
        .map_err(|error| map_index_exclusion_io(IndexExclusionFailureStage::Identity, &error))?
    {
        #[cfg(feature = "test-support")]
        record_index_exclusion_failure(
            IndexExclusionFailureStage::Identity,
            io::ErrorKind::InvalidData,
            None,
        );
        return Err(HostPortError::StaleCapability);
    }
    base.sync()
        .map_err(|error| map_index_exclusion_io(IndexExclusionFailureStage::ParentSync, &error))
}

fn reject_alias_or_nesting(left: &Directory, right: &Directory) -> Result<(), HostPortError> {
    if left.is_same_or_ancestor_of(right) || right.is_same_or_ancestor_of(left) {
        Err(HostPortError::InvalidInput)
    } else {
        Ok(())
    }
}

fn owner_component(id: &str) -> Result<PhysicalComponent, HostPortError> {
    let mut value = String::new();
    value
        .try_reserve_exact(OWNER_PREFIX.len().saturating_add(id.len()))
        .map_err(|_| HostPortError::AllocationFailed)?;
    value.push_str(OWNER_PREFIX);
    value.push_str(id);
    PhysicalComponent::try_new(&value).map_err(|error| map_io(&error))
}

fn staging_component(random: &[u8; 16]) -> Result<PhysicalComponent, HostPortError> {
    let mut value = String::new();
    value
        .try_reserve_exact(STAGING_PREFIX.len() + 32)
        .map_err(|_| HostPortError::AllocationFailed)?;
    value.push_str(STAGING_PREFIX);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| HostPortError::AllocationFailed)?;
    }
    PhysicalComponent::try_new(&value).map_err(|error| map_io(&error))
}

fn try_copy_path(path: &Path) -> Result<PathBuf, HostPortError> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(HostPortError::InvalidInput);
    }
    let mut value = OsString::new();
    value
        .try_reserve_exact(path.as_os_str().as_encoded_bytes().len())
        .map_err(|_| HostPortError::AllocationFailed)?;
    value.push(path.as_os_str());
    Ok(PathBuf::from(value))
}

fn try_join_child(base: &Path, child: &str) -> Result<PathBuf, HostPortError> {
    let total = base
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(child.len())
        .and_then(|value| value.checked_add(1))
        .ok_or(HostPortError::CapacityExceeded)?;
    if total > MAX_PATH_BYTES {
        return Err(HostPortError::CapacityExceeded);
    }
    let mut result = PathBuf::new();
    result
        .try_reserve_exact(total)
        .map_err(|_| HostPortError::AllocationFailed)?;
    result.push(base);
    result.push(child);
    Ok(result)
}

fn try_join_relative(base: &Path, child: &Path) -> Result<PathBuf, HostPortError> {
    let total = base
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(child.as_os_str().as_encoded_bytes().len())
        .and_then(|value| value.checked_add(1))
        .ok_or(HostPortError::CapacityExceeded)?;
    if total > MAX_PATH_BYTES {
        return Err(HostPortError::CapacityExceeded);
    }
    let mut result = PathBuf::new();
    result
        .try_reserve_exact(total)
        .map_err(|_| HostPortError::AllocationFailed)?;
    result.push(base);
    result.push(child);
    Ok(result)
}

fn try_copy_relative_path(path: &Path) -> Result<PathBuf, HostPortError> {
    if path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(HostPortError::InvalidInput);
    }
    let mut value = OsString::new();
    value
        .try_reserve_exact(path.as_os_str().as_encoded_bytes().len())
        .map_err(|_| HostPortError::AllocationFailed)?;
    value.push(path.as_os_str());
    Ok(PathBuf::from(value))
}

fn copy_string(value: &str) -> Result<String, HostPortError> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(value.len())
        .map_err(|_| HostPortError::AllocationFailed)?;
    retained.push_str(value);
    Ok(retained)
}

fn validate_named_lock(
    directory: &Directory,
    lock: &ExclusiveFileLock,
    name: &PhysicalComponent,
) -> Result<(), HostPortError> {
    if lock
        .validates_named_file(directory, name)
        .map_err(|error| map_io(&error))?
    {
        Ok(())
    } else {
        Err(HostPortError::StaleCapability)
    }
}

fn cleanup_abandoned_materialization(inner: &Arc<Inner>, id: MaterializationId) {
    let prepared = {
        let mut state = inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(entry) = state.materializations.get_mut(&id) else {
            return;
        };
        let MaterializationState::Staged(_) = &entry.state else {
            return;
        };
        let parent = match entry
            .parent
            .as_ref()
            .and_then(|parent| parent.try_clone().ok())
        {
            Some(parent) => parent,
            None => return,
        };
        let staging = match PhysicalComponent::try_new(entry.staging.as_str()) {
            Ok(staging) => staging,
            Err(_) => return,
        };
        let MaterializationState::Staged(file) =
            std::mem::replace(&mut entry.state, MaterializationState::Cleaning)
        else {
            return;
        };
        (parent, staging, file)
    };
    let (parent, staging, file) = prepared;
    let cleaned = parent
        .remove_opened_file_if_matches(&file, &staging)
        .is_ok();
    let mut state = inner
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(entry) = state.materializations.get_mut(&id) else {
        return;
    };
    if !matches!(entry.state, MaterializationState::Cleaning) {
        return;
    }
    if cleaned {
        state.materializations.remove(&id);
    } else {
        entry.state = MaterializationState::Staged(file);
    }
}

fn open_materialization_parent(
    inner: &Inner,
    mut directory: Directory,
    path: &Path,
    durable_prefixes: &[PathBuf],
) -> Result<(Directory, PathBuf), HostPortError> {
    let mut components = path.components().peekable();
    let mut prefix_index = 0_usize;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(HostPortError::InvalidInput);
        };
        if components.peek().is_none() {
            return Ok((directory, PathBuf::from(name)));
        }
        let prefix = durable_prefixes
            .get(prefix_index)
            .ok_or(HostPortError::StaleCapability)?;
        prefix_index += 1;
        let cached = inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .durable_directories
            .get(prefix)
            .copied()
            .flatten();
        let opened = match cached {
            Some(expected) => match directory.open_private_workspace_dir(Path::new(name)) {
                Ok(opened) if opened.identity() == expected => opened,
                Ok(_) => {
                    *inner
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .durable_directories
                        .get_mut(prefix)
                        .ok_or(HostPortError::StaleCapability)? = None;
                    directory
                        .open_or_create_private_workspace_dir(Path::new(name))
                        .map_err(|error| map_io(&error))?
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => directory
                    .open_or_create_private_workspace_dir(Path::new(name))
                    .map_err(|error| map_io(&error))?,
                Err(error) => return Err(map_io(&error)),
            },
            None => directory
                .open_or_create_private_workspace_dir(Path::new(name))
                .map_err(|error| map_io(&error))?,
        };
        *inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .durable_directories
            .get_mut(prefix)
            .ok_or(HostPortError::StaleCapability)? = Some(opened.identity());
        directory = opened;
    }
    Err(HostPortError::InvalidInput)
}

fn materialization_prefix_paths(
    workspace_root: &Path,
    relative_path: &Path,
) -> Result<Vec<PathBuf>, HostPortError> {
    let component_count = relative_path.components().count();
    let prefix_count = component_count
        .checked_sub(1)
        .ok_or(HostPortError::InvalidInput)?;
    let mut prefixes = Vec::new();
    prefixes
        .try_reserve_exact(prefix_count)
        .map_err(|_| HostPortError::AllocationFailed)?;
    let mut current = try_copy_path(workspace_root)?;
    for component in relative_path.components().take(prefix_count) {
        let Component::Normal(name) = component else {
            return Err(HostPortError::InvalidInput);
        };
        current = try_join_relative(&current, Path::new(name))?;
        prefixes.push(try_copy_path(&current)?);
    }
    Ok(prefixes)
}

fn path_belongs_to_workspace(path: &Path, base: &Path, workspace: &str) -> bool {
    let Ok(relative) = path.strip_prefix(base) else {
        return false;
    };
    relative
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == workspace)
}
