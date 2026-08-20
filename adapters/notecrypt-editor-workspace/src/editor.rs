use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notecrypt_service::{
    EDITOR_FORCE_REAP_GRACE, EditorCommand, EditorExit, EditorLaunchRequest, EditorProcess,
    EditorQuiescence, EditorResolutionRequest, EditorSupervisionMode, EditorSupervisor,
    HostPortError,
};

use crate::error::map_io;
use crate::workspace::SecureWorkspaceProvider;

const MAX_SUPERVISED_PROCESSES: usize = 1_024;
const DROP_REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(feature = "test-support")]
const MAX_SCRIPTED_DROP_REAP_PENDING_POLLS: usize = 2_048;

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum EditorLaunchFailureStage {
    ExecutableAttestation,
    WorkspacePathRevalidation,
    ExecutableRevalidation,
    ProcessSpawn,
    InitialStopSignal,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct EditorLaunchFailureDiagnostic {
    pub stage: EditorLaunchFailureStage,
    pub error: HostPortError,
    pub io_kind: Option<std::io::ErrorKind>,
    pub raw_os_error: Option<i32>,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct EditorLaunchDiagnosticKey {
    workspace: [u8; 32],
    generation: u64,
}

#[cfg(feature = "test-support")]
impl EditorLaunchDiagnosticKey {
    fn new(workspace: &notecrypt_service::WorkspaceId, generation: u64) -> Self {
        let mut child_name = [0_u8; 32];
        child_name.copy_from_slice(workspace.child_name().as_bytes());
        Self {
            workspace: child_name,
            generation,
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy)]
struct EditorLaunchFailureRecord {
    key: EditorLaunchDiagnosticKey,
    diagnostic: Option<EditorLaunchFailureDiagnostic>,
}

#[cfg(feature = "test-support")]
struct EditorLaunchFailureRecords {
    records: Vec<EditorLaunchFailureRecord>,
    capacity: usize,
}

#[cfg(feature = "test-support")]
struct EditorLaunchDiagnosticReservation<'a> {
    supervisor: &'a SupervisorInner,
    key: EditorLaunchDiagnosticKey,
    retain: bool,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy)]
enum DropReapTestControl {
    PendingPolls(usize),
    AlwaysPending { elapsed: Duration },
    GroupActivePolls(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnershipProfile {
    OwnedTree,
    BlockingUnowned,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EditorProfileFamily {
    Vim,
    Nano,
    EmacsClient,
    Code,
    Zed,
    Notepad,
    NotepadPlusPlus,
}

pub struct ProcessEditorSupervisor {
    inner: Arc<SupervisorInner>,
}

struct SupervisorInner {
    provider: Arc<SecureWorkspaceProvider>,
    registry: Mutex<Vec<Arc<ProcessEntry>>>,
    capacity: usize,
    #[cfg(feature = "test-support")]
    trusted_test_executable: Option<notecrypt_platform_fs::TrustedExecutable>,
    #[cfg(feature = "test-support")]
    pre_revalidation_barrier: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    #[cfg(feature = "test-support")]
    pre_spawn_barrier: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    #[cfg(feature = "test-support")]
    launch_admission_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(feature = "test-support")]
    launch_failures: Mutex<EditorLaunchFailureRecords>,
    #[cfg(feature = "test-support")]
    drop_reap_test_control: Mutex<Option<DropReapTestControl>>,
}

struct ProcessEntry {
    workspace: String,
    generation: u64,
    ownership: OwnershipProfile,
    mode: EditorSupervisionMode,
    attempt: Mutex<Option<crate::workspace::WorkspaceAttempt>>,
    state: Mutex<ProcessState>,
    token_attached: AtomicBool,
    #[cfg(all(feature = "test-support", unix))]
    wait_failure: Mutex<Option<notecrypt_platform_fs::ProcessWaitFailureDiagnostic>>,
}

enum ProcessState {
    Spawning(StopIntent),
    #[cfg(any(unix, windows))]
    Running(notecrypt_platform_fs::SupervisedProcess),
    Terminal(EditorExit),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StopIntent {
    None,
    Graceful,
    Force,
}

struct ProcessToken {
    supervisor: Arc<SupervisorInner>,
    entry: Arc<ProcessEntry>,
    exit: Option<EditorExit>,
}

#[derive(Clone, Copy)]
enum ProcessObservation {
    Active,
    Detached,
    Terminal(EditorExit),
}

enum PreparedProcessObservation {
    Complete(ProcessObservation),
    #[cfg(unix)]
    NeedsGroupProof(i32),
}

impl ProcessEditorSupervisor {
    pub fn new(provider: Arc<SecureWorkspaceProvider>) -> Result<Self, HostPortError> {
        Self::new_with_capacity(provider, MAX_SUPERVISED_PROCESSES)
    }

    fn new_with_capacity(
        provider: Arc<SecureWorkspaceProvider>,
        capacity: usize,
    ) -> Result<Self, HostPortError> {
        if capacity == 0 || capacity > MAX_SUPERVISED_PROCESSES {
            return Err(HostPortError::CapacityExceeded);
        }
        let mut registry = Vec::new();
        registry
            .try_reserve_exact(capacity)
            .map_err(|_| HostPortError::AllocationFailed)?;
        #[cfg(feature = "test-support")]
        let launch_failures = {
            let mut records = Vec::new();
            records
                .try_reserve_exact(capacity)
                .map_err(|_| HostPortError::AllocationFailed)?;
            EditorLaunchFailureRecords { records, capacity }
        };
        Ok(Self {
            inner: Arc::new(SupervisorInner {
                provider,
                registry: Mutex::new(registry),
                capacity,
                #[cfg(feature = "test-support")]
                trusted_test_executable: None,
                #[cfg(feature = "test-support")]
                pre_revalidation_barrier: Mutex::new(None),
                #[cfg(feature = "test-support")]
                pre_spawn_barrier: Mutex::new(None),
                #[cfg(feature = "test-support")]
                launch_admission_barrier: Mutex::new(None),
                #[cfg(feature = "test-support")]
                launch_failures: Mutex::new(launch_failures),
                #[cfg(feature = "test-support")]
                drop_reap_test_control: Mutex::new(None),
            }),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn new_with_trusted_test_executable(
        provider: Arc<SecureWorkspaceProvider>,
        executable: std::path::PathBuf,
    ) -> Result<Self, HostPortError> {
        Self::new_with_trusted_test_executable_and_capacity(
            provider,
            executable,
            MAX_SUPERVISED_PROCESSES,
        )
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn new_with_trusted_test_executable_and_capacity(
        provider: Arc<SecureWorkspaceProvider>,
        executable: std::path::PathBuf,
        capacity: usize,
    ) -> Result<Self, HostPortError> {
        let canonical =
            std::fs::canonicalize(executable).map_err(|error| map_process_io(&error))?;
        let trusted_test_executable =
            notecrypt_platform_fs::TrustedExecutable::open_test_only(&canonical)
                .map_err(|error| map_process_io(&error))?;
        let mut supervisor = Self::new_with_capacity(provider, capacity)?;
        Arc::get_mut(&mut supervisor.inner)
            .ok_or(HostPortError::StaleCapability)?
            .trusted_test_executable = Some(trusted_test_executable);
        Ok(supervisor)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_pre_revalidation_barrier(
        &self,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner
            .pre_revalidation_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace((entered, release));
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_pre_spawn_barrier(
        &self,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner
            .pre_spawn_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace((entered, release));
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_launch_admission_barrier(&self, barrier: Arc<std::sync::Barrier>) {
        self.inner
            .launch_admission_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(barrier);
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn clear_launch_admission_barrier(&self) {
        self.inner
            .launch_admission_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn take_launch_failure_diagnostic(
        &self,
        workspace: &notecrypt_service::WorkspaceId,
        generation: u64,
    ) -> Option<EditorLaunchFailureDiagnostic> {
        let key = EditorLaunchDiagnosticKey::new(workspace, generation);
        let mut failures = self
            .inner
            .launch_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let index = failures
            .records
            .iter()
            .position(|record| record.key == key)?;
        let diagnostic = failures.records[index].diagnostic?;
        failures.records.swap_remove(index);
        Some(diagnostic)
    }

    #[cfg(all(feature = "test-support", unix))]
    #[doc(hidden)]
    pub fn take_process_wait_failure_diagnostic(
        &self,
        workspace: &notecrypt_service::WorkspaceId,
        generation: u64,
    ) -> Option<notecrypt_platform_fs::ProcessWaitFailureDiagnostic> {
        let entry = self.find_process_for_test(workspace, generation)?;
        let diagnostic = entry
            .wait_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if diagnostic.is_some() && entry.is_terminal_for_test() {
            self.inner.remove_exact(&entry);
        }
        diagnostic
    }

    #[cfg(all(feature = "test-support", unix))]
    #[doc(hidden)]
    pub fn leader_exited_unreaped_for_test(
        &self,
        workspace: &notecrypt_service::WorkspaceId,
        generation: u64,
    ) -> Result<bool, HostPortError> {
        let entry = self
            .find_process_for_test(workspace, generation)
            .ok_or(HostPortError::StaleCapability)?;
        entry.leader_exited_unreaped_for_test()
    }

    #[cfg(all(feature = "test-support", unix))]
    fn find_process_for_test(
        &self,
        workspace: &notecrypt_service::WorkspaceId,
        generation: u64,
    ) -> Option<Arc<ProcessEntry>> {
        let registry = self
            .inner
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        registry
            .iter()
            .find(|entry| {
                entry.workspace == workspace.child_name() && entry.generation == generation
            })
            .map(Arc::clone)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_drop_reap_pending_polls(&self, polls: usize) -> Result<(), HostPortError> {
        if polls > MAX_SCRIPTED_DROP_REAP_PENDING_POLLS {
            return Err(HostPortError::CapacityExceeded);
        }
        self.inner
            .drop_reap_test_control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(DropReapTestControl::PendingPolls(polls));
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_drop_reap_deadline_fault(&self) {
        self.inner
            .drop_reap_test_control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(DropReapTestControl::AlwaysPending {
                elapsed: Duration::ZERO,
            });
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn install_drop_reap_group_active_polls(&self, polls: usize) {
        self.inner
            .drop_reap_test_control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(DropReapTestControl::GroupActivePolls(polls));
    }
}

impl EditorSupervisor for ProcessEditorSupervisor {
    fn launch(
        &self,
        request: EditorLaunchRequest,
    ) -> Result<Box<dyn EditorProcess>, HostPortError> {
        let (workspace_id, resolution, workspace_file, generation) = request.into_parts();
        #[cfg(feature = "test-support")]
        let diagnostic_key = EditorLaunchDiagnosticKey::new(&workspace_id, generation);
        #[cfg(feature = "test-support")]
        let mut diagnostic = self.inner.reserve_launch_diagnostic(diagnostic_key)?;
        #[cfg(feature = "test-support")]
        self.inner.wait_at_launch_admission_barrier();
        let (selected, mode) = select_editor(resolution)?;
        let (attestation, selected, profile) = match attest_editor_command_detailed(
            selected,
            #[cfg(feature = "test-support")]
            self.inner.trusted_test_executable.as_ref(),
        ) {
            Ok(attested) => attested,
            Err(failure) => {
                #[cfg(feature = "test-support")]
                diagnostic.record_parts(
                    EditorLaunchFailureStage::ExecutableAttestation,
                    failure.error,
                    failure.io_kind,
                    failure.raw_os_error,
                );
                return Err(failure.error);
            }
        };
        let resolved = apply_profile_with_family(selected, mode, profile)?;
        resolved
            .command
            .validate_workspace_argument(&workspace_file)?;
        #[cfg(feature = "test-support")]
        let test_trusted = self.inner.trusted_test_executable.is_some();
        #[cfg(not(feature = "test-support"))]
        let test_trusted = false;
        validate_strict_mode(&resolved, test_trusted)?;
        let workspace = try_string(workspace_id.child_name())?;
        let entry = Arc::new(ProcessEntry {
            workspace,
            generation,
            ownership: resolved.ownership,
            mode: resolved.mode,
            attempt: Mutex::new(None),
            state: Mutex::new(ProcessState::Spawning(StopIntent::None)),
            token_attached: AtomicBool::new(true),
            #[cfg(all(feature = "test-support", unix))]
            wait_failure: Mutex::new(None),
        });
        let token: Box<dyn EditorProcess> = Box::new(ProcessToken {
            supervisor: Arc::clone(&self.inner),
            entry: Arc::clone(&entry),
            exit: None,
        });
        let attempt = self.inner.provider.reserve_editor_attempt(&workspace_id)?;
        entry
            .attempt
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(attempt);
        {
            let mut registry = self
                .inner
                .registry
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if registry.len() == self.inner.capacity
                || registry.iter().any(|existing| existing.same_key(&entry))
            {
                return Err(HostPortError::CapacityExceeded);
            }
            registry.push(Arc::clone(&entry));
        }
        if let Err(error) = self
            .inner
            .provider
            .validate_editor_path(&workspace_id, &workspace_file)
        {
            #[cfg(feature = "test-support")]
            diagnostic.record(
                EditorLaunchFailureStage::WorkspacePathRevalidation,
                error,
                None,
            );
            self.inner.remove_exact(&entry);
            return Err(error);
        }
        let (executable, arguments) = resolved.command.into_parts();
        #[cfg(feature = "test-support")]
        self.inner.wait_at_pre_revalidation_barrier();
        if let Err(failure) = attestation.revalidate(&executable) {
            #[cfg(feature = "test-support")]
            diagnostic.record_parts(
                EditorLaunchFailureStage::ExecutableRevalidation,
                failure.error,
                failure.io_kind,
                failure.raw_os_error,
            );
            self.inner.remove_exact(&entry);
            return Err(failure.error);
        }
        #[cfg(feature = "test-support")]
        self.inner.wait_at_pre_spawn_barrier();
        #[cfg(any(unix, windows))]
        let process = match notecrypt_platform_fs::SupervisedProcess::spawn(
            &executable,
            &arguments,
            &workspace_file,
            entry.owns_tree(),
        ) {
            Ok(process) => process,
            Err(error) => {
                let mapped = map_process_io(&error);
                #[cfg(feature = "test-support")]
                diagnostic.record(EditorLaunchFailureStage::ProcessSpawn, mapped, Some(&error));
                self.inner.remove_exact(&entry);
                return Err(mapped);
            }
        };
        #[cfg(any(unix, windows))]
        {
            let mut state = entry
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let ProcessState::Spawning(intent) = *state else {
                let _ = process.force_stop();
                drop(state);
                self.inner.remove_exact(&entry);
                return Err(HostPortError::StaleCapability);
            };
            *state = ProcessState::Running(process);
            let ProcessState::Running(process) = &*state else {
                return Err(HostPortError::StaleCapability);
            };
            let signal_result = if intent == StopIntent::Force {
                process.force_stop()
            } else if intent == StopIntent::Graceful {
                process.request_stop()
            } else {
                Ok(())
            };
            if let Err(error) = signal_result {
                let mapped = map_io(&error);
                #[cfg(feature = "test-support")]
                diagnostic.record(
                    EditorLaunchFailureStage::InitialStopSignal,
                    mapped,
                    Some(&error),
                );
                entry.token_attached.store(false, Ordering::Release);
                return Err(mapped);
            }
        }
        Ok(token)
    }

    fn request_stop_all(&self) -> Result<(), HostPortError> {
        let entries = self.inner.snapshot();
        let mut first_error = None;
        for entry in entries.into_iter().flatten() {
            if entry.owns_tree()
                && let Err(error) = entry.signal(false)
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn poll_quiescence(&self) -> Result<EditorQuiescence, HostPortError> {
        let entries = self.inner.snapshot();
        let mut first_error = None;
        let mut observations = [None; MAX_SUPERVISED_PROCESSES];
        #[cfg(unix)]
        let mut groups = [0_i32; MAX_SUPERVISED_PROCESSES];
        #[cfg(unix)]
        let mut group_entries = [0_usize; MAX_SUPERVISED_PROCESSES];
        #[cfg(unix)]
        let mut group_members = [false; MAX_SUPERVISED_PROCESSES];
        #[cfg(unix)]
        let mut group_count = 0_usize;
        for (index, entry) in entries.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            match entry.prepare_batched_poll() {
                Ok(PreparedProcessObservation::Complete(observation)) => {
                    observations[index] = Some(observation);
                }
                #[cfg(unix)]
                Ok(PreparedProcessObservation::NeedsGroupProof(group)) => {
                    groups[group_count] = group;
                    group_entries[group_count] = index;
                    group_count += 1;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    observations[index] = Some(ProcessObservation::Active);
                }
            }
        }
        #[cfg(unix)]
        if group_count != 0 {
            if let Err(error) = notecrypt_platform_fs::process_groups_have_other_members(
                &groups[..group_count],
                &mut group_members[..group_count],
            ) {
                first_error.get_or_insert(map_io(&error));
                for entry_index in &group_entries[..group_count] {
                    observations[*entry_index] = Some(ProcessObservation::Detached);
                }
            } else {
                for probe in 0..group_count {
                    let entry_index = group_entries[probe];
                    let entry = entries[entry_index]
                        .as_ref()
                        .expect("group probe retains its exact process entry");
                    match entry.complete_batched_poll(group_members[probe]) {
                        Ok(observation) => observations[entry_index] = Some(observation),
                        Err(error) => {
                            first_error.get_or_insert(error);
                            observations[entry_index] = Some(ProcessObservation::Active);
                        }
                    }
                }
            }
        }
        let mut active = 0_usize;
        let mut unreaped = 0_usize;
        for (entry, observation) in entries
            .into_iter()
            .zip(observations)
            .filter_map(|(entry, observation)| entry.zip(observation))
        {
            match observation {
                ProcessObservation::Terminal(_) => {
                    if !entry.token_attached.load(Ordering::Acquire) {
                        self.inner.remove_terminal_exact(&entry);
                    }
                }
                ProcessObservation::Active | ProcessObservation::Detached => {
                    active = active
                        .checked_add(1)
                        .ok_or(HostPortError::CapacityExceeded)?;
                    unreaped = unreaped
                        .checked_add(1)
                        .ok_or(HostPortError::CapacityExceeded)?;
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(EditorQuiescence::new(active, unreaped))
    }

    fn force_stop_all(&self) -> Result<(), HostPortError> {
        let entries = self.inner.snapshot();
        let mut first_error = None;
        for entry in entries.into_iter().flatten() {
            if entry.owns_tree()
                && let Err(error) = entry.signal(true)
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl EditorProcess for ProcessToken {
    fn try_wait(&mut self) -> Result<Option<EditorExit>, HostPortError> {
        if let Some(exit) = self.exit {
            return Ok(Some(exit));
        }
        if !self.supervisor.contains_exact(&self.entry) {
            return Err(HostPortError::StaleCapability);
        }
        let entry = Arc::clone(&self.entry);
        match entry.poll()? {
            ProcessObservation::Active => Ok(None),
            ProcessObservation::Detached => Err(HostPortError::DetachedEditor),
            ProcessObservation::Terminal(exit) => {
                self.supervisor.remove_terminal_exact(&entry);
                self.exit = Some(exit);
                Ok(Some(exit))
            }
        }
    }

    fn request_stop(&mut self) -> Result<(), HostPortError> {
        self.signal(false)
    }

    fn force_stop(&mut self) -> Result<(), HostPortError> {
        self.signal(true)
    }
}

impl ProcessToken {
    fn signal(&self, force: bool) -> Result<(), HostPortError> {
        if !self.supervisor.contains_exact(&self.entry) {
            return Err(HostPortError::StaleCapability);
        }
        if !self.entry.owns_tree() {
            return Err(HostPortError::DetachedEditor);
        }
        self.entry.signal(force)
    }
}

impl ProcessEntry {
    fn owns_tree(&self) -> bool {
        matches!(
            self.mode,
            EditorSupervisionMode::Blocking | EditorSupervisionMode::Strict
        ) && self.ownership == OwnershipProfile::OwnedTree
    }

    fn same_key(&self, other: &Self) -> bool {
        self.workspace == other.workspace && self.generation == other.generation
    }

    fn poll(&self) -> Result<ProcessObservation, HostPortError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match &mut *state {
            ProcessState::Spawning(_) => Ok(ProcessObservation::Active),
            #[cfg(any(unix, windows))]
            ProcessState::Running(process) => {
                let observation = match process.poll(self.owns_tree()) {
                    Ok(observation) => observation,
                    Err(error) => {
                        #[cfg(all(feature = "test-support", unix))]
                        self.record_wait_failure(process.take_wait_failure_diagnostic());
                        return Err(map_io(&error));
                    }
                };
                Ok(self.apply_supervised_state(&mut state, observation))
            }
            ProcessState::Terminal(exit) => Ok(ProcessObservation::Terminal(*exit)),
        }
    }

    fn prepare_batched_poll(&self) -> Result<PreparedProcessObservation, HostPortError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match &mut *state {
            ProcessState::Spawning(_) => Ok(PreparedProcessObservation::Complete(
                ProcessObservation::Active,
            )),
            #[cfg(unix)]
            ProcessState::Running(process) if self.owns_tree() => {
                let prepared = match process.prepare_owned_poll() {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        #[cfg(feature = "test-support")]
                        self.record_wait_failure(process.take_wait_failure_diagnostic());
                        return Err(map_io(&error));
                    }
                };
                match prepared {
                    notecrypt_platform_fs::OwnedProcessPoll::Running => Ok(
                        PreparedProcessObservation::Complete(ProcessObservation::Active),
                    ),
                    notecrypt_platform_fs::OwnedProcessPoll::NeedsGroupProof(group) => {
                        Ok(PreparedProcessObservation::NeedsGroupProof(group))
                    }
                }
            }
            #[cfg(any(unix, windows))]
            ProcessState::Running(process) => {
                let observation = match process.poll(false) {
                    Ok(observation) => observation,
                    Err(error) => {
                        #[cfg(all(feature = "test-support", unix))]
                        self.record_wait_failure(process.take_wait_failure_diagnostic());
                        return Err(map_io(&error));
                    }
                };
                Ok(PreparedProcessObservation::Complete(
                    self.apply_supervised_state(&mut state, observation),
                ))
            }
            ProcessState::Terminal(exit) => Ok(PreparedProcessObservation::Complete(
                ProcessObservation::Terminal(*exit),
            )),
        }
    }

    #[cfg(unix)]
    fn complete_batched_poll(
        &self,
        has_other_members: bool,
    ) -> Result<ProcessObservation, HostPortError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match &mut *state {
            ProcessState::Running(process) => {
                let observation = match process.finish_owned_poll(has_other_members) {
                    Ok(observation) => observation,
                    Err(error) => {
                        #[cfg(feature = "test-support")]
                        self.record_wait_failure(process.take_wait_failure_diagnostic());
                        return Err(map_io(&error));
                    }
                };
                Ok(self.apply_supervised_state(&mut state, observation))
            }
            ProcessState::Terminal(exit) => Ok(ProcessObservation::Terminal(*exit)),
            ProcessState::Spawning(_) => Ok(ProcessObservation::Active),
        }
    }

    #[cfg(all(feature = "test-support", unix))]
    fn record_wait_failure(
        &self,
        diagnostic: Option<notecrypt_platform_fs::ProcessWaitFailureDiagnostic>,
    ) {
        let Some(diagnostic) = diagnostic else {
            return;
        };
        let mut slot = self
            .wait_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if slot.is_none() {
            *slot = Some(diagnostic);
        }
    }

    #[cfg(all(feature = "test-support", unix))]
    fn has_wait_failure(&self) -> bool {
        self.wait_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
    }

    #[cfg(all(feature = "test-support", unix))]
    fn is_terminal_for_test(&self) -> bool {
        matches!(
            *self.state.lock().unwrap_or_else(|error| error.into_inner()),
            ProcessState::Terminal(_)
        )
    }

    #[cfg(all(feature = "test-support", unix))]
    fn leader_exited_unreaped_for_test(&self) -> Result<bool, HostPortError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match &*state {
            ProcessState::Running(process) => process
                .leader_exited_unreaped()
                .map_err(|error| map_io(&error)),
            ProcessState::Terminal(_) => Ok(true),
            ProcessState::Spawning(_) => Ok(false),
        }
    }

    #[cfg(any(unix, windows))]
    fn apply_supervised_state(
        &self,
        state: &mut ProcessState,
        observation: notecrypt_platform_fs::SupervisedProcessState,
    ) -> ProcessObservation {
        match observation {
            notecrypt_platform_fs::SupervisedProcessState::Running => ProcessObservation::Active,
            notecrypt_platform_fs::SupervisedProcessState::LeaderExitedTreeActive => {
                ProcessObservation::Detached
            }
            notecrypt_platform_fs::SupervisedProcessState::Exited(code) => {
                let exit = EditorExit::new(code);
                *state = ProcessState::Terminal(exit);
                self.attempt
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                ProcessObservation::Terminal(exit)
            }
        }
    }

    fn signal(&self, force: bool) -> Result<(), HostPortError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match &mut *state {
            ProcessState::Spawning(intent) => {
                let requested = if force {
                    StopIntent::Force
                } else {
                    StopIntent::Graceful
                };
                if requested > *intent {
                    *intent = requested;
                }
                Ok(())
            }
            #[cfg(any(unix, windows))]
            ProcessState::Running(process) if force => {
                process.force_stop().map_err(|error| map_io(&error))
            }
            #[cfg(any(unix, windows))]
            ProcessState::Running(process) => {
                process.request_stop().map_err(|error| map_io(&error))
            }
            ProcessState::Terminal(_) => Ok(()),
        }
    }
}

#[cfg(feature = "test-support")]
impl EditorLaunchDiagnosticReservation<'_> {
    fn record(
        &mut self,
        stage: EditorLaunchFailureStage,
        error: HostPortError,
        source: Option<&std::io::Error>,
    ) {
        self.record_parts(
            stage,
            error,
            source.map(std::io::Error::kind),
            source.and_then(std::io::Error::raw_os_error),
        );
    }

    fn record_parts(
        &mut self,
        stage: EditorLaunchFailureStage,
        error: HostPortError,
        io_kind: Option<std::io::ErrorKind>,
        raw_os_error: Option<i32>,
    ) {
        let mut failures = self
            .supervisor
            .launch_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = failures
            .records
            .iter_mut()
            .find(|record| record.key == self.key)
            .expect("an admitted launch retains its exact diagnostic slot");
        record.diagnostic = Some(EditorLaunchFailureDiagnostic {
            stage,
            error,
            io_kind,
            raw_os_error,
        });
        self.retain = true;
    }
}

#[cfg(feature = "test-support")]
impl Drop for EditorLaunchDiagnosticReservation<'_> {
    fn drop(&mut self) {
        if !self.retain {
            self.supervisor.release_launch_diagnostic(self.key);
        }
    }
}

impl SupervisorInner {
    #[cfg(feature = "test-support")]
    fn reserve_launch_diagnostic(
        &self,
        key: EditorLaunchDiagnosticKey,
    ) -> Result<EditorLaunchDiagnosticReservation<'_>, HostPortError> {
        let mut failures = self
            .launch_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failures.records.len() == failures.capacity
            || failures.records.iter().any(|record| record.key == key)
        {
            return Err(HostPortError::CapacityExceeded);
        }
        failures.records.push(EditorLaunchFailureRecord {
            key,
            diagnostic: None,
        });
        Ok(EditorLaunchDiagnosticReservation {
            supervisor: self,
            key,
            retain: false,
        })
    }

    #[cfg(feature = "test-support")]
    fn release_launch_diagnostic(&self, key: EditorLaunchDiagnosticKey) {
        self.launch_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .records
            .retain(|record| record.key != key);
    }

    #[cfg(feature = "test-support")]
    fn wait_at_launch_admission_barrier(&self) {
        let barrier = self
            .launch_admission_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
    }

    #[cfg(feature = "test-support")]
    fn wait_at_pre_revalidation_barrier(&self) {
        let barriers = self
            .pre_revalidation_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some((entered, release)) = barriers {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(feature = "test-support")]
    fn wait_at_pre_spawn_barrier(&self) {
        let barriers = self
            .pre_spawn_barrier
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some((entered, release)) = barriers {
            entered.wait();
            release.wait();
        }
    }

    fn snapshot(&self) -> [Option<Arc<ProcessEntry>>; MAX_SUPERVISED_PROCESSES] {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        std::array::from_fn(|index| registry.get(index).cloned())
    }

    fn contains_exact(&self, entry: &Arc<ProcessEntry>) -> bool {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .any(|current| Arc::ptr_eq(current, entry))
    }

    fn remove_exact(&self, entry: &Arc<ProcessEntry>) {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|current| !Arc::ptr_eq(current, entry));
    }

    fn remove_terminal_exact(&self, entry: &Arc<ProcessEntry>) {
        #[cfg(all(feature = "test-support", unix))]
        if entry.has_wait_failure() {
            return;
        }
        self.remove_exact(entry);
    }
}

fn reap_until_deadline(
    mut poll_all_owned: impl FnMut() -> bool,
    mut wait_for_next_poll: impl FnMut() -> bool,
) -> bool {
    loop {
        if poll_all_owned() {
            return true;
        }
        if !wait_for_next_poll() {
            return false;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn poll_all_owned_once(
    registry: &[Arc<ProcessEntry>],
    #[cfg(feature = "test-support")] scripted_group_active_polls: &std::cell::Cell<Option<usize>>,
) -> bool {
    let mut all_terminal = true;
    let mut groups = [0_i32; MAX_SUPERVISED_PROCESSES];
    let mut group_entries = [0_usize; MAX_SUPERVISED_PROCESSES];
    let mut group_count = 0_usize;
    for (index, entry) in registry.iter().enumerate() {
        if !entry.owns_tree() {
            continue;
        }
        match entry.prepare_batched_poll() {
            Ok(PreparedProcessObservation::Complete(ProcessObservation::Terminal(_))) => {}
            Ok(PreparedProcessObservation::Complete(
                ProcessObservation::Active | ProcessObservation::Detached,
            ))
            | Err(_) => all_terminal = false,
            Ok(PreparedProcessObservation::NeedsGroupProof(group)) => {
                groups[group_count] = group;
                group_entries[group_count] = index;
                group_count += 1;
            }
        }
    }
    if group_count == 0 {
        return all_terminal;
    }

    let mut members = [true; MAX_SUPERVISED_PROCESSES];
    #[cfg(feature = "test-support")]
    let scripted_group_active = scripted_group_active_polls
        .get()
        .is_some_and(|remaining| remaining != 0);
    #[cfg(feature = "test-support")]
    if let Some(remaining) = scripted_group_active_polls.get()
        && remaining != 0
    {
        scripted_group_active_polls.set(Some(remaining - 1));
    }
    #[cfg(not(feature = "test-support"))]
    let scripted_group_active = false;
    if !scripted_group_active
        && notecrypt_platform_fs::process_groups_have_other_members(
            &groups[..group_count],
            &mut members[..group_count],
        )
        .is_err()
    {
        return false;
    }
    for probe in 0..group_count {
        let index = group_entries[probe];
        match registry[index].complete_batched_poll(members[probe]) {
            Ok(ProcessObservation::Terminal(_)) => {}
            Ok(ProcessObservation::Active | ProcessObservation::Detached) | Err(_) => {
                all_terminal = false;
            }
        }
    }
    all_terminal
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn poll_all_owned_once(
    registry: &[Arc<ProcessEntry>],
    #[cfg(feature = "test-support")] _scripted_group_active_polls: &std::cell::Cell<Option<usize>>,
) -> bool {
    let mut all_terminal = true;
    for entry in registry {
        if entry.owns_tree() && !matches!(entry.poll(), Ok(ProcessObservation::Terminal(_))) {
            all_terminal = false;
        }
    }
    all_terminal
}

fn process_entry_is_terminal(entry: &ProcessEntry) -> bool {
    matches!(
        *entry
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        ProcessState::Terminal(_)
    )
}

impl Drop for SupervisorInner {
    fn drop(&mut self) {
        #[cfg(feature = "test-support")]
        let drop_reap_test_control = self
            .drop_reap_test_control
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        #[cfg(feature = "test-support")]
        let scripted_pending_polls = std::cell::Cell::new(match drop_reap_test_control {
            Some(DropReapTestControl::PendingPolls(polls)) => Some(polls),
            Some(
                DropReapTestControl::AlwaysPending { .. }
                | DropReapTestControl::GroupActivePolls(_),
            )
            | None => None,
        });
        #[cfg(feature = "test-support")]
        let scripted_deadline_elapsed = std::cell::Cell::new(match drop_reap_test_control {
            Some(DropReapTestControl::AlwaysPending { elapsed }) => Some(elapsed),
            Some(
                DropReapTestControl::PendingPolls(_) | DropReapTestControl::GroupActivePolls(_),
            )
            | None => None,
        });
        #[cfg(feature = "test-support")]
        let scripted_group_active_polls = std::cell::Cell::new(match drop_reap_test_control {
            Some(DropReapTestControl::GroupActivePolls(polls)) => Some(polls),
            Some(
                DropReapTestControl::PendingPolls(_) | DropReapTestControl::AlwaysPending { .. },
            )
            | None => None,
        });
        let registry = self
            .registry
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for entry in registry.iter() {
            if entry.owns_tree() {
                let _ = entry.signal(true);
            }
        }
        let deadline = Instant::now() + EDITOR_FORCE_REAP_GRACE;
        let _ = reap_until_deadline(
            || {
                #[cfg(feature = "test-support")]
                {
                    if let Some(remaining) = scripted_pending_polls.get()
                        && remaining != 0
                    {
                        scripted_pending_polls.set(Some(remaining - 1));
                        return false;
                    }
                    if scripted_deadline_elapsed.get().is_some() {
                        return false;
                    }
                }
                poll_all_owned_once(
                    registry,
                    #[cfg(feature = "test-support")]
                    &scripted_group_active_polls,
                )
            },
            || {
                #[cfg(feature = "test-support")]
                {
                    if scripted_pending_polls
                        .get()
                        .is_some_and(|remaining| remaining != 0)
                    {
                        return true;
                    }
                    if let Some(elapsed) = scripted_deadline_elapsed.get() {
                        if elapsed >= EDITOR_FORCE_REAP_GRACE {
                            return false;
                        }
                        scripted_deadline_elapsed.set(Some(
                            elapsed
                                + DROP_REAP_POLL_INTERVAL
                                    .min(EDITOR_FORCE_REAP_GRACE.saturating_sub(elapsed)),
                        ));
                        return true;
                    }
                }
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                std::thread::park_timeout(
                    deadline
                        .saturating_duration_since(now)
                        .min(DROP_REAP_POLL_INTERVAL),
                );
                true
            },
        );
        for entry in registry.drain(..) {
            if !process_entry_is_terminal(&entry) {
                // Losing the retained workspace attempt would permit plaintext cleanup while a
                // process may still own the file. Leaking the bounded unresolved entry fails
                // closed when the aggregate force/reap deadline did not prove quiescence.
                std::mem::forget(entry);
            }
        }
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        if self.supervisor.contains_exact(&self.entry) {
            self.entry.token_attached.store(false, Ordering::Release);
            if matches!(
                *self
                    .entry
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()),
                ProcessState::Terminal(_)
            ) {
                self.supervisor.remove_terminal_exact(&self.entry);
            }
        }
    }
}

pub fn resolve_editor(request: EditorResolutionRequest) -> Result<EditorCommand, HostPortError> {
    let (selected, mode) = select_editor(request)?;
    let (_attestation, selected, profile) = attest_editor_command(
        selected,
        #[cfg(feature = "test-support")]
        None,
    )?;
    apply_profile_with_family(selected, mode, profile).map(|resolved| resolved.command)
}

#[cfg(feature = "test-support")]
pub fn classify_editor_for_test(
    request: EditorResolutionRequest,
) -> Result<EditorCommand, HostPortError> {
    resolve_editor_with_profile(request).map(|resolved| resolved.command)
}

struct ResolvedProfile {
    command: EditorCommand,
    mode: EditorSupervisionMode,
    ownership: OwnershipProfile,
    #[cfg(windows)]
    profile: EditorProfileFamily,
}

#[cfg(feature = "test-support")]
fn resolve_editor_with_profile(
    request: EditorResolutionRequest,
) -> Result<ResolvedProfile, HostPortError> {
    let (command, mode) = select_editor(request)?;
    apply_profile(command, mode)
}

fn select_editor(
    request: EditorResolutionRequest,
) -> Result<(EditorCommand, EditorSupervisionMode), HostPortError> {
    let (explicit, visual, editor, mode) = request.into_parts();
    let command = if let Some(command) = explicit {
        command
    } else if let Some(executable) = visual.or(editor) {
        EditorCommand::try_new(executable, Vec::new())?
    } else {
        EditorCommand::try_new(default_editor(), Vec::new())?
    };
    Ok((command, mode))
}

#[cfg(feature = "test-support")]
fn apply_profile(
    command: EditorCommand,
    mode: EditorSupervisionMode,
) -> Result<ResolvedProfile, HostPortError> {
    let profile = editor_profile_family(command.executable())?;
    apply_profile_with_family(command, mode, profile)
}

fn apply_profile_with_family(
    command: EditorCommand,
    mode: EditorSupervisionMode,
    profile: EditorProfileFamily,
) -> Result<ResolvedProfile, HostPortError> {
    let (executable, arguments) = command.into_parts();
    let (ownership, blocking_arguments): (OwnershipProfile, &[&str]) = match profile {
        EditorProfileFamily::Vim | EditorProfileFamily::Nano => (OwnershipProfile::OwnedTree, &[]),
        EditorProfileFamily::EmacsClient => (OwnershipProfile::BlockingUnowned, &[]),
        EditorProfileFamily::Code | EditorProfileFamily::Zed => {
            (OwnershipProfile::BlockingUnowned, &["--wait"])
        }
        EditorProfileFamily::Notepad => (OwnershipProfile::OwnedTree, &[]),
        EditorProfileFamily::NotepadPlusPlus => {
            (OwnershipProfile::OwnedTree, &["-multiInst", "-nosession"])
        }
    };
    if !arguments.is_empty() {
        return Err(HostPortError::DetachedEditor);
    }
    if mode == EditorSupervisionMode::Strict && ownership != OwnershipProfile::OwnedTree {
        return Err(HostPortError::DetachedEditor);
    }
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(blocking_arguments.len().saturating_add(arguments.len()))
        .map_err(|_| HostPortError::AllocationFailed)?;
    for argument in blocking_arguments {
        resolved.push(try_os_string(argument)?);
    }
    for argument in arguments {
        resolved.push(argument);
    }
    let command = EditorCommand::try_new(executable, resolved)?;
    Ok(ResolvedProfile {
        command,
        mode,
        ownership,
        #[cfg(windows)]
        profile,
    })
}

fn editor_profile_family(executable: &OsStr) -> Result<EditorProfileFamily, HostPortError> {
    let name = executable_name(executable).ok_or(HostPortError::InvalidInput)?;
    if editor_name_is(name, "vi")
        || editor_name_is(name, "vim")
        || editor_name_is(name, "nvim")
        || editor_name_is(name, "vim.basic")
        || editor_name_is(name, "vim.tiny")
    {
        Ok(EditorProfileFamily::Vim)
    } else if editor_name_is(name, "nano") {
        Ok(EditorProfileFamily::Nano)
    } else if editor_name_is(name, "emacsclient") {
        Ok(EditorProfileFamily::EmacsClient)
    } else if editor_name_is(name, "code") {
        Ok(EditorProfileFamily::Code)
    } else if editor_name_is(name, "zed") {
        Ok(EditorProfileFamily::Zed)
    } else if editor_name_is(name, "notepad") {
        Ok(EditorProfileFamily::Notepad)
    } else if editor_name_is(name, "notepad++") {
        Ok(EditorProfileFamily::NotepadPlusPlus)
    } else {
        Err(HostPortError::DetachedEditor)
    }
}

fn editor_name_is(name: &str, expected: &str) -> bool {
    #[cfg(windows)]
    {
        let name = name
            .get(..name.len().saturating_sub(4))
            .filter(|_| name[name.len().saturating_sub(4)..].eq_ignore_ascii_case(".exe"))
            .unwrap_or(name);
        name.eq_ignore_ascii_case(expected)
    }
    #[cfg(not(windows))]
    {
        name == expected
    }
}

fn try_os_string(value: &str) -> Result<OsString, HostPortError> {
    try_copy_os_str(OsStr::new(value))
}

fn try_copy_os_str(value: &OsStr) -> Result<OsString, HostPortError> {
    let mut retained = OsString::new();
    retained
        .try_reserve_exact(value.as_encoded_bytes().len())
        .map_err(|_| HostPortError::AllocationFailed)?;
    retained.push(value);
    Ok(retained)
}

fn try_string(value: &str) -> Result<String, HostPortError> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(value.len())
        .map_err(|_| HostPortError::AllocationFailed)?;
    retained.push_str(value);
    Ok(retained)
}

fn map_process_io(error: &std::io::Error) -> HostPortError {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::Unsupported => {
            HostPortError::Unavailable
        }
        std::io::ErrorKind::PermissionDenied => HostPortError::Permission,
        _ => HostPortError::PlatformFailure,
    }
}

struct ExecutableAttestation {
    trusted: notecrypt_platform_fs::TrustedExecutable,
}

struct ExecutableRevalidationFailure {
    error: HostPortError,
    #[cfg(feature = "test-support")]
    io_kind: Option<std::io::ErrorKind>,
    #[cfg(feature = "test-support")]
    raw_os_error: Option<i32>,
}

struct ExecutableAttestationFailure {
    error: HostPortError,
    #[cfg(feature = "test-support")]
    io_kind: Option<std::io::ErrorKind>,
    #[cfg(feature = "test-support")]
    raw_os_error: Option<i32>,
}

impl ExecutableAttestationFailure {
    fn host(error: HostPortError) -> Self {
        Self {
            error,
            #[cfg(feature = "test-support")]
            io_kind: None,
            #[cfg(feature = "test-support")]
            raw_os_error: None,
        }
    }

    fn io(source: std::io::Error) -> Self {
        Self {
            error: map_process_io(&source),
            #[cfg(feature = "test-support")]
            io_kind: Some(source.kind()),
            #[cfg(feature = "test-support")]
            raw_os_error: source.raw_os_error(),
        }
    }
}

impl ExecutableAttestation {
    fn revalidate(&self, executable: &OsStr) -> Result<(), ExecutableRevalidationFailure> {
        match self.trusted.matches_named(Path::new(executable)) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ExecutableRevalidationFailure {
                error: HostPortError::StaleCapability,
                #[cfg(feature = "test-support")]
                io_kind: None,
                #[cfg(feature = "test-support")]
                raw_os_error: None,
            }),
            Err(source) => Err(ExecutableRevalidationFailure {
                error: map_process_io(&source),
                #[cfg(feature = "test-support")]
                io_kind: Some(source.kind()),
                #[cfg(feature = "test-support")]
                raw_os_error: source.raw_os_error(),
            }),
        }
    }
}

fn attest_editor_command(
    command: EditorCommand,
    #[cfg(feature = "test-support")] trusted_test_executable: Option<
        &notecrypt_platform_fs::TrustedExecutable,
    >,
) -> Result<(ExecutableAttestation, EditorCommand, EditorProfileFamily), HostPortError> {
    attest_editor_command_detailed(
        command,
        #[cfg(feature = "test-support")]
        trusted_test_executable,
    )
    .map_err(|failure| failure.error)
}

fn attest_editor_command_detailed(
    command: EditorCommand,
    #[cfg(feature = "test-support")] trusted_test_executable: Option<
        &notecrypt_platform_fs::TrustedExecutable,
    >,
) -> Result<(ExecutableAttestation, EditorCommand, EditorProfileFamily), ExecutableAttestationFailure>
{
    let (executable, arguments) = command.into_parts();
    let invoked_profile =
        editor_profile_family(&executable).map_err(ExecutableAttestationFailure::host)?;
    #[cfg(unix)]
    {
        let resolved = resolve_unix_executable(&executable)?;
        let canonical_profile = editor_profile_family(resolved.as_os_str())
            .map_err(ExecutableAttestationFailure::host)?;
        if canonical_profile != invoked_profile {
            return Err(ExecutableAttestationFailure::host(
                HostPortError::DetachedEditor,
            ));
        }
        #[cfg(feature = "test-support")]
        let trusted_test = match trusted_test_executable {
            Some(trusted) => trusted
                .try_clone_if_matches_named(&resolved)
                .map_err(ExecutableAttestationFailure::io)?,
            None => None,
        };
        #[cfg(feature = "test-support")]
        let trusted = match trusted_test {
            Some(trusted) => trusted,
            None => notecrypt_platform_fs::TrustedExecutable::open(&resolved)
                .map_err(ExecutableAttestationFailure::io)?,
        };
        #[cfg(not(feature = "test-support"))]
        let trusted = notecrypt_platform_fs::TrustedExecutable::open(&resolved)
            .map_err(ExecutableAttestationFailure::io)?;
        let canonical =
            try_copy_os_str(resolved.as_os_str()).map_err(ExecutableAttestationFailure::host)?;
        let command = EditorCommand::try_new(canonical, arguments)
            .map_err(ExecutableAttestationFailure::host)?;
        let attestation = ExecutableAttestation { trusted };
        Ok((attestation, command, canonical_profile))
    }
    #[cfg(windows)]
    {
        let resolved = resolve_windows_executable(&executable)?;
        let canonical_profile = editor_profile_family(resolved.as_os_str())
            .map_err(ExecutableAttestationFailure::host)?;
        if canonical_profile != invoked_profile {
            return Err(ExecutableAttestationFailure::host(
                HostPortError::DetachedEditor,
            ));
        }
        #[cfg(feature = "test-support")]
        let trusted_test = match trusted_test_executable {
            Some(trusted) => trusted
                .try_clone_if_matches_named(&resolved)
                .map_err(ExecutableAttestationFailure::io)?,
            None => None,
        };
        #[cfg(feature = "test-support")]
        let trusted = match trusted_test {
            Some(trusted) => trusted,
            None => notecrypt_platform_fs::TrustedExecutable::open(&resolved)
                .map_err(ExecutableAttestationFailure::io)?,
        };
        #[cfg(not(feature = "test-support"))]
        let trusted = notecrypt_platform_fs::TrustedExecutable::open(&resolved)
            .map_err(ExecutableAttestationFailure::io)?;
        let canonical =
            try_copy_os_str(resolved.as_os_str()).map_err(ExecutableAttestationFailure::host)?;
        let command = EditorCommand::try_new(canonical, arguments)
            .map_err(ExecutableAttestationFailure::host)?;
        let attestation = ExecutableAttestation { trusted };
        Ok((attestation, command, canonical_profile))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (executable, arguments, invoked_profile);
        Err(ExecutableAttestationFailure::host(
            HostPortError::Unavailable,
        ))
    }
}

#[cfg(windows)]
fn resolve_windows_executable(
    executable: &OsStr,
) -> Result<std::path::PathBuf, ExecutableAttestationFailure> {
    let requested = Path::new(executable);
    if requested.is_absolute() {
        return try_copy_os_str(executable)
            .map(std::path::PathBuf::from)
            .map_err(ExecutableAttestationFailure::host);
    }
    if requested.components().count() != 1 {
        return Err(ExecutableAttestationFailure::host(
            HostPortError::InvalidInput,
        ));
    }
    let candidate = notecrypt_platform_fs::windows_system_editor_candidate(executable)
        .map_err(ExecutableAttestationFailure::io)?;
    Ok(candidate)
}

#[cfg(unix)]
fn resolve_unix_executable(
    executable: &OsStr,
) -> Result<std::path::PathBuf, ExecutableAttestationFailure> {
    let requested = Path::new(executable);
    if requested.is_absolute() {
        return std::fs::canonicalize(requested).map_err(ExecutableAttestationFailure::io);
    }
    if requested.components().count() != 1 {
        return Err(ExecutableAttestationFailure::host(
            HostPortError::InvalidInput,
        ));
    }
    for root in ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        let candidate = Path::new(root).join(requested);
        match std::fs::canonicalize(candidate) {
            Ok(path) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ExecutableAttestationFailure::io(error)),
        }
    }
    Err(ExecutableAttestationFailure::host(
        HostPortError::Unavailable,
    ))
}

fn validate_strict_mode(
    resolved: &ResolvedProfile,
    test_trusted: bool,
) -> Result<(), HostPortError> {
    if resolved.mode != EditorSupervisionMode::Strict {
        return Ok(());
    }
    if resolved.ownership != OwnershipProfile::OwnedTree {
        return Err(HostPortError::DetachedEditor);
    }
    #[cfg(windows)]
    {
        if test_trusted || resolved.profile == EditorProfileFamily::NotepadPlusPlus {
            Ok(())
        } else {
            Err(HostPortError::Unavailable)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = test_trusted;
        Err(HostPortError::Unavailable)
    }
}

fn executable_name(executable: &OsStr) -> Option<&str> {
    let name = Path::new(executable).file_name()?.to_str()?;
    Some(name)
}

fn default_editor() -> OsString {
    #[cfg(windows)]
    {
        OsString::from("notepad")
    }
    #[cfg(not(windows))]
    {
        OsString::from("vi")
    }
}
