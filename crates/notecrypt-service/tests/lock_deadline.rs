use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use notecrypt_core::VaultId;
use notecrypt_service::{
    Command, Control, DeviceKeyReference, DeviceUnlockSecret, EditorLaunchRequest, EditorProcess,
    EditorSupervisor, HostPortError, LocalVaultLease, MaterializationTarget, MonotonicClock,
    OperationContext, OperationExecutor, OperationResult, PublishedGeneration, RecoverySecretInput,
    ReplicationLimitProfile, ReplicationVaultLease, RepositoryPortError, ServiceConfig,
    ServiceError, ServiceHandle, SessionComponents, SessionPolicy, SessionState,
    StartupCleanupReport, TargetWorkspaceRequest, TrustedActivityHandle, UnlockedVaultCapability,
    VaultRepository, VaultWorkspaceRequest, WorkspaceLease, WorkspaceProvider, WorkspaceWatch,
};

const SHORT_WAIT: Duration = Duration::from_secs(5);

struct FakeClock(AtomicU64);

impl FakeClock {
    fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn advance(&self, duration: Duration) {
        self.0.fetch_add(
            u64::try_from(duration.as_nanos()).unwrap(),
            Ordering::AcqRel,
        );
    }
}

impl MonotonicClock for FakeClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        Ok(Duration::from_nanos(self.0.load(Ordering::Acquire)))
    }
}

struct FaultClock(Mutex<Result<Duration, ServiceError>>);

impl FaultClock {
    fn new(now: Duration) -> Self {
        Self(Mutex::new(Ok(now)))
    }

    fn fail(&self) {
        *self.0.lock().unwrap() = Err(ServiceError::ClockFailure);
    }
}

struct BlockingClock {
    now: AtomicU64,
    armed_thread: Mutex<Option<thread::ThreadId>>,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    gate: Arc<TestGate>,
}

impl BlockingClock {
    fn new(entered: mpsc::Sender<()>, gate: Arc<TestGate>) -> Self {
        Self {
            now: AtomicU64::new(0),
            armed_thread: Mutex::new(None),
            entered: Mutex::new(Some(entered)),
            gate,
        }
    }

    fn arm_current_thread(&self) {
        *self.armed_thread.lock().unwrap() = Some(thread::current().id());
    }
}

impl MonotonicClock for BlockingClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        let current = thread::current().id();
        let should_block = {
            let mut armed_thread = self.armed_thread.lock().unwrap();
            if armed_thread.as_ref() == Some(&current) {
                armed_thread.take();
                true
            } else {
                false
            }
        };
        if should_block {
            let entered = self.entered.lock().unwrap().take();
            if let Some(entered) = entered {
                entered.send(()).unwrap();
            }
            self.gate.wait();
        }
        Ok(Duration::from_nanos(self.now.load(Ordering::Acquire)))
    }
}

impl MonotonicClock for FaultClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        *self.0.lock().unwrap()
    }
}

#[derive(Default)]
struct CleanupState {
    fail: bool,
    calls: usize,
    skipped_live: usize,
    block: Option<Arc<RegistrationBlock>>,
}

struct FakeWorkspaceProvider(Mutex<CleanupState>);

impl FakeWorkspaceProvider {
    fn new(fail: bool) -> Self {
        Self(Mutex::new(CleanupState {
            fail,
            calls: 0,
            skipped_live: 0,
            block: None,
        }))
    }

    fn calls(&self) -> usize {
        self.0.lock().unwrap().calls
    }

    fn set_block(&self, block: Arc<RegistrationBlock>) {
        self.0.lock().unwrap().block = Some(block);
    }

    fn set_skipped_live(&self, skipped_live: usize) {
        self.0.lock().unwrap().skipped_live = skipped_live;
    }
}

impl WorkspaceProvider for FakeWorkspaceProvider {
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError> {
        let (fail, skipped_live, block) = {
            let mut state = self.0.lock().unwrap();
            state.calls += 1;
            (state.fail, state.skipped_live, state.block.clone())
        };
        if let Some(block) = block {
            block.entered.send(()).unwrap();
            block.gate.wait();
        }
        if fail {
            Err(HostPortError::CleanupFailed)
        } else {
            StartupCleanupReport::try_new(0, skipped_live)
        }
    }

    fn create_target(
        &self,
        _request: TargetWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn create_whole_vault(
        &self,
        _request: VaultWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn materialization_target(
        &self,
        _lease: &WorkspaceLease,
        _relative_path: &notecrypt_service::LogicalWorkspacePath,
    ) -> Result<MaterializationTarget, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn publish_materialized(
        &self,
        _lease: &WorkspaceLease,
        _target: MaterializationTarget,
    ) -> Result<PublishedGeneration, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn arm_published_path(
        &self,
        _lease: &WorkspaceLease,
        _published: PublishedGeneration,
    ) -> Result<(), HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn watch(&self, _lease: &WorkspaceLease) -> Result<Box<dyn WorkspaceWatch>, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn open_stable_source(
        &self,
        _lease: &WorkspaceLease,
        _relative_path: &notecrypt_service::LogicalWorkspacePath,
        _expected_generation: u64,
    ) -> Result<notecrypt_service::OpenedStableSource, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn validate_stable_source(
        &self,
        _lease: &WorkspaceLease,
        _token: &notecrypt_service::StableSourceToken,
    ) -> Result<(), HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn remove_workspace(
        &self,
        _lease: WorkspaceLease,
    ) -> Result<Box<dyn notecrypt_service::WorkspaceAbsenceGuard>, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn acquire_verified_absence(
        &self,
        _id: &notecrypt_service::WorkspaceId,
    ) -> Result<Box<dyn notecrypt_service::WorkspaceAbsenceGuard>, HostPortError> {
        Err(HostPortError::Unavailable)
    }
}

#[derive(Default)]
struct CapabilityState {
    begin_close: usize,
    close: usize,
    local_leases: usize,
    cancellation_calls: usize,
    registration_block: Option<Arc<RegistrationBlock>>,
    cancellation_block: Option<Arc<RegistrationBlock>>,
    revocation_handle_panics: bool,
    revocation_panics: bool,
    acquisition_block: Option<Arc<RegistrationBlock>>,
    reconciliation_block: Option<Arc<RegistrationBlock>>,
    repository_cancellations: Vec<Arc<notecrypt_service::RepositoryCancellation>>,
}

struct RegistrationBlock {
    entered: mpsc::Sender<()>,
    gate: Arc<TestGate>,
}

struct LeaseCancellation(Arc<Mutex<CapabilityState>>);

impl notecrypt_service::OperationCancellation for LeaseCancellation {
    fn cancel(&self) {
        let block = {
            let mut state = self.0.lock().unwrap();
            state.cancellation_calls += 1;
            state.cancellation_block.clone()
        };
        if let Some(block) = block {
            block.entered.send(()).unwrap();
            block.gate.wait();
        }
    }
}

struct FakeLocalLease {
    state: Arc<Mutex<CapabilityState>>,
    repository_cancellation: Arc<notecrypt_service::RepositoryCancellation>,
}

impl LocalVaultLease for FakeLocalLease {
    fn cancellation_handle(&self) -> Arc<dyn notecrypt_service::OperationCancellation> {
        let registration_block = self.state.lock().unwrap().registration_block.clone();
        if let Some(block) = registration_block {
            block.entered.send(()).unwrap();
            block.gate.wait();
        }
        Arc::new(LeaseCancellation(Arc::clone(&self.state)))
    }

    fn cancel(&self) {}

    fn list_entries(&mut self) -> Result<notecrypt_service::LocalEntryList, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn root_entry_id(&mut self) -> Result<notecrypt_service::LocalEntryId, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn current_snapshot_id(&mut self) -> Result<notecrypt_core::SnapshotId, RepositoryPortError> {
        if self.repository_cancellation.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        Err(RepositoryPortError::Unavailable)
    }

    fn validate_entry_binding(
        &mut self,
        _entry: notecrypt_service::LocalEntryId,
        _parent: notecrypt_service::LocalEntryId,
        _name: &str,
        _kind: notecrypt_service::LocalEntryKind,
        _revision: Option<notecrypt_core::RevisionId>,
    ) -> Result<(), RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn validate_export_binding(
        &mut self,
        _entry: notecrypt_service::LocalEntryId,
        _revision: notecrypt_core::RevisionId,
    ) -> Result<(), RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn apply(
        &mut self,
        _mutation: notecrypt_service::LocalMutation,
        _guard: &mut dyn notecrypt_service::VaultPublicationGuard,
    ) -> Result<notecrypt_service::LocalMutationResult, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn export(
        &mut self,
        _file_id: notecrypt_core::FileId,
        _expected_revision: notecrypt_core::RevisionId,
        _output: &mut dyn std::io::Write,
    ) -> Result<u64, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn commit_stable_revision(
        &mut self,
        _commit: notecrypt_service::StableRevisionCommit<'_>,
    ) -> Result<notecrypt_service::LocalSnapshot, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn finish(self: Box<Self>) -> Result<(), RepositoryPortError> {
        Ok(())
    }
}

struct FakeReplicationLease;
impl ReplicationVaultLease for FakeReplicationLease {
    fn cancellation_handle(&self) -> Arc<dyn notecrypt_service::OperationCancellation> {
        Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    fn cancel(&self) {}

    fn authenticate_bootstrap(&mut self, _bytes: &[u8]) -> Result<(), RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn authenticate_head(
        &mut self,
        _bytes: &[u8],
    ) -> Result<notecrypt_service::ReplicationAuthenticatedHead, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn contains_object(
        &mut self,
        _id: &notecrypt_core::ObjectId,
    ) -> Result<bool, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn begin_import(
        &mut self,
        _expected_id: notecrypt_core::ObjectId,
        _kind: notecrypt_service::ReplicationObjectKind,
        _declared_length: u64,
    ) -> Result<Box<dyn notecrypt_service::ReplicationImport + '_>, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn verify_reachable(
        &mut self,
        _head: notecrypt_service::ReplicationAuthenticatedHead,
        _observation: notecrypt_service::ReplicationObservation,
    ) -> Result<notecrypt_service::ReplicationVerifiedHead, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn export_encrypted(
        &mut self,
        _id: &notecrypt_core::ObjectId,
        _output: &mut dyn std::io::Write,
    ) -> Result<u64, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn commit_replicated_snapshot(
        &mut self,
        _verified: notecrypt_service::ReplicationVerifiedHead,
        _request: notecrypt_service::ReplicationCommitRequest,
        _guard: &mut dyn notecrypt_service::VaultPublicationGuard,
    ) -> Result<notecrypt_service::ReplicationCommittedHead, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn commit_reconciled_snapshot(
        &mut self,
        _verified: notecrypt_service::ReplicationVerifiedHead,
        _request: notecrypt_service::ReplicationCommitRequest,
        _guard: &mut dyn notecrypt_service::VaultPublicationGuard,
    ) -> Result<notecrypt_service::ReplicationPendingPublication, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn confirm_reconciled_publication(
        &mut self,
        _pending: notecrypt_service::ReplicationPendingPublication,
        _verified: notecrypt_service::ReplicationVerifiedHead,
    ) -> Result<notecrypt_service::ReplicationCommittedHead, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn accept_current_verified(
        &mut self,
        _verified: notecrypt_service::ReplicationVerifiedHead,
    ) -> Result<notecrypt_service::ReplicationCommittedHead, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn record_trusted_remote(
        &mut self,
        _committed: notecrypt_service::ReplicationCommittedHead,
    ) -> Result<notecrypt_service::TrustedRemoteRecordOutcome, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn into_freshness_acknowledgement(
        self: Box<Self>,
    ) -> Result<Box<dyn notecrypt_service::PendingFreshnessAction>, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn finish(self: Box<Self>) -> Result<(), RepositoryPortError> {
        Ok(())
    }
}

struct FakeUnlocked(Arc<Mutex<CapabilityState>>);

struct FakeRootRevocation(Arc<Mutex<CapabilityState>>);

impl notecrypt_service::VaultRootRevocation for FakeRootRevocation {
    fn revoke(&self) {
        let revocation_panics = {
            let mut state = self.0.lock().unwrap();
            state.begin_close += 1;
            state.revocation_panics
        };
        assert!(!revocation_panics, "injected root revocation panic");
    }
}

impl UnlockedVaultCapability for FakeUnlocked {
    fn revocation_handle(&self) -> Arc<dyn notecrypt_service::VaultRootRevocation> {
        if self.0.lock().unwrap().revocation_handle_panics {
            panic!("injected revocation-handle panic");
        }
        Arc::new(FakeRootRevocation(Arc::clone(&self.0)))
    }

    fn acquire_local_lease(
        &self,
        cancellation: Arc<notecrypt_service::RepositoryCancellation>,
    ) -> Result<Box<dyn LocalVaultLease>, RepositoryPortError> {
        let block = {
            let mut state = self.0.lock().unwrap();
            state.local_leases += 1;
            state
                .repository_cancellations
                .push(Arc::clone(&cancellation));
            state.acquisition_block.clone()
        };
        if let Some(block) = block {
            block.entered.send(()).unwrap();
            block.gate.wait();
        }
        Ok(Box::new(FakeLocalLease {
            state: Arc::clone(&self.0),
            repository_cancellation: cancellation,
        }))
    }

    fn acquire_replication_lease(
        &self,
        _backend: ReplicationLimitProfile,
        _operation: ReplicationLimitProfile,
        _cancellation: Arc<notecrypt_service::RepositoryCancellation>,
    ) -> Result<Box<dyn ReplicationVaultLease>, RepositoryPortError> {
        Ok(Box::new(FakeReplicationLease))
    }

    fn begin_compromise_rekey(
        &self,
        _request: notecrypt_service::BeginCompromiseRekey,
        _cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<notecrypt_service::PreparedCompromiseRekey, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn register_workspace(
        &self,
    ) -> Result<Box<dyn notecrypt_service::RegisteredWorkspaceCapability>, RepositoryPortError>
    {
        Err(RepositoryPortError::Unavailable)
    }

    fn activate_workspace(
        &self,
        _registered: &mut dyn notecrypt_service::RegisteredWorkspaceCapability,
    ) -> Result<Box<dyn notecrypt_service::ActiveWorkspaceCapability>, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn authenticated_workspaces(
        &self,
    ) -> Result<Vec<notecrypt_service::AuthenticatedWorkspaceCapability>, RepositoryPortError> {
        let block = self.0.lock().unwrap().reconciliation_block.clone();
        if let Some(block) = block {
            block.entered.send(()).unwrap();
            block.gate.wait();
        }
        Ok(Vec::new())
    }

    fn unregister_absent_workspace(
        &self,
        _active: &mut dyn notecrypt_service::ActiveWorkspaceCapability,
    ) -> Result<(), RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn unregister_removed_workspace(
        &self,
        _active: &mut dyn notecrypt_service::ActiveWorkspaceCapability,
        _guard: Box<dyn notecrypt_service::WorkspaceAbsenceGuard>,
    ) -> Result<(), RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn close(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.0.lock().unwrap().close += 1;
        Ok(())
    }
}

struct FakeRepository {
    result: RepositoryPortError,
    capability: Arc<Mutex<CapabilityState>>,
}

impl VaultRepository for FakeRepository {
    fn current_vault_id(&self) -> Result<Option<VaultId>, RepositoryPortError> {
        Ok(Some(VaultId::from_bytes([3; 16])))
    }

    fn unlock_recovery(
        &self,
        _secret: RecoverySecretInput,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<Box<dyn UnlockedVaultCapability>, RepositoryPortError> {
        assert_eq!(
            thread::current().name(),
            Some("notecrypt-service-security-worker")
        );
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        if self.result != RepositoryPortError::Unavailable {
            return Err(self.result);
        }
        Ok(Box::new(FakeUnlocked(Arc::clone(&self.capability))))
    }

    fn begin_recovery_initialization(
        &self,
        _request: notecrypt_service::BeginRecoveryInitialization,
        _cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<notecrypt_service::PreparedRecoveryInitialization, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }
}

struct NoopExecutor;

impl OperationExecutor for NoopExecutor {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Err(ServiceError::ExecutorFailed)
    }
}

#[derive(Default)]
struct TestGate {
    permits: Mutex<usize>,
    changed: Condvar,
}

impl TestGate {
    fn release(&self) {
        let mut permits = self.permits.lock().unwrap();
        *permits += 1;
        self.changed.notify_all();
    }

    fn wait(&self) {
        let mut permits = self.permits.lock().unwrap();
        while *permits == 0 {
            permits = self.changed.wait(permits).unwrap();
        }
        *permits -= 1;
    }
}

struct BlockingExecutor {
    gate: Arc<TestGate>,
    entered: mpsc::Sender<()>,
    arm_final_save: bool,
}

impl OperationExecutor for BlockingExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let _final_save = self
            .arm_final_save
            .then(|| context.arm_final_save().expect("final save must arm"));
        self.entered.send(()).unwrap();
        self.gate.wait();
        context.safe_boundary()?;
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

struct LateLeaseExecutor {
    entered: mpsc::Sender<()>,
    gate: Arc<TestGate>,
}

struct FinalLeaseExecutor {
    entered: mpsc::Sender<()>,
    gate: Arc<TestGate>,
}

struct DualLeaseExecutor {
    final_gate: Arc<TestGate>,
    nonfinal_gate: Arc<TestGate>,
    final_entered: mpsc::Sender<()>,
    nonfinal_entered: mpsc::Sender<()>,
}

impl OperationExecutor for DualLeaseExecutor {
    fn execute(
        &self,
        command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let _lease = context.acquire_local_lease()?;
        match command {
            Command::CreateFile(_) => {
                let _final_save = context.arm_final_save()?;
                self.final_entered.send(()).unwrap();
                self.final_gate.wait();
                context.safe_boundary()?;
            }
            Command::DeleteEntry(_) => {
                self.nonfinal_entered.send(()).unwrap();
                self.nonfinal_gate.wait();
                context.safe_boundary()?;
            }
            _ => return Err(ServiceError::ExecutorFailed),
        }
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

impl OperationExecutor for FinalLeaseExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let _lease = context.acquire_local_lease()?;
        let _final_save = context.arm_final_save()?;
        self.entered.send(()).unwrap();
        self.gate.wait();
        context.safe_boundary()?;
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

impl OperationExecutor for LateLeaseExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let _lease = context.acquire_local_lease()?;
        self.entered.send(()).unwrap();
        self.gate.wait();
        context.safe_boundary()?;
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

struct BlockingGlobalObserver {
    entered: mpsc::Sender<()>,
    gate: Arc<TestGate>,
}

impl OperationExecutor for BlockingGlobalObserver {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }

    fn control(&self, control: Control) {
        if control.is_global_for_test() {
            self.entered.send(()).unwrap();
            self.gate.wait();
        }
    }
}

struct SessionBlockingGlobalObserver {
    observed: mpsc::Sender<(usize, usize)>,
    gate: Arc<TestGate>,
    capability: Arc<Mutex<CapabilityState>>,
}

struct SaturatedObserverExecutor {
    work_gate: Arc<TestGate>,
    work_entered: mpsc::Sender<()>,
    control_gate: Arc<TestGate>,
    controls: mpsc::Sender<Control>,
    first_control: AtomicBool,
}

impl OperationExecutor for SaturatedObserverExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.work_entered.send(()).unwrap();
        self.work_gate.wait();
        context.safe_boundary()?;
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }

    fn control(&self, control: Control) {
        self.controls.send(control).unwrap();
        if !self.first_control.swap(true, Ordering::AcqRel) {
            self.control_gate.wait();
        }
    }
}

impl OperationExecutor for SessionBlockingGlobalObserver {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }

    fn control(&self, control: Control) {
        if control.is_global_for_test() {
            let capability = self.capability.lock().unwrap();
            self.observed
                .send((capability.begin_close, capability.close))
                .unwrap();
            drop(capability);
            self.gate.wait();
        }
    }
}

trait GlobalControlForTest {
    fn is_global_for_test(&self) -> bool;
}

impl GlobalControlForTest for Control {
    fn is_global_for_test(&self) -> bool {
        matches!(
            self,
            Control::LockNow | Control::DeadlineExpired | Control::Suspend
        )
    }
}

fn policy() -> SessionPolicy {
    SessionPolicy::try_new(
        Duration::from_secs(10),
        Duration::from_secs(30),
        vec![Duration::from_secs(5), Duration::from_secs(2)],
        Duration::from_secs(3),
    )
    .unwrap()
}

fn runtime(
    repository_result: RepositoryPortError,
    cleanup_fail: bool,
) -> (
    ServiceHandle,
    TrustedActivityHandle,
    Arc<FakeClock>,
    Arc<FakeWorkspaceProvider>,
    Arc<Mutex<CapabilityState>>,
) {
    let clock = Arc::new(FakeClock::new());
    let workspace = Arc::new(FakeWorkspaceProvider::new(cleanup_fail));
    let capability = Arc::new(Mutex::new(CapabilityState::default()));
    let repository = Arc::new(FakeRepository {
        result: repository_result,
        capability: Arc::clone(&capability),
    });
    let components = SessionComponents::new(repository, workspace.clone(), clock.clone(), policy());
    let (service, activity) = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(NoopExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap();
    (service, activity, clock, workspace, capability)
}

fn runtime_with_executor(
    repository_result: RepositoryPortError,
    cleanup_fail: bool,
    executor: Arc<dyn OperationExecutor>,
) -> (
    ServiceHandle,
    TrustedActivityHandle,
    Arc<FakeClock>,
    Arc<FakeWorkspaceProvider>,
    Arc<Mutex<CapabilityState>>,
) {
    let clock = Arc::new(FakeClock::new());
    let workspace = Arc::new(FakeWorkspaceProvider::new(cleanup_fail));
    let capability = Arc::new(Mutex::new(CapabilityState::default()));
    let repository = Arc::new(FakeRepository {
        result: repository_result,
        capability: Arc::clone(&capability),
    });
    let components = SessionComponents::new(repository, workspace.clone(), clock.clone(), policy());
    let (service, activity) = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        executor,
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap();
    (service, activity, clock, workspace, capability)
}

fn runtime_with_clock(clock: Arc<dyn MonotonicClock>) -> (ServiceHandle, TrustedActivityHandle) {
    let workspace = Arc::new(FakeWorkspaceProvider::new(false));
    let capability = Arc::new(Mutex::new(CapabilityState::default()));
    let repository = Arc::new(FakeRepository {
        result: RepositoryPortError::Unavailable,
        capability,
    });
    let components = SessionComponents::new(repository, workspace, clock, policy());
    ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(NoopExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
}

fn wait_for_state(service: &ServiceHandle, expected: SessionState) {
    let deadline = std::time::Instant::now() + SHORT_WAIT;
    while service.snapshot().session_state() != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "session did not reach {expected:?}"
        );
        thread::yield_now();
    }
}

fn secret() -> RecoverySecretInput {
    RecoverySecretInput::from_protected_bytes(b"alpha beta gamma delta epsilon".to_vec()).unwrap()
}

#[test]
fn session_policy_rejects_invalid_or_overflow_prone_values() {
    assert!(
        SessionPolicy::try_new(
            Duration::ZERO,
            Duration::from_secs(1),
            vec![],
            Duration::ZERO
        )
        .is_err()
    );
    assert!(
        SessionPolicy::try_new(
            Duration::from_secs(2),
            Duration::from_secs(3),
            vec![Duration::from_secs(2)],
            Duration::ZERO
        )
        .is_err()
    );
    assert!(
        SessionPolicy::try_new(
            Duration::from_secs(3),
            Duration::from_secs(3),
            vec![Duration::from_secs(1), Duration::from_secs(2)],
            Duration::ZERO
        )
        .is_err()
    );
    assert!(
        SessionPolicy::try_new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            vec![],
            Duration::from_secs(2)
        )
        .is_err()
    );
}

#[test]
fn cleanup_runs_before_unlock_and_failure_exposes_no_capability() {
    let (service, _activity, _clock, workspace, capability) =
        runtime(RepositoryPortError::Unavailable, true);
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    assert_eq!(
        service.unlock_with_recovery(secret()),
        Err(ServiceError::CleanupRequired)
    );
    assert_eq!(workspace.calls(), 1);
    assert_eq!(
        service.snapshot().session_state(),
        SessionState::CleanupRequired
    );
    assert_eq!(capability.lock().unwrap().local_leases, 0);
}

#[test]
fn repository_allocation_failure_reaches_the_public_service_error_unchanged() {
    let (service, _activity, _clock, _workspace, _capability) =
        runtime(RepositoryPortError::AllocationFailed, false);

    assert_eq!(
        service.unlock_with_recovery(secret()),
        Err(ServiceError::AllocationFailed)
    );
}

#[test]
fn blocked_startup_cleanup_exposes_no_unlock_or_operation_capability() {
    let cleanup_gate = Arc::new(TestGate::default());
    let (cleanup_entered_tx, cleanup_entered_rx) = mpsc::channel();
    let (service, _activity, _clock, workspace, capability) =
        runtime(RepositoryPortError::Unavailable, false);
    workspace.set_block(Arc::new(RegistrationBlock {
        entered: cleanup_entered_tx,
        gate: Arc::clone(&cleanup_gate),
    }));
    let unlock_service = service.clone();
    let unlock = thread::spawn(move || unlock_service.unlock_with_recovery(secret()));
    cleanup_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    assert_eq!(
        service.unlock_with_recovery(secret()),
        Err(ServiceError::Busy)
    );
    assert!(matches!(
        service.submit(Command::Backup(notecrypt_service::BackupVault)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::Status(notecrypt_service::VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::List(notecrypt_service::ListEntries)),
        Err(ServiceError::Locked)
    ));
    assert_eq!(capability.lock().unwrap().local_leases, 0);
    cleanup_gate.release();
    unlock.join().unwrap().unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);
}

#[test]
fn startup_cleanup_live_skip_does_not_claim_or_remove_the_live_workspace() {
    let (service, _activity, _clock, workspace, capability) =
        runtime(RepositoryPortError::Unavailable, false);
    workspace.set_skipped_live(1);
    service.unlock_with_recovery(secret()).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);
    assert_eq!(workspace.calls(), 1);
    assert_eq!(capability.lock().unwrap().begin_close, 0);
}

#[test]
fn lock_revokes_provisional_root_while_authenticated_reconciliation_is_blocked() {
    let reconciliation_gate = Arc::new(TestGate::default());
    let (reconciliation_entered_tx, reconciliation_entered_rx) = mpsc::channel();
    let (service, _activity, _clock, _workspace, capability) =
        runtime(RepositoryPortError::Unavailable, false);
    capability.lock().unwrap().reconciliation_block = Some(Arc::new(RegistrationBlock {
        entered: reconciliation_entered_tx,
        gate: Arc::clone(&reconciliation_gate),
    }));
    let unlock_service = service.clone();
    let unlock = thread::spawn(move || unlock_service.unlock_with_recovery(secret()));
    reconciliation_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocking);

    service.control(Control::LockNow).unwrap();
    let deadline = std::time::Instant::now() + SHORT_WAIT;
    while capability.lock().unwrap().begin_close == 0 {
        assert!(std::time::Instant::now() < deadline);
        thread::yield_now();
    }
    assert!(matches!(
        service.submit(Command::Backup(notecrypt_service::BackupVault)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::Status(notecrypt_service::VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::List(notecrypt_service::ListEntries)),
        Err(ServiceError::Locked)
    ));

    reconciliation_gate.release();
    assert_eq!(unlock.join().unwrap(), Err(ServiceError::Cancelled));
    wait_for_state(&service, SessionState::Locked);
    assert_eq!(capability.lock().unwrap().close, 1);
}

#[test]
fn wrong_recovery_secret_returns_to_locked_state() {
    let (service, _activity, _clock, workspace, capability) =
        runtime(RepositoryPortError::WrongSecret, false);
    assert_eq!(
        service.unlock_with_recovery(secret()),
        Err(ServiceError::AuthenticationFailed)
    );
    assert_eq!(workspace.calls(), 1);
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    assert_eq!(capability.lock().unwrap().local_leases, 0);
}

#[test]
fn revocation_handle_panic_closes_returned_root_and_requires_cleanup_retry() {
    let (service, _activity, _clock, _workspace, capability) =
        runtime(RepositoryPortError::Unavailable, false);
    capability.lock().unwrap().revocation_handle_panics = true;
    assert_eq!(
        service.unlock_with_recovery(secret()),
        Err(ServiceError::CleanupRequired)
    );
    assert_eq!(
        service.snapshot().session_state(),
        SessionState::CleanupRequired
    );
    assert_eq!(capability.lock().unwrap().close, 1);
    service.retry_cleanup().unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
}

#[test]
fn root_revocation_panic_during_lock_still_closes_and_latches_cleanup() {
    let (service, _activity, _clock, _workspace, capability) =
        runtime(RepositoryPortError::Unavailable, false);
    service.unlock_with_recovery(secret()).unwrap();
    capability.lock().unwrap().revocation_panics = true;
    service.control(Control::LockNow).unwrap();
    wait_for_state(&service, SessionState::CleanupRequired);
    let close_deadline = Instant::now() + SHORT_WAIT;
    while capability.lock().unwrap().close != 1 {
        assert!(
            Instant::now() < close_deadline,
            "root close did not finish after revocation panic"
        );
        thread::yield_now();
    }
    let state = capability.lock().unwrap();
    assert_eq!(state.begin_close, 1);
    assert_eq!(state.close, 1);
    drop(state);
    let deadline = Instant::now() + SHORT_WAIT;
    loop {
        match service.retry_cleanup() {
            Ok(()) => break,
            Err(ServiceError::Busy) => {
                assert!(Instant::now() < deadline, "cleanup owner did not finish");
                thread::yield_now();
            }
            Err(error) => panic!("unexpected cleanup retry result: {error:?}"),
        }
    }
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
}

#[test]
fn trusted_activity_resets_inactivity_but_generic_activity_does_not() {
    let (service, activity, clock, _workspace, capability) =
        runtime(RepositoryPortError::Unavailable, false);
    service.unlock_with_recovery(secret()).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);

    clock.advance(Duration::from_secs(8));
    activity.record().unwrap();
    clock.advance(Duration::from_secs(8));
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);

    service.control(Control::UserActivity).unwrap();
    clock.advance(Duration::from_secs(3));
    wait_for_state(&service, SessionState::Locked);
    let state = capability.lock().unwrap();
    assert_eq!(state.begin_close, 1);
    assert_eq!(state.close, 1);
}

#[test]
fn absolute_deadline_ignores_trusted_activity() {
    let (service, activity, clock, _workspace, _capability) =
        runtime(RepositoryPortError::Unavailable, false);
    service.unlock_with_recovery(secret()).unwrap();
    for _ in 0..3 {
        clock.advance(Duration::from_secs(9));
        activity.record().unwrap();
        assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);
    }
    clock.advance(Duration::from_secs(3));
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn explicit_lock_and_suspend_revoke_capability() {
    for control in [Control::LockNow, Control::Suspend] {
        let (service, _activity, _clock, _workspace, capability) =
            runtime(RepositoryPortError::Unavailable, false);
        service.unlock_with_recovery(secret()).unwrap();
        service.control(control).unwrap();
        wait_for_state(&service, SessionState::Locked);
        let state = capability.lock().unwrap();
        assert_eq!(state.begin_close, 1);
        assert_eq!(state.close, 1);
    }
}

#[test]
fn warnings_are_emitted_once_at_each_boundary_even_after_a_large_clock_jump() {
    let (service, _activity, clock, _workspace, _capability) =
        runtime(RepositoryPortError::Unavailable, false);
    service.unlock_with_recovery(secret()).unwrap();

    clock.advance(Duration::from_secs(6));
    assert_eq!(
        service.try_next_session_event(),
        Some(notecrypt_service::SessionEvent::LockWarning {
            remaining: Duration::from_secs(5),
            deadline: notecrypt_service::SessionDeadlineKind::Inactivity,
        })
    );
    assert_eq!(service.try_next_session_event(), None);

    clock.advance(Duration::from_secs(2));
    assert_eq!(
        service.try_next_session_event(),
        Some(notecrypt_service::SessionEvent::LockWarning {
            remaining: Duration::from_secs(2),
            deadline: notecrypt_service::SessionDeadlineKind::Inactivity,
        })
    );
    clock.advance(Duration::from_secs(100));
    wait_for_state(&service, SessionState::Locked);
    assert_eq!(service.try_next_session_event(), None);
}

#[test]
fn mutating_admission_resets_inactivity_but_listing_does_not() {
    for (command, should_remain_unlocked) in [
        (Command::CreateFile(notecrypt_service::CreateFile), true),
        (Command::Backup(notecrypt_service::BackupVault), false),
    ] {
        let gate = Arc::new(TestGate::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let executor = Arc::new(BlockingExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
            arm_final_save: false,
        });
        let (service, _activity, clock, _workspace, _capability) =
            runtime_with_executor(RepositoryPortError::Unavailable, false, executor);
        service.unlock_with_recovery(secret()).unwrap();
        clock.advance(Duration::from_secs(8));
        let operation = service.submit(command).unwrap();
        entered_rx.recv_timeout(SHORT_WAIT).unwrap();
        clock.advance(Duration::from_secs(3));
        assert_eq!(
            service.snapshot().session_state() == SessionState::Unlocked,
            should_remain_unlocked
        );
        gate.release();
        let _ = operation.wait_result(SHORT_WAIT);
    }
}

#[test]
fn final_save_is_the_only_operation_allowed_to_finish_during_lock_grace() {
    let gate = Arc::new(TestGate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let executor = Arc::new(BlockingExecutor {
        gate: Arc::clone(&gate),
        entered: entered_tx,
        arm_final_save: true,
    });
    let (service, _activity, _clock, _workspace, _capability) =
        runtime_with_executor(RepositoryPortError::Unavailable, false, executor);
    service.unlock_with_recovery(secret()).unwrap();
    let final_save = service
        .submit(Command::CreateFile(notecrypt_service::CreateFile))
        .unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    service.control(Control::LockNow).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Locking);
    gate.release();
    let result = final_save.wait_result(SHORT_WAIT);
    assert!(
        matches!(result, Ok(OperationResult::Entries(_))),
        "unexpected final-save result: {result:?}"
    );
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn lock_marks_every_nonfinal_repository_cancel_before_return_even_if_previously_cancelled() {
    let final_gate = Arc::new(TestGate::default());
    let nonfinal_gate = Arc::new(TestGate::default());
    let cancellation_gate = Arc::new(TestGate::default());
    let (final_entered_tx, final_entered_rx) = mpsc::channel();
    let (nonfinal_entered_tx, nonfinal_entered_rx) = mpsc::channel();
    let (cancellation_entered_tx, cancellation_entered_rx) = mpsc::channel();
    let executor = Arc::new(DualLeaseExecutor {
        final_gate: Arc::clone(&final_gate),
        nonfinal_gate: Arc::clone(&nonfinal_gate),
        final_entered: final_entered_tx,
        nonfinal_entered: nonfinal_entered_tx,
    });
    let (service, _activity, _clock, _workspace, capability) =
        runtime_with_executor(RepositoryPortError::Unavailable, false, executor);
    capability.lock().unwrap().cancellation_block = Some(Arc::new(RegistrationBlock {
        entered: cancellation_entered_tx,
        gate: Arc::clone(&cancellation_gate),
    }));
    service.unlock_with_recovery(secret()).unwrap();

    let final_save = service
        .submit(Command::CreateFile(notecrypt_service::CreateFile))
        .unwrap();
    final_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    let nonfinal = service
        .submit(Command::DeleteEntry(notecrypt_service::DeleteEntry))
        .unwrap();
    nonfinal_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    nonfinal.cancel();
    cancellation_entered_rx.recv_timeout(SHORT_WAIT).unwrap();

    service.control(Control::LockNow).unwrap();
    let cancellations = capability.lock().unwrap().repository_cancellations.clone();
    assert_eq!(cancellations.len(), 2);
    assert!(!cancellations[0].is_cancelled());
    assert!(cancellations[1].is_cancelled());

    final_gate.release();
    assert!(matches!(
        final_save.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(_))
    ));
    cancellation_gate.release();
    nonfinal_gate.release();
    assert_eq!(
        nonfinal.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn global_control_returns_while_executor_control_callback_is_blocked() {
    let gate = Arc::new(TestGate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let service = ServiceHandle::with_components(
        ServiceConfig::default(),
        Arc::new(BlockingGlobalObserver {
            entered: entered_tx,
            gate: Arc::clone(&gate),
        }),
        Arc::new(notecrypt_service::OsOperationIdRandom),
    )
    .unwrap();
    service.control(Control::LockNow).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();

    let started = std::time::Instant::now();
    service.control(Control::Suspend).unwrap();
    assert!(started.elapsed() < Duration::from_millis(250));
    gate.release();
    service.shutdown();
}

#[test]
fn session_global_observer_runs_after_close_and_blocks_reopen_until_acknowledged() {
    let gate = Arc::new(TestGate::default());
    let (observed_tx, observed_rx) = mpsc::channel();
    let clock = Arc::new(FakeClock::new());
    let workspace = Arc::new(FakeWorkspaceProvider::new(false));
    let capability = Arc::new(Mutex::new(CapabilityState::default()));
    let repository = Arc::new(FakeRepository {
        result: RepositoryPortError::Unavailable,
        capability: Arc::clone(&capability),
    });
    let components = SessionComponents::new(repository, workspace, clock, policy());
    let executor = Arc::new(SessionBlockingGlobalObserver {
        observed: observed_tx,
        gate: Arc::clone(&gate),
        capability: Arc::clone(&capability),
    });
    let (service, _activity) = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        executor,
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap();

    let first = service.unlock_with_recovery(secret()).unwrap();
    service.control(Control::LockNow).unwrap();
    let (begin_close, close) = observed_rx.recv_timeout(SHORT_WAIT).unwrap();
    assert_eq!((begin_close, close), (1, 1));
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    assert_eq!(
        service.unlock_with_recovery(secret()),
        Err(ServiceError::Locked)
    );

    gate.release();
    let deadline = std::time::Instant::now() + SHORT_WAIT;
    let second = loop {
        match service.unlock_with_recovery(secret()) {
            Ok(summary) => break summary,
            Err(ServiceError::Locked) => {
                assert!(std::time::Instant::now() < deadline);
                thread::yield_now();
            }
            Err(error) => panic!("unexpected reopen failure: {error:?}"),
        }
    };
    assert!(second.generation() > first.generation());
}

#[test]
fn saturated_observer_lane_retains_cancel_activity_trusted_and_global_controls() {
    let work_gate = Arc::new(TestGate::default());
    let control_gate = Arc::new(TestGate::default());
    let (work_entered_tx, work_entered_rx) = mpsc::channel();
    let (controls_tx, controls_rx) = mpsc::channel();
    let executor = Arc::new(SaturatedObserverExecutor {
        work_gate: Arc::clone(&work_gate),
        work_entered: work_entered_tx,
        control_gate: Arc::clone(&control_gate),
        controls: controls_tx,
        first_control: AtomicBool::new(false),
    });
    let clock = Arc::new(FakeClock::new());
    let workspace = Arc::new(FakeWorkspaceProvider::new(false));
    let capability = Arc::new(Mutex::new(CapabilityState::default()));
    let repository = Arc::new(FakeRepository {
        result: RepositoryPortError::Unavailable,
        capability,
    });
    let components = SessionComponents::new(repository, workspace, clock, policy());
    let config = ServiceConfig::new(4, 2, 2, 4, 64, 4).unwrap();
    let (service, activity) = ServiceHandle::with_session_components(
        config,
        executor,
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap();
    service.unlock_with_recovery(secret()).unwrap();

    let mut operations = Vec::new();
    let fill_deadline = std::time::Instant::now() + SHORT_WAIT;
    while operations.len() < 9 {
        match service.submit(Command::CreateFile(notecrypt_service::CreateFile)) {
            Ok(operation) => operations.push(operation),
            Err(ServiceError::Busy) => {
                assert!(std::time::Instant::now() < fill_deadline);
                thread::yield_now();
            }
            Err(error) => panic!("unexpected saturation failure: {error:?}"),
        }
    }
    assert_eq!(operations.len(), 9);
    work_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    work_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    service.control(Control::UserActivity).unwrap();
    assert_eq!(
        controls_rx.recv_timeout(SHORT_WAIT).unwrap(),
        Control::UserActivity
    );

    activity.record().unwrap();
    for operation in &operations {
        operation.cancel();
    }
    service.control(Control::LockNow).unwrap();
    control_gate.release();

    let mut cancel_count = 0;
    let mut activity_count = 1;
    let mut global_count = 0;
    while cancel_count < operations.len() || activity_count < 2 || global_count < 1 {
        match controls_rx.recv_timeout(SHORT_WAIT).unwrap() {
            Control::Cancel(_) => cancel_count += 1,
            Control::UserActivity => activity_count += 1,
            Control::LockNow => global_count += 1,
            control => panic!("unexpected observer control: {control:?}"),
        }
    }
    assert_eq!(cancel_count, operations.len());
    assert_eq!(activity_count, 2);
    assert_eq!(global_count, 1);

    work_gate.release();
    work_gate.release();
    for operation in operations {
        assert_eq!(
            operation.wait_result(SHORT_WAIT),
            Err(ServiceError::Cancelled)
        );
    }
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn lock_reopen_lock_does_not_reuse_the_old_generation() {
    let (service, activity, clock, _workspace, _capability) =
        runtime(RepositoryPortError::Unavailable, false);
    let first = service.unlock_with_recovery(secret()).unwrap();
    activity.record().unwrap();
    service.control(Control::LockNow).unwrap();
    wait_for_state(&service, SessionState::Locked);
    let deadline = std::time::Instant::now() + SHORT_WAIT;
    let second = loop {
        match service.unlock_with_recovery(secret()) {
            Ok(summary) => break summary,
            Err(ServiceError::Locked) => {
                assert!(std::time::Instant::now() < deadline);
                thread::yield_now();
            }
            Err(error) => panic!("unexpected reopen failure: {error:?}"),
        }
    };
    assert!(second.generation() > first.generation());
    clock.advance(Duration::from_secs(11));
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn trusted_activity_is_coalesced_and_rejected_after_lock() {
    let (service, activity, _clock, _workspace, _capability) =
        runtime(RepositoryPortError::Unavailable, false);
    service.unlock_with_recovery(secret()).unwrap();
    for _ in 0..256 {
        activity.record().unwrap();
    }
    service.control(Control::LockNow).unwrap();
    wait_for_state(&service, SessionState::Locked);
    assert_eq!(activity.record(), Err(ServiceError::Locked));
}

#[test]
fn clock_failure_fails_closed_before_admitting_or_observing_more_work() {
    let clock = Arc::new(FaultClock::new(Duration::ZERO));
    let (service, activity) = runtime_with_clock(Arc::clone(&clock) as Arc<dyn MonotonicClock>);
    service.unlock_with_recovery(secret()).unwrap();
    clock.fail();
    assert_eq!(activity.record(), Err(ServiceError::ClockFailure));
    assert!(matches!(
        service.submit(Command::Backup(notecrypt_service::BackupVault)),
        Err(ServiceError::ClockFailure)
    ));
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn no_final_save_exemption_cancels_a_blocked_mutation() {
    let gate = Arc::new(TestGate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let executor = Arc::new(BlockingExecutor {
        gate: Arc::clone(&gate),
        entered: entered_tx,
        arm_final_save: false,
    });
    let (service, _activity, _clock, _workspace, _capability) =
        runtime_with_executor(RepositoryPortError::Unavailable, false, executor);
    service.unlock_with_recovery(secret()).unwrap();
    let operation = service
        .submit(Command::CreateFile(notecrypt_service::CreateFile))
        .unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    service.control(Control::LockNow).unwrap();
    gate.release();
    assert_eq!(
        operation.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn late_lease_registration_after_global_cancel_cancels_exactly_that_lease() {
    let registration_gate = Arc::new(TestGate::default());
    let (registration_entered_tx, registration_entered_rx) = mpsc::channel();
    let executor_gate = Arc::new(TestGate::default());
    let (entered_tx, _entered_rx) = mpsc::channel();
    let executor = Arc::new(LateLeaseExecutor {
        entered: entered_tx,
        gate: executor_gate,
    });
    let (service, _activity, _clock, _workspace, capability) =
        runtime_with_executor(RepositoryPortError::Unavailable, false, executor);
    capability.lock().unwrap().registration_block = Some(Arc::new(RegistrationBlock {
        entered: registration_entered_tx,
        gate: Arc::clone(&registration_gate),
    }));
    service.unlock_with_recovery(secret()).unwrap();
    let operation = service
        .submit(Command::CreateFile(notecrypt_service::CreateFile))
        .unwrap();
    registration_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    service.control(Control::LockNow).unwrap();
    registration_gate.release();
    assert_eq!(
        operation.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
    assert_eq!(capability.lock().unwrap().cancellation_calls, 1);
    wait_for_state(&service, SessionState::Locked);
}

#[test]
fn blocked_adapter_acquire_cannot_delay_detached_root_revocation() {
    let acquisition_gate = Arc::new(TestGate::default());
    let (acquisition_entered_tx, acquisition_entered_rx) = mpsc::channel();
    let executor_gate = Arc::new(TestGate::default());
    let (entered_tx, _entered_rx) = mpsc::channel();
    let executor = Arc::new(LateLeaseExecutor {
        entered: entered_tx,
        gate: executor_gate,
    });
    let (service, _activity, _clock, _workspace, capability) =
        runtime_with_executor(RepositoryPortError::Unavailable, false, executor);
    capability.lock().unwrap().acquisition_block = Some(Arc::new(RegistrationBlock {
        entered: acquisition_entered_tx,
        gate: Arc::clone(&acquisition_gate),
    }));
    service.unlock_with_recovery(secret()).unwrap();
    let operation = service
        .submit(Command::CreateFile(notecrypt_service::CreateFile))
        .unwrap();
    acquisition_entered_rx.recv_timeout(SHORT_WAIT).unwrap();

    service.control(Control::LockNow).unwrap();
    let deadline = std::time::Instant::now() + SHORT_WAIT;
    while capability.lock().unwrap().begin_close == 0 {
        assert!(std::time::Instant::now() < deadline);
        thread::yield_now();
    }
    assert_eq!(capability.lock().unwrap().close, 0);

    acquisition_gate.release();
    assert_eq!(
        operation.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
    wait_for_state(&service, SessionState::Locked);
    assert_eq!(capability.lock().unwrap().close, 1);
}

#[test]
fn blocked_clock_and_cancellation_callback_cannot_delay_post_grace_revocation() {
    let clock_gate = Arc::new(TestGate::default());
    let (clock_entered_tx, clock_entered_rx) = mpsc::channel();
    let clock = Arc::new(BlockingClock::new(
        clock_entered_tx,
        Arc::clone(&clock_gate),
    ));
    let cancellation_gate = Arc::new(TestGate::default());
    let (cancellation_entered_tx, cancellation_entered_rx) = mpsc::channel();
    let executor_gate = Arc::new(TestGate::default());
    let (executor_entered_tx, executor_entered_rx) = mpsc::channel();
    let workspace = Arc::new(FakeWorkspaceProvider::new(false));
    let capability = Arc::new(Mutex::new(CapabilityState::default()));
    capability.lock().unwrap().cancellation_block = Some(Arc::new(RegistrationBlock {
        entered: cancellation_entered_tx,
        gate: Arc::clone(&cancellation_gate),
    }));
    let repository = Arc::new(FakeRepository {
        result: RepositoryPortError::Unavailable,
        capability: Arc::clone(&capability),
    });
    let policy = SessionPolicy::try_new(
        Duration::from_secs(10),
        Duration::from_secs(30),
        Vec::new(),
        Duration::ZERO,
    )
    .unwrap();
    let components = SessionComponents::new(repository, workspace, clock.clone(), policy);
    let (service, activity) = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(FinalLeaseExecutor {
            entered: executor_entered_tx,
            gate: Arc::clone(&executor_gate),
        }),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap();
    service.unlock_with_recovery(secret()).unwrap();
    let operation = service
        .submit(Command::CreateFile(notecrypt_service::CreateFile))
        .unwrap();
    executor_entered_rx.recv_timeout(SHORT_WAIT).unwrap();

    let activity_clock = Arc::clone(&clock);
    let activity_worker = thread::spawn(move || {
        activity_clock.arm_current_thread();
        activity.record()
    });
    clock_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    service.control(Control::LockNow).unwrap();
    cancellation_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    let state = capability.lock().unwrap();
    assert_eq!(state.begin_close, 1);
    assert_eq!(state.close, 1);
    drop(state);

    cancellation_gate.release();
    executor_gate.release();
    clock_gate.release();
    wait_for_state(&service, SessionState::Locked);
    assert_eq!(
        operation.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
    assert_eq!(activity_worker.join().unwrap(), Err(ServiceError::Locked));
}

// Keep unrelated port traits in this test crate's dependency graph so future
// contract changes cannot silently make the session composition non-object-safe.
fn _object_safety(
    _editor: &dyn EditorSupervisor,
    _process: &mut dyn EditorProcess,
    _request: EditorLaunchRequest,
    _reference: &DeviceKeyReference,
    _secret: DeviceUnlockSecret,
) {
}
