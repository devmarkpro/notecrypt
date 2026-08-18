use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use notecrypt_core::VaultId;
use notecrypt_service::{
    BeginCompromiseRekey, BeginRecoveryInitialization, Command, CompromiseRekeyConfirmation,
    Control, HostPortError, MonotonicClock, OperationContext, OperationExecutor, OperationResult,
    PendingCompromiseAction, PendingFreshnessAction, PendingRecoveryAction,
    PreparedCompromiseRekey, PreparedRecoveryInitialization, RecoverySecretInput,
    RecoverySecretPresentation, RecoverySecretPresenter, RepositoryPortError, ServiceConfig,
    ServiceError, ServiceHandle, SessionComponents, SessionPolicy, SessionState,
    StartupCleanupReport, UnlockedVaultCapability, VaultRepository, VaultSummary, WorkspaceLease,
    WorkspaceProvider,
};

const SECRET: &[u8] = b"transition test secret";

struct FixedClock;

impl MonotonicClock for FixedClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        Ok(Duration::ZERO)
    }
}

struct Signal {
    state: Mutex<bool>,
    changed: Condvar,
}

impl Signal {
    fn new() -> Self {
        Self {
            state: Mutex::new(false),
            changed: Condvar::new(),
        }
    }

    fn set(&self) {
        *self.state.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn wait(&self) {
        let mut state = self.state.lock().unwrap();
        while !*state {
            state = self.changed.wait(state).unwrap();
        }
    }
}

struct EmptyWorkspace;

impl WorkspaceProvider for EmptyWorkspace {
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError> {
        StartupCleanupReport::try_new(0, 0)
    }

    fn create_target(
        &self,
        _request: notecrypt_service::TargetWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn create_whole_vault(
        &self,
        _request: notecrypt_service::VaultWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn materialization_target(
        &self,
        _lease: &WorkspaceLease,
        _relative_path: &notecrypt_service::LogicalWorkspacePath,
    ) -> Result<notecrypt_service::MaterializationTarget, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn publish_materialized(
        &self,
        _lease: &WorkspaceLease,
        _target: notecrypt_service::MaterializationTarget,
    ) -> Result<notecrypt_service::PublishedGeneration, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn arm_published_path(
        &self,
        _lease: &WorkspaceLease,
        _published: notecrypt_service::PublishedGeneration,
    ) -> Result<(), HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn watch(
        &self,
        _lease: &WorkspaceLease,
    ) -> Result<Box<dyn notecrypt_service::WorkspaceWatch>, HostPortError> {
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

struct NoopCapability(Arc<ActionCounts>);

struct NoopRootRevocation;

impl notecrypt_service::VaultRootRevocation for NoopRootRevocation {
    fn revoke(&self) {}
}

impl UnlockedVaultCapability for NoopCapability {
    fn revocation_handle(&self) -> Arc<dyn notecrypt_service::VaultRootRevocation> {
        Arc::new(NoopRootRevocation)
    }

    fn acquire_local_lease(
        &self,
        _cancellation: Arc<notecrypt_service::RepositoryCancellation>,
    ) -> Result<Box<dyn notecrypt_service::LocalVaultLease>, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn acquire_replication_lease(
        &self,
        _backend: notecrypt_service::ReplicationLimitProfile,
        _operation: notecrypt_service::ReplicationLimitProfile,
        _cancellation: Arc<notecrypt_service::RepositoryCancellation>,
    ) -> Result<Box<dyn notecrypt_service::ReplicationVaultLease>, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn begin_compromise_rekey(
        &self,
        request: BeginCompromiseRekey,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<PreparedCompromiseRekey, RepositoryPortError> {
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        let action = Box::new(RekeyAction {
            counts: Arc::clone(&self.0),
            probe: self.0.rekey_probe.lock().unwrap().clone(),
        });
        match request.policy() {
            notecrypt_service::RecoverySecretPolicy::Generated => Ok(PreparedCompromiseRekey::new(
                RecoverySecretInput::from_protected_bytes(SECRET.to_vec())
                    .map_err(|_| RepositoryPortError::InvalidInput)?,
                action,
            )),
            notecrypt_service::RecoverySecretPolicy::CustomV1 => {
                Ok(PreparedCompromiseRekey::custom(action))
            }
        }
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
        Ok(())
    }
}

#[derive(Default)]
struct ActionCounts {
    recovery_confirm: AtomicUsize,
    recovery_abort: AtomicUsize,
    recovery_probe: Mutex<Option<Arc<RekeyProbe>>>,
    rekey_confirm: AtomicUsize,
    rekey_abort: AtomicUsize,
    rekey_probe: Mutex<Option<Arc<RekeyProbe>>>,
    recovery_cancellation_handle_panics: AtomicBool,
    rekey_cancellation_handle_panics: AtomicBool,
    freshness_abort: AtomicUsize,
}

struct RekeyProbe {
    entered: Signal,
    cancellation_seen: AtomicBool,
}

impl RekeyProbe {
    fn new() -> Self {
        Self {
            entered: Signal::new(),
            cancellation_seen: AtomicBool::new(false),
        }
    }
}

struct RecoveryAction {
    counts: Arc<ActionCounts>,
    probe: Option<Arc<RekeyProbe>>,
}

struct NoopOperationCancellation;

impl notecrypt_service::OperationCancellation for NoopOperationCancellation {
    fn cancel(&self) {}
}

impl PendingRecoveryAction for RecoveryAction {
    fn cancellation_handle(&self) -> Arc<dyn notecrypt_service::OperationCancellation> {
        if self
            .counts
            .recovery_cancellation_handle_panics
            .load(Ordering::Acquire)
        {
            panic!("injected recovery cancellation-handle panic");
        }
        Arc::new(NoopOperationCancellation)
    }

    fn confirm(
        self: Box<Self>,
        _confirmation: RecoverySecretInput,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<VaultSummary, RepositoryPortError> {
        if let Some(probe) = &self.probe {
            probe.entered.set();
            while !cancel.is_cancelled() {
                thread::yield_now();
            }
            probe.cancellation_seen.store(true, Ordering::Release);
            return Err(RepositoryPortError::Cancelled);
        }
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        self.counts.recovery_confirm.fetch_add(1, Ordering::AcqRel);
        Ok(VaultSummary::new(VaultId::from_bytes([7; 16])))
    }

    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.counts.recovery_abort.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct RekeyAction {
    counts: Arc<ActionCounts>,
    probe: Option<Arc<RekeyProbe>>,
}

impl PendingCompromiseAction for RekeyAction {
    fn cancellation_handle(&self) -> Arc<dyn notecrypt_service::OperationCancellation> {
        if self
            .counts
            .rekey_cancellation_handle_panics
            .load(Ordering::Acquire)
        {
            panic!("injected compromise cancellation-handle panic");
        }
        Arc::new(NoopOperationCancellation)
    }

    fn confirm(
        self: Box<Self>,
        _confirmation: RecoverySecretInput,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<(), RepositoryPortError> {
        if let Some(probe) = &self.probe {
            probe.entered.set();
            while !cancel.is_cancelled() {
                thread::yield_now();
            }
            probe.cancellation_seen.store(true, Ordering::Release);
            return Err(RepositoryPortError::Cancelled);
        }
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        self.counts.rekey_confirm.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.counts.rekey_abort.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct FakeRepository {
    counts: Arc<ActionCounts>,
}

struct PanicFreshnessViewAction(Arc<ActionCounts>);

impl PendingFreshnessAction for PanicFreshnessViewAction {
    fn operation_cancellation(&self) -> &notecrypt_service::RepositoryCancellation {
        panic!("view panic must be handled before binding is queried")
    }

    fn view(&self) -> notecrypt_service::FreshnessAcknowledgementView {
        panic!("injected freshness view panic");
    }

    fn acknowledge(self: Box<Self>) -> Result<(), RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.0.freshness_abort.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct PanicFreshnessExecutor(Arc<ActionCounts>);

impl OperationExecutor for PanicFreshnessExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        context.await_freshness_acknowledgement(Box::new(PanicFreshnessViewAction(Arc::clone(
            &self.0,
        ))))?;
        Ok(OperationResult::SecurityTransitionCompleted)
    }
}

impl VaultRepository for FakeRepository {
    fn current_vault_id(&self) -> Result<Option<VaultId>, RepositoryPortError> {
        Ok(Some(VaultId::from_bytes([7; 16])))
    }

    fn unlock_recovery(
        &self,
        _secret: RecoverySecretInput,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<Box<dyn UnlockedVaultCapability>, RepositoryPortError> {
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        Ok(Box::new(NoopCapability(Arc::clone(&self.counts))))
    }

    fn begin_recovery_initialization(
        &self,
        request: BeginRecoveryInitialization,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<PreparedRecoveryInitialization, RepositoryPortError> {
        if cancel.is_cancelled() {
            return Err(RepositoryPortError::Cancelled);
        }
        let action = Box::new(RecoveryAction {
            counts: Arc::clone(&self.counts),
            probe: self.counts.recovery_probe.lock().unwrap().clone(),
        });
        match request.policy() {
            notecrypt_service::RecoverySecretPolicy::Generated => {
                Ok(PreparedRecoveryInitialization::new(
                    RecoverySecretInput::from_protected_bytes(SECRET.to_vec())
                        .map_err(|_| RepositoryPortError::InvalidInput)?,
                    action,
                ))
            }
            notecrypt_service::RecoverySecretPolicy::CustomV1 => {
                let (secret, acknowledgement) = request
                    .into_custom()
                    .ok_or(RepositoryPortError::InvalidInput)?;
                if acknowledgement.version() != 1 {
                    return Err(RepositoryPortError::InvalidInput);
                }
                Ok(PreparedRecoveryInitialization::custom(secret, action))
            }
        }
    }
}

struct NoopExecutor;

impl OperationExecutor for NoopExecutor {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

struct BlockingExecutor {
    entered: Arc<Signal>,
    release: Arc<Signal>,
}

impl OperationExecutor for BlockingExecutor {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.entered.set();
        self.release.wait();
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

struct PrepareBlockingRandom {
    entered: Arc<Signal>,
    release: Arc<Signal>,
    blocked: AtomicBool,
}

impl PrepareBlockingRandom {
    fn new(entered: Arc<Signal>, release: Arc<Signal>) -> Self {
        Self {
            entered,
            release,
            blocked: AtomicBool::new(false),
        }
    }
}

impl notecrypt_service::OperationIdRandom for PrepareBlockingRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<usize, ServiceError> {
        if !self.blocked.swap(true, Ordering::AcqRel) {
            self.entered.set();
            self.release.wait();
        }
        destination.fill(7);
        Ok(destination.len())
    }
}

struct EntropyFailure;

impl notecrypt_service::OperationIdRandom for EntropyFailure {
    fn fill(&self, _destination: &mut [u8]) -> Result<usize, ServiceError> {
        Err(ServiceError::EntropyUnavailable)
    }
}

struct CapturedPresentation(Vec<u8>);

impl RecoverySecretPresenter for CapturedPresentation {
    fn present(&mut self, secret: &[u8]) -> Result<(), HostPortError> {
        self.0.extend_from_slice(secret);
        Ok(())
    }
}

fn policy() -> SessionPolicy {
    SessionPolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(120),
        Vec::new(),
        Duration::from_secs(1),
    )
    .unwrap()
}

fn service_with(counts: Arc<ActionCounts>) -> ServiceHandle {
    service_with_options(
        counts,
        Arc::new(NoopExecutor),
        ServiceConfig::default(),
        Arc::new(notecrypt_service::OsOperationIdRandom),
    )
}

fn service_with_options(
    counts: Arc<ActionCounts>,
    executor: Arc<dyn OperationExecutor>,
    config: ServiceConfig,
    random: Arc<dyn notecrypt_service::OperationIdRandom>,
) -> ServiceHandle {
    let components = SessionComponents::new(
        Arc::new(FakeRepository { counts }),
        Arc::new(EmptyWorkspace),
        Arc::new(FixedClock),
        policy(),
    );
    ServiceHandle::with_session_components(config, executor, random, components)
        .unwrap()
        .0
}

fn unlocked_service_with(counts: Arc<ActionCounts>) -> ServiceHandle {
    let service = service_with(counts);
    service
        .unlock_with_recovery(RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap())
        .unwrap();
    service
}

fn present(presentation: RecoverySecretPresentation) -> RecoverySecretInput {
    let mut captured = CapturedPresentation(Vec::new());
    presentation.present_once(&mut captured).unwrap();
    RecoverySecretInput::from_protected_bytes(captured.0).unwrap()
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not become true");
        thread::yield_now();
    }
}

fn retry_cleanup_until_locked(service: &ServiceHandle) {
    let mut complete = false;
    wait_until(|| {
        if complete {
            return true;
        }
        match service.retry_cleanup() {
            Ok(()) => {
                complete = true;
                true
            }
            Err(ServiceError::Busy | ServiceError::Locked) => false,
            Err(error) => panic!("unexpected cleanup retry failure: {error:?}"),
        }
    });
}

fn unlock_until_ready(service: &ServiceHandle) {
    let mut unlocked = false;
    wait_until(|| {
        if unlocked {
            return true;
        }
        match service.unlock_with_recovery(
            RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
        ) {
            Ok(_) => {
                unlocked = true;
                true
            }
            Err(ServiceError::Locked) => false,
            Err(error) => panic!("unexpected unlock failure: {error:?}"),
        }
    });
}

#[test]
fn recovery_confirmation_consumes_the_pending_action_once() {
    let counts = Arc::new(ActionCounts::default());
    let service = service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();

    let summary = service
        .confirm_recovery_initialization(pending, present(presentation.unwrap()))
        .unwrap();
    assert_eq!(summary.vault_id(), VaultId::from_bytes([7; 16]));
    assert_eq!(counts.recovery_confirm.load(Ordering::Acquire), 1);
    assert_eq!(counts.recovery_abort.load(Ordering::Acquire), 0);
    service.shutdown();
}

#[test]
fn custom_recovery_uses_two_matching_entries_without_a_presentation() {
    let counts = Arc::new(ActionCounts::default());
    let service = service_with(Arc::clone(&counts));
    let first = RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap();
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::custom_v1(
            first,
            notecrypt_service::OfflineGuessingRiskAcknowledgement::v1(),
        ))
        .unwrap();
    assert!(presentation.is_none());
    service
        .confirm_recovery_initialization(
            pending,
            RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(counts.recovery_confirm.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn recovery_mismatch_and_explicit_cancel_abort_exactly_once() {
    let counts = Arc::new(ActionCounts::default());
    let service = service_with(Arc::clone(&counts));
    let (mismatch, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(presentation);
    assert_eq!(
        service.confirm_recovery_initialization(
            mismatch,
            RecoverySecretInput::from_protected_bytes(b"wrong".to_vec()).unwrap(),
        ),
        Err(ServiceError::AuthenticationFailed)
    );

    let (cancelled, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(presentation);
    service.cancel_recovery_initialization(cancelled).unwrap();
    assert_eq!(counts.recovery_abort.load(Ordering::Acquire), 2);
    service.shutdown();
}

#[test]
fn dropping_recovery_pending_aborts_prepared_action() {
    let counts = Arc::new(ActionCounts::default());
    let service = service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(presentation);
    drop(pending);
    assert_eq!(counts.recovery_abort.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn lock_cancels_consuming_recovery_through_exact_repository_probe() {
    let counts = Arc::new(ActionCounts::default());
    let probe = Arc::new(RekeyProbe::new());
    *counts.recovery_probe.lock().unwrap() = Some(Arc::clone(&probe));
    let service = service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let confirmation = present(presentation.unwrap());
    let confirmer = service.clone();
    let confirmation_thread =
        thread::spawn(move || confirmer.confirm_recovery_initialization(pending, confirmation));
    probe.entered.wait();

    service.control(Control::LockNow).unwrap();
    assert_eq!(
        confirmation_thread.join().unwrap(),
        Err(ServiceError::Cancelled)
    );
    assert!(probe.cancellation_seen.load(Ordering::Acquire));
    assert_eq!(counts.recovery_confirm.load(Ordering::Acquire), 0);
    wait_until(|| service.snapshot().session_state() == SessionState::Locked);

    let independent_counts = Arc::new(ActionCounts::default());
    let independent = service_with(Arc::clone(&independent_counts));
    let (pending, presentation) = independent
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    independent
        .confirm_recovery_initialization(pending, present(presentation.unwrap()))
        .unwrap();
    assert_eq!(
        independent_counts.recovery_confirm.load(Ordering::Acquire),
        1
    );
    independent.shutdown();
}

#[test]
fn compromise_rekey_confirmation_and_cancel_have_linear_consumption() {
    let counts = Arc::new(ActionCounts::default());
    let service = unlocked_service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([1; 16]).unwrap())
        .unwrap();
    let operation = service
        .confirm_compromise_rekey(
            pending,
            CompromiseRekeyConfirmation::generated(present(presentation.unwrap())),
        )
        .unwrap();
    assert_eq!(
        operation.wait_result(Duration::from_secs(1)).unwrap(),
        OperationResult::SecurityTransitionCompleted
    );

    let (mismatch, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([3; 16]).unwrap())
        .unwrap();
    drop(presentation);
    assert!(matches!(
        service.confirm_compromise_rekey(
            mismatch,
            CompromiseRekeyConfirmation::generated(
                RecoverySecretInput::from_protected_bytes(b"wrong".to_vec()).unwrap(),
            ),
        ),
        Err(ServiceError::AuthenticationFailed)
    ));

    let (cancelled, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([2; 16]).unwrap())
        .unwrap();
    drop(presentation);
    service.cancel_compromise_rekey(cancelled).unwrap();
    let (dropped, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([4; 16]).unwrap())
        .unwrap();
    drop(presentation);
    drop(dropped);
    assert_eq!(counts.rekey_confirm.load(Ordering::Acquire), 1);
    assert_eq!(counts.rekey_abort.load(Ordering::Acquire), 3);
    service.shutdown();
}

#[test]
fn custom_compromise_is_secret_free_until_consuming_confirmation() {
    let counts = Arc::new(ActionCounts::default());
    let service = unlocked_service_with(Arc::clone(&counts));
    let request = BeginCompromiseRekey::try_custom_v1(
        [5; 16],
        notecrypt_service::OfflineGuessingRiskAcknowledgement::v1(),
    )
    .unwrap();
    let (pending, presentation) = service.begin_compromise_rekey(request).unwrap();
    assert!(presentation.is_none());
    let operation = service
        .confirm_compromise_rekey(
            pending,
            CompromiseRekeyConfirmation::custom_v1(
                RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
                RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
            ),
        )
        .unwrap();
    assert_eq!(
        operation.wait_result(Duration::from_secs(1)).unwrap(),
        OperationResult::SecurityTransitionCompleted
    );
    assert_eq!(counts.rekey_confirm.load(Ordering::Acquire), 1);
    assert!(matches!(
        BeginCompromiseRekey::try_generated([0; 16]),
        Err(RepositoryPortError::InvalidInput)
    ));
    service.shutdown();
}

#[test]
fn compromise_confirmation_shape_mismatch_aborts_prepared_action_once() {
    let counts = Arc::new(ActionCounts::default());
    let service = unlocked_service_with(Arc::clone(&counts));
    let (generated, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([13; 16]).unwrap())
        .unwrap();
    drop(presentation);
    assert!(matches!(
        service.confirm_compromise_rekey(
            generated,
            CompromiseRekeyConfirmation::custom_v1(
                RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
                RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
            ),
        ),
        Err(ServiceError::AuthenticationFailed)
    ));
    assert_eq!(counts.rekey_abort.load(Ordering::Acquire), 1);

    let (custom, presentation) = service
        .begin_compromise_rekey(
            BeginCompromiseRekey::try_custom_v1(
                [14; 16],
                notecrypt_service::OfflineGuessingRiskAcknowledgement::v1(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(presentation.is_none());
    assert!(matches!(
        service.confirm_compromise_rekey(
            custom,
            CompromiseRekeyConfirmation::generated(
                RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap(),
            ),
        ),
        Err(ServiceError::AuthenticationFailed)
    ));
    assert_eq!(counts.rekey_abort.load(Ordering::Acquire), 2);
    service.shutdown();
}

#[test]
fn entropy_failure_aborts_prepared_recovery_before_returning() {
    let counts = Arc::new(ActionCounts::default());
    let components = SessionComponents::new(
        Arc::new(FakeRepository {
            counts: Arc::clone(&counts),
        }),
        Arc::new(EmptyWorkspace),
        Arc::new(FixedClock),
        policy(),
    );
    let service = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(NoopExecutor),
        Arc::new(EntropyFailure),
        components,
    )
    .unwrap()
    .0;

    assert!(matches!(
        service.begin_recovery_initialization(BeginRecoveryInitialization::generated()),
        Err(ServiceError::EntropyUnavailable)
    ));
    assert_eq!(counts.recovery_abort.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn pending_recovery_is_origin_bound_and_rejected_by_another_service() {
    let first_counts = Arc::new(ActionCounts::default());
    let second_counts = Arc::new(ActionCounts::default());
    let first = service_with(Arc::clone(&first_counts));
    let second = service_with(Arc::clone(&second_counts));
    let (pending, presentation) = first
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let confirmation = present(presentation.unwrap());
    assert_eq!(
        second.confirm_recovery_initialization(pending, confirmation),
        Err(ServiceError::StaleCapability)
    );
    assert_eq!(first_counts.recovery_abort.load(Ordering::Acquire), 1);
    drop(first);
    second.shutdown();
}

#[test]
fn pending_recovery_excludes_unlock_until_it_is_consumed() {
    let counts = Arc::new(ActionCounts::default());
    let service = service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let confirmation = present(presentation.unwrap());

    assert!(matches!(
        service.unlock_with_recovery(
            RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap()
        ),
        Err(ServiceError::Busy)
    ));
    service
        .confirm_recovery_initialization(pending, confirmation)
        .unwrap();
    assert_eq!(counts.recovery_confirm.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn running_compromise_observes_lock_cancellation_and_same_kind_begin_waits_for_exit() {
    let counts = Arc::new(ActionCounts::default());
    let probe = Arc::new(RekeyProbe::new());
    *counts.rekey_probe.lock().unwrap() = Some(Arc::clone(&probe));
    let service = unlocked_service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([8; 16]).unwrap())
        .unwrap();
    let operation = service
        .confirm_compromise_rekey(
            pending,
            CompromiseRekeyConfirmation::generated(present(presentation.unwrap())),
        )
        .unwrap();
    probe.entered.wait();

    assert!(matches!(
        service.begin_compromise_rekey(BeginCompromiseRekey::try_generated([9; 16]).unwrap()),
        Err(ServiceError::Busy)
    ));
    service.control(Control::LockNow).unwrap();
    assert!(matches!(
        operation.wait_result(Duration::from_secs(2)),
        Err(ServiceError::Cancelled)
    ));
    wait_until(|| probe.cancellation_seen.load(Ordering::Acquire));
    assert_eq!(counts.rekey_confirm.load(Ordering::Acquire), 0);
    assert_eq!(counts.rekey_abort.load(Ordering::Acquire), 0);
    service.shutdown();
}

#[test]
fn cancelling_running_compromise_releases_same_kind_admission_after_worker_exit() {
    let counts = Arc::new(ActionCounts::default());
    let probe = Arc::new(RekeyProbe::new());
    *counts.rekey_probe.lock().unwrap() = Some(Arc::clone(&probe));
    let service = unlocked_service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([10; 16]).unwrap())
        .unwrap();
    let operation = service
        .confirm_compromise_rekey(
            pending,
            CompromiseRekeyConfirmation::generated(present(presentation.unwrap())),
        )
        .unwrap();
    probe.entered.wait();
    operation.cancel();
    assert!(matches!(
        operation.wait_result(Duration::from_secs(2)),
        Err(ServiceError::Cancelled)
    ));
    wait_until(|| probe.cancellation_seen.load(Ordering::Acquire));

    *counts.rekey_probe.lock().unwrap() = None;
    let (pending, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([11; 16]).unwrap())
        .unwrap();
    service.cancel_compromise_rekey(pending).unwrap();
    drop(presentation);
    service.shutdown();
}

#[test]
fn queued_compromise_is_aborted_when_shutdown_discards_the_worker_item() {
    let counts = Arc::new(ActionCounts::default());
    let entered = Arc::new(Signal::new());
    let release = Arc::new(Signal::new());
    let config = ServiceConfig::new(2, 1, 64, 64, 64, 8).unwrap();
    let service = service_with_options(
        Arc::clone(&counts),
        Arc::new(BlockingExecutor {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        }),
        config,
        Arc::new(notecrypt_service::OsOperationIdRandom),
    );
    unlock_until_ready(&service);
    let blocker = service
        .submit(Command::List(notecrypt_service::ListEntries))
        .unwrap();
    entered.wait();
    let (pending, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([12; 16]).unwrap())
        .unwrap();
    let queued = service
        .confirm_compromise_rekey(
            pending,
            CompromiseRekeyConfirmation::generated(present(presentation.unwrap())),
        )
        .unwrap();
    service.shutdown();
    release.set();
    let _ = blocker.wait_result(Duration::from_secs(2));
    wait_until(|| counts.rekey_abort.load(Ordering::Acquire) == 1);
    assert!(matches!(
        queued.wait_result(Duration::from_secs(2)),
        Err(ServiceError::Cancelled) | Err(ServiceError::Closed)
    ));
}

#[test]
fn lock_between_recovery_prepare_and_pending_install_aborts_once_without_capability() {
    let counts = Arc::new(ActionCounts::default());
    let entered = Arc::new(Signal::new());
    let release = Arc::new(Signal::new());
    let components = SessionComponents::new(
        Arc::new(FakeRepository {
            counts: Arc::clone(&counts),
        }),
        Arc::new(EmptyWorkspace),
        Arc::new(FixedClock),
        policy(),
    );
    let service = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(NoopExecutor),
        Arc::new(PrepareBlockingRandom::new(
            Arc::clone(&entered),
            Arc::clone(&release),
        )),
        components,
    )
    .unwrap()
    .0;
    let worker = {
        let service = service.clone();
        thread::spawn(move || {
            service.begin_recovery_initialization(BeginRecoveryInitialization::generated())
        })
    };
    entered.wait();
    service.control(Control::LockNow).unwrap();
    release.set();
    assert!(matches!(
        worker.join().unwrap(),
        Err(ServiceError::StaleCapability) | Err(ServiceError::Cancelled)
    ));
    assert_eq!(counts.recovery_abort.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn recovery_cancellation_handle_panic_aborts_and_releases_transition_capacity() {
    let counts = Arc::new(ActionCounts::default());
    counts
        .recovery_cancellation_handle_panics
        .store(true, Ordering::Release);
    let service = service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    assert_eq!(
        service.confirm_recovery_initialization(pending, present(presentation.unwrap())),
        Err(ServiceError::CleanupRequired)
    );
    assert_eq!(counts.recovery_abort.load(Ordering::Acquire), 1);
    wait_until(|| service.snapshot().session_state() == SessionState::CleanupRequired);
    retry_cleanup_until_locked(&service);

    counts
        .recovery_cancellation_handle_panics
        .store(false, Ordering::Release);
    let (next, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(presentation);
    service.cancel_recovery_initialization(next).unwrap();
    service.shutdown();
}

#[test]
fn compromise_cancellation_handle_panic_aborts_and_releases_transition_capacity() {
    let counts = Arc::new(ActionCounts::default());
    counts
        .rekey_cancellation_handle_panics
        .store(true, Ordering::Release);
    let service = unlocked_service_with(Arc::clone(&counts));
    let (pending, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([15; 16]).unwrap())
        .unwrap();
    assert!(matches!(
        service.confirm_compromise_rekey(
            pending,
            CompromiseRekeyConfirmation::generated(present(presentation.unwrap())),
        ),
        Err(ServiceError::CleanupRequired)
    ));
    assert_eq!(counts.rekey_abort.load(Ordering::Acquire), 1);
    wait_until(|| service.snapshot().session_state() == SessionState::CleanupRequired);
    retry_cleanup_until_locked(&service);
    unlock_until_ready(&service);

    counts
        .rekey_cancellation_handle_panics
        .store(false, Ordering::Release);
    let (next, presentation) = service
        .begin_compromise_rekey(BeginCompromiseRekey::try_generated([16; 16]).unwrap())
        .unwrap();
    drop(presentation);
    service.cancel_compromise_rekey(next).unwrap();
    service.shutdown();
}

#[test]
fn freshness_view_panic_aborts_once_and_fails_closed_without_stuck_transition() {
    let counts = Arc::new(ActionCounts::default());
    let service = service_with_options(
        Arc::clone(&counts),
        Arc::new(PanicFreshnessExecutor(Arc::clone(&counts))),
        ServiceConfig::default(),
        Arc::new(notecrypt_service::OsOperationIdRandom),
    );
    service
        .unlock_with_recovery(RecoverySecretInput::from_protected_bytes(SECRET.to_vec()).unwrap())
        .unwrap();
    let operation = service
        .submit(Command::Sync(notecrypt_service::SyncVault))
        .unwrap();
    assert_eq!(
        operation.wait_result(Duration::from_secs(2)),
        Err(ServiceError::CleanupRequired)
    );
    assert_eq!(counts.freshness_abort.load(Ordering::Acquire), 1);
    wait_until(|| service.snapshot().session_state() == SessionState::CleanupRequired);
    retry_cleanup_until_locked(&service);
    service.shutdown();
}
