use std::sync::{Arc, Mutex};
use std::time::Duration;

use notecrypt_service::{
    BeginRecoveryInitialization, Command, CompromiseTargetResolver, HostPortError,
    LocalVaultConfig, LogicalWorkspacePath, MonotonicClock, OfflineGuessingRiskDisclosure,
    OperationContext, OperationExecutor, OperationResult, RecoveryKdfProfileV1,
    RecoverySecretInput, RecoverySecretPresenter, RepositoryPortError, ServiceConfig, ServiceError,
    ServiceHandle, SessionComponents, SessionPolicy, StartupCleanupReport, StoreVaultRepository,
    TargetWorkspaceRequest, VaultWorkspaceRequest, WorkspaceLease, WorkspaceProvider,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const CUSTOM_SECRET: &str = "alpha beta gamma delta epsilon";

fn initialization_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

struct FixedClock;

impl MonotonicClock for FixedClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        Ok(Duration::ZERO)
    }
}

struct UnavailableWorkspace;

impl WorkspaceProvider for UnavailableWorkspace {
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError> {
        StartupCleanupReport::try_new(0, 0)
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
        _relative_path: &LogicalWorkspacePath,
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
        _relative_path: &LogicalWorkspacePath,
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

struct NoTargets;
impl CompromiseTargetResolver for NoTargets {
    fn resolve(&self, _target: [u8; 16]) -> Result<LocalVaultConfig, RepositoryPortError> {
        Err(RepositoryPortError::NotFound)
    }
}

struct RejectingExecutor;
impl OperationExecutor for RejectingExecutor {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Err(ServiceError::ExecutorFailed)
    }
}

fn target(repository: &TempDir, local: &TempDir) -> LocalVaultConfig {
    LocalVaultConfig::try_new(
        repository.path().canonicalize().unwrap(),
        local.path().canonicalize().unwrap(),
        RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap(),
        "device".to_owned(),
    )
    .unwrap()
}

fn service(repository: &TempDir, local: &TempDir) -> ServiceHandle {
    let workspace: Arc<dyn WorkspaceProvider> = Arc::new(UnavailableWorkspace);
    let repository = StoreVaultRepository::vacant(
        target(repository, local),
        Arc::clone(&workspace),
        Arc::new(NoTargets),
    );
    let components = SessionComponents::new(
        Arc::new(repository),
        workspace,
        Arc::new(FixedClock),
        SessionPolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(120),
            Vec::new(),
            Duration::from_secs(1),
        )
        .unwrap(),
    );
    ServiceHandle::with_local_use_cases(
        ServiceConfig::default(),
        Arc::new(RejectingExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0
}

fn secret(value: &[u8]) -> RecoverySecretInput {
    RecoverySecretInput::from_protected_bytes(value.to_vec()).unwrap()
}

struct Capture(Arc<Mutex<Zeroizing<Vec<u8>>>>);
impl RecoverySecretPresenter for Capture {
    fn present(&mut self, presented: &[u8]) -> Result<(), HostPortError> {
        self.0.lock().unwrap().extend_from_slice(presented);
        Ok(())
    }
}

struct PanickingPresenter;

impl RecoverySecretPresenter for PanickingPresenter {
    fn present(&mut self, _presented: &[u8]) -> Result<(), HostPortError> {
        panic!("host presenter panic")
    }
}

fn roots_are_empty(repository: &TempDir, local: &TempDir) -> bool {
    std::fs::read_dir(repository.path())
        .unwrap()
        .next()
        .is_none()
        && std::fs::read_dir(local.path()).unwrap().next().is_none()
}

#[test]
fn generated_recovery_is_twelve_words_and_publishes_only_after_exact_confirmation() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    assert!(roots_are_empty(&repository, &local));
    let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
    presentation
        .unwrap()
        .present_once(&mut Capture(Arc::clone(&captured)))
        .unwrap();
    let phrase = captured.lock().unwrap();
    assert_eq!(phrase.split(|byte| *byte == b' ').count(), 12);
    let confirmation = secret(&phrase);
    drop(phrase);
    let summary = service
        .confirm_recovery_initialization(pending, confirmation)
        .unwrap();
    assert!(!roots_are_empty(&repository, &local));
    assert_eq!(
        service.snapshot().session_state(),
        notecrypt_service::SessionState::Locked
    );
    let unlocked = service
        .unlock_with_recovery(secret(&captured.lock().unwrap()))
        .unwrap();
    assert_eq!(
        service.snapshot().session_state(),
        notecrypt_service::SessionState::Unlocked
    );
    assert_eq!(summary.vault_id(), unlocked.vault_id());
}

#[test]
fn wrong_or_cancelled_generated_confirmation_leaves_no_durable_state() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(presentation);
    assert_eq!(
        service
            .confirm_recovery_initialization(pending, secret(b"wrong generated recovery phrase")),
        Err(ServiceError::AuthenticationFailed)
    );
    assert!(roots_are_empty(&repository, &local));

    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(presentation);
    service.cancel_recovery_initialization(pending).unwrap();
    assert!(roots_are_empty(&repository, &local));
}

#[test]
fn dropped_pending_invalidates_presentation_and_presenter_panic_is_contained() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    drop(pending);
    assert_eq!(
        presentation
            .unwrap()
            .present_once(&mut Capture(Arc::new(Mutex::new(Zeroizing::new(
                Vec::new()
            ),)))),
        Err(HostPortError::InvalidInput)
    );
    assert!(roots_are_empty(&repository, &local));

    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    assert_eq!(
        presentation.unwrap().present_once(&mut PanickingPresenter),
        Err(HostPortError::PlatformFailure)
    );
    service.cancel_recovery_initialization(pending).unwrap();
    assert!(roots_are_empty(&repository, &local));
}

#[test]
fn cancellation_after_active_commit_returns_success_and_installs_repository() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
    presentation
        .unwrap()
        .present_once(&mut Capture(Arc::clone(&captured)))
        .unwrap();
    let hook_service = service.clone();
    notecrypt_store::local_test_support::install_after_initial_availability_hook(move || {
        assert_eq!(
            std::thread::current().name(),
            Some("notecrypt-service-security-worker")
        );
        hook_service
            .control(notecrypt_service::Control::LockNow)
            .unwrap();
    });
    let summary = service
        .confirm_recovery_initialization(pending, secret(&captured.lock().unwrap()))
        .unwrap();
    let unlocked = service
        .unlock_with_recovery(secret(&captured.lock().unwrap()))
        .unwrap();
    assert_eq!(summary.vault_id(), unlocked.vault_id());
}

#[test]
fn cancellation_immediately_before_active_commit_leaves_no_target_state() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
    presentation
        .unwrap()
        .present_once(&mut Capture(Arc::clone(&captured)))
        .unwrap();
    let hook_service = service.clone();
    notecrypt_store::local_test_support::install_before_initial_availability_send_hook(move || {
        assert_eq!(
            std::thread::current().name(),
            Some("notecrypt-service-security-worker")
        );
        hook_service
            .control(notecrypt_service::Control::LockNow)
            .unwrap();
    });
    assert_eq!(
        service.confirm_recovery_initialization(pending, secret(&captured.lock().unwrap())),
        Err(ServiceError::Cancelled)
    );
    assert!(roots_are_empty(&repository, &local));
}

#[test]
fn every_semantic_initialization_entropy_failure_leaves_no_target_state() {
    let _guard = initialization_test_guard();
    use notecrypt_store::local_test_support::InitializationEntropyStage;

    for stage in [
        InitializationEntropyStage::VaultIdentity,
        InitializationEntropyStage::RecoverySlotIdentity,
        InitializationEntropyStage::SnapshotIdentity,
        InitializationEntropyStage::ObjectIdentity,
        InitializationEntropyStage::Nonce,
    ] {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let service = service(&repository, &local);
        let (pending, presentation) = service
            .begin_recovery_initialization(BeginRecoveryInitialization::generated())
            .unwrap();
        let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
        presentation
            .unwrap()
            .present_once(&mut Capture(Arc::clone(&captured)))
            .unwrap();
        notecrypt_store::local_test_support::fail_initialization_entropy_at(stage);
        assert_eq!(
            service.confirm_recovery_initialization(pending, secret(&captured.lock().unwrap())),
            Err(ServiceError::EntropyUnavailable),
            "semantic entropy stage {stage:?} must fail closed"
        );
        assert!(roots_are_empty(&repository, &local));
    }
}

#[test]
fn kdf_cancellation_and_panics_are_typed_and_leave_no_target_state() {
    let _guard = initialization_test_guard();
    use notecrypt_store::local_test_support::InitializationKdfFault;

    for (fault, expected) in [
        (
            InitializationKdfFault::CancelBeforeStart,
            ServiceError::Cancelled,
        ),
        (
            InitializationKdfFault::CancelAfterComputation,
            ServiceError::Cancelled,
        ),
        (
            InitializationKdfFault::PanicBeforeStart,
            ServiceError::CleanupRequired,
        ),
        (
            InitializationKdfFault::PanicAfterComputation,
            ServiceError::CleanupRequired,
        ),
    ] {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let service = service(&repository, &local);
        let (pending, presentation) = service
            .begin_recovery_initialization(BeginRecoveryInitialization::generated())
            .unwrap();
        let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
        presentation
            .unwrap()
            .present_once(&mut Capture(Arc::clone(&captured)))
            .unwrap();
        notecrypt_store::local_test_support::fail_initialization_kdf_at(fault);
        assert_eq!(
            service.confirm_recovery_initialization(pending, secret(&captured.lock().unwrap())),
            Err(expected),
            "KDF fault {fault:?} must be typed"
        );
        assert!(roots_are_empty(&repository, &local));
    }
}

#[test]
fn initialization_csprng_panic_is_contained_before_target_creation() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
    presentation
        .unwrap()
        .present_once(&mut Capture(Arc::clone(&captured)))
        .unwrap();
    notecrypt_store::local_test_support::panic_initialization_entropy_at(
        notecrypt_store::local_test_support::InitializationEntropyStage::VaultIdentity,
    );
    assert_eq!(
        service.confirm_recovery_initialization(pending, secret(&captured.lock().unwrap())),
        Err(ServiceError::CleanupRequired)
    );
    assert!(roots_are_empty(&repository, &local));
}

#[test]
fn blocked_production_initialization_does_not_block_submit_or_priority_lock() {
    let _guard = initialization_test_guard();
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let captured = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
    presentation
        .unwrap()
        .present_once(&mut Capture(Arc::clone(&captured)))
        .unwrap();
    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    notecrypt_store::local_test_support::install_before_initial_availability_send_hook(move || {
        assert_eq!(
            std::thread::current().name(),
            Some("notecrypt-service-security-worker")
        );
        entered_sender.send(()).unwrap();
        release_receiver.recv().unwrap();
    });
    let confirmer = service.clone();
    let confirmation = secret(&captured.lock().unwrap());
    let worker = std::thread::spawn(move || {
        confirmer.confirm_recovery_initialization(pending, confirmation)
    });
    entered_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    assert!(matches!(
        service.submit(Command::Status(notecrypt_service::VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    release_sender.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), Err(ServiceError::Cancelled));
    assert!(roots_are_empty(&repository, &local));
}

#[test]
fn custom_recovery_requires_warning_acceptance_and_matching_confirmation() {
    let _guard = initialization_test_guard();
    assert_eq!(
        OfflineGuessingRiskDisclosure::try_for_policy(2).map(|_| ()),
        Err(RepositoryPortError::InvalidInput)
    );
    let disclosure = OfflineGuessingRiskDisclosure::try_for_policy(1).unwrap();
    assert!(disclosure.warning().contains("offline"));
    assert!(disclosure.warning().contains("Argon2id"));
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let service = service(&repository, &local);
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::custom_v1(
            secret(CUSTOM_SECRET.as_bytes()),
            disclosure.accept(),
        ))
        .unwrap();
    assert!(presentation.is_none());
    assert!(roots_are_empty(&repository, &local));
    assert_eq!(
        service.confirm_recovery_initialization(pending, secret(b"alpha beta gamma delta zeta")),
        Err(ServiceError::AuthenticationFailed)
    );
    assert!(roots_are_empty(&repository, &local));

    let (cancelled, _) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::custom_v1(
            secret(CUSTOM_SECRET.as_bytes()),
            OfflineGuessingRiskDisclosure::try_for_policy(1)
                .unwrap()
                .accept(),
        ))
        .unwrap();
    service.cancel_recovery_initialization(cancelled).unwrap();
    assert!(roots_are_empty(&repository, &local));

    let (pending, _) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::custom_v1(
            secret(CUSTOM_SECRET.as_bytes()),
            OfflineGuessingRiskDisclosure::try_for_policy(1)
                .unwrap()
                .accept(),
        ))
        .unwrap();
    service
        .confirm_recovery_initialization(pending, secret(CUSTOM_SECRET.as_bytes()))
        .unwrap();
    assert!(!roots_are_empty(&repository, &local));
}
