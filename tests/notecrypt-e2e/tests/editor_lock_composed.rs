#![cfg(any(unix, windows))]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_editor_workspace::{ProcessEditorSupervisor, SecureWorkspaceProvider};
#[cfg(windows)]
use notecrypt_platform_fs::{Directory, PhysicalComponent};
use notecrypt_service::{
    BackupVault, Command, CompromiseTargetResolver, Control, EditorCommand, EditorLaunchRequest,
    EditorResolutionRequest, EditorSupervisionMode, EditorSupervisor, LocalVaultConfig,
    LogicalWorkspacePath, MaterializationPublication, MonotonicClock, OperationContext,
    OperationExecutor, OperationResult, RecoveryKdfProfileV1, RecoverySecretInput,
    RepositoryPortError, ServiceConfig, ServiceError, ServiceHandle, SessionComponents,
    SessionPolicy, SessionState, StoreVaultRepository, WorkspaceMode, WorkspaceProvider,
    WorkspaceSession,
};
use notecrypt_store::VaultStore;
use tempfile::TempDir;

const SECRET: &str = "alpha beta gamma delta epsilon";

struct FixedClock;

impl MonotonicClock for FixedClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        Ok(Duration::ZERO)
    }
}

struct NoTargets;

impl CompromiseTargetResolver for NoTargets {
    fn resolve(&self, _target: [u8; 16]) -> Result<LocalVaultConfig, RepositoryPortError> {
        Err(RepositoryPortError::NotFound)
    }
}

struct WorkspaceExecutor {
    repository: PathBuf,
    sender: Mutex<mpsc::Sender<WorkspaceSession>>,
}

#[derive(Clone, Copy, Debug)]
enum PanicStage {
    Request,
    Poll,
    Force,
}

#[derive(Clone, Copy, Debug)]
enum WorkspacePanicStage {
    Remove,
    BaseCleanup,
}

struct PanicOnceWorkspaceProvider {
    inner: Arc<SecureWorkspaceProvider>,
    stage: WorkspacePanicStage,
    armed: AtomicBool,
    fired: AtomicBool,
}

impl PanicOnceWorkspaceProvider {
    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    fn panic_if_selected(&self, stage: WorkspacePanicStage) {
        if self.armed.load(Ordering::Acquire)
            && std::mem::discriminant(&self.stage) == std::mem::discriminant(&stage)
            && !self.fired.swap(true, Ordering::AcqRel)
        {
            panic!("injected workspace cleanup callback panic");
        }
    }
}

impl WorkspaceProvider for PanicOnceWorkspaceProvider {
    fn cleanup_owned_base(
        &self,
    ) -> Result<notecrypt_service::StartupCleanupReport, notecrypt_service::HostPortError> {
        self.panic_if_selected(WorkspacePanicStage::BaseCleanup);
        self.inner.cleanup_owned_base()
    }

    fn create_target(
        &self,
        request: notecrypt_service::TargetWorkspaceRequest,
    ) -> Result<notecrypt_service::WorkspaceLease, notecrypt_service::HostPortError> {
        self.inner.create_target(request)
    }

    fn create_whole_vault(
        &self,
        request: notecrypt_service::VaultWorkspaceRequest,
    ) -> Result<notecrypt_service::WorkspaceLease, notecrypt_service::HostPortError> {
        self.inner.create_whole_vault(request)
    }

    fn confirm_activated(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
    ) -> Result<(), notecrypt_service::HostPortError> {
        self.inner.confirm_activated(lease)
    }

    fn materialization_target(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
    ) -> Result<notecrypt_service::MaterializationTarget, notecrypt_service::HostPortError> {
        self.inner.materialization_target(lease, relative_path)
    }

    fn publish_materialized(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
        target: notecrypt_service::MaterializationTarget,
    ) -> Result<MaterializationPublication, notecrypt_service::HostPortError> {
        self.inner.publish_materialized(lease, target)
    }

    fn confirm_materialized(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
        pending: &mut notecrypt_service::PendingPublishedGeneration,
    ) -> Result<notecrypt_service::PublishedGeneration, notecrypt_service::HostPortError> {
        self.inner.confirm_materialized(lease, pending)
    }

    fn arm_published_path(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
        published: &mut notecrypt_service::PublishedGeneration,
    ) -> Result<(), notecrypt_service::HostPortError> {
        self.inner.arm_published_path(lease, published)
    }

    fn watch(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
    ) -> Result<Box<dyn notecrypt_service::WorkspaceWatch>, notecrypt_service::HostPortError> {
        self.inner.watch(lease)
    }

    fn open_stable_source(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
        expected_generation: u64,
    ) -> Result<notecrypt_service::OpenedStableSource, notecrypt_service::HostPortError> {
        self.inner
            .open_stable_source(lease, relative_path, expected_generation)
    }

    fn validate_stable_source(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
        token: &notecrypt_service::StableSourceToken,
    ) -> Result<(), notecrypt_service::HostPortError> {
        self.inner.validate_stable_source(lease, token)
    }

    fn remove_workspace(
        &self,
        lease: &notecrypt_service::WorkspaceLease,
    ) -> Result<Box<dyn notecrypt_service::WorkspaceAbsenceGuard>, notecrypt_service::HostPortError>
    {
        self.panic_if_selected(WorkspacePanicStage::Remove);
        self.inner.remove_workspace(lease)
    }

    fn acquire_verified_absence(
        &self,
        id: &notecrypt_service::WorkspaceId,
    ) -> Result<Box<dyn notecrypt_service::WorkspaceAbsenceGuard>, notecrypt_service::HostPortError>
    {
        self.inner.acquire_verified_absence(id)
    }
}

struct PanicOnceEditorSupervisor {
    inner: Arc<ProcessEditorSupervisor>,
    stage: PanicStage,
    fired: AtomicBool,
}

impl PanicOnceEditorSupervisor {
    fn panic_if_selected(&self, stage: PanicStage) {
        if std::mem::discriminant(&self.stage) == std::mem::discriminant(&stage)
            && !self.fired.swap(true, Ordering::AcqRel)
        {
            panic!("injected editor supervisor callback panic");
        }
    }
}

impl EditorSupervisor for PanicOnceEditorSupervisor {
    fn launch(
        &self,
        request: EditorLaunchRequest,
    ) -> Result<Box<dyn notecrypt_service::EditorProcess>, notecrypt_service::HostPortError> {
        self.inner.launch(request)
    }

    fn request_stop_all(&self) -> Result<(), notecrypt_service::HostPortError> {
        self.panic_if_selected(PanicStage::Request);
        self.inner.request_stop_all()
    }

    fn poll_quiescence(
        &self,
    ) -> Result<notecrypt_service::EditorQuiescence, notecrypt_service::HostPortError> {
        self.panic_if_selected(PanicStage::Poll);
        self.inner.poll_quiescence()
    }

    fn force_stop_all(&self) -> Result<(), notecrypt_service::HostPortError> {
        self.panic_if_selected(PanicStage::Force);
        self.inner.force_stop_all()
    }
}

impl OperationExecutor for WorkspaceExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let workspace =
            context.create_workspace(WorkspaceMode::Targeted, self.repository.clone())?;
        self.sender
            .lock()
            .unwrap()
            .send(workspace)
            .map_err(|_| ServiceError::ExecutorFailed)?;
        Err(ServiceError::ExecutorFailed)
    }
}

fn private_dir(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    #[cfg(unix)]
    {
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    {
        let parent = Directory::open_ambient(parent).unwrap();
        let component = PhysicalComponent::try_new(name).unwrap();
        drop(parent.create_private_dir(&component).unwrap());
    }
    fs::canonicalize(path).unwrap()
}

fn parameters() -> ValidatedArgon2idParameters {
    ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap()
}

fn secret() -> RecoverySecretInput {
    RecoverySecretInput::from_protected_bytes(SECRET.as_bytes().to_vec()).unwrap()
}

fn run_composed_lock_case(
    helper_mode: &str,
    basename: &str,
    unowned: bool,
    shutdown: bool,
    panic_stage: Option<PanicStage>,
    workspace_panic_stage: Option<WorkspacePanicStage>,
) {
    let root = TempDir::new().unwrap();
    let repository = private_dir(root.path(), "repository");
    let local = private_dir(root.path(), "local");
    let base = private_dir(root.path(), "workspace-v1");
    drop(
        VaultStore::initialize(
            &repository,
            &local,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap(),
    );
    let provider =
        Arc::new(SecureWorkspaceProvider::open(base, repository.clone(), local.clone()).unwrap());
    let editor_dir = private_dir(root.path(), helper_mode);
    let editor = editor_dir.join(if cfg!(windows) {
        format!("{basename}.exe")
    } else {
        basename.to_owned()
    });
    fs::copy(env!("CARGO_BIN_EXE_test_editor"), &editor).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o700)).unwrap();
    let supervisor = Arc::new(
        ProcessEditorSupervisor::new_with_trusted_test_executable(
            Arc::clone(&provider),
            editor.clone(),
        )
        .unwrap(),
    );
    let composed_supervisor: Arc<dyn EditorSupervisor> = match panic_stage {
        Some(stage) => Arc::new(PanicOnceEditorSupervisor {
            inner: Arc::clone(&supervisor),
            stage,
            fired: AtomicBool::new(false),
        }),
        None => supervisor.clone(),
    };
    let panic_workspace = workspace_panic_stage.map(|stage| {
        Arc::new(PanicOnceWorkspaceProvider {
            inner: Arc::clone(&provider),
            stage,
            armed: AtomicBool::new(false),
            fired: AtomicBool::new(false),
        })
    });
    let workspace_port: Arc<dyn WorkspaceProvider> = match &panic_workspace {
        Some(provider) => provider.clone(),
        None => provider.clone(),
    };
    let repository_port = StoreVaultRepository::open(
        LocalVaultConfig::try_new(
            repository.clone(),
            local,
            RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap(),
            "device".to_owned(),
        )
        .unwrap(),
        Arc::clone(&workspace_port),
        Arc::new(NoTargets),
    )
    .unwrap();
    let (sender, receiver) = mpsc::channel();
    let components = SessionComponents::new(
        Arc::new(repository_port),
        workspace_port,
        Arc::new(FixedClock),
        SessionPolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(120),
            Vec::new(),
            Duration::ZERO,
        )
        .unwrap(),
    )
    .with_editor_supervisor(composed_supervisor);
    let (service, _) = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(WorkspaceExecutor {
            repository: repository.clone(),
            sender: Mutex::new(sender),
        }),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap();
    service.unlock_with_recovery(secret()).unwrap();
    let _operation = service.submit(Command::Backup(BackupVault)).unwrap();
    let workspace = receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    let (lease_root, ready, request) = workspace
        .with_lease_for_test(|lease| {
            let logical = LogicalWorkspacePath::new(PathBuf::from("composed lock.md")).unwrap();
            let mut target = provider.materialization_target(lease, &logical).unwrap();
            target.writer_mut().write_all(b"plaintext").unwrap();
            let mut published = match provider.publish_materialized(lease, target).unwrap() {
                MaterializationPublication::Durable(published) => published,
                MaterializationPublication::DurabilityPending(_) => {
                    panic!("ordinary publication unexpectedly remained durability-pending")
                }
            };
            let path = published.path().to_path_buf();
            provider.arm_published_path(lease, &mut published).unwrap();
            let command = EditorCommand::try_new(editor.into_os_string(), Vec::new()).unwrap();
            let resolution = EditorResolutionRequest::try_new(
                Some(command),
                None,
                None,
                if cfg!(windows) && !unowned {
                    EditorSupervisionMode::Strict
                } else {
                    EditorSupervisionMode::Blocking
                },
            )
            .unwrap();
            (
                lease.root().to_path_buf(),
                path.with_extension("ready"),
                EditorLaunchRequest::try_new(lease, resolution, path, 1).unwrap(),
            )
        })
        .unwrap();
    let process = supervisor.launch(request).unwrap();
    drop(process);
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        assert!(
            Instant::now() < ready_deadline,
            "editor did not install its termination handler"
        );
        std::thread::yield_now();
    }
    if let Some(provider) = &panic_workspace {
        provider.arm();
    }

    if shutdown {
        service.shutdown();
    } else {
        service.control(Control::LockNow).unwrap();
    }
    let deadline = Instant::now()
        + if panic_stage.is_some() {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(5)
        };
    let expected = if unowned || panic_stage.is_some() || workspace_panic_stage.is_some() {
        SessionState::CleanupRequired
    } else {
        SessionState::Locked
    };
    while service.snapshot().session_state() != expected {
        assert!(
            Instant::now() < deadline,
            "lock transition did not finish for panic stage {panic_stage:?}"
        );
        std::thread::yield_now();
    }
    if shutdown {
        assert!(service.snapshot().is_closed());
    }
    if panic_stage.is_some() || workspace_panic_stage.is_some() {
        if !matches!(
            workspace_panic_stage,
            Some(WorkspacePanicStage::BaseCleanup)
        ) {
            assert!(lease_root.exists());
        }
        service.retry_cleanup().unwrap();
        assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    } else if unowned {
        assert!(lease_root.exists());
        fs::write(ready.with_extension("release"), b"release").unwrap();
        let exit_deadline = Instant::now() + Duration::from_secs(5);
        while !supervisor.poll_quiescence().unwrap().is_quiescent() {
            assert!(
                Instant::now() < exit_deadline,
                "blocking proxy did not exit naturally"
            );
            std::thread::yield_now();
        }
        service.retry_cleanup().unwrap();
        assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    }
    assert!(!lease_root.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
}

#[test]
fn public_lock_reaps_the_real_editor_before_physical_and_authenticated_cleanup() {
    run_composed_lock_case("ignore-termination", "nvim", false, false, None, None);
}

#[test]
fn public_lock_retains_unowned_workspace_until_natural_exit_and_retry() {
    run_composed_lock_case("blocking", "code", true, false, None, None);
}

#[test]
fn public_shutdown_keeps_components_alive_until_editor_and_workspace_cleanup_finish() {
    run_composed_lock_case("ignore-termination", "nvim", false, true, None, None);
}

#[test]
fn editor_supervisor_callback_panics_retain_workspace_until_retry() {
    for stage in [PanicStage::Request, PanicStage::Poll, PanicStage::Force] {
        run_composed_lock_case(
            "ignore-termination",
            "nvim",
            false,
            false,
            Some(stage),
            None,
        );
    }
}

#[test]
fn workspace_cleanup_callback_panics_retain_exact_state_until_retry() {
    for stage in [
        WorkspacePanicStage::Remove,
        WorkspacePanicStage::BaseCleanup,
    ] {
        run_composed_lock_case("normal", "nvim", false, false, None, Some(stage));
    }
}
