use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notecrypt_core::SnapshotId;
use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_service::{
    Command, CompromiseTargetResolver, HostPortError, LocalStreamRevisionRequest, LocalVaultConfig,
    LogicalWorkspacePath, MonotonicClock, OperationContext, OperationExecutor, OperationResult,
    RecoveryKdfProfileV1, RecoverySecretInput, RepositoryPortError, ServiceConfig, ServiceError,
    ServiceHandle, SessionComponents, SessionPolicy, StableSourceToken, StartupCleanupReport,
    StoreVaultRepository, TargetWorkspaceRequest, VaultWorkspaceRequest, WorkspaceAbsenceGuard,
    WorkspaceLease, WorkspaceMode, WorkspaceOwnershipGuard, WorkspaceProvider, WorkspaceSession,
};
use notecrypt_store::VaultStore;
use tempfile::TempDir;

const SECRET: &str = "alpha beta gamma delta epsilon";
const SOURCE_BYTES: &[u8] = b"stable source bytes";

struct FixedClock;

impl MonotonicClock for FixedClock {
    fn elapsed(&self) -> Result<Duration, ServiceError> {
        Ok(Duration::ZERO)
    }
}

struct OwnershipGuard;

impl WorkspaceOwnershipGuard for OwnershipGuard {}

struct AbsenceGuard;

impl WorkspaceAbsenceGuard for AbsenceGuard {}

struct TargetResolver;

impl CompromiseTargetResolver for TargetResolver {
    fn resolve(&self, _target: [u8; 16]) -> Result<LocalVaultConfig, RepositoryPortError> {
        Err(RepositoryPortError::NotFound)
    }
}

#[derive(Default)]
struct SourceProbe {
    open_calls: AtomicUsize,
    validate_calls: AtomicUsize,
    read_calls: AtomicUsize,
    read_bytes: Mutex<Vec<u8>>,
    validated_tokens: Mutex<Vec<Vec<u8>>>,
    reject_validation: AtomicBool,
    fail_validation_allocation: AtomicBool,
    remove_calls: AtomicUsize,
    remove_failures_remaining: AtomicUsize,
    cleanup_calls: AtomicUsize,
    base_residue: AtomicUsize,
}

struct ObservedReader {
    source: Cursor<&'static [u8]>,
    probe: Arc<SourceProbe>,
}

impl Read for ObservedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.probe.read_calls.fetch_add(1, Ordering::AcqRel);
        let count = self.source.read(output)?;
        self.probe
            .read_bytes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend_from_slice(&output[..count]);
        Ok(count)
    }
}

struct StableSourceWorkspace {
    probe: Arc<SourceProbe>,
    workspace_root: PathBuf,
}

impl StableSourceWorkspace {
    fn lease(&self, request: TargetWorkspaceRequest) -> Result<WorkspaceLease, HostPortError> {
        let root = request.repository_root().join(request.id().child_name());
        WorkspaceLease::from_target_request(request, root, Box::new(OwnershipGuard))
    }
}

impl WorkspaceProvider for StableSourceWorkspace {
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError> {
        self.probe.cleanup_calls.fetch_add(1, Ordering::AcqRel);
        let removed = self.probe.base_residue.swap(0, Ordering::AcqRel);
        StartupCleanupReport::try_new(removed, 0)
    }

    fn create_target(
        &self,
        request: TargetWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError> {
        self.lease(request)
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
        lease: &WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
        expected_generation: u64,
    ) -> Result<notecrypt_service::OpenedStableSource, HostPortError> {
        assert_eq!(
            lease.root(),
            self.workspace_root.join(lease.id().child_name())
        );
        assert_eq!(relative_path.as_path(), Path::new("notes/café.md"));
        assert_eq!(expected_generation, 1);
        self.probe.open_calls.fetch_add(1, Ordering::AcqRel);
        let token = StableSourceToken::from_bytes(vec![0x51, 0x72, 0x93])?;
        Ok(notecrypt_service::OpenedStableSource::new(
            Box::new(ObservedReader {
                source: Cursor::new(SOURCE_BYTES),
                probe: Arc::clone(&self.probe),
            }),
            token,
        ))
    }

    fn validate_stable_source(
        &self,
        _lease: &WorkspaceLease,
        token: &StableSourceToken,
    ) -> Result<(), HostPortError> {
        self.probe.validate_calls.fetch_add(1, Ordering::AcqRel);
        self.probe
            .validated_tokens
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(token.as_bytes().to_vec());
        if self
            .probe
            .fail_validation_allocation
            .load(Ordering::Acquire)
        {
            Err(HostPortError::AllocationFailed)
        } else if self.probe.reject_validation.load(Ordering::Acquire) {
            Err(HostPortError::Denied)
        } else {
            Ok(())
        }
    }

    fn remove_workspace(
        &self,
        _lease: WorkspaceLease,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, HostPortError> {
        self.probe.remove_calls.fetch_add(1, Ordering::AcqRel);
        if self
            .probe
            .remove_failures_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            self.probe.base_residue.fetch_add(1, Ordering::AcqRel);
            return Err(HostPortError::CleanupFailed);
        }
        Ok(Box::new(AbsenceGuard))
    }

    fn acquire_verified_absence(
        &self,
        _id: &notecrypt_service::WorkspaceId,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, HostPortError> {
        Ok(Box::new(AbsenceGuard))
    }
}

struct StableSourceExecutor {
    repository_root: PathBuf,
    probe: Arc<SourceProbe>,
    workspace: Mutex<Option<WorkspaceSession>>,
}

impl StableSourceExecutor {
    fn new(repository_root: PathBuf, probe: Arc<SourceProbe>) -> Self {
        Self {
            repository_root,
            probe,
            workspace: Mutex::new(None),
        }
    }

    fn current_snapshot(&self, context: &OperationContext) -> Result<SnapshotId, ServiceError> {
        let mut lease = context.acquire_local_lease()?;
        let snapshot = lease
            .current_snapshot_id()
            .map_err(|_| ServiceError::ExecutorFailed)?;
        lease.finish().map_err(|_| ServiceError::ExecutorFailed)?;
        Ok(snapshot)
    }
}

impl OperationExecutor for StableSourceExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let mut workspace = self
            .workspace
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if workspace.is_none() {
            *workspace = Some(
                context.create_workspace(WorkspaceMode::Targeted, self.repository_root.clone())?,
            );
        }
        let session = workspace.as_ref().expect("workspace was just installed");
        let snapshot = self.current_snapshot(context)?;
        let request = LocalStreamRevisionRequest::try_create(snapshot, "café.md")
            .map_err(|_| ServiceError::ExecutorFailed)?;
        let path = LogicalWorkspacePath::new(PathBuf::from("notes/café.md"))
            .map_err(|_| ServiceError::ExecutorFailed)?;
        context.commit_workspace_stable_revision(session, &path, 1, request)?;

        let snapshot = self.current_snapshot(context)?;
        let request = LocalStreamRevisionRequest::try_create(snapshot, "collision.md")
            .map_err(|_| ServiceError::ExecutorFailed)?;
        let colliding_path = LogicalWorkspacePath::new(PathBuf::from("NOTES/CAFÉ.MD"))
            .map_err(|_| ServiceError::ExecutorFailed)?;
        let second = context.commit_workspace_stable_revision(session, &colliding_path, 1, request);
        assert!(matches!(second, Err(ServiceError::InvalidConfiguration)));
        assert_eq!(self.probe.open_calls.load(Ordering::Acquire), 1);
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

struct ValidationFailureExecutor {
    repository_root: PathBuf,
    probe: Arc<SourceProbe>,
    workspace: Mutex<Option<WorkspaceSession>>,
    expected_error: Option<ServiceError>,
}

struct TwoWorkspaceExecutor {
    repository_root: PathBuf,
}

impl OperationExecutor for TwoWorkspaceExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let first =
            context.create_workspace(WorkspaceMode::Targeted, self.repository_root.clone())?;
        let second =
            context.create_workspace(WorkspaceMode::Targeted, self.repository_root.clone())?;
        drop(first);
        drop(second);
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

impl OperationExecutor for ValidationFailureExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let mut workspace = self
            .workspace
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = workspace.get_or_insert_with(|| {
            context
                .create_workspace(WorkspaceMode::Targeted, self.repository_root.clone())
                .expect("workspace creation should succeed")
        });
        let mut lease = context.acquire_local_lease()?;
        let before = lease
            .current_snapshot_id()
            .map_err(|_| ServiceError::ExecutorFailed)?;
        lease.finish().map_err(|_| ServiceError::ExecutorFailed)?;
        let request = LocalStreamRevisionRequest::try_create(before, "café.md")
            .map_err(|_| ServiceError::ExecutorFailed)?;
        let path = LogicalWorkspacePath::new(PathBuf::from("notes/café.md"))
            .map_err(|_| ServiceError::ExecutorFailed)?;
        let error = match context.commit_workspace_stable_revision(session, &path, 1, request) {
            Ok(_) => panic!("validation failure must prevent publication"),
            Err(error) => error,
        };
        if let Some(expected) = self.expected_error {
            assert_eq!(error, expected);
        }
        let mut lease = context.acquire_local_lease()?;
        let after = lease
            .current_snapshot_id()
            .map_err(|_| ServiceError::ExecutorFailed)?;
        lease.finish().map_err(|_| ServiceError::ExecutorFailed)?;
        assert_eq!(before, after);
        assert_eq!(self.probe.open_calls.load(Ordering::Acquire), 1);
        assert_eq!(self.probe.validate_calls.load(Ordering::Acquire), 1);
        Ok(OperationResult::Entries(
            notecrypt_service::EntrySummaries::empty(),
        ))
    }
}

fn parameters() -> ValidatedArgon2idParameters {
    ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap()
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

fn service(
    repository_root: &Path,
    local_root: &Path,
    workspace: Arc<StableSourceWorkspace>,
    probe: Arc<SourceProbe>,
    executor: Arc<dyn OperationExecutor>,
) -> ServiceHandle {
    let store = VaultStore::initialize(
        &repository_root.canonicalize().unwrap(),
        &local_root.canonicalize().unwrap(),
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "test-device",
        &AtomicBool::new(false),
    )
    .unwrap();
    drop(store);
    let target = LocalVaultConfig::try_new(
        repository_root.canonicalize().unwrap(),
        local_root.canonicalize().unwrap(),
        RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap(),
        "test-device".to_owned(),
    )
    .unwrap();
    let repository =
        StoreVaultRepository::open(target, workspace.clone(), Arc::new(TargetResolver)).unwrap();
    let components = SessionComponents::new(
        Arc::new(repository),
        workspace,
        Arc::new(FixedClock),
        policy(),
    );
    let service = ServiceHandle::with_session_components(
        ServiceConfig::default(),
        executor,
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0;
    service
        .unlock_with_recovery(
            RecoverySecretInput::from_protected_bytes(SECRET.as_bytes().to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(probe.validate_calls.load(Ordering::Acquire), 0);
    service
}

#[test]
fn stable_source_commit_uses_one_exact_handle_and_rejects_portable_collision_before_open() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let probe = Arc::new(SourceProbe::default());
    let workspace = Arc::new(StableSourceWorkspace {
        probe: Arc::clone(&probe),
        workspace_root: repository.path().to_path_buf(),
    });
    let executor = Arc::new(StableSourceExecutor::new(
        repository.path().to_path_buf(),
        Arc::clone(&probe),
    ));
    let service = service(
        repository.path(),
        local.path(),
        workspace,
        Arc::clone(&probe),
        executor,
    );
    let result = service.submit(Command::Backup(notecrypt_service::BackupVault));
    assert!(result.is_ok());
    result.unwrap().wait_result(Duration::from_secs(5)).unwrap();
    assert_eq!(probe.open_calls.load(Ordering::Acquire), 1);
    assert_eq!(probe.validate_calls.load(Ordering::Acquire), 1);
    assert!(probe.read_calls.load(Ordering::Acquire) >= 1);
    assert_eq!(probe.read_bytes.lock().unwrap().as_slice(), SOURCE_BYTES);
    assert_eq!(
        probe.validated_tokens.lock().unwrap().as_slice(),
        &[vec![0x51, 0x72, 0x93]]
    );
    service.shutdown();
}

#[test]
fn stable_source_validation_failure_publishes_no_revision_and_validates_once() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let probe = Arc::new(SourceProbe::default());
    probe.reject_validation.store(true, Ordering::Release);
    let workspace = Arc::new(StableSourceWorkspace {
        probe: Arc::clone(&probe),
        workspace_root: repository.path().to_path_buf(),
    });
    let executor = Arc::new(ValidationFailureExecutor {
        repository_root: repository.path().to_path_buf(),
        probe: Arc::clone(&probe),
        workspace: Mutex::new(None),
        expected_error: None,
    });
    let service = service(
        repository.path(),
        local.path(),
        workspace,
        Arc::clone(&probe),
        executor,
    );
    let operation = service
        .submit(Command::Backup(notecrypt_service::BackupVault))
        .unwrap();
    operation.wait_result(Duration::from_secs(5)).unwrap();
    assert_eq!(probe.open_calls.load(Ordering::Acquire), 1);
    assert_eq!(probe.validate_calls.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn stable_source_allocation_failure_reaches_the_public_service_error() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let probe = Arc::new(SourceProbe::default());
    probe
        .fail_validation_allocation
        .store(true, Ordering::Release);
    let workspace = Arc::new(StableSourceWorkspace {
        probe: Arc::clone(&probe),
        workspace_root: repository.path().to_path_buf(),
    });
    let executor = Arc::new(ValidationFailureExecutor {
        repository_root: repository.path().to_path_buf(),
        probe: Arc::clone(&probe),
        workspace: Mutex::new(None),
        expected_error: Some(ServiceError::AllocationFailed),
    });
    let service = service(
        repository.path(),
        local.path(),
        workspace,
        Arc::clone(&probe),
        executor,
    );

    service
        .submit(Command::Backup(notecrypt_service::BackupVault))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();

    assert_eq!(probe.validate_calls.load(Ordering::Acquire), 1);
    service.shutdown();
}

#[test]
fn two_workspace_cleanup_failure_is_retryable_after_root_revocation() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let probe = Arc::new(SourceProbe::default());
    probe.remove_failures_remaining.store(1, Ordering::Release);
    let workspace = Arc::new(StableSourceWorkspace {
        probe: Arc::clone(&probe),
        workspace_root: repository.path().to_path_buf(),
    });
    let executor = Arc::new(TwoWorkspaceExecutor {
        repository_root: repository.path().to_path_buf(),
    });
    let service = service(
        repository.path(),
        local.path(),
        workspace,
        Arc::clone(&probe),
        executor,
    );
    service
        .submit(Command::Backup(notecrypt_service::BackupVault))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while service.snapshot().session_state() != notecrypt_service::SessionState::CleanupRequired {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    loop {
        match service.retry_cleanup() {
            Ok(()) => break,
            Err(ServiceError::Busy) => {
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
            Err(error) => panic!("unexpected retry error: {error:?}"),
        }
    }
    assert_eq!(
        service.snapshot().session_state(),
        notecrypt_service::SessionState::Locked
    );
    assert_eq!(probe.remove_calls.load(Ordering::Acquire), 2);
    assert_eq!(probe.base_residue.load(Ordering::Acquire), 0);
    assert!(probe.cleanup_calls.load(Ordering::Acquire) >= 2);
}
