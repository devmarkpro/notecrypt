use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_service::{
    Command, CompromiseTargetResolver, CreateDirectory, CreateFile, DeleteEntry, ExportFile,
    ExportOverwriteConfirmation, ExportSelection, ExternalExportTransaction, ExternalFileProvider,
    HostPortError, ImportFile, ImportSelection, LocalVaultConfig, LogicalWorkspacePath,
    MonotonicClock, MoveEntry, OpenedExport, OpenedImport, OperationContext, OperationEvent,
    OperationExecutor, OperationPhase, OperationResult, PlatformExternalFileProvider,
    RecoveryKdfProfileV1, RecoverySecretInput, RenameEntry, RepositoryPortError, ServiceConfig,
    ServiceError, ServiceHandle, SessionComponents, SessionPolicy, SnapshotVersion,
    StartupCleanupReport, StoreVaultRepository, TargetWorkspaceRequest, VaultStatusRequest,
    VaultWorkspaceRequest, WorkspaceLease, WorkspaceProvider,
};
use notecrypt_store::{VaultStore, local_test_support};
use tempfile::TempDir;

const SECRET: &str = "alpha beta gamma delta epsilon";
const CONTENT: &[u8] = b"task-eleven-service-import-canary";

#[test]
fn mutation_command_bounds_accept_maximum_and_reject_maximum_plus_one() {
    let snapshot = SnapshotVersion::new([0x11; 32]);
    let parent = notecrypt_service::EntryId::new([0x22; 16]);
    let maximum_name = "n".repeat(notecrypt_service::MAX_LOGICAL_COMPONENT_BYTES);
    assert!(CreateFile::try_new(snapshot, parent, &maximum_name).is_ok());
    let oversized_name = "n".repeat(notecrypt_service::MAX_LOGICAL_COMPONENT_BYTES + 1);
    assert_eq!(
        CreateFile::try_new(snapshot, parent, &oversized_name).unwrap_err(),
        ServiceError::CapacityExceeded
    );

    let maximum_path = std::path::PathBuf::from(format!(
        "/{}",
        "p".repeat(notecrypt_service::MAX_NATIVE_PATH_BYTES - 1)
    ));
    assert!(ImportFile::try_new(snapshot, parent, "bounded", maximum_path).is_ok());
    let oversized_path = std::path::PathBuf::from(format!(
        "/{}",
        "p".repeat(notecrypt_service::MAX_NATIVE_PATH_BYTES)
    ));
    assert_eq!(
        ImportFile::try_new(snapshot, parent, "bounded", oversized_path).unwrap_err(),
        ServiceError::CapacityExceeded
    );
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

    fn confirm_activated(&self, _lease: &WorkspaceLease) -> Result<(), HostPortError> {
        Ok(())
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
    ) -> Result<notecrypt_service::MaterializationPublication, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn arm_published_path(
        &self,
        _lease: &WorkspaceLease,
        _published: &mut notecrypt_service::PublishedGeneration,
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
        _lease: &WorkspaceLease,
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

struct ObservedRepository {
    inner: StoreVaultRepository,
    revoked: Arc<AtomicBool>,
}

impl notecrypt_service::VaultRepository for ObservedRepository {
    fn current_vault_id(&self) -> Result<Option<notecrypt_core::VaultId>, RepositoryPortError> {
        notecrypt_service::VaultRepository::current_vault_id(&self.inner)
    }

    fn unlock_recovery(
        &self,
        secret: RecoverySecretInput,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<Box<dyn notecrypt_service::UnlockedVaultCapability>, RepositoryPortError> {
        let inner =
            notecrypt_service::VaultRepository::unlock_recovery(&self.inner, secret, cancel)?;
        Ok(Box::new(ObservedCapability {
            inner,
            revoked: Arc::clone(&self.revoked),
        }))
    }

    fn begin_recovery_initialization(
        &self,
        request: notecrypt_service::BeginRecoveryInitialization,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<notecrypt_service::PreparedRecoveryInitialization, RepositoryPortError> {
        notecrypt_service::VaultRepository::begin_recovery_initialization(
            &self.inner,
            request,
            cancel,
        )
    }
}

struct ObservedCapability {
    inner: Box<dyn notecrypt_service::UnlockedVaultCapability>,
    revoked: Arc<AtomicBool>,
}

struct ObservedRevocation {
    inner: Arc<dyn notecrypt_service::VaultRootRevocation>,
    revoked: Arc<AtomicBool>,
}

impl notecrypt_service::VaultRootRevocation for ObservedRevocation {
    fn revoke(&self) {
        self.inner.revoke();
        self.revoked.store(true, Ordering::Release);
    }
}

impl notecrypt_service::UnlockedVaultCapability for ObservedCapability {
    fn revocation_handle(&self) -> Arc<dyn notecrypt_service::VaultRootRevocation> {
        Arc::new(ObservedRevocation {
            inner: self.inner.revocation_handle(),
            revoked: Arc::clone(&self.revoked),
        })
    }

    fn acquire_local_lease(
        &self,
        cancellation: Arc<notecrypt_service::RepositoryCancellation>,
    ) -> Result<Box<dyn notecrypt_service::LocalVaultLease>, RepositoryPortError> {
        self.inner.acquire_local_lease(cancellation)
    }

    fn acquire_replication_lease(
        &self,
        backend: notecrypt_service::ReplicationLimitProfile,
        operation: notecrypt_service::ReplicationLimitProfile,
        cancellation: Arc<notecrypt_service::RepositoryCancellation>,
    ) -> Result<Box<dyn notecrypt_service::ReplicationVaultLease>, RepositoryPortError> {
        self.inner
            .acquire_replication_lease(backend, operation, cancellation)
    }

    fn begin_compromise_rekey(
        &self,
        request: notecrypt_service::BeginCompromiseRekey,
        cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<notecrypt_service::PreparedCompromiseRekey, RepositoryPortError> {
        self.inner.begin_compromise_rekey(request, cancel)
    }

    fn prepare_workspace_registration(
        &self,
    ) -> Result<Box<dyn notecrypt_service::PreparedWorkspaceUnregister>, RepositoryPortError> {
        self.inner.prepare_workspace_registration()
    }

    fn commit_workspace_registration(
        &self,
        registration: &mut dyn notecrypt_service::PreparedWorkspaceUnregister,
    ) -> Result<(), RepositoryPortError> {
        self.inner.commit_workspace_registration(registration)
    }

    fn activate_prepared_workspace_registration(
        &self,
        registration: &mut dyn notecrypt_service::PreparedWorkspaceUnregister,
    ) -> Result<(), RepositoryPortError> {
        self.inner
            .activate_prepared_workspace_registration(registration)
    }

    fn activate_workspace(
        &self,
        registered: &mut dyn notecrypt_service::RegisteredWorkspaceCapability,
    ) -> Result<Box<dyn notecrypt_service::ActiveWorkspaceCapability>, RepositoryPortError> {
        self.inner.activate_workspace(registered)
    }

    fn authenticated_workspaces(
        &self,
    ) -> Result<Vec<notecrypt_service::AuthenticatedWorkspaceCapability>, RepositoryPortError> {
        self.inner.authenticated_workspaces()
    }

    fn unregister_absent_workspace(
        &self,
        active: &mut dyn notecrypt_service::ActiveWorkspaceCapability,
    ) -> Result<(), RepositoryPortError> {
        self.inner.unregister_absent_workspace(active)
    }

    fn close(self: Box<Self>) -> Result<(), RepositoryPortError> {
        self.inner.close()
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

struct LockCompletionObserver {
    completed: Mutex<Option<mpsc::Sender<()>>>,
}

impl OperationExecutor for LockCompletionObserver {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Err(ServiceError::ExecutorFailed)
    }

    fn control(&self, control: notecrypt_service::Control) {
        if control == notecrypt_service::Control::LockNow
            && let Some(completed) = self.completed.lock().unwrap().take()
        {
            completed.send(()).expect("lock observer remains alive");
        }
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

fn secret() -> RecoverySecretInput {
    RecoverySecretInput::from_protected_bytes(SECRET.as_bytes().to_vec()).unwrap()
}

fn service_for_roots(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
) -> ServiceHandle {
    service_for_roots_with_external(
        repository_root,
        local_root,
        Arc::new(PlatformExternalFileProvider::open(repository_root, local_root).unwrap()),
    )
}

fn service_for_roots_with_external(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
    external_files: Arc<dyn ExternalFileProvider>,
) -> ServiceHandle {
    service_for_roots_with_config_external(
        repository_root,
        local_root,
        ServiceConfig::default(),
        external_files,
    )
}

fn service_for_roots_with_config_external(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
    config: ServiceConfig,
    external_files: Arc<dyn ExternalFileProvider>,
) -> ServiceHandle {
    service_for_roots_with_config_external_executor(
        repository_root,
        local_root,
        config,
        external_files,
        Arc::new(RejectingExecutor),
    )
}

fn service_for_roots_with_config_external_executor(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
    config: ServiceConfig,
    external_files: Arc<dyn ExternalFileProvider>,
    executor: Arc<dyn OperationExecutor>,
) -> ServiceHandle {
    let workspace: Arc<dyn WorkspaceProvider> = Arc::new(UnavailableWorkspace);
    let repository = StoreVaultRepository::open(
        LocalVaultConfig::try_new(
            repository_root.to_path_buf(),
            local_root.to_path_buf(),
            RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap(),
            "device".to_owned(),
        )
        .unwrap(),
        Arc::clone(&workspace),
        Arc::new(NoTargets),
    )
    .unwrap();
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
    )
    .with_external_files(external_files);
    ServiceHandle::with_local_use_cases(
        config,
        executor,
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0
}

fn service_for_roots_with_observed_revocation(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
    external_files: Arc<dyn ExternalFileProvider>,
) -> (ServiceHandle, Arc<AtomicBool>) {
    let workspace: Arc<dyn WorkspaceProvider> = Arc::new(UnavailableWorkspace);
    let repository = StoreVaultRepository::open(
        LocalVaultConfig::try_new(
            repository_root.to_path_buf(),
            local_root.to_path_buf(),
            RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap(),
            "device".to_owned(),
        )
        .unwrap(),
        Arc::clone(&workspace),
        Arc::new(NoTargets),
    )
    .unwrap();
    let revoked = Arc::new(AtomicBool::new(false));
    let components = SessionComponents::new(
        Arc::new(ObservedRepository {
            inner: repository,
            revoked: Arc::clone(&revoked),
        }),
        workspace,
        Arc::new(FixedClock),
        SessionPolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(120),
            Vec::new(),
            Duration::from_secs(1),
        )
        .unwrap(),
    )
    .with_external_files(external_files);
    let service = ServiceHandle::with_local_use_cases(
        ServiceConfig::default(),
        Arc::new(RejectingExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0;
    (service, revoked)
}

struct BlockingExportProvider {
    started: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
    aborted: Arc<AtomicBool>,
    published: Arc<AtomicBool>,
}

struct BlockingPublishProvider {
    started: Mutex<Option<mpsc::Sender<()>>>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
    published: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
}

impl ExternalFileProvider for BlockingPublishProvider {
    fn open_import(&self, _selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn begin_export(&self, _selection: ExportSelection) -> Result<OpenedExport, HostPortError> {
        Ok(OpenedExport::new(Box::new(BlockingPublishExport {
            started: self
                .started
                .lock()
                .unwrap()
                .take()
                .ok_or(HostPortError::PlatformFailure)?,
            release: Arc::clone(&self.release),
            published: Arc::clone(&self.published),
            aborted: Arc::clone(&self.aborted),
        })))
    }
}

struct BlockingPublishExport {
    started: mpsc::Sender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
    published: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
}

impl Write for BlockingPublishExport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ExternalExportTransaction for BlockingPublishExport {
    fn flush_private(&mut self) -> Result<(), HostPortError> {
        Ok(())
    }

    fn publish(
        self: Box<Self>,
        authorization: &mut dyn notecrypt_service::ExternalPublicationAuthorization,
    ) -> Result<(), HostPortError> {
        authorization.authorize_and_publish(&mut || {
            self.started
                .send(())
                .map_err(|_| HostPortError::PlatformFailure)?;
            self.release
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| HostPortError::PlatformFailure)?;
            self.published.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn abort(self: Box<Self>) -> Result<(), HostPortError> {
        self.aborted.store(true, Ordering::Release);
        Ok(())
    }
}

impl ExternalFileProvider for BlockingExportProvider {
    fn open_import(&self, _selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn begin_export(&self, _selection: ExportSelection) -> Result<OpenedExport, HostPortError> {
        self.started
            .lock()
            .unwrap()
            .take()
            .ok_or(HostPortError::PlatformFailure)?
            .send(())
            .map_err(|_| HostPortError::PlatformFailure)?;
        self.release
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| HostPortError::PlatformFailure)?;
        Ok(OpenedExport::new(Box::new(RecordingExport {
            aborted: Arc::clone(&self.aborted),
            published: Arc::clone(&self.published),
            publish_error: None,
        })))
    }
}

struct CleanupFailingExportProvider {
    pending_cleanup: Arc<AtomicBool>,
}

impl ExternalFileProvider for CleanupFailingExportProvider {
    fn open_import(&self, _selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn begin_export(&self, _selection: ExportSelection) -> Result<OpenedExport, HostPortError> {
        Ok(OpenedExport::new(Box::new(CleanupFailingExport {
            pending_cleanup: Arc::clone(&self.pending_cleanup),
        })))
    }

    fn retry_cleanup(&self) -> Result<(), HostPortError> {
        self.pending_cleanup.store(false, Ordering::Release);
        Ok(())
    }
}

struct CleanupFailingExport {
    pending_cleanup: Arc<AtomicBool>,
}

impl std::io::Write for CleanupFailingExport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ExternalExportTransaction for CleanupFailingExport {
    fn flush_private(&mut self) -> Result<(), HostPortError> {
        Ok(())
    }

    fn publish(
        self: Box<Self>,
        authorization: &mut dyn notecrypt_service::ExternalPublicationAuthorization,
    ) -> Result<(), HostPortError> {
        authorization.authorize_and_publish(&mut || {
            self.pending_cleanup.store(true, Ordering::Release);
            Err(HostPortError::CleanupFailed)
        })
    }

    fn abort(self: Box<Self>) -> Result<(), HostPortError> {
        self.pending_cleanup.store(false, Ordering::Release);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ExportFault {
    WriteError,
    WritePanic,
    FlushError,
    FlushPanic,
    PublishDurabilityPending,
    PublishPanic,
    AbortPanic,
}

struct FaultingExportProvider {
    faults: Mutex<VecDeque<ExportFault>>,
    aborts: Arc<std::sync::atomic::AtomicUsize>,
}

impl ExternalFileProvider for FaultingExportProvider {
    fn open_import(&self, _selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn begin_export(&self, _selection: ExportSelection) -> Result<OpenedExport, HostPortError> {
        let fault = self
            .faults
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(HostPortError::PlatformFailure)?;
        Ok(OpenedExport::new(Box::new(FaultingExport {
            fault,
            aborts: Arc::clone(&self.aborts),
        })))
    }
}

struct FaultingExport {
    fault: ExportFault,
    aborts: Arc<std::sync::atomic::AtomicUsize>,
}

struct ScriptedImportProvider {
    scripts: Mutex<VecDeque<(ScriptedReader, GuardBehavior)>>,
}

impl ExternalFileProvider for ScriptedImportProvider {
    fn open_import(&self, _selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        let (reader, guard) = self
            .scripts
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(HostPortError::PlatformFailure)?;
        Ok(OpenedImport::new(Box::new(reader), Box::new(guard)))
    }
}

enum ScriptedReader {
    Bytes(std::io::Cursor<Vec<u8>>),
    ShortInterrupted {
        bytes: Vec<u8>,
        offset: usize,
        calls: usize,
    },
    ErrorAfterBytes {
        returned: bool,
    },
    Panic,
}

impl std::io::Read for ScriptedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Bytes(reader) => std::io::Read::read(reader, output),
            Self::ShortInterrupted {
                bytes,
                offset,
                calls,
            } => {
                *calls += 1;
                if *calls % 3 == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
                }
                if *offset == bytes.len() {
                    return Ok(0);
                }
                let length = output.len().min(7).min(bytes.len() - *offset);
                output[..length].copy_from_slice(&bytes[*offset..*offset + length]);
                *offset += length;
                Ok(length)
            }
            Self::ErrorAfterBytes { returned } if !*returned => {
                *returned = true;
                let length = output.len().min(CONTENT.len());
                output[..length].copy_from_slice(&CONTENT[..length]);
                Ok(length)
            }
            Self::ErrorAfterBytes { .. } => Err(std::io::Error::other("injected import failure")),
            Self::Panic => panic!("injected import reader panic"),
        }
    }
}

enum GuardBehavior {
    Allow,
    Stale,
    Panic,
}

impl notecrypt_service::VaultPublicationGuard for GuardBehavior {
    fn validate(&mut self) -> Result<(), RepositoryPortError> {
        match self {
            Self::Allow => Ok(()),
            Self::Stale => Err(RepositoryPortError::StaleCapability),
            Self::Panic => panic!("injected import guard panic"),
        }
    }
}

struct BlockingImportProvider {
    started: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ExternalFileProvider for BlockingImportProvider {
    fn open_import(&self, _selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        self.started
            .lock()
            .unwrap()
            .take()
            .ok_or(HostPortError::PlatformFailure)?
            .send(())
            .map_err(|_| HostPortError::PlatformFailure)?;
        self.release
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| HostPortError::PlatformFailure)?;
        Ok(OpenedImport::new(
            Box::new(std::io::Cursor::new(CONTENT)),
            Box::new(GuardBehavior::Allow),
        ))
    }
}

impl Write for FaultingExport {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self.fault {
            ExportFault::WriteError | ExportFault::AbortPanic => {
                Err(std::io::Error::other("injected export write failure"))
            }
            ExportFault::WritePanic => panic!("injected export writer panic"),
            _ => Ok(buffer.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ExternalExportTransaction for FaultingExport {
    fn flush_private(&mut self) -> Result<(), HostPortError> {
        match self.fault {
            ExportFault::FlushError => Err(HostPortError::PlatformFailure),
            ExportFault::FlushPanic => panic!("injected export flush panic"),
            _ => Ok(()),
        }
    }

    fn publish(
        self: Box<Self>,
        authorization: &mut dyn notecrypt_service::ExternalPublicationAuthorization,
    ) -> Result<(), HostPortError> {
        authorization.authorize_and_publish(&mut || {
            if matches!(self.fault, ExportFault::PublishDurabilityPending) {
                return Err(HostPortError::DurabilityPending);
            }
            if matches!(self.fault, ExportFault::PublishPanic) {
                panic!("injected export publish panic");
            }
            Ok(())
        })
    }

    fn abort(self: Box<Self>) -> Result<(), HostPortError> {
        if matches!(self.fault, ExportFault::AbortPanic) {
            panic!("injected export abort panic");
        }
        self.aborts.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct RecordingExport {
    aborted: Arc<AtomicBool>,
    published: Arc<AtomicBool>,
    publish_error: Option<HostPortError>,
}

impl Write for RecordingExport {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ExternalExportTransaction for RecordingExport {
    fn flush_private(&mut self) -> Result<(), HostPortError> {
        Ok(())
    }

    fn publish(
        self: Box<Self>,
        authorization: &mut dyn notecrypt_service::ExternalPublicationAuthorization,
    ) -> Result<(), HostPortError> {
        authorization.authorize_and_publish(&mut || {
            if let Some(error) = self.publish_error {
                return Err(error);
            }
            self.published.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn abort(self: Box<Self>) -> Result<(), HostPortError> {
        self.aborted.store(true, Ordering::Release);
        Ok(())
    }
}

fn status(service: &ServiceHandle) -> notecrypt_service::VaultStatus {
    let result = service
        .submit(Command::Status(VaultStatusRequest))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let OperationResult::Status(status) = result else {
        panic!("status returned the wrong result")
    };
    status
}

fn run_mutation(service: &ServiceHandle, command: Command) -> notecrypt_service::MutationSummary {
    let operation = service.submit(command).unwrap();
    let mut events = Vec::new();
    while let Some(event) = operation.wait_next_event(Duration::from_secs(5)).unwrap() {
        let terminal = matches!(event, OperationEvent::Completed | OperationEvent::Failed(_));
        events.push(event);
        if terminal {
            break;
        }
    }
    let result = operation.wait_result(Duration::from_secs(5)).unwrap();
    assert_eq!(events.first(), Some(&OperationEvent::Started));
    assert!(events.contains(&OperationEvent::PhaseChanged(OperationPhase::Publishing)));
    let durable = events
        .iter()
        .position(|event| matches!(event, OperationEvent::RevisionDurable(_)))
        .expect("accepted mutation must publish its durable point");
    assert_eq!(events.last(), Some(&OperationEvent::Completed));
    assert!(durable + 1 == events.len() - 1);
    let OperationResult::EntryChanged(summary) = result else {
        panic!("mutation returned the wrong result")
    };
    summary
}

fn run_export(service: &ServiceHandle, command: Command) -> notecrypt_service::ExportSummary {
    let operation = service.submit(command).unwrap();
    let mut events = Vec::new();
    while let Some(event) = operation.wait_next_event(Duration::from_secs(5)).unwrap() {
        let terminal = matches!(event, OperationEvent::Completed | OperationEvent::Failed(_));
        events.push(event);
        if terminal {
            break;
        }
    }
    let result = operation
        .wait_result(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("export failed with {error:?}; events: {events:?}"));
    assert_eq!(events.first(), Some(&OperationEvent::Started));
    assert!(events.contains(&OperationEvent::PhaseChanged(OperationPhase::Reading)));
    assert!(events.contains(&OperationEvent::PhaseChanged(OperationPhase::Publishing)));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, OperationEvent::RevisionDurable(_)))
    );
    assert_eq!(events.last(), Some(&OperationEvent::Completed));
    let OperationResult::Exported(summary) = result else {
        panic!("export returned the wrong result")
    };
    summary
}

fn run_rejection(
    service: &ServiceHandle,
    command: Command,
    expected: ServiceError,
    snapshot: SnapshotVersion,
) {
    let operation = service.submit(command).unwrap();
    let mut events = Vec::new();
    while let Some(event) = operation.wait_next_event(Duration::from_secs(5)).unwrap() {
        let terminal = matches!(event, OperationEvent::Completed | OperationEvent::Failed(_));
        events.push(event);
        if terminal {
            break;
        }
    }
    assert_eq!(operation.wait_result(Duration::from_secs(5)), Err(expected));
    assert_eq!(events.first(), Some(&OperationEvent::Started));
    assert_eq!(events.last(), Some(&OperationEvent::Failed(expected)));
    assert!(!events.iter().any(|event| matches!(
        event,
        OperationEvent::RevisionDurable(_) | OperationEvent::Completed
    )));
    assert_eq!(status(service).snapshot_id(), snapshot.as_bytes());
}

#[test]
fn typed_mutations_advance_once_reject_stale_and_survive_reopen() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    let initialized = VaultStore::initialize(
        &repository_root,
        &local_root,
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "device",
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let vault = initialized.vault_id();
    drop(initialized);

    let external = TempDir::new().unwrap();
    let source = external.path().join("selected-import");
    std::fs::write(&source, CONTENT).unwrap();
    let source = source.canonicalize().unwrap();
    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let initial_snapshot = SnapshotVersion::new(*initial.snapshot_id());
    let root = notecrypt_service::EntryId::new(*initial.root_entry_id());

    let directory = run_mutation(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(initial_snapshot, root, "private-dir-canary").unwrap(),
        ),
    );
    assert_eq!(directory.name(), "private-dir-canary");
    assert_ne!(directory.snapshot(), initial_snapshot);
    run_rejection(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(directory.snapshot(), root, "PRIVATE-DIR-CANARY").unwrap(),
        ),
        ServiceError::StaleCapability,
        directory.snapshot(),
    );
    run_rejection(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                directory.snapshot(),
                notecrypt_service::EntryId::new([0x5a; 16]),
                "missing-parent-canary",
            )
            .unwrap(),
        ),
        ServiceError::StaleCapability,
        directory.snapshot(),
    );
    let normalized = run_mutation(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(directory.snapshot(), root, "Caf\u{e9}").unwrap(),
        ),
    );
    run_rejection(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(normalized.snapshot(), root, "Cafe\u{301}").unwrap(),
        ),
        ServiceError::StaleCapability,
        normalized.snapshot(),
    );
    run_rejection(
        &service,
        Command::DeleteEntry(
            DeleteEntry::try_directory(normalized.snapshot(), root, root, "protected-root")
                .unwrap(),
        ),
        ServiceError::StaleCapability,
        normalized.snapshot(),
    );

    let empty_file = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                normalized.snapshot(),
                directory.entry_id(),
                "empty-note-canary.md",
            )
            .unwrap(),
        ),
    );
    assert!(empty_file.revision().is_some());
    run_rejection(
        &service,
        Command::RenameEntry(
            RenameEntry::try_new(
                empty_file.snapshot(),
                directory.entry_id(),
                root,
                "private-dir-canary",
                notecrypt_service::EntryKind::File,
                Some(notecrypt_service::RevisionVersion::new([0x3c; 32])),
                "wrong-kind-canary",
            )
            .unwrap(),
        ),
        ServiceError::StaleCapability,
        empty_file.snapshot(),
    );
    run_rejection(
        &service,
        Command::MoveEntry(
            MoveEntry::try_new(
                empty_file.snapshot(),
                directory.entry_id(),
                root,
                "private-dir-canary",
                notecrypt_service::EntryKind::Directory,
                None,
                empty_file.parent_id(),
            )
            .unwrap(),
        ),
        ServiceError::StaleCapability,
        empty_file.snapshot(),
    );
    run_rejection(
        &service,
        Command::DeleteEntry(
            DeleteEntry::try_directory(
                empty_file.snapshot(),
                directory.entry_id(),
                root,
                "private-dir-canary",
            )
            .unwrap(),
        ),
        ServiceError::StaleCapability,
        empty_file.snapshot(),
    );

    let imported = run_mutation(
        &service,
        Command::ImportFile(
            ImportFile::try_new(
                empty_file.snapshot(),
                root,
                "import-note-canary.txt",
                source,
            )
            .unwrap(),
        ),
    );

    let stale = service
        .submit(Command::CreateDirectory(
            CreateDirectory::try_new(initial_snapshot, root, "stale-canary").unwrap(),
        ))
        .unwrap();
    assert_eq!(
        stale.wait_result(Duration::from_secs(5)),
        Err(ServiceError::StaleCapability)
    );
    assert_eq!(
        status(&service).snapshot_id(),
        imported.snapshot().as_bytes()
    );

    local_test_support::fail_authenticated_read_at(
        vault,
        local_test_support::AuthenticatedReadFault::ViewAllocation,
    );
    let renamed = run_mutation(
        &service,
        Command::RenameEntry(
            RenameEntry::try_new(
                imported.snapshot(),
                imported.entry_id(),
                root,
                "import-note-canary.txt",
                notecrypt_service::EntryKind::File,
                imported.revision(),
                "renamed-note-canary.txt",
            )
            .unwrap(),
        ),
    );
    assert_eq!(
        service
            .submit(Command::List(notecrypt_service::ListEntries))
            .unwrap()
            .wait_result(Duration::from_secs(5)),
        Err(ServiceError::AllocationFailed),
        "targeted rename binding must not materialize the presentation-capped view"
    );
    let moved = run_mutation(
        &service,
        Command::MoveEntry(
            MoveEntry::try_new(
                renamed.snapshot(),
                renamed.entry_id(),
                root,
                "renamed-note-canary.txt",
                notecrypt_service::EntryKind::File,
                renamed.revision(),
                directory.entry_id(),
            )
            .unwrap(),
        ),
    );
    let export_path = external
        .path()
        .canonicalize()
        .unwrap()
        .join("exported-note-canary.bin");
    let before_export = status(&service);
    local_test_support::fail_authenticated_read_at(
        vault,
        local_test_support::AuthenticatedReadFault::ViewAllocation,
    );
    let exported = run_export(
        &service,
        Command::ExportFile(
            ExportFile::try_new(
                moved.snapshot(),
                moved.entry_id(),
                moved.revision().unwrap(),
                export_path.clone(),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ),
    );
    assert_eq!(exported.opaque_id(), moved.entry_id().as_bytes());
    assert_eq!(std::fs::read(&export_path).unwrap(), CONTENT);
    assert_eq!(status(&service).snapshot_id(), before_export.snapshot_id());
    assert_eq!(
        service
            .submit(Command::List(notecrypt_service::ListEntries))
            .unwrap()
            .wait_result(Duration::from_secs(5)),
        Err(ServiceError::AllocationFailed),
        "targeted export binding must not materialize the presentation-capped view"
    );

    let refused = service
        .submit(Command::ExportFile(
            ExportFile::try_new(
                moved.snapshot(),
                moved.entry_id(),
                moved.revision().unwrap(),
                export_path.clone(),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        refused.wait_result(Duration::from_secs(5)),
        Err(ServiceError::DestinationExists)
    );
    assert_eq!(std::fs::read(&export_path).unwrap(), CONTENT);

    std::fs::write(&export_path, b"replace this exact destination").unwrap();
    run_export(
        &service,
        Command::ExportFile(
            ExportFile::try_new(
                moved.snapshot(),
                moved.entry_id(),
                moved.revision().unwrap(),
                export_path.clone(),
                ExportOverwriteConfirmation::Confirmed,
            )
            .unwrap(),
        ),
    );
    assert_eq!(std::fs::read(&export_path).unwrap(), CONTENT);

    let protected = service
        .submit(Command::ExportFile(
            ExportFile::try_new(
                moved.snapshot(),
                moved.entry_id(),
                moved.revision().unwrap(),
                repository_root.join("must-not-export"),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        protected.wait_result(Duration::from_secs(5)),
        Err(ServiceError::InvalidInput)
    );
    assert!(!repository_root.join("must-not-export").exists());

    let deleted = run_mutation(
        &service,
        Command::DeleteEntry(
            DeleteEntry::try_file(
                moved.snapshot(),
                moved.entry_id(),
                directory.entry_id(),
                "renamed-note-canary.txt",
                moved.revision().unwrap(),
            )
            .unwrap(),
        ),
    );
    assert_eq!(deleted.kind(), notecrypt_service::EntryKind::Tombstone);
    run_rejection(
        &service,
        Command::DeleteEntry(
            DeleteEntry::try_file(
                deleted.snapshot(),
                moved.entry_id(),
                directory.entry_id(),
                "renamed-note-canary.txt",
                moved.revision().unwrap(),
            )
            .unwrap(),
        ),
        ServiceError::StaleCapability,
        deleted.snapshot(),
    );
    let deleted_directory = run_mutation(
        &service,
        Command::DeleteEntry(
            DeleteEntry::try_directory(
                deleted.snapshot(),
                normalized.entry_id(),
                root,
                "Caf\u{e9}",
            )
            .unwrap(),
        ),
    );
    assert_eq!(
        deleted_directory.kind(),
        notecrypt_service::EntryKind::Tombstone
    );

    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);
    let reopened = service_for_roots(&repository_root, &local_root);
    reopened.unlock_with_recovery(secret()).unwrap();
    assert_eq!(
        status(&reopened).snapshot_id(),
        deleted_directory.snapshot().as_bytes()
    );
    let listed = reopened
        .submit(Command::List(notecrypt_service::ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let OperationResult::Entries(entries) = listed else {
        panic!("list returned the wrong result")
    };
    assert!(entries.iter().any(|entry| {
        entry.opaque_id() == deleted.entry_id().as_bytes()
            && entry.kind() == notecrypt_service::EntryKind::Tombstone
    }));
    assert!(entries.iter().any(|entry| {
        entry.opaque_id() == deleted_directory.entry_id().as_bytes()
            && entry.kind() == notecrypt_service::EntryKind::Tombstone
    }));

    let repository_scan = walk_bytes(&repository_root);
    for canary in [
        CONTENT,
        b"private-dir-canary",
        b"empty-note-canary.md",
        b"import-note-canary.txt",
        b"renamed-note-canary.txt",
    ] {
        assert!(
            !repository_scan
                .windows(canary.len())
                .any(|bytes| bytes == canary)
        );
    }
}

#[test]
fn cancellation_while_external_export_opens_aborts_the_private_transaction() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );

    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let file = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                SnapshotVersion::new(*initial.snapshot_id()),
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "cancelled-export-source",
            )
            .unwrap(),
        ),
    );
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);

    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let aborted = Arc::new(AtomicBool::new(false));
    let published = Arc::new(AtomicBool::new(false));
    let provider = Arc::new(BlockingExportProvider {
        started: Mutex::new(Some(started_sender)),
        release: Mutex::new(release_receiver),
        aborted: Arc::clone(&aborted),
        published: Arc::clone(&published),
    });
    let reopened = service_for_roots_with_external(&repository_root, &local_root, provider);
    reopened.unlock_with_recovery(secret()).unwrap();
    let destination = TempDir::new()
        .unwrap()
        .path()
        .canonicalize()
        .unwrap()
        .join("cancelled-export");
    let operation = reopened
        .submit(Command::ExportFile(
            ExportFile::try_new(
                file.snapshot(),
                file.entry_id(),
                file.revision().unwrap(),
                destination,
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();

    started_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    operation.cancel();
    release_sender.send(()).unwrap();
    assert_eq!(
        operation.wait_result(Duration::from_secs(5)),
        Err(ServiceError::Cancelled)
    );
    assert!(aborted.load(Ordering::Acquire));
    assert!(!published.load(Ordering::Acquire));
    assert_eq!(status(&reopened).snapshot_id(), file.snapshot().as_bytes());
}

#[test]
fn priority_lock_stays_responsive_and_cannot_lock_ahead_of_export_publication() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let file = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                SnapshotVersion::new(*initial.snapshot_id()),
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "publication-lock-source",
            )
            .unwrap(),
        ),
    );
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);

    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let published = Arc::new(AtomicBool::new(false));
    let aborted = Arc::new(AtomicBool::new(false));
    let (reopened, revoked) = service_for_roots_with_observed_revocation(
        &repository_root,
        &local_root,
        Arc::new(BlockingPublishProvider {
            started: Mutex::new(Some(started_sender)),
            release: Arc::new(Mutex::new(release_receiver)),
            published: Arc::clone(&published),
            aborted: Arc::clone(&aborted),
        }),
    );
    reopened.unlock_with_recovery(secret()).unwrap();
    let external = TempDir::new().unwrap();
    let export = reopened
        .submit(Command::ExportFile(
            ExportFile::try_new(
                file.snapshot(),
                file.entry_id(),
                file.revision().unwrap(),
                external.path().canonicalize().unwrap().join("published"),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();
    started_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let lock_entry = Arc::new(std::sync::Barrier::new(2));
    let lock_thread_entry = Arc::clone(&lock_entry);
    let lock_service = reopened.clone();
    let (locked_sender, locked_receiver) = mpsc::channel();
    let lock_thread = std::thread::spawn(move || {
        lock_thread_entry.wait();
        locked_sender
            .send(lock_service.control(notecrypt_service::Control::LockNow))
            .unwrap();
    });
    lock_entry.wait();

    assert_eq!(
        locked_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap(),
        Ok(())
    );
    lock_thread.join().unwrap();
    assert_eq!(
        reopened.snapshot().session_state(),
        notecrypt_service::SessionState::Locking
    );
    let revocation_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !revoked.load(Ordering::Acquire) {
        assert!(std::time::Instant::now() < revocation_deadline);
        std::thread::yield_now();
    }
    assert!(matches!(
        reopened.submit(Command::Status(VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));
    assert!(!published.load(Ordering::Acquire));
    release_sender.send(()).unwrap();
    assert!(matches!(
        export.wait_result(Duration::from_secs(5)),
        Ok(OperationResult::Exported(_))
    ));
    assert!(published.load(Ordering::Acquire));
    assert!(!aborted.load(Ordering::Acquire));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while reopened.snapshot().session_state() != notecrypt_service::SessionState::Locked {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(
        reopened.snapshot().session_state(),
        notecrypt_service::SessionState::Locked
    );
}

#[test]
fn cancellation_after_publication_authorization_keeps_visible_success() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let file = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                SnapshotVersion::new(*initial.snapshot_id()),
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "publication-cancel-source",
            )
            .unwrap(),
        ),
    );
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);

    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let published = Arc::new(AtomicBool::new(false));
    let aborted = Arc::new(AtomicBool::new(false));
    let reopened = service_for_roots_with_external(
        &repository_root,
        &local_root,
        Arc::new(BlockingPublishProvider {
            started: Mutex::new(Some(started_sender)),
            release: Arc::new(Mutex::new(release_receiver)),
            published: Arc::clone(&published),
            aborted: Arc::clone(&aborted),
        }),
    );
    reopened.unlock_with_recovery(secret()).unwrap();
    let external = TempDir::new().unwrap();
    let operation = reopened
        .submit(Command::ExportFile(
            ExportFile::try_new(
                file.snapshot(),
                file.entry_id(),
                file.revision().unwrap(),
                external.path().canonicalize().unwrap().join("published"),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();
    started_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();

    operation.cancel();
    assert!(!published.load(Ordering::Acquire));
    release_sender.send(()).unwrap();
    assert!(matches!(
        operation.wait_result(Duration::from_secs(5)),
        Ok(OperationResult::Exported(_))
    ));
    assert!(published.load(Ordering::Acquire));
    assert!(!aborted.load(Ordering::Acquire));
}

#[test]
fn export_publish_cleanup_failure_latches_cleanup_required() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );

    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let file = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                SnapshotVersion::new(*initial.snapshot_id()),
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "cleanup-failure-source",
            )
            .unwrap(),
        ),
    );
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);

    let pending_cleanup = Arc::new(AtomicBool::new(false));
    let reopened = service_for_roots_with_external(
        &repository_root,
        &local_root,
        Arc::new(CleanupFailingExportProvider {
            pending_cleanup: Arc::clone(&pending_cleanup),
        }),
    );
    reopened.unlock_with_recovery(secret()).unwrap();
    let destination_root = TempDir::new().unwrap();
    let operation = reopened
        .submit(Command::ExportFile(
            ExportFile::try_new(
                file.snapshot(),
                file.entry_id(),
                file.revision().unwrap(),
                destination_root
                    .path()
                    .canonicalize()
                    .unwrap()
                    .join("cleanup-failure-export"),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();

    assert_eq!(
        operation.wait_result(Duration::from_secs(5)),
        Err(ServiceError::CleanupRequired)
    );
    assert_eq!(
        reopened.snapshot().session_state(),
        notecrypt_service::SessionState::CleanupRequired
    );
    assert!(pending_cleanup.load(Ordering::Acquire));
    let mut cleanup_result = Err(ServiceError::Busy);
    for _ in 0..1_000 {
        cleanup_result = reopened.retry_cleanup();
        if cleanup_result != Err(ServiceError::Busy) {
            break;
        }
        std::thread::yield_now();
    }
    cleanup_result.unwrap();
    assert!(!pending_cleanup.load(Ordering::Acquire));
    assert_eq!(
        reopened.snapshot().session_state(),
        notecrypt_service::SessionState::Locked
    );
}

#[test]
fn export_host_faults_and_panics_are_contained_with_exact_cleanup_semantics() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let external = TempDir::new().unwrap();
    let external_root = external.path().canonicalize().unwrap();
    let source = external_root.join("fault-source");
    std::fs::write(&source, CONTENT).unwrap();

    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let file = run_mutation(
        &service,
        Command::ImportFile(
            ImportFile::try_new(
                SnapshotVersion::new(*initial.snapshot_id()),
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "fault-source",
                source.canonicalize().unwrap(),
            )
            .unwrap(),
        ),
    );
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);

    let aborts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let faults = VecDeque::from([
        ExportFault::WriteError,
        ExportFault::WritePanic,
        ExportFault::FlushError,
        ExportFault::FlushPanic,
    ]);
    let faulting = service_for_roots_with_external(
        &repository_root,
        &local_root,
        Arc::new(FaultingExportProvider {
            faults: Mutex::new(faults),
            aborts: Arc::clone(&aborts),
        }),
    );
    faulting.unlock_with_recovery(secret()).unwrap();
    for index in 0..4 {
        run_rejection(
            &faulting,
            Command::ExportFile(
                ExportFile::try_new(
                    file.snapshot(),
                    file.entry_id(),
                    file.revision().unwrap(),
                    external_root.join(format!("fault-export-{index}")),
                    ExportOverwriteConfirmation::Refuse,
                )
                .unwrap(),
            ),
            ServiceError::ExecutorFailed,
            file.snapshot(),
        );
        assert_eq!(aborts.load(Ordering::Acquire), index + 1);
    }
    faulting
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(faulting);

    let durability_pending = service_for_roots_with_external(
        &repository_root,
        &local_root,
        Arc::new(FaultingExportProvider {
            faults: Mutex::new(VecDeque::from([ExportFault::PublishDurabilityPending])),
            aborts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }),
    );
    durability_pending.unlock_with_recovery(secret()).unwrap();
    run_rejection(
        &durability_pending,
        Command::ExportFile(
            ExportFile::try_new(
                file.snapshot(),
                file.entry_id(),
                file.revision().unwrap(),
                external_root.join("publication-durability-pending"),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ),
        ServiceError::DurabilityPending,
        file.snapshot(),
    );
    durability_pending
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(durability_pending);

    for (fault, destination) in [
        (ExportFault::PublishPanic, "publish-panic"),
        (ExportFault::AbortPanic, "abort-panic"),
    ] {
        let service = service_for_roots_with_external(
            &repository_root,
            &local_root,
            Arc::new(FaultingExportProvider {
                faults: Mutex::new(VecDeque::from([fault])),
                aborts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
        );
        service.unlock_with_recovery(secret()).unwrap();
        let operation = service
            .submit(Command::ExportFile(
                ExportFile::try_new(
                    file.snapshot(),
                    file.entry_id(),
                    file.revision().unwrap(),
                    external_root.join(destination),
                    ExportOverwriteConfirmation::Refuse,
                )
                .unwrap(),
            ))
            .unwrap();
        assert_eq!(
            operation.wait_result(Duration::from_secs(5)),
            Err(ServiceError::CleanupRequired)
        );
        assert_eq!(
            service.snapshot().session_state(),
            notecrypt_service::SessionState::CleanupRequired
        );
    }
}

#[test]
fn saturated_mutation_queue_cannot_delay_priority_lock_behind_blocked_export() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let root = notecrypt_service::EntryId::new(*initial.root_entry_id());
    let file = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(
                SnapshotVersion::new(*initial.snapshot_id()),
                root,
                "queue-source",
            )
            .unwrap(),
        ),
    );
    service
        .control(notecrypt_service::Control::LockNow)
        .unwrap();
    drop(service);

    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let aborted = Arc::new(AtomicBool::new(false));
    let provider = Arc::new(BlockingExportProvider {
        started: Mutex::new(Some(started_sender)),
        release: Mutex::new(release_receiver),
        aborted: Arc::clone(&aborted),
        published: Arc::new(AtomicBool::new(false)),
    });
    let config = ServiceConfig::new(1, 1, 16, 16, 8, 8).unwrap();
    let (completed_sender, completed_receiver) = mpsc::channel();
    let reopened = service_for_roots_with_config_external_executor(
        &repository_root,
        &local_root,
        config,
        provider,
        Arc::new(LockCompletionObserver {
            completed: Mutex::new(Some(completed_sender)),
        }),
    );
    reopened.unlock_with_recovery(secret()).unwrap();
    let destination_root = TempDir::new().unwrap();
    let export = reopened
        .submit(Command::ExportFile(
            ExportFile::try_new(
                file.snapshot(),
                file.entry_id(),
                file.revision().unwrap(),
                destination_root
                    .path()
                    .canonicalize()
                    .unwrap()
                    .join("blocked-export"),
                ExportOverwriteConfirmation::Refuse,
            )
            .unwrap(),
        ))
        .unwrap();
    started_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let mut queued = Vec::new();
    for index in 0..16 {
        match reopened.submit(Command::CreateDirectory(
            CreateDirectory::try_new(file.snapshot(), root, &format!("queued-mutation-{index}"))
                .unwrap(),
        )) {
            Ok(operation) => queued.push(operation),
            Err(ServiceError::Busy) => break,
            Err(error) => panic!("unexpected saturation error: {error:?}"),
        }
    }
    assert!(!queued.is_empty());
    assert!(
        queued.len() < 16,
        "mutation submission must reach saturation"
    );

    let priority = reopened.clone();
    let (locked_sender, locked_receiver) = mpsc::channel();
    let lock_thread = std::thread::spawn(move || {
        locked_sender
            .send(priority.control(notecrypt_service::Control::LockNow))
            .unwrap();
    });
    let lock_result = locked_receiver.recv_timeout(Duration::from_secs(3));
    assert_eq!(lock_result.unwrap(), Ok(()));
    let transition = reopened.snapshot();
    assert!(
        matches!(
            transition.session_state(),
            notecrypt_service::SessionState::Locking | notecrypt_service::SessionState::Locked
        ),
        "priority lock must synchronously begin or complete the lock transition"
    );
    assert!(!transition.accepting_operations());
    assert!(!transition.key_leases_open());
    release_sender.send(()).unwrap();
    lock_thread.join().unwrap();
    assert_eq!(
        export.wait_result(Duration::from_secs(5)),
        Err(ServiceError::Cancelled)
    );
    for operation in queued {
        assert_eq!(
            operation.wait_result(Duration::from_secs(5)),
            Err(ServiceError::Cancelled)
        );
    }
    assert!(aborted.load(Ordering::Acquire));
    completed_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("lock observer runs after cleanup completion");
    assert_eq!(
        reopened.snapshot().session_state(),
        notecrypt_service::SessionState::Locked
    );
}

#[test]
fn import_stream_boundaries_errors_and_panics_preserve_exact_head_semantics() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let short_bytes = vec![0x5a; 64 * 1024 + 17];
    let scripts = VecDeque::from([
        (
            ScriptedReader::Bytes(std::io::Cursor::new(Vec::new())),
            GuardBehavior::Allow,
        ),
        (
            ScriptedReader::Bytes(std::io::Cursor::new(vec![0x01])),
            GuardBehavior::Allow,
        ),
        (
            ScriptedReader::ShortInterrupted {
                bytes: short_bytes,
                offset: 0,
                calls: 0,
            },
            GuardBehavior::Allow,
        ),
        (
            ScriptedReader::ErrorAfterBytes { returned: false },
            GuardBehavior::Allow,
        ),
        (ScriptedReader::Panic, GuardBehavior::Allow),
        (
            ScriptedReader::Bytes(std::io::Cursor::new(CONTENT.to_vec())),
            GuardBehavior::Stale,
        ),
        (
            ScriptedReader::Bytes(std::io::Cursor::new(CONTENT.to_vec())),
            GuardBehavior::Panic,
        ),
    ]);
    let service = service_for_roots_with_external(
        &repository_root,
        &local_root,
        Arc::new(ScriptedImportProvider {
            scripts: Mutex::new(scripts),
        }),
    );
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let root = notecrypt_service::EntryId::new(*initial.root_entry_id());
    let selection_root = TempDir::new().unwrap();
    let selection_root = selection_root.path().canonicalize().unwrap();
    let mut snapshot = SnapshotVersion::new(*initial.snapshot_id());

    for (index, name) in [
        "empty-import",
        "one-byte-import",
        "short-interrupted-import",
    ]
    .into_iter()
    .enumerate()
    {
        let committed = run_mutation(
            &service,
            Command::ImportFile(
                ImportFile::try_new(
                    snapshot,
                    root,
                    name,
                    selection_root.join(format!("selected-{index}")),
                )
                .unwrap(),
            ),
        );
        snapshot = committed.snapshot();
    }

    for (index, expected) in [
        ServiceError::ExecutorFailed,
        ServiceError::WorkerPanicked,
        ServiceError::StaleCapability,
        ServiceError::ExecutorFailed,
    ]
    .into_iter()
    .enumerate()
    {
        run_rejection(
            &service,
            Command::ImportFile(
                ImportFile::try_new(
                    snapshot,
                    root,
                    &format!("rejected-import-{index}"),
                    selection_root.join(format!("rejected-selection-{index}")),
                )
                .unwrap(),
            ),
            expected,
            snapshot,
        );
    }
}

#[test]
fn cancellation_while_waiting_for_external_import_opens_no_revision() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let service = service_for_roots_with_external(
        &repository_root,
        &local_root,
        Arc::new(BlockingImportProvider {
            started: Mutex::new(Some(started_sender)),
            release: Mutex::new(release_receiver),
        }),
    );
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let snapshot = SnapshotVersion::new(*initial.snapshot_id());
    let selection = TempDir::new()
        .unwrap()
        .path()
        .canonicalize()
        .unwrap()
        .join("blocked-import");
    let operation = service
        .submit(Command::ImportFile(
            ImportFile::try_new(
                snapshot,
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "blocked-import",
                selection,
            )
            .unwrap(),
        ))
        .unwrap();
    started_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    operation.cancel();
    release_sender.send(()).unwrap();

    assert_eq!(
        operation.wait_result(Duration::from_secs(5)),
        Err(ServiceError::Cancelled)
    );
    assert_eq!(status(&service).snapshot_id(), snapshot.as_bytes());
}

#[test]
fn cancellation_after_revision_durable_keeps_the_committed_result() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    drop(
        VaultStore::initialize(
            &repository_root,
            &local_root,
            RecoveryPassphrase::new(SECRET.to_owned()),
            parameters(),
            "device",
            &AtomicBool::new(false),
        )
        .unwrap(),
    );
    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let before = SnapshotVersion::new(*initial.snapshot_id());
    let operation = service
        .submit(Command::CreateDirectory(
            CreateDirectory::try_new(
                before,
                notecrypt_service::EntryId::new(*initial.root_entry_id()),
                "durable-cancel-race",
            )
            .unwrap(),
        ))
        .unwrap();
    let mut saw_durable = false;
    while let Some(event) = operation.wait_next_event(Duration::from_secs(5)).unwrap() {
        if matches!(event, OperationEvent::RevisionDurable(_)) {
            saw_durable = true;
            operation.cancel();
        }
        if matches!(event, OperationEvent::Completed | OperationEvent::Failed(_)) {
            assert_eq!(event, OperationEvent::Completed);
            break;
        }
    }
    assert!(saw_durable);
    let result = operation.wait_result(Duration::from_secs(5)).unwrap();
    let OperationResult::EntryChanged(summary) = result else {
        panic!("durable cancellation race returned the wrong result")
    };
    assert_ne!(summary.snapshot(), before);
    assert_eq!(
        status(&service).snapshot_id(),
        summary.snapshot().as_bytes()
    );
}

fn walk_bytes(root: &std::path::Path) -> Vec<u8> {
    let mut output = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            output.extend(entry.file_name().to_string_lossy().as_bytes());
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                output.extend(std::fs::read(entry.path()).unwrap());
            }
        }
    }
    output
}
