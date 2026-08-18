use std::sync::{Arc, mpsc};
use std::time::Duration;

use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_service::{
    Command, CompromiseTargetResolver, Control, HostPortError, ListEntries, LocalVaultConfig,
    LogicalWorkspacePath, MonotonicClock, OperationContext, OperationExecutor, OperationResult,
    RecoveryKdfProfileV1, RecoverySecretInput, RepositoryPortError, ServiceConfig, ServiceError,
    ServiceHandle, SessionComponents, SessionPolicy, SessionState, StartupCleanupReport,
    StoreVaultRepository, TargetWorkspaceRequest, VaultStatusRequest, VaultWorkspaceRequest,
    WorkspaceLease, WorkspaceProvider,
};
use notecrypt_store::{
    PublicationGuard, RepositoryMutation, StoreError, VaultStore, local_test_support,
};
use tempfile::TempDir;

const SECRET: &str = "alpha beta gamma delta epsilon";

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

struct AllowPublication;

impl PublicationGuard for AllowPublication {
    fn validate(&mut self) -> Result<(), notecrypt_store::StoreError> {
        Ok(())
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

fn secret(value: &str) -> RecoverySecretInput {
    RecoverySecretInput::from_protected_bytes(value.as_bytes().to_vec()).unwrap()
}

fn local_config(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
) -> LocalVaultConfig {
    LocalVaultConfig::try_new(
        repository_root.to_path_buf(),
        local_root.to_path_buf(),
        RecoveryKdfProfileV1::try_new(65_536, 3, 1).unwrap(),
        "device".to_owned(),
    )
    .unwrap()
}

fn service_for_roots(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
) -> ServiceHandle {
    try_service_for_roots(repository_root, local_root).unwrap()
}

fn try_service_for_roots(
    repository_root: &std::path::Path,
    local_root: &std::path::Path,
) -> Result<ServiceHandle, RepositoryPortError> {
    let workspace: Arc<dyn WorkspaceProvider> = Arc::new(UnavailableWorkspace);
    let repository = StoreVaultRepository::open(
        local_config(repository_root, local_root),
        Arc::clone(&workspace),
        Arc::new(NoTargets),
    )?;
    let components = SessionComponents::new(
        Arc::new(repository),
        workspace,
        Arc::new(FixedClock),
        policy(),
    );
    Ok(ServiceHandle::with_local_use_cases(
        ServiceConfig::default(),
        Arc::new(RejectingExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0)
}

fn mutate_file(path: &std::path::Path) {
    let mut bytes = std::fs::read(path).unwrap();
    assert!(!bytes.is_empty());
    bytes[0] ^= 0x80;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn production_status_and_list_are_authenticated_and_revoked_by_priority_lock() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    let store = VaultStore::initialize(
        &repository_root,
        &local_root,
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "device",
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let expected_vault = store.vault_id();
    drop(store);
    let service = service_for_roots(&repository_root, &local_root);

    assert!(matches!(
        service.submit(Command::Status(VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::List(ListEntries)),
        Err(ServiceError::Locked)
    ));
    let unlocked = service.unlock_with_recovery(secret(SECRET)).unwrap();
    let status_operation = service.submit(Command::Status(VaultStatusRequest)).unwrap();
    assert_eq!(
        status_operation
            .wait_next_event(Duration::from_secs(5))
            .unwrap(),
        Some(notecrypt_service::OperationEvent::Started)
    );
    assert_eq!(
        status_operation
            .wait_next_event(Duration::from_secs(5))
            .unwrap(),
        Some(notecrypt_service::OperationEvent::PhaseChanged(
            notecrypt_service::OperationPhase::Reading,
        ))
    );
    let status = status_operation
        .wait_result(Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        status_operation
            .wait_next_event(Duration::from_secs(5))
            .unwrap(),
        Some(notecrypt_service::OperationEvent::Completed)
    );
    let OperationResult::Status(status) = status else {
        panic!("status command returned the wrong bounded result");
    };
    assert_eq!(status.vault_id(), expected_vault);
    assert_eq!(status.generation(), unlocked.generation());
    assert_eq!(status.entry_count(), 0);
    assert_ne!(status.root_entry_id(), &[0; 16]);
    assert_ne!(status.snapshot_id(), &[0; 32]);

    let listed = service
        .submit(Command::List(ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        listed,
        OperationResult::Entries(notecrypt_service::EntrySummaries::empty())
    );

    service.control(Control::LockNow).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while service.snapshot().session_state() != SessionState::Locked {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(matches!(
        service.submit(Command::List(ListEntries)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::Status(VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));

    let reopened_service = service_for_roots(&repository_root, &local_root);
    assert_eq!(
        reopened_service.unlock_with_recovery(secret("wrong passphrase")),
        Err(ServiceError::AuthenticationFailed)
    );
    reopened_service
        .unlock_with_recovery(secret(SECRET))
        .unwrap();
    let status = reopened_service
        .submit(Command::Status(VaultStatusRequest))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let OperationResult::Status(status) = status else {
        panic!("status command returned the wrong bounded result after reopen");
    };
    assert_eq!(status.vault_id(), expected_vault);
    let listed = reopened_service
        .submit(Command::List(ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        listed,
        OperationResult::Entries(notecrypt_service::EntrySummaries::empty())
    );
}

#[test]
fn production_unlock_is_exclusive_cancelable_and_does_not_expose_reads() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    let store = VaultStore::initialize(
        &repository_root,
        &local_root,
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "device",
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let vault = store.vault_id();
    drop(store);
    let service = service_for_roots(&repository_root, &local_root);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    local_test_support::install_after_recovery_keys_hook(vault, move || {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });

    let unlocking_service = service.clone();
    let unlock = std::thread::spawn(move || unlocking_service.unlock_with_recovery(secret(SECRET)));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocking);
    assert_eq!(
        service.unlock_with_recovery(secret(SECRET)),
        Err(ServiceError::Busy)
    );
    assert!(matches!(
        service.submit(Command::Status(VaultStatusRequest)),
        Err(ServiceError::Locked)
    ));
    assert!(matches!(
        service.submit(Command::List(ListEntries)),
        Err(ServiceError::Locked)
    ));

    let started = std::time::Instant::now();
    service.control(Control::LockNow).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    release_tx.send(()).unwrap();
    assert_eq!(unlock.join().unwrap(), Err(ServiceError::Cancelled));
    assert_eq!(service.snapshot().session_state(), SessionState::Locked);
    assert!(!service.snapshot().accepting_operations());
    assert!(!service.snapshot().key_leases_open());

    service.unlock_with_recovery(secret(SECRET)).unwrap();
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);
}

#[test]
fn production_authenticated_read_bounds_and_allocation_failures_are_typed() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    let store = VaultStore::initialize(
        &repository_root,
        &local_root,
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "device",
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let vault = store.vault_id();
    let unlocked = store
        .unlock_recovery(
            RecoveryPassphrase::new(SECRET.to_owned()),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    assert_eq!(
        lease
            .authenticated_view(0, &std::sync::atomic::AtomicBool::new(false))
            .unwrap()
            .into_entries()
            .len(),
        0
    );
    let snapshot = lease.current_snapshot_id().unwrap();
    let root = lease.root_entry_id().unwrap();
    lease
        .apply(
            RepositoryMutation::create_directory(snapshot, root, "bounded"),
            &mut AllowPublication,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    assert!(matches!(
        lease.authenticated_view(0, &std::sync::atomic::AtomicBool::new(false)),
        Err(StoreError::LimitExceeded)
    ));
    assert_eq!(
        lease
            .authenticated_view(1, &std::sync::atomic::AtomicBool::new(false))
            .unwrap()
            .into_entries()
            .len(),
        1
    );
    drop(lease);
    drop(unlocked);
    drop(store);

    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret(SECRET)).unwrap();

    local_test_support::fail_authenticated_read_at(
        vault,
        local_test_support::AuthenticatedReadFault::StatusAllocation,
    );
    let status = service.submit(Command::Status(VaultStatusRequest)).unwrap();
    assert_eq!(
        status.wait_next_event(Duration::from_secs(5)).unwrap(),
        Some(notecrypt_service::OperationEvent::Started)
    );
    assert_eq!(
        status.wait_next_event(Duration::from_secs(5)).unwrap(),
        Some(notecrypt_service::OperationEvent::PhaseChanged(
            notecrypt_service::OperationPhase::Reading,
        ))
    );
    assert_eq!(
        status.wait_result(Duration::from_secs(5)),
        Err(ServiceError::AllocationFailed)
    );
    assert_eq!(
        status.wait_next_event(Duration::from_secs(5)).unwrap(),
        Some(notecrypt_service::OperationEvent::Failed(
            ServiceError::AllocationFailed,
        ))
    );

    local_test_support::fail_authenticated_read_at(
        vault,
        local_test_support::AuthenticatedReadFault::ViewAllocation,
    );
    let list = service.submit(Command::List(ListEntries)).unwrap();
    assert_eq!(
        list.wait_next_event(Duration::from_secs(5)).unwrap(),
        Some(notecrypt_service::OperationEvent::Started)
    );
    assert_eq!(
        list.wait_next_event(Duration::from_secs(5)).unwrap(),
        Some(notecrypt_service::OperationEvent::PhaseChanged(
            notecrypt_service::OperationPhase::Reading,
        ))
    );
    assert_eq!(
        list.wait_result(Duration::from_secs(5)),
        Err(ServiceError::AllocationFailed)
    );
    assert_eq!(
        list.wait_next_event(Duration::from_secs(5)).unwrap(),
        Some(notecrypt_service::OperationEvent::Failed(
            ServiceError::AllocationFailed,
        ))
    );
    assert_eq!(service.snapshot().session_state(), SessionState::Unlocked);
    assert!(service.snapshot().accepting_operations());
    assert!(service.snapshot().key_leases_open());
}

#[test]
fn configuration_paths_are_not_present_in_status_or_list_formatting() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    let store = VaultStore::initialize(
        &repository_root,
        &local_root,
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "device",
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    drop(store);
    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret(SECRET)).unwrap();

    let status = service
        .submit(Command::Status(VaultStatusRequest))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let list = service
        .submit(Command::List(ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let formatted = format!("{status:?} {list:?}");
    assert!(!formatted.contains(repository_root.to_string_lossy().as_ref()));
    assert!(!formatted.contains(local_root.to_string_lossy().as_ref()));
    assert!(!formatted.contains(SECRET));
}

#[test]
fn nonempty_listing_returns_authenticated_logical_metadata_not_object_ids() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let local_root = local.path().canonicalize().unwrap();
    let store = VaultStore::initialize(
        &repository_root,
        &local_root,
        RecoveryPassphrase::new(SECRET.to_owned()),
        parameters(),
        "device",
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let unlocked = store
        .unlock_recovery(
            RecoveryPassphrase::new(SECRET.to_owned()),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let snapshot = lease.current_snapshot_id().unwrap();
    let root = lease.root_entry_id().unwrap();
    let created = lease
        .apply(
            RepositoryMutation::create_directory(snapshot, root, "notes"),
            &mut AllowPublication,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    drop(lease);
    drop(unlocked);
    drop(store);

    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret(SECRET)).unwrap();
    let listed = service
        .submit(Command::List(ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let OperationResult::Entries(entries) = listed else {
        panic!("list returned the wrong bounded result")
    };
    assert_eq!(entries.len(), 1);
    let entry = &entries.as_slice()[0];
    assert_eq!(entry.opaque_id(), created.entry_id().as_bytes());
    assert_eq!(entry.parent_id(), root.as_bytes());
    assert_eq!(entry.name(), "notes");
    assert_eq!(entry.kind(), notecrypt_service::EntryKind::Directory);
    assert_eq!(entry.revision_id(), None);

    let logical_hex = entry
        .opaque_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let object_names = std::fs::read_dir(repository_root.join("objects"))
        .unwrap()
        .flat_map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap())
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert!(
        object_names
            .iter()
            .all(|object| !object.starts_with(&logical_hex))
    );
}

#[test]
fn reopen_rejects_mutated_bootstrap_head_objects_and_local_records() {
    for mutation in 0..7 {
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
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap(),
        );
        let service = service_for_roots(&repository_root, &local_root);
        let vault_local = std::fs::read_dir(&local_root)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let trusted_record = std::fs::read_dir(vault_local.join("trusted"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.file_name().unwrap() != "availability")
            .unwrap();
        let mut objects = std::fs::read_dir(repository_root.join("objects"))
            .unwrap()
            .flat_map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap())
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        objects.sort();
        assert_eq!(objects.len(), 2);
        let (label, expected) = match mutation {
            0 => {
                mutate_file(&repository_root.join(".notecrypt-vault"));
                ("bootstrap", ServiceError::AuthenticationFailed)
            }
            1 => {
                mutate_file(&repository_root.join("head"));
                ("head", ServiceError::IntegrityFailed)
            }
            2 => {
                mutate_file(&trusted_record);
                ("trusted state", ServiceError::AuthenticationFailed)
            }
            3 => {
                mutate_file(&vault_local.join("trusted/availability"));
                ("availability", ServiceError::AuthenticationFailed)
            }
            4 => {
                mutate_file(&objects[0]);
                ("first reachable object", ServiceError::IntegrityFailed)
            }
            5 => {
                mutate_file(&objects[1]);
                ("second reachable object", ServiceError::IntegrityFailed)
            }
            6 => {
                std::fs::write(
                    vault_local.join("cleanup-registry/untrusted-record"),
                    b"not an authenticated cleanup record",
                )
                .unwrap();
                ("cleanup registry", ServiceError::InvalidInput)
            }
            _ => unreachable!(),
        };
        let error = service.unlock_with_recovery(secret(SECRET)).unwrap_err();
        assert_eq!(error, expected, "{label} mutation returned wrong category");
        let snapshot = service.snapshot();
        assert_eq!(snapshot.session_state(), SessionState::Locked);
        assert!(!snapshot.accepting_operations());
        assert!(!snapshot.key_leases_open());
    }
}
