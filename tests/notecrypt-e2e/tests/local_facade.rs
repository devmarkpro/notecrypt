use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_service::{
    Command, CompromiseTargetResolver, Control, CreateDirectory, CreateFile, DeleteEntry,
    ExportFile, ExportOverwriteConfirmation, HostPortError, ImportFile, LocalVaultConfig,
    LogicalWorkspacePath, MonotonicClock, MoveEntry, OperationContext, OperationEvent,
    OperationExecutor, OperationPhase, OperationResult, PlatformExternalFileProvider, ProgressUnit,
    RecoveryKdfProfileV1, RecoverySecretInput, RenameEntry, RepositoryPortError, ServiceConfig,
    ServiceError, ServiceHandle, SessionComponents, SessionPolicy, SnapshotVersion,
    StartupCleanupReport, StoreVaultRepository, TargetWorkspaceRequest, VaultStatusRequest,
    VaultWorkspaceRequest, WorkspaceLease, WorkspaceProvider,
};
use notecrypt_store::VaultStore;
use tempfile::TempDir;

const SECRET: &str = "alpha beta gamma delta epsilon";
const CONTENT_CANARY: &[u8] = b"content-canary-8d4f99e73bc2a61d";
const DIRECTORY_CANARY: &str = "directory-canary-79d6fda3";
const NESTED_DIRECTORY_CANARY: &str = "nested-directory-canary-46ec28a1";
const EMPTY_FILE_CANARY: &str = "empty-file-canary-a02f3e91.md";
const FILE_NAME_CANARY: &str = "import-file-canary-b6d7310c.e2eextcanary9a7b";
const EXTENSION_CANARY: &[u8] = b"e2eextcanary9a7b";
const RENAME_CANARY: &str = "renamed-file-canary-c7f18824.e2eextcanary9a7b";

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

fn service_for_roots(repository_root: &Path, local_root: &Path) -> ServiceHandle {
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
    .with_external_files(Arc::new(
        PlatformExternalFileProvider::open(repository_root, local_root).unwrap(),
    ));
    ServiceHandle::with_local_use_cases(
        ServiceConfig::default(),
        Arc::new(RejectingExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0
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

fn run_mutation(
    service: &ServiceHandle,
    command: Command,
    before: SnapshotVersion,
) -> notecrypt_service::MutationSummary {
    let expects_byte_progress = matches!(&command, Command::ImportFile(_));
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
        .unwrap_or_else(|error| panic!("mutation failed with {error:?}; events: {events:?}"));
    assert_eq!(events.first(), Some(&OperationEvent::Started));
    assert!(events.contains(&OperationEvent::PhaseChanged(OperationPhase::Publishing)));
    let durable_positions: Vec<_> = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(event, OperationEvent::RevisionDurable(_)).then_some(index)
        })
        .collect();
    assert_eq!(durable_positions.len(), 1);
    let publishing = events
        .iter()
        .position(|event| event == &OperationEvent::PhaseChanged(OperationPhase::Publishing))
        .unwrap();
    let progress = events
        .iter()
        .position(|event| matches!(event, OperationEvent::Progress(_)))
        .unwrap();
    if expects_byte_progress {
        assert!(events.iter().any(|event| matches!(
            event,
            OperationEvent::Progress(progress)
                if progress.unit() == ProgressUnit::Bytes && progress.completed() > 0
        )));
    }
    assert!(progress < publishing);
    assert!(publishing < durable_positions[0]);
    assert_eq!(events.last(), Some(&OperationEvent::Completed));
    assert_eq!(durable_positions[0] + 1, events.len() - 1);
    let OperationResult::EntryChanged(summary) = result else {
        panic!("mutation returned the wrong result")
    };
    assert_ne!(summary.snapshot(), before);
    let after = status(service);
    assert_eq!(after.snapshot_id(), summary.snapshot().as_bytes());
    summary
}

fn run_export(service: &ServiceHandle, command: Command, snapshot: SnapshotVersion) {
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
    let reading = events
        .iter()
        .position(|event| event == &OperationEvent::PhaseChanged(OperationPhase::Reading))
        .unwrap();
    let publishing = events
        .iter()
        .position(|event| event == &OperationEvent::PhaseChanged(OperationPhase::Publishing))
        .unwrap();
    assert!(reading < publishing);
    assert!(events.iter().any(|event| matches!(
        event,
        OperationEvent::Progress(progress)
            if progress.unit() == ProgressUnit::Bytes && progress.completed() > 0
    )));
    assert!(matches!(result, OperationResult::Exported(_)));
    assert_eq!(status(service).snapshot_id(), snapshot.as_bytes());
}

fn run_rejection(service: &ServiceHandle, command: Command, expected: ServiceError) {
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
}

fn multi_chunk_content() -> Vec<u8> {
    let mut content = vec![b'x'; 2 * 1024 * 1024 + 37];
    for offset in [13, 1024 * 1024 + 7, content.len() - CONTENT_CANARY.len()] {
        content[offset..offset + CONTENT_CANARY.len()].copy_from_slice(CONTENT_CANARY);
    }
    content
}

#[test]
fn public_local_workflow_advances_once_exports_safely_and_reopens_durably() {
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

    let external = TempDir::new().unwrap();
    let source_path = external.path().join("explicit-selected-source");
    let content = multi_chunk_content();
    std::fs::write(&source_path, &content).unwrap();
    let source_path = source_path.canonicalize().unwrap();

    let service = service_for_roots(&repository_root, &local_root);
    service.unlock_with_recovery(secret()).unwrap();
    let initial = status(&service);
    let initial_snapshot = SnapshotVersion::new(*initial.snapshot_id());
    let root = notecrypt_service::EntryId::new(*initial.root_entry_id());

    let directory = run_mutation(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(initial_snapshot, root, DIRECTORY_CANARY).unwrap(),
        ),
        initial_snapshot,
    );
    assert_no_plaintext(&repository_root, &local_root);

    let nested = run_mutation(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(
                directory.snapshot(),
                directory.entry_id(),
                NESTED_DIRECTORY_CANARY,
            )
            .unwrap(),
        ),
        directory.snapshot(),
    );
    assert_no_plaintext(&repository_root, &local_root);

    let empty = run_mutation(
        &service,
        Command::CreateFile(
            CreateFile::try_new(nested.snapshot(), nested.entry_id(), EMPTY_FILE_CANARY).unwrap(),
        ),
        nested.snapshot(),
    );
    assert!(empty.revision().is_some());
    assert_no_plaintext(&repository_root, &local_root);

    let imported = run_mutation(
        &service,
        Command::ImportFile(
            ImportFile::try_new(empty.snapshot(), root, FILE_NAME_CANARY, source_path).unwrap(),
        ),
        empty.snapshot(),
    );
    assert_no_plaintext(&repository_root, &local_root);

    let rejected_snapshot = imported.snapshot();
    run_rejection(
        &service,
        Command::CreateDirectory(
            CreateDirectory::try_new(initial_snapshot, root, "stale-e2e-canary-65b273d0").unwrap(),
        ),
        ServiceError::StaleCapability,
    );
    assert_eq!(status(&service).snapshot_id(), rejected_snapshot.as_bytes());

    let renamed = run_mutation(
        &service,
        Command::RenameEntry(
            RenameEntry::try_new(
                imported.snapshot(),
                imported.entry_id(),
                root,
                FILE_NAME_CANARY,
                notecrypt_service::EntryKind::File,
                imported.revision(),
                RENAME_CANARY,
            )
            .unwrap(),
        ),
        imported.snapshot(),
    );
    assert_no_plaintext(&repository_root, &local_root);

    let moved = run_mutation(
        &service,
        Command::MoveEntry(
            MoveEntry::try_new(
                renamed.snapshot(),
                renamed.entry_id(),
                root,
                RENAME_CANARY,
                notecrypt_service::EntryKind::File,
                renamed.revision(),
                nested.entry_id(),
            )
            .unwrap(),
        ),
        renamed.snapshot(),
    );
    assert_no_plaintext(&repository_root, &local_root);

    let listed_after_move = list_entries(&service);
    let moved_entry = listed_after_move
        .iter()
        .find(|entry| entry.opaque_id() == moved.entry_id().as_bytes())
        .expect("moved entry must remain visible in the authenticated view");
    assert_eq!(
        moved_entry.revision_id().copied(),
        moved.revision().map(|revision| *revision.as_bytes())
    );

    let export_path = external
        .path()
        .canonicalize()
        .unwrap()
        .join("explicit-export-destination");
    run_export(
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
        moved.snapshot(),
    );
    assert_eq!(std::fs::read(&export_path).unwrap(), content);

    run_rejection(
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
        ServiceError::DestinationExists,
    );
    assert_eq!(status(&service).snapshot_id(), moved.snapshot().as_bytes());

    std::fs::write(&export_path, b"confirmed-overwrite-sentinel").unwrap();
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
        moved.snapshot(),
    );
    assert_eq!(std::fs::read(&export_path).unwrap(), content);

    let deleted = run_mutation(
        &service,
        Command::DeleteEntry(
            DeleteEntry::try_file(
                moved.snapshot(),
                moved.entry_id(),
                nested.entry_id(),
                RENAME_CANARY,
                moved.revision().unwrap(),
            )
            .unwrap(),
        ),
        moved.snapshot(),
    );
    assert_eq!(deleted.kind(), notecrypt_service::EntryKind::Tombstone);
    assert_no_plaintext(&repository_root, &local_root);

    service.control(Control::LockNow).unwrap();
    assert_eq!(
        service.submit(Command::Status(VaultStatusRequest)).err(),
        Some(ServiceError::Locked)
    );
    drop(service);

    let reopened = service_for_roots(&repository_root, &local_root);
    reopened.unlock_with_recovery(secret()).unwrap();
    let reopened_status = status(&reopened);
    assert_eq!(reopened_status.snapshot_id(), deleted.snapshot().as_bytes());
    let listed = reopened
        .submit(Command::List(notecrypt_service::ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let OperationResult::Entries(entries) = listed else {
        panic!("list returned the wrong result")
    };
    assert!(entries.iter().any(|entry| {
        entry.opaque_id() == directory.entry_id().as_bytes()
            && entry.kind() == notecrypt_service::EntryKind::Directory
    }));
    assert!(entries.iter().any(|entry| {
        entry.opaque_id() == nested.entry_id().as_bytes()
            && entry.parent_id() == directory.entry_id().as_bytes()
            && entry.kind() == notecrypt_service::EntryKind::Directory
    }));
    assert!(entries.iter().any(|entry| {
        entry.opaque_id() == empty.entry_id().as_bytes()
            && entry.parent_id() == nested.entry_id().as_bytes()
            && entry.kind() == notecrypt_service::EntryKind::File
    }));
    assert!(entries.iter().any(|entry| {
        entry.opaque_id() == deleted.entry_id().as_bytes()
            && entry.parent_id() == nested.entry_id().as_bytes()
            && entry.kind() == notecrypt_service::EntryKind::Tombstone
    }));
    assert_no_plaintext(&repository_root, &local_root);
}

fn assert_no_plaintext(repository_root: &Path, local_root: &Path) {
    let repository_scan = walk_components_and_bytes(repository_root);
    let local_scan = walk_components_and_bytes(local_root);
    for canary in [
        CONTENT_CANARY,
        DIRECTORY_CANARY.as_bytes(),
        NESTED_DIRECTORY_CANARY.as_bytes(),
        EMPTY_FILE_CANARY.as_bytes(),
        FILE_NAME_CANARY.as_bytes(),
        EXTENSION_CANARY,
        RENAME_CANARY.as_bytes(),
    ] {
        for encoded in [canary.to_vec(), lowercase_hex(canary)] {
            assert!(!contains(&repository_scan, &encoded));
            assert!(!contains(&local_scan, &encoded));
        }
    }
    assert_repository_objects_are_canonical(repository_root);
}

fn assert_repository_objects_are_canonical(repository_root: &Path) {
    let mut pending = vec![repository_root.join("objects")];
    let mut decoded = 0_usize;
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
                continue;
            }
            let bytes = std::fs::read(entry.path()).unwrap();
            let canonical = notecrypt_format::decode_aead_object(
                &bytes,
                &notecrypt_format::DecodeLimits::PHASE_1,
            )
            .and_then(|value| notecrypt_format::encode_aead_object(&value))
            .is_ok_and(|encoded| encoded == bytes)
                || notecrypt_format::decode_snapshot_object(
                    &bytes,
                    &notecrypt_format::DecodeLimits::PHASE_1,
                )
                .and_then(|value| notecrypt_format::encode_snapshot_object(&value))
                .is_ok_and(|encoded| encoded == bytes)
                || notecrypt_format::decode_content_chunk(
                    &bytes,
                    &notecrypt_format::DecodeLimits::PHASE_1,
                )
                .and_then(|value| notecrypt_format::encode_content_chunk(&value))
                .is_ok_and(|encoded| encoded == bytes);
            assert!(
                canonical,
                "repository object is not canonical encrypted format"
            );
            decoded += 1;
        }
    }
    assert!(decoded != 0, "repository must contain encrypted objects");
}

fn list_entries(service: &ServiceHandle) -> notecrypt_service::EntrySummaries {
    let result = service
        .submit(Command::List(notecrypt_service::ListEntries))
        .unwrap()
        .wait_result(Duration::from_secs(5))
        .unwrap();
    let OperationResult::Entries(entries) = result else {
        panic!("list returned the wrong result")
    };
    entries
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|bytes| bytes == needle)
}

fn lowercase_hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)]);
        output.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    output
}

fn walk_components_and_bytes(root: &Path) -> Vec<u8> {
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
