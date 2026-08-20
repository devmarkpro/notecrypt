use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notecrypt_core::VaultId;
use notecrypt_service::{
    BeginRecoveryInitialization, Command, DeviceKeyReference, DeviceUnlockProvider,
    DeviceUnlockSecret, HostPortError, LogicalWorkspacePath, MAX_DEVICE_KEY_REFERENCE_BYTES,
    MAX_LOGICAL_COMPONENT_BYTES, MAX_LOGICAL_PATH_DEPTH, MAX_RECOVERY_SECRET_BYTES,
    MAX_STABLE_SOURCE_TOKEN_BYTES, MAX_WORKSPACE_PATHS, MonotonicClock, OperationContext,
    OperationExecutor, OperationResult, PendingRecoveryAction, PreparedRecoveryInitialization,
    RecoverySecretInput, RecoverySecretPresenter, RepositoryPortError, ServiceConfig, ServiceError,
    ServiceHandle, SessionComponents, SessionPolicy, StableSourceToken, StartupCleanupReport,
    UnavailableDeviceUnlockProvider, UnlockedVaultCapability, VaultRepository, VaultSummary,
    WorkspaceLease, WorkspacePathRegistry, WorkspaceProvider,
};

const PRESENTED_SECRET: &[u8] = b"generated recovery secret";

fn source_item_body<'a>(source: &'a str, declaration: &str) -> &'a str {
    let item = source
        .find(declaration)
        .unwrap_or_else(|| panic!("missing source declaration {declaration}"));
    let opening = source[item..].find('{').unwrap() + item;
    let mut depth = 0_usize;
    for (offset, byte) in source.as_bytes()[opening..].iter().enumerate() {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[opening + 1..opening + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated source declaration {declaration}")
}

#[test]
fn official_operation_dtos_exclude_protected_security_capabilities() {
    let command_source = include_str!("../src/command.rs");
    let event_source = include_str!("../src/event.rs");
    let service_source = include_str!("../src/service.rs");
    let bodies = [
        source_item_body(command_source, "pub enum Command"),
        source_item_body(command_source, "pub enum OperationResult"),
        source_item_body(event_source, "pub enum OperationEvent"),
        source_item_body(service_source, "pub struct ServiceSnapshot"),
    ];
    let protected = [
        "RecoverySecretInput",
        "RecoverySecretPresentation",
        "DeviceUnlockSecret",
        "CompromiseRekeyConfirmation",
        "StableRevisionCommit",
        "PendingRecoveryInitialization",
        "PendingCompromiseRekey",
        "PendingFreshnessAcknowledgement",
        "StableSourceToken",
        "FinalSaveGuard",
    ];

    for body in bodies {
        for capability in protected {
            assert!(
                !body.contains(capability),
                "official DTO body contains protected capability {capability}",
            );
        }
    }
}

#[test]
fn recovery_verifier_temporaries_are_owned_by_zeroizing_guards() {
    let source = include_str!("../src/ports.rs");
    let body = source_item_body(source, "fn recovery_verifier");
    assert!(body.contains("Zeroizing::new(blake3::Hasher::new_keyed(key))"));
    assert!(body.contains("Zeroizing::new(hasher.finalize())"));
    assert!(body.contains("Zeroizing::new(*digest.as_bytes())"));
    assert!(!body.contains("blake3::keyed_hash"));
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
        _token: &StableSourceToken,
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

struct NoopRecoveryAction;

struct NoopOperationCancellation;

impl notecrypt_service::OperationCancellation for NoopOperationCancellation {
    fn cancel(&self) {}
}

impl PendingRecoveryAction for NoopRecoveryAction {
    fn cancellation_handle(&self) -> Arc<dyn notecrypt_service::OperationCancellation> {
        Arc::new(NoopOperationCancellation)
    }

    fn confirm(
        self: Box<Self>,
        _confirmation: RecoverySecretInput,
        _cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<VaultSummary, RepositoryPortError> {
        Ok(VaultSummary::new(VaultId::from_bytes([9; 16])))
    }

    fn abort(self: Box<Self>) -> Result<(), RepositoryPortError> {
        Ok(())
    }
}

struct PresentationRepository;

impl VaultRepository for PresentationRepository {
    fn current_vault_id(&self) -> Result<Option<VaultId>, RepositoryPortError> {
        Ok(Some(VaultId::from_bytes([9; 16])))
    }

    fn unlock_recovery(
        &self,
        _secret: RecoverySecretInput,
        _cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<Box<dyn UnlockedVaultCapability>, RepositoryPortError> {
        Err(RepositoryPortError::Unavailable)
    }

    fn begin_recovery_initialization(
        &self,
        _request: BeginRecoveryInitialization,
        _cancel: &notecrypt_service::RepositoryCancellation,
    ) -> Result<PreparedRecoveryInitialization, RepositoryPortError> {
        Ok(PreparedRecoveryInitialization::new(
            RecoverySecretInput::from_protected_bytes(PRESENTED_SECRET.to_vec())
                .map_err(|_| RepositoryPortError::InvalidInput)?,
            Box::new(NoopRecoveryAction),
        ))
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

fn presentation_service() -> ServiceHandle {
    let policy = SessionPolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(120),
        Vec::new(),
        Duration::from_secs(1),
    )
    .unwrap();
    let components = SessionComponents::new(
        Arc::new(PresentationRepository),
        Arc::new(UnavailableWorkspace),
        Arc::new(FixedClock),
        policy,
    );
    ServiceHandle::with_session_components(
        ServiceConfig::default(),
        Arc::new(NoopExecutor),
        Arc::new(notecrypt_service::OsOperationIdRandom),
        components,
    )
    .unwrap()
    .0
}

struct RecordingPresenter {
    result: Result<(), HostPortError>,
    observed: Vec<u8>,
}

impl RecoverySecretPresenter for RecordingPresenter {
    fn present(&mut self, secret: &[u8]) -> Result<(), HostPortError> {
        self.observed.extend_from_slice(secret);
        self.result
    }
}

#[test]
fn recovery_secret_presentation_is_delivered_once_on_success() {
    let service = presentation_service();
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let mut presenter = RecordingPresenter {
        result: Ok(()),
        observed: Vec::new(),
    };

    presentation.unwrap().present_once(&mut presenter).unwrap();

    assert_eq!(presenter.observed, PRESENTED_SECRET);
    service.cancel_recovery_initialization(pending).unwrap();
    service.shutdown();
}

#[test]
fn recovery_secret_presentation_is_consumed_when_presenter_fails() {
    let service = presentation_service();
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();
    let mut presenter = RecordingPresenter {
        result: Err(HostPortError::Denied),
        observed: Vec::new(),
    };

    assert_eq!(
        presentation.unwrap().present_once(&mut presenter),
        Err(HostPortError::Denied),
    );
    assert_eq!(presenter.observed, PRESENTED_SECRET);
    service.cancel_recovery_initialization(pending).unwrap();
    service.shutdown();
}

#[test]
fn unpresented_recovery_secret_drop_path_completes_without_presentation() {
    let service = presentation_service();
    let (pending, presentation) = service
        .begin_recovery_initialization(BeginRecoveryInitialization::generated())
        .unwrap();

    drop(presentation.unwrap());

    service.cancel_recovery_initialization(pending).unwrap();
    service.shutdown();
}

#[test]
fn recovery_secret_input_accepts_bounded_utf8_without_exposing_it() {
    assert!(RecoverySecretInput::from_protected_bytes(vec![b'x']).is_ok());
    assert!(
        RecoverySecretInput::from_protected_bytes(vec![b'x'; MAX_RECOVERY_SECRET_BYTES]).is_ok()
    );
    assert!(
        RecoverySecretInput::from_protected_bytes("correct horse 🐎".as_bytes().to_vec()).is_ok()
    );
}

#[test]
fn recovery_secret_input_rejects_empty_nul_invalid_utf8_and_oversize_values() {
    for invalid in [
        Vec::new(),
        b"contains\0nul".to_vec(),
        vec![0xff, 0xfe],
        vec![b'x'; MAX_RECOVERY_SECRET_BYTES + 1],
    ] {
        assert_eq!(
            RecoverySecretInput::from_protected_bytes(invalid).err(),
            Some(HostPortError::InvalidInput),
        );
    }
}

#[test]
fn device_unlock_secrets_require_exact_crypto_key_length() {
    assert_eq!(
        DeviceUnlockSecret::try_from_protected_bytes(vec![7; 31]).err(),
        Some(HostPortError::InvalidInput),
    );
    assert!(DeviceUnlockSecret::try_from_protected_bytes(vec![7; 32]).is_ok());
    assert_eq!(
        DeviceUnlockSecret::try_from_protected_bytes(vec![7; 33]).err(),
        Some(HostPortError::InvalidInput),
    );
}

#[test]
fn unavailable_device_unlock_provider_fails_closed() {
    let provider = UnavailableDeviceUnlockProvider;
    let reference = DeviceKeyReference::from_bytes(vec![1]).unwrap();
    assert_eq!(
        provider.enroll(VaultId::from_bytes([4; 16])).err(),
        Some(HostPortError::Unavailable),
    );
    assert_eq!(
        provider.unlock(&reference).err(),
        Some(HostPortError::Unavailable),
    );
    assert_eq!(
        provider.remove(&reference).err(),
        Some(HostPortError::Unavailable),
    );
}

#[test]
fn device_key_references_are_nonempty_and_bounded() {
    assert_eq!(
        DeviceKeyReference::from_bytes(Vec::new()).err(),
        Some(HostPortError::InvalidInput),
    );
    assert!(DeviceKeyReference::from_bytes(vec![1; MAX_DEVICE_KEY_REFERENCE_BYTES]).is_ok());
    assert_eq!(
        DeviceKeyReference::from_bytes(vec![1; MAX_DEVICE_KEY_REFERENCE_BYTES + 1]).err(),
        Some(HostPortError::InvalidInput),
    );
}

#[test]
fn logical_workspace_paths_reject_nonportable_spellings() {
    let invalid = [
        "",
        ".",
        "..",
        "notes//entry",
        "/absolute",
        r"\\server\share",
        r"C:\notes",
        r"notes\entry",
        "notes/entry:stream",
        "notes/CON",
        "notes/nul.txt",
        "notes/trailing.",
        "notes/trailing ",
        "notes/control\u{0007}",
        "notes/nul\0byte",
    ];

    for candidate in invalid {
        assert_eq!(
            LogicalWorkspacePath::new(PathBuf::from(candidate)).err(),
            Some(HostPortError::InvalidInput),
            "accepted {candidate:?}",
        );
    }

    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let non_utf8 = PathBuf::from(OsString::from_vec(vec![b'n', 0xff]));
        assert_eq!(
            LogicalWorkspacePath::new(non_utf8).err(),
            Some(HostPortError::InvalidInput),
        );
    }
}

#[test]
fn logical_workspace_paths_reject_oversize_components_and_excessive_depth() {
    let oversize_component = "x".repeat(MAX_LOGICAL_COMPONENT_BYTES + 1);
    assert_eq!(
        LogicalWorkspacePath::new(PathBuf::from(oversize_component)).err(),
        Some(HostPortError::CapacityExceeded),
    );

    let excessive_depth = std::iter::repeat_n("x", MAX_LOGICAL_PATH_DEPTH + 1)
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        LogicalWorkspacePath::new(PathBuf::from(excessive_depth)).err(),
        Some(HostPortError::CapacityExceeded),
    );
}

#[test]
fn workspace_path_registry_rejects_portable_collisions() {
    let mut registry = WorkspacePathRegistry::new(8).unwrap();
    let composed = LogicalWorkspacePath::new(PathBuf::from("notes/caf\u{e9}.md")).unwrap();
    registry.insert(&composed).unwrap();

    for collision in [
        "NOTES/CAF\u{c9}.MD",
        "notes/cafe\u{301}.md",
        "notes/\u{1d400}.md",
    ] {
        let path = if collision.contains('\u{1d400}') {
            LogicalWorkspacePath::new(PathBuf::from("notes/a.md")).unwrap()
        } else {
            LogicalWorkspacePath::new(PathBuf::from(collision)).unwrap()
        };
        if collision.contains('\u{1d400}') {
            let mut compatibility = WorkspacePathRegistry::new(2).unwrap();
            let mathematical =
                LogicalWorkspacePath::new(PathBuf::from("notes/\u{1d400}.md")).unwrap();
            compatibility.insert(&mathematical).unwrap();
            assert_eq!(
                compatibility.insert(&path).err(),
                Some(HostPortError::InvalidInput),
            );
        } else {
            assert_eq!(
                registry.insert(&path).err(),
                Some(HostPortError::InvalidInput),
            );
        }
    }
}

#[test]
fn workspace_path_registry_is_bounded() {
    let mut registry = WorkspacePathRegistry::new(1).unwrap();
    let one = LogicalWorkspacePath::new(PathBuf::from("one")).unwrap();
    registry.insert(&one).unwrap();
    registry.insert(&one).unwrap();
    let two = LogicalWorkspacePath::new(PathBuf::from("two")).unwrap();
    assert_eq!(
        registry.insert(&two).err(),
        Some(HostPortError::CapacityExceeded),
    );
    assert_eq!(
        WorkspacePathRegistry::new(0).err(),
        Some(HostPortError::InvalidInput),
    );
    assert!(WorkspacePathRegistry::new(MAX_WORKSPACE_PATHS).is_ok());
    assert_eq!(
        WorkspacePathRegistry::new(MAX_WORKSPACE_PATHS + 1).err(),
        Some(HostPortError::InvalidInput),
    );
}

#[test]
fn stable_source_tokens_are_opaque_and_bounded() {
    assert_eq!(
        StableSourceToken::from_bytes(Vec::new()).err(),
        Some(HostPortError::InvalidInput),
    );
    let token = StableSourceToken::from_bytes(vec![7; MAX_STABLE_SOURCE_TOKEN_BYTES]).unwrap();
    assert_eq!(token.as_bytes(), vec![7; MAX_STABLE_SOURCE_TOKEN_BYTES]);
    assert_eq!(
        StableSourceToken::from_bytes(vec![7; MAX_STABLE_SOURCE_TOKEN_BYTES + 1]).err(),
        Some(HostPortError::InvalidInput),
    );
}

#[test]
fn protected_boundaries_fail_to_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/compile_fail/*.rs");
}
