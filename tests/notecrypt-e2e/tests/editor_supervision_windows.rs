#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notecrypt_editor_workspace::{
    ProcessEditorSupervisor, SecureWorkspaceProvider, resolve_editor,
};
use notecrypt_platform_fs::{Directory, PhysicalComponent};
use notecrypt_service::workspace_test_support::target_request;
use notecrypt_service::{
    EditorCommand, EditorLaunchRequest, EditorProcess, EditorResolutionRequest,
    EditorSupervisionMode, EditorSupervisor, HostPortError, LogicalWorkspacePath,
    MaterializationPublication, WorkspaceLease, WorkspaceProvider,
};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    base: PathBuf,
    repository: PathBuf,
    local_state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = private_dir(root.path(), "workspace-v1");
        let repository = private_dir(root.path(), "repository");
        let local_state = private_dir(root.path(), "local-state");
        Self {
            root,
            base,
            repository,
            local_state,
        }
    }

    fn provider(&self) -> Arc<SecureWorkspaceProvider> {
        Arc::new(
            SecureWorkspaceProvider::open(
                self.base.clone(),
                self.repository.clone(),
                self.local_state.clone(),
            )
            .unwrap(),
        )
    }

    fn editor(&self, mode: &str, basename: &str) -> PathBuf {
        let directory = private_dir(self.root.path(), mode);
        let editor = directory.join(format!("{basename}.exe"));
        fs::copy(env!("CARGO_BIN_EXE_test_editor"), &editor).unwrap();
        editor
    }
}

fn private_dir(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    let parent = Directory::open_ambient(parent).unwrap();
    let component = PhysicalComponent::try_new(name).unwrap();
    let directory = parent.create_private_dir(&component).unwrap();
    drop(directory);
    fs::canonicalize(path).unwrap()
}

fn armed_workspace(
    fixture: &Fixture,
    provider: &Arc<SecureWorkspaceProvider>,
    id: u8,
) -> (WorkspaceLease, PathBuf) {
    let request = target_request([id; 16], [0x41; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("note with spaces.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"plaintext").unwrap();
    let mut published = match provider.publish_materialized(&lease, target).unwrap() {
        MaterializationPublication::Durable(published) => published,
        MaterializationPublication::DurabilityPending(_) => panic!("unexpected pending publish"),
    };
    let path = published.path().to_path_buf();
    provider.arm_published_path(&lease, &mut published).unwrap();
    (lease, path)
}

fn launch_request(
    lease: &WorkspaceLease,
    editor: PathBuf,
    workspace: PathBuf,
    generation: u64,
    mode: EditorSupervisionMode,
) -> EditorLaunchRequest {
    let command = EditorCommand::try_new(editor.into_os_string(), Vec::new()).unwrap();
    let resolution = EditorResolutionRequest::try_new(Some(command), None, None, mode).unwrap();
    EditorLaunchRequest::try_new(lease, resolution, workspace, generation).unwrap()
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "editor barrier timed out");
        std::thread::yield_now();
    }
}

fn wait_for_terminal(process: &mut dyn EditorProcess) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match process.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) | Err(HostPortError::DetachedEditor) => {}
            Err(error) => panic!("editor wait failed: {error:?}"),
        }
        assert!(Instant::now() < deadline, "editor did not terminate");
        std::thread::yield_now();
    }
}

#[test]
fn windows_default_resolves_to_the_attested_system_notepad() {
    let request =
        EditorResolutionRequest::try_new(None, None, None, EditorSupervisionMode::Blocking)
            .unwrap();

    let command = resolve_editor(request).unwrap();

    assert!(
        command
            .executable()
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("\\system32\\notepad.exe")
    );
}

#[test]
fn windows_mixed_case_system_profile_resolves_idempotently() {
    let command = EditorCommand::try_new("NOTEPAD.EXE".into(), Vec::new()).unwrap();
    let request = EditorResolutionRequest::try_new(
        Some(command),
        None,
        None,
        EditorSupervisionMode::Blocking,
    )
    .unwrap();

    let first = resolve_editor(request).unwrap();
    let canonical = first.executable().to_os_string();
    let arguments = first.arguments().to_vec();
    let second = resolve_editor(
        EditorResolutionRequest::try_new(
            Some(EditorCommand::try_new(canonical.clone(), arguments.clone()).unwrap()),
            None,
            None,
            EditorSupervisionMode::Blocking,
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(second.executable(), canonical);
    assert_eq!(second.arguments(), arguments);
    assert!(
        first
            .executable()
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("\\system32\\notepad.exe")
    );
}

#[test]
fn windows_system_notepad_strict_fails_closed_before_spawn() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x60);
    let resolution =
        EditorResolutionRequest::try_new(None, None, None, EditorSupervisionMode::Strict).unwrap();
    let request = EditorLaunchRequest::try_new(&lease, resolution, workspace, 1).unwrap();
    let supervisor = ProcessEditorSupervisor::new(Arc::clone(&provider)).unwrap();

    assert!(matches!(
        supervisor.launch(request),
        Err(HostPortError::Unavailable)
    ));
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn windows_job_contains_a_descendant_until_force_and_verified_reap() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x61);
    let ready = workspace.with_extension("descendant-ready");
    let editor = fixture.editor("child", "notepad");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    let mut process = supervisor
        .launch(launch_request(
            &lease,
            editor,
            workspace,
            1,
            EditorSupervisionMode::Strict,
        ))
        .unwrap();
    wait_for_file(&ready);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match process.try_wait() {
            Err(HostPortError::DetachedEditor) => break,
            Ok(None) => {}
            other => panic!("expected retained Job descendant, got {other:?}"),
        }
        assert!(Instant::now() < deadline, "leader did not exit");
        std::thread::yield_now();
    }
    supervisor.force_stop_all().unwrap();
    wait_for_terminal(&mut *process);
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn windows_blocking_unowned_proxy_is_never_assigned_to_a_kill_job() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x62);
    let ready = workspace.with_extension("ready");
    let release = workspace.with_extension("release");
    let editor = fixture.editor("blocking", "code");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    let mut process = supervisor
        .launch(launch_request(
            &lease,
            editor,
            workspace,
            1,
            EditorSupervisionMode::Blocking,
        ))
        .unwrap();
    wait_for_file(&ready);

    supervisor.request_stop_all().unwrap();
    supervisor.force_stop_all().unwrap();
    assert!(!supervisor.poll_quiescence().unwrap().is_quiescent());
    fs::write(release, b"release").unwrap();
    wait_for_terminal(&mut *process);
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}
