#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use notecrypt_editor_workspace::{
    EditorLaunchFailureStage, ProcessEditorSupervisor, SecureWorkspaceProvider,
};
#[cfg(target_os = "linux")]
use notecrypt_editor_workspace::{
    ProcessWaitFailureDiagnostic, ProcessWaitFailureReason, ProcessWaitFailureStage,
};
use notecrypt_platform_fs::{Directory, FileCapability, PhysicalComponent};
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

struct StagedEditor {
    staging_directory: Directory,
    published_directory: Directory,
    staged_name: PhysicalComponent,
    published_name: PhysicalComponent,
    staged_path: PathBuf,
    published_path: PathBuf,
    writer: FileCapability,
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
        let staged = self.editor_with_open_writer(mode, basename);
        self.publish_editor(staged)
    }

    fn editor_with_open_writer(&self, mode: &str, basename: &str) -> StagedEditor {
        let staging_directory_path = private_dir(self.root.path(), &format!("{mode}-staging"));
        let published_directory_path = private_dir(self.root.path(), mode);
        let staging_directory = Directory::open_ambient(&staging_directory_path).unwrap();
        let published_directory = Directory::open_ambient(&published_directory_path).unwrap();
        let staged_name = PhysicalComponent::try_new(basename).unwrap();
        let published_name = PhysicalComponent::try_new(basename).unwrap();
        let staged_path = staging_directory_path.join(basename);
        let published_path = published_directory_path.join(basename);
        let mut source = fs::File::open(env!("CARGO_BIN_EXE_test_editor")).unwrap();
        let mut writer = staging_directory
            .create_private_file_new(&staged_name)
            .unwrap();
        std::io::copy(&mut source, &mut writer).unwrap();
        fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o700)).unwrap();
        writer.sync_all().unwrap();
        staging_directory.sync().unwrap();
        StagedEditor {
            staging_directory,
            published_directory,
            staged_name,
            published_name,
            staged_path,
            published_path,
            writer,
        }
    }

    fn publish_editor(&self, staged: StagedEditor) -> PathBuf {
        let StagedEditor {
            staging_directory,
            published_directory,
            staged_name,
            published_name,
            staged_path,
            published_path,
            writer,
        } = staged;
        let expected_identity = writer.identity().unwrap();
        drop(writer);
        #[cfg(target_os = "linux")]
        assert_eq!(
            exact_writable_file_descriptor(&staged_path),
            None,
            "the staged helper retained a writable file descriptor after close"
        );
        let source = staging_directory.open_file_nofollow(&staged_name).unwrap();
        assert!(source.matches_identity(&expected_identity).unwrap());
        staging_directory
            .rename_opened_no_replace_from_private_staging(
                &source,
                &staged_name,
                &published_directory,
                &published_name,
            )
            .unwrap();
        staging_directory.sync().unwrap();
        published_directory.sync().unwrap();
        assert!(!staged_path.exists());
        published_path
    }

    fn trusted_supervisor(
        &self,
        provider: &Arc<SecureWorkspaceProvider>,
        editor: &Path,
    ) -> ProcessEditorSupervisor {
        ProcessEditorSupervisor::new_with_trusted_test_executable(
            Arc::clone(provider),
            editor.to_path_buf(),
        )
        .unwrap()
    }
}

fn private_dir(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::canonicalize(path).unwrap()
}

#[cfg(target_os = "linux")]
fn exact_writable_file_descriptor(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;

    const MAXIMUM_FILE_DESCRIPTORS: usize = 4_096;
    const ACCESS_MODE_MASK: u32 = 0o3;

    let expected = fs::metadata(path).unwrap();
    for (index, entry) in fs::read_dir("/proc/self/fd").unwrap().enumerate() {
        assert!(
            index < MAXIMUM_FILE_DESCRIPTORS,
            "file-descriptor observation exceeded its bound"
        );
        let entry = entry.unwrap();
        let Ok(descriptor) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(metadata) = fs::metadata(entry.path()) else {
            continue;
        };
        if metadata.dev() != expected.dev() || metadata.ino() != expected.ino() {
            continue;
        }
        let information = fs::read_to_string(format!("/proc/self/fdinfo/{descriptor}")).unwrap();
        let flags = information
            .lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .and_then(|value| u32::from_str_radix(value, 8).ok())
            .expect("matching file descriptor exposes bounded access flags");
        if flags & ACCESS_MODE_MASK != 0 {
            return Some((descriptor, flags));
        }
    }
    None
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
        MaterializationPublication::DurabilityPending(_) => {
            panic!("ordinary publication unexpectedly remained durability-pending")
        }
    };
    let path = published.path().to_path_buf();
    provider.arm_published_path(&lease, &mut published).unwrap();
    (lease, path)
}

fn launch_request(
    lease: &WorkspaceLease,
    editor: PathBuf,
    workspace: PathBuf,
    mode: EditorSupervisionMode,
    generation: u64,
) -> EditorLaunchRequest {
    launch_request_with_arguments(lease, editor, Vec::new(), workspace, mode, generation)
}

fn launch_request_with_arguments(
    lease: &WorkspaceLease,
    editor: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    workspace: PathBuf,
    mode: EditorSupervisionMode,
    generation: u64,
) -> EditorLaunchRequest {
    let command = EditorCommand::try_new(editor.into_os_string(), arguments).unwrap();
    let resolution = EditorResolutionRequest::try_new(Some(command), None, None, mode).unwrap();
    EditorLaunchRequest::try_new(lease, resolution, workspace, generation).unwrap()
}

fn launch_expected(
    supervisor: &ProcessEditorSupervisor,
    lease: &WorkspaceLease,
    generation: u64,
    request: EditorLaunchRequest,
) -> Box<dyn EditorProcess> {
    supervisor.launch(request).unwrap_or_else(|error| {
        let diagnostic = supervisor.take_launch_failure_diagnostic(lease.id(), generation);
        panic!("expected successful editor launch: error={error:?}, diagnostic={diagnostic:?}")
    })
}

fn wait_for_exit(
    supervisor: &ProcessEditorSupervisor,
    lease: &WorkspaceLease,
    generation: u64,
    label: &str,
    process: &mut dyn EditorProcess,
) {
    let _ = wait_for_terminal(supervisor, lease, generation, label, process);
}

fn wait_for_terminal(
    supervisor: &ProcessEditorSupervisor,
    lease: &WorkspaceLease,
    generation: u64,
    label: &str,
    process: &mut dyn EditorProcess,
) -> notecrypt_service::EditorExit {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match process.try_wait() {
            Ok(Some(exit)) => return exit,
            Ok(None) | Err(HostPortError::DetachedEditor) => {}
            Err(error) => {
                let diagnostic =
                    supervisor.take_process_wait_failure_diagnostic(lease.id(), generation);
                panic!(
                    "editor wait failed: label={label}, error={error:?}, diagnostic={diagnostic:?}"
                )
            }
        }
        assert!(
            Instant::now() < deadline,
            "editor did not reach terminal state: label={label}"
        );
        std::thread::yield_now();
    }
}

fn wait_for_detached(
    supervisor: &ProcessEditorSupervisor,
    lease: &WorkspaceLease,
    generation: u64,
    label: &str,
    process: &mut dyn EditorProcess,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match process.try_wait() {
            Err(HostPortError::DetachedEditor) => return,
            Ok(None) => {}
            Err(error) => {
                let diagnostic =
                    supervisor.take_process_wait_failure_diagnostic(lease.id(), generation);
                panic!(
                    "expected retained descendant evidence: label={label}, error={error:?}, diagnostic={diagnostic:?}"
                )
            }
            Ok(Some(exit)) => {
                panic!("expected retained descendant evidence: label={label}, exit={exit:?}")
            }
        }
        assert!(
            Instant::now() < deadline,
            "leader did not exit: label={label}"
        );
        std::thread::yield_now();
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "editor barrier was not published"
        );
        std::thread::yield_now();
    }
}

#[test]
fn direct_blocking_editor_is_launched_reaped_and_quiescent() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x31);
    let editor = fixture.editor("normal", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );

    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_exit(&supervisor, &lease, 1, "direct-blocking", &mut *process);

    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn nonzero_and_signal_editor_exits_preserve_exact_terminal_status() {
    for (id, helper_mode, expected) in [(0x3b, "nonzero", Some(17)), (0x3c, "signal", None)] {
        let fixture = Fixture::new();
        let provider = fixture.provider();
        let (lease, workspace) = armed_workspace(&fixture, &provider, id);
        let editor = fixture.editor(helper_mode, "nvim");
        let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
            Arc::clone(&provider),
            editor.clone(),
        )
        .unwrap();
        let request = launch_request(
            &lease,
            editor,
            workspace,
            EditorSupervisionMode::Blocking,
            1,
        );

        let mut process = launch_expected(&supervisor, &lease, 1, request);
        assert_eq!(
            wait_for_terminal(&supervisor, &lease, 1, helper_mode, &mut *process).code(),
            expected
        );
        assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
        drop(provider.remove_workspace(&lease).unwrap());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn owned_quick_exit_wait_failures_retry_the_same_token_to_exact_status() {
    use notecrypt_platform_fs::workspace_test_support::inject_process_group_scan_entry_budget;

    for (id, helper_mode, expected) in [(0x5d, "nonzero", Some(17)), (0x5e, "signal", None)] {
        let fixture = Fixture::new();
        let provider = fixture.provider();
        let (lease, workspace) = armed_workspace(&fixture, &provider, id);
        let ready = workspace.with_extension("ready");
        let editor = fixture.editor(helper_mode, "nvim");
        let supervisor = fixture.trusted_supervisor(&provider, &editor);
        let request = launch_request(
            &lease,
            editor,
            workspace,
            EditorSupervisionMode::Blocking,
            1,
        );
        let mut process = launch_expected(&supervisor, &lease, 1, request);
        wait_for_file(&ready);

        let deadline = Instant::now() + Duration::from_secs(5);
        while !supervisor
            .leader_exited_unreaped_for_test(lease.id(), 1)
            .unwrap()
        {
            assert!(
                Instant::now() < deadline,
                "quick-exit editor leader did not become observable: helper_mode={helper_mode}"
            );
            std::thread::yield_now();
        }

        inject_process_group_scan_entry_budget(0);
        assert_eq!(process.try_wait(), Err(HostPortError::PlatformFailure));
        assert_eq!(
            supervisor.take_process_wait_failure_diagnostic(lease.id(), 1),
            Some(ProcessWaitFailureDiagnostic {
                stage: ProcessWaitFailureStage::GroupScanDeadline,
                reason: ProcessWaitFailureReason::EnumerationEntryBudget,
                io_kind: std::io::ErrorKind::TimedOut,
                raw_os_error: None,
            })
        );
        assert_eq!(
            wait_for_terminal(&supervisor, &lease, 1, helper_mode, &mut *process).code(),
            expected
        );
        assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
        drop(provider.remove_workspace(&lease).unwrap());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn wait_failure_diagnostic_survives_a_subsequent_owned_tree_poll() {
    use notecrypt_platform_fs::workspace_test_support::inject_process_group_scan_entry_budget;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x5f);
    let child_ready = workspace.with_extension("descendant-ready");
    let editor = fixture.editor("child", "nvim");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&child_ready);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !supervisor
        .leader_exited_unreaped_for_test(lease.id(), 1)
        .unwrap()
    {
        assert!(
            Instant::now() < deadline,
            "owned-tree leader did not become observable"
        );
        std::thread::yield_now();
    }

    inject_process_group_scan_entry_budget(0);
    assert_eq!(process.try_wait(), Err(HostPortError::PlatformFailure));
    assert_eq!(process.try_wait(), Err(HostPortError::DetachedEditor));
    assert_eq!(
        supervisor.take_process_wait_failure_diagnostic(lease.id(), 1),
        Some(ProcessWaitFailureDiagnostic {
            stage: ProcessWaitFailureStage::GroupScanDeadline,
            reason: ProcessWaitFailureReason::EnumerationEntryBudget,
            io_kind: std::io::ErrorKind::TimedOut,
            raw_os_error: None,
        })
    );

    supervisor.force_stop_all().unwrap();
    wait_for_exit(
        &supervisor,
        &lease,
        1,
        "diagnostic-descendant-force-stop",
        &mut *process,
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_wait_failure_diagnostic_retains_and_reclaims_its_exact_registry_key() {
    use notecrypt_platform_fs::workspace_test_support::inject_process_group_scan_entry_budget;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x60);
    let ready = workspace.with_extension("ready");
    let editor = fixture.editor("nonzero", "nvim");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor.clone(),
        workspace.clone(),
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&ready);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !supervisor
        .leader_exited_unreaped_for_test(lease.id(), 1)
        .unwrap()
    {
        assert!(
            Instant::now() < deadline,
            "quick-exit editor leader did not become observable"
        );
        std::thread::yield_now();
    }

    inject_process_group_scan_entry_budget(0);
    assert_eq!(process.try_wait(), Err(HostPortError::PlatformFailure));
    assert_eq!(
        wait_for_terminal(&supervisor, &lease, 1, "nonzero", &mut *process).code(),
        Some(17)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    assert_eq!(
        supervisor.take_process_wait_failure_diagnostic(lease.id(), 1),
        Some(ProcessWaitFailureDiagnostic {
            stage: ProcessWaitFailureStage::GroupScanDeadline,
            reason: ProcessWaitFailureReason::EnumerationEntryBudget,
            io_kind: std::io::ErrorKind::TimedOut,
            raw_os_error: None,
        })
    );

    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut relaunched = launch_expected(&supervisor, &lease, 1, request);
    assert_eq!(
        wait_for_terminal(&supervisor, &lease, 1, "nonzero-relaunch", &mut *relaunched).code(),
        Some(17)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn unsaved_delay_keeps_plaintext_owned_until_the_release_barrier() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x3d);
    let ready = workspace.with_extension("ready");
    let release = workspace.with_extension("release");
    let saved = workspace.with_extension("saved");
    let editor = fixture.editor("unsaved-delay", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&ready);

    assert!(!saved.exists());
    assert!(provider.remove_workspace(&lease).is_err());
    fs::write(release, b"release").unwrap();
    assert_eq!(
        wait_for_terminal(&supervisor, &lease, 1, "unsaved-delay", &mut *process).code(),
        Some(0)
    );
    assert!(saved.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn optional_metacharacter_arguments_are_rejected_before_spawn() {
    use std::ffi::OsString;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x3e);
    let argv = workspace.with_extension("argv");
    let shell_effect = fixture.root.path().join("must-not-exist");
    let injected = OsString::from(format!("$(touch {})", shell_effect.display()));
    let arguments = vec![
        OsString::from("semi;colon"),
        injected.clone(),
        OsString::from("literal space"),
    ];
    let editor = fixture.editor("argv", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request_with_arguments(
        &lease,
        editor,
        arguments,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::DetachedEditor)
    );
    assert!(!argv.exists());
    assert!(!shell_effect.exists());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn blocking_unowned_proxy_is_never_killed_or_treated_as_quiescent() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x32);
    let ready = workspace.with_extension("ready");
    let release = workspace.with_extension("release");
    let editor = fixture.editor("blocking", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&ready);

    supervisor.request_stop_all().unwrap();
    supervisor.force_stop_all().unwrap();
    assert!(!supervisor.poll_quiescence().unwrap().is_quiescent());
    assert_eq!(
        process.force_stop().err(),
        Some(HostPortError::DetachedEditor)
    );
    assert!(provider.remove_workspace(&lease).is_err());

    fs::write(release, b"release").unwrap();
    wait_for_exit(
        &supervisor,
        &lease,
        1,
        "blocking-unowned-release",
        &mut *process,
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn rejected_duplicate_launch_cannot_detach_the_winning_process_token() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x3f);
    let ready = workspace.with_extension("ready");
    let release = workspace.with_extension("release");
    let blocking_editor = fixture.editor("blocking", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &blocking_editor);
    let first = launch_request(
        &lease,
        blocking_editor.clone(),
        workspace.clone(),
        EditorSupervisionMode::Blocking,
        7,
    );
    let duplicate = launch_request(
        &lease,
        blocking_editor.clone(),
        workspace,
        EditorSupervisionMode::Blocking,
        7,
    );

    let mut winner = launch_expected(&supervisor, &lease, 7, first);
    wait_for_file(&ready);
    assert_eq!(
        supervisor.launch(duplicate).err(),
        Some(HostPortError::CapacityExceeded)
    );

    fs::write(release, b"release").unwrap();
    assert_eq!(
        wait_for_terminal(&supervisor, &lease, 7, "duplicate-winner", &mut *winner).code(),
        Some(0)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn supervisor_accepts_exact_capacity_and_rejects_max_plus_one_before_spawn() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (winning_lease, winning_workspace) = armed_workspace(&fixture, &provider, 0x43);
    let (rejected_lease, rejected_workspace) = armed_workspace(&fixture, &provider, 0x44);
    let winning_ready = winning_workspace.with_extension("ready");
    let winning_release = winning_workspace.with_extension("release");
    let rejected_ready = rejected_workspace.with_extension("ready");
    let editor = fixture.editor("blocking", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable_and_capacity(
        Arc::clone(&provider),
        editor.clone(),
        1,
    )
    .unwrap();

    let mut winner = launch_expected(
        &supervisor,
        &winning_lease,
        1,
        launch_request(
            &winning_lease,
            editor.clone(),
            winning_workspace,
            EditorSupervisionMode::Blocking,
            1,
        ),
    );
    wait_for_file(&winning_ready);

    assert_eq!(
        supervisor
            .launch(launch_request(
                &rejected_lease,
                editor,
                rejected_workspace,
                EditorSupervisionMode::Blocking,
                2,
            ))
            .err(),
        Some(HostPortError::CapacityExceeded)
    );
    assert!(!rejected_ready.exists());

    fs::write(winning_release, b"release").unwrap();
    assert_eq!(
        wait_for_terminal(
            &supervisor,
            &winning_lease,
            1,
            "capacity-winner",
            &mut *winner,
        )
        .code(),
        Some(0)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&winning_lease).unwrap());
    drop(provider.remove_workspace(&rejected_lease).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn one_linux_process_scan_reconciles_multiple_exited_owned_leaders_per_poll() {
    use notecrypt_platform_fs::workspace_test_support::take_process_group_scan_count;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (first_lease, first_workspace) = armed_workspace(&fixture, &provider, 0x45);
    let (second_lease, second_workspace) = armed_workspace(&fixture, &provider, 0x46);
    let first_ready = first_workspace.with_extension("ready");
    let second_ready = second_workspace.with_extension("ready");
    let editor = fixture.editor("normal", "nvim");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let mut first = launch_expected(
        &supervisor,
        &first_lease,
        1,
        launch_request(
            &first_lease,
            editor.clone(),
            first_workspace,
            EditorSupervisionMode::Blocking,
            1,
        ),
    );
    let mut second = launch_expected(
        &supervisor,
        &second_lease,
        2,
        launch_request(
            &second_lease,
            editor,
            second_workspace,
            EditorSupervisionMode::Blocking,
            2,
        ),
    );
    wait_for_file(&first_ready);
    wait_for_file(&second_ready);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        take_process_group_scan_count();
        let quiescence = supervisor.poll_quiescence().unwrap();
        assert!(
            take_process_group_scan_count() <= 1,
            "one quiescence callback must perform at most one /proc traversal"
        );
        if quiescence.is_quiescent() {
            break;
        }
        assert!(Instant::now() < deadline, "owned editors did not settle");
        std::thread::yield_now();
    }

    assert_eq!(
        wait_for_terminal(&supervisor, &first_lease, 1, "batch-first", &mut *first).code(),
        Some(0)
    );
    assert_eq!(
        wait_for_terminal(&supervisor, &second_lease, 2, "batch-second", &mut *second).code(),
        Some(0)
    );
    drop(provider.remove_workspace(&first_lease).unwrap());
    drop(provider.remove_workspace(&second_lease).unwrap());
}

#[test]
fn base_rename_and_replacement_is_rejected_immediately_before_spawn() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x33);
    let editor = fixture.editor("normal", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let moved = fixture.root.path().join("workspace-original");
    fs::rename(&fixture.base, &moved).unwrap();
    fs::create_dir(&fixture.base).unwrap();
    fs::set_permissions(&fixture.base, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::StaleCapability)
    );
    assert_eq!(
        supervisor.take_launch_failure_diagnostic(lease.id(), 1),
        Some(notecrypt_editor_workspace::EditorLaunchFailureDiagnostic {
            stage: EditorLaunchFailureStage::WorkspacePathRevalidation,
            error: HostPortError::StaleCapability,
            io_kind: None,
            raw_os_error: None,
        })
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn bounded_launch_diagnostics_reject_max_plus_one_and_reuse_consumed_slots() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (first_lease, first_workspace) = armed_workspace(&fixture, &provider, 0x45);
    let (second_lease, second_workspace) = armed_workspace(&fixture, &provider, 0x46);
    let (third_lease, third_workspace) = armed_workspace(&fixture, &provider, 0x47);
    let editor = fixture.editor("normal", "code");
    let supervisor = Arc::new(
        ProcessEditorSupervisor::new_with_trusted_test_executable_and_capacity(
            Arc::clone(&provider),
            editor.clone(),
            2,
        )
        .unwrap(),
    );
    let admission = Arc::new(Barrier::new(3));
    supervisor.install_launch_admission_barrier(Arc::clone(&admission));
    fs::write(&first_workspace, b"changed-first").unwrap();
    fs::write(&second_workspace, b"changed-second").unwrap();
    fs::write(&third_workspace, b"changed-third").unwrap();

    let first = launch_request(
        &first_lease,
        editor.clone(),
        first_workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let second = launch_request(
        &second_lease,
        editor.clone(),
        second_workspace,
        EditorSupervisionMode::Blocking,
        2,
    );
    let retry_editor = editor.clone();
    let retry_workspace = third_workspace.clone();
    let third = launch_request(
        &third_lease,
        editor,
        third_workspace,
        EditorSupervisionMode::Blocking,
        3,
    );
    let first_launch = {
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || supervisor.launch(first).err())
    };
    let second_launch = {
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || supervisor.launch(second).err())
    };

    admission.wait();
    supervisor.clear_launch_admission_barrier();
    assert_eq!(
        supervisor.launch(third).err(),
        Some(HostPortError::CapacityExceeded)
    );
    assert_eq!(
        first_launch.join().unwrap(),
        Some(HostPortError::StaleCapability)
    );
    assert_eq!(
        second_launch.join().unwrap(),
        Some(HostPortError::StaleCapability)
    );
    assert_eq!(
        supervisor.take_launch_failure_diagnostic(third_lease.id(), 3),
        None
    );

    for (lease, generation) in [(&first_lease, 1), (&second_lease, 2)] {
        assert_eq!(
            supervisor.take_launch_failure_diagnostic(lease.id(), generation),
            Some(notecrypt_editor_workspace::EditorLaunchFailureDiagnostic {
                stage: EditorLaunchFailureStage::WorkspacePathRevalidation,
                error: HostPortError::StaleCapability,
                io_kind: None,
                raw_os_error: None,
            })
        );
    }
    let third_retry = launch_request(
        &third_lease,
        retry_editor,
        retry_workspace,
        EditorSupervisionMode::Blocking,
        3,
    );
    assert_eq!(
        supervisor.launch(third_retry).err(),
        Some(HostPortError::StaleCapability)
    );
    assert_eq!(
        supervisor.take_launch_failure_diagnostic(third_lease.id(), 3),
        Some(notecrypt_editor_workspace::EditorLaunchFailureDiagnostic {
            stage: EditorLaunchFailureStage::WorkspacePathRevalidation,
            error: HostPortError::StaleCapability,
            io_kind: None,
            raw_os_error: None,
        })
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&first_lease).unwrap());
    drop(provider.remove_workspace(&second_lease).unwrap());
    drop(provider.remove_workspace(&third_lease).unwrap());
}

#[test]
fn executable_replacement_after_attestation_is_rejected_before_spawn() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x40);
    let ready = workspace.with_extension("ready");
    let editor = fixture.editor("normal", "code");
    let displaced = editor.with_extension("displaced");
    let supervisor = Arc::new(fixture.trusted_supervisor(&provider, &editor));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    supervisor.install_pre_revalidation_barrier(Arc::clone(&entered), Arc::clone(&release));
    let request = launch_request(
        &lease,
        editor.clone(),
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let launching = {
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || supervisor.launch(request).err())
    };

    entered.wait();
    fs::rename(&editor, displaced).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_test_editor"), &editor).unwrap();
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o700)).unwrap();
    release.wait();

    assert_eq!(
        launching.join().unwrap(),
        Some(HostPortError::StaleCapability)
    );
    assert_eq!(
        supervisor.take_launch_failure_diagnostic(lease.id(), 1),
        Some(notecrypt_editor_workspace::EditorLaunchFailureDiagnostic {
            stage: EditorLaunchFailureStage::ExecutableRevalidation,
            error: HostPortError::StaleCapability,
            io_kind: None,
            raw_os_error: None,
        })
    );
    assert!(!ready.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn initial_executable_attestation_io_failure_reports_its_exact_stage() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x43);
    let editor = fixture.editor("normal", "code");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor.clone(),
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    fs::remove_file(editor).unwrap();

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::Unavailable)
    );
    let diagnostic = supervisor
        .take_launch_failure_diagnostic(lease.id(), 1)
        .expect("initial attestation failure must retain a diagnostic");
    assert_eq!(
        diagnostic.stage,
        EditorLaunchFailureStage::ExecutableAttestation
    );
    assert_eq!(diagnostic.error, HostPortError::Unavailable);
    assert_eq!(diagnostic.io_kind, Some(std::io::ErrorKind::NotFound));
    assert!(diagnostic.raw_os_error.is_some());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn process_spawn_io_failure_reports_its_exact_stage() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x44);
    let editor = fixture.editor("normal", "code");
    let supervisor = Arc::new(fixture.trusted_supervisor(&provider, &editor));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    supervisor.install_pre_spawn_barrier(Arc::clone(&entered), Arc::clone(&release));
    let request = launch_request(
        &lease,
        editor.clone(),
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let launching = {
        let supervisor = Arc::clone(&supervisor);
        std::thread::spawn(move || supervisor.launch(request).err())
    };

    entered.wait();
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o600)).unwrap();
    release.wait();
    assert_eq!(launching.join().unwrap(), Some(HostPortError::Permission));
    let diagnostic = supervisor
        .take_launch_failure_diagnostic(lease.id(), 1)
        .expect("spawn failure must retain a diagnostic");
    assert_eq!(diagnostic.stage, EditorLaunchFailureStage::ProcessSpawn);
    assert_eq!(diagnostic.error, HostPortError::Permission);
    assert_eq!(
        diagnostic.io_kind,
        Some(std::io::ErrorKind::PermissionDenied)
    );
    assert!(diagnostic.raw_os_error.is_some());
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn writable_attested_helper_fails_closed_until_its_writer_is_dropped() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x4a);
    let staged = fixture.editor_with_open_writer("normal", "code");
    assert!(!staged.published_path.exists());
    assert!(exact_writable_file_descriptor(&staged.staged_path).is_some());
    let supervisor = fixture.trusted_supervisor(&provider, &staged.staged_path);
    let request = launch_request(
        &lease,
        staged.staged_path.clone(),
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::PlatformFailure)
    );
    let diagnostic = supervisor
        .take_launch_failure_diagnostic(lease.id(), 1)
        .expect("the writable helper must retain an exact spawn diagnostic");
    assert_eq!(diagnostic.stage, EditorLaunchFailureStage::ProcessSpawn);
    assert_eq!(diagnostic.error, HostPortError::PlatformFailure);
    assert_eq!(
        diagnostic.io_kind,
        Some(std::io::ErrorKind::ExecutableFileBusy)
    );
    assert_eq!(diagnostic.raw_os_error, Some(26));
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());

    let editor = fixture.publish_editor(staged);
    let (retry_lease, retry_workspace) = armed_workspace(&fixture, &provider, 0x4b);
    let retry = launch_request(
        &retry_lease,
        editor,
        retry_workspace,
        EditorSupervisionMode::Blocking,
        2,
    );
    let mut process = launch_expected(&supervisor, &retry_lease, 2, retry);
    assert_eq!(
        wait_for_terminal(
            &supervisor,
            &retry_lease,
            2,
            "writer-dropped-retry",
            &mut *process,
        )
        .code(),
        Some(0)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&retry_lease).unwrap());
}

#[test]
fn same_family_vi_alias_to_vim_basic_is_attested_and_launched() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x41);
    let canonical = fixture.editor("normal", "vim.basic");
    let alias = canonical.parent().unwrap().join("vi");
    std::os::unix::fs::symlink(&canonical, &alias).unwrap();
    let supervisor = fixture.trusted_supervisor(&provider, &canonical);
    let request = launch_request(&lease, alias, workspace, EditorSupervisionMode::Blocking, 1);

    let mut process = launch_expected(&supervisor, &lease, 1, request);
    assert_eq!(
        wait_for_terminal(&supervisor, &lease, 1, "vi-alias", &mut *process).code(),
        Some(0)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn cross_family_protected_alias_is_rejected_before_spawn() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x42);
    let ready = workspace.with_extension("ready");
    let canonical = fixture.editor("normal", "nvim");
    let alias = canonical.parent().unwrap().join("code");
    std::os::unix::fs::symlink(&canonical, &alias).unwrap();
    let supervisor = fixture.trusted_supervisor(&provider, &canonical);
    let request = launch_request(&lease, alias, workspace, EditorSupervisionMode::Blocking, 1);

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::DetachedEditor)
    );
    assert!(!ready.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn fake_known_basename_cannot_claim_blocking_profile_authority() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x34);
    let ready = workspace.with_extension("detached-ready");
    let supervisor = ProcessEditorSupervisor::new(Arc::clone(&provider)).unwrap();
    let request = launch_request(
        &lease,
        fixture.editor("detach", "nvim"),
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::Permission)
    );
    assert!(!ready.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn blocking_unknown_profile_is_rejected_before_the_detaching_helper_spawns() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x39);
    let ready = workspace.with_extension("detached-ready");
    let editor = fixture.editor("detach", "unknown-editor");
    let supervisor = fixture.trusted_supervisor(&provider, &editor);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::DetachedEditor)
    );
    assert!(!ready.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn strict_mode_fails_closed_before_a_trusted_helper_can_detach() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x38);
    let ready = workspace.with_extension("detached-ready");
    let editor = fixture.editor("detach", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    let request = launch_request(&lease, editor, workspace, EditorSupervisionMode::Strict, 1);

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::Unavailable)
    );
    assert!(!ready.exists());
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn blocking_owned_tree_ignores_graceful_stop_then_is_force_stopped_and_reaped() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x35);
    let ready = workspace.with_extension("ready");
    let editor = fixture.editor("ignore-termination", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&ready);

    supervisor.request_stop_all().unwrap();
    assert!(!supervisor.poll_quiescence().unwrap().is_quiescent());
    supervisor.force_stop_all().unwrap();
    wait_for_exit(
        &supervisor,
        &lease,
        1,
        "owned-tree-force-stop",
        &mut *process,
    );

    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn dropping_the_last_supervisor_owner_force_stops_and_reaps_an_owned_tree() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x3a);
    let ready = workspace.with_extension("ready");
    let editor = fixture.editor("ignore-termination", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&ready);

    drop(process);
    drop(supervisor);

    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn dropping_the_last_supervisor_owner_reaps_descendants_after_the_leader_exits() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x47);
    let child_ready = workspace.with_extension("descendant-ready");
    let editor = fixture.editor("child", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    supervisor.install_drop_reap_group_active_polls(1);
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&child_ready);

    wait_for_detached(
        &supervisor,
        &lease,
        1,
        "drop-descendant-after-leader-exit",
        &mut *process,
    );

    drop(process);
    drop(supervisor);

    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn supervisor_drop_reaping_is_not_bounded_by_the_legacy_poll_count() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x48);
    let ready = workspace.with_extension("ready");
    let editor = fixture.editor("ignore-termination", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    assert_eq!(
        supervisor.install_drop_reap_pending_polls(2_049),
        Err(HostPortError::CapacityExceeded)
    );
    supervisor.install_drop_reap_pending_polls(1_025).unwrap();
    let process = launch_expected(
        &supervisor,
        &lease,
        1,
        launch_request(
            &lease,
            editor,
            workspace,
            EditorSupervisionMode::Blocking,
            1,
        ),
    );
    wait_for_file(&ready);

    drop(process);
    drop(supervisor);

    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn supervisor_drop_deadline_retains_cleanup_authority_when_reaping_stays_unknown() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x49);
    let ready = workspace.with_extension("ready");
    let editor = fixture.editor("ignore-termination", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    supervisor.install_drop_reap_deadline_fault();
    let process = launch_expected(
        &supervisor,
        &lease,
        1,
        launch_request(
            &lease,
            editor,
            workspace.clone(),
            EditorSupervisionMode::Blocking,
            1,
        ),
    );
    wait_for_file(&ready);

    drop(process);
    drop(supervisor);

    assert_eq!(
        provider.remove_workspace(&lease).err(),
        Some(HostPortError::CleanupFailed)
    );
    assert!(workspace.exists());
}

#[test]
fn blocking_owned_tree_detects_descendant_after_leader_exit_and_kills_the_group() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x36);
    let child_ready = workspace.with_extension("descendant-ready");
    let editor = fixture.editor("child", "nvim");
    let supervisor = ProcessEditorSupervisor::new_with_trusted_test_executable(
        Arc::clone(&provider),
        editor.clone(),
    )
    .unwrap();
    let request = launch_request(
        &lease,
        editor,
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );
    let mut process = launch_expected(&supervisor, &lease, 1, request);
    wait_for_file(&child_ready);

    wait_for_detached(
        &supervisor,
        &lease,
        1,
        "owned-descendant-after-leader-exit",
        &mut *process,
    );
    supervisor.force_stop_all().unwrap();
    wait_for_exit(
        &supervisor,
        &lease,
        1,
        "owned-descendant-force-stop",
        &mut *process,
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn missing_executable_is_redacted_as_unavailable() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let (lease, workspace) = armed_workspace(&fixture, &provider, 0x37);
    let supervisor = ProcessEditorSupervisor::new(Arc::clone(&provider)).unwrap();
    let request = launch_request(
        &lease,
        fixture.root.path().join("missing").join("code"),
        workspace,
        EditorSupervisionMode::Blocking,
        1,
    );

    assert_eq!(
        supervisor.launch(request).err(),
        Some(HostPortError::Unavailable)
    );
    assert!(supervisor.poll_quiescence().unwrap().is_quiescent());
    drop(provider.remove_workspace(&lease).unwrap());
}
