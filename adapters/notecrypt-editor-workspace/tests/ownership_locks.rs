use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use notecrypt_editor_workspace::SecureWorkspaceProvider;
#[cfg(feature = "test-support")]
use notecrypt_editor_workspace::workspace_test_support::{
    IndexExclusionFailureStage, take_index_exclusion_failure_diagnostic,
};
#[cfg(feature = "test-support")]
use notecrypt_platform_fs::workspace_test_support::{
    WorkspaceFileSyncFault, inject_file_sync_fault,
};
use notecrypt_platform_fs::{Directory, PhysicalComponent};
use notecrypt_service::workspace_test_support::target_request;
use notecrypt_service::{HostPortError, WorkspaceProvider};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

const HELPER_MODE: &str = "NOTECRYPT_OWNERSHIP_HELPER_MODE";
const HELPER_BASE: &str = "NOTECRYPT_OWNERSHIP_HELPER_BASE";
const HELPER_REPOSITORY: &str = "NOTECRYPT_OWNERSHIP_HELPER_REPOSITORY";
const HELPER_LOCAL_STATE: &str = "NOTECRYPT_OWNERSHIP_HELPER_LOCAL_STATE";
const HELPER_READY: &str = "NOTECRYPT_OWNERSHIP_HELPER_READY";
const HELPER_RELEASE: &str = "NOTECRYPT_OWNERSHIP_HELPER_RELEASE";
const OWNED_WORKSPACE_ID: [u8; 16] = [0x11; 16];

struct Fixture {
    _root: TempDir,
    base: PathBuf,
    repository: PathBuf,
    local_state: PathBuf,
    ready: PathBuf,
    release: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("workspace-v1");
        let repository = root.path().join("repository");
        let local_state = root.path().join("local-state");
        for name in ["workspace-v1", "repository", "local-state"] {
            create_private_fixture_directory(root.path(), name);
        }
        Self {
            ready: root.path().join("ready"),
            release: root.path().join("release"),
            _root: root,
            base: fs::canonicalize(base).unwrap(),
            repository: fs::canonicalize(repository).unwrap(),
            local_state: fs::canonicalize(local_state).unwrap(),
        }
    }

    fn provider(&self) -> SecureWorkspaceProvider {
        SecureWorkspaceProvider::open(
            self.base.clone(),
            self.repository.clone(),
            self.local_state.clone(),
        )
        .unwrap_or_else(|error| {
            #[cfg(feature = "test-support")]
            let diagnostic = take_index_exclusion_failure_diagnostic();
            #[cfg(not(feature = "test-support"))]
            let diagnostic: Option<()> = None;
            panic!("provider open failed: error={error:?}, diagnostic={diagnostic:?}")
        })
    }

    fn spawn_helper(&self, mode: &str) -> Child {
        Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("ownership_process_helper")
            .arg("--nocapture")
            .env(HELPER_MODE, mode)
            .env(HELPER_BASE, &self.base)
            .env(HELPER_REPOSITORY, &self.repository)
            .env(HELPER_LOCAL_STATE, &self.local_state)
            .env(HELPER_READY, &self.ready)
            .env(HELPER_RELEASE, &self.release)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap()
    }
}

fn create_private_fixture_directory(parent: &Path, name: &str) {
    #[cfg(unix)]
    {
        let path = parent.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    {
        let parent = Directory::open_ambient(parent).unwrap();
        let component = PhysicalComponent::try_new(name).unwrap();
        drop(parent.create_private_dir(&component).unwrap());
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "subprocess barrier timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn helper_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).expect("helper path is configured"))
}

#[test]
fn ownership_process_helper() {
    let Some(mode) = env::var_os(HELPER_MODE) else {
        return;
    };
    let base = helper_path(HELPER_BASE);
    let repository = helper_path(HELPER_REPOSITORY);
    let local_state = helper_path(HELPER_LOCAL_STATE);
    let ready = helper_path(HELPER_READY);
    let release = helper_path(HELPER_RELEASE);

    if mode == "base-lock" {
        let base = Directory::open_ambient(&base).unwrap();
        let name = PhysicalComponent::try_new(".base-lock").unwrap();
        let _lock = base.try_lock_exclusive(&name).unwrap();
        fs::write(&ready, b"ready").unwrap();
        wait_for(&release);
        return;
    }

    assert_eq!(mode, "owned-workspace");
    let provider = SecureWorkspaceProvider::open(base, repository.clone(), local_state).unwrap();
    let request = target_request(OWNED_WORKSPACE_ID, [0x22; 16], repository).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    fs::write(&ready, b"ready").unwrap();
    wait_for(&release);
    drop(lease);
}

#[test]
fn base_lock_contention_is_observed_across_processes_and_releases_on_exit() {
    let fixture = Fixture::new();
    let mut helper = fixture.spawn_helper("base-lock");
    wait_for(&fixture.ready);

    let provider = fixture.provider();
    let request = target_request([0x33; 16], [0x44; 16], fixture.repository.clone()).unwrap();
    assert!(matches!(
        provider.create_target(request),
        Err(HostPortError::LiveWorkspace)
    ));

    fs::write(&fixture.release, b"release").unwrap();
    assert!(helper.wait().unwrap().success());
    let request = target_request([0x33; 16], [0x44; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let mut absence = provider.remove_workspace(&lease).unwrap();
    absence.finalize().unwrap();
}

#[test]
fn reopening_provider_authenticates_the_existing_index_exclusion_marker() {
    let fixture = Fixture::new();
    let first = fixture.provider();
    let base = Directory::open_ambient(&fixture.base).unwrap();
    let marker_name = Path::new(".metadata_never_index");
    let before = base
        .open_private_workspace_file_nofollow(marker_name)
        .unwrap();

    let second = fixture.provider();
    let after = base
        .open_private_workspace_file_nofollow(marker_name)
        .unwrap();

    assert!(before.same_identity(&after).unwrap());
    drop(second);
    drop(first);
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn strict_existing_marker_open_exposes_its_sync_authority_boundary() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let base = Directory::open_ambient(&fixture.base).unwrap();
    let marker = base
        .open_private_workspace_file_nofollow(Path::new(".metadata_never_index"))
        .unwrap();

    let error = marker
        .sync_all()
        .expect_err("the strict existing-marker handle is read-only on Windows");
    eprintln!(
        "strict existing-marker sync: kind={:?}, raw={:?}",
        error.kind(),
        error.raw_os_error()
    );
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.raw_os_error(), Some(5));
    drop(provider);
}

#[cfg(feature = "test-support")]
#[test]
fn marker_sync_failures_retain_the_exact_marker_for_provider_retry() {
    for fault in [
        WorkspaceFileSyncFault::BeforeEffect,
        WorkspaceFileSyncFault::AfterEffect,
    ] {
        let fixture = Fixture::new();
        inject_file_sync_fault(fault);
        assert_eq!(
            SecureWorkspaceProvider::open(
                fixture.base.clone(),
                fixture.repository.clone(),
                fixture.local_state.clone(),
            )
            .err(),
            Some(HostPortError::PlatformFailure)
        );
        let diagnostic = take_index_exclusion_failure_diagnostic()
            .expect("marker sync failure records its exact stage");
        assert_eq!(diagnostic.stage, IndexExclusionFailureStage::MarkerSync);
        assert_eq!(diagnostic.io_kind, std::io::ErrorKind::Other);
        assert_eq!(diagnostic.raw_os_error, None);

        let base = Directory::open_ambient(&fixture.base).unwrap();
        let marker_name = Path::new(".metadata_never_index");
        let retained = base
            .open_private_workspace_file_nofollow(marker_name)
            .expect("failed provider retains the exact private marker");
        let provider = fixture.provider();
        let retried = base
            .open_private_workspace_file_nofollow(marker_name)
            .expect("retry retains the exact marker name");
        assert!(retained.same_identity(&retried).unwrap());
        drop(provider);
    }
}

#[test]
fn live_owner_is_skipped_and_crashed_owner_is_cleaned_without_pid_trust() {
    let fixture = Fixture::new();
    let owner_name = format!("o-{}", "11".repeat(16));
    let owner_path = fixture.base.join(&owner_name);
    let owner_contents = b"pid=1\nstale metadata is not authority\n";
    let base = Directory::open_ambient(&fixture.base).unwrap();
    let owner_component = PhysicalComponent::try_new(&owner_name).unwrap();
    let mut owner_file = base.create_private_file_new(&owner_component).unwrap();
    owner_file.write_all(owner_contents).unwrap();
    owner_file.sync_all().unwrap();
    drop(owner_file);
    base.sync().unwrap();
    let mut helper = fixture.spawn_helper("owned-workspace");
    wait_for(&fixture.ready);

    let provider = fixture.provider();
    let live = provider.cleanup_owned_base().unwrap();
    assert_eq!(live.removed(), 0);
    assert_eq!(live.skipped_live(), 1);

    helper.kill().unwrap();
    let _ = helper.wait().unwrap();
    assert_eq!(fs::read(&owner_path).unwrap(), owner_contents);
    let stale = provider.cleanup_owned_base().unwrap();
    assert_eq!(stale.removed(), 1);
    assert_eq!(stale.skipped_live(), 0);
    assert_eq!(fs::read_dir(&fixture.base).unwrap().count(), 2);
}

#[test]
fn deterministic_base_and_owner_lock_name_substitution_is_rejected() {
    let fixture = Fixture::new();
    let directory = Directory::open_ambient(&fixture.base).unwrap();
    for (name, displaced) in [
        (".base-lock", ".displaced-base-lock"),
        (
            "o-11111111111111111111111111111111",
            ".displaced-owner-lock",
        ),
    ] {
        let component = PhysicalComponent::try_new(name).unwrap();
        let held = directory.try_lock_exclusive(&component).unwrap();
        #[cfg(unix)]
        {
            fs::rename(fixture.base.join(name), fixture.base.join(displaced)).unwrap();
            let replacement = directory.try_lock_exclusive(&component).unwrap();

            assert!(!held.validates_named_file(&directory, &component).unwrap());
            assert!(
                replacement
                    .validates_named_file(&directory, &component)
                    .unwrap()
            );
        }
        #[cfg(windows)]
        {
            assert!(fs::rename(fixture.base.join(name), fixture.base.join(displaced)).is_err());
            assert!(held.validates_named_file(&directory, &component).unwrap());
            let error = match directory.try_lock_exclusive(&component) {
                Ok(_) => panic!("live exact Windows lock must reject a second acquisition"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
    }
}

#[test]
fn provider_implements_the_service_owned_cleanup_contract() {
    fn assert_provider<T: WorkspaceProvider>() {}
    assert_provider::<SecureWorkspaceProvider>();

    let _constructor: fn(PathBuf, PathBuf, PathBuf) -> Result<SecureWorkspaceProvider, _> =
        SecureWorkspaceProvider::open;
}
