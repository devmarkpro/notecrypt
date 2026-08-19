use std::fs;
use std::path::PathBuf;

use notecrypt_editor_workspace::SecureWorkspaceProvider;
#[cfg(feature = "test-support")]
use notecrypt_editor_workspace::workspace_test_support::{
    MaterializationIoFault, inject_materialization_entropy_failure,
    inject_materialization_io_fault, toggle_awaiting_arm_suppression,
};
use notecrypt_platform_fs::Directory;
use notecrypt_platform_fs::workspace_test_support::{
    WorkspaceCleanupFault, WorkspaceDirectoryFault, WorkspacePublicationFault,
    inject_cleanup_fault, inject_directory_fault, inject_publication_fault, take_parent_sync_count,
};
use notecrypt_service::workspace_test_support::{inject_allocation_failure_after, target_request};
use notecrypt_service::{LogicalWorkspacePath, MaterializationPublication, WorkspaceProvider};
#[cfg(feature = "test-support")]
use notecrypt_service::{MaterializationTarget, WorkspaceLease};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _root: TempDir,
    base: PathBuf,
    repository: PathBuf,
    local_state: PathBuf,
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
        let base = fs::canonicalize(base).unwrap();
        let repository = fs::canonicalize(repository).unwrap();
        let local_state = fs::canonicalize(local_state).unwrap();
        Self {
            _root: root,
            base,
            repository,
            local_state,
        }
    }

    fn provider(&self) -> SecureWorkspaceProvider {
        Directory::open_ambient(&self.base)
            .unwrap()
            .verify_private()
            .unwrap();
        Directory::open_ambient(&self.repository).unwrap();
        Directory::open_ambient(&self.local_state).unwrap();
        SecureWorkspaceProvider::open(
            self.base.clone(),
            self.repository.clone(),
            self.local_state.clone(),
        )
        .unwrap()
    }
}

fn create_private_fixture_directory(parent: &std::path::Path, name: &str) {
    #[cfg(unix)]
    {
        let path = parent.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    {
        let parent = Directory::open_ambient(parent).unwrap();
        let component = notecrypt_platform_fs::PhysicalComponent::try_new(name).unwrap();
        drop(parent.create_private_dir(&component).unwrap());
    }
}

#[cfg(feature = "test-support")]
fn publish_and_arm(
    provider: &SecureWorkspaceProvider,
    lease: &WorkspaceLease,
    target: MaterializationTarget,
) {
    let mut published = match provider.publish_materialized(lease, target).unwrap() {
        MaterializationPublication::Durable(published) => published,
        MaterializationPublication::DurabilityPending(mut pending) => {
            provider.confirm_materialized(lease, &mut pending).unwrap()
        }
    };
    provider.arm_published_path(lease, &mut published).unwrap();
}

#[test]
fn provider_rejects_relative_noncanonical_and_symlinked_base_names() {
    let fixture = Fixture::new();
    let marker = fixture.base.join(".metadata_never_index");
    assert!(!marker.exists());
    assert!(
        SecureWorkspaceProvider::open(
            PathBuf::from("workspace-v1"),
            fixture.repository.clone(),
            fixture.local_state.clone(),
        )
        .is_err()
    );
    assert!(!marker.exists());

    let mut dot_spelling = fixture.base.as_os_str().to_os_string();
    dot_spelling.push(std::path::MAIN_SEPARATOR_STR);
    dot_spelling.push(".");
    let dot_component = PathBuf::from(dot_spelling);
    assert_ne!(dot_component.as_os_str(), fixture.base.as_os_str());
    assert!(
        SecureWorkspaceProvider::open(
            dot_component,
            fixture.repository.clone(),
            fixture.local_state.clone(),
        )
        .is_err()
    );
    assert!(!marker.exists());

    let mut parent_spelling = fixture.base.as_os_str().to_os_string();
    parent_spelling.push(std::path::MAIN_SEPARATOR_STR);
    parent_spelling.push("..");
    parent_spelling.push(std::path::MAIN_SEPARATOR_STR);
    parent_spelling.push("workspace-v1");
    let noncanonical = PathBuf::from(parent_spelling);
    assert_ne!(noncanonical.as_os_str(), fixture.base.as_os_str());
    assert!(
        noncanonical
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    );
    assert!(
        SecureWorkspaceProvider::open(
            noncanonical,
            fixture.repository.clone(),
            fixture.local_state.clone(),
        )
        .is_err()
    );
    assert!(!marker.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let alias = fixture.base.parent().unwrap().join("workspace-alias");
        symlink(&fixture.base, &alias).unwrap();
        assert!(
            SecureWorkspaceProvider::open(
                alias,
                fixture.repository.clone(),
                fixture.local_state.clone(),
            )
            .is_err()
        );
        assert!(!marker.exists());
    }
}

#[test]
fn rejected_root_aliases_do_not_mutate_any_protected_root() {
    let same = Fixture::new();
    let before = directory_entries(&same.repository);
    assert!(
        SecureWorkspaceProvider::open(
            same.repository.clone(),
            same.repository.clone(),
            same.local_state.clone(),
        )
        .is_err()
    );
    assert_eq!(directory_entries(&same.repository), before);

    let nested = Fixture::new();
    let nested_repository = nested.base.join("nested-repository");
    fs::create_dir(&nested_repository).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&nested_repository, fs::Permissions::from_mode(0o700)).unwrap();
    let nested_repository = fs::canonicalize(nested_repository).unwrap();
    let before_base = directory_entries(&nested.base);
    let before_repository = directory_entries(&nested_repository);
    assert!(
        SecureWorkspaceProvider::open(
            nested.base.clone(),
            nested_repository.clone(),
            nested.local_state.clone(),
        )
        .is_err()
    );
    assert_eq!(directory_entries(&nested.base), before_base);
    assert_eq!(directory_entries(&nested_repository), before_repository);

    let inverse = Fixture::new();
    let nested_base = inverse.repository.join("nested-workspace");
    fs::create_dir(&nested_base).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&nested_base, fs::Permissions::from_mode(0o700)).unwrap();
    let nested_base = fs::canonicalize(nested_base).unwrap();
    let before_repository = directory_entries(&inverse.repository);
    let before_base = directory_entries(&nested_base);
    assert!(
        SecureWorkspaceProvider::open(
            nested_base.clone(),
            inverse.repository.clone(),
            inverse.local_state.clone(),
        )
        .is_err()
    );
    assert_eq!(directory_entries(&inverse.repository), before_repository);
    assert_eq!(directory_entries(&nested_base), before_base);
}

fn directory_entries(path: &std::path::Path) -> Vec<std::ffi::OsString> {
    let mut entries = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[test]
fn dropped_unactivated_lease_becomes_retryable_provider_cleanup() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x19; 16], [0x20; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    let root = lease.root().to_path_buf();
    assert!(root.exists());

    drop(lease);

    let report = provider.cleanup_owned_base().unwrap();
    assert_eq!(report.removed(), 1);
    assert_eq!(report.skipped_live(), 0);
    assert!(!root.exists());
    let contender = fixture.provider();
    assert_eq!(contender.cleanup_owned_base().unwrap().skipped_live(), 0);
}

#[cfg(unix)]
#[test]
fn base_replacement_prevents_publication_from_returning_a_stale_ambient_path() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x29; 16], [0x30; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("renamed base.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"old handle only").unwrap();

    let retained = fixture.base.with_file_name("workspace-retained");
    fs::rename(&fixture.base, &retained).unwrap();
    fs::create_dir(&fixture.base).unwrap();
    fs::set_permissions(&fixture.base, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(provider.publish_materialized(&lease, target).is_err());
    assert!(!fixture.base.join("29".repeat(16)).exists());
}

#[test]
fn workspace_is_a_private_opaque_direct_child_and_base_lock_spans_activation() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x2a; 16], [0x31; 16], fixture.repository.clone()).unwrap();

    let lease = provider.create_target(request).unwrap();

    assert_eq!(lease.root().parent(), Some(fixture.base.as_path()));
    assert_eq!(lease.root().file_name().unwrap(), "2a".repeat(16).as_str());
    assert!(!lease.root().to_string_lossy().contains("secret-note"));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(lease.root()).unwrap().permissions().mode() & 0o077,
        0
    );

    let contender = fixture.provider();
    assert!(contender.cleanup_owned_base().is_err());

    provider.confirm_activated(&lease).unwrap();
    let report = contender.cleanup_owned_base().unwrap();
    assert_eq!(report.removed(), 0);
    assert_eq!(report.skipped_live(), 1);

    let absence = provider.remove_workspace(&lease).unwrap();
    assert!(!fixture.base.join("2a".repeat(16)).exists());
    drop(absence);
}

#[test]
fn materialization_uses_private_staging_and_atomic_no_replace_publication() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x4b; 16], [0x51; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("notes/Confidential Note.md")).unwrap();

    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"private bytes").unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(target.staging_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let mut published = match provider.publish_materialized(&lease, target).unwrap() {
        MaterializationPublication::Durable(published) => published,
        MaterializationPublication::DurabilityPending(_) => {
            panic!("ordinary publication unexpectedly remained durability-pending")
        }
    };
    assert_eq!(published.generation(), 1);
    assert_eq!(fs::read(published.path()).unwrap(), b"private bytes");
    provider.arm_published_path(&lease, &mut published).unwrap();

    let raced_logical =
        LogicalWorkspacePath::new(PathBuf::from("notes/Raced Destination.md")).unwrap();
    let replacement = provider
        .materialization_target(&lease, &raced_logical)
        .unwrap();
    fs::write(
        lease.root().join("notes/Raced Destination.md"),
        b"raced destination",
    )
    .unwrap();
    assert!(provider.publish_materialized(&lease, replacement).is_err());
    assert_eq!(
        fs::read(lease.root().join("notes/Raced Destination.md")).unwrap(),
        b"raced destination"
    );

    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn nested_workspace_directory_sync_failure_is_retryable_before_publication() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x4c; 16], [0x52; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical =
        LogicalWorkspacePath::new(PathBuf::from("first level/second level/note.md")).unwrap();

    inject_directory_fault(WorkspaceDirectoryFault::ParentSync);
    assert!(provider.materialization_target(&lease, &logical).is_err());
    assert!(
        !lease
            .root()
            .join("first level/second level/note.md")
            .exists()
    );

    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"durable path").unwrap();
    let publication = provider.publish_materialized(&lease, target).unwrap();
    let mut published = match publication {
        MaterializationPublication::Durable(published) => published,
        MaterializationPublication::DurabilityPending(mut pending) => {
            provider.confirm_materialized(&lease, &mut pending).unwrap()
        }
    };
    provider.arm_published_path(&lease, &mut published).unwrap();
    assert_eq!(
        fs::read(lease.root().join("first level/second level/note.md")).unwrap(),
        b"durable path"
    );
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn durable_shared_prefix_is_not_resynchronized_for_each_materialization() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x6a; 16], [0x6b; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let first = LogicalWorkspacePath::new(PathBuf::from("shared/first.md")).unwrap();
    let second = LogicalWorkspacePath::new(PathBuf::from("shared/second.md")).unwrap();

    take_parent_sync_count();
    let first_target = provider.materialization_target(&lease, &first).unwrap();
    assert_eq!(take_parent_sync_count(), 1);
    drop(first_target);

    let second_target = provider.materialization_target(&lease, &second).unwrap();
    assert_eq!(take_parent_sync_count(), 0);
    drop(second_target);

    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(feature = "test-support")]
#[test]
fn materialization_io_and_entropy_faults_preserve_exact_retry_ownership() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x6c; 16], [0x6d; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();

    for (index, fault) in [
        MaterializationIoFault::ShortWrite,
        MaterializationIoFault::InterruptedWrite,
    ]
    .into_iter()
    .enumerate()
    {
        let logical =
            LogicalWorkspacePath::new(PathBuf::from(format!("write-{index}.md"))).unwrap();
        let mut target = provider.materialization_target(&lease, &logical).unwrap();
        inject_materialization_io_fault(fault);
        target
            .writer_mut()
            .write_all(b"complete plaintext")
            .unwrap();
        publish_and_arm(&provider, &lease, target);
        assert_eq!(
            fs::read(lease.root().join(logical.as_path())).unwrap(),
            b"complete plaintext"
        );
    }

    let zero = LogicalWorkspacePath::new(PathBuf::from("zero-progress.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &zero).unwrap();
    inject_materialization_io_fault(MaterializationIoFault::ZeroProgress);
    assert!(target.writer_mut().write_all(b"plaintext").is_err());
    drop(target);
    drop(provider.materialization_target(&lease, &zero).unwrap());

    let flush = LogicalWorkspacePath::new(PathBuf::from("flush-failure.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &flush).unwrap();
    target.writer_mut().write_all(b"plaintext").unwrap();
    inject_materialization_io_fault(MaterializationIoFault::Flush);
    assert!(provider.publish_materialized(&lease, target).is_err());
    drop(provider.materialization_target(&lease, &flush).unwrap());

    let sync = LogicalWorkspacePath::new(PathBuf::from("sync-failure.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &sync).unwrap();
    target.writer_mut().write_all(b"plaintext").unwrap();
    inject_materialization_io_fault(MaterializationIoFault::FileSync);
    assert!(provider.publish_materialized(&lease, target).is_err());
    let mut retry = provider.materialization_target(&lease, &sync).unwrap();
    retry.writer_mut().write_all(b"retried plaintext").unwrap();
    publish_and_arm(&provider, &lease, retry);

    let entropy = LogicalWorkspacePath::new(PathBuf::from("entropy-failure.md")).unwrap();
    inject_materialization_entropy_failure();
    assert!(provider.materialization_target(&lease, &entropy).is_err());
    assert!(!lease.root().join(entropy.as_path()).exists());
    drop(provider.materialization_target(&lease, &entropy).unwrap());

    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn nested_mount_boundary_is_rejected_before_plaintext_file_creation() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x4d; 16], [0x53; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("mounted/note.md")).unwrap();

    inject_directory_fault(WorkspaceDirectoryFault::MountBoundary);
    assert!(provider.materialization_target(&lease, &logical).is_err());
    assert!(!lease.root().join("mounted/note.md").exists());

    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires NOTECRYPT_RUN_PRIVILEGED_BIND_MOUNT_EZE=1 and CAP_SYS_ADMIN"]
fn real_bind_mount_boundary_is_rejected_before_plaintext_file_creation() {
    assert_eq!(
        std::env::var_os("NOTECRYPT_RUN_PRIVILEGED_BIND_MOUNT_EZE").as_deref(),
        Some(std::ffi::OsStr::new("1")),
        "privileged bind-mount EZE opt-in must be exactly 1"
    );

    struct BindMount {
        target: PathBuf,
    }

    impl Drop for BindMount {
        fn drop(&mut self) {
            let status = std::process::Command::new("/bin/umount")
                .arg(&self.target)
                .status()
                .expect("Linux runner must provide umount for the bind-mount EZE");
            assert!(status.success(), "bind-mount EZE cleanup must unmount");
        }
    }

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x4f; 16], [0x55; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    create_private_fixture_directory(fixture._root.path(), "external-bind-source");
    let external = fixture._root.path().join("external-bind-source");
    fs::create_dir(lease.root().join("mounted")).unwrap();
    fs::set_permissions(
        lease.root().join("mounted"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let status = std::process::Command::new("/bin/mount")
        .arg("--bind")
        .arg(&external)
        .arg(lease.root().join("mounted"))
        .status()
        .expect("Linux runner must provide mount for the bind-mount EZE");
    assert!(
        status.success(),
        "Linux runner must grant bind-mount capability for this security EZE"
    );
    let mount = BindMount {
        target: lease.root().join("mounted"),
    };
    let logical = LogicalWorkspacePath::new(PathBuf::from("mounted/note.md")).unwrap();

    assert!(provider.materialization_target(&lease, &logical).is_err());
    assert!(!external.join("note.md").exists());

    drop(mount);
    fs::remove_dir(lease.root().join("mounted")).unwrap();
    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(windows)]
#[test]
fn nested_reparse_boundary_is_rejected_before_plaintext_file_creation() {
    use std::os::windows::fs::symlink_dir;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x4e; 16], [0x54; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    create_private_fixture_directory(fixture._root.path(), "external");
    let external = fixture._root.path().join("external");
    let mounted = lease.root().join("mounted");
    symlink_dir(&external, &mounted).expect("Windows runner must permit reparse-point EZE setup");
    let logical = LogicalWorkspacePath::new(PathBuf::from("mounted/note.md")).unwrap();

    assert!(provider.materialization_target(&lease, &logical).is_err());
    assert!(!external.join("note.md").exists());

    fs::remove_dir(&mounted).unwrap();
    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(unix)]
#[test]
fn pending_publication_reconciles_absent_and_exact_two_name_ambiguity() {
    for (index, fault) in [
        WorkspacePublicationFault::PublishedThenDestinationAbsent,
        WorkspacePublicationFault::PublishedWithRetainedStage,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let provider = fixture.provider();
        let id = 0x80_u8 + u8::try_from(index).unwrap();
        let request = target_request([id; 16], [0x52; 16], fixture.repository.clone()).unwrap();
        let lease = provider.create_target(request).unwrap();
        provider.confirm_activated(&lease).unwrap();
        let logical = LogicalWorkspacePath::new(PathBuf::from("notes/pending.md")).unwrap();
        let mut target = provider.materialization_target(&lease, &logical).unwrap();
        target.writer_mut().write_all(b"pending plaintext").unwrap();
        inject_publication_fault(fault);
        let mut pending = match provider.publish_materialized(&lease, target).unwrap() {
            MaterializationPublication::DurabilityPending(pending) => pending,
            MaterializationPublication::Durable(_) => {
                panic!("injected ambiguous publication incorrectly reported durable")
            }
        };

        let mut published = provider.confirm_materialized(&lease, &mut pending).unwrap();
        assert!(pending.is_spent());
        assert_eq!(fs::read(published.path()).unwrap(), b"pending plaintext");
        provider.arm_published_path(&lease, &mut published).unwrap();
        drop(provider.remove_workspace(&lease).unwrap());
    }
}

#[cfg(windows)]
#[test]
fn pending_publication_reconciles_an_exact_moved_destination() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x80; 16], [0x52; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("notes/pending.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"pending plaintext").unwrap();
    inject_publication_fault(WorkspacePublicationFault::PublishedAfterMove);
    let mut pending = match provider.publish_materialized(&lease, target).unwrap() {
        MaterializationPublication::DurabilityPending(pending) => pending,
        MaterializationPublication::Durable(_) => {
            panic!("injected Windows move ambiguity incorrectly reported durable")
        }
    };

    let mut published = provider.confirm_materialized(&lease, &mut pending).unwrap();
    assert!(pending.is_spent());
    assert_eq!(fs::read(published.path()).unwrap(), b"pending plaintext");
    provider.arm_published_path(&lease, &mut published).unwrap();
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn pending_token_allocation_failure_leaves_no_unowned_staging_file() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x82; 16], [0x53; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("allocation.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target
        .writer_mut()
        .write_all(b"allocation plaintext")
        .unwrap();
    let staging = target.staging_path().to_path_buf();
    inject_allocation_failure_after(0);

    assert!(matches!(
        provider.publish_materialized(&lease, target),
        Err(notecrypt_service::HostPortError::AllocationFailed)
    ));
    assert!(!staging.exists());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn failed_arm_retains_the_same_linear_token_for_exact_retry() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x83; 16], [0x54; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("arm-retry.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"arm plaintext").unwrap();
    let mut published = match provider.publish_materialized(&lease, target).unwrap() {
        MaterializationPublication::Durable(published) => published,
        MaterializationPublication::DurabilityPending(_) => {
            panic!("ordinary publication unexpectedly remained durability-pending")
        }
    };
    let destination = published.path().to_path_buf();
    let retained = destination.with_extension("retained");
    fs::rename(&destination, &retained).unwrap();
    fs::write(&destination, b"foreign bytes").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(provider.arm_published_path(&lease, &mut published).is_err());
    assert!(!published.is_armed());
    fs::remove_file(&destination).unwrap();
    fs::rename(&retained, &destination).unwrap();
    provider.arm_published_path(&lease, &mut published).unwrap();
    assert!(published.is_armed());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(feature = "test-support")]
#[test]
fn arming_rejects_cross_lease_suppression_mismatch_and_replay_without_spending_early() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let first = target_request([0x84; 16], [0x55; 16], fixture.repository.clone()).unwrap();
    let second = target_request([0x85; 16], [0x55; 16], fixture.repository.clone()).unwrap();
    let first_lease = provider.create_target(first).unwrap();
    provider.confirm_activated(&first_lease).unwrap();
    let second_lease = provider.create_target(second).unwrap();
    provider.confirm_activated(&second_lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("arm-identity.md")).unwrap();
    let mut target = provider
        .materialization_target(&first_lease, &logical)
        .unwrap();
    target
        .writer_mut()
        .write_all(b"identity plaintext")
        .unwrap();
    let mut published = match provider.publish_materialized(&first_lease, target).unwrap() {
        MaterializationPublication::Durable(published) => published,
        MaterializationPublication::DurabilityPending(_) => {
            panic!("ordinary publication unexpectedly remained durability-pending")
        }
    };

    assert_eq!(
        provider
            .arm_published_path(&second_lease, &mut published)
            .err(),
        Some(notecrypt_service::HostPortError::StaleCapability)
    );
    assert!(!published.is_armed());

    toggle_awaiting_arm_suppression(&provider, &published).unwrap();
    assert_eq!(
        provider
            .arm_published_path(&first_lease, &mut published)
            .err(),
        Some(notecrypt_service::HostPortError::StaleCapability)
    );
    assert!(!published.is_armed());
    toggle_awaiting_arm_suppression(&provider, &published).unwrap();

    provider
        .arm_published_path(&first_lease, &mut published)
        .unwrap();
    assert!(published.is_armed());
    assert_eq!(
        provider
            .arm_published_path(&first_lease, &mut published)
            .err(),
        Some(notecrypt_service::HostPortError::StaleCapability)
    );

    drop(provider.remove_workspace(&first_lease).unwrap());
    drop(provider.remove_workspace(&second_lease).unwrap());
}

#[test]
fn materialization_requires_activation_and_live_writer_blocks_removal() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x6d; 16], [0x71; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("Draft With Spaces.md")).unwrap();

    assert!(provider.materialization_target(&lease, &logical).is_err());
    provider.confirm_activated(&lease).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target.writer_mut().write_all(b"still held").unwrap();

    assert!(provider.remove_workspace(&lease).is_err());
    assert!(lease.root().exists());
    drop(target);

    drop(provider.remove_workspace(&lease).unwrap());
    assert!(!lease.root().exists());
}

#[test]
fn abandoning_a_target_removes_its_exact_private_staging_file() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x8a; 16], [0x8b; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("notes/abandoned draft.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target
        .writer_mut()
        .write_all(b"abandoned plaintext")
        .unwrap();
    let staging = target.staging_path().to_path_buf();
    assert!(staging.exists());

    drop(target);

    assert!(!staging.exists());
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn one_destination_has_at_most_one_live_staging_file() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x91; 16], [0x92; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("duplicate.md")).unwrap();

    let target = provider.materialization_target(&lease, &logical).unwrap();
    assert!(matches!(
        provider.materialization_target(&lease, &logical),
        Err(notecrypt_service::HostPortError::DestinationExists)
    ));
    let staging_count = fs::read_dir(lease.root())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("s-"))
        .count();
    assert_eq!(staging_count, 1);

    drop(target);
    drop(provider.remove_workspace(&lease).unwrap());
}

#[test]
fn post_create_private_file_failure_cleans_or_retains_one_exact_stage() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x95; 16], [0x96; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let cleaned = LogicalWorkspacePath::new(PathBuf::from("cleaned.md")).unwrap();

    inject_directory_fault(WorkspaceDirectoryFault::PrivateFileAfterCreate);
    assert!(provider.materialization_target(&lease, &cleaned).is_err());
    assert_eq!(staging_file_count(lease.root()), 0);
    drop(provider.materialization_target(&lease, &cleaned).unwrap());

    let retained = LogicalWorkspacePath::new(PathBuf::from("retained.md")).unwrap();
    inject_directory_fault(WorkspaceDirectoryFault::PrivateFileAfterCreate);
    inject_cleanup_fault(WorkspaceCleanupFault::StagingUnlinkBeforeEffect);
    assert!(provider.materialization_target(&lease, &retained).is_err());
    #[cfg(not(windows))]
    assert_eq!(staging_file_count(lease.root()), 1);
    #[cfg(not(windows))]
    assert!(matches!(
        provider.materialization_target(&lease, &retained),
        Err(notecrypt_service::HostPortError::DestinationExists)
    ));
    #[cfg(not(windows))]
    assert_eq!(staging_file_count(lease.root()), 1);

    #[cfg(windows)]
    {
        assert_eq!(staging_file_count(lease.root()), 0);
        let retry = provider.materialization_target(&lease, &retained).unwrap();
        drop(retry);
        assert_eq!(staging_file_count(lease.root()), 1);
        assert!(matches!(
            provider.materialization_target(&lease, &retained),
            Err(notecrypt_service::HostPortError::DestinationExists)
        ));
    }

    drop(provider.remove_workspace(&lease).unwrap());
}

#[cfg(feature = "test-support")]
#[test]
fn exact_workspace_path_budget_is_reserved_before_namespace_effects() {
    use notecrypt_editor_workspace::workspace_test_support::seed_workspace_budget;
    use notecrypt_service::{MAX_WORKSPACE_PATHS, MAX_WORKSPACE_PHYSICAL_ENTRIES};

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x93; 16], [0x94; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();

    seed_workspace_budget(
        &provider,
        &lease,
        MAX_WORKSPACE_PATHS - 1,
        MAX_WORKSPACE_PHYSICAL_ENTRIES - 2,
    );
    let last = LogicalWorkspacePath::new(PathBuf::from("last.md")).unwrap();
    drop(provider.materialization_target(&lease, &last).unwrap());
    let rejected = LogicalWorkspacePath::new(PathBuf::from("rejected/new.md")).unwrap();
    assert!(matches!(
        provider.materialization_target(&lease, &rejected),
        Err(notecrypt_service::HostPortError::CapacityExceeded)
    ));
    assert!(!lease.root().join("rejected").exists());

    drop(provider.remove_workspace(&lease).unwrap());

    let physical_fixture = Fixture::new();
    let physical_provider = physical_fixture.provider();
    let physical_request =
        target_request([0x97; 16], [0x98; 16], physical_fixture.repository.clone()).unwrap();
    let physical_lease = physical_provider.create_target(physical_request).unwrap();
    physical_provider
        .confirm_activated(&physical_lease)
        .unwrap();
    seed_workspace_budget(
        &physical_provider,
        &physical_lease,
        0,
        MAX_WORKSPACE_PHYSICAL_ENTRIES - 1,
    );
    let physical_overflow = LogicalWorkspacePath::new(PathBuf::from("physical.md")).unwrap();
    assert!(matches!(
        physical_provider.materialization_target(&physical_lease, &physical_overflow),
        Err(notecrypt_service::HostPortError::CapacityExceeded)
    ));
    assert!(!physical_lease.root().join("physical.md").exists());
    drop(physical_provider.remove_workspace(&physical_lease).unwrap());
}

fn staging_file_count(root: &std::path::Path) -> usize {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("s-"))
        .count()
}

#[cfg(unix)]
#[test]
fn cleanup_owned_base_retries_the_same_providers_failed_exact_removal() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0x9a; 16], [0x9b; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let escaped = lease.root().join("rejected-link");
    symlink(&fixture.repository, &escaped).unwrap();

    assert!(provider.remove_workspace(&lease).is_err());
    assert!(lease.root().exists());

    fs::remove_file(escaped).unwrap();
    let report = provider.cleanup_owned_base().unwrap();

    assert_eq!(report.removed(), 1);
    assert_eq!(report.skipped_live(), 0);
    assert!(!lease.root().exists());
    assert!(!fixture.base.join(format!("o-{}", "9a".repeat(16))).exists());
}

#[cfg(unix)]
#[test]
fn absence_sidecar_substitution_remains_permanently_fail_closed() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0xaa; 16], [0xab; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let owner = fixture.base.join(format!("o-{}", "aa".repeat(16)));
    let mut absence = provider.remove_workspace(&lease).unwrap();

    fs::remove_file(&owner).unwrap();
    fs::create_dir(&owner).unwrap();
    assert!(absence.finalize().is_err());
    assert!(fixture.provider().cleanup_owned_base().is_err());

    fs::remove_dir(&owner).unwrap();
    assert!(absence.finalize().is_err());
    drop(absence);
    assert!(!owner.exists());
    assert_eq!(
        fixture.provider().cleanup_owned_base().unwrap().removed(),
        0
    );
}

#[cfg(unix)]
#[test]
fn ordinary_absence_sidecar_unlink_failure_retries_the_same_exact_lock() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0xac; 16], [0xad; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let owner = fixture.base.join(format!("o-{}", "ac".repeat(16)));
    let mut absence = provider.remove_workspace(&lease).unwrap();

    fs::set_permissions(&fixture.base, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(absence.finalize().is_err());
    fs::set_permissions(&fixture.base, fs::Permissions::from_mode(0o700)).unwrap();

    absence.finalize().unwrap();
    assert!(!owner.exists());
}

#[test]
fn dropped_absence_guard_never_finalizes_before_authenticated_unregister() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0xae; 16], [0xaf; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let owner = fixture.base.join(format!("o-{}", "ae".repeat(16)));

    let absence = provider.remove_workspace(&lease).unwrap();
    assert!(!lease.root().exists());
    assert!(owner.exists());

    drop(absence);
    assert!(owner.exists());

    let mut retry = provider.acquire_verified_absence(lease.id()).unwrap();
    retry.finalize().unwrap();
    assert!(!owner.exists());
}

#[test]
fn tree_removal_before_and_after_effect_failures_retry_the_exact_workspace() {
    for (id, fault, root_remains_after_failure) in [
        (
            [0xb0; 16],
            WorkspaceCleanupFault::TreeRemoveBeforeEffect,
            true,
        ),
        (
            [0xb1; 16],
            WorkspaceCleanupFault::TreeAbsenceReadbackAfterEffect,
            false,
        ),
        (
            [0xb5; 16],
            WorkspaceCleanupFault::DirectorySyncAfterEffect,
            false,
        ),
    ] {
        let fixture = Fixture::new();
        let provider = fixture.provider();
        let request = target_request(id, [0xb2; 16], fixture.repository.clone()).unwrap();
        let lease = provider.create_target(request).unwrap();
        provider.confirm_activated(&lease).unwrap();
        let root = lease.root().to_path_buf();

        inject_cleanup_fault(fault);
        assert!(provider.remove_workspace(&lease).is_err());
        assert_eq!(root.exists(), root_remains_after_failure);

        let report = provider.cleanup_owned_base().unwrap();
        assert_eq!(report.removed(), 1);
        assert!(!root.exists());
    }
}

#[test]
fn owner_unlink_before_and_after_effect_failures_retry_the_exact_guard() {
    for (id, fault, owner_remains_after_failure) in [
        (
            [0xb3; 16],
            WorkspaceCleanupFault::OwnerUnlinkBeforeEffect,
            true,
        ),
        (
            [0xb4; 16],
            WorkspaceCleanupFault::DirectorySyncAfterEffect,
            cfg!(windows),
        ),
    ] {
        let fixture = Fixture::new();
        let provider = fixture.provider();
        let request = target_request(id, [0xb5; 16], fixture.repository.clone()).unwrap();
        let lease = provider.create_target(request).unwrap();
        provider.confirm_activated(&lease).unwrap();
        let owner = fixture.base.join(format!("o-{}", format_id(id)));
        let mut absence = provider.remove_workspace(&lease).unwrap();

        inject_cleanup_fault(fault);
        assert!(absence.finalize().is_err());
        assert_eq!(owner.exists(), owner_remains_after_failure);

        absence.finalize().unwrap();
        assert!(!owner.exists());
    }
}

#[cfg(unix)]
#[test]
fn failed_pending_cleanup_does_not_starve_an_independent_disk_orphan() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let request = target_request([0xb6; 16], [0xb7; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(request).unwrap();
    provider.confirm_activated(&lease).unwrap();
    let rejected_link = lease.root().join("rejected-link");
    symlink(&fixture.repository, &rejected_link).unwrap();
    assert!(provider.remove_workspace(&lease).is_err());

    let orphan_root = {
        let orphan_provider = fixture.provider();
        let request = target_request([0xb8; 16], [0xb9; 16], fixture.repository.clone()).unwrap();
        let orphan = orphan_provider.create_target(request).unwrap();
        orphan_provider.confirm_activated(&orphan).unwrap();
        let root = orphan.root().to_path_buf();
        drop(orphan);
        drop(orphan_provider);
        root
    };

    assert!(provider.cleanup_owned_base().is_err());
    assert!(!orphan_root.exists());
    assert!(lease.root().exists());

    fs::remove_file(rejected_link).unwrap();
    assert_eq!(provider.cleanup_owned_base().unwrap().removed(), 1);
}

#[cfg(unix)]
#[test]
fn invalid_child_never_authorizes_removing_its_owner_sidecar() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let provider = fixture.provider();
    let id = "ba".repeat(16);
    let child = fixture.base.join(&id);
    let owner = fixture.base.join(format!("o-{id}"));
    symlink(&fixture.repository, &child).unwrap();
    fs::write(&owner, []).unwrap();

    assert!(provider.cleanup_owned_base().is_err());
    assert!(owner.exists());

    fs::remove_file(child).unwrap();
    fs::remove_file(owner).unwrap();
}

#[test]
fn disk_orphan_owner_sync_after_effect_is_retried_by_the_final_base_sync() {
    let fixture = Fixture::new();
    let provider = fixture.provider();
    let owner = fixture.base.join(format!("o-{}", "bc".repeat(16)));
    fs::write(&owner, []).unwrap();

    inject_cleanup_fault(WorkspaceCleanupFault::DirectorySyncAfterEffect);
    assert!(provider.cleanup_owned_base().is_err());
    assert!(!owner.exists());

    let report = provider.cleanup_owned_base().unwrap();
    assert_eq!(report.removed(), 0);
    assert_eq!(report.skipped_live(), 0);
}

fn format_id(id: [u8; 16]) -> String {
    let mut value = String::with_capacity(32);
    for byte in id {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").unwrap();
    }
    value
}

#[cfg(feature = "test-support")]
#[test]
fn losing_same_id_preallocated_lease_drop_cannot_corrupt_the_winner() {
    use std::sync::{Arc, Barrier};

    use notecrypt_editor_workspace::workspace_test_support::install_create_barrier;

    let fixture = Fixture::new();
    let provider = Arc::new(fixture.provider());
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    install_create_barrier("bd".repeat(16), Arc::clone(&entered), Arc::clone(&release));
    let losing_provider = Arc::clone(&provider);
    let losing_request =
        target_request([0xbd; 16], [0xbe; 16], fixture.repository.clone()).unwrap();
    let loser = std::thread::spawn(move || losing_provider.create_target(losing_request));

    entered.wait();
    let winning_request =
        target_request([0xbd; 16], [0xbf; 16], fixture.repository.clone()).unwrap();
    let lease = provider.create_target(winning_request).unwrap();
    release.wait();
    assert!(loser.join().unwrap().is_err());

    provider.confirm_activated(&lease).unwrap();
    let logical = LogicalWorkspacePath::new(PathBuf::from("winner.md")).unwrap();
    let mut target = provider.materialization_target(&lease, &logical).unwrap();
    target
        .writer_mut()
        .write_all(b"winner remains live")
        .unwrap();
    drop(target);
    drop(provider.remove_workspace(&lease).unwrap());
}
