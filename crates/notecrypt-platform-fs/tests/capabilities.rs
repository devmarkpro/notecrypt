use std::io::{Read, Seek, Write};

use notecrypt_platform_fs::{Directory, EntryKind, PhysicalComponent};
use tempfile::TempDir;

#[test]
fn physical_components_are_exactly_one_non_special_component() {
    for rejected in [
        "", ".", "..", "a/b", "a\\b", "a\0b", "a:b", "name.", "name ", "CON", "con", "con.txt",
        "nul", "com1", "lpt9",
    ] {
        assert!(
            PhysicalComponent::try_new(rejected).is_err(),
            "{rejected:?}"
        );
    }
    assert!(PhysicalComponent::try_new("objects").is_ok());
    assert!(PhysicalComponent::try_new(&"ab".repeat(31)).is_ok());
}

#[test]
fn all_operations_after_root_acquisition_are_component_relative() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let objects = PhysicalComponent::try_new("objects").expect("component");
    let file_name = PhysicalComponent::try_new("ciphertext").expect("component");
    let child = directory
        .create_dir(&objects)
        .expect("create child capability");
    let mut file = child.create_file_new(&file_name).expect("create file");
    file.write_all(b"encrypted").expect("write");
    file.sync_all().expect("flush");
    child.sync().expect("directory flush");

    let mut opened = child.open_file_nofollow(&file_name).expect("open file");
    let mut bytes = Vec::new();
    opened.read_to_end(&mut bytes).expect("read");
    assert_eq!(bytes, b"encrypted");
    assert_eq!(
        child.entry_kind(&file_name).expect("metadata"),
        EntryKind::File
    );
}

#[test]
fn no_replace_publication_never_clobbers_a_raced_destination() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let staging = directory
        .create_private_dir(&PhysicalComponent::try_new("private-stage").unwrap())
        .unwrap();
    let staged = PhysicalComponent::try_new("staged").expect("component");
    let destination = PhysicalComponent::try_new("destination").expect("component");
    staging
        .create_file_new(&staged)
        .expect("create staged file")
        .write_all(b"new")
        .expect("write staged");
    directory
        .create_file_new(&destination)
        .expect("create raced destination")
        .write_all(b"existing")
        .expect("write destination");

    let collision = match staging.rename_opened_no_replace_to_workspace(
        &staging.open_file_for_rename_nofollow(&staged).unwrap(),
        &staged,
        &directory,
        std::path::Path::new(destination.as_str()),
    ) {
        Ok(_) => panic!("publication must reject a raced destination"),
        Err(collision) => collision,
    };
    assert_eq!(
        collision.effect(),
        notecrypt_platform_fs::WorkspacePublicationEffect::NotPublished
    );
    assert_eq!(collision.error().kind(), std::io::ErrorKind::AlreadyExists);
    assert!(staging.open_file_nofollow(&staged).is_ok());
    let mut bytes = Vec::new();
    directory
        .open_file_nofollow(&destination)
        .expect("open destination")
        .read_to_end(&mut bytes)
        .expect("read destination");
    assert_eq!(bytes, b"existing");
}

#[test]
fn no_replace_publication_moves_one_complete_staged_file() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let staging = directory
        .create_private_dir(&PhysicalComponent::try_new("private-stage").unwrap())
        .unwrap();
    let staged = PhysicalComponent::try_new("staged-success").expect("component");
    let destination = PhysicalComponent::try_new("destination-success").expect("component");
    let mut file = staging.create_file_new(&staged).expect("create staged");
    file.write_all(b"complete").expect("write staged");
    file.sync_all().expect("sync staged");

    staging
        .rename_opened_no_replace_from_private_staging(
            &staging.open_file_for_rename_nofollow(&staged).unwrap(),
            &staged,
            &directory,
            &destination,
        )
        .expect("publish without replacement");
    assert!(staging.open_file_nofollow(&staged).is_err());
    let mut bytes = Vec::new();
    directory
        .open_file_nofollow(&destination)
        .expect("open destination")
        .read_to_end(&mut bytes)
        .expect("read destination");
    assert_eq!(bytes, b"complete");
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_checked_replace_succeeds_with_live_expected_destination_authority() {
    let root = TempDir::new().expect("temp root");
    let ambient = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let records_name = PhysicalComponent::try_new("records").unwrap();
    let records = ambient
        .create_private_dir(&records_name)
        .expect("create private records directory");
    let destination = PhysicalComponent::try_new("record").unwrap();
    let staged_name = PhysicalComponent::try_new("replacement").unwrap();
    let mut current = records
        .create_file_new(&destination)
        .expect("create current record");
    current.write_all(b"old").unwrap();
    current.sync_all().unwrap();
    drop(current);
    let expected = records
        .open_file_nofollow(&destination)
        .expect("retain authenticated destination authority");
    let mut staged = records
        .create_file_new(&staged_name)
        .expect("create staged replacement");
    staged.write_all(b"new").unwrap();
    staged.sync_all().unwrap();

    records
        .replace_opened_atomic_if_destination_matches(
            &staged,
            &staged_name,
            &records,
            &destination,
            &expected,
        )
        .expect("replace while expected destination authority remains live");

    let mut retained_old = expected.try_clone().expect("clone retained old file");
    let mut old_bytes = Vec::new();
    retained_old.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, b"old");
    let mut published = records
        .open_file_nofollow(&destination)
        .expect("open replacement by destination name");
    let mut new_bytes = Vec::new();
    published.read_to_end(&mut new_bytes).unwrap();
    assert_eq!(new_bytes, b"new");
}

#[cfg(unix)]
#[test]
fn nofollow_open_rejects_symlinks_and_hardlinked_files() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    fs::write(root.path().join("outside"), b"secret").expect("outside file");
    symlink(root.path().join("outside"), root.path().join("link")).expect("symlink");
    fs::hard_link(root.path().join("outside"), root.path().join("hard")).expect("hard link");

    let link = PhysicalComponent::try_new("link").expect("component");
    let hard = PhysicalComponent::try_new("hard").expect("component");
    assert!(directory.open_file_nofollow(&link).is_err());
    assert!(directory.open_file_nofollow(&hard).is_err());
}

#[test]
fn capability_probe_uses_owned_scratch_and_leaves_no_residue() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
    let owned = directory
        .create_private_dir(&PhysicalComponent::try_new("owned").unwrap())
        .unwrap();

    let capabilities = owned.probe_capabilities().unwrap();
    assert!(capabilities.directory_sync);
    assert!(capabilities.atomic_replace);
    assert!(capabilities.no_replace_publication);
    assert_eq!(
        std::fs::read_dir(root.path().join("owned"))
            .unwrap()
            .count(),
        0
    );
}

#[cfg(feature = "test-support")]
#[test]
fn private_workspace_file_sync_is_identity_bound_and_retryable() {
    use notecrypt_platform_fs::workspace_test_support::{
        WorkspaceFileSyncFault, inject_file_sync_fault,
    };

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let marker = PhysicalComponent::try_new("marker").unwrap();
    let moved = PhysicalComponent::try_new("moved-marker").unwrap();
    let marker_path = std::path::Path::new(marker.as_str());
    let moved_path = std::path::Path::new(moved.as_str());
    let mut created = directory
        .create_private_workspace_file_new(marker_path)
        .expect("create exact private marker");
    created.write_all(b"original").unwrap();
    drop(created);
    let mut expected = directory
        .open_private_workspace_file_nofollow(marker_path)
        .expect("retain strict read-only marker authority");

    directory
        .sync_private_workspace_file_if_matches(marker_path, &expected)
        .expect("sync exact private marker through narrow authority");
    #[cfg(windows)]
    {
        use notecrypt_platform_fs::workspace_test_support::{
            private_file_sync_access, take_observed_private_file_sync_access,
        };
        assert_eq!(
            take_observed_private_file_sync_access(),
            Some(private_file_sync_access())
        );
    }

    inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
    assert!(
        directory
            .sync_private_workspace_file_if_matches(marker_path, &expected)
            .is_err()
    );
    assert!(
        directory
            .open_private_workspace_file_nofollow(marker_path)
            .unwrap()
            .same_identity(&expected)
            .unwrap()
    );
    directory
        .sync_private_workspace_file_if_matches(marker_path, &expected)
        .expect("retry exact pre-effect sync failure");

    inject_file_sync_fault(WorkspaceFileSyncFault::AfterEffect);
    assert!(
        directory
            .sync_private_workspace_file_if_matches(marker_path, &expected)
            .is_err()
    );
    assert!(
        directory
            .open_private_workspace_file_nofollow(marker_path)
            .unwrap()
            .same_identity(&expected)
            .unwrap()
    );
    directory
        .sync_private_workspace_file_if_matches(marker_path, &expected)
        .expect("retry exact after-effect sync failure");

    std::fs::rename(
        root.path().join(marker.as_str()),
        root.path().join(moved.as_str()),
    )
    .expect("move retained original marker");
    let mut replacement = directory
        .create_private_workspace_file_new(marker_path)
        .expect("create same-name replacement");
    replacement.write_all(b"replacement").unwrap();
    inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
    let mismatch = directory
        .sync_private_workspace_file_if_matches(marker_path, &expected)
        .expect_err("same-name replacement must fail before sync");
    assert_eq!(mismatch.kind(), std::io::ErrorKind::InvalidData);

    let preserved_fault = directory
        .sync_private_workspace_file_if_matches(marker_path, &replacement)
        .expect_err("identity mismatch must not consume the pre-effect fault");
    assert_eq!(preserved_fault.kind(), std::io::ErrorKind::Other);
    directory
        .sync_private_workspace_file_if_matches(marker_path, &replacement)
        .expect("replacement sync succeeds after explicit retry");

    let mut retained_bytes = Vec::new();
    expected.rewind().unwrap();
    expected.read_to_end(&mut retained_bytes).unwrap();
    assert_eq!(retained_bytes, b"original");
    assert!(
        directory
            .open_private_workspace_file_nofollow(moved_path)
            .unwrap()
            .same_identity(&expected)
            .unwrap()
    );
}

#[cfg(feature = "test-support")]
#[test]
fn private_workspace_file_sync_rejects_hostile_named_objects() {
    use notecrypt_platform_fs::workspace_test_support::{
        WorkspaceFileSyncFault, inject_file_sync_fault,
    };

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let marker = PhysicalComponent::try_new("hostile-marker").unwrap();
    let held = PhysicalComponent::try_new("held-marker").unwrap();
    let marker_path = std::path::Path::new(marker.as_str());
    let expected = directory
        .create_private_workspace_file_new(marker_path)
        .expect("create retained private marker");
    std::fs::rename(
        root.path().join(marker.as_str()),
        root.path().join(held.as_str()),
    )
    .expect("move retained marker");
    let prove_fault_remained_before_effect = || {
        std::fs::rename(
            root.path().join(held.as_str()),
            root.path().join(marker.as_str()),
        )
        .expect("restore exact private sync target");
        let fault = directory
            .sync_private_workspace_file_if_matches(marker_path, &expected)
            .expect_err("hostile rejection must not consume the pre-effect fault");
        assert_eq!(fault.kind(), std::io::ErrorKind::Other);
        directory
            .sync_private_workspace_file_if_matches(marker_path, &expected)
            .expect("exact private target sync succeeds after explicit retry");
        std::fs::rename(
            root.path().join(marker.as_str()),
            root.path().join(held.as_str()),
        )
        .expect("retain exact marker away from the next hostile name");
    };

    drop(
        directory
            .create_private_dir(&marker)
            .expect("create same-name private directory"),
    );
    inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
    assert!(
        directory
            .sync_private_workspace_file_if_matches(marker_path, &expected)
            .is_err()
    );
    directory.remove_empty_dir(&marker).unwrap();
    prove_fault_remained_before_effect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        symlink(
            root.path().join(held.as_str()),
            root.path().join(marker.as_str()),
        )
        .expect("create same-name reparse fixture");
        inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
        assert!(
            directory
                .sync_private_workspace_file_if_matches(marker_path, &expected)
                .is_err()
        );
        std::fs::remove_file(root.path().join(marker.as_str())).unwrap();
        prove_fault_remained_before_effect();

        std::fs::write(root.path().join(marker.as_str()), b"nonprivate").unwrap();
        std::fs::set_permissions(
            root.path().join(marker.as_str()),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
        assert!(
            directory
                .sync_private_workspace_file_if_matches(marker_path, &expected)
                .is_err()
        );
        std::fs::remove_file(root.path().join(marker.as_str())).unwrap();
        prove_fault_remained_before_effect();
    }

    #[cfg(windows)]
    {
        use notecrypt_platform_fs::workspace_test_support::make_file_permissive_for_test;
        use std::os::windows::fs::symlink_file;

        symlink_file(
            root.path().join(held.as_str()),
            root.path().join(marker.as_str()),
        )
        .expect("create same-name reparse fixture");
        inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
        assert!(
            directory
                .sync_private_workspace_file_if_matches(marker_path, &expected)
                .is_err()
        );
        std::fs::remove_file(root.path().join(marker.as_str())).unwrap();
        prove_fault_remained_before_effect();

        let permissive = directory
            .create_private_workspace_file_new(marker_path)
            .expect("create exact file before hostile ACL mutation");
        make_file_permissive_for_test(&directory, &marker, &permissive)
            .expect("make exact named file nonprivate");
        inject_file_sync_fault(WorkspaceFileSyncFault::BeforeEffect);
        let error = directory
            .sync_private_workspace_file_if_matches(marker_path, &permissive)
            .expect_err("nonprivate named file must be rejected before sync");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        drop(permissive);
        std::fs::remove_file(root.path().join(marker.as_str())).unwrap();
        prove_fault_remained_before_effect();
    }
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_namespace_mutators_retain_write_through_exact_handles() {
    use notecrypt_platform_fs::workspace_test_support::{
        directory_is_mutation_local_durable, directory_primary_access,
        file_is_mutation_local_durable, rename_target_access, retained_directory_access,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
    };

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let exact_target_access = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    let primary_access = directory_primary_access(&directory).expect("query primary access");
    assert_eq!(
        primary_access & DELETE,
        0,
        "ambient retained primary unexpectedly grants DELETE"
    );
    assert_ne!(
        primary_access & exact_target_access,
        exact_target_access,
        "ambient capability unexpectedly already grants the complete rename-target mask"
    );
    let ordinary_name = PhysicalComponent::try_new("ordinary-child").unwrap();
    let ordinary = directory
        .create_dir(&ordinary_name)
        .expect("create ordinary directory");
    assert_eq!(
        directory_primary_access(&ordinary).expect("query ordinary retained primary access"),
        retained_directory_access(),
    );
    assert!(
        directory_is_mutation_local_durable(&ordinary)
            .expect("query ordinary directory create mode")
    );
    assert_eq!(
        rename_target_access(&ordinary).expect("query exact downscoped rename target access"),
        exact_target_access
    );
    let ordinary_clone = ordinary.try_clone().expect("clone directory capability");
    assert_eq!(
        rename_target_access(&ordinary_clone).expect("query cloned rename-target access"),
        exact_target_access
    );
    assert!(ordinary.same_identity(&ordinary_clone).unwrap());
    drop(ordinary_clone);

    let ordinary_file_name = PhysicalComponent::try_new("ordinary-file").unwrap();
    let ordinary_file = ordinary
        .create_file_new(&ordinary_file_name)
        .expect("create ordinary file");
    assert!(
        file_is_mutation_local_durable(&ordinary_file).expect("query ordinary file create mode")
    );
    let rename_source = ordinary
        .open_file_for_rename_nofollow(&ordinary_file_name)
        .expect("open exact rename source");
    assert!(file_is_mutation_local_durable(&rename_source).expect("query rename-source mode"));
    drop(rename_source);
    drop(ordinary_file);
    ordinary
        .remove_file(&ordinary_file_name)
        .expect("remove inherited ordinary file through an exact write-through handle");

    let private_name = PhysicalComponent::try_new("private-child").unwrap();
    let private = ordinary
        .create_private_dir(&private_name)
        .expect("create protected directory");
    assert_eq!(
        directory_primary_access(&private).expect("query private retained primary access"),
        retained_directory_access(),
    );
    assert!(
        directory_is_mutation_local_durable(&private)
            .expect("query protected directory create mode")
    );
    assert_eq!(
        rename_target_access(&private)
            .expect("query exact protected downscoped rename target access"),
        exact_target_access
    );
    let cleanup = ordinary
        .open_private_dir_for_cleanup(&private_name)
        .expect("reopen protected directory for cleanup");
    assert_eq!(
        directory_primary_access(&cleanup).expect("query cleanup retained primary access"),
        retained_directory_access(),
    );
    assert!(
        directory_is_mutation_local_durable(&cleanup)
            .expect("query protected cleanup-directory mode")
    );
    drop(cleanup);
    ordinary
        .remove_opened_private_tree(&private, &private_name, 1, 1)
        .expect("remove protected directory");
    drop(private);
    directory
        .remove_empty_dir(&ordinary_name)
        .expect("remove ordinary directory while its exact retained handle remains live");
    drop(ordinary);
}

#[cfg(all(windows, feature = "test-support"))]
struct WindowsRenameObservation {
    label: &'static str,
    source_access: u32,
    source_is_private: bool,
    destination_primary_access: u32,
    destination_target_access: u32,
    destination_is_private: bool,
    outcome: Result<(), std::io::Error>,
}

#[cfg(all(windows, feature = "test-support"))]
impl WindowsRenameObservation {
    fn succeeded(&self) -> bool {
        self.outcome.is_ok()
    }

    fn render(&self) -> String {
        let outcome = match &self.outcome {
            Ok(()) => "ok".to_owned(),
            Err(error) => format!(
                "error(kind={:?},code={:?},message={error})",
                error.kind(),
                error.raw_os_error()
            ),
        };
        format!(
            "{}: source=0x{:08X},source-private={},primary=0x{:08X},target=0x{:08X},destination-private={},outcome={outcome}",
            self.label,
            self.source_access,
            self.source_is_private,
            self.destination_primary_access,
            self.destination_target_access,
            self.destination_is_private,
        )
    }
}

#[cfg(all(windows, feature = "test-support"))]
struct WindowsRenameFixture {
    label: &'static str,
    source_directory_private: bool,
    source_file_private: bool,
    destination_private: bool,
    nested_private_parent: bool,
    primary_target: bool,
    permissive_destination: bool,
    replace: bool,
}

#[cfg(all(windows, feature = "test-support"))]
fn observe_windows_rename(fixture: WindowsRenameFixture) -> WindowsRenameObservation {
    use notecrypt_platform_fs::workspace_test_support::{
        directory_primary_access, file_access, file_is_private,
        make_directory_inheritable_for_test, rename_target_access, rename_with_primary_target,
        rename_with_retained_target,
    };

    let root = TempDir::new().expect("temp root");
    let ambient = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let fixture_parent = if fixture.nested_private_parent {
        ambient
            .create_private_dir(&PhysicalComponent::try_new("probe-parent").unwrap())
            .expect("create private probe parent")
    } else {
        ambient.try_clone().expect("clone fixture parent")
    };
    let source_name = PhysicalComponent::try_new("source-directory").unwrap();
    let source_directory = if fixture.source_directory_private {
        fixture_parent
            .create_private_dir(&source_name)
            .expect("create private source directory")
    } else {
        fixture_parent
            .create_dir(&source_name)
            .expect("create ordinary source directory")
    };
    let destination_name = PhysicalComponent::try_new("destination-directory").unwrap();
    let destination_directory = if fixture.destination_private {
        fixture_parent
            .create_private_dir(&destination_name)
            .expect("create private destination directory")
    } else {
        ambient.try_clone().expect("clone ambient destination")
    };
    if fixture.permissive_destination {
        make_directory_inheritable_for_test(
            &fixture_parent,
            &destination_name,
            &destination_directory,
        )
        .expect("install deterministic permissive destination ACL");
    }

    let source_file_name = PhysicalComponent::try_new("source-file").unwrap();
    let source_file = if fixture.source_file_private {
        source_directory
            .create_private_file_new(&source_file_name)
            .expect("create private rename source")
    } else {
        source_directory
            .create_file_new(&source_file_name)
            .expect("create ordinary rename source")
    };
    source_file.sync_all().unwrap();
    drop(source_file);
    let source = source_directory
        .open_file_for_rename_nofollow(&source_file_name)
        .expect("open exact rename source");
    let published_name = std::path::Path::new("published-file");
    if fixture.replace {
        let published_component = PhysicalComponent::try_new("published-file").unwrap();
        let mut existing = if fixture.destination_private {
            destination_directory
                .create_private_file_new(&published_component)
                .expect("create private replacement target")
        } else {
            destination_directory
                .create_file_new(&published_component)
                .expect("create ordinary replacement target")
        };
        existing.write_all(b"old").unwrap();
        existing.sync_all().unwrap();
    }

    let source_access = file_access(&source).expect("query source access");
    let source_is_private = file_is_private(&source);
    let destination_primary_access =
        directory_primary_access(&destination_directory).expect("query destination primary access");
    let destination_target_access =
        rename_target_access(&destination_directory).expect("query destination target access");
    let destination_is_private = destination_directory.verify_private().is_ok();
    let outcome = if fixture.primary_target {
        rename_with_primary_target(
            &source,
            &destination_directory,
            published_name,
            fixture.replace,
        )
    } else {
        rename_with_retained_target(
            &source,
            &destination_directory,
            published_name,
            fixture.replace,
        )
    };
    if outcome.is_ok() {
        let mut published = Vec::new();
        destination_directory
            .open_file_nofollow(&PhysicalComponent::try_new("published-file").unwrap())
            .expect("open published diagnostic file")
            .read_to_end(&mut published)
            .expect("read published diagnostic file");
        assert!(published.is_empty(), "{}", fixture.label);
    }

    WindowsRenameObservation {
        label: fixture.label,
        source_access,
        source_is_private,
        destination_primary_access,
        destination_target_access,
        destination_is_private,
        outcome,
    }
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_rename_access_matrix_localizes_protected_destination_denial() {
    let observations = [
        observe_windows_rename(WindowsRenameFixture {
            label: "ordinary-to-ambient-retained",
            source_directory_private: false,
            source_file_private: false,
            destination_private: false,
            nested_private_parent: false,
            primary_target: false,
            permissive_destination: false,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-ambient-retained",
            source_directory_private: true,
            source_file_private: true,
            destination_private: false,
            nested_private_parent: false,
            primary_target: false,
            permissive_destination: false,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "ordinary-to-private-retained",
            source_directory_private: false,
            source_file_private: false,
            destination_private: true,
            nested_private_parent: false,
            primary_target: false,
            permissive_destination: false,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-private-retained",
            source_directory_private: true,
            source_file_private: true,
            destination_private: true,
            nested_private_parent: false,
            primary_target: false,
            permissive_destination: false,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-private-primary",
            source_directory_private: true,
            source_file_private: true,
            destination_private: true,
            nested_private_parent: false,
            primary_target: true,
            permissive_destination: false,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "probe-ordinary-file-in-nested-private-source",
            source_directory_private: true,
            source_file_private: false,
            destination_private: true,
            nested_private_parent: true,
            primary_target: false,
            permissive_destination: false,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-private-retained-replace",
            source_directory_private: true,
            source_file_private: true,
            destination_private: true,
            nested_private_parent: false,
            primary_target: false,
            permissive_destination: false,
            replace: true,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-private-primary-replace",
            source_directory_private: true,
            source_file_private: true,
            destination_private: true,
            nested_private_parent: false,
            primary_target: true,
            permissive_destination: false,
            replace: true,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-permissive-retained",
            source_directory_private: true,
            source_file_private: true,
            destination_private: true,
            nested_private_parent: false,
            primary_target: false,
            permissive_destination: true,
            replace: false,
        }),
        observe_windows_rename(WindowsRenameFixture {
            label: "private-to-permissive-primary",
            source_directory_private: true,
            source_file_private: true,
            destination_private: true,
            nested_private_parent: false,
            primary_target: true,
            permissive_destination: true,
            replace: false,
        }),
    ];
    let report = observations
        .iter()
        .map(WindowsRenameObservation::render)
        .collect::<Vec<_>>()
        .join("; ");
    eprintln!("native rename access matrix: {report}");
    assert!(
        observations.iter().all(WindowsRenameObservation::succeeded),
        "native rename access matrix: {report}"
    );
}

#[cfg(all(windows, feature = "test-support"))]
struct WindowsProbeSequenceObservation {
    label: &'static str,
    first_source_access: u32,
    first_source_private: bool,
    existing_destination_access: Option<u32>,
    existing_destination_private: Option<bool>,
    replacement_source_access: Option<u32>,
    replacement_source_private: Option<bool>,
    no_replace: std::io::Result<()>,
    replace: Option<std::io::Result<()>>,
}

#[cfg(all(windows, feature = "test-support"))]
impl WindowsProbeSequenceObservation {
    fn succeeded(&self) -> bool {
        self.no_replace.is_ok() && self.replace.as_ref().is_some_and(Result::is_ok)
    }

    fn render_result(result: &std::io::Result<()>) -> String {
        match result {
            Ok(()) => "ok".to_owned(),
            Err(error) => format!(
                "error(kind={:?},code={:?},message={error})",
                error.kind(),
                error.raw_os_error()
            ),
        }
    }

    fn render(&self) -> String {
        let existing_access = self.existing_destination_access.map_or_else(
            || "unavailable".to_owned(),
            |value| format!("0x{value:08X}"),
        );
        let replacement_access = self.replacement_source_access.map_or_else(
            || "unavailable".to_owned(),
            |value| format!("0x{value:08X}"),
        );
        let replace = self
            .replace
            .as_ref()
            .map_or_else(|| "not-run".to_owned(), Self::render_result);
        format!(
            "{}: first-source=0x{:08X},first-private={},no-replace={},existing-destination={existing_access},existing-private={:?},replacement-source={replacement_access},replacement-private={:?},replace={replace}",
            self.label,
            self.first_source_access,
            self.first_source_private,
            Self::render_result(&self.no_replace),
            self.existing_destination_private,
            self.replacement_source_private,
        )
    }
}

#[cfg(all(windows, feature = "test-support"))]
fn observe_windows_probe_sequence(
    label: &'static str,
    keep_first_moved_handle: bool,
) -> WindowsProbeSequenceObservation {
    use notecrypt_platform_fs::workspace_test_support::{file_access, file_is_private};

    let root = TempDir::new().expect("temp root");
    let ambient = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let owned = ambient
        .create_private_dir(&PhysicalComponent::try_new("owned").unwrap())
        .expect("create owned parent");
    let probe = owned
        .create_private_dir(&PhysicalComponent::try_new("probe").unwrap())
        .expect("create probe parent");
    let source_directory = probe
        .create_private_dir(&PhysicalComponent::try_new("source").unwrap())
        .expect("create probe source directory");
    let destination_directory = probe
        .create_private_dir(&PhysicalComponent::try_new("destination").unwrap())
        .expect("create probe destination directory");
    let source_name = PhysicalComponent::try_new("source").unwrap();
    let replacement_name = PhysicalComponent::try_new("replacement").unwrap();
    let destination_name = PhysicalComponent::try_new("destination").unwrap();
    source_directory
        .create_file_new(&source_name)
        .expect("create ordinary first source")
        .sync_all()
        .expect("sync ordinary first source");
    let first = source_directory
        .open_file_for_rename_nofollow(&source_name)
        .expect("open first rename source");
    let first_source_access = file_access(&first).expect("query first source access");
    let first_source_private = file_is_private(&first);
    let no_replace = source_directory.rename_opened_no_replace_from_private_staging(
        &first,
        &source_name,
        &destination_directory,
        &destination_name,
    );
    if no_replace.is_err() {
        return WindowsProbeSequenceObservation {
            label,
            first_source_access,
            first_source_private,
            existing_destination_access: None,
            existing_destination_private: None,
            replacement_source_access: None,
            replacement_source_private: None,
            no_replace,
            replace: None,
        };
    }
    let existing = destination_directory
        .open_file_for_rename_nofollow(&destination_name)
        .expect("open existing probe destination");
    let existing_destination_access = Some(file_access(&existing).expect("query destination"));
    let existing_destination_private = Some(file_is_private(&existing));
    drop(existing);
    source_directory
        .create_file_new(&replacement_name)
        .expect("create ordinary replacement source")
        .sync_all()
        .expect("sync ordinary replacement source");
    let replacement = source_directory
        .open_file_for_rename_nofollow(&replacement_name)
        .expect("open replacement rename source");
    let replacement_source_access =
        Some(file_access(&replacement).expect("query replacement source access"));
    let replacement_source_private = Some(file_is_private(&replacement));
    let retained_first = keep_first_moved_handle.then_some(first);
    let replace = source_directory.replace_opened_atomic_from_private_staging(
        &replacement,
        &replacement_name,
        &destination_directory,
        &destination_name,
    );
    drop(retained_first);
    WindowsProbeSequenceObservation {
        label,
        first_source_access,
        first_source_private,
        existing_destination_access,
        existing_destination_private,
        replacement_source_access,
        replacement_source_private,
        no_replace,
        replace: Some(replace),
    }
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_capability_probe_sequence_localizes_replace_with_live_first_handle() {
    let observations = [
        observe_windows_probe_sequence("drop-first-before-replace", false),
        observe_windows_probe_sequence("keep-first-through-replace", true),
    ];
    let report = observations
        .iter()
        .map(WindowsProbeSequenceObservation::render)
        .collect::<Vec<_>>()
        .join("; ");
    eprintln!("native capability probe sequence: {report}");
    assert!(
        observations
            .iter()
            .all(WindowsProbeSequenceObservation::succeeded),
        "native capability probe sequence: {report}"
    );
}

#[cfg(all(windows, feature = "test-support"))]
fn windows_name_state(directory: &Directory, name: &PhysicalComponent) -> String {
    match directory.entry_kind(name) {
        Ok(_) => "reachable".to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent".to_owned(),
        Err(error) => format!(
            "error(kind={:?},code={:?},message={error})",
            error.kind(),
            error.raw_os_error()
        ),
    }
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_short_lived_cleanup_removes_name_while_retained_capabilities_are_live() {
    use notecrypt_platform_fs::workspace_test_support::{
        directory_primary_access, disposition_empty_tree_production_lifecycle,
        retained_directory_access,
    };

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let name = PhysicalComponent::try_new("production-lifecycle").unwrap();
    let original = directory
        .create_private_dir(&name)
        .expect("create production-lifecycle fixture");
    let clone = original.try_clone().expect("clone retained capability");
    let reopened = directory
        .open_private_dir_for_cleanup(&name)
        .expect("reopen retained cleanup capability");
    for retained in [&original, &clone, &reopened] {
        assert_eq!(
            directory_primary_access(retained).expect("query retained primary access"),
            retained_directory_access(),
        );
    }

    disposition_empty_tree_production_lifecycle(&directory, &original, &name)
        .expect("run exact production cleanup lifecycle");
    assert_eq!(windows_name_state(&directory, &name), "absent");
    drop(reopened);
    drop(clone);
    drop(original);
    assert_eq!(windows_name_state(&directory, &name), "absent");
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_private_directory_enumeration_reports_exact_open_and_iteration_stages() {
    use notecrypt_platform_fs::workspace_test_support::count_directory_entries;

    fn render(result: &std::io::Result<usize>) -> String {
        match result {
            Ok(count) => format!("ok(count={count})"),
            Err(error) => format!(
                "error(kind={:?},code={:?},message={error})",
                error.kind(),
                error.raw_os_error()
            ),
        }
    }

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let empty = directory
        .create_private_dir(&PhysicalComponent::try_new("empty-enumeration").unwrap())
        .expect("create empty enumeration fixture");
    let empty_result = count_directory_entries(&empty);

    let nonempty = directory
        .create_private_dir(&PhysicalComponent::try_new("nonempty-enumeration").unwrap())
        .expect("create nonempty enumeration fixture");
    drop(
        nonempty
            .create_private_file_new(&PhysicalComponent::try_new("file").unwrap())
            .expect("create enumeration file"),
    );
    drop(
        nonempty
            .create_private_dir(&PhysicalComponent::try_new("directory").unwrap())
            .expect("create enumeration directory"),
    );
    let nonempty_result = count_directory_entries(&nonempty);

    let report = format!(
        "empty={},nonempty={}",
        render(&empty_result),
        render(&nonempty_result)
    );
    eprintln!("native private-directory enumeration: {report}");
    assert!(
        matches!(empty_result, Ok(0)),
        "native enumeration: {report}"
    );
    assert!(
        matches!(nonempty_result, Ok(2)),
        "native enumeration: {report}"
    );
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_rename_target_acquisition_rejects_substitution_and_pins_the_verified_directory() {
    use std::cell::Cell;
    use std::rc::Rc;

    use notecrypt_platform_fs::workspace_test_support::{
        inject_rename_target_acquisition_hook, rename_directory_with_retained_target,
    };

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let victim_name = PhysicalComponent::try_new("victim").unwrap();
    let attacker_name = PhysicalComponent::try_new("attacker").unwrap();
    let moved_victim_name = PhysicalComponent::try_new("held-victim").unwrap();
    let victim = directory
        .create_private_dir(&victim_name)
        .expect("create victim directory");
    let attacker = directory
        .create_private_dir(&attacker_name)
        .expect("create attacker directory");
    let victim_path = root.path().join("victim");
    let attacker_path = root.path().join("attacker");
    let held_path = root.path().join("held-victim");
    let hook_parent = directory.try_clone().expect("clone hook parent");
    let hook_victim = victim.try_clone().expect("clone exact victim capability");
    let hook_attacker = attacker
        .try_clone()
        .expect("clone exact attacker capability");
    let hook_victim_name = victim_name.clone();
    let hook_attacker_name = attacker_name.clone();
    let hook_executed = Rc::new(Cell::new(false));
    let hook_executed_in_callback = Rc::clone(&hook_executed);
    inject_rename_target_acquisition_hook(move || {
        hook_executed_in_callback.set(true);
        rename_directory_with_retained_target(
            &hook_parent,
            &hook_victim_name,
            &hook_victim,
            &hook_parent,
            std::path::Path::new("held-victim"),
            false,
        )
        .expect("move retained victim before acquisition");
        rename_directory_with_retained_target(
            &hook_parent,
            &hook_attacker_name,
            &hook_attacker,
            &hook_parent,
            std::path::Path::new("victim"),
            false,
        )
        .expect("substitute attacker before companion acquisition");
    });
    let mismatch = match directory.open_dir_nofollow(&victim_name) {
        Ok(_) => panic!("substituted rename target must be rejected"),
        Err(error) => error,
    };
    assert!(hook_executed.get(), "substitution hook must execute");
    assert_eq!(
        mismatch.kind(),
        std::io::ErrorKind::InvalidData,
        "substitution must reach exact identity mismatch: kind={:?}, code={:?}, error={mismatch}",
        mismatch.kind(),
        mismatch.raw_os_error(),
    );
    assert!(victim_path.is_dir());
    assert!(held_path.is_dir());
    assert!(!attacker_path.exists());
    rename_directory_with_retained_target(
        &directory,
        &victim_name,
        &attacker,
        &directory,
        std::path::Path::new("attacker"),
        false,
    )
    .expect("restore attacker name");
    rename_directory_with_retained_target(
        &directory,
        &moved_victim_name,
        &victim,
        &directory,
        std::path::Path::new("victim"),
        false,
    )
    .expect("restore victim name");
    drop(attacker);
    drop(victim);
    directory
        .remove_empty_dir(&victim_name)
        .expect("remove restored victim");
    directory
        .remove_empty_dir(&attacker_name)
        .expect("remove restored attacker");

    let staging_name = PhysicalComponent::try_new("staging").unwrap();
    let destination_name = PhysicalComponent::try_new("destination").unwrap();
    let moved_destination_name = PhysicalComponent::try_new("destination-held").unwrap();
    let staging = directory
        .create_private_dir(&staging_name)
        .expect("create staging directory");
    let destination = directory
        .create_private_dir(&destination_name)
        .expect("create destination directory");
    let source_name = PhysicalComponent::try_new("source").unwrap();
    let published_name = PhysicalComponent::try_new("published").unwrap();
    let mut source = staging
        .create_private_file_new(&source_name)
        .expect("create exact source");
    source.write_all(b"authenticated").unwrap();
    source.sync_all().unwrap();
    let rename_source = staging
        .open_file_for_rename_nofollow(&source_name)
        .expect("open exact source for rename");
    drop(source);
    rename_directory_with_retained_target(
        &directory,
        &destination_name,
        &destination,
        &directory,
        std::path::Path::new("destination-held"),
        false,
    )
    .expect("replace destination namespace after capability acquisition");
    let attacker_destination = directory
        .create_private_dir(&destination_name)
        .expect("create attacker destination at the old name");
    staging
        .rename_opened_no_replace_from_private_staging(
            &rename_source,
            &source_name,
            &destination,
            &published_name,
        )
        .expect("publish through pinned rename-target companion");
    assert_eq!(
        std::fs::read(root.path().join("destination-held/published")).unwrap(),
        b"authenticated"
    );
    assert!(!root.path().join("destination/published").exists());
    drop(rename_source);
    directory
        .remove_opened_private_tree(&destination, &moved_destination_name, 1, 1)
        .expect("remove moved authenticated destination");
    drop(destination);
    directory
        .remove_opened_private_tree(&attacker_destination, &destination_name, 1, 1)
        .expect("remove attacker destination");
    drop(attacker_destination);
    directory
        .remove_opened_private_tree(&staging, &staging_name, 1, 1)
        .expect("remove staging directory");
    drop(staging);
}

#[test]
fn opened_directory_reports_bounded_available_space() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();

    assert!(directory.available_space().unwrap() > 0);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn opened_directory_can_be_reopened_handle_relative_for_durable_sync() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();

    directory.sync().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn private_child_directory_uses_a_metadata_capable_exact_reopen() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();

    let child = directory
        .create_private_dir(&PhysicalComponent::try_new("private-child").unwrap())
        .unwrap();

    child.verify_private().unwrap();
    directory.sync().unwrap();
}

#[cfg(unix)]
#[test]
fn directory_mount_identity_distinguishes_nested_directories_from_other_mounts() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
    let child = directory
        .create_private_dir(&PhysicalComponent::try_new("child").unwrap())
        .unwrap();
    assert!(directory.same_filesystem(&child).unwrap());

    #[cfg(target_vendor = "apple")]
    let other_mount = std::path::Path::new("/dev");
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let other_mount = std::path::Path::new("/proc");
    let external = Directory::open_ambient(other_mount).unwrap();
    assert!(!directory.same_filesystem(&external).unwrap());
}

#[cfg(unix)]
#[test]
fn private_directories_are_verified_as_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();
    let private = directory
        .create_private_dir(&PhysicalComponent::try_new("private").unwrap())
        .unwrap();
    private.verify_private().unwrap();
    assert_eq!(
        std::fs::metadata(root.path().join("private"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[cfg(windows)]
#[test]
fn private_directory_and_file_acl_installation_survives_exact_reopen() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    #[cfg(feature = "test-support")]
    let private_parent = {
        let hostile_name = PhysicalComponent::try_new("hostile-parent").unwrap();
        let hostile = directory
            .create_private_dir(&hostile_name)
            .expect("create exact hostile-parent handle");
        notecrypt_platform_fs::workspace_test_support::make_directory_inheritable_for_test(
            &directory,
            &hostile_name,
            &hostile,
        )
        .expect("install deterministic inheritable non-owner grant");
        assert!(hostile.verify_private().is_err());
        let inherited_name = PhysicalComponent::try_new("ordinary-inherited").unwrap();
        let inherited = hostile
            .create_dir(&inherited_name)
            .expect("create an ordinary inherited directory");
        assert!(
            inherited.verify_private().is_err(),
            "the fixture must prove the private child overrides inherited grants"
        );
        drop(inherited);
        hostile
            .remove_empty_dir(&inherited_name)
            .expect("remove inherited fixture");
        hostile
    };
    #[cfg(not(feature = "test-support"))]
    let private_parent = directory.try_clone().expect("clone root capability");

    let private_name = PhysicalComponent::try_new("private-space").unwrap();
    let private = private_parent
        .create_private_dir(&private_name)
        .unwrap_or_else(|error| panic!("create private directory: {error}"));
    private
        .verify_private()
        .unwrap_or_else(|error| panic!("read back private directory ACL: {error}"));
    private.sync().expect("sync private directory");
    let workspace_name = std::path::Path::new("workspace space Ω");
    let workspace = private
        .open_or_create_private_workspace_dir(workspace_name)
        .expect("create a private workspace directory with a Unicode and space name");
    workspace
        .verify_private()
        .expect("read back the private workspace directory ACL");
    workspace.sync().expect("sync private workspace directory");
    drop(workspace);
    let nested_name = PhysicalComponent::try_new("nested").unwrap();
    let nested = private
        .create_private_dir(&nested_name)
        .expect("create nested private directory");
    nested.sync().expect("sync nested private directory");
    drop(nested);
    private
        .remove_empty_dir(&nested_name)
        .expect("remove nested private directory");
    let directory_collision = match private_parent.create_private_dir(&private_name) {
        Ok(_) => panic!("private directory creation must be no-replace"),
        Err(error) => error,
    };
    assert_eq!(
        directory_collision.kind(),
        std::io::ErrorKind::AlreadyExists
    );

    let file_name = PhysicalComponent::try_new("private-file").unwrap();
    let mut file = private
        .create_private_file_new(&file_name)
        .unwrap_or_else(|error| panic!("create private file: {error}"));
    #[cfg(feature = "test-support")]
    assert!(
        notecrypt_platform_fs::workspace_test_support::file_is_mutation_local_durable(&file)
            .expect("query protected file create mode")
    );
    file.write_all(b"private").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let file_collision = match private.create_private_file_new(&file_name) {
        Ok(_) => panic!("private file creation must be no-replace"),
        Err(error) => error,
    };
    assert_eq!(file_collision.kind(), std::io::ErrorKind::AlreadyExists);
    let reopened = private
        .open_private_workspace_file_nofollow(std::path::Path::new("private-file"))
        .unwrap_or_else(|error| panic!("reopen private file: {error}"));
    drop(reopened);
    let renamed_name = std::path::Path::new("renamed private Ω");
    let rename_handle = private
        .open_file_for_rename_nofollow(&file_name)
        .expect("open exact private file for rename");
    let published = match private.rename_opened_no_replace_to_workspace(
        &rename_handle,
        &file_name,
        &private,
        renamed_name,
    ) {
        Ok(published) => published,
        Err(failure) => panic!(
            "rename exact private file by handle: effect={:?}, kind={:?}, code={:?}, error={}",
            failure.effect(),
            failure.error().kind(),
            failure.error().raw_os_error(),
            failure.error()
        ),
    };
    drop(published);
    drop(rename_handle);
    drop(
        private
            .open_private_workspace_file_nofollow(renamed_name)
            .expect("reopen renamed private file"),
    );
    private_parent
        .remove_opened_private_tree(&private, &private_name, 2, 2)
        .expect("remove private directory tree");
    drop(private);
    drop(private_parent);
    #[cfg(feature = "test-support")]
    directory
        .remove_empty_dir(&PhysicalComponent::try_new("hostile-parent").unwrap())
        .expect("remove hostile parent fixture");

    let reparse_target = TempDir::new().expect("reparse target");
    let reparse_name = PhysicalComponent::try_new("reparse-collision").unwrap();
    std::os::windows::fs::symlink_dir(reparse_target.path(), root.path().join("reparse-collision"))
        .expect("create reparse collision fixture");
    let reparse_collision = match directory.create_private_dir(&reparse_name) {
        Ok(_) => panic!("private directory creation must not traverse a reparse collision"),
        Err(error) => error,
    };
    assert_eq!(reparse_collision.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        directory
            .open_private_dir_for_cleanup(&reparse_name)
            .is_err(),
        "cleanup must not traverse a reparse point"
    );
    assert_eq!(std::fs::read_dir(reparse_target.path()).unwrap().count(), 0);
    std::fs::remove_dir(root.path().join("reparse-collision"))
        .expect("remove reparse collision fixture");

    #[cfg(feature = "test-support")]
    {
        use notecrypt_platform_fs::WorkspaceDirectoryFault;
        use notecrypt_platform_fs::workspace_test_support::inject_directory_fault;

        let retry_name = PhysicalComponent::try_new("post-create-retry").unwrap();
        inject_directory_fault(WorkspaceDirectoryFault::PrivateDirectoryAfterCreate);
        assert!(directory.create_private_dir(&retry_name).is_err());
        assert_eq!(
            directory.entry_kind(&retry_name).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let retry = directory
            .create_private_dir(&retry_name)
            .expect("retry after exact post-create cleanup");
        drop(retry);
        directory
            .remove_empty_dir(&retry_name)
            .expect("remove retried directory");

        let companion_retry_name =
            PhysicalComponent::try_new("rename-target-post-create-retry").unwrap();
        inject_directory_fault(WorkspaceDirectoryFault::RenameTargetAfterCreate);
        assert!(directory.create_private_dir(&companion_retry_name).is_err());
        assert_eq!(
            directory
                .entry_kind(&companion_retry_name)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        let companion_retry = directory
            .create_private_dir(&companion_retry_name)
            .expect("retry after exact rename-target post-create cleanup");
        drop(companion_retry);
        directory
            .remove_empty_dir(&companion_retry_name)
            .expect("remove rename-target post-create retry directory");

        let readback_retry_name =
            PhysicalComponent::try_new("rename-target-readback-retry").unwrap();
        inject_directory_fault(WorkspaceDirectoryFault::RenameTargetIdentityMismatch);
        assert!(directory.create_private_dir(&readback_retry_name).is_err());
        assert_eq!(
            directory
                .entry_kind(&readback_retry_name)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        let readback_retry = directory
            .create_private_dir(&readback_retry_name)
            .expect("retry after exact rename-target readback cleanup");
        drop(readback_retry);
        directory
            .remove_empty_dir(&readback_retry_name)
            .expect("remove rename-target readback retry directory");

        let retry_file_name = PhysicalComponent::try_new("post-create-file-retry").unwrap();
        inject_directory_fault(WorkspaceDirectoryFault::PrivateFileAfterCreate);
        assert!(directory.create_private_file_new(&retry_file_name).is_err());
        assert_eq!(
            directory.entry_kind(&retry_file_name).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let retry_file = directory
            .create_private_file_new(&retry_file_name)
            .expect("retry private file after exact post-create cleanup");
        directory
            .remove_opened_file_if_matches(&retry_file, &retry_file_name)
            .expect("remove retried private file");
    }
}

#[cfg(feature = "test-support")]
#[test]
fn exact_removal_reconciles_an_after_effect_absence_readback_failure() {
    use notecrypt_platform_fs::WorkspaceCleanupFault;
    use notecrypt_platform_fs::workspace_test_support::inject_cleanup_fault;

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");

    let staging_name = PhysicalComponent::try_new("staging-file").unwrap();
    let staging = directory
        .create_private_file_new(&staging_name)
        .expect("create exact staged file");
    inject_cleanup_fault(WorkspaceCleanupFault::StagingAbsenceReadbackAfterEffect);
    assert!(
        directory
            .remove_opened_file_if_matches_unsynced(&staging, &staging_name)
            .is_err()
    );
    assert_eq!(
        directory.entry_kind(&staging_name).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    directory
        .remove_opened_file_if_matches(&staging, &staging_name)
        .expect("retry must reconcile the exact absent stage");

    let read_only_name = PhysicalComponent::try_new("read-only-expected").unwrap();
    drop(
        directory
            .create_private_file_new(&read_only_name)
            .expect("create file for read-only reopen"),
    );
    let read_only = directory
        .open_private_workspace_file_nofollow(std::path::Path::new("read-only-expected"))
        .expect("reopen expected file without DELETE authority");
    let other_name = PhysicalComponent::try_new("other-private-file").unwrap();
    drop(
        directory
            .create_private_file_new(&other_name)
            .expect("create same-parent substitution fixture"),
    );
    assert!(
        directory
            .remove_opened_file_if_matches_unsynced(&read_only, &other_name)
            .is_err(),
        "a mismatched retained file must not authorize exact removal"
    );
    assert!(directory.entry_kind(&read_only_name).is_ok());
    assert!(directory.entry_kind(&other_name).is_ok());
    directory
        .remove_opened_file_if_matches(&read_only, &read_only_name)
        .expect("exact removal must acquire DELETE authority for a read-only expected handle");
    let other = directory
        .open_private_workspace_file_nofollow(std::path::Path::new("other-private-file"))
        .unwrap();
    directory
        .remove_opened_file_if_matches(&other, &other_name)
        .expect("clean substitution fixture");

    let tree_name = PhysicalComponent::try_new("private-tree").unwrap();
    let tree = directory
        .create_private_dir(&tree_name)
        .expect("create exact private tree");
    inject_cleanup_fault(WorkspaceCleanupFault::TreeAbsenceReadbackAfterEffect);
    assert!(
        directory
            .remove_opened_private_tree_unsynced(&tree, &tree_name, 1, 1)
            .is_err()
    );
    assert_eq!(
        directory.entry_kind(&tree_name).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    directory
        .remove_opened_private_tree(&tree, &tree_name, 1, 1)
        .expect("retry must reconcile the exact absent private tree");
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn inherited_file_owner_can_conflict_with_strict_private_cleanup() {
    use notecrypt_platform_fs::workspace_test_support::file_is_private;

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let private_name = PhysicalComponent::try_new("private-parent").unwrap();
    let private = directory
        .create_private_dir(&private_name)
        .expect("create protected parent");

    let inherited_name = PhysicalComponent::try_new("ordinary-inherited-owner").unwrap();
    let inherited = private
        .create_file_new(&inherited_name)
        .expect("create ordinary inherited child");
    let inherited_is_private = file_is_private(&inherited);
    drop(inherited);

    let inherited_cleanup = private.remove_file_from_private_staging_unsynced(&inherited_name);
    eprintln!(
        "ordinary inherited child: private={inherited_is_private}, cleanup_kind={:?}, cleanup_error={:?}",
        inherited_cleanup.as_ref().err().map(std::io::Error::kind),
        inherited_cleanup.as_ref().err().map(ToString::to_string),
    );
    if inherited_is_private {
        inherited_cleanup.expect("matching token owner permits strict private cleanup");
    } else {
        let error = inherited_cleanup.expect_err(
            "a child owned by the token default owner must fail strict private cleanup",
        );
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "private file is not owned by the effective user"
        );
        assert_eq!(
            private
                .entry_kind(&inherited_name)
                .expect("ordinary child remains"),
            EntryKind::File
        );
        private
            .remove_untrusted_file_from_private_staging(&inherited_name)
            .expect("remove exact untrusted child from the private staging parent");
    }

    let explicit_name = PhysicalComponent::try_new("explicit-token-owner").unwrap();
    let explicit = private
        .create_private_file_new(&explicit_name)
        .expect("create explicitly protected child");
    assert!(
        file_is_private(&explicit),
        "the private creator must install the effective token user as owner"
    );
    drop(explicit);
    private
        .remove_file_from_private_staging_unsynced(&explicit_name)
        .expect("strict cleanup accepts an explicitly protected child");

    drop(private);
    directory
        .remove_empty_dir(&private_name)
        .expect("remove diagnostic parent");
}

#[cfg(windows)]
#[test]
fn reopened_private_tree_cleanup_uses_one_exact_delete_capable_handle() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let tree_name = PhysicalComponent::try_new("reopened-tree").unwrap();
    let created = directory
        .create_private_dir(&tree_name)
        .expect("create private tree");
    let reopened = directory
        .open_private_dir_for_cleanup(&tree_name)
        .expect("reopen exact private tree while its retained capability remains live");
    let nested_name = std::path::Path::new("nested space Ω");
    let nested = reopened
        .open_or_create_private_workspace_dir(nested_name)
        .expect("create Unicode nested private directory");
    let file_name = std::path::Path::new("private file Ω");
    let mut file = nested
        .create_private_workspace_file_new(file_name)
        .expect("create nested private file");
    file.write_all(b"private").unwrap();
    file.sync_all().unwrap();
    drop(file);
    drop(nested);

    directory
        .remove_opened_private_tree(&created, &tree_name, 2, 2)
        .expect("remove nested private tree while both exact retained handles remain live");
    assert_eq!(
        directory.entry_kind(&tree_name).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    drop(reopened);
    drop(created);
}

#[cfg(feature = "test-support")]
#[test]
fn private_tree_cleanup_removes_untrusted_regular_files_without_losing_exact_identity() {
    use notecrypt_platform_fs::workspace_test_support::inject_private_tree_file_cleanup_hook;

    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");
    let tree_name = PhysicalComponent::try_new("private-tree").unwrap();
    let tree = directory
        .create_private_dir(&tree_name)
        .expect("create private tree");
    let file_name = PhysicalComponent::try_new("raced-file").unwrap();
    let mut file = tree
        .create_file_new(&file_name)
        .expect("create ordinary workspace file");
    file.write_all(b"retained original").unwrap();
    file.sync_all().unwrap();
    drop(file);

    let selected = root.path().join("private-tree/raced-file");
    let moved = root.path().join("moved-original");
    let selected_for_hook = selected.clone();
    let moved_for_hook = moved.clone();
    inject_private_tree_file_cleanup_hook(move || {
        std::fs::rename(&selected_for_hook, &moved_for_hook).unwrap();
        std::fs::write(&selected_for_hook, b"attacker replacement").unwrap();
    });

    assert!(
        directory
            .remove_opened_private_tree(&tree, &tree_name, 1, 1)
            .is_err(),
        "a name substitution must fail before deleting the replacement"
    );
    assert_eq!(std::fs::read(&moved).unwrap(), b"retained original");
    assert_eq!(std::fs::read(&selected).unwrap(), b"attacker replacement");

    std::fs::remove_file(&selected).unwrap();
    std::fs::rename(&moved, &selected).unwrap();
    directory
        .remove_opened_private_tree(&tree, &tree_name, 1, 1)
        .expect("retry exact private-tree cleanup");

    let moved_tree_name = PhysicalComponent::try_new("rename-away-tree").unwrap();
    let moved_tree = directory
        .create_private_dir(&moved_tree_name)
        .expect("create rename-away tree");
    let moved_file_name = PhysicalComponent::try_new("rename-away-file").unwrap();
    let mut moved_file = moved_tree
        .create_file_new(&moved_file_name)
        .expect("create rename-away file");
    moved_file.write_all(b"rename-away original").unwrap();
    moved_file.sync_all().unwrap();
    drop(moved_file);
    let selected = root.path().join("rename-away-tree/rename-away-file");
    let moved = root.path().join("rename-away-original");
    let selected_for_hook = selected.clone();
    let moved_for_hook = moved.clone();
    inject_private_tree_file_cleanup_hook(move || {
        std::fs::rename(&selected_for_hook, &moved_for_hook).unwrap();
    });
    assert!(
        directory
            .remove_opened_private_tree(&moved_tree, &moved_tree_name, 1, 1)
            .is_err(),
        "rename-away before disposition must not reconcile as successful cleanup"
    );
    assert_eq!(std::fs::read(&moved).unwrap(), b"rename-away original");
    assert!(!selected.exists());
    std::fs::rename(&moved, &selected).unwrap();
    directory
        .remove_opened_private_tree(&moved_tree, &moved_tree_name, 1, 1)
        .expect("retry rename-away tree cleanup");
}

#[cfg(feature = "test-support")]
#[test]
fn private_tree_cleanup_rejects_hardlinks_and_link_like_entries() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap())
        .expect("open root capability");

    let hardlink_tree_name = PhysicalComponent::try_new("hardlink-tree").unwrap();
    let hardlink_tree = directory
        .create_private_dir(&hardlink_tree_name)
        .expect("create hardlink tree");
    let outside = root.path().join("outside-file");
    std::fs::write(&outside, b"outside").unwrap();
    let hardlink = root.path().join("hardlink-tree/hostile-hardlink");
    std::fs::hard_link(&outside, &hardlink).unwrap();
    assert!(
        directory
            .remove_opened_private_tree(&hardlink_tree, &hardlink_tree_name, 1, 1)
            .is_err(),
        "a hard-linked entry must fail before disposition"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    std::fs::remove_file(&hardlink).unwrap();
    directory
        .remove_opened_private_tree(&hardlink_tree, &hardlink_tree_name, 1, 1)
        .unwrap();

    let link_tree_name = PhysicalComponent::try_new("link-tree").unwrap();
    let link_tree = directory
        .create_private_dir(&link_tree_name)
        .expect("create link tree");
    let link = root.path().join("link-tree/hostile-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside, &link).unwrap();
    assert!(
        directory
            .remove_opened_private_tree(&link_tree, &link_tree_name, 1, 1)
            .is_err(),
        "a symlink or reparse entry must fail before traversal or disposition"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    std::fs::remove_file(&link).unwrap();
    directory
        .remove_opened_private_tree(&link_tree, &link_tree_name, 1, 1)
        .unwrap();
}

#[cfg(unix)]
#[test]
fn lock_capabilities_reject_base_and_owner_sidecar_name_substitution() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();

    for name in [".base-lock", "o-11111111111111111111111111111111"] {
        let component = PhysicalComponent::try_new(name).unwrap();
        let lock = directory.try_lock_exclusive(&component).unwrap();
        assert!(lock.validates_named_file(&directory, &component).unwrap());

        let retained = root
            .path()
            .join(format!("retained-{}", name.trim_start_matches('.')));
        std::fs::rename(root.path().join(name), &retained).unwrap();
        std::fs::write(root.path().join(name), b"replacement").unwrap();

        assert!(!lock.validates_named_file(&directory, &component).unwrap());
    }
}
