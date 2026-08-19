use std::io::{Read, Write};

#[cfg(feature = "test-support")]
use notecrypt_platform_fs::external_test_support::{
    cleanup_authority_storage_is_preallocated, inject_begin_failure,
    inject_final_staging_sync_failure, pending_cleanup_authority_storage_is_preallocated,
};
#[cfg(all(windows, feature = "test-support"))]
use notecrypt_platform_fs::external_test_support::{
    export_payload_attestation, stable_import_observation,
    stable_import_validator_with_current_stamp,
};
#[cfg(all(windows, feature = "test-support"))]
use notecrypt_platform_fs::workspace_test_support::private_file_access;
#[cfg(feature = "test-support")]
use notecrypt_platform_fs::workspace_test_support::{WorkspaceCleanupFault, inject_cleanup_fault};
#[cfg(feature = "test-support")]
use notecrypt_platform_fs::{ExportCleanupDiagnostic, ExportCleanupPending, ExportCleanupStage};
use notecrypt_platform_fs::{ExportOverwrite, ExternalFileSet};
use tempfile::TempDir;

fn fixture() -> (TempDir, TempDir, TempDir, ExternalFileSet) {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    let files = ExternalFileSet::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    (repository, local, external, files)
}

fn external_root(external: &TempDir) -> std::path::PathBuf {
    external.path().canonicalize().unwrap()
}

#[test]
fn import_uses_one_held_file_and_rejects_protected_roots() {
    let (repository, local, external, files) = fixture();
    let external_root = external_root(&external);
    let source = external_root.join("selected input.txt");
    std::fs::write(&source, b"stable plaintext").unwrap();

    let mut opened = files.open_stable_import(&source).unwrap();
    let validator = opened.try_validator().unwrap();
    std::fs::rename(&source, external_root.join("moved-away.txt")).unwrap();
    std::fs::write(&source, b"replacement").unwrap();
    #[cfg(all(windows, feature = "test-support"))]
    {
        let observation = stable_import_observation(&opened).unwrap();
        eprintln!(
            "native held stamp remained unchanged: {}",
            observation.held_stamp_unchanged
        );
        assert!(
            !observation.selected_name_matches,
            "native swap must resolve the retained selected name to a different file"
        );
        let identity_only = stable_import_validator_with_current_stamp(&opened).unwrap();
        assert_eq!(
            identity_only.validate_unchanged().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData,
            "named identity mismatch must fail even when the exact held stamp is current"
        );
    }
    let mut bytes = Vec::new();
    opened.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"stable plaintext");
    assert!(validator.validate_unchanged().is_err());

    std::fs::write(repository.path().join("inside"), b"ciphertext").unwrap();
    std::fs::write(local.path().join("inside"), b"state").unwrap();
    assert!(
        files
            .open_stable_import(&repository.path().join("inside"))
            .is_err()
    );
    assert!(
        files
            .open_stable_import(&local.path().join("inside"))
            .is_err()
    );
}

#[test]
fn stable_import_validation_binds_the_exact_selected_name() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);

    let unchanged = external_root.join("unchanged");
    std::fs::write(&unchanged, b"same").unwrap();
    files
        .open_stable_import(&unchanged)
        .unwrap()
        .validate_unchanged()
        .unwrap();

    let deleted = external_root.join("deleted");
    std::fs::write(&deleted, b"delete me").unwrap();
    let deleted_import = files.open_stable_import(&deleted).unwrap();
    std::fs::remove_file(&deleted).unwrap();
    assert!(deleted_import.validate_unchanged().is_err());

    let replaced = external_root.join("same-content-fresh-inode");
    let moved_replaced = external_root.join("same-content-moved");
    std::fs::write(&replaced, b"same bytes").unwrap();
    let replaced_import = files.open_stable_import(&replaced).unwrap();
    std::fs::rename(&replaced, &moved_replaced).unwrap();
    std::fs::write(&replaced, b"same bytes").unwrap();
    assert_eq!(
        replaced_import.validate_unchanged().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );

    let replaced_by_directory = external_root.join("type-replacement");
    let moved_type = external_root.join("type-replacement-moved");
    std::fs::write(&replaced_by_directory, b"file").unwrap();
    let type_import = files.open_stable_import(&replaced_by_directory).unwrap();
    std::fs::rename(&replaced_by_directory, &moved_type).unwrap();
    std::fs::create_dir(&replaced_by_directory).unwrap();
    assert!(type_import.validate_unchanged().is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let replaced_by_symlink = external_root.join("symlink-replacement");
        let moved_symlink = external_root.join("symlink-replacement-moved");
        std::fs::write(&replaced_by_symlink, b"file").unwrap();
        let symlink_import = files.open_stable_import(&replaced_by_symlink).unwrap();
        std::fs::rename(&replaced_by_symlink, &moved_symlink).unwrap();
        symlink(&moved_symlink, &replaced_by_symlink).unwrap();
        assert!(symlink_import.validate_unchanged().is_err());
    }
}

#[test]
fn stable_import_detects_mutation_of_the_held_file() {
    let (_repository, _local, external, files) = fixture();
    let source = external_root(&external).join("source");
    std::fs::write(&source, b"before").unwrap();

    let mut opened = files.open_stable_import(&source).unwrap();
    std::fs::write(&source, b"after-content").unwrap();
    assert!(opened.validate_unchanged().is_err());

    let mut bytes = Vec::new();
    opened.read_to_end(&mut bytes).unwrap();
    assert_ne!(bytes, b"before");
}

#[test]
fn private_export_is_invisible_until_publish_and_abort_preserves_destination() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("report final.bin");
    std::fs::write(&destination, b"existing").unwrap();

    let refused = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .expect_err("existing destination requires confirmation");
    assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);

    let mut transaction = files
        .begin_export(&destination, ExportOverwrite::Confirmed)
        .unwrap();
    transaction.write_all(b"partial plaintext canary").unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let staging = std::fs::read_dir(&external_root)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".notecrypt-export-")
            })
            .expect("private export staging exists");
        assert_eq!(
            staging.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    transaction.abort().unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 1);
}

#[test]
fn protected_root_capabilities_reject_aliasing_and_nesting() {
    let repository = TempDir::new().unwrap();
    let repository_root = repository.path().canonicalize().unwrap();
    let nested = repository_root.join("nested");
    std::fs::create_dir(&nested).unwrap();

    assert!(ExternalFileSet::open(&repository_root, &repository_root).is_err());
    assert!(ExternalFileSet::open(&repository_root, &nested).is_err());
    assert!(ExternalFileSet::open(&nested, &repository_root).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_parent_cannot_alias_a_protected_root() {
    use std::os::unix::fs::symlink;

    let (repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    std::fs::write(repository.path().join("protected"), b"ciphertext").unwrap();
    symlink(repository.path(), external_root.join("repository-alias")).unwrap();

    let aliased = external_root.join("repository-alias/protected");
    assert!(files.open_stable_import(&aliased).is_err());
    assert!(
        files
            .begin_export(&aliased, ExportOverwrite::Confirmed)
            .is_err()
    );
    assert_eq!(
        std::fs::read(repository.path().join("protected")).unwrap(),
        b"ciphertext"
    );
}

#[test]
fn export_publishes_one_flushed_complete_file() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("new export.bin");
    let mut transaction = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();
    transaction.write_all(b"complete plaintext").unwrap();
    assert!(!destination.exists());
    transaction.publish().unwrap();

    assert_eq!(std::fs::read(&destination).unwrap(), b"complete plaintext");
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 1);
}

#[cfg(feature = "test-support")]
#[test]
fn export_preallocates_cleanup_authority_before_staging_effects() {
    let (_repository, _local, external, files) = fixture();
    let destination = external_root(&external).join("preallocated-cleanup");
    let export = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();

    assert!(cleanup_authority_storage_is_preallocated(&export));
    drop(export);

    inject_begin_failure(&files, 1);
    let failure = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .expect_err("injected payload creation failure");
    let pending = failure
        .into_pending_cleanup()
        .expect("cleanup failure retains preallocated authority");
    assert!(pending_cleanup_authority_storage_is_preallocated(&pending));
    pending.retry().unwrap();
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_export_payload_is_private_before_first_plaintext_write() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("private-before-write");
    let export = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();

    let attestation = export_payload_attestation(&export)
        .expect("attest the exact retained payload before its first write");
    assert!(attestation.private);
    assert!(attestation.single_regular_link);
    assert!(attestation.mutation_local_durable);
    assert!(attestation.cleanup_reopen_matches);
    assert_eq!(attestation.access, private_file_access());

    export
        .abort()
        .expect("private unwritten payload cleans up on its first attempt");
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 0);
}

#[test]
fn raced_destination_is_never_clobbered() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("raced");
    let mut transaction = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();
    transaction.write_all(b"new").unwrap();
    std::fs::write(&destination, b"raced existing").unwrap();

    assert!(transaction.publish().is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"raced existing");
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 1);
}

#[test]
fn confirmed_overwrite_rejects_a_destination_identity_swap() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("replace-me");
    std::fs::write(&destination, b"original").unwrap();
    let mut transaction = files
        .begin_export(&destination, ExportOverwrite::Confirmed)
        .unwrap();
    transaction.write_all(b"new").unwrap();

    std::fs::rename(&destination, external_root.join("original-away")).unwrap();
    std::fs::write(&destination, b"swapped").unwrap();
    assert!(transaction.publish().is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"swapped");
}

#[test]
fn confirmed_overwrite_atomically_replaces_the_held_destination() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("replace-complete");
    std::fs::write(&destination, b"original").unwrap();
    let mut transaction = files
        .begin_export(&destination, ExportOverwrite::Confirmed)
        .unwrap();
    transaction.write_all(b"complete replacement").unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"original");

    transaction.publish().unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"complete replacement"
    );
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn import_and_export_reject_symlinks_and_hardlinks() {
    use std::os::unix::fs::symlink;

    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let ordinary = external_root.join("ordinary");
    let hard = external_root.join("hard");
    let link = external_root.join("link");
    std::fs::write(&ordinary, b"bytes").unwrap();
    std::fs::hard_link(&ordinary, &hard).unwrap();
    symlink(&ordinary, &link).unwrap();

    assert!(files.open_stable_import(&ordinary).is_err());
    assert!(files.open_stable_import(&hard).is_err());
    assert!(files.open_stable_import(&link).is_err());
    assert!(
        files
            .begin_export(&hard, ExportOverwrite::Confirmed)
            .is_err()
    );
    assert!(
        files
            .begin_export(&link, ExportOverwrite::Confirmed)
            .is_err()
    );
}

#[test]
fn path_bearing_capabilities_have_redacted_debug_output() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let source = external_root.join("secret-name.txt");
    std::fs::write(&source, b"bytes").unwrap();
    let import = files.open_stable_import(&source).unwrap();
    let export = files
        .begin_export(
            &external_root.join("secret-export.txt"),
            ExportOverwrite::Refuse,
        )
        .unwrap();

    assert_eq!(format!("{import:?}"), "StableImport(<redacted>)");
    assert_eq!(format!("{export:?}"), "ExportTransaction(<redacted>)");
}

#[cfg(windows)]
#[test]
fn windows_export_staging_verifies_owner_only_dacl_before_plaintext_write() {
    let (_repository, _local, external, files) = fixture();
    let destination = external_root(&external).join("private-export");
    let mut export = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();
    export.write_all(b"private plaintext").unwrap();
    assert!(!destination.exists());
    export.abort().unwrap();
}

#[cfg(feature = "test-support")]
fn retained_cleanup_diagnostic(
    pending: &ExportCleanupPending,
    label: &'static str,
) -> ExportCleanupDiagnostic {
    let diagnostic = pending
        .diagnostic()
        .unwrap_or_else(|| panic!("{label} retained cleanup without a diagnostic"));
    eprintln!(
        "{label}: stage={:?} kind={:?} raw_os_error={:?}",
        diagnostic.stage, diagnostic.kind, diagnostic.raw_os_error
    );
    diagnostic
}

#[cfg(feature = "test-support")]
fn assert_one_exact_staging_namespace(root: &std::path::Path, destination_count: usize) -> bool {
    let mut staging = None;
    let mut ordinary = 0_usize;
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".notecrypt-export-")
        {
            assert!(staging.replace(entry.path()).is_none());
        } else {
            ordinary += 1;
        }
    }
    assert_eq!(ordinary, destination_count);
    let staging = staging.expect("one retained export staging directory");
    let mut payload_visible = false;
    let mut entry_count = 0_usize;
    for entry in std::fs::read_dir(staging).unwrap() {
        let entry = entry.unwrap();
        entry_count += 1;
        assert_eq!(entry.file_name(), "payload");
        assert!(entry.file_type().unwrap().is_file());
        payload_visible = true;
    }
    assert_eq!(entry_count, usize::from(payload_visible));
    payload_visible
}

#[cfg(feature = "test-support")]
#[test]
fn export_cleanup_distinguishes_named_reopen_failure_and_retries_exact_authority() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("named-reopen");
    let mut export = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();
    export.write_all(b"private plaintext").unwrap();
    inject_cleanup_fault(WorkspaceCleanupFault::StagingNamedReopen);

    let pending = export
        .abort()
        .expect_err("named reopen fault retains cleanup");
    let diagnostic = retained_cleanup_diagnostic(&pending, "named reopen cleanup");
    assert_eq!(diagnostic.stage, ExportCleanupStage::PayloadNamedOpen);
    assert!(assert_one_exact_staging_namespace(&external_root, 0));
    pending.retry().unwrap();
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 0);
}

#[cfg(feature = "test-support")]
#[test]
fn final_staging_sync_failure_retains_exact_authority_for_retry() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("final-sync");
    let mut export = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();
    export.write_all(b"private plaintext").unwrap();
    inject_final_staging_sync_failure(&mut export);

    let pending = export
        .abort()
        .expect_err("final sync fault retains cleanup");
    let diagnostic = retained_cleanup_diagnostic(&pending, "final staging sync cleanup");
    assert_eq!(diagnostic.stage, ExportCleanupStage::StagingSync);
    assert!(!assert_one_exact_staging_namespace(&external_root, 0));
    pending.retry().unwrap();
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 0);
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_abort_cleanup_succeeds_without_pending_authority() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("existing");
    std::fs::write(&destination, b"existing").unwrap();
    let mut export = files
        .begin_export(&destination, ExportOverwrite::Confirmed)
        .unwrap();
    assert!(cleanup_authority_storage_is_preallocated(&export));
    export.write_all(b"private plaintext").unwrap();

    export
        .abort()
        .expect("private payload abort cleans up on its first attempt");

    assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 1);
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_raced_publication_cleanup_succeeds_without_pending_authority() {
    let (_repository, _local, external, files) = fixture();
    let external_root = external_root(&external);
    let destination = external_root.join("raced");
    let mut export = files
        .begin_export(&destination, ExportOverwrite::Refuse)
        .unwrap();
    assert!(cleanup_authority_storage_is_preallocated(&export));
    export.write_all(b"new").unwrap();
    std::fs::write(&destination, b"raced existing").unwrap();

    let failure = export.publish().expect_err("raced destination must fail");
    assert!(
        failure.into_pending_cleanup().is_none(),
        "private raced payload cleans up on its first attempt"
    );

    assert_eq!(std::fs::read(&destination).unwrap(), b"raced existing");
    assert_eq!(std::fs::read_dir(&external_root).unwrap().count(), 1);
}
