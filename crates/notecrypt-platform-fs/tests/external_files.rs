use std::io::{Read, Write};

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
