use std::io::{Read, Write};

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

    assert!(
        staging
            .rename_opened_no_replace_from_private_staging(
                &staging.open_file_for_rename_nofollow(&staged).unwrap(),
                &staged,
                &directory,
                &destination,
            )
            .is_err()
    );
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

#[test]
fn opened_directory_reports_bounded_available_space() {
    let root = TempDir::new().expect("temp root");
    let directory = Directory::open_ambient(&root.path().canonicalize().unwrap()).unwrap();

    assert!(directory.available_space().unwrap() > 0);
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
