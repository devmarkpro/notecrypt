use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_format::{DecodeLimits, decode_bootstrap};
use notecrypt_store::{
    PublicationGuard, RepositoryEntryKind, RepositoryMutation, StoreError, StreamRevisionRequest,
    VaultStore,
};
use tempfile::TempDir;

struct AllowPublication;

impl PublicationGuard for AllowPublication {
    fn validate(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

fn passphrase() -> RecoveryPassphrase {
    RecoveryPassphrase::new("alpha beta gamma delta epsilon".to_owned())
}

fn parameters() -> ValidatedArgon2idParameters {
    ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap()
}

fn object_ids(repository: &Path) -> HashSet<String> {
    let mut ids = HashSet::new();
    for shard in fs::read_dir(repository.join("objects")).unwrap() {
        let shard = shard.unwrap();
        let shard_name = shard.file_name().into_string().unwrap();
        for object in fs::read_dir(shard.path()).unwrap() {
            let object_name = object.unwrap().file_name().into_string().unwrap();
            ids.insert(format!("{shard_name}{object_name}"));
        }
    }
    ids
}

fn root_is_empty(root: &Path) -> bool {
    fs::read_dir(root).unwrap().next().is_none()
}

fn active_transaction_exists(repository: &Path) -> bool {
    fs::read_dir(repository.join(".notecrypt-txn"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
}

#[test]
fn unlocked_source_streams_into_a_distinct_empty_physical_target_end_to_end() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let target_repository = TempDir::new().unwrap();
    let target_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let target_repository_path = target_repository.path().canonicalize().unwrap();
    let target_local_path = target_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);

    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let source_vault = source_store.vault_id();
    let source_unlocked = source_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut source_lease = source_unlocked.acquire_lease().unwrap();
    let base = source_lease.current_snapshot_id().unwrap();
    let source_revision = source_lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "note.md"),
            &mut Cursor::new(b"protected plaintext"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    drop(source_lease);

    let mut source = source_unlocked.acquire_compromise_rekey_source().unwrap();
    let mut target = source_store
        .begin_pending_target(
            &target_repository_path,
            &target_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        )
        .unwrap();
    assert!(VaultStore::open(&target_repository_path, &target_local_path).is_err());
    while let Some(entry) = source.next_entry().unwrap() {
        target.stage_entry(source.as_mut(), entry, &cancel).unwrap();
    }
    target.verify_complete(&cancel).unwrap();
    assert!(VaultStore::open(&target_repository_path, &target_local_path).is_err());
    let activated = target.activate(&cancel).unwrap();
    assert_ne!(activated.vault_id(), source_vault);

    let target_store = VaultStore::open(&target_repository_path, &target_local_path).unwrap();
    let target_unlocked = target_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut target_lease = target_unlocked.acquire_lease().unwrap();
    let entries = target_lease.list().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name(), "note.md");
    assert_ne!(entries[0].file_id(), source_revision.file_id());
    let mut plaintext = Vec::new();
    target_lease
        .export(
            entries[0].file_id(),
            entries[0].revision_id(),
            &mut plaintext,
            &cancel,
        )
        .unwrap();
    assert_eq!(plaintext, b"protected plaintext");
}

#[test]
fn authenticated_inactive_state_rejects_unlock_if_the_early_marker_is_removed() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let target_repository = TempDir::new().unwrap();
    let target_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let target_repository_path = target_repository.path().canonicalize().unwrap();
    let target_local_path = target_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let target = source_store
        .begin_pending_target(
            &target_repository_path,
            &target_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        )
        .unwrap();
    assert!(VaultStore::open(&target_repository_path, &target_local_path).is_err());

    fs::remove_file(target_repository_path.join(".notecrypt-pending")).unwrap();
    let prematurely_opened = VaultStore::open(&target_repository_path, &target_local_path).unwrap();
    assert!(
        prematurely_opened
            .unlock_recovery(passphrase(), &cancel)
            .is_err()
    );

    target.abort().unwrap();
    assert!(root_is_empty(&target_repository_path));
    assert!(root_is_empty(&target_local_path));
}

#[test]
fn source_rejects_add_rename_move_and_revision_changes_after_acquisition() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let repository_path = repository.path().canonicalize().unwrap();
    let local_path = local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository_path,
        &local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let root = lease.root_entry_id().unwrap();
    let snapshot = lease.current_snapshot_id().unwrap();
    let base = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(snapshot, "bound.md"),
            &mut Cursor::new(b"bound source"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let snapshot = lease.current_snapshot_id().unwrap();
    let directory = lease
        .apply(
            RepositoryMutation::create_directory(snapshot, root, "directory"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    drop(lease);

    let mut before_add = unlocked.acquire_compromise_rekey_source().unwrap();
    let mut mutation = unlocked.acquire_lease().unwrap();
    let snapshot = mutation.current_snapshot_id().unwrap();
    mutation
        .commit_streamed_revision(
            StreamRevisionRequest::create(snapshot, "added.md"),
            &mut Cursor::new(b"added later"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert!(before_add.next_entry().is_err());

    let mut before_rename = unlocked.acquire_compromise_rekey_source().unwrap();
    let snapshot = mutation.current_snapshot_id().unwrap();
    mutation
        .apply(
            RepositoryMutation::rename(
                snapshot,
                base.file_id().into(),
                root,
                "bound.md",
                root,
                "renamed.md",
            ),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert!(before_rename.next_entry().is_err());

    let mut before_move = unlocked.acquire_compromise_rekey_source().unwrap();
    let snapshot = mutation.current_snapshot_id().unwrap();
    mutation
        .apply(
            RepositoryMutation::rename(
                snapshot,
                base.file_id().into(),
                root,
                "renamed.md",
                directory.entry_id(),
                "renamed.md",
            ),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert!(before_move.next_entry().is_err());

    let mut before_revision = unlocked.acquire_compromise_rekey_source().unwrap();
    let root_entry = before_revision.next_entry().unwrap().unwrap();
    let directory_entry = before_revision.next_entry().unwrap().unwrap();
    let added_entry = before_revision.next_entry().unwrap().unwrap();
    let file_entry = before_revision.next_entry().unwrap().unwrap();
    let snapshot = mutation.current_snapshot_id().unwrap();
    mutation
        .commit_streamed_revision(
            notecrypt_store::StreamRevisionRequest::replace(
                snapshot,
                base.file_id(),
                base.revision_id(),
                "renamed.md",
            ),
            &mut Cursor::new(b"changed later"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let mut plaintext = Vec::new();
    assert!(
        before_revision
            .stream_plaintext(file_entry, &mut plaintext, &cancel)
            .is_err()
    );
    drop((root_entry, directory_entry, added_entry));
}

#[test]
fn verified_target_is_parentless_and_contains_no_source_object_or_logical_identity() {
    let source_repository = TempDir::new().unwrap();
    let shared_local = TempDir::new().unwrap();
    let target_repository = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let shared_local_path = shared_local.path().canonicalize().unwrap();
    let target_repository_path = target_repository.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &shared_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let source_unlocked = source_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = source_unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    let first = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "first.md"),
            &mut Cursor::new(b"first protected entry"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let second = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(first.snapshot_id(), "second.md"),
            &mut Cursor::new(b"second protected entry"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    drop(lease);
    let source_objects = object_ids(&source_repository_path);

    let mut source = source_unlocked.acquire_compromise_rekey_source().unwrap();
    let mut target = source_store
        .begin_pending_target(
            &target_repository_path,
            &shared_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        )
        .unwrap();
    while let Some(entry) = source.next_entry().unwrap() {
        target.stage_entry(source.as_mut(), entry, &cancel).unwrap();
    }
    target.verify_complete(&cancel).unwrap();
    target.activate(&cancel).unwrap();

    let target_objects = object_ids(&target_repository_path);
    assert_eq!(target_objects.len(), 6);
    assert!(target_objects.is_disjoint(&source_objects));
    let source_bootstrap = decode_bootstrap(
        &fs::read(source_repository_path.join(".notecrypt-vault")).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    let target_bootstrap = decode_bootstrap(
        &fs::read(target_repository_path.join(".notecrypt-vault")).unwrap(),
        &DecodeLimits::PHASE_1,
    )
    .unwrap();
    assert_ne!(source_bootstrap.vault_id(), target_bootstrap.vault_id());
    assert_ne!(source_bootstrap.kdf().salt(), target_bootstrap.kdf().salt());
    assert_ne!(
        source_bootstrap.recovery_slots()[0].envelope().object_id(),
        target_bootstrap.recovery_slots()[0].envelope().object_id()
    );
    assert_ne!(
        source_bootstrap.recovery_slots()[0].envelope().ciphertext(),
        target_bootstrap.recovery_slots()[0].envelope().ciphertext()
    );
    let target_store = VaultStore::open(&target_repository_path, &shared_local_path).unwrap();
    let target_unlocked = target_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut target_lease = target_unlocked.acquire_lease().unwrap();
    let entries = target_lease.list().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| {
        entry.file_id() != first.file_id() && entry.file_id() != second.file_id()
    }));
    assert!(entries.iter().all(|entry| {
        entry.revision_id() != first.revision_id() && entry.revision_id() != second.revision_id()
    }));
}

#[test]
fn authenticated_directory_hierarchy_is_rebuilt_with_new_logical_identities() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let target_repository = TempDir::new().unwrap();
    let target_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let target_repository_path = target_repository.path().canonicalize().unwrap();
    let target_local_path = target_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let source_unlocked = source_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = source_unlocked.acquire_lease().unwrap();
    let root = lease.root_entry_id().unwrap();
    let initial_snapshot = lease.current_snapshot_id().unwrap();
    let notes = lease
        .apply(
            RepositoryMutation::create_directory(initial_snapshot, root, "notes"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let notes_snapshot = lease.current_snapshot_id().unwrap();
    let archive = lease
        .apply(
            RepositoryMutation::create_directory(notes_snapshot, notes.entry_id(), "archive"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let file = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(archive.snapshot_id(), "nested.md"),
            &mut Cursor::new(b"nested protected entry"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    lease
        .apply(
            RepositoryMutation::rename(
                file.snapshot_id(),
                file.file_id().into(),
                root,
                "nested.md",
                archive.entry_id(),
                "nested.md",
            ),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let source_entries = lease.list_entries().unwrap();
    drop(lease);

    let mut source = source_unlocked.acquire_compromise_rekey_source().unwrap();
    let mut target = source_store
        .begin_pending_target(
            &target_repository_path,
            &target_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        )
        .unwrap();
    while let Some(entry) = source.next_entry().unwrap() {
        target.stage_entry(source.as_mut(), entry, &cancel).unwrap();
    }
    target.verify_complete(&cancel).unwrap();
    target.activate(&cancel).unwrap();

    let target_store = VaultStore::open(&target_repository_path, &target_local_path).unwrap();
    let target_unlocked = target_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut target_lease = target_unlocked.acquire_lease().unwrap();
    let target_entries = target_lease.list_entries().unwrap();
    assert_eq!(target_entries.len(), 3);
    let target_notes = target_entries
        .iter()
        .find(|entry| entry.name() == "notes")
        .unwrap();
    let target_archive = target_entries
        .iter()
        .find(|entry| entry.name() == "archive")
        .unwrap();
    let target_file = target_entries
        .iter()
        .find(|entry| entry.name() == "nested.md")
        .unwrap();
    assert!(target_notes.kind() == RepositoryEntryKind::Directory);
    assert!(target_archive.parent_id() == target_notes.id());
    assert!(target_file.kind() == RepositoryEntryKind::File);
    assert!(target_file.parent_id() == target_archive.id());
    assert!(target_entries.iter().all(|target_entry| {
        source_entries
            .iter()
            .all(|source_entry| source_entry.id() != target_entry.id())
    }));
    let mut plaintext = Vec::new();
    target_lease
        .export(
            notecrypt_core::FileId::from_bytes(*target_file.id().as_bytes()),
            target_file.revision_id().unwrap(),
            &mut plaintext,
            &cancel,
        )
        .unwrap();
    assert_eq!(plaintext, b"nested protected entry");
}

#[test]
fn empty_source_requires_and_accepts_authenticated_enumeration_completion() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let skipped_repository = TempDir::new().unwrap();
    let skipped_local = TempDir::new().unwrap();
    let complete_repository = TempDir::new().unwrap();
    let complete_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let skipped_repository_path = skipped_repository.path().canonicalize().unwrap();
    let skipped_local_path = skipped_local.path().canonicalize().unwrap();
    let complete_repository_path = complete_repository.path().canonicalize().unwrap();
    let complete_local_path = complete_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let source_unlocked = source_store.unlock_recovery(passphrase(), &cancel).unwrap();

    let mut skipped = source_store
        .begin_pending_target(
            &skipped_repository_path,
            &skipped_local_path,
            passphrase(),
            parameters(),
            "skipped-target",
            &cancel,
        )
        .unwrap();
    assert!(matches!(
        skipped.verify_complete(&cancel),
        Err(StoreError::InvalidCapability)
    ));
    skipped.abort().unwrap();
    assert!(root_is_empty(&skipped_repository_path));
    assert!(root_is_empty(&skipped_local_path));

    let mut source = source_unlocked.acquire_compromise_rekey_source().unwrap();
    let mut complete = source_store
        .begin_pending_target(
            &complete_repository_path,
            &complete_local_path,
            passphrase(),
            parameters(),
            "complete-target",
            &cancel,
        )
        .unwrap();
    while let Some(entry) = source.next_entry().unwrap() {
        complete
            .stage_entry(source.as_mut(), entry, &cancel)
            .unwrap();
    }
    complete.verify_complete(&cancel).unwrap();
    complete.activate(&cancel).unwrap();

    let reopened = VaultStore::open(&complete_repository_path, &complete_local_path).unwrap();
    let unlocked = reopened.unlock_recovery(passphrase(), &cancel).unwrap();
    assert!(
        unlocked
            .acquire_lease()
            .unwrap()
            .list_entries()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn target_rejects_aliases_and_nonempty_physical_repositories() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let unrelated_local = TempDir::new().unwrap();
    let occupied_repository = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let unrelated_local_path = unrelated_local.path().canonicalize().unwrap();
    let occupied_repository_path = occupied_repository.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();

    assert!(matches!(
        source_store.begin_pending_target(
            &source_repository_path,
            &unrelated_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        ),
        Err(StoreError::FilesystemObjectRejected)
    ));

    #[cfg(unix)]
    {
        let alias_parent = TempDir::new().unwrap();
        let repository_alias = alias_parent.path().join("repository-alias");
        std::os::unix::fs::symlink(&source_repository_path, &repository_alias).unwrap();
        assert!(matches!(
            source_store.begin_pending_target(
                &repository_alias,
                &unrelated_local_path,
                passphrase(),
                parameters(),
                "target-device",
                &cancel,
            ),
            Err(StoreError::FilesystemObjectRejected)
        ));
    }

    fs::write(
        occupied_repository_path.join("occupied"),
        b"not owned by notecrypt",
    )
    .unwrap();
    assert!(matches!(
        source_store.begin_pending_target(
            &occupied_repository_path,
            &unrelated_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        ),
        Err(StoreError::FilesystemObjectRejected)
    ));
    assert_eq!(
        fs::read(occupied_repository_path.join("occupied")).unwrap(),
        b"not owned by notecrypt"
    );
}

#[test]
fn partial_activation_fails_and_cleans_the_owned_target() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let target_repository = TempDir::new().unwrap();
    let target_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let target_repository_path = target_repository.path().canonicalize().unwrap();
    let target_local_path = target_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let source_unlocked = source_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = source_unlocked.acquire_lease().unwrap();
    for name in ["first.md", "second.md"] {
        let base = lease.current_snapshot_id().unwrap();
        lease
            .commit_streamed_revision(
                StreamRevisionRequest::create(base, name),
                &mut Cursor::new(name.as_bytes()),
                &mut AllowPublication,
                &cancel,
            )
            .unwrap();
    }
    drop(lease);
    let mut source = source_unlocked.acquire_compromise_rekey_source().unwrap();
    let mut target = source_store
        .begin_pending_target(
            &target_repository_path,
            &target_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        )
        .unwrap();
    let first = source.next_entry().unwrap().unwrap();
    target.stage_entry(source.as_mut(), first, &cancel).unwrap();
    assert!(matches!(
        target.verify_complete(&cancel),
        Err(StoreError::InvalidCapability)
    ));
    assert!(matches!(
        target.activate(&cancel),
        Err(StoreError::InvalidCapability)
    ));
    assert!(root_is_empty(&target_repository_path));
    assert!(root_is_empty(&target_local_path));
}

#[test]
fn abort_and_drop_remove_all_owned_target_state() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();

    for abort_explicitly in [true, false] {
        let target_repository = TempDir::new().unwrap();
        let target_local = TempDir::new().unwrap();
        let target_repository_path = target_repository.path().canonicalize().unwrap();
        let target_local_path = target_local.path().canonicalize().unwrap();
        let target = source_store
            .begin_pending_target(
                &target_repository_path,
                &target_local_path,
                passphrase(),
                parameters(),
                "target-device",
                &cancel,
            )
            .unwrap();
        assert!(!root_is_empty(&target_repository_path));
        assert!(!root_is_empty(&target_local_path));
        if abort_explicitly {
            target.abort().unwrap();
        } else {
            drop(target);
        }
        assert!(root_is_empty(&target_repository_path));
        assert!(root_is_empty(&target_local_path));
    }

    let shared_repository = TempDir::new().unwrap();
    let shared_repository_path = shared_repository.path().canonicalize().unwrap();
    let target = source_store
        .begin_pending_target(
            &shared_repository_path,
            &source_local_path,
            passphrase(),
            parameters(),
            "shared-base-target",
            &cancel,
        )
        .unwrap();
    target.abort().unwrap();
    assert!(root_is_empty(&shared_repository_path));
    assert!(VaultStore::open(&source_repository_path, &source_local_path).is_ok());
}

#[test]
fn source_lock_during_stream_prevents_target_verification_and_cleans_on_drop() {
    let source_repository = TempDir::new().unwrap();
    let source_local = TempDir::new().unwrap();
    let target_repository = TempDir::new().unwrap();
    let target_local = TempDir::new().unwrap();
    let source_repository_path = source_repository.path().canonicalize().unwrap();
    let source_local_path = source_local.path().canonicalize().unwrap();
    let target_repository_path = target_repository.path().canonicalize().unwrap();
    let target_local_path = target_local.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let source_store = VaultStore::initialize(
        &source_repository_path,
        &source_local_path,
        passphrase(),
        parameters(),
        "source-device",
        &cancel,
    )
    .unwrap();
    let source_unlocked = source_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = source_unlocked.acquire_lease().unwrap();
    let mut large_plaintext = std::io::repeat(0x5a).take(8 * 1_048_576 + 1);
    let base = lease.current_snapshot_id().unwrap();
    lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "revoked.md"),
            &mut large_plaintext,
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    drop(lease);
    let mut source = source_unlocked.acquire_compromise_rekey_source().unwrap();
    let mut target = source_store
        .begin_pending_target(
            &target_repository_path,
            &target_local_path,
            passphrase(),
            parameters(),
            "target-device",
            &cancel,
        )
        .unwrap();
    let root = source.next_entry().unwrap().unwrap();
    target.stage_entry(source.as_mut(), root, &cancel).unwrap();
    let entry = source.next_entry().unwrap().unwrap();
    let staging_finished = AtomicBool::new(false);
    let stage_result = std::thread::scope(|scope| {
        let closer = scope.spawn(|| {
            while !active_transaction_exists(&target_repository_path) {
                if staging_finished.load(Ordering::Acquire) {
                    return false;
                }
                std::thread::yield_now();
            }
            source_unlocked.begin_close().unwrap();
            true
        });
        let result = target.stage_entry(source.as_mut(), entry, &cancel);
        staging_finished.store(true, Ordering::Release);
        assert!(closer.join().unwrap());
        result
    });
    assert!(matches!(stage_result, Err(StoreError::Locked)));
    drop(target);
    drop(source);
    source_unlocked.close().unwrap();
    assert!(root_is_empty(&target_repository_path));
    assert!(root_is_empty(&target_local_path));
}

#[test]
fn compromise_capabilities_are_opaque_and_linear() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/compromise_*.rs");
}
