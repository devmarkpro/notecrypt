use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use notecrypt_crypto::{
    Argon2idParameters, DeviceWrappingKey, RecoveryPassphrase, ValidatedArgon2idParameters,
};
use notecrypt_format::{DecodeLimits, decode_bootstrap};
#[cfg(feature = "test-support")]
use notecrypt_store::local_test_support;
use notecrypt_store::{
    DeviceEnrollment, DeviceProvider, DeviceReference, PublicationGuard, ReplicationLimits,
    RepositoryEntryKind, RepositoryMutation, StoreError, StreamRevisionRequest, UnlockedVault,
    VaultRepairAction, VaultStore,
};
use tempfile::TempDir;

struct AllowPublication;

impl PublicationGuard for AllowPublication {
    fn validate(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

struct CloseOnFirstRead<'a> {
    unlocked: &'a UnlockedVault,
    bytes: Cursor<&'static [u8]>,
    closed: bool,
}

struct CloseAtEndOfStream<'a> {
    unlocked: &'a UnlockedVault,
    bytes: Cursor<&'static [u8]>,
    closed: bool,
}

struct CloseDuringPublicationValidation<'a>(&'a UnlockedVault);

impl PublicationGuard for CloseDuringPublicationValidation<'_> {
    fn validate(&mut self) -> Result<(), StoreError> {
        self.0.begin_close()
    }
}

struct GeneratedStagingObserver {
    repository: PathBuf,
    remaining: u64,
    max_read_request: usize,
    saw_staged_before_eof: bool,
}

struct ShortInterruptedReader {
    bytes: Vec<u8>,
    offset: usize,
    calls: usize,
}

impl Read for ShortInterruptedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 3 == 1 {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let available = self.bytes.len().saturating_sub(self.offset);
        let read = available.min(output.len()).min(7);
        output[..read].copy_from_slice(&self.bytes[self.offset..self.offset + read]);
        self.offset += read;
        Ok(read)
    }
}

struct CancelAfterFirstRead<'a> {
    cancel: &'a AtomicBool,
    returned: bool,
}

impl Read for CancelAfterFirstRead<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.returned {
            return Ok(0);
        }
        output[0] = 0x5a;
        self.returned = true;
        self.cancel.store(true, Ordering::Release);
        Ok(1)
    }
}

struct ErrorAfterFirstRead(bool);

struct CorruptRepositoryObjectOnFirstWrite {
    objects: Vec<PathBuf>,
    output: Vec<u8>,
    corrupted: bool,
}

impl Write for CorruptRepositoryObjectOnFirstWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.corrupted {
            for object in &self.objects {
                let mut ciphertext = std::fs::read(object)?;
                let last = ciphertext
                    .last_mut()
                    .ok_or_else(|| io::Error::other("empty encrypted object"))?;
                *last ^= 0x80;
                std::fs::write(object, ciphertext)?;
            }
            self.corrupted = true;
        }
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for ErrorAfterFirstRead {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.0 {
            return Err(io::Error::other("injected source error"));
        }
        output[0] = 0x5a;
        self.0 = true;
        Ok(1)
    }
}

impl Read for GeneratedStagingObserver {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.max_read_request = self.max_read_request.max(output.len());
        if self.remaining != 0 && transaction_staged_file_count(&self.repository) != 0 {
            self.saw_staged_before_eof = true;
        }
        let read = usize::try_from(self.remaining.min(output.len() as u64)).unwrap();
        output[..read].fill(0x6b);
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn transaction_staged_file_count(repository: &Path) -> usize {
    let transaction_root = repository.join(".notecrypt-txn");
    std::fs::read_dir(transaction_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != "mutation-lock")
        .map(|entry| std::fs::read_dir(entry.path()).unwrap().count())
        .sum()
}

impl Read for CloseOnFirstRead<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if !self.closed {
            self.unlocked.begin_close().unwrap();
            self.closed = true;
        }
        self.bytes.read(output)
    }
}

impl Read for CloseAtEndOfStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.bytes.read(output)?;
        if read == 0 && !self.closed {
            self.unlocked
                .begin_close()
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.closed = true;
        }
        Ok(read)
    }
}

#[test]
fn directory_rename_and_tombstone_mutations_are_transactional_end_to_end() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    let first = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "note.md"),
            &mut Cursor::new(b"private note"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let root = lease.root_entry_id().unwrap();

    let directory = lease
        .apply(
            RepositoryMutation::create_directory(first.snapshot_id(), root, "archive"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let renamed = lease
        .apply(
            RepositoryMutation::rename(
                directory.snapshot_id(),
                first.file_id().into(),
                root,
                "note.md",
                directory.entry_id(),
                "renamed.md",
            ),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let edited = lease
        .commit_streamed_revision(
            StreamRevisionRequest::replace(
                renamed.snapshot_id(),
                first.file_id(),
                first.revision_id(),
                "renamed.md",
            ),
            &mut Cursor::new(b"edited in archive"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let edited_entry = lease
        .list_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.id() == first.file_id().into())
        .unwrap();
    assert!(edited_entry.parent_id() == directory.entry_id());
    let deleted = lease
        .apply(
            RepositoryMutation::delete_file(
                edited.snapshot_id(),
                first.file_id().into(),
                directory.entry_id(),
                "renamed.md",
                edited.revision_id(),
            ),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();

    let entries = lease.list_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|entry| {
        entry.kind() == RepositoryEntryKind::Directory && entry.name() == "archive"
    }));
    assert!(entries.iter().any(|entry| {
        entry.kind() == RepositoryEntryKind::Tombstone && entry.name() == "renamed.md"
    }));
    assert_eq!(deleted.snapshot_id(), lease.current_snapshot_id().unwrap());
    assert!(matches!(
        lease.export(
            first.file_id(),
            edited.revision_id(),
            &mut Vec::new(),
            &cancel,
        ),
        Err(StoreError::NotFound)
    ));
}

fn parameters() -> ValidatedArgon2idParameters {
    ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap()
}

fn passphrase() -> RecoveryPassphrase {
    RecoveryPassphrase::new("alpha beta gamma delta epsilon".to_owned())
}

fn different_passphrase() -> RecoveryPassphrase {
    RecoveryPassphrase::new("one two three four five six".to_owned())
}

fn object_files(repository: &Path) -> Vec<PathBuf> {
    let mut output = Vec::new();
    for shard in std::fs::read_dir(repository.join("objects")).unwrap() {
        let shard = shard.unwrap().path();
        for object in std::fs::read_dir(shard).unwrap() {
            output.push(object.unwrap().path());
        }
    }
    output.sort_unstable();
    output
}

#[test]
fn initialize_recovery_unlock_commit_export_and_reopen_are_end_to_end() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let initialized = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    drop(initialized);
    assert!(repository.path().join(".notecrypt-vault").is_file());

    let store = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    assert!(lease.list().unwrap().is_empty());

    let cancel = AtomicBool::new(false);
    let base = lease.current_snapshot_id().unwrap();
    let first = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "note.md"),
            &mut Cursor::new(b"private note"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let listed = lease.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name(), "note.md");
    assert_eq!(listed[0].file_id(), first.file_id());

    let mut exported = Vec::new();
    lease
        .export(first.file_id(), first.revision_id(), &mut exported, &cancel)
        .unwrap();
    assert_eq!(exported, b"private note");
    drop(lease);
    unlocked.close().unwrap();

    let reopened = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    let unlocked = reopened.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let mut exported = Vec::new();
    lease
        .export(first.file_id(), first.revision_id(), &mut exported, &cancel)
        .unwrap();
    assert_eq!(exported, b"private note");
}

#[test]
fn export_binds_the_selected_revision_and_emits_nothing_before_full_authentication() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    let first = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "three-chunks.bin"),
            &mut std::io::repeat(0x6d).take(3 * 1_048_576),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let chunks = object_files(repository.path())
        .into_iter()
        .filter(|path| std::fs::metadata(path).unwrap().len() > 1_048_576)
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), 3);
    for chunk in &chunks {
        let original = std::fs::read(chunk).unwrap();
        let mut corrupted = original.clone();
        let last = corrupted.last_mut().unwrap();
        *last ^= 0x80;
        std::fs::write(chunk, corrupted).unwrap();
        let mut destination = b"unchanged".to_vec();
        assert!(
            lease
                .export(
                    first.file_id(),
                    first.revision_id(),
                    &mut destination,
                    &cancel,
                )
                .is_err()
        );
        assert_eq!(destination, b"unchanged");
        std::fs::write(chunk, original).unwrap();
    }
    let missing_chunk = chunks.last().unwrap();
    let original = std::fs::read(missing_chunk).unwrap();
    std::fs::remove_file(missing_chunk).unwrap();
    let mut destination = b"unchanged".to_vec();
    assert!(
        lease
            .export(
                first.file_id(),
                first.revision_id(),
                &mut destination,
                &cancel,
            )
            .is_err()
    );
    assert_eq!(destination, b"unchanged");
    std::fs::write(missing_chunk, original).unwrap();

    let originals = chunks
        .iter()
        .map(|object| (object.clone(), std::fs::read(object).unwrap()))
        .collect::<Vec<_>>();
    let mut destination = CorruptRepositoryObjectOnFirstWrite {
        objects: chunks.clone(),
        output: Vec::new(),
        corrupted: false,
    };
    lease
        .export(
            first.file_id(),
            first.revision_id(),
            &mut destination,
            &cancel,
        )
        .unwrap();
    assert!(destination.corrupted);
    assert_eq!(destination.output, vec![0x6d; 3 * 1_048_576]);
    for (object, original) in originals {
        std::fs::write(object, original).unwrap();
    }

    let second = lease
        .commit_streamed_revision(
            StreamRevisionRequest::replace(
                first.snapshot_id(),
                first.file_id(),
                first.revision_id(),
                "three-chunks.bin",
            ),
            &mut Cursor::new(b"new revision"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let mut destination = b"unchanged".to_vec();
    assert!(matches!(
        lease.export(
            first.file_id(),
            first.revision_id(),
            &mut destination,
            &cancel,
        ),
        Err(StoreError::InvalidCapability)
    ));
    assert_eq!(destination, b"unchanged");
    assert_ne!(first.revision_id(), second.revision_id());
}

#[test]
fn two_vaults_share_one_local_state_base_without_cross_vault_state() {
    let first_repository = TempDir::new().unwrap();
    let second_repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let first = VaultStore::initialize(
        &first_repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "first-device",
        &cancel,
    )
    .unwrap();
    let second = VaultStore::initialize(
        &second_repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "second-device",
        &cancel,
    )
    .unwrap();
    assert_ne!(first.vault_id(), second.vault_id());
    assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 2);
    first.unlock_recovery(passphrase(), &cancel).unwrap();
    second.unlock_recovery(passphrase(), &cancel).unwrap();
}

#[test]
fn post_create_initialization_failure_removes_only_the_new_vault_state() {
    let existing_repository = TempDir::new().unwrap();
    let failing_repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    VaultStore::initialize(
        &existing_repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "existing-device",
        &cancel,
    )
    .unwrap();
    assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 1);

    let invalid_label = "x".repeat(4_096);
    assert!(
        VaultStore::initialize(
            &failing_repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            passphrase(),
            parameters(),
            &invalid_label,
            &cancel,
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 1);
    assert_eq!(
        std::fs::read_dir(failing_repository.path())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn wrong_passphrase_and_missing_ancestor_object_fail_closed() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    assert!(matches!(
        store.unlock_recovery(different_passphrase(), &cancel),
        Err(StoreError::AuthenticationFailed)
    ));
    let initial_objects = object_files(repository.path());
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "note.md"),
            &mut Cursor::new(b"private note"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    drop(lease);
    unlocked.close().unwrap();
    std::fs::remove_file(&initial_objects[0]).unwrap();

    let reopened = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    assert!(reopened.unlock_recovery(passphrase(), &cancel).is_err());
}

#[cfg(feature = "test-support")]
#[test]
fn mutation_revalidates_every_current_reference_before_advancing_head() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    let committed = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "large.bin"),
            &mut std::io::repeat(0x6b).take(2 * 1_048_576),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let chunk_authentications_after_commit =
        local_test_support::local_chunk_authentication_count(&lease);
    let root = lease.root_entry_id().unwrap();
    let validated = lease
        .apply(
            RepositoryMutation::create_directory(committed.snapshot_id(), root, "validated"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert_eq!(
        local_test_support::local_chunk_authentication_count(&lease),
        chunk_authentications_after_commit,
        "the first metadata-only mutation after a streamed commit must use the authenticated publication stamp cache",
    );
    let head_before = std::fs::read(repository.path().join("head")).unwrap();
    let local_vault = std::fs::read_dir(local.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trusted_before = std::fs::read(local_vault.join("trusted/head")).unwrap();
    let chunk = object_files(repository.path())
        .into_iter()
        .max_by_key(|path| std::fs::metadata(path).unwrap().len())
        .unwrap();
    assert!(std::fs::metadata(&chunk).unwrap().len() > 1_048_576);
    let original_modified = std::fs::metadata(&chunk).unwrap().modified().unwrap();
    let mut corrupted = std::fs::read(&chunk).unwrap();
    *corrupted.last_mut().unwrap() ^= 0x80;
    std::fs::write(&chunk, corrupted).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&chunk)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(original_modified))
        .unwrap();

    assert!(
        lease
            .apply(
                RepositoryMutation::create_directory(validated.snapshot_id(), root, "must-fail"),
                &mut AllowPublication,
                &cancel,
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(repository.path().join("head")).unwrap(),
        head_before
    );
    assert_eq!(
        std::fs::read(local_vault.join("trusted/head")).unwrap(),
        trusted_before
    );
    assert_eq!(transaction_staged_file_count(repository.path()), 0);
}

#[cfg(feature = "test-support")]
#[test]
fn unavailable_change_metadata_forces_full_chunk_authentication_on_every_mutation() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    let committed = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "fallback.bin"),
            &mut Cursor::new(vec![0x4d; 1_048_576]),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let root = lease.root_entry_id().unwrap();
    local_test_support::simulate_unavailable_change_metadata(&lease);
    let before_first = local_test_support::local_chunk_authentication_count(&lease);
    let first = lease
        .apply(
            RepositoryMutation::create_directory(committed.snapshot_id(), root, "first"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let after_first = local_test_support::local_chunk_authentication_count(&lease);
    assert!(after_first > before_first);
    lease
        .apply(
            RepositoryMutation::create_directory(first.snapshot_id(), root, "second"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert!(local_test_support::local_chunk_authentication_count(&lease) > after_first);
}

#[test]
fn mutation_rejects_a_missing_tombstone_revision_object_before_advancing_head() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let base = lease.current_snapshot_id().unwrap();
    let committed = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "deleted.bin"),
            &mut std::io::repeat(0x5c).take(2 * 1_048_576),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let listed = lease
        .list_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.kind() == RepositoryEntryKind::File)
        .unwrap();
    let root = lease.root_entry_id().unwrap();
    let deleted = lease
        .apply(
            RepositoryMutation::delete_file(
                committed.snapshot_id(),
                listed.id(),
                listed.parent_id(),
                listed.name(),
                committed.revision_id(),
            ),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let head_before = std::fs::read(repository.path().join("head")).unwrap();
    let local_vault = std::fs::read_dir(local.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trusted_before = std::fs::read(local_vault.join("trusted/head")).unwrap();
    let chunk = object_files(repository.path())
        .into_iter()
        .find(|path| std::fs::metadata(path).unwrap().len() > 1_048_576)
        .unwrap();
    std::fs::remove_file(chunk).unwrap();

    assert!(
        lease
            .apply(
                RepositoryMutation::create_directory(deleted.snapshot_id(), root, "must-fail"),
                &mut AllowPublication,
                &cancel,
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(repository.path().join("head")).unwrap(),
        head_before
    );
    assert_eq!(
        std::fs::read(local_vault.join("trusted/head")).unwrap(),
        trusted_before
    );
    assert_eq!(transaction_staged_file_count(repository.path()), 0);
}

#[test]
fn mutated_bootstrap_never_opens_an_unlocked_capability() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let bootstrap = repository.path().join(".notecrypt-vault");
    let mut bytes = std::fs::read(&bootstrap).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x80;
    std::fs::write(&bootstrap, bytes).unwrap();
    let reopened = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    assert!(reopened.unlock_recovery(passphrase(), &cancel).is_err());
}

#[test]
fn replication_requires_the_exact_passphrase_authenticated_bootstrap() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let bootstrap_bytes = std::fs::read(repository.path().join(".notecrypt-vault")).unwrap();
    let bootstrap = decode_bootstrap(&bootstrap_bytes, &DecodeLimits::PHASE_1).unwrap();
    let envelope = bootstrap.recovery_slots()[0].envelope();
    let protected_fields = [
        bootstrap.kdf().salt().as_slice(),
        envelope.ciphertext(),
        envelope.nonce().as_slice(),
        envelope.tag().as_slice(),
    ];

    for protected_field in protected_fields {
        let mut mutated = bootstrap_bytes.clone();
        let offsets = mutated
            .windows(protected_field.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == protected_field).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(
            offsets.len(),
            1,
            "field must occur exactly once in bootstrap"
        );
        mutated[offsets[0]] ^= 0x80;
        assert!(decode_bootstrap(&mutated, &DecodeLimits::PHASE_1).is_ok());

        let mut lease = unlocked
            .acquire_replication_lease(ReplicationLimits::PHASE_1, ReplicationLimits::PHASE_1)
            .unwrap();
        assert!(matches!(
            lease.authenticate_bootstrap(&mutated),
            Err(StoreError::AuthenticationFailed)
        ));
    }
}

#[cfg(feature = "test-support")]
#[test]
fn streamed_revision_rejects_the_first_over_limit_chunk_before_publication() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let head_before = std::fs::read(repository.path().join("head")).unwrap();
    let mut source = Cursor::new(vec![0x5a; (2 * 1_048_576) + 1]);

    assert!(matches!(
        local_test_support::commit_with_maximum_chunks(
            &mut lease,
            "too-many.bin",
            &mut source,
            &mut AllowPublication,
            &cancel,
            2,
        ),
        Err(StoreError::LimitExceeded)
    ));
    assert_eq!(source.position(), (2 * 1_048_576 + 1) as u64);
    assert_eq!(
        std::fs::read(repository.path().join("head")).unwrap(),
        head_before
    );
    assert_eq!(transaction_staged_file_count(repository.path()), 0);
}

#[test]
fn passphrase_authorized_repair_is_explicit_and_rebuilds_only_trusted_head() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let _active = unlocked
        .enroll_device_slot(DeviceEnrollment::new(
            DeviceProvider::try_new("test-provider".to_owned()).unwrap(),
            DeviceReference::try_new("test-reference".to_owned()).unwrap(),
            DeviceWrappingKey::try_from_protected_bytes(vec![0x74; 32]).unwrap(),
        ))
        .unwrap();
    unlocked.close().unwrap();

    let local_vault = std::fs::read_dir(local.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trusted_path = local_vault.join("trusted/head");
    let mut corrupted = std::fs::read(&trusted_path).unwrap();
    let last = corrupted.last_mut().unwrap();
    *last ^= 0x80;
    std::fs::write(&trusted_path, &corrupted).unwrap();

    let candidate = store.list_device_slots().unwrap().pop().unwrap();
    assert!(matches!(
        store.unlock_device(
            candidate,
            DeviceWrappingKey::try_from_protected_bytes(vec![0x74; 32]).unwrap(),
        ),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
    assert!(matches!(
        store.unlock_recovery(passphrase(), &cancel),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
    assert_eq!(std::fs::read(&trusted_path).unwrap(), corrupted);

    let repair = store.authorize_repair(passphrase(), &cancel).unwrap();
    repair
        .apply(VaultRepairAction::RebuildTrustedHead, &cancel)
        .unwrap();

    let reopened = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    reopened
        .unlock_recovery(passphrase(), &cancel)
        .unwrap()
        .close()
        .unwrap();
}

#[test]
fn repair_refuses_to_reconstruct_state_from_an_incomplete_repository_graph() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let local_vault = std::fs::read_dir(local.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trusted_path = local_vault.join("trusted/head");
    let mut corrupted = std::fs::read(&trusted_path).unwrap();
    *corrupted.last_mut().unwrap() ^= 0x80;
    std::fs::write(&trusted_path, &corrupted).unwrap();
    std::fs::remove_file(object_files(repository.path()).pop().unwrap()).unwrap();

    assert!(store.authorize_repair(passphrase(), &cancel).is_err());
    assert_eq!(std::fs::read(trusted_path).unwrap(), corrupted);
}

#[cfg(feature = "test-support")]
#[test]
fn repair_cancellation_during_graph_authentication_never_mutates_trusted_state() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let local_vault = std::fs::read_dir(local.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trusted_path = local_vault.join("trusted/head");
    let mut corrupted = std::fs::read(&trusted_path).unwrap();
    *corrupted.last_mut().unwrap() ^= 0x80;
    std::fs::write(&trusted_path, &corrupted).unwrap();

    assert!(matches!(
        local_test_support::authorize_repair_cancel_during_graph(&store, passphrase(), &cancel,),
        Err(StoreError::Cancelled)
    ));
    assert_eq!(std::fs::read(&trusted_path).unwrap(), corrupted);

    cancel.store(false, Ordering::Release);
    let repair = store.authorize_repair(passphrase(), &cancel).unwrap();
    assert!(matches!(
        local_test_support::apply_repair_cancel_during_graph(
            repair,
            VaultRepairAction::RebuildTrustedHead,
            &cancel,
        ),
        Err(StoreError::Cancelled)
    ));
    assert_eq!(std::fs::read(&trusted_path).unwrap(), corrupted);

    cancel.store(false, Ordering::Release);
    store
        .authorize_repair(passphrase(), &cancel)
        .unwrap()
        .apply(VaultRepairAction::RebuildTrustedHead, &cancel)
        .unwrap();
}

#[test]
fn same_position_chunk_reuse_keeps_unchanged_a_and_c_objects() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let mut first_bytes = Vec::new();
    first_bytes.extend_from_slice(&vec![b'a'; 1_048_576]);
    first_bytes.extend_from_slice(&vec![b'b'; 1_048_576]);
    first_bytes.extend_from_slice(&vec![b'c'; 1_048_576]);
    let base = lease.current_snapshot_id().unwrap();
    let first = lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "large.bin"),
            &mut Cursor::new(&first_bytes),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    let before = object_files(repository.path()).len();
    let mut second_bytes = first_bytes.clone();
    second_bytes[1_048_576..2 * 1_048_576].fill(b'x');
    let second = lease
        .commit_streamed_revision(
            StreamRevisionRequest::replace(
                first.snapshot_id(),
                first.file_id(),
                first.revision_id(),
                "large.bin",
            ),
            &mut Cursor::new(&second_bytes),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert_ne!(first.revision_id(), second.revision_id());
    assert_eq!(object_files(repository.path()).len() - before, 4);
    let mut exported = Vec::new();
    lease
        .export(
            first.file_id(),
            second.revision_id(),
            &mut exported,
            &cancel,
        )
        .unwrap();
    assert_eq!(exported, second_bytes);
}

#[test]
#[cfg(feature = "test-support")]
fn partial_chunk_random_failures_never_advance_head_or_leave_staging() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let expected = lease.current_snapshot_id().unwrap();

    for failure in [
        local_test_support::ChunkRandomFailure::ObjectIdentity,
        local_test_support::ChunkRandomFailure::DataKey,
        local_test_support::ChunkRandomFailure::ContentNonce,
        local_test_support::ChunkRandomFailure::WrappingNonce,
    ] {
        let result = local_test_support::commit_with_partial_random_failure(
            &mut lease,
            "note.md",
            &mut Cursor::new(b"private note"),
            &mut AllowPublication,
            &cancel,
            failure,
        );
        assert!(matches!(result, Err(StoreError::RandomSource)));
        assert_eq!(lease.current_snapshot_id().unwrap(), expected);
        let transaction_entries = std::fs::read_dir(repository.path().join(".notecrypt-txn"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(transaction_entries.len(), 1);
        assert_eq!(transaction_entries[0], "mutation-lock");
    }
}

#[test]
fn optimistic_streamed_revision_rejects_a_stale_base() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let first_store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let second_store = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    let first_unlocked = first_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let second_unlocked = second_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut first = first_unlocked.acquire_lease().unwrap();
    let mut second = second_unlocked.acquire_lease().unwrap();
    let base = first.current_snapshot_id().unwrap();
    first
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "first.md"),
            &mut Cursor::new(b"first"),
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert!(matches!(
        second.commit_streamed_revision(
            StreamRevisionRequest::create(base, "second.md"),
            &mut Cursor::new(b"second"),
            &mut AllowPublication,
            &cancel,
        ),
        Err(StoreError::RollbackDetected)
    ));
}

#[test]
fn close_during_streaming_cleans_staging_and_never_advances_head() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let expected = lease.current_snapshot_id().unwrap();
    let mut source = CloseOnFirstRead {
        unlocked: &unlocked,
        bytes: Cursor::new(b"private note"),
        closed: false,
    };
    assert!(matches!(
        lease.commit_streamed_revision(
            StreamRevisionRequest::create(expected, "note.md"),
            &mut source,
            &mut AllowPublication,
            &cancel,
        ),
        Err(StoreError::Locked)
    ));
    drop(lease);
    unlocked.close().unwrap();
    assert_eq!(
        std::fs::read_dir(repository.path().join(".notecrypt-txn"))
            .unwrap()
            .count(),
        1
    );
    let reopened = VaultStore::open(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
    )
    .unwrap();
    let unlocked = reopened.unlock_recovery(passphrase(), &cancel).unwrap();
    assert_eq!(
        unlocked
            .acquire_lease()
            .unwrap()
            .current_snapshot_id()
            .unwrap(),
        expected
    );
}

#[test]
fn close_after_the_final_chunk_prevents_manifest_and_head_publication() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let expected = lease.current_snapshot_id().unwrap();
    let head_before = std::fs::read(repository.path().join("head")).unwrap();
    let mut source = CloseAtEndOfStream {
        unlocked: &unlocked,
        bytes: Cursor::new(b"one complete encrypted chunk"),
        closed: false,
    };
    assert!(matches!(
        lease.commit_streamed_revision(
            StreamRevisionRequest::create(expected, "note.md"),
            &mut source,
            &mut AllowPublication,
            &cancel,
        ),
        Err(StoreError::Locked)
    ));
    assert_eq!(
        std::fs::read(repository.path().join("head")).unwrap(),
        head_before
    );
    assert_eq!(transaction_staged_file_count(repository.path()), 0);
}

#[test]
fn close_from_the_production_publication_guard_prevents_head_publication() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let expected = lease.current_snapshot_id().unwrap();
    let head_before = std::fs::read(repository.path().join("head")).unwrap();
    assert!(matches!(
        lease.commit_streamed_revision(
            StreamRevisionRequest::create(expected, "note.md"),
            &mut Cursor::new(b"one complete encrypted chunk"),
            &mut CloseDuringPublicationValidation(&unlocked),
            &cancel,
        ),
        Err(StoreError::Locked)
    ));
    assert_eq!(
        std::fs::read(repository.path().join("head")).unwrap(),
        head_before
    );
    assert_eq!(transaction_staged_file_count(repository.path()), 0);
}

#[test]
fn streamed_revision_handles_boundaries_short_reads_errors_and_cancellation() {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();

    for (index, length) in [0_usize, 1, 1_048_575, 1_048_576, 1_048_577, 2_097_152]
        .into_iter()
        .enumerate()
    {
        let bytes = vec![u8::try_from(index).unwrap(); length];
        let base = lease.current_snapshot_id().unwrap();
        let mut source = ShortInterruptedReader {
            bytes: bytes.clone(),
            offset: 0,
            calls: 0,
        };
        let committed = lease
            .commit_streamed_revision(
                StreamRevisionRequest::create(base, &format!("boundary-{index}.bin")),
                &mut source,
                &mut AllowPublication,
                &cancel,
            )
            .unwrap();
        let mut exported = Vec::new();
        lease
            .export(
                committed.file_id(),
                committed.revision_id(),
                &mut exported,
                &cancel,
            )
            .unwrap();
        assert_eq!(exported, bytes);
    }

    let before_error = lease.current_snapshot_id().unwrap();
    assert!(matches!(
        lease.commit_streamed_revision(
            StreamRevisionRequest::create(before_error, "error.bin"),
            &mut ErrorAfterFirstRead(false),
            &mut AllowPublication,
            &cancel,
        ),
        Err(StoreError::Io(_))
    ));
    assert_eq!(lease.current_snapshot_id().unwrap(), before_error);
    assert_eq!(transaction_staged_file_count(repository.path()), 0);

    let cancelled = AtomicBool::new(false);
    let mut source = CancelAfterFirstRead {
        cancel: &cancelled,
        returned: false,
    };
    assert!(matches!(
        lease.commit_streamed_revision(
            StreamRevisionRequest::create(before_error, "cancelled.bin"),
            &mut source,
            &mut AllowPublication,
            &cancelled,
        ),
        Err(StoreError::Cancelled)
    ));
    assert_eq!(lease.current_snapshot_id().unwrap(), before_error);
    assert_eq!(transaction_staged_file_count(repository.path()), 0);
}

#[test]
fn large_revision_stages_completed_chunks_before_end_of_stream() {
    run_streaming_stress(32 * 1_048_576);
}

#[test]
#[ignore = "manual 10 GiB bounded-memory stress"]
fn ten_gib_revision_remains_bounded_by_chunk_and_codec_limits() {
    run_streaming_stress(10 * 1_024 * 1_024 * 1_024);
}

fn run_streaming_stress(bytes: u64) {
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "test-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked.acquire_lease().unwrap();
    let mut source = GeneratedStagingObserver {
        repository: repository.path().to_path_buf(),
        remaining: bytes,
        max_read_request: 0,
        saw_staged_before_eof: false,
    };
    let base = lease.current_snapshot_id().unwrap();
    lease
        .commit_streamed_revision(
            StreamRevisionRequest::create(base, "large.bin"),
            &mut source,
            &mut AllowPublication,
            &cancel,
        )
        .unwrap();
    assert!(source.saw_staged_before_eof);
    assert!(source.max_read_request <= 64 * 1_024);
    assert_eq!(source.remaining, 0);
}
