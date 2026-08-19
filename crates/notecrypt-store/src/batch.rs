use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use notecrypt_core::ObjectId;
use notecrypt_platform_fs::{Directory, ExclusiveFileLock, FileCapability, PhysicalComponent};

use crate::StoreError;
use crate::layout::{StoreLayout, component, encode_hex};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const ID_RETRIES: usize = 16;
const MAX_BATCH_OBJECTS: usize = 10_000_000;
const MAX_BATCH_BYTES: u64 = 1_u64 << 40;
const MAX_STALE_OPERATIONS: usize = 1_024;

pub(crate) struct DurableBatch<'a> {
    repository: &'a Directory,
    objects: &'a Directory,
    transaction_root: &'a Directory,
    operation: PhysicalComponent,
    staging: Directory,
    staged: Vec<StagedObject>,
    replacements: Vec<PhysicalComponent>,
    staged_ids: HashSet<ObjectId>,
    staged_bytes: u64,
    finished: bool,
    _os_lock: ExclusiveFileLock,
    _mutation: MutationGuard<'a>,
}

pub(crate) struct PublishedBatch<'a> {
    batch: DurableBatch<'a>,
    metrics: BatchMetrics,
}

struct StagedObject {
    id: ObjectId,
    name: PhysicalComponent,
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct BatchMetrics {
    pub(crate) staged_file_syncs: u64,
    pub(crate) staging_directory_syncs: u64,
    pub(crate) immutable_renames: u64,
    pub(crate) exact_existing: u64,
    pub(crate) shard_directory_syncs: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum BatchBoundary {
    Flushed,
    Authenticated,
    PublishedNames,
    DirectoriesSynced,
}

impl<'a> DurableBatch<'a> {
    pub(crate) fn begin(
        layout: &'a StoreLayout,
        mutation_active: &'a AtomicBool,
    ) -> Result<Self, StoreError> {
        let mutation = MutationGuard::acquire(mutation_active)?;
        let transaction_root = &layout.transactions;
        let os_lock = transaction_root
            .try_lock_exclusive(&component("mutation-lock")?)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    StoreError::Busy
                } else {
                    StoreError::from(error)
                }
            })?;
        sweep_stale_operations(transaction_root)?;
        let (operation, staging) = create_operation_directory(transaction_root)?;
        Ok(Self {
            repository: &layout.repository,
            objects: &layout.objects,
            transaction_root,
            operation,
            staging,
            staged: Vec::new(),
            replacements: Vec::new(),
            staged_ids: HashSet::new(),
            staged_bytes: 0,
            finished: false,
            _os_lock: os_lock,
            _mutation: mutation,
        })
    }

    pub(crate) fn stage(
        &mut self,
        id: ObjectId,
        source: &mut dyn Read,
        declared_length: u64,
    ) -> Result<(), StoreError> {
        self.stage_checked(id, source, declared_length, |_| Ok(()))
    }

    pub(crate) fn stage_checked(
        &mut self,
        id: ObjectId,
        source: &mut dyn Read,
        declared_length: u64,
        mut check_boundary: impl FnMut(u64) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if self.staged_ids.contains(&id) {
            return Err(StoreError::ImmutableObjectConflict);
        }
        if self.staged.len() >= MAX_BATCH_OBJECTS {
            return Err(StoreError::LimitExceeded);
        }
        let aggregate = self
            .staged_bytes
            .checked_add(declared_length)
            .ok_or(StoreError::LimitExceeded)?;
        if aggregate > MAX_BATCH_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        self.staged
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.staged_ids
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.staged_ids.insert(id);
        let name = component(&encode_hex(id.as_bytes()))?;
        let mut file = match self.staging.create_private_file_new(&name) {
            Ok(file) => file,
            Err(error) => {
                self.staged_ids.remove(&id);
                return Err(StoreError::from(error));
            }
        };
        self.staged.push(StagedObject { id, name });
        if let Err(primary) =
            copy_exact_bounded_checked(source, &mut file, declared_length, &mut check_boundary)
        {
            let staged = self.staged.last().ok_or(StoreError::InvalidCapability)?;
            let cleanup = self
                .staging
                .remove_untrusted_file_from_private_staging_unsynced(&staged.name);
            return match cleanup {
                Ok(()) => {
                    self.staged.pop();
                    self.staged_ids.remove(&id);
                    Err(primary)
                }
                Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(primary),
                    cleanup,
                }),
            };
        }
        self.staged_bytes = aggregate;
        Ok(())
    }

    pub(crate) fn open_staged(&self, id: &ObjectId) -> Result<FileCapability, StoreError> {
        if !self.staged_ids.contains(id) {
            return Err(StoreError::InvalidCapability);
        }
        let name = component(&encode_hex(id.as_bytes()))?;
        self.staging
            .open_file_nofollow(&name)
            .map_err(StoreError::from)
    }

    pub(crate) fn discard(mut self) -> Result<(), StoreError> {
        self.cleanup(true)?;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn authenticate_and_publish(
        self,
        authenticate: impl FnMut(&ObjectId, &mut FileCapability) -> Result<(), StoreError>,
    ) -> Result<PublishedBatch<'a>, StoreError> {
        self.authenticate_and_publish_checked(authenticate, || Ok(()))
    }

    pub(crate) fn authenticate_and_publish_checked(
        self,
        authenticate: impl FnMut(&ObjectId, &mut FileCapability) -> Result<(), StoreError>,
        check_boundary: impl FnMut() -> Result<(), StoreError>,
    ) -> Result<PublishedBatch<'a>, StoreError> {
        self.authenticate_and_publish_inner(authenticate, |_, _| Ok(()), check_boundary)
    }

    pub(crate) fn authenticate_and_publish_observed(
        self,
        authenticate: impl FnMut(&ObjectId, &mut FileCapability) -> Result<(), StoreError>,
        observe: impl FnMut(BatchBoundary, bool) -> Result<(), StoreError>,
    ) -> Result<PublishedBatch<'a>, StoreError> {
        self.authenticate_and_publish_inner(authenticate, observe, || Ok(()))
    }

    fn authenticate_and_publish_inner(
        mut self,
        mut authenticate: impl FnMut(&ObjectId, &mut FileCapability) -> Result<(), StoreError>,
        mut observe: impl FnMut(BatchBoundary, bool) -> Result<(), StoreError>,
        mut check_boundary: impl FnMut() -> Result<(), StoreError>,
    ) -> Result<PublishedBatch<'a>, StoreError> {
        let operation = self.publish(&mut authenticate, &mut observe, &mut check_boundary);
        #[cfg(feature = "test-support")]
        if matches!(operation, Err(StoreError::SimulatedCrash)) {
            self.finished = true;
            return Err(StoreError::SimulatedCrash);
        }
        match operation {
            Ok(metrics) => Ok(PublishedBatch {
                batch: self,
                metrics,
            }),
            Err(primary) => match self.cleanup(true) {
                Ok(()) => {
                    self.finished = true;
                    Err(primary)
                }
                Err(StoreError::Io(cleanup)) => Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(primary),
                    cleanup,
                }),
                Err(cleanup) => Err(cleanup),
            },
        }
    }

    fn publish(
        &mut self,
        authenticate: &mut impl FnMut(&ObjectId, &mut FileCapability) -> Result<(), StoreError>,
        observe: &mut impl FnMut(BatchBoundary, bool) -> Result<(), StoreError>,
        check_boundary: &mut impl FnMut() -> Result<(), StoreError>,
    ) -> Result<BatchMetrics, StoreError> {
        let mut metrics = BatchMetrics::default();
        observe(BatchBoundary::Flushed, true)?;
        for staged in &self.staged {
            check_boundary()?;
            let file = self.staging.open_file_for_sync_nofollow(&staged.name)?;
            file.sync_all()?;
            check_boundary()?;
            metrics.staged_file_syncs = checked_increment(metrics.staged_file_syncs)?;
        }
        self.staging.sync()?;
        metrics.staging_directory_syncs = 1;
        observe(BatchBoundary::Flushed, false)?;

        observe(BatchBoundary::Authenticated, true)?;
        for staged in &self.staged {
            check_boundary()?;
            let mut file = self.staging.open_file_nofollow(&staged.name)?;
            authenticate(&staged.id, &mut file)?;
            check_boundary()?;
        }
        observe(BatchBoundary::Authenticated, false)?;

        let mut shards = BTreeMap::new();
        for staged in &self.staged {
            check_boundary()?;
            let encoded = encode_hex(staged.id.as_bytes());
            let shard_name = component(&encoded[..2])?;
            if !shards.contains_key(&encoded[..2]) {
                let shard = self.objects.open_or_create_dir(&shard_name)?;
                if !self.staging.same_filesystem(&shard)? {
                    return Err(StoreError::UnsupportedDurability);
                }
                shards.insert(encoded[..2].to_owned(), shard);
            }
        }
        self.objects.sync()?;

        observe(BatchBoundary::PublishedNames, true)?;
        let mut touched = BTreeSet::new();
        for staged in &self.staged {
            check_boundary()?;
            let encoded = encode_hex(staged.id.as_bytes());
            let shard = shards
                .get(&encoded[..2])
                .ok_or(StoreError::InvalidCapability)?;
            let destination = component(&encoded[2..])?;
            let mut opened = self.staging.open_file_for_rename_nofollow(&staged.name)?;
            authenticate(&staged.id, &mut opened)?;
            check_boundary()?;
            opened.seek(SeekFrom::Start(0))?;
            match self.staging.rename_opened_no_replace_from_private_staging(
                &opened,
                &staged.name,
                shard,
                &destination,
            ) {
                Ok(()) => {
                    metrics.immutable_renames = checked_increment(metrics.immutable_renames)?;
                    touched.insert(encoded[..2].to_owned());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = shard.open_file_nofollow(&destination)?;
                    authenticate(&staged.id, &mut existing)?;
                    existing.seek(SeekFrom::Start(0))?;
                    compare_streams(&mut opened, &mut existing)?;
                    self.staging
                        .remove_untrusted_file_from_private_staging_unsynced(&staged.name)?;
                    metrics.exact_existing = checked_increment(metrics.exact_existing)?;
                }
                Err(error) => return Err(StoreError::from(error)),
            }
            check_boundary()?;
        }
        observe(BatchBoundary::PublishedNames, false)?;

        observe(BatchBoundary::DirectoriesSynced, true)?;
        for name in touched {
            check_boundary()?;
            let shard = shards.get(&name).ok_or(StoreError::InvalidCapability)?;
            shard.sync()?;
            check_boundary()?;
            metrics.shard_directory_syncs = checked_increment(metrics.shard_directory_syncs)?;
        }
        self.staging.sync()?;
        metrics.staging_directory_syncs = checked_increment(metrics.staging_directory_syncs)?;
        observe(BatchBoundary::DirectoriesSynced, false)?;
        Ok(metrics)
    }

    fn cleanup(&mut self, sync_staging: bool) -> Result<(), StoreError> {
        for staged in &self.staged {
            match self
                .staging
                .remove_untrusted_file_from_private_staging_unsynced(&staged.name)
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::from(error)),
            }
        }
        for replacement in &self.replacements {
            match self
                .staging
                .remove_untrusted_file_from_private_staging_unsynced(replacement)
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::from(error)),
            }
        }
        if sync_staging {
            self.staging.sync()?;
        }
        self.transaction_root.remove_empty_dir(&self.operation)?;
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn preserve_for_simulated_crash(&mut self) {
        self.finished = true;
    }
}

fn sweep_stale_operations(transaction_root: &Directory) -> Result<(), StoreError> {
    let maximum_files = MAX_BATCH_OBJECTS
        .checked_add(1)
        .ok_or(StoreError::LimitExceeded)?;
    for operation in transaction_root.entry_names_bounded(MAX_STALE_OPERATIONS)? {
        if operation.as_str() == "mutation-lock" {
            continue;
        }
        if operation.as_str().len() != 32
            || !operation
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(StoreError::FilesystemObjectRejected);
        }
        transaction_root.remove_private_file_tree(&operation, maximum_files)?;
    }
    Ok(())
}

impl PublishedBatch<'_> {
    #[cfg(any(test, feature = "benchmark-support"))]
    pub(crate) const fn metrics(&self) -> &BatchMetrics {
        &self.metrics
    }

    pub(crate) fn stage_replacement(
        &mut self,
        name: PhysicalComponent,
        source: &mut dyn Read,
        declared_length: u64,
    ) -> Result<(), StoreError> {
        if self.batch.replacements.contains(&name) {
            return Err(StoreError::InvalidCapability);
        }
        self.batch
            .replacements
            .try_reserve(1)
            .map_err(|_| StoreError::LimitExceeded)?;
        let mut file = self.batch.staging.create_private_file_new(&name)?;
        self.batch.replacements.push(name);
        if let Err(primary) = copy_exact_bounded(source, &mut file, declared_length) {
            return self.remove_failed_replacement(primary);
        }
        file.sync_all()?;
        self.batch.staging.sync()?;
        Ok(())
    }

    pub(crate) fn publish_replacement(
        &mut self,
        staged: &PhysicalComponent,
        destination: &PhysicalComponent,
    ) -> Result<(), StoreError> {
        self.publish_replacement_unsynced(staged, destination)?;
        self.sync_replacement_directories()
    }

    pub(crate) fn publish_replacement_unsynced(
        &mut self,
        staged: &PhysicalComponent,
        destination: &PhysicalComponent,
    ) -> Result<(), StoreError> {
        if !self.batch.replacements.contains(staged) {
            return Err(StoreError::InvalidCapability);
        }
        let source = self.batch.staging.open_file_for_rename_nofollow(staged)?;
        source.sync_all()?;
        self.batch
            .staging
            .replace_opened_atomic_from_private_staging(
                &source,
                staged,
                self.batch.repository,
                destination,
            )?;
        Ok(())
    }

    pub(crate) fn sync_replacement_directories(&self) -> Result<(), StoreError> {
        self.batch.repository.sync()?;
        self.batch.staging.sync()?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<BatchMetrics, StoreError> {
        self.batch.cleanup(false)?;
        self.batch.finished = true;
        Ok(std::mem::take(&mut self.metrics))
    }

    fn remove_failed_replacement(&mut self, primary: StoreError) -> Result<(), StoreError> {
        let name = self
            .batch
            .replacements
            .last()
            .ok_or(StoreError::InvalidCapability)?;
        match self
            .batch
            .staging
            .remove_untrusted_file_from_private_staging_unsynced(name)
        {
            Ok(()) => {
                self.batch.replacements.pop();
                Err(primary)
            }
            Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                primary: Box::new(primary),
                cleanup,
            }),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn preserve_for_simulated_crash(&mut self) {
        self.batch.finished = true;
    }
}

struct MutationGuard<'a>(&'a AtomicBool);

impl<'a> MutationGuard<'a> {
    fn acquire(active: &'a AtomicBool) -> Result<Self, StoreError> {
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StoreError::InvalidCapability)?;
        Ok(Self(active))
    }
}

impl Drop for MutationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Drop for DurableBatch<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup(true);
        }
    }
}

fn create_operation_directory(
    transaction_root: &Directory,
) -> Result<(PhysicalComponent, Directory), StoreError> {
    for _ in 0..ID_RETRIES {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::RandomSource)?;
        let operation = component(&encode_hex(&random))?;
        match transaction_root.create_private_dir(&operation) {
            Ok(directory) => {
                transaction_root.sync()?;
                return Ok((operation, directory));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::from(error)),
        }
    }
    Err(StoreError::IdentityCollision)
}

fn copy_exact_bounded(
    source: &mut dyn Read,
    destination: &mut FileCapability,
    declared_length: u64,
) -> Result<(), StoreError> {
    copy_exact_bounded_checked(source, destination, declared_length, &mut |_| Ok(()))
}

fn copy_exact_bounded_checked(
    source: &mut dyn Read,
    destination: &mut FileCapability,
    declared_length: u64,
    check_boundary: &mut impl FnMut(u64) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut remaining = declared_length;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .map_err(|_| StoreError::LimitExceeded)?;
        check_boundary(u64::try_from(maximum).map_err(|_| StoreError::LimitExceeded)?)?;
        let read = source.read(&mut buffer[..maximum])?;
        if read == 0 {
            return Err(StoreError::MalformedObject);
        }
        destination.write_all(&buffer[..read])?;
        check_boundary(0)?;
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| StoreError::LimitExceeded)?)
            .ok_or(StoreError::LimitExceeded)?;
    }
    let mut extra = [0_u8; 1];
    check_boundary(0)?;
    if source.read(&mut extra)? != 0 {
        return Err(StoreError::LimitExceeded);
    }
    Ok(())
}

fn compare_streams(left: &mut dyn Read, right: &mut dyn Read) -> Result<(), StoreError> {
    let mut left_buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut right_buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Err(StoreError::ImmutableObjectConflict);
        }
        if left_read == 0 {
            return Ok(());
        }
    }
}

fn checked_increment(value: u64) -> Result<u64, StoreError> {
    value.checked_add(1).ok_or(StoreError::LimitExceeded)
}

#[cfg(test)]
pub(crate) fn unique_shard_count(ids: impl IntoIterator<Item = ObjectId>) -> usize {
    ids.into_iter()
        .map(|id| encode_hex(id.as_bytes())[..2].to_owned())
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use notecrypt_core::VaultId;
    use tempfile::TempDir;

    use super::*;
    use crate::VaultStore;

    #[test]
    fn durable_batch_publishes_streams_and_removes_transient_tree() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            VaultId::from_bytes([1; 16]),
        )
        .unwrap();
        let ids = [object(0x11), object(0x12), object(0xff)];
        let mut batch = store.begin_durable_batch().unwrap();
        for (index, id) in ids.iter().enumerate() {
            let bytes = vec![u8::try_from(index).unwrap(); 17];
            batch.stage(*id, &mut Cursor::new(bytes), 17).unwrap();
        }
        let published = batch
            .authenticate_and_publish(|_, reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes)?;
                if bytes.len() != 17 {
                    return Err(StoreError::AuthenticationFailed);
                }
                Ok(())
            })
            .unwrap();
        let metrics = published.metrics();
        assert_eq!(metrics.staged_file_syncs, 3);
        assert_eq!(metrics.staging_directory_syncs, 2);
        assert_eq!(metrics.immutable_renames, 3);
        assert_eq!(metrics.shard_directory_syncs, 3);
        published.finish().unwrap();
        assert_eq!(transaction_operation_count(repository.path()), 0);
        for id in ids {
            let encoded = encode_hex(id.as_bytes());
            assert!(
                repository
                    .path()
                    .join("objects")
                    .join(&encoded[..2])
                    .join(&encoded[2..])
                    .is_file()
            );
        }
    }

    #[test]
    fn ten_thousand_objects_touch_at_most_256_shards() {
        let ids = (0_u32..10_000).map(|value| {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&value.to_be_bytes());
            ObjectId::from_bytes(bytes)
        });
        assert_eq!(unique_shard_count(ids), 1);

        let ids = (0_u32..10_000).map(|value| {
            let mut bytes = [0_u8; 32];
            bytes[0] = u8::try_from(value % 256).unwrap();
            bytes[1..5].copy_from_slice(&value.to_be_bytes());
            ObjectId::from_bytes(bytes)
        });
        assert_eq!(unique_shard_count(ids), 256);
    }

    #[test]
    fn dropped_partial_batch_removes_only_its_owned_operation() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            VaultId::from_bytes([2; 16]),
        )
        .unwrap();
        {
            let mut batch = store.begin_durable_batch().unwrap();
            batch
                .stage(object(3), &mut Cursor::new(vec![7; 32]), 32)
                .unwrap();
        }
        assert_eq!(transaction_operation_count(repository.path()), 0);
    }

    #[test]
    fn malformed_streams_and_concurrent_mutation_leave_no_residue() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            VaultId::from_bytes([3; 16]),
        )
        .unwrap();
        let mut batch = store.begin_durable_batch().unwrap();
        assert!(matches!(
            store.begin_durable_batch(),
            Err(StoreError::InvalidCapability)
        ));
        assert!(matches!(
            batch.stage(object(4), &mut Cursor::new(vec![1; 3]), 4),
            Err(StoreError::MalformedObject)
        ));
        assert!(matches!(
            batch.stage(object(5), &mut Cursor::new(vec![1; 5]), 4),
            Err(StoreError::LimitExceeded)
        ));
        drop(batch);
        assert_eq!(transaction_operation_count(repository.path()), 0);
        assert!(store.begin_durable_batch().is_ok());
    }

    #[test]
    fn operating_system_lock_prevents_a_second_store_from_sweeping_live_staging() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let repository_path = repository.path().canonicalize().unwrap();
        let local_path = local.path().canonicalize().unwrap();
        let first =
            VaultStore::create_empty(&repository_path, &local_path, VaultId::from_bytes([6; 16]))
                .unwrap();
        let second =
            VaultStore::create_empty(&repository_path, &local_path, VaultId::from_bytes([6; 16]))
                .unwrap();
        let mut batch = first.begin_durable_batch().unwrap();
        batch
            .stage(object(3), &mut Cursor::new(vec![7; 32]), 32)
            .unwrap();
        assert_eq!(transaction_operation_count(repository.path()), 1);
        assert!(matches!(
            second.begin_durable_batch(),
            Err(StoreError::Busy)
        ));
        assert_eq!(transaction_operation_count(repository.path()), 1);
        drop(batch);
        assert_eq!(transaction_operation_count(repository.path()), 0);
        assert!(second.begin_durable_batch().is_ok());
    }

    #[test]
    fn operating_system_lock_excludes_a_second_process() {
        const CHILD: &str = "NOTECRYPT_STORE_LOCK_CHILD";
        const REPOSITORY: &str = "NOTECRYPT_STORE_LOCK_REPOSITORY";
        const LOCAL: &str = "NOTECRYPT_STORE_LOCK_LOCAL";
        const READY: &str = "NOTECRYPT_STORE_LOCK_READY";
        const RELEASE: &str = "NOTECRYPT_STORE_LOCK_RELEASE";

        if std::env::var_os(CHILD).is_some() {
            let repository = std::path::PathBuf::from(std::env::var_os(REPOSITORY).unwrap());
            let local = std::path::PathBuf::from(std::env::var_os(LOCAL).unwrap());
            let ready = std::path::PathBuf::from(std::env::var_os(READY).unwrap());
            let release = std::path::PathBuf::from(std::env::var_os(RELEASE).unwrap());
            let store =
                VaultStore::create_empty(&repository, &local, VaultId::from_bytes([0x16; 16]))
                    .unwrap();
            let _batch = store.begin_durable_batch().unwrap();
            std::fs::write(&ready, b"ready").unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !release.is_file() {
                assert!(
                    Instant::now() < deadline,
                    "parent did not release child lock"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            return;
        }

        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let coordination = TempDir::new().unwrap();
        let repository_path = repository.path().canonicalize().unwrap();
        let local_path = local.path().canonicalize().unwrap();
        let ready = coordination.path().join("ready");
        let release = coordination.path().join("release");
        let store = VaultStore::create_empty(
            &repository_path,
            &local_path,
            VaultId::from_bytes([0x16; 16]),
        )
        .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("batch::tests::operating_system_lock_excludes_a_second_process")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(REPOSITORY, &repository_path)
            .env(LOCAL, &local_path)
            .env(READY, &ready)
            .env(RELEASE, &release)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.is_file() {
            assert!(Instant::now() < deadline, "child did not acquire lock");
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before ready"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(store.begin_durable_batch(), Err(StoreError::Busy)));
        std::fs::write(&release, b"release").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(store.begin_durable_batch().is_ok());
    }

    #[test]
    fn name_swap_after_step_four_authentication_is_reauthenticated_and_rejected() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            VaultId::from_bytes([4; 16]),
        )
        .unwrap();
        let id = object(8);
        let encoded = encode_hex(id.as_bytes());
        let mut batch = store.begin_durable_batch().unwrap();
        batch
            .stage(id, &mut Cursor::new(b"authenticated"), 13)
            .unwrap();
        let operation = std::fs::read_dir(repository.path().join(".notecrypt-txn"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_type().unwrap().is_dir())
            .unwrap()
            .path();
        let source_path = operation.join(&encoded);
        let original_path = outside.path().join("original");
        let mut calls = 0;
        let result = batch.authenticate_and_publish(|_, reader| {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            calls += 1;
            if bytes != b"authenticated" {
                return Err(StoreError::AuthenticationFailed);
            }
            if calls == 1 {
                std::fs::rename(&source_path, &original_path)?;
                std::fs::write(&source_path, b"attacker-data")?;
            }
            Ok(())
        });
        assert!(matches!(result, Err(StoreError::AuthenticationFailed)));
        assert_eq!(
            std::fs::read(&original_path).expect("read moved original"),
            b"authenticated"
        );
        assert_eq!(transaction_operation_count(repository.path()), 0);
        assert!(
            !repository
                .path()
                .join("objects")
                .join(&encoded[..2])
                .join(&encoded[2..])
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn beginning_a_mutation_nofollow_sweeps_owned_crash_residue() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let store = VaultStore::create_empty(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
            VaultId::from_bytes([5; 16]),
        )
        .unwrap();
        let transaction_root = repository.path().join(".notecrypt-txn");
        let stale = transaction_root.join("11111111111111111111111111111111");
        std::fs::create_dir(&stale).unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(stale.join("ciphertext"), b"encrypted").unwrap();
        let batch = store.begin_durable_batch().unwrap();
        assert!(!stale.exists());
        drop(batch);
        assert_eq!(transaction_operation_count(repository.path()), 0);

        let outside = TempDir::new().unwrap();
        symlink(
            outside.path(),
            transaction_root.join("22222222222222222222222222222222"),
        )
        .unwrap();
        assert!(matches!(
            store.begin_durable_batch(),
            Err(StoreError::Io(_)) | Err(StoreError::FilesystemObjectRejected)
        ));
        assert!(outside.path().is_dir());
    }

    fn object(first: u8) -> ObjectId {
        let mut bytes = [0_u8; 32];
        bytes[0] = first;
        ObjectId::from_bytes(bytes)
    }

    fn transaction_operation_count(repository: &std::path::Path) -> usize {
        std::fs::read_dir(repository.join(".notecrypt-txn"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .count()
    }
}
