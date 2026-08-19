use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use notecrypt_core::{ObjectId, VaultId};
use notecrypt_crypto::{DeviceWrappingKey, OsRandom};
use notecrypt_format::{DecodeLimits, decode_local_state};
use notecrypt_platform_fs::{Directory, ExclusiveFileLock, FileCapability};

use crate::StoreError;
use crate::batch::DurableBatch;
use crate::cleanup::{
    ActiveWorkspace, AuthenticatedCleanupRecord, CleanupRecordPersistence, CleanupRecordVisitor,
    CleanupRegistry, CreateRecordOutcome,
    PreparedWorkspaceRegistration as PreparedCleanupRegistration,
    PreparedWorkspaceUnregister as PreparedCleanupUnregister, RegisteredWorkspace,
    WorkspaceAbsenceAuthority, WorkspaceAbsenceProof,
};
use crate::device::{
    ActiveDeviceSlot, CreateDeviceRecordOutcome, DeviceEnrollment, DeviceRecordVisitor,
    DeviceSlotPersistence, DeviceSlotRegistry, DisabledDeviceSlotPendingProviderRemoval,
    UntrustedDeviceSlotCandidate,
};
use crate::key_cell::KeyCell;
use crate::layout::StoreLayout;
use crate::layout::{component, encode_hex};
use crate::local::{StampCachePolicy, VerifiedChunkStamp};
use crate::local_io::{
    DurableMutationOutcome, read_optional, remove_durable_if_exact, replace_durable_if_exact,
};
use crate::reachability::OperationRegistry;
use crate::replication::{QuarantineLease, ReplicationLease, ReplicationLimits};
use crate::replication::{QuarantineReservations, reservations_for};

pub struct VaultStore {
    pub(crate) layout: StoreLayout,
    pub(crate) mutation_active: AtomicBool,
    pub(crate) quarantine_reservations: Arc<QuarantineReservations>,
    pub(crate) repository_reservations: Arc<QuarantineReservations>,
    pub(crate) replication_operations: Arc<OperationRegistry>,
}

pub struct UnlockedVault {
    pub(crate) store: Arc<VaultStore>,
    pub(crate) keys: Arc<KeyCell>,
    pub(crate) generation: u64,
    pub(crate) workspace_absence_authority: Option<WorkspaceAbsenceAuthority>,
    pub(crate) verified_chunks: Arc<Mutex<HashMap<ObjectId, VerifiedChunkStamp>>>,
    pub(crate) stamp_cache_policy: Arc<StampCachePolicy>,
    pub(crate) authenticated_bootstrap: Option<Arc<[u8]>>,
}

/// Linear revocation-safe authority for one exact authenticated workspace record deletion.
pub struct PreparedWorkspaceUnregister {
    store: Arc<VaultStore>,
    generation: u64,
    authority: WorkspaceAbsenceAuthority,
    prepared: PreparedCleanupUnregister,
}

/// Caller-retained exact registration and cleanup intent prepared before durable publication.
pub struct PreparedWorkspaceRegistration {
    store: Arc<VaultStore>,
    generation: u64,
    authority: WorkspaceAbsenceAuthority,
    prepared: PreparedCleanupRegistration,
}

impl PreparedWorkspaceRegistration {
    #[must_use]
    pub const fn workspace_id(&self) -> &crate::CleanupWorkspaceId {
        self.prepared.workspace_id()
    }

    pub fn unregister_absent(&mut self) -> Result<(), StoreError> {
        let active = {
            let _mutation = self.store.begin_store_mutation()?;
            let mut registry = CleanupRegistry::new(
                self.store.layout.vault,
                self.generation,
                1_024,
                OsRandom,
                FilesystemCleanupPersistence::new(
                    &self.store.layout.cleanup_registry,
                    &self.store.layout.cleanup_staging,
                ),
            )?;
            let Some(active) = registry.reconcile_registration(&mut self.prepared)? else {
                return registry.cancel_registration_if_absent(&mut self.prepared);
            };
            active
        };
        let mut proof = self
            .authority
            .acquire_registration(&self.prepared, active)?;
        let _mutation = self.store.begin_store_mutation()?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        if registry.reconcile_registration(&mut self.prepared)? != Some(active) {
            return Err(StoreError::InvalidCapability);
        }
        registry.unregister_registration_absence(
            &mut self.prepared,
            &mut proof,
            &self.authority,
            active,
        )
    }
}

impl PreparedWorkspaceUnregister {
    #[must_use]
    pub const fn workspace_id(&self) -> &crate::CleanupWorkspaceId {
        self.prepared.workspace_id()
    }

    pub fn unregister_absent(&mut self) -> Result<(), StoreError> {
        let mut proof = self.authority.acquire_prepared(&self.prepared)?;
        let _mutation = self.store.begin_store_mutation()?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.unregister_prepared_absence(&mut self.prepared, &mut proof, &self.authority)
    }
}

pub(crate) struct StoreMutation<'a> {
    active: &'a AtomicBool,
    _lock: ExclusiveFileLock,
}

impl Drop for StoreMutation<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

pub(crate) struct FilesystemCleanupPersistence<'a> {
    directory: &'a Directory,
    staging: &'a Directory,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegistrationPersistenceFault {
    ShortWrite,
    FileSync,
    PublicationBeforeEffect,
    PublicationAfterEffect,
    SourceDirectorySync,
    DestinationDirectorySync,
    Readback,
}

#[cfg(test)]
thread_local! {
    static REGISTRATION_PERSISTENCE_FAULT: std::cell::Cell<Option<RegistrationPersistenceFault>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn install_registration_persistence_fault(fault: RegistrationPersistenceFault) {
    REGISTRATION_PERSISTENCE_FAULT.set(Some(fault));
}

#[cfg(test)]
fn take_registration_persistence_fault(fault: RegistrationPersistenceFault) -> bool {
    REGISTRATION_PERSISTENCE_FAULT.with(|installed| {
        if installed.get() == Some(fault) {
            installed.set(None);
            true
        } else {
            false
        }
    })
}

pub(crate) struct FilesystemDeviceSlotPersistence<'a> {
    layout: &'a StoreLayout,
}

impl<'a> FilesystemDeviceSlotPersistence<'a> {
    pub(crate) const fn new(layout: &'a StoreLayout) -> Self {
        Self { layout }
    }
}

impl DeviceSlotPersistence for FilesystemDeviceSlotPersistence<'_> {
    fn create_if_absent(
        &mut self,
        record_id: [u8; 32],
        canonical_record: &[u8],
        maximum_records: usize,
    ) -> Result<CreateDeviceRecordOutcome, StoreError> {
        if self
            .layout
            .device_slots
            .entry_names_bounded(maximum_records)?
            .len()
            >= maximum_records
        {
            return Err(StoreError::LimitExceeded);
        }
        let name = component(&encode_hex(&record_id))?;
        let mut file = match self.layout.device_slots.create_private_file_new(&name) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(CreateDeviceRecordOutcome::AlreadyExists);
            }
            Err(error) => return Err(StoreError::from(error)),
        };
        let operation = file
            .write_all(canonical_record)
            .and_then(|()| file.sync_all())
            .and_then(|()| self.layout.device_slots.sync());
        if let Err(primary) = operation {
            return match self.layout.device_slots.remove_file(&name) {
                Ok(()) => Err(StoreError::Io(primary)),
                Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(StoreError::Io(primary)),
                    cleanup,
                }),
            };
        }
        Ok(CreateDeviceRecordOutcome::Created)
    }

    fn read_bounded(
        &mut self,
        record_id: &[u8; 32],
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let result = read_optional(
            &self.layout.device_slots,
            &component(&encode_hex(record_id))?,
        )?;
        if result
            .as_ref()
            .is_some_and(|bytes| bytes.len() > maximum_bytes)
        {
            return Err(StoreError::LimitExceeded);
        }
        Ok(result)
    }

    fn replace_if_exact(
        &mut self,
        record_id: &[u8; 32],
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<DurableMutationOutcome, StoreError> {
        let name = component(&encode_hex(record_id))?;
        replace_durable_if_exact(&self.layout.device_slots, &name, expected, replacement)
    }

    fn remove_if_exact(
        &mut self,
        record_id: &[u8; 32],
        expected: &[u8],
    ) -> Result<DurableMutationOutcome, StoreError> {
        let name = component(&encode_hex(record_id))?;
        remove_durable_if_exact(&self.layout.device_slots, &name, expected)
    }

    fn sync_directory(&mut self) -> Result<(), StoreError> {
        self.layout.device_slots.sync().map_err(StoreError::from)
    }

    fn visit_device_records_bounded(
        &mut self,
        maximum_records: usize,
        maximum_record_bytes: usize,
        visitor: &mut DeviceRecordVisitor<'_>,
    ) -> Result<(), StoreError> {
        visit_local_directory(
            &self.layout.device_slots,
            maximum_records,
            maximum_record_bytes,
            visitor,
        )
    }

    fn visit_all_local_records_bounded(
        &mut self,
        maximum_records: usize,
        maximum_record_bytes: usize,
        visitor: &mut DeviceRecordVisitor<'_>,
    ) -> Result<(), StoreError> {
        let mut visited = 0_usize;
        for directory in [
            &self.layout.device_slots,
            &self.layout.trusted,
            &self.layout.trusted_remote,
            &self.layout.journal,
            &self.layout.cleanup_registry,
        ] {
            visit_local_directory(
                directory,
                maximum_records.saturating_sub(visited),
                maximum_record_bytes,
                &mut |record_id, bytes| {
                    visited = visited.checked_add(1).ok_or(StoreError::LimitExceeded)?;
                    if visited > maximum_records {
                        return Err(StoreError::LimitExceeded);
                    }
                    visitor(record_id, bytes)
                },
            )?;
        }
        Ok(())
    }
}

fn visit_local_directory(
    directory: &Directory,
    maximum_records: usize,
    maximum_record_bytes: usize,
    visitor: &mut DeviceRecordVisitor<'_>,
) -> Result<(), StoreError> {
    for name in directory.entry_names_bounded(maximum_records)? {
        let bytes = read_optional(directory, &name)?.ok_or(StoreError::NotFound)?;
        if bytes.len() > maximum_record_bytes {
            return Err(StoreError::LimitExceeded);
        }
        let record = decode_local_state(&bytes, &DecodeLimits::PHASE_1)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
        visitor(*record.object_id(), &bytes)?;
    }
    Ok(())
}

impl<'a> FilesystemCleanupPersistence<'a> {
    pub(crate) const fn new(directory: &'a Directory, staging: &'a Directory) -> Self {
        Self { directory, staging }
    }
}

impl CleanupRecordPersistence for FilesystemCleanupPersistence<'_> {
    fn cleanup_staging_bounded(&mut self, _maximum_records: usize) -> Result<(), StoreError> {
        let names = self.staging.entry_names_bounded(1)?;
        if names.is_empty() {
            return Ok(());
        }
        for name in names {
            let value = name.as_str();
            if value != "registration" {
                return Err(StoreError::MalformedObject);
            }
            self.staging.remove_file(&component(value)?)?;
        }
        self.staging.sync()?;
        Ok(())
    }

    fn record_count_bounded(&mut self, maximum_records: usize) -> Result<usize, StoreError> {
        Ok(self.directory.entry_names_bounded(maximum_records)?.len())
    }

    fn create_if_absent(
        &mut self,
        record_id: [u8; 32],
        canonical_record: &[u8],
    ) -> Result<CreateRecordOutcome, StoreError> {
        let name = component(&encode_hex(&record_id))?;
        let staged = component("registration")?;
        match self.staging.remove_file(&staged) {
            Ok(()) => self.staging.sync()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::from(error)),
        }
        let mut file = self.staging.create_private_file_new(&staged)?;
        #[cfg(test)]
        if take_registration_persistence_fault(RegistrationPersistenceFault::ShortWrite) {
            let count = canonical_record.len().min(7);
            file.write_all(&canonical_record[..count])?;
            let primary = std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "injected short registration write",
            );
            return match self.staging.remove_opened_file_if_matches(&file, &staged) {
                Ok(()) => Err(StoreError::Io(primary)),
                Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(StoreError::Io(primary)),
                    cleanup,
                }),
            };
        }
        if let Err(primary) = file.write_all(canonical_record).and_then(|()| {
            #[cfg(test)]
            if take_registration_persistence_fault(RegistrationPersistenceFault::FileSync) {
                return Err(std::io::Error::other(
                    "injected registration file sync failure",
                ));
            }
            file.sync_all()
        }) {
            return match self.staging.remove_opened_file_if_matches(&file, &staged) {
                Ok(()) => Err(StoreError::Io(primary)),
                Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(StoreError::Io(primary)),
                    cleanup,
                }),
            };
        }
        #[cfg(test)]
        if take_registration_persistence_fault(
            RegistrationPersistenceFault::PublicationBeforeEffect,
        ) {
            self.staging.remove_opened_file_if_matches(&file, &staged)?;
            return Err(StoreError::Io(std::io::Error::other(
                "injected registration publication failure before effect",
            )));
        }
        match self.staging.rename_opened_no_replace_from_private_staging(
            &file,
            &staged,
            self.directory,
            &name,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.staging.remove_opened_file_if_matches(&file, &staged)?;
                return Ok(CreateRecordOutcome::AlreadyExists);
            }
            Err(primary) => {
                return match self.staging.remove_opened_file_if_matches(&file, &staged) {
                    Ok(()) => Err(StoreError::Io(primary)),
                    Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => {
                        Err(StoreError::Io(primary))
                    }
                    Err(cleanup) => Err(StoreError::CleanupAfterFailure {
                        primary: Box::new(StoreError::Io(primary)),
                        cleanup,
                    }),
                };
            }
        }
        #[cfg(test)]
        if take_registration_persistence_fault(RegistrationPersistenceFault::PublicationAfterEffect)
        {
            return Err(StoreError::Io(std::io::Error::other(
                "injected registration publication failure after effect",
            )));
        }
        #[cfg(test)]
        if take_registration_persistence_fault(RegistrationPersistenceFault::SourceDirectorySync) {
            return Err(StoreError::Io(std::io::Error::other(
                "injected registration source-directory sync failure",
            )));
        }
        self.staging.sync()?;
        #[cfg(test)]
        if take_registration_persistence_fault(
            RegistrationPersistenceFault::DestinationDirectorySync,
        ) {
            return Err(StoreError::Io(std::io::Error::other(
                "injected registration destination-directory sync failure",
            )));
        }
        self.directory.sync()?;
        #[cfg(test)]
        if take_registration_persistence_fault(RegistrationPersistenceFault::Readback) {
            return Err(StoreError::Io(std::io::Error::other(
                "injected registration readback failure",
            )));
        }
        if read_optional(self.directory, &name)?.as_deref() != Some(canonical_record) {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        Ok(CreateRecordOutcome::Created)
    }

    fn read_bounded(
        &mut self,
        record_id: &[u8; 32],
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let result = read_optional(self.directory, &component(&encode_hex(record_id))?)?;
        if result
            .as_ref()
            .is_some_and(|bytes| bytes.len() > maximum_bytes)
        {
            return Err(StoreError::LimitExceeded);
        }
        Ok(result)
    }

    fn replace_if_exact(
        &mut self,
        record_id: &[u8; 32],
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<DurableMutationOutcome, StoreError> {
        let name = component(&encode_hex(record_id))?;
        replace_durable_if_exact(self.directory, &name, expected, replacement)
    }

    fn remove_if_exact(
        &mut self,
        record_id: &[u8; 32],
        expected: &[u8],
    ) -> Result<DurableMutationOutcome, StoreError> {
        let name = component(&encode_hex(record_id))?;
        remove_durable_if_exact(self.directory, &name, expected)
    }

    fn sync_directory(&mut self) -> Result<(), StoreError> {
        self.directory.sync().map_err(StoreError::from)
    }

    fn sync_registration_source_directory(&mut self) -> Result<(), StoreError> {
        self.staging.sync().map_err(StoreError::from)
    }

    fn visit_bounded(
        &mut self,
        maximum_records: usize,
        maximum_record_bytes: usize,
        visitor: &mut CleanupRecordVisitor<'_>,
    ) -> Result<(), StoreError> {
        for name in self.directory.entry_names_bounded(maximum_records)? {
            let record_id = decode_record_id(name.as_str())?;
            let bytes = read_optional(self.directory, &name)?.ok_or(StoreError::NotFound)?;
            if bytes.len() > maximum_record_bytes {
                return Err(StoreError::LimitExceeded);
            }
            visitor(record_id, &bytes)?;
        }
        Ok(())
    }
}

fn decode_record_id(value: &str) -> Result<[u8; 32], StoreError> {
    if value.len() != 64 {
        return Err(StoreError::FilesystemObjectRejected);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn decode_nibble(value: u8) -> Result<u8, StoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StoreError::FilesystemObjectRejected),
    }
}

impl VaultStore {
    #[cfg(feature = "test-support")]
    pub(crate) fn create_empty(
        repository_root: &Path,
        local_state_root: &Path,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        Self::create_empty_inner(repository_root, local_state_root, vault)
    }

    #[cfg(all(test, not(feature = "test-support")))]
    pub(crate) fn create_empty(
        repository_root: &Path,
        local_state_root: &Path,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        Self::create_empty_inner(repository_root, local_state_root, vault)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn create_empty_inner(
        repository_root: &Path,
        local_state_root: &Path,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        let repository = open_root(repository_root)?;
        let local_state = open_root(local_state_root)?;
        reject_related_roots(&repository, &local_state)?;
        let layout = StoreLayout::create(repository, local_state, vault)?;
        let quarantine_reservations = reservations_for(&layout.quarantine)?;
        let repository_reservations = reservations_for(&layout.transactions)?;
        Ok(Self {
            layout,
            mutation_active: AtomicBool::new(false),
            quarantine_reservations,
            repository_reservations,
            replication_operations: Arc::new(OperationRegistry::new()),
        })
    }

    #[cfg(feature = "benchmark-support")]
    pub(crate) fn create_benchmark(
        repository_root: &Path,
        local_state_root: &Path,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        let repository = open_root(repository_root)?;
        let local_state = open_root(local_state_root)?;
        reject_related_roots(&repository, &local_state)?;
        let layout = StoreLayout::create(repository, local_state, vault)?;
        let quarantine_reservations = reservations_for(&layout.quarantine)?;
        let repository_reservations = reservations_for(&layout.transactions)?;
        Ok(Self {
            layout,
            mutation_active: AtomicBool::new(false),
            quarantine_reservations,
            repository_reservations,
            replication_operations: Arc::new(OperationRegistry::new()),
        })
    }

    pub(crate) fn create_new(
        repository_root: &Path,
        local_state_root: &Path,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        let repository = open_root(repository_root)?;
        let local_state = open_root(local_state_root)?;
        reject_related_roots(&repository, &local_state)?;
        if !repository.entry_names_bounded(1)?.is_empty() {
            return Err(StoreError::ImmutableObjectConflict);
        }
        let vault_component = component(&encode_hex(vault.as_bytes()))?;
        match local_state.entry_kind(&vault_component) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(StoreError::ImmutableObjectConflict),
            Err(error) => return Err(StoreError::from(error)),
        }
        let layout = StoreLayout::create(repository, local_state, vault)?;
        let quarantine_reservations = reservations_for(&layout.quarantine)?;
        let repository_reservations = reservations_for(&layout.transactions)?;
        Ok(Self {
            layout,
            mutation_active: AtomicBool::new(false),
            quarantine_reservations,
            repository_reservations,
            replication_operations: Arc::new(OperationRegistry::new()),
        })
    }

    pub(crate) fn open_existing(
        repository_root: &Path,
        local_state_root: &Path,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        let repository = open_root(repository_root)?;
        let local_state = open_root(local_state_root)?;
        reject_related_roots(&repository, &local_state)?;
        let layout = StoreLayout::open_existing(repository, local_state, vault)?;
        let quarantine_reservations = reservations_for(&layout.quarantine)?;
        let repository_reservations = reservations_for(&layout.transactions)?;
        Ok(Self {
            layout,
            mutation_active: AtomicBool::new(false),
            quarantine_reservations,
            repository_reservations,
            replication_operations: Arc::new(OperationRegistry::new()),
        })
    }

    pub(crate) fn begin_durable_batch(&self) -> Result<DurableBatch<'_>, StoreError> {
        DurableBatch::begin(&self.layout, &self.mutation_active)
    }

    pub(crate) fn begin_store_mutation(&self) -> Result<StoreMutation<'_>, StoreError> {
        self.mutation_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StoreError::Busy)?;
        let lock = match self
            .layout
            .transactions
            .try_lock_exclusive(&component("mutation-lock")?)
        {
            Ok(lock) => lock,
            Err(error) => {
                self.mutation_active.store(false, Ordering::Release);
                return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
                    StoreError::Busy
                } else {
                    StoreError::from(error)
                });
            }
        };
        Ok(StoreMutation {
            active: &self.mutation_active,
            _lock: lock,
        })
    }

    pub fn list_device_slots(&self) -> Result<Vec<UntrustedDeviceSlotCandidate>, StoreError> {
        let _mutation = self.begin_store_mutation()?;
        let mut registry = DeviceSlotRegistry::new(
            self.layout.vault,
            1,
            OsRandom,
            FilesystemDeviceSlotPersistence::new(&self.layout),
        )?;
        registry.list_locked()
    }

    pub fn unlock_device(
        self: &Arc<Self>,
        candidate: UntrustedDeviceSlotCandidate,
        wrapping_key: DeviceWrappingKey,
    ) -> Result<UnlockedVault, StoreError> {
        let keys = {
            let _mutation = self.begin_store_mutation()?;
            let mut registry = DeviceSlotRegistry::new(
                self.layout.vault,
                1,
                OsRandom,
                FilesystemDeviceSlotPersistence::new(&self.layout),
            )?;
            Arc::new(registry.unlock(candidate, wrapping_key)?.into_key_cell())
        };
        crate::local::unlock_with_keys(self, keys, None, None)
    }

    pub(crate) fn open_object(
        &self,
        id: &notecrypt_core::ObjectId,
    ) -> Result<FileCapability, StoreError> {
        let encoded = encode_hex(id.as_bytes());
        let shard = self
            .layout
            .objects
            .open_dir_nofollow(&component(&encoded[..2])?)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound
                } else {
                    StoreError::from(error)
                }
            })?;
        shard
            .open_file_nofollow(&component(&encoded[2..])?)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound
                } else {
                    StoreError::from(error)
                }
            })
    }
}

impl UnlockedVault {
    /// Returns an opaque one-way handle that revokes this exact key generation.
    #[must_use]
    pub fn revocation_handle(&self) -> VaultRevocationHandle {
        VaultRevocationHandle {
            keys: Arc::clone(&self.keys),
        }
    }
    #[must_use]
    pub fn with_workspace_absence_authority(
        mut self,
        authority: WorkspaceAbsenceAuthority,
    ) -> Self {
        self.workspace_absence_authority = Some(authority);
        self
    }

    pub fn register_cleanup_workspace(&self) -> Result<RegisteredWorkspace, StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.reserve_and_register(self.keys.as_ref())
    }

    pub fn prepare_cleanup_workspace_registration(
        &self,
    ) -> Result<PreparedWorkspaceRegistration, StoreError> {
        let authority = self
            .workspace_absence_authority
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        let prepared = registry.prepare_registration(self.keys.as_ref(), authority)?;
        Ok(PreparedWorkspaceRegistration {
            store: Arc::clone(&self.store),
            generation: self.generation,
            authority: authority.clone_bound(),
            prepared,
        })
    }

    pub fn commit_cleanup_workspace_registration(
        &self,
        registration: &mut PreparedWorkspaceRegistration,
    ) -> Result<(), StoreError> {
        if !Arc::ptr_eq(&self.store, &registration.store)
            || self.generation != registration.generation
        {
            return Err(StoreError::InvalidCapability);
        }
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.commit_registration(&mut registration.prepared)
    }

    pub fn activate_cleanup_workspace_registration(
        &self,
        registration: &mut PreparedWorkspaceRegistration,
    ) -> Result<(), StoreError> {
        if !Arc::ptr_eq(&self.store, &registration.store)
            || self.generation != registration.generation
        {
            return Err(StoreError::InvalidCapability);
        }
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.activate_registration(&mut registration.prepared)
    }

    pub fn activate_cleanup_workspace(
        &self,
        registered: &mut RegisteredWorkspace,
    ) -> Result<ActiveWorkspace, StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.activate(registered, self.keys.as_ref())
    }

    pub fn prepare_cleanup_workspace_unregister(
        &self,
        active: &mut ActiveWorkspace,
    ) -> Result<PreparedWorkspaceUnregister, StoreError> {
        let authority = self
            .workspace_absence_authority
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        let prepared =
            registry.prepare_workspace_unregister(active, authority, self.keys.as_ref())?;
        Ok(PreparedWorkspaceUnregister {
            store: Arc::clone(&self.store),
            generation: self.generation,
            authority: authority.clone_bound(),
            prepared,
        })
    }

    pub fn authenticated_cleanup_workspaces(
        &self,
    ) -> Result<Vec<AuthenticatedCleanupRecord>, StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.authenticated_records(self.keys.as_ref())
    }

    pub fn acquire_cleanup_workspace_absence(
        &self,
        active: &ActiveWorkspace,
    ) -> Result<WorkspaceAbsenceProof, StoreError> {
        self.workspace_absence_authority
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?
            .acquire(active)
    }

    pub fn unregister_cleanup_workspace(
        &self,
        active: &mut ActiveWorkspace,
        proof: &mut WorkspaceAbsenceProof,
    ) -> Result<(), StoreError> {
        let authority = self
            .workspace_absence_authority
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = CleanupRegistry::new(
            self.store.layout.vault,
            self.generation,
            1_024,
            OsRandom,
            FilesystemCleanupPersistence::new(
                &self.store.layout.cleanup_registry,
                &self.store.layout.cleanup_staging,
            ),
        )?;
        registry.unregister_verified_absence(active, proof, authority, self.keys.as_ref())
    }

    pub fn acquire_replication_lease(
        &self,
        backend_limits: ReplicationLimits,
        operation_limits: ReplicationLimits,
    ) -> Result<Box<dyn ReplicationLease>, StoreError> {
        self.acquire_replication_lease_with_cancellation(backend_limits, operation_limits, None)
    }

    pub fn acquire_replication_lease_with_cancellation(
        &self,
        backend_limits: ReplicationLimits,
        operation_limits: ReplicationLimits,
        cancellation: Option<Arc<dyn crate::ReplicationCancellationProbe>>,
    ) -> Result<Box<dyn ReplicationLease>, StoreError> {
        self.keys.validate_generation(self.generation)?;
        let authenticated_bootstrap = Arc::clone(
            self.authenticated_bootstrap
                .as_ref()
                .ok_or(StoreError::InvalidCapability)?,
        );
        Ok(Box::new(QuarantineLease::acquire_authenticated(
            Arc::clone(&self.store),
            ReplicationLimits::PHASE_1,
            backend_limits,
            operation_limits,
            Arc::clone(&self.keys),
            self.generation,
            self.store.layout.vault,
            authenticated_bootstrap,
            cancellation,
        )?))
    }

    pub fn enroll_device_slot(
        &self,
        enrollment: DeviceEnrollment,
    ) -> Result<ActiveDeviceSlot, StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = DeviceSlotRegistry::new(
            self.store.layout.vault,
            self.generation,
            OsRandom,
            FilesystemDeviceSlotPersistence::new(&self.store.layout),
        )?;
        registry.enroll(&self.keys, enrollment)
    }

    pub fn disable_device_slot(
        &self,
        active: &mut ActiveDeviceSlot,
    ) -> Result<DisabledDeviceSlotPendingProviderRemoval, StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = DeviceSlotRegistry::new(
            self.store.layout.vault,
            self.generation,
            OsRandom,
            FilesystemDeviceSlotPersistence::new(&self.store.layout),
        )?;
        registry.disable(&self.keys, active)
    }

    pub fn delete_disabled_device_slot(
        &self,
        disabled: &mut DisabledDeviceSlotPendingProviderRemoval,
    ) -> Result<(), StoreError> {
        let _mutation = self.store.begin_store_mutation()?;
        let _publication = self.keys.authorize_publication(self.generation)?;
        let mut registry = DeviceSlotRegistry::new(
            self.store.layout.vault,
            self.generation,
            OsRandom,
            FilesystemDeviceSlotPersistence::new(&self.store.layout),
        )?;
        registry.delete_disabled(&self.keys, disabled)
    }

    pub fn begin_close(&self) -> Result<(), StoreError> {
        self.keys.begin_close()
    }

    pub fn close(self) -> Result<(), StoreError> {
        self.keys.close()
    }
}

/// Opaque one-way root revocation capability.
#[derive(Clone)]
pub struct VaultRevocationHandle {
    keys: Arc<KeyCell>,
}

impl VaultRevocationHandle {
    /// Makes every later bounded use of this unlocked generation fail closed.
    pub fn revoke(&self) {
        self.keys.revoke();
    }
}

pub(crate) fn open_root(path: &Path) -> Result<Directory, StoreError> {
    Directory::open_ambient(path).map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::NotADirectory
        ) {
            StoreError::FilesystemObjectRejected
        } else {
            StoreError::from(error)
        }
    })
}

pub(crate) fn reject_related_roots(
    repository: &Directory,
    local: &Directory,
) -> Result<(), StoreError> {
    if repository.is_same_or_ancestor_of(local) || local.is_same_or_ancestor_of(repository) {
        return Err(StoreError::FilesystemObjectRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use notecrypt_crypto::{CryptoError, SecureRandom, VaultRootKey};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        DeviceProvider, DeviceReference, TrustedWorkspaceAbsenceVerifier,
        WorkspaceAbsenceAuthority, WorkspaceAbsenceGuard,
    };

    struct FixedRandom(u8);

    struct HeldAbsence;

    impl WorkspaceAbsenceGuard for HeldAbsence {}

    struct AlwaysAbsent;

    impl TrustedWorkspaceAbsenceVerifier for AlwaysAbsent {
        fn acquire_verified_absence(
            &self,
            _workspace: &crate::CleanupWorkspaceId,
        ) -> Result<Box<dyn WorkspaceAbsenceGuard>, StoreError> {
            Ok(Box::new(HeldAbsence))
        }
    }

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    fn filesystem_device_lifecycle_unlocks_only_after_complete_local_authentication() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0x71; 16]);
        let store = Arc::new(
            VaultStore::create_empty(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                vault,
            )
            .unwrap(),
        );
        let root = VaultRootKey::generate(&mut FixedRandom(0x22)).unwrap();
        let keys = crate::local::initialize_empty_graph(
            store.as_ref(),
            root,
            "test-device",
            &mut FixedRandom(0x23),
            &AtomicBool::new(false),
        )
        .unwrap();
        let generation = keys.generation();
        crate::availability::write_initial(
            &store.layout,
            keys.as_ref(),
            generation,
            crate::availability::VaultAvailability::Active,
        )
        .unwrap();
        let unlocked = UnlockedVault {
            store: Arc::clone(&store),
            keys: Arc::clone(&keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        };
        let enrollment = DeviceEnrollment::new(
            DeviceProvider::try_new("test-provider".to_owned()).unwrap(),
            DeviceReference::try_new("test-reference".to_owned()).unwrap(),
            DeviceWrappingKey::try_from_protected_bytes(vec![0x74; 32]).unwrap(),
        );
        let mut active = unlocked.enroll_device_slot(enrollment).unwrap();
        assert_eq!(
            store
                .layout
                .device_slots
                .entry_names_bounded(2)
                .unwrap()
                .len(),
            1
        );

        let candidate = store.list_device_slots().unwrap().pop().unwrap();
        let reopened = store
            .unlock_device(
                candidate,
                DeviceWrappingKey::try_from_protected_bytes(vec![0x74; 32]).unwrap(),
            )
            .unwrap();
        reopened
            .keys
            .validate_generation(reopened.generation)
            .unwrap();
        reopened.close().unwrap();

        let mut disabled = unlocked.disable_device_slot(&mut active).unwrap();
        unlocked.delete_disabled_device_slot(&mut disabled).unwrap();
        assert!(store.list_device_slots().unwrap().is_empty());
        unlocked.close().unwrap();
    }

    #[test]
    fn filesystem_cleanup_registry_preserves_linear_authenticated_lifecycle() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0x81; 16]);
        let store = Arc::new(
            VaultStore::create_empty(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                vault,
            )
            .unwrap(),
        );
        let root = VaultRootKey::generate(&mut FixedRandom(0x82)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let generation = keys.generation();
        let unlocked = UnlockedVault {
            store: Arc::clone(&store),
            keys: Arc::new(keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        }
        .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent)));

        let mut registered = unlocked.register_cleanup_workspace().unwrap();
        assert_eq!(registered.workspace_id().child_name().len(), 32);
        let mut active = unlocked
            .activate_cleanup_workspace(&mut registered)
            .unwrap();
        let authenticated = unlocked.authenticated_cleanup_workspaces().unwrap();
        assert_eq!(authenticated.len(), 1);
        assert_eq!(
            authenticated[0].state(),
            crate::CleanupWorkspaceState::Active
        );
        assert_eq!(
            active.workspace_id().child_name(),
            authenticated[0].workspace_id().child_name()
        );
        let wrong_authority = WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent));
        let mut wrong_proof = wrong_authority.acquire(&active).unwrap();
        assert!(matches!(
            unlocked.unregister_cleanup_workspace(&mut active, &mut wrong_proof),
            Err(StoreError::InvalidCapability)
        ));
        let mut proof = unlocked.acquire_cleanup_workspace_absence(&active).unwrap();
        unlocked
            .unregister_cleanup_workspace(&mut active, &mut proof)
            .unwrap();
        assert!(
            unlocked
                .authenticated_cleanup_workspaces()
                .unwrap()
                .is_empty()
        );
        unlocked.close().unwrap();
    }

    #[test]
    fn prepared_workspace_unregister_survives_general_root_revocation_and_is_linear() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0x91; 16]);
        let store = Arc::new(
            VaultStore::create_empty(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                vault,
            )
            .unwrap(),
        );
        let root = VaultRootKey::generate(&mut FixedRandom(0x92)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let generation = keys.generation();
        let unlocked = UnlockedVault {
            store: Arc::clone(&store),
            keys: Arc::new(keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        }
        .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent)));
        let mut registered = unlocked.register_cleanup_workspace().unwrap();
        let mut active = unlocked
            .activate_cleanup_workspace(&mut registered)
            .unwrap();
        let mut prepared = unlocked
            .prepare_cleanup_workspace_unregister(&mut active)
            .unwrap();
        let child = prepared.workspace_id().child_name();

        unlocked.revocation_handle().revoke();
        prepared.unregister_absent().unwrap();

        assert_eq!(prepared.workspace_id().child_name(), child);
        assert!(matches!(
            prepared.unregister_absent(),
            Err(StoreError::InvalidCapability)
        ));
        assert!(
            store
                .layout
                .cleanup_registry
                .entry_names_bounded(1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn prepared_registration_unregisters_after_revocation_without_activation() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0xa1; 16]);
        let store = Arc::new(
            VaultStore::create_empty(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                vault,
            )
            .unwrap(),
        );
        let root = VaultRootKey::generate(&mut FixedRandom(0xa2)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let generation = keys.generation();
        let unlocked = UnlockedVault {
            store: Arc::clone(&store),
            keys: Arc::new(keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        }
        .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent)));

        let mut registration = unlocked.prepare_cleanup_workspace_registration().unwrap();
        assert!(
            unlocked
                .authenticated_cleanup_workspaces()
                .unwrap()
                .is_empty()
        );
        unlocked
            .commit_cleanup_workspace_registration(&mut registration)
            .unwrap();
        assert_eq!(
            unlocked.authenticated_cleanup_workspaces().unwrap()[0].state(),
            crate::CleanupWorkspaceState::Registered
        );

        unlocked.revocation_handle().revoke();
        registration.unregister_absent().unwrap();
        assert!(
            store
                .layout
                .cleanup_registry
                .entry_names_bounded(1)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            registration.unregister_absent(),
            Err(StoreError::InvalidCapability)
        ));
    }

    #[test]
    fn prepared_registration_cleans_the_single_crash_staging_slot_before_publish() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault = VaultId::from_bytes([0xa3; 16]);
        let store = Arc::new(
            VaultStore::create_empty(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                vault,
            )
            .unwrap(),
        );
        let mut stale = store
            .layout
            .cleanup_staging
            .create_private_file_new(&component("registration").unwrap())
            .unwrap();
        stale.write_all(b"partial authenticated record").unwrap();
        stale.sync_all().unwrap();
        store.layout.cleanup_staging.sync().unwrap();
        drop(stale);

        let root = VaultRootKey::generate(&mut FixedRandom(0xa4)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let generation = keys.generation();
        let unlocked = UnlockedVault {
            store: Arc::clone(&store),
            keys: Arc::new(keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        }
        .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent)));

        let mut registration = unlocked.prepare_cleanup_workspace_registration().unwrap();
        unlocked
            .commit_cleanup_workspace_registration(&mut registration)
            .unwrap();

        assert!(
            store
                .layout
                .cleanup_staging
                .entry_names_bounded(1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            unlocked.authenticated_cleanup_workspaces().unwrap().len(),
            1
        );
    }

    #[test]
    fn prepared_registration_faults_never_publish_a_partial_final_record_and_retry_exactly() {
        for fault in [
            RegistrationPersistenceFault::ShortWrite,
            RegistrationPersistenceFault::FileSync,
            RegistrationPersistenceFault::PublicationBeforeEffect,
            RegistrationPersistenceFault::PublicationAfterEffect,
            RegistrationPersistenceFault::SourceDirectorySync,
            RegistrationPersistenceFault::DestinationDirectorySync,
            RegistrationPersistenceFault::Readback,
        ] {
            let repository = TempDir::new().unwrap();
            let local = TempDir::new().unwrap();
            let vault = VaultId::from_bytes([0xa5; 16]);
            let store = Arc::new(
                VaultStore::create_empty(
                    &repository.path().canonicalize().unwrap(),
                    &local.path().canonicalize().unwrap(),
                    vault,
                )
                .unwrap(),
            );
            let root = VaultRootKey::generate(&mut FixedRandom(0xa6)).unwrap();
            let keys = KeyCell::new(root).unwrap();
            let generation = keys.generation();
            let unlocked = UnlockedVault {
                store: Arc::clone(&store),
                keys: Arc::new(keys),
                generation,
                workspace_absence_authority: None,
                verified_chunks: Arc::new(Mutex::new(HashMap::new())),
                stamp_cache_policy: Arc::new(StampCachePolicy::new()),
                authenticated_bootstrap: None,
            }
            .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(
                AlwaysAbsent,
            )));
            let mut registration = unlocked.prepare_cleanup_workspace_registration().unwrap();

            install_registration_persistence_fault(fault);
            assert!(matches!(
                unlocked.commit_cleanup_workspace_registration(&mut registration),
                Err(StoreError::Io(_))
            ));
            let records_after_fault = unlocked.authenticated_cleanup_workspaces().unwrap();
            assert!(
                records_after_fault.is_empty()
                    || (records_after_fault.len() == 1
                        && records_after_fault[0].state()
                            == crate::CleanupWorkspaceState::Registered)
            );

            unlocked
                .commit_cleanup_workspace_registration(&mut registration)
                .unwrap();
            assert_eq!(
                unlocked.authenticated_cleanup_workspaces().unwrap().len(),
                1
            );
            assert!(
                store
                    .layout
                    .cleanup_staging
                    .entry_names_bounded(1)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn prepared_registration_source_sync_fault_is_recoverable_after_store_reopen() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let repository_path = repository.path().canonicalize().unwrap();
        let local_path = local.path().canonicalize().unwrap();
        let vault = VaultId::from_bytes([0xb5; 16]);
        let store =
            Arc::new(VaultStore::create_empty(&repository_path, &local_path, vault).unwrap());
        let root = VaultRootKey::generate(&mut FixedRandom(0xb6)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let generation = keys.generation();
        let unlocked = UnlockedVault {
            store: Arc::clone(&store),
            keys: Arc::new(keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        }
        .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent)));
        let mut registration = unlocked.prepare_cleanup_workspace_registration().unwrap();
        install_registration_persistence_fault(RegistrationPersistenceFault::SourceDirectorySync);
        assert!(matches!(
            unlocked.commit_cleanup_workspace_registration(&mut registration),
            Err(StoreError::Io(_))
        ));
        drop(registration);
        drop(unlocked);
        drop(store);

        let reopened =
            Arc::new(VaultStore::open_existing(&repository_path, &local_path, vault).unwrap());
        let root = VaultRootKey::generate(&mut FixedRandom(0xb6)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let unlocked = UnlockedVault {
            store: Arc::clone(&reopened),
            keys: Arc::new(keys),
            generation,
            workspace_absence_authority: None,
            verified_chunks: Arc::new(Mutex::new(HashMap::new())),
            stamp_cache_policy: Arc::new(StampCachePolicy::new()),
            authenticated_bootstrap: None,
        }
        .with_workspace_absence_authority(WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent)));

        assert_eq!(
            unlocked.authenticated_cleanup_workspaces().unwrap().len(),
            1
        );
        let _next = unlocked.prepare_cleanup_workspace_registration().unwrap();
        assert!(
            reopened
                .layout
                .cleanup_staging
                .entry_names_bounded(1)
                .unwrap()
                .is_empty()
        );
    }
}
