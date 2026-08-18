#[cfg(test)]
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use notecrypt_platform_fs::{
    ExportBeginError, ExportCleanupPending, ExportOverwrite, ExportPublicationEffect,
    ExportPublishAttemptError, ExportTransaction, ExternalFileSet, StableImportValidator,
};

use crate::{
    ExportOverwriteConfirmation, ExportSelection, ExternalExportTransaction, ExternalFileProvider,
    HostPortError, ImportSelection, OpenedExport, OpenedImport, RepositoryPortError,
    VaultPublicationGuard,
};

/// Production exact-handle adapter for explicit import and export selections.
pub struct PlatformExternalFileProvider {
    files: ExternalFileSet,
    cleanup_registry: Arc<Mutex<CleanupRegistry>>,
    #[cfg(test)]
    cleanup_faults: Mutex<VecDeque<usize>>,
    #[cfg(test)]
    publish_panics: Mutex<VecDeque<bool>>,
}

const MAX_TRACKED_EXPORTS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
struct ExportCleanupId(u64);

struct CleanupRegistry {
    next_id: u64,
    entries: Vec<CleanupEntry>,
    retry_in_progress: bool,
    #[cfg(test)]
    retry_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

struct CleanupEntry {
    id: ExportCleanupId,
    state: CleanupState,
}

enum CleanupState {
    InFlight,
    Retrying,
    Pending(ExportCleanupPending),
}

impl CleanupRegistry {
    fn new() -> Self {
        Self {
            next_id: 1,
            entries: Vec::new(),
            retry_in_progress: false,
            #[cfg(test)]
            retry_gate: None,
        }
    }

    fn reserve(&mut self) -> Result<ExportCleanupId, HostPortError> {
        if self.entries.len() == MAX_TRACKED_EXPORTS {
            return Err(HostPortError::CapacityExceeded);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let id = ExportCleanupId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(HostPortError::CapacityExceeded)?;
        self.entries.push(CleanupEntry {
            id,
            state: CleanupState::InFlight,
        });
        Ok(id)
    }

    fn finish(&mut self, id: ExportCleanupId) -> Result<(), HostPortError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(HostPortError::StaleCapability)?;
        self.entries.swap_remove(index);
        Ok(())
    }

    fn retain(&mut self, id: ExportCleanupId, pending: ExportCleanupPending) {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .expect("an exposed export always retains its registry reservation");
        entry.state = CleanupState::Pending(pending);
    }

    fn pending_ids(&self) -> Result<Vec<ExportCleanupId>, HostPortError> {
        let count = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.state, CleanupState::Pending(_)))
            .count();
        let mut ids = Vec::new();
        ids.try_reserve_exact(count)
            .map_err(|_| HostPortError::AllocationFailed)?;
        ids.extend(self.entries.iter().filter_map(|entry| {
            matches!(entry.state, CleanupState::Pending(_)).then_some(entry.id)
        }));
        Ok(ids)
    }

    fn begin_retry(&mut self) -> Result<Vec<ExportCleanupId>, HostPortError> {
        if self.retry_in_progress {
            return Err(HostPortError::LiveWorkspace);
        }
        self.retry_in_progress = true;
        match self.pending_ids() {
            Ok(ids) => Ok(ids),
            Err(error) => {
                self.retry_in_progress = false;
                Err(error)
            }
        }
    }

    fn end_retry(&mut self) {
        self.retry_in_progress = false;
    }

    fn take_pending(&mut self, id: ExportCleanupId) -> Result<ExportCleanupPending, HostPortError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(HostPortError::StaleCapability)?;
        match std::mem::replace(&mut entry.state, CleanupState::Retrying) {
            CleanupState::Pending(pending) => Ok(pending),
            state => {
                entry.state = state;
                Err(HostPortError::StaleCapability)
            }
        }
    }
}

impl PlatformExternalFileProvider {
    /// Binds the encrypted repository and local-state roots for alias rejection.
    pub fn open(repository_root: &Path, local_state_root: &Path) -> Result<Self, HostPortError> {
        ExternalFileSet::open(repository_root, local_state_root)
            .map(|files| Self {
                files,
                cleanup_registry: Arc::new(Mutex::new(CleanupRegistry::new())),
                #[cfg(test)]
                cleanup_faults: Mutex::new(VecDeque::new()),
                #[cfg(test)]
                publish_panics: Mutex::new(VecDeque::new()),
            })
            .map_err(map_platform_error)
    }

    #[cfg(test)]
    fn inject_cleanup_failures(&self, failures: impl IntoIterator<Item = usize>) {
        self.cleanup_faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend(failures);
    }

    #[cfg(test)]
    fn inject_begin_failure(&self, cleanup_failures: usize) {
        notecrypt_platform_fs::external_test_support::inject_begin_failure(
            &self.files,
            cleanup_failures,
        );
    }

    #[cfg(test)]
    fn inject_publish_panic(&self) {
        self.publish_panics
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push_back(true);
    }

    #[cfg(test)]
    fn inject_retry_gate(
        &self,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.cleanup_registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retry_gate = Some((entered, release));
    }
}

impl ExternalFileProvider for PlatformExternalFileProvider {
    fn open_import(&self, selection: ImportSelection) -> Result<OpenedImport, HostPortError> {
        let input = self
            .files
            .open_stable_import(selection.path())
            .map_err(map_platform_error)?;
        let validator = input.try_validator().map_err(map_platform_error)?;
        Ok(OpenedImport::new(
            Box::new(input),
            Box::new(PlatformImportGuard(validator)),
        ))
    }

    fn begin_export(&self, selection: ExportSelection) -> Result<OpenedExport, HostPortError> {
        let id = self
            .cleanup_registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reserve()?;
        let overwrite = match selection.overwrite() {
            ExportOverwriteConfirmation::Refuse => ExportOverwrite::Refuse,
            ExportOverwriteConfirmation::Confirmed => ExportOverwrite::Confirmed,
        };
        let transaction = match self.files.begin_export(selection.path(), overwrite) {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(retain_and_map_export_begin_error(
                    error,
                    id,
                    &self.cleanup_registry,
                ));
            }
        };
        #[cfg(test)]
        let transaction = {
            let mut transaction = transaction;
            if let Some(failures) = self
                .cleanup_faults
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pop_front()
            {
                notecrypt_platform_fs::external_test_support::inject_cleanup_failures(
                    &mut transaction,
                    failures,
                );
            }
            if self
                .publish_panics
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pop_front()
                .unwrap_or(false)
            {
                notecrypt_platform_fs::external_test_support::inject_publish_panic(
                    &mut transaction,
                );
            }
            transaction
        };
        Ok(OpenedExport::new(Box::new(PlatformExportTransaction {
            inner: Some(transaction),
            id,
            cleanup_registry: Arc::clone(&self.cleanup_registry),
        })))
    }

    fn retry_cleanup(&self) -> Result<(), HostPortError> {
        let (ids, gate) = {
            let mut registry = self
                .cleanup_registry
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let ids = registry.begin_retry()?;
            #[cfg(test)]
            let gate = registry.retry_gate.take();
            #[cfg(not(test))]
            let gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)> = None;
            (ids, gate)
        };
        if let Some((entered, release)) = gate {
            entered.wait();
            release.wait();
        }
        let mut failed = false;
        let mut unexpected = None;
        for id in ids {
            let pending = match self
                .cleanup_registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take_pending(id)
            {
                Ok(pending) => pending,
                Err(error) => {
                    unexpected = Some(error);
                    break;
                }
            };
            match pending.retry() {
                Ok(()) => {
                    self.cleanup_registry
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .finish(id)?;
                }
                Err(pending) => {
                    self.cleanup_registry
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .retain(id, pending);
                    failed = true;
                }
            }
        }
        self.cleanup_registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .end_retry();
        if let Some(error) = unexpected {
            Err(error)
        } else if failed {
            Err(HostPortError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

struct PlatformImportGuard(StableImportValidator);

impl VaultPublicationGuard for PlatformImportGuard {
    fn validate(&mut self) -> Result<(), RepositoryPortError> {
        self.0.validate_unchanged().map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidData {
                RepositoryPortError::StaleCapability
            } else {
                map_platform_repository_error(error)
            }
        })
    }
}

struct PlatformExportTransaction {
    inner: Option<ExportTransaction>,
    id: ExportCleanupId,
    cleanup_registry: Arc<Mutex<CleanupRegistry>>,
}

impl std::io::Write for PlatformExportTransaction {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.inner
            .as_mut()
            .ok_or_else(|| std::io::Error::other("export transaction is closed"))?
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| std::io::Error::other("export transaction is closed"))?
            .flush()
    }
}

impl ExternalExportTransaction for PlatformExportTransaction {
    fn flush_private(&mut self) -> Result<(), HostPortError> {
        self.inner
            .as_mut()
            .ok_or(HostPortError::StaleCapability)?
            .flush_private()
            .map_err(map_platform_error)
    }

    fn publish(
        mut self: Box<Self>,
        authorization: &mut dyn crate::ExternalPublicationAuthorization,
    ) -> Result<(), HostPortError> {
        if self.inner.is_none() {
            return Err(HostPortError::StaleCapability);
        }
        let mut attempt_error = None;
        let result = {
            let mut publication = || match self
                .inner
                .as_mut()
                .ok_or(HostPortError::StaleCapability)?
                .try_publish()
            {
                Ok(_) => Ok(()),
                Err(error) => {
                    let mapped = map_export_publish_attempt(&error);
                    attempt_error = Some(error);
                    Err(mapped)
                }
            };
            authorization.authorize_and_publish(&mut publication)
        };
        if let Some(error) = attempt_error.as_ref() {
            let primary = map_export_publish_attempt(error);
            return match self.abort_inner() {
                Ok(()) => Err(primary),
                Err(error) => Err(error),
            };
        }
        match result {
            Ok(()) => {
                drop(self.inner.take());
                self.finish_registry()?;
                Ok(())
            }
            Err(primary) => match self.abort_inner() {
                Ok(()) => Err(primary),
                Err(error) => Err(error),
            },
        }
    }

    fn abort(mut self: Box<Self>) -> Result<(), HostPortError> {
        self.abort_inner()
    }
}

impl PlatformExportTransaction {
    fn abort_inner(&mut self) -> Result<(), HostPortError> {
        let transaction = self.inner.take().ok_or(HostPortError::StaleCapability)?;
        match transaction.abort() {
            Ok(()) => self.finish_registry(),
            Err(pending) => {
                self.retain_pending(pending);
                Err(HostPortError::CleanupFailed)
            }
        }
    }

    fn finish_registry(&self) -> Result<(), HostPortError> {
        self.cleanup_registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish(self.id)
    }

    fn retain_pending(&self, pending: ExportCleanupPending) {
        self.cleanup_registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(self.id, pending);
    }
}

impl Drop for PlatformExportTransaction {
    fn drop(&mut self) {
        let Some(transaction) = self.inner.take() else {
            return;
        };
        match transaction.abort() {
            Ok(()) => {
                let _ = self.finish_registry();
            }
            Err(pending) => self.retain_pending(pending),
        }
    }
}

fn retain_and_map_export_begin_error(
    error: ExportBeginError,
    id: ExportCleanupId,
    cleanup_registry: &Mutex<CleanupRegistry>,
) -> HostPortError {
    let kind = error.kind();
    if let Some(pending) = error.into_pending_cleanup() {
        cleanup_registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(id, pending);
        return HostPortError::CleanupFailed;
    }
    let _ = cleanup_registry
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .finish(id);
    match kind {
        std::io::ErrorKind::AlreadyExists => HostPortError::DestinationExists,
        std::io::ErrorKind::InvalidData => HostPortError::StaleCapability,
        std::io::ErrorKind::InvalidInput => HostPortError::InvalidInput,
        std::io::ErrorKind::PermissionDenied => HostPortError::Denied,
        std::io::ErrorKind::OutOfMemory => HostPortError::AllocationFailed,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::Unsupported => {
            HostPortError::Unavailable
        }
        _ => HostPortError::PlatformFailure,
    }
}

fn map_export_publish_attempt(error: &ExportPublishAttemptError) -> HostPortError {
    if error.effect() != ExportPublicationEffect::NotPublished {
        return HostPortError::DurabilityPending;
    }
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => HostPortError::DestinationExists,
        std::io::ErrorKind::InvalidData => HostPortError::StaleCapability,
        _ => HostPortError::PlatformFailure,
    }
}

fn map_platform_error(error: std::io::Error) -> HostPortError {
    match error.kind() {
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            HostPortError::InvalidInput
        }
        std::io::ErrorKind::PermissionDenied => HostPortError::Denied,
        std::io::ErrorKind::OutOfMemory => HostPortError::AllocationFailed,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::Unsupported => {
            HostPortError::Unavailable
        }
        _ => HostPortError::PlatformFailure,
    }
}

fn map_platform_repository_error(error: std::io::Error) -> RepositoryPortError {
    match map_platform_error(error) {
        HostPortError::InvalidInput => RepositoryPortError::InvalidInput,
        HostPortError::AllocationFailed => RepositoryPortError::AllocationFailed,
        HostPortError::Unavailable => RepositoryPortError::Unavailable,
        _ => RepositoryPortError::PlatformFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, Barrier};

    use tempfile::TempDir;

    use super::*;

    struct AllowPublication;

    impl crate::ExternalPublicationAuthorization for AllowPublication {
        fn authorize_and_publish(
            &mut self,
            publication: &mut dyn FnMut() -> Result<(), HostPortError>,
        ) -> Result<(), HostPortError> {
            publication()
        }
    }

    struct PanicAuthorization;

    impl crate::ExternalPublicationAuthorization for PanicAuthorization {
        fn authorize_and_publish(
            &mut self,
            _publication: &mut dyn FnMut() -> Result<(), HostPortError>,
        ) -> Result<(), HostPortError> {
            panic!("injected publication authorization panic");
        }
    }

    struct RejectAuthorization;

    impl crate::ExternalPublicationAuthorization for RejectAuthorization {
        fn authorize_and_publish(
            &mut self,
            _publication: &mut dyn FnMut() -> Result<(), HostPortError>,
        ) -> Result<(), HostPortError> {
            Err(HostPortError::Cancelled)
        }
    }

    fn provider() -> (PlatformExternalFileProvider, TempDir, TempDir, TempDir) {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let provider = PlatformExternalFileProvider::open(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
        )
        .unwrap();
        (provider, repository, local, external)
    }

    fn selection(external: &TempDir, name: &str) -> ExportSelection {
        ExportSelection::try_new(
            external.path().canonicalize().unwrap().join(name),
            ExportOverwriteConfirmation::Refuse,
        )
        .unwrap()
    }

    #[test]
    fn production_abort_retains_cleanup_until_a_later_retry_proves_absence() {
        let (provider, _repository, _local, external) = provider();
        provider.inject_cleanup_failures([2]);
        let mut transaction = provider
            .begin_export(selection(&external, "destination"))
            .unwrap()
            .into_transaction();
        transaction.write_all(b"private plaintext").unwrap();

        assert_eq!(transaction.abort(), Err(HostPortError::CleanupFailed));
        assert_eq!(provider.retry_cleanup(), Err(HostPortError::CleanupFailed));
        provider.retry_cleanup().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
    }

    #[test]
    fn publication_panics_retain_exact_cleanup_until_absence_is_proven() {
        let (provider, _repository, _local, external) = provider();
        provider.inject_cleanup_failures([2]);
        let mut transaction = provider
            .begin_export(selection(&external, "authorization-panic"))
            .unwrap()
            .into_transaction();
        transaction.write_all(b"private plaintext").unwrap();

        let authorization_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            transaction.publish(&mut PanicAuthorization)
        }));
        assert!(authorization_panic.is_err());
        assert_eq!(provider.retry_cleanup(), Err(HostPortError::CleanupFailed));
        provider.retry_cleanup().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());

        provider.inject_cleanup_failures([2]);
        provider.inject_publish_panic();
        let mut transaction = provider
            .begin_export(selection(&external, "platform-panic"))
            .unwrap()
            .into_transaction();
        transaction.write_all(b"private plaintext").unwrap();
        let platform_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            transaction.publish(&mut AllowPublication)
        }));
        assert!(platform_panic.is_err());
        assert_eq!(provider.retry_cleanup(), Err(HostPortError::CleanupFailed));
        provider.retry_cleanup().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
    }

    #[test]
    fn rejected_authorization_reports_cleanup_failure_until_absence_is_proven() {
        let (provider, _repository, _local, external) = provider();
        provider.inject_cleanup_failures([2]);
        let mut transaction = provider
            .begin_export(selection(&external, "rejected-authorization"))
            .unwrap()
            .into_transaction();
        transaction.write_all(b"private plaintext").unwrap();

        assert_eq!(
            transaction.publish(&mut RejectAuthorization),
            Err(HostPortError::CleanupFailed)
        );
        assert_eq!(provider.retry_cleanup(), Err(HostPortError::CleanupFailed));
        provider.retry_cleanup().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
    }

    #[test]
    fn production_begin_failure_retains_cleanup_until_absence_is_proven() {
        let (provider, _repository, _local, external) = provider();
        provider.inject_begin_failure(2);

        assert!(matches!(
            provider.begin_export(selection(&external, "never-opened")),
            Err(HostPortError::CleanupFailed)
        ));
        assert_eq!(provider.retry_cleanup(), Err(HostPortError::CleanupFailed));
        provider.retry_cleanup().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
    }

    #[test]
    fn concurrent_abort_failures_retain_both_exact_cleanup_capabilities() {
        let (provider, _repository, _local, external) = provider();
        provider.inject_cleanup_failures([1, 1]);
        let provider = Arc::new(provider);
        let mut first = provider
            .begin_export(selection(&external, "first"))
            .unwrap()
            .into_transaction();
        let mut second = provider
            .begin_export(selection(&external, "second"))
            .unwrap()
            .into_transaction();
        first.write_all(b"first private plaintext").unwrap();
        second.write_all(b"second private plaintext").unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_thread = std::thread::spawn(move || {
            first_barrier.wait();
            first.abort()
        });
        let second_barrier = Arc::clone(&barrier);
        let second_thread = std::thread::spawn(move || {
            second_barrier.wait();
            second.abort()
        });
        barrier.wait();

        assert_eq!(
            first_thread.join().unwrap(),
            Err(HostPortError::CleanupFailed)
        );
        assert_eq!(
            second_thread.join().unwrap(),
            Err(HostPortError::CleanupFailed)
        );
        provider.retry_cleanup().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
    }

    #[test]
    fn concurrent_cleanup_retry_is_rejected_without_moving_exact_ownership() {
        let (provider, _repository, _local, external) = provider();
        provider.inject_cleanup_failures([1]);
        let transaction = provider
            .begin_export(selection(&external, "retry-race"))
            .unwrap()
            .into_transaction();
        assert_eq!(transaction.abort(), Err(HostPortError::CleanupFailed));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        provider.inject_retry_gate(Arc::clone(&entered), Arc::clone(&release));
        let provider = Arc::new(provider);
        let retry_provider = Arc::clone(&provider);
        let retry = std::thread::spawn(move || retry_provider.retry_cleanup());
        entered.wait();

        assert_eq!(provider.retry_cleanup(), Err(HostPortError::LiveWorkspace));
        release.wait();
        retry.join().unwrap().unwrap();
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
    }

    #[test]
    fn cleanup_registry_rejects_wrong_ids_and_capacity_plus_one() {
        let mut registry = CleanupRegistry::new();
        assert_eq!(
            registry.finish(ExportCleanupId(u64::MAX)),
            Err(HostPortError::StaleCapability)
        );
        for _ in 0..MAX_TRACKED_EXPORTS {
            registry.reserve().unwrap();
        }
        assert!(matches!(
            registry.reserve(),
            Err(HostPortError::CapacityExceeded)
        ));
    }
}
