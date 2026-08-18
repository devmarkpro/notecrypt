#[cfg(any(test, feature = "test-support"))]
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Component, Path};
#[cfg(any(test, feature = "test-support"))]
use std::sync::Mutex;

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions;

use super::{
    Directory, FileCapability, FileStamp, PhysicalComponent, published_matches_exact_source,
    rename_no_replace_observed, rename_replace,
};

const MAX_EXTERNAL_PATH_BYTES: usize = 32 * 1024;
const STAGING_RETRIES: usize = 8;

/// Whether an already existing export destination may be replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportOverwrite {
    /// Fail if the destination exists at selection or publication time.
    Refuse,
    /// Replace only the exact regular, single-link file opened at selection time.
    Confirmed,
}

/// Redacted export initialization failure with optional exact cleanup ownership.
pub struct ExportBeginError {
    primary: io::Error,
    cleanup: Option<ExportCleanupPending>,
}

impl ExportBeginError {
    fn without_cleanup(primary: io::Error) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }

    fn with_cleanup(primary: io::Error, cleanup: ExportCleanupPending) -> Self {
        Self {
            primary,
            cleanup: Some(cleanup),
        }
    }

    /// Returns the primary platform failure kind.
    pub fn kind(&self) -> io::ErrorKind {
        self.primary.kind()
    }

    /// Transfers exact ownership of staging that still requires cleanup.
    pub fn into_pending_cleanup(mut self) -> Option<ExportCleanupPending> {
        self.cleanup.take()
    }
}

impl fmt::Debug for ExportBeginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportBeginError")
            .field("kind", &self.primary.kind())
            .field("cleanup_required", &self.cleanup.is_some())
            .finish()
    }
}

impl fmt::Display for ExportBeginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("external export initialization failed")
    }
}

impl std::error::Error for ExportBeginError {}

/// Capability-bound external files kept separate from encrypted storage roots.
pub struct ExternalFileSet {
    repository: Directory,
    local_state: Directory,
    #[cfg(any(test, feature = "test-support"))]
    begin_faults: Mutex<VecDeque<BeginExportFault>>,
}

#[cfg(any(test, feature = "test-support"))]
struct BeginExportFault {
    cleanup_failures: usize,
}

impl ExternalFileSet {
    /// Opens and binds the two protected roots once for later identity checks.
    pub fn open(repository_root: &Path, local_state_root: &Path) -> io::Result<Self> {
        validate_external_path_bound(repository_root)?;
        validate_external_path_bound(local_state_root)?;
        let repository = Directory::open_ambient(repository_root)?;
        let local_state = Directory::open_ambient(local_state_root)?;
        if repository.is_same_or_ancestor_of(&local_state)
            || local_state.is_same_or_ancestor_of(&repository)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protected roots alias or nest",
            ));
        }
        Ok(Self {
            repository,
            local_state,
            #[cfg(any(test, feature = "test-support"))]
            begin_faults: Mutex::new(VecDeque::new()),
        })
    }

    /// Opens one exact regular, single-link input and captures its stable stamp.
    pub fn open_stable_import(&self, path: &Path) -> io::Result<StableImport> {
        let (parent, name) = self.open_external_parent(path)?;
        let file = open_external_file(&parent, name, false)?;
        let initial = file.stamp()?;
        Ok(StableImport { file, initial })
    }

    /// Creates private same-parent staging for an explicit export destination.
    pub fn begin_export(
        &self,
        path: &Path,
        overwrite: ExportOverwrite,
    ) -> Result<ExportTransaction, ExportBeginError> {
        self.begin_export_inner(path, overwrite)
    }

    fn begin_export_inner(
        &self,
        path: &Path,
        overwrite: ExportOverwrite,
    ) -> Result<ExportTransaction, ExportBeginError> {
        let (parent, destination) = self
            .open_external_parent(path)
            .map_err(ExportBeginError::without_cleanup)?;
        let expected_destination = match open_external_file(&parent, destination, true) {
            Ok(file) if overwrite == ExportOverwrite::Refuse => {
                drop(file);
                return Err(ExportBeginError::without_cleanup(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "export destination already exists",
                )));
            }
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(ExportBeginError::without_cleanup(error)),
        };
        let mut retained_destination = std::path::PathBuf::new();
        retained_destination
            .try_reserve_exact(destination.as_os_str().as_encoded_bytes().len())
            .map_err(|_| {
                ExportBeginError::without_cleanup(io::Error::other(
                    "destination-name allocation failed",
                ))
            })?;
        retained_destination.push(destination);
        let payload_name =
            PhysicalComponent::try_new("payload").map_err(ExportBeginError::without_cleanup)?;
        let (staging_name, staging) =
            create_random_private_staging(&parent).map_err(ExportBeginError::without_cleanup)?;
        let mut transaction = ExportTransaction {
            parent: Some(parent),
            destination: retained_destination,
            expected_destination,
            staging: Some(staging),
            staging_name,
            payload: None,
            payload_name,
            source_moved: false,
            destination_visible: false,
            #[cfg(any(test, feature = "test-support"))]
            cleanup_failures_remaining: 0,
            #[cfg(any(test, feature = "test-support"))]
            panic_on_publish: false,
        };
        #[cfg(any(test, feature = "test-support"))]
        let begin_fault = self
            .begin_faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front();
        #[cfg(not(any(test, feature = "test-support")))]
        let begin_fault: Option<()> = None;
        let payload = if begin_fault.is_some() {
            Err(io::Error::other("injected payload creation failure"))
        } else {
            transaction
                .staging
                .as_ref()
                .expect("new export owns staging")
                .create_file_new(&transaction.payload_name)
        };
        match payload {
            Ok(payload) => {
                transaction.payload = Some(payload);
                Ok(transaction)
            }
            Err(primary) => {
                #[cfg(any(test, feature = "test-support"))]
                if let Some(fault) = begin_fault {
                    transaction.cleanup_failures_remaining = fault.cleanup_failures;
                }
                match transaction.cleanup_owned_staging() {
                    Ok(()) => Err(ExportBeginError::without_cleanup(primary)),
                    Err(_) => Err(ExportBeginError::with_cleanup(
                        primary,
                        ExportCleanupPending::new(transaction),
                    )),
                }
            }
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn inject_begin_failure(&self, cleanup_failures: usize) {
        self.begin_faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push_back(BeginExportFault { cleanup_failures });
    }

    fn open_external_parent<'a>(&self, path: &'a Path) -> io::Result<(Directory, &'a Path)> {
        validate_external_path_bound(path)?;
        let destination = match path.components().next_back() {
            Some(Component::Normal(name)) => Path::new(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "external path must end in a file name",
                ));
            }
        };
        let parent_path = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "external path has no parent directory",
            )
        })?;
        let parent = Directory::open_ambient(parent_path)?;
        if self.repository.is_same_or_ancestor_of(&parent)
            || self.local_state.is_same_or_ancestor_of(&parent)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "external file is inside a protected root",
            ));
        }
        Ok((parent, destination))
    }
}

/// One already-opened import handle with a mutation-detection stamp.
pub struct StableImport {
    file: FileCapability,
    initial: FileStamp,
}

impl StableImport {
    /// Clones the exact held descriptor into an independent publication validator.
    pub fn try_validator(&self) -> io::Result<StableImportValidator> {
        Ok(StableImportValidator {
            file: FileCapability {
                inner: self.file.inner.try_clone()?,
            },
            initial: self.initial,
        })
    }

    /// Verifies the exact held regular file has not changed since selection.
    pub fn validate_unchanged(&self) -> io::Result<()> {
        validate_stable_import(&self.file, self.initial)
    }
}

/// Independent exact-handle validation retained until store publication.
pub struct StableImportValidator {
    file: FileCapability,
    initial: FileStamp,
}

impl StableImportValidator {
    /// Rejects publication if the selected file changed after it was opened.
    pub fn validate_unchanged(&self) -> io::Result<()> {
        validate_stable_import(&self.file, self.initial)
    }
}

impl fmt::Debug for StableImportValidator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableImportValidator(<redacted>)")
    }
}

impl Read for StableImport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl fmt::Debug for StableImport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableImport(<redacted>)")
    }
}

/// Private export staging that can be atomically published or explicitly aborted.
pub struct ExportTransaction {
    parent: Option<Directory>,
    destination: std::path::PathBuf,
    expected_destination: Option<FileCapability>,
    staging: Option<Directory>,
    staging_name: PhysicalComponent,
    payload: Option<FileCapability>,
    payload_name: PhysicalComponent,
    source_moved: bool,
    destination_visible: bool,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) cleanup_failures_remaining: usize,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) panic_on_publish: bool,
}

/// Redacted publication failure with explicit visibility and cleanup state.
pub struct ExportPublishError {
    primary: io::Error,
    effect: ExportPublicationEffect,
    cleanup: Option<ExportCleanupPending>,
}

/// Redacted publication failure that leaves the exact transaction with the caller.
pub struct ExportPublishAttemptError {
    primary: io::Error,
    effect: ExportPublicationEffect,
}

/// Exact owned-staging capability retained until cleanup is proven complete.
pub struct ExportCleanupPending {
    transaction: Option<Box<ExportTransaction>>,
}

impl ExportCleanupPending {
    fn new(transaction: ExportTransaction) -> Self {
        Self {
            transaction: Some(Box::new(transaction)),
        }
    }

    /// Retries cleanup while preserving the exact capability on failure.
    pub fn retry(mut self) -> Result<(), Self> {
        let result = self
            .transaction
            .as_mut()
            .expect("pending cleanup always owns its transaction")
            .cleanup_owned_staging();
        match result {
            Ok(()) => {
                drop(self.transaction.take());
                Ok(())
            }
            Err(_) => Err(self),
        }
    }
}

impl fmt::Debug for ExportCleanupPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportCleanupPending(<redacted>)")
    }
}

/// Caller-visible effect of an external export publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportPublicationEffect {
    /// The selected destination was not created or replaced.
    NotPublished,
    /// The complete destination is visible and its parent is durably synchronized.
    PublishedDurable,
    /// The complete destination may be visible, but durable publication is unproven.
    PublishedDurabilityPending,
}

impl ExportPublishError {
    /// Returns the primary platform error kind.
    pub fn kind(&self) -> io::ErrorKind {
        self.primary.kind()
    }

    /// Reports whether the destination may already contain the complete plaintext file.
    pub const fn published(&self) -> bool {
        !matches!(self.effect, ExportPublicationEffect::NotPublished)
    }

    /// Returns the exact caller-visible publication effect.
    pub const fn effect(&self) -> ExportPublicationEffect {
        self.effect
    }

    /// Reports whether exact owned-staging cleanup failed.
    pub const fn cleanup_failed(&self) -> bool {
        self.cleanup.is_some()
    }

    /// Transfers exact ownership of staging that still requires cleanup.
    pub fn into_pending_cleanup(mut self) -> Option<ExportCleanupPending> {
        self.cleanup.take()
    }
}

impl fmt::Debug for ExportPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportPublishError")
            .field("kind", &self.primary.kind())
            .field("effect", &self.effect)
            .field("cleanup_failed", &self.cleanup.is_some())
            .finish()
    }
}

impl fmt::Display for ExportPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("external export publication failed")
    }
}

impl std::error::Error for ExportPublishError {}

impl ExportPublishAttemptError {
    /// Returns the primary platform failure kind.
    pub fn kind(&self) -> io::ErrorKind {
        self.primary.kind()
    }

    /// Returns the exact caller-visible publication effect.
    pub const fn effect(&self) -> ExportPublicationEffect {
        self.effect
    }
}

impl fmt::Debug for ExportPublishAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportPublishAttemptError")
            .field("kind", &self.primary.kind())
            .field("effect", &self.effect)
            .finish()
    }
}

impl fmt::Display for ExportPublishAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("external export publication attempt failed")
    }
}

impl std::error::Error for ExportPublishAttemptError {}

impl ExportTransaction {
    /// Flushes the complete private plaintext file before publication.
    pub fn flush_private(&mut self) -> io::Result<()> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?;
        payload.sync_all()?;
        self.staging
            .as_ref()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?
            .sync()
    }

    /// Atomically publishes the complete file under the selected destination name.
    ///
    /// No-replace publication is race-free. On Unix, confirmed replacement compares
    /// the held destination immediately before rename, but the OS has no portable
    /// compare-by-inode-and-replace operation against a malicious same-UID process.
    pub fn publish(mut self) -> Result<ExportPublicationEffect, ExportPublishError> {
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.try_publish()));
        match attempt {
            Ok(Ok(effect)) => Ok(effect),
            Ok(Err(attempt)) => {
                let cleanup = self
                    .cleanup_owned_staging()
                    .is_err()
                    .then_some(ExportCleanupPending::new(self));
                Err(ExportPublishError {
                    primary: attempt.primary,
                    effect: attempt.effect,
                    cleanup,
                })
            }
            Err(_) => {
                let effect = if self.destination_visible {
                    ExportPublicationEffect::PublishedDurabilityPending
                } else {
                    ExportPublicationEffect::NotPublished
                };
                let cleanup = self
                    .cleanup_owned_staging()
                    .is_err()
                    .then_some(ExportCleanupPending::new(self));
                Err(ExportPublishError {
                    primary: io::Error::other("external export publication panicked"),
                    effect,
                    cleanup,
                })
            }
        }
    }

    /// Attempts publication while retaining the exact transaction for panic-safe cleanup.
    pub fn try_publish(&mut self) -> Result<ExportPublicationEffect, ExportPublishAttemptError> {
        #[cfg(any(test, feature = "test-support"))]
        if std::mem::replace(&mut self.panic_on_publish, false) {
            panic!("injected external export publication panic");
        }
        match self.publish_inner() {
            Ok(()) => Ok(ExportPublicationEffect::PublishedDurable),
            Err(primary) => Err(ExportPublishAttemptError {
                primary,
                effect: if self.destination_visible {
                    ExportPublicationEffect::PublishedDurabilityPending
                } else {
                    ExportPublicationEffect::NotPublished
                },
            }),
        }
    }

    fn publish_inner(&mut self) -> io::Result<()> {
        self.flush_private()?;
        drop(self.payload.take());
        let staging = self
            .staging
            .as_ref()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?;
        let source = staging.open_file_for_rename_nofollow(&self.payload_name)?;
        match self.expected_destination.as_ref() {
            None => {
                match rename_no_replace_observed(
                    &source,
                    &staging.inner,
                    self.payload_name.as_path(),
                    &parent.inner,
                    &self.destination,
                ) {
                    Ok(()) => {
                        self.destination_visible = true;
                        self.source_moved = true;
                    }
                    Err(failure) => {
                        self.destination_visible = failure.destination_may_be_visible;
                        return Err(failure.primary);
                    }
                }
                let published = open_external_file(parent, &self.destination, false)?;
                if !published_matches_exact_source(&source, &published)? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "published export identity changed",
                    ));
                }
            }
            Some(expected) => {
                let named_destination = open_external_file(parent, &self.destination, true)?;
                if !expected.same_file(&named_destination)? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "export destination identity changed before publication",
                    ));
                }
                rename_replace(
                    &source,
                    &staging.inner,
                    self.payload_name.as_path(),
                    parent,
                    &self.destination,
                )?;
                self.destination_visible = true;
                self.source_moved = true;
                source.sync_all()?;
                let published = open_external_file(parent, &self.destination, false)?;
                if !source.same_file(&published)? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "replaced export identity changed",
                    ));
                }
            }
        }
        parent.sync()?;
        staging.sync()?;
        self.remove_empty_staging()
    }

    /// Removes only this transaction's exact private staging objects.
    pub fn abort(mut self) -> Result<(), ExportCleanupPending> {
        match self.cleanup_owned_staging() {
            Ok(()) => Ok(()),
            Err(_) => Err(ExportCleanupPending::new(self)),
        }
    }

    fn cleanup_owned_staging(&mut self) -> io::Result<()> {
        #[cfg(any(test, feature = "test-support"))]
        if self.cleanup_failures_remaining != 0 {
            self.cleanup_failures_remaining -= 1;
            return Err(io::Error::other("injected export cleanup failure"));
        }
        drop(self.payload.take());
        if self.source_moved {
            return self.remove_empty_staging();
        }
        let Some(staging) = self.staging.as_ref() else {
            return Ok(());
        };
        match staging.open_file_nofollow(&self.payload_name) {
            Ok(expected) => {
                staging.remove_opened_file_if_matches(&expected, &self.payload_name)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.remove_empty_staging()
    }

    fn remove_empty_staging(&mut self) -> io::Result<()> {
        let Some(staging) = self.staging.take() else {
            return Ok(());
        };
        staging.sync()?;
        drop(staging);
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?;
        parent.remove_empty_dir(&self.staging_name)
    }
}

impl Write for ExportTransaction {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.payload
            .as_mut()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.payload
            .as_mut()
            .ok_or_else(|| io::Error::other("export transaction is closed"))?
            .flush()
    }
}

impl fmt::Debug for ExportTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportTransaction(<redacted>)")
    }
}

impl Drop for ExportTransaction {
    fn drop(&mut self) {
        let _ = self.cleanup_owned_staging();
    }
}

fn open_external_file(
    directory: &Directory,
    name: &Path,
    for_replacement: bool,
) -> io::Result<FileCapability> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    if for_replacement {
        options.write(true);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{DELETE, GENERIC_READ, GENERIC_WRITE};
            options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE);
        }
    }
    let inner = directory.inner.open_with(name, &options)?;
    let file = FileCapability { inner };
    file.require_single_regular_link()?;
    Ok(file)
}

fn create_random_private_staging(parent: &Directory) -> io::Result<(PhysicalComponent, Directory)> {
    for _ in 0..STAGING_RETRIES {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
        let mut value = String::new();
        value
            .try_reserve_exact(".notecrypt-export-".len() + 32)
            .map_err(|_| io::Error::other("staging-name allocation failed"))?;
        value.push_str(".notecrypt-export-");
        for byte in random {
            use fmt::Write as _;
            write!(&mut value, "{byte:02x}").map_err(io::Error::other)?;
        }
        let name = PhysicalComponent::try_new(&value)?;
        match parent.create_private_dir(&name) {
            Ok(staging) => return Ok((name, staging)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "export staging identity retries exhausted",
    ))
}

fn validate_external_path_bound(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_EXTERNAL_PATH_BYTES
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid or oversized external path",
        ));
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn publish_reports_cleanup_failure_after_destination_race() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let files = ExternalFileSet::open(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
        )
        .unwrap();
        let destination = external
            .path()
            .canonicalize()
            .unwrap()
            .join("raced-destination");
        let mut transaction = files
            .begin_export(&destination, ExportOverwrite::Refuse)
            .unwrap();
        transaction
            .write_all(b"complete private plaintext")
            .unwrap();
        std::fs::write(&destination, b"raced existing").unwrap();
        transaction.cleanup_failures_remaining = 1;

        let error = transaction.publish().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!error.published());
        assert!(error.cleanup_failed());
        assert!(error.into_pending_cleanup().is_some());
        assert_eq!(std::fs::read(destination).unwrap(), b"raced existing");
    }

    #[test]
    fn abort_retains_exact_cleanup_ownership_across_repeated_failures() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let external_root = external.path().canonicalize().unwrap();
        let files = ExternalFileSet::open(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
        )
        .unwrap();
        let mut transaction = files
            .begin_export(
                &external_root.join("never-published"),
                ExportOverwrite::Refuse,
            )
            .unwrap();
        transaction.write_all(b"private plaintext").unwrap();
        transaction.cleanup_failures_remaining = 2;

        let pending = transaction.abort().unwrap_err();
        let pending = pending.retry().unwrap_err();
        pending.retry().unwrap();

        assert!(std::fs::read_dir(external_root).unwrap().next().is_none());
    }

    #[test]
    fn consuming_publish_contains_panic_and_returns_exact_cleanup_ownership() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let external_root = external.path().canonicalize().unwrap();
        let files = ExternalFileSet::open(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
        )
        .unwrap();
        let mut transaction = files
            .begin_export(
                &external_root.join("never-published"),
                ExportOverwrite::Refuse,
            )
            .unwrap();
        transaction.write_all(b"private plaintext").unwrap();
        transaction.panic_on_publish = true;
        transaction.cleanup_failures_remaining = 1;

        let error = transaction.publish().unwrap_err();
        assert!(!error.published());
        let pending = error.into_pending_cleanup().unwrap();
        pending.retry().unwrap();
        assert!(std::fs::read_dir(external_root).unwrap().next().is_none());
    }
}

fn validate_stable_import(file: &FileCapability, initial: FileStamp) -> io::Result<()> {
    file.require_single_regular_link()?;
    if file.stamp()? != initial {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "selected import changed while it was read",
        ));
    }
    Ok(())
}
