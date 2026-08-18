//! Handle-relative filesystem capabilities for Notecrypt storage.

use std::ffi::OsString;
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, PermissionsExt};
use cap_std::time::SystemTime;

mod external;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod external_test_support {
    use crate::{ExportTransaction, ExternalFileSet};

    pub fn inject_cleanup_failures(transaction: &mut ExportTransaction, failures: usize) {
        transaction.cleanup_failures_remaining = failures;
    }

    pub fn inject_publish_panic(transaction: &mut ExportTransaction) {
        transaction.panic_on_publish = true;
    }

    pub fn inject_begin_failure(files: &ExternalFileSet, cleanup_failures: usize) {
        files.inject_begin_failure(cleanup_failures);
    }
}

pub use external::{
    ExportBeginError, ExportCleanupPending, ExportOverwrite, ExportPublicationEffect,
    ExportPublishAttemptError, ExportPublishError, ExportTransaction, ExternalFileSet,
    StableImport, StableImportValidator,
};

/// A validated single physical name accepted by capability-relative operations.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalComponent(Box<str>);

impl PhysicalComponent {
    pub fn try_new(value: &str) -> io::Result<Self> {
        let portable = value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        });
        let base = value.split('.').next().unwrap_or_default();
        let numbered_device = |prefix: &str| {
            base.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        };
        let reserved = matches!(base, "con" | "prn" | "aux" | "nul")
            || numbered_device("com")
            || numbered_device("lpt");
        if value.is_empty()
            || value.len() > 255
            || matches!(value, "." | "..")
            || value.ends_with('.')
            || !portable
            || reserved
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid physical component",
            ));
        }
        Ok(Self(value.into()))
    }

    fn as_path(&self) -> &Path {
        Path::new(&*self.0)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub directory_sync: bool,
    pub atomic_replace: bool,
    pub no_replace_publication: bool,
}

/// An opened directory handle from which all later names are resolved.
pub struct Directory {
    inner: Dir,
    identity_chain: Vec<FileIdentity>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    identity: FileIdentity,
    length: u64,
    modified: SystemTime,
    change: Option<FileChangeStamp>,
}

impl FileStamp {
    pub const fn is_cacheable(&self) -> bool {
        self.change.is_some()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileChangeStamp {
    seconds_or_ticks: i64,
    nanoseconds: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FilesystemIdentity(u64);

impl Directory {
    /// Acquires the only ambient path authority in the crate.
    pub fn open_ambient(path: &Path) -> io::Result<Self> {
        let (platform_root, components) = split_absolute(path)?;
        let mut inner = Dir::open_ambient_dir(platform_root, ambient_authority())?;
        let mut identity_chain = vec![identity(&inner)?];
        for component in components {
            inner = inner.open_dir_nofollow(Path::new(&component))?;
            identity_chain.push(identity(&inner)?);
        }
        Ok(Self {
            inner,
            identity_chain,
        })
    }

    pub fn create_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        self.inner.create_dir(name.as_path())?;
        self.open_dir_nofollow(name)
    }

    pub fn create_private_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        self.inner.create_dir_with(name.as_path(), &builder)?;
        let initialized = match self.open_dir_nofollow(name) {
            Ok(directory) => {
                #[cfg(windows)]
                let prepared = windows::make_private_directory(&directory.inner);
                #[cfg(not(windows))]
                let prepared = Ok(());
                prepared.and_then(|()| directory.verify_private().map(|()| directory))
            }
            Err(error) => Err(error),
        };
        match initialized {
            Ok(directory) => Ok(directory),
            Err(primary) => match self.inner.remove_dir(name.as_path()) {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(io::Error::other(format!(
                    "private-directory initialization failed: {primary}; cleanup failed: {cleanup}"
                ))),
            },
        }
    }

    pub fn open_dir_nofollow(&self, name: &PhysicalComponent) -> io::Result<Self> {
        let inner = self.inner.open_dir_nofollow(name.as_path())?;
        let mut identity_chain = self.identity_chain.clone();
        identity_chain.push(identity(&inner)?);
        Ok(Self {
            inner,
            identity_chain,
        })
    }

    pub fn open_or_create_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        match self.open_dir_nofollow(name) {
            Ok(directory) => Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.create_dir(name),
            Err(error) => Err(error),
        }
    }

    pub fn open_or_create_private_dir(&self, name: &PhysicalComponent) -> io::Result<Self> {
        let directory = match self.open_dir_nofollow(name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.create_private_dir(name)?
            }
            Err(error) => return Err(error),
        };
        directory.verify_private()?;
        Ok(directory)
    }

    pub fn create_file_new(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn open_file_nofollow(&self, name: &PhysicalComponent) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn open_file_for_sync_nofollow(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn open_file_for_rename_nofollow(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{DELETE, GENERIC_READ, GENERIC_WRITE};
            options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE);
        }
        let inner = self.inner.open_with(name.as_path(), &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn try_lock_exclusive(&self, name: &PhysicalComponent) -> io::Result<ExclusiveFileLock> {
        let file = match self.create_file_new(name) {
            Ok(file) => {
                file.sync_all()?;
                self.sync()?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.open_file_for_sync_nofollow(name)?
            }
            Err(error) => return Err(error),
        };
        lock_file_nonblocking(&file)?;
        Ok(ExclusiveFileLock { file })
    }

    pub fn entry_kind(&self, name: &PhysicalComponent) -> io::Result<EntryKind> {
        let metadata = self.inner.symlink_metadata(name.as_path())?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "symbolic links are rejected",
            ));
        }
        if file_type.is_file() {
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hard-linked files are rejected",
                ));
            }
            Ok(EntryKind::File)
        } else if file_type.is_dir() {
            Ok(EntryKind::Directory)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "special filesystem objects are rejected",
            ))
        }
    }

    pub fn entry_names_bounded(&self, maximum: usize) -> io::Result<Vec<PhysicalComponent>> {
        let mut names = Vec::new();
        names
            .try_reserve(maximum.min(64))
            .map_err(|_| io::Error::other("directory enumeration allocation failed"))?;
        for entry in self.inner.read_dir(".")? {
            if names.len() >= maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry limit exceeded",
                ));
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 physical name")
            })?;
            names.push(PhysicalComponent::try_new(name)?);
        }
        names.sort_unstable();
        Ok(names)
    }

    pub fn sync(&self) -> io::Result<()> {
        self.inner.try_clone()?.into_std_file().sync_all()
    }

    pub fn verify_private(&self) -> io::Result<()> {
        let metadata = self.inner.dir_metadata()?;
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory permissions are not private",
            ));
        }
        #[cfg(windows)]
        windows::verify_private_directory(&self.inner)?;
        #[cfg(not(unix))]
        let _ = metadata;
        Ok(())
    }

    pub fn same_identity(&self, other: &Self) -> io::Result<bool> {
        Ok(self.final_identity() == other.final_identity())
    }

    pub fn identity(&self) -> FileIdentity {
        self.final_identity()
    }

    pub fn filesystem_identity(&self) -> FilesystemIdentity {
        FilesystemIdentity(self.final_identity().device)
    }

    #[cfg(unix)]
    pub fn available_space(&self) -> io::Result<u64> {
        use std::os::fd::AsFd as _;

        let statistics = rustix::fs::fstatvfs(self.inner.as_fd())?;
        statistics
            .f_frsize
            .checked_mul(statistics.f_bavail)
            .ok_or_else(|| io::Error::other("available-space calculation overflowed"))
    }

    #[cfg(windows)]
    pub fn available_space(&self) -> io::Result<u64> {
        windows::available_space(&self.inner)
    }

    pub fn is_same_or_ancestor_of(&self, other: &Self) -> bool {
        other.identity_chain.contains(&self.final_identity())
    }

    pub fn same_filesystem(&self, other: &Self) -> io::Result<bool> {
        Ok(self.final_identity().device == other.final_identity().device)
    }

    fn final_identity(&self) -> FileIdentity {
        *self
            .identity_chain
            .last()
            .expect("every directory capability includes its platform root")
    }

    /// Renames a synced file from a held private staging directory without syncing directories.
    ///
    /// The caller must batch directory synchronization after all renames.
    pub fn rename_opened_no_replace_from_private_staging(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        rename_no_replace(
            source,
            &self.inner,
            staged.as_path(),
            &destination_directory.inner,
            destination.as_path(),
        )?;
        let published = match destination_directory.open_file_nofollow(destination) {
            Ok(file) => file,
            Err(error) => {
                let _ = destination_directory
                    .inner
                    .remove_file(destination.as_path());
                let _ = destination_directory.sync();
                return Err(error);
            }
        };
        if !published_matches_exact_source(source, &published)? {
            destination_directory
                .inner
                .remove_file(destination.as_path())?;
            destination_directory.sync()?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published file identity changed",
            ));
        }
        Ok(())
    }

    pub fn replace_atomic_from_private_staging(
        &self,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        let source = self.open_file_for_rename_nofollow(staged)?;
        source.sync_all()?;
        self.replace_opened_atomic_from_private_staging(
            &source,
            staged,
            destination_directory,
            destination,
        )?;
        destination_directory.sync()?;
        self.sync()
    }

    pub fn replace_opened_atomic_from_private_staging(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
    ) -> io::Result<()> {
        self.replace_opened_atomic_checked(
            source,
            staged,
            destination_directory,
            destination.as_path(),
            None,
        )
    }

    pub fn replace_opened_atomic_if_destination_matches(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &PhysicalComponent,
        expected_destination: &FileCapability,
    ) -> io::Result<()> {
        self.replace_opened_atomic_checked(
            source,
            staged,
            destination_directory,
            destination.as_path(),
            Some(expected_destination),
        )
    }

    fn replace_opened_atomic_checked(
        &self,
        source: &FileCapability,
        staged: &PhysicalComponent,
        destination_directory: &Self,
        destination: &Path,
        expected_destination: Option<&FileCapability>,
    ) -> io::Result<()> {
        self.verify_private()?;
        // Unix has no portable atomic replace syscall that names an already-open
        // source descriptor. The source lives in an unpredictable 0700 directory
        // under the store's OS mutation lock. Reopen and compare immediately
        // before the atomic path replacement so no cooperative process can
        // substitute a different source entry.
        let named_source = self.open_file_for_rename_nofollow(staged)?;
        if !source.same_file(&named_source)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staged replacement identity changed before publication",
            ));
        }
        if let Some(expected) = expected_destination {
            let named_destination = destination_directory.open_file_nofollow_path(destination)?;
            if !expected.same_file(&named_destination)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "replacement destination identity changed before publication",
                ));
            }
        }
        rename_replace(
            source,
            &self.inner,
            staged.as_path(),
            destination_directory,
            destination,
        )?;
        source.sync_all()?;
        let published = destination_directory.open_file_nofollow_path(destination)?;
        if !source.same_file(&published)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replaced file identity changed",
            ));
        }
        Ok(())
    }

    fn open_file_nofollow_path(&self, name: &Path) -> io::Result<FileCapability> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let inner = self.inner.open_with(name, &options)?;
        let file = FileCapability { inner };
        file.require_single_regular_link()?;
        Ok(file)
    }

    pub fn remove_opened_file_if_matches(
        &self,
        expected: &FileCapability,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.remove_opened_file_if_matches_unsynced(expected, name)?;
        self.sync()
    }

    pub fn remove_opened_file_if_matches_unsynced(
        &self,
        expected: &FileCapability,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        let named = self.open_file_nofollow(name)?;
        if !expected.same_file(&named)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "removal target identity changed before removal",
            ));
        }
        self.inner.remove_file(name.as_path())
    }

    pub fn remove_file(&self, name: &PhysicalComponent) -> io::Result<()> {
        self.entry_kind(name)?;
        self.inner.remove_file(name.as_path())?;
        self.sync()
    }

    pub fn remove_file_from_private_staging_unsynced(
        &self,
        name: &PhysicalComponent,
    ) -> io::Result<()> {
        self.verify_private()?;
        self.entry_kind(name)?;
        self.inner.remove_file(name.as_path())
    }

    pub fn remove_empty_dir(&self, name: &PhysicalComponent) -> io::Result<()> {
        self.inner.remove_dir(name.as_path())?;
        self.sync()
    }

    pub fn remove_private_file_tree(
        &self,
        name: &PhysicalComponent,
        maximum_files: usize,
    ) -> io::Result<()> {
        let child = self.open_dir_nofollow(name)?;
        child.verify_private()?;
        let mut count = 0_usize;
        for entry in child.inner.read_dir(".")? {
            if count >= maximum_files {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owned transaction file limit exceeded",
                ));
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("owned transaction count overflow"))?;
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 physical name")
            })?;
            let entry = PhysicalComponent::try_new(name)?;
            if child.entry_kind(&entry)? != EntryKind::File {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owned transaction tree contains a non-file entry",
                ));
            }
            child.inner.remove_file(entry.as_path())?;
        }
        child.sync()?;
        drop(child);
        self.inner.remove_dir(name.as_path())?;
        self.sync()
    }

    pub fn probe_capabilities(&self) -> io::Result<Capabilities> {
        let probe_name = random_probe_component()?;
        let probe = self.create_private_dir(&probe_name)?;
        let source_name = PhysicalComponent::try_new("source")?;
        let destination_name = PhysicalComponent::try_new("destination")?;
        let source_directory = probe.create_private_dir(&source_name)?;
        let destination_directory = probe.create_private_dir(&destination_name)?;
        let source = PhysicalComponent::try_new("source")?;
        let replacement = PhysicalComponent::try_new("replacement")?;
        let destination = PhysicalComponent::try_new("destination")?;
        let result = (|| {
            source_directory.create_file_new(&source)?.sync_all()?;
            source_directory.sync()?;
            let opened = source_directory.open_file_for_rename_nofollow(&source)?;
            source_directory.rename_opened_no_replace_from_private_staging(
                &opened,
                &source,
                &destination_directory,
                &destination,
            )?;
            destination_directory.sync()?;
            source_directory.create_file_new(&replacement)?.sync_all()?;
            source_directory.replace_atomic_from_private_staging(
                &replacement,
                &destination_directory,
                &destination,
            )?;
            Ok(Capabilities {
                directory_sync: true,
                atomic_replace: true,
                no_replace_publication: true,
            })
        })();
        let cleanup_source = [&source, &replacement].into_iter().try_for_each(|name| {
            match source_directory.inner.remove_file(name.as_path()) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        });
        let cleanup_destination = match destination_directory
            .inner
            .remove_file(destination.as_path())
        {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        let cleanup_files = cleanup_source
            .and(cleanup_destination)
            .and_then(|()| source_directory.sync())
            .and_then(|()| destination_directory.sync());
        drop(source_directory);
        drop(destination_directory);
        let cleanup_directories = cleanup_files
            .and_then(|()| probe.inner.remove_dir(source_name.as_path()))
            .and_then(|()| probe.inner.remove_dir(destination_name.as_path()))
            .and_then(|()| probe.sync());
        drop(probe);
        let cleanup = cleanup_directories
            .and_then(|()| self.inner.remove_dir(probe_name.as_path()))
            .and_then(|()| self.sync());
        cleanup?;
        result.map(|_| Capabilities {
            directory_sync: true,
            atomic_replace: true,
            no_replace_publication: true,
        })
    }
}

fn identity(directory: &Dir) -> io::Result<FileIdentity> {
    let metadata = directory.dir_metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn split_absolute(path: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem roots must be absolute",
        ));
    }
    let mut platform_root = PathBuf::new();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if names.is_empty() => platform_root.push(prefix.as_os_str()),
            Component::RootDir if names.is_empty() => platform_root.push(component.as_os_str()),
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_)
            | Component::RootDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "filesystem root contains a special component",
                ));
            }
        }
    }
    if platform_root.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem root has no platform root",
        ));
    }
    Ok((platform_root, names))
}

fn random_probe_component() -> io::Result<PhysicalComponent> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
    let mut value = String::new();
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(io::Error::other)?;
    }
    PhysicalComponent::try_new(&value)
}

struct NoReplaceFailure {
    primary: io::Error,
    destination_may_be_visible: bool,
}

fn finish_linked_publication_after_source_remove_failure(
    primary: io::Error,
    rollback: io::Result<()>,
    rollback_sync: io::Result<()>,
) -> NoReplaceFailure {
    match (rollback, rollback_sync) {
        (Ok(()), Ok(())) => NoReplaceFailure {
            primary,
            destination_may_be_visible: false,
        },
        (Err(cleanup), _) | (_, Err(cleanup)) => NoReplaceFailure {
            primary: io::Error::other(format!(
                "publication failed and destination rollback is unproven: {primary}; {cleanup}"
            )),
            destination_may_be_visible: true,
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_no_replace_observed(
    source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Dir,
    destination: &Path,
) -> Result<(), NoReplaceFailure> {
    use std::os::fd::AsRawFd as _;

    // `AT_EMPTY_PATH` requires CAP_DAC_READ_SEARCH and therefore cannot be
    // used by an ordinary desktop process. Linking through procfs preserves
    // exact ownership of the already-authenticated descriptor without adding
    // that capability requirement. Initialization probes this exact operation
    // and fails closed when procfs or the target filesystem cannot provide it.
    let proc_file = PathBuf::from(format!("/proc/self/fd/{}", source_file.inner.as_raw_fd()));
    rustix::fs::linkat(
        rustix::fs::CWD,
        &proc_file,
        destination_directory,
        destination,
        rustix::fs::AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(io::Error::from)
    .map_err(|primary| NoReplaceFailure {
        primary,
        destination_may_be_visible: false,
    })?;
    if let Err(primary) = source_directory.remove_file(source) {
        let rollback = destination_directory.remove_file(destination);
        let rollback_sync = destination_directory
            .try_clone()
            .and_then(|directory| directory.into_std_file().sync_all());
        return Err(finish_linked_publication_after_source_remove_failure(
            primary,
            rollback,
            rollback_sync,
        ));
    }
    Ok(())
}

#[cfg(not(target_vendor = "apple"))]
fn published_matches_exact_source(
    source: &FileCapability,
    published: &FileCapability,
) -> io::Result<bool> {
    source.same_file(published)
}

#[cfg(target_vendor = "apple")]
fn published_matches_exact_source(
    source: &FileCapability,
    published: &FileCapability,
) -> io::Result<bool> {
    // fclonefileat publishes a copy-on-write clone from the exact held descriptor,
    // so the destination intentionally has a distinct filesystem identity.
    Ok(source.len()? == published.len()?)
}

#[cfg(target_vendor = "apple")]
fn rename_no_replace_observed(
    source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Dir,
    destination: &Path,
) -> Result<(), NoReplaceFailure> {
    rustix::fs::fclonefileat(
        &source_file.inner,
        destination_directory,
        destination,
        rustix::fs::CloneFlags::empty(),
    )
    .map_err(io::Error::from)
    .map_err(|primary| NoReplaceFailure {
        primary,
        destination_may_be_visible: false,
    })?;
    if let Err(primary) = source_directory.remove_file(source) {
        let rollback = destination_directory.remove_file(destination);
        let rollback_sync = destination_directory
            .try_clone()
            .and_then(|directory| directory.into_std_file().sync_all());
        return Err(finish_linked_publication_after_source_remove_failure(
            primary,
            rollback,
            rollback_sync,
        ));
    }
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn rename_no_replace_observed(
    _source_file: &FileCapability,
    _source_directory: &Dir,
    _source: &Path,
    _destination_directory: &Dir,
    _destination: &Path,
) -> Result<(), NoReplaceFailure> {
    Err(NoReplaceFailure {
        primary: io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is unavailable",
        ),
        destination_may_be_visible: false,
    })
}

#[cfg(windows)]
fn rename_no_replace_observed(
    source_file: &FileCapability,
    _source_directory: &Dir,
    _source: &Path,
    destination_directory: &Dir,
    destination: &Path,
) -> Result<(), NoReplaceFailure> {
    windows::rename_by_handle(source_file, destination_directory, destination, false).map_err(
        |primary| NoReplaceFailure {
            primary,
            destination_may_be_visible: false,
        },
    )
}

fn rename_no_replace(
    source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Dir,
    destination: &Path,
) -> io::Result<()> {
    rename_no_replace_observed(
        source_file,
        source_directory,
        source,
        destination_directory,
        destination,
    )
    .map_err(|failure| failure.primary)
}

#[cfg(windows)]
fn rename_replace(
    source_file: &FileCapability,
    _source_directory: &Dir,
    _source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> io::Result<()> {
    windows::rename_by_handle(source_file, &destination_directory.inner, destination, true)
}

#[cfg(not(windows))]
fn rename_replace(
    _source_file: &FileCapability,
    source_directory: &Dir,
    source: &Path,
    destination_directory: &Directory,
    destination: &Path,
) -> io::Result<()> {
    source_directory.rename(source, &destination_directory.inner, destination)
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::ffi::c_void;
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    use cap_std::fs::Dir;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
        SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid,
        GetAce, GetSecurityDescriptorControl, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_BASIC_INFO, FILE_RENAME_INFO, FileBasicInfo, FileRenameInfo,
        GetDiskFreeSpaceExW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, SetFileInformationByHandle,
        UnlockFileEx, VOLUME_NAME_DOS,
    };
    #[cfg(feature = "benchmark-support")]
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    #[cfg(feature = "benchmark-support")]
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    use super::FileCapability;

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was returned by a Windows API documented to require
                // `LocalFree`, and this guard owns the only cleanup of that allocation.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    pub(super) fn make_private_directory(directory: &Dir) -> io::Result<()> {
        let handle = directory.as_raw_handle().cast();
        let (owner, descriptor) = read_owner(handle)?;
        let _descriptor = LocalAllocation(descriptor.cast());
        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: owner.cast(),
        };
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `access` is live for the call, the owner SID remains live through
        // `_descriptor`, and `acl` is a valid output pointer.
        let status = unsafe { SetEntriesInAclW(1, &access, std::ptr::null(), &mut acl) };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        let _acl = LocalAllocation(acl.cast());
        // SAFETY: `handle` is a live directory handle, and `acl` remains live through `_acl`.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        verify_private_directory(directory)
    }

    pub(super) fn verify_private_directory(directory: &Dir) -> io::Result<()> {
        let handle = directory.as_raw_handle().cast();
        let mut owner: PSID = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: all output pointers are valid and `handle` remains live for the call.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        let _descriptor = LocalAllocation(descriptor.cast());
        if owner.is_null() || acl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory has no owner-only DACL",
            ));
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `descriptor` remains live through `_descriptor`, and both outputs are valid.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory DACL inherits permissions",
            ));
        }
        // SAFETY: `acl` is part of the live descriptor allocation.
        let ace_count = unsafe { (*acl).AceCount };
        if ace_count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory DACL is not owner-only",
            ));
        }
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: the verified ACL contains one entry and `ace` is a valid output pointer.
        if unsafe { GetAce(acl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: the only supported owner entry must be an ACCESS_ALLOWED_ACE, checked before
        // reading its mask and trailing SID.
        let (ace_type, ace_flags, mask, sid) = unsafe {
            (
                (*allowed).Header.AceType,
                u32::from((*allowed).Header.AceFlags),
                (*allowed).Mask,
                std::ptr::addr_of_mut!((*allowed).SidStart).cast(),
            )
        };
        let required_inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        // ACCESS_ALLOWED_ACE_TYPE is zero in the stable Windows ABI.
        // SAFETY: `sid` points into the live ACE and `owner` into the live descriptor.
        let same_owner = unsafe { EqualSid(sid, owner) } != 0;
        if ace_type != 0
            || ace_flags & required_inheritance != required_inheritance
            || mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
            || !same_owner
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory DACL is not owner-only",
            ));
        }
        Ok(())
    }

    fn read_owner(
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> io::Result<(PSID, PSECURITY_DESCRIPTOR)> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: output pointers are valid and `handle` remains live for the call.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(win32_error(status));
        }
        if owner.is_null() || descriptor.is_null() {
            // SAFETY: a non-null descriptor returned by GetSecurityInfo requires LocalFree.
            unsafe {
                LocalFree(descriptor.cast());
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory has no authenticated owner",
            ));
        }
        Ok((owner, descriptor))
    }

    fn win32_error(status: u32) -> io::Error {
        io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
    }

    pub(super) fn change_time(file: &FileCapability) -> io::Result<i64> {
        let mut information = FILE_BASIC_INFO::default();
        let information_bytes = u32::try_from(size_of::<FILE_BASIC_INFO>())
            .map_err(|_| io::Error::other("file information size overflowed"))?;
        // SAFETY: `file` owns a valid handle and `information` is writable for the exact
        // FILE_BASIC_INFO size for the duration of the call.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                file.inner.as_raw_handle().cast(),
                FileBasicInfo,
                std::ptr::addr_of_mut!(information).cast(),
                information_bytes,
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(information.ChangeTime)
        }
    }

    pub(super) fn available_space(directory: &Dir) -> io::Result<u64> {
        let handle = directory.as_raw_handle().cast();
        // The first call intentionally supplies no buffer and returns the required UTF-16 size.
        // SAFETY: `handle` is valid for the call and a null buffer with zero capacity is the
        // documented size-query form of GetFinalPathNameByHandleW.
        let required =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_DOS) };
        if required == 0 {
            return Err(io::Error::last_os_error());
        }
        let capacity = required
            .checked_add(1)
            .ok_or_else(|| io::Error::other("final directory path length overflowed"))?;
        let mut path = vec![
            0_u16;
            usize::try_from(capacity).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "final directory path is too long",
                )
            })?
        ];
        // SAFETY: `path` is writable for `capacity` UTF-16 units and `handle` remains valid.
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), capacity, VOLUME_NAME_DOS)
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written >= capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "final directory path changed during lookup",
            ));
        }
        path.truncate(usize::try_from(written).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "final directory path is too long",
            )
        })?);
        path.push(0);
        let mut available = 0_u64;
        // SAFETY: `path` is NUL-terminated and remains live, while `available` is a valid output.
        let succeeded = unsafe {
            GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(available)
        }
    }

    pub(super) fn rename_by_handle(
        source: &FileCapability,
        destination_directory: &Dir,
        destination: &std::path::Path,
        replace: bool,
    ) -> io::Result<()> {
        let filename: Vec<u16> = destination.as_os_str().encode_wide().collect();
        if filename.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical component contains an embedded NUL",
            ));
        }
        let filename_bytes = filename
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let buffer_bytes = offset_of!(FILE_RENAME_INFO, FileName)
            .checked_add(filename_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let words = buffer_bytes.div_ceil(size_of::<usize>());
        let mut aligned = vec![0_usize; words];
        let info = aligned.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        let filename_length = u32::try_from(filename_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        // SAFETY: `aligned` is pointer-aligned and sized for the fixed header plus all UTF-16
        // code units. Both borrowed handles remain valid for the duration of this call.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = replace;
            (*info).RootDirectory = destination_directory.as_raw_handle().cast();
            (*info).FileNameLength = filename_length;
            std::ptr::copy_nonoverlapping(
                filename.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                filename.len(),
            );
            if SetFileInformationByHandle(
                source.inner.as_raw_handle().cast(),
                FileRenameInfo,
                info.cast(),
                u32::try_from(buffer_bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn lock_file_nonblocking(file: &FileCapability) -> io::Result<()> {
        // SAFETY: `OVERLAPPED` is a C POD structure for which all-zero is the documented
        // synchronous byte-range origin.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: `file` owns a valid handle and `overlapped` remains live and exclusively
        // borrowed for this synchronous nonblocking lock call.
        let succeeded = unsafe {
            LockFileEx(
                file.inner.as_raw_handle().cast(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if succeeded == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(33) {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mutation lock is held",
                ))
            } else {
                Err(error)
            }
        } else {
            Ok(())
        }
    }

    pub(super) fn unlock_file(file: &FileCapability) -> io::Result<()> {
        // SAFETY: `OVERLAPPED` is a C POD structure for which all-zero is the documented
        // synchronous byte-range origin.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: `file` owns the handle used for the matching lock and `overlapped` remains live
        // and exclusively borrowed for the duration of this synchronous unlock call.
        let succeeded =
            unsafe { UnlockFileEx(file.inner.as_raw_handle().cast(), 0, 1, 0, &mut overlapped) };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "benchmark-support")]
    pub(super) fn mark_sparse_file(file: &std::fs::File) -> io::Result<()> {
        let mut bytes_returned = 0_u32;
        // SAFETY: `file` owns a valid handle for this call, and Microsoft documents null input
        // and output buffers for FSCTL_SET_SPARSE.
        let succeeded = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// An opened regular file with no path authority.
pub struct FileCapability {
    inner: File,
}

pub struct ExclusiveFileLock {
    file: FileCapability,
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn lock_file_nonblocking(file: &FileCapability) -> io::Result<()> {
    rustix::fs::flock(
        &file.inner,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| {
        let error = io::Error::from(error);
        if matches!(error.kind(), io::ErrorKind::WouldBlock) {
            io::Error::new(io::ErrorKind::WouldBlock, "mutation lock is held")
        } else {
            error
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn unlock_file(file: &FileCapability) -> io::Result<()> {
    rustix::fs::flock(&file.inner, rustix::fs::FlockOperation::Unlock).map_err(io::Error::from)
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn lock_file_nonblocking(_file: &FileCapability) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "exclusive mutation locking is unavailable",
    ))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn unlock_file(_file: &FileCapability) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn lock_file_nonblocking(file: &FileCapability) -> io::Result<()> {
    windows::lock_file_nonblocking(file)
}

#[cfg(windows)]
fn unlock_file(file: &FileCapability) -> io::Result<()> {
    windows::unlock_file(file)
}

/// Marks a benchmark fixture sparse where the platform requires an explicit operation.
#[cfg(all(feature = "benchmark-support", not(windows)))]
pub fn mark_sparse_file(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

/// Marks a benchmark fixture sparse without exposing the Windows FFI boundary.
#[cfg(all(feature = "benchmark-support", windows))]
pub fn mark_sparse_file(file: &std::fs::File) -> io::Result<()> {
    windows::mark_sparse_file(file)
}

impl FileCapability {
    pub fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(self.inner.metadata()?.len())
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn identity(&self) -> io::Result<FileIdentity> {
        let metadata = self.inner.metadata()?;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub fn stamp(&self) -> io::Result<FileStamp> {
        let metadata = self.inner.metadata()?;
        #[cfg(unix)]
        let change = {
            use std::os::fd::AsFd as _;

            let status = rustix::fs::fstat(self.inner.as_fd())?;
            Some(FileChangeStamp {
                seconds_or_ticks: status.st_ctime,
                nanoseconds: status.st_ctime_nsec,
            })
        };
        #[cfg(windows)]
        let change = Some(FileChangeStamp {
            seconds_or_ticks: windows::change_time(self)?,
            nanoseconds: 0,
        });
        #[cfg(not(any(unix, windows)))]
        let change = None;
        Ok(FileStamp {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            length: metadata.len(),
            modified: metadata.modified()?,
            change,
        })
    }

    pub fn matches_identity(&self, expected: &FileIdentity) -> io::Result<bool> {
        Ok(self.identity()? == *expected)
    }

    fn require_single_regular_link(&self) -> io::Result<()> {
        let metadata = self.inner.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file is not a single-linked regular file",
            ));
        }
        Ok(())
    }

    fn same_file(&self, other: &Self) -> io::Result<bool> {
        let left = self.inner.metadata()?;
        let right = other.inner.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
}

impl Read for FileCapability {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for FileCapability {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for FileCapability {
    fn seek(&mut self, position: std::io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::io::Read;
    use std::io::Write;

    use tempfile::TempDir;

    use super::{
        Directory, FileIdentity, FileStamp, PhysicalComponent,
        finish_linked_publication_after_source_remove_failure,
    };

    #[test]
    fn no_replace_reports_visibility_when_source_unlink_and_rollback_fail() {
        let failure = finish_linked_publication_after_source_remove_failure(
            std::io::Error::other("injected source unlink failure"),
            Err(std::io::Error::other(
                "injected destination rollback failure",
            )),
            Ok(()),
        );

        assert!(failure.destination_may_be_visible);
        assert_eq!(failure.primary.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn no_replace_reports_visibility_when_rollback_sync_fails() {
        let failure = finish_linked_publication_after_source_remove_failure(
            std::io::Error::other("injected source unlink failure"),
            Ok(()),
            Err(std::io::Error::other("injected rollback sync failure")),
        );

        assert!(failure.destination_may_be_visible);
    }

    #[test]
    fn no_replace_reports_not_published_only_after_durable_rollback() {
        let failure = finish_linked_publication_after_source_remove_failure(
            std::io::Error::other("injected source unlink failure"),
            Ok(()),
            Ok(()),
        );

        assert!(!failure.destination_may_be_visible);
    }

    #[test]
    fn unavailable_change_metadata_is_not_cacheable() {
        let stamp = FileStamp {
            identity: FileIdentity {
                device: 1,
                inode: 2,
            },
            length: 3,
            modified: cap_std::time::SystemTime::from_std(std::time::SystemTime::UNIX_EPOCH),
            change: None,
        };
        assert!(!stamp.is_cacheable());
    }

    #[cfg(unix)]
    #[test]
    fn change_stamp_detects_equal_length_rewrite_after_mtime_restore() {
        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let name = PhysicalComponent::try_new("object").unwrap();
        let mut file = directory.create_file_new(&name).unwrap();
        file.write_all(b"authenticated").unwrap();
        file.sync_all().unwrap();
        let before = file.stamp().unwrap();
        let modified = std::fs::metadata(root_path.join("object"))
            .unwrap()
            .modified()
            .unwrap();

        std::fs::write(root_path.join("object"), b"compromised!!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(root_path.join("object"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();

        let after = directory
            .open_file_nofollow(&name)
            .unwrap()
            .stamp()
            .unwrap();
        assert!(before.is_cacheable());
        assert!(before != after);
    }

    #[test]
    fn source_name_swap_cannot_publish_an_unverified_file() {
        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging_name = PhysicalComponent::try_new("staging").unwrap();
        let staging = directory.create_private_dir(&staging_name).unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        staging
            .create_file_new(&source)
            .unwrap()
            .write_all(b"authenticated")
            .unwrap();
        std::fs::write(root_path.join("attacker"), b"attacker").unwrap();

        let opened = staging.open_file_for_rename_nofollow(&source).unwrap();
        std::fs::rename(
            root_path.join("staging/source"),
            root_path.join("staging/original"),
        )
        .unwrap();
        std::fs::rename(root_path.join("attacker"), root_path.join("staging/source")).unwrap();
        let result = staging.rename_opened_no_replace_from_private_staging(
            &opened,
            &source,
            &directory,
            &destination,
        );

        match result {
            Ok(()) => assert_eq!(
                std::fs::read(root_path.join("destination")).unwrap(),
                b"authenticated"
            ),
            Err(_) => assert!(!root_path.join("destination").exists()),
        }
        assert_eq!(
            std::fs::read(root_path.join("staging/original")).unwrap(),
            b"authenticated"
        );
    }

    #[test]
    fn checked_replace_and_remove_reject_source_and_destination_swaps() {
        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging = directory
            .create_private_dir(&PhysicalComponent::try_new("staging").unwrap())
            .unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        let mut staged = staging.create_file_new(&source).unwrap();
        staged.write_all(b"replacement").unwrap();
        staged.sync_all().unwrap();
        let mut current = directory.create_file_new(&destination).unwrap();
        current.write_all(b"current").unwrap();
        current.sync_all().unwrap();
        let expected_source = staging.open_file_for_rename_nofollow(&source).unwrap();
        let expected_destination = directory.open_file_nofollow(&destination).unwrap();

        std::fs::rename(
            root_path.join("staging/source"),
            root_path.join("staging/original-source"),
        )
        .unwrap();
        std::fs::write(root_path.join("staging/source"), b"attacker-source").unwrap();
        assert!(
            staging
                .replace_opened_atomic_if_destination_matches(
                    &expected_source,
                    &source,
                    &directory,
                    &destination,
                    &expected_destination,
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"current"
        );

        std::fs::remove_file(root_path.join("staging/source")).unwrap();
        std::fs::rename(
            root_path.join("staging/original-source"),
            root_path.join("staging/source"),
        )
        .unwrap();
        std::fs::rename(
            root_path.join("destination"),
            root_path.join("original-destination"),
        )
        .unwrap();
        std::fs::write(root_path.join("destination"), b"attacker-destination").unwrap();
        assert!(
            staging
                .replace_opened_atomic_if_destination_matches(
                    &expected_source,
                    &source,
                    &directory,
                    &destination,
                    &expected_destination,
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"attacker-destination"
        );

        assert!(
            directory
                .remove_opened_file_if_matches(&expected_destination, &destination)
                .is_err()
        );
        assert!(root_path.join("destination").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reachable_reader_rejects_link_publication_until_staging_name_is_unlinked() {
        use std::os::fd::AsRawFd as _;

        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging = directory
            .create_private_dir(&PhysicalComponent::try_new("staging").unwrap())
            .unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        let mut file = staging.create_file_new(&source).unwrap();
        file.write_all(b"authenticated").unwrap();
        file.sync_all().unwrap();
        let opened = staging.open_file_for_rename_nofollow(&source).unwrap();

        let proc_file = PathBuf::from(format!("/proc/self/fd/{}", opened.inner.as_raw_fd()));
        rustix::fs::linkat(
            rustix::fs::CWD,
            &proc_file,
            &directory.inner,
            destination.as_path(),
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        )
        .unwrap();
        directory.sync().unwrap();
        assert!(directory.open_file_nofollow(&destination).is_err());

        staging
            .remove_file_from_private_staging_unsynced(&source)
            .unwrap();
        staging.sync().unwrap();
        let mut published = directory.open_file_nofollow(&destination).unwrap();
        let mut bytes = Vec::new();
        published.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"authenticated");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_child_process_publishes_from_the_exact_authenticated_descriptor() {
        const CHILD: &str = "NOTECRYPT_PLATFORM_FS_UNPRIVILEGED_CHILD";

        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("tests::ordinary_child_process_publishes_from_the_exact_authenticated_descriptor")
                .arg("--nocapture")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .map(|value| u64::from_str_radix(value, 16).unwrap())
            .unwrap();
        assert_eq!(
            effective & (1_u64 << 2),
            0,
            "child unexpectedly has CAP_DAC_READ_SEARCH"
        );

        let root = TempDir::new().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = Directory::open_ambient(&root_path).unwrap();
        let staging = directory
            .create_private_dir(&PhysicalComponent::try_new("staging").unwrap())
            .unwrap();
        let source = PhysicalComponent::try_new("source").unwrap();
        let destination = PhysicalComponent::try_new("destination").unwrap();
        let mut file = staging.create_file_new(&source).unwrap();
        file.write_all(b"authenticated").unwrap();
        file.sync_all().unwrap();
        let opened = staging.open_file_for_rename_nofollow(&source).unwrap();

        staging
            .rename_opened_no_replace_from_private_staging(
                &opened,
                &source,
                &directory,
                &destination,
            )
            .unwrap();
        directory.sync().unwrap();
        staging.sync().unwrap();

        assert_eq!(
            std::fs::read(root_path.join("destination")).unwrap(),
            b"authenticated"
        );
        assert!(!root_path.join("staging/source").exists());
    }
}
