//! Deterministic benchmark corpus generation.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const WRITE_BUFFER_BYTES: usize = 64 * 1024;
const RENAME_FIXTURE_BYTES: usize = 4 * 1024;
const SPARSE_MARKER_BYTES: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct CorpusSpec {
    pub seed: u64,
    pub tiny_file_count: usize,
    pub mixed_bytes: u64,
    pub large_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusManifest {
    pub root: PathBuf,
    pub file_count: usize,
    pub logical_bytes: u64,
}

#[derive(Debug)]
pub enum CorpusError {
    DestinationNotEmpty(PathBuf),
    Io { path: PathBuf, source: io::Error },
    SizeOverflow,
}

impl fmt::Display for CorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationNotEmpty(path) => {
                write!(
                    formatter,
                    "benchmark destination is not empty: {}",
                    path.display()
                )
            }
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "benchmark corpus I/O failed at {}: {source}",
                    path.display()
                )
            }
            Self::SizeOverflow => formatter.write_str("benchmark corpus size overflow"),
        }
    }
}

impl std::error::Error for CorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::DestinationNotEmpty(_) | Self::SizeOverflow => None,
        }
    }
}

pub struct BenchmarkCorpus;

impl BenchmarkCorpus {
    pub fn generate(spec: &CorpusSpec, destination: &Path) -> Result<CorpusManifest, CorpusError> {
        prepare_destination(destination)?;
        let mut bytes = SyntheticBytes::new(spec.seed);
        let mut logical_bytes = 0_u64;

        let tiny_directory = destination.join("tiny");
        create_directory(&tiny_directory)?;
        for index in 0..spec.tiny_file_count {
            let length = bytes.next_usize(128) + 1;
            let path = tiny_directory.join(format!("{index:06}.bin"));
            write_seeded_file(&path, length as u64, &mut bytes)?;
            logical_bytes = logical_bytes
                .checked_add(length as u64)
                .ok_or(CorpusError::SizeOverflow)?;
        }

        let mixed_directory = destination.join("mixed");
        create_directory(&mixed_directory)?;
        let first_mixed_bytes = spec.mixed_bytes / 2;
        write_seeded_file(
            &mixed_directory.join("incompressible-a.bin"),
            first_mixed_bytes,
            &mut bytes,
        )?;
        write_seeded_file(
            &mixed_directory.join("incompressible-b.bin"),
            spec.mixed_bytes - first_mixed_bytes,
            &mut bytes,
        )?;
        logical_bytes = logical_bytes
            .checked_add(spec.mixed_bytes)
            .ok_or(CorpusError::SizeOverflow)?;

        let large_directory = destination.join("large");
        create_directory(&large_directory)?;
        write_sparse_file(
            &large_directory.join("sparse.bin"),
            spec.large_file_bytes,
            &mut bytes,
        )?;
        logical_bytes = logical_bytes
            .checked_add(spec.large_file_bytes)
            .ok_or(CorpusError::SizeOverflow)?;

        let rename_directory = destination.join("rename-save");
        create_directory(&rename_directory)?;
        write_rename_save_fixtures(&rename_directory, &mut bytes)?;
        logical_bytes = logical_bytes
            .checked_add((RENAME_FIXTURE_BYTES * 2) as u64)
            .ok_or(CorpusError::SizeOverflow)?;

        let file_count = spec
            .tiny_file_count
            .checked_add(5)
            .ok_or(CorpusError::SizeOverflow)?;

        Ok(CorpusManifest {
            root: destination.to_path_buf(),
            file_count,
            logical_bytes,
        })
    }
}

fn prepare_destination(destination: &Path) -> Result<(), CorpusError> {
    create_directory(destination)?;
    let mut entries = fs::read_dir(destination).map_err(|source| CorpusError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|source| CorpusError::Io {
            path: destination.to_path_buf(),
            source,
        })?
        .is_some()
    {
        return Err(CorpusError::DestinationNotEmpty(destination.to_path_buf()));
    }

    Ok(())
}

fn create_directory(path: &Path) -> Result<(), CorpusError> {
    fs::create_dir_all(path).map_err(|source| CorpusError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_seeded_file(
    path: &Path,
    length: u64,
    bytes: &mut SyntheticBytes,
) -> Result<(), CorpusError> {
    let file = File::create(path).map_err(|source| CorpusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut writer = BufWriter::new(file);
    let mut buffer = [0_u8; WRITE_BUFFER_BYTES];
    let mut remaining = length;

    while remaining > 0 {
        let chunk_length = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| CorpusError::SizeOverflow)?;
        bytes.fill(&mut buffer[..chunk_length]);
        writer
            .write_all(&buffer[..chunk_length])
            .map_err(|source| CorpusError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        remaining -= chunk_length as u64;
    }

    writer.flush().map_err(|source| CorpusError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_sparse_file(
    path: &Path,
    length: u64,
    bytes: &mut SyntheticBytes,
) -> Result<(), CorpusError> {
    let mut file = File::create(path).map_err(|source| CorpusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    mark_sparse_file(&file, path)?;
    file.set_len(length).map_err(|source| CorpusError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if length == 0 {
        return Ok(());
    }

    let marker_length = usize::try_from(length.min(SPARSE_MARKER_BYTES as u64))
        .map_err(|_| CorpusError::SizeOverflow)?;
    let mut marker = [0_u8; SPARSE_MARKER_BYTES];
    bytes.fill(&mut marker);
    file.write_all(&marker[..marker_length])
        .map_err(|source| CorpusError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    if length > marker_length as u64 {
        file.seek(SeekFrom::Start(length - marker_length as u64))
            .map_err(|source| CorpusError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        bytes.fill(&mut marker);
        file.write_all(&marker[..marker_length])
            .map_err(|source| CorpusError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }

    Ok(())
}

#[cfg(not(windows))]
fn mark_sparse_file(_file: &File, _path: &Path) -> Result<(), CorpusError> {
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn mark_sparse_file(file: &File, path: &Path) -> Result<(), CorpusError> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    let mut bytes_returned = 0_u32;
    // SAFETY: The file owns a valid handle for the duration of the call.
    // Microsoft documents null input and output buffers for setting the sparse flag.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    if succeeded == 0 {
        return Err(CorpusError::Io {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }

    Ok(())
}

fn write_rename_save_fixtures(
    directory: &Path,
    bytes: &mut SyntheticBytes,
) -> Result<(), CorpusError> {
    let mut original = vec![0_u8; RENAME_FIXTURE_BYTES];
    bytes.fill(&mut original);
    let mut saved = original.clone();
    bytes.fill(&mut saved[RENAME_FIXTURE_BYTES / 2..RENAME_FIXTURE_BYTES / 2 + 32]);

    write_bytes(&directory.join("original.bin"), &original)?;
    write_bytes(&directory.join("saved.bin"), &saved)
}

fn write_bytes(path: &Path, contents: &[u8]) -> Result<(), CorpusError> {
    fs::write(path, contents).map_err(|source| CorpusError::Io {
        path: path.to_path_buf(),
        source,
    })
}

struct SyntheticBytes {
    state: u64,
}

impl SyntheticBytes {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(size_of::<u64>()) {
            let random = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
    }

    fn next_usize(&mut self, upper_bound: usize) -> usize {
        (self.next_u64() % upper_bound as u64) as usize
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Read;
    use std::path::{Path, PathBuf};

    use super::{BenchmarkCorpus, CorpusSpec};

    #[test]
    fn generates_each_required_fixture_and_reports_exact_totals() {
        let destination = tempfile::tempdir().unwrap();
        let spec = CorpusSpec {
            seed: 41,
            tiny_file_count: 3,
            mixed_bytes: 257,
            large_file_bytes: 8_192,
        };

        let manifest = BenchmarkCorpus::generate(&spec, destination.path()).unwrap();
        let files = fingerprint_files(destination.path());

        assert_eq!(manifest.root, destination.path());
        assert_eq!(manifest.file_count, files.len());
        assert_eq!(manifest.logical_bytes, logical_bytes(destination.path()));
        assert_eq!(files.len(), spec.tiny_file_count + 5);
        assert!(files.contains_key(&PathBuf::from("mixed/incompressible-a.bin")));
        assert!(files.contains_key(&PathBuf::from("mixed/incompressible-b.bin")));
        assert!(files.contains_key(&PathBuf::from("large/sparse.bin")));
        assert!(files.contains_key(&PathBuf::from("rename-save/original.bin")));
        assert!(files.contains_key(&PathBuf::from("rename-save/saved.bin")));
    }

    #[test]
    fn the_same_seed_produces_identical_file_trees() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let spec = CorpusSpec {
            seed: 99,
            tiny_file_count: 4,
            mixed_bytes: 1_025,
            large_file_bytes: 32 * 1024 * 1024,
        };

        BenchmarkCorpus::generate(&spec, first.path()).unwrap();
        BenchmarkCorpus::generate(&spec, second.path()).unwrap();

        assert_eq!(
            fingerprint_files(first.path()),
            fingerprint_files(second.path())
        );
    }

    #[test]
    fn changing_the_seed_changes_synthetic_content() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_spec = CorpusSpec {
            seed: 7,
            tiny_file_count: 1,
            mixed_bytes: 128,
            large_file_bytes: 128,
        };
        let second_spec = CorpusSpec {
            seed: 8,
            ..first_spec
        };

        BenchmarkCorpus::generate(&first_spec, first.path()).unwrap();
        BenchmarkCorpus::generate(&second_spec, second.path()).unwrap();

        assert_ne!(
            fingerprint_files(first.path()),
            fingerprint_files(second.path())
        );
    }

    #[test]
    fn platform_sparse_setup_accepts_a_regular_file() {
        let destination = tempfile::tempdir().unwrap();
        let path = destination.path().join("sparse.bin");
        let file = File::create(&path).unwrap();

        super::mark_sparse_file(&file, &path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sparse_fixture_allocates_materially_less_than_its_logical_length() {
        use std::os::unix::fs::MetadataExt;

        const LOGICAL_BYTES: u64 = 64 * 1024 * 1024;

        let destination = tempfile::tempdir().unwrap();
        let spec = CorpusSpec {
            seed: 17,
            tiny_file_count: 0,
            mixed_bytes: 0,
            large_file_bytes: LOGICAL_BYTES,
        };

        BenchmarkCorpus::generate(&spec, destination.path()).unwrap();
        let metadata = fs::metadata(destination.path().join("large/sparse.bin")).unwrap();
        let allocated_bytes = metadata.blocks() * 512;

        assert_eq!(metadata.len(), LOGICAL_BYTES);
        assert!(allocated_bytes < LOGICAL_BYTES / 4);
    }

    #[cfg(windows)]
    #[test]
    fn sparse_fixture_has_the_windows_sparse_file_attribute() {
        use std::os::windows::fs::MetadataExt;

        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SPARSE_FILE;

        let destination = tempfile::tempdir().unwrap();
        let spec = CorpusSpec {
            seed: 17,
            tiny_file_count: 0,
            mixed_bytes: 0,
            large_file_bytes: 64 * 1024 * 1024,
        };

        BenchmarkCorpus::generate(&spec, destination.path()).unwrap();
        let attributes = fs::metadata(destination.path().join("large/sparse.bin"))
            .unwrap()
            .file_attributes();

        assert_ne!(attributes & FILE_ATTRIBUTE_SPARSE_FILE, 0);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FileFingerprint {
        logical_bytes: u64,
        digest: [u8; 32],
    }

    fn fingerprint_files(root: &Path) -> BTreeMap<PathBuf, FileFingerprint> {
        let mut files = BTreeMap::new();
        collect_fingerprints(root, root, &mut files);
        files
    }

    fn collect_fingerprints(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<PathBuf, FileFingerprint>,
    ) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_fingerprints(root, &path, files);
            } else {
                let metadata = fs::metadata(&path).unwrap();
                let mut file = File::open(&path).unwrap();
                let mut hasher = blake3::Hasher::new();
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let bytes_read = file.read(&mut buffer).unwrap();
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    FileFingerprint {
                        logical_bytes: metadata.len(),
                        digest: *hasher.finalize().as_bytes(),
                    },
                );
            }
        }
    }

    fn logical_bytes(root: &Path) -> u64 {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .map(|path| {
                if path.is_dir() {
                    logical_bytes(&path)
                } else {
                    fs::metadata(path).unwrap().len()
                }
            })
            .sum()
    }
}
