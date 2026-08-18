use std::io::{Read, Write};

use notecrypt_platform_fs::{Directory, FileCapability, PhysicalComponent};
use zeroize::Zeroizing;

use crate::StoreError;
use crate::layout::{component, encode_hex};

const LOCAL_RECORD_LIMIT: usize = 64 * 1024;
const TEMP_RETRIES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableMutationOutcome {
    Applied,
    NotApplied,
    AppliedNeedsDirectorySync,
}

pub(crate) fn read_optional(
    directory: &Directory,
    name: &PhysicalComponent,
) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(open_and_read_optional(directory, name)?.map(|(_file, bytes)| bytes))
}

fn open_and_read_optional(
    directory: &Directory,
    name: &PhysicalComponent,
) -> Result<Option<(FileCapability, Vec<u8>)>, StoreError> {
    let mut file = match directory.open_file_nofollow(name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::from(error)),
    };
    let length = usize::try_from(file.len()?).map_err(|_| StoreError::LimitExceeded)?;
    if length > LOCAL_RECORD_LIMIT {
        return Err(StoreError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| StoreError::LimitExceeded)?;
    (&mut file)
        .take((LOCAL_RECORD_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != length || bytes.len() > LOCAL_RECORD_LIMIT {
        return Err(StoreError::LimitExceeded);
    }
    Ok(Some((file, bytes)))
}

pub(crate) fn replace_durable(
    directory: &Directory,
    destination: &PhysicalComponent,
    bytes: &[u8],
) -> Result<(), StoreError> {
    if bytes.len() > LOCAL_RECORD_LIMIT {
        return Err(StoreError::LimitExceeded);
    }
    let (temporary, mut file) = create_temporary(directory)?;
    let operation = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        directory.sync()?;
        directory.replace_opened_atomic_from_private_staging(
            &file,
            &temporary,
            directory,
            destination,
        )?;
        directory.sync()?;
        let published = read_optional(directory, destination)?.ok_or(StoreError::NotFound)?;
        if published != bytes {
            return Err(StoreError::AuthenticationFailed);
        }
        Ok(())
    })();
    if let Err(primary) = operation {
        match directory.remove_file(&temporary) {
            Ok(()) => return Err(primary),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(primary),
            Err(cleanup) => {
                return Err(StoreError::CleanupAfterFailure {
                    primary: Box::new(primary),
                    cleanup,
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn replace_durable_if_exact(
    directory: &Directory,
    destination: &PhysicalComponent,
    expected: &[u8],
    replacement: &[u8],
) -> Result<DurableMutationOutcome, StoreError> {
    replace_durable_if_exact_with_sync(
        directory,
        destination,
        expected,
        replacement,
        &mut |directory| directory.sync(),
    )
}

fn replace_durable_if_exact_with_sync(
    directory: &Directory,
    destination: &PhysicalComponent,
    expected: &[u8],
    replacement: &[u8],
    sync_directory: &mut dyn FnMut(&Directory) -> std::io::Result<()>,
) -> Result<DurableMutationOutcome, StoreError> {
    if replacement.len() > LOCAL_RECORD_LIMIT {
        return Err(StoreError::LimitExceeded);
    }
    let Some((current_file, current)) = open_and_read_optional(directory, destination)? else {
        return Ok(DurableMutationOutcome::NotApplied);
    };
    let current = Zeroizing::new(current);
    if current.as_slice() != expected {
        return Ok(DurableMutationOutcome::NotApplied);
    }

    let (temporary, mut staged_file) = create_temporary(directory)?;
    let operation = (|| {
        staged_file.write_all(replacement)?;
        staged_file.sync_all()?;
        sync_directory(directory)?;
        directory.replace_opened_atomic_if_destination_matches(
            &staged_file,
            &temporary,
            directory,
            destination,
            &current_file,
        )?;
        if sync_directory(directory).is_err() {
            return Ok(DurableMutationOutcome::AppliedNeedsDirectorySync);
        }
        let published = read_optional(directory, destination)?.ok_or(StoreError::NotFound)?;
        if published != replacement {
            return Err(StoreError::AuthenticationFailed);
        }
        Ok(DurableMutationOutcome::Applied)
    })();
    cleanup_temporary_after_operation(directory, &temporary, operation)
}

pub(crate) fn remove_durable_if_exact(
    directory: &Directory,
    destination: &PhysicalComponent,
    expected: &[u8],
) -> Result<DurableMutationOutcome, StoreError> {
    remove_durable_if_exact_with_sync(directory, destination, expected, &mut |directory| {
        directory.sync()
    })
}

fn remove_durable_if_exact_with_sync(
    directory: &Directory,
    destination: &PhysicalComponent,
    expected: &[u8],
    sync_directory: &mut dyn FnMut(&Directory) -> std::io::Result<()>,
) -> Result<DurableMutationOutcome, StoreError> {
    let Some((current_file, current)) = open_and_read_optional(directory, destination)? else {
        return Ok(DurableMutationOutcome::NotApplied);
    };
    let current = Zeroizing::new(current);
    if current.as_slice() != expected {
        return Ok(DurableMutationOutcome::NotApplied);
    }
    directory.remove_opened_file_if_matches_unsynced(&current_file, destination)?;
    if sync_directory(directory).is_err() {
        return Ok(DurableMutationOutcome::AppliedNeedsDirectorySync);
    }
    Ok(DurableMutationOutcome::Applied)
}

fn cleanup_temporary_after_operation<T>(
    directory: &Directory,
    temporary: &PhysicalComponent,
    operation: Result<T, StoreError>,
) -> Result<T, StoreError> {
    let Err(primary) = operation else {
        return operation;
    };
    match directory.remove_file(temporary) {
        Ok(()) => Err(primary),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(primary),
        Err(cleanup) => Err(StoreError::CleanupAfterFailure {
            primary: Box::new(primary),
            cleanup,
        }),
    }
}

fn create_temporary(
    directory: &Directory,
) -> Result<(PhysicalComponent, notecrypt_platform_fs::FileCapability), StoreError> {
    for _ in 0..TEMP_RETRIES {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::RandomSource)?;
        let name = component(&encode_hex(&random))?;
        match directory.create_file_new(&name) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::from(error)),
        }
    }
    Err(StoreError::IdentityCollision)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use notecrypt_platform_fs::Directory;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn applied_replace_and_remove_are_not_durable_until_directory_sync_retries() {
        let temporary = TempDir::new().unwrap();
        let root = Directory::open_ambient(&temporary.path().canonicalize().unwrap()).unwrap();
        let records = root
            .create_private_dir(&component("records").unwrap())
            .unwrap();
        let name = component("record").unwrap();
        let mut original = records.create_file_new(&name).unwrap();
        original.write_all(b"old").unwrap();
        original.sync_all().unwrap();
        records.sync().unwrap();

        let mut sync_calls = 0_usize;
        let replaced =
            replace_durable_if_exact_with_sync(&records, &name, b"old", b"new", &mut |directory| {
                sync_calls += 1;
                if sync_calls == 2 {
                    return Err(io::Error::other("injected post-replace sync failure"));
                }
                directory.sync()
            })
            .unwrap();
        assert!(matches!(
            replaced,
            DurableMutationOutcome::AppliedNeedsDirectorySync
        ));
        assert_eq!(read_optional(&records, &name).unwrap().unwrap(), b"new");
        records.sync().unwrap();

        let removed =
            remove_durable_if_exact_with_sync(&records, &name, b"new", &mut |_directory| {
                Err(io::Error::other("injected post-unlink sync failure"))
            })
            .unwrap();
        assert!(matches!(
            removed,
            DurableMutationOutcome::AppliedNeedsDirectorySync
        ));
        assert!(read_optional(&records, &name).unwrap().is_none());
        records.sync().unwrap();
    }
}
