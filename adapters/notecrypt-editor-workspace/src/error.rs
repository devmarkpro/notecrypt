use std::io;

use notecrypt_service::HostPortError;

pub(crate) fn map_io(error: &io::Error) -> HostPortError {
    match error.kind() {
        io::ErrorKind::AlreadyExists => HostPortError::DestinationExists,
        io::ErrorKind::WouldBlock => HostPortError::LiveWorkspace,
        io::ErrorKind::PermissionDenied => HostPortError::Permission,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => HostPortError::InvalidInput,
        io::ErrorKind::NotFound => HostPortError::StaleCapability,
        io::ErrorKind::OutOfMemory => HostPortError::AllocationFailed,
        _ => HostPortError::PlatformFailure,
    }
}
