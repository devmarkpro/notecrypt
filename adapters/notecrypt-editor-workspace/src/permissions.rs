use notecrypt_platform_fs::Directory;

use notecrypt_service::HostPortError;

use crate::error::map_io;

pub(crate) fn verify_private(directory: &Directory) -> Result<(), HostPortError> {
    directory.verify_private().map_err(|error| map_io(&error))
}
