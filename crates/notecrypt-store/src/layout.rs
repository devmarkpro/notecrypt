use notecrypt_core::VaultId;
use notecrypt_platform_fs::{Directory, PhysicalComponent};

use crate::StoreError;

pub(crate) struct StoreLayout {
    pub(crate) vault: VaultId,
    pub(crate) repository: Directory,
    pub(crate) objects: Directory,
    pub(crate) transactions: Directory,
    pub(crate) journal: Directory,
    pub(crate) trusted: Directory,
    pub(crate) trusted_remote: Directory,
    pub(crate) cleanup_registry: Directory,
    pub(crate) cleanup_staging: Directory,
    pub(crate) device_slots: Directory,
    pub(crate) quarantine: Directory,
}

impl StoreLayout {
    pub(crate) fn create(
        repository: Directory,
        local_state: Directory,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        let objects = child(&repository, "objects", false)?;
        let transactions = child(&repository, ".notecrypt-txn", true)?;
        let vault_component = encode_hex(vault.as_bytes());
        let vault_local = child(&local_state, &vault_component, true)?;
        require_capabilities(&transactions)?;
        let journal = child(&vault_local, "journal", true)?;
        let trusted = child(&vault_local, "trusted", true)?;
        let trusted_remote = child(&vault_local, "trusted-remote", true)?;
        let cleanup_registry = child(&vault_local, "cleanup-registry", true)?;
        let cleanup_staging = child(&vault_local, "cleanup-staging", true)?;
        let device_slots = child(&vault_local, "device-slots", true)?;
        let quarantine = child(&vault_local, "replication-quarantine", true)?;
        require_capabilities(&journal)?;
        Ok(Self {
            vault,
            repository,
            objects,
            transactions,
            journal,
            trusted,
            trusted_remote,
            cleanup_registry,
            cleanup_staging,
            device_slots,
            quarantine,
        })
    }

    pub(crate) fn open_existing(
        repository: Directory,
        local_state: Directory,
        vault: VaultId,
    ) -> Result<Self, StoreError> {
        let objects = existing_child(&repository, "objects", false)?;
        let transactions = existing_child(&repository, ".notecrypt-txn", true)?;
        let vault_component = encode_hex(vault.as_bytes());
        let vault_local = existing_child(&local_state, &vault_component, true)?;
        require_capabilities(&transactions)?;
        let journal = existing_child(&vault_local, "journal", true)?;
        let trusted = existing_child(&vault_local, "trusted", true)?;
        let trusted_remote = existing_child(&vault_local, "trusted-remote", true)?;
        let cleanup_registry = existing_child(&vault_local, "cleanup-registry", true)?;
        let cleanup_staging = existing_child(&vault_local, "cleanup-staging", true)?;
        let device_slots = existing_child(&vault_local, "device-slots", true)?;
        let quarantine = existing_child(&vault_local, "replication-quarantine", true)?;
        require_capabilities(&journal)?;
        Ok(Self {
            vault,
            repository,
            objects,
            transactions,
            journal,
            trusted,
            trusted_remote,
            cleanup_registry,
            cleanup_staging,
            device_slots,
            quarantine,
        })
    }
}

pub(crate) fn component(value: &str) -> Result<PhysicalComponent, StoreError> {
    PhysicalComponent::try_new(value).map_err(StoreError::from)
}

fn child(parent: &Directory, name: &str, private: bool) -> Result<Directory, StoreError> {
    let name = component(name)?;
    let result = if private {
        parent.open_or_create_private_dir(&name)
    } else {
        parent.open_or_create_dir(&name)
    };
    result.map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::NotADirectory | std::io::ErrorKind::InvalidData
        ) {
            StoreError::FilesystemObjectRejected
        } else {
            StoreError::from(error)
        }
    })
}

fn existing_child(parent: &Directory, name: &str, private: bool) -> Result<Directory, StoreError> {
    let result = parent.open_dir_nofollow(&component(name)?);
    let directory = result.map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::NotADirectory
                | std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::NotFound
        ) {
            StoreError::FilesystemObjectRejected
        } else {
            StoreError::from(error)
        }
    })?;
    if private {
        directory.verify_private()?;
    }
    Ok(directory)
}

fn require_capabilities(directory: &Directory) -> Result<(), StoreError> {
    let capabilities = directory.probe_capabilities()?;
    if capabilities.directory_sync
        && capabilities.atomic_replace
        && capabilities.no_replace_publication
    {
        Ok(())
    } else {
        Err(StoreError::UnsupportedDurability)
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
