use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notecrypt_core::{LogicalPath, VaultId};
use notecrypt_crypto::{DeviceWrappingKey, RecoveryPassphrase};
use notecrypt_store::CleanupWorkspaceId;
use zeroize::{Zeroize, Zeroizing};

/// Maximum opaque stable-source evidence retained by the service.
pub const MAX_STABLE_SOURCE_TOKEN_BYTES: usize = 256;
/// Maximum native credential-store reference retained by the service.
pub const MAX_DEVICE_KEY_REFERENCE_BYTES: usize = 2 * 1024;
/// Maximum logical paths tracked for collision detection in one workspace.
pub const MAX_WORKSPACE_PATHS: usize = 1_000_000;
/// Maximum aggregate collision-key and normalized identity bytes per workspace.
pub const MAX_WORKSPACE_COLLISION_KEY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum raw UTF-8 bytes accepted for one logical path component.
pub const MAX_LOGICAL_COMPONENT_BYTES: usize = 1_024;
/// Maximum component depth accepted for one logical workspace path.
pub const MAX_LOGICAL_PATH_DEPTH: usize = 16;
/// Maximum raw UTF-8 bytes accepted for one logical workspace path.
pub const MAX_LOGICAL_PATH_BYTES: usize =
    MAX_LOGICAL_PATH_DEPTH * MAX_LOGICAL_COMPONENT_BYTES + MAX_LOGICAL_PATH_DEPTH - 1;
/// Small eager reservation used before per-entry fallible growth.
const INITIAL_WORKSPACE_PATH_CAPACITY: usize = 128;
/// Maximum editor arguments accepted in one launch request.
pub const MAX_EDITOR_ARGUMENTS: usize = 64;
/// Maximum encoded bytes accepted in one editor argument.
pub const MAX_EDITOR_ARGUMENT_BYTES: usize = 4 * 1024;
/// Maximum aggregate encoded bytes accepted in one editor command line.
pub const MAX_EDITOR_COMMAND_BYTES: usize = 32 * 1024;
/// Maximum direct workspaces accounted by one startup cleanup pass.
pub const MAX_STARTUP_WORKSPACES: usize = 1_000_000;
/// Maximum recovery credential bytes accepted at the service boundary.
pub const MAX_RECOVERY_SECRET_BYTES: usize = 1_024;
/// Maximum native path bytes retained by any service-owned host DTO.
pub const MAX_NATIVE_PATH_BYTES: usize = 32 * 1_024;

/// Stable bounded host-boundary failures without raw platform details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostPortError {
    Unavailable,
    Denied,
    InvalidInput,
    CapacityExceeded,
    AllocationFailed,
    DetachedEditor,
    Permission,
    LiveWorkspace,
    CleanupFailed,
    PlatformFailure,
}

#[cfg(test)]
thread_local! {
    static ALLOCATION_FAILURE_COUNTDOWN: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn inject_allocation_failure_after_for_test(successful_reservations: usize) {
    ALLOCATION_FAILURE_COUNTDOWN.set(Some(successful_reservations));
}

#[cfg(test)]
pub(crate) fn allocation_failure_injected_for_test() -> bool {
    ALLOCATION_FAILURE_COUNTDOWN.with(|countdown| match countdown.get() {
        Some(0) => {
            countdown.set(None);
            true
        }
        Some(remaining) => {
            countdown.set(Some(remaining - 1));
            false
        }
        None => false,
    })
}

#[cfg(not(test))]
pub(crate) const fn allocation_failure_injected_for_test() -> bool {
    false
}

fn try_rehome_bytes_inner(
    source: &mut Vec<u8>,
    maximum_bytes: usize,
    fail_reservation_for_test: bool,
) -> Result<Vec<u8>, HostPortError> {
    if source.is_empty() || source.len() > maximum_bytes {
        source.zeroize();
        return Err(HostPortError::InvalidInput);
    }
    let mut retained = Vec::new();
    if fail_reservation_for_test || allocation_failure_injected_for_test() {
        source.zeroize();
        return Err(HostPortError::AllocationFailed);
    }
    if retained.try_reserve_exact(source.len()).is_err() {
        source.zeroize();
        return Err(HostPortError::AllocationFailed);
    }
    retained.extend_from_slice(source);
    source.zeroize();
    Ok(retained)
}

pub(crate) fn try_rehome_bytes(
    source: &mut Vec<u8>,
    maximum_bytes: usize,
) -> Result<Vec<u8>, HostPortError> {
    try_rehome_bytes_inner(source, maximum_bytes, false)
}

pub(crate) fn try_rehome_string(
    mut source: String,
    maximum_bytes: usize,
) -> Result<String, HostPortError> {
    if source.is_empty() || source.len() > maximum_bytes || source.as_bytes().contains(&0) {
        source.zeroize();
        return Err(HostPortError::InvalidInput);
    }
    let mut retained = String::new();
    if allocation_failure_injected_for_test() {
        source.zeroize();
        return Err(HostPortError::AllocationFailed);
    }
    if retained.try_reserve_exact(source.len()).is_err() {
        source.zeroize();
        return Err(HostPortError::AllocationFailed);
    }
    retained.push_str(&source);
    source.zeroize();
    Ok(retained)
}

pub(crate) fn try_copy_str(value: &str, maximum_bytes: usize) -> Result<String, HostPortError> {
    if value.is_empty() || value.len() > maximum_bytes || value.as_bytes().contains(&0) {
        return Err(HostPortError::InvalidInput);
    }
    let mut retained = String::new();
    if allocation_failure_injected_for_test() {
        return Err(HostPortError::AllocationFailed);
    }
    retained
        .try_reserve_exact(value.len())
        .map_err(|_| HostPortError::AllocationFailed)?;
    retained.push_str(value);
    Ok(retained)
}

pub(crate) fn try_rehome_os_string(
    mut source: OsString,
    maximum_bytes: usize,
) -> Result<OsString, HostPortError> {
    let length = encoded_len(&source);
    if length > maximum_bytes {
        return Err(HostPortError::CapacityExceeded);
    }
    let mut retained = OsString::new();
    if allocation_failure_injected_for_test() {
        source.clear();
        return Err(HostPortError::AllocationFailed);
    }
    retained
        .try_reserve_exact(length)
        .map_err(|_| HostPortError::AllocationFailed)?;
    retained.push(&source);
    source.clear();
    Ok(retained)
}

pub(crate) fn try_rehome_path(
    source: PathBuf,
    maximum_bytes: usize,
) -> Result<PathBuf, HostPortError> {
    try_rehome_os_string(source.into_os_string(), maximum_bytes).map(PathBuf::from)
}

/// Store-issued opaque identity for one Notecrypt-owned workspace.
pub struct WorkspaceId {
    child_name: String,
}

impl WorkspaceId {
    pub(crate) fn from_store(value: &CleanupWorkspaceId) -> Result<Self, HostPortError> {
        let child_name = value.child_name();
        if child_name.len() != 32
            || !child_name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(HostPortError::InvalidInput);
        }
        let child_name = try_rehome_string(child_name, 32)?;
        Ok(Self { child_name })
    }

    /// Returns the exact direct child name reserved by the store.
    pub fn child_name(&self) -> &str {
        &self.child_name
    }

    pub(crate) fn try_duplicate(&self) -> Result<Self, HostPortError> {
        let child_name = try_copy_str(&self.child_name, 32)?;
        Ok(Self { child_name })
    }
}

/// Plaintext materialization scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceMode {
    Targeted,
    WholeVault,
}

/// Lifetime ownership evidence retained until verified physical removal.
pub trait WorkspaceOwnershipGuard: Send {}

/// Held physical-absence evidence transferred into the store authority bridge.
pub trait WorkspaceAbsenceGuard: Send {}

/// One owned plaintext workspace below the provider's fixed base.
pub struct WorkspaceLease {
    id: WorkspaceId,
    root: PathBuf,
    mode: WorkspaceMode,
    _ownership: Mutex<Box<dyn WorkspaceOwnershipGuard>>,
}

impl WorkspaceLease {
    /// Constructs a provider result while retaining its lifetime ownership guard.
    pub(crate) fn new(
        id: WorkspaceId,
        root: PathBuf,
        mode: WorkspaceMode,
        ownership: Box<dyn WorkspaceOwnershipGuard>,
    ) -> Result<Self, HostPortError> {
        if !valid_absolute_path(&root) || root.file_name() != Some(OsStr::new(id.child_name())) {
            return Err(HostPortError::InvalidInput);
        }
        let root = try_rehome_path(root, MAX_NATIVE_PATH_BYTES)?;
        Ok(Self {
            id,
            root,
            mode,
            _ownership: Mutex::new(ownership),
        })
    }

    /// Constructs a targeted lease by consuming the exact provider request.
    pub fn from_target_request(
        request: TargetWorkspaceRequest,
        root: PathBuf,
        ownership: Box<dyn WorkspaceOwnershipGuard>,
    ) -> Result<Self, HostPortError> {
        Self::new(request.id, root, WorkspaceMode::Targeted, ownership)
    }

    /// Constructs a whole-vault lease by consuming the exact provider request.
    pub fn from_vault_request(
        request: VaultWorkspaceRequest,
        root: PathBuf,
        ownership: Box<dyn WorkspaceOwnershipGuard>,
    ) -> Result<Self, HostPortError> {
        Self::new(request.id, root, WorkspaceMode::WholeVault, ownership)
    }

    pub fn id(&self) -> &WorkspaceId {
        &self.id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn mode(&self) -> WorkspaceMode {
        self.mode
    }
}

/// Bounded result of one fixed-base startup cleanup pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupCleanupReport {
    removed: usize,
    skipped_live: usize,
}

impl StartupCleanupReport {
    pub fn try_new(removed: usize, skipped_live: usize) -> Result<Self, HostPortError> {
        if removed > MAX_STARTUP_WORKSPACES
            || skipped_live > MAX_STARTUP_WORKSPACES
            || removed
                .checked_add(skipped_live)
                .is_none_or(|total| total > MAX_STARTUP_WORKSPACES)
        {
            return Err(HostPortError::CapacityExceeded);
        }
        Ok(Self {
            removed,
            skipped_live,
        })
    }

    pub const fn removed(&self) -> usize {
        self.removed
    }

    pub const fn skipped_live(&self) -> usize {
        self.skipped_live
    }
}

/// Request for one targeted workspace using a store-reserved identity.
pub struct TargetWorkspaceRequest {
    id: WorkspaceId,
    vault_id: VaultId,
    repository_root: PathBuf,
}

impl TargetWorkspaceRequest {
    pub(crate) fn new(
        id: WorkspaceId,
        vault_id: VaultId,
        repository_root: PathBuf,
    ) -> Result<Self, HostPortError> {
        if !valid_absolute_path(&repository_root) {
            return Err(HostPortError::InvalidInput);
        }
        let repository_root = try_rehome_path(repository_root, MAX_NATIVE_PATH_BYTES)?;
        Ok(Self {
            id,
            vault_id,
            repository_root,
        })
    }

    pub fn id(&self) -> &WorkspaceId {
        &self.id
    }

    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }
}

/// Request for one whole-vault workspace using a store-reserved identity.
pub struct VaultWorkspaceRequest {
    id: WorkspaceId,
    vault_id: VaultId,
    repository_root: PathBuf,
}

impl VaultWorkspaceRequest {
    pub(crate) fn new(
        id: WorkspaceId,
        vault_id: VaultId,
        repository_root: PathBuf,
    ) -> Result<Self, HostPortError> {
        if !valid_absolute_path(&repository_root) {
            return Err(HostPortError::InvalidInput);
        }
        let repository_root = try_rehome_path(repository_root, MAX_NATIVE_PATH_BYTES)?;
        Ok(Self {
            id,
            vault_id,
            repository_root,
        })
    }

    pub fn id(&self) -> &WorkspaceId {
        &self.id
    }

    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }
}

/// A normalized portable logical path that is safe to pass to an adapter.
pub struct LogicalWorkspacePath {
    logical: LogicalPath,
    path: PathBuf,
}

impl LogicalWorkspacePath {
    pub fn new(path: PathBuf) -> Result<Self, HostPortError> {
        let value = path.to_str().ok_or(HostPortError::InvalidInput)?;
        if value.len() > MAX_LOGICAL_PATH_BYTES {
            return Err(HostPortError::CapacityExceeded);
        }
        let mut depth = 0_usize;
        for component in value.split('/') {
            depth = depth
                .checked_add(1)
                .ok_or(HostPortError::CapacityExceeded)?;
            if depth > MAX_LOGICAL_PATH_DEPTH || component.len() > MAX_LOGICAL_COMPONENT_BYTES {
                return Err(HostPortError::CapacityExceeded);
            }
        }
        let logical = LogicalPath::try_parse_bounded(
            value,
            MAX_LOGICAL_PATH_DEPTH,
            MAX_LOGICAL_COMPONENT_BYTES,
        )
        .map_err(|error| match error {
            notecrypt_core::CoreError::AllocationFailed => HostPortError::AllocationFailed,
            notecrypt_core::CoreError::CapacityExceeded => HostPortError::CapacityExceeded,
            _ => HostPortError::InvalidInput,
        })?;
        let _normalized =
            logical
                .try_render(MAX_LOGICAL_PATH_BYTES)
                .map_err(|error| match error {
                    notecrypt_core::CoreError::AllocationFailed => HostPortError::AllocationFailed,
                    _ => HostPortError::CapacityExceeded,
                })?;
        let path = try_rehome_path(path, MAX_LOGICAL_PATH_BYTES)?;
        Ok(Self { logical, path })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn collision_key(&self) -> Result<String, HostPortError> {
        self.logical
            .try_collision_key(MAX_LOGICAL_PATH_BYTES)
            .map_err(|error| match error {
                notecrypt_core::CoreError::AllocationFailed => HostPortError::AllocationFailed,
                _ => HostPortError::CapacityExceeded,
            })
    }
}

/// Bounded collision registry checked before logical paths enter an adapter.
pub struct WorkspacePathRegistry {
    maximum: usize,
    collision_key_bytes: usize,
    collision_keys: HashMap<String, String>,
}

impl WorkspacePathRegistry {
    pub fn new(maximum: usize) -> Result<Self, HostPortError> {
        if maximum == 0 || maximum > MAX_WORKSPACE_PATHS {
            return Err(HostPortError::InvalidInput);
        }
        let mut collision_keys = HashMap::new();
        collision_keys
            .try_reserve(maximum.min(INITIAL_WORKSPACE_PATH_CAPACITY))
            .map_err(|_| HostPortError::AllocationFailed)?;
        Ok(Self {
            maximum,
            collision_key_bytes: 0,
            collision_keys,
        })
    }

    pub fn insert(&mut self, path: &LogicalWorkspacePath) -> Result<(), HostPortError> {
        let key = path.collision_key()?;
        let rendered = path.as_path().to_str().ok_or(HostPortError::InvalidInput)?;
        if let Some(existing) = self.collision_keys.get(&key) {
            return if existing == rendered {
                Ok(())
            } else {
                Err(HostPortError::InvalidInput)
            };
        }
        if self.collision_keys.len() == self.maximum {
            return Err(HostPortError::CapacityExceeded);
        }
        if key.len() > MAX_LOGICAL_PATH_BYTES {
            return Err(HostPortError::CapacityExceeded);
        }
        let next_bytes = self
            .collision_key_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(rendered.len()))
            .ok_or(HostPortError::CapacityExceeded)?;
        if next_bytes > MAX_WORKSPACE_COLLISION_KEY_BYTES {
            return Err(HostPortError::CapacityExceeded);
        }
        self.collision_keys
            .try_reserve(1)
            .map_err(|_| HostPortError::AllocationFailed)?;
        let mut retained = String::new();
        retained
            .try_reserve_exact(rendered.len())
            .map_err(|_| HostPortError::AllocationFailed)?;
        retained.push_str(rendered);
        self.collision_keys.insert(key, retained);
        self.collision_key_bytes = next_bytes;
        Ok(())
    }
}

/// One bounded watcher event whose path has already passed portable validation.
pub struct WorkspaceEvent {
    generation: u64,
    change: WorkspaceChange,
}

impl WorkspaceEvent {
    pub fn new(generation: u64, change: WorkspaceChange) -> Result<Self, HostPortError> {
        if generation == 0 {
            return Err(HostPortError::InvalidInput);
        }
        Ok(Self { generation, change })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn change(&self) -> &WorkspaceChange {
        &self.change
    }
}

/// One validated logical workspace change.
pub enum WorkspaceChange {
    Created {
        path: LogicalWorkspacePath,
    },
    Modified {
        path: LogicalWorkspacePath,
    },
    Renamed {
        source: LogicalWorkspacePath,
        destination: LogicalWorkspacePath,
    },
    Deleted {
        path: LogicalWorkspacePath,
    },
}

/// Opaque generation-suppression identity created by the workspace adapter.
pub struct SuppressionToken([u8; 16]);

impl SuppressionToken {
    pub const fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Opaque stable-handle identity and generation evidence.
pub struct StableSourceToken(Vec<u8>);

impl StableSourceToken {
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, HostPortError> {
        try_rehome_bytes(&mut bytes, MAX_STABLE_SOURCE_TOKEN_BYTES).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for StableSourceToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Adapter-selected private staging and final materialization paths.
pub struct MaterializationTarget {
    staging_path: PathBuf,
    destination: PathBuf,
    suppression: SuppressionToken,
}

impl MaterializationTarget {
    pub fn new(
        lease: &WorkspaceLease,
        staging_path: PathBuf,
        destination: PathBuf,
        suppression: SuppressionToken,
    ) -> Result<Self, HostPortError> {
        if !valid_workspace_child(lease, &staging_path)
            || !valid_workspace_child(lease, &destination)
            || staging_path == destination
        {
            return Err(HostPortError::InvalidInput);
        }
        let staging_path = try_rehome_path(staging_path, MAX_NATIVE_PATH_BYTES)?;
        let destination = try_rehome_path(destination, MAX_NATIVE_PATH_BYTES)?;
        Ok(Self {
            staging_path,
            destination,
            suppression,
        })
    }

    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    pub const fn suppression(&self) -> &SuppressionToken {
        &self.suppression
    }
}

/// One atomically published workspace generation awaiting watcher arming.
pub struct PublishedGeneration {
    path: PathBuf,
    generation: u64,
    suppression: SuppressionToken,
}

impl PublishedGeneration {
    pub fn from_materialization(
        lease: &WorkspaceLease,
        target: MaterializationTarget,
        generation: u64,
    ) -> Result<Self, HostPortError> {
        if !valid_workspace_child(lease, &target.destination) || generation == 0 {
            return Err(HostPortError::InvalidInput);
        }
        Ok(Self {
            path: target.destination,
            generation,
            suppression: target.suppression,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn suppression(&self) -> &SuppressionToken {
        &self.suppression
    }
}

/// Bounded editor process request.
pub struct EditorLaunchRequest {
    executable: OsString,
    arguments: Vec<OsString>,
    workspace_file: PathBuf,
}

impl EditorLaunchRequest {
    pub fn try_new(
        lease: &WorkspaceLease,
        executable: OsString,
        arguments: Vec<OsString>,
        workspace_file: PathBuf,
    ) -> Result<Self, HostPortError> {
        if executable.is_empty()
            || encoded_len(&executable) > MAX_EDITOR_ARGUMENT_BYTES
            || executable.as_encoded_bytes().contains(&0)
            || arguments.len() > MAX_EDITOR_ARGUMENTS
            || !valid_editor_workspace(lease, &workspace_file)
        {
            return Err(HostPortError::InvalidInput);
        }
        let mut aggregate = encoded_len(&executable)
            .checked_add(encoded_len(workspace_file.as_os_str()))
            .and_then(|value| value.checked_add(1))
            .ok_or(HostPortError::CapacityExceeded)?;
        if aggregate > MAX_EDITOR_COMMAND_BYTES {
            return Err(HostPortError::CapacityExceeded);
        }
        for argument in &arguments {
            let length = encoded_len(argument);
            if length > MAX_EDITOR_ARGUMENT_BYTES || argument.as_encoded_bytes().contains(&0) {
                return Err(HostPortError::CapacityExceeded);
            }
            aggregate = aggregate
                .checked_add(length)
                .and_then(|value| value.checked_add(1))
                .ok_or(HostPortError::CapacityExceeded)?;
            if aggregate > MAX_EDITOR_COMMAND_BYTES {
                return Err(HostPortError::CapacityExceeded);
            }
        }
        let executable = try_rehome_os_string(executable, MAX_EDITOR_ARGUMENT_BYTES)?;
        let mut retained_arguments = Vec::new();
        retained_arguments
            .try_reserve_exact(arguments.len())
            .map_err(|_| HostPortError::AllocationFailed)?;
        for argument in arguments {
            retained_arguments.push(try_rehome_os_string(argument, MAX_EDITOR_ARGUMENT_BYTES)?);
        }
        let workspace_file = try_rehome_path(workspace_file, MAX_NATIVE_PATH_BYTES)?;
        Ok(Self {
            executable,
            arguments: retained_arguments,
            workspace_file,
        })
    }

    pub fn executable(&self) -> &OsStr {
        &self.executable
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub fn workspace_file(&self) -> &Path {
        &self.workspace_file
    }
}

fn encoded_len(value: &OsStr) -> usize {
    value.as_encoded_bytes().len()
}

pub(crate) fn valid_absolute_path(path: &Path) -> bool {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || encoded_len(path.as_os_str()) > MAX_NATIVE_PATH_BYTES
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return false;
    }
    let mut root_seen = false;
    for (index, component) in path.components().enumerate() {
        match component {
            Component::Prefix(_) if index == 0 => {}
            Component::RootDir if !root_seen && index <= 1 => root_seen = true,
            Component::Normal(value) if !value.is_empty() => {}
            _ => return false,
        }
    }
    root_seen
}

fn valid_workspace_child(lease: &WorkspaceLease, path: &Path) -> bool {
    valid_absolute_path(path) && path != lease.root() && path.starts_with(lease.root())
}

fn valid_editor_workspace(lease: &WorkspaceLease, path: &Path) -> bool {
    valid_absolute_path(path)
        && path.starts_with(lease.root())
        && (path != lease.root() || lease.mode() == WorkspaceMode::WholeVault)
}

/// Bounded editor terminal status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditorExit {
    code: Option<i32>,
}

impl EditorExit {
    pub const fn new(code: Option<i32>) -> Self {
        Self { code }
    }

    pub const fn code(&self) -> Option<i32> {
        self.code
    }
}

/// Opaque bounded native device-key reference.
pub struct DeviceKeyReference(Vec<u8>);

impl DeviceKeyReference {
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, HostPortError> {
        try_rehome_bytes(&mut bytes, MAX_DEVICE_KEY_REFERENCE_BYTES).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for DeviceKeyReference {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Protected native device wrapping key with only a consuming internal bridge.
pub struct DeviceUnlockSecret(DeviceWrappingKey);

impl DeviceUnlockSecret {
    pub fn try_from_protected_bytes(bytes: Vec<u8>) -> Result<Self, HostPortError> {
        DeviceWrappingKey::try_from_protected_bytes(bytes)
            .map(Self)
            .map_err(|_| HostPortError::InvalidInput)
    }

    #[expect(
        dead_code,
        reason = "Checkpoint A defines the provider boundary before device unlock composition"
    )]
    pub(crate) fn into_store_key(self) -> DeviceWrappingKey {
        self.0
    }
}

/// Recovery credential owner with a no-copy consuming crypto bridge.
pub struct RecoverySecretInput {
    value: Zeroizing<Vec<u8>>,
}

fn recovery_verifier(key: &[u8; 32], value: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(key));
    hasher.update(value);
    let digest = Zeroizing::new(hasher.finalize());
    Zeroizing::new(*digest.as_bytes())
}

impl RecoverySecretInput {
    pub fn from_protected_bytes(mut bytes: Vec<u8>) -> Result<Self, HostPortError> {
        if bytes.is_empty() || bytes.len() > MAX_RECOVERY_SECRET_BYTES || bytes.contains(&0) {
            bytes.zeroize();
            return Err(HostPortError::InvalidInput);
        }
        let retained = try_rehome_bytes(&mut bytes, MAX_RECOVERY_SECRET_BYTES)?;
        if std::str::from_utf8(&retained).is_err() {
            let mut retained = retained;
            retained.zeroize();
            return Err(HostPortError::InvalidInput);
        }
        Ok(Self {
            value: Zeroizing::new(retained),
        })
    }

    pub(crate) fn from_zeroizing_bytes(
        mut bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, HostPortError> {
        if bytes.is_empty()
            || bytes.len() > MAX_RECOVERY_SECRET_BYTES
            || bytes.contains(&0)
            || std::str::from_utf8(bytes.as_slice()).is_err()
        {
            bytes.zeroize();
            return Err(HostPortError::InvalidInput);
        }
        Ok(Self { value: bytes })
    }

    pub(crate) fn into_crypto_passphrase(mut self) -> RecoveryPassphrase {
        let bytes = std::mem::take(self.value.as_mut());
        let value = String::from_utf8(bytes)
            .expect("RecoverySecretInput validates UTF-8 before construction");
        RecoveryPassphrase::new(value)
    }

    pub(crate) fn into_presentation_payload(
        mut self,
        key: &[u8; 32],
    ) -> (Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>) {
        let verifier = recovery_verifier(key, self.value.as_slice());
        let payload = Zeroizing::new(std::mem::take(self.value.as_mut()));
        (payload, verifier)
    }

    pub(crate) fn verify_and_retain(self, key: &[u8; 32], expected: &[u8; 32]) -> Result<Self, ()> {
        let actual = recovery_verifier(key, self.value.as_slice());
        let matches = constant_time_eq::constant_time_eq_32(&actual, expected);
        if matches { Ok(self) } else { Err(()) }
    }

    pub(crate) fn into_verifier(mut self, key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let verifier = recovery_verifier(key, self.value.as_slice());
        self.value.zeroize();
        verifier
    }
}

impl Drop for RecoverySecretInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// One-time recovery secret presentation owner.
pub struct RecoverySecretPresentation {
    payload: RecoveryPresentationCell,
}

pub(crate) type RecoveryPresentationCell = Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>;

impl RecoverySecretPresentation {
    pub(crate) fn from_shared(payload: RecoveryPresentationCell) -> Self {
        Self { payload }
    }

    pub fn present_once(
        self,
        presenter: &mut dyn RecoverySecretPresenter,
    ) -> Result<(), HostPortError> {
        let payload = self
            .payload
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or(HostPortError::InvalidInput)?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            presenter.present(payload.as_slice())
        }))
        .map_err(|_| HostPortError::PlatformFailure)?
    }
}

impl Drop for RecoverySecretPresentation {
    fn drop(&mut self) {
        let _ = self
            .payload
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
}

/// Narrow one-call presentation port for recovery material.
pub trait RecoverySecretPresenter: Send {
    fn present(&mut self, secret: &[u8]) -> Result<(), HostPortError>;
}

/// Native provider enrollment output.
pub struct EnrolledDeviceKey {
    reference: DeviceKeyReference,
    wrapping_key: DeviceUnlockSecret,
}

impl EnrolledDeviceKey {
    pub fn new(reference: DeviceKeyReference, wrapping_key: DeviceUnlockSecret) -> Self {
        Self {
            reference,
            wrapping_key,
        }
    }

    pub fn reference(&self) -> &DeviceKeyReference {
        &self.reference
    }

    #[expect(
        dead_code,
        reason = "Checkpoint A defines enrollment output before device-slot composition"
    )]
    pub(crate) fn into_parts(self) -> (DeviceKeyReference, DeviceUnlockSecret) {
        (self.reference, self.wrapping_key)
    }
}

pub trait WorkspaceWatch: Send {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<WorkspaceEvent>, HostPortError>;
}

pub struct OpenedStableSource {
    reader: Box<dyn Read + Send>,
    token: StableSourceToken,
}

impl OpenedStableSource {
    pub fn new(reader: Box<dyn Read + Send>, token: StableSourceToken) -> Self {
        Self { reader, token }
    }

    pub(crate) fn into_parts(self) -> (Box<dyn Read + Send>, StableSourceToken) {
        (self.reader, self.token)
    }
}

pub trait WorkspaceProvider: Send + Sync {
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError>;
    fn create_target(
        &self,
        request: TargetWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError>;
    fn create_whole_vault(
        &self,
        request: VaultWorkspaceRequest,
    ) -> Result<WorkspaceLease, HostPortError>;
    fn materialization_target(
        &self,
        lease: &WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
    ) -> Result<MaterializationTarget, HostPortError>;
    fn publish_materialized(
        &self,
        lease: &WorkspaceLease,
        target: MaterializationTarget,
    ) -> Result<PublishedGeneration, HostPortError>;
    fn arm_published_path(
        &self,
        lease: &WorkspaceLease,
        published: PublishedGeneration,
    ) -> Result<(), HostPortError>;
    fn watch(&self, lease: &WorkspaceLease) -> Result<Box<dyn WorkspaceWatch>, HostPortError>;
    fn open_stable_source(
        &self,
        lease: &WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
        expected_generation: u64,
    ) -> Result<OpenedStableSource, HostPortError>;
    fn validate_stable_source(
        &self,
        lease: &WorkspaceLease,
        token: &StableSourceToken,
    ) -> Result<(), HostPortError>;
    fn remove_workspace(
        &self,
        lease: WorkspaceLease,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, HostPortError>;
    fn acquire_verified_absence(
        &self,
        id: &WorkspaceId,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, HostPortError>;
}

/// Final store publication guard retaining the exact source token and workspace lease.
pub struct StableSourcePublicationGuard<'a> {
    provider: Arc<dyn WorkspaceProvider>,
    lease: &'a WorkspaceLease,
    token: StableSourceToken,
}

impl<'a> StableSourcePublicationGuard<'a> {
    pub(crate) fn new(
        provider: Arc<dyn WorkspaceProvider>,
        lease: &'a WorkspaceLease,
        token: StableSourceToken,
    ) -> Self {
        Self {
            provider,
            lease,
            token,
        }
    }
}

impl crate::VaultPublicationGuard for StableSourcePublicationGuard<'_> {
    fn validate(&mut self) -> Result<(), crate::RepositoryPortError> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.provider
                .validate_stable_source(self.lease, &self.token)
        }))
        .map_err(|_| crate::RepositoryPortError::PlatformFailure)?
        .map_err(crate::session::map_host_repository_error)
    }
}

pub trait EditorSupervisor: Send + Sync {
    fn launch(&self, request: EditorLaunchRequest)
    -> Result<Box<dyn EditorProcess>, HostPortError>;
}

pub trait EditorProcess: Send {
    fn try_wait(&mut self) -> Result<Option<EditorExit>, HostPortError>;
    fn request_stop(&mut self) -> Result<(), HostPortError>;
    fn force_stop(&mut self) -> Result<(), HostPortError>;
}

pub trait DeviceUnlockProvider: Send + Sync {
    fn enroll(&self, vault: VaultId) -> Result<EnrolledDeviceKey, HostPortError>;
    fn unlock(&self, reference: &DeviceKeyReference) -> Result<DeviceUnlockSecret, HostPortError>;
    fn remove(&self, reference: &DeviceKeyReference) -> Result<(), HostPortError>;
}

/// Checkpoint-A provider that always requires recovery unlock.
pub struct UnavailableDeviceUnlockProvider;

impl DeviceUnlockProvider for UnavailableDeviceUnlockProvider {
    fn enroll(&self, _vault: VaultId) -> Result<EnrolledDeviceKey, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn unlock(&self, _reference: &DeviceKeyReference) -> Result<DeviceUnlockSecret, HostPortError> {
        Err(HostPortError::Unavailable)
    }

    fn remove(&self, _reference: &DeviceKeyReference) -> Result<(), HostPortError> {
        Err(HostPortError::Unavailable)
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    struct Ownership;
    impl WorkspaceOwnershipGuard for Ownership {}

    fn workspace_id(byte: u8) -> WorkspaceId {
        WorkspaceId::from_store(&notecrypt_store::cleanup_test_support::workspace_id(
            [byte; 16],
        ))
        .unwrap()
    }

    fn oversized_bytes(value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1_000_000);
        bytes.extend_from_slice(value);
        assert!(bytes.capacity() > MAX_RECOVERY_SECRET_BYTES);
        bytes
    }

    #[test]
    fn accepted_byte_and_secret_values_discard_caller_spare_capacity() {
        let token = StableSourceToken::from_bytes(oversized_bytes(b"t")).unwrap();
        assert!(token.0.capacity() <= MAX_STABLE_SOURCE_TOKEN_BYTES);

        let reference = DeviceKeyReference::from_bytes(oversized_bytes(b"r")).unwrap();
        assert!(reference.0.capacity() <= MAX_DEVICE_KEY_REFERENCE_BYTES);

        let secret = RecoverySecretInput::from_protected_bytes(oversized_bytes(b"secret")).unwrap();
        assert!(secret.value.capacity() <= MAX_RECOVERY_SECRET_BYTES);

        let mut payload = Vec::with_capacity(1_000_000);
        payload.extend_from_slice(b"secret");
        let mut source = payload;
        let payload =
            Zeroizing::new(try_rehome_bytes(&mut source, MAX_RECOVERY_SECRET_BYTES).unwrap());
        let cell = Arc::new(Mutex::new(Some(payload)));
        let presentation = RecoverySecretPresentation::from_shared(cell);
        assert!(
            presentation
                .payload
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .capacity()
                <= MAX_RECOVERY_SECRET_BYTES
        );
    }

    #[test]
    fn protected_source_is_zeroized_on_success_invalid_input_and_reservation_failure() {
        let mut success = b"secret".to_vec();
        let retained =
            try_rehome_bytes_inner(&mut success, MAX_RECOVERY_SECRET_BYTES, false).unwrap();
        assert!(success.is_empty());
        assert_eq!(retained, b"secret");

        let mut invalid = vec![1; MAX_RECOVERY_SECRET_BYTES + 1];
        assert_eq!(
            try_rehome_bytes_inner(&mut invalid, MAX_RECOVERY_SECRET_BYTES, false),
            Err(HostPortError::InvalidInput)
        );
        assert!(invalid.is_empty());

        let mut allocation_failure = b"secret".to_vec();
        assert_eq!(
            try_rehome_bytes_inner(&mut allocation_failure, MAX_RECOVERY_SECRET_BYTES, true,),
            Err(HostPortError::AllocationFailed)
        );
        assert!(allocation_failure.is_empty());
    }

    #[test]
    fn accepted_paths_editor_arguments_and_nested_collections_are_rehomed() {
        let mut logical_source = PathBuf::with_capacity(1_000_000);
        logical_source.push("note.txt");
        assert!(logical_source.capacity() > MAX_LOGICAL_PATH_BYTES);
        let logical = LogicalWorkspacePath::new(logical_source).unwrap();
        assert!(logical.path.capacity() <= MAX_LOGICAL_PATH_BYTES);

        let id = workspace_id(1);
        assert!(id.child_name.capacity() <= 32);
        let mut root = PathBuf::with_capacity(1_000_000);
        root.push(std::env::temp_dir());
        root.push(id.child_name());
        let lease =
            WorkspaceLease::new(id, root, WorkspaceMode::Targeted, Box::new(Ownership)).unwrap();
        assert!(lease.root.capacity() <= MAX_NATIVE_PATH_BYTES);

        let mut repository_root = PathBuf::with_capacity(1_000_000);
        repository_root.push(std::env::temp_dir());
        let target_request = TargetWorkspaceRequest::new(
            workspace_id(2),
            VaultId::from_bytes([3; 16]),
            repository_root,
        )
        .unwrap();
        assert!(target_request.repository_root.capacity() <= MAX_NATIVE_PATH_BYTES);

        let mut repository_root = PathBuf::with_capacity(1_000_000);
        repository_root.push(std::env::temp_dir());
        let vault_request = VaultWorkspaceRequest::new(
            workspace_id(4),
            VaultId::from_bytes([5; 16]),
            repository_root,
        )
        .unwrap();
        assert!(vault_request.repository_root.capacity() <= MAX_NATIVE_PATH_BYTES);

        let mut staging_path = PathBuf::with_capacity(1_000_000);
        staging_path.push(lease.root());
        staging_path.push("staging");
        let mut destination = PathBuf::with_capacity(1_000_000);
        destination.push(lease.root());
        destination.push("note.txt");
        let materialization = MaterializationTarget::new(
            &lease,
            staging_path,
            destination,
            SuppressionToken::from_random_bytes([6; 16]),
        )
        .unwrap();
        assert!(materialization.staging_path.capacity() <= MAX_NATIVE_PATH_BYTES);
        assert!(materialization.destination.capacity() <= MAX_NATIVE_PATH_BYTES);
        let published =
            PublishedGeneration::from_materialization(&lease, materialization, 1).unwrap();
        assert!(published.path.capacity() <= MAX_NATIVE_PATH_BYTES);

        let mut executable = OsString::with_capacity(1_000_000);
        executable.push("editor");
        let mut argument = OsString::with_capacity(1_000_000);
        argument.push("--wait");
        let mut arguments = Vec::with_capacity(1_000_000);
        arguments.push(argument);
        let mut workspace_file = PathBuf::with_capacity(1_000_000);
        workspace_file.push(lease.root());
        workspace_file.push("note.txt");

        let request =
            EditorLaunchRequest::try_new(&lease, executable, arguments, workspace_file).unwrap();
        assert!(request.executable.capacity() <= MAX_EDITOR_ARGUMENT_BYTES);
        assert!(request.arguments.capacity() <= MAX_EDITOR_ARGUMENTS);
        assert!(
            request
                .arguments
                .iter()
                .all(|argument| argument.capacity() <= MAX_EDITOR_ARGUMENT_BYTES)
        );
        assert!(request.workspace_file.capacity() <= MAX_NATIVE_PATH_BYTES);
    }
}
