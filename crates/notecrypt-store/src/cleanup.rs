use std::sync::Arc;

use minicbor::{Decoder, Encoder};
use notecrypt_core::VaultId;
use notecrypt_crypto::{
    LOCAL_STATE_OBJECT_KIND, LocalStateAuthenticator, LocalStateContext, PublicEnvelopeIdentity,
    SecureRandom,
};
#[cfg(any(test, feature = "test-support"))]
use notecrypt_crypto::{LocalVerificationKey, authenticate_local_state, verify_local_state};
use notecrypt_format::{
    AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits, FormatVersion, LocalRecordType,
    LocalStatePayload, LocalStateRecord, decode_local_state, decode_local_state_payload,
    encode_local_state, encode_local_state_payload,
};

use crate::StoreError;
use crate::key_cell::KeyCell;
use crate::local_io::DurableMutationOutcome;

const CLEANUP_VERSION: u16 = 1;
const MAX_CLEANUP_INNER_BYTES: usize = 256;
const ID_RETRIES: usize = 16;
const RECORD_ID_DOMAIN: &[u8] = b"notecrypt/cleanup-record/v1";
const REGISTERED_DOMAIN: &[u8] = b"notecrypt/cleanup-registered/v1";
const ACTIVE_DOMAIN: &[u8] = b"notecrypt/cleanup-active/v1";

/// A store-generated opaque identity for one Notecrypt-owned plaintext workspace.
pub struct CleanupWorkspaceId([u8; 16]);

impl CleanupWorkspaceId {
    /// Returns the only physical child name derived from this identity.
    #[must_use]
    pub fn child_name(&self) -> String {
        encode_hex(&self.0)
    }

    fn from_csprng(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Authenticated lifecycle state stored for a workspace identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupWorkspaceState {
    Registered,
    Active,
}

/// Linear capability proving that the Registered record was durably authenticated.
pub struct RegisteredWorkspace {
    binding: TokenBinding,
    active: bool,
    pending_active: Option<TokenBinding>,
}

impl RegisteredWorkspace {
    #[must_use]
    pub const fn workspace_id(&self) -> &CleanupWorkspaceId {
        &self.binding.workspace_id
    }
}

/// Linear capability proving that the Active record was durably authenticated.
pub struct ActiveWorkspace {
    binding: TokenBinding,
    active: bool,
    removal_pending: bool,
}

/// Linear exact-record authority prepared while the vault generation is authenticated.
pub(crate) struct PreparedWorkspaceUnregister {
    binding: TokenBinding,
    canonical: Vec<u8>,
    active: bool,
    removal_pending: bool,
    authority: Arc<WorkspaceAbsenceAuthorityInner>,
}

pub(crate) struct PreparedWorkspaceRegistration {
    registered: TokenBinding,
    registered_canonical: Vec<u8>,
    active: TokenBinding,
    active_canonical: Vec<u8>,
    stage: RegistrationStage,
    removal_pending: bool,
    authority: Arc<WorkspaceAbsenceAuthorityInner>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegistrationStage {
    Pending,
    Creating,
    Registered,
    ActivationPending,
    Active,
    NoOwnedRecord,
    Complete,
}

impl PreparedWorkspaceRegistration {
    pub(crate) const fn workspace_id(&self) -> &CleanupWorkspaceId {
        &self.registered.workspace_id
    }
}

impl PreparedWorkspaceUnregister {
    pub(crate) const fn workspace_id(&self) -> &CleanupWorkspaceId {
        &self.binding.workspace_id
    }
}

impl ActiveWorkspace {
    #[must_use]
    pub const fn workspace_id(&self) -> &CleanupWorkspaceId {
        &self.binding.workspace_id
    }
}

pub trait WorkspaceAbsenceGuard: Send {}

pub trait TrustedWorkspaceAbsenceVerifier: Send + Sync {
    fn acquire_verified_absence(
        &self,
        workspace: &CleanupWorkspaceId,
    ) -> Result<Box<dyn WorkspaceAbsenceGuard>, StoreError>;
}

pub struct WorkspaceAbsenceAuthority {
    inner: Arc<WorkspaceAbsenceAuthorityInner>,
}

struct WorkspaceAbsenceAuthorityInner {
    verifier: Arc<dyn TrustedWorkspaceAbsenceVerifier>,
}

impl WorkspaceAbsenceAuthority {
    #[must_use]
    pub fn new(verifier: Arc<dyn TrustedWorkspaceAbsenceVerifier>) -> Self {
        Self {
            inner: Arc::new(WorkspaceAbsenceAuthorityInner { verifier }),
        }
    }

    pub fn acquire(&self, active: &ActiveWorkspace) -> Result<WorkspaceAbsenceProof, StoreError> {
        if !active.active {
            return Err(StoreError::InvalidCapability);
        }
        let binding = &active.binding;
        let guard = self
            .inner
            .verifier
            .acquire_verified_absence(&binding.workspace_id)?;
        Ok(WorkspaceAbsenceProof {
            authority: Arc::clone(&self.inner),
            workspace_id: *binding.workspace_id.as_bytes(),
            vault: binding.vault,
            generation: binding.generation,
            record_id: binding.record_id,
            record_commitment: binding.record_commitment,
            active: true,
            _guard: guard,
        })
    }

    pub(crate) fn acquire_prepared(
        &self,
        prepared: &PreparedWorkspaceUnregister,
    ) -> Result<WorkspaceAbsenceProof, StoreError> {
        if !prepared.active || !Arc::ptr_eq(&prepared.authority, &self.inner) {
            return Err(StoreError::InvalidCapability);
        }
        let binding = &prepared.binding;
        let guard = self
            .inner
            .verifier
            .acquire_verified_absence(&binding.workspace_id)?;
        Ok(WorkspaceAbsenceProof {
            authority: Arc::clone(&self.inner),
            workspace_id: *binding.workspace_id.as_bytes(),
            vault: binding.vault,
            generation: binding.generation,
            record_id: binding.record_id,
            record_commitment: binding.record_commitment,
            active: true,
            _guard: guard,
        })
    }

    pub(crate) fn acquire_registration(
        &self,
        registration: &PreparedWorkspaceRegistration,
        active: bool,
    ) -> Result<WorkspaceAbsenceProof, StoreError> {
        if matches!(
            registration.stage,
            RegistrationStage::NoOwnedRecord | RegistrationStage::Complete
        ) || !Arc::ptr_eq(&registration.authority, &self.inner)
        {
            return Err(StoreError::InvalidCapability);
        }
        let binding = if active {
            &registration.active
        } else {
            &registration.registered
        };
        let guard = self
            .inner
            .verifier
            .acquire_verified_absence(&binding.workspace_id)?;
        Ok(WorkspaceAbsenceProof {
            authority: Arc::clone(&self.inner),
            workspace_id: *binding.workspace_id.as_bytes(),
            vault: binding.vault,
            generation: binding.generation,
            record_id: binding.record_id,
            record_commitment: binding.record_commitment,
            active: true,
            _guard: guard,
        })
    }

    pub(crate) fn clone_bound(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub struct WorkspaceAbsenceProof {
    authority: Arc<WorkspaceAbsenceAuthorityInner>,
    workspace_id: [u8; 16],
    vault: VaultId,
    generation: u64,
    record_id: [u8; 32],
    record_commitment: [u8; 32],
    active: bool,
    _guard: Box<dyn WorkspaceAbsenceGuard>,
}

/// One authenticated record discovered during bounded registry enumeration.
pub struct AuthenticatedCleanupRecord {
    binding: TokenBinding,
    state: CleanupWorkspaceState,
}

impl AuthenticatedCleanupRecord {
    #[must_use]
    pub const fn workspace_id(&self) -> &CleanupWorkspaceId {
        &self.binding.workspace_id
    }

    #[must_use]
    pub const fn state(&self) -> CleanupWorkspaceState {
        self.state
    }

    pub fn into_registered(self) -> Result<RegisteredWorkspace, StoreError> {
        if self.state != CleanupWorkspaceState::Registered {
            return Err(StoreError::InvalidCapability);
        }
        Ok(RegisteredWorkspace {
            binding: self.binding,
            active: true,
            pending_active: None,
        })
    }

    pub fn into_active(self) -> Result<ActiveWorkspace, StoreError> {
        if self.state != CleanupWorkspaceState::Active {
            return Err(StoreError::InvalidCapability);
        }
        Ok(ActiveWorkspace {
            binding: self.binding,
            active: true,
            removal_pending: false,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
#[cfg(feature = "test-support")]
pub(crate) struct RemovalConfirmedWorkspace {
    binding: TokenBinding,
}

struct TokenBinding {
    workspace_id: CleanupWorkspaceId,
    vault: VaultId,
    generation: u64,
    record_id: [u8; 32],
    record_commitment: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreateRecordOutcome {
    Created,
    AlreadyExists,
}

pub(crate) type CleanupRecordVisitor<'a> =
    dyn FnMut([u8; 32], &[u8]) -> Result<(), StoreError> + 'a;

pub(crate) trait CleanupRecordPersistence {
    fn cleanup_staging_bounded(&mut self, maximum_records: usize) -> Result<(), StoreError>;

    fn record_count_bounded(&mut self, maximum_records: usize) -> Result<usize, StoreError>;

    fn create_if_absent(
        &mut self,
        record_id: [u8; 32],
        canonical_record: &[u8],
    ) -> Result<CreateRecordOutcome, StoreError>;

    fn read_bounded(
        &mut self,
        record_id: &[u8; 32],
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StoreError>;

    fn replace_if_exact(
        &mut self,
        record_id: &[u8; 32],
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<DurableMutationOutcome, StoreError>;

    fn remove_if_exact(
        &mut self,
        record_id: &[u8; 32],
        expected: &[u8],
    ) -> Result<DurableMutationOutcome, StoreError>;

    fn sync_directory(&mut self) -> Result<(), StoreError>;

    fn sync_registration_source_directory(&mut self) -> Result<(), StoreError>;

    fn visit_bounded(
        &mut self,
        maximum_records: usize,
        maximum_record_bytes: usize,
        visitor: &mut CleanupRecordVisitor<'_>,
    ) -> Result<(), StoreError>;
}

pub(crate) trait CleanupAuthenticator {
    fn authenticate_cleanup(
        &self,
        generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
    ) -> Result<LocalStateAuthenticator, StoreError>;

    fn verify_cleanup(
        &self,
        generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
        authenticator: &LocalStateAuthenticator,
    ) -> Result<(), StoreError>;
}

impl CleanupAuthenticator for KeyCell {
    fn authenticate_cleanup(
        &self,
        generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
    ) -> Result<LocalStateAuthenticator, StoreError> {
        self.authenticate_local(generation, context, canonical)
    }

    fn verify_cleanup(
        &self,
        generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
        authenticator: &LocalStateAuthenticator,
    ) -> Result<(), StoreError> {
        self.verify_local(generation, context, canonical, authenticator)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CleanupAuthenticator for LocalVerificationKey {
    fn authenticate_cleanup(
        &self,
        _generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
    ) -> Result<LocalStateAuthenticator, StoreError> {
        Ok(authenticate_local_state(context, canonical, self)?)
    }

    fn verify_cleanup(
        &self,
        _generation: u64,
        context: &LocalStateContext,
        canonical: &[u8],
        authenticator: &LocalStateAuthenticator,
    ) -> Result<(), StoreError> {
        Ok(verify_local_state(context, canonical, authenticator, self)?)
    }
}

pub(crate) struct CleanupRegistry<R, P> {
    vault: VaultId,
    generation: u64,
    maximum_records: usize,
    enumeration_limit: usize,
    random: R,
    persistence: P,
}

impl<R: SecureRandom, P: CleanupRecordPersistence> CleanupRegistry<R, P> {
    pub(crate) fn new(
        vault: VaultId,
        generation: u64,
        maximum_records: usize,
        random: R,
        persistence: P,
    ) -> Result<Self, StoreError> {
        if maximum_records == 0 {
            return Err(StoreError::LimitExceeded);
        }
        Ok(Self {
            vault,
            generation,
            maximum_records,
            enumeration_limit: maximum_records,
            random,
            persistence,
        })
    }

    pub(crate) fn reserve_and_register(
        &mut self,
        key: &dyn CleanupAuthenticator,
    ) -> Result<RegisteredWorkspace, StoreError> {
        if self
            .persistence
            .record_count_bounded(self.maximum_records)?
            >= self.maximum_records
        {
            return Err(StoreError::LimitExceeded);
        }
        for _ in 0..ID_RETRIES {
            let mut bytes = [0_u8; 16];
            if self.random.fill(&mut bytes).is_err() {
                return Err(StoreError::RandomSource);
            }
            let workspace_id = CleanupWorkspaceId::from_csprng(bytes);
            let inner = CleanupRecord::new(
                self.vault,
                workspace_id.as_bytes(),
                self.generation,
                CleanupWorkspaceState::Registered,
            );
            let record_id = inner.record_id();
            let canonical = encode_authenticated_record(&inner, key)?;
            match self.persistence.create_if_absent(record_id, &canonical)? {
                CreateRecordOutcome::Created => {
                    return Ok(RegisteredWorkspace {
                        binding: token_binding(&inner, &canonical),
                        active: true,
                        pending_active: None,
                    });
                }
                CreateRecordOutcome::AlreadyExists => {}
            }
        }
        Err(StoreError::IdentityCollision)
    }

    pub(crate) fn prepare_registration(
        &mut self,
        key: &dyn CleanupAuthenticator,
        authority: &WorkspaceAbsenceAuthority,
    ) -> Result<PreparedWorkspaceRegistration, StoreError> {
        if self
            .persistence
            .record_count_bounded(self.maximum_records)?
            >= self.maximum_records
        {
            return Err(StoreError::LimitExceeded);
        }
        let mut bytes = [0_u8; 16];
        self.random
            .fill(&mut bytes)
            .map_err(|_| StoreError::RandomSource)?;
        let workspace_id = CleanupWorkspaceId::from_csprng(bytes);
        let registered_record = CleanupRecord::new(
            self.vault,
            workspace_id.as_bytes(),
            self.generation,
            CleanupWorkspaceState::Registered,
        );
        let registered_canonical = encode_authenticated_record(&registered_record, key)?;
        let active_record = CleanupRecord::new(
            self.vault,
            workspace_id.as_bytes(),
            self.generation,
            CleanupWorkspaceState::Active,
        );
        let active_canonical = encode_authenticated_record(&active_record, key)?;
        Ok(PreparedWorkspaceRegistration {
            registered: token_binding(&registered_record, &registered_canonical),
            registered_canonical,
            active: token_binding(&active_record, &active_canonical),
            active_canonical,
            stage: RegistrationStage::Pending,
            removal_pending: false,
            authority: Arc::clone(&authority.inner),
        })
    }

    pub(crate) fn commit_registration(
        &mut self,
        registration: &mut PreparedWorkspaceRegistration,
    ) -> Result<(), StoreError> {
        self.validate_registration_lineage(registration)?;
        match registration.stage {
            RegistrationStage::Registered
            | RegistrationStage::ActivationPending
            | RegistrationStage::Active => return Ok(()),
            RegistrationStage::NoOwnedRecord => return Err(StoreError::IdentityCollision),
            RegistrationStage::Complete => return Err(StoreError::InvalidCapability),
            RegistrationStage::Creating => {
                match self.persistence.read_bounded(
                    &registration.registered.record_id,
                    phase_one_local_record_limit()?,
                )? {
                    None => registration.stage = RegistrationStage::Pending,
                    Some(current) if current == registration.registered_canonical => {
                        self.persistence.sync_registration_source_directory()?;
                        self.persistence.sync_directory()?;
                        registration.stage = RegistrationStage::Registered;
                        return Ok(());
                    }
                    Some(_) => {
                        registration.stage = RegistrationStage::NoOwnedRecord;
                        return Err(StoreError::IdentityCollision);
                    }
                }
            }
            RegistrationStage::Pending => {}
        }
        self.persistence
            .cleanup_staging_bounded(self.maximum_records)?;
        if self
            .persistence
            .record_count_bounded(self.maximum_records)?
            >= self.maximum_records
        {
            return Err(StoreError::LimitExceeded);
        }
        registration.stage = RegistrationStage::Creating;
        match self.persistence.create_if_absent(
            registration.registered.record_id,
            &registration.registered_canonical,
        ) {
            Ok(CreateRecordOutcome::Created) => {
                registration.stage = RegistrationStage::Registered;
                Ok(())
            }
            Ok(CreateRecordOutcome::AlreadyExists) => {
                registration.stage = RegistrationStage::NoOwnedRecord;
                Err(StoreError::IdentityCollision)
            }
            Err(error) => Err(error),
        }
    }

    fn validate_registration_lineage(
        &self,
        registration: &PreparedWorkspaceRegistration,
    ) -> Result<(), StoreError> {
        self.validate_token(&registration.registered)?;
        self.validate_token(&registration.active)?;
        if registration.registered.workspace_id.as_bytes()
            != registration.active.workspace_id.as_bytes()
            || registration.registered.record_id != registration.active.record_id
        {
            return Err(StoreError::InvalidCapability);
        }
        Ok(())
    }

    pub(crate) fn reconcile_registration(
        &mut self,
        registration: &mut PreparedWorkspaceRegistration,
    ) -> Result<Option<bool>, StoreError> {
        self.validate_registration_lineage(registration)?;
        if registration.stage == RegistrationStage::Complete {
            return Err(StoreError::InvalidCapability);
        }
        if registration.stage == RegistrationStage::NoOwnedRecord {
            return Ok(None);
        }
        let current = self.persistence.read_bounded(
            &registration.registered.record_id,
            phase_one_local_record_limit()?,
        )?;
        match current {
            None if matches!(
                registration.stage,
                RegistrationStage::Pending | RegistrationStage::Creating
            ) =>
            {
                registration.stage = RegistrationStage::Pending;
                Ok(None)
            }
            None if registration.removal_pending => match registration.stage {
                RegistrationStage::Active => Ok(Some(true)),
                RegistrationStage::Registered => Ok(Some(false)),
                _ => Err(StoreError::InvalidCapability),
            },
            None => Err(StoreError::InvalidCapability),
            Some(current) if current == registration.registered_canonical => {
                registration.stage = RegistrationStage::Registered;
                Ok(Some(false))
            }
            Some(current) if current == registration.active_canonical => {
                registration.stage = RegistrationStage::Active;
                Ok(Some(true))
            }
            Some(_)
                if matches!(
                    registration.stage,
                    RegistrationStage::Pending | RegistrationStage::Creating
                ) =>
            {
                registration.stage = RegistrationStage::NoOwnedRecord;
                Ok(None)
            }
            Some(_) => Err(StoreError::InvalidCapability),
        }
    }

    pub(crate) fn cancel_registration_if_absent(
        &mut self,
        registration: &mut PreparedWorkspaceRegistration,
    ) -> Result<(), StoreError> {
        if registration.stage == RegistrationStage::NoOwnedRecord {
            registration.stage = RegistrationStage::Complete;
            return Ok(());
        }
        if self.reconcile_registration(registration)?.is_some() {
            return Err(StoreError::InvalidCapability);
        }
        registration.stage = RegistrationStage::Complete;
        Ok(())
    }

    pub(crate) fn activate_registration(
        &mut self,
        registration: &mut PreparedWorkspaceRegistration,
    ) -> Result<(), StoreError> {
        self.validate_registration_lineage(registration)?;
        match registration.stage {
            RegistrationStage::Active => {
                return Ok(());
            }
            RegistrationStage::ActivationPending => {
                match self.persistence.read_bounded(
                    &registration.registered.record_id,
                    phase_one_local_record_limit()?,
                )? {
                    Some(current) if current == registration.active_canonical => {
                        self.persistence.sync_directory()?;
                        registration.stage = RegistrationStage::Active;
                        return Ok(());
                    }
                    Some(current) if current == registration.registered_canonical => {}
                    _ => return Err(StoreError::InvalidCapability),
                }
            }
            RegistrationStage::Registered => {
                match self.persistence.read_bounded(
                    &registration.registered.record_id,
                    phase_one_local_record_limit()?,
                )? {
                    Some(current) if current == registration.registered_canonical => {}
                    _ => return Err(StoreError::InvalidCapability),
                }
            }
            RegistrationStage::Pending | RegistrationStage::Creating => {
                return Err(StoreError::InvalidCapability);
            }
            RegistrationStage::NoOwnedRecord => return Err(StoreError::IdentityCollision),
            RegistrationStage::Complete => return Err(StoreError::InvalidCapability),
        }
        registration.stage = RegistrationStage::ActivationPending;
        match self.persistence.replace_if_exact(
            &registration.registered.record_id,
            &registration.registered_canonical,
            &registration.active_canonical,
        ) {
            Ok(DurableMutationOutcome::Applied) => {
                registration.stage = RegistrationStage::Active;
                Ok(())
            }
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                Err(StoreError::DurabilityPending)
            }
            Ok(DurableMutationOutcome::NotApplied) => {
                match self.persistence.read_bounded(
                    &registration.registered.record_id,
                    phase_one_local_record_limit()?,
                )? {
                    Some(current) if current == registration.active_canonical => {
                        Err(StoreError::DurabilityPending)
                    }
                    Some(current) if current == registration.registered_canonical => {
                        Err(StoreError::InvalidCapability)
                    }
                    _ => Err(StoreError::InvalidCapability),
                }
            }
            Err(primary) => {
                match self.persistence.read_bounded(
                    &registration.registered.record_id,
                    phase_one_local_record_limit()?,
                )? {
                    Some(current) if current == registration.registered_canonical => Err(primary),
                    Some(current) if current == registration.active_canonical => {
                        Err(StoreError::DurabilityPending)
                    }
                    _ => Err(StoreError::InvalidCapability),
                }
            }
        }
    }

    pub(crate) fn unregister_registration_absence(
        &mut self,
        registration: &mut PreparedWorkspaceRegistration,
        proof: &mut WorkspaceAbsenceProof,
        authority: &WorkspaceAbsenceAuthority,
        active: bool,
    ) -> Result<(), StoreError> {
        self.validate_registration_lineage(registration)?;
        let (binding, canonical) = if active {
            (&registration.active, &registration.active_canonical)
        } else {
            (&registration.registered, &registration.registered_canonical)
        };
        let exact = proof.active
            && Arc::ptr_eq(&registration.authority, &authority.inner)
            && Arc::ptr_eq(&proof.authority, &authority.inner)
            && proof.workspace_id == *binding.workspace_id.as_bytes()
            && proof.vault == binding.vault
            && proof.generation == binding.generation
            && proof.record_id == binding.record_id
            && proof.record_commitment == binding.record_commitment;
        if !exact {
            return Err(StoreError::InvalidCapability);
        }
        if registration.removal_pending {
            if self
                .persistence
                .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                .is_some()
            {
                return Err(StoreError::InvalidCapability);
            }
            self.persistence.sync_directory()?;
            registration.removal_pending = false;
            registration.stage = RegistrationStage::Complete;
            proof.active = false;
            return Ok(());
        }
        match self
            .persistence
            .remove_if_exact(&binding.record_id, canonical)
        {
            Ok(DurableMutationOutcome::Applied) => {}
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                registration.removal_pending = true;
                return Err(StoreError::DurabilityPending);
            }
            Ok(DurableMutationOutcome::NotApplied) => {
                if self
                    .persistence
                    .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                    .is_none()
                {
                    registration.removal_pending = true;
                    return Err(StoreError::DurabilityPending);
                }
                return Err(StoreError::InvalidCapability);
            }
            Err(primary) => {
                match self
                    .persistence
                    .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                {
                    None => {
                        registration.removal_pending = true;
                        return Err(StoreError::DurabilityPending);
                    }
                    Some(current) if current == *canonical => return Err(primary),
                    Some(_) => return Err(StoreError::InvalidCapability),
                }
            }
        }
        registration.stage = RegistrationStage::Complete;
        proof.active = false;
        Ok(())
    }

    pub(crate) fn activate(
        &mut self,
        registered: &mut RegisteredWorkspace,
        key: &dyn CleanupAuthenticator,
    ) -> Result<ActiveWorkspace, StoreError> {
        if !registered.active {
            return Err(StoreError::InvalidCapability);
        }
        if registered.pending_active.is_some() {
            let pending = registered
                .pending_active
                .as_ref()
                .ok_or(StoreError::InvalidCapability)?;
            let (current, canonical) = self.read_authenticated(&pending.record_id, key)?;
            validate_transition_source(
                pending,
                &current,
                &canonical,
                CleanupWorkspaceState::Active,
            )?;
            self.persistence.sync_directory()?;
            let binding = registered
                .pending_active
                .take()
                .ok_or(StoreError::InvalidCapability)?;
            registered.active = false;
            return Ok(ActiveWorkspace {
                binding,
                active: true,
                removal_pending: false,
            });
        }
        self.validate_token(&registered.binding)?;
        let (current, canonical) = self.read_authenticated(&registered.binding.record_id, key)?;
        validate_transition_source(
            &registered.binding,
            &current,
            &canonical,
            CleanupWorkspaceState::Registered,
        )?;
        let active = CleanupRecord::new(
            self.vault,
            current.workspace_id.as_bytes(),
            self.generation,
            CleanupWorkspaceState::Active,
        );
        let replacement = encode_authenticated_record(&active, key)?;
        let replacement_binding = token_binding(&active, &replacement);
        match self.persistence.replace_if_exact(
            &registered.binding.record_id,
            &canonical,
            &replacement,
        ) {
            Ok(DurableMutationOutcome::Applied) => {}
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                registered.pending_active = Some(replacement_binding);
                return Err(StoreError::DurabilityPending);
            }
            Ok(DurableMutationOutcome::NotApplied) => {
                let current = self
                    .persistence
                    .read_bounded(
                        &registered.binding.record_id,
                        phase_one_local_record_limit()?,
                    )?
                    .ok_or(StoreError::InvalidCapability)?;
                if current != replacement {
                    return Err(StoreError::InvalidCapability);
                }
                registered.pending_active = Some(replacement_binding);
                return Err(StoreError::DurabilityPending);
            }
            Err(primary) => {
                let current = self
                    .persistence
                    .read_bounded(
                        &registered.binding.record_id,
                        phase_one_local_record_limit()?,
                    )?
                    .ok_or(StoreError::InvalidCapability)?;
                if current == canonical {
                    return Err(primary);
                }
                if current == replacement {
                    registered.pending_active = Some(replacement_binding);
                    return Err(StoreError::DurabilityPending);
                }
                return Err(StoreError::InvalidCapability);
            }
        }
        registered.active = false;
        Ok(ActiveWorkspace {
            binding: replacement_binding,
            active: true,
            removal_pending: false,
        })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn confirm_adapter_removal<F>(
        &self,
        active: ActiveWorkspace,
        confirm_absent: F,
    ) -> Result<RemovalConfirmedWorkspace, StoreError>
    where
        F: FnOnce(&CleanupWorkspaceId) -> Result<(), StoreError>,
    {
        if !active.active {
            return Err(StoreError::InvalidCapability);
        }
        let binding = active.binding;
        self.validate_token(&binding)?;
        confirm_absent(&binding.workspace_id)?;
        Ok(RemovalConfirmedWorkspace { binding })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn unregister(
        &mut self,
        removed: RemovalConfirmedWorkspace,
        key: &dyn CleanupAuthenticator,
    ) -> Result<(), StoreError> {
        self.validate_token(&removed.binding)?;
        let (current, canonical) = self.read_authenticated(&removed.binding.record_id, key)?;
        validate_transition_source(
            &removed.binding,
            &current,
            &canonical,
            CleanupWorkspaceState::Active,
        )?;
        if self
            .persistence
            .remove_if_exact(&removed.binding.record_id, &canonical)?
            != DurableMutationOutcome::Applied
        {
            return Err(StoreError::InvalidCapability);
        }
        Ok(())
    }

    pub(crate) fn unregister_verified_absence(
        &mut self,
        active: &mut ActiveWorkspace,
        proof: &mut WorkspaceAbsenceProof,
        authority: &WorkspaceAbsenceAuthority,
        key: &dyn CleanupAuthenticator,
    ) -> Result<(), StoreError> {
        if !active.active || !proof.active {
            return Err(StoreError::InvalidCapability);
        }
        let binding = &active.binding;
        self.validate_token(binding)?;
        let exact = Arc::ptr_eq(&proof.authority, &authority.inner)
            && proof.workspace_id == *binding.workspace_id.as_bytes()
            && proof.vault == binding.vault
            && proof.generation == binding.generation
            && proof.record_id == binding.record_id
            && proof.record_commitment == binding.record_commitment;
        if !exact {
            return Err(StoreError::InvalidCapability);
        }
        if active.removal_pending {
            if self
                .persistence
                .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                .is_some()
            {
                return Err(StoreError::InvalidCapability);
            }
            self.persistence.sync_directory()?;
            active.active = false;
            active.removal_pending = false;
            proof.active = false;
            return Ok(());
        }
        let (current, canonical) = self.read_authenticated(&binding.record_id, key)?;
        validate_transition_source(binding, &current, &canonical, CleanupWorkspaceState::Active)?;
        match self
            .persistence
            .remove_if_exact(&binding.record_id, &canonical)
        {
            Ok(DurableMutationOutcome::Applied) => {}
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                active.removal_pending = true;
                return Err(StoreError::DurabilityPending);
            }
            Ok(DurableMutationOutcome::NotApplied) => {
                if self
                    .persistence
                    .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                    .is_none()
                {
                    active.removal_pending = true;
                    return Err(StoreError::DurabilityPending);
                }
                return Err(StoreError::InvalidCapability);
            }
            Err(primary) => {
                match self
                    .persistence
                    .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                {
                    None => {
                        active.removal_pending = true;
                        return Err(StoreError::DurabilityPending);
                    }
                    Some(bytes) if bytes == canonical => return Err(primary),
                    Some(_) => return Err(StoreError::InvalidCapability),
                }
            }
        }
        active.active = false;
        proof.active = false;
        Ok(())
    }

    pub(crate) fn prepare_workspace_unregister(
        &mut self,
        active: &mut ActiveWorkspace,
        authority: &WorkspaceAbsenceAuthority,
        key: &dyn CleanupAuthenticator,
    ) -> Result<PreparedWorkspaceUnregister, StoreError> {
        if !active.active || active.removal_pending {
            return Err(StoreError::InvalidCapability);
        }
        self.validate_token(&active.binding)?;
        let (current, canonical) = self.read_authenticated(&active.binding.record_id, key)?;
        validate_transition_source(
            &active.binding,
            &current,
            &canonical,
            CleanupWorkspaceState::Active,
        )?;
        let binding = token_binding(&current, &canonical);
        active.active = false;
        Ok(PreparedWorkspaceUnregister {
            binding,
            canonical,
            active: true,
            removal_pending: false,
            authority: Arc::clone(&authority.inner),
        })
    }

    pub(crate) fn unregister_prepared_absence(
        &mut self,
        prepared: &mut PreparedWorkspaceUnregister,
        proof: &mut WorkspaceAbsenceProof,
        authority: &WorkspaceAbsenceAuthority,
    ) -> Result<(), StoreError> {
        if !prepared.active || !proof.active {
            return Err(StoreError::InvalidCapability);
        }
        let binding = &prepared.binding;
        self.validate_token(binding)?;
        let exact = Arc::ptr_eq(&prepared.authority, &authority.inner)
            && Arc::ptr_eq(&proof.authority, &authority.inner)
            && proof.workspace_id == *binding.workspace_id.as_bytes()
            && proof.vault == binding.vault
            && proof.generation == binding.generation
            && proof.record_id == binding.record_id
            && proof.record_commitment == binding.record_commitment;
        if !exact {
            return Err(StoreError::InvalidCapability);
        }
        if prepared.removal_pending {
            if self
                .persistence
                .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                .is_some()
            {
                return Err(StoreError::InvalidCapability);
            }
            self.persistence.sync_directory()?;
            prepared.active = false;
            prepared.removal_pending = false;
            proof.active = false;
            return Ok(());
        }
        let current = self
            .persistence
            .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
            .ok_or(StoreError::InvalidCapability)?;
        if current != prepared.canonical || record_commitment(&current) != binding.record_commitment
        {
            return Err(StoreError::InvalidCapability);
        }
        match self
            .persistence
            .remove_if_exact(&binding.record_id, &prepared.canonical)
        {
            Ok(DurableMutationOutcome::Applied) => {}
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                prepared.removal_pending = true;
                return Err(StoreError::DurabilityPending);
            }
            Ok(DurableMutationOutcome::NotApplied) => {
                if self
                    .persistence
                    .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                    .is_none()
                {
                    prepared.removal_pending = true;
                    return Err(StoreError::DurabilityPending);
                }
                return Err(StoreError::InvalidCapability);
            }
            Err(primary) => {
                match self
                    .persistence
                    .read_bounded(&binding.record_id, phase_one_local_record_limit()?)?
                {
                    None => {
                        prepared.removal_pending = true;
                        return Err(StoreError::DurabilityPending);
                    }
                    Some(bytes) if bytes == prepared.canonical => return Err(primary),
                    Some(_) => return Err(StoreError::InvalidCapability),
                }
            }
        }
        prepared.active = false;
        proof.active = false;
        Ok(())
    }

    pub(crate) fn authenticated_records(
        &mut self,
        key: &dyn CleanupAuthenticator,
    ) -> Result<Vec<AuthenticatedCleanupRecord>, StoreError> {
        let mut records = Vec::new();
        records
            .try_reserve(self.enumeration_limit.min(64))
            .map_err(|_| StoreError::AllocationFailed)?;
        let vault = self.vault;
        let generation = self.generation;
        let mut visitor = |storage_id: [u8; 32], bytes: &[u8]| {
            if records.len() >= self.enumeration_limit {
                return Err(StoreError::LimitExceeded);
            }
            let record = decode_authenticated_record(bytes, key, generation)?;
            if record.vault != vault || record.record_id() != storage_id {
                return Err(StoreError::LocalStateAuthenticationFailed);
            }
            records
                .try_reserve(1)
                .map_err(|_| StoreError::AllocationFailed)?;
            records.push(AuthenticatedCleanupRecord {
                state: record.state,
                binding: token_binding(&record, bytes),
            });
            Ok(())
        };
        self.persistence.visit_bounded(
            self.enumeration_limit,
            phase_one_local_record_limit()?,
            &mut visitor,
        )?;
        Ok(records)
    }

    fn read_authenticated(
        &mut self,
        record_id: &[u8; 32],
        key: &dyn CleanupAuthenticator,
    ) -> Result<(CleanupRecord, Vec<u8>), StoreError> {
        let canonical = self
            .persistence
            .read_bounded(record_id, phase_one_local_record_limit()?)?
            .ok_or(StoreError::InvalidCapability)?;
        let record = decode_authenticated_record(&canonical, key, self.generation)?;
        if record.vault != self.vault || record.record_id() != *record_id {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        Ok((record, canonical))
    }

    fn validate_token(&self, token: &TokenBinding) -> Result<(), StoreError> {
        if token.generation != self.generation {
            return Err(StoreError::Locked);
        }
        if token.vault != self.vault
            || token.record_id != record_id(&self.vault, &token.workspace_id)
        {
            return Err(StoreError::InvalidCapability);
        }
        Ok(())
    }
}

struct CleanupRecord {
    vault: VaultId,
    workspace_id: CleanupWorkspaceId,
    generation: u64,
    state: CleanupWorkspaceState,
}

impl CleanupRecord {
    fn new(
        vault: VaultId,
        workspace_id: &[u8; 16],
        generation: u64,
        state: CleanupWorkspaceState,
    ) -> Self {
        Self {
            vault,
            workspace_id: CleanupWorkspaceId(*workspace_id),
            generation,
            state,
        }
    }

    fn record_id(&self) -> [u8; 32] {
        record_id(&self.vault, &self.workspace_id)
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let domain = state_domain(self.state);
        let binding = state_binding(domain, &self.vault, &self.workspace_id, self.generation);
        let mut output = Vec::with_capacity(MAX_CLEANUP_INNER_BYTES);
        Encoder::new(&mut output)
            .array(7)
            .and_then(|encoder| encoder.u16(CLEANUP_VERSION))
            .and_then(|encoder| encoder.bytes(domain))
            .and_then(|encoder| encoder.u8(state_number(self.state)))
            .and_then(|encoder| encoder.bytes(self.vault.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.workspace_id.as_bytes()))
            .and_then(|encoder| encoder.u64(self.generation))
            .and_then(|encoder| encoder.bytes(&binding))
            .map_err(|_| StoreError::MalformedObject)?;
        if output.len() > MAX_CLEANUP_INNER_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_CLEANUP_INNER_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| StoreError::MalformedObject)? != Some(7)
            || decoder.u16().map_err(|_| StoreError::MalformedObject)? != CLEANUP_VERSION
        {
            return Err(StoreError::MalformedObject);
        }
        let domain = decoder.bytes().map_err(|_| StoreError::MalformedObject)?;
        let state = state_from_number(decoder.u8().map_err(|_| StoreError::MalformedObject)?)?;
        if domain != state_domain(state) {
            return Err(StoreError::MalformedObject);
        }
        let vault = VaultId::from_bytes(fixed(
            decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
        )?);
        let workspace_id = CleanupWorkspaceId(fixed(
            decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
        )?);
        let generation = decoder.u64().map_err(|_| StoreError::MalformedObject)?;
        let binding: [u8; 32] = fixed(decoder.bytes().map_err(|_| StoreError::MalformedObject)?)?;
        if decoder.position() != bytes.len()
            || binding != state_binding(domain, &vault, &workspace_id, generation)
        {
            return Err(StoreError::MalformedObject);
        }
        let record = Self {
            vault,
            workspace_id,
            generation,
            state,
        };
        if record.encode()? != bytes {
            return Err(StoreError::MalformedObject);
        }
        Ok(record)
    }
}

fn encode_authenticated_record(
    inner: &CleanupRecord,
    key: &dyn CleanupAuthenticator,
) -> Result<Vec<u8>, StoreError> {
    let record_id = inner.record_id();
    let payload = LocalStatePayload::try_new(
        LocalRecordType::Cleanup,
        record_id,
        inner.encode()?,
        &DecodeLimits::PHASE_1,
    )?;
    let canonical_payload = encode_local_state_payload(&payload)?;
    let context = cleanup_context(inner.vault, record_id)?;
    let authenticator = key.authenticate_cleanup(inner.generation, &context, &canonical_payload)?;
    let record = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        *inner.vault.as_bytes(),
        FormatVersion::v1(),
        record_id,
        payload,
        authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )?;
    encode_local_state(&record).map_err(StoreError::from)
}

fn decode_authenticated_record(
    canonical: &[u8],
    key: &dyn CleanupAuthenticator,
    generation: u64,
) -> Result<CleanupRecord, StoreError> {
    if canonical.len() > phase_one_local_record_limit()? {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let result = (|| {
        let record = decode_local_state(canonical, &DecodeLimits::PHASE_1)?;
        let context =
            cleanup_context(VaultId::from_bytes(*record.vault_id()), *record.object_id())?;
        let authenticator = LocalStateAuthenticator::try_from_bytes(record.authenticator())?;
        key.verify_cleanup(
            generation,
            &context,
            record.untrusted_payload_bytes(),
            &authenticator,
        )?;
        let payload =
            decode_local_state_payload(record.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)?;
        let (record_type, payload_record_id, bytes) = payload.into_parts();
        if record_type != LocalRecordType::Cleanup || payload_record_id != *record.object_id() {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        let inner = CleanupRecord::decode(&bytes)?;
        if inner.vault.as_bytes() != record.vault_id() || inner.record_id() != payload_record_id {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        Ok(inner)
    })();
    result.map_err(|_| StoreError::LocalStateAuthenticationFailed)
}

fn cleanup_context(vault: VaultId, record_id: [u8; 32]) -> Result<LocalStateContext, StoreError> {
    LocalStateContext::try_new(PublicEnvelopeIdentity {
        profile_id: CryptoProfileId::profile_one().get(),
        vault_id: *vault.as_bytes(),
        object_kind: LOCAL_STATE_OBJECT_KIND,
        format_version: FormatVersion::v1().get(),
        object_id: record_id,
    })
    .map_err(StoreError::from)
}

fn validate_transition_source(
    token: &TokenBinding,
    record: &CleanupRecord,
    canonical: &[u8],
    expected_state: CleanupWorkspaceState,
) -> Result<(), StoreError> {
    if record.state != expected_state
        || record.vault != token.vault
        || record.generation != token.generation
        || record.workspace_id.as_bytes() != token.workspace_id.as_bytes()
        || record.record_id() != token.record_id
        || record_commitment(canonical) != token.record_commitment
    {
        return Err(StoreError::InvalidCapability);
    }
    Ok(())
}

fn token_binding(record: &CleanupRecord, canonical: &[u8]) -> TokenBinding {
    TokenBinding {
        workspace_id: CleanupWorkspaceId(*record.workspace_id.as_bytes()),
        vault: record.vault,
        generation: record.generation,
        record_id: record.record_id(),
        record_commitment: record_commitment(canonical),
    }
}

fn record_id(vault: &VaultId, workspace_id: &CleanupWorkspaceId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_ID_DOMAIN);
    hasher.update(vault.as_bytes());
    hasher.update(workspace_id.as_bytes());
    *hasher.finalize().as_bytes()
}

fn record_commitment(canonical: &[u8]) -> [u8; 32] {
    *blake3::hash(canonical).as_bytes()
}

fn state_binding(
    domain: &[u8],
    vault: &VaultId,
    workspace_id: &CleanupWorkspaceId,
    generation: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(vault.as_bytes());
    hasher.update(workspace_id.as_bytes());
    hasher.update(&generation.to_be_bytes());
    *hasher.finalize().as_bytes()
}

const fn state_domain(state: CleanupWorkspaceState) -> &'static [u8] {
    match state {
        CleanupWorkspaceState::Registered => REGISTERED_DOMAIN,
        CleanupWorkspaceState::Active => ACTIVE_DOMAIN,
    }
}

const fn state_number(state: CleanupWorkspaceState) -> u8 {
    match state {
        CleanupWorkspaceState::Registered => 1,
        CleanupWorkspaceState::Active => 2,
    }
}

fn state_from_number(value: u8) -> Result<CleanupWorkspaceState, StoreError> {
    match value {
        1 => Ok(CleanupWorkspaceState::Registered),
        2 => Ok(CleanupWorkspaceState::Active),
        _ => Err(StoreError::MalformedObject),
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::MalformedObject)
}

fn phase_one_local_record_limit() -> Result<usize, StoreError> {
    usize::try_from(DecodeLimits::PHASE_1.max_local_record_bytes)
        .map_err(|_| StoreError::LimitExceeded)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_and_active_use_distinct_domains_and_bindings() {
        let vault = VaultId::from_bytes([0x41; 16]);
        let workspace_id = CleanupWorkspaceId([0x42; 16]);
        let registered_domain = state_domain(CleanupWorkspaceState::Registered);
        let active_domain = state_domain(CleanupWorkspaceState::Active);

        assert_ne!(registered_domain, active_domain);
        assert_ne!(
            state_binding(registered_domain, &vault, &workspace_id, 7),
            state_binding(active_domain, &vault, &workspace_id, 7)
        );
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::collections::{BTreeMap, VecDeque};
    use std::io;

    use notecrypt_crypto::{CryptoError, VaultRootKey, derive_vault_keys};

    use super::*;

    pub fn workspace_id(bytes: [u8; 16]) -> CleanupWorkspaceId {
        CleanupWorkspaceId(bytes)
    }

    pub enum CleanupRandomStep {
        Bytes([u8; 16]),
        PartialFailure { bytes: [u8; 16], written: usize },
    }

    pub enum CleanupPersistenceFault {
        ReplaceBeforeEffect,
        ReplaceAfterEffect,
        RemoveBeforeEffect,
        RemoveAfterEffect,
    }

    struct AlwaysAbsent;

    impl WorkspaceAbsenceGuard for AlwaysAbsent {}

    impl TrustedWorkspaceAbsenceVerifier for AlwaysAbsent {
        fn acquire_verified_absence(
            &self,
            _workspace: &CleanupWorkspaceId,
        ) -> Result<Box<dyn WorkspaceAbsenceGuard>, StoreError> {
            Ok(Box::new(AlwaysAbsent))
        }
    }

    pub struct ScriptedCleanupRegistry {
        registry: CleanupRegistry<ScriptedRandom, ScriptedPersistence>,
        key: LocalVerificationKey,
    }

    pub struct ScriptedPreparedRegistration {
        inner: PreparedWorkspaceRegistration,
    }

    impl ScriptedCleanupRegistry {
        pub fn new(
            vault: VaultId,
            generation: u64,
            maximum_records: usize,
            steps: impl IntoIterator<Item = CleanupRandomStep>,
        ) -> Result<Self, StoreError> {
            let mut root_random = FixedRootRandom;
            let root = VaultRootKey::generate(&mut root_random)?;
            let keys = derive_vault_keys(&root)?;
            let registry = CleanupRegistry::new(
                vault,
                generation,
                maximum_records,
                ScriptedRandom {
                    steps: steps.into_iter().collect(),
                },
                ScriptedPersistence::default(),
            )?;
            Ok(Self {
                registry,
                key: keys.local_verification,
            })
        }

        pub fn reserve_and_register(&mut self) -> Result<RegisteredWorkspace, StoreError> {
            self.registry.reserve_and_register(&self.key)
        }

        pub fn prepare_registration(&mut self) -> Result<ScriptedPreparedRegistration, StoreError> {
            let authority = WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent));
            self.registry
                .prepare_registration(&self.key, &authority)
                .map(|inner| ScriptedPreparedRegistration { inner })
        }

        pub fn commit_prepared_registration(
            &mut self,
            registration: &mut ScriptedPreparedRegistration,
        ) -> Result<(), StoreError> {
            self.registry.commit_registration(&mut registration.inner)
        }

        pub fn cancel_prepared_registration(
            &mut self,
            registration: &mut ScriptedPreparedRegistration,
        ) -> Result<(), StoreError> {
            self.registry
                .cancel_registration_if_absent(&mut registration.inner)
        }

        pub fn activate(
            &mut self,
            mut registered: RegisteredWorkspace,
        ) -> Result<ActiveWorkspace, StoreError> {
            self.registry.activate(&mut registered, &self.key)
        }

        pub fn activate_retryable(
            &mut self,
            registered: &mut RegisteredWorkspace,
        ) -> Result<ActiveWorkspace, StoreError> {
            self.registry.activate(registered, &self.key)
        }

        pub fn acquire_absence_proof(
            &self,
            active: &ActiveWorkspace,
        ) -> Result<(WorkspaceAbsenceAuthority, WorkspaceAbsenceProof), StoreError> {
            let authority = WorkspaceAbsenceAuthority::new(Arc::new(AlwaysAbsent));
            let proof = authority.acquire(active)?;
            Ok((authority, proof))
        }

        pub fn unregister_retryable(
            &mut self,
            active: &mut ActiveWorkspace,
            proof: &mut WorkspaceAbsenceProof,
            authority: &WorkspaceAbsenceAuthority,
        ) -> Result<(), StoreError> {
            self.registry
                .unregister_verified_absence(active, proof, authority, &self.key)
        }

        pub fn push_persistence_fault(&mut self, fault: CleanupPersistenceFault) {
            self.registry.persistence.faults.push_back(fault);
        }

        pub fn directory_sync_count(&self) -> usize {
            self.registry.persistence.directory_sync_count
        }

        pub fn unregister_after_adapter_removal_for_test(
            &mut self,
            active: ActiveWorkspace,
        ) -> Result<(), StoreError> {
            let removed = self.registry.confirm_adapter_removal(active, |_| Ok(()))?;
            self.registry.unregister(removed, &self.key)
        }

        pub fn fail_adapter_removal_for_test(
            &mut self,
            active: ActiveWorkspace,
        ) -> Result<(), StoreError> {
            let removed = self
                .registry
                .confirm_adapter_removal(active, |_| Err(StoreError::Cancelled))?;
            self.registry.unregister(removed, &self.key)
        }

        pub fn enumerate_authenticated(
            &mut self,
        ) -> Result<Vec<AuthenticatedCleanupRecord>, StoreError> {
            self.registry.authenticated_records(&self.key)
        }

        pub fn persisted_record_count(&self) -> usize {
            self.registry.persistence.records.len()
        }

        pub fn tamper_record(
            &mut self,
            workspace_id: &CleanupWorkspaceId,
            offset: usize,
        ) -> Result<(), StoreError> {
            let id = record_id(&self.registry.vault, workspace_id);
            let bytes = self
                .registry
                .persistence
                .records
                .get_mut(&id)
                .ok_or(StoreError::NotFound)?;
            let byte = bytes.get_mut(offset).ok_or(StoreError::LimitExceeded)?;
            *byte ^= 1;
            Ok(())
        }

        pub fn rewrite_authenticated_state_for_test(
            &mut self,
            workspace_id: &CleanupWorkspaceId,
            state: CleanupWorkspaceState,
        ) -> Result<(), StoreError> {
            let id = record_id(&self.registry.vault, workspace_id);
            let current = self
                .registry
                .persistence
                .records
                .get(&id)
                .ok_or(StoreError::NotFound)?;
            let decoded =
                decode_authenticated_record(current, &self.key, self.registry.generation)?;
            let replacement = CleanupRecord::new(
                self.registry.vault,
                decoded.workspace_id.as_bytes(),
                decoded.generation,
                state,
            );
            let canonical = encode_authenticated_record(&replacement, &self.key)?;
            self.registry.persistence.records.insert(id, canonical);
            Ok(())
        }

        pub fn advance_generation(&mut self) -> Result<(), StoreError> {
            self.registry.generation = self
                .registry
                .generation
                .checked_add(1)
                .ok_or(StoreError::SessionGenerationExhausted)?;
            Ok(())
        }

        pub fn set_enumeration_limit_for_test(&mut self, limit: usize) {
            self.registry.enumeration_limit = limit;
        }
    }

    struct ScriptedRandom {
        steps: VecDeque<CleanupRandomStep>,
    }

    impl SecureRandom for ScriptedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            let step = self.steps.pop_front().ok_or(CryptoError::RandomSource)?;
            match step {
                CleanupRandomStep::Bytes(bytes) => {
                    if destination.len() != bytes.len() {
                        return Err(CryptoError::RandomSource);
                    }
                    destination.copy_from_slice(&bytes);
                    Ok(())
                }
                CleanupRandomStep::PartialFailure { bytes, written } => {
                    let count = written.min(destination.len()).min(bytes.len());
                    destination[..count].copy_from_slice(&bytes[..count]);
                    Err(CryptoError::RandomSource)
                }
            }
        }
    }

    struct FixedRootRandom;

    impl SecureRandom for FixedRootRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0xa5);
            Ok(())
        }
    }

    #[derive(Default)]
    struct ScriptedPersistence {
        records: BTreeMap<[u8; 32], Vec<u8>>,
        faults: VecDeque<CleanupPersistenceFault>,
        directory_sync_count: usize,
    }

    impl CleanupRecordPersistence for ScriptedPersistence {
        fn cleanup_staging_bounded(&mut self, _maximum_records: usize) -> Result<(), StoreError> {
            Ok(())
        }

        fn record_count_bounded(&mut self, maximum_records: usize) -> Result<usize, StoreError> {
            if self.records.len() > maximum_records {
                return Err(StoreError::LimitExceeded);
            }
            Ok(self.records.len())
        }

        fn create_if_absent(
            &mut self,
            record_id: [u8; 32],
            canonical_record: &[u8],
        ) -> Result<CreateRecordOutcome, StoreError> {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.records.entry(record_id)
            {
                entry.insert(canonical_record.to_vec());
                Ok(CreateRecordOutcome::Created)
            } else {
                Ok(CreateRecordOutcome::AlreadyExists)
            }
        }

        fn read_bounded(
            &mut self,
            record_id: &[u8; 32],
            maximum_bytes: usize,
        ) -> Result<Option<Vec<u8>>, StoreError> {
            let Some(record) = self.records.get(record_id) else {
                return Ok(None);
            };
            if record.len() > maximum_bytes {
                return Err(StoreError::LimitExceeded);
            }
            Ok(Some(record.clone()))
        }

        fn replace_if_exact(
            &mut self,
            record_id: &[u8; 32],
            expected: &[u8],
            replacement: &[u8],
        ) -> Result<DurableMutationOutcome, StoreError> {
            if matches!(
                self.faults.front(),
                Some(CleanupPersistenceFault::ReplaceBeforeEffect)
            ) {
                self.faults.pop_front();
                return Err(StoreError::Io(io::Error::other(
                    "scripted replace before effect",
                )));
            }
            let Some(current) = self.records.get_mut(record_id) else {
                return Ok(DurableMutationOutcome::NotApplied);
            };
            if current.as_slice() != expected {
                return Ok(DurableMutationOutcome::NotApplied);
            }
            *current = replacement.to_vec();
            if matches!(
                self.faults.front(),
                Some(CleanupPersistenceFault::ReplaceAfterEffect)
            ) {
                self.faults.pop_front();
                return Ok(DurableMutationOutcome::AppliedNeedsDirectorySync);
            }
            Ok(DurableMutationOutcome::Applied)
        }

        fn remove_if_exact(
            &mut self,
            record_id: &[u8; 32],
            expected: &[u8],
        ) -> Result<DurableMutationOutcome, StoreError> {
            if matches!(
                self.faults.front(),
                Some(CleanupPersistenceFault::RemoveBeforeEffect)
            ) {
                self.faults.pop_front();
                return Err(StoreError::Io(io::Error::other(
                    "scripted remove before effect",
                )));
            }
            let Some(current) = self.records.get(record_id) else {
                return Ok(DurableMutationOutcome::NotApplied);
            };
            if current.as_slice() != expected {
                return Ok(DurableMutationOutcome::NotApplied);
            }
            self.records.remove(record_id);
            if matches!(
                self.faults.front(),
                Some(CleanupPersistenceFault::RemoveAfterEffect)
            ) {
                self.faults.pop_front();
                return Ok(DurableMutationOutcome::AppliedNeedsDirectorySync);
            }
            Ok(DurableMutationOutcome::Applied)
        }

        fn sync_directory(&mut self) -> Result<(), StoreError> {
            self.directory_sync_count = self.directory_sync_count.saturating_add(1);
            Ok(())
        }

        fn sync_registration_source_directory(&mut self) -> Result<(), StoreError> {
            Ok(())
        }

        fn visit_bounded(
            &mut self,
            maximum_records: usize,
            maximum_record_bytes: usize,
            visitor: &mut CleanupRecordVisitor<'_>,
        ) -> Result<(), StoreError> {
            if self.records.len() > maximum_records {
                return Err(StoreError::LimitExceeded);
            }
            for (id, record) in &self.records {
                if record.len() > maximum_record_bytes {
                    return Err(StoreError::LimitExceeded);
                }
                visitor(*id, record)?;
            }
            Ok(())
        }
    }
}
