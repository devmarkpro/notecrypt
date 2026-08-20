use std::collections::HashSet;

use minicbor::{Decoder, Encoder};
use notecrypt_core::VaultId;
use notecrypt_crypto::{
    AeadEnvelopeParts, DeviceSlotContext, DeviceSlotEnvelope, DeviceWrappingKey,
    LOCAL_STATE_OBJECT_KIND, LocalStateAuthenticator, LocalStateContext, PublicEnvelopeIdentity,
    SecureRandom, TypedAeadEnvelope, decrypt_device_slot,
};
use notecrypt_format::{
    AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits,
    FormatVersion, LocalRecordType, LocalStatePayload, LocalStateRecord, OrdinaryAeadKind,
    decode_aead_object, decode_local_state, decode_local_state_payload, encode_aead_object,
    encode_local_state, encode_local_state_payload,
};
use zeroize::{Zeroize, Zeroizing};

use crate::StoreError;
use crate::key_cell::KeyCell;
use crate::local_io::DurableMutationOutcome;
use crate::trusted_state::verify_authenticated_trusted_head;

const DEVICE_RECORD_VERSION: u16 = 1;
const DEVICE_RECORD_ID_DOMAIN: &[u8] = b"notecrypt/device-slot-record/v1";
const ID_RETRIES: usize = 16;
const MAX_DEVICE_RECORD_BYTES: usize = 8 * 1024;
const MAX_PROVIDER_BYTES: usize = 128;
const MAX_REFERENCE_BYTES: usize = 2 * 1024;
const DEFAULT_MAX_SLOTS: usize = 64;
const DEFAULT_MAX_LOCAL_RECORDS: usize = 4_096;
const MAX_LOCAL_RECORD_BYTES: usize = 64 * 1024;

/// A bounded native credential-provider identifier.
pub struct DeviceProvider(String);

impl DeviceProvider {
    pub fn try_new(mut value: String) -> Result<Self, StoreError> {
        if let Err(error) = validate_bounded_text(&value, MAX_PROVIDER_BYTES) {
            value.zeroize();
            return Err(error);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for DeviceProvider {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A bounded opaque reference understood only by the selected native provider.
pub struct DeviceReference(String);

impl DeviceReference {
    pub fn try_new(mut value: String) -> Result<Self, StoreError> {
        if let Err(error) = validate_bounded_text(&value, MAX_REFERENCE_BYTES) {
            value.zeroize();
            return Err(error);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for DeviceReference {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Enrollment input. The store generates the slot identity and consumes the wrapping key.
pub struct DeviceEnrollment {
    provider: DeviceProvider,
    reference: DeviceReference,
    wrapping_key: DeviceWrappingKey,
    #[cfg(feature = "test-support")]
    key_drop_probe: Option<KeyDropProbe>,
}

impl DeviceEnrollment {
    #[must_use]
    pub fn new(
        provider: DeviceProvider,
        reference: DeviceReference,
        wrapping_key: DeviceWrappingKey,
    ) -> Self {
        Self {
            provider,
            reference,
            wrapping_key,
            #[cfg(feature = "test-support")]
            key_drop_probe: None,
        }
    }
}

/// Linear capability for an authenticated active device slot.
pub struct ActiveDeviceSlot {
    binding: Option<SlotBinding>,
    pending_disabled: Option<PendingDisabledTransition>,
}

struct PendingDisabledTransition {
    binding: SlotBinding,
    provider: DeviceProvider,
    reference: DeviceReference,
}

/// Linear capability for a disabled slot whose native provider entry still needs removal.
pub struct DisabledDeviceSlotPendingProviderRemoval {
    binding: Option<SlotBinding>,
    provider: DeviceProvider,
    reference: DeviceReference,
    removal_pending: bool,
}

impl DisabledDeviceSlotPendingProviderRemoval {
    #[must_use]
    pub const fn provider(&self) -> &DeviceProvider {
        &self.provider
    }

    #[must_use]
    pub const fn reference(&self) -> &DeviceReference {
        &self.reference
    }
}

/// A structurally bounded but unauthenticated candidate returned while the vault is locked.
pub struct UntrustedDeviceSlotCandidate {
    provider: DeviceProvider,
    reference: DeviceReference,
    vault: VaultId,
    record_id: [u8; 32],
    canonical_record: Vec<u8>,
}

impl UntrustedDeviceSlotCandidate {
    #[must_use]
    pub const fn provider(&self) -> &DeviceProvider {
        &self.provider
    }

    #[must_use]
    pub const fn reference(&self) -> &DeviceReference {
        &self.reference
    }
}

impl Drop for UntrustedDeviceSlotCandidate {
    fn drop(&mut self) {
        self.canonical_record.zeroize();
    }
}

struct SlotBinding {
    vault: VaultId,
    generation: u64,
    record_id: [u8; 32],
    record_commitment: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceSlotState {
    Active,
    DisabledPendingProviderRemoval,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreateDeviceRecordOutcome {
    Created,
    AlreadyExists,
}

pub(crate) type DeviceRecordVisitor<'a> = dyn FnMut([u8; 32], &[u8]) -> Result<(), StoreError> + 'a;

/// Persistence boundary for authenticated canonical records. It conveys no path authority.
pub(crate) trait DeviceSlotPersistence {
    fn create_if_absent(
        &mut self,
        record_id: [u8; 32],
        canonical_record: &[u8],
        maximum_records: usize,
    ) -> Result<CreateDeviceRecordOutcome, StoreError>;

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

    fn visit_device_records_bounded(
        &mut self,
        maximum_records: usize,
        maximum_record_bytes: usize,
        visitor: &mut DeviceRecordVisitor<'_>,
    ) -> Result<(), StoreError>;

    fn visit_all_local_records_bounded(
        &mut self,
        maximum_records: usize,
        maximum_record_bytes: usize,
        visitor: &mut DeviceRecordVisitor<'_>,
    ) -> Result<(), StoreError>;
}

pub(crate) struct DeviceSlotRegistry<R, P> {
    vault: VaultId,
    generation: u64,
    maximum_slots: usize,
    maximum_local_records: usize,
    listing_limit: usize,
    random: R,
    persistence: P,
}

impl<R: SecureRandom, P: DeviceSlotPersistence> DeviceSlotRegistry<R, P> {
    pub(crate) fn authenticate_existing(&mut self, keys: &KeyCell) -> Result<usize, StoreError> {
        self.authenticated_slot_count(keys)
    }

    pub(crate) fn authenticate_all_local_records(
        &mut self,
        keys: &KeyCell,
    ) -> Result<usize, StoreError> {
        let mut authenticated_records = 0_usize;
        let mut seen = HashSet::new();
        seen.try_reserve(self.maximum_local_records)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.persistence.visit_all_local_records_bounded(
            self.maximum_local_records,
            MAX_LOCAL_RECORD_BYTES,
            &mut |record_id, bytes| {
                if authenticated_records >= self.maximum_local_records || !seen.insert(record_id) {
                    return Err(StoreError::LocalStateAuthenticationFailed);
                }
                let (_, authenticated_id, _) =
                    authenticate_complete_local_record(bytes, keys, self.generation, self.vault)?;
                if authenticated_id != record_id {
                    return Err(StoreError::LocalStateAuthenticationFailed);
                }
                authenticated_records = authenticated_records
                    .checked_add(1)
                    .ok_or(StoreError::LimitExceeded)?;
                Ok(())
            },
        )?;
        Ok(authenticated_records)
    }

    pub(crate) fn new(
        vault: VaultId,
        generation: u64,
        random: R,
        persistence: P,
    ) -> Result<Self, StoreError> {
        if generation == 0 {
            return Err(StoreError::InvalidCapability);
        }
        Ok(Self {
            vault,
            generation,
            maximum_slots: DEFAULT_MAX_SLOTS,
            maximum_local_records: DEFAULT_MAX_LOCAL_RECORDS,
            listing_limit: DEFAULT_MAX_SLOTS,
            random,
            persistence,
        })
    }

    pub(crate) fn enroll(
        &mut self,
        keys: &KeyCell,
        enrollment: DeviceEnrollment,
    ) -> Result<ActiveDeviceSlot, StoreError> {
        keys.validate_generation(self.generation)?;
        if self.authenticated_slot_count(keys)? >= self.maximum_slots {
            return Err(StoreError::LimitExceeded);
        }
        let DeviceEnrollment {
            mut provider,
            mut reference,
            wrapping_key,
            #[cfg(feature = "test-support")]
                key_drop_probe: _key_drop_probe,
        } = enrollment;
        for _ in 0..ID_RETRIES {
            let mut slot_id = [0_u8; 16];
            if self.random.fill(&mut slot_id).is_err() {
                slot_id.zeroize();
                return Err(StoreError::RandomSource);
            }
            let record_id = device_record_id(self.vault, &slot_id);
            let context = device_slot_context(self.vault, record_id)?;
            let envelope = keys.wrap_root_for_device(
                self.generation,
                &context,
                &wrapping_key,
                &mut self.random,
            )?;
            let record = DeviceRecord {
                vault: self.vault,
                slot_id,
                generation: self.generation,
                state: DeviceSlotState::Active,
                provider,
                reference,
                envelope: encode_device_envelope(envelope)?,
            };
            let canonical = encode_authenticated_device_record(&record, keys, self.generation)?;
            let binding = slot_binding(&record, &canonical);
            let create =
                self.persistence
                    .create_if_absent(record_id, &canonical, self.maximum_slots);
            match create {
                Ok(CreateDeviceRecordOutcome::Created) => {
                    return Ok(ActiveDeviceSlot {
                        binding: Some(binding),
                        pending_disabled: None,
                    });
                }
                Ok(CreateDeviceRecordOutcome::AlreadyExists) => {
                    let current = self
                        .persistence
                        .read_bounded(&record_id, MAX_DEVICE_RECORD_BYTES)?
                        .ok_or(StoreError::InvalidCapability)?;
                    let current = Zeroizing::new(current);
                    verify_device_record(&current, keys, self.generation, self.vault)?;
                    if current.as_slice() == canonical.as_slice() {
                        return Ok(ActiveDeviceSlot {
                            binding: Some(binding),
                            pending_disabled: None,
                        });
                    }
                }
                Err(primary) => {
                    if let Some(reissued) = self
                        .reconcile_create_failure(record_id, &canonical, binding, keys, primary)?
                    {
                        return Ok(reissued);
                    }
                }
            }
            let DeviceRecord {
                provider: recovered_provider,
                reference: recovered_reference,
                ..
            } = record;
            provider = recovered_provider;
            reference = recovered_reference;
        }
        Err(StoreError::IdentityCollision)
    }

    fn reconcile_create_failure(
        &mut self,
        record_id: [u8; 32],
        canonical: &[u8],
        binding: SlotBinding,
        keys: &KeyCell,
        primary: StoreError,
    ) -> Result<Option<ActiveDeviceSlot>, StoreError> {
        let Some(current) = self
            .persistence
            .read_bounded(&record_id, MAX_DEVICE_RECORD_BYTES)?
        else {
            return Err(primary);
        };
        let current = Zeroizing::new(current);
        verify_device_record(&current, keys, self.generation, self.vault)?;
        if current.as_slice() == canonical {
            Ok(Some(ActiveDeviceSlot {
                binding: Some(binding),
                pending_disabled: None,
            }))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn list_locked(&mut self) -> Result<Vec<UntrustedDeviceSlotCandidate>, StoreError> {
        if self.listing_limit == 0 || self.listing_limit > self.maximum_slots {
            return Err(StoreError::LimitExceeded);
        }
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(self.listing_limit)
            .map_err(|_| StoreError::LimitExceeded)?;
        let mut seen = HashSet::new();
        seen.try_reserve(self.listing_limit)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.persistence.visit_device_records_bounded(
            self.listing_limit,
            MAX_DEVICE_RECORD_BYTES,
            &mut |record_id, bytes| {
                if !seen.insert(record_id) || candidates.len() >= self.listing_limit {
                    return Err(StoreError::LimitExceeded);
                }
                let record = decode_untrusted_device_record(bytes, self.vault, record_id)?;
                candidates.push(UntrustedDeviceSlotCandidate {
                    provider: record.provider,
                    reference: record.reference,
                    vault: record.vault,
                    record_id,
                    canonical_record: copy_bytes_bounded(bytes, MAX_DEVICE_RECORD_BYTES)?,
                });
                Ok(())
            },
        )?;
        Ok(candidates)
    }

    pub(crate) fn disable(
        &mut self,
        keys: &KeyCell,
        active: &mut ActiveDeviceSlot,
    ) -> Result<DisabledDeviceSlotPendingProviderRemoval, StoreError> {
        if active.pending_disabled.is_some() {
            let pending = active
                .pending_disabled
                .as_ref()
                .ok_or(StoreError::InvalidCapability)?;
            let (record, canonical) =
                self.read_authenticated_device_record(&pending.binding.record_id, keys)?;
            validate_binding_record(
                &pending.binding,
                &record,
                &canonical,
                DeviceSlotState::DisabledPendingProviderRemoval,
            )?;
            self.persistence.sync_directory()?;
            let pending = active
                .pending_disabled
                .take()
                .ok_or(StoreError::InvalidCapability)?;
            active.binding.take().ok_or(StoreError::InvalidCapability)?;
            return Ok(DisabledDeviceSlotPendingProviderRemoval {
                binding: Some(pending.binding),
                provider: pending.provider,
                reference: pending.reference,
                removal_pending: false,
            });
        }
        let binding = active
            .binding
            .as_ref()
            .ok_or(StoreError::InvalidCapability)?;
        self.validate_binding(binding)?;
        keys.validate_generation(self.generation)?;
        let (mut record, canonical) =
            self.read_authenticated_device_record(&binding.record_id, keys)?;
        validate_binding_record(binding, &record, &canonical, DeviceSlotState::Active)?;
        record.state = DeviceSlotState::DisabledPendingProviderRemoval;
        let replacement = encode_authenticated_device_record(&record, keys, self.generation)?;
        let replacement_binding = slot_binding(&record, &replacement);
        let replace =
            self.persistence
                .replace_if_exact(&binding.record_id, &canonical, &replacement);
        let primary = match replace {
            Ok(DurableMutationOutcome::Applied) => None,
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                active.pending_disabled = Some(PendingDisabledTransition {
                    binding: replacement_binding,
                    provider: record.provider,
                    reference: record.reference,
                });
                return Err(StoreError::DurabilityPending);
            }
            Ok(DurableMutationOutcome::NotApplied) => Some(StoreError::InvalidCapability),
            Err(error) => Some(error),
        };
        if let Some(primary) = primary {
            let current = self
                .persistence
                .read_bounded(&binding.record_id, MAX_DEVICE_RECORD_BYTES)?
                .ok_or(StoreError::InvalidCapability)?;
            let current = Zeroizing::new(current);
            verify_device_record(&current, keys, self.generation, self.vault)?;
            if current.as_slice() != replacement.as_slice() {
                if current.as_slice() == canonical.as_slice() {
                    return Err(primary);
                }
                return Err(StoreError::InvalidCapability);
            }
            active.pending_disabled = Some(PendingDisabledTransition {
                binding: replacement_binding,
                provider: record.provider,
                reference: record.reference,
            });
            return Err(StoreError::DurabilityPending);
        }
        active.binding.take().ok_or(StoreError::InvalidCapability)?;
        Ok(DisabledDeviceSlotPendingProviderRemoval {
            binding: Some(replacement_binding),
            provider: record.provider,
            reference: record.reference,
            removal_pending: false,
        })
    }

    pub(crate) fn delete_disabled(
        &mut self,
        keys: &KeyCell,
        disabled: &mut DisabledDeviceSlotPendingProviderRemoval,
    ) -> Result<(), StoreError> {
        self.delete_disabled_binding(keys, &mut disabled.binding, &mut disabled.removal_pending)
    }

    fn delete_disabled_binding(
        &mut self,
        keys: &KeyCell,
        binding: &mut Option<SlotBinding>,
        removal_pending: &mut bool,
    ) -> Result<(), StoreError> {
        let current_binding = binding.as_ref().ok_or(StoreError::InvalidCapability)?;
        self.validate_binding(current_binding)?;
        keys.validate_generation(self.generation)?;
        if *removal_pending {
            if self
                .persistence
                .read_bounded(&current_binding.record_id, MAX_DEVICE_RECORD_BYTES)?
                .is_some()
            {
                return Err(StoreError::InvalidCapability);
            }
            self.persistence.sync_directory()?;
            binding.take().ok_or(StoreError::InvalidCapability)?;
            *removal_pending = false;
            return Ok(());
        }
        let (record, canonical) =
            self.read_authenticated_device_record(&current_binding.record_id, keys)?;
        validate_binding_record(
            current_binding,
            &record,
            &canonical,
            DeviceSlotState::DisabledPendingProviderRemoval,
        )?;
        let remove = self
            .persistence
            .remove_if_exact(&current_binding.record_id, &canonical);
        let primary = match remove {
            Ok(DurableMutationOutcome::Applied) => None,
            Ok(DurableMutationOutcome::AppliedNeedsDirectorySync) => {
                *removal_pending = true;
                return Err(StoreError::DurabilityPending);
            }
            Ok(DurableMutationOutcome::NotApplied) => Some(StoreError::InvalidCapability),
            Err(error) => Some(error),
        };
        if let Some(primary) = primary {
            match self
                .persistence
                .read_bounded(&current_binding.record_id, MAX_DEVICE_RECORD_BYTES)?
            {
                None => {
                    *removal_pending = true;
                    return Err(StoreError::DurabilityPending);
                }
                Some(current) => {
                    let current = Zeroizing::new(current);
                    verify_device_record(&current, keys, self.generation, self.vault)?;
                    if current.as_slice() == canonical.as_slice() {
                        return Err(primary);
                    }
                    return Err(StoreError::InvalidCapability);
                }
            }
        }
        binding.take().ok_or(StoreError::InvalidCapability)?;
        Ok(())
    }

    pub(crate) fn unlock(
        &mut self,
        candidate: UntrustedDeviceSlotCandidate,
        wrapping_key: DeviceWrappingKey,
    ) -> Result<AuthenticatedDeviceUnlock, StoreError> {
        if candidate.vault != self.vault {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        let current = self
            .persistence
            .read_bounded(&candidate.record_id, MAX_DEVICE_RECORD_BYTES)?
            .ok_or(StoreError::LocalStateAuthenticationFailed)?;
        let current = Zeroizing::new(current);
        let untrusted = decode_untrusted_device_record(&current, self.vault, candidate.record_id)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
        let envelope = decode_device_envelope(&untrusted.envelope, self.vault, candidate.record_id)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
        let context = device_slot_context(self.vault, candidate.record_id)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
        let root = decrypt_device_slot(&context, &envelope, &wrapping_key)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?
            .into_root_key();
        let keys = KeyCell::new(root).map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
        let generation = keys.generation();
        let authenticated = verify_device_record(&current, &keys, generation, self.vault)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
        if authenticated.state != DeviceSlotState::Active {
            return Err(StoreError::InvalidCapability);
        }
        if current.as_slice() != candidate.canonical_record.as_slice()
            || authenticated.provider.as_str() != candidate.provider.as_str()
            || authenticated.reference.as_str() != candidate.reference.as_str()
        {
            return Err(StoreError::InvalidCapability);
        }

        let mut authenticated_records = 0_usize;
        let mut candidate_seen = false;
        let mut trusted_head_seen = false;
        let mut seen = HashSet::new();
        seen.try_reserve(self.maximum_local_records)
            .map_err(|_| StoreError::LimitExceeded)?;
        self.persistence.visit_all_local_records_bounded(
            self.maximum_local_records,
            MAX_LOCAL_RECORD_BYTES,
            &mut |record_id, bytes| {
                if authenticated_records >= self.maximum_local_records {
                    return Err(StoreError::LimitExceeded);
                }
                if !seen.insert(record_id) {
                    return Err(StoreError::LocalStateAuthenticationFailed);
                }
                let (record_type, authenticated_id, _) =
                    authenticate_complete_local_record(bytes, &keys, generation, self.vault)
                        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
                if authenticated_id != record_id {
                    return Err(StoreError::LocalStateAuthenticationFailed);
                }
                authenticated_records = authenticated_records
                    .checked_add(1)
                    .ok_or(StoreError::LimitExceeded)?;
                if record_id == candidate.record_id {
                    candidate_seen = true;
                    if bytes != current.as_slice() {
                        return Err(StoreError::LocalStateAuthenticationFailed);
                    }
                }
                if record_type == LocalRecordType::TrustedHead {
                    if trusted_head_seen {
                        return Err(StoreError::LocalStateAuthenticationFailed);
                    }
                    let record = decode_local_state(bytes, &DecodeLimits::PHASE_1)
                        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
                    verify_authenticated_trusted_head(&record, &keys, generation)
                        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
                    trusted_head_seen = true;
                }
                Ok(())
            },
        )?;
        if !candidate_seen || !trusted_head_seen {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        Ok(AuthenticatedDeviceUnlock {
            keys,
            #[cfg(feature = "test-support")]
            authenticated_records,
        })
    }

    fn authenticated_slot_count(&mut self, keys: &KeyCell) -> Result<usize, StoreError> {
        let mut count = 0_usize;
        self.persistence.visit_device_records_bounded(
            self.maximum_slots,
            MAX_DEVICE_RECORD_BYTES,
            &mut |record_id, bytes| {
                verify_device_record(bytes, keys, self.generation, self.vault)?;
                if record_id != outer_record_id(bytes)? {
                    return Err(StoreError::LocalStateAuthenticationFailed);
                }
                count = count.checked_add(1).ok_or(StoreError::LimitExceeded)?;
                Ok(())
            },
        )?;
        Ok(count)
    }

    fn read_authenticated_device_record(
        &mut self,
        record_id: &[u8; 32],
        keys: &KeyCell,
    ) -> Result<(DeviceRecord, Zeroizing<Vec<u8>>), StoreError> {
        let canonical = self
            .persistence
            .read_bounded(record_id, MAX_DEVICE_RECORD_BYTES)?
            .ok_or(StoreError::NotFound)?;
        let canonical = Zeroizing::new(canonical);
        let record = verify_device_record(&canonical, keys, self.generation, self.vault)?;
        Ok((record, canonical))
    }

    fn validate_binding(&self, binding: &SlotBinding) -> Result<(), StoreError> {
        if binding.vault != self.vault {
            return Err(StoreError::InvalidCapability);
        }
        if binding.generation != self.generation {
            return Err(StoreError::Locked);
        }
        Ok(())
    }
}

pub(crate) struct AuthenticatedDeviceUnlock {
    keys: KeyCell,
    #[cfg(feature = "test-support")]
    authenticated_records: usize,
}

impl AuthenticatedDeviceUnlock {
    pub(crate) fn into_key_cell(self) -> KeyCell {
        self.keys
    }

    #[cfg(feature = "test-support")]
    fn authenticated_records(&self) -> usize {
        self.authenticated_records
    }
}

struct DeviceRecord {
    vault: VaultId,
    slot_id: [u8; 16],
    generation: u64,
    state: DeviceSlotState,
    provider: DeviceProvider,
    reference: DeviceReference,
    envelope: Vec<u8>,
}

impl DeviceRecord {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut output = Zeroizing::new(Vec::new());
        output
            .try_reserve_exact(MAX_DEVICE_RECORD_BYTES)
            .map_err(|_| StoreError::LimitExceeded)?;
        Encoder::new(&mut *output)
            .array(8)
            .and_then(|encoder| encoder.u16(DEVICE_RECORD_VERSION))
            .and_then(|encoder| encoder.bytes(self.vault.as_bytes()))
            .and_then(|encoder| encoder.bytes(&self.slot_id))
            .and_then(|encoder| encoder.u64(self.generation))
            .and_then(|encoder| encoder.u8(state_number(self.state)))
            .and_then(|encoder| encoder.str(self.provider.as_str()))
            .and_then(|encoder| encoder.str(self.reference.as_str()))
            .and_then(|encoder| encoder.bytes(&self.envelope))
            .map_err(|_| StoreError::MalformedObject)?;
        if output.len() > MAX_DEVICE_RECORD_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_DEVICE_RECORD_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| StoreError::MalformedObject)? != Some(8)
            || decoder.u16().map_err(|_| StoreError::MalformedObject)? != DEVICE_RECORD_VERSION
        {
            return Err(StoreError::MalformedObject);
        }
        let record = Self {
            vault: VaultId::from_bytes(fixed(
                decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
            )?),
            slot_id: fixed(decoder.bytes().map_err(|_| StoreError::MalformedObject)?)?,
            generation: decoder.u64().map_err(|_| StoreError::MalformedObject)?,
            state: state_from_number(decoder.u8().map_err(|_| StoreError::MalformedObject)?)?,
            provider: DeviceProvider::try_new(copy_text_bounded(
                decoder.str().map_err(|_| StoreError::MalformedObject)?,
                MAX_PROVIDER_BYTES,
            )?)?,
            reference: DeviceReference::try_new(copy_text_bounded(
                decoder.str().map_err(|_| StoreError::MalformedObject)?,
                MAX_REFERENCE_BYTES,
            )?)?,
            envelope: copy_bytes_bounded(
                decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
                MAX_DEVICE_RECORD_BYTES,
            )?,
        };
        if decoder.position() != bytes.len() || record.encode()?.as_slice() != bytes {
            return Err(StoreError::MalformedObject);
        }
        Ok(record)
    }
}

fn encode_authenticated_device_record(
    record: &DeviceRecord,
    keys: &KeyCell,
    generation: u64,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let record_id = device_record_id(record.vault, &record.slot_id);
    let mut inner = record.encode()?;
    let payload = LocalStatePayload::try_new(
        LocalRecordType::DeviceSlot,
        record_id,
        std::mem::take(&mut *inner),
        &DecodeLimits::PHASE_1,
    )?;
    let canonical_payload = Zeroizing::new(encode_local_state_payload(&payload)?);
    let context = local_state_context(record.vault, record_id)?;
    let authenticator = keys.authenticate_local(generation, &context, &canonical_payload)?;
    let outer = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        *record.vault.as_bytes(),
        FormatVersion::v1(),
        record_id,
        payload,
        authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )?;
    let encoded = Zeroizing::new(encode_local_state(&outer)?);
    if encoded.len() > MAX_DEVICE_RECORD_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    Ok(encoded)
}

fn verify_device_record(
    bytes: &[u8],
    keys: &KeyCell,
    generation: u64,
    expected_vault: VaultId,
) -> Result<DeviceRecord, StoreError> {
    let (record_type, record_id, inner) =
        authenticate_complete_local_record(bytes, keys, generation, expected_vault)?;
    if record_type != LocalRecordType::DeviceSlot {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let record =
        DeviceRecord::decode(&inner).map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    if record.vault != expected_vault
        || record.generation != generation
        || device_record_id(record.vault, &record.slot_id) != record_id
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    decode_device_envelope(&record.envelope, record.vault, record_id)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    Ok(record)
}

type AuthenticatedLocalRecordParts = (LocalRecordType, [u8; 32], Zeroizing<Vec<u8>>);

fn authenticate_complete_local_record(
    bytes: &[u8],
    keys: &KeyCell,
    generation: u64,
    expected_vault: VaultId,
) -> Result<AuthenticatedLocalRecordParts, StoreError> {
    if bytes.len() > MAX_LOCAL_RECORD_BYTES {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let record = decode_local_state(bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    if record.vault_id() != expected_vault.as_bytes() {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let record_id = *record.object_id();
    let context = local_state_context(expected_vault, record_id)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    let authenticator = LocalStateAuthenticator::try_from_bytes(record.authenticator())
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    keys.verify_local(
        generation,
        &context,
        record.untrusted_payload_bytes(),
        &authenticator,
    )
    .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    let payload =
        decode_local_state_payload(record.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    let (record_type, payload_id, inner) = payload.into_parts();
    if payload_id != record_id {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    Ok((record_type, record_id, Zeroizing::new(inner)))
}

fn decode_untrusted_device_record(
    bytes: &[u8],
    expected_vault: VaultId,
    expected_record_id: [u8; 32],
) -> Result<DeviceRecord, StoreError> {
    if bytes.len() > MAX_DEVICE_RECORD_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    let outer = decode_local_state(bytes, &DecodeLimits::PHASE_1)?;
    if outer.vault_id() != expected_vault.as_bytes() || outer.object_id() != &expected_record_id {
        return Err(StoreError::MalformedObject);
    }
    let payload =
        decode_local_state_payload(outer.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)?;
    let (kind, payload_id, inner) = payload.into_parts();
    if kind != LocalRecordType::DeviceSlot || payload_id != expected_record_id {
        return Err(StoreError::MalformedObject);
    }
    let inner = Zeroizing::new(inner);
    let record = DeviceRecord::decode(&inner)?;
    if record.vault != expected_vault
        || device_record_id(record.vault, &record.slot_id) != expected_record_id
    {
        return Err(StoreError::MalformedObject);
    }
    decode_device_envelope(&record.envelope, expected_vault, expected_record_id)?;
    Ok(record)
}

fn encode_device_envelope(envelope: DeviceSlotEnvelope) -> Result<Vec<u8>, StoreError> {
    let (identity, nonce, ciphertext, tag) =
        envelope.into_parts().into_public_parts().into_components();
    let object = AeadObject::try_new(
        CryptoProfileId::profile_one(),
        AeadAlgorithmId::xchacha20_poly1305(),
        identity.vault_id,
        OrdinaryAeadKind::DeviceSlot,
        FormatVersion::v1(),
        identity.object_id,
        &nonce,
        ciphertext,
        &tag,
        &DecodeLimits::PHASE_1,
    )?;
    Ok(encode_aead_object(&object)?)
}

fn decode_device_envelope(
    bytes: &[u8],
    vault: VaultId,
    record_id: [u8; 32],
) -> Result<DeviceSlotEnvelope, StoreError> {
    let object = decode_aead_object(bytes, &DecodeLimits::PHASE_1)?;
    if object.vault_id() != vault.as_bytes()
        || object.object_id() != &record_id
        || object.kind() != OrdinaryAeadKind::DeviceSlot
    {
        return Err(StoreError::AuthenticationFailed);
    }
    let (profile, _algorithm, vault_id, kind, version, object_id, nonce, ciphertext, tag) =
        object.into_parts().into_components();
    let identity = PublicEnvelopeIdentity {
        profile_id: profile.get(),
        vault_id,
        object_kind: kind.object_kind().get(),
        format_version: version.get(),
        object_id,
    };
    DeviceSlotEnvelope::try_from_parts(AeadEnvelopeParts::try_new(
        identity, &nonce, ciphertext, &tag,
    )?)
    .map_err(StoreError::from)
}

fn validate_binding_record(
    binding: &SlotBinding,
    record: &DeviceRecord,
    canonical: &[u8],
    expected_state: DeviceSlotState,
) -> Result<(), StoreError> {
    if record.vault != binding.vault
        || record.generation != binding.generation
        || device_record_id(record.vault, &record.slot_id) != binding.record_id
        || record_commitment(canonical) != binding.record_commitment
        || record.state != expected_state
    {
        return Err(StoreError::InvalidCapability);
    }
    Ok(())
}

fn slot_binding(record: &DeviceRecord, canonical: &[u8]) -> SlotBinding {
    SlotBinding {
        vault: record.vault,
        generation: record.generation,
        record_id: device_record_id(record.vault, &record.slot_id),
        record_commitment: record_commitment(canonical),
    }
}

fn outer_record_id(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    Ok(*decode_local_state(bytes, &DecodeLimits::PHASE_1)?.object_id())
}

fn device_record_id(vault: VaultId, slot_id: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DEVICE_RECORD_ID_DOMAIN);
    hasher.update(vault.as_bytes());
    hasher.update(slot_id);
    *hasher.finalize().as_bytes()
}

fn record_commitment(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn device_slot_context(
    vault: VaultId,
    record_id: [u8; 32],
) -> Result<DeviceSlotContext, StoreError> {
    Ok(DeviceSlotContext::try_new(PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: *vault.as_bytes(),
        object_kind: notecrypt_crypto::DEVICE_SLOT_OBJECT_KIND,
        format_version: 1,
        object_id: record_id,
    })?)
}

fn local_state_context(
    vault: VaultId,
    record_id: [u8; 32],
) -> Result<LocalStateContext, StoreError> {
    Ok(LocalStateContext::try_new(PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: *vault.as_bytes(),
        object_kind: LOCAL_STATE_OBJECT_KIND,
        format_version: 1,
        object_id: record_id,
    })?)
}

fn validate_bounded_text(value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(StoreError::LimitExceeded);
    }
    Ok(())
}

fn copy_text_bounded(value: &str, maximum: usize) -> Result<String, StoreError> {
    if value.len() > maximum {
        return Err(StoreError::LimitExceeded);
    }
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| StoreError::LimitExceeded)?;
    owned.push_str(value);
    Ok(owned)
}

fn copy_bytes_bounded(value: &[u8], maximum: usize) -> Result<Vec<u8>, StoreError> {
    if value.len() > maximum {
        return Err(StoreError::LimitExceeded);
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| StoreError::LimitExceeded)?;
    owned.extend_from_slice(value);
    Ok(owned)
}

#[cfg(feature = "test-support")]
struct KeyDropProbe(std::sync::Arc<std::sync::atomic::AtomicBool>);

#[cfg(feature = "test-support")]
impl Drop for KeyDropProbe {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

const fn state_number(state: DeviceSlotState) -> u8 {
    match state {
        DeviceSlotState::Active => 1,
        DeviceSlotState::DisabledPendingProviderRemoval => 2,
    }
}

fn state_from_number(value: u8) -> Result<DeviceSlotState, StoreError> {
    match value {
        1 => Ok(DeviceSlotState::Active),
        2 => Ok(DeviceSlotState::DisabledPendingProviderRemoval),
        _ => Err(StoreError::MalformedObject),
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::MalformedObject)
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::collections::{BTreeMap, VecDeque};
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use notecrypt_core::SnapshotId;
    use notecrypt_crypto::{CryptoError, DeviceWrappingKey, SecureRandom, VaultRootKey};

    use super::*;
    use crate::trusted_state::{TrustedHead, build_authenticated_trusted_head};

    pub enum DeviceRandomStep {
        Fill(Vec<u8>),
        PartialFailure(Vec<u8>),
    }

    pub enum DevicePersistenceFault {
        CreateBeforeEffect,
        CreateAfterEffect,
        ReplaceBeforeEffect,
        ReplaceAfterEffect,
        ReplaceAppliedButReportedMismatch,
        RemoveBeforeEffect,
        RemoveAfterEffect,
        RemoveAppliedButReportedMismatch,
    }

    struct ScriptedRandom {
        steps: VecDeque<DeviceRandomStep>,
        fills: usize,
        close_after_fill: Option<(usize, Arc<KeyCell>)>,
    }

    impl SecureRandom for ScriptedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            self.fills = self.fills.saturating_add(1);
            let result = match self.steps.pop_front() {
                Some(DeviceRandomStep::Fill(bytes)) if bytes.len() == destination.len() => {
                    destination.copy_from_slice(&bytes);
                    Ok(())
                }
                Some(DeviceRandomStep::PartialFailure(bytes)) => {
                    let copied = bytes.len().min(destination.len());
                    destination[..copied].copy_from_slice(&bytes[..copied]);
                    Err(CryptoError::RandomSource)
                }
                _ => Err(CryptoError::RandomSource),
            };
            if self
                .close_after_fill
                .as_ref()
                .is_some_and(|(fill, _)| *fill == self.fills)
                && let Some((_, keys)) = self.close_after_fill.take()
            {
                let _ = keys.begin_close();
            }
            result
        }
    }

    #[derive(Default)]
    struct MemoryPersistence {
        device: BTreeMap<[u8; 32], Vec<u8>>,
        trusted: BTreeMap<[u8; 32], Vec<u8>>,
        faults: VecDeque<DevicePersistenceFault>,
        reverse_local_enumeration: bool,
        duplicate_trusted_head: bool,
        omit_devices_from_local_enumeration: bool,
        remove_devices_before_local_enumeration: bool,
        underreport_device_count_once: bool,
    }

    impl Drop for MemoryPersistence {
        fn drop(&mut self) {
            for bytes in self.device.values_mut().chain(self.trusted.values_mut()) {
                bytes.zeroize();
            }
        }
    }

    impl DeviceSlotPersistence for MemoryPersistence {
        fn create_if_absent(
            &mut self,
            record_id: [u8; 32],
            canonical_record: &[u8],
            maximum_records: usize,
        ) -> Result<CreateDeviceRecordOutcome, StoreError> {
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::CreateBeforeEffect)
            ) {
                self.faults.pop_front();
                return Err(scripted_persistence_error());
            }
            if self.device.contains_key(&record_id) {
                return Ok(CreateDeviceRecordOutcome::AlreadyExists);
            }
            if self.device.len() >= maximum_records {
                return Err(StoreError::LimitExceeded);
            }
            self.device.insert(
                record_id,
                copy_bytes_bounded(canonical_record, MAX_DEVICE_RECORD_BYTES)?,
            );
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::CreateAfterEffect)
            ) {
                self.faults.pop_front();
                return Err(scripted_persistence_error());
            }
            Ok(CreateDeviceRecordOutcome::Created)
        }

        fn read_bounded(
            &mut self,
            record_id: &[u8; 32],
            maximum_bytes: usize,
        ) -> Result<Option<Vec<u8>>, StoreError> {
            let Some(bytes) = self.device.get(record_id) else {
                return Ok(None);
            };
            if bytes.len() > maximum_bytes {
                return Err(StoreError::LimitExceeded);
            }
            Ok(Some(bytes.clone()))
        }

        fn replace_if_exact(
            &mut self,
            record_id: &[u8; 32],
            expected: &[u8],
            replacement: &[u8],
        ) -> Result<DurableMutationOutcome, StoreError> {
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::ReplaceBeforeEffect)
            ) {
                self.faults.pop_front();
                return Err(scripted_persistence_error());
            }
            let Some(current) = self.device.get_mut(record_id) else {
                return Ok(DurableMutationOutcome::NotApplied);
            };
            if current.as_slice() != expected {
                return Ok(DurableMutationOutcome::NotApplied);
            }
            current.zeroize();
            *current = copy_bytes_bounded(replacement, MAX_DEVICE_RECORD_BYTES)?;
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::ReplaceAfterEffect)
            ) {
                self.faults.pop_front();
                return Ok(DurableMutationOutcome::AppliedNeedsDirectorySync);
            }
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::ReplaceAppliedButReportedMismatch)
            ) {
                self.faults.pop_front();
                return Ok(DurableMutationOutcome::NotApplied);
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
                Some(DevicePersistenceFault::RemoveBeforeEffect)
            ) {
                self.faults.pop_front();
                return Err(scripted_persistence_error());
            }
            if self.device.get(record_id).map(Vec::as_slice) != Some(expected) {
                return Ok(DurableMutationOutcome::NotApplied);
            }
            if let Some(mut removed) = self.device.remove(record_id) {
                removed.zeroize();
            }
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::RemoveAfterEffect)
            ) {
                self.faults.pop_front();
                return Ok(DurableMutationOutcome::AppliedNeedsDirectorySync);
            }
            if matches!(
                self.faults.front(),
                Some(DevicePersistenceFault::RemoveAppliedButReportedMismatch)
            ) {
                self.faults.pop_front();
                return Ok(DurableMutationOutcome::NotApplied);
            }
            Ok(DurableMutationOutcome::Applied)
        }

        fn sync_directory(&mut self) -> Result<(), StoreError> {
            Ok(())
        }

        fn visit_device_records_bounded(
            &mut self,
            maximum_records: usize,
            maximum_record_bytes: usize,
            visitor: &mut DeviceRecordVisitor<'_>,
        ) -> Result<(), StoreError> {
            if self.underreport_device_count_once {
                self.underreport_device_count_once = false;
                return Ok(());
            }
            if self.device.len() > maximum_records {
                return Err(StoreError::LimitExceeded);
            }
            for (id, bytes) in &self.device {
                if bytes.len() > maximum_record_bytes {
                    return Err(StoreError::LimitExceeded);
                }
                visitor(*id, bytes)?;
            }
            Ok(())
        }

        fn visit_all_local_records_bounded(
            &mut self,
            maximum_records: usize,
            maximum_record_bytes: usize,
            visitor: &mut DeviceRecordVisitor<'_>,
        ) -> Result<(), StoreError> {
            if self.remove_devices_before_local_enumeration {
                self.remove_devices_before_local_enumeration = false;
                for bytes in self.device.values_mut() {
                    bytes.zeroize();
                }
                self.device.clear();
            }
            if self.device.len().saturating_add(self.trusted.len()) > maximum_records {
                return Err(StoreError::LimitExceeded);
            }
            let visit = |id: &[u8; 32],
                         bytes: &[u8],
                         visitor: &mut DeviceRecordVisitor<'_>|
             -> Result<(), StoreError> {
                if bytes.len() > maximum_record_bytes {
                    return Err(StoreError::LimitExceeded);
                }
                visitor(*id, bytes)
            };
            if self.reverse_local_enumeration {
                for (id, bytes) in self.trusted.iter().rev().chain(self.device.iter().rev()) {
                    if self.omit_devices_from_local_enumeration && self.device.contains_key(id) {
                        continue;
                    }
                    visit(id, bytes, visitor)?;
                }
            } else {
                for (id, bytes) in self.device.iter().chain(&self.trusted) {
                    if self.omit_devices_from_local_enumeration && self.device.contains_key(id) {
                        continue;
                    }
                    visit(id, bytes, visitor)?;
                }
            }
            if self.duplicate_trusted_head {
                let (id, bytes) = self.trusted.first_key_value().ok_or(StoreError::NotFound)?;
                visit(id, bytes, visitor)?;
            }
            Ok(())
        }
    }

    pub struct ScriptedDeviceRegistry {
        registry: DeviceSlotRegistry<ScriptedRandom, MemoryPersistence>,
        keys: Arc<KeyCell>,
        authenticated_trusted_reads: usize,
    }

    impl ScriptedDeviceRegistry {
        pub fn new(
            vault: VaultId,
            steps: impl IntoIterator<Item = DeviceRandomStep>,
        ) -> Result<Self, StoreError> {
            let root = VaultRootKey::generate(&mut FixedRootRandom)?;
            let keys = Arc::new(KeyCell::new(root)?);
            let registry = DeviceSlotRegistry::new(
                vault,
                keys.generation(),
                ScriptedRandom {
                    steps: steps.into_iter().collect(),
                    fills: 0,
                    close_after_fill: None,
                },
                MemoryPersistence::default(),
            )?;
            Ok(Self {
                registry,
                keys,
                authenticated_trusted_reads: 0,
            })
        }

        pub fn enroll(
            &mut self,
            enrollment: DeviceEnrollment,
        ) -> Result<ActiveDeviceSlot, StoreError> {
            self.registry.enroll(&self.keys, enrollment)
        }

        pub fn enrollment_with_drop_probe(
            provider: DeviceProvider,
            reference: DeviceReference,
            protected_key: Vec<u8>,
        ) -> Result<(DeviceEnrollment, Arc<AtomicBool>), StoreError> {
            let dropped = Arc::new(AtomicBool::new(false));
            let enrollment = DeviceEnrollment {
                provider,
                reference,
                wrapping_key: DeviceWrappingKey::try_from_protected_bytes(protected_key)?,
                key_drop_probe: Some(KeyDropProbe(Arc::clone(&dropped))),
            };
            Ok((enrollment, dropped))
        }

        pub fn list_locked(&mut self) -> Result<Vec<UntrustedDeviceSlotCandidate>, StoreError> {
            self.registry.list_locked()
        }

        pub fn unlock(
            &mut self,
            candidate: UntrustedDeviceSlotCandidate,
            protected_key: Vec<u8>,
        ) -> Result<(), StoreError> {
            let key = DeviceWrappingKey::try_from_protected_bytes(protected_key)?;
            let unlocked = self.registry.unlock(candidate, key)?;
            self.authenticated_trusted_reads = unlocked.authenticated_records();
            drop(unlocked.into_key_cell());
            Ok(())
        }

        pub fn disable(
            &mut self,
            mut active: ActiveDeviceSlot,
        ) -> Result<DisabledDeviceSlotPendingProviderRemoval, StoreError> {
            self.registry.disable(&self.keys, &mut active)
        }

        pub fn disable_retryable(
            &mut self,
            active: &mut ActiveDeviceSlot,
        ) -> Result<DisabledDeviceSlotPendingProviderRemoval, StoreError> {
            self.registry.disable(&self.keys, active)
        }

        pub fn delete_disabled(
            &mut self,
            mut disabled: DisabledDeviceSlotPendingProviderRemoval,
        ) -> Result<(), StoreError> {
            self.registry.delete_disabled(&self.keys, &mut disabled)
        }

        pub fn delete_disabled_retryable(
            &mut self,
            disabled: &mut DisabledDeviceSlotPendingProviderRemoval,
        ) -> Result<(), StoreError> {
            self.registry.delete_disabled(&self.keys, disabled)
        }

        pub fn delete_active_for_test(
            &mut self,
            mut active: ActiveDeviceSlot,
        ) -> Result<(), StoreError> {
            let mut removal_pending = false;
            self.registry.delete_disabled_binding(
                &self.keys,
                &mut active.binding,
                &mut removal_pending,
            )
        }

        pub fn add_authenticated_trusted_head(&mut self) -> Result<[u8; 32], StoreError> {
            let trusted = TrustedHead::new(
                self.registry.vault,
                SnapshotId::from_bytes([0x73; 32]),
                [0x74; 32],
            );
            let record =
                build_authenticated_trusted_head(&trusted, &self.keys, self.registry.generation)?;
            let record_id = *record.object_id();
            if let Some(mut previous) = self
                .registry
                .persistence
                .trusted
                .insert(record_id, encode_local_state(&record)?)
            {
                previous.zeroize();
            }
            Ok(record_id)
        }

        pub fn tamper_candidate_record(
            &mut self,
            candidate: &UntrustedDeviceSlotCandidate,
            offset: usize,
        ) -> Result<(), StoreError> {
            tamper(
                self.registry
                    .persistence
                    .device
                    .get_mut(&candidate.record_id)
                    .ok_or(StoreError::NotFound)?,
                offset,
            )
        }

        pub fn tamper_trusted_record(
            &mut self,
            record_id: [u8; 32],
            offset: usize,
        ) -> Result<(), StoreError> {
            tamper(
                self.registry
                    .persistence
                    .trusted
                    .get_mut(&record_id)
                    .ok_or(StoreError::NotFound)?,
                offset,
            )
        }

        #[must_use]
        pub fn persisted_slot_count(&self) -> usize {
            self.registry.persistence.device.len()
        }

        #[must_use]
        pub fn random_fill_count(&self) -> usize {
            self.registry.random.fills
        }

        #[must_use]
        pub fn authenticated_trusted_reads(&self) -> usize {
            self.authenticated_trusted_reads
        }

        pub fn advance_generation(&mut self) -> Result<(), StoreError> {
            self.registry.generation = self
                .registry
                .generation
                .checked_add(1)
                .ok_or(StoreError::SessionGenerationExhausted)?;
            Ok(())
        }

        pub fn set_listing_limit(&mut self, limit: usize) {
            self.registry.listing_limit = limit;
        }

        pub fn set_maximum_slots(&mut self, limit: usize) {
            self.registry.maximum_slots = limit;
            self.registry.listing_limit = self.registry.listing_limit.min(limit);
        }

        pub fn push_persistence_fault(&mut self, fault: DevicePersistenceFault) {
            self.registry.persistence.faults.push_back(fault);
        }

        pub fn set_reverse_local_enumeration(&mut self, reverse: bool) {
            self.registry.persistence.reverse_local_enumeration = reverse;
        }

        pub fn set_duplicate_trusted_head_enumeration(&mut self, duplicate: bool) {
            self.registry.persistence.duplicate_trusted_head = duplicate;
        }

        pub fn set_omit_devices_from_local_enumeration(&mut self, omit: bool) {
            self.registry
                .persistence
                .omit_devices_from_local_enumeration = omit;
        }

        pub fn remove_devices_before_local_enumeration_once(&mut self) {
            self.registry
                .persistence
                .remove_devices_before_local_enumeration = true;
        }

        pub fn underreport_slot_count_once(&mut self) {
            self.registry.persistence.underreport_device_count_once = true;
        }

        pub fn close_after_random_fill(&mut self, fill: usize) {
            self.registry.random.close_after_fill = Some((fill, Arc::clone(&self.keys)));
        }

        pub fn begin_close(&self) -> Result<(), StoreError> {
            self.keys.begin_close()
        }
    }

    struct FixedRootRandom;

    impl SecureRandom for FixedRootRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0x5a);
            Ok(())
        }
    }

    fn tamper(bytes: &mut [u8], offset: usize) -> Result<(), StoreError> {
        let byte = bytes.get_mut(offset).ok_or(StoreError::LimitExceeded)?;
        *byte ^= 1;
        Ok(())
    }

    fn scripted_persistence_error() -> StoreError {
        StoreError::Io(io::Error::other("scripted device persistence failure"))
    }
}
