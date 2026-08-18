use minicbor::{Decoder, Encoder};
use notecrypt_core::VaultId;
use notecrypt_crypto::{
    LOCAL_STATE_OBJECT_KIND, LocalStateAuthenticator, LocalStateContext, PublicEnvelopeIdentity,
};
use notecrypt_format::{
    AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits, FormatVersion, LocalRecordType,
    LocalStatePayload, LocalStateRecord, decode_local_state, decode_local_state_payload,
    encode_local_state, encode_local_state_payload,
};

use crate::StoreError;
use crate::key_cell::KeyCell;
use crate::layout::{StoreLayout, component};
use crate::local_io::{
    DurableMutationOutcome, read_optional, replace_durable, replace_durable_if_exact,
};

const AVAILABILITY_FILE: &str = "availability";
const AVAILABILITY_VERSION: u16 = 1;
const AVAILABILITY_RECORD_DOMAIN: &[u8] = b"notecrypt/vault-availability-id/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultAvailability {
    Inactive,
    Activating,
    Active,
}

pub(crate) fn write_initial(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
    state: VaultAvailability,
) -> Result<(), StoreError> {
    let bytes = build_record(layout.vault, keys, generation, state)?;
    replace_durable(&layout.trusted, &component(AVAILABILITY_FILE)?, &bytes)?;
    verify_exact(layout, keys, generation, state)
}

pub(crate) fn require_active(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    verify_exact(layout, keys, generation, VaultAvailability::Active)
}

pub(crate) fn begin_activation(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    transition(
        layout,
        keys,
        generation,
        VaultAvailability::Inactive,
        VaultAvailability::Activating,
    )
}

pub(crate) fn complete_activation(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    transition(
        layout,
        keys,
        generation,
        VaultAvailability::Activating,
        VaultAvailability::Active,
    )
}

pub(crate) fn authenticated_state(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<VaultAvailability, StoreError> {
    let bytes = read_optional(&layout.trusted, &component(AVAILABILITY_FILE)?)?
        .ok_or(StoreError::LocalStateAuthenticationFailed)?;
    verify_record(&bytes, layout.vault, keys, generation)
}

pub(crate) fn untrusted_state(
    layout: &StoreLayout,
) -> Result<Option<VaultAvailability>, StoreError> {
    let Some(bytes) = read_optional(&layout.trusted, &component(AVAILABILITY_FILE)?)? else {
        return Ok(None);
    };
    decode_record_without_authentication(&bytes, layout.vault).map(Some)
}

fn transition(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
    expected: VaultAvailability,
    replacement_state: VaultAvailability,
) -> Result<(), StoreError> {
    let name = component(AVAILABILITY_FILE)?;
    let current =
        read_optional(&layout.trusted, &name)?.ok_or(StoreError::LocalStateAuthenticationFailed)?;
    let current_state = verify_record(&current, layout.vault, keys, generation)?;
    if current_state == replacement_state {
        return Ok(());
    }
    if current_state != expected {
        return Err(StoreError::InvalidCapability);
    }
    let replacement = build_record(layout.vault, keys, generation, replacement_state)?;
    match replace_durable_if_exact(&layout.trusted, &name, &current, &replacement)? {
        DurableMutationOutcome::Applied => {}
        DurableMutationOutcome::AppliedNeedsDirectorySync => layout.trusted.sync()?,
        DurableMutationOutcome::NotApplied => return Err(StoreError::InvalidCapability),
    }
    verify_exact(layout, keys, generation, replacement_state)
}

fn verify_exact(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
    expected: VaultAvailability,
) -> Result<(), StoreError> {
    let bytes = read_optional(&layout.trusted, &component(AVAILABILITY_FILE)?)?
        .ok_or(StoreError::LocalStateAuthenticationFailed)?;
    if verify_record(&bytes, layout.vault, keys, generation)? == expected {
        Ok(())
    } else {
        Err(StoreError::InvalidCapability)
    }
}

fn build_record(
    vault: VaultId,
    keys: &KeyCell,
    generation: u64,
    state: VaultAvailability,
) -> Result<Vec<u8>, StoreError> {
    let record_id = record_id(vault);
    let inner = encode_inner(vault, state)?;
    let payload = LocalStatePayload::try_new(
        LocalRecordType::VaultAvailability,
        record_id,
        inner,
        &DecodeLimits::PHASE_1,
    )?;
    let canonical = encode_local_state_payload(&payload)?;
    let context = context(vault, record_id)?;
    let authenticator = keys.authenticate_local(generation, &context, &canonical)?;
    let record = LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        *vault.as_bytes(),
        FormatVersion::v1(),
        record_id,
        payload,
        authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )?;
    Ok(encode_local_state(&record)?)
}

fn verify_record(
    bytes: &[u8],
    expected_vault: VaultId,
    keys: &KeyCell,
    generation: u64,
) -> Result<VaultAvailability, StoreError> {
    let record = decode_local_state(bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    if record.vault_id() != expected_vault.as_bytes()
        || record.object_id() != &record_id(expected_vault)
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let context = context(expected_vault, *record.object_id())?;
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
    let (kind, payload_id, inner) = payload.into_parts();
    if kind != LocalRecordType::VaultAvailability
        || payload_id != *record.object_id()
        || payload_id != record_id(expected_vault)
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    decode_inner(&inner, expected_vault).map_err(|_| StoreError::LocalStateAuthenticationFailed)
}

fn decode_record_without_authentication(
    bytes: &[u8],
    expected_vault: VaultId,
) -> Result<VaultAvailability, StoreError> {
    let record = decode_local_state(bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    if record.vault_id() != expected_vault.as_bytes()
        || record.object_id() != &record_id(expected_vault)
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let payload =
        decode_local_state_payload(record.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)
            .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    let (kind, payload_id, inner) = payload.into_parts();
    if kind != LocalRecordType::VaultAvailability
        || payload_id != *record.object_id()
        || payload_id != record_id(expected_vault)
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    decode_inner(&inner, expected_vault).map_err(|_| StoreError::LocalStateAuthenticationFailed)
}

fn encode_inner(vault: VaultId, state: VaultAvailability) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    Encoder::new(&mut output)
        .array(3)
        .and_then(|encoder| encoder.u16(AVAILABILITY_VERSION))
        .and_then(|encoder| encoder.bytes(vault.as_bytes()))
        .and_then(|encoder| {
            encoder.u8(match state {
                VaultAvailability::Inactive => 0,
                VaultAvailability::Activating => 2,
                VaultAvailability::Active => 1,
            })
        })
        .map_err(|_| StoreError::MalformedObject)?;
    Ok(output)
}

fn decode_inner(bytes: &[u8], expected_vault: VaultId) -> Result<VaultAvailability, StoreError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| StoreError::MalformedObject)? != Some(3)
        || decoder.u16().map_err(|_| StoreError::MalformedObject)? != AVAILABILITY_VERSION
        || decoder.bytes().map_err(|_| StoreError::MalformedObject)? != expected_vault.as_bytes()
    {
        return Err(StoreError::MalformedObject);
    }
    let state = match decoder.u8().map_err(|_| StoreError::MalformedObject)? {
        0 => VaultAvailability::Inactive,
        1 => VaultAvailability::Active,
        2 => VaultAvailability::Activating,
        _ => return Err(StoreError::MalformedObject),
    };
    if decoder.position() != bytes.len() || encode_inner(expected_vault, state)? != bytes {
        return Err(StoreError::MalformedObject);
    }
    Ok(state)
}

fn context(vault: VaultId, record_id: [u8; 32]) -> Result<LocalStateContext, StoreError> {
    Ok(LocalStateContext::try_new(PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: *vault.as_bytes(),
        object_kind: LOCAL_STATE_OBJECT_KIND,
        format_version: 1,
        object_id: record_id,
    })?)
}

fn record_id(vault: VaultId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AVAILABILITY_RECORD_DOMAIN);
    hasher.update(vault.as_bytes());
    *hasher.finalize().as_bytes()
}
