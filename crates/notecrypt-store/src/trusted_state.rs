use minicbor::{Decoder, Encoder};
use notecrypt_core::{SnapshotId, VaultId};
use notecrypt_crypto::{
    LOCAL_STATE_OBJECT_KIND, LocalStateAuthenticator, LocalStateContext, PublicEnvelopeIdentity,
};
use notecrypt_format::{
    AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits, FormatVersion, LocalRecordType,
    LocalStatePayload, LocalStateRecord, decode_local_state_payload, encode_local_state_payload,
};

use crate::StoreError;
use crate::key_cell::KeyCell;

const TRUSTED_VERSION: u16 = 1;
const TRUSTED_HEAD_DOMAIN: &[u8] = b"notecrypt/trusted-head-id/v1";

pub(crate) struct TrustedHead {
    vault: VaultId,
    snapshot: SnapshotId,
    head_commitment: [u8; 32],
}

impl TrustedHead {
    pub(crate) const fn new(
        vault: VaultId,
        snapshot: SnapshotId,
        head_commitment: [u8; 32],
    ) -> Self {
        Self {
            vault,
            snapshot,
            head_commitment,
        }
    }

    pub(crate) const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    pub(crate) const fn head_commitment(&self) -> &[u8; 32] {
        &self.head_commitment
    }

    fn record_id(&self) -> [u8; 32] {
        trusted_record_id(self.vault)
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut output = Vec::new();
        Encoder::new(&mut output)
            .array(4)
            .and_then(|encoder| encoder.u16(TRUSTED_VERSION))
            .and_then(|encoder| encoder.bytes(self.vault.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.snapshot.as_bytes()))
            .and_then(|encoder| encoder.bytes(&self.head_commitment))
            .map_err(|_| StoreError::MalformedObject)?;
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| StoreError::MalformedObject)? != Some(4)
            || decoder.u16().map_err(|_| StoreError::MalformedObject)? != TRUSTED_VERSION
        {
            return Err(StoreError::MalformedObject);
        }
        let vault = VaultId::from_bytes(fixed(
            decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
        )?);
        let snapshot = SnapshotId::from_bytes(fixed(
            decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
        )?);
        let head_commitment = fixed(decoder.bytes().map_err(|_| StoreError::MalformedObject)?)?;
        if decoder.position() != bytes.len() {
            return Err(StoreError::MalformedObject);
        }
        let value = Self::new(vault, snapshot, head_commitment);
        if value.encode()? != bytes {
            return Err(StoreError::MalformedObject);
        }
        Ok(value)
    }
}

pub(crate) fn build_authenticated_trusted_head(
    trusted: &TrustedHead,
    keys: &KeyCell,
    generation: u64,
) -> Result<LocalStateRecord, StoreError> {
    let record_id = trusted.record_id();
    let payload = LocalStatePayload::try_new(
        LocalRecordType::TrustedHead,
        record_id,
        trusted.encode()?,
        &DecodeLimits::PHASE_1,
    )?;
    let canonical = encode_local_state_payload(&payload)?;
    let context = context(trusted.vault, record_id)?;
    let authenticator = keys.authenticate_local(generation, &context, &canonical)?;
    Ok(LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        *trusted.vault.as_bytes(),
        FormatVersion::v1(),
        record_id,
        payload,
        authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )?)
}

pub(crate) fn verify_authenticated_trusted_head(
    record: &LocalStateRecord,
    keys: &KeyCell,
    generation: u64,
) -> Result<TrustedHead, StoreError> {
    let vault = VaultId::from_bytes(*record.vault_id());
    let expected_record_id = trusted_record_id(vault);
    let context = context(vault, *record.object_id())?;
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
    if record_type != LocalRecordType::TrustedHead
        || payload_id != *record.object_id()
        || payload_id != expected_record_id
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let trusted =
        TrustedHead::decode(&inner).map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    if trusted.vault != vault {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    Ok(trusted)
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

fn trusted_record_id(vault: VaultId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRUSTED_HEAD_DOMAIN);
    hasher.update(vault.as_bytes());
    *hasher.finalize().as_bytes()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::MalformedObject)
}
