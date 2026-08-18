use minicbor::{Decoder, Encoder};
use notecrypt_core::{ObjectId, SnapshotId, VaultId};
use notecrypt_crypto::{
    LOCAL_STATE_OBJECT_KIND, LocalStateAuthenticator, LocalStateContext, PublicEnvelopeIdentity,
};
use notecrypt_format::{
    AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits, FormatVersion, LocalRecordType,
    LocalStatePayload, LocalStateRecord, decode_local_state_payload, encode_local_state,
    encode_local_state_payload,
};

use crate::StoreError;
use crate::key_cell::KeyCell;
use crate::layout::{StoreLayout, component};
use crate::local_io::read_optional;
use crate::local_io::replace_durable;

const VERSION: u16 = 1;
const RECORD_ID_DOMAIN: &[u8] = b"notecrypt/trusted-remote-id/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustedRemoteProvenance {
    FreshnessProven,
    FreshnessUnprovableAcknowledged,
}

pub(crate) struct TrustedRemoteRecord {
    vault: VaultId,
    snapshot: SnapshotId,
    snapshot_object: ObjectId,
    head_commitment: [u8; 32],
    observation_commitment: [u8; 32],
    binding_commitment: [u8; 32],
    provenance: TrustedRemoteProvenance,
}

impl TrustedRemoteRecord {
    pub(crate) const fn new(
        vault: VaultId,
        snapshot: SnapshotId,
        snapshot_object: ObjectId,
        head_commitment: [u8; 32],
        observation_commitment: [u8; 32],
        binding_commitment: [u8; 32],
        provenance: TrustedRemoteProvenance,
    ) -> Self {
        Self {
            vault,
            snapshot,
            snapshot_object,
            head_commitment,
            observation_commitment,
            binding_commitment,
            provenance,
        }
    }

    #[cfg(test)]
    pub(crate) const fn provenance(&self) -> TrustedRemoteProvenance {
        self.provenance
    }

    fn record_id(&self) -> [u8; 32] {
        record_id(self.vault)
    }

    pub(crate) const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    pub(crate) const fn snapshot_object(&self) -> ObjectId {
        self.snapshot_object
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut output = Vec::new();
        Encoder::new(&mut output)
            .array(8)
            .and_then(|encoder| encoder.u16(VERSION))
            .and_then(|encoder| encoder.bytes(self.vault.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.snapshot.as_bytes()))
            .and_then(|encoder| encoder.bytes(self.snapshot_object.as_bytes()))
            .and_then(|encoder| encoder.bytes(&self.head_commitment))
            .and_then(|encoder| encoder.bytes(&self.observation_commitment))
            .and_then(|encoder| encoder.bytes(&self.binding_commitment))
            .and_then(|encoder| {
                encoder.u8(match self.provenance {
                    TrustedRemoteProvenance::FreshnessProven => 1,
                    TrustedRemoteProvenance::FreshnessUnprovableAcknowledged => 2,
                })
            })
            .map_err(|_| StoreError::MalformedObject)?;
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| StoreError::MalformedObject)? != Some(8)
            || decoder.u16().map_err(|_| StoreError::MalformedObject)? != VERSION
        {
            return Err(StoreError::MalformedObject);
        }
        let vault = VaultId::from_bytes(fixed(decoder.bytes().map_err(map_decode)?)?);
        let snapshot = SnapshotId::from_bytes(fixed(decoder.bytes().map_err(map_decode)?)?);
        let snapshot_object = ObjectId::from_bytes(fixed(decoder.bytes().map_err(map_decode)?)?);
        let head_commitment = fixed(decoder.bytes().map_err(map_decode)?)?;
        let observation_commitment = fixed(decoder.bytes().map_err(map_decode)?)?;
        let binding_commitment = fixed(decoder.bytes().map_err(map_decode)?)?;
        let provenance = match decoder.u8().map_err(map_decode)? {
            1 => TrustedRemoteProvenance::FreshnessProven,
            2 => TrustedRemoteProvenance::FreshnessUnprovableAcknowledged,
            _ => return Err(StoreError::MalformedObject),
        };
        if decoder.position() != bytes.len() {
            return Err(StoreError::MalformedObject);
        }
        let value = Self::new(
            vault,
            snapshot,
            snapshot_object,
            head_commitment,
            observation_commitment,
            binding_commitment,
            provenance,
        );
        if value.encode()? != bytes {
            return Err(StoreError::MalformedObject);
        }
        Ok(value)
    }
}

pub(crate) fn build_authenticated_trusted_remote(
    trusted: &TrustedRemoteRecord,
    keys: &KeyCell,
    generation: u64,
) -> Result<LocalStateRecord, StoreError> {
    let record_id = trusted.record_id();
    let payload = LocalStatePayload::try_new(
        LocalRecordType::TrustedRemote,
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

pub(crate) fn verify_authenticated_trusted_remote(
    record: &LocalStateRecord,
    keys: &KeyCell,
    generation: u64,
) -> Result<TrustedRemoteRecord, StoreError> {
    let result = (|| {
        let vault = VaultId::from_bytes(*record.vault_id());
        let expected_id = record_id(vault);
        let context = context(vault, *record.object_id())?;
        let authenticator = LocalStateAuthenticator::try_from_bytes(record.authenticator())?;
        keys.verify_local(
            generation,
            &context,
            record.untrusted_payload_bytes(),
            &authenticator,
        )?;
        let payload =
            decode_local_state_payload(record.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)?;
        let (record_type, payload_id, inner) = payload.into_parts();
        if record_type != LocalRecordType::TrustedRemote
            || payload_id != *record.object_id()
            || payload_id != expected_id
        {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        let trusted = TrustedRemoteRecord::decode(&inner)?;
        if trusted.vault != vault {
            return Err(StoreError::LocalStateAuthenticationFailed);
        }
        Ok(trusted)
    })();
    result.map_err(|_| StoreError::LocalStateAuthenticationFailed)
}

pub(crate) fn write_trusted_remote(
    layout: &StoreLayout,
    trusted: &TrustedRemoteRecord,
    keys: &KeyCell,
    generation: u64,
) -> Result<(), StoreError> {
    let record = build_authenticated_trusted_remote(trusted, keys, generation)?;
    let bytes = encode_local_state(&record)?;
    replace_durable(&layout.trusted_remote, &component("remote")?, &bytes)
}

pub(crate) fn authenticate_trusted_remote_if_present(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<Option<TrustedRemoteRecord>, StoreError> {
    let names = layout.trusted_remote.entry_names_bounded(1)?;
    if names.is_empty() {
        return Ok(None);
    }
    let expected = component("remote")?;
    if names.len() != 1 || names[0].as_str() != expected.as_str() {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let bytes = read_optional(&layout.trusted_remote, &expected)?
        .ok_or(StoreError::LocalStateAuthenticationFailed)?;
    let record = notecrypt_format::decode_local_state(&bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    Ok(Some(verify_authenticated_trusted_remote(
        &record, keys, generation,
    )?))
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
    hasher.update(RECORD_ID_DOMAIN);
    hasher.update(vault.as_bytes());
    *hasher.finalize().as_bytes()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::MalformedObject)
}

fn map_decode(_: minicbor::decode::Error) -> StoreError {
    StoreError::MalformedObject
}

#[cfg(test)]
mod tests {
    use notecrypt_crypto::{CryptoError, SecureRandom, VaultRootKey};

    use super::*;

    struct FixedRandom(u8);

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    fn provenance_and_complete_committed_binding_are_authenticated() {
        let vault = VaultId::from_bytes([0x31; 16]);
        let root = VaultRootKey::generate(&mut FixedRandom(0x32)).unwrap();
        let keys = KeyCell::new(root).unwrap();
        let trusted = TrustedRemoteRecord::new(
            vault,
            SnapshotId::from_bytes([0x33; 32]),
            ObjectId::from_bytes([0x35; 32]),
            [0x36; 32],
            [0x37; 32],
            [0x34; 32],
            TrustedRemoteProvenance::FreshnessUnprovableAcknowledged,
        );
        let record =
            build_authenticated_trusted_remote(&trusted, &keys, keys.generation()).unwrap();
        let verified =
            verify_authenticated_trusted_remote(&record, &keys, keys.generation()).unwrap();
        assert_eq!(verified.vault, vault);
        assert_eq!(verified.snapshot, SnapshotId::from_bytes([0x33; 32]));
        assert_eq!(verified.snapshot_object, ObjectId::from_bytes([0x35; 32]));
        assert_eq!(verified.head_commitment, [0x36; 32]);
        assert_eq!(verified.observation_commitment, [0x37; 32]);
        assert_eq!(verified.binding_commitment, [0x34; 32]);
        assert!(matches!(
            verified.provenance,
            TrustedRemoteProvenance::FreshnessUnprovableAcknowledged
        ));
    }
}
