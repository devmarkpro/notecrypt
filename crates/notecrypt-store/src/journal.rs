use minicbor::{Decoder, Encoder};

use notecrypt_core::VaultId;
use notecrypt_crypto::{
    LOCAL_STATE_OBJECT_KIND, LocalStateAuthenticator, LocalStateContext, PublicEnvelopeIdentity,
};
#[cfg(test)]
use notecrypt_crypto::{LocalVerificationKey, verify_local_state};
use notecrypt_format::{
    AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits, FormatVersion, LocalRecordType,
    LocalStatePayload, LocalStateRecord, decode_local_state_payload, encode_local_state_payload,
};

use crate::StoreError;
use crate::key_cell::KeyCell;

const JOURNAL_VERSION: u16 = 1;
const MAX_EMBEDDED_HEAD_BYTES: usize = 48 * 1024;
const JOURNAL_DOMAIN: &[u8] = b"notecrypt/journal-id/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum JournalPhase {
    Intended = 1,
    Complete = 2,
}

pub(crate) struct JournalTransition {
    transaction_id: [u8; 16],
    vault: VaultId,
    session_generation: u64,
    prior_head_commitment: [u8; 32],
    intended_head: Vec<u8>,
    phase: JournalPhase,
}

impl JournalTransition {
    pub(crate) fn try_new(
        transaction_id: [u8; 16],
        vault: VaultId,
        session_generation: u64,
        prior_head_commitment: [u8; 32],
        intended_head: Vec<u8>,
        phase: JournalPhase,
    ) -> Result<Self, StoreError> {
        if intended_head.len() > MAX_EMBEDDED_HEAD_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        Ok(Self {
            transaction_id,
            vault,
            session_generation,
            prior_head_commitment,
            intended_head,
            phase,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut output = Vec::new();
        let mut encoder = Encoder::new(&mut output);
        encoder
            .array(9)
            .and_then(|encoder| encoder.u16(JOURNAL_VERSION))
            .and_then(|encoder| encoder.bytes(&self.transaction_id))
            .and_then(|encoder| encoder.bytes(self.vault.as_bytes()))
            .and_then(|encoder| encoder.u64(self.session_generation))
            .and_then(|encoder| encoder.bytes(&self.prior_head_commitment))
            .and_then(|encoder| encoder.u64(self.intended_head.len() as u64))
            .and_then(|encoder| encoder.bytes(&self.intended_head))
            .and_then(|encoder| encoder.bytes(blake3::hash(&self.intended_head).as_bytes()))
            .and_then(|encoder| encoder.u8(self.phase as u8))
            .map_err(|_| StoreError::MalformedObject)?;
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_EMBEDDED_HEAD_BYTES + 256 {
            return Err(StoreError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| StoreError::MalformedObject)? != Some(9)
            || decoder.u16().map_err(|_| StoreError::MalformedObject)? != JOURNAL_VERSION
        {
            return Err(StoreError::MalformedObject);
        }
        let transaction_id = fixed(decoder.bytes().map_err(|_| StoreError::MalformedObject)?)?;
        let vault = VaultId::from_bytes(fixed(
            decoder.bytes().map_err(|_| StoreError::MalformedObject)?,
        )?);
        let session_generation = decoder.u64().map_err(|_| StoreError::MalformedObject)?;
        let prior_head_commitment =
            fixed(decoder.bytes().map_err(|_| StoreError::MalformedObject)?)?;
        let declared = decoder.u64().map_err(|_| StoreError::MalformedObject)?;
        let head = decoder.bytes().map_err(|_| StoreError::MalformedObject)?;
        if declared != head.len() as u64 || head.len() > MAX_EMBEDDED_HEAD_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut intended_head = Vec::new();
        intended_head
            .try_reserve_exact(head.len())
            .map_err(|_| StoreError::LimitExceeded)?;
        intended_head.extend_from_slice(head);
        let commitment: [u8; 32] =
            fixed(decoder.bytes().map_err(|_| StoreError::MalformedObject)?)?;
        if commitment != *blake3::hash(&intended_head).as_bytes() {
            return Err(StoreError::AuthenticationFailed);
        }
        let phase = match decoder.u8().map_err(|_| StoreError::MalformedObject)? {
            1 => JournalPhase::Intended,
            2 => JournalPhase::Complete,
            _ => return Err(StoreError::MalformedObject),
        };
        if decoder.position() != bytes.len() {
            return Err(StoreError::MalformedObject);
        }
        let transition = Self::try_new(
            transaction_id,
            vault,
            session_generation,
            prior_head_commitment,
            intended_head,
            phase,
        )?;
        if transition.encode()? != bytes {
            return Err(StoreError::MalformedObject);
        }
        Ok(transition)
    }

    pub(crate) fn record_id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(JOURNAL_DOMAIN);
        hasher.update(&self.transaction_id);
        *hasher.finalize().as_bytes()
    }

    pub(crate) fn with_phase(&self, phase: JournalPhase) -> Result<Self, StoreError> {
        Self::try_new(
            self.transaction_id,
            self.vault,
            self.session_generation,
            self.prior_head_commitment,
            self.intended_head.clone(),
            phase,
        )
    }

    pub(crate) fn intended_head(&self) -> &[u8] {
        &self.intended_head
    }

    pub(crate) const fn prior_head_commitment(&self) -> &[u8; 32] {
        &self.prior_head_commitment
    }

    pub(crate) const fn phase(&self) -> JournalPhase {
        self.phase
    }

    pub(crate) const fn vault(&self) -> VaultId {
        self.vault
    }

    pub(crate) const fn session_generation(&self) -> u64 {
        self.session_generation
    }
}

pub(crate) fn build_authenticated_journal(
    transition: &JournalTransition,
    keys: &KeyCell,
    expected_generation: u64,
) -> Result<LocalStateRecord, StoreError> {
    let record_id = transition.record_id();
    let payload = LocalStatePayload::try_new(
        LocalRecordType::Journal,
        record_id,
        transition.encode()?,
        &DecodeLimits::PHASE_1,
    )?;
    let canonical = encode_local_state_payload(&payload)?;
    let context = LocalStateContext::try_new(PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: *transition.vault.as_bytes(),
        object_kind: LOCAL_STATE_OBJECT_KIND,
        format_version: 1,
        object_id: record_id,
    })?;
    let authenticator = keys.authenticate_local(expected_generation, &context, &canonical)?;
    Ok(LocalStateRecord::try_new(
        CryptoProfileId::profile_one(),
        AuthenticationAlgorithmId::keyed_blake3_256(),
        *transition.vault.as_bytes(),
        FormatVersion::v1(),
        record_id,
        payload,
        authenticator.as_bytes(),
        &DecodeLimits::PHASE_1,
    )?)
}

pub(crate) fn verify_authenticated_journal_with_cell(
    record: &LocalStateRecord,
    keys: &KeyCell,
    expected_generation: u64,
) -> Result<JournalTransition, StoreError> {
    (|| {
        let (context, authenticator) = journal_authentication_parts(record)?;
        keys.verify_local(
            expected_generation,
            &context,
            record.untrusted_payload_bytes(),
            &authenticator,
        )?;
        decode_verified_journal(record)
    })()
    .map_err(|_| StoreError::LocalStateAuthenticationFailed)
}

#[cfg(test)]
pub(crate) fn verify_authenticated_journal(
    record: &LocalStateRecord,
    key: &LocalVerificationKey,
) -> Result<JournalTransition, StoreError> {
    (|| {
        let (context, authenticator) = journal_authentication_parts(record)?;
        verify_local_state(
            &context,
            record.untrusted_payload_bytes(),
            &authenticator,
            key,
        )?;
        decode_verified_journal(record)
    })()
    .map_err(|_| StoreError::LocalStateAuthenticationFailed)
}

fn journal_authentication_parts(
    record: &LocalStateRecord,
) -> Result<(LocalStateContext, LocalStateAuthenticator), StoreError> {
    let context = LocalStateContext::try_new(PublicEnvelopeIdentity {
        profile_id: record.profile_id().get(),
        vault_id: *record.vault_id(),
        object_kind: LOCAL_STATE_OBJECT_KIND,
        format_version: record.version().get(),
        object_id: *record.object_id(),
    })?;
    let authenticator = LocalStateAuthenticator::try_from_bytes(record.authenticator())?;
    Ok((context, authenticator))
}

fn decode_verified_journal(record: &LocalStateRecord) -> Result<JournalTransition, StoreError> {
    let payload =
        decode_local_state_payload(record.untrusted_payload_bytes(), &DecodeLimits::PHASE_1)?;
    let (record_type, payload_record_id, bytes) = payload.into_parts();
    if record_type != LocalRecordType::Journal || payload_record_id != *record.object_id() {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    let transition = JournalTransition::decode(&bytes)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    if transition.vault.as_bytes() != record.vault_id()
        || transition.record_id() != payload_record_id
    {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    Ok(transition)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::MalformedObject)
}

#[cfg(test)]
mod tests {
    use notecrypt_crypto::{
        CryptoError, SecureRandom, VaultRootKey, authenticate_local_state, derive_vault_keys,
    };
    use notecrypt_format::{
        AuthenticationAlgorithmId, CryptoProfileId, FormatVersion, LocalStatePayload,
        encode_local_state,
    };

    use super::*;

    #[test]
    fn journal_inner_schema_is_canonical_bounded_and_commitment_checked() {
        let transition = JournalTransition::try_new(
            [1; 16],
            VaultId::from_bytes([2; 16]),
            3,
            [4; 32],
            b"authenticated-head".to_vec(),
            JournalPhase::Intended,
        )
        .unwrap();
        let bytes = transition.encode().unwrap();
        let decoded = JournalTransition::decode(&bytes).unwrap();
        assert_eq!(decoded.transaction_id, [1; 16]);
        assert_eq!(decoded.record_id(), transition.record_id());

        let mut tampered = bytes;
        let index = tampered.len() - 10;
        tampered[index] ^= 1;
        assert!(JournalTransition::decode(&tampered).is_err());
        assert!(matches!(
            JournalTransition::try_new(
                [1; 16],
                VaultId::from_bytes([2; 16]),
                3,
                [4; 32],
                vec![0; MAX_EMBEDDED_HEAD_BYTES + 1],
                JournalPhase::Intended,
            ),
            Err(StoreError::LimitExceeded)
        ));
    }

    #[test]
    fn complete_outer_journal_is_bounded_and_all_identity_layers_are_bound() {
        struct FixedRandom;
        impl SecureRandom for FixedRandom {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
                output.fill(9);
                Ok(())
            }
        }
        let root = VaultRootKey::generate(&mut FixedRandom).unwrap();
        let keys = derive_vault_keys(&root).unwrap();
        let vault = VaultId::from_bytes([1; 16]);
        let transition = JournalTransition::try_new(
            [1; 16],
            vault,
            4,
            [2; 32],
            vec![3; MAX_EMBEDDED_HEAD_BYTES],
            JournalPhase::Intended,
        )
        .unwrap();
        let record_id = transition.record_id();
        let inner = transition.encode().unwrap();
        let payload = LocalStatePayload::try_new(
            LocalRecordType::Journal,
            record_id,
            inner,
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let canonical = notecrypt_format::encode_local_state_payload(&payload).unwrap();
        let context = LocalStateContext::try_new(PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: LOCAL_STATE_OBJECT_KIND,
            format_version: 1,
            object_id: record_id,
        })
        .unwrap();
        let authenticator =
            authenticate_local_state(&context, &canonical, &keys.local_verification).unwrap();
        let record = LocalStateRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            *vault.as_bytes(),
            FormatVersion::v1(),
            record_id,
            payload,
            authenticator.as_bytes(),
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        assert!(encode_local_state(&record).unwrap().len() <= 64 * 1024);
        assert!(verify_authenticated_journal(&record, &keys.local_verification).is_ok());

        let wrong_outer_vault = authenticated_record(
            VaultId::from_bytes([8; 16]),
            record_id,
            record_id,
            transition.encode().unwrap(),
            &keys.local_verification,
        );
        assert!(matches!(
            verify_authenticated_journal(&wrong_outer_vault, &keys.local_verification),
            Err(StoreError::LocalStateAuthenticationFailed)
        ));

        let wrong_outer_id = authenticated_record(
            vault,
            [7; 32],
            record_id,
            transition.encode().unwrap(),
            &keys.local_verification,
        );
        assert!(matches!(
            verify_authenticated_journal(&wrong_outer_id, &keys.local_verification),
            Err(StoreError::LocalStateAuthenticationFailed)
        ));

        let wrong_payload_id = authenticated_record(
            vault,
            record_id,
            [6; 32],
            transition.encode().unwrap(),
            &keys.local_verification,
        );
        assert!(matches!(
            verify_authenticated_journal(&wrong_payload_id, &keys.local_verification),
            Err(StoreError::LocalStateAuthenticationFailed)
        ));

        let different_transaction = JournalTransition::try_new(
            [5; 16],
            vault,
            4,
            [2; 32],
            vec![3; MAX_EMBEDDED_HEAD_BYTES],
            JournalPhase::Intended,
        )
        .unwrap();
        let wrong_inner_transaction = authenticated_record(
            vault,
            record_id,
            record_id,
            different_transaction.encode().unwrap(),
            &keys.local_verification,
        );
        assert!(matches!(
            verify_authenticated_journal(&wrong_inner_transaction, &keys.local_verification),
            Err(StoreError::LocalStateAuthenticationFailed)
        ));
    }

    fn authenticated_record(
        vault: VaultId,
        outer_id: [u8; 32],
        payload_id: [u8; 32],
        inner: Vec<u8>,
        key: &LocalVerificationKey,
    ) -> LocalStateRecord {
        let payload = LocalStatePayload::try_new(
            LocalRecordType::Journal,
            payload_id,
            inner,
            &DecodeLimits::PHASE_1,
        )
        .unwrap();
        let canonical = notecrypt_format::encode_local_state_payload(&payload).unwrap();
        let context = LocalStateContext::try_new(PublicEnvelopeIdentity {
            profile_id: 1,
            vault_id: *vault.as_bytes(),
            object_kind: LOCAL_STATE_OBJECT_KIND,
            format_version: 1,
            object_id: outer_id,
        })
        .unwrap();
        let authenticator = authenticate_local_state(&context, &canonical, key).unwrap();
        LocalStateRecord::try_new(
            CryptoProfileId::profile_one(),
            AuthenticationAlgorithmId::keyed_blake3_256(),
            *vault.as_bytes(),
            FormatVersion::v1(),
            outer_id,
            payload,
            authenticator.as_bytes(),
            &DecodeLimits::PHASE_1,
        )
        .unwrap()
    }
}
