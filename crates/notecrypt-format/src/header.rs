use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};

use crate::object::{
    CanonicalCompareWriter, CountingWriter, check_input_bound, encode_aead_to, finish, fixed_bytes,
    output_buffer, require_array, require_depth,
};
use crate::{
    AeadAlgorithmId, AeadObject, AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits,
    DerivationProfileId, FingerprintAlgorithmId, FormatError, FormatVersion, KdfProfileId,
    ObjectKind,
};

const MAGIC: &[u8; 9] = b"NOTECRYPT";
const ARGON2_MIN_MEMORY_KIB: u32 = 65_536;
const ARGON2_MAX_MEMORY_KIB: u32 = 1_048_576;
const ARGON2_MIN_ITERATIONS: u32 = 3;
const ARGON2_MAX_ITERATIONS: u32 = 10;
const ARGON2_MIN_LANES: u32 = 1;
const ARGON2_MAX_LANES: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoSuite {
    profile: CryptoProfileId,
    aead: AeadAlgorithmId,
    authentication: AuthenticationAlgorithmId,
    fingerprint: FingerprintAlgorithmId,
    kdf: KdfProfileId,
    derivation: DerivationProfileId,
}

impl CryptoSuite {
    #[must_use]
    pub const fn profile_one() -> Self {
        Self {
            profile: CryptoProfileId::profile_one(),
            aead: AeadAlgorithmId::xchacha20_poly1305(),
            authentication: AuthenticationAlgorithmId::keyed_blake3_256(),
            fingerprint: FingerprintAlgorithmId::keyed_blake3_256(),
            kdf: KdfProfileId::argon2id_v1(),
            derivation: DerivationProfileId::hkdf_sha256_v1(),
        }
    }

    #[must_use]
    pub const fn profile_id(self) -> CryptoProfileId {
        self.profile
    }
    #[must_use]
    pub const fn aead_algorithm_id(self) -> AeadAlgorithmId {
        self.aead
    }
    #[must_use]
    pub const fn authentication_algorithm_id(self) -> AuthenticationAlgorithmId {
        self.authentication
    }
    #[must_use]
    pub const fn fingerprint_algorithm_id(self) -> FingerprintAlgorithmId {
        self.fingerprint
    }
    #[must_use]
    pub const fn kdf_profile_id(self) -> KdfProfileId {
        self.kdf
    }
    #[must_use]
    pub const fn derivation_profile_id(self) -> DerivationProfileId {
        self.derivation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParameters {
    profile: KdfProfileId,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: [u8; 16],
}

impl KdfParameters {
    pub fn try_new(
        profile: KdfProfileId,
        memory_kib: u32,
        iterations: u32,
        lanes: u32,
        salt: &[u8],
    ) -> Result<Self, FormatError> {
        if !(ARGON2_MIN_MEMORY_KIB..=ARGON2_MAX_MEMORY_KIB).contains(&memory_kib)
            || !(ARGON2_MIN_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&iterations)
            || !(ARGON2_MIN_LANES..=ARGON2_MAX_LANES).contains(&lanes)
            || memory_kib == u32::MAX
            || iterations == u32::MAX
            || lanes == u32::MAX
            || salt.len() != 16
        {
            return Err(FormatError::LimitExceeded);
        }
        let memory_bytes = u64::from(memory_kib)
            .checked_mul(1024)
            .ok_or(FormatError::Overflow)?;
        usize::try_from(memory_bytes).map_err(|_| FormatError::Overflow)?;
        let mut checked_salt = [0; 16];
        checked_salt.copy_from_slice(salt);
        Ok(Self {
            profile,
            memory_kib,
            iterations,
            lanes,
            salt: checked_salt,
        })
    }

    #[must_use]
    pub const fn profile_id(&self) -> KdfProfileId {
        self.profile
    }
    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }
    #[must_use]
    pub const fn lanes(&self) -> u32 {
        self.lanes
    }
    #[must_use]
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RecoverySlot(AeadObject);

impl RecoverySlot {
    pub fn try_new(envelope: AeadObject) -> Result<Self, FormatError> {
        if envelope.kind().object_kind() != ObjectKind::RecoverySlot {
            return Err(FormatError::UnsupportedObjectKind);
        }
        Ok(Self(envelope))
    }
    #[must_use]
    pub const fn envelope(&self) -> &AeadObject {
        &self.0
    }
    #[must_use]
    pub fn into_envelope(self) -> AeadObject {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BootstrapHeader {
    version: FormatVersion,
    suite: CryptoSuite,
    vault_id: [u8; 16],
    kdf: KdfParameters,
    recovery_slots: Vec<RecoverySlot>,
}

impl BootstrapHeader {
    pub fn try_new(
        version: FormatVersion,
        suite: CryptoSuite,
        vault_id: [u8; 16],
        kdf: KdfParameters,
        recovery_slots: Vec<RecoverySlot>,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if recovery_slots.len() != 1 || limits.max_recovery_slots != 1 {
            return Err(FormatError::LimitExceeded);
        }
        if suite.kdf_profile_id() != kdf.profile_id()
            || recovery_slots.iter().any(|slot| {
                slot.envelope().profile_id() != suite.profile_id()
                    || slot.envelope().algorithm_id() != suite.aead_algorithm_id()
                    || slot.envelope().vault_id() != &vault_id
            })
        {
            return Err(FormatError::UnsupportedCryptoIdentifier);
        }
        Ok(Self {
            version,
            suite,
            vault_id,
            kdf,
            recovery_slots,
        })
    }
    #[must_use]
    pub const fn version(&self) -> FormatVersion {
        self.version
    }
    #[must_use]
    pub const fn suite(&self) -> CryptoSuite {
        self.suite
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    #[must_use]
    pub const fn kdf(&self) -> &KdfParameters {
        &self.kdf
    }
    #[must_use]
    pub fn recovery_slots(&self) -> &[RecoverySlot] {
        &self.recovery_slots
    }
}

pub fn encode_bootstrap(value: &BootstrapHeader) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_bootstrap_to(&mut Encoder::new(&mut counter), value)?;
    let mut encoder = Encoder::new(output_buffer(
        counter.length()?,
        DecodeLimits::PHASE_1.max_header_bytes,
    )?);
    encode_bootstrap_to(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

fn encode_bootstrap_to<W: Write>(
    encoder: &mut Encoder<W>,
    value: &BootstrapHeader,
) -> Result<(), FormatError> {
    encoder.array(6)?;
    encoder.bytes(MAGIC)?;
    encoder.u16(value.version.get())?;
    encode_suite(encoder, value.suite)?;
    encoder.bytes(&value.vault_id)?;
    encode_kdf(encoder, &value.kdf)?;
    encoder.array(1)?;
    let mut slot_counter = CountingWriter::default();
    encode_aead_to(
        &mut Encoder::new(&mut slot_counter),
        value.recovery_slots[0].envelope(),
    )?;
    encoder.bytes_len(u64::try_from(slot_counter.length()?).map_err(|_| FormatError::Overflow)?)?;
    encode_aead_to(encoder, value.recovery_slots[0].envelope())?;
    Ok(())
}

pub fn decode_bootstrap(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<BootstrapHeader, FormatError> {
    require_depth(limits, 3)?;
    check_input_bound(
        bytes,
        u64::try_from(limits.max_header_bytes).map_err(|_| FormatError::Overflow)?,
    )?;
    let mut decoder = Decoder::new(bytes);
    require_array(&mut decoder, 6)?;
    if decoder.bytes()? != MAGIC {
        return Err(FormatError::Malformed);
    }
    let version = FormatVersion::try_from(decoder.u16()?)?;
    let suite = decode_suite(&mut decoder)?;
    let vault_id = fixed_bytes::<16>(decoder.bytes()?)?;
    let kdf = decode_kdf(&mut decoder)?;
    let count = decoder.array()?.ok_or(FormatError::NonCanonical)?;
    if count != 1 || limits.max_recovery_slots != 1 {
        return Err(FormatError::LimitExceeded);
    }
    let count = usize::try_from(count).map_err(|_| FormatError::Overflow)?;
    let allocation = count
        .checked_mul(std::mem::size_of::<RecoverySlot>())
        .ok_or(FormatError::Overflow)?;
    let aggregate = allocation.checked_add(32).ok_or(FormatError::Overflow)?;
    if aggregate > limits.max_aggregate_allocation_bytes {
        return Err(FormatError::LimitExceeded);
    }
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| FormatError::AllocationFailed)?;
    for _ in 0..count {
        slots.push(RecoverySlot::try_new(crate::decode_aead_object(
            decoder.bytes()?,
            limits,
        )?)?);
    }
    finish(&decoder, bytes)?;
    let value = BootstrapHeader::try_new(version, suite, vault_id, kdf, slots, limits)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_bootstrap_to(&mut Encoder::new(&mut writer), &value)?;
    writer.finish()?;
    Ok(value)
}

fn encode_suite<W: Write>(encoder: &mut Encoder<W>, suite: CryptoSuite) -> Result<(), FormatError> {
    encoder.array(6)?;
    encoder.u16(suite.profile_id().get())?;
    encoder.u16(suite.aead_algorithm_id().get())?;
    encoder.u16(suite.authentication_algorithm_id().get())?;
    encoder.u16(suite.fingerprint_algorithm_id().get())?;
    encoder.u16(suite.kdf_profile_id().get())?;
    encoder.u16(suite.derivation_profile_id().get())?;
    Ok(())
}

fn decode_suite(decoder: &mut Decoder<'_>) -> Result<CryptoSuite, FormatError> {
    require_array(decoder, 6)?;
    CryptoProfileId::try_from(decoder.u16()?)?;
    AeadAlgorithmId::try_from(decoder.u16()?)?;
    AuthenticationAlgorithmId::try_from(decoder.u16()?)?;
    FingerprintAlgorithmId::try_from(decoder.u16()?)?;
    KdfProfileId::try_from(decoder.u16()?)?;
    DerivationProfileId::try_from(decoder.u16()?)?;
    Ok(CryptoSuite::profile_one())
}

fn encode_kdf<W: Write>(
    encoder: &mut Encoder<W>,
    value: &KdfParameters,
) -> Result<(), FormatError> {
    encoder.array(5)?;
    encoder.u16(value.profile.get())?;
    encoder.u32(value.memory_kib)?;
    encoder.u32(value.iterations)?;
    encoder.u32(value.lanes)?;
    encoder.bytes(&value.salt)?;
    Ok(())
}

fn decode_kdf(decoder: &mut Decoder<'_>) -> Result<KdfParameters, FormatError> {
    require_array(decoder, 5)?;
    let profile = KdfProfileId::try_from(decoder.u16()?)?;
    let memory = decoder.u32()?;
    let iterations = decoder.u32()?;
    let lanes = decoder.u32()?;
    let salt = decoder.bytes()?;
    KdfParameters::try_new(profile, memory, iterations, lanes, salt)
}
