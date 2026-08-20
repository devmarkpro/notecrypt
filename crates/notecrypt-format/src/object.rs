use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};

use crate::{
    AeadAlgorithmId, AuthenticationAlgorithmId, CryptoProfileId, DecodeLimits, FormatError,
    FormatVersion, HeadPayload, LocalStatePayload, ObjectKind, OrdinaryAeadKind,
    encode_head_payload, encode_local_state_payload,
};
use zeroize::Zeroize;

const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const CHUNK_KEY_BYTES: usize = 32;
const MAX_METADATA_BYTES: usize = 1_048_576;
const MAX_TREE_BYTES: usize = 268_435_456;
const MAX_MANIFEST_BYTES: usize = 67_108_864;

#[derive(PartialEq, Eq)]
pub struct AeadObject {
    profile_id: CryptoProfileId,
    algorithm_id: AeadAlgorithmId,
    vault_id: [u8; 16],
    kind: OrdinaryAeadKind,
    format_version: FormatVersion,
    object_id: [u8; 32],
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_BYTES],
}
impl std::fmt::Debug for AeadObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AeadObject")
            .field("profile_id", &self.profile_id)
            .field("algorithm_id", &self.algorithm_id)
            .field("kind", &self.kind)
            .field("format_version", &self.format_version)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Owned, already-validated public wire fields for a consuming crypto bridge.
pub struct AeadObjectParts {
    profile_id: CryptoProfileId,
    algorithm_id: AeadAlgorithmId,
    vault_id: [u8; 16],
    kind: OrdinaryAeadKind,
    format_version: FormatVersion,
    object_id: [u8; 32],
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_BYTES],
}

impl AeadObjectParts {
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_components(
        self,
    ) -> (
        CryptoProfileId,
        AeadAlgorithmId,
        [u8; 16],
        OrdinaryAeadKind,
        FormatVersion,
        [u8; 32],
        [u8; NONCE_BYTES],
        Vec<u8>,
        [u8; TAG_BYTES],
    ) {
        (
            self.profile_id,
            self.algorithm_id,
            self.vault_id,
            self.kind,
            self.format_version,
            self.object_id,
            self.nonce,
            self.ciphertext,
            self.tag,
        )
    }
}

impl AeadObject {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        profile_id: CryptoProfileId,
        algorithm_id: AeadAlgorithmId,
        vault_id: [u8; 16],
        kind: OrdinaryAeadKind,
        format_version: FormatVersion,
        object_id: [u8; 32],
        nonce: &[u8],
        ciphertext: Vec<u8>,
        tag: &[u8],
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if nonce.len() != NONCE_BYTES || tag.len() != TAG_BYTES {
            return Err(FormatError::InvalidLength);
        }
        validate_aead_ciphertext(kind, ciphertext.len(), limits)?;
        let mut checked_nonce = [0; NONCE_BYTES];
        checked_nonce.copy_from_slice(nonce);
        let mut checked_tag = [0; TAG_BYTES];
        checked_tag.copy_from_slice(tag);
        Ok(Self {
            profile_id,
            algorithm_id,
            vault_id,
            kind,
            format_version,
            object_id,
            nonce: checked_nonce,
            ciphertext,
            tag: checked_tag,
        })
    }

    #[must_use]
    pub const fn profile_id(&self) -> CryptoProfileId {
        self.profile_id
    }
    #[must_use]
    pub const fn algorithm_id(&self) -> AeadAlgorithmId {
        self.algorithm_id
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    #[must_use]
    pub const fn kind(&self) -> OrdinaryAeadKind {
        self.kind
    }
    #[must_use]
    pub const fn format_version(&self) -> FormatVersion {
        self.format_version
    }
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    #[must_use]
    pub const fn tag(&self) -> &[u8; TAG_BYTES] {
        &self.tag
    }
    #[must_use]
    pub fn into_parts(self) -> AeadObjectParts {
        AeadObjectParts {
            profile_id: self.profile_id,
            algorithm_id: self.algorithm_id,
            vault_id: self.vault_id,
            kind: self.kind,
            format_version: self.format_version,
            object_id: self.object_id,
            nonce: self.nonce,
            ciphertext: self.ciphertext,
            tag: self.tag,
        }
    }
}

pub fn encode_aead_object(value: &AeadObject) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_aead_to(&mut Encoder::new(&mut counter), value)?;
    let mut encoder = Encoder::new(output_buffer(
        counter.length()?,
        DecodeLimits::PHASE_1.max_aggregate_allocation_bytes,
    )?);
    encode_aead_to(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

pub fn decode_aead_object(bytes: &[u8], limits: &DecodeLimits) -> Result<AeadObject, FormatError> {
    require_depth(limits, 1)?;
    check_input_bound(bytes, limits.max_object_bytes)?;
    let mut decoder = Decoder::new(bytes);
    require_array(&mut decoder, 10)?;
    let profile_id = CryptoProfileId::try_from(decoder.u16()?)?;
    let algorithm_id = AeadAlgorithmId::try_from(decoder.u16()?)?;
    let vault_id = fixed_bytes::<16>(decoder.bytes()?)?;
    let kind = OrdinaryAeadKind::try_from(ObjectKind::try_from(decoder.u8()?)?)?;
    let version = FormatVersion::try_from(decoder.u16()?)?;
    let object_id = fixed_bytes::<32>(decoder.bytes()?)?;
    let nonce = fixed_bytes::<NONCE_BYTES>(decoder.bytes()?)?;
    let declared_length = decoder.u64()?;
    let ciphertext_bytes = decoder.bytes()?;
    let actual_length = u64::try_from(ciphertext_bytes.len()).map_err(|_| FormatError::Overflow)?;
    if declared_length != actual_length {
        return Err(FormatError::LengthMismatch);
    }
    validate_aead_ciphertext(kind, ciphertext_bytes.len(), limits)?;
    let ciphertext = copy_bounded(ciphertext_bytes, limits)?;
    let tag = fixed_bytes::<TAG_BYTES>(decoder.bytes()?)?;
    finish(&decoder, bytes)?;
    let value = AeadObject::try_new(
        profile_id,
        algorithm_id,
        vault_id,
        kind,
        version,
        object_id,
        &nonce,
        ciphertext,
        &tag,
        limits,
    )?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_aead_to(&mut Encoder::new(&mut writer), &value)?;
    writer.finish()?;
    Ok(value)
}

pub(crate) fn encode_aead_to<W: Write>(
    encoder: &mut Encoder<W>,
    value: &AeadObject,
) -> Result<(), FormatError> {
    encoder
        .array(10)?
        .u16(value.profile_id.get())?
        .u16(value.algorithm_id.get())?
        .bytes(&value.vault_id)?
        .u8(value.kind.object_kind().get())?
        .u16(value.format_version.get())?
        .bytes(&value.object_id)?
        .bytes(&value.nonce)?
        .u64(u64::try_from(value.ciphertext.len()).map_err(|_| FormatError::Overflow)?)?
        .bytes(&value.ciphertext)?
        .bytes(&value.tag)?;
    Ok(())
}

pub(crate) fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), FormatError> {
    match decoder.array()? {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(FormatError::Malformed),
        None => Err(FormatError::NonCanonical),
    }
}

pub(crate) fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], FormatError> {
    bytes.try_into().map_err(|_| FormatError::InvalidLength)
}

pub(crate) fn finish(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), FormatError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(FormatError::TrailingBytes)
    }
}

pub(crate) fn check_input_bound(bytes: &[u8], maximum: u64) -> Result<(), FormatError> {
    if u64::try_from(bytes.len()).map_err(|_| FormatError::Overflow)? > maximum {
        Err(FormatError::LimitExceeded)
    } else {
        Ok(())
    }
}

pub(crate) fn copy_bounded(bytes: &[u8], limits: &DecodeLimits) -> Result<Vec<u8>, FormatError> {
    if bytes.len() > limits.max_aggregate_allocation_bytes {
        return Err(FormatError::LimitExceeded);
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| FormatError::AllocationFailed)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

pub(crate) fn output_buffer(capacity: usize, maximum: usize) -> Result<Vec<u8>, FormatError> {
    if capacity > maximum {
        return Err(FormatError::LimitExceeded);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| FormatError::AllocationFailed)?;
    Ok(output)
}

pub(crate) fn require_depth(limits: &DecodeLimits, required: u8) -> Result<(), FormatError> {
    if limits.max_recursion_depth < required {
        Err(FormatError::LimitExceeded)
    } else {
        Ok(())
    }
}

pub(crate) struct CanonicalCompareWriter<'a> {
    expected: &'a [u8],
    position: usize,
    mismatch: bool,
}

impl<'a> CanonicalCompareWriter<'a> {
    pub(crate) const fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            position: 0,
            mismatch: false,
        }
    }
    pub(crate) fn finish(self) -> Result<(), FormatError> {
        if !self.mismatch && self.position == self.expected.len() {
            Ok(())
        } else {
            Err(FormatError::NonCanonical)
        }
    }
}

impl Write for CanonicalCompareWriter<'_> {
    type Error = std::convert::Infallible;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let end = self.position.checked_add(bytes.len());
        match end.and_then(|end| self.expected.get(self.position..end)) {
            Some(expected) if expected == bytes => {}
            _ => self.mismatch = true,
        }
        self.position = end.unwrap_or(usize::MAX);
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct CountingWriter {
    length: usize,
    overflowed: bool,
}
impl CountingWriter {
    pub(crate) const fn length(&self) -> Result<usize, FormatError> {
        if self.overflowed {
            Err(FormatError::Overflow)
        } else {
            Ok(self.length)
        }
    }
}
impl Write for CountingWriter {
    type Error = std::convert::Infallible;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        match self.length.checked_add(bytes.len()) {
            Some(v) => self.length = v,
            None => self.overflowed = true,
        }
        Ok(())
    }
}

fn validate_aead_ciphertext(
    kind: OrdinaryAeadKind,
    length: usize,
    limits: &DecodeLimits,
) -> Result<(), FormatError> {
    let valid = match kind {
        OrdinaryAeadKind::RecoverySlot | OrdinaryAeadKind::DeviceSlot => length == CHUNK_KEY_BYTES,
        OrdinaryAeadKind::Metadata => length <= MAX_METADATA_BYTES,
        OrdinaryAeadKind::Tree => {
            length
                <= usize::try_from(limits.max_tree_bytes)
                    .map_err(|_| FormatError::Overflow)?
                    .min(MAX_TREE_BYTES)
        }
        OrdinaryAeadKind::Manifest => {
            length
                <= usize::try_from(limits.max_manifest_bytes)
                    .map_err(|_| FormatError::Overflow)?
                    .min(MAX_MANIFEST_BYTES)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(FormatError::LimitExceeded)
    }
}

#[derive(PartialEq, Eq)]
pub struct SnapshotObject {
    profile: CryptoProfileId,
    aead: AeadAlgorithmId,
    authentication: AuthenticationAlgorithmId,
    vault_id: [u8; 16],
    version: FormatVersion,
    object_id: [u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
    outer_authenticator: [u8; 32],
}
pub struct SnapshotObjectParts {
    profile: CryptoProfileId,
    aead: AeadAlgorithmId,
    authentication: AuthenticationAlgorithmId,
    vault_id: [u8; 16],
    version: FormatVersion,
    object_id: [u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
    outer_authenticator: [u8; 32],
}
impl SnapshotObjectParts {
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_components(
        self,
    ) -> (
        CryptoProfileId,
        AeadAlgorithmId,
        AuthenticationAlgorithmId,
        [u8; 16],
        FormatVersion,
        [u8; 32],
        [u8; 24],
        Vec<u8>,
        [u8; 16],
        [u8; 32],
    ) {
        (
            self.profile,
            self.aead,
            self.authentication,
            self.vault_id,
            self.version,
            self.object_id,
            self.nonce,
            self.ciphertext,
            self.tag,
            self.outer_authenticator,
        )
    }
}
impl SnapshotObject {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        profile: CryptoProfileId,
        aead: AeadAlgorithmId,
        authentication: AuthenticationAlgorithmId,
        vault_id: [u8; 16],
        version: FormatVersion,
        object_id: [u8; 32],
        nonce: &[u8],
        ciphertext: Vec<u8>,
        tag: &[u8],
        outer: &[u8],
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if nonce.len() != 24
            || tag.len() != 16
            || outer.len() != 32
            || ciphertext.len()
                > usize::try_from(limits.max_snapshot_bytes).map_err(|_| FormatError::Overflow)?
        {
            return Err(FormatError::InvalidLength);
        }
        let mut n = [0; 24];
        n.copy_from_slice(nonce);
        let mut t = [0; 16];
        t.copy_from_slice(tag);
        let mut o = [0; 32];
        o.copy_from_slice(outer);
        Ok(Self {
            profile,
            aead,
            authentication,
            vault_id,
            version,
            object_id,
            nonce: n,
            ciphertext,
            tag: t,
            outer_authenticator: o,
        })
    }
    #[must_use]
    pub const fn profile_id(&self) -> CryptoProfileId {
        self.profile
    }
    #[must_use]
    pub const fn aead_algorithm_id(&self) -> AeadAlgorithmId {
        self.aead
    }
    #[must_use]
    pub const fn authentication_algorithm_id(&self) -> AuthenticationAlgorithmId {
        self.authentication
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    #[must_use]
    pub const fn version(&self) -> FormatVersion {
        self.version
    }
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    #[must_use]
    pub const fn tag(&self) -> &[u8; 16] {
        &self.tag
    }
    #[must_use]
    pub const fn outer_authenticator(&self) -> &[u8; 32] {
        &self.outer_authenticator
    }
    #[must_use]
    pub fn into_parts(self) -> SnapshotObjectParts {
        SnapshotObjectParts {
            profile: self.profile,
            aead: self.aead,
            authentication: self.authentication,
            vault_id: self.vault_id,
            version: self.version,
            object_id: self.object_id,
            nonce: self.nonce,
            ciphertext: self.ciphertext,
            tag: self.tag,
            outer_authenticator: self.outer_authenticator,
        }
    }
}
pub fn encode_snapshot_object(v: &SnapshotObject) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_snapshot_to(&mut Encoder::new(&mut counter), v)?;
    let mut e = Encoder::new(output_buffer(
        counter.length()?,
        DecodeLimits::PHASE_1.max_aggregate_allocation_bytes,
    )?);
    encode_snapshot_to(&mut e, v)?;
    Ok(e.into_writer())
}
fn encode_snapshot_to<W: Write>(e: &mut Encoder<W>, v: &SnapshotObject) -> Result<(), FormatError> {
    e.array(12)?
        .u16(v.profile.get())?
        .u16(v.aead.get())?
        .u16(v.authentication.get())?
        .bytes(&v.vault_id)?
        .u8(ObjectKind::Snapshot.get())?
        .u16(v.version.get())?
        .bytes(&v.object_id)?
        .bytes(&v.nonce)?
        .u64(u64::try_from(v.ciphertext.len()).map_err(|_| FormatError::Overflow)?)?
        .bytes(&v.ciphertext)?
        .bytes(&v.tag)?
        .bytes(&v.outer_authenticator)?;
    Ok(())
}
pub fn decode_snapshot_object(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<SnapshotObject, FormatError> {
    require_depth(limits, 1)?;
    check_input_bound(bytes, u64::from(limits.max_snapshot_bytes) + 256)?;
    let mut d = Decoder::new(bytes);
    require_array(&mut d, 12)?;
    let p = CryptoProfileId::try_from(d.u16()?)?;
    let a = AeadAlgorithmId::try_from(d.u16()?)?;
    let auth = AuthenticationAlgorithmId::try_from(d.u16()?)?;
    let vault = fixed_bytes::<16>(d.bytes()?)?;
    if ObjectKind::try_from(d.u8()?)? != ObjectKind::Snapshot {
        return Err(FormatError::UnsupportedObjectKind);
    }
    let ver = FormatVersion::try_from(d.u16()?)?;
    let obj = fixed_bytes::<32>(d.bytes()?)?;
    let nonce = fixed_bytes::<24>(d.bytes()?)?;
    let declared = d.u64()?;
    let raw = d.bytes()?;
    if declared != u64::try_from(raw.len()).map_err(|_| FormatError::Overflow)? {
        return Err(FormatError::LengthMismatch);
    }
    let cipher = copy_bounded(raw, limits)?;
    let tag = fixed_bytes::<16>(d.bytes()?)?;
    let outer = fixed_bytes::<32>(d.bytes()?)?;
    finish(&d, bytes)?;
    let v = SnapshotObject::try_new(
        p, a, auth, vault, ver, obj, &nonce, cipher, &tag, &outer, limits,
    )?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_snapshot_to(&mut Encoder::new(&mut writer), &v)?;
    writer.finish()?;
    Ok(v)
}

pub struct HeadRecord {
    profile: CryptoProfileId,
    authentication: AuthenticationAlgorithmId,
    vault_id: [u8; 16],
    version: FormatVersion,
    object_id: [u8; 32],
    canonical_payload: Vec<u8>,
    authenticator: [u8; 32],
}
impl HeadRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        profile: CryptoProfileId,
        authentication: AuthenticationAlgorithmId,
        vault_id: [u8; 16],
        version: FormatVersion,
        object_id: [u8; 32],
        payload: HeadPayload,
        authenticator: &[u8],
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if authenticator.len() != 32 {
            return Err(FormatError::InvalidLength);
        }
        let mut a = [0; 32];
        a.copy_from_slice(authenticator);
        let canonical_payload = encode_head_payload(&payload)?;
        Self::try_from_canonical_payload(
            profile,
            authentication,
            vault_id,
            version,
            object_id,
            canonical_payload,
            a,
            limits,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn try_from_canonical_payload(
        profile: CryptoProfileId,
        authentication: AuthenticationAlgorithmId,
        vault_id: [u8; 16],
        version: FormatVersion,
        object_id: [u8; 32],
        canonical_payload: Vec<u8>,
        authenticator: [u8; 32],
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        let value = Self {
            profile,
            authentication,
            vault_id,
            version,
            object_id,
            canonical_payload,
            authenticator,
        };
        enforce_mac_record_size(&value, ObjectKind::AuthenticatedHead, limits.max_head_bytes)?;
        Ok(value)
    }
    #[must_use]
    pub const fn profile_id(&self) -> CryptoProfileId {
        self.profile
    }
    #[must_use]
    pub const fn authentication_algorithm_id(&self) -> AuthenticationAlgorithmId {
        self.authentication
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    #[must_use]
    pub const fn version(&self) -> FormatVersion {
        self.version
    }
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    /// Bytes covered by the authenticator but not yet trusted or semantically decoded.
    #[must_use]
    pub fn untrusted_payload_bytes(&self) -> &[u8] {
        &self.canonical_payload
    }
    #[must_use]
    pub const fn authenticator(&self) -> &[u8; 32] {
        &self.authenticator
    }
}
impl Drop for HeadRecord {
    fn drop(&mut self) {
        self.canonical_payload.zeroize();
    }
}
pub fn encode_head(v: &HeadRecord) -> Result<Vec<u8>, FormatError> {
    encode_mac_record(v, ObjectKind::AuthenticatedHead)
}
pub fn decode_head(bytes: &[u8], limits: &DecodeLimits) -> Result<HeadRecord, FormatError> {
    require_depth(limits, 2)?;
    check_input_bound(bytes, u64::from(limits.max_head_bytes))?;
    let (p, a, vault, ver, obj, payload, auth) =
        decode_mac_fields(bytes, ObjectKind::AuthenticatedHead, limits)?;
    let v = HeadRecord::try_from_canonical_payload(p, a, vault, ver, obj, payload, auth, limits)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_mac_to(
        &mut Encoder::new(&mut writer),
        &v,
        ObjectKind::AuthenticatedHead,
    )?;
    writer.finish()?;
    Ok(v)
}

pub struct LocalStateRecord {
    profile: CryptoProfileId,
    authentication: AuthenticationAlgorithmId,
    vault_id: [u8; 16],
    version: FormatVersion,
    object_id: [u8; 32],
    canonical_payload: Vec<u8>,
    authenticator: [u8; 32],
}
impl LocalStateRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        profile: CryptoProfileId,
        authentication: AuthenticationAlgorithmId,
        vault_id: [u8; 16],
        version: FormatVersion,
        object_id: [u8; 32],
        payload: LocalStatePayload,
        authenticator: &[u8],
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if authenticator.len() != 32 {
            return Err(FormatError::InvalidLength);
        }
        let mut a = [0; 32];
        a.copy_from_slice(authenticator);
        let canonical_payload = encode_local_state_payload(&payload)?;
        Self::try_from_canonical_payload(
            profile,
            authentication,
            vault_id,
            version,
            object_id,
            canonical_payload,
            a,
            limits,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn try_from_canonical_payload(
        profile: CryptoProfileId,
        authentication: AuthenticationAlgorithmId,
        vault_id: [u8; 16],
        version: FormatVersion,
        object_id: [u8; 32],
        canonical_payload: Vec<u8>,
        authenticator: [u8; 32],
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        let value = Self {
            profile,
            authentication,
            vault_id,
            version,
            object_id,
            canonical_payload,
            authenticator,
        };
        enforce_mac_record_size(
            &value,
            ObjectKind::LocalState,
            limits.max_local_record_bytes,
        )?;
        Ok(value)
    }
    #[must_use]
    pub const fn profile_id(&self) -> CryptoProfileId {
        self.profile
    }
    #[must_use]
    pub const fn authentication_algorithm_id(&self) -> AuthenticationAlgorithmId {
        self.authentication
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    #[must_use]
    pub const fn version(&self) -> FormatVersion {
        self.version
    }
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    /// Bytes covered by the authenticator but not yet trusted or semantically decoded.
    #[must_use]
    pub fn untrusted_payload_bytes(&self) -> &[u8] {
        &self.canonical_payload
    }
    #[must_use]
    pub const fn authenticator(&self) -> &[u8; 32] {
        &self.authenticator
    }
}
impl Drop for LocalStateRecord {
    fn drop(&mut self) {
        self.canonical_payload.zeroize();
    }
}
pub fn encode_local_state(v: &LocalStateRecord) -> Result<Vec<u8>, FormatError> {
    encode_mac_record(v, ObjectKind::LocalState)
}
pub fn decode_local_state(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<LocalStateRecord, FormatError> {
    require_depth(limits, 2)?;
    check_input_bound(bytes, u64::from(limits.max_local_record_bytes))?;
    let (p, a, vault, ver, obj, payload, auth) =
        decode_mac_fields(bytes, ObjectKind::LocalState, limits)?;
    let v =
        LocalStateRecord::try_from_canonical_payload(p, a, vault, ver, obj, payload, auth, limits)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_mac_to(&mut Encoder::new(&mut writer), &v, ObjectKind::LocalState)?;
    writer.finish()?;
    Ok(v)
}

trait MacRecordFields {
    fn profile(&self) -> CryptoProfileId;
    fn authentication(&self) -> AuthenticationAlgorithmId;
    fn vault_id(&self) -> &[u8; 16];
    fn version(&self) -> FormatVersion;
    fn object_id(&self) -> &[u8; 32];
    fn canonical_payload(&self) -> &[u8];
    fn authenticator(&self) -> &[u8; 32];
}
macro_rules! mac_fields {
    ($record:ty) => {
        impl MacRecordFields for $record {
            fn profile(&self) -> CryptoProfileId {
                self.profile
            }
            fn authentication(&self) -> AuthenticationAlgorithmId {
                self.authentication
            }
            fn vault_id(&self) -> &[u8; 16] {
                &self.vault_id
            }
            fn version(&self) -> FormatVersion {
                self.version
            }
            fn object_id(&self) -> &[u8; 32] {
                &self.object_id
            }
            fn canonical_payload(&self) -> &[u8] {
                &self.canonical_payload
            }
            fn authenticator(&self) -> &[u8; 32] {
                &self.authenticator
            }
        }
    };
}
mac_fields!(HeadRecord);
mac_fields!(LocalStateRecord);

fn encode_mac_record(
    value: &impl MacRecordFields,
    kind: ObjectKind,
) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_mac_to(&mut Encoder::new(&mut counter), value, kind)?;
    let mut e = Encoder::new(output_buffer(
        counter.length()?,
        DecodeLimits::PHASE_1.max_aggregate_allocation_bytes,
    )?);
    encode_mac_to(&mut e, value, kind)?;
    Ok(e.into_writer())
}
fn enforce_mac_record_size(
    value: &impl MacRecordFields,
    kind: ObjectKind,
    maximum: u32,
) -> Result<(), FormatError> {
    let mut counter = CountingWriter::default();
    encode_mac_to(&mut Encoder::new(&mut counter), value, kind)?;
    if counter.length()? > usize::try_from(maximum).map_err(|_| FormatError::Overflow)? {
        return Err(FormatError::LimitExceeded);
    }
    Ok(())
}
fn encode_mac_to<W: Write>(
    e: &mut Encoder<W>,
    value: &impl MacRecordFields,
    kind: ObjectKind,
) -> Result<(), FormatError> {
    e.array(9)?
        .u16(value.profile().get())?
        .u16(value.authentication().get())?
        .bytes(value.vault_id())?
        .u8(kind.get())?
        .u16(value.version().get())?
        .bytes(value.object_id())?
        .u64(u64::try_from(value.canonical_payload().len()).map_err(|_| FormatError::Overflow)?)?
        .bytes(value.canonical_payload())?
        .bytes(value.authenticator())?;
    Ok(())
}
#[allow(clippy::type_complexity)]
fn decode_mac_fields(
    bytes: &[u8],
    expected: ObjectKind,
    limits: &DecodeLimits,
) -> Result<
    (
        CryptoProfileId,
        AuthenticationAlgorithmId,
        [u8; 16],
        FormatVersion,
        [u8; 32],
        Vec<u8>,
        [u8; 32],
    ),
    FormatError,
> {
    let mut d = Decoder::new(bytes);
    require_array(&mut d, 9)?;
    let p = CryptoProfileId::try_from(d.u16()?)?;
    let a = AuthenticationAlgorithmId::try_from(d.u16()?)?;
    let vault = fixed_bytes::<16>(d.bytes()?)?;
    if ObjectKind::try_from(d.u8()?)? != expected {
        return Err(FormatError::UnsupportedObjectKind);
    }
    let ver = FormatVersion::try_from(d.u16()?)?;
    let obj = fixed_bytes::<32>(d.bytes()?)?;
    let declared = d.u64()?;
    let raw = d.bytes()?;
    if declared != u64::try_from(raw.len()).map_err(|_| FormatError::Overflow)? {
        return Err(FormatError::LengthMismatch);
    }
    let payload = copy_bounded(raw, limits)?;
    let auth = fixed_bytes::<32>(d.bytes()?)?;
    finish(&d, bytes)?;
    Ok((p, a, vault, ver, obj, payload, auth))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactChunkKey {
    algorithm: AeadAlgorithmId,
    nonce: [u8; 24],
    ciphertext: [u8; 32],
    tag: [u8; 16],
}
impl CompactChunkKey {
    pub fn try_new(
        algorithm: AeadAlgorithmId,
        nonce: &[u8],
        ciphertext: Vec<u8>,
        tag: &[u8],
    ) -> Result<Self, FormatError> {
        if nonce.len() != 24 || ciphertext.len() != 32 || tag.len() != 16 {
            return Err(FormatError::InvalidLength);
        }
        let c = ciphertext
            .try_into()
            .map_err(|_| FormatError::InvalidLength)?;
        Self::try_from_fixed(algorithm, nonce, c, tag)
    }
    fn try_from_fixed(
        algorithm: AeadAlgorithmId,
        nonce: &[u8],
        ciphertext: [u8; 32],
        tag: &[u8],
    ) -> Result<Self, FormatError> {
        if nonce.len() != 24 || tag.len() != 16 {
            return Err(FormatError::InvalidLength);
        }
        let mut n = [0; 24];
        n.copy_from_slice(nonce);
        let mut t = [0; 16];
        t.copy_from_slice(tag);
        Ok(Self {
            algorithm,
            nonce: n,
            ciphertext,
            tag: t,
        })
    }
    pub fn encoded_len(&self) -> Result<usize, FormatError> {
        Ok(encode_compact_wrapper(self)?.len())
    }
    #[must_use]
    pub const fn algorithm_id(&self) -> AeadAlgorithmId {
        self.algorithm
    }
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; 32] {
        &self.ciphertext
    }
    #[must_use]
    pub const fn tag(&self) -> &[u8; 16] {
        &self.tag
    }
}
fn encode_compact_wrapper(v: &CompactChunkKey) -> Result<Vec<u8>, FormatError> {
    let mut e = Encoder::new(output_buffer(128, 128)?);
    e.array(6)?
        .u16(v.algorithm.get())?
        .u8(ObjectKind::ChunkKey.get())?
        .bytes(&v.nonce)?
        .u64(32)?
        .bytes(&v.ciphertext)?
        .bytes(&v.tag)?;
    let out = e.into_writer();
    if out.len() > 128 {
        return Err(FormatError::LimitExceeded);
    }
    Ok(out)
}
fn decode_compact_wrapper(d: &mut Decoder<'_>) -> Result<CompactChunkKey, FormatError> {
    require_array(d, 6)?;
    let a = AeadAlgorithmId::try_from(d.u16()?)?;
    if ObjectKind::try_from(d.u8()?)? != ObjectKind::ChunkKey {
        return Err(FormatError::UnsupportedObjectKind);
    }
    let n = fixed_bytes::<24>(d.bytes()?)?;
    if d.u64()? != 32 {
        return Err(FormatError::LengthMismatch);
    }
    let c = fixed_bytes::<32>(d.bytes()?)?;
    let t = fixed_bytes::<16>(d.bytes()?)?;
    CompactChunkKey::try_from_fixed(a, &n, c, &t)
}

#[derive(PartialEq, Eq)]
pub struct ContentChunkObject {
    profile: CryptoProfileId,
    algorithm: AeadAlgorithmId,
    vault_id: [u8; 16],
    version: FormatVersion,
    object_id: [u8; 32],
    nonce: [u8; 24],
    wrapper: CompactChunkKey,
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}
pub struct ContentChunkObjectParts {
    profile: CryptoProfileId,
    algorithm: AeadAlgorithmId,
    vault_id: [u8; 16],
    version: FormatVersion,
    object_id: [u8; 32],
    nonce: [u8; 24],
    wrapper: CompactChunkKey,
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}
impl ContentChunkObjectParts {
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_components(
        self,
    ) -> (
        CryptoProfileId,
        AeadAlgorithmId,
        [u8; 16],
        FormatVersion,
        [u8; 32],
        [u8; 24],
        CompactChunkKey,
        Vec<u8>,
        [u8; 16],
    ) {
        (
            self.profile,
            self.algorithm,
            self.vault_id,
            self.version,
            self.object_id,
            self.nonce,
            self.wrapper,
            self.ciphertext,
            self.tag,
        )
    }
}
impl ContentChunkObject {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        profile: CryptoProfileId,
        algorithm: AeadAlgorithmId,
        vault_id: [u8; 16],
        version: FormatVersion,
        object_id: [u8; 32],
        nonce: &[u8],
        wrapper: CompactChunkKey,
        ciphertext: Vec<u8>,
        tag: &[u8],
    ) -> Result<Self, FormatError> {
        if nonce.len() != 24 || tag.len() != 16 || ciphertext.len() > 4 * 1_048_576 {
            return Err(FormatError::InvalidLength);
        }
        let mut n = [0; 24];
        n.copy_from_slice(nonce);
        let mut t = [0; 16];
        t.copy_from_slice(tag);
        Ok(Self {
            profile,
            algorithm,
            vault_id,
            version,
            object_id,
            nonce: n,
            wrapper,
            ciphertext,
            tag: t,
        })
    }
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    #[must_use]
    pub const fn profile_id(&self) -> CryptoProfileId {
        self.profile
    }
    #[must_use]
    pub const fn algorithm_id(&self) -> AeadAlgorithmId {
        self.algorithm
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    #[must_use]
    pub const fn version(&self) -> FormatVersion {
        self.version
    }
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    #[must_use]
    pub const fn tag(&self) -> &[u8; 16] {
        &self.tag
    }
    #[must_use]
    pub const fn wrapper(&self) -> &CompactChunkKey {
        &self.wrapper
    }
    #[must_use]
    pub fn into_parts(self) -> ContentChunkObjectParts {
        ContentChunkObjectParts {
            profile: self.profile,
            algorithm: self.algorithm,
            vault_id: self.vault_id,
            version: self.version,
            object_id: self.object_id,
            nonce: self.nonce,
            wrapper: self.wrapper,
            ciphertext: self.ciphertext,
            tag: self.tag,
        }
    }
}
pub fn encode_content_chunk(v: &ContentChunkObject) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_content_chunk_to(&mut Encoder::new(&mut counter), v)?;
    let mut e = Encoder::new(output_buffer(
        counter.length()?,
        DecodeLimits::PHASE_1.max_aggregate_allocation_bytes,
    )?);
    encode_content_chunk_to(&mut e, v)?;
    Ok(e.into_writer())
}
fn encode_content_chunk_to<W: Write>(
    e: &mut Encoder<W>,
    v: &ContentChunkObject,
) -> Result<(), FormatError> {
    e.array(11)?
        .u16(v.profile.get())?
        .u16(v.algorithm.get())?
        .bytes(&v.vault_id)?
        .u8(ObjectKind::ContentChunk.get())?
        .u16(v.version.get())?
        .bytes(&v.object_id)?
        .bytes(&v.nonce)?
        .u64(u64::try_from(v.ciphertext.len()).map_err(|_| FormatError::Overflow)?)?;
    encode_compact_to(e, &v.wrapper)?;
    e.bytes(&v.ciphertext)?.bytes(&v.tag)?;
    Ok(())
}
fn encode_compact_to<W: Write>(e: &mut Encoder<W>, v: &CompactChunkKey) -> Result<(), FormatError> {
    e.array(6)?
        .u16(v.algorithm.get())?
        .u8(ObjectKind::ChunkKey.get())?
        .bytes(&v.nonce)?
        .u64(32)?
        .bytes(&v.ciphertext)?
        .bytes(&v.tag)?;
    Ok(())
}
pub fn decode_content_chunk(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<ContentChunkObject, FormatError> {
    require_depth(limits, 2)?;
    check_input_bound(bytes, 4 * 1_048_576 + 512)?;
    let mut d = Decoder::new(bytes);
    require_array(&mut d, 11)?;
    let p = CryptoProfileId::try_from(d.u16()?)?;
    let a = AeadAlgorithmId::try_from(d.u16()?)?;
    let vault = fixed_bytes::<16>(d.bytes()?)?;
    if ObjectKind::try_from(d.u8()?)? != ObjectKind::ContentChunk {
        return Err(FormatError::UnsupportedObjectKind);
    }
    let ver = FormatVersion::try_from(d.u16()?)?;
    let obj = fixed_bytes::<32>(d.bytes()?)?;
    let nonce = fixed_bytes::<24>(d.bytes()?)?;
    let declared = d.u64()?;
    let wrapper = decode_compact_wrapper(&mut d)?;
    let raw = d.bytes()?;
    if declared != u64::try_from(raw.len()).map_err(|_| FormatError::Overflow)? {
        return Err(FormatError::LengthMismatch);
    }
    let ciphertext = copy_bounded(raw, limits)?;
    let tag = fixed_bytes::<16>(d.bytes()?)?;
    finish(&d, bytes)?;
    let v = ContentChunkObject::try_new(p, a, vault, ver, obj, &nonce, wrapper, ciphertext, &tag)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_content_chunk_to(&mut Encoder::new(&mut writer), &v)?;
    writer.finish()?;
    Ok(v)
}
