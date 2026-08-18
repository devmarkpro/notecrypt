use minicbor::{Decoder, Encoder};
use zeroize::{Zeroize, Zeroizing};

use crate::object::{
    CanonicalCompareWriter, CountingWriter, check_input_bound, copy_bounded, finish, fixed_bytes,
    output_buffer, require_array, require_depth,
};
use crate::{DecodeLimits, FORMAT_VERSION_V1, FormatError};

pub const CONTENT_CHUNK_BYTES_V1: u32 = 1_048_576;

#[derive(PartialEq, Eq)]
pub struct ContentPayload {
    file_id: [u8; 16],
    position: u64,
    bytes: Vec<u8>,
}

impl ContentPayload {
    pub fn try_new(
        file_id: [u8; 16],
        position: u64,
        mut bytes: Vec<u8>,
    ) -> Result<Self, FormatError> {
        if bytes.is_empty()
            || bytes.len()
                > usize::try_from(CONTENT_CHUNK_BYTES_V1).map_err(|_| FormatError::Overflow)?
        {
            bytes.zeroize();
            return Err(FormatError::LimitExceeded);
        }
        Ok(Self {
            file_id,
            position,
            bytes,
        })
    }
    #[must_use]
    pub const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
    }
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
    pub fn consume<R>(self, consumer: impl FnOnce(&[u8]) -> R) -> R {
        consumer(&self.bytes)
    }
}

impl Drop for ContentPayload {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub fn encode_content_payload(value: &ContentPayload) -> Result<Vec<u8>, FormatError> {
    let capacity = value
        .bytes
        .len()
        .checked_add(64)
        .ok_or(FormatError::Overflow)?;
    let mut encoder = Encoder::new(output_buffer(
        capacity,
        DecodeLimits::PHASE_1.max_aggregate_allocation_bytes,
    )?);
    encode_content_to(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

pub fn decode_content_payload(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<ContentPayload, FormatError> {
    require_depth(limits, 1)?;
    check_input_bound(bytes, u64::from(CONTENT_CHUNK_BYTES_V1) + 64)?;
    let mut decoder = Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    require_v1(decoder.u16()?)?;
    let file_id = fixed_bytes::<16>(decoder.bytes()?)?;
    let position = decoder.u64()?;
    let declared = decoder.u64()?;
    let payload = decoder.bytes()?;
    if declared != u64::try_from(payload.len()).map_err(|_| FormatError::Overflow)? {
        return Err(FormatError::LengthMismatch);
    }
    let owned = copy_bounded(payload, limits)?;
    finish(&decoder, bytes)?;
    let value = ContentPayload::try_new(file_id, position, owned)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_content_to(&mut Encoder::new(&mut writer), &value)?;
    writer.finish()?;
    Ok(value)
}

pub struct ChunkDescriptor {
    object_id: [u8; 32],
    fingerprint: [u8; 32],
    plaintext_bytes: u32,
}

impl ChunkDescriptor {
    pub fn try_new(
        object_id: [u8; 32],
        fingerprint: &[u8],
        plaintext_bytes: u32,
    ) -> Result<Self, FormatError> {
        if fingerprint.len() != 32
            || plaintext_bytes == 0
            || plaintext_bytes > CONTENT_CHUNK_BYTES_V1
        {
            return Err(FormatError::InvalidLength);
        }
        let mut checked = [0; 32];
        checked.copy_from_slice(fingerprint);
        Ok(Self {
            object_id,
            fingerprint: checked,
            plaintext_bytes,
        })
    }
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    #[must_use]
    pub const fn plaintext_bytes(&self) -> u32 {
        self.plaintext_bytes
    }
    #[must_use]
    pub fn into_parts(mut self) -> ([u8; 32], [u8; 32], u32) {
        (
            self.object_id,
            std::mem::take(&mut self.fingerprint),
            self.plaintext_bytes,
        )
    }
}

impl Drop for ChunkDescriptor {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
    }
}

pub struct RevisionManifest {
    file_id: [u8; 16],
    revision_id: [u8; 32],
    chunks: Vec<ChunkDescriptor>,
    total_plaintext_bytes: u64,
}

impl RevisionManifest {
    pub fn try_new(
        file_id: [u8; 16],
        revision_id: [u8; 32],
        chunks: Vec<ChunkDescriptor>,
        total_plaintext_bytes: u64,
        limits: &DecodeLimits,
    ) -> Result<Self, FormatError> {
        if chunks.len()
            > usize::try_from(limits.max_chunks_per_file).map_err(|_| FormatError::Overflow)?
        {
            return Err(FormatError::LimitExceeded);
        }
        let chunk_storage = chunks
            .len()
            .checked_mul(std::mem::size_of::<ChunkDescriptor>())
            .ok_or(FormatError::Overflow)?;
        let duplicate_index = chunks
            .len()
            .checked_mul(std::mem::size_of::<[u8; 32]>())
            .ok_or(FormatError::Overflow)?;
        let transient_budget = chunk_storage
            .checked_add(duplicate_index)
            .ok_or(FormatError::Overflow)?;
        if transient_budget > limits.max_aggregate_allocation_bytes {
            return Err(FormatError::LimitExceeded);
        }
        let mut sum = 0_u64;
        let mut ids = Vec::new();
        ids.try_reserve_exact(chunks.len())
            .map_err(|_| FormatError::AllocationFailed)?;
        for (index, chunk) in chunks.iter().enumerate() {
            ids.push(chunk.object_id);
            if index + 1 < chunks.len() && chunk.plaintext_bytes != CONTENT_CHUNK_BYTES_V1 {
                return Err(FormatError::InvalidLength);
            }
            sum = sum
                .checked_add(u64::from(chunk.plaintext_bytes))
                .ok_or(FormatError::Overflow)?;
        }
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FormatError::Malformed);
        }
        if sum != total_plaintext_bytes {
            return Err(FormatError::LengthMismatch);
        }
        Ok(Self {
            file_id,
            revision_id,
            chunks,
            total_plaintext_bytes,
        })
    }
    #[must_use]
    pub const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
    }
    #[must_use]
    pub const fn revision_id(&self) -> &[u8; 32] {
        &self.revision_id
    }
    #[must_use]
    pub fn chunks(&self) -> &[ChunkDescriptor] {
        &self.chunks
    }
    #[must_use]
    pub const fn total_plaintext_bytes(&self) -> u64 {
        self.total_plaintext_bytes
    }
    #[must_use]
    pub fn into_parts(mut self) -> ([u8; 16], [u8; 32], Vec<ChunkDescriptor>, u64) {
        (
            self.file_id,
            self.revision_id,
            std::mem::take(&mut self.chunks),
            self.total_plaintext_bytes,
        )
    }
}

pub fn encode_manifest(value: &RevisionManifest) -> Result<Vec<u8>, FormatError> {
    let mut counter = CountingWriter::default();
    encode_manifest_to(&mut Encoder::new(&mut counter), value)?;
    let capacity = counter.length()?;
    let mut encoder = Encoder::new(output_buffer(
        capacity,
        usize::try_from(DecodeLimits::PHASE_1.max_manifest_bytes)
            .map_err(|_| FormatError::Overflow)?,
    )?);
    encode_manifest_to(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

pub fn decode_manifest(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<RevisionManifest, FormatError> {
    require_depth(limits, 3)?;
    check_input_bound(bytes, u64::from(limits.max_manifest_bytes))?;
    let mut decoder = Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    require_v1(decoder.u16()?)?;
    let file_id = fixed_bytes::<16>(decoder.bytes()?)?;
    let revision_id = fixed_bytes::<32>(decoder.bytes()?)?;
    let total = decoder.u64()?;
    let count = decoder.array()?.ok_or(FormatError::NonCanonical)?;
    if count > u64::from(limits.max_chunks_per_file) {
        return Err(FormatError::LimitExceeded);
    }
    let count = usize::try_from(count).map_err(|_| FormatError::Overflow)?;
    let allocation = count
        .checked_mul(std::mem::size_of::<ChunkDescriptor>())
        .ok_or(FormatError::Overflow)?;
    if allocation > limits.max_aggregate_allocation_bytes {
        return Err(FormatError::LimitExceeded);
    }
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(count)
        .map_err(|_| FormatError::AllocationFailed)?;
    for _ in 0..count {
        require_array(&mut decoder, 3)?;
        let object_id = fixed_bytes::<32>(decoder.bytes()?)?;
        let fingerprint = Zeroizing::new(fixed_bytes::<32>(decoder.bytes()?)?);
        let length = decoder.u32()?;
        chunks.push(ChunkDescriptor::try_new(object_id, &*fingerprint, length)?);
    }
    finish(&decoder, bytes)?;
    let value = RevisionManifest::try_new(file_id, revision_id, chunks, total, limits)?;
    let mut writer = CanonicalCompareWriter::new(bytes);
    encode_manifest_to(&mut Encoder::new(&mut writer), &value)?;
    writer.finish()?;
    Ok(value)
}

fn require_v1(version: u16) -> Result<(), FormatError> {
    if version == FORMAT_VERSION_V1 {
        Ok(())
    } else {
        Err(FormatError::UnsupportedVersion(version))
    }
}

fn encode_content_to<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    value: &ContentPayload,
) -> Result<(), FormatError> {
    encoder
        .array(5)?
        .u16(FORMAT_VERSION_V1)?
        .bytes(&value.file_id)?
        .u64(value.position)?
        .u64(u64::try_from(value.bytes.len()).map_err(|_| FormatError::Overflow)?)?
        .bytes(&value.bytes)?;
    Ok(())
}

fn encode_manifest_to<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    value: &RevisionManifest,
) -> Result<(), FormatError> {
    encoder
        .array(5)?
        .u16(FORMAT_VERSION_V1)?
        .bytes(&value.file_id)?
        .bytes(&value.revision_id)?
        .u64(value.total_plaintext_bytes)?
        .array(u64::try_from(value.chunks.len()).map_err(|_| FormatError::Overflow)?)?;
    for chunk in &value.chunks {
        encoder
            .array(3)?
            .bytes(&chunk.object_id)?
            .bytes(&chunk.fingerprint)?
            .u32(chunk.plaintext_bytes)?;
    }
    Ok(())
}
