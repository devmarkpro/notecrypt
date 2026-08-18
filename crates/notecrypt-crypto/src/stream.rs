use minicbor::Encoder;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::aead::{
    decrypt_parts, encrypt_parts, keyed_hasher, protected_bytes_from_sensitive_buffer,
    validate_typed_identity,
};
use crate::{
    AeadEnvelopeParts, CHUNK_KEY_OBJECT_KIND, CONTENT_CHUNK_OBJECT_KIND, ChunkFingerprintKey,
    ContentWrappingKey, CryptoError, ProtectedBytes, PublicEnvelopeIdentity, SecureRandom,
    TypedAeadEnvelope,
};

pub const MAX_CONTENT_CHUNK_BYTES: usize = 4 * 1_048_576;
pub const CHUNK_FINGERPRINT_SEMANTICS_BYTES: usize = 24;
const CHUNK_KEY_BYTES: usize = 32;

pub struct EncryptedChunkDescriptor {
    pub object_id: [u8; 32],
    pub fingerprint: ChunkFingerprint,
    pub sequence: u64,
    pub plaintext_bytes: u32,
}

pub struct EncryptedChunk {
    pub descriptor: EncryptedChunkDescriptor,
    pub encoded: Vec<u8>,
}

macro_rules! chunk_context_type {
    ($name:ident, $kind:expr) => {
        pub struct $name(PublicEnvelopeIdentity);

        impl $name {
            pub const OBJECT_KIND: u8 = $kind;

            pub fn try_new(identity: PublicEnvelopeIdentity) -> Result<Self, CryptoError> {
                validate_typed_identity(&identity, Self::OBJECT_KIND)?;
                Ok(Self(identity))
            }

            #[must_use]
            pub const fn identity(&self) -> &PublicEnvelopeIdentity {
                &self.0
            }
        }
    };
}

chunk_context_type!(ChunkKeyWrapContext, CHUNK_KEY_OBJECT_KIND);
chunk_context_type!(ContentChunkContext, CONTENT_CHUNK_OBJECT_KIND);

pub struct ChunkFingerprintContext {
    _private: (),
}

impl ChunkFingerprintContext {
    #[must_use]
    pub const fn profile_one() -> Self {
        Self { _private: () }
    }
}

pub struct ChunkKeyPlaintext(SecretBox<[u8; CHUNK_KEY_BYTES]>);

impl ChunkKeyPlaintext {
    pub fn generate(random: &mut dyn SecureRandom) -> Result<Self, CryptoError> {
        let mut bytes = Box::new([0_u8; CHUNK_KEY_BYTES]);
        if let Err(error) = random.fill(bytes.as_mut()) {
            bytes.zeroize();
            return Err(error);
        }
        Ok(Self(SecretBox::new(bytes)))
    }

    fn try_from_buffer(mut bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != CHUNK_KEY_BYTES {
            bytes.zeroize();
            return Err(CryptoError::InvalidPlaintextLength);
        }
        let mut key = Box::new([0_u8; CHUNK_KEY_BYTES]);
        key.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(SecretBox::new(key)))
    }

    fn expose_secret(&self) -> &[u8; CHUNK_KEY_BYTES] {
        self.0.expose_secret()
    }

    fn into_buffer(self) -> Vec<u8> {
        self.0.expose_secret().to_vec()
    }
}

pub struct ContentChunkPlaintext(Vec<u8>);

impl ContentChunkPlaintext {
    pub fn try_new(mut bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_CONTENT_CHUNK_BYTES {
            bytes.zeroize();
            return Err(CryptoError::PlaintextTooLarge);
        }
        Ok(Self(bytes))
    }

    fn into_buffer(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    #[must_use]
    pub fn into_protected_bytes(self) -> ProtectedBytes {
        protected_bytes_from_sensitive_buffer(self.into_buffer())
    }
}

impl Drop for ContentChunkPlaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

macro_rules! chunk_envelope_type {
    ($name:ident, $kind:expr, exact $length:expr) => {
        pub struct $name(AeadEnvelopeParts);

        impl $name {
            pub fn validate_ciphertext_len(length: usize) -> Result<(), CryptoError> {
                if length != $length {
                    return Err(CryptoError::InvalidPlaintextLength);
                }
                Ok(())
            }
        }

        impl TypedAeadEnvelope for $name {
            fn try_from_parts(parts: AeadEnvelopeParts) -> Result<Self, CryptoError> {
                validate_typed_identity(parts.identity(), $kind)?;
                Self::validate_ciphertext_len(parts.ciphertext().len())?;
                Ok(Self(parts))
            }

            fn parts(&self) -> &AeadEnvelopeParts {
                &self.0
            }

            fn into_parts(self) -> AeadEnvelopeParts {
                self.0
            }
        }
    };
    ($name:ident, $kind:expr, max $length:expr) => {
        pub struct $name(AeadEnvelopeParts);

        impl $name {
            pub fn validate_ciphertext_len(length: usize) -> Result<(), CryptoError> {
                if length > $length {
                    return Err(CryptoError::PlaintextTooLarge);
                }
                Ok(())
            }
        }

        impl TypedAeadEnvelope for $name {
            fn try_from_parts(parts: AeadEnvelopeParts) -> Result<Self, CryptoError> {
                validate_typed_identity(parts.identity(), $kind)?;
                Self::validate_ciphertext_len(parts.ciphertext().len())?;
                Ok(Self(parts))
            }

            fn parts(&self) -> &AeadEnvelopeParts {
                &self.0
            }

            fn into_parts(self) -> AeadEnvelopeParts {
                self.0
            }
        }
    };
}

chunk_envelope_type!(
    ChunkKeyEnvelope,
    CHUNK_KEY_OBJECT_KIND,
    exact CHUNK_KEY_BYTES
);
chunk_envelope_type!(
    ContentChunkEnvelope,
    CONTENT_CHUNK_OBJECT_KIND,
    max MAX_CONTENT_CHUNK_BYTES
);

pub struct ChunkFingerprint([u8; 32]);

impl ChunkFingerprint {
    pub fn try_from_protected_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidPlaintextLength);
        }
        let mut checked = [0_u8; 32];
        checked.copy_from_slice(bytes);
        Ok(Self(checked))
    }

    #[must_use]
    pub fn into_protected_bytes(mut self) -> [u8; 32] {
        std::mem::take(&mut self.0)
    }

    fn as_zeroizing_hash(&self) -> Zeroizing<blake3::Hash> {
        Zeroizing::new(blake3::Hash::from_bytes(self.0))
    }
}

impl Drop for ChunkFingerprint {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn wrap_chunk_key(
    context: &ChunkKeyWrapContext,
    value: ChunkKeyPlaintext,
    key: &ContentWrappingKey,
    random: &mut dyn SecureRandom,
) -> Result<ChunkKeyEnvelope, CryptoError> {
    ChunkKeyEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn unwrap_chunk_key(
    context: &ChunkKeyWrapContext,
    envelope: &ChunkKeyEnvelope,
    key: &ContentWrappingKey,
) -> Result<ChunkKeyPlaintext, CryptoError> {
    ChunkKeyPlaintext::try_from_buffer(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn encrypt_content_chunk(
    context: &ContentChunkContext,
    value: ContentChunkPlaintext,
    key: &ChunkKeyPlaintext,
    random: &mut dyn SecureRandom,
) -> Result<ContentChunkEnvelope, CryptoError> {
    ContentChunkEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn decrypt_content_chunk(
    context: &ContentChunkContext,
    envelope: &ContentChunkEnvelope,
    key: &ChunkKeyPlaintext,
) -> Result<ContentChunkPlaintext, CryptoError> {
    ContentChunkPlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn fingerprint_chunk(
    _context: &ChunkFingerprintContext,
    protected_semantics: &[u8],
    plaintext: &[u8],
    key: &ChunkFingerprintKey,
) -> Result<ChunkFingerprint, CryptoError> {
    validate_fingerprint_input(protected_semantics, plaintext)?;
    let plaintext_len =
        u64::try_from(plaintext.len()).map_err(|_| CryptoError::PlaintextTooLarge)?;

    let checked_position = Zeroizing::new(u64::from_be_bytes(
        protected_semantics[16..]
            .try_into()
            .map_err(|_| CryptoError::InvalidPlaintextLength)?,
    ));
    let mut prefix = Zeroizing::new(Vec::with_capacity(40));
    {
        let mut encoder = Encoder::new(&mut *prefix);
        encoder.array(4).map_err(|_| CryptoError::InvalidEnvelope)?;
        encoder
            .bytes(&protected_semantics[..16])
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        encoder
            .u64(*checked_position)
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        encoder
            .u64(plaintext_len)
            .map_err(|_| CryptoError::InvalidEnvelope)?;
    }

    let (plaintext_header, header_len) = canonical_byte_string_header(plaintext.len())?;
    let mut hasher = keyed_hasher(key.expose_secret());
    hasher.update(&prefix);
    hasher.update(&plaintext_header[..header_len]);
    hasher.update(plaintext);
    let finalized = Zeroizing::new(hasher.finalize());
    ChunkFingerprint::try_from_protected_bytes(finalized.as_bytes())
}

pub fn verify_chunk_fingerprint(
    context: &ChunkFingerprintContext,
    protected_semantics: &[u8],
    plaintext: &[u8],
    expected: &ChunkFingerprint,
    key: &ChunkFingerprintKey,
) -> Result<(), CryptoError> {
    let actual = fingerprint_chunk(context, protected_semantics, plaintext, key)?;
    let actual_hash = actual.as_zeroizing_hash();
    let expected_hash = expected.as_zeroizing_hash();
    if *actual_hash == *expected_hash {
        Ok(())
    } else {
        Err(CryptoError::Authentication)
    }
}

fn validate_fingerprint_input(
    protected_semantics: &[u8],
    plaintext: &[u8],
) -> Result<(), CryptoError> {
    if protected_semantics.len() != CHUNK_FINGERPRINT_SEMANTICS_BYTES {
        return Err(CryptoError::InvalidPlaintextLength);
    }
    if plaintext.len() > MAX_CONTENT_CHUNK_BYTES {
        return Err(CryptoError::PlaintextTooLarge);
    }
    Ok(())
}

fn canonical_byte_string_header(length: usize) -> Result<([u8; 5], usize), CryptoError> {
    let mut encoded = [0_u8; 5];
    match length {
        0..=23 => {
            encoded[0] = 0x40 | u8::try_from(length).map_err(|_| CryptoError::InvalidEnvelope)?;
            Ok((encoded, 1))
        }
        24..=255 => {
            encoded[0] = 0x58;
            encoded[1] = u8::try_from(length).map_err(|_| CryptoError::InvalidEnvelope)?;
            Ok((encoded, 2))
        }
        256..=65_535 => {
            encoded[0] = 0x59;
            encoded[1..3].copy_from_slice(
                &u16::try_from(length)
                    .map_err(|_| CryptoError::InvalidEnvelope)?
                    .to_be_bytes(),
            );
            Ok((encoded, 3))
        }
        _ => {
            encoded[0] = 0x5a;
            encoded[1..5].copy_from_slice(
                &u32::try_from(length)
                    .map_err(|_| CryptoError::PlaintextTooLarge)?
                    .to_be_bytes(),
            );
            Ok((encoded, 5))
        }
    }
}

#[cfg(test)]
mod tests {
    use minicbor::Encoder;

    use super::{ChunkFingerprintContext, canonical_byte_string_header, fingerprint_chunk};
    use crate::{VaultRootKey, derive_vault_keys};

    #[test]
    fn streamed_plaintext_byte_header_matches_canonical_minicbor() {
        for length in [0, 23, 24, 255, 256, 65_535, 65_536, 4 * 1_048_576] {
            let plaintext = vec![0x5a; length];
            let mut semantics = vec![0x11; 16];
            semantics.extend_from_slice(&7_u64.to_be_bytes());

            let mut one_shot = Encoder::new(Vec::new());
            one_shot.array(4).unwrap();
            one_shot.bytes(&semantics[..16]).unwrap();
            one_shot.u64(7).unwrap();
            one_shot.u64(length as u64).unwrap();
            one_shot.bytes(&plaintext).unwrap();

            let mut streamed_prefix = Encoder::new(Vec::new());
            streamed_prefix.array(4).unwrap();
            streamed_prefix.bytes(&semantics[..16]).unwrap();
            streamed_prefix.u64(7).unwrap();
            streamed_prefix.u64(length as u64).unwrap();
            let (header, header_len) = canonical_byte_string_header(length).unwrap();
            let mut streamed = streamed_prefix.into_writer();
            streamed.extend_from_slice(&header[..header_len]);
            streamed.extend_from_slice(&plaintext);

            assert_eq!(streamed, one_shot.into_writer());
        }
    }

    #[test]
    fn profile_one_fingerprint_matches_frozen_vector() {
        let root = VaultRootKey::from_boxed_bytes(Box::new([0x42; 32]));
        let keys = derive_vault_keys(&root).unwrap();
        let fingerprint = fingerprint_chunk(
            &ChunkFingerprintContext::profile_one(),
            &{
                let mut semantics = vec![0x11; 16];
                semantics.extend_from_slice(&7_u64.to_be_bytes());
                semantics
            },
            b"notecrypt-profile-one-chunk",
            &keys.chunk_fingerprint,
        )
        .unwrap();

        assert_eq!(
            fingerprint.into_protected_bytes(),
            [
                8, 186, 83, 84, 6, 23, 73, 109, 120, 247, 12, 33, 83, 84, 114, 137, 147, 163, 22,
                159, 9, 70, 0, 172, 157, 151, 48, 209, 90, 238, 137, 120,
            ]
        );
    }
}
