use chacha20poly1305::{
    Key, Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use minicbor::Encoder;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::{
    CryptoError, DeviceWrappingKey, LocalVerificationKey, MetadataKey, RecoveryWrappingKey,
    SecureRandom, SnapshotAuthenticationKey, VaultRootKey,
};

pub const CRYPTO_PROFILE_V1: u16 = 0x0001;
pub const FORMAT_VERSION_V1: u16 = 0x0001;
pub const RECOVERY_SLOT_OBJECT_KIND: u8 = 0x01;
pub const DEVICE_SLOT_OBJECT_KIND: u8 = 0x02;
pub const METADATA_OBJECT_KIND: u8 = 0x03;
pub const TREE_OBJECT_KIND: u8 = 0x04;
pub const MANIFEST_OBJECT_KIND: u8 = 0x05;
pub const SNAPSHOT_OBJECT_KIND: u8 = 0x06;
pub const AUTHENTICATED_HEAD_OBJECT_KIND: u8 = 0x07;
pub const LOCAL_STATE_OBJECT_KIND: u8 = 0x08;
pub const CHUNK_KEY_OBJECT_KIND: u8 = 0x09;
pub const CONTENT_CHUNK_OBJECT_KIND: u8 = 0x0a;

const RECOVERY_SLOT_LEN: usize = 32;
const DEVICE_SLOT_LEN: usize = 32;
const METADATA_MAX_LEN: usize = 1_048_576;
const TREE_MAX_LEN: usize = 268_435_456;
const MANIFEST_MAX_LEN: usize = 67_108_864;
const SNAPSHOT_MAX_LEN: usize = 1_048_576;
const AUTHENTICATED_RECORD_MAX_LEN: usize = 65_536;
const MAX_TASK3_CIPHERTEXT_LEN: usize = TREE_MAX_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicEnvelopeIdentity {
    pub profile_id: u16,
    pub vault_id: [u8; 16],
    pub object_kind: u8,
    pub format_version: u16,
    pub object_id: [u8; 32],
}

macro_rules! context_type {
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

context_type!(RecoverySlotContext, RECOVERY_SLOT_OBJECT_KIND);
context_type!(DeviceSlotContext, DEVICE_SLOT_OBJECT_KIND);
context_type!(MetadataContext, METADATA_OBJECT_KIND);
context_type!(TreeContext, TREE_OBJECT_KIND);
context_type!(ManifestContext, MANIFEST_OBJECT_KIND);
context_type!(SnapshotContext, SNAPSHOT_OBJECT_KIND);
context_type!(AuthenticatedHeadContext, AUTHENTICATED_HEAD_OBJECT_KIND);
context_type!(LocalStateContext, LOCAL_STATE_OBJECT_KIND);

macro_rules! plaintext_type {
    ($name:ident, exact $length:expr) => {
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn try_new(mut bytes: Vec<u8>) -> Result<Self, CryptoError> {
                if bytes.len() != $length {
                    bytes.zeroize();
                    return Err(CryptoError::InvalidPlaintextLength);
                }
                Ok(Self(bytes))
            }

            fn into_buffer(mut self) -> Vec<u8> {
                std::mem::take(&mut self.0)
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
    };
    ($name:ident, max $length:expr) => {
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn try_new(mut bytes: Vec<u8>) -> Result<Self, CryptoError> {
                if bytes.len() > $length {
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
                ProtectedBytes(self.into_buffer())
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

plaintext_type!(RecoverySlotPlaintext, exact RECOVERY_SLOT_LEN);
plaintext_type!(DeviceSlotPlaintext, exact DEVICE_SLOT_LEN);
plaintext_type!(MetadataPlaintext, max METADATA_MAX_LEN);
plaintext_type!(TreePlaintext, max TREE_MAX_LEN);
plaintext_type!(ManifestPlaintext, max MANIFEST_MAX_LEN);
plaintext_type!(SnapshotPlaintext, max SNAPSHOT_MAX_LEN);

/// Consuming access to authenticated plaintext that wipes its allocation on drop.
pub struct ProtectedBytes(Vec<u8>);

impl ProtectedBytes {
    pub fn consume<R>(self, consumer: impl FnOnce(&[u8]) -> R) -> R {
        consumer(&self.0)
    }
}

pub(crate) fn protected_bytes_from_sensitive_buffer(bytes: Vec<u8>) -> ProtectedBytes {
    ProtectedBytes(bytes)
}

impl Drop for ProtectedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl RecoverySlotPlaintext {
    #[must_use]
    pub fn from_root_key(key: &VaultRootKey) -> Self {
        Self(key.expose_secret().to_vec())
    }

    #[must_use]
    pub fn into_root_key(self) -> VaultRootKey {
        let mut bytes = Box::new([0_u8; 32]);
        bytes.copy_from_slice(&self.0);
        VaultRootKey::from_boxed_bytes(bytes)
    }
}

impl DeviceSlotPlaintext {
    #[must_use]
    pub fn from_root_key(key: &VaultRootKey) -> Self {
        Self(key.expose_secret().to_vec())
    }

    #[must_use]
    pub fn into_root_key(self) -> VaultRootKey {
        let mut bytes = Box::new([0_u8; 32]);
        bytes.copy_from_slice(&self.0);
        VaultRootKey::from_boxed_bytes(bytes)
    }
}

pub struct AeadEnvelopeParts {
    identity: PublicEnvelopeIdentity,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

/// Owned public fields transferred from a structurally checked AEAD envelope.
///
/// This transfer preserves the checks performed by [`AeadEnvelopeParts::try_new`].
/// A receiving crypto boundary must still rebuild [`AeadEnvelopeParts`] and use the typed
/// envelope constructor to validate the expected object kind and ciphertext length.
pub struct PublicAeadEnvelopeParts {
    identity: PublicEnvelopeIdentity,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

impl AeadEnvelopeParts {
    pub fn try_new(
        identity: PublicEnvelopeIdentity,
        nonce: &[u8],
        ciphertext: Vec<u8>,
        tag: &[u8],
    ) -> Result<Self, CryptoError> {
        validate_public_identity(&identity)?;
        if nonce.len() != 24 || tag.len() != 16 || ciphertext.len() > MAX_TASK3_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        u64::try_from(ciphertext.len()).map_err(|_| CryptoError::InvalidEnvelope)?;
        let mut checked_nonce = [0_u8; 24];
        checked_nonce.copy_from_slice(nonce);
        let mut checked_tag = [0_u8; 16];
        checked_tag.copy_from_slice(tag);
        Ok(Self {
            identity,
            nonce: checked_nonce,
            ciphertext,
            tag: checked_tag,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &PublicEnvelopeIdentity {
        &self.identity
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

    /// Transfers checked public fields without copying the ciphertext allocation.
    #[must_use]
    pub fn into_public_parts(self) -> PublicAeadEnvelopeParts {
        PublicAeadEnvelopeParts {
            identity: self.identity,
            nonce: self.nonce,
            ciphertext: self.ciphertext,
            tag: self.tag,
        }
    }
}

impl PublicAeadEnvelopeParts {
    /// Consumes the transfer value and returns its owned public components.
    #[must_use]
    pub fn into_components(self) -> (PublicEnvelopeIdentity, [u8; 24], Vec<u8>, [u8; 16]) {
        (self.identity, self.nonce, self.ciphertext, self.tag)
    }
}

pub trait TypedAeadEnvelope: Sized {
    fn try_from_parts(parts: AeadEnvelopeParts) -> Result<Self, CryptoError>;
    fn parts(&self) -> &AeadEnvelopeParts;
    fn into_parts(self) -> AeadEnvelopeParts;
}

macro_rules! typed_envelope {
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

typed_envelope!(RecoverySlotEnvelope, RECOVERY_SLOT_OBJECT_KIND, exact RECOVERY_SLOT_LEN);
typed_envelope!(DeviceSlotEnvelope, DEVICE_SLOT_OBJECT_KIND, exact DEVICE_SLOT_LEN);
typed_envelope!(MetadataEnvelope, METADATA_OBJECT_KIND, max METADATA_MAX_LEN);
typed_envelope!(TreeEnvelope, TREE_OBJECT_KIND, max TREE_MAX_LEN);
typed_envelope!(ManifestEnvelope, MANIFEST_OBJECT_KIND, max MANIFEST_MAX_LEN);

pub struct SnapshotEnvelope {
    encrypted: AeadEnvelopeParts,
    outer_authenticator: [u8; 32],
}

impl SnapshotEnvelope {
    pub fn try_new(
        encrypted: AeadEnvelopeParts,
        outer_authenticator: &[u8],
    ) -> Result<Self, CryptoError> {
        validate_typed_identity(encrypted.identity(), SNAPSHOT_OBJECT_KIND)?;
        Self::validate_ciphertext_len(encrypted.ciphertext().len())?;
        if outer_authenticator.len() != 32 {
            return Err(CryptoError::InvalidEnvelope);
        }
        let mut checked = [0_u8; 32];
        checked.copy_from_slice(outer_authenticator);
        Ok(Self {
            encrypted,
            outer_authenticator: checked,
        })
    }

    pub fn validate_ciphertext_len(length: usize) -> Result<(), CryptoError> {
        if length > SNAPSHOT_MAX_LEN {
            return Err(CryptoError::PlaintextTooLarge);
        }
        Ok(())
    }

    #[must_use]
    pub const fn encrypted_parts(&self) -> &AeadEnvelopeParts {
        &self.encrypted
    }

    #[must_use]
    pub const fn outer_authenticator(&self) -> &[u8; 32] {
        &self.outer_authenticator
    }

    #[must_use]
    pub fn into_parts(self) -> (AeadEnvelopeParts, [u8; 32]) {
        (self.encrypted, self.outer_authenticator)
    }
}

macro_rules! authenticator_type {
    ($name:ident) => {
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
                if bytes.len() != 32 {
                    return Err(CryptoError::InvalidEnvelope);
                }
                let mut checked = [0_u8; 32];
                checked.copy_from_slice(bytes);
                Ok(Self(checked))
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

authenticator_type!(HeadAuthenticator);
authenticator_type!(LocalStateAuthenticator);

pub fn encrypt_recovery_slot(
    context: &RecoverySlotContext,
    value: RecoverySlotPlaintext,
    key: &RecoveryWrappingKey,
    random: &mut dyn SecureRandom,
) -> Result<RecoverySlotEnvelope, CryptoError> {
    RecoverySlotEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn decrypt_recovery_slot(
    context: &RecoverySlotContext,
    envelope: &RecoverySlotEnvelope,
    key: &RecoveryWrappingKey,
) -> Result<RecoverySlotPlaintext, CryptoError> {
    RecoverySlotPlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn encrypt_device_slot(
    context: &DeviceSlotContext,
    value: DeviceSlotPlaintext,
    key: &DeviceWrappingKey,
    random: &mut dyn SecureRandom,
) -> Result<DeviceSlotEnvelope, CryptoError> {
    DeviceSlotEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn decrypt_device_slot(
    context: &DeviceSlotContext,
    envelope: &DeviceSlotEnvelope,
    key: &DeviceWrappingKey,
) -> Result<DeviceSlotPlaintext, CryptoError> {
    DeviceSlotPlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn encrypt_metadata(
    context: &MetadataContext,
    value: MetadataPlaintext,
    key: &MetadataKey,
    random: &mut dyn SecureRandom,
) -> Result<MetadataEnvelope, CryptoError> {
    MetadataEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn decrypt_metadata(
    context: &MetadataContext,
    envelope: &MetadataEnvelope,
    key: &MetadataKey,
) -> Result<MetadataPlaintext, CryptoError> {
    MetadataPlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn encrypt_tree(
    context: &TreeContext,
    value: TreePlaintext,
    key: &MetadataKey,
    random: &mut dyn SecureRandom,
) -> Result<TreeEnvelope, CryptoError> {
    TreeEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn decrypt_tree(
    context: &TreeContext,
    envelope: &TreeEnvelope,
    key: &MetadataKey,
) -> Result<TreePlaintext, CryptoError> {
    TreePlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn encrypt_manifest(
    context: &ManifestContext,
    value: ManifestPlaintext,
    key: &MetadataKey,
    random: &mut dyn SecureRandom,
) -> Result<ManifestEnvelope, CryptoError> {
    ManifestEnvelope::try_from_parts(encrypt_parts(
        context.identity(),
        value.into_buffer(),
        key.expose_secret(),
        random,
    )?)
}

pub fn decrypt_manifest(
    context: &ManifestContext,
    envelope: &ManifestEnvelope,
    key: &MetadataKey,
) -> Result<ManifestPlaintext, CryptoError> {
    ManifestPlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.parts(),
        key.expose_secret(),
    )?)
}

pub fn encrypt_snapshot(
    context: &SnapshotContext,
    value: SnapshotPlaintext,
    metadata_key: &MetadataKey,
    authentication_key: &SnapshotAuthenticationKey,
    random: &mut dyn SecureRandom,
) -> Result<SnapshotEnvelope, CryptoError> {
    let encrypted = encrypt_parts(
        context.identity(),
        value.into_buffer(),
        metadata_key.expose_secret(),
        random,
    )?;
    let authenticator = snapshot_authenticator(&encrypted, authentication_key)?;
    SnapshotEnvelope::try_new(encrypted, authenticator.as_bytes())
}

pub fn decrypt_snapshot(
    context: &SnapshotContext,
    envelope: &SnapshotEnvelope,
    metadata_key: &MetadataKey,
    authentication_key: &SnapshotAuthenticationKey,
) -> Result<SnapshotPlaintext, CryptoError> {
    if context.identity() != envelope.encrypted_parts().identity() {
        return Err(CryptoError::Authentication);
    }
    let expected = snapshot_authenticator(envelope.encrypted_parts(), authentication_key)?;
    if expected != blake3::Hash::from_bytes(*envelope.outer_authenticator()) {
        return Err(CryptoError::Authentication);
    }
    SnapshotPlaintext::try_new(decrypt_parts(
        context.identity(),
        envelope.encrypted_parts(),
        metadata_key.expose_secret(),
    )?)
}

pub fn authenticate_head(
    context: &AuthenticatedHeadContext,
    canonical_head: &[u8],
    key: &SnapshotAuthenticationKey,
) -> Result<HeadAuthenticator, CryptoError> {
    let input = canonical_authenticated_record(context.identity(), canonical_head)?;
    HeadAuthenticator::try_from_bytes(keyed_hash(key.expose_secret(), &input).as_bytes())
}

pub fn verify_head(
    context: &AuthenticatedHeadContext,
    canonical_head: &[u8],
    authenticator: &HeadAuthenticator,
    key: &SnapshotAuthenticationKey,
) -> Result<(), CryptoError> {
    let expected = authenticate_head(context, canonical_head, key)?;
    if blake3::Hash::from_bytes(*expected.as_bytes())
        == blake3::Hash::from_bytes(*authenticator.as_bytes())
    {
        Ok(())
    } else {
        Err(CryptoError::Authentication)
    }
}

pub fn authenticate_local_state(
    context: &LocalStateContext,
    canonical_record: &[u8],
    key: &LocalVerificationKey,
) -> Result<LocalStateAuthenticator, CryptoError> {
    let input = canonical_authenticated_record(context.identity(), canonical_record)?;
    LocalStateAuthenticator::try_from_bytes(keyed_hash(key.expose_secret(), &input).as_bytes())
}

pub fn verify_local_state(
    context: &LocalStateContext,
    canonical_record: &[u8],
    authenticator: &LocalStateAuthenticator,
    key: &LocalVerificationKey,
) -> Result<(), CryptoError> {
    let expected = authenticate_local_state(context, canonical_record, key)?;
    if blake3::Hash::from_bytes(*expected.as_bytes())
        == blake3::Hash::from_bytes(*authenticator.as_bytes())
    {
        Ok(())
    } else {
        Err(CryptoError::Authentication)
    }
}

fn validate_public_identity(identity: &PublicEnvelopeIdentity) -> Result<(), CryptoError> {
    if identity.profile_id != CRYPTO_PROFILE_V1
        || identity.format_version != FORMAT_VERSION_V1
        || !(RECOVERY_SLOT_OBJECT_KIND..=CONTENT_CHUNK_OBJECT_KIND).contains(&identity.object_kind)
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(())
}

pub(crate) fn validate_typed_identity(
    identity: &PublicEnvelopeIdentity,
    expected_kind: u8,
) -> Result<(), CryptoError> {
    validate_public_identity(identity)?;
    if identity.object_kind != expected_kind {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(())
}

pub(crate) fn encrypt_parts(
    identity: &PublicEnvelopeIdentity,
    plaintext: Vec<u8>,
    key: &[u8; 32],
    random: &mut dyn SecureRandom,
) -> Result<AeadEnvelopeParts, CryptoError> {
    let mut plaintext = SensitiveBuffer::new(plaintext);
    let mut nonce = [0_u8; 24];
    if let Err(error) = random.fill(&mut nonce) {
        nonce.zeroize();
        return Err(error);
    }
    let aad = canonical_aad(identity, &nonce, plaintext.bytes.len())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let tag = match cipher.encrypt_in_place_detached(
        XNonce::from_slice(&nonce),
        &aad,
        &mut plaintext.bytes,
    ) {
        Ok(tag) => tag,
        Err(_) => return Err(CryptoError::Authentication),
    };
    AeadEnvelopeParts::try_new(
        identity.to_owned(),
        &nonce,
        plaintext.into_public(),
        tag.as_slice(),
    )
}

pub(crate) fn decrypt_parts(
    identity: &PublicEnvelopeIdentity,
    parts: &AeadEnvelopeParts,
    key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    if identity != parts.identity() {
        return Err(CryptoError::Authentication);
    }
    let aad = canonical_aad(identity, parts.nonce(), parts.ciphertext().len())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut plaintext = SensitiveBuffer::new(parts.ciphertext().to_vec());
    if cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(parts.nonce()),
            &aad,
            &mut plaintext.bytes,
            Tag::from_slice(parts.tag()),
        )
        .is_err()
    {
        return Err(CryptoError::Authentication);
    }
    Ok(plaintext.into_sensitive())
}

struct SensitiveBuffer {
    bytes: Vec<u8>,
    wipe_on_drop: bool,
}

impl SensitiveBuffer {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            wipe_on_drop: true,
        }
    }

    fn into_public(mut self) -> Vec<u8> {
        self.wipe_on_drop = false;
        std::mem::take(&mut self.bytes)
    }

    fn into_sensitive(mut self) -> Vec<u8> {
        self.wipe_on_drop = false;
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        if self.wipe_on_drop {
            self.bytes.zeroize();
        }
    }
}

fn canonical_aad(
    identity: &PublicEnvelopeIdentity,
    nonce: &[u8; 24],
    ciphertext_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let ciphertext_len = u64::try_from(ciphertext_len).map_err(|_| CryptoError::InvalidEnvelope)?;
    let mut encoder = Encoder::new(Vec::with_capacity(96));
    encoder.array(7).map_err(|_| CryptoError::InvalidEnvelope)?;
    encode_identity(&mut encoder, identity)?;
    encoder
        .bytes(nonce)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .u64(ciphertext_len)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    Ok(encoder.into_writer())
}

fn snapshot_authenticator(
    parts: &AeadEnvelopeParts,
    key: &SnapshotAuthenticationKey,
) -> Result<blake3::Hash, CryptoError> {
    let length =
        u64::try_from(parts.ciphertext().len()).map_err(|_| CryptoError::InvalidEnvelope)?;
    let mut encoder = Encoder::new(Vec::with_capacity(
        parts.ciphertext().len().saturating_add(128),
    ));
    encoder.array(9).map_err(|_| CryptoError::InvalidEnvelope)?;
    encode_identity(&mut encoder, parts.identity())?;
    encoder
        .bytes(parts.nonce())
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .u64(length)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .bytes(parts.ciphertext())
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .bytes(parts.tag())
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    Ok(keyed_hash(key.expose_secret(), &encoder.into_writer()))
}

fn canonical_authenticated_record(
    identity: &PublicEnvelopeIdentity,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_public_identity(identity)?;
    if payload.len() > AUTHENTICATED_RECORD_MAX_LEN {
        return Err(CryptoError::PlaintextTooLarge);
    }
    let length = u64::try_from(payload.len()).map_err(|_| CryptoError::InvalidEnvelope)?;
    let mut encoder = Encoder::new(Vec::with_capacity(payload.len().saturating_add(80)));
    encoder.array(7).map_err(|_| CryptoError::InvalidEnvelope)?;
    encode_identity(&mut encoder, identity)?;
    encoder
        .u64(length)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .bytes(payload)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    Ok(encoder.into_writer())
}

fn encode_identity(
    encoder: &mut Encoder<Vec<u8>>,
    identity: &PublicEnvelopeIdentity,
) -> Result<(), CryptoError> {
    encoder
        .u16(identity.profile_id)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .bytes(&identity.vault_id)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .u8(identity.object_kind)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .u16(identity.format_version)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    encoder
        .bytes(&identity.object_id)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    Ok(())
}

pub(crate) fn keyed_hasher(key: &[u8; 32]) -> Zeroizing<blake3::Hasher> {
    Zeroizing::new(blake3::Hasher::new_keyed(key))
}

fn keyed_hash(key: &[u8; 32], input: &[u8]) -> blake3::Hash {
    let mut hasher = keyed_hasher(key);
    hasher.update(input);
    hasher.finalize()
}
