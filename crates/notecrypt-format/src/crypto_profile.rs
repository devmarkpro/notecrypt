use crate::FormatError;

macro_rules! checked_identifier {
    ($name:ident, $constructor:ident, $value:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(u16);

        impl $name {
            #[must_use]
            pub const fn $constructor() -> Self {
                Self($value)
            }

            #[must_use]
            pub const fn get(self) -> u16 {
                self.0
            }
        }

        impl TryFrom<u16> for $name {
            type Error = FormatError;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                if value == $value {
                    Ok(Self(value))
                } else {
                    Err(FormatError::UnsupportedCryptoIdentifier)
                }
            }
        }
    };
}

checked_identifier!(CryptoProfileId, profile_one, 0x0001);
checked_identifier!(AeadAlgorithmId, xchacha20_poly1305, 0x0001);
checked_identifier!(AuthenticationAlgorithmId, keyed_blake3_256, 0x0002);
checked_identifier!(FingerprintAlgorithmId, keyed_blake3_256, 0x0003);
checked_identifier!(KdfProfileId, argon2id_v1, 0x0001);
checked_identifier!(DerivationProfileId, hkdf_sha256_v1, 0x0001);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatVersion(u16);

impl FormatVersion {
    #[must_use]
    pub const fn v1() -> Self {
        Self(crate::FORMAT_VERSION_V1)
    }
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for FormatVersion {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value == crate::FORMAT_VERSION_V1 {
            Ok(Self(value))
        } else {
            Err(FormatError::UnsupportedVersion(value))
        }
    }
}

/// Checked phase-one wire kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    RecoverySlot = 0x01,
    DeviceSlot = 0x02,
    Metadata = 0x03,
    Tree = 0x04,
    Manifest = 0x05,
    Snapshot = 0x06,
    AuthenticatedHead = 0x07,
    LocalState = 0x08,
    ChunkKey = 0x09,
    ContentChunk = 0x0a,
}

impl ObjectKind {
    #[must_use]
    pub const fn get(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ObjectKind {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::RecoverySlot),
            0x02 => Ok(Self::DeviceSlot),
            0x03 => Ok(Self::Metadata),
            0x04 => Ok(Self::Tree),
            0x05 => Ok(Self::Manifest),
            0x06 => Ok(Self::Snapshot),
            0x07 => Ok(Self::AuthenticatedHead),
            0x08 => Ok(Self::LocalState),
            0x09 => Ok(Self::ChunkKey),
            0x0a => Ok(Self::ContentChunk),
            _ => Err(FormatError::UnsupportedObjectKind),
        }
    }
}

/// Kinds represented by the ordinary AEAD envelope schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrdinaryAeadKind {
    RecoverySlot,
    DeviceSlot,
    Metadata,
    Tree,
    Manifest,
}

impl OrdinaryAeadKind {
    #[must_use]
    pub const fn object_kind(self) -> ObjectKind {
        match self {
            Self::RecoverySlot => ObjectKind::RecoverySlot,
            Self::DeviceSlot => ObjectKind::DeviceSlot,
            Self::Metadata => ObjectKind::Metadata,
            Self::Tree => ObjectKind::Tree,
            Self::Manifest => ObjectKind::Manifest,
        }
    }
}

impl TryFrom<ObjectKind> for OrdinaryAeadKind {
    type Error = FormatError;

    fn try_from(value: ObjectKind) -> Result<Self, Self::Error> {
        match value {
            ObjectKind::RecoverySlot => Ok(Self::RecoverySlot),
            ObjectKind::DeviceSlot => Ok(Self::DeviceSlot),
            ObjectKind::Metadata => Ok(Self::Metadata),
            ObjectKind::Tree => Ok(Self::Tree),
            ObjectKind::Manifest => Ok(Self::Manifest),
            _ => Err(FormatError::UnsupportedObjectKind),
        }
    }
}
