use thiserror::Error;

/// Structural failures detected before domain or cryptographic construction.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("input exceeds a phase-one format bound")]
    LimitExceeded,
    #[error("input is malformed CBOR")]
    Malformed,
    #[error("input is not the unique canonical encoding")]
    NonCanonical,
    #[error("input contains trailing bytes")]
    TrailingBytes,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported cryptographic identifier")]
    UnsupportedCryptoIdentifier,
    #[error("unsupported object kind")]
    UnsupportedObjectKind,
    #[error("field has an invalid length")]
    InvalidLength,
    #[error("declared and actual lengths differ")]
    LengthMismatch,
    #[error("numeric conversion or size arithmetic overflowed")]
    Overflow,
    #[error("bounded allocation failed")]
    AllocationFailed,
}

impl From<minicbor::decode::Error> for FormatError {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::Malformed
    }
}

impl<E> From<minicbor::encode::Error<E>> for FormatError {
    fn from(_: minicbor::encode::Error<E>) -> Self {
        Self::Overflow
    }
}
