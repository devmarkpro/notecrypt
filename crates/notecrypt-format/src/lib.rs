//! Canonical and bounded durable formats for Notecrypt.

mod crypto_profile;
mod error;
mod header;
mod limits;
mod manifest;
mod object;
mod snapshot;

pub use crypto_profile::{
    AeadAlgorithmId, AuthenticationAlgorithmId, CryptoProfileId, DerivationProfileId,
    FingerprintAlgorithmId, FormatVersion, KdfProfileId, ObjectKind, OrdinaryAeadKind,
};
pub use error::FormatError;
pub use header::{
    BootstrapHeader, CryptoSuite, KdfParameters, RecoverySlot, decode_bootstrap, encode_bootstrap,
};
pub use limits::DecodeLimits;
pub use manifest::{
    ChunkDescriptor, ContentPayload, RevisionManifest, decode_content_payload, decode_manifest,
    encode_content_payload, encode_manifest,
};
pub use object::{
    AeadObject, AeadObjectParts, CompactChunkKey, ContentChunkObject, ContentChunkObjectParts,
    HeadRecord, LocalStateRecord, SnapshotObject, SnapshotObjectParts, decode_aead_object,
    decode_content_chunk, decode_head, decode_local_state, decode_snapshot_object,
    encode_aead_object, encode_content_chunk, encode_head, encode_local_state,
    encode_snapshot_object,
};
pub use snapshot::{
    HeadPayload, LocalRecordType, LocalStatePayload, LogicalTree, PriorEntryKind, SnapshotPayload,
    TreeEntry, decode_head_payload, decode_local_state_payload, decode_snapshot_payload,
    decode_tree, encode_head_payload, encode_local_state_payload, encode_snapshot_payload,
    encode_tree,
};

/// Version one of the durable vault format.
pub const FORMAT_VERSION_V1: u16 = 0x0001;
