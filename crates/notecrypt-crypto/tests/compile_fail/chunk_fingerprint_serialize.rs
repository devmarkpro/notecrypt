use notecrypt_crypto::{
    ChunkFingerprint, ChunkFingerprintContext, ChunkKeyEnvelope, ChunkKeyPlaintext,
    ChunkKeyWrapContext, ContentChunkContext, ContentChunkEnvelope, ContentChunkPlaintext,
    EncryptedChunk, EncryptedChunkDescriptor,
};
use serde::Serialize;

fn require_serialize<T: Serialize>() {}

fn main() {
    require_serialize::<ChunkKeyWrapContext>();
    require_serialize::<ContentChunkContext>();
    require_serialize::<ChunkFingerprintContext>();
    require_serialize::<ChunkKeyPlaintext>();
    require_serialize::<ContentChunkPlaintext>();
    require_serialize::<ChunkKeyEnvelope>();
    require_serialize::<ContentChunkEnvelope>();
    require_serialize::<ChunkFingerprint>();
    require_serialize::<EncryptedChunkDescriptor>();
    require_serialize::<EncryptedChunk>();
}
