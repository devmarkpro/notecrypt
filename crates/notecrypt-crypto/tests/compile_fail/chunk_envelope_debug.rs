use std::fmt::{Debug, Display};

use notecrypt_crypto::{
    ChunkFingerprint, ChunkFingerprintContext, ChunkKeyEnvelope, ChunkKeyPlaintext,
    ChunkKeyWrapContext, ContentChunkContext, ContentChunkEnvelope, ContentChunkPlaintext,
    EncryptedChunk, EncryptedChunkDescriptor,
};

fn require_clone<T: Clone>() {}
fn require_debug<T: Debug>() {}
fn require_display<T: Display>() {}

fn main() {
    require_clone::<ChunkKeyWrapContext>();
    require_clone::<ContentChunkContext>();
    require_clone::<ChunkFingerprintContext>();
    require_clone::<ChunkKeyPlaintext>();
    require_clone::<ContentChunkPlaintext>();
    require_clone::<ChunkKeyEnvelope>();
    require_clone::<ContentChunkEnvelope>();
    require_clone::<ChunkFingerprint>();
    require_clone::<EncryptedChunkDescriptor>();
    require_clone::<EncryptedChunk>();
    require_debug::<ChunkKeyWrapContext>();
    require_debug::<ContentChunkContext>();
    require_debug::<ChunkFingerprintContext>();
    require_debug::<ChunkKeyPlaintext>();
    require_debug::<ContentChunkPlaintext>();
    require_debug::<ChunkKeyEnvelope>();
    require_debug::<ContentChunkEnvelope>();
    require_debug::<ChunkFingerprint>();
    require_debug::<EncryptedChunkDescriptor>();
    require_debug::<EncryptedChunk>();
    require_display::<ChunkKeyWrapContext>();
    require_display::<ContentChunkContext>();
    require_display::<ChunkFingerprintContext>();
    require_display::<ChunkKeyPlaintext>();
    require_display::<ContentChunkPlaintext>();
    require_display::<ChunkKeyEnvelope>();
    require_display::<ContentChunkEnvelope>();
    require_display::<ChunkFingerprint>();
    require_display::<EncryptedChunkDescriptor>();
    require_display::<EncryptedChunk>();

    let _ = ChunkKeyWrapContext(todo!());
    let _ = ContentChunkContext(todo!());
    let _ = ChunkFingerprintContext {};
    let _ = ChunkKeyPlaintext(todo!());
    let _ = ContentChunkPlaintext(Vec::new());
    let _ = ChunkKeyEnvelope(todo!());
    let _ = ContentChunkEnvelope(todo!());
    let _ = ChunkFingerprint([0; 32]);
}
