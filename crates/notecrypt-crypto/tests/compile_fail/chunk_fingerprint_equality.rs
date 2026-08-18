use notecrypt_crypto::{ChunkFingerprint, EncryptedChunk, EncryptedChunkDescriptor};

fn require_partial_eq<T: PartialEq>() {}
fn require_eq<T: Eq>() {}

fn main() {
    require_partial_eq::<ChunkFingerprint>();
    require_eq::<ChunkFingerprint>();
    require_partial_eq::<EncryptedChunkDescriptor>();
    require_eq::<EncryptedChunkDescriptor>();
    require_partial_eq::<EncryptedChunk>();
    require_eq::<EncryptedChunk>();
}
