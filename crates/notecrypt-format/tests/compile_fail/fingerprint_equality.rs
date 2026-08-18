use notecrypt_format::{ChunkDescriptor, RevisionManifest};

fn require_partial_eq<T: PartialEq>() {}
fn require_eq<T: Eq>() {}

fn main() {
    require_partial_eq::<ChunkDescriptor>();
    require_eq::<ChunkDescriptor>();
    require_partial_eq::<RevisionManifest>();
    require_eq::<RevisionManifest>();
}
