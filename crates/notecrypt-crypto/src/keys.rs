use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    ChunkFingerprintKey, ContentWrappingKey, CryptoError, LocalVerificationKey, MetadataKey,
    SnapshotAuthenticationKey, VaultRootKey,
};

pub struct VaultKeys {
    pub metadata: MetadataKey,
    pub snapshot_authentication: SnapshotAuthenticationKey,
    pub chunk_fingerprint: ChunkFingerprintKey,
    pub content_wrapping: ContentWrappingKey,
    pub local_verification: LocalVerificationKey,
}

pub fn derive_vault_keys(root: &VaultRootKey) -> Result<VaultKeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root.expose_secret());
    Ok(VaultKeys {
        metadata: MetadataKey::from_boxed_bytes(expand(&hkdf, b"notecrypt/metadata/v1")?),
        snapshot_authentication: SnapshotAuthenticationKey::from_boxed_bytes(expand(
            &hkdf,
            b"notecrypt/snapshot-authentication/v1",
        )?),
        chunk_fingerprint: ChunkFingerprintKey::from_boxed_bytes(expand(
            &hkdf,
            b"notecrypt/chunk-fingerprint/v1",
        )?),
        content_wrapping: ContentWrappingKey::from_boxed_bytes(expand(
            &hkdf,
            b"notecrypt/content-wrapping/v1",
        )?),
        local_verification: LocalVerificationKey::from_boxed_bytes(expand(
            &hkdf,
            b"notecrypt/local-verification/v1",
        )?),
    })
}

fn expand(hkdf: &Hkdf<Sha256>, label: &[u8]) -> Result<Box<[u8; 32]>, CryptoError> {
    let mut output = Box::new([0_u8; 32]);
    if hkdf.expand(label, output.as_mut()).is_err() {
        output.zeroize();
        return Err(CryptoError::KeyDerivation);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::derive_vault_keys;
    use crate::VaultRootKey;

    #[test]
    fn profile_one_hkdf_outputs_match_frozen_vectors() {
        let mut root = [0_u8; 32];
        for (index, byte) in root.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let keys = derive_vault_keys(&VaultRootKey::from_boxed_bytes(Box::new(root))).unwrap();

        assert_eq!(
            hex(keys.metadata.expose_secret()),
            "ce948947db5a10971e7e6220b299bf76877ffc1ed340aaf76bbfbb91ef1119b9"
        );
        assert_eq!(
            hex(keys.snapshot_authentication.expose_secret()),
            "771e66d762711a835a14c1bb038c7ebe3b96d46127460f24490374cadb53172f"
        );
        assert_eq!(
            hex(keys.chunk_fingerprint.expose_secret()),
            "7f9d06c8bd4ba1237371ae761cb63a2f46e512d66f187173f4a3c6eba3f532c0"
        );
        assert_eq!(
            hex(keys.content_wrapping.expose_secret()),
            "170294fd1aa51560b49f5d659032b8005801f04d62a8dade2914c7f89d9ece73"
        );
        assert_eq!(
            hex(keys.local_verification.expose_secret()),
            "93ecded6fddf662623ca50e6b38eea6f479ce80d2c53a573314a5c3d4151c019"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
