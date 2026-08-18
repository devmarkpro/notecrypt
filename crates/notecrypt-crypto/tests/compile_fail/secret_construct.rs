use notecrypt_crypto::{
    ChunkFingerprintKey, ContentWrappingKey, DeviceWrappingKey, LocalVerificationKey, MetadataKey,
    RecoveryPassphrase, RecoveryPhrase, RecoveryWrappingKey, SnapshotAuthenticationKey,
    VaultRootKey,
};

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

fn main() {
    let _ = RecoveryPassphrase(value());
    let _ = RecoveryPhrase(value());
    let _ = VaultRootKey(value());
    let _ = RecoveryWrappingKey(value());
    let _ = MetadataKey(value());
    let _ = SnapshotAuthenticationKey(value());
    let _ = ChunkFingerprintKey(value());
    let _ = ContentWrappingKey(value());
    let _ = LocalVerificationKey(value());
    let _ = DeviceWrappingKey(value());
}
