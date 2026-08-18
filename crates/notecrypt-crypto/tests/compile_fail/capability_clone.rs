use notecrypt_crypto::{
    AeadEnvelopeParts, AuthenticatedHeadContext, ChunkFingerprintKey, ContentWrappingKey,
    DeviceSlotContext, DeviceSlotEnvelope, DeviceSlotPlaintext, DeviceWrappingKey,
    HeadAuthenticator, LocalStateAuthenticator, LocalStateContext, LocalVerificationKey,
    ManifestContext, ManifestEnvelope, ManifestPlaintext, MetadataContext, MetadataEnvelope,
    MetadataKey, MetadataPlaintext, ProtectedBytes, RecoveryPassphrase, RecoveryPhrase,
    RecoverySlotContext, RecoverySlotEnvelope, RecoverySlotPlaintext, RecoveryWrappingKey,
    SnapshotAuthenticationKey, SnapshotContext, SnapshotEnvelope, SnapshotPlaintext, TreeContext,
    TreeEnvelope, TreePlaintext, VaultRootKey,
};

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<RecoveryPassphrase>();
    assert_clone::<RecoveryPhrase>();
    assert_clone::<VaultRootKey>();
    assert_clone::<RecoveryWrappingKey>();
    assert_clone::<MetadataKey>();
    assert_clone::<SnapshotAuthenticationKey>();
    assert_clone::<ChunkFingerprintKey>();
    assert_clone::<ContentWrappingKey>();
    assert_clone::<LocalVerificationKey>();
    assert_clone::<DeviceWrappingKey>();
    assert_clone::<RecoverySlotPlaintext>();
    assert_clone::<DeviceSlotPlaintext>();
    assert_clone::<MetadataPlaintext>();
    assert_clone::<TreePlaintext>();
    assert_clone::<ManifestPlaintext>();
    assert_clone::<SnapshotPlaintext>();
    assert_clone::<ProtectedBytes>();
    assert_clone::<RecoverySlotContext>();
    assert_clone::<DeviceSlotContext>();
    assert_clone::<MetadataContext>();
    assert_clone::<TreeContext>();
    assert_clone::<ManifestContext>();
    assert_clone::<SnapshotContext>();
    assert_clone::<AuthenticatedHeadContext>();
    assert_clone::<LocalStateContext>();
    assert_clone::<AeadEnvelopeParts>();
    assert_clone::<RecoverySlotEnvelope>();
    assert_clone::<DeviceSlotEnvelope>();
    assert_clone::<MetadataEnvelope>();
    assert_clone::<TreeEnvelope>();
    assert_clone::<ManifestEnvelope>();
    assert_clone::<SnapshotEnvelope>();
    assert_clone::<HeadAuthenticator>();
    assert_clone::<LocalStateAuthenticator>();
}
