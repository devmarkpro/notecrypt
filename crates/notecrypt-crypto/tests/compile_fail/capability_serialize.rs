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
use serde::Serialize;

fn assert_serialize<T: Serialize>() {}

fn main() {
    assert_serialize::<RecoveryPassphrase>();
    assert_serialize::<RecoveryPhrase>();
    assert_serialize::<VaultRootKey>();
    assert_serialize::<RecoveryWrappingKey>();
    assert_serialize::<MetadataKey>();
    assert_serialize::<SnapshotAuthenticationKey>();
    assert_serialize::<ChunkFingerprintKey>();
    assert_serialize::<ContentWrappingKey>();
    assert_serialize::<LocalVerificationKey>();
    assert_serialize::<DeviceWrappingKey>();
    assert_serialize::<RecoverySlotPlaintext>();
    assert_serialize::<DeviceSlotPlaintext>();
    assert_serialize::<MetadataPlaintext>();
    assert_serialize::<TreePlaintext>();
    assert_serialize::<ManifestPlaintext>();
    assert_serialize::<SnapshotPlaintext>();
    assert_serialize::<ProtectedBytes>();
    assert_serialize::<RecoverySlotContext>();
    assert_serialize::<DeviceSlotContext>();
    assert_serialize::<MetadataContext>();
    assert_serialize::<TreeContext>();
    assert_serialize::<ManifestContext>();
    assert_serialize::<SnapshotContext>();
    assert_serialize::<AuthenticatedHeadContext>();
    assert_serialize::<LocalStateContext>();
    assert_serialize::<AeadEnvelopeParts>();
    assert_serialize::<RecoverySlotEnvelope>();
    assert_serialize::<DeviceSlotEnvelope>();
    assert_serialize::<MetadataEnvelope>();
    assert_serialize::<TreeEnvelope>();
    assert_serialize::<ManifestEnvelope>();
    assert_serialize::<SnapshotEnvelope>();
    assert_serialize::<HeadAuthenticator>();
    assert_serialize::<LocalStateAuthenticator>();
}
