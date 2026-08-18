use std::fmt::Display;

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

fn assert_display<T: Display>() {}

fn main() {
    assert_display::<RecoveryPassphrase>();
    assert_display::<RecoveryPhrase>();
    assert_display::<VaultRootKey>();
    assert_display::<RecoveryWrappingKey>();
    assert_display::<MetadataKey>();
    assert_display::<SnapshotAuthenticationKey>();
    assert_display::<ChunkFingerprintKey>();
    assert_display::<ContentWrappingKey>();
    assert_display::<LocalVerificationKey>();
    assert_display::<DeviceWrappingKey>();
    assert_display::<RecoverySlotPlaintext>();
    assert_display::<DeviceSlotPlaintext>();
    assert_display::<MetadataPlaintext>();
    assert_display::<TreePlaintext>();
    assert_display::<ManifestPlaintext>();
    assert_display::<SnapshotPlaintext>();
    assert_display::<ProtectedBytes>();
    assert_display::<RecoverySlotContext>();
    assert_display::<DeviceSlotContext>();
    assert_display::<MetadataContext>();
    assert_display::<TreeContext>();
    assert_display::<ManifestContext>();
    assert_display::<SnapshotContext>();
    assert_display::<AuthenticatedHeadContext>();
    assert_display::<LocalStateContext>();
    assert_display::<AeadEnvelopeParts>();
    assert_display::<RecoverySlotEnvelope>();
    assert_display::<DeviceSlotEnvelope>();
    assert_display::<MetadataEnvelope>();
    assert_display::<TreeEnvelope>();
    assert_display::<ManifestEnvelope>();
    assert_display::<SnapshotEnvelope>();
    assert_display::<HeadAuthenticator>();
    assert_display::<LocalStateAuthenticator>();
}
