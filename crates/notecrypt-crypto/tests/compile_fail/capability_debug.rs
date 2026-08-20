use std::fmt::Debug;

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

fn assert_debug<T: Debug>() {}

fn main() {
    assert_debug::<RecoveryPassphrase>();
    assert_debug::<RecoveryPhrase>();
    assert_debug::<VaultRootKey>();
    assert_debug::<RecoveryWrappingKey>();
    assert_debug::<MetadataKey>();
    assert_debug::<SnapshotAuthenticationKey>();
    assert_debug::<ChunkFingerprintKey>();
    assert_debug::<ContentWrappingKey>();
    assert_debug::<LocalVerificationKey>();
    assert_debug::<DeviceWrappingKey>();
    assert_debug::<RecoverySlotPlaintext>();
    assert_debug::<DeviceSlotPlaintext>();
    assert_debug::<MetadataPlaintext>();
    assert_debug::<TreePlaintext>();
    assert_debug::<ManifestPlaintext>();
    assert_debug::<SnapshotPlaintext>();
    assert_debug::<ProtectedBytes>();
    assert_debug::<RecoverySlotContext>();
    assert_debug::<DeviceSlotContext>();
    assert_debug::<MetadataContext>();
    assert_debug::<TreeContext>();
    assert_debug::<ManifestContext>();
    assert_debug::<SnapshotContext>();
    assert_debug::<AuthenticatedHeadContext>();
    assert_debug::<LocalStateContext>();
    assert_debug::<AeadEnvelopeParts>();
    assert_debug::<RecoverySlotEnvelope>();
    assert_debug::<DeviceSlotEnvelope>();
    assert_debug::<MetadataEnvelope>();
    assert_debug::<TreeEnvelope>();
    assert_debug::<ManifestEnvelope>();
    assert_debug::<SnapshotEnvelope>();
    assert_debug::<HeadAuthenticator>();
    assert_debug::<LocalStateAuthenticator>();
}
