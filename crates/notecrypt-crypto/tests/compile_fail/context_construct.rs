use notecrypt_crypto::{
    AuthenticatedHeadContext, DeviceSlotContext, LocalStateContext, ManifestContext,
    MetadataContext, PublicEnvelopeIdentity, RecoverySlotContext, SnapshotContext, TreeContext,
};

fn main() {
    let identity = PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [0; 16],
        object_kind: 1,
        format_version: 1,
        object_id: [0; 32],
    };
    let _ = RecoverySlotContext(identity);
    let _ = DeviceSlotContext(identity);
    let _ = MetadataContext(identity);
    let _ = TreeContext(identity);
    let _ = ManifestContext(identity);
    let _ = SnapshotContext(identity);
    let _ = AuthenticatedHeadContext(identity);
    let _ = LocalStateContext(identity);
}
