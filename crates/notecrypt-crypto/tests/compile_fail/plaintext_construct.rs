use notecrypt_crypto::{
    DeviceSlotPlaintext, ManifestPlaintext, MetadataPlaintext, ProtectedBytes,
    RecoverySlotPlaintext, SnapshotPlaintext, TreePlaintext,
};

fn main() {
    let _ = RecoverySlotPlaintext(vec![0; 32]);
    let _ = DeviceSlotPlaintext(vec![0; 32]);
    let _ = MetadataPlaintext(vec![]);
    let _ = TreePlaintext(vec![]);
    let _ = ManifestPlaintext(vec![]);
    let _ = SnapshotPlaintext(vec![]);
    let _ = ProtectedBytes(vec![]);
}
