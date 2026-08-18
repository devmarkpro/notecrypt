use notecrypt_crypto::{
    AeadEnvelopeParts, DeviceSlotEnvelope, ManifestEnvelope, MetadataEnvelope,
    RecoverySlotEnvelope, TreeEnvelope,
};

fn recovery(parts: AeadEnvelopeParts) {
    let _ = RecoverySlotEnvelope(parts);
}

fn device(parts: AeadEnvelopeParts) {
    let _ = DeviceSlotEnvelope(parts);
}

fn metadata(parts: AeadEnvelopeParts) {
    let _ = MetadataEnvelope(parts);
}

fn tree(parts: AeadEnvelopeParts) {
    let _ = TreeEnvelope(parts);
}

fn manifest(parts: AeadEnvelopeParts) {
    let _ = ManifestEnvelope(parts);
}

fn main() {}
