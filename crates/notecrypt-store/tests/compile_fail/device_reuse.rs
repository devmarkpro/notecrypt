use notecrypt_core::VaultId;
use notecrypt_crypto::DeviceWrappingKey;
use notecrypt_store::device_test_support::{DeviceRandomStep, ScriptedDeviceRegistry};
use notecrypt_store::{DeviceEnrollment, DeviceProvider, DeviceReference};

fn main() {
    let mut registry = ScriptedDeviceRegistry::new(
        VaultId::from_bytes([0x51; 16]),
        [
            DeviceRandomStep::Fill(vec![1; 16]),
            DeviceRandomStep::Fill(vec![2; 24]),
        ],
    )
    .unwrap();
    let enrollment = DeviceEnrollment::new(
        DeviceProvider::try_new("provider".to_owned()).unwrap(),
        DeviceReference::try_new("reference".to_owned()).unwrap(),
        DeviceWrappingKey::try_from_protected_bytes(vec![3; 32]).unwrap(),
    );
    let _first = registry.enroll(enrollment).unwrap();
    let _reuse = registry.enroll(enrollment).unwrap();
}
