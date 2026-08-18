use notecrypt_core::VaultId;
use notecrypt_store::cleanup_test_support::{CleanupRandomStep, ScriptedCleanupRegistry};

fn main() {
    let mut registry = ScriptedCleanupRegistry::new(
        VaultId::from_bytes([0x41; 16]),
        7,
        8,
        [CleanupRandomStep::Bytes([0x12; 16])],
    )
    .unwrap();
    let registered = registry.reserve_and_register().unwrap();
    let _active = registry.activate(registered).unwrap();
    let _reused = registry.activate(registered).unwrap();
}
