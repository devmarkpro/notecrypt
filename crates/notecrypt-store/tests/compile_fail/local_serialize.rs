use notecrypt_store::{UnlockedVault, UnlockedVaultLease};

fn require_serialize<T: serde::Serialize>() {}

fn main() {
    require_serialize::<UnlockedVault>();
    require_serialize::<UnlockedVaultLease>();
}
