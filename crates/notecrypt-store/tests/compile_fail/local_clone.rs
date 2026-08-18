use notecrypt_store::{UnlockedVault, UnlockedVaultLease};

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<UnlockedVault>();
    require_clone::<UnlockedVaultLease>();
}
