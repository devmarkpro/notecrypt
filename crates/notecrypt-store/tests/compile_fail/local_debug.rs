use notecrypt_store::{UnlockedVault, UnlockedVaultLease};

fn require_debug<T: std::fmt::Debug>() {}

fn main() {
    require_debug::<UnlockedVault>();
    require_debug::<UnlockedVaultLease>();
}
