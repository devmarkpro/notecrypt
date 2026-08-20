use notecrypt_store::{UnlockedVault, UnlockedVaultLease};

fn inspect_session(value: UnlockedVault) {
    let _ = value.keys;
}

fn inspect_lease(value: UnlockedVaultLease) {
    let _ = value.generation;
}

fn main() {}
