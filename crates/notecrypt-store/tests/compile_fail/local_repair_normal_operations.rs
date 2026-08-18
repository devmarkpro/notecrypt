use notecrypt_store::VaultRepair;

fn bypass_repair_only_scope(repair: VaultRepair) {
    let _ = repair.acquire_lease();
}

fn main() {}
