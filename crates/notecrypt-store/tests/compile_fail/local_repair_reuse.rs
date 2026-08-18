use std::sync::atomic::AtomicBool;

use notecrypt_store::{VaultRepair, VaultRepairAction};

fn use_twice(repair: VaultRepair, cancel: &AtomicBool) {
    let _ = repair.apply(VaultRepairAction::RebuildTrustedHead, cancel);
    let _ = repair.apply(VaultRepairAction::RebuildTrustedHead, cancel);
}

fn main() {}
