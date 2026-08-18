use std::sync::atomic::AtomicBool;

use notecrypt_store::{AuthenticatedLogicalEntry, CompromiseRekeySource, PendingVaultTarget};

fn reuse(
    target: &mut dyn PendingVaultTarget,
    source: &mut dyn CompromiseRekeySource,
    entry: AuthenticatedLogicalEntry,
    cancel: &AtomicBool,
) {
    let _ = target.stage_entry(source, entry, cancel);
    let _ = target.stage_entry(source, entry, cancel);
}

fn main() {}
