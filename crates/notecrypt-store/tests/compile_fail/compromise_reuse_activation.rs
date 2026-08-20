use notecrypt_store::PendingVaultTarget;

fn reuse(target: Box<dyn PendingVaultTarget>) {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let _ = target.activate(&cancel);
    let _ = target.activate(&cancel);
}

fn main() {}
