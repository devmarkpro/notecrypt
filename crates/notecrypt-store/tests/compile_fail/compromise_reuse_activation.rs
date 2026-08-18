use notecrypt_store::PendingVaultTarget;

fn reuse(target: Box<dyn PendingVaultTarget>) {
    let _ = target.activate();
    let _ = target.activate();
}

fn main() {}
