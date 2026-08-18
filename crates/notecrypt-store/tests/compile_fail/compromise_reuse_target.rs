use notecrypt_store::PendingVaultTarget;

fn reuse(target: Box<dyn PendingVaultTarget>) {
    let _ = target.abort();
    let _ = target.abort();
}

fn main() {}
