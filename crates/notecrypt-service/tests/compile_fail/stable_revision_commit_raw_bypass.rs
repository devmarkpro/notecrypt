use notecrypt_service::{LocalStreamRevisionRequest, LocalVaultLease, VaultPublicationGuard};

fn bypass(
    lease: &mut dyn LocalVaultLease,
    request: LocalStreamRevisionRequest,
    guard: &mut dyn VaultPublicationGuard,
) {
    let mut source = std::io::empty();
    let _ = lease.commit_streamed_revision(request, &mut source, guard);
}

fn main() {}
