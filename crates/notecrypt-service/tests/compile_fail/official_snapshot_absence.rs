use notecrypt_service::{PendingRecoveryInitialization, ServiceSnapshot};

fn embed(pending: PendingRecoveryInitialization) -> ServiceSnapshot {
    ServiceSnapshot::PendingRecoveryInitialization(pending)
}

fn main() {}
