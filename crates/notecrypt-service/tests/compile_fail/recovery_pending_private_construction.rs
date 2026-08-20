use notecrypt_service::{OperationId, PendingRecoveryInitialization};

fn forge(operation: OperationId) -> PendingRecoveryInitialization {
    PendingRecoveryInitialization {
        generation: 1,
        operation,
        guard: None,
    }
}

fn main() {}
