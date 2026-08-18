use notecrypt_service::{OperationId, PendingFreshnessAcknowledgement};

fn forge(operation: OperationId) -> PendingFreshnessAcknowledgement {
    PendingFreshnessAcknowledgement {
        generation: 1,
        operation,
        guard: None,
    }
}

fn main() {}
