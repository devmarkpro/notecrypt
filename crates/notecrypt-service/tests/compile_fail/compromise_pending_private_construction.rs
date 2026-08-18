use notecrypt_service::{OperationId, PendingCompromiseRekey};

fn forge(operation: OperationId) -> PendingCompromiseRekey {
    PendingCompromiseRekey {
        generation: 1,
        operation,
        guard: None,
    }
}

fn main() {}
