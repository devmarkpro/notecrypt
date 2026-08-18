use notecrypt_service::{OperationResult, RecoverySecretPresentation};

fn embed(secret: RecoverySecretPresentation) -> OperationResult {
    OperationResult::RecoverySecret(secret)
}

fn main() {}
