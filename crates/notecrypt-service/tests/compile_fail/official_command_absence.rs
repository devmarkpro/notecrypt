use notecrypt_service::{Command, RecoverySecretInput};

fn embed(secret: RecoverySecretInput) -> Command {
    Command::RecoverySecret(secret)
}

fn main() {}
