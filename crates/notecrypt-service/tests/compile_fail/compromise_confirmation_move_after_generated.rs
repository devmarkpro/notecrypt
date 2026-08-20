use notecrypt_service::{CompromiseRekeyConfirmation, RecoverySecretInput};

fn consume(value: CompromiseRekeyConfirmation) {
    drop(value);
    drop(value);
}

fn main() {
    consume(CompromiseRekeyConfirmation::generated(
        RecoverySecretInput::from_protected_bytes(vec![1]).unwrap(),
    ));
}
