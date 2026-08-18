use notecrypt_service::{CompromiseRekeyConfirmation, RecoverySecretInput};

fn inaccessible<T>() -> T {
    loop {}
}

fn forge() -> CompromiseRekeyConfirmation {
    CompromiseRekeyConfirmation {
        first: inaccessible::<RecoverySecretInput>(),
        matching: None,
    }
}

fn main() {
    let _ = forge();
}
