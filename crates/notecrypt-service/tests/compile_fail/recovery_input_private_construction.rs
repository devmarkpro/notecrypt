use notecrypt_service::RecoverySecretInput;

fn forge(value: Vec<u8>) -> RecoverySecretInput {
    RecoverySecretInput {
        value: zeroize::Zeroizing::new(value),
    }
}

fn main() {}
