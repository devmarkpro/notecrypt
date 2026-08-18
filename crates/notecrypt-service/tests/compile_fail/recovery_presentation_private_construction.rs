use notecrypt_service::RecoverySecretPresentation;

fn forge(payload: String) -> RecoverySecretPresentation {
    RecoverySecretPresentation {
        generation: 1,
        payload,
    }
}

fn main() {}
