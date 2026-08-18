use std::sync::{Arc, Mutex};

use notecrypt_service::RecoverySecretPresentation;

fn forge(payload: Vec<u8>) -> RecoverySecretPresentation {
    RecoverySecretPresentation {
        payload: Arc::new(Mutex::new(Some(zeroize::Zeroizing::new(payload)))),
    }
}

fn main() {}
