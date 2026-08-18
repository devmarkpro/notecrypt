use notecrypt_service::{DeviceUnlockSecret, OperationEvent};

fn embed(secret: DeviceUnlockSecret) -> OperationEvent {
    OperationEvent::DeviceUnlockSecret(secret)
}

fn main() {}
