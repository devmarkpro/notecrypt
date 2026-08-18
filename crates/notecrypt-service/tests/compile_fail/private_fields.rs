use notecrypt_service::{
    DeviceUnlockSecret, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
};

fn inspect_recovery_input(value: RecoverySecretInput) {
    let _ = value.value;
}

fn inspect_recovery_presentation(value: RecoverySecretPresentation) {
    let _ = value.generation;
    let _ = value.payload;
}

fn inspect_device_secret(value: DeviceUnlockSecret) {
    let _ = value.0;
}

fn inspect_recovery_pending(value: PendingRecoveryInitialization) {
    let _ = value.generation;
    let _ = value.operation;
    let _ = value.guard;
}

fn inspect_compromise_pending(value: PendingCompromiseRekey) {
    let _ = value.generation;
    let _ = value.operation;
    let _ = value.guard;
}

fn inspect_freshness_pending(value: PendingFreshnessAcknowledgement) {
    let _ = value.generation;
    let _ = value.operation;
    let _ = value.guard;
}

fn main() {}
