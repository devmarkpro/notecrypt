use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
};

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<RecoverySecretInput>();
    require_clone::<RecoverySecretPresentation>();
    require_clone::<DeviceUnlockSecret>();
    require_clone::<PendingRecoveryInitialization>();
    require_clone::<PendingCompromiseRekey>();
    require_clone::<PendingFreshnessAcknowledgement>();
    require_clone::<FinalSaveGuard>();
}
