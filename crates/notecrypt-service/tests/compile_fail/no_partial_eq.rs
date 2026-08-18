use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
};

fn require_partial_eq<T: PartialEq>() {}

fn main() {
    require_partial_eq::<RecoverySecretInput>();
    require_partial_eq::<RecoverySecretPresentation>();
    require_partial_eq::<DeviceUnlockSecret>();
    require_partial_eq::<PendingRecoveryInitialization>();
    require_partial_eq::<PendingCompromiseRekey>();
    require_partial_eq::<PendingFreshnessAcknowledgement>();
    require_partial_eq::<FinalSaveGuard>();
}
