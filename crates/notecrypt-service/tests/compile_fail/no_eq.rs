use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
};

fn require_eq<T: Eq>() {}

fn main() {
    require_eq::<RecoverySecretInput>();
    require_eq::<RecoverySecretPresentation>();
    require_eq::<DeviceUnlockSecret>();
    require_eq::<PendingRecoveryInitialization>();
    require_eq::<PendingCompromiseRekey>();
    require_eq::<PendingFreshnessAcknowledgement>();
    require_eq::<FinalSaveGuard>();
}
