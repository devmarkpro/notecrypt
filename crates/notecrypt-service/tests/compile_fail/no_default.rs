use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
};

fn require_default<T: Default>() {}

fn main() {
    require_default::<RecoverySecretInput>();
    require_default::<RecoverySecretPresentation>();
    require_default::<DeviceUnlockSecret>();
    require_default::<PendingRecoveryInitialization>();
    require_default::<PendingCompromiseRekey>();
    require_default::<PendingFreshnessAcknowledgement>();
    require_default::<FinalSaveGuard>();
}
