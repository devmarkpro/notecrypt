use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
    StableSourceToken,
};

fn require_debug<T: std::fmt::Debug>() {}

fn main() {
    require_debug::<RecoverySecretInput>();
    require_debug::<RecoverySecretPresentation>();
    require_debug::<DeviceUnlockSecret>();
    require_debug::<PendingRecoveryInitialization>();
    require_debug::<PendingCompromiseRekey>();
    require_debug::<PendingFreshnessAcknowledgement>();
    require_debug::<StableSourceToken>();
    require_debug::<FinalSaveGuard>();
}
