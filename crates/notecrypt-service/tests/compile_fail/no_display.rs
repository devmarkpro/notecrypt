use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
    StableSourceToken,
};

fn require_display<T: std::fmt::Display>() {}

fn main() {
    require_display::<RecoverySecretInput>();
    require_display::<RecoverySecretPresentation>();
    require_display::<DeviceUnlockSecret>();
    require_display::<PendingRecoveryInitialization>();
    require_display::<PendingCompromiseRekey>();
    require_display::<PendingFreshnessAcknowledgement>();
    require_display::<StableSourceToken>();
    require_display::<FinalSaveGuard>();
}
