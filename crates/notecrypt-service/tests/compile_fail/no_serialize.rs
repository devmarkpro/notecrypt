use notecrypt_service::{
    DeviceUnlockSecret, FinalSaveGuard, PendingCompromiseRekey, PendingFreshnessAcknowledgement,
    PendingRecoveryInitialization, RecoverySecretInput, RecoverySecretPresentation,
    StableSourceToken,
};
use serde::Serialize;

fn require_serialize<T: Serialize>() {}

fn main() {
    require_serialize::<RecoverySecretInput>();
    require_serialize::<RecoverySecretPresentation>();
    require_serialize::<DeviceUnlockSecret>();
    require_serialize::<PendingRecoveryInitialization>();
    require_serialize::<PendingCompromiseRekey>();
    require_serialize::<PendingFreshnessAcknowledgement>();
    require_serialize::<StableSourceToken>();
    require_serialize::<FinalSaveGuard>();
}
