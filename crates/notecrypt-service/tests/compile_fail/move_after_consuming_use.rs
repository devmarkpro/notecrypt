use notecrypt_service::{
    BeginRecoveryInitialization, DeviceKeyReference, DeviceUnlockSecret, EnrolledDeviceKey,
    HostPortError, OfflineGuessingRiskAcknowledgement, PendingCompromiseRekey,
    PendingFreshnessAcknowledgement, PendingRecoveryInitialization, RecoverySecretInput,
    RecoverySecretPresentation, RecoverySecretPresenter, ServiceHandle,
};

struct Presenter;

impl RecoverySecretPresenter for Presenter {
    fn present(&mut self, _secret: &[u8]) -> Result<(), HostPortError> {
        Ok(())
    }
}

fn recovery_input(value: RecoverySecretInput) {
    let _request =
        BeginRecoveryInitialization::custom_v1(value, OfflineGuessingRiskAcknowledgement::v1());
    drop(value);
}

fn recovery_presentation(value: RecoverySecretPresentation) {
    value.present_once(&mut Presenter).unwrap();
    drop(value);
}

fn device_secret(value: DeviceUnlockSecret) {
    let reference = DeviceKeyReference::from_bytes(vec![1]).unwrap();
    let _enrolled = EnrolledDeviceKey::new(reference, value);
    drop(value);
}

fn recovery_pending(service: &ServiceHandle, value: PendingRecoveryInitialization) {
    service.cancel_recovery_initialization(value).unwrap();
    service.cancel_recovery_initialization(value).unwrap();
}

fn compromise_pending(service: &ServiceHandle, value: PendingCompromiseRekey) {
    service.cancel_compromise_rekey(value).unwrap();
    service.cancel_compromise_rekey(value).unwrap();
}

fn freshness_pending(service: &ServiceHandle, value: PendingFreshnessAcknowledgement) {
    service.cancel_freshness_acknowledgement(value).unwrap();
    service.cancel_freshness_acknowledgement(value).unwrap();
}

fn main() {}
