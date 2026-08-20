use notecrypt_store::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<DeviceEnrollment>();
    assert_clone::<DeviceProvider>();
    assert_clone::<DeviceReference>();
    assert_clone::<ActiveDeviceSlot>();
    assert_clone::<DisabledDeviceSlotPendingProviderRemoval>();
    assert_clone::<UntrustedDeviceSlotCandidate>();
}
