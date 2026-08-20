use notecrypt_store::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};

fn assert_display<T: std::fmt::Display>() {}

fn main() {
    assert_display::<DeviceProvider>();
    assert_display::<DeviceReference>();
    assert_display::<UntrustedDeviceSlotCandidate>();
    assert_display::<DeviceEnrollment>();
    assert_display::<ActiveDeviceSlot>();
    assert_display::<DisabledDeviceSlotPendingProviderRemoval>();
}
