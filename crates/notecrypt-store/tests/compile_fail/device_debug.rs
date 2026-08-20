use notecrypt_store::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};

fn assert_debug<T: std::fmt::Debug>() {}

fn main() {
    assert_debug::<DeviceEnrollment>();
    assert_debug::<DeviceProvider>();
    assert_debug::<DeviceReference>();
    assert_debug::<ActiveDeviceSlot>();
    assert_debug::<DisabledDeviceSlotPendingProviderRemoval>();
    assert_debug::<UntrustedDeviceSlotCandidate>();
}
