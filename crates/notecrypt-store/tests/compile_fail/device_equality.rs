use notecrypt_store::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};

fn assert_partial_equality<T: PartialEq>() {}
fn assert_equality<T: Eq>() {}

fn main() {
    assert_equality::<DeviceEnrollment>();
    assert_equality::<DeviceProvider>();
    assert_equality::<DeviceReference>();
    assert_equality::<ActiveDeviceSlot>();
    assert_equality::<DisabledDeviceSlotPendingProviderRemoval>();
    assert_equality::<UntrustedDeviceSlotCandidate>();
    assert_partial_equality::<DeviceEnrollment>();
    assert_partial_equality::<DeviceProvider>();
    assert_partial_equality::<DeviceReference>();
    assert_partial_equality::<ActiveDeviceSlot>();
    assert_partial_equality::<DisabledDeviceSlotPendingProviderRemoval>();
    assert_partial_equality::<UntrustedDeviceSlotCandidate>();
}
