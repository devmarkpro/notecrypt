use notecrypt_store::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};

fn assert_serialize<T: serde::Serialize>() {}

fn main() {
    assert_serialize::<DeviceEnrollment>();
    assert_serialize::<DeviceProvider>();
    assert_serialize::<DeviceReference>();
    assert_serialize::<ActiveDeviceSlot>();
    assert_serialize::<DisabledDeviceSlotPendingProviderRemoval>();
    assert_serialize::<UntrustedDeviceSlotCandidate>();
}
