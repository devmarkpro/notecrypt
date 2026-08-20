use notecrypt_store::{
    ActiveDeviceSlot, DeviceEnrollment, DeviceProvider, DeviceReference,
    DisabledDeviceSlotPendingProviderRemoval, UntrustedDeviceSlotCandidate,
};

fn assert_default<T: Default>() {}

fn main() {
    assert_default::<DeviceEnrollment>();
    assert_default::<DeviceProvider>();
    assert_default::<DeviceReference>();
    assert_default::<ActiveDeviceSlot>();
    assert_default::<DisabledDeviceSlotPendingProviderRemoval>();
    assert_default::<UntrustedDeviceSlotCandidate>();
}
