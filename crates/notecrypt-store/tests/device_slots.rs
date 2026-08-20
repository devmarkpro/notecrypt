#![cfg(feature = "test-support")]

use notecrypt_core::VaultId;
use notecrypt_crypto::DeviceWrappingKey;
use notecrypt_store::device_test_support::{
    DevicePersistenceFault, DeviceRandomStep, ScriptedDeviceRegistry,
};
use notecrypt_store::{DeviceEnrollment, DeviceProvider, DeviceReference, StoreError};
use std::sync::atomic::Ordering;

const VAULT_A: VaultId = VaultId::from_bytes([0x51; 16]);
const VAULT_B: VaultId = VaultId::from_bytes([0x52; 16]);

fn key(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn enrollment(provider: &str, reference: &str, key_byte: u8) -> DeviceEnrollment {
    DeviceEnrollment::new(
        DeviceProvider::try_new(provider.to_owned()).unwrap(),
        DeviceReference::try_new(reference.to_owned()).unwrap(),
        DeviceWrappingKey::try_from_protected_bytes(key(key_byte)).unwrap(),
    )
}

fn successful_random(slot: u8, nonce: u8) -> [DeviceRandomStep; 2] {
    [
        DeviceRandomStep::Fill(vec![slot; 16]),
        DeviceRandomStep::Fill(vec![nonce; 24]),
    ]
}

#[test]
fn enrollment_listing_and_unlock_authenticate_the_complete_record_and_trusted_state() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    registry.add_authenticated_trusted_head().unwrap();

    let _active = registry
        .enroll(enrollment("apple-keychain", "credential-42", 9))
        .unwrap();
    let mut candidates = registry.list_locked().unwrap();
    assert_eq!(candidates.len(), 1);
    let candidate = candidates.pop().unwrap();
    assert_eq!(candidate.provider().as_str(), "apple-keychain");
    assert_eq!(candidate.reference().as_str(), "credential-42");

    registry.unlock(candidate, key(9)).unwrap();
    assert_eq!(registry.authenticated_trusted_reads(), 2);
}

#[test]
fn enrollment_identity_and_nonce_failures_publish_nothing() {
    let mut partial_identity =
        ScriptedDeviceRegistry::new(VAULT_A, [DeviceRandomStep::PartialFailure(vec![0x11; 8])])
            .unwrap();
    assert!(matches!(
        partial_identity.enroll(enrollment("provider", "reference", 1)),
        Err(StoreError::RandomSource)
    ));
    assert_eq!(partial_identity.persisted_slot_count(), 0);

    let mut partial_nonce = ScriptedDeviceRegistry::new(
        VAULT_A,
        [
            DeviceRandomStep::Fill(vec![0x12; 16]),
            DeviceRandomStep::PartialFailure(vec![0x13; 12]),
        ],
    )
    .unwrap();
    assert!(matches!(
        partial_nonce.enroll(enrollment("provider", "reference", 1)),
        Err(StoreError::RandomSource)
    ));
    assert_eq!(partial_nonce.persisted_slot_count(), 0);
}

#[test]
fn failed_enrollment_drops_the_sole_wrapping_key_owner() {
    let mut registry = ScriptedDeviceRegistry::new(
        VAULT_A,
        [
            DeviceRandomStep::Fill(vec![0x21; 16]),
            DeviceRandomStep::PartialFailure(vec![0x22; 12]),
        ],
    )
    .unwrap();
    let (enrollment, dropped) = ScriptedDeviceRegistry::enrollment_with_drop_probe(
        DeviceProvider::try_new("provider".to_owned()).unwrap(),
        DeviceReference::try_new("reference".to_owned()).unwrap(),
        key(7),
    )
    .unwrap();

    assert!(matches!(
        registry.enroll(enrollment),
        Err(StoreError::RandomSource)
    ));
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(registry.persisted_slot_count(), 0);
}

#[test]
fn identity_collision_retries_without_accepting_the_caller_identity() {
    let mut registry = ScriptedDeviceRegistry::new(
        VAULT_A,
        [
            DeviceRandomStep::Fill(vec![1; 16]),
            DeviceRandomStep::Fill(vec![2; 24]),
            DeviceRandomStep::Fill(vec![1; 16]),
            DeviceRandomStep::Fill(vec![3; 24]),
            DeviceRandomStep::Fill(vec![4; 16]),
            DeviceRandomStep::Fill(vec![5; 24]),
        ],
    )
    .unwrap();
    registry.enroll(enrollment("provider", "first", 1)).unwrap();
    registry
        .enroll(enrollment("provider", "second", 2))
        .unwrap();
    assert_eq!(registry.persisted_slot_count(), 2);
    assert_eq!(registry.random_fill_count(), 6);
}

#[test]
fn identity_collision_exhaustion_publishes_no_second_slot() {
    let mut steps = vec![
        DeviceRandomStep::Fill(vec![1; 16]),
        DeviceRandomStep::Fill(vec![2; 24]),
    ];
    for nonce in 0..16_u8 {
        steps.push(DeviceRandomStep::Fill(vec![1; 16]));
        steps.push(DeviceRandomStep::Fill(vec![nonce.wrapping_add(3); 24]));
    }
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, steps).unwrap();
    registry.enroll(enrollment("p", "first", 1)).unwrap();

    assert!(matches!(
        registry.enroll(enrollment("p", "second", 2)),
        Err(StoreError::IdentityCollision)
    ));
    assert_eq!(registry.persisted_slot_count(), 1);
    assert_eq!(registry.random_fill_count(), 34);
}

#[test]
fn create_failures_are_atomic_or_reissue_the_authenticated_active_capability() {
    let mut before = ScriptedDeviceRegistry::new(
        VAULT_A,
        [
            DeviceRandomStep::Fill(vec![1; 16]),
            DeviceRandomStep::Fill(vec![2; 24]),
            DeviceRandomStep::Fill(vec![3; 16]),
            DeviceRandomStep::Fill(vec![4; 24]),
        ],
    )
    .unwrap();
    before.push_persistence_fault(DevicePersistenceFault::CreateBeforeEffect);
    assert!(matches!(
        before.enroll(enrollment("p", "first", 1)),
        Err(StoreError::Io(_))
    ));
    assert_eq!(before.persisted_slot_count(), 0);
    let _active = before.enroll(enrollment("p", "retry", 2)).unwrap();
    assert_eq!(before.persisted_slot_count(), 1);

    let mut after = ScriptedDeviceRegistry::new(VAULT_A, successful_random(5, 6)).unwrap();
    after.push_persistence_fault(DevicePersistenceFault::CreateAfterEffect);
    let _reissued = after.enroll(enrollment("p", "reissued", 3)).unwrap();
    assert_eq!(after.persisted_slot_count(), 1);
}

#[test]
fn replace_failures_preserve_retry_or_reissue_the_disabled_capability() {
    let cases = [
        DevicePersistenceFault::ReplaceAfterEffect,
        DevicePersistenceFault::ReplaceAppliedButReportedMismatch,
    ];
    for fault in cases {
        let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
        let mut active = registry.enroll(enrollment("p", "r", 3)).unwrap();
        registry.push_persistence_fault(fault);
        assert!(matches!(
            registry.disable_retryable(&mut active),
            Err(StoreError::DurabilityPending)
        ));
        let disabled = registry.disable_retryable(&mut active).unwrap();
        assert_eq!(disabled.provider().as_str(), "p");
        assert!(matches!(
            registry.disable_retryable(&mut active),
            Err(StoreError::InvalidCapability)
        ));
    }

    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(3, 4)).unwrap();
    let mut active = registry.enroll(enrollment("p", "retry", 4)).unwrap();
    registry.push_persistence_fault(DevicePersistenceFault::ReplaceBeforeEffect);
    assert!(matches!(
        registry.disable_retryable(&mut active),
        Err(StoreError::Io(_))
    ));
    let disabled = registry.disable_retryable(&mut active).unwrap();
    assert_eq!(disabled.reference().as_str(), "retry");
}

#[test]
fn remove_failures_preserve_retry_or_confirm_the_already_applied_delete() {
    let mut before = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    let active = before.enroll(enrollment("p", "r", 3)).unwrap();
    let mut disabled = before.disable(active).unwrap();
    before.push_persistence_fault(DevicePersistenceFault::RemoveBeforeEffect);
    assert!(matches!(
        before.delete_disabled_retryable(&mut disabled),
        Err(StoreError::Io(_))
    ));
    before.delete_disabled_retryable(&mut disabled).unwrap();
    assert_eq!(before.persisted_slot_count(), 0);

    for fault in [
        DevicePersistenceFault::RemoveAfterEffect,
        DevicePersistenceFault::RemoveAppliedButReportedMismatch,
    ] {
        let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(3, 4)).unwrap();
        let active = registry.enroll(enrollment("p", "r", 4)).unwrap();
        let mut disabled = registry.disable(active).unwrap();
        registry.push_persistence_fault(fault);
        assert!(matches!(
            registry.delete_disabled_retryable(&mut disabled),
            Err(StoreError::DurabilityPending)
        ));
        registry.delete_disabled_retryable(&mut disabled).unwrap();
        assert_eq!(registry.persisted_slot_count(), 0);
        assert!(matches!(
            registry.delete_disabled_retryable(&mut disabled),
            Err(StoreError::InvalidCapability)
        ));
    }
}

#[test]
fn tamper_wrong_key_wrong_slot_and_cross_vault_fail_closed() {
    let mut registry = ScriptedDeviceRegistry::new(
        VAULT_A,
        [
            DeviceRandomStep::Fill(vec![1; 16]),
            DeviceRandomStep::Fill(vec![2; 24]),
            DeviceRandomStep::Fill(vec![3; 16]),
            DeviceRandomStep::Fill(vec![4; 24]),
        ],
    )
    .unwrap();
    registry.enroll(enrollment("p", "one", 1)).unwrap();
    registry.enroll(enrollment("p", "two", 2)).unwrap();

    let mut candidates = registry.list_locked().unwrap();
    let first_index = candidates
        .iter()
        .position(|candidate| candidate.reference().as_str() == "one")
        .unwrap();
    let first = candidates.remove(first_index);
    assert!(matches!(
        registry.unlock(first, key(2)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));

    let mut candidates = registry.list_locked().unwrap();
    let first_index = candidates
        .iter()
        .position(|candidate| candidate.reference().as_str() == "one")
        .unwrap();
    let candidate = candidates.remove(first_index);
    registry.tamper_candidate_record(&candidate, 20).unwrap();
    assert!(matches!(
        registry.unlock(candidate, key(1)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));

    let mut source = ScriptedDeviceRegistry::new(VAULT_A, successful_random(8, 9)).unwrap();
    source.enroll(enrollment("p", "cross", 8)).unwrap();
    let candidate = source.list_locked().unwrap().remove(0);
    let mut other = ScriptedDeviceRegistry::new(VAULT_B, []).unwrap();
    assert!(matches!(
        other.unlock(candidate, key(8)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
}

#[test]
fn trusted_state_tamper_blocks_unlock_after_the_slot_itself_authenticates() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    let trusted_id = registry.add_authenticated_trusted_head().unwrap();
    registry.enroll(enrollment("p", "r", 3)).unwrap();
    let candidate = registry.list_locked().unwrap().remove(0);
    registry.tamper_trusted_record(trusted_id, 12).unwrap();
    assert!(matches!(
        registry.unlock(candidate, key(3)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
}

#[test]
fn missing_trusted_head_blocks_unlock_after_the_slot_itself_authenticates() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    registry.enroll(enrollment("p", "r", 3)).unwrap();
    let candidate = registry.list_locked().unwrap().remove(0);

    assert!(matches!(
        registry.unlock(candidate, key(3)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
}

#[test]
fn trusted_head_enumeration_order_is_irrelevant_but_duplicates_and_omissions_fail_closed() {
    let mut reverse = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    reverse.add_authenticated_trusted_head().unwrap();
    reverse.enroll(enrollment("p", "r", 3)).unwrap();
    reverse.set_reverse_local_enumeration(true);
    let candidate = reverse.list_locked().unwrap().remove(0);
    reverse.unlock(candidate, key(3)).unwrap();

    let mut duplicate = ScriptedDeviceRegistry::new(VAULT_A, successful_random(4, 5)).unwrap();
    duplicate.add_authenticated_trusted_head().unwrap();
    duplicate.enroll(enrollment("p", "r", 6)).unwrap();
    duplicate.set_duplicate_trusted_head_enumeration(true);
    let candidate = duplicate.list_locked().unwrap().remove(0);
    assert!(matches!(
        duplicate.unlock(candidate, key(6)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));

    let mut omitted = ScriptedDeviceRegistry::new(VAULT_A, successful_random(7, 8)).unwrap();
    omitted.add_authenticated_trusted_head().unwrap();
    omitted.enroll(enrollment("p", "r", 9)).unwrap();
    omitted.set_omit_devices_from_local_enumeration(true);
    let candidate = omitted.list_locked().unwrap().remove(0);
    assert!(matches!(
        omitted.unlock(candidate, key(9)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
}

#[test]
fn candidate_captured_before_a_durable_state_transition_cannot_unlock() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    registry.add_authenticated_trusted_head().unwrap();
    let active = registry.enroll(enrollment("p", "r", 3)).unwrap();
    let candidate = registry.list_locked().unwrap().remove(0);
    let _disabled = registry.disable(active).unwrap();

    assert!(matches!(
        registry.unlock(candidate, key(3)),
        Err(StoreError::InvalidCapability)
    ));
}

#[test]
fn candidate_reread_and_complete_local_enumeration_must_observe_the_same_slot() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    registry.add_authenticated_trusted_head().unwrap();
    registry.enroll(enrollment("p", "r", 3)).unwrap();
    let candidate = registry.list_locked().unwrap().remove(0);
    registry.remove_devices_before_local_enumeration_once();

    assert!(matches!(
        registry.unlock(candidate, key(3)),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
}

#[test]
fn active_disable_pending_provider_removal_delete_is_linear() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    let active = registry.enroll(enrollment("p", "r", 3)).unwrap();
    assert!(matches!(
        registry.delete_active_for_test(active),
        Err(StoreError::InvalidCapability)
    ));

    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    let active = registry.enroll(enrollment("p", "r", 3)).unwrap();
    let disabled = registry.disable(active).unwrap();
    assert_eq!(disabled.provider().as_str(), "p");
    assert_eq!(disabled.reference().as_str(), "r");
    let candidate = registry.list_locked().unwrap().remove(0);
    assert!(matches!(
        registry.unlock(candidate, key(3)),
        Err(StoreError::InvalidCapability)
    ));
    registry.delete_disabled(disabled).unwrap();
    assert_eq!(registry.persisted_slot_count(), 0);
}

#[test]
fn stale_generation_and_token_reuse_are_rejected() {
    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    let active = registry.enroll(enrollment("p", "r", 3)).unwrap();
    registry.advance_generation().unwrap();
    assert!(matches!(registry.disable(active), Err(StoreError::Locked)));
}

#[test]
fn provider_reference_and_listing_are_bounded() {
    assert!(DeviceProvider::try_new(String::new()).is_err());
    assert!(DeviceProvider::try_new("p".repeat(129)).is_err());
    assert!(DeviceReference::try_new(String::new()).is_err());
    assert!(DeviceReference::try_new("r".repeat(2049)).is_err());

    let mut registry = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    registry.enroll(enrollment("p", "r", 3)).unwrap();
    registry.set_listing_limit(0);
    assert!(matches!(
        registry.list_locked(),
        Err(StoreError::LimitExceeded)
    ));
}

#[test]
fn persistence_rechecks_the_slot_limit_after_a_stale_preflight_count() {
    let mut registry = ScriptedDeviceRegistry::new(
        VAULT_A,
        [
            DeviceRandomStep::Fill(vec![1; 16]),
            DeviceRandomStep::Fill(vec![2; 24]),
            DeviceRandomStep::Fill(vec![3; 16]),
            DeviceRandomStep::Fill(vec![4; 24]),
        ],
    )
    .unwrap();
    registry.set_maximum_slots(1);
    registry.enroll(enrollment("p", "first", 1)).unwrap();
    registry.underreport_slot_count_once();
    assert!(matches!(
        registry.enroll(enrollment("p", "racing", 2)),
        Err(StoreError::LimitExceeded)
    ));
    assert_eq!(registry.persisted_slot_count(), 1);
}

#[test]
fn close_before_or_during_key_wrapping_prevents_publication() {
    let mut before = ScriptedDeviceRegistry::new(VAULT_A, successful_random(1, 2)).unwrap();
    before.begin_close().unwrap();
    assert!(matches!(
        before.enroll(enrollment("p", "r", 3)),
        Err(StoreError::Locked)
    ));
    assert_eq!(before.persisted_slot_count(), 0);

    let mut during = ScriptedDeviceRegistry::new(VAULT_A, successful_random(4, 5)).unwrap();
    during.close_after_random_fill(2);
    assert!(matches!(
        during.enroll(enrollment("p", "r", 6)),
        Err(StoreError::Locked)
    ));
    assert_eq!(during.persisted_slot_count(), 0);
}
