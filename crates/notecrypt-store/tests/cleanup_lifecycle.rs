#![cfg(feature = "test-support")]

use notecrypt_core::VaultId;
use notecrypt_store::cleanup_test_support::{
    CleanupPersistenceFault, CleanupRandomStep, ScriptedCleanupRegistry,
};
use notecrypt_store::{CleanupWorkspaceState, StoreError};

const VAULT: VaultId = VaultId::from_bytes([0x41; 16]);

#[test]
fn registered_active_removed_unregister_is_linear_and_authenticated() {
    let workspace = [0x12; 16];
    let mut registry = registry(8, [CleanupRandomStep::Bytes(workspace)]);

    let registered = registry.reserve_and_register().unwrap();
    assert_eq!(
        registered.workspace_id().child_name(),
        "12121212121212121212121212121212"
    );
    assert_records(
        &mut registry,
        &[(
            "12121212121212121212121212121212",
            CleanupWorkspaceState::Registered,
        )],
    );

    let active = registry.activate(registered).unwrap();
    assert_records(
        &mut registry,
        &[(
            "12121212121212121212121212121212",
            CleanupWorkspaceState::Active,
        )],
    );

    registry
        .unregister_after_adapter_removal_for_test(active)
        .unwrap();
    assert!(registry.enumerate_authenticated().unwrap().is_empty());
    assert_eq!(registry.persisted_record_count(), 0);
}

#[test]
fn tampering_fails_before_enumeration_or_transition_exposes_state() {
    let mut registry = registry(8, [CleanupRandomStep::Bytes([0x22; 16])]);
    let registered = registry.reserve_and_register().unwrap();
    registry
        .tamper_record(registered.workspace_id(), 17)
        .unwrap();

    assert!(matches!(
        registry.enumerate_authenticated(),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
    assert!(matches!(
        registry.activate(registered),
        Err(StoreError::LocalStateAuthenticationFailed)
    ));
}

#[test]
fn stale_generation_and_valid_but_wrong_transition_fail_closed() {
    let mut stale = registry(8, [CleanupRandomStep::Bytes([0x31; 16])]);
    let registered = stale.reserve_and_register().unwrap();
    stale.advance_generation().unwrap();
    assert!(matches!(
        stale.activate(registered),
        Err(StoreError::Locked)
    ));

    let mut wrong_state = registry(8, [CleanupRandomStep::Bytes([0x32; 16])]);
    let registered = wrong_state.reserve_and_register().unwrap();
    wrong_state
        .rewrite_authenticated_state_for_test(
            registered.workspace_id(),
            CleanupWorkspaceState::Active,
        )
        .unwrap();
    assert!(matches!(
        wrong_state.activate(registered),
        Err(StoreError::InvalidCapability)
    ));
}

#[test]
fn failed_adapter_absence_confirmation_keeps_the_active_record_registered() {
    let mut registry = registry(8, [CleanupRandomStep::Bytes([0x39; 16])]);
    let registered = registry.reserve_and_register().unwrap();
    let active = registry.activate(registered).unwrap();

    assert!(matches!(
        registry.fail_adapter_removal_for_test(active),
        Err(StoreError::Cancelled)
    ));
    let recovered = registry
        .enumerate_authenticated()
        .unwrap()
        .pop()
        .unwrap()
        .into_active()
        .unwrap();
    registry
        .unregister_after_adapter_removal_for_test(recovered)
        .unwrap();
    assert_eq!(registry.persisted_record_count(), 0);
}

#[test]
fn applied_cleanup_transitions_require_a_successful_retry_flush() {
    let mut activation = registry(8, [CleanupRandomStep::Bytes([0x3a; 16])]);
    let mut registered = activation.reserve_and_register().unwrap();
    activation.push_persistence_fault(CleanupPersistenceFault::ReplaceBeforeEffect);
    assert!(matches!(
        activation.activate_retryable(&mut registered),
        Err(StoreError::Io(_))
    ));
    activation.push_persistence_fault(CleanupPersistenceFault::ReplaceAfterEffect);
    assert!(matches!(
        activation.activate_retryable(&mut registered),
        Err(StoreError::DurabilityPending)
    ));
    assert_eq!(activation.directory_sync_count(), 0);
    let mut active = activation.activate_retryable(&mut registered).unwrap();
    assert_eq!(activation.directory_sync_count(), 1);

    let (authority, mut proof) = activation.acquire_absence_proof(&active).unwrap();
    activation.push_persistence_fault(CleanupPersistenceFault::RemoveBeforeEffect);
    assert!(matches!(
        activation.unregister_retryable(&mut active, &mut proof, &authority),
        Err(StoreError::Io(_))
    ));
    activation.push_persistence_fault(CleanupPersistenceFault::RemoveAfterEffect);
    assert!(matches!(
        activation.unregister_retryable(&mut active, &mut proof, &authority),
        Err(StoreError::DurabilityPending)
    ));
    assert_eq!(activation.persisted_record_count(), 0);
    assert_eq!(activation.directory_sync_count(), 1);
    activation
        .unregister_retryable(&mut active, &mut proof, &authority)
        .unwrap();
    assert_eq!(activation.directory_sync_count(), 2);
    assert!(matches!(
        activation.unregister_retryable(&mut active, &mut proof, &authority),
        Err(StoreError::InvalidCapability)
    ));
}

#[test]
fn collisions_retry_and_exhaustion_never_replace_existing_records() {
    let first = [0x44; 16];
    let second = [0x45; 16];
    let mut colliding = registry(
        8,
        [
            CleanupRandomStep::Bytes(first),
            CleanupRandomStep::Bytes(first),
            CleanupRandomStep::Bytes(second),
        ],
    );
    let first_token = colliding.reserve_and_register().unwrap();
    let second_token = colliding.reserve_and_register().unwrap();
    assert_eq!(first_token.workspace_id().child_name(), "44".repeat(16));
    assert_eq!(second_token.workspace_id().child_name(), "45".repeat(16));
    assert_eq!(colliding.persisted_record_count(), 2);

    let collision = [0x66; 16];
    let steps = std::iter::once(CleanupRandomStep::Bytes(collision))
        .chain((0..16).map(|_| CleanupRandomStep::Bytes(collision)));
    let mut exhausted = registry(8, steps);
    let original = exhausted.reserve_and_register().unwrap();
    assert!(matches!(
        exhausted.reserve_and_register(),
        Err(StoreError::IdentityCollision)
    ));
    assert_eq!(original.workspace_id().child_name(), "66".repeat(16));
    assert_eq!(exhausted.persisted_record_count(), 1);
}

#[test]
fn partial_rng_failure_is_atomic_and_does_not_use_partial_identity() {
    let mut registry = registry(
        8,
        [
            CleanupRandomStep::PartialFailure {
                bytes: [0x77; 16],
                written: 7,
            },
            CleanupRandomStep::Bytes([0x78; 16]),
        ],
    );

    assert!(matches!(
        registry.reserve_and_register(),
        Err(StoreError::RandomSource)
    ));
    assert_eq!(registry.persisted_record_count(), 0);
    let registered = registry.reserve_and_register().unwrap();
    assert_eq!(registered.workspace_id().child_name(), "78".repeat(16));
}

#[test]
fn record_count_and_authenticated_enumeration_are_independently_bounded() {
    let mut registry = registry(
        2,
        [
            CleanupRandomStep::Bytes([0x81; 16]),
            CleanupRandomStep::Bytes([0x82; 16]),
            CleanupRandomStep::Bytes([0x83; 16]),
        ],
    );
    let _first = registry.reserve_and_register().unwrap();
    let _second = registry.reserve_and_register().unwrap();
    assert!(matches!(
        registry.reserve_and_register(),
        Err(StoreError::LimitExceeded)
    ));
    assert_eq!(registry.enumerate_authenticated().unwrap().len(), 2);

    registry.set_enumeration_limit_for_test(1);
    assert!(matches!(
        registry.enumerate_authenticated(),
        Err(StoreError::LimitExceeded)
    ));
}

#[test]
fn cleanup_registry_contract_contains_no_path_authority() {
    let source = include_str!("../src/cleanup.rs");
    assert!(!source.contains("std::path"));
    assert!(!source.contains("PathBuf"));
    assert!(!source.contains("Path>"));
}

fn registry(
    maximum_records: usize,
    steps: impl IntoIterator<Item = CleanupRandomStep>,
) -> ScriptedCleanupRegistry {
    ScriptedCleanupRegistry::new(VAULT, 7, maximum_records, steps).unwrap()
}

fn assert_records(
    registry: &mut ScriptedCleanupRegistry,
    expected: &[(&str, CleanupWorkspaceState)],
) {
    let records = registry.enumerate_authenticated().unwrap();
    assert_eq!(records.len(), expected.len());
    for (record, (expected_id, expected_state)) in records.iter().zip(expected) {
        assert_eq!(record.workspace_id().child_name(), *expected_id);
        assert_eq!(record.state(), *expected_state);
    }
}
