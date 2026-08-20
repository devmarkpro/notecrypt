#![cfg(feature = "test-support")]

use notecrypt_store::StoreError;
use notecrypt_store::rollback_test_support::prove;

#[test]
fn trusted_snapshot_must_be_equal_or_an_authenticated_ancestor() {
    let graph = [
        ([4; 32], vec![[3; 32]]),
        ([3; 32], vec![[2; 32]]),
        ([2; 32], vec![[1; 32]]),
    ];
    prove(
        [4; 32],
        [1; 32],
        graph.clone(),
        notecrypt_store::ReplicationLimits::PHASE_1,
    )
    .unwrap();
    prove(
        [1; 32],
        [1; 32],
        graph.clone(),
        notecrypt_store::ReplicationLimits::PHASE_1,
    )
    .unwrap();
    assert!(matches!(
        prove(
            [4; 32],
            [9; 32],
            graph,
            notecrypt_store::ReplicationLimits::PHASE_1,
        ),
        Err(StoreError::RollbackDetected)
    ));
}

#[test]
fn missing_or_corrupt_ancestry_and_independent_limits_fail_closed() {
    let mut limits = notecrypt_store::ReplicationLimits::PHASE_1;
    limits.max_graph_edges = 1;
    let graph = [([4; 32], vec![[3; 32], [2; 32]])];
    assert!(matches!(
        prove([4; 32], [1; 32], graph, limits),
        Err(StoreError::LimitExceeded)
    ));

    assert!(matches!(
        prove(
            [4; 32],
            [1; 32],
            [([4; 32], vec![[3; 32]])],
            notecrypt_store::ReplicationLimits::PHASE_1,
        ),
        Err(StoreError::RollbackDetected)
    ));
}
