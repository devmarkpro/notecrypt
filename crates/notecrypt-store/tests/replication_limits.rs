use notecrypt_store::{ReplicationBudget, ReplicationLimits, StoreError};

#[test]
fn phase_one_numeric_limits_are_exact_and_independent() {
    let limits = ReplicationLimits::PHASE_1;
    assert_eq!(limits.max_bootstrap_bytes, 1 << 20);
    assert_eq!(limits.max_head_bytes, 64 << 10);
    assert_eq!(limits.max_chunk_object_bytes, (4 << 20) + (4 << 10));
    assert_eq!(limits.max_manifest_object_bytes, 64 << 20);
    assert_eq!(limits.max_tree_object_bytes, 256 << 20);
    assert_eq!(limits.max_snapshot_object_bytes, 1 << 20);
    assert_eq!(limits.max_aggregate_bytes, 1 << 40);
    assert_eq!(limits.max_object_count, 10_000_000);
    assert_eq!(limits.max_graph_edges, 100_000);
    assert_eq!(limits.max_graph_depth, 100_000);

    let mut edges = ReplicationBudget::new(limits);
    edges.add_edges(100_000).unwrap();
    assert!(matches!(edges.add_edges(1), Err(StoreError::LimitExceeded)));
    let depth = ReplicationBudget::new(limits);
    depth.check_depth(100_000).unwrap();
    assert!(matches!(
        depth.check_depth(100_001),
        Err(StoreError::LimitExceeded)
    ));
}

#[test]
fn quarantine_budget_is_strictest_limit_with_integer_free_space_reserve() {
    let limits = ReplicationLimits::PHASE_1;
    let free = 10_u64 << 30;
    assert_eq!(
        limits
            .effective_quarantine_bytes(u64::MAX, u64::MAX, free)
            .unwrap(),
        8_u64 << 30
    );
    assert_eq!(
        limits
            .effective_quarantine_bytes(3 << 30, 2 << 30, free)
            .unwrap(),
        2_u64 << 30
    );
    assert!(
        limits
            .effective_quarantine_bytes(u64::MAX, u64::MAX, (1 << 30) - 1)
            .is_err()
    );
    assert_eq!(
        limits
            .effective_quarantine_bytes(u64::MAX, u64::MAX, u64::MAX)
            .unwrap(),
        1 << 40
    );
}

#[test]
fn aggregate_and_object_counts_use_checked_exact_boundaries() {
    let mut limits = ReplicationLimits::PHASE_1;
    limits.max_object_count = 2;
    limits.max_aggregate_bytes = 5;
    let mut budget = ReplicationBudget::new(limits);
    budget.add_object(2).unwrap();
    budget.add_object(3).unwrap();
    assert!(matches!(
        budget.add_object(0),
        Err(StoreError::LimitExceeded)
    ));
}
