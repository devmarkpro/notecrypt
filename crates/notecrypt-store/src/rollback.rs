#[cfg(feature = "test-support")]
use std::collections::{HashSet, VecDeque};

#[cfg(feature = "test-support")]
use notecrypt_core::SnapshotId;
use notecrypt_core::VaultId;

use crate::StoreError;
use crate::transaction::AuthenticatedHead;
use crate::trusted_state::TrustedHead;
#[cfg(feature = "test-support")]
use crate::{ReplicationBudget, ReplicationLimits};

pub(crate) fn require_exact_trusted_head(
    vault: VaultId,
    trusted: &TrustedHead,
    presented: &AuthenticatedHead,
) -> Result<(), StoreError> {
    if presented.vault == vault
        && presented.snapshot == trusted.snapshot()
        && presented.commitment == *trusted.head_commitment()
    {
        Ok(())
    } else {
        Err(StoreError::RollbackDetected)
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn prove_trusted_ancestor(
    presented: SnapshotId,
    trusted: SnapshotId,
    limits: ReplicationLimits,
    mut authenticated_parents: impl FnMut(SnapshotId) -> Result<Vec<SnapshotId>, StoreError>,
) -> Result<(), StoreError> {
    if presented == trusted {
        return Ok(());
    }
    let mut budget = ReplicationBudget::new(limits);
    let mut pending = VecDeque::new();
    let mut visited = HashSet::new();
    pending
        .try_reserve(1)
        .map_err(|_| StoreError::LimitExceeded)?;
    visited
        .try_reserve(1)
        .map_err(|_| StoreError::LimitExceeded)?;
    pending.push_back((presented, 0_u32));
    visited.insert(presented);
    while let Some((snapshot, depth)) = pending.pop_front() {
        budget.check_depth(depth)?;
        budget.add_object(0)?;
        let parents = authenticated_parents(snapshot).map_err(|error| match error {
            StoreError::NotFound
            | StoreError::MalformedObject
            | StoreError::AuthenticationFailed => StoreError::RollbackDetected,
            other => other,
        })?;
        budget.add_edges(u64::try_from(parents.len()).map_err(|_| StoreError::LimitExceeded)?)?;
        for parent in parents {
            if parent == trusted {
                return Ok(());
            }
            if visited.insert(parent) {
                pending
                    .try_reserve(1)
                    .map_err(|_| StoreError::LimitExceeded)?;
                pending.push_back((
                    parent,
                    depth.checked_add(1).ok_or(StoreError::LimitExceeded)?,
                ));
            }
        }
    }
    Err(StoreError::RollbackDetected)
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::collections::HashMap;

    use notecrypt_core::SnapshotId;

    use super::*;

    pub fn prove(
        presented: [u8; 32],
        trusted: [u8; 32],
        graph: impl IntoIterator<Item = ([u8; 32], Vec<[u8; 32]>)>,
        limits: ReplicationLimits,
    ) -> Result<(), StoreError> {
        let graph: HashMap<SnapshotId, Vec<SnapshotId>> = graph
            .into_iter()
            .map(|(snapshot, parents)| {
                (
                    SnapshotId::from_bytes(snapshot),
                    parents.into_iter().map(SnapshotId::from_bytes).collect(),
                )
            })
            .collect();
        prove_trusted_ancestor(
            SnapshotId::from_bytes(presented),
            SnapshotId::from_bytes(trusted),
            limits,
            |snapshot| graph.get(&snapshot).cloned().ok_or(StoreError::NotFound),
        )
    }
}
