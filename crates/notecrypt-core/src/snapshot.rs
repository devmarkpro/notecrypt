use std::fmt;

use unicode_normalization::UnicodeNormalization;

use crate::{CoreError, DeviceId, SnapshotId, VaultTree, path::nfkc_case_fold};

/// An unlocked local device label used only in conflict presentation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.nfc().collect())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn sanitized(&self) -> String {
        let mut sanitized = String::new();
        let mut separator_pending = false;
        for character in nfkc_case_fold(&self.0).chars() {
            if character.is_alphanumeric() {
                if separator_pending && !sanitized.is_empty() {
                    sanitized.push('-');
                }
                separator_pending = false;
                sanitized.push(character);
            } else {
                separator_pending = true;
            }
            if sanitized.chars().count() >= 32 {
                break;
            }
        }
        if sanitized.is_empty() {
            "device".to_owned()
        } else {
            sanitized
        }
    }
}

impl fmt::Debug for DeviceLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceLabel(<redacted>)")
    }
}

/// A complete authenticated logical snapshot supplied to reconciliation.
#[derive(Clone, PartialEq, Eq)]
pub struct Snapshot {
    id: SnapshotId,
    device_id: DeviceId,
    device_label: DeviceLabel,
    tree: VaultTree,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Snapshot(<redacted>)")
    }
}

impl Snapshot {
    #[must_use]
    pub const fn new(
        id: SnapshotId,
        device_id: DeviceId,
        device_label: DeviceLabel,
        tree: VaultTree,
    ) -> Self {
        Self {
            id,
            device_id,
            device_label,
            tree,
        }
    }

    #[must_use]
    pub const fn id(&self) -> SnapshotId {
        self.id
    }

    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn device_label(&self) -> &DeviceLabel {
        &self.device_label
    }

    #[must_use]
    pub const fn tree(&self) -> &VaultTree {
        &self.tree
    }
}

/// Deterministic two-parent metadata for the new merge snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInput {
    parents: [SnapshotId; 2],
}

impl SnapshotInput {
    pub fn two_parent(first: SnapshotId, second: SnapshotId) -> Result<Self, CoreError> {
        if first == second {
            return Err(CoreError::DuplicateSnapshotParent);
        }
        let mut parents = [first, second];
        parents.sort();
        Ok(Self { parents })
    }

    #[must_use]
    pub const fn parents(&self) -> &[SnapshotId; 2] {
        &self.parents
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceLabel, Snapshot, SnapshotInput};
    use crate::{DeviceId, FileId, SnapshotId, VaultTree};

    #[test]
    fn device_labels_are_sanitized_for_conflict_names() {
        let label = DeviceLabel::new("  Mark's MacBook / Work  ");

        assert_eq!(label.sanitized(), "mark-s-macbook-work");
    }

    #[test]
    fn empty_device_labels_have_a_portable_fallback() {
        assert_eq!(DeviceLabel::new("!? ").sanitized(), "device");
    }

    #[test]
    fn snapshot_input_sorts_its_two_distinct_parents() {
        let first = SnapshotId::from_bytes([2; 32]);
        let second = SnapshotId::from_bytes([1; 32]);
        let input = SnapshotInput::two_parent(first, second).unwrap();

        assert_eq!(input.parents(), &[second, first]);
    }

    #[test]
    fn snapshot_carries_origin_and_immutable_tree() {
        let tree = VaultTree::empty(FileId::from_bytes([1; 16]));
        let snapshot = Snapshot::new(
            SnapshotId::from_bytes([2; 32]),
            DeviceId::from_bytes([3; 16]),
            DeviceLabel::new("laptop"),
            tree.clone(),
        );

        assert_eq!(snapshot.tree(), &tree);
        assert_eq!(snapshot.device_label().as_str(), "laptop");
    }

    #[test]
    fn debug_output_does_not_disclose_device_labels() {
        let label = DeviceLabel::new("personally identifying laptop");

        assert!(!format!("{label:?}").contains("identifying"));
    }
}
