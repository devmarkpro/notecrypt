use notecrypt_format::{RevisionLocator, SnapshotParentLocator};

fn main() {
    let revision = RevisionLocator::new([1; 32], [2; 32]);
    let parent = SnapshotParentLocator::new([3; 32], [4; 32]);
    let _ = revision.revision_id;
    let _ = revision.manifest_object_id;
    let _ = parent.snapshot_id;
    let _ = parent.snapshot_object_id;
}
