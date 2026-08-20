use notecrypt_format::{RevisionLocator, SnapshotParentLocator};

fn require<T: Clone>() {}

fn main() {
    require::<RevisionLocator>();
    require::<SnapshotParentLocator>();
}
