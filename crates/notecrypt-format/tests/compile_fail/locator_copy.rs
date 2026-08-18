use notecrypt_format::{RevisionLocator, SnapshotParentLocator};

fn require<T: Copy>() {}

fn main() {
    require::<RevisionLocator>();
    require::<SnapshotParentLocator>();
}
