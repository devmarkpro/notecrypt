use notecrypt_format::{RevisionLocator, SnapshotParentLocator};

fn require<T: std::fmt::Debug>() {}

fn main() {
    require::<RevisionLocator>();
    require::<SnapshotParentLocator>();
}
