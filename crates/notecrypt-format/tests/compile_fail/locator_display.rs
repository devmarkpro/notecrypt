use notecrypt_format::{RevisionLocator, SnapshotParentLocator};

fn require<T: std::fmt::Display>() {}

fn main() {
    require::<RevisionLocator>();
    require::<SnapshotParentLocator>();
}
