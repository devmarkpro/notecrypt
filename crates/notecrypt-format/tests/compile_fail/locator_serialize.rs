use notecrypt_format::{RevisionLocator, SnapshotParentLocator};
use serde::Serialize;

fn require<T: Serialize>() {}

fn main() {
    require::<RevisionLocator>();
    require::<SnapshotParentLocator>();
}
