//! Deterministic domain types and behavior for Notecrypt.

mod error;
mod ids;
mod path;
mod persistent;
mod reconcile;
mod snapshot;
mod tree;
mod tree_index;

pub use error::CoreError;
pub use ids::{DeviceId, FileId, ObjectId, RevisionId, SnapshotId, VaultId};
pub use path::{EntryName, LogicalPath};
pub use reconcile::{
    ConflictAlternative, ConflictKind, ConflictRecord, ReconcileResult, reconcile,
};
pub use snapshot::{DeviceLabel, Snapshot, SnapshotInput};
pub use tree::{DirectoryEntry, Entry, EntryKind, FileEntry, Tombstone, VaultTree};
