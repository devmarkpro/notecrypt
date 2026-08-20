use std::fmt;

use crate::{
    CoreError, EntryName, FileId, RevisionId, SnapshotId, persistent::PersistentTrie,
    tree_index::TreeIndexes,
};

/// Immutable input for a logical file entry.
#[derive(Clone, PartialEq, Eq)]
pub struct FileEntry {
    id: FileId,
    name: EntryName,
    revision: RevisionId,
}

impl fmt::Debug for FileEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileEntry(<redacted>)")
    }
}

impl FileEntry {
    #[must_use]
    pub const fn new(id: FileId, name: EntryName, revision: RevisionId) -> Self {
        Self { id, name, revision }
    }
}

/// Immutable input for a logical directory entry.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    id: FileId,
    name: EntryName,
}

impl fmt::Debug for DirectoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectoryEntry(<redacted>)")
    }
}

impl DirectoryEntry {
    #[must_use]
    pub const fn new(id: FileId, name: EntryName) -> Self {
        Self { id, name }
    }
}

/// The stable kind of a logical tree entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Root,
    File,
    Directory,
    Tombstone,
}

/// Deleted logical metadata retained to prevent offline resurrection.
#[derive(Clone, PartialEq, Eq)]
pub struct Tombstone {
    id: FileId,
    parent: FileId,
    name: EntryName,
    deleted_in: SnapshotId,
    prior_kind: EntryKind,
    last_revision: Option<RevisionId>,
}

impl fmt::Debug for Tombstone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Tombstone(<redacted>)")
    }
}

/// An immutable unlocked logical entry.
#[derive(Clone, PartialEq, Eq)]
pub enum Entry {
    Root {
        id: FileId,
    },
    File {
        parent: FileId,
        file: FileEntry,
    },
    Directory {
        parent: FileId,
        directory: DirectoryEntry,
    },
    Tombstone(Tombstone),
}

impl fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Entry").field(&self.kind()).finish()
    }
}

impl Entry {
    #[must_use]
    pub const fn id(&self) -> FileId {
        match self {
            Self::Root { id } => *id,
            Self::File { file, .. } => file.id,
            Self::Directory { directory, .. } => directory.id,
            Self::Tombstone(tombstone) => tombstone.id,
        }
    }

    #[must_use]
    pub const fn parent(&self) -> Option<FileId> {
        match self {
            Self::Root { .. } => None,
            Self::File { parent, .. } | Self::Directory { parent, .. } => Some(*parent),
            Self::Tombstone(tombstone) => Some(tombstone.parent),
        }
    }

    #[must_use]
    pub const fn name(&self) -> Option<&EntryName> {
        match self {
            Self::Root { .. } => None,
            Self::File { file, .. } => Some(&file.name),
            Self::Directory { directory, .. } => Some(&directory.name),
            Self::Tombstone(tombstone) => Some(&tombstone.name),
        }
    }

    #[must_use]
    pub const fn revision(&self) -> Option<RevisionId> {
        match self {
            Self::File { file, .. } => Some(file.revision),
            Self::Tombstone(tombstone) => tombstone.last_revision,
            Self::Root { .. } | Self::Directory { .. } => None,
        }
    }

    #[must_use]
    pub const fn deleted_in(&self) -> Option<SnapshotId> {
        match self {
            Self::Tombstone(tombstone) => Some(tombstone.deleted_in),
            Self::Root { .. } | Self::File { .. } | Self::Directory { .. } => None,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> EntryKind {
        match self {
            Self::Root { .. } => EntryKind::Root,
            Self::File { .. } => EntryKind::File,
            Self::Directory { .. } => EntryKind::Directory,
            Self::Tombstone(_) => EntryKind::Tombstone,
        }
    }

    #[must_use]
    pub const fn prior_kind(&self) -> Option<EntryKind> {
        match self {
            Self::Tombstone(tombstone) => Some(tombstone.prior_kind),
            Self::Root { .. } | Self::File { .. } | Self::Directory { .. } => None,
        }
    }

    pub(crate) fn with_name(&self, name: EntryName) -> Self {
        match self {
            Self::File { parent, file } => Self::File {
                parent: *parent,
                file: FileEntry::new(file.id, name, file.revision),
            },
            Self::Directory { parent, directory } => Self::Directory {
                parent: *parent,
                directory: DirectoryEntry::new(directory.id, name),
            },
            Self::Root { .. } | Self::Tombstone(_) => self.clone(),
        }
    }

    pub(crate) fn with_parent(&self, parent: FileId) -> Self {
        match self {
            Self::File { file, .. } => Self::File {
                parent,
                file: file.clone(),
            },
            Self::Directory { directory, .. } => Self::Directory {
                parent,
                directory: directory.clone(),
            },
            Self::Root { .. } | Self::Tombstone(_) => self.clone(),
        }
    }

    fn into_tombstone(self, deleted_in: SnapshotId) -> Self {
        let prior_kind = self.kind();
        Self::Tombstone(Tombstone {
            id: self.id(),
            parent: self.parent().expect("the root is never tombstoned"),
            name: self.name().expect("the root is never tombstoned").clone(),
            deleted_in,
            prior_kind,
            last_revision: self.revision(),
        })
    }

    pub(crate) fn is_live(&self) -> bool {
        !matches!(self, Self::Tombstone(_))
    }

    pub(crate) fn copy_with(&self, id: FileId, parent: FileId, name: EntryName) -> Option<Self> {
        match self {
            Self::File { file, .. } => Some(Self::File {
                parent,
                file: FileEntry::new(id, name, file.revision),
            }),
            Self::Directory { .. } => Some(Self::Directory {
                parent,
                directory: DirectoryEntry::new(id, name),
            }),
            Self::Root { .. } | Self::Tombstone(_) => None,
        }
    }
}

/// A structurally shared immutable logical vault tree.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultTree {
    root: FileId,
    pub(crate) entries: PersistentTrie<16, Entry>,
    indexes: TreeIndexes,
}

impl fmt::Debug for VaultTree {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultTree")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl VaultTree {
    #[must_use]
    pub fn empty(root: FileId) -> Self {
        let mut entries = PersistentTrie::new();
        entries.insert(*root.as_bytes(), Entry::Root { id: root });
        Self {
            root,
            entries,
            indexes: TreeIndexes::new(),
        }
    }

    pub fn create_file(&self, parent: FileId, entry: FileEntry) -> Result<Self, CoreError> {
        self.create_entry(
            parent,
            entry.id,
            Entry::File {
                parent,
                file: entry,
            },
        )
    }

    pub fn create_directory(
        &self,
        parent: FileId,
        entry: DirectoryEntry,
    ) -> Result<Self, CoreError> {
        self.create_entry(
            parent,
            entry.id,
            Entry::Directory {
                parent,
                directory: entry,
            },
        )
    }

    pub fn rename(&self, id: FileId, name: EntryName) -> Result<Self, CoreError> {
        let current = self.mutable_entry(id)?;
        let parent = current
            .parent()
            .expect("mutable entries always have parents");
        self.ensure_destination_available(parent, &name, Some(id))?;
        self.with_entry(current.with_name(name))
    }

    pub fn move_entry(&self, id: FileId, parent: FileId) -> Result<Self, CoreError> {
        let current = self.mutable_entry(id)?;
        self.require_directory_parent(parent)?;
        if current.kind() == EntryKind::Directory && self.is_descendant(parent, id) {
            return Err(CoreError::DirectoryCycle);
        }
        self.ensure_destination_available(
            parent,
            current.name().expect("mutable entries have names"),
            Some(id),
        )?;
        self.with_entry(current.with_parent(parent))
    }

    pub fn remove(&self, id: FileId, deleted_in: SnapshotId) -> Result<Self, CoreError> {
        self.mutable_entry(id)?;
        let mut result = self.clone();
        let mut pending = vec![id];
        while let Some(next) = pending.pop() {
            pending.extend(result.live_child_ids(next));
            let current = result
                .entries
                .get(next.as_bytes())
                .expect("queued entries came from the tree")
                .clone();
            result = result.with_entry(current.into_tombstone(deleted_in))?;
        }
        Ok(result)
    }

    #[must_use]
    pub fn entry(&self, id: FileId) -> Option<&Entry> {
        self.entries.get(id.as_bytes())
    }

    pub fn children(&self, parent: FileId) -> Result<Vec<&Entry>, CoreError> {
        self.require_directory_parent(parent)?;
        let mut children = self
            .indexes
            .children(parent)
            .into_iter()
            .map(|id| {
                self.entries
                    .get(id.as_bytes())
                    .expect("child indexes reference existing entries")
            })
            .collect::<Vec<_>>();
        children.sort_by(|left, right| {
            left.name()
                .expect("children have names")
                .collision_key()
                .cmp(&right.name().expect("children have names").collision_key())
                .then_with(|| left.id().cmp(&right.id()))
        });
        Ok(children)
    }

    #[must_use]
    pub const fn root(&self) -> FileId {
        self.root
    }

    fn create_entry(&self, parent: FileId, id: FileId, entry: Entry) -> Result<Self, CoreError> {
        self.require_directory_parent(parent)?;
        if self.entries.contains_key(id.as_bytes()) {
            return Err(CoreError::EntryAlreadyExists);
        }
        self.ensure_destination_available(
            parent,
            entry.name().expect("new entries always have names"),
            None,
        )?;
        self.with_entry(entry)
    }

    fn mutable_entry(&self, id: FileId) -> Result<&Entry, CoreError> {
        let entry = self
            .entries
            .get(id.as_bytes())
            .ok_or(CoreError::MissingEntry)?;
        if id == self.root {
            return Err(CoreError::RootMutation);
        }
        if !entry.is_live() {
            return Err(CoreError::MissingEntry);
        }
        Ok(entry)
    }

    fn require_directory_parent(&self, parent: FileId) -> Result<(), CoreError> {
        let entry = self
            .entries
            .get(parent.as_bytes())
            .ok_or(CoreError::MissingParent)?;
        match entry.kind() {
            EntryKind::Root | EntryKind::Directory => Ok(()),
            EntryKind::File | EntryKind::Tombstone => Err(CoreError::ParentNotDirectory),
        }
    }

    fn ensure_destination_available(
        &self,
        parent: FileId,
        name: &EntryName,
        excluding: Option<FileId>,
    ) -> Result<(), CoreError> {
        let collision_key = name.collision_key();
        let occupied = self.indexes.destination(parent, &collision_key);
        if occupied.is_some() && occupied != excluding {
            Err(CoreError::DuplicateDestination)
        } else {
            Ok(())
        }
    }

    fn is_descendant(&self, candidate: FileId, ancestor: FileId) -> bool {
        let mut current = Some(candidate);
        let mut visited = std::collections::BTreeSet::new();
        while let Some(id) = current {
            if id == ancestor {
                return true;
            }
            if !visited.insert(id) {
                return false;
            }
            current = self.entries.get(id.as_bytes()).and_then(Entry::parent);
        }
        false
    }

    fn live_child_ids(&self, parent: FileId) -> Vec<FileId> {
        self.indexes.children(parent)
    }

    fn with_entry(&self, entry: Entry) -> Result<Self, CoreError> {
        let mut entries = self.entries.clone();
        let mut indexes = self.indexes.clone();
        if let Some(previous) = entries.get(entry.id().as_bytes()) {
            indexes.remove(previous);
        }
        indexes.add(&entry)?;
        entries.insert(*entry.id().as_bytes(), entry);
        Ok(Self {
            root: self.root,
            entries,
            indexes,
        })
    }

    pub(crate) fn from_entries(
        root: FileId,
        entries: PersistentTrie<16, Entry>,
    ) -> Result<Self, CoreError> {
        validate_entries(root, &entries)?;
        let indexes = TreeIndexes::from_entries(entries.values())?;
        Ok(Self {
            root,
            entries,
            indexes,
        })
    }

    pub(crate) fn child_ids(&self, parent: FileId) -> Vec<FileId> {
        self.indexes.children(parent)
    }
}

fn validate_entries(root: FileId, entries: &PersistentTrie<16, Entry>) -> Result<(), CoreError> {
    if !matches!(entries.get(root.as_bytes()), Some(Entry::Root { id }) if *id == root) {
        return Err(CoreError::RootMismatch);
    }

    let mut live_directories = std::collections::BTreeSet::new();
    for (key, entry) in entries.key_values() {
        if key != entry.id().as_bytes() {
            return Err(CoreError::RootMismatch);
        }
        if matches!(entry, Entry::Root { id } if *id != root) {
            return Err(CoreError::RootMismatch);
        }
        if !entry.is_live() || entry.id() == root {
            continue;
        }
        let parent = entry.parent().ok_or(CoreError::MissingParent)?;
        let parent_entry = entries
            .get(parent.as_bytes())
            .ok_or(CoreError::MissingParent)?;
        if parent != root
            && (!parent_entry.is_live() || parent_entry.kind() != EntryKind::Directory)
        {
            return Err(CoreError::MissingParent);
        }
        if entry.kind() == EntryKind::Directory {
            live_directories.insert(entry.id());
        }
    }

    let mut finished = std::collections::BTreeSet::new();
    for start in live_directories.iter().copied() {
        if finished.contains(&start) {
            continue;
        }
        let mut path = Vec::new();
        let mut positions = std::collections::BTreeMap::new();
        let mut current = start;
        while current != root && !finished.contains(&current) {
            if positions.insert(current, path.len()).is_some() {
                return Err(CoreError::DirectoryCycle);
            }
            path.push(current);
            current = entries
                .get(current.as_bytes())
                .and_then(Entry::parent)
                .ok_or(CoreError::MissingParent)?;
        }
        finished.extend(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DirectoryEntry, EntryKind, FileEntry, VaultTree};
    use crate::{
        CoreError, EntryName, FileId, RevisionId, SnapshotId, persistent::measure_node_visits,
        tree_index::TreeIndexes,
    };

    fn file_id(byte: u8) -> FileId {
        FileId::from_bytes([byte; 16])
    }

    fn numbered_file_id(number: u64) -> FileId {
        let mut bytes = [0_u8; 16];
        bytes[8..].copy_from_slice(&number.to_be_bytes());
        FileId::from_bytes(bytes)
    }

    fn revision_id(byte: u8) -> RevisionId {
        RevisionId::from_bytes([byte; 32])
    }

    fn name(value: &str) -> EntryName {
        EntryName::parse(value).unwrap()
    }

    fn assert_indexes_match_entries(tree: &VaultTree) {
        let rebuilt = TreeIndexes::from_entries(tree.entries.values()).unwrap();
        assert!(tree.indexes == rebuilt);
    }

    #[test]
    fn create_file_returns_a_new_tree_and_keeps_identity() {
        let root = file_id(1);
        let tree = VaultTree::empty(root);
        let created = tree
            .create_file(
                root,
                FileEntry::new(file_id(2), name("note.md"), revision_id(3)),
            )
            .unwrap();

        assert!(tree.entry(file_id(2)).is_none());
        let entry = created.entry(file_id(2)).unwrap();
        assert_eq!(entry.id(), file_id(2));
        assert_eq!(entry.parent(), Some(root));
        assert_eq!(entry.name().unwrap().as_str(), "note.md");
        assert_eq!(entry.revision(), Some(revision_id(3)));
    }

    #[test]
    fn indexes_match_entries_after_every_tree_transition() {
        let root = file_id(1);
        let directory = file_id(2);
        let file = file_id(3);
        let empty = VaultTree::empty(root);
        assert_indexes_match_entries(&empty);
        let with_directory = empty
            .create_directory(root, DirectoryEntry::new(directory, name("notes")))
            .unwrap();
        assert_indexes_match_entries(&with_directory);
        let with_file = with_directory
            .create_file(root, FileEntry::new(file, name("draft"), revision_id(1)))
            .unwrap();
        assert_indexes_match_entries(&with_file);
        let renamed = with_file.rename(file, name("final")).unwrap();
        assert_indexes_match_entries(&renamed);
        let moved = renamed.move_entry(file, directory).unwrap();
        assert_indexes_match_entries(&moved);
        let removed = moved
            .remove(directory, SnapshotId::from_bytes([9; 32]))
            .unwrap();
        assert_indexes_match_entries(&removed);
    }

    #[test]
    fn indexed_create_operation_count_does_not_grow_with_vault_size() {
        fn tree_with_files(count: u64) -> VaultTree {
            let root = numbered_file_id(u64::MAX);
            let mut tree = VaultTree::empty(root);
            for number in 0..count {
                tree = tree
                    .create_file(
                        root,
                        FileEntry::new(
                            numbered_file_id(number),
                            name(&format!("file-{number:05}")),
                            revision_id(1),
                        ),
                    )
                    .unwrap();
            }
            tree
        }

        let one_thousand = tree_with_files(1_000);
        let five_thousand = tree_with_files(5_000);
        let (_, visits_at_one_thousand) = measure_node_visits(|| {
            one_thousand
                .create_file(
                    one_thousand.root(),
                    FileEntry::new(numbered_file_id(10_000), name("new-a"), revision_id(2)),
                )
                .unwrap()
        });
        let (_, visits_at_five_thousand) = measure_node_visits(|| {
            five_thousand
                .create_file(
                    five_thousand.root(),
                    FileEntry::new(numbered_file_id(10_001), name("new-b"), revision_id(2)),
                )
                .unwrap()
        });
        eprintln!(
            "create_visits_1000={visits_at_one_thousand} create_visits_5000={visits_at_five_thousand}"
        );

        assert!(visits_at_five_thousand.abs_diff(visits_at_one_thousand) <= 64);
        assert!(visits_at_five_thousand < 2_500);
    }

    #[test]
    fn compact_indexes_have_linear_retained_node_and_byte_bounds() {
        let root = numbered_file_id(u64::MAX);
        let mut tree = VaultTree::empty(root);
        for number in 0_u64..10_000 {
            tree = tree
                .create_file(
                    root,
                    FileEntry::new(
                        numbered_file_id(number),
                        name(&format!("file-{number:05}")),
                        revision_id(1),
                    ),
                )
                .unwrap();
        }

        let retained_nodes =
            tree.entries.retained_node_count() + tree.indexes.retained_node_count();
        let estimated_node_bytes = tree.entries.estimated_retained_node_bytes()
            + tree.indexes.estimated_retained_node_bytes();
        eprintln!(
            "entries=10000 retained_nodes={retained_nodes} estimated_node_bytes={estimated_node_bytes}"
        );

        assert_eq!(retained_nodes, 59_999);
        assert!(estimated_node_bytes < 8 * 1024 * 1024);
    }

    #[test]
    fn from_entries_rejects_live_entries_with_non_live_parents() {
        let root = file_id(1);
        let missing_parent = file_id(2);
        let child = file_id(3);
        let mut entries = crate::persistent::PersistentTrie::new();
        entries.insert(*root.as_bytes(), crate::Entry::Root { id: root });
        entries.insert(
            *child.as_bytes(),
            crate::Entry::Directory {
                parent: missing_parent,
                directory: DirectoryEntry::new(child, name("child")),
            },
        );

        assert_eq!(
            VaultTree::from_entries(root, entries).unwrap_err(),
            CoreError::MissingParent,
        );
    }

    #[test]
    fn from_entries_rejects_unreachable_directory_cycles() {
        let root = file_id(1);
        let a = file_id(2);
        let b = file_id(3);
        let mut entries = crate::persistent::PersistentTrie::new();
        entries.insert(*root.as_bytes(), crate::Entry::Root { id: root });
        entries.insert(
            *a.as_bytes(),
            crate::Entry::Directory {
                parent: b,
                directory: DirectoryEntry::new(a, name("a")),
            },
        );
        entries.insert(
            *b.as_bytes(),
            crate::Entry::Directory {
                parent: a,
                directory: DirectoryEntry::new(b, name("b")),
            },
        );

        assert_eq!(
            VaultTree::from_entries(root, entries).unwrap_err(),
            CoreError::DirectoryCycle,
        );
    }

    #[test]
    fn create_directory_requires_an_existing_directory_parent() {
        let root = file_id(1);
        let tree = VaultTree::empty(root);
        let missing =
            tree.create_directory(file_id(9), DirectoryEntry::new(file_id(2), name("notes")));
        assert_eq!(missing.unwrap_err(), CoreError::MissingParent);

        let with_file = tree
            .create_file(
                root,
                FileEntry::new(file_id(2), name("file"), revision_id(1)),
            )
            .unwrap();
        let not_directory =
            with_file.create_directory(file_id(2), DirectoryEntry::new(file_id(3), name("nested")));
        assert_eq!(not_directory.unwrap_err(), CoreError::ParentNotDirectory);
    }

    #[test]
    fn create_rejects_exact_normalization_and_case_fold_collisions() {
        let root = file_id(1);
        let tree = VaultTree::empty(root)
            .create_file(
                root,
                FileEntry::new(file_id(2), name("Caf\u{e9}.md"), revision_id(1)),
            )
            .unwrap();

        for colliding in ["Cafe\u{301}.md", "CAF\u{c9}.MD"] {
            let result = tree.create_file(
                root,
                FileEntry::new(file_id(3), name(colliding), revision_id(2)),
            );
            assert_eq!(result.unwrap_err(), CoreError::DuplicateDestination);
        }
    }

    #[test]
    fn rename_and_move_preserve_file_identity_and_revision() {
        let root = file_id(1);
        let notes = file_id(2);
        let file = file_id(3);
        let tree = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(notes, name("notes")))
            .unwrap()
            .create_file(root, FileEntry::new(file, name("draft"), revision_id(4)))
            .unwrap();

        let changed = tree
            .rename(file, name("final"))
            .unwrap()
            .move_entry(file, notes)
            .unwrap();
        let entry = changed.entry(file).unwrap();

        assert_eq!(entry.id(), file);
        assert_eq!(entry.parent(), Some(notes));
        assert_eq!(entry.name().unwrap().as_str(), "final");
        assert_eq!(entry.revision(), Some(revision_id(4)));
    }

    #[test]
    fn rename_and_move_reject_duplicate_destinations() {
        let root = file_id(1);
        let folder = file_id(2);
        let first = file_id(3);
        let second = file_id(4);
        let tree = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(folder, name("folder")))
            .unwrap()
            .create_file(root, FileEntry::new(first, name("one"), revision_id(1)))
            .unwrap()
            .create_file(root, FileEntry::new(second, name("two"), revision_id(2)))
            .unwrap()
            .create_file(
                folder,
                FileEntry::new(file_id(5), name("one"), revision_id(3)),
            )
            .unwrap();

        assert_eq!(
            tree.rename(second, name("ONE")).unwrap_err(),
            CoreError::DuplicateDestination,
        );
        assert_eq!(
            tree.move_entry(first, folder).unwrap_err(),
            CoreError::DuplicateDestination,
        );
    }

    #[test]
    fn move_rejects_missing_parents_and_directory_cycles() {
        let root = file_id(1);
        let parent = file_id(2);
        let child = file_id(3);
        let tree = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(parent, name("parent")))
            .unwrap()
            .create_directory(parent, DirectoryEntry::new(child, name("child")))
            .unwrap();

        assert_eq!(
            tree.move_entry(child, file_id(9)).unwrap_err(),
            CoreError::MissingParent,
        );
        assert_eq!(
            tree.move_entry(parent, child).unwrap_err(),
            CoreError::DirectoryCycle,
        );
    }

    #[test]
    fn remove_creates_tombstones_without_mutating_the_old_tree() {
        let root = file_id(1);
        let folder = file_id(2);
        let file = file_id(3);
        let tree = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(folder, name("folder")))
            .unwrap()
            .create_file(folder, FileEntry::new(file, name("note"), revision_id(4)))
            .unwrap();
        let deleted_in = SnapshotId::from_bytes([5; 32]);

        let removed = tree.remove(folder, deleted_in).unwrap();

        assert_eq!(tree.entry(file).unwrap().kind(), EntryKind::File);
        assert_eq!(removed.entry(folder).unwrap().kind(), EntryKind::Tombstone);
        assert_eq!(removed.entry(file).unwrap().kind(), EntryKind::Tombstone);
        assert_eq!(removed.entry(file).unwrap().deleted_in(), Some(deleted_in));
        assert!(removed.children(root).unwrap().is_empty());
    }

    #[test]
    fn children_are_sorted_by_portable_name_then_identity() {
        let root = file_id(1);
        let tree = VaultTree::empty(root)
            .create_file(
                root,
                FileEntry::new(file_id(2), name("zeta"), revision_id(1)),
            )
            .unwrap()
            .create_file(
                root,
                FileEntry::new(file_id(3), name("Alpha"), revision_id(2)),
            )
            .unwrap();

        let children = tree.children(root).unwrap();
        assert_eq!(children[0].name().unwrap().as_str(), "Alpha");
        assert_eq!(children[1].name().unwrap().as_str(), "zeta");
    }

    #[test]
    fn tree_debug_output_does_not_disclose_logical_names() {
        let root = file_id(1);
        let tree = VaultTree::empty(root)
            .create_file(
                root,
                FileEntry::new(file_id(2), name("pii.txt"), revision_id(1)),
            )
            .unwrap();

        assert!(!format!("{tree:?}").contains("pii.txt"));
    }
}
