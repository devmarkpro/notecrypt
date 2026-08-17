use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    CoreError, DeviceId, DeviceLabel, Entry, EntryKind, EntryName, FileId, RevisionId, Snapshot,
    SnapshotId, SnapshotInput, VaultTree, persistent::PersistentTrie,
};

/// The reason reconciliation preserved explicit alternatives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictKind {
    SameFileChanged,
    Rename,
    DeleteVersusModify,
    TypeChanged,
    PathCollision,
    ParentDeleted,
    DirectoryCycle,
}

/// One authenticated side of a conflict, without file bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ConflictAlternative {
    snapshot_id: SnapshotId,
    device_id: DeviceId,
    device_label: DeviceLabel,
    entry: Entry,
}

impl fmt::Debug for ConflictAlternative {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConflictAlternative(<redacted>)")
    }
}

impl ConflictAlternative {
    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
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
    pub const fn entry(&self) -> &Entry {
        &self.entry
    }
}

/// A deterministic conflict record retaining both logical alternatives.
#[derive(Clone, PartialEq, Eq)]
pub struct ConflictRecord {
    original_id: FileId,
    kind: ConflictKind,
    alternatives: Vec<ConflictAlternative>,
}

impl fmt::Debug for ConflictRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConflictRecord")
            .field("kind", &self.kind)
            .field("alternative_count", &self.alternatives.len())
            .finish_non_exhaustive()
    }
}

impl ConflictRecord {
    #[must_use]
    pub const fn original_id(&self) -> FileId {
        self.original_id
    }

    #[must_use]
    pub const fn kind(&self) -> ConflictKind {
        self.kind
    }

    #[must_use]
    pub fn alternatives(&self) -> &[ConflictAlternative] {
        &self.alternatives
    }
}

/// Complete deterministic output of a three-way logical reconciliation.
#[derive(Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    merged_tree: VaultTree,
    conflicts: Vec<ConflictRecord>,
    snapshot_input: SnapshotInput,
}

impl fmt::Debug for ReconcileResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconcileResult")
            .field("merged_tree", &self.merged_tree)
            .field("conflict_count", &self.conflicts.len())
            .field("snapshot_input", &self.snapshot_input)
            .finish()
    }
}

impl ReconcileResult {
    #[must_use]
    pub const fn merged_tree(&self) -> &VaultTree {
        &self.merged_tree
    }

    #[must_use]
    pub fn conflicts(&self) -> &[ConflictRecord] {
        &self.conflicts
    }

    #[must_use]
    pub const fn snapshot_input(&self) -> &SnapshotInput {
        &self.snapshot_input
    }

    #[must_use]
    pub fn preserved_revisions(&self) -> Vec<RevisionId> {
        let mut revisions = self
            .merged_tree
            .entries
            .values()
            .into_iter()
            .filter_map(Entry::revision)
            .collect::<BTreeSet<_>>();
        for alternative in self
            .conflicts
            .iter()
            .flat_map(|conflict| conflict.alternatives())
        {
            if let Some(revision) = alternative.entry().revision() {
                revisions.insert(revision);
            }
        }
        revisions.into_iter().collect()
    }
}

#[derive(Clone)]
struct Origin {
    snapshot_id: SnapshotId,
    device_id: DeviceId,
    device_label: DeviceLabel,
}

impl Origin {
    fn from_snapshot(snapshot: &Snapshot) -> Self {
        Self {
            snapshot_id: snapshot.id(),
            device_id: snapshot.device_id(),
            device_label: snapshot.device_label().clone(),
        }
    }

    fn alternative(&self, entry: Entry) -> ConflictAlternative {
        ConflictAlternative {
            snapshot_id: self.snapshot_id,
            device_id: self.device_id,
            device_label: self.device_label.clone(),
            entry,
        }
    }
}

#[derive(Clone)]
struct SelectedEntry {
    entry: Entry,
    origin: Origin,
    source: SourceSide,
}

#[derive(Clone, Copy)]
enum SourceSide {
    First,
    Second,
}

struct ChangedAlternatives<'a> {
    id: FileId,
    first: &'a Entry,
    first_origin: &'a Origin,
    first_tree: &'a VaultTree,
    second: &'a Entry,
    second_origin: &'a Origin,
    second_tree: &'a VaultTree,
}

/// Reconciles authenticated logical metadata without inspecting or merging file bytes.
pub fn reconcile(
    base: &VaultTree,
    local: &Snapshot,
    remote: &Snapshot,
) -> Result<ReconcileResult, CoreError> {
    if base.root() != local.tree().root() || base.root() != remote.tree().root() {
        return Err(CoreError::RootMismatch);
    }

    let snapshot_input = SnapshotInput::two_parent(local.id(), remote.id())?;
    let (first, second) = ordered_snapshots(local, remote);
    let first_origin = Origin::from_snapshot(first);
    let second_origin = Origin::from_snapshot(second);
    let mut selected = BTreeMap::<FileId, SelectedEntry>::new();
    let mut conflicts = Vec::new();

    let ids = base
        .entries
        .values()
        .into_iter()
        .chain(first.tree().entries.values())
        .chain(second.tree().entries.values())
        .map(Entry::id)
        .collect::<BTreeSet<_>>();
    let mut occupied_ids = ids.clone();

    for id in ids.into_iter().filter(|id| *id != base.root()) {
        let base_entry = base.entries.get(id.as_bytes());
        let first_entry = first.tree().entries.get(id.as_bytes());
        let second_entry = second.tree().entries.get(id.as_bytes());

        if first_entry == second_entry {
            if let Some(entry) = first_entry {
                selected.insert(
                    id,
                    SelectedEntry {
                        entry: entry.clone(),
                        origin: first_origin.clone(),
                        source: SourceSide::First,
                    },
                );
            }
        } else if first_entry == base_entry {
            if let Some(entry) = second_entry {
                selected.insert(
                    id,
                    SelectedEntry {
                        entry: entry.clone(),
                        origin: second_origin.clone(),
                        source: SourceSide::Second,
                    },
                );
            }
        } else if second_entry == base_entry {
            if let Some(entry) = first_entry {
                selected.insert(
                    id,
                    SelectedEntry {
                        entry: entry.clone(),
                        origin: first_origin.clone(),
                        source: SourceSide::First,
                    },
                );
            }
        } else if let (Some(first_entry), Some(second_entry)) = (first_entry, second_entry) {
            preserve_changed_alternatives(
                ChangedAlternatives {
                    id,
                    first: first_entry,
                    first_origin: &first_origin,
                    first_tree: first.tree(),
                    second: second_entry,
                    second_origin: &second_origin,
                    second_tree: second.tree(),
                },
                &mut selected,
                &mut occupied_ids,
                &mut conflicts,
            );
        } else if let Some(entry) = first_entry.or(second_entry) {
            let (origin, source) = if first_entry.is_some() {
                (first_origin.clone(), SourceSide::First)
            } else {
                (second_origin.clone(), SourceSide::Second)
            };
            selected.insert(
                id,
                SelectedEntry {
                    entry: entry.clone(),
                    origin,
                    source,
                },
            );
        }
    }

    repair_structure(
        base,
        first.tree(),
        second.tree(),
        &mut selected,
        &mut occupied_ids,
        &mut conflicts,
    )?;
    resolve_path_collisions(base, &mut selected, &mut conflicts);

    let mut entries = PersistentTrie::new();
    entries.insert(*base.root().as_bytes(), Entry::Root { id: base.root() });
    for selected_entry in selected.into_values() {
        entries.insert(*selected_entry.entry.id().as_bytes(), selected_entry.entry);
    }
    sort_conflicts(&mut conflicts);

    Ok(ReconcileResult {
        merged_tree: VaultTree::from_entries(base.root(), entries)?,
        conflicts,
        snapshot_input,
    })
}

fn ordered_snapshots<'a>(
    first: &'a Snapshot,
    second: &'a Snapshot,
) -> (&'a Snapshot, &'a Snapshot) {
    if (first.id(), first.device_id()) <= (second.id(), second.device_id()) {
        (first, second)
    } else {
        (second, first)
    }
}

fn preserve_changed_alternatives(
    changed: ChangedAlternatives<'_>,
    selected: &mut BTreeMap<FileId, SelectedEntry>,
    occupied_ids: &mut BTreeSet<FileId>,
    conflicts: &mut Vec<ConflictRecord>,
) {
    let ChangedAlternatives {
        id,
        first,
        first_origin,
        first_tree,
        second,
        second_origin,
        second_tree,
    } = changed;
    let kind = classify_conflict(first, second);
    let (
        primary,
        primary_origin,
        primary_source,
        alternate,
        alternate_origin,
        alternate_tree,
        alternate_source,
    ) = if kind == ConflictKind::DeleteVersusModify && second.kind() == EntryKind::Tombstone {
        (
            second,
            second_origin,
            SourceSide::Second,
            first,
            first_origin,
            first_tree,
            SourceSide::First,
        )
    } else {
        (
            first,
            first_origin,
            SourceSide::First,
            second,
            second_origin,
            second_tree,
            SourceSide::Second,
        )
    };

    selected.insert(
        id,
        SelectedEntry {
            entry: primary.clone(),
            origin: primary_origin.clone(),
            source: primary_source,
        },
    );

    if alternate.is_live() {
        preserve_conflict_subtree(
            alternate,
            alternate_origin,
            alternate_tree,
            alternate_source,
            selected,
            occupied_ids,
        );
    }

    conflicts.push(conflict_record(
        id,
        kind,
        [(first, first_origin), (second, second_origin)],
    ));
}

fn classify_conflict(first: &Entry, second: &Entry) -> ConflictKind {
    if first.kind() == EntryKind::Tombstone || second.kind() == EntryKind::Tombstone {
        ConflictKind::DeleteVersusModify
    } else if first.kind() != second.kind() {
        ConflictKind::TypeChanged
    } else if first.name() != second.name() || first.parent() != second.parent() {
        ConflictKind::Rename
    } else {
        ConflictKind::SameFileChanged
    }
}

fn derived_available_id(
    original: FileId,
    origin: &Origin,
    occupied_ids: &BTreeSet<FileId>,
) -> Option<FileId> {
    let mut counter = 0_u32;
    loop {
        let id = derived_conflict_id(original, origin.snapshot_id, counter);
        if !occupied_ids.contains(&id) {
            return Some(id);
        }
        counter = counter.checked_add(1)?;
    }
}

fn preserve_conflict_subtree(
    alternate: &Entry,
    origin: &Origin,
    source_tree: &VaultTree,
    source: SourceSide,
    selected: &mut BTreeMap<FileId, SelectedEntry>,
    occupied_ids: &mut BTreeSet<FileId>,
) {
    let Some(root_id) = derived_available_id(alternate.id(), origin, occupied_ids) else {
        return;
    };
    let root_parent = alternate
        .parent()
        .expect("live non-root alternatives have parents");
    let root_name = conflict_name(
        alternate
            .name()
            .expect("live non-root alternatives have names"),
        origin,
        None,
    );
    let Some(root_copy) = alternate.copy_with(root_id, root_parent, root_name) else {
        return;
    };
    occupied_ids.insert(root_id);
    selected.insert(
        root_id,
        SelectedEntry {
            entry: root_copy,
            origin: origin.clone(),
            source,
        },
    );

    if alternate.kind() != EntryKind::Directory {
        return;
    }

    let mut pending = vec![(alternate.id(), root_id)];
    while let Some((source_parent, copied_parent)) = pending.pop() {
        let mut children = source_tree.child_ids(source_parent);
        children.sort();
        for child_id in children {
            let child = source_tree
                .entry(child_id)
                .expect("source indexes reference existing entries");
            let Some(copied_id) = derived_available_id(child_id, origin, occupied_ids) else {
                continue;
            };
            let Some(copied) = child.copy_with(
                copied_id,
                copied_parent,
                child
                    .name()
                    .expect("live source children have names")
                    .clone(),
            ) else {
                continue;
            };
            occupied_ids.insert(copied_id);
            selected.insert(
                copied_id,
                SelectedEntry {
                    entry: copied,
                    origin: origin.clone(),
                    source,
                },
            );
            if child.kind() == EntryKind::Directory {
                pending.push((child_id, copied_id));
            }
        }
    }
}

fn repair_structure(
    base: &VaultTree,
    first_tree: &VaultTree,
    second_tree: &VaultTree,
    selected: &mut BTreeMap<FileId, SelectedEntry>,
    occupied_ids: &mut BTreeSet<FileId>,
    conflicts: &mut Vec<ConflictRecord>,
) -> Result<(), CoreError> {
    let maximum_cycle_repairs = selected
        .values()
        .filter(|candidate| {
            candidate.entry.is_live() && candidate.entry.kind() == EntryKind::Directory
        })
        .count();
    let mut cycle_repairs = 0_usize;
    loop {
        let repaired_cycles = resolve_directory_cycles(
            base,
            first_tree,
            second_tree,
            selected,
            occupied_ids,
            conflicts,
        );
        cycle_repairs = cycle_repairs
            .checked_add(repaired_cycles)
            .ok_or(CoreError::DirectoryCycle)?;
        if cycle_repairs > maximum_cycle_repairs {
            return Err(CoreError::DirectoryCycle);
        }
        let repaired_orphans = relocate_orphans(base.root(), selected, conflicts);
        if repaired_cycles == 0 && !repaired_orphans {
            break;
        }
    }
    Ok(())
}

fn relocate_orphans(
    root: FileId,
    selected: &mut BTreeMap<FileId, SelectedEntry>,
    conflicts: &mut Vec<ConflictRecord>,
) -> bool {
    let orphan_ids = selected
        .iter()
        .filter_map(|(id, candidate)| {
            if !candidate.entry.is_live() {
                return None;
            }
            let parent = candidate.entry.parent()?;
            let parent_is_directory = parent == root
                || selected.get(&parent).is_some_and(|entry| {
                    entry.entry.is_live() && entry.entry.kind() == EntryKind::Directory
                });
            (!parent_is_directory).then_some(*id)
        })
        .collect::<Vec<_>>();
    let repaired = !orphan_ids.is_empty();

    for id in orphan_ids {
        let candidate = selected
            .get(&id)
            .expect("orphan IDs came from selected")
            .clone();
        let moved = candidate.entry.with_parent(root).with_name(conflict_name(
            candidate.entry.name().expect("orphans have names"),
            &candidate.origin,
            Some("parent-deleted"),
        ));
        selected.insert(
            id,
            SelectedEntry {
                entry: moved.clone(),
                origin: candidate.origin.clone(),
                source: candidate.source,
            },
        );
        conflicts.push(ConflictRecord {
            original_id: id,
            kind: ConflictKind::ParentDeleted,
            alternatives: vec![candidate.origin.alternative(candidate.entry)],
        });
    }
    repaired
}

fn resolve_directory_cycles(
    base: &VaultTree,
    first_tree: &VaultTree,
    second_tree: &VaultTree,
    selected: &mut BTreeMap<FileId, SelectedEntry>,
    occupied_ids: &mut BTreeSet<FileId>,
    conflicts: &mut Vec<ConflictRecord>,
) -> usize {
    let cycles = find_directory_cycles(base.root(), selected);
    let repaired = cycles.len();
    for cycle in cycles {
        let cycle_ids = cycle.iter().copied().collect::<BTreeSet<_>>();
        let victim_id = cycle
            .iter()
            .copied()
            .filter(|id| {
                base.entry(*id).is_some_and(|entry| {
                    entry.is_live()
                        && entry.kind() == EntryKind::Directory
                        && entry
                            .parent()
                            .is_some_and(|parent| !cycle_ids.contains(&parent))
                })
            })
            .max()
            .or_else(|| cycle.iter().copied().max())
            .expect("detected cycles contain at least one directory");
        let attempted = selected
            .get(&victim_id)
            .expect("cycle IDs came from selected")
            .clone();
        let source_tree = match attempted.source {
            SourceSide::First => first_tree,
            SourceSide::Second => second_tree,
        };

        let restored = base
            .entry(victim_id)
            .filter(|entry| {
                entry.is_live()
                    && entry.kind() == EntryKind::Directory
                    && entry
                        .parent()
                        .is_some_and(|parent| !cycle_ids.contains(&parent))
            })
            .cloned()
            .unwrap_or_else(|| attempted.entry.with_parent(base.root()));
        selected.insert(
            victim_id,
            SelectedEntry {
                entry: restored,
                origin: attempted.origin.clone(),
                source: attempted.source,
            },
        );
        preserve_conflict_subtree(
            &attempted.entry,
            &attempted.origin,
            source_tree,
            attempted.source,
            selected,
            occupied_ids,
        );
        conflicts.push(ConflictRecord {
            original_id: victim_id,
            kind: ConflictKind::DirectoryCycle,
            alternatives: vec![attempted.origin.alternative(attempted.entry)],
        });
    }
    repaired
}

fn find_directory_cycles(
    root: FileId,
    selected: &BTreeMap<FileId, SelectedEntry>,
) -> Vec<Vec<FileId>> {
    let directories = selected
        .iter()
        .filter_map(|(id, candidate)| {
            (candidate.entry.is_live() && candidate.entry.kind() == EntryKind::Directory)
                .then_some(*id)
        })
        .collect::<BTreeSet<_>>();
    let mut finished = BTreeSet::new();
    let mut cycles = Vec::new();
    for start in directories.iter().copied() {
        if finished.contains(&start) {
            continue;
        }
        let mut path = Vec::new();
        let mut positions = BTreeMap::new();
        let mut current = start;
        while current != root && directories.contains(&current) && !finished.contains(&current) {
            if let Some(position) = positions.insert(current, path.len()) {
                cycles.push(path[position..].to_vec());
                break;
            }
            path.push(current);
            let Some(parent) = selected
                .get(&current)
                .and_then(|entry| entry.entry.parent())
            else {
                break;
            };
            current = parent;
        }
        finished.extend(path);
    }
    cycles
}

fn resolve_path_collisions(
    base: &VaultTree,
    selected: &mut BTreeMap<FileId, SelectedEntry>,
    conflicts: &mut Vec<ConflictRecord>,
) {
    let mut destinations = BTreeMap::<(FileId, String), BTreeSet<FileId>>::new();
    for (id, candidate) in selected
        .iter()
        .filter(|(_, candidate)| candidate.entry.is_live())
    {
        destinations
            .entry(destination_of(&candidate.entry))
            .or_default()
            .insert(*id);
    }
    let collisions = destinations
        .iter()
        .filter_map(|(destination, candidates)| {
            (candidates.len() > 1).then_some(destination.clone())
        })
        .collect::<Vec<_>>();

    for destination in collisions {
        let mut colliding = destinations
            .get(&destination)
            .expect("collision destinations came from the index")
            .iter()
            .copied()
            .collect::<Vec<_>>();
        colliding.sort_by_key(|id| {
            let matches_base = base.entries.get(id.as_bytes()).is_some_and(|base_entry| {
                selected
                    .get(id)
                    .is_some_and(|candidate| &candidate.entry == base_entry)
            });
            (!matches_base, *id)
        });
        let winner_id = colliding[0];
        let winner = selected
            .get(&winner_id)
            .expect("collision winners came from selected")
            .clone();

        for loser_id in colliding.into_iter().skip(1) {
            let loser = selected
                .get(&loser_id)
                .expect("collision losers came from selected")
                .clone();
            let new_name = unique_conflict_name(&loser, &destinations);
            destinations
                .get_mut(&destination)
                .expect("the old destination remains indexed")
                .remove(&loser_id);
            destinations
                .entry((
                    loser.entry.parent().expect("live entries have parents"),
                    new_name.collision_key(),
                ))
                .or_default()
                .insert(loser_id);
            selected.insert(
                loser_id,
                SelectedEntry {
                    entry: loser.entry.with_name(new_name),
                    origin: loser.origin.clone(),
                    source: loser.source,
                },
            );
            conflicts.push(conflict_record(
                loser_id,
                ConflictKind::PathCollision,
                [
                    (&winner.entry, &winner.origin),
                    (&loser.entry, &loser.origin),
                ],
            ));
        }
    }
}

fn destination_of(entry: &Entry) -> (FileId, String) {
    (
        entry.parent().expect("live non-root entries have parents"),
        entry
            .name()
            .expect("live non-root entries have names")
            .collision_key(),
    )
}

fn unique_conflict_name(
    candidate: &SelectedEntry,
    destinations: &BTreeMap<(FileId, String), BTreeSet<FileId>>,
) -> EntryName {
    let parent = candidate.entry.parent().expect("live entries have parents");
    for counter in 0_u32.. {
        let qualifier = (counter != 0).then(|| counter.to_string());
        let proposed = conflict_name(
            candidate.entry.name().expect("live entries have names"),
            &candidate.origin,
            qualifier.as_deref(),
        );
        let key = proposed.collision_key();
        let occupied = destinations
            .get(&(parent, key))
            .is_some_and(|ids| ids.iter().any(|id| *id != candidate.entry.id()));
        if !occupied {
            return proposed;
        }
    }
    unreachable!("u32 conflict suffix space cannot be exhausted")
}

fn conflict_record<const N: usize>(
    original_id: FileId,
    kind: ConflictKind,
    alternatives: [(&Entry, &Origin); N],
) -> ConflictRecord {
    let mut alternatives = alternatives
        .into_iter()
        .map(|(entry, origin)| origin.alternative(entry.clone()))
        .collect::<Vec<_>>();
    alternatives.sort_by_key(|alternative| (alternative.snapshot_id, alternative.device_id));
    ConflictRecord {
        original_id,
        kind,
        alternatives,
    }
}

fn conflict_name(name: &EntryName, origin: &Origin, qualifier: Option<&str>) -> EntryName {
    let value = name.as_str();
    let extension_index = value.rfind('.').filter(|index| *index > 0);
    let (stem, extension) = extension_index.map_or((value, ""), |index| value.split_at(index));
    let qualifier = qualifier.map_or(String::new(), |value| format!("-{value}"));
    EntryName::parse(&format!(
        "{stem} (conflict {}-{}{}){extension}",
        origin.device_label.sanitized(),
        short_snapshot(origin.snapshot_id),
        qualifier,
    ))
    .expect("validated names plus a sanitized suffix stay portable")
}

fn short_snapshot(id: SnapshotId) -> String {
    id.as_bytes()[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn derived_conflict_id(original: FileId, snapshot: SnapshotId, counter: u32) -> FileId {
    let mut hasher = blake3::Hasher::new_derive_key("notecrypt core conflict file id v1");
    hasher.update(original.as_bytes());
    hasher.update(snapshot.as_bytes());
    hasher.update(&counter.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    FileId::from_bytes(bytes)
}

fn sort_conflicts(conflicts: &mut [ConflictRecord]) {
    conflicts.sort_by(|left, right| {
        left.original_id
            .cmp(&right.original_id)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| {
                left.alternatives
                    .iter()
                    .map(|alternative| (alternative.snapshot_id, alternative.device_id))
                    .cmp(
                        right
                            .alternatives
                            .iter()
                            .map(|alternative| (alternative.snapshot_id, alternative.device_id)),
                    )
            })
    });
}

#[cfg(test)]
mod tests {
    use super::{ConflictKind, reconcile};
    use crate::{
        DeviceId, DeviceLabel, DirectoryEntry, EntryKind, EntryName, FileEntry, FileId, RevisionId,
        Snapshot, SnapshotId, VaultTree,
    };

    fn file_id(byte: u8) -> FileId {
        FileId::from_bytes([byte; 16])
    }

    fn revision_id(byte: u8) -> RevisionId {
        RevisionId::from_bytes([byte; 32])
    }

    fn snapshot_id(byte: u8) -> SnapshotId {
        SnapshotId::from_bytes([byte; 32])
    }

    fn name(value: &str) -> EntryName {
        EntryName::parse(value).unwrap()
    }

    fn snapshot(byte: u8, label: &str, tree: VaultTree) -> Snapshot {
        Snapshot::new(
            snapshot_id(byte),
            DeviceId::from_bytes([byte; 16]),
            DeviceLabel::new(label),
            tree,
        )
    }

    fn one_file_tree(root: FileId, file: FileId, file_name: &str, revision: u8) -> VaultTree {
        VaultTree::empty(root)
            .create_file(
                root,
                FileEntry::new(file, name(file_name), revision_id(revision)),
            )
            .unwrap()
    }

    #[test]
    fn independent_file_changes_merge_without_conflicts() {
        let root = file_id(1);
        let base = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file_id(2), name("a"), revision_id(1)))
            .unwrap()
            .create_file(root, FileEntry::new(file_id(3), name("b"), revision_id(1)))
            .unwrap();
        let local = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file_id(2), name("a"), revision_id(2)))
            .unwrap()
            .create_file(root, FileEntry::new(file_id(3), name("b"), revision_id(1)))
            .unwrap();
        let remote = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file_id(2), name("a"), revision_id(1)))
            .unwrap()
            .create_file(root, FileEntry::new(file_id(3), name("b"), revision_id(3)))
            .unwrap();

        let result = reconcile(
            &base,
            &snapshot(10, "local", local.clone()),
            &snapshot(11, "remote", remote.clone()),
        )
        .unwrap();

        assert!(result.conflicts().is_empty());
        assert_eq!(
            result.merged_tree().entry(file_id(2)).unwrap().revision(),
            Some(revision_id(2)),
        );
        assert_eq!(
            result.merged_tree().entry(file_id(3)).unwrap().revision(),
            Some(revision_id(3)),
        );
        assert_eq!(
            result.snapshot_input().parents(),
            &[snapshot_id(10), snapshot_id(11)]
        );
    }

    #[test]
    fn same_file_changes_preserve_both_revisions_without_merging_bytes() {
        let root = file_id(1);
        let file = file_id(2);
        let base = one_file_tree(root, file, "note.md", 1);
        let local = one_file_tree(root, file, "note.md", 2);
        let remote = one_file_tree(root, file, "note.md", 3);

        let result = reconcile(
            &base,
            &snapshot(10, "Mark's Mac", local),
            &snapshot(11, "Work PC", remote),
        )
        .unwrap();

        assert_eq!(result.conflicts()[0].kind(), ConflictKind::SameFileChanged);
        let revisions = result.preserved_revisions();
        assert!(revisions.contains(&revision_id(2)));
        assert!(revisions.contains(&revision_id(3)));
        let names = result
            .merged_tree()
            .children(root)
            .unwrap()
            .iter()
            .map(|entry| entry.name().unwrap().as_str())
            .collect::<Vec<_>>();
        assert!(names.iter().any(|value| value.contains("work-pc-0b0b0b0b")));
    }

    #[test]
    fn rename_conflicts_preserve_both_names_as_explicit_alternatives() {
        let root = file_id(1);
        let file = file_id(2);
        let base = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file, name("draft"), revision_id(1)))
            .unwrap();
        let local = base.rename(file, name("local-name")).unwrap();
        let remote = base.rename(file, name("remote-name")).unwrap();

        let result = reconcile(
            &base,
            &snapshot(10, "local", local.clone()),
            &snapshot(11, "remote", remote.clone()),
        )
        .unwrap();

        assert_eq!(result.conflicts()[0].kind(), ConflictKind::Rename);
        let alternative_names = result.conflicts()[0]
            .alternatives()
            .iter()
            .map(|alternative| alternative.entry().name().unwrap().as_str())
            .collect::<Vec<_>>();
        assert!(alternative_names.contains(&"local-name"));
        assert!(alternative_names.contains(&"remote-name"));
    }

    #[test]
    fn delete_versus_modify_keeps_tombstone_and_modified_revision() {
        let root = file_id(1);
        let file = file_id(2);
        let base = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file, name("note"), revision_id(1)))
            .unwrap();
        let local = base.remove(file, snapshot_id(10)).unwrap();
        let remote = one_file_tree(root, file, "note", 3);

        let result = reconcile(
            &base,
            &snapshot(10, "local", local),
            &snapshot(11, "remote", remote),
        )
        .unwrap();

        assert_eq!(
            result.conflicts()[0].kind(),
            ConflictKind::DeleteVersusModify
        );
        assert_eq!(
            result.merged_tree().entry(file).unwrap().kind(),
            EntryKind::Tombstone
        );
        assert!(result.preserved_revisions().contains(&revision_id(3)));
    }

    #[test]
    fn independently_created_normalized_path_collisions_are_both_preserved() {
        let root = file_id(1);
        let base = VaultTree::empty(root);
        let local = base
            .create_file(
                root,
                FileEntry::new(file_id(2), name("Caf\u{e9}"), revision_id(2)),
            )
            .unwrap();
        let remote = base
            .create_file(
                root,
                FileEntry::new(file_id(3), name("CAFE\u{301}"), revision_id(3)),
            )
            .unwrap();

        let result = reconcile(
            &base,
            &snapshot(10, "local", local),
            &snapshot(11, "remote", remote),
        )
        .unwrap();

        assert!(
            result
                .conflicts()
                .iter()
                .any(|conflict| conflict.kind() == ConflictKind::PathCollision)
        );
        let children = result.merged_tree().children(root).unwrap();
        assert_eq!(children.len(), 2);
        assert_ne!(
            children[0].name().unwrap().collision_key(),
            children[1].name().unwrap().collision_key(),
        );
    }

    #[test]
    fn directory_and_file_additions_with_different_names_are_retained() {
        let root = file_id(1);
        let base = VaultTree::empty(root);
        let local = base
            .create_directory(root, DirectoryEntry::new(file_id(2), name("folder")))
            .unwrap();
        let remote = base
            .create_file(
                root,
                FileEntry::new(file_id(3), name("file"), revision_id(3)),
            )
            .unwrap();

        let result = reconcile(
            &base,
            &snapshot(10, "local", local),
            &snapshot(11, "remote", remote),
        )
        .unwrap();

        assert_eq!(result.merged_tree().children(root).unwrap().len(), 2);
    }

    #[test]
    fn directory_rename_conflicts_do_not_invent_empty_directory_copies() {
        let root = file_id(1);
        let directory = file_id(2);
        let child = file_id(3);
        let nested = file_id(4);
        let grandchild = file_id(5);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(directory, name("base")))
            .unwrap()
            .create_file(
                directory,
                FileEntry::new(child, name("child"), revision_id(7)),
            )
            .unwrap()
            .create_directory(directory, DirectoryEntry::new(nested, name("nested")))
            .unwrap()
            .create_file(
                nested,
                FileEntry::new(grandchild, name("grandchild"), revision_id(8)),
            )
            .unwrap();
        let local = base.rename(directory, name("local")).unwrap();
        let remote = base.rename(directory, name("remote")).unwrap();

        let result = reconcile(
            &base,
            &snapshot(10, "local", local.clone()),
            &snapshot(11, "remote", remote.clone()),
        )
        .unwrap();

        let reversed = reconcile(
            &base,
            &snapshot(11, "remote", remote),
            &snapshot(10, "local", local),
        )
        .unwrap();

        assert_eq!(result, reversed);
        let root_children = result.merged_tree().children(root).unwrap();
        assert_eq!(root_children.len(), 2);
        let copied_directory = root_children
            .iter()
            .find(|entry| entry.id() != directory)
            .unwrap();
        assert!(
            copied_directory
                .name()
                .unwrap()
                .as_str()
                .contains("conflict remote-0b0b0b0b")
        );
        let copied_children = result
            .merged_tree()
            .children(copied_directory.id())
            .unwrap();
        assert_eq!(copied_children.len(), 2);
        let copied_file = copied_children
            .iter()
            .find(|entry| entry.kind() == EntryKind::File)
            .unwrap();
        assert_ne!(copied_file.id(), child);
        assert_eq!(copied_file.revision(), Some(revision_id(7)));
        let copied_nested = copied_children
            .iter()
            .find(|entry| entry.kind() == EntryKind::Directory)
            .unwrap();
        assert_ne!(copied_nested.id(), nested);
        let copied_grandchildren = result.merged_tree().children(copied_nested.id()).unwrap();
        assert_eq!(copied_grandchildren.len(), 1);
        assert_ne!(copied_grandchildren[0].id(), grandchild);
        assert_eq!(copied_grandchildren[0].revision(), Some(revision_id(8)));
        assert!(result.preserved_revisions().contains(&revision_id(7)));
        assert!(result.preserved_revisions().contains(&revision_id(8)));
        assert_eq!(result.conflicts()[0].kind(), ConflictKind::Rename);
        assert_eq!(result.conflicts()[0].alternatives().len(), 2);
    }

    #[test]
    fn concurrent_structural_moves_cannot_create_a_directory_cycle() {
        let root = file_id(1);
        let a = file_id(2);
        let b = file_id(3);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(a, name("a")))
            .unwrap()
            .create_directory(root, DirectoryEntry::new(b, name("b")))
            .unwrap();
        let local = base.move_entry(a, b).unwrap();
        let remote = base.move_entry(b, a).unwrap();

        let result = reconcile(
            &base,
            &snapshot(10, "local", local),
            &snapshot(11, "remote", remote),
        )
        .unwrap();

        assert!(
            result
                .conflicts()
                .iter()
                .any(|conflict| conflict.kind() == ConflictKind::DirectoryCycle)
        );
        assert!(!has_parent_cycle(result.merged_tree(), &[a, b]));
    }

    #[test]
    fn cycle_repair_cannot_leave_a_live_subtree_under_a_tombstoned_parent() {
        let root = file_id(1);
        let parent = file_id(2);
        let b = file_id(3);
        let child = file_id(4);
        let a = file_id(9);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(parent, name("parent")))
            .unwrap()
            .create_directory(parent, DirectoryEntry::new(a, name("a")))
            .unwrap()
            .create_directory(root, DirectoryEntry::new(b, name("b")))
            .unwrap()
            .create_file(b, FileEntry::new(child, name("child"), revision_id(7)))
            .unwrap();
        let local = base
            .move_entry(a, b)
            .unwrap()
            .remove(parent, snapshot_id(10))
            .unwrap();
        let remote = base.move_entry(b, a).unwrap();
        let local_snapshot = snapshot(10, "local", local);
        let remote_snapshot = snapshot(11, "remote", remote);

        let result = reconcile(&base, &local_snapshot, &remote_snapshot).unwrap();
        let reversed = reconcile(&base, &remote_snapshot, &local_snapshot).unwrap();

        assert_eq!(result, reversed);
        assert!(!has_parent_cycle(result.merged_tree(), &[a, b]));
        assert_all_live_entries_reach_root(result.merged_tree());
        assert!(result.preserved_revisions().contains(&revision_id(7)));
        assert!(
            result
                .conflicts()
                .iter()
                .any(|conflict| conflict.kind() == ConflictKind::DirectoryCycle)
        );
        assert!(
            result
                .conflicts()
                .iter()
                .any(|conflict| conflict.kind() == ConflictKind::ParentDeleted)
        );
    }

    #[test]
    fn feeder_cycle_repair_resolves_successive_cycles_to_a_fixpoint() {
        let root = file_id(1);
        let parent = file_id(2);
        let b = file_id(3);
        let child = file_id(4);
        let a = file_id(9);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(parent, name("parent")))
            .unwrap()
            .create_directory(parent, DirectoryEntry::new(a, name("a")))
            .unwrap()
            .create_directory(root, DirectoryEntry::new(b, name("b")))
            .unwrap()
            .create_file(b, FileEntry::new(child, name("child"), revision_id(7)))
            .unwrap();
        let local = base
            .move_entry(a, b)
            .unwrap()
            .move_entry(parent, a)
            .unwrap();
        let remote = base.move_entry(b, a).unwrap();
        let local_snapshot = snapshot(10, "local", local);
        let remote_snapshot = snapshot(11, "remote", remote);

        let result = reconcile(&base, &local_snapshot, &remote_snapshot).unwrap();
        let reversed = reconcile(&base, &remote_snapshot, &local_snapshot).unwrap();

        assert_eq!(result, reversed);
        assert!(!has_parent_cycle(result.merged_tree(), &[parent, a, b]));
        assert_all_live_entries_reach_root(result.merged_tree());
        assert!(result.preserved_revisions().contains(&revision_id(7)));
        assert_eq!(
            result
                .conflicts()
                .iter()
                .filter(|conflict| conflict.kind() == ConflictKind::DirectoryCycle)
                .count(),
            2
        );
    }

    fn has_parent_cycle(tree: &VaultTree, ids: &[FileId]) -> bool {
        ids.iter().copied().any(|start| {
            let mut current = Some(start);
            let mut seen = std::collections::BTreeSet::new();
            while let Some(id) = current {
                if !seen.insert(id) {
                    return true;
                }
                current = tree.entry(id).and_then(crate::Entry::parent);
            }
            false
        })
    }

    fn assert_all_live_entries_reach_root(tree: &VaultTree) {
        for entry in tree.entries.values() {
            if !entry.is_live() || entry.id() == tree.root() {
                continue;
            }
            let mut current = entry.id();
            let mut visited = std::collections::BTreeSet::new();
            loop {
                assert!(visited.insert(current));
                let candidate = tree.entry(current).unwrap();
                let parent = candidate.parent().unwrap();
                if parent == tree.root() {
                    break;
                }
                let parent_entry = tree.entry(parent).unwrap();
                assert!(parent_entry.is_live());
                assert_eq!(parent_entry.kind(), EntryKind::Directory);
                current = parent;
            }
        }
    }
}
