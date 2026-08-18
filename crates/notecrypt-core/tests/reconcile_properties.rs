use std::collections::BTreeSet;

use notecrypt_core::{
    ConflictKind, DeviceId, DeviceLabel, DirectoryEntry, EntryName, FileEntry, FileId, RevisionId,
    Snapshot, SnapshotId, VaultTree, reconcile,
};
use proptest::prelude::*;

fn file_id(byte: u8) -> FileId {
    FileId::from_bytes([byte; 16])
}

fn revision_id(byte: u8) -> RevisionId {
    RevisionId::from_bytes([byte; 32])
}

fn snapshot(byte: u8, label: &str, tree: VaultTree) -> Snapshot {
    Snapshot::new(
        SnapshotId::from_bytes([byte; 32]),
        DeviceId::from_bytes([byte; 16]),
        DeviceLabel::new(label),
        tree,
    )
}

fn entry_name(value: &str) -> EntryName {
    EntryName::parse(value).unwrap()
}

fn one_file_tree(root: FileId, file: FileId, revision: RevisionId) -> VaultTree {
    VaultTree::empty(root)
        .create_file(root, FileEntry::new(file, entry_name("note"), revision))
        .unwrap()
}

fn has_parent_cycle(tree: &VaultTree, ids: &[FileId]) -> bool {
    ids.iter().copied().any(|start| {
        let mut current = Some(start);
        let mut seen = BTreeSet::new();
        while let Some(id) = current {
            if !seen.insert(id) {
                return true;
            }
            current = tree.entry(id).and_then(notecrypt_core::Entry::parent);
        }
        false
    })
}

fn reaches_root(tree: &VaultTree, start: FileId) -> bool {
    let mut current = start;
    let mut seen = BTreeSet::new();
    while seen.insert(current) {
        let Some(entry) = tree.entry(current) else {
            return false;
        };
        let Some(parent) = entry.parent() else {
            return current == tree.root();
        };
        current = parent;
    }
    false
}

proptest! {
    #[test]
    fn reconciliation_is_deterministic_and_commutative(
        local_revision in 2_u8..=120,
        remote_revision in 121_u8..=250,
    ) {
        let root = file_id(1);
        let file = file_id(2);
        let base = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file, entry_name("note"), revision_id(1)))
            .unwrap();
        let local = snapshot(
            10,
            "local laptop",
            one_file_tree(root, file, revision_id(local_revision)),
        );
        let remote = snapshot(
            11,
            "remote pc",
            one_file_tree(root, file, revision_id(remote_revision)),
        );

        let first = reconcile(&base, &local, &remote).unwrap();
        let repeated = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();

        prop_assert_eq!(&first, &repeated);
        prop_assert_eq!(&first, &reversed);
        let preserved = first.preserved_revisions().into_iter().collect::<BTreeSet<_>>();
        prop_assert!(preserved.contains(&revision_id(local_revision)));
        prop_assert!(preserved.contains(&revision_id(remote_revision)));
    }

    #[test]
    fn independent_changes_do_not_drop_revisions(
        left_revision in 2_u8..=120,
        right_revision in 121_u8..=250,
    ) {
        let root = file_id(1);
        let left = file_id(2);
        let right = file_id(3);
        let base = VaultTree::empty(root)
            .create_file(root, FileEntry::new(left, entry_name("left"), revision_id(1))).unwrap()
            .create_file(root, FileEntry::new(right, entry_name("right"), revision_id(1))).unwrap();
        let local_tree = VaultTree::empty(root)
            .create_file(root, FileEntry::new(left, entry_name("left"), revision_id(left_revision))).unwrap()
            .create_file(root, FileEntry::new(right, entry_name("right"), revision_id(1))).unwrap();
        let remote_tree = VaultTree::empty(root)
            .create_file(root, FileEntry::new(left, entry_name("left"), revision_id(1))).unwrap()
            .create_file(root, FileEntry::new(right, entry_name("right"), revision_id(right_revision))).unwrap();
        let local = snapshot(10, "local", local_tree);
        let remote = snapshot(11, "remote", remote_tree);

        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();
        let preserved = result.preserved_revisions();

        prop_assert_eq!(&result, &reversed);
        prop_assert!(preserved.contains(&revision_id(left_revision)));
        prop_assert!(preserved.contains(&revision_id(right_revision)));
    }

    #[test]
    fn rename_conflicts_preserve_both_names(seed in "[a-z]{1,12}") {
        let root = file_id(1);
        let file = file_id(2);
        let base = one_file_tree(root, file, revision_id(1));
        let local_name = format!("local-{seed}");
        let remote_name = format!("remote-{seed}");
        let local = snapshot(10, "local", base.rename(file, entry_name(&local_name)).unwrap());
        let remote = snapshot(11, "remote", base.rename(file, entry_name(&remote_name)).unwrap());

        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();
        let names = result.conflicts()[0]
            .alternatives()
            .iter()
            .map(|alternative| alternative.entry().name().unwrap().as_str())
            .collect::<BTreeSet<_>>();

        prop_assert_eq!(&result, &reversed);
        prop_assert!(names.contains(local_name.as_str()));
        prop_assert!(names.contains(remote_name.as_str()));
    }

    #[test]
    fn delete_versus_modify_preserves_the_new_revision(remote_revision in 2_u8..=250) {
        let root = file_id(1);
        let file = file_id(2);
        let base = one_file_tree(root, file, revision_id(1));
        let local = snapshot(
            10,
            "local",
            base.remove(file, SnapshotId::from_bytes([10; 32])).unwrap(),
        );
        let remote = snapshot(
            11,
            "remote",
            one_file_tree(root, file, revision_id(remote_revision)),
        );

        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();

        prop_assert_eq!(&result, &reversed);
        prop_assert!(result.preserved_revisions().contains(&revision_id(remote_revision)));
    }

    #[test]
    fn normalized_path_collisions_preserve_both_files(seed in "[a-z]{1,8}") {
        let root = file_id(1);
        let base = VaultTree::empty(root);
        let local_name = format!("caf\u{e9}-{seed}");
        let remote_name = format!("CAFE\u{301}-{}", seed.to_uppercase());
        let local_tree = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file_id(2), entry_name(&local_name), revision_id(2)))
            .unwrap();
        let remote_tree = VaultTree::empty(root)
            .create_file(root, FileEntry::new(file_id(3), entry_name(&remote_name), revision_id(3)))
            .unwrap();

        let local = snapshot(10, "local", local_tree);
        let remote = snapshot(11, "remote", remote_tree);
        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();
        let children = result.merged_tree().children(root).unwrap();

        prop_assert_eq!(&result, &reversed);
        prop_assert_eq!(children.len(), 2);
        prop_assert_ne!(
            children[0].name().unwrap().collision_key(),
            children[1].name().unwrap().collision_key(),
        );
        let revisions = result.preserved_revisions();
        prop_assert!(revisions.contains(&revision_id(2)));
        prop_assert!(revisions.contains(&revision_id(3)));
    }

    #[test]
    fn compatibility_casefold_collisions_are_commutative(seed in "[a-z]{1,8}") {
        let root = file_id(1);
        let base = VaultTree::empty(root);
        let local = snapshot(
            10,
            "local",
            base.create_file(
                root,
                FileEntry::new(
                    file_id(2),
                    entry_name(&format!("\u{1d400}-{seed}")),
                    revision_id(2),
                ),
            ).unwrap(),
        );
        let remote = snapshot(
            11,
            "remote",
            base.create_file(
                root,
                FileEntry::new(
                    file_id(3),
                    entry_name(&format!("a-{seed}")),
                    revision_id(3),
                ),
            ).unwrap(),
        );

        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();
        let children = result.merged_tree().children(root).unwrap();

        prop_assert_eq!(&result, &reversed);
        prop_assert_eq!(children.len(), 2);
        let has_collision = result
            .conflicts()
            .iter()
            .any(|conflict| conflict.kind() == ConflictKind::PathCollision);
        prop_assert!(has_collision);
        prop_assert!(result.preserved_revisions().contains(&revision_id(2)));
        prop_assert!(result.preserved_revisions().contains(&revision_id(3)));
    }

    #[test]
    fn independent_structural_moves_are_commutative(seed in "[a-z]{1,8}") {
        let root = file_id(1);
        let left_directory = file_id(2);
        let right_directory = file_id(3);
        let left_file = file_id(4);
        let right_file = file_id(5);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(left_directory, entry_name("left"))).unwrap()
            .create_directory(root, DirectoryEntry::new(right_directory, entry_name("right"))).unwrap()
            .create_file(root, FileEntry::new(left_file, entry_name(&format!("left-{seed}")), revision_id(4))).unwrap()
            .create_file(root, FileEntry::new(right_file, entry_name(&format!("right-{seed}")), revision_id(5))).unwrap();
        let local = snapshot(10, "local", base.move_entry(left_file, left_directory).unwrap());
        let remote = snapshot(11, "remote", base.move_entry(right_file, right_directory).unwrap());

        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();

        prop_assert_eq!(&result, &reversed);
        prop_assert_eq!(result.merged_tree().entry(left_file).unwrap().parent(), Some(left_directory));
        prop_assert_eq!(result.merged_tree().entry(right_file).unwrap().parent(), Some(right_directory));
        prop_assert!(result.preserved_revisions().contains(&revision_id(4)));
        prop_assert!(result.preserved_revisions().contains(&revision_id(5)));
    }

    #[test]
    fn opposing_directory_moves_resolve_cycles_commutatively(seed in "[a-z]{1,8}") {
        let root = file_id(1);
        let a = file_id(2);
        let b = file_id(3);
        let child = file_id(4);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(a, entry_name(&format!("a-{seed}")))).unwrap()
            .create_directory(root, DirectoryEntry::new(b, entry_name(&format!("b-{seed}")))).unwrap()
            .create_file(a, FileEntry::new(child, entry_name("child"), revision_id(9))).unwrap();
        let local = snapshot(10, "local", base.move_entry(a, b).unwrap());
        let remote = snapshot(11, "remote", base.move_entry(b, a).unwrap());

        let result = reconcile(&base, &local, &remote).unwrap();
        let repeated = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();

        prop_assert_eq!(&result, &repeated);
        prop_assert_eq!(&result, &reversed);
        prop_assert!(!has_parent_cycle(result.merged_tree(), &[a, b]));
        prop_assert!(result.preserved_revisions().contains(&revision_id(9)));
        let has_cycle_conflict = result
            .conflicts()
            .iter()
            .any(|conflict| conflict.kind() == ConflictKind::DirectoryCycle);
        prop_assert!(has_cycle_conflict);
    }

    #[test]
    fn feeder_cycles_reach_a_commutative_fixpoint(seed in "[a-z]{1,8}") {
        let root = file_id(1);
        let parent = file_id(2);
        let b = file_id(3);
        let child = file_id(4);
        let a = file_id(9);
        let base = VaultTree::empty(root)
            .create_directory(root, DirectoryEntry::new(parent, entry_name(&format!("p-{seed}")))).unwrap()
            .create_directory(parent, DirectoryEntry::new(a, entry_name(&format!("a-{seed}")))).unwrap()
            .create_directory(root, DirectoryEntry::new(b, entry_name(&format!("b-{seed}")))).unwrap()
            .create_file(b, FileEntry::new(child, entry_name("child"), revision_id(9))).unwrap();
        let local = snapshot(
            10,
            "local",
            base.move_entry(a, b).unwrap().move_entry(parent, a).unwrap(),
        );
        let remote = snapshot(11, "remote", base.move_entry(b, a).unwrap());

        let result = reconcile(&base, &local, &remote).unwrap();
        let reversed = reconcile(&base, &remote, &local).unwrap();

        prop_assert_eq!(&result, &reversed);
        prop_assert!(!has_parent_cycle(result.merged_tree(), &[parent, a, b]));
        prop_assert!(reaches_root(result.merged_tree(), parent));
        prop_assert!(reaches_root(result.merged_tree(), a));
        prop_assert!(reaches_root(result.merged_tree(), b));
        prop_assert!(reaches_root(result.merged_tree(), child));
        prop_assert!(result.preserved_revisions().contains(&revision_id(9)));
        let cycle_conflicts = result
            .conflicts()
            .iter()
            .filter(|conflict| conflict.kind() == ConflictKind::DirectoryCycle)
            .count();
        prop_assert_eq!(cycle_conflicts, 2);
    }
}
