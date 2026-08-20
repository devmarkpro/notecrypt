use notecrypt_store::StoreError;
use tempfile::TempDir;

#[cfg(feature = "test-support")]
use notecrypt_store::transaction_test_support::{
    RecoveredSnapshot, create_empty_layout, exercise_fault,
};
#[cfg(feature = "test-support")]
use notecrypt_store::{BoundaryMoment, TransactionBoundary};

#[test]
fn layout_uses_only_opaque_components_and_vault_scoped_local_state() {
    let root = TempDir::new().expect("repository temp directory");
    let local = TempDir::new().expect("local-state temp directory");
    let root_path = root.path().canonicalize().unwrap();
    let local_path = local.path().canonicalize().unwrap();
    create_empty_layout(&root_path, &local_path, [0x42; 16]).expect("create store");

    let repository_names = names(&root_path);
    assert_eq!(repository_names, [".notecrypt-txn", "objects"]);
    let vault_local = local_path.join("42424242424242424242424242424242");
    assert_eq!(
        names(&vault_local),
        [
            "cleanup-registry",
            "cleanup-staging",
            "device-slots",
            "journal",
            "replication-quarantine",
            "trusted",
            "trusted-remote",
        ]
    );
}

#[cfg(unix)]
#[test]
fn repository_creation_rejects_a_symlinked_objects_directory() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().expect("repository temp directory");
    let local = TempDir::new().expect("local-state temp directory");
    let outside = TempDir::new().expect("outside temp directory");
    symlink(outside.path(), root.path().join("objects")).expect("create malicious link");

    let result = create_empty_layout(
        &root.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        [0x11; 16],
    );

    let error = result.expect_err("symlink must be rejected");
    assert!(
        matches!(error, StoreError::FilesystemObjectRejected),
        "unexpected error: {error:?}"
    );
}

#[test]
fn repository_and_local_state_roots_cannot_alias_or_nest() {
    let root = TempDir::new().expect("root temp directory");
    let root_path = root.path().canonicalize().unwrap();
    let nested = root_path.join("nested");
    std::fs::create_dir(&nested).unwrap();
    let before = names(&root_path);

    assert!(matches!(
        create_empty_layout(&root_path, &root_path, [0x22; 16]),
        Err(StoreError::FilesystemObjectRejected)
    ));
    assert!(matches!(
        create_empty_layout(&root_path, &nested, [0x22; 16]),
        Err(StoreError::FilesystemObjectRejected)
    ));
    assert!(matches!(
        create_empty_layout(&nested, &root_path, [0x22; 16]),
        Err(StoreError::FilesystemObjectRejected)
    ));
    assert_eq!(
        names(&root_path),
        before,
        "rejection must not mutate either root"
    );
}

#[cfg(unix)]
#[test]
fn repository_and_local_state_roots_reject_symlink_aliases() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().expect("root temp directory");
    let parent = TempDir::new().expect("parent temp directory");
    let alias = parent.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    let root_before = names(root.path());
    let parent_before = names(parent.path());

    let result = create_empty_layout(&root.path().canonicalize().unwrap(), &alias, [0x22; 16]);
    let error = result.expect_err("symlink alias must fail");
    assert!(
        matches!(error, StoreError::FilesystemObjectRejected),
        "unexpected error: {error:?}"
    );
    assert_eq!(names(root.path()), root_before);
    assert_eq!(names(parent.path()), parent_before);
}

fn names(path: &std::path::Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[derive(Clone, Copy)]
enum Boundary {
    AuthenticateCurrent,
    StageObjects,
    FlushStaged,
    AuthenticateStaged,
    PublishObjects,
    WriteJournal,
    ReplaceHead,
    FlushHeadDirectory,
    UpdateTrustedState,
    CompleteJournal,
}

const BOUNDARIES: [Boundary; 10] = [
    Boundary::AuthenticateCurrent,
    Boundary::StageObjects,
    Boundary::FlushStaged,
    Boundary::AuthenticateStaged,
    Boundary::PublishObjects,
    Boundary::WriteJournal,
    Boundary::ReplaceHead,
    Boundary::FlushHeadDirectory,
    Boundary::UpdateTrustedState,
    Boundary::CompleteJournal,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Snapshot {
    Old,
    New,
}

#[derive(Clone, Copy)]
struct Image {
    objects: bool,
    journal: bool,
    head: Snapshot,
    trusted: Snapshot,
    complete: bool,
}

struct CrashState {
    durable: Image,
    volatile: Image,
}

impl CrashState {
    fn initial() -> Self {
        let image = Image {
            objects: false,
            journal: false,
            head: Snapshot::Old,
            trusted: Snapshot::Old,
            complete: false,
        };
        Self {
            durable: image,
            volatile: image,
        }
    }

    fn apply(&mut self, boundary: Boundary) {
        match boundary {
            Boundary::AuthenticateCurrent | Boundary::AuthenticateStaged => {}
            Boundary::StageObjects => self.volatile.objects = true,
            Boundary::FlushStaged => self.durable.objects = self.volatile.objects,
            Boundary::PublishObjects => self.durable.objects = true,
            Boundary::WriteJournal => {
                assert!(self.durable.objects);
                self.volatile.journal = true;
                self.durable.journal = true;
            }
            Boundary::ReplaceHead => self.volatile.head = Snapshot::New,
            Boundary::FlushHeadDirectory => self.durable.head = self.volatile.head,
            Boundary::UpdateTrustedState => {
                self.volatile.trusted = Snapshot::New;
                self.durable.trusted = Snapshot::New;
            }
            Boundary::CompleteJournal => {
                self.volatile.complete = true;
                self.durable.complete = true;
            }
        }
    }

    fn crash_and_recover(&mut self) -> Snapshot {
        self.volatile = self.durable;
        if self.durable.journal && self.durable.objects {
            self.durable.head = Snapshot::New;
            self.durable.trusted = Snapshot::New;
            self.durable.complete = true;
        } else {
            self.durable.head = Snapshot::Old;
            self.durable.trusted = Snapshot::Old;
        }
        self.volatile = self.durable;
        assert_eq!(self.durable.head, self.durable.trusted);
        self.durable.head
    }
}

#[test]
fn every_transaction_boundary_recovers_idempotently_to_one_complete_snapshot() {
    for crash_after in 0..=BOUNDARIES.len() {
        let mut state = CrashState::initial();
        for boundary in BOUNDARIES.iter().take(crash_after) {
            state.apply(*boundary);
        }
        let first = state.crash_and_recover();
        let second = state.crash_and_recover();
        assert!(matches!(first, Snapshot::Old | Snapshot::New));
        assert_eq!(first, second);
    }
}

#[cfg(feature = "test-support")]
#[test]
fn production_commit_and_recovery_are_old_or_new_at_every_fault_boundary() {
    let boundaries = [
        TransactionBoundary::AuthenticateCurrent,
        TransactionBoundary::StageObjects,
        TransactionBoundary::FlushStaged,
        TransactionBoundary::AuthenticateStaged,
        TransactionBoundary::PublishObjects,
        TransactionBoundary::WriteJournal,
        TransactionBoundary::ReplaceHead,
        TransactionBoundary::FlushHeadDirectory,
        TransactionBoundary::UpdateTrustedState,
        TransactionBoundary::CompleteJournal,
    ];
    for boundary in boundaries {
        for moment in [BoundaryMoment::Before, BoundaryMoment::After] {
            let repository = TempDir::new().unwrap();
            let local = TempDir::new().unwrap();
            let result = exercise_fault(
                &repository.path().canonicalize().unwrap(),
                &local.path().canonicalize().unwrap(),
                boundary,
                moment,
            )
            .unwrap_or_else(|error| panic!("{boundary:?} {moment:?}: {error:?}"));
            assert!(matches!(
                result.first,
                RecoveredSnapshot::Old | RecoveredSnapshot::New
            ));
            assert_eq!(result.first, result.second, "{boundary:?} {moment:?}");
            assert_eq!(result.transient_entries, 0, "{boundary:?} {moment:?}");
            let requires_authentication = matches!(
                (boundary, moment),
                (
                    TransactionBoundary::AuthenticateStaged,
                    BoundaryMoment::After
                ) | (TransactionBoundary::PublishObjects, _)
                    | (TransactionBoundary::WriteJournal, _)
                    | (TransactionBoundary::ReplaceHead, _)
                    | (TransactionBoundary::FlushHeadDirectory, _)
                    | (TransactionBoundary::UpdateTrustedState, _)
                    | (TransactionBoundary::CompleteJournal, _)
            );
            if requires_authentication {
                assert!(
                    result.authenticated_objects > 0,
                    "{boundary:?} {moment:?} did not authenticate a real object"
                );
            }
        }
    }
}
