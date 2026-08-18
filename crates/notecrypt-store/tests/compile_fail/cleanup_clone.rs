use notecrypt_store::{
    ActiveWorkspace, AuthenticatedCleanupRecord, RegisteredWorkspace, WorkspaceAbsenceProof,
};

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<RegisteredWorkspace>();
    assert_clone::<ActiveWorkspace>();
    assert_clone::<AuthenticatedCleanupRecord>();
    assert_clone::<WorkspaceAbsenceProof>();
}
