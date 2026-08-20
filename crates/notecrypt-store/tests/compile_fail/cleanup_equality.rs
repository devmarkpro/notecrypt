use notecrypt_store::{
    ActiveWorkspace, AuthenticatedCleanupRecord, RegisteredWorkspace, WorkspaceAbsenceProof,
};

fn assert_partial_eq<T: PartialEq>() {}
fn assert_eq<T: Eq>() {}

fn main() {
    assert_partial_eq::<RegisteredWorkspace>();
    assert_partial_eq::<ActiveWorkspace>();
    assert_partial_eq::<AuthenticatedCleanupRecord>();
    assert_partial_eq::<WorkspaceAbsenceProof>();
    assert_eq::<RegisteredWorkspace>();
    assert_eq::<ActiveWorkspace>();
    assert_eq::<AuthenticatedCleanupRecord>();
    assert_eq::<WorkspaceAbsenceProof>();
}
