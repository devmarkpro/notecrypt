use notecrypt_store::{
    ActiveWorkspace, AuthenticatedCleanupRecord, RegisteredWorkspace, WorkspaceAbsenceProof,
};

fn assert_default<T: Default>() {}

fn main() {
    assert_default::<RegisteredWorkspace>();
    assert_default::<ActiveWorkspace>();
    assert_default::<AuthenticatedCleanupRecord>();
    assert_default::<WorkspaceAbsenceProof>();
}
