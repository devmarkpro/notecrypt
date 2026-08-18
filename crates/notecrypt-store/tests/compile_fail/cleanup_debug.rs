use notecrypt_store::{
    ActiveWorkspace, AuthenticatedCleanupRecord, RegisteredWorkspace, WorkspaceAbsenceProof,
};

fn assert_debug<T: std::fmt::Debug>() {}

fn main() {
    assert_debug::<RegisteredWorkspace>();
    assert_debug::<ActiveWorkspace>();
    assert_debug::<AuthenticatedCleanupRecord>();
    assert_debug::<WorkspaceAbsenceProof>();
}
