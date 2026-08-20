use notecrypt_store::{
    ActiveWorkspace, AuthenticatedCleanupRecord, RegisteredWorkspace, WorkspaceAbsenceProof,
};

fn assert_serialize<T: serde::Serialize>() {}

fn main() {
    assert_serialize::<RegisteredWorkspace>();
    assert_serialize::<ActiveWorkspace>();
    assert_serialize::<AuthenticatedCleanupRecord>();
    assert_serialize::<WorkspaceAbsenceProof>();
}
