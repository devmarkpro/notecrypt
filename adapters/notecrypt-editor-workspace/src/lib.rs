//! Secure plaintext workspace and editor supervision for Notecrypt.

mod editor;
mod error;
mod permissions;
mod workspace;

pub use editor::{ProcessEditorSupervisor, resolve_editor};

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use editor::{
    EditorLaunchFailureDiagnostic, EditorLaunchFailureStage, classify_editor_for_test,
};
#[cfg(all(feature = "test-support", unix))]
#[doc(hidden)]
pub use notecrypt_platform_fs::{
    ProcessWaitFailureDiagnostic, ProcessWaitFailureReason, ProcessWaitFailureStage,
};
pub use workspace::SecureWorkspaceProvider;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod workspace_test_support {
    use std::sync::{Arc, Barrier};

    use notecrypt_service::{HostPortError, PublishedGeneration, WorkspaceLease};

    use crate::SecureWorkspaceProvider;

    pub use crate::workspace::{
        IndexExclusionFailureDiagnostic, IndexExclusionFailureStage, MaterializationIoFault,
    };

    pub fn take_index_exclusion_failure_diagnostic() -> Option<IndexExclusionFailureDiagnostic> {
        crate::workspace::take_index_exclusion_failure_diagnostic()
    }

    pub fn install_create_barrier(workspace: String, entered: Arc<Barrier>, release: Arc<Barrier>) {
        crate::workspace::install_create_barrier(workspace, entered, release);
    }

    pub fn seed_workspace_budget(
        provider: &SecureWorkspaceProvider,
        lease: &WorkspaceLease,
        logical_paths: usize,
        physical_entries: usize,
    ) {
        provider.seed_workspace_budget(lease, logical_paths, physical_entries);
    }

    pub fn inject_materialization_io_fault(fault: MaterializationIoFault) {
        crate::workspace::inject_materialization_io_fault(fault);
    }

    pub fn inject_materialization_entropy_failure() {
        crate::workspace::inject_materialization_entropy_failure();
    }

    pub fn toggle_awaiting_arm_suppression(
        provider: &SecureWorkspaceProvider,
        published: &PublishedGeneration,
    ) -> Result<(), HostPortError> {
        provider.toggle_awaiting_arm_suppression(published)
    }
}
