use std::sync::Arc;

use crate::operation::OperationState;
use crate::service::ServiceInner;
use crate::{OperationContext, OperationResult, ServiceError, VaultStatus};

pub(crate) fn list_entries(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Reading)?;
    let mut lease = service.acquire_local_lease(state)?;
    let result = (|| {
        let view = lease
            .authenticated_view(crate::MAX_RESULT_ENTRIES)
            .map_err(crate::session::map_repository_error)?;
        let summaries = view.into_entry_summaries()?;
        context.safe_boundary()?;
        Ok(OperationResult::Entries(summaries))
    })();
    finish_lease(lease, result)
}

pub(crate) fn status(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Reading)?;
    let generation = state.session_generation.ok_or(ServiceError::Locked)?;
    let vault_id = service
        .session
        .as_ref()
        .and_then(|session| session.current_vault_id())
        .ok_or(ServiceError::Locked)?;
    let mut lease = service.acquire_local_lease(state)?;
    let result = (|| {
        let view = lease
            .authenticated_status(crate::MAX_RESULT_ENTRIES)
            .map_err(crate::session::map_repository_error)?;
        context.safe_boundary()?;
        Ok(OperationResult::Status(VaultStatus::new(
            vault_id,
            generation,
            *view.root_entry_id().as_bytes(),
            *view.snapshot_id().as_bytes(),
            view.entry_count(),
        )))
    })();
    finish_lease(lease, result)
}

fn finish_lease(
    lease: Box<dyn crate::LocalVaultLease>,
    result: Result<OperationResult, ServiceError>,
) -> Result<OperationResult, ServiceError> {
    let finished = lease.finish().map_err(crate::session::map_repository_error);
    match (result, finished) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(result), Ok(())) => Ok(result),
    }
}
