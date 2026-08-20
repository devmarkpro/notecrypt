use std::io::{Read, Write};
use std::sync::Arc;

use crate::operation::OperationState;
use crate::service::ServiceInner;
use crate::{OperationContext, OperationResult, ServiceError, VaultStatus};

struct OperationPublicationGuard<'a> {
    context: &'a OperationContext,
    external: Option<&'a mut dyn crate::VaultPublicationGuard>,
}

struct ExternalPublicationAuthorization<'a> {
    service: &'a Arc<ServiceInner>,
    state: &'a Arc<OperationState>,
}

impl crate::ExternalPublicationAuthorization for ExternalPublicationAuthorization<'_> {
    fn authorize_and_publish(
        &mut self,
        publication: &mut dyn FnMut() -> Result<(), crate::HostPortError>,
    ) -> Result<(), crate::HostPortError> {
        self.service
            .authorize_external_publication(self.state, publication)
    }
}

impl crate::VaultPublicationGuard for OperationPublicationGuard<'_> {
    fn validate(&mut self) -> Result<(), crate::RepositoryPortError> {
        if let Some(external) = self.external.as_deref_mut() {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| external.validate()))
                .map_err(|_| crate::RepositoryPortError::PlatformFailure)??;
        }
        self.context.safe_boundary().map_err(map_publication_error)
    }
}

fn map_publication_error(error: ServiceError) -> crate::RepositoryPortError {
    match error {
        ServiceError::Cancelled => crate::RepositoryPortError::Cancelled,
        ServiceError::Locked | ServiceError::StaleCapability => crate::RepositoryPortError::Locked,
        ServiceError::Busy => crate::RepositoryPortError::Busy,
        ServiceError::CapacityExceeded => crate::RepositoryPortError::CapacityExceeded,
        ServiceError::AllocationFailed => crate::RepositoryPortError::AllocationFailed,
        ServiceError::TimedOut => crate::RepositoryPortError::TimedOut,
        _ => crate::RepositoryPortError::PlatformFailure,
    }
}

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

pub(crate) fn create_directory(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::CreateDirectory,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Preparing)?;
    let (snapshot, parent, name) = command.into_parts()?;
    let mut lease = service.acquire_local_lease(state)?;
    let mutation = crate::LocalMutation::try_create_directory(
        notecrypt_core::SnapshotId::from_bytes(*snapshot.as_bytes()),
        crate::LocalEntryId::from_bytes(*parent.as_bytes()),
        name.as_str(),
    )
    .map_err(crate::session::map_repository_error)?;
    context.emit_progress(crate::Progress::items(0, Some(1))?)?;
    context.phase_changed(crate::OperationPhase::Publishing)?;
    let mut guard = OperationPublicationGuard {
        context,
        external: None,
    };
    let result = lease
        .apply(mutation, &mut guard)
        .map_err(crate::session::map_repository_error);
    let result = finish_repository_lease(lease, result)?;
    let committed = crate::SnapshotVersion::new(*result.snapshot_id().as_bytes());
    context.revision_durable_committed(durability(committed))?;
    Ok(OperationResult::EntryChanged(crate::MutationSummary::new(
        crate::EntryId::new(*result.entry_id().as_bytes()),
        parent,
        committed,
        None,
        name,
        crate::EntryKind::Directory,
    )))
}

pub(crate) fn create_file(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::CreateFile,
) -> Result<OperationResult, ServiceError> {
    let (snapshot, parent, name) = command.into_parts()?;
    let mut empty = std::io::Cursor::new([]);
    commit_import(
        service, state, context, snapshot, parent, name, &mut empty, None,
    )
}

pub(crate) fn import_file(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::ImportFile,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Preparing)?;
    let (snapshot, parent, name, selection) = command.into_parts()?;
    context.phase_changed(crate::OperationPhase::Reading)?;
    let session = service.session.as_ref().ok_or(ServiceError::Locked)?;
    let opened = session.open_import(selection)?;
    let (mut reader, mut external_guard) = opened.into_parts();
    commit_import(
        service,
        state,
        context,
        snapshot,
        parent,
        name,
        reader.as_mut(),
        Some(external_guard.as_mut()),
    )
}

pub(crate) fn export_file(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::ExportFile,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Preparing)?;
    let (snapshot, entry, revision, selection) = command.into_parts()?;
    let mut lease = service.acquire_local_lease(state)?;
    if lease
        .current_snapshot_id()
        .map_err(crate::session::map_repository_error)?
        .as_bytes()
        != snapshot.as_bytes()
    {
        return finish_repository_lease(lease, Err(ServiceError::StaleCapability));
    }
    if let Err(error) = lease
        .validate_export_binding(
            crate::LocalEntryId::from_bytes(*entry.as_bytes()),
            notecrypt_core::RevisionId::from_bytes(*revision.as_bytes()),
        )
        .map_err(crate::session::map_repository_error)
    {
        return finish_repository_lease(lease, Err(error));
    }
    let session = service.session.as_ref().ok_or(ServiceError::Locked)?;
    let opened = match session.begin_export(selection) {
        Ok(opened) => opened,
        Err(error) => return fail_external_cleanup(service, error),
    };
    let mut transaction = opened.into_transaction();
    if let Err(primary) = context.phase_changed(crate::OperationPhase::Reading) {
        return abort_export(service, transaction, primary);
    }
    let export = {
        let mut writer = PanicContainedWriter {
            transaction: transaction.as_mut(),
            context,
            completed: 0,
        };
        lease
            .export(
                notecrypt_core::FileId::from_bytes(*entry.as_bytes()),
                notecrypt_core::RevisionId::from_bytes(*revision.as_bytes()),
                &mut writer,
            )
            .map_err(crate::session::map_repository_error)
    };
    let export = finish_repository_lease(lease, export);
    let bytes = match export {
        Ok(bytes) => bytes,
        Err(primary) => return abort_export(service, transaction, primary),
    };
    if let Err(primary) = context.emit_progress(crate::Progress::bytes(bytes, Some(bytes))?) {
        return abort_export(service, transaction, primary);
    }
    if let Err(primary) = context.phase_changed(crate::OperationPhase::Publishing) {
        return abort_export(service, transaction, primary);
    }
    let flush = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        transaction.flush_private()
    })) {
        Ok(result) => result.map_err(map_external_error),
        Err(_) => Err(ServiceError::ExecutorFailed),
    };
    if let Err(primary) = flush {
        return abort_export(service, transaction, primary);
    }
    if let Err(primary) = context.safe_boundary() {
        return abort_export(service, transaction, primary);
    }
    let mut authorization = ExternalPublicationAuthorization { service, state };
    let published = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        transaction.publish(&mut authorization)
    }))
    .map_err(|_| ServiceError::CleanupRequired)
    .and_then(|result| result.map_err(map_external_error));
    if let Err(error) = published {
        return fail_external_cleanup(service, error);
    }
    Ok(OperationResult::Exported(crate::ExportSummary::new(
        *entry.as_bytes(),
    )))
}

struct PanicContainedWriter<'a> {
    transaction: &'a mut dyn crate::ExternalExportTransaction,
    context: &'a OperationContext,
    completed: u64,
}

impl Write for PanicContainedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.transaction.write(buffer)
        }))
        .map_err(|_| std::io::Error::other("external export writer panicked"))??;
        self.completed = self
            .completed
            .checked_add(u64::try_from(written).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("export progress overflow"))?;
        let _ = self.context.emit_progress(
            crate::Progress::bytes(self.completed, None).map_err(std::io::Error::other)?,
        );
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.transaction.flush()))
            .map_err(|_| std::io::Error::other("external export writer panicked"))?
    }
}

struct ProgressReader<'a> {
    source: &'a mut dyn Read,
    context: &'a OperationContext,
    completed: u64,
}

impl Read for ProgressReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.source.read(buffer)?;
        self.completed = self
            .completed
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("import progress overflow"))?;
        if read != 0 {
            let _ = self.context.emit_progress(
                crate::Progress::bytes(self.completed, None).map_err(std::io::Error::other)?,
            );
        }
        Ok(read)
    }
}

fn abort_export(
    service: &Arc<ServiceInner>,
    transaction: Box<dyn crate::ExternalExportTransaction>,
    primary: ServiceError,
) -> Result<OperationResult, ServiceError> {
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| transaction.abort()))
        .map_err(|_| ServiceError::CleanupRequired)
        .and_then(|result| result.map_err(map_external_error));
    match cleanup {
        Ok(()) => Err(primary),
        Err(_) => fail_external_cleanup(service, ServiceError::CleanupRequired),
    }
}

fn fail_external_cleanup(
    service: &Arc<ServiceInner>,
    error: ServiceError,
) -> Result<OperationResult, ServiceError> {
    if error == ServiceError::CleanupRequired {
        service.latch_cleanup_required();
    }
    Err(error)
}

fn map_external_error(error: crate::HostPortError) -> ServiceError {
    match error {
        crate::HostPortError::Cancelled => ServiceError::Cancelled,
        crate::HostPortError::CapacityExceeded => ServiceError::CapacityExceeded,
        crate::HostPortError::AllocationFailed => ServiceError::AllocationFailed,
        crate::HostPortError::DestinationExists => ServiceError::DestinationExists,
        crate::HostPortError::StaleCapability => ServiceError::StaleCapability,
        crate::HostPortError::DurabilityPending => ServiceError::DurabilityPending,
        crate::HostPortError::CleanupFailed => ServiceError::CleanupRequired,
        crate::HostPortError::Unavailable => ServiceError::Unavailable,
        crate::HostPortError::InvalidInput
        | crate::HostPortError::Denied
        | crate::HostPortError::Permission => ServiceError::InvalidInput,
        crate::HostPortError::LiveWorkspace => ServiceError::Busy,
        crate::HostPortError::DetachedEditor | crate::HostPortError::PlatformFailure => {
            ServiceError::ExecutorFailed
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_import<'a>(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &'a OperationContext,
    snapshot: crate::SnapshotVersion,
    parent: crate::EntryId,
    name: zeroize::Zeroizing<String>,
    source: &mut dyn std::io::Read,
    external: Option<&'a mut dyn crate::VaultPublicationGuard>,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Encrypting)?;
    let mut lease = service.acquire_local_lease(state)?;
    let request = crate::LocalStreamRevisionRequest::try_create_in_parent(
        notecrypt_core::SnapshotId::from_bytes(*snapshot.as_bytes()),
        crate::LocalEntryId::from_bytes(*parent.as_bytes()),
        name.as_str(),
    )
    .map_err(crate::session::map_repository_error)?;
    context.emit_progress(crate::Progress::items(0, Some(1))?)?;
    context.phase_changed(crate::OperationPhase::Publishing)?;
    let mut guard = OperationPublicationGuard { context, external };
    let mut source = ProgressReader {
        source,
        context,
        completed: 0,
    };
    let commit = crate::session::selected_revision_commit(request, &mut source, &mut guard);
    let result = lease
        .commit_stable_revision(commit)
        .map_err(crate::session::map_repository_error);
    let result = finish_repository_lease(lease, result)?;
    let committed = crate::SnapshotVersion::new(*result.snapshot_id().as_bytes());
    let revision = crate::RevisionVersion::new(*result.revision_id().as_bytes());
    context.revision_durable_committed(durability(committed))?;
    Ok(OperationResult::EntryChanged(crate::MutationSummary::new(
        crate::EntryId::new(*result.file_id().as_bytes()),
        parent,
        committed,
        Some(revision),
        name,
        crate::EntryKind::File,
    )))
}

pub(crate) fn rename(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::RenameEntry,
) -> Result<OperationResult, ServiceError> {
    relocate(service, state, context, command.into_parts()?)
}

pub(crate) fn move_entry(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::MoveEntry,
) -> Result<OperationResult, ServiceError> {
    relocate(service, state, context, command.into_parts()?)
}

fn relocate(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    parts: crate::command::RelocateParts,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Preparing)?;
    let mut lease = service.acquire_local_lease(state)?;
    let kind = local_kind(parts.expected_kind)?;
    let revision = parts
        .expected_revision
        .map(|revision| notecrypt_core::RevisionId::from_bytes(*revision.as_bytes()));
    lease
        .validate_entry_binding(
            crate::LocalEntryId::from_bytes(*parts.entry.as_bytes()),
            crate::LocalEntryId::from_bytes(*parts.expected_parent.as_bytes()),
            parts.expected_name.as_str(),
            kind,
            revision,
        )
        .map_err(crate::session::map_repository_error)?;
    let mutation = crate::LocalMutation::try_rename(
        notecrypt_core::SnapshotId::from_bytes(*parts.expected_snapshot.as_bytes()),
        crate::LocalEntryId::from_bytes(*parts.entry.as_bytes()),
        crate::LocalEntryId::from_bytes(*parts.expected_parent.as_bytes()),
        parts.expected_name.as_str(),
        crate::LocalEntryId::from_bytes(*parts.new_parent.as_bytes()),
        parts.new_name.as_str(),
    )
    .map_err(crate::session::map_repository_error)?;
    context.emit_progress(crate::Progress::items(0, Some(1))?)?;
    context.phase_changed(crate::OperationPhase::Publishing)?;
    let mut guard = OperationPublicationGuard {
        context,
        external: None,
    };
    let result = lease
        .apply(mutation, &mut guard)
        .map_err(crate::session::map_repository_error);
    let result = finish_repository_lease(lease, result)?;
    let committed = crate::SnapshotVersion::new(*result.snapshot_id().as_bytes());
    context.revision_durable_committed(durability(committed))?;
    Ok(OperationResult::EntryChanged(crate::MutationSummary::new(
        parts.entry,
        parts.new_parent,
        committed,
        parts.expected_revision,
        parts.new_name,
        parts.expected_kind,
    )))
}

pub(crate) fn delete_entry(
    service: &Arc<ServiceInner>,
    state: &Arc<OperationState>,
    context: &OperationContext,
    command: crate::DeleteEntry,
) -> Result<OperationResult, ServiceError> {
    context.phase_changed(crate::OperationPhase::Preparing)?;
    let parts = command.into_parts()?;
    let mut lease = service.acquire_local_lease(state)?;
    let (kind, mutation) = match parts.expected_revision {
        Some(revision) => (
            crate::LocalEntryKind::File,
            crate::LocalMutation::try_delete_file(
                notecrypt_core::SnapshotId::from_bytes(*parts.expected_snapshot.as_bytes()),
                crate::LocalEntryId::from_bytes(*parts.entry.as_bytes()),
                crate::LocalEntryId::from_bytes(*parts.expected_parent.as_bytes()),
                parts.expected_name.as_str(),
                notecrypt_core::RevisionId::from_bytes(*revision.as_bytes()),
            ),
        ),
        None => (
            crate::LocalEntryKind::Directory,
            crate::LocalMutation::try_delete_directory(
                notecrypt_core::SnapshotId::from_bytes(*parts.expected_snapshot.as_bytes()),
                crate::LocalEntryId::from_bytes(*parts.entry.as_bytes()),
                crate::LocalEntryId::from_bytes(*parts.expected_parent.as_bytes()),
                parts.expected_name.as_str(),
            ),
        ),
    };
    lease
        .validate_entry_binding(
            crate::LocalEntryId::from_bytes(*parts.entry.as_bytes()),
            crate::LocalEntryId::from_bytes(*parts.expected_parent.as_bytes()),
            parts.expected_name.as_str(),
            kind,
            parts
                .expected_revision
                .map(|revision| notecrypt_core::RevisionId::from_bytes(*revision.as_bytes())),
        )
        .map_err(crate::session::map_repository_error)?;
    let mutation = mutation.map_err(crate::session::map_repository_error)?;
    context.emit_progress(crate::Progress::items(0, Some(1))?)?;
    context.phase_changed(crate::OperationPhase::Publishing)?;
    let mut guard = OperationPublicationGuard {
        context,
        external: None,
    };
    let result = lease
        .apply(mutation, &mut guard)
        .map_err(crate::session::map_repository_error);
    let result = finish_repository_lease(lease, result)?;
    let committed = crate::SnapshotVersion::new(*result.snapshot_id().as_bytes());
    context.revision_durable_committed(durability(committed))?;
    Ok(OperationResult::EntryChanged(crate::MutationSummary::new(
        parts.entry,
        parts.expected_parent,
        committed,
        None,
        parts.expected_name,
        crate::EntryKind::Tombstone,
    )))
}

fn local_kind(kind: crate::EntryKind) -> Result<crate::LocalEntryKind, ServiceError> {
    match kind {
        crate::EntryKind::File => Ok(crate::LocalEntryKind::File),
        crate::EntryKind::Directory => Ok(crate::LocalEntryKind::Directory),
        crate::EntryKind::Tombstone => Err(ServiceError::InvalidInput),
    }
}

fn durability(snapshot: crate::SnapshotVersion) -> crate::DurabilitySummary {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&snapshot.as_bytes()[..16]);
    crate::DurabilitySummary::new(bytes)
}

fn finish_repository_lease<T>(
    lease: Box<dyn crate::LocalVaultLease>,
    result: Result<T, ServiceError>,
) -> Result<T, ServiceError> {
    let finished = lease.finish().map_err(crate::session::map_repository_error);
    match (result, finished) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(result), Ok(())) => Ok(result),
    }
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
