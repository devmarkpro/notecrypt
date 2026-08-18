use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use crate::event::{ConflictSummary, DurabilitySummary, OperationPhase, WarningCode};
use crate::service::ServiceInner;
use crate::{OperationEvent, OperationResult, Progress, ProgressUnit, ServiceError};

const ACCEPTED: u8 = 0;
const RUNNING: u8 = 1;
const TERMINAL: u8 = 2;
const MAX_OPERATION_LEASES: u8 = 8;

/// A service-generated opaque operation identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(pub(crate) [u8; 16]);

impl OperationId {
    /// Borrows the opaque bytes for correlation only.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

pub(crate) struct SequencedEvent {
    sequence: u64,
    event: OperationEvent,
}

pub(crate) struct EventBuffer {
    lossless: VecDeque<SequencedEvent>,
    item_progress: Option<SequencedEvent>,
    byte_progress: Option<SequencedEvent>,
    terminal: Option<SequencedEvent>,
    next_sequence: u64,
    lossless_capacity: usize,
    consumer_gone: bool,
}

impl EventBuffer {
    fn new(capacity: usize) -> Result<Self, ServiceError> {
        let mut lossless = VecDeque::new();
        lossless
            .try_reserve_exact(capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(Self {
            lossless,
            item_progress: None,
            byte_progress: None,
            terminal: None,
            next_sequence: 0,
            lossless_capacity: capacity,
            consumer_gone: false,
        })
    }

    fn sequence(&mut self, event: OperationEvent) -> Result<SequencedEvent, ServiceError> {
        if self.next_sequence == u64::MAX {
            return Err(ServiceError::EventSequenceExhausted);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ServiceError::EventSequenceExhausted)?;
        Ok(SequencedEvent { sequence, event })
    }

    fn terminal_sequence(&self, event: OperationEvent) -> SequencedEvent {
        SequencedEvent {
            sequence: self.next_sequence,
            event,
        }
    }

    fn pop_next(&mut self) -> Option<OperationEvent> {
        let lossless = self.lossless.front().map(|event| event.sequence);
        let item_progress = self.item_progress.as_ref().map(|event| event.sequence);
        let byte_progress = self.byte_progress.as_ref().map(|event| event.sequence);
        let terminal = self.terminal.as_ref().map(|event| event.sequence);
        let minimum = [lossless, item_progress, byte_progress, terminal]
            .into_iter()
            .flatten()
            .min()?;

        if lossless == Some(minimum) {
            return self.lossless.pop_front().map(|event| event.event);
        }
        if item_progress == Some(minimum) {
            return self.item_progress.take().map(|event| event.event);
        }
        if byte_progress == Some(minimum) {
            return self.byte_progress.take().map(|event| event.event);
        }
        self.terminal.take().map(|event| event.event)
    }
}

pub(crate) struct OperationState {
    pub(crate) id: OperationId,
    lifecycle: AtomicU8,
    pub(crate) cancelled: AtomicBool,
    pub(crate) cancel_notification_pending: AtomicBool,
    pub(crate) cancel_notification_acknowledged: AtomicBool,
    events: Mutex<EventBuffer>,
    event_changed: Condvar,
    result: Mutex<Option<Result<OperationResult, ServiceError>>>,
    result_changed: Condvar,
    transition_result: Mutex<Option<Result<(), ServiceError>>>,
    transition_result_changed: Condvar,
    pub(crate) session_generation: Option<u64>,
    pub(crate) mutating: bool,
    lease_cancellations: Mutex<LeaseCancellations>,
    lease_cancellation_queued: AtomicBool,
    lease_cancellation_dispatched: AtomicBool,
    repository_cancellation: Arc<crate::RepositoryCancellation>,
}

struct LeaseCancellations {
    values: [Option<Arc<dyn crate::OperationCancellation>>; MAX_OPERATION_LEASES as usize],
    len: usize,
}

impl LeaseCancellations {
    fn new() -> Self {
        Self {
            values: std::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl OperationState {
    pub(crate) fn new(
        id: OperationId,
        event_capacity: usize,
        session_generation: Option<u64>,
        mutating: bool,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            id,
            lifecycle: AtomicU8::new(ACCEPTED),
            cancelled: AtomicBool::new(false),
            cancel_notification_pending: AtomicBool::new(false),
            cancel_notification_acknowledged: AtomicBool::new(false),
            events: Mutex::new(EventBuffer::new(event_capacity)?),
            event_changed: Condvar::new(),
            result: Mutex::new(None),
            result_changed: Condvar::new(),
            transition_result: Mutex::new(None),
            transition_result_changed: Condvar::new(),
            session_generation,
            mutating,
            lease_cancellations: Mutex::new(LeaseCancellations::new()),
            lease_cancellation_queued: AtomicBool::new(false),
            lease_cancellation_dispatched: AtomicBool::new(false),
            repository_cancellation: Arc::new(crate::RepositoryCancellation::new()),
        })
    }

    pub(crate) fn register_lease_cancellation(
        &self,
        cancellation: Arc<dyn crate::OperationCancellation>,
    ) -> Result<(), ServiceError> {
        let mut slots = lock(&self.lease_cancellations);
        if self.cancelled.load(Ordering::Acquire) {
            drop(slots);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cancellation.cancel();
            }));
            return Err(ServiceError::Cancelled);
        }
        if slots.len == slots.values.len() {
            return Err(ServiceError::CapacityExceeded);
        }
        let index = slots.len;
        slots.values[index] = Some(cancellation);
        slots.len += 1;
        Ok(())
    }

    pub(crate) fn mark_running(&self) -> bool {
        self.lifecycle
            .compare_exchange(ACCEPTED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == TERMINAL
    }

    pub(crate) fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == RUNNING
    }

    pub(crate) fn is_accepted(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == ACCEPTED
    }

    pub(crate) fn mark_cancelled(&self) {
        self.mark_security_cancelled();
        let _events = lock(&self.events);
    }

    pub(crate) fn mark_security_cancelled(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.repository_cancellation.cancel();
        self.event_changed.notify_all();
        self.result_changed.notify_all();
        self.transition_result_changed.notify_all();
    }

    pub(crate) fn cancel_registered_leases(&self) -> bool {
        if self
            .lease_cancellation_dispatched
            .swap(true, Ordering::AcqRel)
        {
            return false;
        }
        let snapshot = {
            let cancellations = lock(&self.lease_cancellations);
            std::array::from_fn::<_, { MAX_OPERATION_LEASES as usize }, _>(|index| {
                (index < cancellations.len)
                    .then(|| cancellations.values[index].as_ref().map(Arc::clone))
                    .flatten()
            })
        };
        for cancellation in snapshot.iter().flatten() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cancellation.cancel();
            }));
        }
        true
    }

    pub(crate) fn mark_lease_cancellation_queued(&self) -> bool {
        !self.lease_cancellation_queued.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn request_cancel(&self) {
        self.mark_cancelled();
    }

    pub(crate) fn repository_cancellation(&self) -> Arc<crate::RepositoryCancellation> {
        Arc::clone(&self.repository_cancellation)
    }

    pub(crate) fn publish(&self, event: OperationEvent) -> Result<(), ServiceError> {
        if event.terminal() {
            return Err(ServiceError::ExecutorFailed);
        }

        let mut events = lock(&self.events);
        if events.consumer_gone {
            return Err(ServiceError::Cancelled);
        }
        if self.is_terminal() {
            return Err(ServiceError::Closed);
        }
        if event.replaceable() {
            let unit = match &event {
                OperationEvent::Progress(progress) => progress.unit(),
                _ => return Err(ServiceError::ExecutorFailed),
            };
            let sequenced = events.sequence(event)?;
            match unit {
                ProgressUnit::Items => events.item_progress = Some(sequenced),
                ProgressUnit::Bytes => events.byte_progress = Some(sequenced),
            }
            self.event_changed.notify_all();
            return Ok(());
        }

        while events.lossless.len() == events.lossless_capacity
            && !events.consumer_gone
            && !self.cancelled.load(Ordering::Acquire)
            && !self.is_terminal()
        {
            events = wait(&self.event_changed, events);
        }
        if events.consumer_gone || self.cancelled.load(Ordering::Acquire) {
            return Err(ServiceError::Cancelled);
        }
        if self.is_terminal() {
            return Err(ServiceError::Closed);
        }
        let sequenced = events.sequence(event)?;
        events.lossless.push_back(sequenced);
        self.event_changed.notify_all();
        Ok(())
    }

    pub(crate) fn finish(&self, outcome: Result<OperationResult, ServiceError>) -> bool {
        let mut events = lock(&self.events);
        let mut lifecycle = self.lifecycle.load(Ordering::Acquire);
        loop {
            if lifecycle == TERMINAL {
                return false;
            }
            match self.lifecycle.compare_exchange(
                lifecycle,
                TERMINAL,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => lifecycle = observed,
            }
        }

        let terminal_event = match &outcome {
            Ok(_) => OperationEvent::Completed,
            Err(ServiceError::Cancelled) => OperationEvent::Cancelled,
            Err(error) => OperationEvent::Failed(*error),
        };
        if !events.consumer_gone {
            events.terminal = Some(events.terminal_sequence(terminal_event));
        }
        *lock(&self.result) = Some(outcome);
        self.event_changed.notify_all();
        self.result_changed.notify_all();
        true
    }

    pub(crate) fn finish_transition(&self, outcome: Result<(), ServiceError>) -> bool {
        let mut lifecycle = self.lifecycle.load(Ordering::Acquire);
        loop {
            if lifecycle == TERMINAL {
                return false;
            }
            match self.lifecycle.compare_exchange(
                lifecycle,
                TERMINAL,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => lifecycle = observed,
            }
        }
        *lock(&self.transition_result) = Some(outcome);
        self.event_changed.notify_all();
        self.result_changed.notify_all();
        self.transition_result_changed.notify_all();
        true
    }

    fn wait_transition_result(&self, timeout: Duration) -> Result<(), ServiceError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut result = lock(&self.transition_result);
        loop {
            if let Some(result) = result.take() {
                return result;
            }
            let Some(deadline) = deadline else {
                return Err(ServiceError::TimedOut);
            };
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ServiceError::TimedOut);
            };
            let (next_result, timed_out) =
                wait_timeout(&self.transition_result_changed, result, remaining);
            result = next_result;
            if timed_out && result.is_none() {
                return Err(ServiceError::TimedOut);
            }
        }
    }

    fn next_event(&self) -> Option<OperationEvent> {
        let mut events = lock(&self.events);
        let next = events.pop_next();
        if next.is_some() {
            self.event_changed.notify_all();
        }
        next
    }

    fn wait_next_event(&self, timeout: Duration) -> Option<OperationEvent> {
        let deadline = Instant::now().checked_add(timeout);
        let mut events = lock(&self.events);
        loop {
            if let Some(next) = events.pop_next() {
                self.event_changed.notify_all();
                return Some(next);
            }
            if self.is_terminal() || events.consumer_gone {
                return None;
            }
            let deadline = deadline?;
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (next_events, timed_out) = wait_timeout(&self.event_changed, events, remaining);
            events = next_events;
            if timed_out {
                return events.pop_next().inspect(|_event| {
                    self.event_changed.notify_all();
                });
            }
        }
    }

    fn take_result(&self) -> Option<Result<OperationResult, ServiceError>> {
        lock(&self.result).take()
    }

    fn wait_result(&self, timeout: Duration) -> Result<OperationResult, ServiceError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut result = lock(&self.result);
        loop {
            if let Some(result) = result.take() {
                return result;
            }
            let Some(deadline) = deadline else {
                return Err(ServiceError::TimedOut);
            };
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ServiceError::TimedOut);
            };
            let (next_result, timed_out) = wait_timeout(&self.result_changed, result, remaining);
            result = next_result;
            if timed_out && result.is_none() {
                return Err(ServiceError::TimedOut);
            }
        }
    }

    pub(crate) fn abandon_consumer(&self) {
        let mut events = lock(&self.events);
        events.consumer_gone = true;
        events.lossless.clear();
        events.item_progress = None;
        events.byte_progress = None;
        events.terminal = None;
        self.cancelled.store(true, Ordering::Release);
        self.event_changed.notify_all();
        self.result_changed.notify_all();
        drop(events);
    }
}

/// Safe operation callbacks supplied to a synchronous executor.
pub struct OperationContext {
    state: Arc<OperationState>,
    service: Weak<ServiceInner>,
}

impl OperationContext {
    pub(crate) fn new(state: Arc<OperationState>, service: Weak<ServiceInner>) -> Self {
        Self { state, service }
    }

    pub fn id(&self) -> OperationId {
        self.state.id
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Checks cooperative cancellation at one explicit bounded boundary.
    pub fn safe_boundary(&self) -> Result<(), ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .operation_safe_boundary(&self.state)
    }

    pub fn phase_changed(&self, phase: OperationPhase) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::PhaseChanged(phase))?;
        self.safe_boundary()
    }

    pub fn emit_progress(&self, progress: Progress) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::Progress(progress))?;
        self.safe_boundary()
    }

    pub fn warning(&self, warning: WarningCode) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::Warning(warning))?;
        self.safe_boundary()
    }

    pub fn conflict(&self, conflict: ConflictSummary) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::Conflict(conflict))?;
        self.safe_boundary()
    }

    pub fn revision_durable(&self, durable: DurabilitySummary) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state
            .publish(OperationEvent::RevisionDurable(durable))?;
        self.safe_boundary()
    }

    pub fn save_detected(&self) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::SaveDetected)?;
        self.safe_boundary()
    }

    pub fn sync_published(&self) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::SyncPublished)?;
        self.safe_boundary()
    }

    pub fn cleanup_required(&self) -> Result<(), ServiceError> {
        self.safe_boundary()?;
        self.state.publish(OperationEvent::CleanupRequired)?;
        self.safe_boundary()
    }

    pub fn acquire_local_lease(&self) -> Result<Box<dyn crate::LocalVaultLease>, ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .acquire_local_lease(&self.state)
    }

    pub fn acquire_replication_lease(
        &self,
        backend: crate::ReplicationLimitProfile,
        operation: crate::ReplicationLimitProfile,
    ) -> Result<Box<dyn crate::ReplicationVaultLease>, ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .acquire_replication_lease(&self.state, backend, operation)
    }

    pub fn create_workspace(
        &self,
        mode: crate::WorkspaceMode,
        repository_root: std::path::PathBuf,
    ) -> Result<crate::WorkspaceSession, ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .create_workspace(&self.state, mode, repository_root)
    }

    pub fn remove_workspace(&self, workspace: crate::WorkspaceSession) -> Result<(), ServiceError> {
        let service = self.service.upgrade().ok_or(ServiceError::Closed)?;
        let generation = self.state.session_generation.ok_or(ServiceError::Locked)?;
        let session = service.session.as_ref().ok_or(ServiceError::Locked)?;
        let result = session.remove_workspace(workspace, generation);
        if result == Err(ServiceError::CleanupRequired) {
            service.latch_cleanup_required();
        }
        result
    }

    pub fn commit_workspace_stable_revision(
        &self,
        workspace: &crate::WorkspaceSession,
        relative_path: &crate::LogicalWorkspacePath,
        expected_generation: u64,
        request: crate::LocalStreamRevisionRequest,
    ) -> Result<crate::LocalSnapshot, ServiceError> {
        let service = self.service.upgrade().ok_or(ServiceError::Closed)?;
        let generation = self.state.session_generation.ok_or(ServiceError::Locked)?;
        let session = service.session.as_ref().ok_or(ServiceError::Locked)?;
        if !session.owns_workspace(workspace, generation) {
            return Err(ServiceError::StaleCapability);
        }
        let mut lease = service.acquire_local_lease(&self.state)?;
        let result = session.commit_stable_revision(
            workspace,
            relative_path,
            expected_generation,
            lease.as_mut(),
            request,
        );
        let finish = lease.finish().map_err(crate::session::map_repository_error);
        let outcome = match (result, finish) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), Ok(())) => Err(primary),
            (_, Err(cleanup)) => Err(cleanup),
        };
        if matches!(outcome, Err(ServiceError::CleanupRequired)) {
            service.latch_cleanup_required();
        }
        outcome
    }

    /// Arms this exact running mutating operation as the sole bounded final save.
    pub fn arm_final_save(&self) -> Result<FinalSaveGuard, ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .arm_final_save(&self.state)
    }

    /// Pauses this exact verified replication operation for explicit freshness consent.
    pub fn await_freshness_acknowledgement(
        &self,
        action: Box<dyn crate::PendingFreshnessAction>,
    ) -> Result<(), ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .await_freshness_acknowledgement(&self.state, action)
    }
}

/// Linear guard for the one exact operation permitted to finish during lock grace.
pub struct FinalSaveGuard {
    pub(crate) service: Weak<ServiceInner>,
    pub(crate) state: Arc<OperationState>,
    pub(crate) generation: u64,
    pub(crate) armed: bool,
}

impl Drop for FinalSaveGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(service) = self.service.upgrade() {
                service.disarm_final_save(&self.state, self.generation);
            }
            self.armed = false;
        }
    }
}

/// Handle for non-blocking event and result observation.
pub struct OperationHandle {
    state: Arc<OperationState>,
    service: Weak<ServiceInner>,
}

impl OperationHandle {
    pub(crate) fn new(state: Arc<OperationState>, service: Weak<ServiceInner>) -> Self {
        Self { state, service }
    }

    pub fn id(&self) -> OperationId {
        self.state.id
    }

    pub fn try_next_event(&self) -> Result<Option<OperationEvent>, ServiceError> {
        Ok(self.state.next_event())
    }

    pub fn wait_next_event(
        &self,
        timeout: Duration,
    ) -> Result<Option<OperationEvent>, ServiceError> {
        Ok(self.state.wait_next_event(timeout))
    }

    pub fn cancel(&self) {
        if self.state.is_terminal() {
            return;
        }
        self.state.request_cancel();
        if let Some(service) = self.service.upgrade() {
            service.cancel_exact(&self.state);
        }
    }

    pub fn try_result(&self) -> Result<Option<OperationResult>, ServiceError> {
        match self.state.take_result() {
            Some(Ok(result)) => Ok(Some(result)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    pub fn wait_result(&self, timeout: Duration) -> Result<OperationResult, ServiceError> {
        self.state.wait_result(timeout)
    }
}

impl Drop for OperationHandle {
    fn drop(&mut self) {
        self.state.abandon_consumer();
        if let Some(service) = self.service.upgrade() {
            service.detach(&self.state);
        }
    }
}

/// Dedicated handle for a non-ordinary security transition completion.
pub struct SecurityTransitionHandle {
    state: Arc<OperationState>,
    service: Weak<ServiceInner>,
}

impl SecurityTransitionHandle {
    pub(crate) fn new(state: Arc<OperationState>, service: Weak<ServiceInner>) -> Self {
        Self { state, service }
    }

    pub fn cancel(&self) {
        if self.state.is_terminal() {
            return;
        }
        self.state.request_cancel();
        if let Some(service) = self.service.upgrade() {
            service.enqueue_security_cancellation(&self.state);
        }
    }

    pub fn wait_result(&self, timeout: Duration) -> Result<(), ServiceError> {
        self.state.wait_transition_result(timeout)
    }
}

impl Drop for SecurityTransitionHandle {
    fn drop(&mut self) {
        if !self.state.is_terminal() {
            self.state.request_cancel();
            if let Some(service) = self.service.upgrade() {
                service.enqueue_security_cancellation(&self.state);
            }
        }
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn wait<'a, T>(condition: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condition
        .wait(guard)
        .unwrap_or_else(|error| error.into_inner())
}

fn wait_timeout<'a, T>(
    condition: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
) -> (MutexGuard<'a, T>, bool) {
    match condition.wait_timeout(guard, timeout) {
        Ok((guard, result)) => (guard, result.timed_out()),
        Err(error) => {
            let (guard, result) = error.into_inner();
            (guard, result.timed_out())
        }
    }
}
