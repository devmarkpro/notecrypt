use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError, bounded};
use zeroize::Zeroizing;

use crate::operation::{FinalSaveGuard, OperationState, lock};
use crate::session::{
    EDITOR_FORCE_REAP_GRACE, EditorQuiescenceObservation, RootCapabilitySlot, SessionManager,
};
use crate::{
    BeginCompromiseRekey, BeginRecoveryInitialization, Command, CompromiseRekeyConfirmation,
    FreshnessAcknowledgementView, OperationContext, OperationHandle, OperationId, OperationResult,
    PendingCompromiseAction, PendingFreshnessAction, PendingRecoveryAction, RecoverySecretInput,
    RecoverySecretPresentation, SecurityTransitionHandle, ServiceError, SessionComponents,
    SessionEvent, SessionState, SessionSummary, VaultSummary, WarningCode,
};

type SecurityJob = Box<dyn FnOnce() + Send + 'static>;

/// Default number of synchronous workers.
pub const DEFAULT_WORKERS: usize = 4;
/// Default bounded ordinary-command capacity.
pub const DEFAULT_QUEUE_CAPACITY: usize = 64;
/// Default bounded lossless events retained per operation.
pub const DEFAULT_EVENT_CAPACITY: usize = 64;
/// Default number of completed operation summaries retained by the service.
pub const DEFAULT_COMPLETED_CAPACITY: usize = 256;
/// Default lifetime operation-identity budget for one service instance.
pub const DEFAULT_ISSUED_CAPACITY: u64 = u64::MAX;
/// Default collision retry budget for injected operation identity sources.
pub const DEFAULT_ID_RETRIES: usize = 8;
/// Maximum fixed worker count accepted in phase one.
pub const MAX_WORKERS: usize = 64;
/// Maximum ordinary queue capacity accepted in phase one.
pub const MAX_QUEUE_CAPACITY: usize = 4096;
/// Maximum lossless events retained per operation in phase one.
pub const MAX_EVENT_CAPACITY: usize = 1024;
/// Maximum completed tombstones retained by the runtime in phase one.
pub const MAX_COMPLETED_CAPACITY: usize = 4096;
/// Maximum operation-ID collision retries accepted in phase one.
pub const MAX_ID_RETRIES: usize = 64;

/// Priority control delivered outside the bounded ordinary queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Control {
    LockNow,
    DeadlineExpired,
    Suspend,
    Cancel(OperationId),
    UserActivity,
}

impl Control {
    const fn is_global(self) -> bool {
        matches!(self, Self::LockNow | Self::DeadlineExpired | Self::Suspend)
    }
}

/// Cryptographically secure randomness seam used only for service-owned IDs.
pub trait OperationIdRandom: Send + Sync + 'static {
    /// Fills part or all of `destination` and reports the exact byte count.
    ///
    /// Returning zero, a count larger than the destination, or an error fails
    /// closed before any operation state or queue capacity is published.
    fn fill(&self, destination: &mut [u8]) -> Result<usize, ServiceError>;
}

/// Operating-system cryptographically secure operation-ID source.
pub struct OsOperationIdRandom;

impl OperationIdRandom for OsOperationIdRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<usize, ServiceError> {
        getrandom::fill(destination).map_err(|_| ServiceError::EntropyUnavailable)?;
        Ok(destination.len())
    }
}

/// Synchronous runtime-neutral operation implementation.
pub trait OperationExecutor: Send + Sync + 'static {
    /// Runs one accepted ordinary command on a fixed worker.
    fn execute(
        &self,
        command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError>;

    /// Observes one coalesced priority notification on the dedicated observer thread.
    ///
    /// Global cancellation flags and submission gates have already changed
    /// before this callback runs. Global notifications run only after concrete
    /// revocation, close, and cleanup complete. Implementations must keep this
    /// callback bounded and must not assume worker or coordinator thread affinity.
    fn control(&self, _control: Control) {}
}

/// Validated hard bounds for one service runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    queue_capacity: usize,
    workers: usize,
    event_capacity: usize,
    completed_capacity: usize,
    issued_capacity: u64,
    id_retries: usize,
}

impl ServiceConfig {
    pub fn new(
        queue_capacity: usize,
        workers: usize,
        event_capacity: usize,
        completed_capacity: usize,
        issued_capacity: u64,
        id_retries: usize,
    ) -> Result<Self, ServiceError> {
        if queue_capacity == 0
            || workers == 0
            || event_capacity == 0
            || completed_capacity == 0
            || issued_capacity == 0
            || id_retries == 0
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        if queue_capacity > MAX_QUEUE_CAPACITY
            || workers > MAX_WORKERS
            || event_capacity > MAX_EVENT_CAPACITY
            || completed_capacity > MAX_COMPLETED_CAPACITY
            || id_retries > MAX_ID_RETRIES
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        let active_capacity = workers
            .checked_mul(2)
            .and_then(|workers| queue_capacity.checked_add(workers))
            .and_then(|capacity| capacity.checked_add(1))
            .ok_or(ServiceError::InvalidConfiguration)?;
        if issued_capacity < active_capacity as u64 {
            return Err(ServiceError::InvalidConfiguration);
        }
        Ok(Self {
            queue_capacity,
            workers,
            event_capacity,
            completed_capacity,
            issued_capacity,
            id_retries,
        })
    }

    pub const fn queue_capacity(&self) -> usize {
        self.queue_capacity
    }

    pub const fn workers(&self) -> usize {
        self.workers
    }

    pub const fn event_capacity(&self) -> usize {
        self.event_capacity
    }

    pub const fn completed_capacity(&self) -> usize {
        self.completed_capacity
    }

    pub const fn issued_capacity(&self) -> u64 {
        self.issued_capacity
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            workers: DEFAULT_WORKERS,
            event_capacity: DEFAULT_EVENT_CAPACITY,
            completed_capacity: DEFAULT_COMPLETED_CAPACITY,
            issued_capacity: DEFAULT_ISSUED_CAPACITY,
            id_retries: DEFAULT_ID_RETRIES,
        }
    }
}

/// Bounded coherent service state for presentation layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceSnapshot {
    session_state: SessionState,
    accepting_operations: bool,
    key_leases_open: bool,
    queued_operations: usize,
    running_operations: usize,
    active_operations: usize,
    retained_completed_operations: usize,
    closed: bool,
}

impl ServiceSnapshot {
    pub const fn session_state(&self) -> SessionState {
        self.session_state
    }

    pub const fn accepting_operations(&self) -> bool {
        self.accepting_operations
    }

    pub const fn key_leases_open(&self) -> bool {
        self.key_leases_open
    }

    pub const fn queued_operations(&self) -> usize {
        self.queued_operations
    }

    pub const fn running_operations(&self) -> usize {
        self.running_operations
    }

    pub const fn active_operations(&self) -> usize {
        self.active_operations
    }

    pub const fn retained_completed_operations(&self) -> usize {
        self.retained_completed_operations
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }
}

struct WorkItem {
    payload: WorkPayload,
    state: Arc<OperationState>,
}

enum WorkPayload {
    Command(Command),
    Compromise {
        action: Box<dyn PendingCompromiseAction>,
        confirmation: RecoverySecretInput,
        record: Arc<TransitionRecord>,
    },
}

#[derive(Clone, Copy)]
struct PendingControl {
    control: Control,
    generation: u64,
    trusted_activity: bool,
}

struct ControlMailbox {
    pending: VecDeque<PendingControl>,
    global_notified: Option<u64>,
    global_control: Option<PendingControl>,
    trusted_activity_pending: Option<u64>,
    trusted_activity_dispatched: Option<u64>,
    untrusted_activity_pending: Option<u64>,
    capacity: usize,
}

impl ControlMailbox {
    fn new(capacity: usize) -> Result<Self, ServiceError> {
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(Self {
            pending,
            global_notified: None,
            global_control: None,
            trusted_activity_pending: None,
            trusted_activity_dispatched: None,
            untrusted_activity_pending: None,
            capacity,
        })
    }

    fn push(&mut self, control: Control, generation: u64, trusted_activity: bool) -> bool {
        if self.pending.len() == self.capacity {
            return false;
        }
        self.pending.push_back(PendingControl {
            control,
            generation,
            trusted_activity,
        });
        true
    }

    fn pop(&mut self) -> Option<PendingControl> {
        let pending = self.pending.pop_front()?;
        if pending.control.is_global() && self.global_notified == Some(pending.generation) {
            self.global_notified = None;
        }
        if pending.control == Control::UserActivity {
            let slot = if pending.trusted_activity {
                &mut self.trusted_activity_pending
            } else {
                &mut self.untrusted_activity_pending
            };
            if *slot == Some(pending.generation) {
                *slot = None;
            }
        }
        Some(pending)
    }

    fn pop_trusted_activity(&mut self) -> Option<PendingControl> {
        let generation = self.trusted_activity_pending?;
        if self.trusted_activity_dispatched == Some(generation) {
            return None;
        }
        self.trusted_activity_dispatched = Some(generation);
        Some(PendingControl {
            control: Control::UserActivity,
            generation,
            trusted_activity: true,
        })
    }

    fn pop_global(&mut self) -> Option<PendingControl> {
        self.global_control.take()
    }

    fn reset_for_generation(&mut self, generation: u64) {
        self.pending
            .retain(|pending| pending.generation == generation);
        self.global_notified = None;
        self.global_control = None;
        self.trusted_activity_pending = None;
        self.trusted_activity_dispatched = None;
        self.untrusted_activity_pending = None;
    }
}

struct FinalSaveSlot {
    generation: u64,
    state: Arc<OperationState>,
}

struct ExternalPublicationRegistration<'a> {
    service: &'a ServiceInner,
    state: &'a Arc<OperationState>,
    generation: u64,
}

impl Drop for ExternalPublicationRegistration<'_> {
    fn drop(&mut self) {
        self.service
            .finish_external_publication(self.state, self.generation);
    }
}

struct LockJob {
    generation: u64,
    root: Option<Arc<RootCapabilitySlot>>,
    final_save: Option<Arc<OperationState>>,
    grace_deadline: Option<std::time::Instant>,
    force_reap_deadline: Option<std::time::Instant>,
}

struct SchedulerState {
    accepting: bool,
    key_leases_open: bool,
    closed: bool,
    active: HashMap<OperationId, Arc<OperationState>>,
    completed: VecDeque<OperationId>,
    controls: ControlMailbox,
    generation: u64,
    final_save: Option<FinalSaveSlot>,
    external_publications: HashMap<OperationId, Arc<OperationState>>,
    lock_job: Option<LockJob>,
    session_events: VecDeque<(u64, SessionEvent)>,
    unlock_in_progress: bool,
    observer_in_flight: usize,
}

impl SchedulerState {
    fn new(config: ServiceConfig) -> Result<Self, ServiceError> {
        let active_capacity = config
            .workers
            .checked_mul(2)
            .and_then(|workers| config.queue_capacity.checked_add(workers))
            .and_then(|capacity| capacity.checked_add(1))
            .ok_or(ServiceError::InvalidConfiguration)?;
        let control_capacity = active_capacity
            .checked_add(2)
            .ok_or(ServiceError::InvalidConfiguration)?;
        let mut active = HashMap::new();
        active
            .try_reserve(active_capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        let mut completed = VecDeque::new();
        completed
            .try_reserve_exact(config.completed_capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        let mut session_events = VecDeque::new();
        session_events
            .try_reserve_exact(crate::MAX_WARNING_OFFSETS.saturating_mul(2))
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        let mut external_publications = HashMap::new();
        external_publications
            .try_reserve(active_capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(Self {
            accepting: true,
            key_leases_open: true,
            closed: false,
            active,
            completed,
            controls: ControlMailbox::new(control_capacity)?,
            generation: 0,
            final_save: None,
            external_publications,
            lock_job: None,
            session_events,
            unlock_in_progress: false,
            observer_in_flight: 0,
        })
    }
}

pub(crate) struct ServiceInner {
    config: ServiceConfig,
    executor: Arc<dyn OperationExecutor>,
    random: Arc<dyn OperationIdRandom>,
    scheduler: Mutex<SchedulerState>,
    scheduler_changed: Condvar,
    ordinary_sender: Mutex<Option<Sender<WorkItem>>>,
    ordinary_receiver: Receiver<WorkItem>,
    worker_sender: Mutex<Option<Sender<WorkItem>>>,
    cancellation_sender: Mutex<Option<Sender<Arc<OperationState>>>>,
    control_sender: Mutex<Option<Sender<PendingControl>>>,
    security_sender: Mutex<Option<Sender<SecurityJob>>>,
    security_busy: AtomicBool,
    identity: Mutex<IdentityState>,
    pub(crate) session: Option<Arc<SessionManager>>,
    transitions: Mutex<TransitionRegistry>,
}

const TRANSITION_PENDING: u8 = 0;
const TRANSITION_CONSUMING: u8 = 1;
const TRANSITION_CANCELLED: u8 = 2;
const TRANSITION_COMPLETED: u8 = 3;

fn clear_presentation(record: &TransitionRecord) {
    if let Some(presentation) = &record.presentation {
        let _ = lock(presentation).take();
    }
}

enum PendingAction {
    Recovery(Box<dyn PendingRecoveryAction>),
    Compromise(Box<dyn PendingCompromiseAction>),
    Freshness {
        action: Box<dyn PendingFreshnessAction>,
        view: FreshnessAcknowledgementView,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransitionKind {
    Recovery,
    Compromise,
    Freshness,
}

struct SecretVerifier {
    key: Zeroizing<[u8; 32]>,
    expected: Zeroizing<[u8; 32]>,
}

struct TransitionRecord {
    kind: TransitionKind,
    generation: u64,
    operation: OperationId,
    state: AtomicU8,
    action: Mutex<Option<PendingAction>>,
    verifier: Mutex<Option<SecretVerifier>>,
    presentation: Option<crate::ports::RecoveryPresentationCell>,
    offered: AtomicU8,
    resolution: Mutex<Option<Result<(), ServiceError>>>,
    resolution_changed: Condvar,
    operation_state: Mutex<Option<std::sync::Weak<OperationState>>>,
}

struct TransitionRegistry {
    records: HashMap<OperationId, Arc<TransitionRecord>>,
    cancellation_scratch: Vec<Arc<TransitionRecord>>,
    capacity: usize,
    recovery_prepare: Option<Arc<crate::RepositoryCancellation>>,
    compromise_prepare: Option<Arc<crate::RepositoryCancellation>>,
}

impl TransitionRegistry {
    fn new(capacity: usize) -> Result<Self, ServiceError> {
        let mut records = HashMap::new();
        records
            .try_reserve(capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        let mut cancellation_scratch = Vec::new();
        cancellation_scratch
            .try_reserve_exact(capacity)
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(Self {
            records,
            cancellation_scratch,
            capacity,
            recovery_prepare: None,
            compromise_prepare: None,
        })
    }
}

struct IdentityState {
    nonce: Option<[u8; 8]>,
    next: u64,
}

impl ServiceInner {
    fn begin_prepare(
        &self,
        kind: TransitionKind,
        generation: u64,
    ) -> Result<Arc<crate::RepositoryCancellation>, ServiceError> {
        let scheduler = lock(&self.scheduler);
        let valid = match kind {
            TransitionKind::Recovery => self.session.as_ref().is_some_and(|session| {
                !scheduler.closed
                    && !scheduler.unlock_in_progress
                    && scheduler.lock_job.is_none()
                    && session.state() == SessionState::Locked
                    && session.binding_epoch() == generation
            }),
            TransitionKind::Compromise => self.session.as_ref().is_some_and(|session| {
                !scheduler.closed
                    && scheduler.accepting
                    && scheduler.key_leases_open
                    && scheduler.generation == generation
                    && session.current_generation() == Some(generation)
            }),
            TransitionKind::Freshness => false,
        };
        if !valid {
            return Err(ServiceError::Locked);
        }
        let mut registry = lock(&self.transitions);
        if registry.records.values().any(|record| record.kind == kind) {
            return Err(ServiceError::Busy);
        }
        let slot = match kind {
            TransitionKind::Recovery => &mut registry.recovery_prepare,
            TransitionKind::Compromise => &mut registry.compromise_prepare,
            TransitionKind::Freshness => return Err(ServiceError::InvalidConfiguration),
        };
        if slot.is_some() {
            return Err(ServiceError::Busy);
        }
        let cancellation = Arc::new(crate::RepositoryCancellation::new());
        *slot = Some(Arc::clone(&cancellation));
        drop(registry);
        drop(scheduler);
        Ok(cancellation)
    }

    fn prepare_is_active(
        &self,
        kind: TransitionKind,
        cancellation: &Arc<crate::RepositoryCancellation>,
    ) -> bool {
        let registry = lock(&self.transitions);
        let slot = match kind {
            TransitionKind::Recovery => &registry.recovery_prepare,
            TransitionKind::Compromise => &registry.compromise_prepare,
            TransitionKind::Freshness => return false,
        };
        let exact = slot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, cancellation));
        exact && !cancellation.is_cancelled()
    }

    fn clear_prepare(
        &self,
        kind: TransitionKind,
        cancellation: &Arc<crate::RepositoryCancellation>,
    ) {
        let mut registry = lock(&self.transitions);
        let slot = match kind {
            TransitionKind::Recovery => &mut registry.recovery_prepare,
            TransitionKind::Compromise => &mut registry.compromise_prepare,
            TransitionKind::Freshness => return,
        };
        if slot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, cancellation))
        {
            *slot = None;
        }
    }

    fn cancel_prepare_attempts(&self) {
        let registry = lock(&self.transitions);
        if let Some(cancellation) = &registry.recovery_prepare {
            cancellation.cancel();
        }
        if let Some(cancellation) = &registry.compromise_prepare {
            cancellation.cancel();
        }
    }

    pub(crate) fn latch_cleanup_required(&self) {
        if let Some(session) = &self.session {
            let was_unlocked = session.state() == SessionState::Unlocked;
            if was_unlocked {
                self.start_global_lock(Control::LockNow, false);
            }
            session.mark_cleanup_required();
        }
    }

    fn candidate_id(
        &self,
        identity: &mut IdentityState,
    ) -> Result<(OperationId, u64), ServiceError> {
        if identity.nonce.is_none() {
            for _ in 0..self.config.id_retries {
                let mut nonce = [0_u8; 8];
                fill_exact(self.random.as_ref(), &mut nonce)?;
                if nonce != [0; 8] {
                    identity.nonce = Some(nonce);
                    break;
                }
            }
        }
        let nonce = identity.nonce.ok_or(ServiceError::IdentifierExhausted)?;
        if identity.next == self.config.issued_capacity {
            return Err(ServiceError::IdentifierExhausted);
        }
        let sequence = identity.next;
        let next = identity
            .next
            .checked_add(1)
            .ok_or(ServiceError::IdentifierExhausted)?;
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&nonce);
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        Ok((OperationId(bytes), next))
    }

    pub(crate) fn cancel_exact(&self, state: &Arc<OperationState>) {
        let mut scheduler = lock(&self.scheduler);
        let is_active = scheduler
            .active
            .get(&state.id)
            .is_some_and(|active| Arc::ptr_eq(active, state));
        if is_active {
            state.mark_cancelled();
            let generation = scheduler.generation;
            if !state
                .cancel_notification_pending
                .swap(true, Ordering::AcqRel)
                && !scheduler
                    .controls
                    .push(Control::Cancel(state.id), generation, false)
            {
                drop(scheduler);
                self.shutdown();
                return;
            }
            self.scheduler_changed.notify_all();
        }
    }

    pub(crate) fn arm_final_save(
        self: &Arc<Self>,
        state: &Arc<OperationState>,
    ) -> Result<FinalSaveGuard, ServiceError> {
        let mut scheduler = lock(&self.scheduler);
        let generation = state.session_generation.ok_or(ServiceError::Locked)?;
        if scheduler.closed
            || !scheduler.accepting
            || !scheduler.key_leases_open
            || scheduler.generation != generation
            || !state.mutating
            || !state.is_running()
            || state.cancelled.load(Ordering::Acquire)
            || !scheduler
                .active
                .get(&state.id)
                .is_some_and(|active| Arc::ptr_eq(active, state))
            || scheduler.final_save.is_some()
        {
            return Err(ServiceError::StaleCapability);
        }
        scheduler.final_save = Some(FinalSaveSlot {
            generation,
            state: Arc::clone(state),
        });
        self.scheduler_changed.notify_all();
        Ok(FinalSaveGuard {
            service: Arc::downgrade(self),
            state: Arc::clone(state),
            generation,
            armed: true,
        })
    }

    pub(crate) fn disarm_final_save(&self, state: &Arc<OperationState>, generation: u64) {
        let mut scheduler = lock(&self.scheduler);
        let exact = scheduler
            .final_save
            .as_ref()
            .is_some_and(|slot| slot.generation == generation && Arc::ptr_eq(&slot.state, state));
        if exact && scheduler.accepting {
            scheduler.final_save = None;
            self.scheduler_changed.notify_all();
        }
    }

    fn enqueue_trusted_activity(&self) -> Result<(), ServiceError> {
        let session = self.session.as_ref().ok_or(ServiceError::Locked)?;
        {
            let scheduler = lock(&self.scheduler);
            if scheduler.closed {
                return Err(ServiceError::Closed);
            }
            if !scheduler.accepting || scheduler.generation == 0 {
                return Err(ServiceError::Locked);
            }
        }
        let sample = match session.sample_now() {
            Ok(sample) => sample,
            Err(error) => {
                self.start_global_lock(Control::DeadlineExpired, false);
                return Err(error);
            }
        };
        let mut scheduler = lock(&self.scheduler);
        if scheduler.closed {
            return Err(ServiceError::Closed);
        }
        if !scheduler.accepting || scheduler.generation == 0 {
            return Err(ServiceError::Locked);
        }
        let generation = scheduler.generation;
        if let Err(error) = session.record_trusted_activity_at(sample) {
            drop(scheduler);
            self.start_global_lock(Control::DeadlineExpired, false);
            return Err(error);
        }
        scheduler.session_events.retain(|(_, event)| {
            !matches!(
                event,
                SessionEvent::LockWarning {
                    deadline: crate::SessionDeadlineKind::Inactivity,
                    ..
                }
            )
        });
        if scheduler.controls.trusted_activity_pending != Some(generation) {
            scheduler.controls.trusted_activity_pending = Some(generation);
        }
        self.scheduler_changed.notify_all();
        Ok(())
    }

    pub(crate) fn detach(&self, state: &Arc<OperationState>) {
        let still_accounted = lock(&self.scheduler)
            .active
            .get(&state.id)
            .is_some_and(|active| Arc::ptr_eq(active, state));
        if still_accounted {
            self.cancel_exact(state);
            self.cancel_transition_for_operation(state.id);
        }
        self.scheduler_changed.notify_all();
    }

    fn finish(&self, state: &Arc<OperationState>, outcome: Result<OperationResult, ServiceError>) {
        let mut scheduler = lock(&self.scheduler);
        let should_remove = scheduler
            .active
            .get(&state.id)
            .is_some_and(|active| Arc::ptr_eq(active, state));
        if !should_remove {
            return;
        }
        if !state.finish(outcome) {
            return;
        }
        if scheduler
            .final_save
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(&slot.state, state))
        {
            scheduler.final_save = None;
        }
        let waiting_for_cancel_notice = state.cancel_notification_pending.load(Ordering::Acquire)
            && !state
                .cancel_notification_acknowledged
                .load(Ordering::Acquire);
        if waiting_for_cancel_notice {
            self.scheduler_changed.notify_all();
            return;
        }
        self.retire_locked(&mut scheduler, state.id);
    }

    fn acknowledge_cancel(&self, id: OperationId) {
        let mut scheduler = lock(&self.scheduler);
        let Some(state) = scheduler.active.get(&id).cloned() else {
            return;
        };
        state
            .cancel_notification_acknowledged
            .store(true, Ordering::Release);
        if state.is_terminal() {
            self.retire_locked(&mut scheduler, id);
        }
    }

    fn retire_locked(&self, scheduler: &mut SchedulerState, id: OperationId) {
        scheduler.active.remove(&id);
        if scheduler.completed.len() == self.config.completed_capacity {
            scheduler.completed.pop_front();
        }
        scheduler.completed.push_back(id);
        self.scheduler_changed.notify_all();
    }

    fn start_global_lock(&self, control: Control, close_service: bool) {
        let mut scheduler = lock(&self.scheduler);
        if close_service {
            scheduler.closed = true;
            lock(&self.ordinary_sender).take();
            lock(&self.security_sender).take();
        }
        scheduler.accepting = false;
        scheduler.key_leases_open = false;
        let generation = scheduler.generation;
        let final_save = (!close_service)
            .then(|| {
                scheduler.final_save.as_ref().and_then(|slot| {
                    (slot.generation == generation
                        && slot.state.is_running()
                        && !slot.state.cancelled.load(Ordering::Acquire))
                    .then(|| Arc::clone(&slot.state))
                })
            })
            .flatten();
        for state in scheduler.active.values() {
            if final_save
                .as_ref()
                .is_some_and(|final_save| Arc::ptr_eq(final_save, state))
                || scheduler
                    .external_publications
                    .get(&state.id)
                    .is_some_and(|publication| Arc::ptr_eq(publication, state))
            {
                continue;
            }
            state.mark_security_cancelled();
            if close_service {
                state.finish(Err(ServiceError::Closed));
            }
        }
        self.cancel_prepare_attempts();
        let root = self
            .session
            .as_ref()
            .and_then(|session| session.begin_lock());
        let eager_root = root.as_ref().map(Arc::clone);
        let grace_deadline = self
            .session
            .as_ref()
            .and_then(|session| std::time::Instant::now().checked_add(session.final_save_grace()));
        let force_reap_deadline =
            grace_deadline.and_then(|deadline| deadline.checked_add(EDITOR_FORCE_REAP_GRACE));
        if scheduler.lock_job.is_none() {
            scheduler.lock_job = Some(LockJob {
                generation,
                root,
                final_save,
                grace_deadline,
                force_reap_deadline,
            });
        }
        if scheduler.controls.global_notified != Some(generation) {
            scheduler.controls.global_notified = Some(generation);
            scheduler.controls.global_control = Some(PendingControl {
                control,
                generation,
                trusted_activity: false,
            });
        }
        self.scheduler_changed.notify_all();
        drop(scheduler);
        {
            let registry = lock(&self.transitions);
            for record in registry.records.values() {
                if record.kind == TransitionKind::Freshness
                    || record.state.load(Ordering::Acquire) != TRANSITION_CONSUMING
                {
                    continue;
                }
                if let Some(state) = lock(&record.operation_state)
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                {
                    state.mark_security_cancelled();
                    if close_service {
                        state.finish_transition(Err(ServiceError::Closed));
                    }
                    self.enqueue_lease_cancellation(&state);
                }
            }
        }
        if let Some(root) = eager_root
            && catch_unwind(AssertUnwindSafe(|| root.begin_close())).is_err()
            && let Some(session) = &self.session
        {
            session.mark_cleanup_required();
        }
    }

    fn shutdown(&self) {
        self.start_global_lock(Control::LockNow, true);
    }

    fn enforce_deadline(&self) -> Result<Option<std::time::Duration>, ServiceError> {
        let Some(session) = &self.session else {
            return Ok(None);
        };
        let now = match session.sample_now() {
            Ok(now) => now,
            Err(error) => {
                self.start_global_lock(Control::DeadlineExpired, false);
                return Err(error);
            }
        };
        self.enforce_deadline_at(now)
    }

    fn enforce_deadline_at(
        &self,
        now: std::time::Duration,
    ) -> Result<Option<std::time::Duration>, ServiceError> {
        let Some(session) = &self.session else {
            return Ok(None);
        };
        let observation = match session.observe_at(now) {
            Ok(observation) => observation,
            Err(error) => {
                self.start_global_lock(Control::DeadlineExpired, false);
                return Err(error);
            }
        };
        if !observation.warnings.is_empty() {
            let mut scheduler = lock(&self.scheduler);
            let generation = scheduler.generation;
            if session.current_generation() == Some(generation) {
                for warning in observation.warnings {
                    if scheduler.session_events.len()
                        == crate::MAX_WARNING_OFFSETS.saturating_mul(2)
                    {
                        scheduler.session_events.pop_front();
                    }
                    scheduler.session_events.push_back((generation, warning));
                }
                self.scheduler_changed.notify_all();
            }
        }
        if !observation.expired {
            return Ok(observation.next_wait);
        }
        self.start_global_lock(Control::DeadlineExpired, false);
        Ok(None)
    }

    fn enqueue_lease_cancellation(&self, state: &Arc<OperationState>) {
        if !state.mark_lease_cancellation_queued() {
            return;
        }
        let sender = lock(&self.cancellation_sender);
        if sender
            .as_ref()
            .is_none_or(|sender| sender.try_send(Arc::clone(state)).is_err())
        {
            drop(sender);
            self.shutdown();
        }
    }

    pub(crate) fn enqueue_security_cancellation(&self, state: &Arc<OperationState>) {
        self.enqueue_lease_cancellation(state);
    }

    fn cancel_nonfinal_operations(&self, final_save: Option<&Arc<OperationState>>) {
        let sender = lock(&self.cancellation_sender).as_ref().cloned();
        let mut dispatch_failed = sender.is_none();
        {
            let scheduler = lock(&self.scheduler);
            for state in scheduler.active.values() {
                if final_save.is_some_and(|final_save| Arc::ptr_eq(final_save, state)) {
                    continue;
                }
                if scheduler
                    .external_publications
                    .get(&state.id)
                    .is_some_and(|publication| Arc::ptr_eq(publication, state))
                {
                    continue;
                }
                state.mark_security_cancelled();
                if state.mark_lease_cancellation_queued()
                    && sender
                        .as_ref()
                        .is_none_or(|sender| sender.try_send(Arc::clone(state)).is_err())
                {
                    dispatch_failed = true;
                }
            }
        }
        if dispatch_failed {
            self.shutdown();
        }
    }

    fn process_lock_job(&self, generation: u64) {
        let job = {
            let mut scheduler = lock(&self.scheduler);
            if scheduler
                .lock_job
                .as_ref()
                .is_some_and(|job| job.generation == generation)
            {
                scheduler.lock_job.take()
            } else {
                None
            }
        };
        let Some(job) = job else {
            return;
        };
        // Cancellation state and the grace deadline must become authoritative
        // before any injected callback can block this security path.
        self.cancel_nonfinal_operations(job.final_save.as_ref());
        if let Some(final_save) = &job.final_save {
            let deadline = job.grace_deadline;
            loop {
                let still_armed = {
                    let scheduler = lock(&self.scheduler);
                    scheduler.final_save.as_ref().is_some_and(|slot| {
                        slot.generation == generation && Arc::ptr_eq(&slot.state, final_save)
                    })
                };
                if !still_armed
                    || final_save.is_terminal()
                    || final_save.cancelled.load(Ordering::Acquire)
                {
                    break;
                }
                let Some(deadline) = deadline else {
                    final_save.mark_cancelled();
                    break;
                };
                let now = std::time::Instant::now();
                if now >= deadline {
                    final_save.mark_cancelled();
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                let scheduler = lock(&self.scheduler);
                let _ = self
                    .scheduler_changed
                    .wait_timeout(scheduler, remaining)
                    .unwrap_or_else(|error| error.into_inner());
            }
            if !final_save.is_terminal() {
                final_save.mark_cancelled();
            }
        }
        // Revoke the root generation before invoking cleanup callbacks. This
        // keeps a stalled transition abort or lease cancellation from extending
        // the one permitted final-save grace period.
        if let Some(root) = &job.root
            && catch_unwind(AssertUnwindSafe(|| root.begin_adapter_close())).is_err()
            && let Some(session) = &self.session
        {
            session.mark_cleanup_required();
        }
        let mut editors_quiescent = true;
        if let Some(session) = &self.session {
            let mut callbacks_ok = session.request_editor_stop();
            let mut quiescent = false;
            loop {
                match session.editors_are_quiescent() {
                    EditorQuiescenceObservation::Known(true) => {
                        quiescent = true;
                        break;
                    }
                    EditorQuiescenceObservation::Known(false)
                    | EditorQuiescenceObservation::Unknown => {}
                    EditorQuiescenceObservation::Panicked => callbacks_ok = false,
                }
                let Some(deadline) = job.grace_deadline else {
                    break;
                };
                let now = std::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                let scheduler = lock(&self.scheduler);
                let _ = self
                    .scheduler_changed
                    .wait_timeout(
                        scheduler,
                        remaining.min(std::time::Duration::from_millis(10)),
                    )
                    .unwrap_or_else(|error| error.into_inner());
            }
            if !quiescent {
                callbacks_ok &= session.force_editor_stop();
                loop {
                    match session.editors_are_quiescent() {
                        EditorQuiescenceObservation::Known(true) => {
                            quiescent = true;
                            break;
                        }
                        EditorQuiescenceObservation::Known(false)
                        | EditorQuiescenceObservation::Unknown => {}
                        EditorQuiescenceObservation::Panicked => callbacks_ok = false,
                    }
                    let Some(deadline) = job.force_reap_deadline else {
                        break;
                    };
                    let now = std::time::Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let scheduler = lock(&self.scheduler);
                    let _ = self
                        .scheduler_changed
                        .wait_timeout(
                            scheduler,
                            deadline
                                .saturating_duration_since(now)
                                .min(std::time::Duration::from_millis(10)),
                        )
                        .unwrap_or_else(|error| error.into_inner());
                }
            }
            editors_quiescent = callbacks_ok && quiescent;
        }
        if let Some(final_save) = &job.final_save
            && final_save.cancelled.load(Ordering::Acquire)
        {
            self.enqueue_lease_cancellation(final_save);
        }
        let root_was_present = job.root.is_some();
        let close_failed = self
            .session
            .as_ref()
            .is_some_and(|session| session.close_root_for_lock(job.root.as_ref()));
        self.cancel_all_transitions();
        loop {
            let scheduler = lock(&self.scheduler);
            let publication_in_flight = scheduler
                .external_publications
                .values()
                .any(|state| state.session_generation == Some(generation));
            if !publication_in_flight {
                break;
            }
            let _scheduler = self
                .scheduler_changed
                .wait(scheduler)
                .unwrap_or_else(|error| error.into_inner());
        }
        self.cancel_nonfinal_operations(job.final_save.as_ref());
        debug_assert!(
            !lock(&self.scheduler)
                .external_publications
                .values()
                .any(|state| state.session_generation == Some(generation))
        );
        if let Some(session) = &self.session {
            session.finish_lock_after_close(root_was_present, close_failed, editors_quiescent);
        }
    }

    pub(crate) fn acquire_local_lease(
        &self,
        state: &Arc<OperationState>,
    ) -> Result<Box<dyn crate::LocalVaultLease>, ServiceError> {
        let generation = {
            let scheduler = lock(&self.scheduler);
            if scheduler.closed
                || !scheduler.key_leases_open
                || !state.is_running()
                || state.cancelled.load(Ordering::Acquire)
                || !scheduler
                    .active
                    .get(&state.id)
                    .is_some_and(|active| Arc::ptr_eq(active, state))
            {
                return Err(ServiceError::Locked);
            }
            state.session_generation.ok_or(ServiceError::Locked)?
        };
        let lease = match self
            .session
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .acquire_local(generation, state.repository_cancellation())
        {
            Ok(lease) => lease,
            Err(ServiceError::Locked) if !lock(&self.scheduler).key_leases_open => {
                state.mark_cancelled();
                return Err(ServiceError::Cancelled);
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = state.register_lease_cancellation(lease.cancellation_handle()) {
            lease.cancel();
            let _ = lease.finish();
            return Err(error);
        }
        Ok(lease)
    }

    pub(crate) fn operation_safe_boundary(
        &self,
        state: &Arc<OperationState>,
    ) -> Result<(), ServiceError> {
        if state.is_durable() {
            return Ok(());
        }
        if state.cancelled.load(Ordering::Acquire) {
            return Err(ServiceError::Cancelled);
        }
        let scheduler = lock(&self.scheduler);
        let final_save = scheduler
            .final_save
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(&slot.state, state));
        if (!scheduler.accepting && !final_save)
            || !scheduler
                .active
                .get(&state.id)
                .is_some_and(|active| Arc::ptr_eq(active, state))
        {
            drop(scheduler);
            state.mark_cancelled();
            return Err(ServiceError::Cancelled);
        }
        Ok(())
    }

    pub(crate) fn authorize_external_publication(
        &self,
        state: &Arc<OperationState>,
        publication: &mut dyn FnMut() -> Result<(), crate::HostPortError>,
    ) -> Result<(), crate::HostPortError> {
        let generation = {
            let mut scheduler = lock(&self.scheduler);
            if scheduler.closed
                || !scheduler.accepting
                || !scheduler.key_leases_open
                || !state.is_running()
                || state.is_durable()
                || state.cancelled.load(Ordering::Acquire)
                || state.session_generation != Some(scheduler.generation)
                || !scheduler
                    .active
                    .get(&state.id)
                    .is_some_and(|active| Arc::ptr_eq(active, state))
                || scheduler.external_publications.contains_key(&state.id)
            {
                return Err(crate::HostPortError::Cancelled);
            }
            let generation = scheduler.generation;
            scheduler
                .external_publications
                .insert(state.id, Arc::clone(state));
            self.scheduler_changed.notify_all();
            generation
        };
        let _registration = ExternalPublicationRegistration {
            service: self,
            state,
            generation,
        };
        let result = publication();
        if result.is_ok() {
            state.mark_irrevocable();
        }
        result
    }

    fn finish_external_publication(&self, state: &Arc<OperationState>, generation: u64) {
        let mut scheduler = lock(&self.scheduler);
        let exact = state.session_generation == Some(generation)
            && scheduler
                .external_publications
                .get(&state.id)
                .is_some_and(|registered| Arc::ptr_eq(registered, state));
        if exact {
            scheduler.external_publications.remove(&state.id);
            self.scheduler_changed.notify_all();
        }
    }

    pub(crate) fn acquire_replication_lease(
        &self,
        state: &Arc<OperationState>,
        backend: crate::ReplicationLimitProfile,
        operation: crate::ReplicationLimitProfile,
    ) -> Result<Box<dyn crate::ReplicationVaultLease>, ServiceError> {
        let generation = {
            let scheduler = lock(&self.scheduler);
            if scheduler.closed
                || !scheduler.key_leases_open
                || !state.is_running()
                || state.cancelled.load(Ordering::Acquire)
                || !scheduler
                    .active
                    .get(&state.id)
                    .is_some_and(|active| Arc::ptr_eq(active, state))
            {
                return Err(ServiceError::Locked);
            }
            state.session_generation.ok_or(ServiceError::Locked)?
        };
        let lease = self
            .session
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .acquire_replication(
                generation,
                backend,
                operation,
                state.repository_cancellation(),
            )?;
        if let Err(error) = state.register_lease_cancellation(lease.cancellation_handle()) {
            lease.cancel();
            let _ = lease.finish();
            return Err(error);
        }
        Ok(lease)
    }

    pub(crate) fn create_workspace(
        self: &Arc<Self>,
        state: &Arc<OperationState>,
        mode: crate::WorkspaceMode,
        repository_root: std::path::PathBuf,
    ) -> Result<crate::WorkspaceSession, ServiceError> {
        let generation = {
            let scheduler = lock(&self.scheduler);
            let generation = state.session_generation.ok_or(ServiceError::Locked)?;
            if scheduler.closed
                || !scheduler.key_leases_open
                || scheduler.generation != generation
                || !state.is_running()
                || state.cancelled.load(Ordering::Acquire)
                || !scheduler
                    .active
                    .get(&state.id)
                    .is_some_and(|active| Arc::ptr_eq(active, state))
            {
                return Err(ServiceError::Locked);
            }
            generation
        };
        let result = self
            .session
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .create_workspace(generation, mode, repository_root);
        if matches!(result, Err(ServiceError::CleanupRequired)) {
            self.latch_cleanup_required();
        }
        result
    }

    fn register_transition(
        self: &Arc<Self>,
        kind: TransitionKind,
        generation: u64,
        action: PendingAction,
        verifier: Option<SecretVerifier>,
        presentation: Option<crate::ports::RecoveryPresentationCell>,
        cancellation: &Arc<crate::RepositoryCancellation>,
    ) -> Result<Arc<TransitionRecord>, ServiceError> {
        let mut identity = lock(&self.identity);
        let (operation, next) = match self.candidate_id(&mut identity) {
            Ok(candidate) => candidate,
            Err(error) => {
                drop(identity);
                self.clear_prepare(kind, cancellation);
                self.abort_pending_action(action);
                return Err(error);
            }
        };
        let record = Arc::new(TransitionRecord {
            kind,
            generation,
            operation,
            state: AtomicU8::new(TRANSITION_PENDING),
            action: Mutex::new(Some(action)),
            verifier: Mutex::new(verifier),
            presentation,
            offered: AtomicU8::new(1),
            resolution: Mutex::new(None),
            resolution_changed: Condvar::new(),
            operation_state: Mutex::new(None),
        });
        let scheduler = lock(&self.scheduler);
        let mut registry = lock(&self.transitions);
        let slot = match kind {
            TransitionKind::Recovery => &mut registry.recovery_prepare,
            TransitionKind::Compromise => &mut registry.compromise_prepare,
            TransitionKind::Freshness => unreachable!(),
        };
        let exact_prepare = slot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, cancellation));
        let valid_binding = match kind {
            TransitionKind::Recovery => self.session.as_ref().is_some_and(|session| {
                !scheduler.closed
                    && !scheduler.unlock_in_progress
                    && scheduler.lock_job.is_none()
                    && session.state() == SessionState::Locked
                    && session.binding_epoch() == generation
            }),
            TransitionKind::Compromise => self.session.as_ref().is_some_and(|session| {
                !scheduler.closed
                    && scheduler.accepting
                    && scheduler.key_leases_open
                    && scheduler.generation == generation
                    && session.current_generation() == Some(generation)
            }),
            TransitionKind::Freshness => false,
        };
        if exact_prepare {
            *slot = None;
        }
        let transition_full = registry.records.len() == registry.capacity;
        if !exact_prepare || cancellation.is_cancelled() || !valid_binding || transition_full {
            drop(registry);
            drop(scheduler);
            drop(identity);
            if let Some(action) = lock(&record.action).take() {
                self.abort_pending_action(action);
            }
            return Err(if transition_full {
                ServiceError::Busy
            } else if cancellation.is_cancelled() {
                ServiceError::Cancelled
            } else {
                ServiceError::StaleCapability
            });
        }
        registry.records.insert(operation, Arc::clone(&record));
        identity.next = next;
        Ok(record)
    }

    fn claim_security_transition(
        self: &Arc<Self>,
        record: &Arc<TransitionRecord>,
    ) -> Result<(PendingAction, Arc<OperationState>), ServiceError> {
        let state = Arc::new(OperationState::new(
            record.operation,
            self.config.event_capacity,
            Some(record.generation),
            true,
        )?);
        let scheduler = lock(&self.scheduler);
        let valid = match record.kind {
            TransitionKind::Recovery => self.session.as_ref().is_some_and(|session| {
                !scheduler.closed
                    && !scheduler.unlock_in_progress
                    && scheduler.lock_job.is_none()
                    && session.state() == SessionState::Locked
                    && session.binding_epoch() == record.generation
            }),
            TransitionKind::Compromise => self.session.as_ref().is_some_and(|session| {
                !scheduler.closed
                    && scheduler.accepting
                    && scheduler.key_leases_open
                    && scheduler.generation == record.generation
                    && session.current_generation() == Some(record.generation)
            }),
            TransitionKind::Freshness => false,
        };
        if !valid {
            return Err(ServiceError::StaleCapability);
        }
        let mut registry = lock(&self.transitions);
        let exact = registry
            .records
            .get(&record.operation)
            .is_some_and(|active| Arc::ptr_eq(active, record));
        if !exact
            || record
                .state
                .compare_exchange(
                    TRANSITION_PENDING,
                    TRANSITION_CONSUMING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return Err(ServiceError::StaleCapability);
        }
        let Some(action) = lock(&record.action).take() else {
            record.state.store(TRANSITION_COMPLETED, Ordering::Release);
            registry.records.remove(&record.operation);
            return Err(ServiceError::StaleCapability);
        };
        *lock(&record.operation_state) = Some(Arc::downgrade(&state));
        self.scheduler_changed.notify_all();
        drop(registry);
        drop(scheduler);
        Ok((action, state))
    }

    fn abort_pending_action(&self, action: PendingAction) {
        let failed = catch_unwind(AssertUnwindSafe(|| match action {
            PendingAction::Recovery(action) => action.abort().is_err(),
            PendingAction::Compromise(action) => action.abort().is_err(),
            PendingAction::Freshness { action, .. } => action.abort().is_err(),
        }))
        .unwrap_or(true);
        if failed {
            self.latch_cleanup_required();
        }
    }

    fn discard_transition_execution(&self, state: &Arc<OperationState>, error: ServiceError) {
        state.finish_transition(Err(error));
        self.scheduler_changed.notify_all();
    }

    fn finish_transition_execution(
        &self,
        state: &Arc<OperationState>,
        outcome: Result<(), ServiceError>,
    ) {
        state.finish_transition(outcome);
        self.scheduler_changed.notify_all();
    }

    pub(crate) fn await_freshness_acknowledgement(
        self: &Arc<Self>,
        state: &Arc<OperationState>,
        action: Box<dyn PendingFreshnessAction>,
    ) -> Result<(), ServiceError> {
        let view = match catch_unwind(AssertUnwindSafe(|| action.view())) {
            Ok(view) => view,
            Err(_) => {
                let _ = catch_unwind(AssertUnwindSafe(|| action.abort()));
                self.latch_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        let operation_binding = state.repository_cancellation();
        let binding_matches = catch_unwind(AssertUnwindSafe(|| {
            std::ptr::eq(action.operation_cancellation(), operation_binding.as_ref())
        }));
        match binding_matches {
            Ok(true) => {}
            Ok(false) => {
                self.abort_pending_action(PendingAction::Freshness { action, view });
                return Err(ServiceError::StaleCapability);
            }
            Err(_) => {
                let _ = catch_unwind(AssertUnwindSafe(|| action.abort()));
                self.latch_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        }
        let generation = state.session_generation.ok_or(ServiceError::Locked)?;
        {
            let scheduler = lock(&self.scheduler);
            if scheduler.closed
                || !scheduler.key_leases_open
                || scheduler.generation != generation
                || !state.is_running()
                || state.cancelled.load(Ordering::Acquire)
                || !scheduler
                    .active
                    .get(&state.id)
                    .is_some_and(|active| Arc::ptr_eq(active, state))
            {
                drop(scheduler);
                self.abort_pending_action(PendingAction::Freshness { action, view });
                return Err(ServiceError::StaleCapability);
            }
        }
        let record = Arc::new(TransitionRecord {
            kind: TransitionKind::Freshness,
            generation,
            operation: state.id,
            state: AtomicU8::new(TRANSITION_PENDING),
            action: Mutex::new(Some(PendingAction::Freshness { action, view })),
            verifier: Mutex::new(None),
            presentation: None,
            offered: AtomicU8::new(0),
            resolution: Mutex::new(None),
            resolution_changed: Condvar::new(),
            operation_state: Mutex::new(Some(Arc::downgrade(state))),
        });
        {
            let mut registry = lock(&self.transitions);
            if registry.records.len() == registry.capacity
                || registry.records.contains_key(&state.id)
            {
                drop(registry);
                if let Some(PendingAction::Freshness { action, .. }) = lock(&record.action).take() {
                    self.abort_pending_action(PendingAction::Freshness { action, view });
                }
                return Err(ServiceError::Busy);
            }
            registry.records.insert(state.id, Arc::clone(&record));
        }
        if let Err(error) = state.publish(crate::OperationEvent::Warning(
            WarningCode::FreshnessUnprovable,
        )) {
            self.cancel_transition(&record);
            return Err(error);
        }
        self.scheduler_changed.notify_all();
        let mut resolution = lock(&record.resolution);
        loop {
            if let Some(result) = resolution.take() {
                return result;
            }
            if state.cancelled.load(Ordering::Acquire) {
                drop(resolution);
                self.cancel_transition(&record);
                resolution = lock(&record.resolution);
                continue;
            }
            resolution = record
                .resolution_changed
                .wait(resolution)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    fn claim_transition(
        &self,
        record: &Arc<TransitionRecord>,
    ) -> Result<PendingAction, ServiceError> {
        let scheduler = lock(&self.scheduler);
        let valid_binding = match record.kind {
            TransitionKind::Recovery => self.session.as_ref().is_some_and(|session| {
                session.state() == SessionState::Locked
                    && session.binding_epoch() == record.generation
                    && scheduler.lock_job.is_none()
            }),
            TransitionKind::Compromise => self.session.as_ref().is_some_and(|session| {
                scheduler.accepting
                    && scheduler.key_leases_open
                    && scheduler.generation == record.generation
                    && session.current_generation() == Some(record.generation)
            }),
            TransitionKind::Freshness => {
                let exact_operation = lock(&record.operation_state).as_ref().is_some_and(|weak| {
                    weak.upgrade().is_some_and(|state| {
                        state.is_running()
                            && !state.cancelled.load(Ordering::Acquire)
                            && scheduler
                                .active
                                .get(&record.operation)
                                .is_some_and(|active| Arc::ptr_eq(active, &state))
                    })
                });
                let valid = self.session.as_ref().is_some_and(|session| {
                    scheduler.accepting
                        && scheduler.key_leases_open
                        && scheduler.generation == record.generation
                        && session.current_generation() == Some(record.generation)
                        && exact_operation
                });
                #[cfg(test)]
                let valid = valid
                    || (self.session.is_none()
                        && scheduler.accepting
                        && scheduler.key_leases_open
                        && scheduler.generation == record.generation
                        && exact_operation);
                valid
            }
        };
        if !valid_binding {
            return Err(ServiceError::StaleCapability);
        }
        let registry = lock(&self.transitions);
        let exact = registry
            .records
            .get(&record.operation)
            .is_some_and(|active| Arc::ptr_eq(active, record));
        if !exact
            || record
                .state
                .compare_exchange(
                    TRANSITION_PENDING,
                    TRANSITION_CONSUMING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return Err(ServiceError::StaleCapability);
        }
        drop(registry);
        drop(scheduler);
        lock(&record.action)
            .take()
            .ok_or(ServiceError::StaleCapability)
    }

    fn complete_transition(&self, record: &Arc<TransitionRecord>) {
        drop(lock(&record.verifier).take());
        clear_presentation(record);
        let mut registry = lock(&self.transitions);
        let exact = registry
            .records
            .get(&record.operation)
            .is_some_and(|active| Arc::ptr_eq(active, record));
        if exact
            && record
                .state
                .compare_exchange(
                    TRANSITION_CONSUMING,
                    TRANSITION_COMPLETED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            registry.records.remove(&record.operation);
        }
    }

    fn cancel_transition(&self, record: &Arc<TransitionRecord>) {
        let action = {
            let mut registry = lock(&self.transitions);
            let exact = registry
                .records
                .get(&record.operation)
                .is_some_and(|active| Arc::ptr_eq(active, record));
            if !exact
                || record
                    .state
                    .compare_exchange(
                        TRANSITION_PENDING,
                        TRANSITION_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
            {
                return;
            }
            registry.records.remove(&record.operation);
            drop(registry);
            drop(lock(&record.verifier).take());
            clear_presentation(record);
            lock(&record.action).take()
        };
        self.abort_cancelled_transition(record, action);
    }

    fn abort_cancelled_transition(
        &self,
        record: &Arc<TransitionRecord>,
        action: Option<PendingAction>,
    ) {
        let failed = catch_unwind(AssertUnwindSafe(|| match action {
            Some(PendingAction::Recovery(action)) => action.abort().is_err(),
            Some(PendingAction::Compromise(action)) => action.abort().is_err(),
            Some(PendingAction::Freshness { action, .. }) => action.abort().is_err(),
            None => false,
        }))
        .unwrap_or(true);
        if failed {
            self.latch_cleanup_required();
        }
        *lock(&record.resolution) = Some(Err(ServiceError::Cancelled));
        record.resolution_changed.notify_all();
    }

    fn cancel_transition_for_operation(&self, operation: OperationId) {
        let record = lock(&self.transitions).records.get(&operation).cloned();
        if let Some(record) = record {
            self.cancel_transition(&record);
        }
    }

    fn cancel_all_transitions(&self) {
        let mut detached = {
            let mut registry = lock(&self.transitions);
            let mut detached = std::mem::take(&mut registry.cancellation_scratch);
            registry.records.retain(|_, record| {
                let claimed = record
                    .state
                    .compare_exchange(
                        TRANSITION_PENDING,
                        TRANSITION_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok();
                if claimed {
                    detached.push(Arc::clone(record));
                }
                !claimed
            });
            detached
        };
        while let Some(record) = detached.pop() {
            drop(lock(&record.verifier).take());
            clear_presentation(&record);
            let action = lock(&record.action).take();
            self.abort_cancelled_transition(&record, action);
        }
        lock(&self.transitions).cancellation_scratch = detached;
    }
}

struct ServiceClient {
    inner: Arc<ServiceInner>,
}

impl Drop for ServiceClient {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}

/// Cloneable synchronous facade for submitting work and priority controls.
#[derive(Clone)]
pub struct ServiceHandle {
    client: Arc<ServiceClient>,
}

impl ServiceHandle {
    pub fn new(executor: Arc<dyn OperationExecutor>) -> Result<Self, ServiceError> {
        Self::with_components(
            ServiceConfig::default(),
            executor,
            Arc::new(OsOperationIdRandom),
        )
    }

    pub fn with_components(
        config: ServiceConfig,
        executor: Arc<dyn OperationExecutor>,
        random: Arc<dyn OperationIdRandom>,
    ) -> Result<Self, ServiceError> {
        Self::build(config, executor, random, None)
    }

    pub fn with_session_components(
        config: ServiceConfig,
        executor: Arc<dyn OperationExecutor>,
        random: Arc<dyn OperationIdRandom>,
        components: SessionComponents,
    ) -> Result<(Self, TrustedActivityHandle), ServiceError> {
        let session = SessionManager::new(components)?;
        let service = Self::build(config, executor, random, Some(Arc::clone(&session)))?;
        let trusted_service = Arc::downgrade(&service.client.inner);
        Ok((
            service,
            TrustedActivityHandle {
                service: trusted_service,
            },
        ))
    }

    /// Builds an unlock-aware facade whose status and list commands use production leases.
    pub fn with_local_use_cases(
        config: ServiceConfig,
        executor: Arc<dyn OperationExecutor>,
        random: Arc<dyn OperationIdRandom>,
        components: SessionComponents,
    ) -> Result<(Self, TrustedActivityHandle), ServiceError> {
        Self::with_session_components(config, executor, random, components)
    }

    fn build(
        config: ServiceConfig,
        executor: Arc<dyn OperationExecutor>,
        random: Arc<dyn OperationIdRandom>,
        session: Option<Arc<SessionManager>>,
    ) -> Result<Self, ServiceError> {
        let mut scheduler = SchedulerState::new(config)?;
        if session.is_some() {
            scheduler.accepting = false;
            scheduler.key_leases_open = false;
        }
        let (ordinary_sender, ordinary_receiver) = bounded(config.queue_capacity);
        let (worker_sender, worker_receiver) = bounded(config.workers);
        let cancellation_capacity = active_capacity(config)?
            .checked_add(2)
            .ok_or(ServiceError::InvalidConfiguration)?;
        let observer_capacity = active_capacity(config)?
            .checked_add(3)
            .ok_or(ServiceError::InvalidConfiguration)?;
        let (cancellation_sender, cancellation_receiver) = bounded(cancellation_capacity);
        let (control_sender, control_receiver) = bounded(observer_capacity);
        let (security_sender, security_receiver) = bounded::<SecurityJob>(1);
        let inner = Arc::new(ServiceInner {
            config,
            executor,
            random,
            scheduler: Mutex::new(scheduler),
            scheduler_changed: Condvar::new(),
            ordinary_sender: Mutex::new(Some(ordinary_sender)),
            ordinary_receiver,
            worker_sender: Mutex::new(Some(worker_sender)),
            cancellation_sender: Mutex::new(Some(cancellation_sender)),
            control_sender: Mutex::new(Some(control_sender)),
            security_sender: Mutex::new(Some(security_sender)),
            security_busy: AtomicBool::new(false),
            identity: Mutex::new(IdentityState {
                nonce: None,
                next: 0,
            }),
            session,
            transitions: Mutex::new(TransitionRegistry::new(config.completed_capacity)?),
        });

        thread::Builder::new()
            .name("notecrypt-service-security-worker".to_owned())
            .spawn(move || {
                while let Ok(job) = security_receiver.recv() {
                    job();
                }
            })
            .map_err(|_| {
                inner.shutdown();
                ServiceError::InvalidConfiguration
            })?;

        for index in 0..config.workers {
            let worker_inner = Arc::clone(&inner);
            let receiver = worker_receiver.clone();
            thread::Builder::new()
                .name(format!("notecrypt-service-worker-{index}"))
                .spawn(move || {
                    let panic_inner = Arc::clone(&worker_inner);
                    if catch_unwind(AssertUnwindSafe(|| worker_loop(worker_inner, receiver)))
                        .is_err()
                    {
                        panic_inner.shutdown();
                    }
                })
                .map_err(|_| {
                    inner.shutdown();
                    ServiceError::InvalidConfiguration
                })?;
        }
        let observer_inner = Arc::clone(&inner);
        thread::Builder::new()
            .name("notecrypt-service-control-observer".to_owned())
            .spawn(move || control_observer_loop(observer_inner, control_receiver))
            .map_err(|_| {
                inner.shutdown();
                ServiceError::InvalidConfiguration
            })?;
        thread::Builder::new()
            .name("notecrypt-service-cancellation".to_owned())
            .spawn(move || cancellation_loop(cancellation_receiver))
            .map_err(|_| {
                inner.shutdown();
                ServiceError::InvalidConfiguration
            })?;
        let coordinator_inner = Arc::clone(&inner);
        thread::Builder::new()
            .name("notecrypt-service-coordinator".to_owned())
            .spawn(move || {
                let panic_inner = Arc::clone(&coordinator_inner);
                if catch_unwind(AssertUnwindSafe(|| coordinator_loop(coordinator_inner))).is_err() {
                    panic_inner.shutdown();
                }
            })
            .map_err(|_| {
                inner.shutdown();
                ServiceError::InvalidConfiguration
            })?;
        if inner.session.is_some() {
            let deadline_inner = Arc::clone(&inner);
            thread::Builder::new()
                .name("notecrypt-service-deadline".to_owned())
                .spawn(move || {
                    let panic_inner = Arc::clone(&deadline_inner);
                    if catch_unwind(AssertUnwindSafe(|| deadline_loop(deadline_inner))).is_err() {
                        panic_inner.shutdown();
                    }
                })
                .map_err(|_| {
                    inner.shutdown();
                    ServiceError::InvalidConfiguration
                })?;
        }

        Ok(Self {
            client: Arc::new(ServiceClient { inner }),
        })
    }

    pub fn submit(&self, command: Command) -> Result<OperationHandle, ServiceError> {
        let inner = &self.client.inner;
        inner.enforce_deadline()?;
        let resets_inactivity = command.resets_inactivity();
        let admission_generation = {
            let scheduler = lock(&inner.scheduler);
            if scheduler.closed {
                return Err(ServiceError::Closed);
            }
            if !scheduler.accepting {
                return Err(ServiceError::Locked);
            }
            if scheduler.active.len() == active_capacity(inner.config)? {
                return Err(ServiceError::Busy);
            }
            let sender_guard = lock(&inner.ordinary_sender);
            let Some(sender) = sender_guard.as_ref() else {
                return Err(ServiceError::Closed);
            };
            if sender.is_full() {
                return Err(ServiceError::Busy);
            }
            scheduler.generation
        };
        let mut identity = lock(&inner.identity);
        let (id, next_identity) = inner.candidate_id(&mut identity)?;
        let activity_sample = if resets_inactivity {
            if let Some(session) = &inner.session {
                let sample = match session.sample_now() {
                    Ok(sample) => sample,
                    Err(error) => {
                        inner.start_global_lock(Control::DeadlineExpired, false);
                        return Err(error);
                    }
                };
                inner.enforce_deadline_at(sample)?;
                Some(sample)
            } else {
                None
            }
        } else {
            inner.enforce_deadline()?;
            None
        };
        let session_generation = inner
            .session
            .as_ref()
            .and_then(|session| session.current_generation());
        let state = Arc::new(OperationState::new(
            id,
            inner.config.event_capacity,
            session_generation,
            resets_inactivity,
        )?);
        let mut scheduler = lock(&inner.scheduler);
        if scheduler.closed {
            return Err(ServiceError::Closed);
        }
        if !scheduler.accepting {
            return Err(ServiceError::Locked);
        }
        if scheduler.generation != admission_generation {
            return Err(ServiceError::StaleCapability);
        }
        if scheduler.active.len() == active_capacity(inner.config)? {
            return Err(ServiceError::Busy);
        }
        let sender_guard = lock(&inner.ordinary_sender);
        let Some(sender) = sender_guard.as_ref() else {
            return Err(ServiceError::Closed);
        };
        if sender.is_full() {
            return Err(ServiceError::Busy);
        }
        if let (Some(session), Some(sample)) = (&inner.session, activity_sample) {
            if let Err(error) = session.record_trusted_activity_at(sample) {
                drop(sender_guard);
                drop(scheduler);
                inner.start_global_lock(Control::DeadlineExpired, false);
                return Err(error);
            }
            scheduler.session_events.retain(|(_, event)| {
                !matches!(
                    event,
                    SessionEvent::LockWarning {
                        deadline: crate::SessionDeadlineKind::Inactivity,
                        ..
                    }
                )
            });
        }
        scheduler.active.insert(id, Arc::clone(&state));
        let item = WorkItem {
            payload: WorkPayload::Command(command),
            state: Arc::clone(&state),
        };
        match sender.try_send(item) {
            Ok(()) => {
                identity.next = next_identity;
                inner.scheduler_changed.notify_all();
                Ok(OperationHandle::new(state, Arc::downgrade(inner)))
            }
            Err(TrySendError::Full(_)) => {
                scheduler.active.remove(&id);
                Err(ServiceError::Busy)
            }
            Err(TrySendError::Disconnected(_)) => {
                scheduler.active.remove(&id);
                Err(ServiceError::Closed)
            }
        }
    }

    pub fn control(&self, control: Control) -> Result<(), ServiceError> {
        let inner = &self.client.inner;
        if control.is_global() {
            inner.start_global_lock(control, false);
            return Ok(());
        }
        let mut scheduler = lock(&inner.scheduler);
        let mut mailbox_overflow = false;
        if scheduler.closed {
            return Err(ServiceError::Closed);
        }
        let generation = scheduler.generation;

        match control {
            Control::Cancel(id) => {
                let Some(state) = scheduler.active.get(&id).cloned() else {
                    return Ok(());
                };
                state.mark_cancelled();
                if !state
                    .cancel_notification_pending
                    .swap(true, Ordering::AcqRel)
                {
                    mailbox_overflow = !scheduler.controls.push(control, generation, false);
                }
            }
            Control::UserActivity
                if scheduler.controls.untrusted_activity_pending != Some(generation) =>
            {
                scheduler.controls.untrusted_activity_pending = Some(generation);
                mailbox_overflow = !scheduler.controls.push(control, generation, false);
            }
            _ => {}
        }
        inner.scheduler_changed.notify_all();
        drop(scheduler);
        if mailbox_overflow {
            inner.shutdown();
        }
        Ok(())
    }

    pub fn snapshot(&self) -> ServiceSnapshot {
        let _ = self.client.inner.enforce_deadline();
        let scheduler = lock(&self.client.inner.scheduler);
        let queued_operations = scheduler
            .active
            .values()
            .filter(|state| state.is_accepted())
            .count();
        let running_operations = scheduler
            .active
            .values()
            .filter(|state| state.is_running())
            .count();
        let active_operations = queued_operations + running_operations;
        ServiceSnapshot {
            session_state: self
                .client
                .inner
                .session
                .as_ref()
                .map_or(SessionState::Unlocked, |session| session.state()),
            accepting_operations: scheduler.accepting,
            key_leases_open: scheduler.key_leases_open,
            queued_operations,
            running_operations,
            active_operations,
            retained_completed_operations: scheduler.completed.len(),
            closed: scheduler.closed,
        }
    }

    pub fn shutdown(&self) {
        self.client.inner.shutdown();
    }

    pub fn unlock_with_recovery(
        &self,
        secret: RecoverySecretInput,
    ) -> Result<SessionSummary, ServiceError> {
        let service = self.clone();
        self.run_security_job(move || service.unlock_with_recovery_on_security_worker(secret))
    }

    fn unlock_with_recovery_on_security_worker(
        &self,
        secret: RecoverySecretInput,
    ) -> Result<SessionSummary, ServiceError> {
        let inner = &self.client.inner;
        let session = inner
            .session
            .as_ref()
            .ok_or(ServiceError::InvalidConfiguration)?;
        {
            let mut scheduler = lock(&inner.scheduler);
            if scheduler.closed
                || scheduler.unlock_in_progress
                || !scheduler.active.is_empty()
                || scheduler.lock_job.is_some()
                || scheduler.observer_in_flight != 0
            {
                return Err(ServiceError::Locked);
            }
            let transitions = lock(&inner.transitions);
            if transitions.recovery_prepare.is_some()
                || transitions
                    .records
                    .values()
                    .any(|record| record.kind == TransitionKind::Recovery)
            {
                return Err(ServiceError::Busy);
            }
            drop(transitions);
            scheduler.unlock_in_progress = true;
        }
        let summary = match session.unlock(secret) {
            Ok(summary) => summary,
            Err(error) => {
                lock(&inner.scheduler).unlock_in_progress = false;
                inner.scheduler_changed.notify_all();
                return Err(error);
            }
        };
        let mut scheduler = lock(&inner.scheduler);
        scheduler.unlock_in_progress = false;
        if scheduler.closed
            || session.state() != SessionState::Unlocked
            || !scheduler.active.is_empty()
            || scheduler.lock_job.is_some()
        {
            drop(scheduler);
            inner.start_global_lock(Control::LockNow, false);
            return Err(ServiceError::Cancelled);
        }
        scheduler.generation = summary.generation();
        scheduler
            .controls
            .reset_for_generation(summary.generation());
        scheduler.session_events.clear();
        scheduler.final_save = None;
        scheduler.accepting = true;
        scheduler.key_leases_open = true;
        inner.scheduler_changed.notify_all();
        Ok(summary)
    }

    pub fn retry_cleanup(&self) -> Result<(), ServiceError> {
        {
            let scheduler = lock(&self.client.inner.scheduler);
            if scheduler.lock_job.is_some() || scheduler.unlock_in_progress {
                return Err(ServiceError::Busy);
            }
        }
        self.client
            .inner
            .session
            .as_ref()
            .ok_or(ServiceError::InvalidConfiguration)?
            .retry_cleanup()
    }

    pub fn try_next_session_event(&self) -> Option<SessionEvent> {
        let _ = self.client.inner.enforce_deadline();
        let mut scheduler = lock(&self.client.inner.scheduler);
        let generation = scheduler.generation;
        while let Some((event_generation, event)) = scheduler.session_events.pop_front() {
            if event_generation == generation {
                return Some(event);
            }
        }
        None
    }

    pub fn wait_next_session_event(&self, timeout: std::time::Duration) -> Option<SessionEvent> {
        let deadline = std::time::Instant::now().checked_add(timeout)?;
        loop {
            if let Some(event) = self.try_next_session_event() {
                return Some(event);
            }
            let scheduler = lock(&self.client.inner.scheduler);
            if scheduler.closed {
                return None;
            }
            let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
            let (_scheduler, timed_out) = self
                .client
                .inner
                .scheduler_changed
                .wait_timeout(scheduler, remaining)
                .unwrap_or_else(|error| error.into_inner());
            if timed_out.timed_out() {
                return self.try_next_session_event();
            }
        }
    }

    pub fn begin_recovery_initialization(
        &self,
        request: BeginRecoveryInitialization,
    ) -> Result<
        (
            PendingRecoveryInitialization,
            Option<RecoverySecretPresentation>,
        ),
        ServiceError,
    > {
        let service = self.clone();
        self.run_security_job(move || {
            service.begin_recovery_initialization_on_security_worker(request)
        })
    }

    fn begin_recovery_initialization_on_security_worker(
        &self,
        request: BeginRecoveryInitialization,
    ) -> Result<
        (
            PendingRecoveryInitialization,
            Option<RecoverySecretPresentation>,
        ),
        ServiceError,
    > {
        let inner = &self.client.inner;
        let session = inner
            .session
            .as_ref()
            .ok_or(ServiceError::InvalidConfiguration)?;
        if session.state() != SessionState::Locked {
            return Err(ServiceError::Locked);
        }
        let generation = session.binding_epoch();
        let cancel = inner.begin_prepare(TransitionKind::Recovery, generation)?;
        let prepared_result = catch_unwind(AssertUnwindSafe(|| {
            session
                .repository()
                .begin_recovery_initialization(request, cancel.as_ref())
                .map_err(crate::session::map_repository_error)
        }));
        let prepare_active = inner.prepare_is_active(TransitionKind::Recovery, &cancel);
        let prepared = match prepared_result {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => {
                inner.clear_prepare(TransitionKind::Recovery, &cancel);
                return Err(error);
            }
            Err(_) => {
                inner.clear_prepare(TransitionKind::Recovery, &cancel);
                inner.latch_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        if !prepare_active
            || session.state() != SessionState::Locked
            || session.binding_epoch() != generation
        {
            inner.clear_prepare(TransitionKind::Recovery, &cancel);
            inner.abort_pending_action(PendingAction::Recovery(prepared.action));
            return Err(ServiceError::StaleCapability);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        let entropy = catch_unwind(AssertUnwindSafe(|| fill_security_entropy(&mut *key)))
            .unwrap_or(Err(ServiceError::EntropyUnavailable));
        if let Err(error) = entropy {
            inner.clear_prepare(TransitionKind::Recovery, &cancel);
            inner.abort_pending_action(PendingAction::Recovery(prepared.action));
            return Err(error);
        }
        let (presentation_secret, expected) = if prepared.generated {
            let (payload, expected) = prepared.secret.into_presentation_payload(&key);
            (Some(Arc::new(Mutex::new(Some(payload)))), expected)
        } else {
            (None, prepared.secret.into_verifier(&key))
        };
        let record = inner.register_transition(
            TransitionKind::Recovery,
            generation,
            PendingAction::Recovery(prepared.action),
            Some(SecretVerifier { key, expected }),
            presentation_secret.as_ref().map(Arc::clone),
            &cancel,
        )?;
        let presentation = presentation_secret.map(RecoverySecretPresentation::from_shared);
        Ok((
            PendingRecoveryInitialization::new(inner, record),
            presentation,
        ))
    }

    pub fn confirm_recovery_initialization(
        &self,
        pending: PendingRecoveryInitialization,
        confirmation: RecoverySecretInput,
    ) -> Result<VaultSummary, ServiceError> {
        let service = self.clone();
        self.run_security_job(move || {
            service.confirm_recovery_initialization_on_security_worker(pending, confirmation)
        })
    }

    fn confirm_recovery_initialization_on_security_worker(
        &self,
        mut pending: PendingRecoveryInitialization,
        confirmation: RecoverySecretInput,
    ) -> Result<VaultSummary, ServiceError> {
        let record = pending.claim_for(&self.client.inner)?;
        let (action, state) = self.client.inner.claim_security_transition(&record)?;
        pending.disarm();
        let PendingAction::Recovery(action) = action else {
            self.client
                .inner
                .discard_transition_execution(&state, ServiceError::StaleCapability);
            self.client.inner.complete_transition(&record);
            return Err(ServiceError::StaleCapability);
        };
        clear_presentation(&record);
        let verifier = lock(&record.verifier).take();
        let Some(verifier) = verifier else {
            self.client
                .inner
                .abort_pending_action(PendingAction::Recovery(action));
            self.client
                .inner
                .discard_transition_execution(&state, ServiceError::StaleCapability);
            self.client.inner.complete_transition(&record);
            return Err(ServiceError::StaleCapability);
        };
        let confirmation = match confirmation.verify_and_retain(&verifier.key, &verifier.expected) {
            Ok(confirmation) => confirmation,
            Err(()) => {
                drop(verifier);
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Recovery(action));
                self.client
                    .inner
                    .discard_transition_execution(&state, ServiceError::AuthenticationFailed);
                self.client.inner.complete_transition(&record);
                return Err(ServiceError::AuthenticationFailed);
            }
        };
        drop(verifier);
        let cancellation = match catch_unwind(AssertUnwindSafe(|| action.cancellation_handle())) {
            Ok(cancellation) => cancellation,
            Err(_) => {
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Recovery(action));
                self.client
                    .inner
                    .discard_transition_execution(&state, ServiceError::CleanupRequired);
                self.client.inner.complete_transition(&record);
                self.client.inner.latch_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        if let Err(error) = state.register_lease_cancellation(cancellation) {
            self.client
                .inner
                .abort_pending_action(PendingAction::Recovery(action));
            self.client
                .inner
                .discard_transition_execution(&state, error);
            self.client.inner.complete_transition(&record);
            return Err(error);
        }
        if !state.mark_running() {
            self.client
                .inner
                .abort_pending_action(PendingAction::Recovery(action));
            self.client
                .inner
                .discard_transition_execution(&state, ServiceError::StaleCapability);
            self.client.inner.complete_transition(&record);
            return Err(ServiceError::StaleCapability);
        }
        let repository_cancellation = state.repository_cancellation();
        let result = match catch_unwind(AssertUnwindSafe(|| {
            action.confirm(confirmation, repository_cancellation.as_ref())
        })) {
            Ok(result) => result.map_err(crate::session::map_repository_error),
            Err(_) => {
                self.client.inner.latch_cleanup_required();
                Err(ServiceError::CleanupRequired)
            }
        };
        self.client.inner.finish_transition_execution(
            &state,
            result.as_ref().map(|_| ()).map_err(|error| *error),
        );
        if matches!(result, Err(ServiceError::CleanupRequired)) {
            self.client.inner.latch_cleanup_required();
        }
        self.client.inner.complete_transition(&record);
        result
    }

    fn run_security_job<T: Send + 'static>(
        &self,
        action: impl FnOnce() -> Result<T, ServiceError> + Send + 'static,
    ) -> Result<T, ServiceError> {
        if self
            .client
            .inner
            .security_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ServiceError::Busy);
        }
        let (result_sender, result_receiver) = bounded(1);
        let inner = Arc::clone(&self.client.inner);
        let job: SecurityJob = Box::new(move || {
            let result = catch_unwind(AssertUnwindSafe(action)).unwrap_or_else(|_| {
                inner.latch_cleanup_required();
                Err(ServiceError::CleanupRequired)
            });
            inner.security_busy.store(false, Ordering::Release);
            let _ = result_sender.send(result);
        });
        let security_sender = lock(&self.client.inner.security_sender);
        let Some(sender) = security_sender.as_ref() else {
            self.client
                .inner
                .security_busy
                .store(false, Ordering::Release);
            return Err(ServiceError::Closed);
        };
        match sender.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.client
                    .inner
                    .security_busy
                    .store(false, Ordering::Release);
                return Err(ServiceError::Busy);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.client
                    .inner
                    .security_busy
                    .store(false, Ordering::Release);
                return Err(ServiceError::Closed);
            }
        }
        drop(security_sender);
        result_receiver.recv().unwrap_or(Err(ServiceError::Closed))
    }

    pub fn cancel_recovery_initialization(
        &self,
        mut pending: PendingRecoveryInitialization,
    ) -> Result<(), ServiceError> {
        let record = pending.claim_for(&self.client.inner)?;
        self.client.inner.cancel_transition(&record);
        pending.disarm();
        Ok(())
    }

    pub fn begin_compromise_rekey(
        &self,
        request: BeginCompromiseRekey,
    ) -> Result<(PendingCompromiseRekey, Option<RecoverySecretPresentation>), ServiceError> {
        let inner = &self.client.inner;
        let session = inner
            .session
            .as_ref()
            .ok_or(ServiceError::InvalidConfiguration)?;
        let generation = {
            let scheduler = lock(&inner.scheduler);
            let generation = session.current_generation().ok_or(ServiceError::Locked)?;
            if !scheduler.accepting
                || !scheduler.key_leases_open
                || scheduler.generation != generation
            {
                return Err(ServiceError::Locked);
            }
            generation
        };
        let cancel = inner.begin_prepare(TransitionKind::Compromise, generation)?;
        let prepared_result = catch_unwind(AssertUnwindSafe(|| {
            session
                .begin_compromise_rekey(generation, request, cancel.as_ref())
                .map_err(crate::session::map_repository_error)
        }));
        let prepare_active = inner.prepare_is_active(TransitionKind::Compromise, &cancel);
        let prepared = match prepared_result {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => {
                inner.clear_prepare(TransitionKind::Compromise, &cancel);
                return Err(error);
            }
            Err(_) => {
                inner.clear_prepare(TransitionKind::Compromise, &cancel);
                inner.latch_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        {
            let scheduler = lock(&inner.scheduler);
            if !prepare_active
                || !scheduler.accepting
                || !scheduler.key_leases_open
                || scheduler.generation != generation
                || session.current_generation() != Some(generation)
            {
                drop(scheduler);
                inner.clear_prepare(TransitionKind::Compromise, &cancel);
                inner.abort_pending_action(PendingAction::Compromise(prepared.action));
                return Err(ServiceError::StaleCapability);
            }
        }
        let (presentation_secret, verifier) = if let Some(secret) = prepared.secret {
            let mut key = Zeroizing::new([0_u8; 32]);
            let entropy = catch_unwind(AssertUnwindSafe(|| fill_security_entropy(&mut *key)))
                .unwrap_or(Err(ServiceError::EntropyUnavailable));
            if let Err(error) = entropy {
                inner.clear_prepare(TransitionKind::Compromise, &cancel);
                inner.abort_pending_action(PendingAction::Compromise(prepared.action));
                return Err(error);
            }
            let (payload, expected) = secret.into_presentation_payload(&key);
            (
                Some(Arc::new(Mutex::new(Some(payload)))),
                Some(SecretVerifier { key, expected }),
            )
        } else {
            (None, None)
        };
        let record = inner.register_transition(
            TransitionKind::Compromise,
            generation,
            PendingAction::Compromise(prepared.action),
            verifier,
            presentation_secret.as_ref().map(Arc::clone),
            &cancel,
        )?;
        let presentation = presentation_secret.map(RecoverySecretPresentation::from_shared);
        Ok((PendingCompromiseRekey::new(inner, record), presentation))
    }

    pub fn confirm_compromise_rekey(
        &self,
        mut pending: PendingCompromiseRekey,
        confirmation: CompromiseRekeyConfirmation,
    ) -> Result<SecurityTransitionHandle, ServiceError> {
        let record = pending.claim_for(&self.client.inner)?;
        let (action, state) = self.client.inner.claim_security_transition(&record)?;
        pending.disarm();
        let PendingAction::Compromise(action) = action else {
            self.client
                .inner
                .discard_transition_execution(&state, ServiceError::StaleCapability);
            self.client.inner.complete_transition(&record);
            return Err(ServiceError::StaleCapability);
        };
        let (first, matching) = confirmation.into_parts();
        clear_presentation(&record);
        let verifier = lock(&record.verifier).take();
        let confirmation = if let Some(verifier) = verifier {
            if matching.is_some() {
                drop(verifier);
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Compromise(action));
                self.client
                    .inner
                    .discard_transition_execution(&state, ServiceError::AuthenticationFailed);
                self.client.inner.complete_transition(&record);
                return Err(ServiceError::AuthenticationFailed);
            }
            let confirmation = first.verify_and_retain(&verifier.key, &verifier.expected);
            drop(verifier);
            match confirmation {
                Ok(confirmation) => confirmation,
                Err(()) => {
                    self.client
                        .inner
                        .abort_pending_action(PendingAction::Compromise(action));
                    self.client
                        .inner
                        .discard_transition_execution(&state, ServiceError::AuthenticationFailed);
                    self.client.inner.complete_transition(&record);
                    return Err(ServiceError::AuthenticationFailed);
                }
            }
        } else {
            let Some(matching) = matching else {
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Compromise(action));
                self.client
                    .inner
                    .discard_transition_execution(&state, ServiceError::AuthenticationFailed);
                self.client.inner.complete_transition(&record);
                return Err(ServiceError::AuthenticationFailed);
            };
            let mut key = Zeroizing::new([0_u8; 32]);
            if let Err(error) = fill_security_entropy(&mut *key) {
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Compromise(action));
                self.client
                    .inner
                    .discard_transition_execution(&state, error);
                self.client.inner.complete_transition(&record);
                return Err(error);
            }
            let expected = first.into_verifier(&key);
            match matching.verify_and_retain(&key, &expected) {
                Ok(confirmation) => confirmation,
                Err(()) => {
                    self.client
                        .inner
                        .abort_pending_action(PendingAction::Compromise(action));
                    self.client
                        .inner
                        .discard_transition_execution(&state, ServiceError::AuthenticationFailed);
                    self.client.inner.complete_transition(&record);
                    return Err(ServiceError::AuthenticationFailed);
                }
            }
        };
        let cancellation = match catch_unwind(AssertUnwindSafe(|| action.cancellation_handle())) {
            Ok(cancellation) => cancellation,
            Err(_) => {
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Compromise(action));
                self.client
                    .inner
                    .discard_transition_execution(&state, ServiceError::CleanupRequired);
                self.client.inner.complete_transition(&record);
                self.client.inner.latch_cleanup_required();
                return Err(ServiceError::CleanupRequired);
            }
        };
        if let Err(error) = state.register_lease_cancellation(cancellation) {
            self.client
                .inner
                .abort_pending_action(PendingAction::Compromise(action));
            self.client
                .inner
                .discard_transition_execution(&state, error);
            self.client.inner.complete_transition(&record);
            return Err(error);
        }
        let item = WorkItem {
            payload: WorkPayload::Compromise {
                action,
                confirmation,
                record: Arc::clone(&record),
            },
            state: Arc::clone(&state),
        };
        let mut scheduler = lock(&self.client.inner.scheduler);
        let sender_guard = lock(&self.client.inner.ordinary_sender);
        let Some(sender) = sender_guard.as_ref() else {
            scheduler.active.remove(&record.operation);
            drop(sender_guard);
            drop(scheduler);
            if let WorkPayload::Compromise { action, .. } = item.payload {
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Compromise(action));
            }
            state.finish_transition(Err(ServiceError::Closed));
            self.client.inner.complete_transition(&record);
            return Err(ServiceError::Closed);
        };
        if sender.is_full() {
            scheduler.active.remove(&record.operation);
            drop(sender_guard);
            drop(scheduler);
            if let WorkPayload::Compromise { action, .. } = item.payload {
                self.client
                    .inner
                    .abort_pending_action(PendingAction::Compromise(action));
            }
            state.finish_transition(Err(ServiceError::Busy));
            self.client.inner.complete_transition(&record);
            return Err(ServiceError::Busy);
        }
        match sender.try_send(item) {
            Ok(()) => {
                drop(sender_guard);
                drop(scheduler);
                self.client.inner.scheduler_changed.notify_all();
            }
            Err(error) => {
                scheduler.active.remove(&record.operation);
                let item = error.into_inner();
                drop(sender_guard);
                drop(scheduler);
                if let WorkPayload::Compromise { action, .. } = item.payload {
                    self.client
                        .inner
                        .abort_pending_action(PendingAction::Compromise(action));
                }
                state.finish_transition(Err(ServiceError::Closed));
                self.client.inner.complete_transition(&record);
                return Err(ServiceError::Closed);
            }
        }
        Ok(SecurityTransitionHandle::new(
            state,
            Arc::downgrade(&self.client.inner),
        ))
    }

    pub fn cancel_compromise_rekey(
        &self,
        mut pending: PendingCompromiseRekey,
    ) -> Result<(), ServiceError> {
        let record = pending.claim_for(&self.client.inner)?;
        self.client.inner.cancel_transition(&record);
        pending.disarm();
        Ok(())
    }

    pub fn begin_freshness_acknowledgement(
        &self,
        operation: OperationId,
    ) -> Result<
        (
            PendingFreshnessAcknowledgement,
            FreshnessAcknowledgementView,
        ),
        ServiceError,
    > {
        let record = {
            let registry = lock(&self.client.inner.transitions);
            Arc::clone(
                registry
                    .records
                    .get(&operation)
                    .ok_or(ServiceError::StaleCapability)?,
            )
        };
        let state = lock(&record.operation_state)
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(ServiceError::StaleCapability)?;
        {
            let scheduler = lock(&self.client.inner.scheduler);
            if scheduler.generation != record.generation
                || !state.is_running()
                || state.cancelled.load(Ordering::Acquire)
                || !scheduler
                    .active
                    .get(&operation)
                    .is_some_and(|active| Arc::ptr_eq(active, &state))
            {
                return Err(ServiceError::StaleCapability);
            }
            if record
                .offered
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(ServiceError::StaleCapability);
            }
        }
        let view = match lock(&record.action).as_ref() {
            Some(PendingAction::Freshness { view, .. }) => *view,
            _ => return Err(ServiceError::StaleCapability),
        };
        Ok((
            PendingFreshnessAcknowledgement::new(&self.client.inner, record),
            view,
        ))
    }

    pub fn acknowledge_unprovable_freshness(
        &self,
        mut pending: PendingFreshnessAcknowledgement,
    ) -> Result<(), ServiceError> {
        let record = pending.claim_for(&self.client.inner)?;
        let action = self.client.inner.claim_transition(&record)?;
        pending.disarm();
        let result = match catch_unwind(AssertUnwindSafe(|| match action {
            PendingAction::Freshness { action, .. } => action
                .acknowledge()
                .map_err(crate::session::map_repository_error),
            _ => Err(ServiceError::StaleCapability),
        })) {
            Ok(result) => result,
            Err(_) => {
                self.client.inner.latch_cleanup_required();
                Err(ServiceError::CleanupRequired)
            }
        };
        *lock(&record.resolution) = Some(result);
        record.resolution_changed.notify_all();
        self.client.inner.complete_transition(&record);
        if result == Err(ServiceError::CleanupRequired) {
            self.client.inner.latch_cleanup_required();
        }
        result
    }

    pub fn cancel_freshness_acknowledgement(
        &self,
        mut pending: PendingFreshnessAcknowledgement,
    ) -> Result<(), ServiceError> {
        let record = pending.claim_for(&self.client.inner)?;
        self.client.inner.cancel_transition(&record);
        pending.disarm();
        Ok(())
    }
}

struct PendingTransitionGuard {
    service: std::sync::Weak<ServiceInner>,
    record: Arc<TransitionRecord>,
    armed: bool,
}

impl Drop for PendingTransitionGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(service) = self.service.upgrade()
        {
            service.cancel_transition(&self.record);
        }
    }
}

macro_rules! pending_transition {
    ($name:ident) => {
        pub struct $name {
            generation: u64,
            operation: OperationId,
            guard: Option<PendingTransitionGuard>,
        }

        impl $name {
            fn new(service: &Arc<ServiceInner>, record: Arc<TransitionRecord>) -> Self {
                Self {
                    generation: record.generation,
                    operation: record.operation,
                    guard: Some(PendingTransitionGuard {
                        service: Arc::downgrade(service),
                        record,
                        armed: true,
                    }),
                }
            }

            fn claim_for(
                &self,
                expected: &Arc<ServiceInner>,
            ) -> Result<Arc<TransitionRecord>, ServiceError> {
                let guard = self.guard.as_ref().ok_or(ServiceError::StaleCapability)?;
                let origin = guard.service.upgrade().ok_or(ServiceError::Closed)?;
                if !Arc::ptr_eq(&origin, expected)
                    || self.generation != guard.record.generation
                    || self.operation != guard.record.operation
                {
                    return Err(ServiceError::StaleCapability);
                }
                Ok(Arc::clone(&guard.record))
            }

            fn disarm(&mut self) {
                if let Some(mut guard) = self.guard.take() {
                    guard.armed = false;
                }
            }
        }
    };
}

pending_transition!(PendingRecoveryInitialization);
pending_transition!(PendingCompromiseRekey);
pending_transition!(PendingFreshnessAcknowledgement);

/// Dedicated trusted local-input capability for coalesced inactivity resets.
pub struct TrustedActivityHandle {
    service: std::sync::Weak<ServiceInner>,
}

impl TrustedActivityHandle {
    pub fn record(&self) -> Result<(), ServiceError> {
        self.service
            .upgrade()
            .ok_or(ServiceError::Closed)?
            .enqueue_trusted_activity()
    }
}

fn discard_work_item(inner: &ServiceInner, item: WorkItem, error: ServiceError) {
    match item.payload {
        WorkPayload::Compromise { action, record, .. } => {
            inner.abort_pending_action(PendingAction::Compromise(action));
            inner.complete_transition(&record);
            item.state.finish_transition(Err(error));
        }
        WorkPayload::Command(_) => {
            item.state.finish(Err(error));
        }
    }
}

fn complete_control_observation(inner: &ServiceInner, pending: PendingControl) {
    let mut scheduler = lock(&inner.scheduler);
    scheduler.observer_in_flight = scheduler
        .observer_in_flight
        .checked_sub(1)
        .expect("a delivered control must retain one observer reservation");
    if pending.trusted_activity
        && scheduler.controls.trusted_activity_pending == Some(pending.generation)
    {
        scheduler.controls.trusted_activity_pending = None;
        scheduler.controls.trusted_activity_dispatched = None;
    }
    inner.scheduler_changed.notify_all();
}

fn coordinator_loop(inner: Arc<ServiceInner>) {
    let mut pending: Option<WorkItem> = None;
    loop {
        let control = {
            let mut scheduler = lock(&inner.scheduler);
            loop {
                let pending_control = scheduler
                    .controls
                    .pop_global()
                    .or_else(|| scheduler.controls.pop_trusted_activity())
                    .or_else(|| scheduler.controls.pop());
                if let Some(pending_control) = pending_control {
                    if pending_control.generation != scheduler.generation {
                        continue;
                    }
                    scheduler.observer_in_flight += 1;
                    break Some(pending_control);
                }
                if scheduler.closed {
                    scheduler.active.clear();
                    drop(scheduler);
                    if let Some(item) = pending.take() {
                        discard_work_item(&inner, item, ServiceError::Closed);
                    }
                    while let Ok(item) = inner.ordinary_receiver.try_recv() {
                        discard_work_item(&inner, item, ServiceError::Closed);
                    }
                    lock(&inner.worker_sender).take();
                    lock(&inner.control_sender).take();
                    lock(&inner.cancellation_sender).take();
                    return;
                }
                if scheduler.observer_in_flight != 0 {
                    drop(
                        inner
                            .scheduler_changed
                            .wait(scheduler)
                            .unwrap_or_else(|error| error.into_inner()),
                    );
                    break None;
                }
                if pending.is_none() {
                    match inner.ordinary_receiver.try_recv() {
                        Ok(item) => pending = Some(item),
                        Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => return,
                    }
                }
                if let Some(item) = pending.take() {
                    let worker_sender = lock(&inner.worker_sender);
                    let Some(sender) = worker_sender.as_ref() else {
                        drop(worker_sender);
                        drop(scheduler);
                        discard_work_item(&inner, item, ServiceError::Closed);
                        return;
                    };
                    match sender.try_send(item) {
                        Ok(()) => continue,
                        Err(TrySendError::Full(item)) => pending = Some(item),
                        Err(TrySendError::Disconnected(item)) => {
                            drop(worker_sender);
                            drop(scheduler);
                            discard_work_item(&inner, item, ServiceError::Closed);
                            return;
                        }
                    }
                }
                drop(
                    inner
                        .scheduler_changed
                        .wait(scheduler)
                        .unwrap_or_else(|error| error.into_inner()),
                );
                break None;
            }
        };

        if let Some(pending_control) = control {
            let current_generation = lock(&inner.scheduler).generation;
            if pending_control.generation != current_generation {
                complete_control_observation(&inner, pending_control);
                continue;
            }
            if pending_control.trusted_activity {
                let sender = lock(&inner.control_sender);
                let delivered = sender
                    .as_ref()
                    .is_some_and(|sender| sender.try_send(pending_control).is_ok());
                if !delivered {
                    complete_control_observation(&inner, pending_control);
                }
                continue;
            }
            if let Control::Cancel(id) = pending_control.control {
                let state = lock(&inner.scheduler).active.get(&id).cloned();
                if let Some(state) = state {
                    inner.enqueue_lease_cancellation(&state);
                }
                inner.cancel_transition_for_operation(id);
            }
            let observer_reserved = pending_control.control.is_global();
            if observer_reserved {
                inner.process_lock_job(pending_control.generation);
            } else if let Control::Cancel(id) = pending_control.control {
                inner.acknowledge_cancel(id);
            }
            let sender = lock(&inner.control_sender);
            let mut delivery_failed = false;
            if let Some(sender) = sender.as_ref() {
                if sender.try_send(pending_control).is_err() {
                    delivery_failed = true;
                }
            } else {
                delivery_failed = true;
            }
            drop(sender);
            if delivery_failed {
                complete_control_observation(&inner, pending_control);
                inner.shutdown();
            }
        }
    }
}

fn cancellation_loop(receiver: Receiver<Arc<OperationState>>) {
    while let Ok(state) = receiver.recv() {
        let _ = state.cancel_registered_leases();
    }
}

fn deadline_loop(inner: Arc<ServiceInner>) {
    loop {
        let wait_for = inner.enforce_deadline().unwrap_or(None);
        let scheduler = lock(&inner.scheduler);
        if scheduler.closed {
            return;
        }
        if let Some(wait_for) = wait_for {
            let _ = inner
                .scheduler_changed
                .wait_timeout(scheduler, wait_for)
                .unwrap_or_else(|error| error.into_inner());
        } else {
            drop(
                inner
                    .scheduler_changed
                    .wait(scheduler)
                    .unwrap_or_else(|error| error.into_inner()),
            );
        }
    }
}

fn control_observer_loop(inner: Arc<ServiceInner>, receiver: Receiver<PendingControl>) {
    while let Ok(pending) = receiver.recv() {
        if lock(&inner.scheduler).generation != pending.generation {
            complete_control_observation(&inner, pending);
            continue;
        }
        let panicked =
            catch_unwind(AssertUnwindSafe(|| inner.executor.control(pending.control))).is_err();
        complete_control_observation(&inner, pending);
        if panicked {
            inner.shutdown();
            return;
        }
    }
}

fn worker_loop(inner: Arc<ServiceInner>, receiver: Receiver<WorkItem>) {
    while let Ok(item) = receiver.recv() {
        inner.scheduler_changed.notify_all();
        if !item.state.mark_running() {
            if let WorkPayload::Compromise { action, record, .. } = item.payload {
                inner.abort_pending_action(PendingAction::Compromise(action));
                inner.complete_transition(&record);
            }
            continue;
        }
        match item.payload {
            WorkPayload::Command(command) => {
                let context =
                    OperationContext::new(Arc::clone(&item.state), Arc::downgrade(&inner));
                let started = context
                    .safe_boundary()
                    .and_then(|()| item.state.publish(crate::OperationEvent::Started));
                let outcome = if let Err(error) = started {
                    Err(error)
                } else {
                    match catch_unwind(AssertUnwindSafe(|| match command {
                        Command::List(_) if inner.session.is_some() => {
                            crate::local_use_cases::list_entries(&inner, &item.state, &context)
                        }
                        Command::Status(_) if inner.session.is_some() => {
                            crate::local_use_cases::status(&inner, &item.state, &context)
                        }
                        Command::CreateFile(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::create_file(
                                &inner,
                                &item.state,
                                &context,
                                request,
                            )
                        }
                        Command::CreateDirectory(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::create_directory(
                                &inner,
                                &item.state,
                                &context,
                                request,
                            )
                        }
                        Command::ImportFile(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::import_file(
                                &inner,
                                &item.state,
                                &context,
                                request,
                            )
                        }
                        Command::ExportFile(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::export_file(
                                &inner,
                                &item.state,
                                &context,
                                request,
                            )
                        }
                        Command::RenameEntry(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::rename(&inner, &item.state, &context, request)
                        }
                        Command::MoveEntry(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::move_entry(
                                &inner,
                                &item.state,
                                &context,
                                request,
                            )
                        }
                        Command::DeleteEntry(request)
                            if inner.session.is_some() && request.is_configured() =>
                        {
                            crate::local_use_cases::delete_entry(
                                &inner,
                                &item.state,
                                &context,
                                request,
                            )
                        }
                        command => inner.executor.execute(command, &context),
                    })) {
                        Ok(Ok(result)) => context.safe_boundary().map(|()| result),
                        Ok(Err(error)) => Err(error),
                        Err(_) => Err(ServiceError::WorkerPanicked),
                    }
                };
                inner.finish(&item.state, outcome);
            }
            WorkPayload::Compromise {
                action,
                confirmation,
                record,
            } => {
                let repository_cancellation = item.state.repository_cancellation();
                let outcome = match catch_unwind(AssertUnwindSafe(|| {
                    action.confirm(confirmation, repository_cancellation.as_ref())
                })) {
                    Ok(result) => result.map_err(crate::session::map_repository_error),
                    Err(_) => Err(ServiceError::CleanupRequired),
                };
                if matches!(outcome, Err(ServiceError::CleanupRequired)) {
                    inner.latch_cleanup_required();
                }
                inner.complete_transition(&record);
                inner.finish_transition_execution(&item.state, outcome);
            }
        }
    }
}

fn active_capacity(config: ServiceConfig) -> Result<usize, ServiceError> {
    config
        .workers
        .checked_mul(2)
        .and_then(|workers| config.queue_capacity.checked_add(workers))
        .and_then(|capacity| capacity.checked_add(1))
        .ok_or(ServiceError::InvalidConfiguration)
}

fn fill_exact(random: &dyn OperationIdRandom, destination: &mut [u8]) -> Result<(), ServiceError> {
    let mut filled = 0_usize;
    while filled < destination.len() {
        let written = catch_unwind(AssertUnwindSafe(|| random.fill(&mut destination[filled..])))
            .map_err(|_| ServiceError::EntropyUnavailable)??;
        let remaining = destination.len() - filled;
        if written == 0 || written > remaining {
            return Err(ServiceError::EntropyUnavailable);
        }
        filled = filled
            .checked_add(written)
            .ok_or(ServiceError::EntropyUnavailable)?;
    }
    Ok(())
}

fn fill_security_entropy(destination: &mut [u8]) -> Result<(), ServiceError> {
    getrandom::fill(destination).map_err(|_| ServiceError::EntropyUnavailable)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use crossbeam_channel::{Receiver, Sender, bounded};
    use tempfile::TempDir;

    use super::{
        Command, Control, OperationContext, OperationExecutor, OperationIdRandom, OperationResult,
        OperationState, PendingControl, ServiceConfig, ServiceError, ServiceHandle,
        complete_control_observation, lock,
    };

    struct FreshnessCounts {
        acknowledged: AtomicUsize,
        aborted: AtomicUsize,
    }

    struct BoundFreshnessAction {
        binding: Arc<crate::RepositoryCancellation>,
        counts: Arc<FreshnessCounts>,
        snapshot: notecrypt_core::SnapshotId,
    }

    struct ProductionFreshnessHarness {
        _repository: TempDir,
        _local: TempDir,
        readback: notecrypt_store::replication_test_support::FreshnessReadback,
    }

    impl ProductionFreshnessHarness {
        fn new(
            state: &Arc<OperationState>,
            seed: u8,
        ) -> (
            Self,
            Box<dyn crate::PendingFreshnessAction>,
            notecrypt_core::SnapshotId,
        ) {
            let repository = TempDir::new().unwrap();
            let local = TempDir::new().unwrap();
            let (fixture, readback) =
                notecrypt_store::replication_test_support::pending_unprovable_remote(
                    &repository.path().canonicalize().unwrap(),
                    &local.path().canonicalize().unwrap(),
                    notecrypt_core::VaultId::from_bytes([seed; 16]),
                    seed,
                )
                .unwrap();
            let (action, snapshot) = crate::session::production_freshness_action_for_test(
                fixture,
                state.repository_cancellation(),
            );
            (
                Self {
                    _repository: repository,
                    _local: local,
                    readback,
                },
                action,
                snapshot,
            )
        }

        fn acknowledged(&self) -> bool {
            notecrypt_store::replication_test_support::freshness_unprovable_was_acknowledged(
                &self.readback,
            )
            .unwrap()
        }
    }

    impl crate::PendingFreshnessAction for BoundFreshnessAction {
        fn operation_cancellation(&self) -> &crate::RepositoryCancellation {
            &self.binding
        }

        fn view(&self) -> crate::FreshnessAcknowledgementView {
            crate::FreshnessAcknowledgementView::new(self.snapshot)
        }

        fn acknowledge(self: Box<Self>) -> Result<(), crate::RepositoryPortError> {
            self.counts.acknowledged.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn abort(self: Box<Self>) -> Result<(), crate::RepositoryPortError> {
            self.counts.aborted.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn install_running_state(runtime: &ServiceHandle, byte: u8) -> Arc<OperationState> {
        let state = Arc::new(
            OperationState::new(crate::OperationId([byte; 16]), 4, Some(0), false).unwrap(),
        );
        assert!(state.mark_running());
        lock(&runtime.client.inner.scheduler)
            .active
            .insert(state.id, Arc::clone(&state));
        state
    }

    fn wait_for_transition(runtime: &ServiceHandle, id: crate::OperationId) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !lock(&runtime.client.inner.transitions)
            .records
            .contains_key(&id)
        {
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
    }

    struct NoopExecutor;

    impl OperationExecutor for NoopExecutor {
        fn execute(
            &self,
            _command: Command,
            _context: &OperationContext,
        ) -> Result<OperationResult, ServiceError> {
            unreachable!("the global control must reject this submission")
        }
    }

    #[test]
    fn observer_completion_is_scheduler_owned_and_wakes_waiters() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let inner = Arc::clone(&runtime.client.inner);
        let generation = {
            let mut scheduler = lock(&inner.scheduler);
            scheduler.observer_in_flight = 1;
            scheduler.generation
        };

        let (waiter_ready_tx, waiter_ready_rx) = bounded(1);
        let (woke_tx, woke_rx) = bounded(1);
        let waiter_inner = Arc::clone(&inner);
        let waiter = thread::spawn(move || {
            let mut scheduler = lock(&waiter_inner.scheduler);
            while scheduler.observer_in_flight != 0 {
                let _ = waiter_ready_tx.try_send(());
                scheduler = waiter_inner
                    .scheduler_changed
                    .wait(scheduler)
                    .unwrap_or_else(|error| error.into_inner());
            }
            woke_tx.send(()).unwrap();
        });
        waiter_ready_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        let scheduler = lock(&inner.scheduler);
        assert_eq!(scheduler.observer_in_flight, 1);
        let (completion_started_tx, completion_started_rx) = bounded(1);
        let (completion_tx, completion_rx) = bounded(1);
        let completion_inner = Arc::clone(&inner);
        let completion = thread::spawn(move || {
            completion_started_tx.send(()).unwrap();
            complete_control_observation(
                &completion_inner,
                PendingControl {
                    control: Control::UserActivity,
                    generation,
                    trusted_activity: false,
                },
            );
            completion_tx.send(()).unwrap();
        });
        completion_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(matches!(
            completion_rx.try_recv(),
            Err(crossbeam_channel::TryRecvError::Empty)
        ));

        drop(scheduler);
        completion_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        woke_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        completion.join().unwrap();
        waiter.join().unwrap();
        assert_eq!(lock(&inner.scheduler).observer_in_flight, 0);
    }

    struct BlockingRandom {
        entered: Sender<()>,
        release: Receiver<()>,
    }

    impl OperationIdRandom for BlockingRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<usize, ServiceError> {
            self.entered
                .send(())
                .expect("the test observer remains alive");
            self.release.recv().expect("the test release remains alive");
            destination.fill(1);
            Ok(destination.len())
        }
    }

    #[test]
    fn rejected_submit_race_does_not_consume_identity_budget() {
        let (entered_tx, entered_rx) = bounded(1);
        let (release_tx, release_rx) = bounded(1);
        let runtime = ServiceHandle::with_components(
            ServiceConfig::new(1, 1, 1, 1, 4, 1).expect("valid minimum configuration"),
            Arc::new(NoopExecutor),
            Arc::new(BlockingRandom {
                entered: entered_tx,
                release: release_rx,
            }),
        )
        .expect("runtime starts");
        let submitter = runtime.clone();
        let submit = thread::spawn(move || submitter.submit(Command::List(crate::ListEntries)));

        let entered = entered_rx.recv_timeout(Duration::from_secs(2));
        let controller = runtime.clone();
        let (control_result_tx, control_result_rx) = bounded(1);
        let control = thread::spawn(move || {
            let result = controller.control(super::Control::LockNow);
            let _ignored = control_result_tx.send(result);
        });
        let control_result = control_result_rx.recv_timeout(Duration::from_secs(2));
        release_tx.send(()).expect("blocked entropy resumes");
        control.join().expect("control thread exits");
        assert_eq!(entered, Ok(()));
        assert_eq!(control_result, Ok(Ok(())));
        assert!(matches!(
            submit.join().expect("submit thread exits"),
            Err(ServiceError::Locked)
        ));

        let issued = lock(&runtime.client.inner.identity).next;
        assert_eq!(issued, 0, "a rejected submit must not consume an identity");
    }

    #[test]
    fn freshness_acknowledgement_resumes_exact_operation_and_rejects_replay() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let state = install_running_state(&runtime, 0x31);
        let counts = Arc::new(FreshnessCounts {
            acknowledged: AtomicUsize::new(0),
            aborted: AtomicUsize::new(0),
        });
        let snapshot = notecrypt_core::SnapshotId::from_bytes([0x32; 32]);
        let action = Box::new(BoundFreshnessAction {
            binding: state.repository_cancellation(),
            counts: Arc::clone(&counts),
            snapshot,
        });
        let inner = Arc::clone(&runtime.client.inner);
        let worker_state = Arc::clone(&state);
        let worker =
            thread::spawn(move || inner.await_freshness_acknowledgement(&worker_state, action));
        wait_for_transition(&runtime, state.id);

        let (pending, view) = runtime.begin_freshness_acknowledgement(state.id).unwrap();
        assert_eq!(view.authenticated_snapshot(), snapshot);
        runtime.acknowledge_unprovable_freshness(pending).unwrap();
        assert_eq!(worker.join().unwrap(), Ok(()));
        assert_eq!(counts.acknowledged.load(Ordering::Acquire), 1);
        assert_eq!(counts.aborted.load(Ordering::Acquire), 0);
        assert!(matches!(
            runtime.begin_freshness_acknowledgement(state.id),
            Err(ServiceError::StaleCapability)
        ));
    }

    #[test]
    fn freshness_drop_aborts_and_cross_operation_binding_is_rejected() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let first = install_running_state(&runtime, 0x41);
        let second = install_running_state(&runtime, 0x42);
        let counts = Arc::new(FreshnessCounts {
            acknowledged: AtomicUsize::new(0),
            aborted: AtomicUsize::new(0),
        });

        let mismatch = Box::new(BoundFreshnessAction {
            binding: first.repository_cancellation(),
            counts: Arc::clone(&counts),
            snapshot: notecrypt_core::SnapshotId::from_bytes([0x43; 32]),
        });
        assert_eq!(
            runtime
                .client
                .inner
                .await_freshness_acknowledgement(&second, mismatch),
            Err(ServiceError::StaleCapability)
        );
        assert_eq!(counts.aborted.load(Ordering::Acquire), 1);

        let action = Box::new(BoundFreshnessAction {
            binding: first.repository_cancellation(),
            counts: Arc::clone(&counts),
            snapshot: notecrypt_core::SnapshotId::from_bytes([0x44; 32]),
        });
        let inner = Arc::clone(&runtime.client.inner);
        let worker_state = Arc::clone(&first);
        let worker =
            thread::spawn(move || inner.await_freshness_acknowledgement(&worker_state, action));
        wait_for_transition(&runtime, first.id);
        let (pending, _) = runtime.begin_freshness_acknowledgement(first.id).unwrap();
        drop(pending);
        assert_eq!(worker.join().unwrap(), Err(ServiceError::Cancelled));
        assert_eq!(counts.acknowledged.load(Ordering::Acquire), 0);
        assert_eq!(counts.aborted.load(Ordering::Acquire), 2);
    }

    #[test]
    fn cancelled_operation_cannot_offer_or_acknowledge_freshness() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let state = install_running_state(&runtime, 0x51);
        let counts = Arc::new(FreshnessCounts {
            acknowledged: AtomicUsize::new(0),
            aborted: AtomicUsize::new(0),
        });
        let action = Box::new(BoundFreshnessAction {
            binding: state.repository_cancellation(),
            counts: Arc::clone(&counts),
            snapshot: notecrypt_core::SnapshotId::from_bytes([0x52; 32]),
        });
        let inner = Arc::clone(&runtime.client.inner);
        let worker_state = Arc::clone(&state);
        let worker =
            thread::spawn(move || inner.await_freshness_acknowledgement(&worker_state, action));
        wait_for_transition(&runtime, state.id);

        state.request_cancel();
        assert!(matches!(
            runtime.begin_freshness_acknowledgement(state.id),
            Err(ServiceError::StaleCapability)
        ));
        runtime
            .client
            .inner
            .cancel_transition_for_operation(state.id);
        assert_eq!(worker.join().unwrap(), Err(ServiceError::Cancelled));
        assert_eq!(counts.acknowledged.load(Ordering::Acquire), 0);
        assert_eq!(counts.aborted.load(Ordering::Acquire), 1);
    }

    #[test]
    fn offered_freshness_cannot_acknowledge_after_exact_operation_cancel() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let state = install_running_state(&runtime, 0x61);
        let counts = Arc::new(FreshnessCounts {
            acknowledged: AtomicUsize::new(0),
            aborted: AtomicUsize::new(0),
        });
        let action = Box::new(BoundFreshnessAction {
            binding: state.repository_cancellation(),
            counts: Arc::clone(&counts),
            snapshot: notecrypt_core::SnapshotId::from_bytes([0x62; 32]),
        });
        let inner = Arc::clone(&runtime.client.inner);
        let worker_state = Arc::clone(&state);
        let worker =
            thread::spawn(move || inner.await_freshness_acknowledgement(&worker_state, action));
        wait_for_transition(&runtime, state.id);
        let (pending, _) = runtime.begin_freshness_acknowledgement(state.id).unwrap();

        state.request_cancel();
        assert_eq!(
            runtime.acknowledge_unprovable_freshness(pending),
            Err(ServiceError::StaleCapability)
        );
        assert_eq!(worker.join().unwrap(), Err(ServiceError::Cancelled));
        assert_eq!(counts.acknowledged.load(Ordering::Acquire), 0);
        assert_eq!(counts.aborted.load(Ordering::Acquire), 1);
    }

    #[test]
    fn production_freshness_acknowledgement_records_exact_task6_baseline() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let state = install_running_state(&runtime, 0x71);
        let (harness, action, snapshot) = ProductionFreshnessHarness::new(&state, 0x72);
        assert!(!harness.acknowledged());
        let inner = Arc::clone(&runtime.client.inner);
        let worker_state = Arc::clone(&state);
        let worker =
            thread::spawn(move || inner.await_freshness_acknowledgement(&worker_state, action));
        wait_for_transition(&runtime, state.id);

        let (pending, view) = runtime.begin_freshness_acknowledgement(state.id).unwrap();
        assert_eq!(view.authenticated_snapshot(), snapshot);
        runtime.acknowledge_unprovable_freshness(pending).unwrap();
        assert_eq!(worker.join().unwrap(), Ok(()));
        assert!(harness.acknowledged());
    }

    #[test]
    fn dropping_production_freshness_capability_records_no_task6_baseline() {
        let runtime = ServiceHandle::with_components(
            ServiceConfig::default(),
            Arc::new(NoopExecutor),
            Arc::new(crate::OsOperationIdRandom),
        )
        .unwrap();
        let state = install_running_state(&runtime, 0x73);
        let (harness, action, _) = ProductionFreshnessHarness::new(&state, 0x74);
        let inner = Arc::clone(&runtime.client.inner);
        let worker_state = Arc::clone(&state);
        let worker =
            thread::spawn(move || inner.await_freshness_acknowledgement(&worker_state, action));
        wait_for_transition(&runtime, state.id);
        let (pending, _) = runtime.begin_freshness_acknowledgement(state.id).unwrap();

        drop(pending);
        assert_eq!(worker.join().unwrap(), Err(ServiceError::Cancelled));
        assert!(!harness.acknowledged());
    }
}
