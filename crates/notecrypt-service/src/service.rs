use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError, bounded};

use crate::operation::{OperationState, lock};
use crate::{
    Command, OperationContext, OperationHandle, OperationId, OperationResult, ServiceError,
};

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

    /// Observes one coalesced priority notification on the coordinator thread.
    ///
    /// Global cancellation flags and submission gates have already changed
    /// before this callback runs. Implementations must keep the callback bounded.
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
    accepting_operations: bool,
    key_leases_open: bool,
    queued_operations: usize,
    running_operations: usize,
    active_operations: usize,
    retained_completed_operations: usize,
    closed: bool,
}

impl ServiceSnapshot {
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
    command: Command,
    state: Arc<OperationState>,
}

#[derive(Clone, Copy)]
struct PendingControl {
    control: Control,
}

struct ControlMailbox {
    pending: VecDeque<PendingControl>,
    global_notified: bool,
    activity_pending: bool,
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
            global_notified: false,
            activity_pending: false,
            capacity,
        })
    }

    fn push(&mut self, control: Control) -> bool {
        if self.pending.len() == self.capacity {
            return false;
        }
        self.pending.push_back(PendingControl { control });
        true
    }

    fn pop(&mut self) -> Option<PendingControl> {
        let pending = self.pending.pop_front()?;
        if pending.control == Control::UserActivity {
            self.activity_pending = false;
        }
        Some(pending)
    }
}

struct SchedulerState {
    accepting: bool,
    key_leases_open: bool,
    closed: bool,
    active: HashMap<OperationId, Arc<OperationState>>,
    completed: VecDeque<OperationId>,
    controls: ControlMailbox,
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
        Ok(Self {
            accepting: true,
            key_leases_open: true,
            closed: false,
            active,
            completed,
            controls: ControlMailbox::new(control_capacity)?,
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
    identity: Mutex<IdentityState>,
}

struct IdentityState {
    nonce: Option<[u8; 8]>,
    next: u64,
}

impl ServiceInner {
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
            state.request_cancel();
            if !state
                .cancel_notification_pending
                .swap(true, Ordering::AcqRel)
                && !scheduler.controls.push(Control::Cancel(state.id))
            {
                drop(scheduler);
                self.shutdown();
                return;
            }
            self.scheduler_changed.notify_all();
        }
    }

    pub(crate) fn detach(&self, state: &Arc<OperationState>) {
        let scheduler = lock(&self.scheduler);
        let _still_accounted = scheduler
            .active
            .get(&state.id)
            .is_some_and(|active| Arc::ptr_eq(active, state));
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

    fn shutdown(&self) {
        let states = {
            let mut scheduler = lock(&self.scheduler);
            if scheduler.closed {
                return;
            }
            scheduler.closed = true;
            scheduler.accepting = false;
            scheduler.key_leases_open = false;
            let states = std::mem::take(&mut scheduler.active);
            for state in states.values() {
                state.request_cancel();
            }
            lock(&self.ordinary_sender).take();
            lock(&self.worker_sender).take();
            self.scheduler_changed.notify_all();
            states
        };
        for state in states.into_values() {
            state.finish(Err(ServiceError::Closed));
        }
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
        let scheduler = SchedulerState::new(config)?;
        let (ordinary_sender, ordinary_receiver) = bounded(config.queue_capacity);
        let (worker_sender, worker_receiver) = bounded(config.workers);
        let inner = Arc::new(ServiceInner {
            config,
            executor,
            random,
            scheduler: Mutex::new(scheduler),
            scheduler_changed: Condvar::new(),
            ordinary_sender: Mutex::new(Some(ordinary_sender)),
            ordinary_receiver,
            worker_sender: Mutex::new(Some(worker_sender)),
            identity: Mutex::new(IdentityState {
                nonce: None,
                next: 0,
            }),
        });

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

        Ok(Self {
            client: Arc::new(ServiceClient { inner }),
        })
    }

    pub fn submit(&self, command: Command) -> Result<OperationHandle, ServiceError> {
        let inner = &self.client.inner;
        {
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
        }
        let mut identity = lock(&inner.identity);
        let (id, next_identity) = inner.candidate_id(&mut identity)?;
        let state = Arc::new(OperationState::new(id, inner.config.event_capacity)?);
        let mut scheduler = lock(&inner.scheduler);
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
        scheduler.active.insert(id, Arc::clone(&state));
        let item = WorkItem {
            command,
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
        let mut scheduler = lock(&inner.scheduler);
        let mut mailbox_overflow = false;
        if scheduler.closed {
            return Err(ServiceError::Closed);
        }

        match control {
            Control::Cancel(id) => {
                let Some(state) = scheduler.active.get(&id).cloned() else {
                    return Ok(());
                };
                state.request_cancel();
                if !state
                    .cancel_notification_pending
                    .swap(true, Ordering::AcqRel)
                {
                    mailbox_overflow = !scheduler.controls.push(control);
                }
            }
            Control::UserActivity => {
                if !scheduler.controls.activity_pending {
                    scheduler.controls.activity_pending = true;
                    mailbox_overflow = !scheduler.controls.push(control);
                }
            }
            global if global.is_global() => {
                scheduler.accepting = false;
                scheduler.key_leases_open = false;
                for state in scheduler.active.values() {
                    state.request_cancel();
                }
                if !scheduler.controls.global_notified {
                    scheduler.controls.global_notified = true;
                    mailbox_overflow = !scheduler.controls.push(global);
                }
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
}

fn coordinator_loop(inner: Arc<ServiceInner>) {
    let mut pending: Option<WorkItem> = None;
    loop {
        let control = {
            let mut scheduler = lock(&inner.scheduler);
            loop {
                if let Some(control) = scheduler.controls.pop() {
                    break Some(control);
                }
                if scheduler.closed {
                    if let Some(item) = pending.take() {
                        item.state.finish(Err(ServiceError::Closed));
                    }
                    while let Ok(item) = inner.ordinary_receiver.try_recv() {
                        item.state.finish(Err(ServiceError::Closed));
                    }
                    return;
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
                        item.state.finish(Err(ServiceError::Closed));
                        return;
                    };
                    match sender.try_send(item) {
                        Ok(()) => continue,
                        Err(TrySendError::Full(item)) => pending = Some(item),
                        Err(TrySendError::Disconnected(item)) => {
                            item.state.finish(Err(ServiceError::Closed));
                            return;
                        }
                    }
                }
                scheduler = inner
                    .scheduler_changed
                    .wait(scheduler)
                    .unwrap_or_else(|error| error.into_inner());
            }
        };

        if let Some(pending_control) = control {
            if catch_unwind(AssertUnwindSafe(|| {
                inner.executor.control(pending_control.control);
            }))
            .is_err()
            {
                inner.shutdown();
                return;
            }
            if let Control::Cancel(id) = pending_control.control {
                inner.acknowledge_cancel(id);
            }
        }
    }
}

fn worker_loop(inner: Arc<ServiceInner>, receiver: Receiver<WorkItem>) {
    while let Ok(item) = receiver.recv() {
        inner.scheduler_changed.notify_all();
        if !item.state.mark_running() {
            continue;
        }
        let context = OperationContext::new(Arc::clone(&item.state));
        let outcome = if let Err(error) = context.safe_boundary() {
            Err(error)
        } else if let Err(error) = item.state.publish(crate::OperationEvent::Started) {
            Err(error)
        } else {
            match catch_unwind(AssertUnwindSafe(|| {
                inner.executor.execute(item.command, &context)
            })) {
                Ok(Ok(result)) => context.safe_boundary().map(|()| result),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(ServiceError::WorkerPanicked),
            }
        };
        inner.finish(&item.state, outcome);
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
        let written = random.fill(&mut destination[filled..])?;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crossbeam_channel::{Receiver, Sender, bounded};

    use super::{
        Command, OperationContext, OperationExecutor, OperationIdRandom, OperationResult,
        ServiceConfig, ServiceError, ServiceHandle, lock,
    };

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
}
