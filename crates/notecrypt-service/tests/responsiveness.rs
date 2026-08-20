use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use notecrypt_service::{
    Command, ConflictSummary, Control, CreateDirectory, CreateFile, DurabilitySummary,
    EntrySummaries, ExportFile, ImportFile, ListEntries, MAX_COMPLETED_CAPACITY,
    MAX_EVENT_CAPACITY, MAX_ID_RETRIES, MAX_QUEUE_CAPACITY, MAX_WORKERS, OperationContext,
    OperationEvent, OperationExecutor, OperationId, OperationIdRandom, OperationResult, Progress,
    ServiceConfig, ServiceError, ServiceHandle, WarningCode,
};

const SHORT_WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Gate {
    permits: Mutex<usize>,
    changed: Condvar,
}

impl Gate {
    fn release(&self, permits: usize) {
        let mut available = self
            .permits
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *available = available
            .checked_add(permits)
            .expect("test permit overflow");
        self.changed.notify_all();
    }

    fn wait(&self) {
        let mut available = self
            .permits
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while *available == 0 {
            available = self
                .changed
                .wait(available)
                .unwrap_or_else(|error| error.into_inner());
        }
        *available -= 1;
    }
}

struct BlockingExecutor {
    gate: Arc<Gate>,
    entered: mpsc::Sender<()>,
    boundary: mpsc::Sender<Result<(), ServiceError>>,
    executions: AtomicUsize,
}

struct EventExecutor {
    gate: Arc<Gate>,
    entered: mpsc::Sender<()>,
}

impl OperationExecutor for EventExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.entered.send(()).expect("test observer is alive");
        self.gate.wait();
        context.emit_progress(Progress::items(1, Some(4))?)?;
        context.emit_progress(Progress::items(2, Some(4))?)?;
        context.emit_progress(Progress::bytes(10, Some(40))?)?;
        context.emit_progress(Progress::bytes(20, Some(40))?)?;
        context.warning(WarningCode::DurabilityPending)?;
        context.conflict(ConflictSummary::new([0x31; 16]))?;
        context.revision_durable(DurabilitySummary::new([0x32; 16]))?;
        context.save_detected()?;
        context.sync_published()?;
        context.cleanup_required()?;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }
}

struct DelayedControlExecutor {
    control_gate: Arc<Gate>,
    control_entered: mpsc::Sender<()>,
    emit_attempted: mpsc::Sender<()>,
    emit_result: mpsc::Sender<Result<(), ServiceError>>,
}

impl OperationExecutor for DelayedControlExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.emit_attempted
            .send(())
            .expect("test observer is alive");
        let result = context.warning(WarningCode::CleanupRequired);
        self.emit_result
            .send(result)
            .expect("test observer is alive");
        result?;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, control: Control) {
        if control == Control::UserActivity {
            self.control_entered
                .send(())
                .expect("test observer is alive");
            self.control_gate.wait();
        }
    }
}

struct CancellationAudit {
    cancelled: Mutex<usize>,
    changed: Condvar,
}

impl CancellationAudit {
    fn record(&self) {
        let mut cancelled = self
            .cancelled
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *cancelled += 1;
        self.changed.notify_all();
    }

    fn wait_for(&self, expected: usize) {
        let mut cancelled = self
            .cancelled
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while *cancelled < expected {
            cancelled = self
                .changed
                .wait(cancelled)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

struct GlobalControlExecutor {
    gate: Arc<Gate>,
    entered: mpsc::Sender<()>,
    audit: Arc<CancellationAudit>,
    cleanup: mpsc::Sender<Control>,
    expected: usize,
}

impl OperationExecutor for GlobalControlExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.entered.send(()).expect("test observer is alive");
        self.gate.wait();
        let boundary = context.safe_boundary();
        if boundary == Err(ServiceError::Cancelled) {
            self.audit.record();
        }
        boundary?;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, control: Control) {
        if matches!(
            control,
            Control::LockNow | Control::DeadlineExpired | Control::Suspend
        ) {
            self.gate.release(self.expected);
            self.audit.wait_for(self.expected);
            self.cleanup.send(control).expect("test observer is alive");
        }
    }
}

struct OrderedExecutor {
    first_gate: Arc<Gate>,
    first_entered: mpsc::Sender<()>,
    controls_seen: mpsc::Sender<Control>,
    order: Arc<Mutex<Vec<&'static str>>>,
}

impl OperationExecutor for OrderedExecutor {
    fn execute(
        &self,
        command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        match command {
            Command::List(_) => {
                self.first_entered.send(()).expect("test observer is alive");
                self.first_gate.wait();
                context.safe_boundary()?;
            }
            Command::CreateDirectory(_) => {
                self.order
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push("execute-directory");
            }
            Command::CreateFile(_) => {
                panic!("a cancelled queued operation reached the executor");
            }
            _ => {}
        }
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, control: Control) {
        let label = match control {
            Control::Cancel(_) => "cancel",
            Control::UserActivity => "activity",
            _ => "global",
        };
        self.order
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(label);
        self.controls_seen
            .send(control)
            .expect("test observer is alive");
    }
}

struct FaultExecutor {
    gate: Arc<Gate>,
    entered: mpsc::Sender<()>,
}

impl OperationExecutor for FaultExecutor {
    fn execute(
        &self,
        command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        match command {
            Command::ImportFile(_) => panic!("injected worker panic"),
            Command::ExportFile(_) => Err(ServiceError::ExecutorFailed),
            Command::List(_) => {
                self.entered.send(()).expect("test observer is alive");
                self.gate.wait();
                context.safe_boundary()?;
                Ok(OperationResult::Entries(EntrySummaries::empty()))
            }
            _ => Ok(OperationResult::Entries(EntrySummaries::empty())),
        }
    }
}

struct ExactlyOnceExecutor {
    counts: Mutex<HashMap<OperationId, usize>>,
}

impl OperationExecutor for ExactlyOnceExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *counts.entry(context.id()).or_default() += 1;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }
}

struct GenerationExecutor {
    work_gate: Arc<Gate>,
    control_gate: Arc<Gate>,
    work_entered: mpsc::Sender<()>,
    control_entered: mpsc::Sender<()>,
}

impl OperationExecutor for GenerationExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.work_entered.send(()).expect("test observer is alive");
        self.work_gate.wait();
        context.safe_boundary()?;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, control: Control) {
        if control == Control::UserActivity {
            self.control_entered
                .send(())
                .expect("test observer is alive");
            self.control_gate.wait();
        }
    }
}

struct ControlRecordingExecutor {
    controls: mpsc::Sender<Control>,
}

impl OperationExecutor for ControlRecordingExecutor {
    fn execute(
        &self,
        _command: Command,
        _context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, control: Control) {
        self.controls.send(control).expect("test observer is alive");
    }
}

struct PanicControlExecutor {
    gate: Arc<Gate>,
    entered: mpsc::Sender<()>,
}

struct PendingCancelOrderExecutor {
    first_gate: Arc<Gate>,
    control_gate: Arc<Gate>,
    first_entered: mpsc::Sender<()>,
    order: mpsc::Sender<&'static str>,
    activity_callbacks: AtomicUsize,
}

struct BackendBoundaryExecutor {
    gate: Arc<Gate>,
    entered: mpsc::Sender<()>,
    observed: mpsc::Sender<bool>,
}

impl OperationExecutor for BackendBoundaryExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.entered.send(()).expect("test observer is alive");
        self.gate.wait();
        self.observed
            .send(context.is_cancelled())
            .expect("test observer is alive");
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }
}

impl OperationExecutor for PendingCancelOrderExecutor {
    fn execute(
        &self,
        command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        match command {
            Command::List(_) => {
                self.first_entered.send(()).expect("test observer is alive");
                self.first_gate.wait();
                context.safe_boundary()?;
            }
            Command::CreateDirectory(_) => {
                self.order.send("ordinary").expect("test observer is alive");
            }
            _ => {}
        }
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, control: Control) {
        match control {
            Control::UserActivity => {
                let callback = self.activity_callbacks.fetch_add(1, Ordering::AcqRel);
                self.order
                    .send("activity-entered")
                    .expect("test observer is alive");
                if callback == 0 {
                    self.control_gate.wait();
                }
            }
            Control::Cancel(_) => {
                self.order.send("cancel").expect("test observer is alive");
            }
            _ => {}
        }
    }
}

impl OperationExecutor for PanicControlExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.entered.send(()).expect("test observer is alive");
        self.gate.wait();
        context.safe_boundary()?;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }

    fn control(&self, _control: Control) {
        panic!("injected control callback panic");
    }
}

impl OperationExecutor for BlockingExecutor {
    fn execute(
        &self,
        _command: Command,
        context: &OperationContext,
    ) -> Result<OperationResult, ServiceError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.send(());
        self.gate.wait();
        let boundary = context.safe_boundary();
        let _ = self.boundary.send(boundary);
        context.emit_progress(Progress::items(1, Some(1))?)?;
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    }
}

struct ScriptedRandom {
    values: Mutex<VecDeque<Result<Vec<u8>, ServiceError>>>,
}

impl ScriptedRandom {
    fn new(values: impl IntoIterator<Item = Result<Vec<u8>, ServiceError>>) -> Self {
        Self {
            values: Mutex::new(values.into_iter().collect()),
        }
    }
}

impl OperationIdRandom for ScriptedRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<usize, ServiceError> {
        let value = self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
            .unwrap_or(Err(ServiceError::EntropyUnavailable))?;
        if value.len() > destination.len() {
            return Ok(value.len());
        }
        destination[..value.len()].copy_from_slice(&value);
        Ok(value.len())
    }
}

fn random_id(byte: u8) -> Result<Vec<u8>, ServiceError> {
    Ok(vec![byte; 8])
}

fn config(queue_capacity: usize, workers: usize, event_capacity: usize) -> ServiceConfig {
    ServiceConfig::new(queue_capacity, workers, event_capacity, 8, 64, 4).unwrap()
}

fn service(
    executor: Arc<dyn OperationExecutor>,
    random: Arc<dyn OperationIdRandom>,
    config: ServiceConfig,
) -> ServiceHandle {
    ServiceHandle::with_components(config, executor, random).unwrap()
}

#[test]
fn submission_stays_responsive_and_cancellation_is_seen_at_the_next_boundary() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (boundary_tx, boundary_rx) = mpsc::channel();
    let executor = Arc::new(BlockingExecutor {
        gate: Arc::clone(&gate),
        entered: entered_tx,
        boundary: boundary_tx,
        executions: AtomicUsize::new(0),
    });
    let runtime = service(
        executor,
        Arc::new(ScriptedRandom::new([random_id(1), random_id(2)])),
        config(2, 1, 4),
    );

    let first = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();

    let started = Instant::now();
    let second = runtime.submit(Command::CreateFile(CreateFile)).unwrap();
    let submit_elapsed = started.elapsed();
    eprintln!("saturated submit latency: {submit_elapsed:?}");
    assert!(submit_elapsed < Duration::from_millis(10));

    first.cancel();
    gate.release(1);
    assert_eq!(
        boundary_rx.recv_timeout(SHORT_WAIT).unwrap(),
        Err(ServiceError::Cancelled)
    );
    assert_eq!(first.wait_result(SHORT_WAIT), Err(ServiceError::Cancelled));

    gate.release(1);
    assert_eq!(boundary_rx.recv_timeout(SHORT_WAIT).unwrap(), Ok(()));
    assert_eq!(
        second.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
}

#[test]
fn progress_is_visible_promptly_after_the_worker_reaches_a_boundary() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (boundary_tx, boundary_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(BlockingExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
            boundary: boundary_tx,
            executions: AtomicUsize::new(0),
        }),
        Arc::new(ScriptedRandom::new([random_id(3)])),
        config(1, 1, 4),
    );
    let operation = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    assert!(matches!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Started)
    ));

    let boundary_started = Instant::now();
    gate.release(1);
    assert_eq!(boundary_rx.recv_timeout(SHORT_WAIT).unwrap(), Ok(()));
    let event = operation
        .wait_next_event(Duration::from_millis(100))
        .unwrap();
    let progress_elapsed = boundary_started.elapsed();
    eprintln!("first progress latency: {progress_elapsed:?}");
    assert!(progress_elapsed < Duration::from_millis(100));
    assert!(matches!(event, Some(OperationEvent::Progress(_))));
}

#[test]
fn saturated_work_returns_busy_but_priority_controls_remain_accepted() {
    let first_gate = Arc::new(Gate::default());
    let control_gate = Arc::new(Gate::default());
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (order_tx, order_rx) = mpsc::channel();
    let executor = Arc::new(PendingCancelOrderExecutor {
        first_gate: Arc::clone(&first_gate),
        control_gate: Arc::clone(&control_gate),
        first_entered: first_entered_tx,
        order: order_tx,
        activity_callbacks: AtomicUsize::new(0),
    });
    let runtime = service(
        executor.clone(),
        Arc::new(ScriptedRandom::new([
            random_id(4),
            random_id(5),
            random_id(6),
        ])),
        config(1, 1, 2),
    );
    let active = runtime.submit(Command::List(ListEntries)).unwrap();
    first_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    assert_eq!(runtime.control(Control::UserActivity), Ok(()));
    assert_eq!(
        order_rx.recv_timeout(SHORT_WAIT).unwrap(),
        "activity-entered"
    );
    let queued = runtime
        .submit(Command::CreateDirectory(CreateDirectory))
        .unwrap();

    let started = Instant::now();
    assert!(matches!(
        runtime.submit(Command::CreateFile(CreateFile)),
        Err(ServiceError::Busy)
    ));
    assert!(started.elapsed() < Duration::from_millis(10));
    assert_eq!(runtime.control(Control::Cancel(queued.id())), Ok(()));
    assert_eq!(runtime.control(Control::UserActivity), Ok(()));

    first_gate.release(1);
    assert_eq!(
        active.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    match order_rx.try_recv() {
        Err(mpsc::TryRecvError::Empty) => {}
        unexpected => panic!("work ran while the control observer was blocked: {unexpected:?}"),
    }

    control_gate.release(1);
    assert_eq!(order_rx.recv_timeout(SHORT_WAIT).unwrap(), "cancel");
    assert_eq!(
        order_rx.recv_timeout(SHORT_WAIT).unwrap(),
        "activity-entered"
    );
    let queued_result = queued.wait_result(SHORT_WAIT);
    assert_eq!(
        queued_result,
        Err(ServiceError::Cancelled),
        "snapshot={:?}, activity_callbacks={}",
        runtime.snapshot(),
        executor.activity_callbacks.load(Ordering::Acquire)
    );
    assert!(matches!(
        order_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn entropy_failures_and_collision_exhaustion_publish_no_operation() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, _entered_rx) = mpsc::channel();
    let (boundary_tx, _boundary_rx) = mpsc::channel();
    let random = Arc::new(ScriptedRandom::new([
        Err(ServiceError::EntropyUnavailable),
        Ok(vec![8; 3]),
        Ok(vec![8; 5]),
    ]));
    let runtime = service(
        Arc::new(BlockingExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
            boundary: boundary_tx,
            executions: AtomicUsize::new(0),
        }),
        random,
        config(4, 1, 2),
    );

    assert!(matches!(
        runtime.submit(Command::List(ListEntries)),
        Err(ServiceError::EntropyUnavailable)
    ));
    let accepted = runtime.submit(Command::List(ListEntries)).unwrap();
    assert_eq!(runtime.snapshot().active_operations(), 1);
    gate.release(1);
    assert_eq!(
        accepted.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );

    let collision_gate = Arc::new(Gate::default());
    let (collision_entered, _) = mpsc::channel();
    let (collision_boundary, _) = mpsc::channel();
    let collision_service = service(
        Arc::new(BlockingExecutor {
            gate: collision_gate,
            entered: collision_entered,
            boundary: collision_boundary,
            executions: AtomicUsize::new(0),
        }),
        Arc::new(ScriptedRandom::new([
            random_id(0),
            random_id(0),
            random_id(0),
            random_id(0),
        ])),
        config(1, 1, 2),
    );
    assert!(matches!(
        collision_service.submit(Command::List(ListEntries)),
        Err(ServiceError::IdentifierExhausted)
    ));
    assert_eq!(collision_service.snapshot().active_operations(), 0);
}

#[test]
fn progress_coalesces_but_lossless_events_and_terminal_stay_ordered() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(EventExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(10)])),
        config(1, 1, 8),
    );
    let operation = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Started)
    );

    gate.release(1);
    assert_eq!(
        operation.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Progress(
            Progress::items(2, Some(4)).unwrap()
        ))
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Progress(
            Progress::bytes(20, Some(40)).unwrap()
        ))
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Warning(WarningCode::DurabilityPending))
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Conflict(ConflictSummary::new([0x31; 16])))
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::RevisionDurable(DurabilitySummary::new(
            [0x32; 16]
        )))
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::SaveDetected)
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::SyncPublished)
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::CleanupRequired)
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Completed)
    );
}

#[test]
fn direct_cancellation_wakes_event_backpressure_while_notification_is_delayed() {
    for (index, global) in [false, true].into_iter().enumerate() {
        let control_gate = Arc::new(Gate::default());
        let (control_entered_tx, control_entered_rx) = mpsc::channel();
        let (emit_attempted_tx, emit_attempted_rx) = mpsc::channel();
        let (emit_result_tx, emit_result_rx) = mpsc::channel();
        let runtime = service(
            Arc::new(DelayedControlExecutor {
                control_gate: Arc::clone(&control_gate),
                control_entered: control_entered_tx,
                emit_attempted: emit_attempted_tx,
                emit_result: emit_result_tx,
            }),
            Arc::new(ScriptedRandom::new([random_id(11 + index as u8)])),
            config(1, 1, 1),
        );
        let operation = runtime.submit(Command::List(ListEntries)).unwrap();
        emit_attempted_rx.recv_timeout(SHORT_WAIT).unwrap();
        runtime.control(Control::UserActivity).unwrap();
        control_entered_rx.recv_timeout(SHORT_WAIT).unwrap();

        let cancellation = if global {
            Control::LockNow
        } else {
            Control::Cancel(operation.id())
        };
        runtime.control(cancellation).unwrap();
        assert_eq!(
            emit_result_rx.recv_timeout(SHORT_WAIT).unwrap(),
            Err(ServiceError::Cancelled)
        );
        assert_eq!(
            operation.wait_result(SHORT_WAIT),
            Err(ServiceError::Cancelled)
        );
        control_gate.release(1);
    }
}

#[test]
fn every_global_control_closes_the_gate_cancels_all_active_work_then_runs_cleanup() {
    for (index, control) in [Control::LockNow, Control::DeadlineExpired, Control::Suspend]
        .into_iter()
        .enumerate()
    {
        let gate = Arc::new(Gate::default());
        let audit = Arc::new(CancellationAudit {
            cancelled: Mutex::new(0),
            changed: Condvar::new(),
        });
        let (entered_tx, entered_rx) = mpsc::channel();
        let (cleanup_tx, cleanup_rx) = mpsc::channel();
        let runtime = service(
            Arc::new(GlobalControlExecutor {
                gate,
                entered: entered_tx,
                audit,
                cleanup: cleanup_tx,
                expected: 2,
            }),
            Arc::new(ScriptedRandom::new([random_id(20 + index as u8)])),
            config(2, 2, 2),
        );
        let first = runtime.submit(Command::List(ListEntries)).unwrap();
        let second = runtime.submit(Command::List(ListEntries)).unwrap();
        entered_rx.recv_timeout(SHORT_WAIT).unwrap();
        entered_rx.recv_timeout(SHORT_WAIT).unwrap();

        assert_eq!(runtime.control(control), Ok(()));
        let snapshot = runtime.snapshot();
        assert!(!snapshot.accepting_operations());
        assert!(!snapshot.key_leases_open());
        assert!(matches!(
            runtime.submit(Command::CreateFile(CreateFile)),
            Err(ServiceError::Locked)
        ));
        assert_eq!(cleanup_rx.recv_timeout(SHORT_WAIT).unwrap(), control);
        assert_eq!(first.wait_result(SHORT_WAIT), Err(ServiceError::Cancelled));
        assert_eq!(second.wait_result(SHORT_WAIT), Err(ServiceError::Cancelled));
        assert_eq!(runtime.control(control), Ok(()));
    }
}

#[test]
fn all_pending_controls_are_observed_before_the_next_ordinary_execution() {
    let gate = Arc::new(Gate::default());
    let order = Arc::new(Mutex::new(Vec::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (controls_tx, controls_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(OrderedExecutor {
            first_gate: Arc::clone(&gate),
            first_entered: entered_tx,
            controls_seen: controls_tx,
            order: Arc::clone(&order),
        }),
        Arc::new(ScriptedRandom::new([random_id(30)])),
        config(2, 1, 2),
    );
    let first = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    let cancelled = runtime.submit(Command::CreateFile(CreateFile)).unwrap();
    let next = runtime
        .submit(Command::CreateDirectory(CreateDirectory))
        .unwrap();

    runtime.control(Control::Cancel(cancelled.id())).unwrap();
    runtime.control(Control::UserActivity).unwrap();
    controls_rx.recv_timeout(SHORT_WAIT).unwrap();
    controls_rx.recv_timeout(SHORT_WAIT).unwrap();
    gate.release(1);

    assert_eq!(
        first.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    assert_eq!(
        cancelled.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
    assert_eq!(
        next.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    let order = order.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(&*order, &["cancel", "activity", "execute-directory"]);
}

#[test]
fn worker_panic_executor_error_and_shutdown_resolve_without_stranding_handles() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(FaultExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(40)])),
        config(3, 1, 2),
    );
    let panic_operation = runtime.submit(Command::ImportFile(ImportFile)).unwrap();
    assert_eq!(
        panic_operation.wait_result(SHORT_WAIT),
        Err(ServiceError::WorkerPanicked)
    );
    let error_operation = runtime.submit(Command::ExportFile(ExportFile)).unwrap();
    assert_eq!(
        error_operation.wait_result(SHORT_WAIT),
        Err(ServiceError::ExecutorFailed)
    );

    let blocked = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    let shutdown_started = Instant::now();
    runtime.shutdown();
    assert!(shutdown_started.elapsed() < Duration::from_millis(10));
    assert_eq!(blocked.wait_result(SHORT_WAIT), Err(ServiceError::Closed));
    assert!(matches!(
        runtime.submit(Command::List(ListEntries)),
        Err(ServiceError::Closed)
    ));
    assert_eq!(
        runtime.control(Control::UserActivity),
        Err(ServiceError::Closed)
    );
    gate.release(1);
}

#[test]
fn unknown_and_stale_cancellation_never_retargets_a_later_operation() {
    let executor = Arc::new(ExactlyOnceExecutor {
        counts: Mutex::new(HashMap::new()),
    });
    let runtime = service(
        executor,
        Arc::new(ScriptedRandom::new([random_id(50)])),
        ServiceConfig::new(1, 1, 2, 1, 4, 4).unwrap(),
    );
    let first = runtime.submit(Command::List(ListEntries)).unwrap();
    let stale = first.id();
    assert_eq!(
        first.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    let second = runtime.submit(Command::List(ListEntries)).unwrap();
    assert_eq!(
        second.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    runtime.control(Control::Cancel(stale)).unwrap();
    runtime.control(Control::Cancel(stale)).unwrap();
    let third = runtime.submit(Command::List(ListEntries)).unwrap();
    assert_ne!(third.id(), stale);
    assert_eq!(
        third.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    let fourth = runtime.submit(Command::List(ListEntries)).unwrap();
    assert_eq!(
        fourth.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    assert!(matches!(
        runtime.submit(Command::List(ListEntries)),
        Err(ServiceError::IdentifierExhausted)
    ));
}

#[test]
fn multiple_workers_execute_each_operation_once_and_snapshots_stay_coherent() {
    let executor = Arc::new(ExactlyOnceExecutor {
        counts: Mutex::new(HashMap::new()),
    });
    let runtime = service(
        executor.clone(),
        Arc::new(ScriptedRandom::new([random_id(60)])),
        ServiceConfig::new(8, 3, 2, 4, 32, 4).unwrap(),
    );
    let mut operations = Vec::new();
    operations.try_reserve_exact(8).unwrap();
    for _ in 0..8 {
        operations.push(runtime.submit(Command::List(ListEntries)).unwrap());
        let snapshot = runtime.snapshot();
        assert_eq!(
            snapshot.active_operations(),
            snapshot.queued_operations() + snapshot.running_operations()
        );
    }
    for operation in &operations {
        assert_eq!(
            operation.wait_result(SHORT_WAIT),
            Ok(OperationResult::Entries(EntrySummaries::empty()))
        );
    }
    let counts = executor
        .counts
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert_eq!(counts.len(), 8);
    assert!(counts.values().all(|count| *count == 1));
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.active_operations(), 0);
    assert!(snapshot.retained_completed_operations() <= 4);
}

#[test]
fn submit_and_global_control_race_has_only_linearized_outcomes() {
    let gate = Arc::new(Gate::default());
    gate.release(1);
    let (entered_tx, _entered_rx) = mpsc::channel();
    let (boundary_tx, _boundary_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(BlockingExecutor {
            gate,
            entered: entered_tx,
            boundary: boundary_tx,
            executions: AtomicUsize::new(0),
        }),
        Arc::new(ScriptedRandom::new([random_id(70)])),
        config(2, 1, 2),
    );
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let submit_runtime = runtime.clone();
    let submit_barrier = Arc::clone(&barrier);
    let submitter = std::thread::spawn(move || {
        submit_barrier.wait();
        submit_runtime.submit(Command::List(ListEntries))
    });
    let control_runtime = runtime.clone();
    let control_barrier = Arc::clone(&barrier);
    let controller = std::thread::spawn(move || {
        control_barrier.wait();
        control_runtime.control(Control::LockNow)
    });
    barrier.wait();
    let submitted = submitter.join().unwrap();
    assert_eq!(controller.join().unwrap(), Ok(()));
    match submitted {
        Ok(operation) => assert!(matches!(
            operation.wait_result(SHORT_WAIT),
            Err(ServiceError::Cancelled) | Ok(OperationResult::Entries(_))
        )),
        Err(error) => assert_eq!(error, ServiceError::Locked),
    }
    let snapshot = runtime.snapshot();
    assert!(!snapshot.accepting_operations());
    assert_eq!(
        snapshot.active_operations(),
        snapshot.queued_operations() + snapshot.running_operations()
    );
}

#[test]
fn handle_drop_cancels_exact_work_and_does_not_leak_the_worker() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (boundary_tx, boundary_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(BlockingExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
            boundary: boundary_tx,
            executions: AtomicUsize::new(0),
        }),
        Arc::new(ScriptedRandom::new([random_id(80)])),
        config(1, 1, 2),
    );
    let abandoned = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    drop(abandoned);
    gate.release(1);
    assert_eq!(
        boundary_rx.recv_timeout(SHORT_WAIT).unwrap(),
        Err(ServiceError::Cancelled)
    );

    let next = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    gate.release(1);
    assert_eq!(boundary_rx.recv_timeout(SHORT_WAIT).unwrap(), Ok(()));
    assert_eq!(
        next.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
    assert_eq!(runtime.snapshot().active_operations(), 0);
}

#[test]
fn immediate_submission_after_startup_always_reaches_a_worker() {
    for nonce in 90_u8..122 {
        let executor = Arc::new(ExactlyOnceExecutor {
            counts: Mutex::new(HashMap::new()),
        });
        let runtime = service(
            executor,
            Arc::new(ScriptedRandom::new([random_id(nonce)])),
            config(1, 1, 2),
        );
        let operation = runtime.submit(Command::List(ListEntries)).unwrap();
        assert_eq!(
            operation.wait_result(SHORT_WAIT),
            Ok(OperationResult::Entries(EntrySummaries::empty()))
        );
    }
}

#[test]
fn configuration_enforces_explicit_phase_one_maxima() {
    assert!(
        ServiceConfig::new(
            MAX_QUEUE_CAPACITY,
            MAX_WORKERS,
            MAX_EVENT_CAPACITY,
            MAX_COMPLETED_CAPACITY,
            u64::MAX,
            MAX_ID_RETRIES,
        )
        .is_ok()
    );
    assert_eq!(
        ServiceConfig::new(MAX_QUEUE_CAPACITY + 1, 1, 1, 1, u64::MAX, 1),
        Err(ServiceError::InvalidConfiguration)
    );
    assert_eq!(
        ServiceConfig::new(1, MAX_WORKERS + 1, 1, 1, u64::MAX, 1),
        Err(ServiceError::InvalidConfiguration)
    );
    assert_eq!(
        ServiceConfig::new(1, 1, MAX_EVENT_CAPACITY + 1, 1, u64::MAX, 1),
        Err(ServiceError::InvalidConfiguration)
    );
    assert_eq!(
        ServiceConfig::new(1, 1, 1, MAX_COMPLETED_CAPACITY + 1, u64::MAX, 1),
        Err(ServiceError::InvalidConfiguration)
    );
    assert_eq!(
        ServiceConfig::new(1, 1, 1, 1, u64::MAX, MAX_ID_RETRIES + 1),
        Err(ServiceError::InvalidConfiguration)
    );
}

#[test]
fn repeated_and_mixed_global_controls_trigger_cleanup_once() {
    let (controls_tx, controls_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(ControlRecordingExecutor {
            controls: controls_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(123)])),
        config(1, 1, 2),
    );
    runtime.control(Control::LockNow).unwrap();
    assert_eq!(
        controls_rx.recv_timeout(SHORT_WAIT).unwrap(),
        Control::LockNow
    );
    runtime.control(Control::LockNow).unwrap();
    runtime.control(Control::DeadlineExpired).unwrap();
    runtime.control(Control::Suspend).unwrap();
    runtime.control(Control::UserActivity).unwrap();
    assert_eq!(
        controls_rx.recv_timeout(SHORT_WAIT).unwrap(),
        Control::UserActivity
    );
    assert!(controls_rx.try_recv().is_err());
}

#[test]
fn delayed_control_does_not_accumulate_cancel_notices_across_generations() {
    let work_gate = Arc::new(Gate::default());
    let control_gate = Arc::new(Gate::default());
    let (work_entered_tx, work_entered_rx) = mpsc::channel();
    let (control_entered_tx, control_entered_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(GenerationExecutor {
            work_gate: Arc::clone(&work_gate),
            control_gate: Arc::clone(&control_gate),
            work_entered: work_entered_tx,
            control_entered: control_entered_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(124)])),
        config(2, 2, 2),
    );
    let mut current = vec![
        runtime.submit(Command::List(ListEntries)).unwrap(),
        runtime.submit(Command::List(ListEntries)).unwrap(),
    ];
    work_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    work_entered_rx.recv_timeout(SHORT_WAIT).unwrap();

    for _ in 0..6 {
        runtime.control(Control::UserActivity).unwrap();
        control_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
        for operation in &current {
            runtime.control(Control::Cancel(operation.id())).unwrap();
            runtime.control(Control::Cancel(operation.id())).unwrap();
        }
        work_gate.release(2);
        for operation in &current {
            assert_eq!(
                operation.wait_result(SHORT_WAIT),
                Err(ServiceError::Cancelled)
            );
        }

        let next = vec![
            runtime.submit(Command::List(ListEntries)).unwrap(),
            runtime.submit(Command::List(ListEntries)).unwrap(),
        ];
        control_gate.release(1);
        work_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
        work_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
        current = next;
    }

    work_gate.release(2);
    for operation in current {
        assert_eq!(
            operation.wait_result(SHORT_WAIT),
            Ok(OperationResult::Entries(EntrySummaries::empty()))
        );
    }
    assert!(!runtime.snapshot().is_closed());
}

#[test]
fn completed_cancellation_notice_is_processed_before_later_ordinary_work() {
    let first_gate = Arc::new(Gate::default());
    let control_gate = Arc::new(Gate::default());
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (order_tx, order_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(PendingCancelOrderExecutor {
            first_gate: Arc::clone(&first_gate),
            control_gate: Arc::clone(&control_gate),
            first_entered: first_entered_tx,
            order: order_tx,
            activity_callbacks: AtomicUsize::new(0),
        }),
        Arc::new(ScriptedRandom::new([random_id(129)])),
        config(1, 1, 2),
    );
    let first = runtime.submit(Command::List(ListEntries)).unwrap();
    first_entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    runtime.control(Control::UserActivity).unwrap();
    assert_eq!(
        order_rx.recv_timeout(SHORT_WAIT).unwrap(),
        "activity-entered"
    );
    let ordinary = runtime
        .submit(Command::CreateDirectory(CreateDirectory))
        .unwrap();
    runtime.control(Control::Cancel(first.id())).unwrap();
    first_gate.release(1);
    assert_eq!(first.wait_result(SHORT_WAIT), Err(ServiceError::Cancelled));
    match order_rx.try_recv() {
        Err(mpsc::TryRecvError::Empty) => {}
        unexpected => panic!("work ran while the control observer was blocked: {unexpected:?}"),
    }

    control_gate.release(1);
    assert_eq!(order_rx.recv_timeout(SHORT_WAIT).unwrap(), "cancel");
    assert_eq!(order_rx.recv_timeout(SHORT_WAIT).unwrap(), "ordinary");
    assert_eq!(
        ordinary.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(EntrySummaries::empty()))
    );
}

#[test]
fn synchronous_backend_boundary_observes_the_exact_shared_cancellation_flag() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (observed_tx, observed_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(BackendBoundaryExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
            observed: observed_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(130)])),
        config(1, 1, 2),
    );
    let operation = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    runtime.control(Control::Cancel(operation.id())).unwrap();
    gate.release(1);
    assert!(observed_rx.recv_timeout(SHORT_WAIT).unwrap());
    assert_eq!(
        operation.wait_result(SHORT_WAIT),
        Err(ServiceError::Cancelled)
    );
}

#[test]
fn priority_control_survives_simultaneous_ordinary_and_event_saturation() {
    let control_gate = Arc::new(Gate::default());
    let (control_entered_tx, _control_entered_rx) = mpsc::channel();
    let (emit_attempted_tx, emit_attempted_rx) = mpsc::channel();
    let (emit_result_tx, emit_result_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(DelayedControlExecutor {
            control_gate,
            control_entered: control_entered_tx,
            emit_attempted: emit_attempted_tx,
            emit_result: emit_result_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(125)])),
        config(1, 1, 1),
    );
    let first = runtime.submit(Command::List(ListEntries)).unwrap();
    emit_attempted_rx.recv_timeout(SHORT_WAIT).unwrap();
    let mut accepted = Vec::new();
    loop {
        match runtime.submit(Command::List(ListEntries)) {
            Ok(operation) => accepted.push(operation),
            Err(ServiceError::Busy) => break,
            Err(error) => panic!("unexpected saturation error: {error}"),
        }
    }
    assert_eq!(runtime.control(Control::Suspend), Ok(()));
    assert_eq!(
        emit_result_rx.recv_timeout(SHORT_WAIT).unwrap(),
        Err(ServiceError::Cancelled)
    );
    assert_eq!(first.wait_result(SHORT_WAIT), Err(ServiceError::Cancelled));
    for operation in accepted {
        assert_eq!(
            operation.wait_result(SHORT_WAIT),
            Err(ServiceError::Cancelled)
        );
    }
}

#[test]
fn control_callback_panic_fails_closed_and_resolves_active_operations() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(PanicControlExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
        }),
        Arc::new(ScriptedRandom::new([random_id(126)])),
        config(1, 1, 2),
    );
    let operation = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    runtime.control(Control::UserActivity).unwrap();
    assert_eq!(operation.wait_result(SHORT_WAIT), Err(ServiceError::Closed));
    assert!(runtime.snapshot().is_closed());
    gate.release(1);
}

#[test]
fn try_result_is_nonblocking_and_consumes_one_terminal_value() {
    let executor = Arc::new(ExactlyOnceExecutor {
        counts: Mutex::new(HashMap::new()),
    });
    let runtime = service(
        executor,
        Arc::new(ScriptedRandom::new([random_id(127)])),
        config(1, 1, 2),
    );
    let operation = runtime.submit(Command::List(ListEntries)).unwrap();
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Started)
    );
    assert_eq!(
        operation.wait_next_event(SHORT_WAIT).unwrap(),
        Some(OperationEvent::Completed)
    );
    assert_eq!(
        operation.try_result(),
        Ok(Some(OperationResult::Entries(EntrySummaries::empty())))
    );
    assert_eq!(operation.try_result(), Ok(None));
}

#[test]
fn snapshots_remain_coherent_during_submit_cancel_completion_and_shutdown() {
    let gate = Arc::new(Gate::default());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (boundary_tx, _boundary_rx) = mpsc::channel();
    let runtime = service(
        Arc::new(BlockingExecutor {
            gate: Arc::clone(&gate),
            entered: entered_tx,
            boundary: boundary_tx,
            executions: AtomicUsize::new(0),
        }),
        Arc::new(ScriptedRandom::new([random_id(128)])),
        config(2, 2, 2),
    );
    let first = runtime.submit(Command::List(ListEntries)).unwrap();
    let second = runtime.submit(Command::List(ListEntries)).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    entered_rx.recv_timeout(SHORT_WAIT).unwrap();
    let queued = runtime.submit(Command::List(ListEntries)).unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(6));
    let submit_runtime = runtime.clone();
    let submit_barrier = Arc::clone(&barrier);
    let submitter = std::thread::spawn(move || {
        submit_barrier.wait();
        submit_runtime.submit(Command::CreateFile(CreateFile))
    });
    let cancel_runtime = runtime.clone();
    let cancel_barrier = Arc::clone(&barrier);
    let first_id = first.id();
    let canceller = std::thread::spawn(move || {
        cancel_barrier.wait();
        cancel_runtime.control(Control::Cancel(first_id))
    });
    let snapshot_runtime = runtime.clone();
    let snapshot_barrier = Arc::clone(&barrier);
    let observer = std::thread::spawn(move || {
        snapshot_barrier.wait();
        snapshot_runtime.snapshot()
    });
    let shutdown_runtime = runtime.clone();
    let shutdown_barrier = Arc::clone(&barrier);
    let shutdown = std::thread::spawn(move || {
        shutdown_barrier.wait();
        shutdown_runtime.shutdown();
    });
    let completion_gate = Arc::clone(&gate);
    let completion_barrier = Arc::clone(&barrier);
    let completion = std::thread::spawn(move || {
        completion_barrier.wait();
        completion_gate.release(2);
    });
    barrier.wait();

    let submitted = submitter.join().unwrap();
    let cancel_result = canceller.join().unwrap();
    let snapshot = observer.join().unwrap();
    shutdown.join().unwrap();
    completion.join().unwrap();
    assert_eq!(
        snapshot.active_operations(),
        snapshot.queued_operations() + snapshot.running_operations()
    );
    assert!(matches!(cancel_result, Ok(()) | Err(ServiceError::Closed)));
    assert!(matches!(
        submitted,
        Ok(_) | Err(ServiceError::Busy) | Err(ServiceError::Closed)
    ));
    assert!(matches!(
        first.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(_)) | Err(ServiceError::Cancelled) | Err(ServiceError::Closed)
    ));
    assert!(matches!(
        second.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(_)) | Err(ServiceError::Cancelled) | Err(ServiceError::Closed)
    ));
    assert!(matches!(
        queued.wait_result(SHORT_WAIT),
        Ok(OperationResult::Entries(_)) | Err(ServiceError::Cancelled) | Err(ServiceError::Closed)
    ));
    gate.release(4);
    let final_snapshot = runtime.snapshot();
    assert!(final_snapshot.is_closed());
    assert_eq!(final_snapshot.active_operations(), 0);
}
