//! Black-box conformance checks reusable by storage adapters.

use std::error::Error;
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use crate::{
    BackendError, BackendErrorKind, BackendObjectSink, BootstrapBytes, CreateBootstrapOutcome,
    HeadValue, HeadVersion, OpaqueObjectId, PublishOutcome, StageOutcome, VaultBackend,
};

const MAX_CONFORMANCE_OBJECT_BYTES: u64 = 64 * 1024;
const MAX_CONFORMANCE_BATCH_ITEMS: usize = 64;

/// Creates isolated adapter handles for the standard conformance scenarios.
///
/// Test fixtures advertise an object bound of at most 64 KiB and a batch bound
/// of at most 64 items so exact-boundary tests remain fast and memory bounded,
/// even when the production adapter advertises larger limits.
pub trait ConformanceFactory {
    /// Creates two handles to one fresh backend namespace.
    fn same_namespace(&self) -> Result<ConformanceBackends, BackendError>;

    /// Creates a handle to a separate fresh backend namespace.
    fn distinct_namespace(&self) -> Result<Box<dyn VaultBackend>, BackendError>;

    /// Creates two fresh same-namespace handles with one observable fault armed.
    fn same_namespace_with_fault(
        &self,
        fault: ConformanceFaultPoint,
    ) -> Result<ConformanceBackends, BackendError>;
}

/// Two independent adapter handles to one fresh storage namespace.
pub struct ConformanceBackends {
    /// Primary handle used to initiate operations.
    pub primary: Box<dyn VaultBackend>,
    /// Independent peer handle used for readback.
    pub peer: Box<dyn VaultBackend>,
}

impl ConformanceBackends {
    /// Constructs a same-namespace handle pair.
    pub fn new(primary: Box<dyn VaultBackend>, peer: Box<dyn VaultBackend>) -> Self {
        Self { primary, peer }
    }
}

/// Portable fault boundaries required from an adapter conformance fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceFaultPoint {
    /// Fail before bootstrap read completion.
    BootstrapRead,
    /// Fail before bootstrap creation.
    BootstrapCreate,
    /// Fail before staging consumes object bytes.
    StageBeforeTransfer,
    /// Fail after staging consumes object bytes but before success.
    StageAfterTransfer,
    /// Fail before a fetched object writes any quarantine byte.
    FetchBeforeTransfer,
    /// Fail after fetched bytes are staged but before transfer handoff.
    FetchAfterPartialTransfer,
    /// Fail before any immutable publication bytes become visible.
    CommitBeforeObjects,
    /// Fail after immutable objects may be visible but before the head changes.
    CommitAfterObjects,
    /// Lose the response after the head may have changed.
    CommitAfterHead,
    /// Observe cancellation after a known successful atomic head change.
    CancelAfterKnownCommit,
}

/// Failure of a named black-box conformance scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConformanceFailure {
    scenario: &'static str,
    backend_error: Option<BackendError>,
}

impl ConformanceFailure {
    fn assertion(scenario: &'static str) -> Self {
        Self {
            scenario,
            backend_error: None,
        }
    }

    fn backend(scenario: &'static str, error: BackendError) -> Self {
        Self {
            scenario,
            backend_error: Some(error),
        }
    }

    /// Returns the stable scenario name.
    pub const fn scenario(&self) -> &'static str {
        self.scenario
    }

    /// Returns the adapter error that interrupted the scenario, if any.
    pub const fn backend_error(&self) -> Option<BackendError> {
        self.backend_error
    }
}

impl fmt::Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "backend conformance scenario failed: {}",
            self.scenario
        )
    }
}

impl Error for ConformanceFailure {}

/// Runs portable black-box scenarios through only the public backend SPI.
///
/// The factory must return fresh namespaces and expose portable boundary fault
/// injection so each adapter proves the same deterministic observable outcomes.
/// The standard suite exercises conditional multi-writer publication; adapters
/// advertising no conditional-head support require a separate explicitly
/// single-writer integration proof at their application boundary.
pub fn run_standard_conformance(
    factory: &dyn ConformanceFactory,
) -> Result<(), ConformanceFailure> {
    bootstrap_scenario(factory)?;
    advertised_boundary_scenario(factory)?;
    cancellation_scenario(factory)?;
    publication_scenario(factory)?;
    cursor_namespace_scenario(factory)?;
    adversarial_stream_scenario(factory)?;
    concurrent_scenario(factory)?;
    fault_boundary_scenario(factory)?;
    Ok(())
}

struct CountingReader {
    reads: usize,
}

impl Read for CountingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.reads = self.reads.saturating_add(1);
        Ok(0)
    }
}

fn advertised_boundary_scenario(
    factory: &dyn ConformanceFactory,
) -> Result<(), ConformanceFailure> {
    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("boundary factory", error))?;
    let capabilities = primary.capabilities();
    if capabilities.max_object_bytes() > MAX_CONFORMANCE_OBJECT_BYTES
        || capabilities.max_batch_items() > MAX_CONFORMANCE_BATCH_ITEMS
    {
        return Err(ConformanceFailure::assertion(
            "factory must advertise a bounded conformance test profile",
        ));
    }
    let cancel = AtomicBool::new(false);

    let bootstrap_length = usize::try_from(capabilities.max_bootstrap_bytes())
        .map_err(|_| ConformanceFailure::assertion("bootstrap boundary conversion"))?;
    let mut bootstrap_bytes = Vec::new();
    bootstrap_bytes
        .try_reserve_exact(bootstrap_length)
        .map_err(|_| ConformanceFailure::assertion("bootstrap boundary allocation"))?;
    bootstrap_bytes.resize(bootstrap_length, 7);
    let bootstrap = BootstrapBytes::from_bytes(bootstrap_bytes)
        .map_err(|_| ConformanceFailure::assertion("bootstrap exact boundary"))?;
    primary
        .create_bootstrap_if_absent(&bootstrap, &cancel)
        .map_err(|error| ConformanceFailure::backend("bootstrap exact boundary", error))?;
    let observed = peer
        .read_bootstrap(&cancel)
        .map_err(|error| ConformanceFailure::backend("bootstrap boundary readback", error))?
        .ok_or_else(|| ConformanceFailure::assertion("bootstrap boundary readback"))?;
    if observed.as_bytes() != bootstrap.as_bytes() {
        return Err(ConformanceFailure::assertion("bootstrap boundary readback"));
    }
    let plus_one = bootstrap_length
        .checked_add(1)
        .ok_or_else(|| ConformanceFailure::assertion("bootstrap plus-one arithmetic"))?;
    if plus_one <= crate::MAX_BOOTSTRAP_BYTES {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(plus_one)
            .map_err(|_| ConformanceFailure::assertion("bootstrap plus-one allocation"))?;
        bytes.resize(plus_one, 8);
        let oversized = BootstrapBytes::from_bytes(bytes)
            .map_err(|_| ConformanceFailure::assertion("bootstrap plus-one construction"))?;
        let oversized_backend = factory
            .same_namespace()
            .map_err(|error| ConformanceFailure::backend("bootstrap plus-one factory", error))?
            .primary;
        if !matches!(
            oversized_backend.create_bootstrap_if_absent(&oversized, &cancel),
            Err(error) if error.kind() == BackendErrorKind::Permanent
        ) {
            return Err(ConformanceFailure::assertion("bootstrap plus one"));
        }
    } else {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(plus_one)
            .map_err(|_| ConformanceFailure::assertion("bootstrap hard plus-one allocation"))?;
        bytes.resize(plus_one, 0);
        if !matches!(
            BootstrapBytes::from_bytes(bytes),
            Err(crate::BackendTypeError::LimitExceeded)
        ) {
            return Err(ConformanceFailure::assertion("bootstrap hard plus one"));
        }
    }

    let object_length = usize::try_from(capabilities.max_object_bytes())
        .map_err(|_| ConformanceFailure::assertion("object boundary conversion"))?;
    let mut object = Vec::new();
    object
        .try_reserve_exact(object_length)
        .map_err(|_| ConformanceFailure::assertion("object boundary allocation"))?;
    object.resize(object_length, 9);
    let object_id = OpaqueObjectId::from_bytes([21; 32]);
    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("object boundary begin", error))?;
    publication
        .stage_object(
            &object_id,
            &mut Cursor::new(object.as_slice()),
            capabilities.max_object_bytes(),
            &cancel,
        )
        .map_err(|error| ConformanceFailure::backend("object exact boundary", error))?;
    let head = HeadValue::try_from_slice(b"boundary")
        .map_err(|_| ConformanceFailure::assertion("boundary head"))?;
    if !matches!(
        publication
            .commit(&head, &cancel)
            .map_err(|error| ConformanceFailure::backend("object boundary commit", error))?,
        PublishOutcome::Committed { .. }
    ) {
        return Err(ConformanceFailure::assertion("object boundary commit"));
    }
    let mut sink = AdversarialWriter::new(usize::MAX);
    peer.fetch_object(&object_id, &mut sink, &cancel)
        .map_err(|error| ConformanceFailure::backend("object boundary readback", error))?;
    sink.caller_finalize(false)
        .map_err(|_| ConformanceFailure::assertion("object boundary caller finalize"))?;
    if sink.visible != object
        || sink.finish_transfer_count != 1
        || sink.abort_transfer_count != 0
        || sink.caller_finalize_count != 1
    {
        return Err(ConformanceFailure::assertion("object boundary readback"));
    }
    let observed = peer
        .read_head(&cancel)
        .map_err(|error| ConformanceFailure::backend("object boundary head readback", error))?
        .ok_or_else(|| ConformanceFailure::assertion("object boundary head readback"))?;
    let mut publication = primary
        .begin_publication(Some(observed.version()), &cancel)
        .map_err(|error| ConformanceFailure::backend("object plus-one begin", error))?;
    let mut unread = CountingReader { reads: 0 };
    let plus_one = capabilities
        .max_object_bytes()
        .checked_add(1)
        .ok_or_else(|| ConformanceFailure::assertion("object plus-one arithmetic"))?;
    if !matches!(
        publication.stage_object(
            &OpaqueObjectId::from_bytes([22; 32]),
            &mut unread,
            plus_one,
            &cancel,
        ),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) || unread.reads != 0
    {
        return Err(ConformanceFailure::assertion("object plus one"));
    }
    Ok(())
}

fn bootstrap_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("bootstrap factory", error))?;
    let cancel = AtomicBool::new(false);
    let bootstrap = BootstrapBytes::try_from_slice(b"a")
        .map_err(|_| ConformanceFailure::assertion("construct bootstrap"))?;
    let conflicting = BootstrapBytes::try_from_slice(b"b")
        .map_err(|_| ConformanceFailure::assertion("construct conflicting bootstrap"))?;

    let missing = primary
        .read_bootstrap(&cancel)
        .map_err(|error| ConformanceFailure::backend("read missing bootstrap", error))?;
    if missing.is_some() {
        return Err(ConformanceFailure::assertion("read missing bootstrap"));
    }
    let created = primary
        .create_bootstrap_if_absent(&bootstrap, &cancel)
        .map_err(|error| ConformanceFailure::backend("create bootstrap", error))?;
    if created != CreateBootstrapOutcome::Created {
        return Err(ConformanceFailure::assertion("create bootstrap"));
    }
    let observed = peer
        .read_bootstrap(&cancel)
        .map_err(|error| ConformanceFailure::backend("independent bootstrap readback", error))?
        .ok_or_else(|| ConformanceFailure::assertion("independent bootstrap readback"))?;
    if observed.as_bytes() != bootstrap.as_bytes() {
        return Err(ConformanceFailure::assertion(
            "independent bootstrap readback",
        ));
    }
    let repeated = peer
        .create_bootstrap_if_absent(&bootstrap, &cancel)
        .map_err(|error| ConformanceFailure::backend("bootstrap exact idempotence", error))?;
    if repeated != CreateBootstrapOutcome::AlreadyMatching {
        return Err(ConformanceFailure::assertion("bootstrap exact idempotence"));
    }
    let conflict = primary.create_bootstrap_if_absent(&conflicting, &cancel);
    if !matches!(
        conflict,
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) {
        return Err(ConformanceFailure::assertion("bootstrap conflict"));
    }
    let preserved = peer
        .read_bootstrap(&cancel)
        .map_err(|error| ConformanceFailure::backend("bootstrap conflict preservation", error))?
        .ok_or_else(|| ConformanceFailure::assertion("bootstrap conflict preservation"))?;
    if preserved.as_bytes() != bootstrap.as_bytes() {
        return Err(ConformanceFailure::assertion(
            "bootstrap conflict preservation",
        ));
    }
    Ok(())
}

fn cancellation_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    let ConformanceBackends {
        primary: backend, ..
    } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("cancellation factory", error))?;
    let cancel = AtomicBool::new(true);
    for result in [
        backend.read_bootstrap(&cancel).map(|_| ()),
        backend.read_head(&cancel).map(|_| ()),
    ] {
        if !matches!(result, Err(error) if error.kind() == BackendErrorKind::Cancelled) {
            return Err(ConformanceFailure::assertion("pre-cancelled read"));
        }
    }
    if !matches!(
        backend.begin_publication(None, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Cancelled
    ) {
        return Err(ConformanceFailure::assertion("pre-cancelled publication"));
    }
    let bootstrap = BootstrapBytes::try_from_slice(b"cancelled bootstrap")
        .map_err(|_| ConformanceFailure::assertion("cancel bootstrap construction"))?;
    if !matches!(
        backend.create_bootstrap_if_absent(&bootstrap, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Cancelled
    ) || !matches!(
        backend.list_objects(None, 1, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Cancelled
    ) {
        return Err(ConformanceFailure::assertion("pre-cancelled mutation"));
    }
    let mut output = AdversarialWriter::new(usize::MAX);
    if !matches!(
        backend.fetch_object(
            &OpaqueObjectId::from_bytes([1; 32]),
            &mut output,
            &cancel,
        ),
        Err(error) if error.kind() == BackendErrorKind::Cancelled
    ) || !output.visible.is_empty()
        || output.finish_transfer_count != 0
        || output.abort_transfer_count != 1
    {
        return Err(ConformanceFailure::assertion("pre-cancelled fetch"));
    }
    Ok(())
}

fn publication_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("publication factory", error))?;
    let cancel = AtomicBool::new(false);
    let object_id = OpaqueObjectId::from_bytes([1; 32]);
    let object = b"x";
    let replacement = HeadValue::try_from_slice(b"opaque head")
        .map_err(|_| ConformanceFailure::assertion("construct head"))?;

    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("begin publication", error))?;
    let mut reader = Cursor::new(object.as_slice());
    let staged = publication
        .stage_object(&object_id, &mut reader, object.len() as u64, &cancel)
        .map_err(|error| ConformanceFailure::backend("stage object", error))?;
    if staged != StageOutcome::Staged {
        return Err(ConformanceFailure::assertion("stage object"));
    }
    let committed = publication
        .commit(&replacement, &cancel)
        .map_err(|error| ConformanceFailure::backend("commit publication", error))?;
    let committed_version = match committed {
        PublishOutcome::Committed { observed }
            if observed.value().as_bytes() == replacement.as_bytes() =>
        {
            observed
                .version()
                .try_clone()
                .map_err(|_| ConformanceFailure::assertion("copy committed head version"))?
        }
        _ => return Err(ConformanceFailure::assertion("commit publication")),
    };

    let readback = peer
        .read_head(&cancel)
        .map_err(|error| ConformanceFailure::backend("head readback", error))?
        .ok_or_else(|| ConformanceFailure::assertion("head readback"))?;
    if readback.value().as_bytes() != replacement.as_bytes()
        || readback.version().as_bytes() != committed_version.as_bytes()
    {
        return Err(ConformanceFailure::assertion("head readback"));
    }

    let mut fetched_bytes = Vec::new();
    fetched_bytes
        .try_reserve_exact(object.len())
        .map_err(|_| ConformanceFailure::assertion("fetch allocation"))?;
    let mut fetched = AdversarialWriter::new(usize::MAX);
    fetched.staged = fetched_bytes;
    peer.fetch_object(&object_id, &mut fetched, &cancel)
        .map_err(|error| ConformanceFailure::backend("object readback", error))?;
    fetched
        .caller_finalize(false)
        .map_err(|_| ConformanceFailure::assertion("object caller finalize"))?;
    if fetched.visible != object
        || fetched.finish_transfer_count != 1
        || fetched.abort_transfer_count != 0
        || fetched.caller_finalize_count != 1
    {
        return Err(ConformanceFailure::assertion("object readback"));
    }

    let mut missing_output = AdversarialWriter::new(usize::MAX);
    let missing = peer.fetch_object(
        &OpaqueObjectId::from_bytes([9; 32]),
        &mut missing_output,
        &cancel,
    );
    if !matches!(missing, Err(error) if error.kind() == BackendErrorKind::NotFound)
        || !missing_output.visible.is_empty()
        || missing_output.finish_transfer_count != 0
        || missing_output.abort_transfer_count != 1
    {
        return Err(ConformanceFailure::assertion("missing object"));
    }

    let mut stale = peer
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("begin stale publication", error))?;
    let mut duplicate_reader = Cursor::new(object.as_slice());
    let duplicate = stale
        .stage_object(
            &object_id,
            &mut duplicate_reader,
            object.len() as u64,
            &cancel,
        )
        .map_err(|error| ConformanceFailure::backend("idempotent staging", error))?;
    if duplicate != StageOutcome::AlreadyMatching {
        return Err(ConformanceFailure::assertion("idempotent staging"));
    }
    let stale_replacement = HeadValue::try_from_slice(b"must not replace")
        .map_err(|_| ConformanceFailure::assertion("construct stale replacement"))?;
    let stale_outcome = stale
        .commit(&stale_replacement, &cancel)
        .map_err(|error| ConformanceFailure::backend("stale publication", error))?;
    if !matches!(
        stale_outcome,
        PublishOutcome::Stale { observed: Some(ref observed) }
            if observed.value().as_bytes() == replacement.as_bytes()
    ) {
        return Err(ConformanceFailure::assertion("stale publication"));
    }

    let aborted = peer
        .begin_publication(Some(&committed_version), &cancel)
        .map_err(|error| ConformanceFailure::backend("begin aborted publication", error))?;
    aborted
        .abort()
        .map_err(|error| ConformanceFailure::backend("abort publication", error))?;
    let after_abort = primary
        .read_head(&cancel)
        .map_err(|error| ConformanceFailure::backend("head after abort", error))?
        .ok_or_else(|| ConformanceFailure::assertion("head after abort"))?;
    if after_abort.version().as_bytes() != committed_version.as_bytes() {
        return Err(ConformanceFailure::assertion("head after abort"));
    }

    let page = primary
        .list_objects(None, 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("inventory readback", error))?;
    if page.objects() != [object_id] {
        return Err(ConformanceFailure::assertion("inventory readback"));
    }
    Ok(())
}

fn cursor_namespace_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("cursor factory", error))?;
    let other = factory
        .distinct_namespace()
        .map_err(|error| ConformanceFailure::backend("cursor other factory", error))?;
    let cancel = AtomicBool::new(false);
    if primary.identity() != peer.identity() || primary.identity() == other.identity() {
        return Err(ConformanceFailure::assertion("stable backend identity"));
    }

    if !matches!(
        primary.list_objects(None, 0, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) {
        return Err(ConformanceFailure::assertion("zero inventory limit"));
    }
    let maximum = primary.capabilities().max_inventory_page();
    let too_large = maximum
        .checked_add(1)
        .ok_or_else(|| ConformanceFailure::assertion("inventory limit checked arithmetic"))?;
    if !matches!(
        primary.list_objects(None, too_large, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) {
        return Err(ConformanceFailure::assertion("oversized inventory limit"));
    }

    let first = primary
        .list_objects(None, maximum, &cancel)
        .map_err(|error| ConformanceFailure::backend("empty inventory", error))?;
    if !first.objects().is_empty() || first.next_cursor().is_some() {
        return Err(ConformanceFailure::assertion("empty inventory"));
    }

    let mut expected = None;
    for value in [1_u8, 2] {
        let mut publication = primary
            .begin_publication(expected.as_ref(), &cancel)
            .map_err(|error| ConformanceFailure::backend("cursor publication begin", error))?;
        let mut reader = Cursor::new([value]);
        publication
            .stage_object(
                &OpaqueObjectId::from_bytes([value; 32]),
                &mut reader,
                1,
                &cancel,
            )
            .map_err(|error| ConformanceFailure::backend("cursor publication stage", error))?;
        let head = HeadValue::try_from_slice(&[value])
            .map_err(|_| ConformanceFailure::assertion("cursor head construction"))?;
        expected = match publication
            .commit(&head, &cancel)
            .map_err(|error| ConformanceFailure::backend("cursor publication commit", error))?
        {
            PublishOutcome::Committed { observed } => Some(
                observed
                    .version()
                    .try_clone()
                    .map_err(|_| ConformanceFailure::assertion("cursor head version"))?,
            ),
            _ => return Err(ConformanceFailure::assertion("cursor publication commit")),
        };
    }
    let first = primary
        .list_objects(None, 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("nonempty first inventory page", error))?;
    let cursor = first
        .next_cursor()
        .ok_or_else(|| ConformanceFailure::assertion("nonempty first inventory cursor"))?;
    let second = peer
        .list_objects(Some(cursor), 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("same-namespace cursor", error))?;
    let replay = peer
        .list_objects(Some(cursor), 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("cursor replay", error))?;
    if second.objects().len() != 1
        || second.objects()[0].as_bytes() != replay.objects()[0].as_bytes()
        || second.next_cursor().is_some()
    {
        return Err(ConformanceFailure::assertion("deterministic cursor replay"));
    }
    if !matches!(
        other.list_objects(Some(cursor), 1, &cancel),
        Err(error) if error.kind() == BackendErrorKind::CorruptResponse
    ) {
        return Err(ConformanceFailure::assertion("cross-namespace cursor"));
    }

    let malformed = crate::InventoryCursor::try_from_slice(b"not a valid adapter cursor")
        .map_err(|_| ConformanceFailure::assertion("construct malformed cursor"))?;
    if !matches!(
        primary.list_objects(Some(&malformed), 1, &cancel),
        Err(error) if error.kind() == BackendErrorKind::CorruptResponse
    ) || !matches!(
        other.list_objects(Some(&malformed), 1, &cancel),
        Err(error) if error.kind() == BackendErrorKind::CorruptResponse
    ) {
        return Err(ConformanceFailure::assertion("malformed cursor"));
    }
    Ok(())
}

struct InterruptOnceReader<R> {
    inner: R,
    interrupted: bool,
}

impl<R: Read> Read for InterruptOnceReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.inner.read(bytes)
    }
}

struct CancellingReader<'a> {
    cancel: &'a AtomicBool,
    emitted: bool,
}

impl Read for CancellingReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.emitted {
            return Ok(0);
        }
        self.emitted = true;
        bytes[0] = 1;
        self.cancel.store(true, Ordering::Release);
        Ok(1)
    }
}

struct AdversarialWriter<'a> {
    staged: Vec<u8>,
    visible: Vec<u8>,
    maximum: usize,
    interrupt_once: bool,
    fail_after_first: bool,
    fail_flush: bool,
    writes: usize,
    cancel: Option<&'a AtomicBool>,
    cancel_on_finish_transfer: Option<&'a AtomicBool>,
    fail_finish_transfer: bool,
    finish_transfer_count: usize,
    abort_transfer_count: usize,
    caller_finalize_count: usize,
    drop_counter: Option<&'a std::sync::atomic::AtomicUsize>,
}

impl<'a> AdversarialWriter<'a> {
    fn new(maximum: usize) -> Self {
        Self {
            staged: Vec::new(),
            visible: Vec::new(),
            maximum,
            interrupt_once: false,
            fail_after_first: false,
            fail_flush: false,
            writes: 0,
            cancel: None,
            cancel_on_finish_transfer: None,
            fail_finish_transfer: false,
            finish_transfer_count: 0,
            abort_transfer_count: 0,
            caller_finalize_count: 0,
            drop_counter: None,
        }
    }

    fn caller_finalize(&mut self, fail: bool) -> Result<(), ()> {
        self.caller_finalize_count = self.caller_finalize_count.saturating_add(1);
        if fail {
            return Err(());
        }
        self.visible = std::mem::take(&mut self.staged);
        Ok(())
    }
}

impl Write for AdversarialWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.interrupt_once {
            self.interrupt_once = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if self.fail_after_first && self.writes != 0 {
            return Err(io::Error::other("injected writer failure"));
        }
        let length = bytes.len().min(self.maximum);
        self.staged.extend_from_slice(&bytes[..length]);
        self.writes = self.writes.saturating_add(1);
        if length != 0
            && let Some(cancel) = self.cancel
        {
            cancel.store(true, Ordering::Release);
        }
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

impl BackendObjectSink for AdversarialWriter<'_> {
    fn finish_transfer(&mut self) -> io::Result<()> {
        self.finish_transfer_count = self.finish_transfer_count.saturating_add(1);
        if self.fail_finish_transfer {
            return Err(io::Error::other("injected finish-transfer failure"));
        }
        if let Some(cancel) = self.cancel_on_finish_transfer {
            cancel.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn abort_transfer(&mut self) {
        self.abort_transfer_count = self.abort_transfer_count.saturating_add(1);
        self.staged.clear();
    }
}

impl Drop for AdversarialWriter<'_> {
    fn drop(&mut self) {
        if let Some(counter) = self.drop_counter {
            counter.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn adversarial_stream_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    let cancel = AtomicBool::new(false);
    let id = OpaqueObjectId::from_bytes([11; 32]);
    for (declared, bytes, scenario) in [
        (1_u64, b"".as_slice(), "short reader"),
        (1, b"xy".as_slice(), "long reader"),
        (1, b"".as_slice(), "zero-progress reader"),
    ] {
        let ConformanceBackends { primary, .. } = factory
            .same_namespace()
            .map_err(|error| ConformanceFailure::backend(scenario, error))?;
        let mut publication = primary
            .begin_publication(None, &cancel)
            .map_err(|error| ConformanceFailure::backend(scenario, error))?;
        let mut reader = Cursor::new(bytes);
        if !matches!(
            publication.stage_object(&id, &mut reader, declared, &cancel),
            Err(error) if error.kind() == BackendErrorKind::Permanent
        ) {
            return Err(ConformanceFailure::assertion(scenario));
        }
        let head =
            HeadValue::try_from_slice(b"x").map_err(|_| ConformanceFailure::assertion(scenario))?;
        if !matches!(
            publication.commit(&head, &cancel),
            Err(error) if error.kind() == BackendErrorKind::Permanent
        ) {
            return Err(ConformanceFailure::assertion("poisoned publication"));
        }
    }

    let ConformanceBackends { primary, .. } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("interrupted reader factory", error))?;
    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("interrupted reader begin", error))?;
    let mut interrupted = InterruptOnceReader {
        inner: Cursor::new(b"x"),
        interrupted: false,
    };
    if publication
        .stage_object(&id, &mut interrupted, 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("interrupted reader retry", error))?
        != StageOutcome::Staged
    {
        return Err(ConformanceFailure::assertion("interrupted reader retry"));
    }

    let ConformanceBackends { primary, .. } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("cancelling reader factory", error))?;
    let transfer_cancel = AtomicBool::new(false);
    let mut publication = primary
        .begin_publication(None, &transfer_cancel)
        .map_err(|error| ConformanceFailure::backend("cancelling reader begin", error))?;
    let mut cancelling = CancellingReader {
        cancel: &transfer_cancel,
        emitted: false,
    };
    if !matches!(
        publication.stage_object(&id, &mut cancelling, 1, &transfer_cancel),
        Err(error) if error.kind() == BackendErrorKind::Cancelled
    ) {
        return Err(ConformanceFailure::assertion("cancelling reader"));
    }

    let ConformanceBackends { primary, .. } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("duplicate factory", error))?;
    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("duplicate begin", error))?;
    let mut first = Cursor::new(b"x");
    publication
        .stage_object(&id, &mut first, 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("duplicate first stage", error))?;
    let mut same = Cursor::new(b"x");
    if publication
        .stage_object(&id, &mut same, 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("duplicate exact stage", error))?
        != StageOutcome::AlreadyMatching
    {
        return Err(ConformanceFailure::assertion("duplicate exact stage"));
    }
    let mut different = Cursor::new(b"y");
    if !matches!(
        publication.stage_object(&id, &mut different, 1, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) {
        return Err(ConformanceFailure::assertion("same id different bytes"));
    }

    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("writer factory", error))?;
    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("writer publication begin", error))?;
    let object_length = primary.capabilities().max_object_bytes().min(2);
    let object_bytes = &b"xy"[..object_length as usize];
    publication
        .stage_object(&id, &mut Cursor::new(object_bytes), object_length, &cancel)
        .map_err(|error| ConformanceFailure::backend("writer object stage", error))?;
    let head = HeadValue::try_from_slice(b"writer")
        .map_err(|_| ConformanceFailure::assertion("writer head"))?;
    if !matches!(
        publication
            .commit(&head, &cancel)
            .map_err(|error| ConformanceFailure::backend("writer publication commit", error))?,
        PublishOutcome::Committed { .. }
    ) {
        return Err(ConformanceFailure::assertion("writer publication commit"));
    }
    for (maximum, interrupt_once, scenario) in [
        (1, false, "short writer"),
        (usize::MAX, true, "interrupted writer"),
    ] {
        let mut writer = AdversarialWriter::new(maximum);
        writer.interrupt_once = interrupt_once;
        peer.fetch_object(&id, &mut writer, &cancel)
            .map_err(|error| ConformanceFailure::backend(scenario, error))?;
        writer
            .caller_finalize(false)
            .map_err(|_| ConformanceFailure::assertion(scenario))?;
        if writer.visible != object_bytes
            || writer.finish_transfer_count != 1
            || writer.abort_transfer_count != 0
            || writer.caller_finalize_count != 1
        {
            return Err(ConformanceFailure::assertion(scenario));
        }
    }
    let finish_drop_count = std::sync::atomic::AtomicUsize::new(0);
    {
        let mut finish_failure = AdversarialWriter::new(usize::MAX);
        finish_failure.fail_finish_transfer = true;
        finish_failure.drop_counter = Some(&finish_drop_count);
        if !matches!(
            peer.fetch_object(&id, &mut finish_failure, &cancel),
            Err(error) if error.kind() == BackendErrorKind::Permanent
        ) || finish_failure.finish_transfer_count != 1
            || finish_failure.abort_transfer_count != 1
            || finish_failure.caller_finalize_count != 0
            || !finish_failure.visible.is_empty()
            || !finish_failure.staged.is_empty()
            || finish_drop_count.load(Ordering::Acquire) != 0
        {
            return Err(ConformanceFailure::assertion(
                "finish-transfer failure abort protocol",
            ));
        }
    }
    if finish_drop_count.load(Ordering::Acquire) != 1 {
        return Err(ConformanceFailure::assertion(
            "finish-transfer failure caller drop",
        ));
    }

    let late_cancel = AtomicBool::new(false);
    let late_drop_count = std::sync::atomic::AtomicUsize::new(0);
    {
        let mut late = AdversarialWriter::new(usize::MAX);
        late.cancel_on_finish_transfer = Some(&late_cancel);
        late.drop_counter = Some(&late_drop_count);
        peer.fetch_object(&id, &mut late, &late_cancel)
            .map_err(|error| {
                ConformanceFailure::backend("late cancellation after transfer handoff", error)
            })?;
        if !late_cancel.load(Ordering::Acquire)
            || late.finish_transfer_count != 1
            || late.abort_transfer_count != 0
            || late.caller_finalize_count != 0
            || !late.visible.is_empty()
            || late.staged != object_bytes
            || late_drop_count.load(Ordering::Acquire) != 0
        {
            return Err(ConformanceFailure::assertion(
                "late cancellation after transfer handoff",
            ));
        }
    }
    if late_drop_count.load(Ordering::Acquire) != 1 {
        return Err(ConformanceFailure::assertion("late cancellation drop"));
    }

    let drop_count = std::sync::atomic::AtomicUsize::new(0);
    {
        let mut finalize_failure = AdversarialWriter::new(usize::MAX);
        finalize_failure.drop_counter = Some(&drop_count);
        peer.fetch_object(&id, &mut finalize_failure, &cancel)
            .map_err(|error| ConformanceFailure::backend("caller finalize setup", error))?;
        if finalize_failure.caller_finalize(true).is_ok()
            || finalize_failure.finish_transfer_count != 1
            || finalize_failure.abort_transfer_count != 0
            || finalize_failure.caller_finalize_count != 1
            || !finalize_failure.visible.is_empty()
            || finalize_failure.staged != object_bytes
        {
            return Err(ConformanceFailure::assertion("caller finalize failure"));
        }
    }
    if drop_count.load(Ordering::Acquire) != 1 {
        return Err(ConformanceFailure::assertion(
            "caller finalize failure drop count",
        ));
    }
    if object_bytes.len() > 1 {
        let mut failing = AdversarialWriter::new(1);
        failing.fail_after_first = true;
        if !matches!(
            peer.fetch_object(&id, &mut failing, &cancel),
            Err(error) if error.kind() == BackendErrorKind::Permanent
        ) || !failing.staged.is_empty()
            || !failing.visible.is_empty()
            || failing.finish_transfer_count != 0
            || failing.abort_transfer_count != 1
        {
            return Err(ConformanceFailure::assertion(
                "writer failure leaves no visible bytes",
            ));
        }
    }
    let mut flush_failure = AdversarialWriter::new(usize::MAX);
    flush_failure.fail_flush = true;
    if !matches!(
        peer.fetch_object(&id, &mut flush_failure, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) || flush_failure.finish_transfer_count != 0
        || flush_failure.abort_transfer_count != 1
        || !flush_failure.visible.is_empty()
        || !flush_failure.staged.is_empty()
    {
        return Err(ConformanceFailure::assertion(
            "flush failure abort protocol",
        ));
    }
    let mut zero = AdversarialWriter::new(0);
    if !matches!(
        peer.fetch_object(&id, &mut zero, &cancel),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) || !zero.visible.is_empty()
        || zero.finish_transfer_count != 0
        || zero.abort_transfer_count != 1
    {
        return Err(ConformanceFailure::assertion("zero-progress writer"));
    }
    let writer_cancel = AtomicBool::new(false);
    let mut cancelling_writer = AdversarialWriter::new(1);
    cancelling_writer.cancel = Some(&writer_cancel);
    if !matches!(
        peer.fetch_object(&id, &mut cancelling_writer, &writer_cancel),
        Err(error) if error.kind() == BackendErrorKind::Cancelled
    ) || !cancelling_writer.visible.is_empty()
        || !cancelling_writer.staged.is_empty()
        || cancelling_writer.finish_transfer_count != 0
        || cancelling_writer.abort_transfer_count != 1
    {
        return Err(ConformanceFailure::assertion("cancelling writer"));
    }

    let ConformanceBackends { primary, .. } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("batch factory", error))?;
    let maximum = primary.capabilities().max_batch_items();
    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("batch begin", error))?;
    for index in 0..maximum {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
        publication
            .stage_object(
                &OpaqueObjectId::from_bytes(bytes),
                &mut Cursor::new(b"x"),
                1,
                &cancel,
            )
            .map_err(|error| ConformanceFailure::backend("exact batch", error))?;
    }
    let mut extra_bytes = [0_u8; 32];
    extra_bytes[24..].copy_from_slice(&(maximum as u64).to_be_bytes());
    if !matches!(
        publication.stage_object(
            &OpaqueObjectId::from_bytes(extra_bytes),
            &mut Cursor::new(b"x"),
            1,
            &cancel,
        ),
        Err(error) if error.kind() == BackendErrorKind::Permanent
    ) {
        return Err(ConformanceFailure::assertion("batch plus one"));
    }
    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("exact batch factory", error))?;
    let mut publication = primary
        .begin_publication(None, &cancel)
        .map_err(|error| ConformanceFailure::backend("exact batch begin", error))?;
    for index in 0..maximum {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
        publication
            .stage_object(
                &OpaqueObjectId::from_bytes(bytes),
                &mut Cursor::new(b"x"),
                1,
                &cancel,
            )
            .map_err(|error| ConformanceFailure::backend("exact batch stage", error))?;
    }
    let batch_head = HeadValue::try_from_slice(b"batch")
        .map_err(|_| ConformanceFailure::assertion("exact batch head"))?;
    if !matches!(
        publication
            .commit(&batch_head, &cancel)
            .map_err(|error| ConformanceFailure::backend("exact batch commit", error))?,
        PublishOutcome::Committed { .. }
    ) || peer
        .read_head(&cancel)
        .map_err(|error| ConformanceFailure::backend("exact batch readback", error))?
        .is_none()
    {
        return Err(ConformanceFailure::assertion("exact batch commit"));
    }
    Ok(())
}

fn commit_one(
    backend: &dyn VaultBackend,
    expected: Option<&HeadVersion>,
    id: OpaqueObjectId,
    value: u8,
) -> Result<HeadVersion, ConformanceFailure> {
    let cancel = AtomicBool::new(false);
    let mut publication = backend
        .begin_publication(expected, &cancel)
        .map_err(|error| ConformanceFailure::backend("concurrent setup begin", error))?;
    publication
        .stage_object(&id, &mut Cursor::new([value]), 1, &cancel)
        .map_err(|error| ConformanceFailure::backend("concurrent setup stage", error))?;
    let head = HeadValue::try_from_slice(&[value])
        .map_err(|_| ConformanceFailure::assertion("concurrent setup head"))?;
    match publication
        .commit(&head, &cancel)
        .map_err(|error| ConformanceFailure::backend("concurrent setup commit", error))?
    {
        PublishOutcome::Committed { observed } => observed
            .version()
            .try_clone()
            .map_err(|_| ConformanceFailure::assertion("concurrent setup version")),
        _ => Err(ConformanceFailure::assertion("concurrent setup commit")),
    }
}

fn concurrent_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("concurrent inventory factory", error))?;
    let first = OpaqueObjectId::from_bytes([1; 32]);
    let second = OpaqueObjectId::from_bytes([2; 32]);
    let third = OpaqueObjectId::from_bytes([3; 32]);
    let first_version = commit_one(primary.as_ref(), None, first, 1)?;
    let second_version = commit_one(primary.as_ref(), Some(&first_version), second, 2)?;
    let barrier = Arc::new(Barrier::new(2));
    let listing_barrier = Arc::clone(&barrier);
    let listing = thread::spawn(move || {
        listing_barrier.wait();
        let cancel = AtomicBool::new(false);
        let mut identifiers = Vec::new();
        identifiers
            .try_reserve_exact(3)
            .map_err(|_| ConformanceFailure::assertion("concurrent inventory allocation"))?;
        let mut cursor = None;
        let mut page_count = 0_usize;
        loop {
            page_count = page_count
                .checked_add(1)
                .ok_or_else(|| ConformanceFailure::assertion("concurrent inventory page count"))?;
            if page_count > 3 {
                return Err(ConformanceFailure::assertion(
                    "concurrent inventory page budget",
                ));
            }
            let page = primary
                .list_objects(cursor.as_ref(), 1, &cancel)
                .map_err(|error| ConformanceFailure::backend("concurrent inventory page", error))?;
            let total = identifiers
                .len()
                .checked_add(page.objects().len())
                .ok_or_else(|| {
                    ConformanceFailure::assertion("concurrent inventory object count")
                })?;
            if total > 3 {
                return Err(ConformanceFailure::assertion(
                    "concurrent inventory object budget",
                ));
            }
            identifiers.extend_from_slice(page.objects());
            cursor = page
                .next_cursor()
                .map(crate::InventoryCursor::try_clone)
                .transpose()
                .map_err(|_| ConformanceFailure::assertion("concurrent inventory cursor copy"))?;
            if cursor.is_none() {
                break;
            }
        }
        Ok::<_, ConformanceFailure>(identifiers)
    });
    let publishing_barrier = Arc::clone(&barrier);
    let publishing = thread::spawn(move || {
        publishing_barrier.wait();
        let cancel = AtomicBool::new(false);
        let mut publication = peer.begin_publication(Some(&second_version), &cancel)?;
        publication.stage_object(&third, &mut Cursor::new([3]), 1, &cancel)?;
        let head = HeadValue::try_from_slice(b"three")
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        publication.commit(&head, &cancel)
    });
    let identifiers = listing
        .join()
        .map_err(|_| ConformanceFailure::assertion("concurrent inventory thread"))??;
    if !matches!(
        publishing
            .join()
            .map_err(|_| ConformanceFailure::assertion("concurrent publication thread"))?
            .map_err(|error| ConformanceFailure::backend("concurrent inventory publish", error))?,
        PublishOutcome::Committed { .. }
    ) {
        return Err(ConformanceFailure::assertion(
            "concurrent inventory publish",
        ));
    }
    let pre = [first, second];
    let post = [first, second, third];
    if identifiers.as_slice() != pre && identifiers.as_slice() != post {
        return Err(ConformanceFailure::assertion(
            "concurrent complete inventory snapshot",
        ));
    }

    let ConformanceBackends { primary, peer } = factory
        .same_namespace()
        .map_err(|error| ConformanceFailure::backend("concurrent cas factory", error))?;
    let version = commit_one(
        primary.as_ref(),
        None,
        OpaqueObjectId::from_bytes([7; 32]),
        7,
    )?;
    let cancel = AtomicBool::new(false);
    let mut left = primary
        .begin_publication(Some(&version), &cancel)
        .map_err(|error| ConformanceFailure::backend("left cas begin", error))?;
    let mut right = peer
        .begin_publication(Some(&version), &cancel)
        .map_err(|error| ConformanceFailure::backend("right cas begin", error))?;
    left.stage_object(
        &OpaqueObjectId::from_bytes([8; 32]),
        &mut Cursor::new([8]),
        1,
        &cancel,
    )
    .map_err(|error| ConformanceFailure::backend("left cas stage", error))?;
    right
        .stage_object(
            &OpaqueObjectId::from_bytes([9; 32]),
            &mut Cursor::new([9]),
            1,
            &cancel,
        )
        .map_err(|error| ConformanceFailure::backend("right cas stage", error))?;
    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let left_commit = thread::spawn(move || {
        left_barrier.wait();
        left.commit(
            &HeadValue::try_from_slice(b"left")
                .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?,
            &AtomicBool::new(false),
        )
    });
    let right_barrier = Arc::clone(&barrier);
    let right_commit = thread::spawn(move || {
        right_barrier.wait();
        right.commit(
            &HeadValue::try_from_slice(b"right")
                .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?,
            &AtomicBool::new(false),
        )
    });
    let left_outcome = left_commit
        .join()
        .map_err(|_| ConformanceFailure::assertion("left cas thread"))?
        .map_err(|error| ConformanceFailure::backend("left cas commit", error))?;
    let right_outcome = right_commit
        .join()
        .map_err(|_| ConformanceFailure::assertion("right cas thread"))?
        .map_err(|error| ConformanceFailure::backend("right cas commit", error))?;
    let left_won = matches!(left_outcome, PublishOutcome::Committed { .. });
    let right_won = matches!(right_outcome, PublishOutcome::Committed { .. });
    if left_won == right_won
        || !matches!(
            if left_won {
                right_outcome
            } else {
                left_outcome
            },
            PublishOutcome::Stale { .. }
        )
    {
        return Err(ConformanceFailure::assertion(
            "concurrent conditional single winner",
        ));
    }
    let final_head = primary
        .read_head(&AtomicBool::new(false))
        .map_err(|error| ConformanceFailure::backend("concurrent cas readback", error))?
        .ok_or_else(|| ConformanceFailure::assertion("concurrent cas readback"))?;
    let expected = if left_won {
        b"left".as_slice()
    } else {
        b"right".as_slice()
    };
    if final_head.value().as_bytes() != expected {
        return Err(ConformanceFailure::assertion("concurrent cas winner"));
    }
    Ok(())
}

fn fault_boundary_scenario(factory: &dyn ConformanceFactory) -> Result<(), ConformanceFailure> {
    use ConformanceFaultPoint::{
        BootstrapCreate, BootstrapRead, CancelAfterKnownCommit, CommitAfterHead,
        CommitAfterObjects, CommitBeforeObjects, FetchAfterPartialTransfer, FetchBeforeTransfer,
        StageAfterTransfer, StageBeforeTransfer,
    };

    let cancel = AtomicBool::new(false);
    let bootstrap = BootstrapBytes::try_from_slice(b"x")
        .map_err(|_| ConformanceFailure::assertion("fault bootstrap construction"))?;
    let ConformanceBackends {
        primary: backend, ..
    } = factory
        .same_namespace_with_fault(BootstrapRead)
        .map_err(|error| ConformanceFailure::backend("bootstrap read fault factory", error))?;
    if !matches!(backend.read_bootstrap(&cancel), Err(error) if error.kind() == BackendErrorKind::Unavailable)
    {
        return Err(ConformanceFailure::assertion("bootstrap read fault"));
    }
    let ConformanceBackends {
        primary: backend,
        peer,
    } = factory
        .same_namespace_with_fault(BootstrapCreate)
        .map_err(|error| ConformanceFailure::backend("bootstrap create fault factory", error))?;
    if !matches!(backend.create_bootstrap_if_absent(&bootstrap, &cancel), Err(error) if error.kind() == BackendErrorKind::Unavailable)
        || peer
            .read_bootstrap(&cancel)
            .map_err(|error| ConformanceFailure::backend("bootstrap create fault readback", error))?
            .is_some()
    {
        return Err(ConformanceFailure::assertion("bootstrap create fault"));
    }

    for fault in [StageBeforeTransfer, StageAfterTransfer] {
        let ConformanceBackends {
            primary: backend,
            peer,
        } = factory
            .same_namespace_with_fault(fault)
            .map_err(|error| ConformanceFailure::backend("stage fault factory", error))?;
        let mut publication = backend
            .begin_publication(None, &cancel)
            .map_err(|error| ConformanceFailure::backend("stage fault begin", error))?;
        let mut reader = Cursor::new(b"x".as_slice());
        if !matches!(publication.stage_object(&OpaqueObjectId::from_bytes([1; 32]), &mut reader, 1, &cancel), Err(error) if error.kind() == BackendErrorKind::Unavailable)
            || peer
                .read_head(&cancel)
                .map_err(|error| ConformanceFailure::backend("stage fault readback", error))?
                .is_some()
        {
            return Err(ConformanceFailure::assertion("stage fault"));
        }
    }

    for fault in [FetchBeforeTransfer, FetchAfterPartialTransfer] {
        let ConformanceBackends {
            primary: backend,
            peer,
        } = factory
            .same_namespace_with_fault(fault)
            .map_err(|error| ConformanceFailure::backend("fetch fault factory", error))?;
        let object_id = OpaqueObjectId::from_bytes([3; 32]);
        let mut publication = backend
            .begin_publication(None, &cancel)
            .map_err(|error| ConformanceFailure::backend("fetch fault begin", error))?;
        publication
            .stage_object(&object_id, &mut Cursor::new(b"x"), 1, &cancel)
            .map_err(|error| ConformanceFailure::backend("fetch fault stage", error))?;
        let head = HeadValue::try_from_slice(b"fetch fault")
            .map_err(|_| ConformanceFailure::assertion("fetch fault head"))?;
        if !matches!(
            publication
                .commit(&head, &cancel)
                .map_err(|error| ConformanceFailure::backend("fetch fault commit", error))?,
            PublishOutcome::Committed { .. }
        ) {
            return Err(ConformanceFailure::assertion("fetch fault commit"));
        }

        let drop_count = std::sync::atomic::AtomicUsize::new(0);
        {
            let mut sink = AdversarialWriter::new(usize::MAX);
            sink.drop_counter = Some(&drop_count);
            if !matches!(
                peer.fetch_object(&object_id, &mut sink, &cancel),
                Err(error) if error.kind() == BackendErrorKind::Unavailable
            ) || sink.finish_transfer_count != 0
                || sink.abort_transfer_count != 1
                || sink.caller_finalize_count != 0
                || !sink.staged.is_empty()
                || !sink.visible.is_empty()
                || drop_count.load(Ordering::Acquire) != 0
            {
                return Err(ConformanceFailure::assertion("fetch fault abort protocol"));
            }
        }
        if drop_count.load(Ordering::Acquire) != 1 {
            return Err(ConformanceFailure::assertion("fetch fault caller drop"));
        }
    }

    for fault in [
        CommitBeforeObjects,
        CommitAfterObjects,
        CommitAfterHead,
        CancelAfterKnownCommit,
    ] {
        let ConformanceBackends {
            primary: backend,
            peer,
        } = factory
            .same_namespace_with_fault(fault)
            .map_err(|error| ConformanceFailure::backend("commit fault factory", error))?;
        let object_id = OpaqueObjectId::from_bytes([2; 32]);
        let mut publication = backend
            .begin_publication(None, &cancel)
            .map_err(|error| ConformanceFailure::backend("commit fault begin", error))?;
        let mut reader = Cursor::new(b"x".as_slice());
        publication
            .stage_object(&object_id, &mut reader, 1, &cancel)
            .map_err(|error| ConformanceFailure::backend("commit fault stage", error))?;
        let head = HeadValue::try_from_slice(b"fault head")
            .map_err(|_| ConformanceFailure::assertion("fault head construction"))?;
        let outcome = publication.commit(&head, &cancel);
        let late_cancellation_observed = cancel.load(std::sync::atomic::Ordering::Acquire);
        if fault == CancelAfterKnownCommit {
            cancel.store(false, std::sync::atomic::Ordering::Release);
        }
        let readback = peer
            .read_head(&cancel)
            .map_err(|error| ConformanceFailure::backend("commit fault head readback", error))?;
        match fault {
            CommitBeforeObjects | CommitAfterObjects => {
                if !matches!(outcome, Err(error) if error.kind() == BackendErrorKind::Unavailable)
                    || readback.is_some()
                {
                    return Err(ConformanceFailure::assertion("pre-head commit fault"));
                }
            }
            CommitAfterHead => {
                if !matches!(outcome, Ok(PublishOutcome::Indeterminate)) {
                    return Err(ConformanceFailure::assertion(
                        "post-head indeterminate outcome",
                    ));
                }
                let readback = readback.ok_or_else(|| {
                    ConformanceFailure::assertion("indeterminate mandatory readback")
                })?;
                if readback.value().as_bytes() != head.as_bytes() {
                    return Err(ConformanceFailure::assertion(
                        "indeterminate mandatory readback",
                    ));
                }
                let mut object = AdversarialWriter::new(usize::MAX);
                peer.fetch_object(&object_id, &mut object, &cancel)
                    .map_err(|error| {
                        ConformanceFailure::backend("indeterminate object readback", error)
                    })?;
                object
                    .caller_finalize(false)
                    .map_err(|_| ConformanceFailure::assertion("indeterminate caller finalize"))?;
                if object.visible != b"x" {
                    return Err(ConformanceFailure::assertion(
                        "indeterminate object readback",
                    ));
                }
            }
            CancelAfterKnownCommit => {
                if !matches!(outcome, Ok(PublishOutcome::Committed { .. }))
                    || !late_cancellation_observed
                    || readback.is_none()
                {
                    return Err(ConformanceFailure::assertion(
                        "known commit wins over late cancellation",
                    ));
                }
            }
            _ => return Err(ConformanceFailure::assertion("commit fault dispatch")),
        }
    }
    Ok(())
}
