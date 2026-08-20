use std::io::{self, Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;

use notecrypt_backend::conformance::{
    ConformanceBackends, ConformanceFactory, ConformanceFaultPoint, run_standard_conformance,
};
use notecrypt_backend::{
    BackendCapabilities, BackendError, BackendErrorKind, BackendIdentity, BackendObjectSink,
    BackendPublication, BackendTypeError, BootstrapBytes, CreateBootstrapOutcome, HeadValue,
    HeadVersion, InventoryCursor, InventoryPage, MAX_ADVERTISED_BATCH_ITEMS,
    MAX_ADVERTISED_CONCURRENCY, MAX_ADVERTISED_INVENTORY_PAGE, MAX_ADVERTISED_OBJECT_BYTES,
    MAX_BOOTSTRAP_BYTES, MAX_CURSOR_BYTES, MAX_HEAD_BYTES, MAX_HEAD_VERSION_BYTES, ObservedHead,
    OpaqueObjectId, PublishOutcome, StageOutcome, VaultBackend, check_cancelled,
};

const MAX_OBJECT_BYTES: u64 = 4096;
const MAX_PAGE: usize = 3;
const MAX_BATCH: usize = 3;
const MAX_SNAPSHOTS: usize = 64;
const CURSOR_MAGIC: [u8; 8] = *b"NCMEM001";

static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FaultPoint {
    None = 0,
    BootstrapRead = 1,
    BootstrapCreate = 2,
    StageBeforeRead = 3,
    StageAfterRead = 4,
    CommitBeforeObjects = 5,
    CommitAfterObjects = 6,
    CommitAfterHead = 7,
    CancelAfterKnownCommit = 8,
    FetchBeforeTransfer = 9,
    FetchAfterPartialTransfer = 10,
}

struct Namespace {
    id: u64,
    capabilities: BackendCapabilities,
    state: Mutex<State>,
    fault: AtomicU8,
}

struct State {
    bootstrap: Option<Vec<u8>>,
    head: Option<StoredHead>,
    objects: Vec<(OpaqueObjectId, Vec<u8>)>,
    snapshots: Vec<(u64, Vec<OpaqueObjectId>)>,
    next_snapshot: u64,
    next_head_version: u64,
}

struct StoredHead {
    version: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone)]
struct MemoryBackend {
    namespace: Arc<Namespace>,
}

impl MemoryBackend {
    fn fresh() -> Self {
        Self::fresh_with_capabilities(
            BackendCapabilities::new(
                true,
                MAX_BOOTSTRAP_BYTES as u64,
                MAX_OBJECT_BYTES,
                MAX_PAGE,
                MAX_BATCH,
                2,
            )
            .expect("static capabilities are valid"),
        )
    }

    fn fresh_with_capabilities(capabilities: BackendCapabilities) -> Self {
        Self {
            namespace: Arc::new(Namespace {
                id: NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed),
                capabilities,
                state: Mutex::new(State {
                    bootstrap: None,
                    head: None,
                    objects: Vec::new(),
                    snapshots: Vec::new(),
                    next_snapshot: 1,
                    next_head_version: 1,
                }),
                fault: AtomicU8::new(FaultPoint::None as u8),
            }),
        }
    }

    fn peer(&self) -> Self {
        self.clone()
    }

    fn inject(&self, fault: FaultPoint) {
        self.namespace.fault.store(fault as u8, Ordering::Release);
    }

    fn take_fault(&self, fault: FaultPoint) -> bool {
        self.namespace
            .fault
            .compare_exchange(
                fault as u8,
                FaultPoint::None as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, BackendError> {
        self.namespace
            .state
            .lock()
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))
    }

    fn observed(head: &StoredHead) -> Result<ObservedHead, BackendError> {
        let version = HeadVersion::try_from_slice(&head.version)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        let value = HeadValue::try_from_slice(&head.value)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        Ok(ObservedHead::new(version, value))
    }
}

impl VaultBackend for MemoryBackend {
    fn identity(&self) -> BackendIdentity {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&self.namespace.id.to_be_bytes());
        BackendIdentity::from_bytes(bytes)
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.namespace.capabilities
    }

    fn read_bootstrap(&self, cancel: &AtomicBool) -> Result<Option<BootstrapBytes>, BackendError> {
        check_cancelled(cancel)?;
        if self.take_fault(FaultPoint::BootstrapRead) {
            return Err(BackendError::new(BackendErrorKind::Unavailable));
        }
        let state = self.lock()?;
        check_cancelled(cancel)?;
        state
            .bootstrap
            .as_deref()
            .map(BootstrapBytes::try_from_slice)
            .transpose()
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))
    }

    fn create_bootstrap_if_absent(
        &self,
        bootstrap: &BootstrapBytes,
        cancel: &AtomicBool,
    ) -> Result<CreateBootstrapOutcome, BackendError> {
        check_cancelled(cancel)?;
        self.capabilities().check_bootstrap(bootstrap)?;
        if self.take_fault(FaultPoint::BootstrapCreate) {
            return Err(BackendError::new(BackendErrorKind::Unavailable));
        }
        let mut state = self.lock()?;
        check_cancelled(cancel)?;
        match state.bootstrap.as_deref() {
            Some(existing) if existing == bootstrap.as_bytes() => {
                Ok(CreateBootstrapOutcome::AlreadyMatching)
            }
            Some(_) => Err(BackendError::new(BackendErrorKind::Permanent)),
            None => {
                let mut stored = Vec::new();
                stored
                    .try_reserve_exact(bootstrap.len())
                    .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
                stored.extend_from_slice(bootstrap.as_bytes());
                state.bootstrap = Some(stored);
                Ok(CreateBootstrapOutcome::Created)
            }
        }
    }

    fn read_head(&self, cancel: &AtomicBool) -> Result<Option<ObservedHead>, BackendError> {
        check_cancelled(cancel)?;
        let state = self.lock()?;
        check_cancelled(cancel)?;
        state.head.as_ref().map(Self::observed).transpose()
    }

    fn list_objects(
        &self,
        cursor: Option<&InventoryCursor>,
        limit: usize,
        cancel: &AtomicBool,
    ) -> Result<InventoryPage, BackendError> {
        check_cancelled(cancel)?;
        let capabilities = self.capabilities();
        capabilities.check_inventory_limit(limit)?;
        let mut state = self.lock()?;
        check_cancelled(cancel)?;

        let (snapshot_id, offset) = match cursor {
            Some(cursor) => decode_cursor(cursor, self.namespace.id)?,
            None => {
                let snapshot_id = state.next_snapshot;
                state.next_snapshot = state
                    .next_snapshot
                    .checked_add(1)
                    .ok_or_else(|| BackendError::new(BackendErrorKind::Permanent))?;
                let mut identifiers = Vec::new();
                identifiers
                    .try_reserve_exact(state.objects.len())
                    .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
                identifiers.extend(state.objects.iter().map(|(id, _)| *id));
                identifiers.sort_unstable();
                if identifiers.len() > limit {
                    if state.snapshots.len() >= MAX_SNAPSHOTS {
                        return Err(BackendError::new(BackendErrorKind::RateLimited));
                    }
                    state
                        .snapshots
                        .try_reserve(1)
                        .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
                    state.snapshots.push((snapshot_id, identifiers));
                } else {
                    return InventoryPage::from_parts(identifiers, None, limit, &capabilities)
                        .map_err(|_| BackendError::new(BackendErrorKind::CorruptResponse));
                }
                (snapshot_id, 0)
            }
        };
        let snapshot = state
            .snapshots
            .iter()
            .find(|(candidate, _)| *candidate == snapshot_id)
            .map(|(_, identifiers)| identifiers)
            .ok_or_else(|| BackendError::new(BackendErrorKind::CorruptResponse))?;
        if offset > snapshot.len() {
            return Err(BackendError::new(BackendErrorKind::CorruptResponse));
        }
        let end = offset
            .checked_add(limit)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Permanent))?
            .min(snapshot.len());
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(end - offset)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        objects.extend_from_slice(&snapshot[offset..end]);
        let next = if end < snapshot.len() {
            Some(encode_cursor(self.namespace.id, snapshot_id, end)?)
        } else {
            None
        };
        check_cancelled(cancel)?;
        InventoryPage::from_parts(objects, next, limit, &capabilities)
            .map_err(|_| BackendError::new(BackendErrorKind::CorruptResponse))
    }

    fn fetch_object(
        &self,
        id: &OpaqueObjectId,
        writer: &mut dyn BackendObjectSink,
        cancel: &AtomicBool,
    ) -> Result<(), BackendError> {
        macro_rules! abort_with {
            ($error:expr) => {{
                writer.abort_transfer();
                return Err($error);
            }};
        }
        if let Err(error) = check_cancelled(cancel) {
            abort_with!(error);
        }
        if self.take_fault(FaultPoint::FetchBeforeTransfer) {
            abort_with!(BackendError::new(BackendErrorKind::Unavailable));
        }
        let state = match self.lock() {
            Ok(state) => state,
            Err(error) => abort_with!(error),
        };
        if let Err(error) = check_cancelled(cancel) {
            abort_with!(error);
        }
        let Some(stored) = state
            .objects
            .iter()
            .find(|(candidate, _)| candidate == id)
            .map(|(_, bytes)| bytes)
        else {
            abort_with!(BackendError::new(BackendErrorKind::NotFound));
        };
        let mut copy = Vec::new();
        if copy.try_reserve_exact(stored.len()).is_err() {
            abort_with!(BackendError::new(BackendErrorKind::Permanent));
        }
        copy.extend_from_slice(stored);
        drop(state);
        if let Err(error) = check_cancelled(cancel) {
            abort_with!(error);
        }
        let mut offset = 0;
        while offset < copy.len() {
            if let Err(error) = check_cancelled(cancel) {
                abort_with!(error);
            }
            let written = loop {
                match writer.write(&copy[offset..]) {
                    Ok(written) => break written,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        if let Err(error) = check_cancelled(cancel) {
                            abort_with!(error);
                        }
                    }
                    Err(_) => abort_with!(BackendError::new(BackendErrorKind::Permanent)),
                }
            };
            if let Err(error) = check_cancelled(cancel) {
                abort_with!(error);
            }
            if written == 0 {
                abort_with!(BackendError::new(BackendErrorKind::Permanent));
            }
            let Some(next_offset) = offset.checked_add(written) else {
                abort_with!(BackendError::new(BackendErrorKind::Permanent));
            };
            offset = next_offset;
            if self.take_fault(FaultPoint::FetchAfterPartialTransfer) {
                abort_with!(BackendError::new(BackendErrorKind::Unavailable));
            }
        }
        loop {
            match writer.flush() {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    if let Err(error) = check_cancelled(cancel) {
                        abort_with!(error);
                    }
                }
                Err(_) => abort_with!(BackendError::new(BackendErrorKind::Permanent)),
            }
        }
        if let Err(error) = check_cancelled(cancel) {
            abort_with!(error);
        }
        match writer.finish_transfer() {
            Ok(()) => Ok(()),
            Err(_) => {
                writer.abort_transfer();
                Err(BackendError::new(BackendErrorKind::Permanent))
            }
        }
    }

    fn begin_publication(
        &self,
        expected: Option<&HeadVersion>,
        cancel: &AtomicBool,
    ) -> Result<Box<dyn BackendPublication>, BackendError> {
        check_cancelled(cancel)?;
        let capabilities = self.capabilities();
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(capabilities.max_batch_items())
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        let expected = expected
            .map(HeadVersion::try_clone)
            .transpose()
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        check_cancelled(cancel)?;
        Ok(Box::new(MemoryPublication {
            backend: self.clone(),
            expected,
            staged,
            poisoned: false,
        }))
    }
}

struct MemoryPublication {
    backend: MemoryBackend,
    expected: Option<HeadVersion>,
    staged: Vec<(OpaqueObjectId, Vec<u8>)>,
    poisoned: bool,
}

impl MemoryPublication {
    fn fail<T>(&mut self, kind: BackendErrorKind) -> Result<T, BackendError> {
        self.poisoned = true;
        Err(BackendError::new(kind))
    }

    fn read_exact_object(
        &mut self,
        reader: &mut dyn Read,
        length: u64,
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>, BackendError> {
        let length =
            usize::try_from(length).map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        let mut buffer = [0_u8; 1024];
        while bytes.len() < length {
            check_cancelled(cancel)?;
            let remaining = length - bytes.len();
            let requested = remaining.min(buffer.len());
            let read = loop {
                match reader.read(&mut buffer[..requested]) {
                    Ok(read) => break read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        check_cancelled(cancel)?;
                    }
                    Err(_) => return Err(BackendError::new(BackendErrorKind::Unavailable)),
                }
            };
            check_cancelled(cancel)?;
            if read == 0 {
                return Err(BackendError::new(BackendErrorKind::Permanent));
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        check_cancelled(cancel)?;
        let mut excess = [0_u8; 1];
        let read = loop {
            match reader.read(&mut excess) {
                Ok(read) => break read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    check_cancelled(cancel)?;
                }
                Err(_) => return Err(BackendError::new(BackendErrorKind::Unavailable)),
            }
        };
        check_cancelled(cancel)?;
        if read != 0 {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        Ok(bytes)
    }
}

impl BackendPublication for MemoryPublication {
    fn stage_object(
        &mut self,
        id: &OpaqueObjectId,
        reader: &mut dyn Read,
        length: u64,
        cancel: &AtomicBool,
    ) -> Result<StageOutcome, BackendError> {
        if self.poisoned {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        if let Err(error) = check_cancelled(cancel) {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.backend.capabilities().check_object_length(length) {
            self.poisoned = true;
            return Err(error);
        }
        if self.backend.take_fault(FaultPoint::StageBeforeRead) {
            return self.fail(BackendErrorKind::Unavailable);
        }
        let bytes = match self.read_exact_object(reader, length, cancel) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if self.backend.take_fault(FaultPoint::StageAfterRead) {
            return self.fail(BackendErrorKind::Unavailable);
        }

        if let Some((_, existing)) = self.staged.iter().find(|(candidate, _)| candidate == id) {
            return if existing == &bytes {
                Ok(StageOutcome::AlreadyMatching)
            } else {
                self.fail(BackendErrorKind::Permanent)
            };
        }
        {
            if let Err(error) = check_cancelled(cancel) {
                return self.fail(error.kind());
            }
            let backend = self.backend.clone();
            let state = match backend.lock() {
                Ok(state) => state,
                Err(error) => return self.fail(error.kind()),
            };
            if let Err(error) = check_cancelled(cancel) {
                drop(state);
                return self.fail(error.kind());
            }
            let existing_match = state
                .objects
                .iter()
                .find(|(candidate, _)| candidate == id)
                .map(|(_, existing)| existing == &bytes);
            drop(state);
            if let Some(matches) = existing_match {
                if matches {
                    return Ok(StageOutcome::AlreadyMatching);
                }
                return self.fail(BackendErrorKind::Permanent);
            }
        }
        let next_count = self
            .staged
            .len()
            .checked_add(1)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Permanent))?;
        if let Err(error) = self.backend.capabilities().check_batch_count(next_count) {
            self.poisoned = true;
            return Err(error);
        }
        self.staged.push((*id, bytes));
        Ok(StageOutcome::Staged)
    }

    fn commit(
        mut self: Box<Self>,
        replacement: &HeadValue,
        cancel: &AtomicBool,
    ) -> Result<PublishOutcome, BackendError> {
        if self.poisoned {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        check_cancelled(cancel)?;
        if self.backend.take_fault(FaultPoint::CommitBeforeObjects) {
            return Err(BackendError::new(BackendErrorKind::Unavailable));
        }

        let mut replacement_bytes = Vec::new();
        replacement_bytes
            .try_reserve_exact(replacement.len())
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        replacement_bytes.extend_from_slice(replacement.as_bytes());

        let mut state = self.backend.lock()?;
        check_cancelled(cancel)?;
        let current_version = state.head.as_ref().map(|head| head.version.as_slice());
        let expected_version = self.expected.as_ref().map(HeadVersion::as_bytes);
        if current_version != expected_version {
            return Ok(PublishOutcome::Stale {
                observed: state
                    .head
                    .as_ref()
                    .map(MemoryBackend::observed)
                    .transpose()?,
            });
        }

        for (id, bytes) in &self.staged {
            if let Some((_, existing)) = state.objects.iter().find(|(candidate, _)| candidate == id)
                && existing != bytes
            {
                return Err(BackendError::new(BackendErrorKind::Permanent));
            }
        }
        let missing = self
            .staged
            .iter()
            .filter(|(id, _)| !state.objects.iter().any(|(candidate, _)| candidate == id))
            .count();
        state
            .objects
            .try_reserve(missing)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        for entry in self.staged.drain(..) {
            if !state
                .objects
                .iter()
                .any(|(candidate, _)| candidate == &entry.0)
            {
                state.objects.push(entry);
            }
        }
        state.objects.sort_unstable_by_key(|(id, _)| *id);
        if self.backend.take_fault(FaultPoint::CommitAfterObjects) {
            return Err(BackendError::new(BackendErrorKind::Unavailable));
        }
        check_cancelled(cancel)?;

        let version_number = state.next_head_version;
        state.next_head_version = state
            .next_head_version
            .checked_add(1)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Permanent))?;
        let mut version = Vec::new();
        version
            .try_reserve_exact(8)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        version.extend_from_slice(&version_number.to_be_bytes());
        let observed_version = HeadVersion::try_from_slice(&version)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        let observed_value = HeadValue::try_from_slice(&replacement_bytes)
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        state.head = Some(StoredHead {
            version,
            value: replacement_bytes,
        });
        if self.backend.take_fault(FaultPoint::CommitAfterHead) {
            return Ok(PublishOutcome::Indeterminate);
        }
        if self.backend.take_fault(FaultPoint::CancelAfterKnownCommit) {
            cancel.store(true, Ordering::Release);
        }
        Ok(PublishOutcome::Committed {
            observed: ObservedHead::new(observed_version, observed_value),
        })
    }

    fn abort(self: Box<Self>) -> Result<(), BackendError> {
        Ok(())
    }
}

fn encode_cursor(
    namespace: u64,
    snapshot: u64,
    offset: usize,
) -> Result<InventoryCursor, BackendError> {
    let offset =
        u64::try_from(offset).map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(32)
        .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
    bytes.extend_from_slice(&CURSOR_MAGIC);
    bytes.extend_from_slice(&namespace.to_be_bytes());
    bytes.extend_from_slice(&snapshot.to_be_bytes());
    bytes.extend_from_slice(&offset.to_be_bytes());
    InventoryCursor::from_bytes(bytes).map_err(|_| BackendError::new(BackendErrorKind::Permanent))
}

fn decode_cursor(cursor: &InventoryCursor, namespace: u64) -> Result<(u64, usize), BackendError> {
    let bytes: &[u8; 32] = cursor
        .as_bytes()
        .try_into()
        .map_err(|_| BackendError::new(BackendErrorKind::CorruptResponse))?;
    if bytes[..8] != CURSOR_MAGIC
        || u64::from_be_bytes(bytes[8..16].try_into().unwrap()) != namespace
    {
        return Err(BackendError::new(BackendErrorKind::CorruptResponse));
    }
    let snapshot = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let offset = usize::try_from(u64::from_be_bytes(bytes[24..32].try_into().unwrap()))
        .map_err(|_| BackendError::new(BackendErrorKind::CorruptResponse))?;
    Ok((snapshot, offset))
}

struct MemoryFactory;

struct LowLimitMemoryFactory;

fn memory_fault(fault: ConformanceFaultPoint) -> FaultPoint {
    match fault {
        ConformanceFaultPoint::BootstrapRead => FaultPoint::BootstrapRead,
        ConformanceFaultPoint::BootstrapCreate => FaultPoint::BootstrapCreate,
        ConformanceFaultPoint::StageBeforeTransfer => FaultPoint::StageBeforeRead,
        ConformanceFaultPoint::StageAfterTransfer => FaultPoint::StageAfterRead,
        ConformanceFaultPoint::FetchBeforeTransfer => FaultPoint::FetchBeforeTransfer,
        ConformanceFaultPoint::FetchAfterPartialTransfer => FaultPoint::FetchAfterPartialTransfer,
        ConformanceFaultPoint::CommitBeforeObjects => FaultPoint::CommitBeforeObjects,
        ConformanceFaultPoint::CommitAfterObjects => FaultPoint::CommitAfterObjects,
        ConformanceFaultPoint::CommitAfterHead => FaultPoint::CommitAfterHead,
        ConformanceFaultPoint::CancelAfterKnownCommit => FaultPoint::CancelAfterKnownCommit,
    }
}

impl ConformanceFactory for MemoryFactory {
    fn same_namespace(&self) -> Result<ConformanceBackends, BackendError> {
        let primary = MemoryBackend::fresh();
        Ok(ConformanceBackends::new(
            Box::new(primary.peer()),
            Box::new(primary),
        ))
    }

    fn distinct_namespace(&self) -> Result<Box<dyn VaultBackend>, BackendError> {
        Ok(Box::new(MemoryBackend::fresh()))
    }

    fn same_namespace_with_fault(
        &self,
        fault: ConformanceFaultPoint,
    ) -> Result<ConformanceBackends, BackendError> {
        let backend = MemoryBackend::fresh();
        backend.inject(memory_fault(fault));
        Ok(ConformanceBackends::new(
            Box::new(backend.peer()),
            Box::new(backend),
        ))
    }
}

impl LowLimitMemoryFactory {
    fn fresh() -> MemoryBackend {
        MemoryBackend::fresh_with_capabilities(
            BackendCapabilities::new(true, 1, 1, 1, 1, 1).unwrap(),
        )
    }
}

impl ConformanceFactory for LowLimitMemoryFactory {
    fn same_namespace(&self) -> Result<ConformanceBackends, BackendError> {
        let backend = Self::fresh();
        Ok(ConformanceBackends::new(
            Box::new(backend.peer()),
            Box::new(backend),
        ))
    }

    fn distinct_namespace(&self) -> Result<Box<dyn VaultBackend>, BackendError> {
        Ok(Box::new(Self::fresh()))
    }

    fn same_namespace_with_fault(
        &self,
        fault: ConformanceFaultPoint,
    ) -> Result<ConformanceBackends, BackendError> {
        let backend = Self::fresh();
        backend.inject(memory_fault(fault));
        Ok(ConformanceBackends::new(
            Box::new(backend.peer()),
            Box::new(backend),
        ))
    }
}

fn publish(
    backend: &MemoryBackend,
    expected: Option<&HeadVersion>,
    objects: &[(OpaqueObjectId, &[u8])],
    head: &[u8],
) -> PublishOutcome {
    let cancel = AtomicBool::new(false);
    let mut publication = backend.begin_publication(expected, &cancel).unwrap();
    for (id, bytes) in objects {
        let mut reader = Cursor::new(*bytes);
        publication
            .stage_object(id, &mut reader, bytes.len() as u64, &cancel)
            .unwrap();
    }
    let head = HeadValue::try_from_slice(head).unwrap();
    publication.commit(&head, &cancel).unwrap()
}

fn committed_version(outcome: PublishOutcome) -> HeadVersion {
    match outcome {
        PublishOutcome::Committed { observed } => observed.version().try_clone().unwrap(),
        _ => panic!("expected committed publication"),
    }
}

fn error_kind<T>(result: Result<T, BackendError>) -> BackendErrorKind {
    match result {
        Ok(_) => panic!("expected backend error"),
        Err(error) => error.kind(),
    }
}

#[test]
fn reusable_black_box_conformance_is_green() {
    run_standard_conformance(&MemoryFactory).unwrap();
    run_standard_conformance(&LowLimitMemoryFactory).unwrap();
}

#[test]
fn bounded_types_and_capabilities_reject_invalid_limits() {
    let exact_bootstrap = BootstrapBytes::from_bytes(vec![0; MAX_BOOTSTRAP_BYTES]).unwrap();
    let exact_backend = MemoryBackend::fresh();
    let cancel = AtomicBool::new(false);
    assert_eq!(
        exact_backend
            .create_bootstrap_if_absent(&exact_bootstrap, &cancel)
            .unwrap(),
        CreateBootstrapOutcome::Created
    );
    assert_eq!(
        exact_backend
            .read_bootstrap(&cancel)
            .unwrap()
            .unwrap()
            .len(),
        MAX_BOOTSTRAP_BYTES
    );
    assert!(matches!(
        BootstrapBytes::from_bytes(vec![0; MAX_BOOTSTRAP_BYTES + 1]),
        Err(BackendTypeError::LimitExceeded)
    ));
    assert!(HeadValue::from_bytes(vec![0; MAX_HEAD_BYTES]).is_ok());
    assert!(matches!(
        HeadValue::from_bytes(vec![0; MAX_HEAD_BYTES + 1]),
        Err(BackendTypeError::LimitExceeded)
    ));
    assert!(HeadVersion::from_bytes(vec![0; MAX_HEAD_VERSION_BYTES]).is_ok());
    assert!(matches!(
        HeadVersion::from_bytes(vec![0; MAX_HEAD_VERSION_BYTES + 1]),
        Err(BackendTypeError::LimitExceeded)
    ));
    assert!(InventoryCursor::from_bytes(vec![0; MAX_CURSOR_BYTES]).is_ok());
    assert!(matches!(
        InventoryCursor::from_bytes(vec![0; MAX_CURSOR_BYTES + 1]),
        Err(BackendTypeError::LimitExceeded)
    ));
    for invalid in [
        BackendCapabilities::new(true, 0, 1, 1, 1, 1),
        BackendCapabilities::new(true, 1, 0, 1, 1, 1),
        BackendCapabilities::new(true, 1, 1, 0, 1, 1),
        BackendCapabilities::new(true, 1, 1, 1, 0, 1),
        BackendCapabilities::new(true, 1, 1, 1, 1, 0),
    ] {
        assert_eq!(invalid, Err(BackendTypeError::ZeroLimit));
    }
    assert_eq!(
        BackendCapabilities::new(true, MAX_BOOTSTRAP_BYTES as u64 + 1, 1, 1, 1, 1),
        Err(BackendTypeError::IncoherentCapabilities)
    );
    for invalid in [
        BackendCapabilities::new(true, 1, MAX_ADVERTISED_OBJECT_BYTES + 1, 1, 1, 1),
        BackendCapabilities::new(true, 1, 1, MAX_ADVERTISED_INVENTORY_PAGE + 1, 1, 1),
        BackendCapabilities::new(true, 1, 1, 1, MAX_ADVERTISED_BATCH_ITEMS + 1, 1),
        BackendCapabilities::new(true, 1, 1, 1, 1, MAX_ADVERTISED_CONCURRENCY + 1),
    ] {
        assert_eq!(invalid, Err(BackendTypeError::IncoherentCapabilities));
    }
    assert!(
        BackendCapabilities::new(
            true,
            MAX_BOOTSTRAP_BYTES as u64,
            MAX_ADVERTISED_OBJECT_BYTES,
            MAX_ADVERTISED_INVENTORY_PAGE,
            MAX_ADVERTISED_BATCH_ITEMS,
            MAX_ADVERTISED_CONCURRENCY,
        )
        .is_ok()
    );
    let capabilities = MemoryBackend::fresh().capabilities();
    assert!(capabilities.conditional_head());
    assert_eq!(
        capabilities.max_bootstrap_bytes(),
        MAX_BOOTSTRAP_BYTES as u64
    );
    assert_eq!(capabilities.max_object_bytes(), MAX_OBJECT_BYTES);
    assert_eq!(capabilities.max_inventory_page(), MAX_PAGE);
    assert_eq!(capabilities.max_batch_items(), MAX_BATCH);
    assert_eq!(capabilities.safe_concurrency(), 2);
    assert!(capabilities.check_concurrency(2).is_ok());
    assert_eq!(
        capabilities.check_concurrency(3).unwrap_err().kind(),
        BackendErrorKind::Permanent
    );
}

#[test]
fn bootstrap_is_opaque_exact_immutable_and_independently_readable() {
    for bytes in [
        b"malformed transport".as_slice(),
        b"stale profile bytes".as_slice(),
        b"another vault replay".as_slice(),
    ] {
        let backend = MemoryBackend::fresh();
        let peer = backend.peer();
        let cancel = AtomicBool::new(false);
        let bootstrap = BootstrapBytes::try_from_slice(bytes).unwrap();
        assert_eq!(
            backend
                .create_bootstrap_if_absent(&bootstrap, &cancel)
                .unwrap(),
            CreateBootstrapOutcome::Created
        );
        assert_eq!(
            peer.read_bootstrap(&cancel).unwrap().unwrap().as_bytes(),
            bytes
        );
        let conflict = BootstrapBytes::try_from_slice(b"conflict").unwrap();
        assert_eq!(
            peer.create_bootstrap_if_absent(&conflict, &cancel)
                .unwrap_err()
                .kind(),
            BackendErrorKind::Permanent
        );
        assert_eq!(
            backend.read_bootstrap(&cancel).unwrap().unwrap().as_bytes(),
            bytes
        );
    }

    let backend = MemoryBackend::fresh();
    backend.inject(FaultPoint::BootstrapRead);
    assert_eq!(
        error_kind(backend.read_bootstrap(&AtomicBool::new(false))),
        BackendErrorKind::Unavailable
    );
    backend.inject(FaultPoint::BootstrapCreate);
    let value = BootstrapBytes::try_from_slice(b"value").unwrap();
    assert_eq!(
        backend
            .create_bootstrap_if_absent(&value, &AtomicBool::new(false))
            .unwrap_err()
            .kind(),
        BackendErrorKind::Unavailable
    );
    assert!(
        backend
            .read_bootstrap(&AtomicBool::new(false))
            .unwrap()
            .is_none()
    );
}

struct InterruptOnce<R> {
    inner: R,
    interrupted: bool,
}

impl<R: Read> Read for InterruptOnce<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.inner.read(buffer)
    }
}

struct CancellingReader<'a> {
    cancel: &'a AtomicBool,
    emitted: bool,
}

impl Read for CancellingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.emitted {
            return Ok(0);
        }
        self.emitted = true;
        buffer[0] = 7;
        self.cancel.store(true, Ordering::Release);
        Ok(1)
    }
}

struct PanicReader;

impl Read for PanicReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("oversized declaration must fail before reading")
    }
}

#[test]
fn staging_enforces_exact_streams_cancellation_and_poisoning() {
    let backend = MemoryBackend::fresh();
    let cancel = AtomicBool::new(false);
    let id = OpaqueObjectId::from_bytes([1; 32]);

    for (declared, bytes) in [
        (3, b"ab".as_slice()),
        (2, b"abc".as_slice()),
        (1, b"".as_slice()),
    ] {
        let mut publication = backend.begin_publication(None, &cancel).unwrap();
        let mut reader = Cursor::new(bytes);
        assert_eq!(
            publication
                .stage_object(&id, &mut reader, declared, &cancel)
                .unwrap_err()
                .kind(),
            BackendErrorKind::Permanent
        );
        let head = HeadValue::try_from_slice(b"head").unwrap();
        assert_eq!(
            error_kind(publication.commit(&head, &cancel)),
            BackendErrorKind::Permanent
        );
    }

    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    let mut interrupted = InterruptOnce {
        inner: Cursor::new(b"abc"),
        interrupted: false,
    };
    assert_eq!(
        publication
            .stage_object(&id, &mut interrupted, 3, &cancel)
            .unwrap(),
        StageOutcome::Staged
    );

    let cancelled = AtomicBool::new(false);
    let mut publication = backend.begin_publication(None, &cancelled).unwrap();
    let mut cancelling = CancellingReader {
        cancel: &cancelled,
        emitted: false,
    };
    assert_eq!(
        publication
            .stage_object(&id, &mut cancelling, 2, &cancelled)
            .unwrap_err()
            .kind(),
        BackendErrorKind::Cancelled
    );

    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    assert_eq!(
        publication
            .stage_object(&id, &mut PanicReader, MAX_OBJECT_BYTES + 1, &cancel)
            .unwrap_err()
            .kind(),
        BackendErrorKind::Permanent
    );

    let maximum = vec![5_u8; MAX_OBJECT_BYTES as usize];
    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    assert_eq!(
        publication
            .stage_object(
                &id,
                &mut Cursor::new(maximum.as_slice()),
                MAX_OBJECT_BYTES,
                &cancel,
            )
            .unwrap(),
        StageOutcome::Staged
    );
}

#[test]
fn staging_is_idempotent_rejects_conflicts_and_enforces_batch_limit() {
    let backend = MemoryBackend::fresh();
    let cancel = AtomicBool::new(false);
    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    let first = OpaqueObjectId::from_bytes([1; 32]);
    let bytes = b"same";
    assert_eq!(
        publication
            .stage_object(&first, &mut Cursor::new(bytes), 4, &cancel)
            .unwrap(),
        StageOutcome::Staged
    );
    assert_eq!(
        publication
            .stage_object(&first, &mut Cursor::new(bytes), 4, &cancel)
            .unwrap(),
        StageOutcome::AlreadyMatching
    );
    assert_eq!(
        publication
            .stage_object(&first, &mut Cursor::new(b"diff"), 4, &cancel)
            .unwrap_err()
            .kind(),
        BackendErrorKind::Permanent
    );

    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    for value in 0_u8..MAX_BATCH as u8 {
        let id = OpaqueObjectId::from_bytes([value; 32]);
        assert_eq!(
            publication
                .stage_object(&id, &mut Cursor::new([value]), 1, &cancel)
                .unwrap(),
            StageOutcome::Staged
        );
    }
    let extra = OpaqueObjectId::from_bytes([9; 32]);
    assert_eq!(
        publication
            .stage_object(&extra, &mut Cursor::new([9]), 1, &cancel)
            .unwrap_err()
            .kind(),
        BackendErrorKind::Permanent
    );
}

#[test]
fn inventory_is_snapshot_bound_replayable_and_namespace_safe() {
    let backend = MemoryBackend::fresh();
    let peer = backend.peer();
    let other = MemoryBackend::fresh();
    let cancel = AtomicBool::new(false);
    let objects: Vec<_> = (1_u8..=3)
        .map(|value| (OpaqueObjectId::from_bytes([value; 32]), vec![value]))
        .collect();
    let borrowed: Vec<_> = objects
        .iter()
        .map(|(id, bytes)| (*id, bytes.as_slice()))
        .collect();
    let version = committed_version(publish(&backend, None, &borrowed, b"head-1"));

    let first = backend.list_objects(None, 1, &cancel).unwrap();
    assert_eq!(first.objects().len(), 1);
    let cursor = first.next_cursor().unwrap().try_clone().unwrap();

    let new_id = OpaqueObjectId::from_bytes([4; 32]);
    let _ = publish(&backend, Some(&version), &[(new_id, b"four")], b"head-2");
    let second = peer.list_objects(Some(&cursor), 1, &cancel).unwrap();
    let replay = peer.list_objects(Some(&cursor), 1, &cancel).unwrap();
    assert_eq!(
        second
            .objects()
            .iter()
            .map(OpaqueObjectId::as_bytes)
            .collect::<Vec<_>>(),
        replay
            .objects()
            .iter()
            .map(OpaqueObjectId::as_bytes)
            .collect::<Vec<_>>()
    );
    assert_ne!(second.objects()[0].as_bytes(), new_id.as_bytes());
    assert_eq!(
        error_kind(other.list_objects(Some(&cursor), 1, &cancel)),
        BackendErrorKind::CorruptResponse
    );

    let mut seen = Vec::new();
    let mut next = None;
    loop {
        let page = backend
            .list_objects(next.as_ref(), MAX_PAGE, &cancel)
            .unwrap();
        seen.extend_from_slice(page.objects());
        next = page
            .next_cursor()
            .map(InventoryCursor::try_clone)
            .transpose()
            .unwrap();
        if next.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 4, "pagination must not duplicate identifiers");
    seen.sort_unstable();
    let expected = (1_u8..=4)
        .map(|value| OpaqueObjectId::from_bytes([value; 32]))
        .collect::<Vec<_>>();
    assert_eq!(
        seen.iter()
            .map(OpaqueObjectId::as_bytes)
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(OpaqueObjectId::as_bytes)
            .collect::<Vec<_>>()
    );
    seen.dedup();
    assert_eq!(seen.len(), 4);
    assert!(backend.list_objects(None, MAX_PAGE, &cancel).is_ok());
    assert_eq!(
        error_kind(backend.list_objects(None, MAX_PAGE + 1, &cancel)),
        BackendErrorKind::Permanent
    );
}

#[test]
fn concurrent_inventory_is_a_complete_pre_or_post_publication_snapshot() {
    let backend = MemoryBackend::fresh();
    let base_objects = [
        (OpaqueObjectId::from_bytes([1; 32]), b"a".as_slice()),
        (OpaqueObjectId::from_bytes([2; 32]), b"b".as_slice()),
    ];
    let version = committed_version(publish(&backend, None, &base_objects, b"base"));
    let barrier = Arc::new(Barrier::new(2));

    let listing_backend = backend.peer();
    let listing_barrier = Arc::clone(&barrier);
    let listing = thread::spawn(move || {
        listing_barrier.wait();
        let cancel = AtomicBool::new(false);
        let mut identifiers = Vec::new();
        let mut cursor = None;
        loop {
            let page = listing_backend
                .list_objects(cursor.as_ref(), 1, &cancel)
                .unwrap();
            identifiers.extend_from_slice(page.objects());
            cursor = page
                .next_cursor()
                .map(InventoryCursor::try_clone)
                .transpose()
                .unwrap();
            if cursor.is_none() {
                break;
            }
        }
        identifiers
    });

    let publishing_backend = backend.peer();
    let publishing_barrier = Arc::clone(&barrier);
    let publishing = thread::spawn(move || {
        publishing_barrier.wait();
        publish(
            &publishing_backend,
            Some(&version),
            &[(OpaqueObjectId::from_bytes([3; 32]), b"c")],
            b"next",
        )
    });

    let listed = listing.join().unwrap();
    assert!(matches!(
        publishing.join().unwrap(),
        PublishOutcome::Committed { .. }
    ));
    let pre = vec![
        OpaqueObjectId::from_bytes([1; 32]),
        OpaqueObjectId::from_bytes([2; 32]),
    ];
    let post = vec![
        OpaqueObjectId::from_bytes([1; 32]),
        OpaqueObjectId::from_bytes([2; 32]),
        OpaqueObjectId::from_bytes([3; 32]),
    ];
    assert!(listed == pre || listed == post);
}

#[test]
fn concurrent_conditional_publications_have_one_winner() {
    let backend = MemoryBackend::fresh();
    let peer = backend.peer();
    let version = committed_version(publish(&backend, None, &[], b"base"));
    let cancel = AtomicBool::new(false);
    let mut first = backend.begin_publication(Some(&version), &cancel).unwrap();
    let mut second = peer.begin_publication(Some(&version), &cancel).unwrap();
    first
        .stage_object(
            &OpaqueObjectId::from_bytes([1; 32]),
            &mut Cursor::new(b"a"),
            1,
            &cancel,
        )
        .unwrap();
    second
        .stage_object(
            &OpaqueObjectId::from_bytes([2; 32]),
            &mut Cursor::new(b"b"),
            1,
            &cancel,
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = Arc::clone(&barrier);
    let first_commit = thread::spawn(move || {
        first_barrier.wait();
        first.commit(
            &HeadValue::try_from_slice(b"first").unwrap(),
            &AtomicBool::new(false),
        )
    });
    let second_barrier = Arc::clone(&barrier);
    let second_commit = thread::spawn(move || {
        second_barrier.wait();
        second.commit(
            &HeadValue::try_from_slice(b"second").unwrap(),
            &AtomicBool::new(false),
        )
    });
    let first_outcome = first_commit.join().unwrap().unwrap();
    let second_outcome = second_commit.join().unwrap().unwrap();
    let first_won = matches!(first_outcome, PublishOutcome::Committed { .. });
    let second_won = matches!(second_outcome, PublishOutcome::Committed { .. });
    assert_ne!(first_won, second_won);
    assert!(matches!(
        if first_won {
            second_outcome
        } else {
            first_outcome
        },
        PublishOutcome::Stale { .. }
    ));
    let final_head = backend.read_head(&AtomicBool::new(false)).unwrap().unwrap();
    assert_eq!(
        final_head.value().as_bytes(),
        if first_won {
            b"first".as_slice()
        } else {
            b"second".as_slice()
        }
    );
}

#[test]
fn publication_faults_preserve_atomic_head_semantics() {
    let cancel = AtomicBool::new(false);
    for fault in [
        FaultPoint::CommitBeforeObjects,
        FaultPoint::CommitAfterObjects,
    ] {
        let backend = MemoryBackend::fresh();
        backend.inject(fault);
        let mut publication = backend.begin_publication(None, &cancel).unwrap();
        publication
            .stage_object(
                &OpaqueObjectId::from_bytes([1; 32]),
                &mut Cursor::new(b"object"),
                6,
                &cancel,
            )
            .unwrap();
        let head = HeadValue::try_from_slice(b"new").unwrap();
        assert_eq!(
            error_kind(publication.commit(&head, &cancel)),
            BackendErrorKind::Unavailable
        );
        assert!(backend.read_head(&cancel).unwrap().is_none());
        let mut unreachable = ShortWriter {
            staged: Vec::new(),
            visible: Vec::new(),
            maximum: usize::MAX,
        };
        let fetch = backend.fetch_object(
            &OpaqueObjectId::from_bytes([1; 32]),
            &mut unreachable,
            &cancel,
        );
        if fault == FaultPoint::CommitAfterObjects {
            assert!(fetch.is_ok());
            assert!(unreachable.visible.is_empty());
            unreachable.caller_finalize();
            assert_eq!(unreachable.visible, b"object");
        } else {
            assert_eq!(error_kind(fetch), BackendErrorKind::NotFound);
            assert!(unreachable.visible.is_empty());
        }
    }

    let backend = MemoryBackend::fresh();
    backend.inject(FaultPoint::CommitAfterHead);
    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    let id = OpaqueObjectId::from_bytes([7; 32]);
    publication
        .stage_object(&id, &mut Cursor::new(b"object"), 6, &cancel)
        .unwrap();
    let head = HeadValue::try_from_slice(b"new").unwrap();
    assert!(matches!(
        publication.commit(&head, &cancel).unwrap(),
        PublishOutcome::Indeterminate
    ));
    let observed = backend.read_head(&cancel).unwrap().unwrap();
    assert_eq!(observed.value().as_bytes(), b"new");
    let mut output = ShortWriter {
        staged: Vec::new(),
        visible: Vec::new(),
        maximum: usize::MAX,
    };
    backend.fetch_object(&id, &mut output, &cancel).unwrap();
    assert!(output.visible.is_empty());
    output.caller_finalize();
    assert_eq!(output.visible, b"object");

    for fault in [FaultPoint::StageBeforeRead, FaultPoint::StageAfterRead] {
        let backend = MemoryBackend::fresh();
        backend.inject(fault);
        let mut publication = backend.begin_publication(None, &cancel).unwrap();
        assert_eq!(
            publication
                .stage_object(&id, &mut Cursor::new(b"object"), 6, &cancel)
                .unwrap_err()
                .kind(),
            BackendErrorKind::Unavailable
        );
        assert_eq!(
            error_kind(publication.commit(&head, &cancel)),
            BackendErrorKind::Permanent
        );
        assert!(backend.read_head(&cancel).unwrap().is_none());
    }
}

#[test]
fn cancellation_and_abort_before_commit_preserve_the_head() {
    let backend = MemoryBackend::fresh();
    let cancel = AtomicBool::new(false);
    let id = OpaqueObjectId::from_bytes([3; 32]);
    let mut publication = backend.begin_publication(None, &cancel).unwrap();
    publication
        .stage_object(&id, &mut Cursor::new(b"x"), 1, &cancel)
        .unwrap();
    cancel.store(true, Ordering::Release);
    let head = HeadValue::try_from_slice(b"head").unwrap();
    assert_eq!(
        error_kind(publication.commit(&head, &cancel)),
        BackendErrorKind::Cancelled
    );
    assert!(
        backend
            .read_head(&AtomicBool::new(false))
            .unwrap()
            .is_none()
    );

    let active = AtomicBool::new(false);
    let mut publication = backend.begin_publication(None, &active).unwrap();
    publication
        .stage_object(&id, &mut Cursor::new(b"x"), 1, &active)
        .unwrap();
    publication.abort().unwrap();
    assert!(backend.read_head(&active).unwrap().is_none());
}

struct ShortWriter {
    staged: Vec<u8>,
    visible: Vec<u8>,
    maximum: usize,
}

impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len().min(self.maximum);
        self.staged.extend_from_slice(&bytes[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BackendObjectSink for ShortWriter {
    fn finish_transfer(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn abort_transfer(&mut self) {
        self.staged.clear();
    }
}

impl ShortWriter {
    fn caller_finalize(&mut self) {
        self.visible = std::mem::take(&mut self.staged);
    }
}

struct CancellingWriter<'a> {
    cancel: &'a AtomicBool,
    staged: Vec<u8>,
    visible: Vec<u8>,
}

struct InterruptOnceWriter {
    interrupted: bool,
    staged: Vec<u8>,
    visible: Vec<u8>,
}

impl Write for InterruptOnceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.staged.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BackendObjectSink for InterruptOnceWriter {
    fn finish_transfer(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn abort_transfer(&mut self) {
        self.staged.clear();
    }
}

impl InterruptOnceWriter {
    fn caller_finalize(&mut self) {
        self.visible = std::mem::take(&mut self.staged);
    }
}

impl Write for CancellingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len().min(1);
        self.staged.extend_from_slice(&bytes[..length]);
        self.cancel.store(true, Ordering::Release);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BackendObjectSink for CancellingWriter<'_> {
    fn finish_transfer(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn abort_transfer(&mut self) {
        self.staged.clear();
    }
}

#[test]
fn fetch_handles_short_zero_and_cancelled_writers() {
    let backend = MemoryBackend::fresh();
    let id = OpaqueObjectId::from_bytes([1; 32]);
    let _ = publish(&backend, None, &[(id, b"object")], b"head");
    let cancel = AtomicBool::new(false);
    let mut short = ShortWriter {
        staged: Vec::new(),
        visible: Vec::new(),
        maximum: 1,
    };
    backend.fetch_object(&id, &mut short, &cancel).unwrap();
    assert!(short.visible.is_empty());
    short.caller_finalize();
    assert_eq!(short.visible, b"object");

    let mut interrupted = InterruptOnceWriter {
        interrupted: false,
        staged: Vec::new(),
        visible: Vec::new(),
    };
    backend
        .fetch_object(&id, &mut interrupted, &cancel)
        .unwrap();
    assert!(interrupted.visible.is_empty());
    interrupted.caller_finalize();
    assert_eq!(interrupted.visible, b"object");

    let mut zero = ShortWriter {
        staged: Vec::new(),
        visible: Vec::new(),
        maximum: 0,
    };
    assert_eq!(
        backend
            .fetch_object(&id, &mut zero, &cancel)
            .unwrap_err()
            .kind(),
        BackendErrorKind::Permanent
    );

    let cancelled = AtomicBool::new(false);
    let mut writer = CancellingWriter {
        cancel: &cancelled,
        staged: Vec::new(),
        visible: Vec::new(),
    };
    assert_eq!(
        backend
            .fetch_object(&id, &mut writer, &cancelled)
            .unwrap_err()
            .kind(),
        BackendErrorKind::Cancelled
    );
    assert!(writer.staged.is_empty());
    assert!(writer.visible.is_empty());

    let mut untouched = ShortWriter {
        staged: Vec::new(),
        visible: Vec::new(),
        maximum: usize::MAX,
    };
    assert_eq!(
        backend
            .fetch_object(
                &OpaqueObjectId::from_bytes([9; 32]),
                &mut untouched,
                &cancel,
            )
            .unwrap_err()
            .kind(),
        BackendErrorKind::NotFound
    );
    assert!(untouched.staged.is_empty());
    assert!(untouched.visible.is_empty());
}
