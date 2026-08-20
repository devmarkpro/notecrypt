use std::sync::atomic::{AtomicBool, Ordering};

use crate::{BackendError, BackendErrorKind, BackendTypeError};

/// Hard phase-one bootstrap transport bound.
pub const MAX_BOOTSTRAP_BYTES: usize = 1024 * 1024;
/// Hard phase-one opaque head bound.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Hard phase-one conditional head-version bound.
pub const MAX_HEAD_VERSION_BYTES: usize = 1024;
/// Hard bound for backend-owned inventory cursors.
pub const MAX_CURSOR_BYTES: usize = 1024;
/// Hard bound for one advertised object stream.
pub const MAX_ADVERTISED_OBJECT_BYTES: u64 = 1_099_511_627_776;
/// Hard bound for an advertised inventory page.
pub const MAX_ADVERTISED_INVENTORY_PAGE: usize = 65_536;
/// Hard bound for advertised unique objects in one publication.
pub const MAX_ADVERTISED_BATCH_ITEMS: usize = 65_536;
/// Hard bound for advertised concurrent backend calls.
pub const MAX_ADVERTISED_CONCURRENCY: usize = 4096;

/// An opaque immutable encrypted-object identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueObjectId([u8; 32]);

impl OpaqueObjectId {
    /// Constructs an identifier without interpreting its bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact opaque identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A stable opaque identity for one canonical backend storage namespace.
///
/// It contains no credential, token, or user-info bytes, remains stable across
/// reconnects and credential rotation, and changes when the canonical remote
/// namespace or dedicated branch changes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendIdentity([u8; 32]);

impl BackendIdentity {
    /// Constructs a stable identity without interpreting its bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact opaque identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! bounded_bytes {
    ($name:ident, $maximum:expr, $description:literal) => {
        #[doc = $description]
        #[derive(PartialEq, Eq)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Validates and takes ownership of opaque transport bytes.
            pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BackendTypeError> {
                if bytes.len() > $maximum {
                    return Err(BackendTypeError::LimitExceeded);
                }
                Ok(Self(bytes))
            }

            /// Fallibly copies bounded transport bytes.
            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, BackendTypeError> {
                if bytes.len() > $maximum {
                    return Err(BackendTypeError::LimitExceeded);
                }
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| BackendTypeError::AllocationFailed)?;
                owned.extend_from_slice(bytes);
                Ok(Self(owned))
            }

            /// Fallibly copies this value without exposing an infallible clone.
            pub fn try_clone(&self) -> Result<Self, BackendTypeError> {
                Self::try_from_slice(&self.0)
            }

            /// Borrows the exact opaque bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Returns the bounded byte length.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Reports whether the opaque byte value is empty.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

bounded_bytes!(
    BootstrapBytes,
    MAX_BOOTSTRAP_BYTES,
    "Opaque immutable vault bootstrap bytes bounded to one MiB."
);
bounded_bytes!(
    HeadValue,
    MAX_HEAD_BYTES,
    "Opaque remote head bytes bounded to 64 KiB."
);
bounded_bytes!(
    HeadVersion,
    MAX_HEAD_VERSION_BYTES,
    "Opaque conditional head-version bytes bounded to one KiB."
);
bounded_bytes!(
    InventoryCursor,
    MAX_CURSOR_BYTES,
    "Opaque backend-owned cursor bound to one inventory snapshot."
);

/// One observed opaque head value and its conditional replacement version.
#[derive(PartialEq, Eq)]
pub struct ObservedHead {
    version: HeadVersion,
    value: HeadValue,
}

impl ObservedHead {
    /// Constructs an observed head from independently bounded components.
    pub const fn new(version: HeadVersion, value: HeadValue) -> Self {
        Self { version, value }
    }

    /// Borrows the conditional version.
    pub const fn version(&self) -> &HeadVersion {
        &self.version
    }

    /// Borrows the opaque head bytes.
    pub const fn value(&self) -> &HeadValue {
        &self.value
    }

    /// Fallibly copies the bounded observation.
    pub fn try_clone(&self) -> Result<Self, BackendTypeError> {
        Ok(Self::new(
            self.version.try_clone()?,
            self.value.try_clone()?,
        ))
    }
}

/// Result of idempotently staging one immutable object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// New immutable bytes were staged.
    Staged,
    /// Byte-identical immutable bytes were already present.
    AlreadyMatching,
}

/// Result of consuming a publication at its atomic head boundary.
#[derive(PartialEq, Eq)]
pub enum PublishOutcome {
    /// The replacement is known committed with its resulting fresh observation.
    Committed {
        /// Fresh post-commit head observation.
        observed: ObservedHead,
    },
    /// The expected version was stale and the prior head was preserved.
    Stale {
        /// Fresh observation, or `None` if the head is still absent.
        observed: Option<ObservedHead>,
    },
    /// The backend cannot determine whether the atomic boundary completed.
    ///
    /// Callers must reread the head before any retry.
    Indeterminate,
}

/// Validated limits and atomicity capabilities advertised by an adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    conditional_head: bool,
    max_bootstrap_bytes: u64,
    max_object_bytes: u64,
    max_inventory_page: usize,
    max_batch_items: usize,
    safe_concurrency: usize,
}

impl BackendCapabilities {
    /// Validates an adapter capability declaration.
    pub fn new(
        conditional_head: bool,
        max_bootstrap_bytes: u64,
        max_object_bytes: u64,
        max_inventory_page: usize,
        max_batch_items: usize,
        safe_concurrency: usize,
    ) -> Result<Self, BackendTypeError> {
        if max_bootstrap_bytes == 0
            || max_object_bytes == 0
            || max_inventory_page == 0
            || max_batch_items == 0
            || safe_concurrency == 0
        {
            return Err(BackendTypeError::ZeroLimit);
        }
        if max_bootstrap_bytes > MAX_BOOTSTRAP_BYTES as u64
            || max_object_bytes > MAX_ADVERTISED_OBJECT_BYTES
            || max_inventory_page > MAX_ADVERTISED_INVENTORY_PAGE
            || max_batch_items > MAX_ADVERTISED_BATCH_ITEMS
            || safe_concurrency > MAX_ADVERTISED_CONCURRENCY
        {
            return Err(BackendTypeError::IncoherentCapabilities);
        }
        Ok(Self {
            conditional_head,
            max_bootstrap_bytes,
            max_object_bytes,
            max_inventory_page,
            max_batch_items,
            safe_concurrency,
        })
    }

    /// Reports whether exact conditional head replacement is supported.
    pub const fn conditional_head(&self) -> bool {
        self.conditional_head
    }

    /// Returns the adapter bootstrap byte bound.
    pub const fn max_bootstrap_bytes(&self) -> u64 {
        self.max_bootstrap_bytes
    }

    /// Returns the per-object byte bound.
    pub const fn max_object_bytes(&self) -> u64 {
        self.max_object_bytes
    }

    /// Returns the maximum requested inventory page size.
    pub const fn max_inventory_page(&self) -> usize {
        self.max_inventory_page
    }

    /// Returns the maximum unique objects in one publication.
    pub const fn max_batch_items(&self) -> usize {
        self.max_batch_items
    }

    /// Returns the maximum calls safely dispatched through one local handle.
    ///
    /// This local throttle does not waive atomicity or snapshot correctness
    /// across independent handles or devices using the same namespace.
    pub const fn safe_concurrency(&self) -> usize {
        self.safe_concurrency
    }

    /// Validates one bootstrap against the advertised and hard bounds.
    pub fn check_bootstrap(&self, value: &BootstrapBytes) -> Result<(), BackendError> {
        let length = u64::try_from(value.len())
            .map_err(|_| BackendError::new(BackendErrorKind::Permanent))?;
        if length > self.max_bootstrap_bytes {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        Ok(())
    }

    /// Validates a declared object stream length.
    pub fn check_object_length(&self, length: u64) -> Result<(), BackendError> {
        if length > self.max_object_bytes {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        Ok(())
    }

    /// Validates a requested inventory page limit.
    pub fn check_inventory_limit(&self, limit: usize) -> Result<(), BackendError> {
        if limit == 0 || limit > self.max_inventory_page {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        Ok(())
    }

    /// Validates a unique staged-object count with checked arithmetic.
    pub fn check_batch_count(&self, count: usize) -> Result<(), BackendError> {
        if count > self.max_batch_items {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        Ok(())
    }

    /// Validates a requested concurrency level.
    pub fn check_concurrency(&self, count: usize) -> Result<(), BackendError> {
        if count == 0 || count > self.safe_concurrency {
            return Err(BackendError::new(BackendErrorKind::Permanent));
        }
        Ok(())
    }
}

/// One deterministic, duplicate-free inventory page.
pub struct InventoryPage {
    objects: Vec<OpaqueObjectId>,
    next: Option<InventoryCursor>,
}

impl InventoryPage {
    /// Validates a page against the request and advertised backend limit.
    ///
    /// Adapters remain responsible for constructing the supplied vector with
    /// fallible reservation because validation cannot retroactively make an
    /// already-completed allocation safe.
    pub fn from_parts(
        objects: Vec<OpaqueObjectId>,
        next: Option<InventoryCursor>,
        requested_limit: usize,
        capabilities: &BackendCapabilities,
    ) -> Result<Self, BackendTypeError> {
        if requested_limit == 0
            || requested_limit > capabilities.max_inventory_page
            || objects.len() > requested_limit
        {
            return Err(BackendTypeError::LimitExceeded);
        }
        if objects.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BackendTypeError::NonCanonicalInventory);
        }
        if objects.is_empty() && next.is_some() {
            return Err(BackendTypeError::NonCanonicalInventory);
        }
        Ok(Self { objects, next })
    }

    /// Borrows the strictly increasing opaque identifiers.
    pub fn objects(&self) -> &[OpaqueObjectId] {
        &self.objects
    }

    /// Borrows the snapshot-bound continuation cursor.
    pub const fn next_cursor(&self) -> Option<&InventoryCursor> {
        self.next.as_ref()
    }

    /// Consumes the page into identifiers and a continuation cursor.
    pub fn into_parts(self) -> (Vec<OpaqueObjectId>, Option<InventoryCursor>) {
        (self.objects, self.next)
    }
}

/// Returns cancellation at a cooperative boundary.
pub fn check_cancelled(cancel: &AtomicBool) -> Result<(), BackendError> {
    if cancel.load(Ordering::Acquire) {
        Err(BackendError::new(BackendErrorKind::Cancelled))
    } else {
        Ok(())
    }
}
