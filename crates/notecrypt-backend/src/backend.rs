use std::io::{Read, Write};
use std::sync::atomic::AtomicBool;

use crate::{
    BackendCapabilities, BackendError, BackendIdentity, BootstrapBytes, CreateBootstrapOutcome,
    HeadValue, HeadVersion, InventoryCursor, InventoryPage, ObservedHead, OpaqueObjectId,
    PublishOutcome, StageOutcome,
};

/// A linear, bounded publication prepared against one observed head version.
///
/// Implementations may make immutable objects physically visible while staging.
/// They must not make the replacement head visible before all staged bytes are
/// readable. Cancellation after an uncertain commit boundary must produce
/// [`PublishOutcome::Indeterminate`], never a cancellation error.
pub trait BackendPublication: Send {
    /// Stages one exact-length immutable encrypted object.
    fn stage_object(
        &mut self,
        id: &OpaqueObjectId,
        reader: &mut dyn Read,
        length: u64,
        cancel: &AtomicBool,
    ) -> Result<StageOutcome, BackendError>;

    /// Atomically publishes all staged objects with an opaque replacement head.
    fn commit(
        self: Box<Self>,
        replacement: &HeadValue,
        cancel: &AtomicBool,
    ) -> Result<PublishOutcome, BackendError>;

    /// Detaches non-blocking adapter-local staging without changing the remote head.
    ///
    /// Potentially blocking remote cleanup is a separate adapter-owned bounded
    /// maintenance operation because this exact SPI method has no cancellation input.
    fn abort(self: Box<Self>) -> Result<(), BackendError>;
}

/// A caller-owned quarantine destination whose writes are never externally visible.
///
/// A successful fetch means the exact object bytes are completely staged and
/// the non-blocking transfer handoff completed exactly once. The caller then
/// owns the separate consuming authentication and finalization step, including its
/// typed metadata and error domain. Backend code never authenticates, commits,
/// performs quarantine cleanup, or otherwise exposes the destination.
///
/// Implementations must retain every write in quarantine until that later
/// caller-owned finalization succeeds. Dropping an unfinished sink may perform
/// cleanup, so backends borrow this value and never drop it.
///
/// The sink is fresh and open when passed to [`VaultBackend::fetch_object`].
/// A successful fetch calls [`Self::finish_transfer`] exactly once and never
/// calls [`Self::abort_transfer`]. Every failure before a successful handoff
/// calls `abort_transfer` exactly once, including a failed `finish_transfer`.
/// After a successful `finish_transfer` or after `abort_transfer` returns, the
/// backend never touches the sink again.
pub trait BackendObjectSink: Write + Send {
    /// Seals a complete byte transfer through a non-blocking local state change.
    ///
    /// This method performs no I/O, authentication, publication, or cleanup.
    /// It does not make staged bytes visible. An error guarantees the staged
    /// bytes remain quarantined and [`Self::abort_transfer`] can still run.
    fn finish_transfer(&mut self) -> std::io::Result<()>;

    /// Marks an incomplete transfer aborted through a non-blocking local state change.
    ///
    /// The caller remains responsible for dropping the quarantine and running
    /// any potentially blocking cleanup outside the backend call.
    fn abort_transfer(&mut self);
}

/// Synchronous encrypted-object transport implemented by storage adapters.
///
/// Every potentially blocking adapter implementation must use bounded I/O and
/// check the supplied cancellation flag immediately before and after each
/// blocking or state-changing boundary. The sole terminal exception is a
/// successful [`BackendObjectSink::finish_transfer`]: that known handoff wins
/// over cancellation raised inside the callback, and the caller must check
/// cancellation again before consuming its store-owned finalizer.
pub trait VaultBackend: Send + Sync {
    /// Returns a stable opaque identity for this configured storage namespace.
    ///
    /// It must survive reconnects and must differ for distinct namespaces.
    /// This accessor is side-effect free and uses adapter-construction state;
    /// it must not perform filesystem, process, or network I/O.
    fn identity(&self) -> BackendIdentity;

    /// Reports immutable validated transport limits.
    ///
    /// This accessor is side-effect free and uses adapter-construction state;
    /// it must not perform filesystem, process, or network I/O.
    fn capabilities(&self) -> BackendCapabilities;

    /// Reads the complete immutable bootstrap, if present.
    fn read_bootstrap(&self, cancel: &AtomicBool) -> Result<Option<BootstrapBytes>, BackendError>;

    /// Creates the exact bootstrap only when absent.
    fn create_bootstrap_if_absent(
        &self,
        bootstrap: &BootstrapBytes,
        cancel: &AtomicBool,
    ) -> Result<CreateBootstrapOutcome, BackendError>;

    /// Reads the current opaque remote head and its conditional version from one observation.
    fn read_head(&self, cancel: &AtomicBool) -> Result<Option<ObservedHead>, BackendError>;

    /// Lists one deterministic page from an inventory snapshot.
    fn list_objects(
        &self,
        cursor: Option<&InventoryCursor>,
        limit: usize,
        cancel: &AtomicBool,
    ) -> Result<InventoryPage, BackendError>;

    /// Streams one immutable encrypted object to a transactional quarantine sink.
    ///
    /// On any backend, writer, or cancellation error, no staged byte is visible
    /// and the backend invokes [`BackendObjectSink::abort_transfer`] exactly
    /// once. A failed transfer handoff is followed by the same abort marker.
    /// On success, the backend invokes [`BackendObjectSink::finish_transfer`]
    /// exactly once, never invokes the abort marker, and does not recheck late
    /// cancellation after that known handoff. The caller must check cancellation
    /// again and consume its store-owned quarantine finalizer only after success.
    /// It must drop the unfinished sink after any error.
    fn fetch_object(
        &self,
        id: &OpaqueObjectId,
        writer: &mut dyn BackendObjectSink,
        cancel: &AtomicBool,
    ) -> Result<(), BackendError>;

    /// Starts a linear publication conditional on an exact prior head.
    ///
    /// `None` means the head must still be absent, not unconditional replacement.
    fn begin_publication(
        &self,
        expected: Option<&HeadVersion>,
        cancel: &AtomicBool,
    ) -> Result<Box<dyn BackendPublication>, BackendError>;
}
