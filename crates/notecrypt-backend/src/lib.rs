//! Backend-neutral, synchronous encrypted-object transport contracts.
//!
//! This crate deliberately treats bootstrap, head, cursor, and object bytes as
//! opaque transport data. Authentication and graph validation belong to the
//! store and replication layers.
//!
//! Opaque heap-backed transport values intentionally have no infallible clone:
//!
//! ```compile_fail
//! use notecrypt_backend::BootstrapBytes;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<BootstrapBytes>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::HeadValue;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<HeadValue>();
//! ```
//!
//! Head versions intentionally have no infallible clone:
//!
//! ```compile_fail
//! use notecrypt_backend::HeadVersion;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<HeadVersion>();
//! ```
//!
//! Inventory cursors intentionally have no infallible clone:
//!
//! ```compile_fail
//! use notecrypt_backend::InventoryCursor;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<InventoryCursor>();
//! ```
//!
//! Opaque head values intentionally have no byte-revealing debug view:
//!
//! ```compile_fail
//! use notecrypt_backend::HeadValue;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<HeadValue>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::BootstrapBytes;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<BootstrapBytes>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::HeadVersion;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<HeadVersion>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::InventoryCursor;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<InventoryCursor>();
//! ```
//!
//! Publication outcomes intentionally have no byte-revealing debug view:
//!
//! ```compile_fail
//! use notecrypt_backend::PublishOutcome;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<PublishOutcome>();
//! ```
//!
//! Inventory pages intentionally have no byte-revealing debug view:
//!
//! ```compile_fail
//! use notecrypt_backend::InventoryPage;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<InventoryPage>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::InventoryPage;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<InventoryPage>();
//! ```
//!
//! Observations intentionally have no infallible clone:
//!
//! ```compile_fail
//! use notecrypt_backend::ObservedHead;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<ObservedHead>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::ObservedHead;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<ObservedHead>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::OpaqueObjectId;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<OpaqueObjectId>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::BackendIdentity;
//! fn requires_debug<T: core::fmt::Debug>() {}
//! requires_debug::<BackendIdentity>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::BootstrapBytes;
//! fn requires_display<T: core::fmt::Display>() {}
//! requires_display::<BootstrapBytes>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::HeadValue;
//! fn requires_display<T: core::fmt::Display>() {}
//! requires_display::<HeadValue>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::HeadVersion;
//! fn requires_display<T: core::fmt::Display>() {}
//! requires_display::<HeadVersion>();
//! ```
//!
//! ```compile_fail
//! use notecrypt_backend::InventoryCursor;
//! fn requires_display<T: core::fmt::Display>() {}
//! requires_display::<InventoryCursor>();
//! ```
//!
//! A consumed publication cannot be reused:
//!
//! ```compile_fail
//! use notecrypt_backend::{BackendPublication, HeadValue};
//! use std::sync::atomic::AtomicBool;
//! fn reuse(publication: Box<dyn BackendPublication>, head: &HeadValue, cancel: &AtomicBool) {
//!     let _ = publication.commit(head, cancel);
//!     let _ = publication.abort();
//! }
//! ```
//!
//! An arbitrary writer cannot bypass the transactional fetch protocol:
//!
//! ```compile_fail
//! use notecrypt_backend::{OpaqueObjectId, VaultBackend};
//! use std::sync::atomic::AtomicBool;
//! fn fetch(backend: &dyn VaultBackend, id: &OpaqueObjectId, cancel: &AtomicBool) {
//!     let mut visible_bytes = Vec::new();
//!     let _ = backend.fetch_object(id, &mut visible_bytes, cancel);
//! }
//! ```

#![deny(missing_docs)]

mod backend;
mod bootstrap;
pub mod conformance;
mod error;
mod types;

pub use backend::{BackendObjectSink, BackendPublication, VaultBackend};
pub use bootstrap::CreateBootstrapOutcome;
pub use error::{BackendError, BackendErrorKind, BackendTypeError, DiagnosticId};
pub use types::{
    BackendCapabilities, BackendIdentity, BootstrapBytes, HeadValue, HeadVersion, InventoryCursor,
    InventoryPage, MAX_ADVERTISED_BATCH_ITEMS, MAX_ADVERTISED_CONCURRENCY,
    MAX_ADVERTISED_INVENTORY_PAGE, MAX_ADVERTISED_OBJECT_BYTES, MAX_BOOTSTRAP_BYTES,
    MAX_CURSOR_BYTES, MAX_HEAD_BYTES, MAX_HEAD_VERSION_BYTES, ObservedHead, OpaqueObjectId,
    PublishOutcome, StageOutcome, check_cancelled,
};
