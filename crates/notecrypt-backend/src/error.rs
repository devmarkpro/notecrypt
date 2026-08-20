use std::error::Error;
use std::fmt;
use std::time::Duration;

/// A structural error constructing a bounded backend contract type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendTypeError {
    /// A byte or item limit was exceeded.
    LimitExceeded,
    /// A required positive capability limit was zero.
    ZeroLimit,
    /// Capability values are internally inconsistent.
    IncoherentCapabilities,
    /// A bounded allocation failed.
    AllocationFailed,
    /// Inventory identifiers were not strictly increasing.
    NonCanonicalInventory,
}

impl fmt::Display for BackendTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "backend contract limit exceeded",
            Self::ZeroLimit => "backend capability limit must be positive",
            Self::IncoherentCapabilities => "backend capabilities are incoherent",
            Self::AllocationFailed => "bounded backend allocation failed",
            Self::NonCanonicalInventory => "inventory identifiers are not strictly increasing",
        })
    }
}

impl Error for BackendTypeError {}

/// A machine-matchable backend failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendErrorKind {
    /// Backend credentials were missing, invalid, or expired.
    Authentication,
    /// Authenticated credentials do not authorize the operation.
    Authorization,
    /// The backend is temporarily unavailable.
    Unavailable,
    /// The backend is temporarily rate limited.
    RateLimited,
    /// The backend returned malformed or contradictory transport data.
    CorruptResponse,
    /// The requested backend operation is unsupported.
    Unsupported,
    /// A stale observation was detected where no typed publication outcome applies.
    ///
    /// Ordinary publication compare-and-swap conflicts use
    /// [`crate::PublishOutcome::Stale`] instead.
    StaleHead,
    /// Cooperative cancellation was observed before an irreversible boundary.
    Cancelled,
    /// An immutable object was not found.
    NotFound,
    /// A non-retryable backend failure occurred.
    Permanent,
}

/// A bounded, log-safe correlation value for backend diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DiagnosticId(u64);

impl DiagnosticId {
    /// Constructs a diagnostic identifier supplied by an adapter.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric correlation value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A bounded and machine-matchable backend error.
///
/// It intentionally carries no arbitrary strings or backend response bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendError {
    kind: BackendErrorKind,
    diagnostic_id: Option<DiagnosticId>,
    retry_after: Option<Duration>,
}

impl BackendError {
    /// Constructs an error with no backend-provided detail.
    pub const fn new(kind: BackendErrorKind) -> Self {
        Self {
            kind,
            diagnostic_id: None,
            retry_after: None,
        }
    }

    /// Attaches a bounded, log-safe correlation value.
    pub const fn with_diagnostic_id(mut self, diagnostic_id: DiagnosticId) -> Self {
        self.diagnostic_id = Some(diagnostic_id);
        self
    }

    /// Constructs a rate-limit error with a retry delay.
    pub const fn rate_limited(retry_after: Duration) -> Self {
        Self {
            kind: BackendErrorKind::RateLimited,
            diagnostic_id: None,
            retry_after: Some(retry_after),
        }
    }

    /// Returns the stable failure category.
    pub const fn kind(&self) -> BackendErrorKind {
        self.kind
    }

    /// Returns the optional log-safe correlation value.
    pub const fn diagnostic_id(&self) -> Option<DiagnosticId> {
        self.diagnostic_id
    }

    /// Returns a retry delay only for rate-limit errors.
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            BackendErrorKind::Authentication => "backend authentication failed",
            BackendErrorKind::Authorization => "backend authorization failed",
            BackendErrorKind::Unavailable => "backend is unavailable",
            BackendErrorKind::RateLimited => "backend is rate limited",
            BackendErrorKind::CorruptResponse => "backend returned a corrupt response",
            BackendErrorKind::Unsupported => "backend operation is unsupported",
            BackendErrorKind::StaleHead => "backend head is stale",
            BackendErrorKind::Cancelled => "backend operation was cancelled",
            BackendErrorKind::NotFound => "backend object was not found",
            BackendErrorKind::Permanent => "backend operation failed permanently",
        })
    }
}

impl Error for BackendError {}
