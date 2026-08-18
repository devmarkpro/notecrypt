use std::error::Error;
use std::fmt;

/// Stable, bounded failures exposed by the application service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceError {
    /// The bounded ordinary queue cannot accept more work.
    Busy,
    /// The service has shut down.
    Closed,
    /// A global security control stopped new work.
    Locked,
    /// Cooperative cancellation was observed at a safe boundary.
    Cancelled,
    /// The injected executor reported a bounded application failure.
    ExecutorFailed,
    /// An executor panicked and its operation was contained.
    WorkerPanicked,
    /// The cryptographically secure random source failed.
    EntropyUnavailable,
    /// Fresh operation identity generation exhausted its retry or lifetime bound.
    IdentifierExhausted,
    /// A runtime limit was zero, inconsistent, or could not be reserved.
    InvalidConfiguration,
    /// A bounded public collection exceeded its documented element limit.
    CapacityExceeded,
    /// A bounded collection could not reserve its required memory.
    AllocationFailed,
    /// A progress value contradicted its declared total.
    InvalidProgress,
    /// An operation exhausted its event sequence space.
    EventSequenceExhausted,
    /// A bounded observation wait elapsed without a value.
    TimedOut,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "the service is busy",
            Self::Closed => "the service is closed",
            Self::Locked => "the service is locked",
            Self::Cancelled => "the operation was cancelled",
            Self::ExecutorFailed => "the operation executor failed",
            Self::WorkerPanicked => "the operation executor panicked",
            Self::EntropyUnavailable => "the operating-system random source failed",
            Self::IdentifierExhausted => "operation identity generation was exhausted",
            Self::InvalidConfiguration => "the service configuration is invalid",
            Self::CapacityExceeded => "the bounded service capacity was exceeded",
            Self::AllocationFailed => "the bounded service allocation failed",
            Self::InvalidProgress => "the operation progress is invalid",
            Self::EventSequenceExhausted => "the operation event sequence was exhausted",
            Self::TimedOut => "the bounded service wait timed out",
        })
    }
}

impl Error for ServiceError {}
