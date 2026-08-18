/// Result of creating an immutable vault bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateBootstrapOutcome {
    /// The exact supplied bytes were created because no bootstrap existed.
    Created,
    /// Byte-identical bootstrap content already existed.
    AlreadyMatching,
}
