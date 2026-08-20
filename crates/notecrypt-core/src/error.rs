use thiserror::Error;

/// Stable failures produced by deterministic domain operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("allocation failed while retaining a bounded logical path")]
    AllocationFailed,
    #[error("the logical path exceeds a configured capacity")]
    CapacityExceeded,
    #[error("the logical path is empty")]
    EmptyPath,
    #[error("absolute logical paths are not allowed")]
    AbsolutePath,
    #[error("parent traversal is not allowed")]
    ParentTraversal,
    #[error("current-directory path components are not allowed")]
    CurrentDirectory,
    #[error("logical paths cannot contain empty components")]
    EmptyPathComponent,
    #[error("logical paths cannot contain NUL")]
    NulInPath,
    #[error("platform-specific path separators are not allowed")]
    PlatformSeparator,
    #[error("the path component is reserved on a supported platform")]
    ReservedPathComponent,
    #[error("the path component contains a non-portable character")]
    NonPortablePathCharacter,
    #[error("path components cannot end in a dot or space")]
    TrailingDotOrSpace,
    #[error("the entry already exists")]
    EntryAlreadyExists,
    #[error("the entry does not exist")]
    MissingEntry,
    #[error("the parent entry does not exist")]
    MissingParent,
    #[error("the parent entry is not a directory")]
    ParentNotDirectory,
    #[error("an entry with a colliding destination name already exists")]
    DuplicateDestination,
    #[error("the logical root cannot be changed")]
    RootMutation,
    #[error("moving the directory would create a cycle")]
    DirectoryCycle,
    #[error("a merge snapshot requires two distinct parents")]
    DuplicateSnapshotParent,
    #[error("the reconciled trees do not share a root identity")]
    RootMismatch,
}

#[cfg(test)]
mod tests {
    use super::CoreError;

    #[test]
    fn errors_compare_by_category() {
        assert_eq!(CoreError::ParentTraversal, CoreError::ParentTraversal);
    }
}
