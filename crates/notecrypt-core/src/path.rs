use std::fmt;

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use crate::CoreError;

/// A single normalized and portable unlocked logical name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        validate_component(value)?;
        Ok(Self(value.nfc().collect()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn collision_key(&self) -> String {
        nfkc_case_fold(&self.0)
    }
}

pub(crate) fn nfkc_case_fold(value: &str) -> String {
    value.nfkc().case_fold().nfkc().collect()
}

impl fmt::Display for EntryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for EntryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntryName(<redacted>)")
    }
}

/// A normalized path in the unlocked logical tree.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogicalPath(Vec<EntryName>);

impl LogicalPath {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        validate_path_prefix(value)?;

        let components = value
            .split('/')
            .map(EntryName::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(components))
    }

    #[must_use]
    pub fn components(&self) -> &[EntryName] {
        &self.0
    }

    #[must_use]
    pub fn collision_key(&self) -> String {
        self.0
            .iter()
            .map(EntryName::collision_key)
            .collect::<Vec<_>>()
            .join("/")
    }
}

impl fmt::Display for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, component) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("/")?;
            }
            fmt::Display::fmt(component, formatter)?;
        }
        Ok(())
    }
}

impl fmt::Debug for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LogicalPath(<redacted>)")
    }
}

fn validate_path_prefix(value: &str) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::EmptyPath);
    }
    if value.contains('\0') {
        return Err(CoreError::NulInPath);
    }
    if value.starts_with('/') || value.starts_with('\\') || has_drive_prefix(value) {
        return Err(CoreError::AbsolutePath);
    }
    if value.contains('\\') {
        return Err(CoreError::PlatformSeparator);
    }
    Ok(())
}

fn has_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_component(value: &str) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::EmptyPathComponent);
    }
    if value.contains('\0') {
        return Err(CoreError::NulInPath);
    }
    if value == ".." {
        return Err(CoreError::ParentTraversal);
    }
    if value == "." {
        return Err(CoreError::CurrentDirectory);
    }
    if value.contains(['/', '\\']) {
        return Err(CoreError::PlatformSeparator);
    }
    if value.ends_with(['.', ' ']) {
        return Err(CoreError::TrailingDotOrSpace);
    }
    if value.chars().any(|character| {
        character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
    }) {
        return Err(CoreError::NonPortablePathCharacter);
    }
    if is_windows_reserved(value) {
        return Err(CoreError::ReservedPathComponent);
    }
    Ok(())
}

fn is_windows_reserved(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or(value);
    let folded = stem.nfkc().collect::<String>().to_ascii_uppercase();
    matches!(folded.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || folded
            .strip_prefix("COM")
            .is_some_and(is_reserved_device_number)
        || folded
            .strip_prefix("LPT")
            .is_some_and(is_reserved_device_number)
}

fn is_reserved_device_number(suffix: &str) -> bool {
    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

#[cfg(test)]
mod tests {
    use super::{EntryName, LogicalPath};
    use crate::CoreError;

    #[test]
    fn logical_path_rejects_parent_traversal() {
        assert_eq!(
            LogicalPath::parse("notes/../secret").unwrap_err(),
            CoreError::ParentTraversal,
        );
    }

    #[test]
    fn logical_path_rejects_absolute_and_platform_specific_paths() {
        for path in [
            "/notes/file",
            r"\\server\share",
            r"C:\notes",
            r"notes\secret",
        ] {
            assert!(LogicalPath::parse(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn logical_path_rejects_empty_components_and_nul() {
        assert_eq!(
            LogicalPath::parse("notes//secret").unwrap_err(),
            CoreError::EmptyPathComponent,
        );
        assert_eq!(
            LogicalPath::parse("notes/secret\0copy").unwrap_err(),
            CoreError::NulInPath,
        );
    }

    #[test]
    fn entry_name_rejects_portable_reserved_components() {
        for name in [
            "CON",
            "nul.txt",
            "COM1",
            "lpt9.md",
            "COM\u{b9}.txt",
            "LPT\u{b3}",
            "trailing.",
            "space ",
        ] {
            assert!(EntryName::parse(name).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn paths_are_nfc_normalized_and_have_portable_collision_keys() {
        let composed = LogicalPath::parse("notes/caf\u{e9}.md").unwrap();
        let decomposed = LogicalPath::parse("notes/cafe\u{301}.md").unwrap();
        let upper = LogicalPath::parse("NOTES/CAF\u{c9}.MD").unwrap();

        assert_eq!(composed, decomposed);
        assert_eq!(composed.collision_key(), upper.collision_key());
        assert_eq!(composed.to_string(), "notes/caf\u{e9}.md");
    }

    #[test]
    fn compatibility_normalization_precedes_full_case_folding() {
        let mathematical_bold_capital_a = EntryName::parse("\u{1d400}").unwrap();
        let ascii_lowercase_a = EntryName::parse("a").unwrap();

        assert_eq!(
            mathematical_bold_capital_a.collision_key(),
            ascii_lowercase_a.collision_key(),
        );
    }

    #[test]
    fn logical_paths_have_deterministic_ordering() {
        let a = LogicalPath::parse("a/file").unwrap();
        let b = LogicalPath::parse("b/file").unwrap();

        assert!(a < b);
    }

    #[test]
    fn debug_output_does_not_disclose_unlocked_names() {
        let path = LogicalPath::parse("private/pii.txt").unwrap();

        assert!(!format!("{path:?}").contains("pii.txt"));
    }
}
