use std::fmt;

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use crate::CoreError;

/// A single normalized and portable unlocked logical name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        Self::try_parse_bounded(value, usize::MAX)
    }

    pub fn try_parse_bounded(value: &str, maximum_bytes: usize) -> Result<Self, CoreError> {
        if value.len() > maximum_bytes {
            return Err(CoreError::CapacityExceeded);
        }
        validate_component(value, maximum_bytes)?;
        let mut normalized = String::new();
        normalized
            .try_reserve(value.len())
            .map_err(|_| CoreError::AllocationFailed)?;
        for character in value.nfc() {
            let next = normalized
                .len()
                .checked_add(character.len_utf8())
                .ok_or(CoreError::CapacityExceeded)?;
            if next > maximum_bytes {
                return Err(CoreError::CapacityExceeded);
            }
            normalized
                .try_reserve(character.len_utf8())
                .map_err(|_| CoreError::AllocationFailed)?;
            normalized.push(character);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    #[must_use]
    pub fn collision_key(&self) -> String {
        nfkc_case_fold(&self.0)
    }

    pub fn try_collision_key(&self, maximum_bytes: usize) -> Result<String, CoreError> {
        try_nfkc_case_fold(&self.0, maximum_bytes)
    }
}

pub(crate) fn nfkc_case_fold(value: &str) -> String {
    value.nfkc().case_fold().nfkc().collect()
}

fn try_nfkc_case_fold(value: &str, maximum_bytes: usize) -> Result<String, CoreError> {
    let mut output = String::new();
    output
        .try_reserve(value.len().min(maximum_bytes))
        .map_err(|_| CoreError::AllocationFailed)?;
    for character in value.nfkc().case_fold().nfkc() {
        let next = output
            .len()
            .checked_add(character.len_utf8())
            .ok_or(CoreError::CapacityExceeded)?;
        if next > maximum_bytes {
            return Err(CoreError::CapacityExceeded);
        }
        output
            .try_reserve(character.len_utf8())
            .map_err(|_| CoreError::AllocationFailed)?;
        output.push(character);
    }
    Ok(output)
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
        Self::try_parse_bounded(value, usize::MAX, usize::MAX)
    }

    pub fn try_parse_bounded(
        value: &str,
        maximum_depth: usize,
        maximum_component_bytes: usize,
    ) -> Result<Self, CoreError> {
        let maximum_path_bytes = maximum_depth
            .checked_mul(maximum_component_bytes)
            .and_then(|components| components.checked_add(maximum_depth.saturating_sub(1)))
            .unwrap_or(usize::MAX);
        if value.len() > maximum_path_bytes {
            return Err(CoreError::CapacityExceeded);
        }
        validate_path_prefix(value)?;
        let depth = value
            .as_bytes()
            .iter()
            .filter(|byte| **byte == b'/')
            .count()
            .checked_add(1)
            .ok_or(CoreError::CapacityExceeded)?;
        if depth > maximum_depth {
            return Err(CoreError::CapacityExceeded);
        }
        let mut components = Vec::new();
        components
            .try_reserve_exact(depth)
            .map_err(|_| CoreError::AllocationFailed)?;
        for component in value.split('/') {
            components.push(EntryName::try_parse_bounded(
                component,
                maximum_component_bytes,
            )?);
        }
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

    pub fn try_collision_key(&self, maximum_bytes: usize) -> Result<String, CoreError> {
        let mut output = String::new();
        output
            .try_reserve(self.0.len().min(maximum_bytes))
            .map_err(|_| CoreError::AllocationFailed)?;
        for (index, component) in self.0.iter().enumerate() {
            let key = component.try_collision_key(maximum_bytes.saturating_sub(output.len()))?;
            let separator = usize::from(index != 0);
            let next = output
                .len()
                .checked_add(separator)
                .and_then(|length| length.checked_add(key.len()))
                .ok_or(CoreError::CapacityExceeded)?;
            if next > maximum_bytes {
                return Err(CoreError::CapacityExceeded);
            }
            output
                .try_reserve(separator + key.len())
                .map_err(|_| CoreError::AllocationFailed)?;
            if index != 0 {
                output.push('/');
            }
            output.push_str(&key);
        }
        Ok(output)
    }

    pub fn try_render(&self, maximum_bytes: usize) -> Result<String, CoreError> {
        let mut output = String::new();
        for (index, component) in self.0.iter().enumerate() {
            let separator = usize::from(index != 0);
            let next = output
                .len()
                .checked_add(separator)
                .and_then(|length| length.checked_add(component.as_str().len()))
                .ok_or(CoreError::CapacityExceeded)?;
            if next > maximum_bytes {
                return Err(CoreError::CapacityExceeded);
            }
            output
                .try_reserve(separator + component.as_str().len())
                .map_err(|_| CoreError::AllocationFailed)?;
            if index != 0 {
                output.push('/');
            }
            output.push_str(component.as_str());
        }
        Ok(output)
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

fn validate_component(value: &str, maximum_bytes: usize) -> Result<(), CoreError> {
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
    if is_windows_reserved(value, maximum_bytes)? {
        return Err(CoreError::ReservedPathComponent);
    }
    Ok(())
}

fn is_windows_reserved(value: &str, maximum_bytes: usize) -> Result<bool, CoreError> {
    let stem = value.split('.').next().unwrap_or(value);
    let folded = try_nfkc_case_fold(stem, maximum_bytes)?;
    Ok(matches!(folded.as_str(), "con" | "prn" | "aux" | "nul")
        || folded
            .strip_prefix("com")
            .is_some_and(is_reserved_device_number)
        || folded
            .strip_prefix("lpt")
            .is_some_and(is_reserved_device_number))
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
    fn bounded_entry_name_rejects_raw_and_normalized_expansion_before_retention() {
        assert_eq!(
            EntryName::try_parse_bounded(&"x".repeat(1_000_000), 16).unwrap_err(),
            CoreError::CapacityExceeded,
        );
        assert_eq!(
            EntryName::try_parse_bounded("\u{fdfa}", 3).unwrap_err(),
            CoreError::CapacityExceeded,
        );
    }

    #[test]
    fn bounded_logical_path_rejects_input_beyond_its_checked_total_limit() {
        assert_eq!(
            LogicalPath::try_parse_bounded(&"x".repeat(1_000_000), 2, 8).unwrap_err(),
            CoreError::CapacityExceeded,
        );
        assert_eq!(
            LogicalPath::try_parse_bounded("a/b/c", 2, 8).unwrap_err(),
            CoreError::CapacityExceeded,
        );
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
