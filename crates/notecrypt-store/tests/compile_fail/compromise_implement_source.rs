use std::io::Write;
use std::sync::atomic::AtomicBool;

use notecrypt_store::{AuthenticatedLogicalEntry, CompromiseRekeySource, StoreError};

struct ForgedSource;

impl CompromiseRekeySource for ForgedSource {
    fn next_entry(&mut self) -> Result<Option<AuthenticatedLogicalEntry>, StoreError> {
        Ok(None)
    }

    fn stream_plaintext(
        &mut self,
        _entry: AuthenticatedLogicalEntry,
        _output: &mut dyn Write,
        _cancel: &AtomicBool,
    ) -> Result<u64, StoreError> {
        Ok(0)
    }
}

fn main() {}
