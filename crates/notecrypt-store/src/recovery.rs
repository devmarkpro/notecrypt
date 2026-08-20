use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};

use notecrypt_core::SnapshotId;
use notecrypt_format::{DecodeLimits, decode_local_state};

use crate::StoreError;
use crate::batch::DurableBatch;
use crate::journal::{JournalPhase, verify_authenticated_journal_with_cell};
use crate::key_cell::KeyCell;
use crate::layout::{StoreLayout, component};
use crate::local_io::read_optional;
use crate::transaction::{authenticate_head, write_journal, write_trusted};
use crate::trusted_state::{TrustedHead, verify_authenticated_trusted_head};

/// Result of authenticating and repairing a previously interrupted local transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Empty,
    Current(SnapshotId),
    Completed(SnapshotId),
}

pub(crate) fn recover(
    layout: &StoreLayout,
    batch: DurableBatch<'_>,
    keys: &KeyCell,
    mut authenticate_object: impl FnMut(
        &notecrypt_core::ObjectId,
        &mut notecrypt_platform_fs::FileCapability,
    ) -> Result<(), StoreError>,
    mut verify_reachable: impl FnMut(&[u8]) -> Result<(), StoreError>,
    cancel: Option<&AtomicBool>,
) -> Result<RecoveryOutcome, StoreError> {
    let check_cancel = || {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire)) {
            Err(StoreError::Cancelled)
        } else {
            Ok(())
        }
    };
    check_cancel()?;
    let generation = keys.generation();
    keys.validate_generation(generation)?;
    let journal_name = component("active")?;
    let Some(journal_bytes) = read_optional(&layout.journal, &journal_name)? else {
        drop(batch);
        return match read_trusted_only(layout, keys, generation)? {
            None => {
                if read_optional(&layout.repository, &component("head")?)?.is_some() {
                    Err(StoreError::LocalStateAuthenticationFailed)
                } else {
                    Ok(RecoveryOutcome::Empty)
                }
            }
            Some(trusted) => {
                let head_bytes = read_optional(&layout.repository, &component("head")?)?
                    .ok_or(StoreError::RollbackDetected)?;
                let head = authenticate_head(&head_bytes, keys, generation)?;
                if head.snapshot != trusted.snapshot()
                    || head.commitment != *trusted.head_commitment()
                {
                    return Err(StoreError::RollbackDetected);
                }
                Ok(RecoveryOutcome::Current(trusted.snapshot()))
            }
        };
    };
    let record = decode_local_state(&journal_bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    let journal = verify_authenticated_journal_with_cell(&record, keys, generation)?;
    if journal.vault() != layout.vault || journal.session_generation() != generation {
        return Err(StoreError::LocalStateAuthenticationFailed);
    }
    verify_reachable(journal.intended_head())?;
    let intended = authenticate_head(journal.intended_head(), keys, generation)?;
    if intended.vault != layout.vault {
        return Err(StoreError::AuthenticationFailed);
    }

    let trusted = read_trusted_only(layout, keys, generation)?;
    let current_head = match read_optional(&layout.repository, &component("head")?)? {
        Some(bytes) => Some(authenticate_head(&bytes, keys, generation)?),
        None => None,
    };
    if let Some(current) = &current_head {
        let is_old = current.commitment == *journal.prior_head_commitment();
        let is_new = current.commitment == intended.commitment;
        if !is_old && !is_new {
            return Err(StoreError::RollbackDetected);
        }
    } else if journal.prior_head_commitment() != blake3::hash(&[]).as_bytes() {
        return Err(StoreError::RollbackDetected);
    }
    if let Some(trusted) = &trusted {
        let is_old = trusted.head_commitment() == journal.prior_head_commitment();
        let is_new = trusted.head_commitment() == &intended.commitment;
        if !is_old && !is_new {
            return Err(StoreError::RollbackDetected);
        }
    }

    check_cancel()?;
    let mut published =
        batch.authenticate_and_publish_checked(&mut authenticate_object, &check_cancel)?;
    check_cancel()?;
    let head_is_new = current_head
        .as_ref()
        .is_some_and(|current| current.commitment == intended.commitment);
    if !head_is_new {
        let stage = component("head-recovery")?;
        published.stage_replacement(
            stage.clone(),
            &mut Cursor::new(journal.intended_head()),
            u64::try_from(journal.intended_head().len()).map_err(|_| StoreError::LimitExceeded)?,
        )?;
        let authorization = keys.authorize_publication(generation)?;
        check_cancel()?;
        published.publish_replacement(&stage, &component("head")?)?;
        drop(authorization);
    }
    let trusted_is_new = trusted
        .as_ref()
        .is_some_and(|trusted| trusted.head_commitment() == &intended.commitment);
    if !trusted_is_new {
        write_trusted(
            layout,
            &TrustedHead::new(layout.vault, intended.snapshot, intended.commitment),
            keys,
            generation,
        )?;
    }
    if journal.phase() != JournalPhase::Complete {
        write_journal(
            layout,
            &journal.with_phase(JournalPhase::Complete)?,
            keys,
            generation,
        )?;
    }
    published.finish()?;
    Ok(RecoveryOutcome::Completed(intended.snapshot))
}

fn read_trusted_only(
    layout: &StoreLayout,
    keys: &KeyCell,
    generation: u64,
) -> Result<Option<TrustedHead>, StoreError> {
    let Some(bytes) = read_optional(&layout.trusted, &component("head")?)? else {
        return Ok(None);
    };
    let record = decode_local_state(&bytes, &DecodeLimits::PHASE_1)
        .map_err(|_| StoreError::LocalStateAuthenticationFailed)?;
    Ok(Some(verify_authenticated_trusted_head(
        &record, keys, generation,
    )?))
}
