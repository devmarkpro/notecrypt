#![cfg(feature = "test-support")]

use std::sync::{Arc, Barrier};
use std::thread;

use notecrypt_store::StoreError;
use notecrypt_store::revocation_test_support::ScriptedKeyCell;

#[test]
fn close_before_chunk_manifest_or_publication_rejects_every_boundary() {
    let session = ScriptedKeyCell::new().unwrap();
    session.begin_close().unwrap();
    assert!(matches!(
        session.bounded_step(|| {}),
        Err(StoreError::Locked)
    ));
    assert!(matches!(
        session.validate_publication(),
        Err(StoreError::Locked)
    ));
    session.close().unwrap();
    assert!(matches!(
        session.bounded_step(|| {}),
        Err(StoreError::Locked)
    ));
}

#[test]
fn close_during_a_bounded_chunk_discards_its_result_and_rejects_new_work() {
    let session = Arc::new(ScriptedKeyCell::new().unwrap());
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = {
        let session = Arc::clone(&session);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        thread::spawn(move || {
            session.bounded_step(|| {
                entered.wait();
                release.wait();
            })
        })
    };
    entered.wait();
    session.begin_close().unwrap();
    assert!(matches!(
        session.bounded_step(|| {}),
        Err(StoreError::Locked)
    ));
    release.wait();
    assert!(matches!(worker.join().unwrap(), Err(StoreError::Locked)));
    session.close().unwrap();
}
