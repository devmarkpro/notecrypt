use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use notecrypt_core::ObjectId;
use notecrypt_crypto::{Argon2idParameters, RecoveryPassphrase, ValidatedArgon2idParameters};
use notecrypt_store::{ReplicationLimits, StoreError, VaultStore};
use tempfile::TempDir;

static OWNED_LEASE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn replication_lease_moves_to_worker_and_observes_root_revocation() {
    let _test_lock = OWNED_LEASE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "owned-lease-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut lease = unlocked
        .acquire_replication_lease(ReplicationLimits::PHASE_1, ReplicationLimits::PHASE_1)
        .unwrap();
    let ready = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let worker_ready = Arc::clone(&ready);
    let worker_released = Arc::clone(&released);

    let worker = thread::Builder::new()
        .name("notecrypt-owned-replication-lease-eze".to_owned())
        .spawn(move || {
            worker_ready.wait();
            worker_released.wait();
            lease.contains_object(&ObjectId::from_bytes([0x44; 32]))
        })
        .unwrap();

    ready.wait();
    unlocked.begin_close().unwrap();
    assert!(matches!(
        unlocked.acquire_replication_lease(ReplicationLimits::PHASE_1, ReplicationLimits::PHASE_1,),
        Err(StoreError::Locked),
    ));
    released.wait();
    assert!(matches!(worker.join().unwrap(), Err(StoreError::Locked)));
    unlocked.close().unwrap();
}

#[test]
fn cancellation_handle_reaches_only_its_owned_worker_lease() {
    let _test_lock = OWNED_LEASE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "cancellation-handle-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let mut cancelled_lease = unlocked
        .acquire_replication_lease(ReplicationLimits::PHASE_1, ReplicationLimits::PHASE_1)
        .unwrap();
    let cancellation = cancelled_lease.cancellation_handle();
    let ready = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    let worker_ready = Arc::clone(&ready);
    let worker_proceed = Arc::clone(&proceed);
    let worker = thread::Builder::new()
        .name("notecrypt-replication-cancellation-handle-eze".to_owned())
        .spawn(move || {
            worker_ready.wait();
            worker_proceed.wait();
            cancelled_lease.contains_object(&ObjectId::from_bytes([0x45; 32]))
        })
        .unwrap();

    ready.wait();
    cancellation.cancel();
    proceed.wait();
    assert!(matches!(worker.join().unwrap(), Err(StoreError::Cancelled)));
    let mut unaffected = unlocked
        .acquire_replication_lease(ReplicationLimits::PHASE_1, ReplicationLimits::PHASE_1)
        .unwrap();
    assert!(
        unaffected
            .contains_object(&ObjectId::from_bytes([0x46; 32]))
            .is_ok()
    );
    unaffected.cancel();
    drop(unaffected);
    unlocked.close().unwrap();
}

#[test]
fn root_revocation_handle_is_one_way_and_isolated_from_another_vault() {
    let _test_lock = OWNED_LEASE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let repository = TempDir::new().unwrap();
    let local = TempDir::new().unwrap();
    let other_repository = TempDir::new().unwrap();
    let other_local = TempDir::new().unwrap();
    let cancel = AtomicBool::new(false);
    let store = VaultStore::initialize(
        &repository.path().canonicalize().unwrap(),
        &local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "revocation-handle-device",
        &cancel,
    )
    .unwrap();
    let other_store = VaultStore::initialize(
        &other_repository.path().canonicalize().unwrap(),
        &other_local.path().canonicalize().unwrap(),
        passphrase(),
        parameters(),
        "unrelated-revocation-device",
        &cancel,
    )
    .unwrap();
    let unlocked = store.unlock_recovery(passphrase(), &cancel).unwrap();
    let other = other_store.unlock_recovery(passphrase(), &cancel).unwrap();
    let handle = unlocked.revocation_handle();
    let mut local_lease = unlocked.acquire_lease().unwrap();
    let mut replication = unlocked
        .acquire_replication_lease(ReplicationLimits::PHASE_1, ReplicationLimits::PHASE_1)
        .unwrap();

    let revoker = thread::Builder::new()
        .name("notecrypt-root-revocation-handle-eze".to_owned())
        .spawn(move || handle.revoke())
        .unwrap();
    revoker.join().unwrap();

    assert!(matches!(
        local_lease.current_snapshot_id(),
        Err(StoreError::Locked)
    ));
    assert!(matches!(
        replication.contains_object(&ObjectId::from_bytes([0x47; 32])),
        Err(StoreError::Locked)
    ));
    assert!(matches!(unlocked.acquire_lease(), Err(StoreError::Locked)));
    assert!(other.acquire_lease().is_ok());
    unlocked.close().unwrap();
    other.close().unwrap();
}

fn parameters() -> ValidatedArgon2idParameters {
    ValidatedArgon2idParameters::try_from(Argon2idParameters {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    })
    .unwrap()
}

fn passphrase() -> RecoveryPassphrase {
    RecoveryPassphrase::new("alpha beta gamma delta epsilon".to_owned())
}
