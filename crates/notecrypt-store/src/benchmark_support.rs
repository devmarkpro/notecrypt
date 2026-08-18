use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::path::Path;
use std::time::{Duration, Instant};

use notecrypt_core::VaultId;
use notecrypt_crypto::{OsRandom, SecureRandom};

use crate::batch::{BatchBoundary, BatchMetrics};
use crate::local::generate_unique_object;
use crate::{StoreError, VaultStore};

const COPY_PAGE_BYTES: usize = 64 * 1024;
const ACCOUNTED_BATCH_METADATA_BYTES_PER_OBJECT: usize =
    size_of::<notecrypt_core::ObjectId>() + size_of::<notecrypt_platform_fs::PhysicalComponent>();

pub struct PublicationBenchmark {
    store: VaultStore,
}

pub struct PublicationBenchmarkMetrics {
    pub stage: Duration,
    pub flush: Duration,
    pub authenticate: Duration,
    pub publish: Duration,
    pub directory_sync: Duration,
    pub finish: Duration,
    pub total: Duration,
    pub staged_file_syncs: u64,
    pub staging_directory_syncs: u64,
    pub immutable_publications: u64,
    pub exact_existing: u64,
    pub shard_directory_syncs: u64,
    pub accounted_buffer_bytes: usize,
    pub accounted_batch_metadata_bytes: usize,
}

impl PublicationBenchmark {
    pub fn create(repository_root: &Path, local_state_root: &Path) -> Result<Self, StoreError> {
        let mut random = OsRandom;
        let mut vault = [0_u8; 16];
        random
            .fill(&mut vault)
            .map_err(|_| StoreError::RandomSource)?;
        Ok(Self {
            store: VaultStore::create_benchmark(
                repository_root,
                local_state_root,
                VaultId::from_bytes(vault),
            )?,
        })
    }

    pub fn publish_generated(
        &mut self,
        object_bytes: u64,
        object_count: usize,
    ) -> Result<PublicationBenchmarkMetrics, StoreError> {
        let total_started = Instant::now();
        let mut batch = self.store.begin_durable_batch()?;
        let mut random = OsRandom;
        let stage_started = Instant::now();
        for _ in 0..object_count {
            let id = generate_unique_object(&self.store, &mut random)?;
            let mut source = std::io::repeat(0x5a).take(object_bytes);
            batch.stage(id, &mut source, object_bytes)?;
        }
        let stage = stage_started.elapsed();

        let mut flush = Duration::ZERO;
        let mut authenticate = Duration::ZERO;
        let mut publish = Duration::ZERO;
        let mut directory_sync = Duration::ZERO;
        let mut boundary_started = Instant::now();
        let published = batch.authenticate_and_publish_observed(
            |_, file| authenticate_generated(file, object_bytes),
            |boundary, before| {
                if before {
                    boundary_started = Instant::now();
                } else {
                    let elapsed = boundary_started.elapsed();
                    match boundary {
                        BatchBoundary::Flushed => flush = elapsed,
                        BatchBoundary::Authenticated => authenticate = elapsed,
                        BatchBoundary::PublishedNames => publish = elapsed,
                        BatchBoundary::DirectoriesSynced => directory_sync = elapsed,
                    }
                }
                Ok(())
            },
        )?;
        let counts = metrics_counts(published.metrics());
        let finish_started = Instant::now();
        published.finish()?;
        let finish = finish_started.elapsed();
        Ok(PublicationBenchmarkMetrics {
            stage,
            flush,
            authenticate,
            publish,
            directory_sync,
            finish,
            total: total_started.elapsed(),
            staged_file_syncs: counts.0,
            staging_directory_syncs: counts.1,
            immutable_publications: counts.2,
            exact_existing: counts.3,
            shard_directory_syncs: counts.4,
            accounted_buffer_bytes: COPY_PAGE_BYTES,
            accounted_batch_metadata_bytes: object_count
                .checked_mul(ACCOUNTED_BATCH_METADATA_BYTES_PER_OBJECT)
                .ok_or(StoreError::LimitExceeded)?,
        })
    }
}

fn authenticate_generated(file: &mut impl ReadSeek, expected: u64) -> Result<(), StoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = expected;
    let mut buffer = [0_u8; COPY_PAGE_BYTES];
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(COPY_PAGE_BYTES as u64))
            .map_err(|_| StoreError::LimitExceeded)?;
        let read = file.read(&mut buffer[..maximum])?;
        if read == 0 || buffer[..read].iter().any(|byte| *byte != 0x5a) {
            return Err(StoreError::AuthenticationFailed);
        }
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| StoreError::LimitExceeded)?)
            .ok_or(StoreError::LimitExceeded)?;
    }
    let mut sentinel = [0_u8; 1];
    if file.read(&mut sentinel)? != 0 {
        return Err(StoreError::LimitExceeded);
    }
    Ok(())
}

trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

const fn metrics_counts(metrics: &BatchMetrics) -> (u64, u64, u64, u64, u64) {
    (
        metrics.staged_file_syncs,
        metrics.staging_directory_syncs,
        metrics.immutable_renames,
        metrics.exact_existing,
        metrics.shard_directory_syncs,
    )
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{ACCOUNTED_BATCH_METADATA_BYTES_PER_OBJECT, PublicationBenchmark};

    #[test]
    fn benchmark_support_uses_batched_production_publication() {
        let repository = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let mut benchmark = PublicationBenchmark::create(
            &repository.path().canonicalize().unwrap(),
            &local.path().canonicalize().unwrap(),
        )
        .unwrap();
        let metrics = benchmark.publish_generated(1_024, 10).unwrap();
        assert_eq!(metrics.staged_file_syncs, 10);
        assert_eq!(metrics.immutable_publications, 10);
        assert_eq!(metrics.exact_existing, 0);
        assert_eq!(metrics.staging_directory_syncs, 2);
        assert!(metrics.shard_directory_syncs <= 10);
        assert_eq!(
            metrics.accounted_batch_metadata_bytes,
            10 * ACCOUNTED_BATCH_METADATA_BYTES_PER_OBJECT
        );
    }
}
