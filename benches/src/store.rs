use notecrypt_store::PublicationBenchmark;
use serde_json::json;
use tempfile::TempDir;

const KIB: u64 = 1_024;
const MIB: u64 = 1_048_576;
const WARM_REPETITIONS: usize = 3;

fn main() {
    for (workload, object_bytes, object_count) in [
        ("1KiB", KIB, 1_usize),
        ("1MiB", MIB, 1),
        ("100MiB", 100 * MIB, 1),
        ("10k-tiny", KIB, 10_000),
    ] {
        let repository = TempDir::new().expect("benchmark repository");
        let local = TempDir::new().expect("benchmark local state");
        let mut benchmark = PublicationBenchmark::create(
            &repository
                .path()
                .canonicalize()
                .expect("canonical benchmark repository"),
            &local
                .path()
                .canonicalize()
                .expect("canonical benchmark local state"),
        )
        .expect("create production store benchmark");
        measure_and_report(
            &mut benchmark,
            workload,
            "cold-first-new-repository",
            0,
            object_bytes,
            object_count,
        );
        for repetition in 1..=WARM_REPETITIONS {
            measure_and_report(
                &mut benchmark,
                workload,
                "warm-repeated-same-repository",
                repetition,
                object_bytes,
                object_count,
            );
        }
    }
}

fn measure_and_report(
    benchmark: &mut PublicationBenchmark,
    workload: &str,
    cache_state: &str,
    repetition: usize,
    object_bytes: u64,
    object_count: usize,
) {
    let metrics = benchmark
        .publish_generated(object_bytes, object_count)
        .expect("publish through production DurableBatch");
    let aggregate_bytes = object_bytes
        .checked_mul(u64::try_from(object_count).expect("object count fits u64"))
        .expect("aggregate bytes");
    let throughput_mib_s = aggregate_bytes as f64 / MIB as f64 / metrics.total.as_secs_f64();
    println!(
        "NOTECRYPT_STORE_BENCH {}",
        json!({
            "schema": "notecrypt.store-publication.v3",
            "platform_method": platform_method(),
            "measurement_scope": "production DurableBatch staging, authentication, batching, exact publication, synchronization, and cleanup without cryptography",
            "workload": workload,
            "cache_state": cache_state,
            "cache_definition": cache_definition(cache_state),
            "repetition": repetition,
            "object_count": object_count,
            "object_bytes": object_bytes,
            "aggregate_bytes": aggregate_bytes,
            "stage_ns": metrics.stage.as_nanos(),
            "flush_ns": metrics.flush.as_nanos(),
            "authenticate_ns": metrics.authenticate.as_nanos(),
            "publish_ns": metrics.publish.as_nanos(),
            "directory_sync_ns": metrics.directory_sync.as_nanos(),
            "finish_cleanup_ns": metrics.finish.as_nanos(),
            "total_ns": metrics.total.as_nanos(),
            "throughput_mib_s": throughput_mib_s,
            "file_sync_count": metrics.staged_file_syncs,
            "staging_directory_sync_count": metrics.staging_directory_syncs,
            "immutable_publish_count": metrics.immutable_publications,
            "exact_existing_count": metrics.exact_existing,
            "shard_directory_sync_count": metrics.shard_directory_syncs,
            "max_accounted_buffer_bytes": metrics.accounted_buffer_bytes,
            "accounted_batch_metadata_bytes": metrics.accounted_batch_metadata_bytes,
            "accounted_batch_metadata_derivation": "object_count * (size_of(ObjectId) + size_of(PhysicalComponent)); allocator and collection overhead are not included",
            "retained_object_payload_bytes": 0,
        })
    );
}

fn cache_definition(cache_state: &str) -> &'static str {
    if cache_state == "cold-first-new-repository" {
        "first measured publication in a newly initialized repository; OS cache is not forcibly dropped"
    } else {
        "subsequent equivalent publication through the same store, filesystem capabilities, and process"
    }
}

#[cfg(target_os = "linux")]
fn platform_method() -> &'static str {
    "Linux exact-fd procfs linkat publication plus explicit fsync"
}

#[cfg(target_os = "macos")]
fn platform_method() -> &'static str {
    "macOS exact-fd clonefile publication plus explicit fsync"
}

#[cfg(target_os = "windows")]
fn platform_method() -> &'static str {
    "Windows exact-handle FILE_RENAME_INFO publication plus FlushFileBuffers"
}
