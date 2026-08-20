use std::hint::black_box;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, Throughput};
#[cfg(target_os = "macos")]
use notecrypt_benches::rss::parse_macos_time_peak_rss;
use notecrypt_benches::rss::{RSS_MEASUREMENT_METHOD, RssEvidence, initial_process_rss_bytes};
use notecrypt_crypto::{
    ChunkFingerprint, ChunkFingerprintContext, ChunkKeyPlaintext, ChunkKeyWrapContext,
    ContentChunkContext, ContentChunkPlaintext, CryptoError, OsRandom, PublicEnvelopeIdentity,
    SecureRandom, TypedAeadEnvelope, VaultKeys, VaultRootKey, decrypt_content_chunk,
    derive_vault_keys, encrypt_content_chunk, fingerprint_chunk, unwrap_chunk_key, wrap_chunk_key,
};
use serde_json::{Value, json};

const KIB: usize = 1_024;
const MIB: usize = 1_048_576;
const CANDIDATE_BYTES: [usize; 3] = [MIB, 2 * MIB, 4 * MIB];
const WORKLOAD_BYTES: [usize; 3] = [KIB, MIB, 100 * MIB];
const WARMUP_REPETITIONS: usize = 3;
const MEASURED_REPETITIONS: usize = 9;
const PUBLIC_FRAMING_BYTES_PER_CHUNK: usize = 192;

fn main() {
    if std::env::args().any(|argument| argument == "--notecrypt-worker") {
        run_worker();
        return;
    }

    run_machine_readable_matrix();
    run_criterion_smoke();
}

fn run_machine_readable_matrix() {
    let executable = std::env::current_exe().expect("benchmark executable must resolve");
    for candidate_bytes in CANDIDATE_BYTES {
        for workload_bytes in WORKLOAD_BYTES {
            for operation in ["new_chunk", "authenticated_read"] {
                let (worker, rss) =
                    invoke_worker(&executable, candidate_bytes, workload_bytes, operation);
                let durations = worker["durations_ns"]
                    .as_array()
                    .expect("worker durations must be an array")
                    .iter()
                    .map(|value| value.as_u64().expect("duration must be an integer"))
                    .collect::<Vec<_>>();
                let throughput = durations
                    .iter()
                    .map(|duration| mib_per_second(workload_bytes, *duration))
                    .collect::<Vec<_>>();
                let record = json!({
                    "schema": "notecrypt.chunk-size-measurement.v1",
                    "crypto_profile": 1,
                    "operation": operation,
                    "candidate_chunk_bytes": candidate_bytes,
                    "workload_bucket": workload_bucket(workload_bytes),
                    "workload_bytes": workload_bytes,
                    "warmup_repetitions": WARMUP_REPETITIONS,
                    "measured_repetitions": MEASURED_REPETITIONS,
                    "median_throughput_mib_s": percentile(throughput.clone(), 0.50),
                    "p05_throughput_mib_s": percentile(throughput.clone(), 0.05),
                    "p95_throughput_mib_s": percentile(throughput, 0.95),
                    "initial_fresh_process_rss_bytes": rss.initial_bytes,
                    "peak_fresh_process_rss_bytes": rss.peak_bytes,
                    "peak_fresh_process_rss_delta_bytes": rss.delta_bytes,
                    "rss_measurement_method": rss.measurement_method,
                    "rss_measurement_available": rss.measurement_available,
                    "max_accounted_live_chunk_buffer_bytes": worker["max_accounted_live_chunk_buffer_bytes"],
                    "observed_p95_chunk_ms": worker["observed_p95_chunk_ms"],
                    "observed_max_chunk_ms": worker["observed_max_chunk_ms"],
                    "manifest_entries": worker["manifest_entries"],
                    "estimated_public_framing_bytes": worker["estimated_public_framing_bytes"],
                    "toolchain": rustc_release(),
                    "target_arch": std::env::consts::ARCH,
                    "target_os": std::env::consts::OS,
                });
                println!("NOTECRYPT_BASELINE {}", record);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn invoke_worker(
    executable: &std::path::Path,
    candidate_bytes: usize,
    workload_bytes: usize,
    operation: &str,
) -> (Value, RssEvidence) {
    let mut timed = Command::new("/usr/bin/time");
    timed.arg("-l").arg(executable).arg("--notecrypt-worker");
    configure_worker(&mut timed, candidate_bytes, workload_bytes, operation);
    let output = timed
        .output()
        .expect("/usr/bin/time must start the fresh benchmark worker");
    assert!(
        output.status.success(),
        "benchmark worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let worker: Value =
        serde_json::from_slice(&output.stdout).expect("worker output must be one JSON value");
    let initial_rss = required_worker_u64(&worker, "initial_rss_bytes");
    let peak_rss = parse_macos_time_peak_rss(&output.stderr)
        .expect("macOS absolute peak RSS must be available");
    let evidence = RssEvidence::try_new(initial_rss, peak_rss, RSS_MEASUREMENT_METHOD)
        .expect("same-worker RSS evidence must be ordered and complete");
    (worker, evidence)
}

#[cfg(any(target_os = "linux", windows))]
fn invoke_worker(
    executable: &std::path::Path,
    candidate_bytes: usize,
    workload_bytes: usize,
    operation: &str,
) -> (Value, RssEvidence) {
    let mut direct = Command::new(executable);
    direct.arg("--notecrypt-worker");
    configure_worker(&mut direct, candidate_bytes, workload_bytes, operation);
    let output = direct.output().expect("fresh benchmark worker must start");
    assert!(
        output.status.success(),
        "benchmark worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let worker: Value =
        serde_json::from_slice(&output.stdout).expect("worker output must be one JSON value");
    let initial_rss = required_worker_u64(&worker, "initial_rss_bytes");
    let peak_rss = required_worker_u64(&worker, "peak_os_rss_bytes");
    let evidence = RssEvidence::try_new(initial_rss, peak_rss, RSS_MEASUREMENT_METHOD)
        .expect("same-worker RSS evidence must be ordered and complete");
    (worker, evidence)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn invoke_worker(
    _executable: &std::path::Path,
    _candidate_bytes: usize,
    _workload_bytes: usize,
    _operation: &str,
) -> (Value, RssEvidence) {
    panic!("RSS measurement is unsupported on this operating system")
}

fn configure_worker(
    command: &mut Command,
    candidate_bytes: usize,
    workload_bytes: usize,
    operation: &str,
) {
    command
        .env("NOTECRYPT_CHUNK_BYTES", candidate_bytes.to_string())
        .env("NOTECRYPT_WORKLOAD_BYTES", workload_bytes.to_string())
        .env("NOTECRYPT_OPERATION", operation)
        .stdin(Stdio::null());
}

fn required_worker_u64(worker: &Value, field: &str) -> u64 {
    let value = worker[field]
        .as_u64()
        .unwrap_or_else(|| panic!("worker field {field} must be an unsigned integer"));
    assert!(value > 0, "worker field {field} must be non-zero");
    value
}

fn run_worker() {
    let candidate_bytes = env_usize("NOTECRYPT_CHUNK_BYTES");
    let workload_bytes = env_usize("NOTECRYPT_WORKLOAD_BYTES");
    let operation = std::env::var("NOTECRYPT_OPERATION").expect("operation must be set");
    assert!(CANDIDATE_BYTES.contains(&candidate_bytes));
    assert!(WORKLOAD_BYTES.contains(&workload_bytes));

    let initial_rss =
        initial_process_rss_bytes().expect("same-worker initial RSS must be available");
    let keys = benchmark_keys();
    let mut max_accounted_live_chunk_buffer_bytes = 0_usize;
    for repetition in 0..WARMUP_REPETITIONS {
        let mut warmup_chunk_durations = Vec::new();
        let _ = measure_once(
            candidate_bytes,
            workload_bytes,
            &operation,
            repetition,
            &keys,
            &mut max_accounted_live_chunk_buffer_bytes,
            &mut warmup_chunk_durations,
        );
    }

    let mut durations = Vec::with_capacity(MEASURED_REPETITIONS);
    let mut chunk_durations = Vec::new();
    for repetition in 0..MEASURED_REPETITIONS {
        durations.push(measure_once(
            candidate_bytes,
            workload_bytes,
            &operation,
            repetition + WARMUP_REPETITIONS,
            &keys,
            &mut max_accounted_live_chunk_buffer_bytes,
            &mut chunk_durations,
        ));
    }
    let p95_chunk_ns = percentile_u64(chunk_durations.clone(), 0.95);
    let max_chunk_ns = chunk_durations
        .iter()
        .copied()
        .max()
        .expect("every benchmark workload must contain a chunk");
    let result = json!({
        "durations_ns": durations,
        "initial_rss_bytes": initial_rss,
        "max_accounted_live_chunk_buffer_bytes": max_accounted_live_chunk_buffer_bytes,
        "observed_p95_chunk_ms": p95_chunk_ns as f64 / 1_000_000.0,
        "observed_max_chunk_ms": max_chunk_ns as f64 / 1_000_000.0,
        "manifest_entries": workload_bytes.div_ceil(candidate_bytes),
        "estimated_public_framing_bytes": workload_bytes
            .div_ceil(candidate_bytes)
            .saturating_mul(PUBLIC_FRAMING_BYTES_PER_CHUNK),
    });
    let result = attach_worker_peak_rss(result);
    println!("{result}");
}

#[cfg(any(target_os = "linux", windows))]
fn attach_worker_peak_rss(mut result: Value) -> Value {
    result["peak_os_rss_bytes"] = json!(
        notecrypt_benches::rss::worker_peak_rss_bytes()
            .expect("same-worker absolute peak RSS must be available")
    );
    result
}

#[cfg(not(any(target_os = "linux", windows)))]
fn attach_worker_peak_rss(result: Value) -> Value {
    result
}

fn measure_once(
    candidate_bytes: usize,
    workload_bytes: usize,
    operation: &str,
    repetition: usize,
    keys: &VaultKeys,
    max_accounted_live_chunk_buffer_bytes: &mut usize,
    chunk_durations: &mut Vec<u64>,
) -> u64 {
    let mut processed = 0_usize;
    let mut elapsed = Duration::ZERO;
    while processed < workload_bytes {
        let chunk_bytes = (workload_bytes - processed).min(candidate_bytes);
        let seed = (repetition as u64)
            .wrapping_mul(0x9e37_79b9)
            .wrapping_add(processed as u64);
        match operation {
            "new_chunk" => {
                let plaintext = synthetic_bytes(chunk_bytes, seed);
                *max_accounted_live_chunk_buffer_bytes =
                    (*max_accounted_live_chunk_buffer_bytes).max(plaintext.capacity());
                let semantics = fingerprint_semantics(processed / candidate_bytes);
                let started = Instant::now();
                let mut random = OsRandom;
                let chunk_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
                let fingerprint = fingerprint_chunk(
                    &ChunkFingerprintContext::profile_one(),
                    &semantics,
                    &plaintext,
                    &keys.chunk_fingerprint,
                )
                .unwrap();
                let content = encrypt_content_chunk(
                    &content_context(),
                    ContentChunkPlaintext::try_new(plaintext).unwrap(),
                    &chunk_key,
                    &mut random,
                )
                .unwrap();
                let wrapped = wrap_chunk_key(
                    &wrap_context(),
                    chunk_key,
                    &keys.content_wrapping,
                    &mut random,
                )
                .unwrap();
                *max_accounted_live_chunk_buffer_bytes = (*max_accounted_live_chunk_buffer_bytes)
                    .max(content.parts().ciphertext().len());
                let chunk_elapsed = started.elapsed();
                elapsed += chunk_elapsed;
                chunk_durations.push(u64::try_from(chunk_elapsed.as_nanos()).unwrap_or(u64::MAX));
                black_box(fingerprint);
                black_box(content.parts().ciphertext());
                black_box(wrapped.parts().ciphertext());
            }
            "authenticated_read" => {
                let plaintext = synthetic_bytes(chunk_bytes, seed);
                *max_accounted_live_chunk_buffer_bytes =
                    (*max_accounted_live_chunk_buffer_bytes).max(plaintext.capacity());
                let semantics = fingerprint_semantics(processed / candidate_bytes);
                let fingerprint = fingerprint_chunk(
                    &ChunkFingerprintContext::profile_one(),
                    &semantics,
                    &plaintext,
                    &keys.chunk_fingerprint,
                )
                .unwrap();
                let mut random = OsRandom;
                let chunk_key = ChunkKeyPlaintext::generate(&mut random).unwrap();
                let content = encrypt_content_chunk(
                    &content_context(),
                    ContentChunkPlaintext::try_new(plaintext).unwrap(),
                    &chunk_key,
                    &mut random,
                )
                .unwrap();
                let wrapped = wrap_chunk_key(
                    &wrap_context(),
                    chunk_key,
                    &keys.content_wrapping,
                    &mut random,
                )
                .unwrap();

                let started = Instant::now();
                let recovered_key =
                    unwrap_chunk_key(&wrap_context(), &wrapped, &keys.content_wrapping).unwrap();
                let recovered =
                    decrypt_content_chunk(&content_context(), &content, &recovered_key).unwrap();
                recovered.into_protected_bytes().consume(|bytes| {
                    let live_chunk_bytes = content
                        .parts()
                        .ciphertext()
                        .len()
                        .checked_add(bytes.len())
                        .expect("live chunk-buffer accounting must not overflow");
                    *max_accounted_live_chunk_buffer_bytes =
                        (*max_accounted_live_chunk_buffer_bytes).max(live_chunk_bytes);
                    notecrypt_crypto::verify_chunk_fingerprint(
                        &ChunkFingerprintContext::profile_one(),
                        &semantics,
                        bytes,
                        &fingerprint,
                        &keys.chunk_fingerprint,
                    )
                    .unwrap();
                    black_box(bytes.len());
                });
                let chunk_elapsed = started.elapsed();
                elapsed += chunk_elapsed;
                chunk_durations.push(u64::try_from(chunk_elapsed.as_nanos()).unwrap_or(u64::MAX));
            }
            _ => panic!("unsupported benchmark operation"),
        }
        processed += chunk_bytes;
    }
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

fn run_criterion_smoke() {
    let keys = benchmark_keys();
    let mut criterion = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .configure_from_args();
    let mut group = criterion.benchmark_group("bounded_chunk_crypto");

    for candidate_bytes in CANDIDATE_BYTES {
        group.throughput(Throughput::Bytes(candidate_bytes as u64));
        group.bench_function(format!("new/{candidate_bytes}"), |bencher| {
            bencher.iter_batched(
                || {
                    (
                        synthetic_bytes(candidate_bytes, 7),
                        fingerprint_semantics(0),
                    )
                },
                |(plaintext, semantics)| {
                    let mut random = OsRandom;
                    let key = ChunkKeyPlaintext::generate(&mut random).unwrap();
                    let fingerprint = fingerprint_chunk(
                        &ChunkFingerprintContext::profile_one(),
                        &semantics,
                        &plaintext,
                        &keys.chunk_fingerprint,
                    )
                    .unwrap();
                    let content = encrypt_content_chunk(
                        &content_context(),
                        ContentChunkPlaintext::try_new(plaintext).unwrap(),
                        &key,
                        &mut random,
                    )
                    .unwrap();
                    let wrapped =
                        wrap_chunk_key(&wrap_context(), key, &keys.content_wrapping, &mut random)
                            .unwrap();
                    black_box((fingerprint, content, wrapped));
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(format!("read/{candidate_bytes}"), |bencher| {
            bencher.iter_batched(
                || encrypted_fixture(candidate_bytes, &keys),
                |(content, wrapped, fingerprint, semantics)| {
                    let key = unwrap_chunk_key(&wrap_context(), &wrapped, &keys.content_wrapping)
                        .unwrap();
                    let plaintext =
                        decrypt_content_chunk(&content_context(), &content, &key).unwrap();
                    plaintext.into_protected_bytes().consume(|bytes| {
                        notecrypt_crypto::verify_chunk_fingerprint(
                            &ChunkFingerprintContext::profile_one(),
                            &semantics,
                            bytes,
                            &fingerprint,
                            &keys.chunk_fingerprint,
                        )
                        .unwrap();
                        black_box(bytes.len());
                    });
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
    criterion.final_summary();
}

fn encrypted_fixture(
    bytes: usize,
    keys: &VaultKeys,
) -> (
    notecrypt_crypto::ContentChunkEnvelope,
    notecrypt_crypto::ChunkKeyEnvelope,
    ChunkFingerprint,
    Vec<u8>,
) {
    let mut random = OsRandom;
    let plaintext = synthetic_bytes(bytes, 11);
    let semantics = fingerprint_semantics(0);
    let fingerprint = fingerprint_chunk(
        &ChunkFingerprintContext::profile_one(),
        &semantics,
        &plaintext,
        &keys.chunk_fingerprint,
    )
    .unwrap();
    let key = ChunkKeyPlaintext::generate(&mut random).unwrap();
    let content = encrypt_content_chunk(
        &content_context(),
        ContentChunkPlaintext::try_new(plaintext).unwrap(),
        &key,
        &mut random,
    )
    .unwrap();
    let wrapped =
        wrap_chunk_key(&wrap_context(), key, &keys.content_wrapping, &mut random).unwrap();
    (content, wrapped, fingerprint, semantics)
}

fn benchmark_keys() -> VaultKeys {
    struct FixedRandom;
    impl SecureRandom for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0x42);
            Ok(())
        }
    }
    derive_vault_keys(&VaultRootKey::generate(&mut FixedRandom).unwrap()).unwrap()
}

fn content_context() -> ContentChunkContext {
    ContentChunkContext::try_new(identity(ContentChunkContext::OBJECT_KIND, 2)).unwrap()
}

fn wrap_context() -> ChunkKeyWrapContext {
    ChunkKeyWrapContext::try_new(identity(ChunkKeyWrapContext::OBJECT_KIND, 3)).unwrap()
}

fn identity(kind: u8, object: u8) -> PublicEnvelopeIdentity {
    PublicEnvelopeIdentity {
        profile_id: 1,
        vault_id: [1; 16],
        object_kind: kind,
        format_version: 1,
        object_id: [object; 32],
    }
}

fn fingerprint_semantics(sequence: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&[4; 16]);
    bytes.extend_from_slice(&(sequence as u64).to_be_bytes());
    bytes
}

fn synthetic_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0xa076_1d64_78bd_642f;
    let mut bytes = vec![0_u8; length];
    for chunk in bytes.chunks_mut(8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let generated = state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
        chunk.copy_from_slice(&generated[..chunk.len()]);
    }
    bytes
}

fn env_usize(name: &str) -> usize {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be an integer"))
}

fn workload_bucket(bytes: usize) -> &'static str {
    match bytes {
        KIB => "1KiB",
        MIB => "1MiB",
        _ => "100MiB",
    }
}

fn mib_per_second(bytes: usize, nanoseconds: u64) -> f64 {
    bytes as f64 / MIB as f64 / (nanoseconds as f64 / 1_000_000_000.0)
}

fn percentile(mut values: Vec<f64>, fraction: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    let index = ((values.len() - 1) as f64 * fraction).ceil() as usize;
    values[index]
}

fn percentile_u64(mut values: Vec<u64>, fraction: f64) -> u64 {
    values.sort_unstable();
    let index = ((values.len() - 1) as f64 * fraction).ceil() as usize;
    values[index]
}

fn rustc_release() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}
