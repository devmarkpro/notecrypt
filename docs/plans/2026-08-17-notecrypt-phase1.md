# Notecrypt Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `common:subagent-driven-development` (recommended) or `common:executing-plans` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a secure, responsive Rust encrypted-file vault with a usable CLI and TUI, supervised external editing, whole-vault sessions, and portable Git synchronization.

**Architecture:** A Cargo workspace separates deterministic domain behavior, durable formats, cryptography, transactional encrypted storage, backend contracts, replication, and application orchestration.
The CLI and TUI consume one in-process service facade whose worker model keeps all blocking work outside the terminal event loop.

**Tech Stack:** Rust 1.96.1, Cargo resolver 3, Argon2id, XChaCha20-Poly1305, HKDF-SHA-256, keyed BLAKE3, `bip39`, `minicbor`, `zeroize`, `secrecy`, `serde`, `serde_json`, `thiserror`, `uuid`, `tempfile`, `crossbeam-channel`, `notify`, `clap`, `ratatui`, `crossterm`, `keyring`, `rpassword`, `tracing`, Criterion, Proptest, Trybuild, cargo-fuzz, cargo-deny, cargo-audit, and the installed Git executable.

**Design specification:** `docs/plans/2026-08-17-notecrypt-phase1-design.md`

## Global Constraints

- Work on a feature branch and never commit directly to `main` or `master`.
- Plaintext content and logical paths must never be written inside the encrypted vault repository.
- Targeted editing must not scan, decrypt, or encrypt the entire vault.
- TUI rendering and input handling must never perform blocking cryptography, filesystem traversal, keyring, Git, or network work.
- File processing must stream through bounded buffers and remain bounded in memory for 10 GiB inputs.
- Every durable decoder must reject malformed, oversized, unsupported, non-canonical, reordered, duplicated, and truncated input.
- Cryptographic profile 1, Argon2id profile 1, custom-passphrase policy 1, and replication budget profile 1 use the exact identifiers, limits, AAD, MAC, and key domains in the design specification.
- Any CSPRNG failure is fatal to the operation and publishes no state.
- Generated 128-bit recovery phrases are the default, and custom recovery passphrases require the explicit versioned warning and confirmation path.
- Whole-stream operations must not retain raw key references between chunks, and lock revocation must be checked before and after every bounded chunk.
- Save acknowledgement must distinguish detected, encrypting, locally durable, and synchronized states.
- A failed local transaction must never advance the trusted local head.
- A failed remote publish must never overwrite an unexpected remote head.
- Bootstrap bytes are immutable for a vault identity and must transfer and independently read back during conformance, backend copy, Git onboarding, backup, and clean-device recovery.
- Replication must use the object-safe revocable store lease and enforce per-kind, aggregate-byte, object-count, graph-depth, timeout, progress, and quarantine-disk budgets.
- Plaintext cleanup accepts only random workspace identities below the fixed Notecrypt-owned base and follows reserve, register, activate, remove, and unregister ownership ordering.
- Every internal Git operation uses the hardened runner and verifies fetched candidate history plus the complete authenticated graph before trust advances.
- Phase 1 supports regular files and directories only.
- Durable format, snapshot layout, backend SPI, and CLI JSON versions evolve independently.
- No public API may expose Tokio, Git implementation, `anyhow`, serializer, or cryptographic-library types.
- Dependencies must be reviewed, locked in `Cargo.lock`, audited, and denied by default when licenses are outside the repository policy.
- Every implementation task follows test-driven development and ends in one conventional commit with a lowercase scope and no trailing period.

## Delivery Checkpoints

- Checkpoint A after Task 15 is a runnable local vault with CLI, TUI, passphrase unlock, targeted editing, lock, and reopen.
- Checkpoint B after Task 17 adds arbitrary-file whole-vault sessions, budgeted authenticated replication, deterministic conflict reconciliation, `BackendCopy`, and `CompromiseRekey` service behavior.
- Checkpoint C after Task 19 adds hardened Git synchronization, verified backup, device-local unlock, and the explicit CLI and TUI presentation-integration gate.
- Checkpoint D after Task 21 is the hardened phase 1 release candidate.

## Specification Traceability

| Specification area | Implementation tasks |
| --- | --- |
| Workspace boundaries and dependency rules | 1, 20 |
| Domain identities, logical tree, tombstones, and conflicts | 2, 17 |
| Key hierarchy, generated recovery, KDF bounds, compromise rekey, and authenticated chunks | 3, 4, 10, 14, 15, 17, 20 |
| Durable cryptographic profiles, formats, and independent versioning | 3, 4, 5, 6, 20 |
| Crash-consistent local transactions, cleanup ownership, and rollback detection | 6, 9, 12, 16, 20 |
| Portable backend SPI, immutable bootstrap, `BackendCopy`, and `CompromiseRekey` | 7, 10, 17, 18, 20 |
| Runtime-neutral service, sessions, progress, cancellation, and lock | 8, 9, 10, 11, 13, 16 |
| Complete local application use cases | 10, 11 |
| Targeted editing, stable sources, revocation, and local plaintext minimization | 6, 9, 12, 13, 20 |
| Complete CLI and polished TUI | 10, 14, 15, 16, 17, 18, 19, 20 |
| Whole-vault autosave and filesystem safety | 9, 12, 16, 20 |
| Budgeted authenticated synchronization and conflict preservation | 6, 7, 17, 20 |
| Hardened Git onboarding, history verification, synchronization, and backup | 7, 18, 20 |
| Native device unlock, removal, and recovery fallback | 19, 20 |
| Security, recovery, fuzzing, canary, and platform evidence | 20 |
| Performance budgets and regression protection | 1, 4, 6, 13, 14, 15, 21 |

## Planned File Map

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
deny.toml
.gitignore
.github/workflows/ci.yml
crates/notecrypt-core/src/{lib.rs,error.rs,ids.rs,path.rs,tree.rs,snapshot.rs,reconcile.rs}
crates/notecrypt-format/src/{lib.rs,error.rs,limits.rs,crypto_profile.rs,header.rs,object.rs,manifest.rs,snapshot.rs}
crates/notecrypt-crypto/src/{lib.rs,error.rs,secret.rs,recovery.rs,kdf.rs,keys.rs,aead.rs,stream.rs}
crates/notecrypt-store/src/{lib.rs,error.rs,layout.rs,repository.rs,journal.rs,transaction.rs,recovery.rs,trusted_state.rs,cleanup.rs,replication.rs,stream.rs,durability/mod.rs,durability/unix.rs,durability/windows.rs}
crates/notecrypt-backend/src/{lib.rs,error.rs,types.rs,bootstrap.rs,backend.rs,conformance.rs}
crates/notecrypt-replication/src/{lib.rs,error.rs,limits.rs,plan.rs,reconcile.rs,sync.rs,migration.rs,compromise_rekey.rs}
crates/notecrypt-service/src/{lib.rs,command.rs,error.rs,event.rs,operation.rs,ports.rs,session.rs,service.rs,local_use_cases.rs}
adapters/notecrypt-backend-git/src/{lib.rs,error.rs,runner.rs,repository.rs,backend.rs,hooks.rs,quarantine.rs,verify.rs}
adapters/notecrypt-device-unlock/src/{lib.rs,error.rs,native.rs}
adapters/notecrypt-editor-workspace/src/{lib.rs,error.rs,editor.rs,permissions.rs,workspace.rs,watcher.rs}
ui/notecrypt-tui/src/{lib.rs,app.rs,event_loop.rs,keymap.rs,view_model.rs,widgets.rs,dialogs.rs}
apps/notecrypt-cli/src/{main.rs,args.rs,config.rs,commands.rs,output.rs,password.rs}
tests/notecrypt-e2e/Cargo.toml
tests/notecrypt-e2e/src/{lib.rs,workspace_policy.rs,test_editor.rs}
tests/notecrypt-e2e/tests/{local_facade.rs,local_vault.rs,cli_journey.rs,tui_journey.rs,whole_vault.rs,git_sync.rs,presentation_journey.rs,recovery_journey.rs,plaintext_canary.rs,crash_recovery.rs}
benches/src/{lib.rs,corpus.rs,crypto.rs,store.rs,targeted_edit.rs,tui_latency.rs}
benches/baselines/chunk-size-v1.json
docs/decisions/{0001-rust-core-and-ui.md,0002-encrypted-object-format.md,0003-chunk-reuse-leakage.md,0004-backend-contract.md}
docs/security/{threat-model.md,recovery.md}
```

---

### Task 1: Establish the workspace, policies, and measurement harness

**Files:**

- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `.gitignore`
- Create: `deny.toml`
- Create: `.github/workflows/ci.yml`
- Create: one `Cargo.toml` and `src/lib.rs` or `src/main.rs` for every planned package
- Create: `benches/Cargo.toml`
- Create: `benches/src/lib.rs`
- Create: `benches/src/corpus.rs`
- Create: `tests/notecrypt-e2e/Cargo.toml`
- Create: `tests/notecrypt-e2e/src/lib.rs`
- Create: `tests/notecrypt-e2e/src/workspace_policy.rs`

**Interfaces:**

- Produces: a compiling virtual workspace with resolver 3 and private crates.
- Produces: `BenchmarkCorpus::generate(&Path) -> Result<CorpusManifest, CorpusError>`.
- Produces: CI jobs for format, lint, unit tests, documentation, dependency policy, and three desktop operating systems.

- [ ] **Step 1: Write a failing workspace-policy test**

Create `tests/notecrypt-e2e/src/workspace_policy.rs` and a package test that parse every workspace manifest, assert `publish = false`, reject forbidden dependency directions, and verify that the workspace resolver is `3`.

```rust
#[test]
fn workspace_packages_are_private_and_dependencies_point_inward() {
    let workspace = WorkspacePolicy::load(env!("CARGO_MANIFEST_DIR")).unwrap();
    workspace.assert_resolver("3").unwrap();
    workspace.assert_all_private().unwrap();
    workspace.assert_dependency_rules().unwrap();
}
```

- [ ] **Step 2: Run the policy test and verify failure**

Run: `cargo test -p notecrypt-e2e workspace_policy`

Expected: failure because the workspace and policy loader do not exist.

- [ ] **Step 3: Create the virtual workspace and package skeletons**

Set workspace package values to edition `2024`, rust-version `1.96.1`, version `0.1.0`, and `publish = false`.
Add workspace dependency families listed in the tech stack without enabling mutually exclusive backend features.
Implement `WorkspacePolicy` inside the integration test support module so the test reports the exact offending edge.

- [ ] **Step 4: Add the deterministic benchmark corpus generator**

Implement these exact public types in `benches/src/corpus.rs`:

```rust
pub struct CorpusSpec {
    pub seed: u64,
    pub tiny_file_count: usize,
    pub mixed_bytes: u64,
    pub large_file_bytes: u64,
}

pub struct CorpusManifest {
    pub root: std::path::PathBuf,
    pub file_count: usize,
    pub logical_bytes: u64,
}

pub struct BenchmarkCorpus;

impl BenchmarkCorpus {
    pub fn generate(
        spec: &CorpusSpec,
        destination: &std::path::Path,
    ) -> Result<CorpusManifest, CorpusError>;
}
```

The generator writes seeded synthetic bytes only and includes tiny files, incompressible files, a sparse-file case, and rename-save fixtures.

- [ ] **Step 5: Add CI and dependency policy**

Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc --workspace --no-deps`, `cargo deny check`, and the workspace-policy test.
Build on stable macOS, Ubuntu, and Windows.
Keep absolute performance gates out of shared runners and reserve them for dedicated benchmark workers.

- [ ] **Step 6: Verify and commit**

Run: `cargo test --workspace && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`

Expected: all workspace tests pass and all crates compile.

Commit: `chore(workspace): establish rust workspace and quality gates`

---

### Task 2: Implement deterministic domain identities and logical trees

**Files:**

- Create: `crates/notecrypt-core/src/error.rs`
- Create: `crates/notecrypt-core/src/ids.rs`
- Create: `crates/notecrypt-core/src/path.rs`
- Create: `crates/notecrypt-core/src/tree.rs`
- Create: `crates/notecrypt-core/src/snapshot.rs`
- Create: `crates/notecrypt-core/src/reconcile.rs`
- Modify: `crates/notecrypt-core/src/lib.rs`
- Test: unit tests beside each module
- Test: `crates/notecrypt-core/tests/reconcile_properties.rs`

**Interfaces:**

- Produces: opaque `VaultId`, `DeviceId`, `FileId`, `RevisionId`, `ObjectId`, and `SnapshotId` newtypes over fixed byte arrays.
- Produces: validated `LogicalPath` and immutable `VaultTree` operations.
- Produces: deterministic `reconcile(base, local, remote) -> ReconcileResult`.

- [ ] **Step 1: Write failing identity and path tests**

Test equality and ordering of identities, rejection of `..`, absolute paths, empty components, NUL, platform-reserved components, Unicode normalization collisions, and case-fold collisions.

```rust
#[test]
fn logical_path_rejects_parent_traversal() {
    assert_eq!(
        LogicalPath::parse("notes/../secret").unwrap_err(),
        CoreError::ParentTraversal,
    );
}
```

- [ ] **Step 2: Implement identities and path validation**

Use private fields and explicit constructors.
Give `ObjectId` only `from_bytes([u8; 32]) -> Self` and `as_bytes(&self) -> &[u8; 32]` conversion methods for the replication boundary.
Store normalized path components without accepting platform-specific separators as hidden traversal.
Expose display names only through unlocked domain values.

- [ ] **Step 3: Write failing tree-transition tests**

Cover create, rename, move, delete, duplicate destination, missing parent, stable file identity across rename, and tombstone creation.

- [ ] **Step 4: Implement immutable tree transitions**

Implement these exact public operations:

```rust
impl VaultTree {
    pub fn empty(root: FileId) -> Self;
    pub fn create_file(&self, parent: FileId, entry: FileEntry) -> Result<Self, CoreError>;
    pub fn create_directory(&self, parent: FileId, entry: DirectoryEntry) -> Result<Self, CoreError>;
    pub fn rename(&self, id: FileId, name: EntryName) -> Result<Self, CoreError>;
    pub fn move_entry(&self, id: FileId, parent: FileId) -> Result<Self, CoreError>;
    pub fn remove(&self, id: FileId, deleted_in: SnapshotId) -> Result<Self, CoreError>;
    pub fn entry(&self, id: FileId) -> Option<&Entry>;
    pub fn children(&self, parent: FileId) -> Result<Vec<&Entry>, CoreError>;
}
```

- [ ] **Step 5: Write failing reconciliation properties**

Generate independent changes, same-file changes, rename conflicts, delete-versus-modify, and normalized-path collisions.
Assert determinism, commutativity of preserved content, and absence of dropped revisions.

- [ ] **Step 6: Implement deterministic reconciliation**

Return merged tree, conflict records, and two-parent snapshot input.
Conflict suffixes contain a sanitized device label and short snapshot identity.
Never merge file bytes.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-core`

Expected: unit and property tests pass.

Commit: `feat(core): add vault tree and deterministic reconciliation`

---

### Task 3: Implement the key hierarchy and passphrase recovery

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/notecrypt-crypto/Cargo.toml`
- Create: `crates/notecrypt-crypto/src/error.rs`
- Create: `crates/notecrypt-crypto/src/secret.rs`
- Create: `crates/notecrypt-crypto/src/recovery.rs`
- Create: `crates/notecrypt-crypto/src/kdf.rs`
- Create: `crates/notecrypt-crypto/src/keys.rs`
- Create: `crates/notecrypt-crypto/src/aead.rs`
- Modify: `crates/notecrypt-crypto/src/lib.rs`
- Test: `crates/notecrypt-crypto/tests/domain_separation.rs`
- Test: `crates/notecrypt-crypto/tests/recovery_credentials.rs`

**Interfaces:**

- Produces: non-formatting secret key types.
- Produces: 128-bit generated recovery phrases, custom-passphrase policy version 1, strictly bounded Argon2id profile 1, and Vault Root Key wrapping.

- [ ] **Step 1: Write compile-fail and domain-separation tests**

Use `trybuild` to prove that recovery, root, and derived secret types cannot be cloned, debug-formatted, displayed, or serialized.
Assert that changing any authenticated context field makes decryption fail and that a failing CSPRNG returns a hard error before any key or wrapper is returned.

- [ ] **Step 2: Implement secret and KDF types**

Implement these public types and functions:

```rust
pub struct RecoveryPassphrase(secrecy::SecretString);
pub struct VaultRootKey(secrecy::SecretBox<[u8; 32]>);
pub struct RecoveryWrappingKey(secrecy::SecretBox<[u8; 32]>);
pub struct MetadataKey(secrecy::SecretBox<[u8; 32]>);
pub struct SnapshotAuthenticationKey(secrecy::SecretBox<[u8; 32]>);
pub struct ChunkFingerprintKey(secrecy::SecretBox<[u8; 32]>);
pub struct ContentWrappingKey(secrecy::SecretBox<[u8; 32]>);
pub struct LocalVerificationKey(secrecy::SecretBox<[u8; 32]>);
pub struct DeviceWrappingKey(secrecy::SecretBox<[u8; 32]>);
pub struct RecoveryPhrase(secrecy::SecretString);

pub struct VaultKeys {
    pub metadata: MetadataKey,
    pub snapshot_authentication: SnapshotAuthenticationKey,
    pub chunk_fingerprint: ChunkFingerprintKey,
    pub content_wrapping: ContentWrappingKey,
    pub local_verification: LocalVerificationKey,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

pub struct ValidatedArgon2idParameters(Argon2idParameters);

impl TryFrom<Argon2idParameters> for ValidatedArgon2idParameters {
    type Error = CryptoError;

    fn try_from(value: Argon2idParameters) -> Result<Self, Self::Error>;
}

pub enum CustomPassphrasePolicy {
    V1,
}

pub trait SecureRandom: Send {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError>;
}

pub fn generate_recovery_phrase(
    random: &mut dyn SecureRandom,
) -> Result<RecoveryPhrase, CryptoError>;

pub fn validate_custom_passphrase(
    passphrase: RecoveryPassphrase,
    policy: CustomPassphrasePolicy,
) -> Result<RecoveryPassphrase, CryptoError>;

pub fn calibrate_argon2id(
    target: std::time::Duration,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<ValidatedArgon2idParameters, CryptoError>;

pub fn derive_recovery_wrapping_key(
    passphrase: &RecoveryPassphrase,
    salt: &[u8; 16],
    parameters: ValidatedArgon2idParameters,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<RecoveryWrappingKey, CryptoError>;

pub fn derive_vault_keys(root: &VaultRootKey) -> Result<VaultKeys, CryptoError>;
```

`generate_recovery_phrase` consumes exactly 128 CSPRNG bits and encodes BIP39 English version 1 as 12 words plus checksum.
Custom policy version 1 accepts 20 through 1,024 UTF-8 bytes, at least five whitespace-delimited words, no NUL, and no implicit normalization.
Set the profile floor to 65,536 KiB, three iterations, and one lane and the ceiling to 1,048,576 KiB, ten iterations, and sixteen lanes.
Construct `ValidatedArgon2idParameters` only through checked validation before allocation or integer conversion.
Calibration targets 750 to 1,500 ms, stays within both bounds, and never reduces the floor.
Check cancellation before calling Argon2id and after it returns but before returning or publishing a key.
Do not claim or simulate interruption inside one Argon2id library call.

- [ ] **Step 3: Write failing key-slot tests**

Cover generated phrase entropy and checksum, deterministic decoding, custom policy boundaries, recovery wrapping, wrong passphrase, modified salt, modified vault ID, modified algorithm identifier, independent derived subkeys, and offline-verifier disclosure text.
Test each KDF field at its minimum, maximum, maximum plus one, zero, and `u32::MAX` together with checked byte-count and platform allocation overflow.
Test cancellation before Argon2id and cancellation set after computation but before derived-key publication using an instrumented KDF seam.

- [ ] **Step 4: Implement key wrapping and derivation**

Derive metadata, snapshot-authentication, chunk-fingerprint, content-wrapping, and local-verification subkeys with distinct fixed HKDF labels.
Wrap the Vault Root Key with XChaCha20-Poly1305 using a random nonce and authenticated vault-header context.
Use the exact recovery-slot profile, nonce length, canonical AAD fields, tag length, and size limit from cryptographic profile 1.
Treat failure to generate the Vault Root Key, salt, slot ID, or nonce as a hard error with no returned bootstrap material.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-crypto`

Expected: generated recovery, custom policy, CSPRNG failure, secret compile-fail, KDF floors and ceilings, cancellation boundaries, wrapping, wrong-passphrase, and domain-separation tests pass.

Commit: `feat(crypto): add passphrase recovery and key hierarchy`

---

### Task 4: Implement and benchmark bounded streaming cryptography

**Files:**

- Create: `crates/notecrypt-crypto/src/stream.rs`
- Modify: `crates/notecrypt-crypto/src/lib.rs`
- Test: `crates/notecrypt-crypto/tests/stream_integrity.rs`
- Benchmark: `benches/src/crypto.rs`
- Create: `benches/baselines/chunk-size-v1.json`

**Interfaces:**

- Consumes: chunk-fingerprint and content-wrapping keys plus the fallible CSPRNG port from Task 3.
- Produces: independently authenticated per-chunk primitives that let the store enforce revocation between bounded chunks.

- [ ] **Step 1: Write failing streaming integrity tests**

Cover 0 bytes, 1 byte, every chunk boundary around 1 MiB, 2 MiB, and 4 MiB, a 64 MiB store-orchestrated smoke stream, modified chunks, wrong file identity, wrong object identity, wrong plaintext length, wrong sequence, CSPRNG failure, and cancellation between chunks.
Mark the 1 GiB and 10 GiB corpus tests ignored in ordinary package runs and execute them on dedicated performance workers in Task 21.
Format and store tests cover revision-manifest reordering, missing chunks, duplicated chunks, wrong revision, and wrong total length.

- [ ] **Step 2: Implement the bounded streaming API**

```rust
pub struct ChunkContext {
    pub vault_id: [u8; 16],
    pub file_id: [u8; 16],
    pub object_id: [u8; 32],
    pub format_version: u16,
    pub algorithm_id: u16,
    pub object_kind: u8,
    pub nonce_domain: [u8; 16],
    pub sequence: u64,
    pub plaintext_bytes: u32,
}

pub struct EncryptedChunkDescriptor {
    pub object_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub sequence: u64,
    pub plaintext_bytes: u32,
}

pub struct EncryptedChunk {
    pub descriptor: EncryptedChunkDescriptor,
    pub encoded: Vec<u8>,
}

pub fn fingerprint_chunk(
    plaintext: &[u8],
    context: &ChunkContext,
    fingerprint_key: &ChunkFingerprintKey,
) -> Result<[u8; 32], CryptoError>;

pub fn encrypt_chunk(
    plaintext: &[u8],
    context: &ChunkContext,
    wrapping_key: &ContentWrappingKey,
    random: &mut dyn SecureRandom,
) -> Result<EncryptedChunk, CryptoError>;

pub fn decrypt_chunk(
    encoded: &[u8],
    context: &ChunkContext,
    wrapping_key: &ContentWrappingKey,
) -> Result<Vec<u8>, CryptoError>;
```

These functions borrow key material for one bounded chunk call only and provide no whole-stream key-bearing API.
The store owns the reader loop, session-generation checks, descriptor reuse decision, and bounded buffers in Task 6.
Generate one fresh 16-byte content nonce domain for each newly encrypted file revision and combine it with the checked 64-bit chunk sequence.
Generate a fresh data key and 24-byte wrapping nonce for every newly encrypted chunk.
Use the exact content-chunk, chunk-key-wrapper, and same-position-fingerprint contexts from cryptographic profile 1.
Return keyed fingerprints only to the unlocked store pipeline so it can compare the prior descriptor at the same file position before choosing reuse or fresh encryption.
Reject plaintext above 4 MiB and keep at most two chunk buffers live per store pipeline.
Return no descriptor or encoded bytes after a CSPRNG, wrap, encryption, authentication, or length failure.

- [ ] **Step 3: Establish streaming baselines**

Measure 1 KiB, 1 MiB, and 100 MiB generated inputs for chunk-size selection.
Record throughput and peak resident memory without real paths or exact user sizes.
Select 1 MiB, 2 MiB, or 4 MiB only after the comparison and record the machine-readable evidence in `benches/baselines/chunk-size-v1.json`.
Task 5 consumes that evidence when it records the durable-format decision.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-crypto && cargo bench -p notecrypt-benches --bench crypto`

Expected: per-chunk integrity and CSPRNG-failure tests pass, store-orchestrated memory remains bounded, and the selected chunk size has recorded evidence.

Commit: `feat(crypto): add bounded streaming encryption`

---

### Task 5: Freeze the versioned bootstrap and encrypted object formats

**Files:**

- Create: `crates/notecrypt-format/src/error.rs`
- Create: `crates/notecrypt-format/src/limits.rs`
- Create: `crates/notecrypt-format/src/crypto_profile.rs`
- Create: `crates/notecrypt-format/src/header.rs`
- Create: `crates/notecrypt-format/src/object.rs`
- Create: `crates/notecrypt-format/src/manifest.rs`
- Create: `crates/notecrypt-format/src/snapshot.rs`
- Modify: `crates/notecrypt-format/src/lib.rs`
- Create: `crates/notecrypt-format/tests/golden.rs`
- Create: `crates/notecrypt-format/tests/malformed.rs`
- Create: `crates/notecrypt-format/tests/crypto_profile.rs`
- Create: `crates/notecrypt-format/tests/fixtures/v1/`
- Create: `docs/decisions/0002-encrypted-object-format.md`
- Create: `docs/decisions/0003-chunk-reuse-leakage.md`

**Interfaces:**

- Produces: canonical version-1 encoders, format-owned numeric cryptographic identifiers, and bounded decoders.
- Produces: stable fixture bytes for bootstrap, every cryptographic-profile kind, file manifest, logical tree, snapshot, authenticated head, and local-state records.

- [ ] **Step 1: Write failing canonical-format tests**

Assert byte-for-byte deterministic encoding, rejection of indefinite collections, duplicate fields, unknown critical fields, trailing bytes, unsupported major versions, oversized collections, and integer overflow.
Before fixtures freeze, cover every profile row with cross-kind, cross-vault, wrong-object, wrong-version, wrong-length, wrong-slot, modified-AAD, modified-MAC, truncated-tag, and unsupported-algorithm tests.

- [ ] **Step 2: Define explicit limits**

```rust
pub struct DecodeLimits {
    pub max_header_bytes: usize,
    pub max_object_bytes: u64,
    pub max_chunks_per_file: u32,
    pub max_tree_entries: u32,
    pub max_snapshot_parents: u8,
    pub max_name_bytes: u16,
    pub max_head_bytes: u32,
    pub max_manifest_bytes: u32,
    pub max_tree_bytes: u32,
    pub max_snapshot_bytes: u32,
    pub max_local_record_bytes: u32,
}

impl DecodeLimits {
    pub const PHASE_1: Self = Self {
        max_header_bytes: 1_048_576,
        max_object_bytes: 1_099_511_627_776,
        max_chunks_per_file: 1_048_576,
        max_tree_entries: 1_000_000,
        max_snapshot_parents: 2,
        max_name_bytes: 1_024,
        max_head_bytes: 65_536,
        max_manifest_bytes: 67_108_864,
        max_tree_bytes: 268_435_456,
        max_snapshot_bytes: 1_048_576,
        max_local_record_bytes: 65_536,
    };
}
```

Define `CryptoProfileId(0x0001)`, `AeadAlgorithmId(0x0001)`, `AuthenticationAlgorithmId(0x0002)`, `FingerprintAlgorithmId(0x0003)`, `KdfProfileId(0x0001)`, and `DerivationProfileId(0x0001)` in `notecrypt-format`.
Keep the numeric types private-field newtypes with checked decoders and no cryptographic implementation.

- [ ] **Step 3: Implement canonical `minicbor` schemas**

Use fixed-position arrays with explicit version and object-kind fields.
Reject non-canonical encodings before constructing domain objects.
Keep schema records separate from domain types and convert explicitly.
Encode all AAD and MAC inputs as canonical length-delimited arrays in the exact profile-1 field order from the design.
Encode each chunk envelope with its random object identity, nonce domain and sequence, wrapped random data key, plaintext length, ciphertext, and authentication tag.
Encode each encrypted revision manifest with ordered chunk identities, keyed plaintext fingerprints, per-chunk lengths, and total plaintext length.
Encode recovery slots, device slots, metadata, trees, manifests, snapshots, authenticated heads, chunk-key wrappers, content chunks, and local-state records with their exact profile identifiers, nonce lengths, tag lengths, and per-kind bounds.

- [ ] **Step 4: Add chunk-reuse security decision**

Record that phase 1 reuses unchanged fixed-size chunks within the same logical file so aligned or in-place edits avoid re-encrypting unchanged regions.
Record that insertion or deletion can shift subsequent boundaries and require re-encrypting the remainder of the file.
Record the leak of unchanged fixed-size regions across revisions, the absence of cross-file deduplication, and the rejected alternative of full-file re-encryption on every save.

- [ ] **Step 5: Generate and lock golden fixtures**

Generate each fixture once from deterministic test keys and non-sensitive canary text after the complete cross-context test matrix passes.
Check fixture hashes into the golden test and prohibit fixture replacement without an explicit format-version decision.

- [ ] **Step 6: Fuzz decoder entry points**

Add cargo-fuzz targets for header, object, manifest, tree, and snapshot decoding.
Set allocation and recursion limits before decoding attacker-controlled lengths.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-format`

Run from `crates/notecrypt-format`: `cargo fuzz run decode_object -- -max_total_time=60`

Expected: profile, cross-context, canonical, malformed, and golden tests pass and the bounded fuzz run finds no crash or unbounded allocation.

Commit: `feat(format): define versioned encrypted vault formats`

---

### Task 6: Build crash-consistent encrypted local storage

**Files:**

- Create: `crates/notecrypt-store/src/error.rs`
- Create: `crates/notecrypt-store/src/layout.rs`
- Create: `crates/notecrypt-store/src/repository.rs`
- Create: `crates/notecrypt-store/src/journal.rs`
- Create: `crates/notecrypt-store/src/transaction.rs`
- Create: `crates/notecrypt-store/src/recovery.rs`
- Create: `crates/notecrypt-store/src/trusted_state.rs`
- Create: `crates/notecrypt-store/src/cleanup.rs`
- Create: `crates/notecrypt-store/src/replication.rs`
- Create: `crates/notecrypt-store/src/stream.rs`
- Create: `crates/notecrypt-store/src/durability/mod.rs`
- Create: `crates/notecrypt-store/src/durability/unix.rs`
- Create: `crates/notecrypt-store/src/durability/windows.rs`
- Modify: `crates/notecrypt-store/src/lib.rs`
- Test: `crates/notecrypt-store/tests/transaction_faults.rs`
- Test: `crates/notecrypt-store/tests/rollback.rs`
- Test: `crates/notecrypt-store/tests/chunk_revocation.rs`
- Test: `crates/notecrypt-store/tests/cleanup_lifecycle.rs`
- Test: `crates/notecrypt-store/tests/replication_limits.rs`
- Benchmark: `benches/src/store.rs`

**Interfaces:**

- Consumes: core identities, format codecs, and crypto operations.
- Produces: `VaultRepository`, `VaultStore`, revocable local and replication capabilities, store-owned per-chunk orchestration, authenticated cleanup ownership, and an injectable durability seam.

- [ ] **Step 1: Write failing repository-layout tests**

Assert exact locations for `.notecrypt-vault`, sharded object IDs, `head`, transaction staging, journal, trusted local state, cleanup registry, replication quarantine, and the one canonical Notecrypt-owned workspace base.
Assert that no logical path is accepted as a repository path.
Assert that cleanup accepts only CSPRNG-generated 128-bit workspace identities, derives lowercase hexadecimal child names below the fixed base, and cannot store or follow an arbitrary path, symlink, junction, or reparse point.

- [ ] **Step 2: Implement layout and immutable object publication**

```rust
pub struct VaultStore {
    repository_root: std::path::PathBuf,
    local_state_root: std::path::PathBuf,
    durability: std::sync::Arc<dyn Durability>,
}

impl VaultStore {
    pub fn create(
        input: CreateVault,
        durability: std::sync::Arc<dyn Durability>,
    ) -> Result<Self, StoreError>;
    pub fn open(
        input: OpenVault,
        durability: std::sync::Arc<dyn Durability>,
    ) -> Result<Self, StoreError>;
    pub(crate) fn read_trusted_snapshot(
        &self,
        keys: &VaultKeys,
    ) -> Result<ReadSnapshot, StoreError>;
    pub(crate) fn begin_mutation(&self, base: SnapshotId) -> Result<Mutation, StoreError>;
    pub(crate) fn recover(&self, keys: &VaultKeys) -> Result<RecoveryReport, StoreError>;
}

pub trait VaultRepository: Send + Sync {
    fn cleanup_owned_workspace_base(&self) -> Result<PreUnlockCleanupReport, StoreError>;
    fn initialize(&self, request: InitializeRepository) -> Result<RepositorySnapshot, StoreError>;
    fn unlock(&self, request: UnlockRepository) -> Result<Box<dyn UnlockedVault>, StoreError>;
    fn list_device_slots(&self) -> Result<Vec<LocalDeviceSlotRecord>, StoreError>;
}

pub trait UnlockedVault: Send + Sync {
    fn acquire_lease(&self) -> Result<Box<dyn UnlockedVaultLease>, StoreError>;
    fn acquire_replication_lease(
        &self,
        limits: ReplicationLimits,
    ) -> Result<Box<dyn ReplicationLease>, StoreError>;
    fn begin_close(&self);
    fn close(self: Box<Self>) -> Result<(), StoreError>;
}

pub trait UnlockedVaultLease: Send {
    fn list(&self, request: ListRepositoryEntries) -> Result<Vec<RepositoryEntry>, StoreError>;
    fn apply(&self, request: RepositoryMutation) -> Result<RepositorySnapshot, StoreError>;
    fn export(&self, request: ExportRepositoryFile) -> Result<ExportedFile, StoreError>;
    fn commit_streamed_revision(
        &self,
        request: &StreamRevisionRequest,
        source: &mut dyn std::io::Read,
        publication_guard: &mut dyn PublicationGuard,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<RepositorySnapshot, StoreError>;
    fn reserve_workspace(&self) -> Result<CleanupWorkspaceId, StoreError>;
    fn register_workspace(&self, id: &CleanupWorkspaceId) -> Result<(), StoreError>;
    fn activate_workspace(&self, id: &CleanupWorkspaceId) -> Result<(), StoreError>;
    fn unregister_workspace(&self, id: &CleanupWorkspaceId) -> Result<(), StoreError>;
    fn enroll_device_slot(
        &self,
        input: EnrollLocalDeviceSlot,
    ) -> Result<LocalDeviceSlotRecord, StoreError>;
    fn disable_device_slot(&self, id: LocalDeviceSlotId) -> Result<LocalDeviceSlotRecord, StoreError>;
    fn delete_disabled_device_slot(&self, id: LocalDeviceSlotId) -> Result<(), StoreError>;
}

pub trait PublicationGuard: Send {
    fn validate(&mut self) -> Result<(), StoreError>;
}

pub trait ReplicationLease: Send {
    fn authenticate_bootstrap(&self, bytes: &[u8]) -> Result<AuthenticatedBootstrap, StoreError>;
    fn authenticate_head(&self, bytes: &[u8]) -> Result<AuthenticatedHead, StoreError>;
    fn contains_object(&self, id: &ObjectId) -> Result<bool, StoreError>;
    fn import_authenticated(
        &self,
        input: &mut dyn std::io::Read,
        declared_length: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<ImportedObjectMetadata, StoreError>;
    fn read_snapshot(&self, id: &ObjectId) -> Result<AuthenticatedSnapshotMetadata, StoreError>;
    fn read_tree(&self, id: &ObjectId) -> Result<AuthenticatedTreeMetadata, StoreError>;
    fn read_manifest(&self, id: &ObjectId) -> Result<AuthenticatedManifestMetadata, StoreError>;
    fn traverse_reachable(
        &self,
        head: &AuthenticatedHead,
        visitor: &mut dyn ReachableObjectVisitor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<ReachabilitySummary, StoreError>;
    fn export_encrypted(
        &self,
        id: &ObjectId,
        output: &mut dyn std::io::Write,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, StoreError>;
    fn commit_replicated_snapshot(
        &self,
        input: CommitReplicatedSnapshot,
    ) -> Result<RepositorySnapshot, StoreError>;
    fn record_trusted_remote(
        &self,
        observation: TrustedRemoteObservation,
    ) -> Result<(), StoreError>;
}

pub enum ReplicatedCommitMode {
    FastForward { expected_local: SnapshotId },
    Reconciled { local: SnapshotId, remote: SnapshotId },
}

pub struct CommitReplicatedSnapshot {
    pub mode: ReplicatedCommitMode,
    pub snapshot_object: ObjectId,
}

pub trait ReachableObjectVisitor: Send {
    fn visit(&mut self, object: &ReferencedObjectMetadata) -> Result<(), StoreError>;
}

pub struct ReplicationLimits {
    pub max_bootstrap_bytes: u64,
    pub max_head_bytes: u64,
    pub max_chunk_object_bytes: u64,
    pub max_manifest_object_bytes: u64,
    pub max_tree_object_bytes: u64,
    pub max_snapshot_object_bytes: u64,
    pub max_aggregate_bytes: u64,
    pub max_object_count: u64,
    pub max_graph_depth: u32,
    pub max_duration: std::time::Duration,
    pub progress_interval: std::time::Duration,
    pub max_quarantine_bytes: u64,
    pub free_space_reserve_bytes: u64,
}

pub struct LocalDeviceSlotId([u8; 16]);
pub struct CleanupWorkspaceId([u8; 16]);

impl LocalDeviceSlotId {
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
}

impl CleanupWorkspaceId {
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
}

pub struct LocalDeviceSlotRecord {
    pub version: u16,
    pub id: LocalDeviceSlotId,
    pub provider: String,
    pub provider_reference: Vec<u8>,
    pub wrapped_root_key: Vec<u8>,
    pub authentication_tag: [u8; 32],
    pub state: DeviceSlotState,
}

pub enum DeviceSlotState {
    Active,
    DisabledPendingProviderRemoval,
}

pub struct EnrollLocalDeviceSlot {
    pub id: LocalDeviceSlotId,
    pub provider: String,
    pub provider_reference: Vec<u8>,
    pub wrapping_key: notecrypt_crypto::DeviceWrappingKey,
}

pub trait Durability: Send + Sync {
    fn sync_file(&self, file: &std::fs::File) -> Result<(), StoreError>;
    fn sync_directory(&self, path: &std::path::Path) -> Result<(), StoreError>;
    fn replace_atomic(
        &self,
        source: &std::path::Path,
        destination: &std::path::Path,
    ) -> Result<(), StoreError>;
    fn capabilities(&self) -> DurabilityCapabilities;
}
```

Store key material in one revocable key cell owned by the unlocked capability.
Local and replication leases reference that cell and never copy root or derived keys into lease-owned storage.
The store loop checks the session generation, acquires a key guard for one bounded chunk, fingerprints the candidate, drops the guard, compares the same-position previous descriptor, reacquires only the needed keys for fresh encryption, drops the guard, and checks the generation again before accepting the chunk.
No raw key borrow survives between chunks, and no chunk completed across a generation change may enter a manifest or published revision.
`commit_streamed_revision` calls `PublicationGuard::validate` after every staged object authenticates and immediately before it writes the journal that can advance the head.
Every key-required replication operation is available only through the object-safe `ReplicationLease`.
Keep all raw `VaultStore` helpers crate-private.
`enroll_device_slot` performs root-key wrapping, local-record authentication, and atomic persistence inside the store because only that capability may access both the root key and supplied device-wrapping key.
`begin_close` rejects new leases and makes existing leases fail with `StoreError::Locked` at the next chunk or transaction boundary.
`close` zeroizes the central cell even if cancelled worker objects have not yet dropped.
Set `ReplicationLimits::PHASE_1` to 1 MiB bootstrap, 64 KiB head, 4 MiB plus 4 KiB chunk object, 64 MiB manifest, 256 MiB tree, 1 MiB snapshot, 1 TiB aggregate, 10,000,000 objects, 100,000 graph edges, 30 minutes total, 30 seconds progress interval, the smaller of 1 TiB and 80 percent of starting free space for quarantine, and a 1 GiB free-space reserve.
Apply the strictest store profile, backend capability, and available-space limit for each operation.
On cancellation, lock, timeout, stalled progress, authentication failure, or any budget failure, remove that operation's quarantine tree before returning.
Workspace lifecycle is reserve, authenticated register, adapter creation and permission verification, authenticated activate, plaintext use, adapter removal and absence verification, then authenticated unregister.
At startup `cleanup_owned_workspace_base` enumerates only direct random-ID children below the fixed canonical Notecrypt-owned base without following links and exposes no unlock until safe cleanup finishes successfully.
Failure presents a blocking retry-or-exit warning and cannot be acknowledged into an unlocked session.

- [ ] **Step 3: Write a failure test for every transaction boundary**

Inject failure before and after staging write, staged-file flush, staged verification, immutable publication, journal write, head replacement, directory flush, trusted-state update, and completion marker.
Assert that recovery yields either the old complete snapshot or the new complete snapshot.
Add deterministic lock-during-encryption tests before a chunk, inside the instrumented chunk primitive, after a chunk, before manifest creation, and in the publication guard.
Assert that generation changes prevent any affected descriptor, manifest, snapshot, or head from publication and that the central key cell is zeroized after close.

- [ ] **Step 4: Implement transaction commit and recovery**

Implement the ten-step transaction order from the design specification.
Implement Unix and macOS durability with file and directory synchronization plus same-filesystem rename.
Implement Windows durability with explicit file flush and replace semantics behind `windows-sys`.
Expose capability differences and fail vault initialization if the required head-replacement guarantee is unavailable.
Use a deterministic fake to inject every crash-test failure point.
Never overwrite an immutable object with different bytes.
Translate every format-owned numeric cryptographic identifier into the matching typed crypto context explicitly and reject unknown or cross-kind identifiers before invoking cryptography.
Implement same-position fingerprint comparison inside the store so the crypto crate never chooses reuse and the service never receives a fingerprint.

- [ ] **Step 5: Implement rollback detection**

Persist the last trusted local and observed remote snapshot identities outside the repository.
Authenticate trusted-head, migration, cleanup, and device-slot local records with the derived `LocalVerificationKey` and a record-type domain label.
After passphrase unlock, derive the key and verify all existing trusted records before applying rollback decisions.
During device unlock, unwrap the root key with the OS-protected key first, derive the local-verification key, and then verify the complete slot record and trusted state before exposing an unlocked capability.
Treat records returned by locked `list_device_slots` as untrusted candidates and use their provider references only to attempt authenticated root-key unwrap.
Treat local-record authentication failure as `StoreError::LocalStateAuthenticationFailed`, refuse device-slot use, and require passphrase recovery plus explicit local-state repair.
Return `StoreError::RollbackDetected` before modifying state when a presented head is behind or excludes the trusted snapshot.
Authenticate registered and active cleanup states plus trusted remote observations with distinct profile-1 local-verification labels.
Record a trusted remote observation atomically only after the replication lease has authenticated the head and traversed the complete reachable graph within budget.

Exercise infinite inventory, trickle reads, every oversized object kind, excessive object count, excessive graph depth, aggregate-byte exhaustion, timeout, disk-budget exhaustion, cancellation, and lock.
Assert typed referenced-object metadata for successful imports and complete quarantine removal for every failure.
Exercise startup base enumeration, reserve/register/activate/remove/unregister failures, stale records, symlinks, junctions, reparse points, and attempts to register arbitrary paths.

- [ ] **Step 6: Benchmark transaction overhead**

Measure object publication separately from cryptography for 1 KiB, 1 MiB, 100 MiB, 10,000 tiny objects, cold cache, and warm cache.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-store --test transaction_faults --test rollback --test chunk_revocation --test cleanup_lifecycle --test replication_limits && cargo bench -p notecrypt-benches --bench store`

Expected: all fault points recover to a valid authenticated head, revoked chunks never publish, replication budgets clean quarantine, and cleanup remains confined to the fixed base.

Commit: `feat(store): add crash-consistent encrypted object storage`

---

### Task 7: Define and prove the portable backend contract

**Files:**

- Create: `crates/notecrypt-backend/src/error.rs`
- Create: `crates/notecrypt-backend/src/types.rs`
- Create: `crates/notecrypt-backend/src/bootstrap.rs`
- Create: `crates/notecrypt-backend/src/backend.rs`
- Create: `crates/notecrypt-backend/src/conformance.rs`
- Modify: `crates/notecrypt-backend/src/lib.rs`
- Test: `crates/notecrypt-backend/tests/memory_backend.rs`
- Create: `docs/decisions/0004-backend-contract.md`

**Interfaces:**

- Produces: a synchronous backend SPI with bounded immutable bootstrap operations suitable for blocking worker execution.
- Produces: a conformance suite reusable by Git and future adapters.

- [ ] **Step 1: Write a failing conformance suite against an in-memory backend**

Test missing bootstrap, bounded read, create-if-absent, idempotent exact match, oversized bootstrap, replay from another vault, conflicting existing bytes, malformed bytes, stale profile, bootstrap transfer and independent readback, idempotent staged objects, paginated inventory, missing object behavior, atomic publication success, stale expected-head rejection, readback, batch limits, abort, cancellation, unreachable leftovers, and injected transient errors.

- [ ] **Step 2: Implement the exact backend contract**

```rust
pub struct OpaqueObjectId([u8; 32]);
pub struct BootstrapBytes(Vec<u8>);
pub struct HeadValue(Vec<u8>);
pub struct HeadVersion(Vec<u8>);

pub struct ObservedHead {
    pub version: HeadVersion,
    pub value: HeadValue,
}

pub enum CreateBootstrapOutcome {
    Created,
    AlreadyMatching,
}

impl OpaqueObjectId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32];
}

impl BootstrapBytes {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BackendTypeError>;
    pub fn as_bytes(&self) -> &[u8];
}

impl HeadValue {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BackendTypeError>;
    pub fn as_bytes(&self) -> &[u8];
}

impl HeadVersion {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BackendTypeError>;
    pub fn as_bytes(&self) -> &[u8];
}

pub enum PublishOutcome {
    Committed { observed: ObservedHead },
    Stale { observed: Option<ObservedHead> },
    Indeterminate,
}

pub struct BackendCapabilities {
    pub conditional_head: bool,
    pub max_bootstrap_bytes: u64,
    pub max_object_bytes: u64,
    pub max_inventory_page: usize,
    pub max_batch_items: usize,
    pub safe_concurrency: usize,
}

pub trait BackendPublication: Send {
    fn stage_object(
        &mut self,
        id: &OpaqueObjectId,
        reader: &mut dyn std::io::Read,
        length: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<StageOutcome, BackendError>;
    fn commit(
        self: Box<Self>,
        replacement: &HeadValue,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<PublishOutcome, BackendError>;
    fn abort(self: Box<Self>) -> Result<(), BackendError>;
}

pub trait VaultBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    fn read_bootstrap(
        &self,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<BootstrapBytes>, BackendError>;
    fn create_bootstrap_if_absent(
        &self,
        bootstrap: &BootstrapBytes,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<CreateBootstrapOutcome, BackendError>;
    fn read_head(
        &self,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<ObservedHead>, BackendError>;
    fn list_objects(
        &self,
        cursor: Option<&InventoryCursor>,
        limit: usize,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<InventoryPage, BackendError>;
    fn fetch_object(
        &self,
        id: &OpaqueObjectId,
        writer: &mut dyn std::io::Write,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(), BackendError>;
    fn begin_publication(
        &self,
        expected: Option<&HeadVersion>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Box<dyn BackendPublication>, BackendError>;
}
```

Limit `BootstrapBytes` to 1 MiB at construction and preserve it as opaque transport bytes until the store validates its canonical format, profile, vault ID, and recovery-slot binding.
Limit `HeadValue` to 64 KiB and `HeadVersion` to 1 KiB at construction.
Treat both as opaque transport bytes until replication asks the store to authenticate the head value.
`create_bootstrap_if_absent` returns `AlreadyMatching` only for byte-identical existing content and returns a permanent conflict without replacement for any mismatch.
`BackendPublication::commit` must make every staged object readable with the replacement head or leave the prior head unchanged.
A stale expected version leaves the prior head unchanged but may leave unreachable immutable objects.
Git stages objects and tree state in its local object database and publishes them only through the final fast-forward push.
Object-store adapters may upload immutable objects during staging and conditionally replace their head during commit.
`PublishOutcome::Indeterminate` means the backend cannot tell whether the remote accepted the publication, so callers must reread the head before retrying.
Backend atomicity covers staged encrypted bytes and the opaque head only.
The replication layer must authenticate the bootstrap and prove the complete reachable graph before recording success.

- [ ] **Step 3: Add capabilities and safe error categories**

Represent conditional-head support, maximum bootstrap and object sizes, inventory page size, batch size, and safe concurrency.
Classify errors as authentication, authorization, unavailable, rate-limited, corrupt response, unsupported, stale head, cancelled, and permanent.

- [ ] **Step 4: Record the contract decision**

Explain why the backend SPI is the sole dedicated contracts crate, why immutable typed bootstrap operations belong beside opaque head and object transport, why backend atomicity does not replace graph authentication, why it contains no Git types, and why a backend without conditional replacement requires explicit single-writer mode.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-backend`

Expected: the in-memory adapter passes immutable bootstrap, atomic publication, bounded transport, cancellation, and readback conformance.

Commit: `feat(backend): define portable encrypted object contract`

---

### Task 8: Implement the operation runtime and priority controls

**Files:**

- Create: `crates/notecrypt-service/src/command.rs`
- Create: `crates/notecrypt-service/src/error.rs`
- Create: `crates/notecrypt-service/src/event.rs`
- Create: `crates/notecrypt-service/src/operation.rs`
- Create: `crates/notecrypt-service/src/service.rs`
- Modify: `crates/notecrypt-service/src/lib.rs`
- Test: `crates/notecrypt-service/tests/responsiveness.rs`

**Interfaces:**

- Produces: runtime-neutral `ServiceHandle`, `OperationHandle`, commands, typed results, events, bounded ordinary work, and non-rejectable priority control delivery.

- [ ] **Step 1: Write failing service responsiveness tests**

Use a blocking fake store and assert that `submit` returns in under 10 ms, progress appears within 100 ms, and cancellation is observed at the next safe boundary.

- [ ] **Step 2: Define command, event, and operation types**

```rust
pub enum Command {
    BeginInitialize(BeginInitializeVault),
    ConfirmInitialize(ConfirmInitializeVault),
    CancelInitialize(CancelInitializeVault),
    Unlock(UnlockVault),
    List(ListEntries),
    CreateFile(CreateFile),
    CreateDirectory(CreateDirectory),
    ImportFile(ImportFile),
    ExportFile(ExportFile),
    EditFile(EditFile),
    RenameEntry(RenameEntry),
    MoveEntry(MoveEntry),
    DeleteEntry(DeleteEntry),
    OpenVault(OpenWholeVault),
    Sync(SyncVault),
    Backup(BackupVault),
}

pub struct OperationId([u8; 16]);
pub struct ServiceHandle;
pub struct OperationHandle;

pub enum OperationResult {
    InitializationPending(InitializationPending),
    Initialized(VaultSummary),
    Unlocked(SessionSummary),
    Entries(Vec<EntrySummary>),
    EntryChanged(EntrySummary),
    Exported(ExportSummary),
    WorkspaceOpened(WorkspaceSummary),
    Synchronized(SyncSummary),
    BackedUp(BackupSummary),
}

pub enum Control {
    LockNow,
    DeadlineExpired,
    Suspend,
    Cancel(OperationId),
    UserActivity,
}

impl ServiceHandle {
    pub fn submit(&self, command: Command) -> Result<OperationHandle, ServiceError>;
    pub fn control(&self, control: Control) -> Result<(), ServiceError>;
    pub fn snapshot(&self) -> ServiceSnapshot;
}

impl OperationHandle {
    pub fn id(&self) -> OperationId;
    pub fn try_next_event(&self) -> Result<Option<OperationEvent>, ServiceError>;
    pub fn cancel(&self);
    pub fn try_result(&self) -> Result<Option<OperationResult>, ServiceError>;
}
```

- [ ] **Step 3: Implement bounded worker execution**

Use bounded `crossbeam-channel` queues and named worker threads.
Reject commands with `ServiceError::Busy` when queue policy cannot safely coalesce them.
Coalesce progress events but never terminal, warning, conflict, or durability events.
Create a separate unbounded control channel for lock, deadline, suspend, cancellation, and trusted activity.
Process all pending control messages before taking another ordinary command.
`ServiceHandle::control` may return `ServiceError::Closed` after shutdown but must never return `ServiceError::Busy`.
Store cancellation in `Arc<AtomicBool>` and set it directly before enqueueing the control notification.
`Control::LockNow`, deadline, and suspend atomically stop new key leases and broadcast cancellation to every active operation before enqueueing cleanup work.
Workers check cancellation between bounded chunks and transaction phases, while the lock coordinator waits only for the configured final-save grace before revoking remaining leases and continuing cleanup.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-service --test responsiveness`

Expected: submission, progress, cancellation, queue saturation, and priority control tests pass without arbitrary sleeps.

Commit: `feat(service): add operation runtime and priority controls`

---

### Task 9: Implement unlock sessions and consumer-owned host ports

**Files:**

- Create: `crates/notecrypt-service/src/ports.rs`
- Create: `crates/notecrypt-service/src/session.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Modify: `crates/notecrypt-service/src/lib.rs`
- Test: `crates/notecrypt-service/tests/lock_deadline.rs`

**Interfaces:**

- Consumes: an injected `Arc<dyn VaultRepository>` that returns an opaque `UnlockedVault` capability.
- Produces: session policies, scoped capability ownership, and every consumer-owned host-port DTO and trait.

- [ ] **Step 1: Define every service-owned host port before implementing adapters**

```rust
pub struct WorkspaceId([u8; 16]);

impl WorkspaceId {
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
}

pub enum WorkspaceMode {
    Targeted,
    WholeVault,
}

pub struct WorkspaceLease {
    pub id: WorkspaceId,
    pub root: std::path::PathBuf,
    pub mode: WorkspaceMode,
}

pub struct TargetWorkspaceRequest {
    pub id: WorkspaceId,
    pub vault_id: VaultId,
    pub repository_root: std::path::PathBuf,
}

pub struct VaultWorkspaceRequest {
    pub id: WorkspaceId,
    pub vault_id: VaultId,
    pub repository_root: std::path::PathBuf,
}

pub struct WorkspaceEvent {
    pub generation: u64,
    pub change: WorkspaceChange,
}

pub enum WorkspaceChange {
    Created { path: std::path::PathBuf },
    Modified { path: std::path::PathBuf },
    Renamed {
        source: std::path::PathBuf,
        destination: std::path::PathBuf,
    },
    Deleted { path: std::path::PathBuf },
}

pub struct MaterializationTarget {
    pub staging_path: std::path::PathBuf,
    pub destination: std::path::PathBuf,
    pub suppression: SuppressionToken,
}

pub struct PublishedGeneration {
    pub path: std::path::PathBuf,
    pub generation: u64,
    pub suppression: SuppressionToken,
}

pub struct SuppressionToken([u8; 16]);
pub struct StableSourceToken(Vec<u8>);
pub struct LogicalWorkspacePath(std::path::PathBuf);

impl SuppressionToken {
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
}

impl LogicalWorkspacePath {
    pub fn new(path: std::path::PathBuf) -> Result<Self, HostPortError>;
    pub fn as_path(&self) -> &std::path::Path;
}

impl StableSourceToken {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, HostPortError>;
    pub fn as_bytes(&self) -> &[u8];
}

pub struct EditorLaunchRequest {
    pub executable: std::ffi::OsString,
    pub arguments: Vec<std::ffi::OsString>,
    pub workspace_file: std::path::PathBuf,
}

pub struct EditorExit {
    pub code: Option<i32>,
}

pub struct DeviceKeyReference(Vec<u8>);
pub struct DeviceUnlockSecret(notecrypt_crypto::DeviceWrappingKey);

impl DeviceKeyReference {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, HostPortError>;
    pub fn as_bytes(&self) -> &[u8];
}

impl DeviceUnlockSecret {
    pub fn from_random_bytes(bytes: [u8; 32]) -> Self;
}

pub struct EnrolledDeviceKey {
    pub reference: DeviceKeyReference,
    pub wrapping_key: DeviceUnlockSecret,
}

pub enum HostPortError {
    Unavailable,
    Denied,
    InvalidInput,
    DetachedEditor,
    Permission,
    CleanupFailed,
    PlatformFailure,
}

pub trait WorkspaceProvider: Send + Sync {
    fn create_target(&self, request: TargetWorkspaceRequest) -> Result<WorkspaceLease, HostPortError>;
    fn create_whole_vault(&self, request: VaultWorkspaceRequest) -> Result<WorkspaceLease, HostPortError>;
    fn materialization_target(
        &self,
        lease: &WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
    ) -> Result<MaterializationTarget, HostPortError>;
    fn publish_materialized(
        &self,
        lease: &WorkspaceLease,
        target: MaterializationTarget,
    ) -> Result<PublishedGeneration, HostPortError>;
    fn arm_published_path(
        &self,
        lease: &WorkspaceLease,
        published: PublishedGeneration,
    ) -> Result<(), HostPortError>;
    fn watch(&self, lease: &WorkspaceLease) -> Result<Box<dyn WorkspaceWatch>, HostPortError>;
    fn open_stable_source(
        &self,
        lease: &WorkspaceLease,
        relative_path: &LogicalWorkspacePath,
        expected_generation: u64,
    ) -> Result<Box<dyn StableSource>, HostPortError>;
    fn validate_stable_source(
        &self,
        lease: &WorkspaceLease,
        token: &StableSourceToken,
    ) -> Result<(), HostPortError>;
    fn remove_workspace(&self, lease: &WorkspaceLease) -> Result<(), HostPortError>;
    fn workspace_absent(&self, id: &WorkspaceId) -> Result<bool, HostPortError>;
}

pub trait WorkspaceWatch: Send {
    fn next_event(&mut self, timeout: std::time::Duration) -> Result<Option<WorkspaceEvent>, HostPortError>;
}

pub trait StableSource: std::io::Read + Send {
    fn token(&self) -> &StableSourceToken;
}

pub trait EditorSupervisor: Send + Sync {
    fn launch(&self, request: EditorLaunchRequest) -> Result<Box<dyn EditorProcess>, HostPortError>;
}

pub trait EditorProcess: Send {
    fn try_wait(&mut self) -> Result<Option<EditorExit>, HostPortError>;
    fn request_stop(&mut self) -> Result<(), HostPortError>;
    fn force_stop(&mut self) -> Result<(), HostPortError>;
}

pub trait DeviceUnlockProvider: Send + Sync {
    fn enroll(&self, vault: VaultId) -> Result<EnrolledDeviceKey, HostPortError>;
    fn unlock(&self, reference: &DeviceKeyReference) -> Result<DeviceUnlockSecret, HostPortError>;
    fn remove(&self, reference: &DeviceKeyReference) -> Result<(), HostPortError>;
}
```

Define every request, result, identifier, and `HostPortError` in `notecrypt-service::ports`.
Validate `LogicalWorkspacePath` against absolute paths, traversal, empty components, reserved names, and platform normalization collisions before an adapter receives it.
Limit `StableSourceToken` to 256 opaque bytes, forbid formatting and serialization, and let only the workspace adapter create or validate its identity and generation evidence.
Stream saved bytes only from `StableSource` and never reopen the path after the handle is acquired.
The service wraps `validate_stable_source` in the store's `PublicationGuard` so validation occurs after staged authentication and immediately before journal publication.
Create workspaces only for a store-reserved `WorkspaceId` below the fixed canonical Notecrypt-owned base.
The provider never accepts a caller-supplied base or cleanup path and never enumerates cleanup candidates itself.
Make `DeviceUnlockSecret` non-cloneable and non-formatting, and do not expose `secrecy` or raw key bytes through the port.
Give the service an internal consuming conversion from `DeviceUnlockSecret` to the store's `DeviceWrappingKey` input without exposing bytes to a UI or loggable DTO.
Permit the service crate's otherwise narrow dependency on `notecrypt-crypto` only for this opaque secret container, and enforce with dependency tests that no service command, result, event, or UI-facing port exposes it.
Provide fake implementations for service tests and an unavailable device-unlock implementation for Checkpoint A.

- [ ] **Step 2: Write failing unlock and lock tests**

Cover wrong passphrase, KDF cancellation before start and after computation before publication, saturated ordinary queue, pre-unlock fixed-base cleanup failure, inactivity timeout, absolute deadline, explicit lock, system suspend notification, coalesced trusted TUI activity, cleanup failure, and a pending durable save.
Assert that lock and deadline controls cannot be rejected or starved by ordinary work.

- [ ] **Step 3: Implement session state**

```rust
pub struct SessionPolicy {
    pub inactivity_timeout: std::time::Duration,
    pub absolute_timeout: std::time::Duration,
    pub warning_offsets: Vec<std::time::Duration>,
    pub final_save_grace: std::time::Duration,
}

pub enum SessionState {
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    CleanupRequired,
}
```

Use monotonic time.
Mutating commands and coalesced `Control::UserActivity` from local TUI input reset inactivity.
Sync traffic, watcher noise, and progress events do not reset inactivity.
Hold the opaque `Box<dyn UnlockedVault>` capability inside the service session.
Workers receive only `Box<dyn UnlockedVaultLease>` values for bounded operations.
Replication workers receive only `Box<dyn ReplicationLease>` with profile-1 limits reduced by backend and available-space capabilities.
Call `begin_close` when lock begins so new leases fail, close the capability after active leases reach a safe boundary or the final-save grace expires, and rely on capability drop to erase store-owned key material.
Run `VaultRepository::cleanup_owned_workspace_base` before entering `Unlocking` and expose no unlocked session while that cleanup is incomplete.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-service`

Expected: responsiveness and deadline tests pass without sleeping on arbitrary timing assumptions.

Commit: `feat(service): add unlock sessions and host ports`

---

### Task 10: Implement initialization, unlock, and authenticated reads

**Files:**

- Create: `crates/notecrypt-service/src/local_use_cases.rs`
- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/event.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Modify: `crates/notecrypt-store/src/repository.rs`
- Create: `crates/notecrypt-service/tests/local_use_cases.rs`
- Create: `crates/notecrypt-service/tests/recovery_initialization.rs`

**Interfaces:**

- Consumes: `Arc<dyn VaultRepository>` plus fake host ports.
- Produces: generated and custom recovery initialization state machines, in-process unlock, status, list, priority lock control, and reopen behavior before any CLI or TUI adaptation.

- [ ] **Step 1: Write failing command-to-result contract tests**

Submit begin-initialize, confirmation, cancellation, unlock, status, list, lock control, and reopen through `ServiceHandle` against a temporary `VaultStore`.
Assert the exact `OperationResult`, event sequence, error category, session-state transition, and repository-head transition for each command.
Prove that generated mode emits one non-cloneable one-time 12-word phrase, requires exact confirmation, and publishes no bootstrap, slot, snapshot, trusted state, or head before confirmation.
Prove that custom mode requires policy version 1, exposes the offline-verifier warning, requires explicit risk acceptance and a second matching secret, and publishes nothing on rejection, mismatch, cancellation, or CSPRNG failure.

- [ ] **Step 2: Implement initialization and reopen**

Make generated recovery the default and keep the pending phrase only in zeroizing process memory until exact confirmation or cancellation.
Create the cryptographic-profile-1 bootstrap header, recovery key slot, empty logical tree, first authenticated parentless snapshot, local trusted state, and cleanup registry only after confirmation.
Disclose that the public bootstrap permits offline credential verification and that Argon2 only slows guesses.
Use strictly validated Argon2id profile-1 parameters and return no initialization result if cancellation arrives after Argon2 but before key or state publication.
On reopen, validate the bootstrap and trusted head before accepting a passphrase.

- [ ] **Step 3: Implement unlocked read use cases**

Implement list and status through authenticated cached metadata scoped to the unlock session.
Return immutable `EntrySummary` values and never expose store or crypto types to UI consumers.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-service --test local_use_cases --test recovery_initialization`

Expected: generated and custom recovery initialization, no-publication cancellation, passphrase unlock, authenticated browsing, priority lock, and reopen pass through the service facade.

Commit: `feat(service): add initialization and authenticated reads`

---

### Task 11: Implement local mutations, export, and durable reopen

**Files:**

- Modify: `crates/notecrypt-service/src/local_use_cases.rs`
- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/event.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Modify: `crates/notecrypt-store/src/repository.rs`
- Modify: `crates/notecrypt-store/src/transaction.rs`
- Create: `crates/notecrypt-service/tests/local_mutations.rs`
- Create: `tests/notecrypt-e2e/tests/local_facade.rs`

**Interfaces:**

- Consumes: the authenticated `UnlockedVault` capability and local read use cases.
- Produces: typed create, create-directory, import, export, rename, move, delete, and durable reopen behavior.

- [ ] **Step 1: Implement local mutation use cases**

Implement create file, create directory, import, rename, move, and delete through one `RepositoryMutation` per user command.
Validate all logical names before staging and emit `RevisionDurable` only after the store transaction advances the local head.

- [ ] **Step 2: Implement export, lock, and reopen verification**

Export only to an explicit path outside the encrypted repository and refuse collisions unless overwrite was explicitly confirmed in the command.
Lock through the priority control path, erase the session cache, reopen, and verify every prior operation from durable encrypted state.

- [ ] **Step 3: Prove the local facade contains no plaintext leakage**

Use unique canaries for file contents, logical names, extensions, and directory names.
Scan repository paths and bytes after every mutation and after reopen.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-service --test local_mutations && cargo test -p notecrypt-e2e --test local_facade`

Expected: every local command is proven before presentation adapters exist and no plaintext canary enters the repository.

Commit: `feat(service): add local mutations and durable reopen`

---

### Task 12: Implement secure workspace supervision and targeted editing

**Files:**

- Create: `adapters/notecrypt-editor-workspace/src/error.rs`
- Create: `adapters/notecrypt-editor-workspace/src/editor.rs`
- Create: `adapters/notecrypt-editor-workspace/src/permissions.rs`
- Create: `adapters/notecrypt-editor-workspace/src/workspace.rs`
- Modify: `adapters/notecrypt-editor-workspace/src/lib.rs`
- Create: `tests/notecrypt-e2e/src/test_editor.rs`
- Test: `adapters/notecrypt-editor-workspace/tests/editor_profiles.rs`
- Test: `adapters/notecrypt-editor-workspace/tests/workspace_boundary.rs`

**Interfaces:**

- Consumes: service-owned `WorkspaceProvider`, `EditorSupervisor`, and their request and result DTOs.
- Produces: secure workspace and editor-supervision adapters without creating adapter-owned contract types.

- [ ] **Step 1: Write failing workspace-boundary tests**

Assert that workspaces are direct random-ID children of the fixed canonical Notecrypt-owned base, paths are outside the repository, permissions are restrictive, random names reveal no logical filename, authenticated register and activate precede plaintext creation, materialized files publish atomically with suppression generations, arming establishes a baseline, and indexing exclusions are attempted without claiming guarantees.
Reject arbitrary bases and paths, nested cleanup targets, preexisting children, symlinks, junctions, reparse points, and workspace IDs not reserved by the store capability.

- [ ] **Step 2: Implement the service-owned workspace ports**

Implement `WorkspaceProvider` and `WorkspaceWatch` from `notecrypt-service` without redefining their types in the adapter.
Consume a store-reserved ID, let the store authenticate registered state, create only the derived fixed-base child, verify restrictive permissions, let the store activate the record, and write no plaintext before activation.
On cleanup remove without following links, verify absence through the provider, and let the store unregister only after that proof.
Keep enumeration and cleanup-record authentication in the store, not the adapter.
Implement staged materialization, atomic publication, suppression-token correlation, and explicit path arming before exposing the adapter to whole-vault orchestration.
Return `HostPortError` categories without leaking operating-system paths into default diagnostics.

- [ ] **Step 3: Write failing editor-supervision tests**

Create `tests/notecrypt-e2e/src/test_editor.rs` with selectable blocking, unsaved-delay, normal-exit, ignore-termination, and detached behaviors.
Use that executable from adapter and process-level tests.
Assert that strict mode rejects detachment and lock terminates the supervised process tree after grace.

- [ ] **Step 4: Implement editor profiles and supervision**

Resolve explicit `editor.command` first and `$VISUAL` then `$EDITOR` when unset.
Provide blocking profiles for Vim, Neovim, Nano, Emacs client, Visual Studio Code, Zed, Windows Notepad, and Notepad++.
When no editor is configured, use `vi` on macOS and Linux and Notepad on Windows after verifying the executable can be launched in blocking mode.
Pass the path as a direct process argument and never through a shell.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-editor-workspace --test editor_profiles --test workspace_boundary`

Expected: fixed-base workspace ownership, reserve/register/activate/remove/unregister ordering, editor profiles, strict supervision, and process termination pass on the current platform.

Commit: `feat(editor): add secure workspace and editor supervision`

---

### Task 13: Implement stable watching and targeted edit orchestration

**Files:**

- Create: `adapters/notecrypt-editor-workspace/src/watcher.rs`
- Modify: `adapters/notecrypt-editor-workspace/src/lib.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Test: `adapters/notecrypt-editor-workspace/tests/save_patterns.rs`
- Test: `tests/notecrypt-e2e/tests/local_vault.rs`
- Benchmark: `benches/src/targeted_edit.rs`

**Interfaces:**

- Consumes: the service-owned `WorkspaceWatch` port, complete local use cases, editor supervision, and store transactions.
- Produces: stable saved-revision events and the complete targeted edit workflow.

- [ ] **Step 1: Write failing watcher save-pattern tests**

Cover in-place write, truncate-and-rewrite, temporary-file rename, rapid repeated saves, a write during encryption, deletion, and stale source generation.
Assert one active pipeline per path and eventual publication of the newest stable bytes.
Cover rename after handle acquisition, same-path replacement, symlink substitution, Windows junction or reparse substitution, stale handle identity, lock before a chunk, lock during an instrumented chunk, lock after a chunk, and lock in the final publication guard.
Assert that only the exact bytes read from the stable handle can publish and that every identity or session-generation race discards staged ciphertext without advancing the head.

- [ ] **Step 2: Implement per-path debounce and stable-source validation**

Start with a 100 ms quiet interval within the approved 75 to 150 ms calibration range.
Ask the adapter for an opaque `StableSource` and `StableSourceToken` at the expected workspace generation, then stream only from that handle.
Pass a service wrapper around `WorkspaceProvider::validate_stable_source` as the store `PublicationGuard` so adapter-side identity and generation validation runs after staged authentication and immediately before journal publication.
Let the store acquire and release key guards per bounded chunk, compare same-position fingerprints before descriptor reuse, and verify the same session generation before and after every chunk.
Discard superseded temporary ciphertext without advancing the head.

- [ ] **Step 3: Complete the targeted edit vertical path**

Wire service command, selected revision decryption, editor launch, save events, transactional encryption, final save, cleanup, and lock.
Emit `SaveDetected`, `Encrypting`, `RevisionDurable`, `CleanupRequired`, and terminal events.
Use the authenticated store cleanup lifecycle and do not let the workspace adapter register or deregister itself.

- [ ] **Step 4: Benchmark targeted edit**

Measure fixed overhead and throughput separately.
Enforce p95 below 200 ms to request editor launch for a 1 MiB file after unlock and p95 below 350 ms from final event to durable ciphertext for a 1 MiB save.
Verify sustained streaming throughput of at least 150 MiB per second and bounded memory for 10 GiB.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-editor-workspace --test save_patterns && cargo test -p notecrypt-store --test chunk_revocation && cargo test -p notecrypt-service && cargo test -p notecrypt-e2e --test local_vault`

Expected: all editor, stable-handle, replacement, watcher, chunk-revocation, lock, publication-guard, and plaintext-boundary tests pass.

Commit: `feat(editor): add responsive targeted editing workflow`

---

### Task 14: Implement the CLI adapter and machine-readable contract

**Files:**

- Create: `apps/notecrypt-cli/src/args.rs`
- Create: `apps/notecrypt-cli/src/config.rs`
- Create: `apps/notecrypt-cli/src/commands.rs`
- Create: `apps/notecrypt-cli/src/output.rs`
- Create: `apps/notecrypt-cli/src/password.rs`
- Modify: `apps/notecrypt-cli/src/main.rs`
- Test: `apps/notecrypt-cli/tests/cli.rs`
- Test: `tests/notecrypt-e2e/tests/cli_journey.rs`

**Interfaces:**

- Consumes: `notecrypt-service` plus composition-root adapter constructors.
- Produces: one-shot `notecrypt init`, `create`, `list`, `edit`, `status`, `import`, `export`, `rm`, `mv`, and `mkdir` commands with complete recovery-credential initialization.
- Produces: CLI JSON envelope version 1.

- [ ] **Step 1: Write failing CLI contract tests**

Test `--vault-root`, `NOTECRYPT_VAULT_ROOT`, precedence, protected passphrase prompt, refusal of passphrase command arguments, stable exit codes, human output, and JSON fixtures.
Test that interactive `init` defaults to a generated 12-word recovery phrase, shows it once, discloses offline verification, requires exact confirmation, and leaves the target empty on mismatch, cancellation, output failure, confirmation failure, or CSPRNG failure.
Test that custom recovery requires `--custom-recovery-passphrase`, policy version 1, the offline-guessing warning, explicit risk acceptance, and two protected matching entries.
Test that non-interactive generated recovery requires an explicit owner-only recovery-output file descriptor plus a separate confirmation-input descriptor and never places the phrase in arguments, normal stdout, logs, JSON, or error text.
Test that non-interactive custom recovery additionally requires `--accept-offline-guessing-risk`, two distinct protected input descriptors, and exact policy-compliant matching bytes.
Test that no standalone `unlock` or `lock` subcommand is exposed in phase 1.
Test `create` as the explicit empty-file creation command and reject collisions unless replacement is explicitly requested.
For Checkpoint A, accept an empty non-Git directory or reopen an existing local Notecrypt vault.
Reject Git-backed onboarding until the validated Git adapter in Task 18 is available, and always reject embedding into a repository containing unrelated files or history.

- [ ] **Step 2: Implement CLI composition and configuration**

```rust
#[derive(clap::Parser)]
pub struct Cli {
    #[arg(long, env = "NOTECRYPT_VAULT_ROOT")]
    pub vault_root: Option<std::path::PathBuf>,
    #[arg(long, value_enum, default_value = "human")]
    pub output: OutputMode,
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(serde::Serialize)]
pub struct JsonEnvelope<T> {
    pub version: u16,
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<JsonError>,
}
```

Read passphrases from a protected terminal prompt or explicit file descriptor, never a positional or option value.
Keep recovery output and confirmation descriptors separate from `--output json`, reject terminals and reused descriptors in non-interactive mode, cap each secret input at 1,024 bytes, and zeroize buffers after submission.

- [ ] **Step 3: Adapt every proven local service use case**

Map each CLI subcommand to one typed service command and typed result.
Drive generated initialization through begin, one-time display or protected output, exact secret confirmation, and terminal initialization result.
Drive custom initialization only after rendering or returning the stable offline-risk warning and collecting explicit acknowledgement plus matching protected input.
For every protected command, construct the process-local service, prompt for the recovery passphrase, unlock, perform the requested operation, call `ServiceHandle::control(Control::LockNow)`, and await cleanup before exit.
Keep persistent unlock and immediate lock actions inside the TUI process.
Do not claim cross-process session control until a separately specified authenticated IPC owner exists.
Map stable error categories to documented exit codes and JSON errors.
Do not parse human output internally.

- [ ] **Step 4: Add a process-level CLI journey**

Spawn the built binary to initialize through generated interactive and generated non-interactive confirmation paths, assert failure leaves an empty target, and exercise the explicit custom path with its warning and matching inputs.
Then run one-shot create, import, edit through the blocking test editor, list, export, and delete invocations using protected test input for each protected command.
Verify every process locks and completes workspace cleanup before exit, then reopen through a new process.
Verify exit codes, JSON fixtures, durable bytes, and absence of plaintext canaries.

- [ ] **Step 5: Enforce CLI startup performance**

Measure `notecrypt --help` and locked `notecrypt status` in a release build.
Enforce p95 below 75 ms without unlock or repository scan.

- [ ] **Step 6: Verify and commit**

Run: `cargo test -p notecrypt-cli && cargo test -p notecrypt-e2e --test cli_journey`

Expected: generated and custom recovery initialization plus every local use case work through the built CLI without secret leakage and JSON fixtures remain stable.

Commit: `feat(cli): expose complete local vault commands`

---

### Task 15: Deliver the runnable TUI local-vault checkpoint

**Files:**

- Create: `ui/notecrypt-tui/src/app.rs`
- Create: `ui/notecrypt-tui/src/event_loop.rs`
- Create: `ui/notecrypt-tui/src/keymap.rs`
- Create: `ui/notecrypt-tui/src/view_model.rs`
- Create: `ui/notecrypt-tui/src/widgets.rs`
- Create: `ui/notecrypt-tui/src/dialogs.rs`
- Modify: `ui/notecrypt-tui/src/lib.rs`
- Modify: `apps/notecrypt-cli/src/args.rs`
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Modify: `README.md`
- Test: `ui/notecrypt-tui/tests/render.rs`
- Test: `ui/notecrypt-tui/tests/responsiveness.rs`
- Test: `tests/notecrypt-e2e/tests/tui_journey.rs`
- Benchmark: `benches/src/tui_latency.rs`

**Interfaces:**

- Consumes: only service commands, typed results, events, snapshots, and the priority control path.
- Produces: the `notecrypt tui` presentation and the first user-testable checkpoint.

- [ ] **Step 1: Write failing TUI render and navigation tests**

Use `ratatui::backend::TestBackend` to snapshot initialization mode selection, one-time generated recovery display, phrase confirmation, custom offline-risk warning, custom confirmation, locked, unlocking, tree, activity, warning, and cleanup-required screens at 80x24, 120x40, and the minimum supported size.
Test keyboard-only navigation, clear focus, secret-input masking, and zeroization of the passphrase input buffer after submission.
Test that navigation cannot dismiss or bypass required recovery confirmation and that cancellation publishes no vault state.

- [ ] **Step 2: Implement the view model and event loop**

Poll terminal input and service events without blocking.
Render the status header, virtualized tree, details and activity pane, hint bar, unlock dialog, create dialog, confirmation dialog, and progress state.
Coalesce progress to the terminal refresh rate and preserve warning and terminal events.
Send coalesced `Control::UserActivity` for trusted local keyboard and navigation input.

- [ ] **Step 3: Adapt all local user flows**

Wire generated initialization as the default through one-time display and exact masked confirmation.
Place custom recovery behind a separate action that renders the offline-verifier and Argon2 warning, requires explicit acknowledgement, enforces policy version 1, and confirms the secret before service submission.
Wire unlock, browse, create, import, edit, rename, move, delete, export, and status to service commands.
Wire the TUI lock action directly to `ServiceHandle::control(Control::LockNow)`.
Show dirty, encrypting, durable, and cleanup-required states distinctly.
Add a Checkpoint A quick start to `README.md` with only user-facing installation, setup, generated-recovery initialization, one-shot CLI examples, and the persistent TUI unlock, edit, lock, and reopen flow.
Keep security rationale, architecture, compromise recovery detail, and release evidence under `docs/`.

- [ ] **Step 4: Enforce responsiveness budgets**

Measure input-to-render p50, p95, and p99 while fake 10 GiB encryption and blocking Git operations run on workers.
Enforce p95 below 50 ms and idle CPU below 1 percent.

- [ ] **Step 5: Run real CLI and pseudo-terminal TUI journeys**

Drive the built CLI through initialize and one-shot protected operations, with each invocation unlocking and locking internally.
Drive pseudo-terminal TUI journeys through generated initialization, the explicit custom warning path, cancellation before confirmation, unlock, create, edit, lock, reopen, and content verification.
Assert the same durable result through both adapters.

- [ ] **Step 6: Verify and commit**

Run: `cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test cli_journey --test tui_journey --test local_vault`

Expected: both built user interfaces complete generated and custom recovery Checkpoint A journeys, cancelled initialization publishes nothing, and the TUI meets its response budget.

Commit: `feat(tui): deliver runnable local encrypted vault`

---

### Task 16: Add whole-vault sessions and autosave

**Files:**

- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/session.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Modify: `adapters/notecrypt-editor-workspace/src/workspace.rs`
- Modify: `adapters/notecrypt-editor-workspace/src/watcher.rs`
- Modify: `apps/notecrypt-cli/src/args.rs`
- Modify: `apps/notecrypt-cli/src/config.rs`
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Modify: `ui/notecrypt-tui/src/app.rs`
- Modify: `ui/notecrypt-tui/src/keymap.rs`
- Modify: `ui/notecrypt-tui/src/view_model.rs`
- Modify: `ui/notecrypt-tui/src/dialogs.rs`
- Test: `tests/notecrypt-e2e/tests/whole_vault.rs`
- Test: `adapters/notecrypt-editor-workspace/tests/path_safety.rs`

**Interfaces:**

- Consumes: store transactions and workspace leases.
- Produces: `OpenWholeVault`, progressive materialization, autosave, tombstones, bounded locking, startup cleanup, and complete CLI and TUI whole-vault presentation.

- [ ] **Step 1: Write failing progressive-materialization tests**

Test metadata-first traversal, small-file priority, bounded worker count, progress, cancellation, no zero-byte placeholders, cleanup of a partially materialized workspace, suppression of Notecrypt-created events, and a genuine edit racing with later materialization.
Drive the built CLI `vault open --for` path and pseudo-terminal TUI open dialog through progress, edits, cancellation, deadline lock, cleanup success, cleanup failure, and reopen.

- [ ] **Step 2: Implement bounded whole-vault materialization**

Use two file workers by default and measure two, three, and four before changing the default.
Create directories only after path validation.
Decrypt each file into staging outside the watched tree, atomically publish it with a suppression generation, establish its baseline, and arm that path only after publication.
Treat any later generation as a genuine user edit while other files continue materializing.

- [ ] **Step 3: Write failing path and filesystem-object tests**

Cover traversal, absolute paths, symlinks, hard links, sockets, FIFOs, device files, Windows reserved names, case collisions, Unicode collisions, alternate data streams, and sparse files.

- [ ] **Step 4: Implement safe autosave transitions**

Map create, modify, rename, move, and delete into core tree transitions and store transactions.
Reject unsupported filesystem objects.
Reject sparse files by default and report logical expansion before an explicit materializing import.

- [ ] **Step 5: Implement strict lock and cleanup recovery**

Warn at configured offsets, stop new changes, process the latest stable saved state within the grace interval, terminate supervised editors, remove plaintext, and erase session keys.
Use reserve, authenticated register, create, authenticated activate, remove, absence verification, and authenticated unregister ordering.
On the next process start, enumerate only the fixed canonical application-owned base without following links and complete or block on cleanup before exposing unlock.
Show a critical CLI exit and persistent TUI dialog for cleanup failure without displaying arbitrary paths by default.

- [ ] **Step 6: Complete CLI and TUI whole-vault integration**

Add duration, concurrency, sparse-materialization acknowledgement, and cleanup-warning options to CLI parsing and configuration.
Wire the TUI action, keymap, view model, progress, cancellation, deadline warnings, cleanup warning, and retry dialog directly to the same service types.
Add built-process and pseudo-terminal assertions for lock during materialization and save encryption, startup cleanup failure, and successful cleanup retry.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-editor-workspace --test path_safety && cargo test -p notecrypt-service --test lock_deadline && cargo test -p notecrypt-cli && cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test whole_vault --test cli_journey --test tui_journey`

Expected: CLI and TUI whole-vault journeys survive reopen, lock and cleanup warnings remain honest, and unsupported objects fail without publication.

Commit: `feat(vault): add bounded whole-vault autosave sessions`

---

### Task 17: Implement authenticated replication and conflict preservation

**Files:**

- Create: `crates/notecrypt-replication/src/error.rs`
- Create: `crates/notecrypt-replication/src/limits.rs`
- Create: `crates/notecrypt-replication/src/plan.rs`
- Create: `crates/notecrypt-replication/src/reconcile.rs`
- Create: `crates/notecrypt-replication/src/sync.rs`
- Create: `crates/notecrypt-replication/src/migration.rs`
- Create: `crates/notecrypt-replication/src/compromise_rekey.rs`
- Modify: `crates/notecrypt-replication/src/lib.rs`
- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Modify: `apps/notecrypt-cli/src/args.rs`
- Modify: `apps/notecrypt-cli/src/config.rs`
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Modify: `ui/notecrypt-tui/src/app.rs`
- Modify: `ui/notecrypt-tui/src/keymap.rs`
- Modify: `ui/notecrypt-tui/src/view_model.rs`
- Modify: `ui/notecrypt-tui/src/dialogs.rs`
- Test: `crates/notecrypt-replication/tests/sync_matrix.rs`
- Test: `crates/notecrypt-replication/tests/migration.rs`
- Test: `crates/notecrypt-replication/tests/limits.rs`
- Create: `tests/notecrypt-e2e/tests/presentation_journey.rs`
- Test: `tests/notecrypt-e2e/tests/recovery_journey.rs`

**Interfaces:**

- Consumes: `VaultBackend`, bounded immutable bootstrap operations, an object-safe revocable `ReplicationLease`, and deterministic core reconciliation.
- Produces: budgeted authenticated fetch, reconciliation, conditional publish, retry, `BackendCopy`, and history-free `CompromiseRekey`.
- Produces: explicit byte-preserving conversion between core `ObjectId` and backend `OpaqueObjectId` without exposing either private field.

- [ ] **Step 1: Write failing synchronization-matrix tests**

Cover missing, oversized, replayed, conflicting, malformed, and stale bootstrap; empty remote; equal heads; local ahead; remote ahead; independent edits; same-file edits; rename conflict; delete-versus-modify; missing object; corrupt object; stale conditional head; bounded retry; rollback; cancellation; and unavailable backend.
Use adversarial backends for infinite inventory, trickle pages and object streams, every oversized object kind, excessive object count, excessive graph depth, aggregate-byte exhaustion, 30-minute timeout through fake time, 30-second progress starvation, disk-budget exhaustion, and lock revocation.
Assert that each failure cleans quarantine, leaves trusted local and remote observations unchanged, and cannot advance either head.

- [ ] **Step 2: Implement a side-effect-free sync plan**

```rust
pub enum SyncAction {
    EnsureBootstrap,
    NoChange,
    Fetch { objects: Vec<OpaqueObjectId> },
    FastForwardLocal { remote: SnapshotId },
    PublishLocal { expected: Option<HeadVersion> },
    Reconcile { base: SnapshotId, local: SnapshotId, remote: SnapshotId },
}

pub fn plan_sync(input: &SyncInput) -> Result<Vec<SyncAction>, ReplicationError>;

pub fn to_backend_object_id(id: &ObjectId) -> OpaqueObjectId;
pub fn to_core_object_id(id: &OpaqueObjectId) -> ObjectId;
```

Test the plan independently from I/O.

- [ ] **Step 3: Implement fetch, authenticate, and publish ordering**

Fetch into quarantine, authenticate through the store, and move verified immutable objects into the repository.
Never advance a local or remote head before all reachable objects authenticate.
Read and validate the bounded immutable bootstrap before any head, create it only when absent during publication, reject mismatched existing bytes, and independently read back the exact bootstrap before success.
Perform bounded existence checks, authenticated imports returning typed referenced-object metadata, authenticated snapshot, tree, and manifest reads, reachable traversal, encrypted export, replicated snapshot commits, and trusted-remote recording only through the object-safe revocable lease supplied by the active service session.
Use the strictest profile-1, backend-advertised, and available-space limit for every object kind, aggregate bytes, object count, graph depth, timeout, progress interval, and quarantine disk.
Treat `StoreError::Locked` as cancellation and never retain a raw `VaultStore` handle in replication state.
Begin a backend publication with the observed head version, stream missing immutable objects through bounded `stage_object` calls, and commit the authenticated replacement head.
Treat a stale publication result as a refetch and reconciliation retry.
Treat an indeterminate publication result by rereading the remote head and authenticating it before deciding whether the attempted replacement committed or needs reconciliation.
Verify the bootstrap, published head, and complete reachable graph through independent readback before atomically recording the trusted remote observation or sync success.
Remove quarantine on cancellation, lock, timeout, stalled trickle input, authentication failure, or any limit failure.

- [ ] **Step 4: Implement conflict preservation**

Use the core deterministic result to commit a two-parent snapshot.
Emit conflict events containing unlocked logical details only to the active local session.
Expose typed conflict inspection and explicit keep-local, keep-remote, keep-both, rename, and tombstone-aware resolution requests without merging file bytes.

- [ ] **Step 5: Implement `BackendCopy` and `CompromiseRekey`**

Define `BackendCopy` as migration of the same vault ID, Vault Root Key, bootstrap, authenticated graph, and history to a separately configured backend.
Persist source head, target backend identity, verified object cursor, bootstrap state, and target head state outside the vault repository.
Transfer and independently read back the immutable bootstrap, authenticate and copy every reachable encrypted object, publish the same head conditionally, and switch the active backend only after the target graph verifies.
Define `CompromiseRekey` as creation of a new vault ID, Vault Root Key, generated or explicitly confirmed custom recovery credential, file and revision identities, object identities, bootstrap, and parentless current-state snapshot in an empty target backend.
Stream current authenticated plaintext through bounded decrypt and fresh encryption without copying any old wrapper, object, snapshot parent, Git commit, or backend history.
Reject non-empty targets and state explicitly that already exposed ciphertext and keys cannot be made confidential again.
Never route suspected compromise to `BackendCopy` or recovery-slot rewrapping.

- [ ] **Step 6: Complete sync, conflict, copy, and rekey presentation**

Add CLI parsing, configuration, typed output, and warning acknowledgements for `sync`, conflict list, conflict inspect, conflict resolve, `vault backend-copy`, and `vault compromise-rekey`.
Add TUI actions, keymap entries, view-model states, progress, conflict inspector and resolver dialogs, rollback warnings, indeterminate-publication warnings, backend-copy confirmation, and compromise-rekey exposure warning plus recovery-phrase confirmation.
Drive built-process CLI and pseudo-terminal TUI journeys through rollback warning, conflict display and resolution, lock during sync and rekey, backend-copy bootstrap readback failure, empty-target enforcement, and a parentless history-free rekey result.

- [ ] **Step 7: Verify Checkpoint B and commit**

Run: `cargo test -p notecrypt-core && cargo test -p notecrypt-replication --test sync_matrix --test migration --test limits && cargo test -p notecrypt-cli && cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test recovery_journey --test presentation_journey`

Expected: bounded sync preserves all authenticated content, limits clean quarantine, conflicts are inspectable and resolvable through CLI and TUI, backend copy preserves history, compromise rekey creates a new history-free vault, and no stale head is overwritten.

Commit: `feat(sync): add authenticated replication and conflicts`

---

### Task 18: Implement the Git backend, onboarding hooks, and verified backup

**Files:**

- Create: `adapters/notecrypt-backend-git/src/error.rs`
- Create: `adapters/notecrypt-backend-git/src/runner.rs`
- Create: `adapters/notecrypt-backend-git/src/repository.rs`
- Create: `adapters/notecrypt-backend-git/src/backend.rs`
- Create: `adapters/notecrypt-backend-git/src/hooks.rs`
- Create: `adapters/notecrypt-backend-git/src/quarantine.rs`
- Create: `adapters/notecrypt-backend-git/src/verify.rs`
- Modify: `adapters/notecrypt-backend-git/src/lib.rs`
- Modify: `apps/notecrypt-cli/src/args.rs`
- Modify: `apps/notecrypt-cli/src/config.rs`
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Modify: `ui/notecrypt-tui/src/app.rs`
- Modify: `ui/notecrypt-tui/src/keymap.rs`
- Modify: `ui/notecrypt-tui/src/view_model.rs`
- Modify: `ui/notecrypt-tui/src/dialogs.rs`
- Test: `adapters/notecrypt-backend-git/tests/conformance.rs`
- Test: `adapters/notecrypt-backend-git/tests/hardening.rs`
- Test: `adapters/notecrypt-backend-git/tests/history_verification.rs`
- Test: `tests/notecrypt-e2e/tests/git_sync.rs`
- Test: `tests/notecrypt-e2e/tests/plaintext_canary.rs`

**Interfaces:**

- Produces: `GitBackend` implementing the complete backend conformance suite.
- Produces: fully parsed and presented `notecrypt vault onboard`, `notecrypt sync`, and `notecrypt vault backup` CLI and TUI journeys with verified bootstrap, history, and graph readback.

- [ ] **Step 1: Write failing Git runner security tests**

Use a fake executable to capture argument boundaries.
Test spaces, leading dashes, Unicode, malicious remote names, ref injection, shell metacharacters, hostile Git output, non-repository paths, unexpected worktree layout, hostile hooks, `include` and `includeIf`, aliases, filters, submodules, pagers, custom SSH commands, external remote helpers, inherited `GIT_*` variables, replace objects, repository alternates, and local `file` transport without the separate local capability.
Test repository marker, canonical absolute Git directory, worktree relationship, dedicated branch, remote, protocol, and configuration validation on every operation.
Test that an unrelated existing branch, worktree, path, mode, commit, or history cannot enter the dedicated Notecrypt branch.

- [ ] **Step 2: Implement direct Git execution**

```rust
pub trait GitRunner: Send + Sync {
    fn run(
        &self,
        request: GitRequest,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<GitOutput, GitError>;
}

pub struct GitRequest {
    pub repository: std::path::PathBuf,
    pub arguments: Vec<std::ffi::OsString>,
    pub operation: GitOperation,
}
```

Invoke `git` directly with argument arrays.
Use this one runner policy for onboarding, fetch, sync, backup, `BackendCopy`, and recovery.
Use exact built-in subcommands, validated remote and branch names, literal pathspec handling, bounded output capture, cancellation, and a sanitized environment.
Remove every inherited `GIT_*` variable, then set only Notecrypt-controlled `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `GIT_TERMINAL_PROMPT`, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_GLOBAL`, and `GIT_PAGER` values.
For every invocation set `core.hooksPath` to an empty trusted Notecrypt-owned directory, disable pagers and replace objects, use `push --no-verify` for internal publication, bypass system and global configuration, and reject local includes or any key outside the documented allowlist.
Reject aliases, filters, submodules, custom SSH commands, repository alternates, unknown remote-helper schemes, `ext`, and local `file` transport unless the caller holds the separate local or test capability.
Allow only explicitly configured HTTPS or SSH remotes for normal operations and set protocol policy to deny everything else.
Never execute Git aliases, hooks, external helpers, pagers, filters, or a shell.
Before every operation validate the repository marker, canonical absolute Git directory, worktree relationship, dedicated branch, configured remote, selected transport, and complete allowed local configuration.

- [ ] **Step 3: Implement Git backend conformance**

Implement onboarding for a local encrypted vault that is not yet a Git repository and recovery into a clean dedicated clone.
Create or read the bounded immutable bootstrap first, reject any mismatch, and require independent bootstrap readback for onboarding, backup, `BackendCopy`, and clean-device recovery.
Create and validate one dedicated branch with no unrelated files or history, and reject embedding in a general-purpose repository.
Implement `begin_publication` as an isolated local Git publication state rooted at the observed dedicated-branch commit and addressed through a private temporary ref.
Implement `stage_object` with `git hash-object -w --no-filters` and retain the resulting object-to-path mapping only in that publication state.
On commit, construct validated trees with `git mktree`, create one commit with `git commit-tree`, update only the private temporary ref, and push that ref with `--no-verify` to the remote dedicated branch with normal fast-forward protection.
Treat `ls-remote` as ref discovery only.
Fetch the exact discovered candidate into an isolated quarantine repository with no alternates before advancing visible state.
Validate every newly introduced commit, tree, path, mode, and blob from the last trusted commit through the candidate, or the full ancestry when no trusted commit exists, including intermediate ancestry whose tip is clean.
Accept only the repository marker, byte-identical immutable bootstrap, authenticated head, allowed encrypted object paths, and regular-file or directory modes.
Reject unexpected paths, executable modes, symlinks, submodules, transient plaintext commits, malformed or unauthenticated vault blobs, missing blobs, corrupt objects, replacement references, and an incomplete reachable graph.
Ask replication to authenticate the bootstrap, head, and complete reachable Notecrypt graph through its bounded revocable lease, then record the trusted remote observation atomically.
Advance the visible local tracking ref only after isolated fetch, history validation, and complete graph authentication succeed.
If push might have succeeded but its response or verification read is unavailable, return `PublishOutcome::Indeterminate` without retrying or moving visible local state.
On abort or cancellation, discard publication state while allowing unreachable local Git objects to remain for Git maintenance.
Repository attributes, content filters, hooks, pagers, includes, replace objects, SSH overrides, and external helpers cannot alter or execute during Notecrypt publication.
Use a fixed `Notecrypt <notecrypt@local.invalid>` author and committer identity plus a constant non-sensitive commit-message prefix.
Fetch and authenticate before publish, create the commit based on the verified remote branch, use a normal fast-forward push, and treat rejection as a stale-head result.

- [ ] **Step 4: Add managed onboarding hooks**

Install a versioned pre-commit hook that invokes `notecrypt vault validate --staged`.
The validator rejects unexpected paths, registered plaintext workspaces, known plaintext canaries, malformed bootstrap data, and unauthenticated layout changes.
Document that `--no-verify` bypasses hooks and that the core security boundary remains encryption before repository writes.

- [ ] **Step 5: Implement verified backup**

Validate the repository, construct a Git tree from only allowed encrypted paths through the plumbing path, create a commit when changes exist, and push when a remote exists.
When no remote exists, stop after the local commit and report that state explicitly.
Read back the immutable bootstrap and discover the remote ref after push, fetch the exact candidate into isolated quarantine, verify every newly introduced history object, authenticate the complete reachable graph, and compare the verified commit with the attempted identity.
Return indeterminate rather than success on bootstrap, candidate fetch, history, graph, or trusted-observation readback failure.

- [ ] **Step 6: Run two-device and canary tests**

Create two local clones and a bare remote.
Exercise independent changes, same-file conflicts, push races, remote deletion, malformed remote objects, missing blobs, corrupt objects, a clean tip with an unsafe intermediate commit, false committed outcomes, false `ls-remote` readback, bootstrap mismatch, backup readback failure, and clean-device recovery.
Scan every Git commit, path, blob, log line, and process argument for unique plaintext canaries and logical names.

- [ ] **Step 7: Complete Git CLI and TUI integration**

Add onboarding remote, dedicated branch, transport, prompt policy, sync retry, and backup configuration to CLI parsing and typed JSON output.
Wire TUI onboarding, sync, and backup actions through the app, keymap, view model, progress pane, and dialogs.
Show rollback, conflict, stale-head retry, no-remote backup, indeterminate publication, and verification failure states without claiming success.
Drive built-process CLI and pseudo-terminal TUI journeys through onboarding, sync, backup, conflict display, rollback warning, indeterminate warning, and backup readback failure.

- [ ] **Step 8: Verify and commit**

Run: `cargo test -p notecrypt-backend-git --test conformance --test hardening --test history_verification && cargo test -p notecrypt-cli && cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test git_sync --test plaintext_canary --test presentation_journey --test recovery_journey`

Expected: Git passes bootstrap and backend conformance, hostile process state cannot execute, complete candidate history and graph verification reject every adversarial case, CLI and TUI warnings remain honest, two-device tests preserve conflicts, and canary scans find no plaintext.

Commit: `feat(git): add verified synchronization and backup`

---

### Task 19: Add native device unlock without weakening recovery security

**Files:**

- Create: `adapters/notecrypt-device-unlock/src/error.rs`
- Create: `adapters/notecrypt-device-unlock/src/native.rs`
- Modify: `adapters/notecrypt-device-unlock/src/lib.rs`
- Modify: `crates/notecrypt-service/src/session.rs`
- Modify: `crates/notecrypt-store/src/repository.rs`
- Modify: `crates/notecrypt-store/src/trusted_state.rs`
- Modify: `apps/notecrypt-cli/src/args.rs`
- Modify: `apps/notecrypt-cli/src/config.rs`
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Modify: `apps/notecrypt-cli/src/output.rs`
- Modify: `ui/notecrypt-tui/src/app.rs`
- Modify: `ui/notecrypt-tui/src/keymap.rs`
- Modify: `ui/notecrypt-tui/src/view_model.rs`
- Modify: `ui/notecrypt-tui/src/dialogs.rs`
- Test: `adapters/notecrypt-device-unlock/tests/keyring.rs`
- Test: `crates/notecrypt-service/tests/device_unlock.rs`
- Test: `tests/notecrypt-e2e/tests/presentation_journey.rs`
- Test: `tests/notecrypt-e2e/tests/recovery_journey.rs`

**Interfaces:**

- Consumes: the service-owned `DeviceUnlockProvider` port and `DeviceUnlockSecret` result type defined in Task 9.
- Produces: a platform-native port implementation.
- Produces: device-slot enrollment, unlock, recoverable removal, passphrase fallback, and the final complete CLI and TUI presentation gate.

- [ ] **Step 1: Write failing device-slot tests**

Cover enrollment after recovery unlock, native approval, denial, missing item, locked keyring, corrupt wrapped slot, local-slot transaction failure, native cleanup after failed enrollment, removal, native removal failure, disabled-slot recovery, and passphrase fallback.
Test device-binding behavior only on a provider that explicitly advertises a verifiable device-binding capability.

- [ ] **Step 2: Implement device-local slot persistence and orchestration**

Use the existing service-owned port to generate and store a random device-wrapping key in the native credential store.
Consume the returned `DeviceUnlockSecret` into an `EnrollLocalDeviceSlot` request and invoke `UnlockedVaultLease::enroll_device_slot`.
The store capability wraps the current Vault Root Key, authenticates the record, and persists the wrapped bytes plus non-secret provider reference as a versioned `LocalDeviceSlotRecord` in trusted local state.
Commit the local record before reporting enrollment success and remove both sides with recoverable ordering during removal.
If store enrollment fails after native key creation, remove the unused native item and report any residue.
For removal, first call `disable_device_slot` to atomically authenticate and persist disabled state, then remove the native item, then call `delete_disabled_device_slot`.
If native removal fails, keep the local record disabled, report cleanup required, and never use it for unlock.
Never store the recovery passphrase.

- [ ] **Step 3: Implement native credential storage**

Use the `keyring` crate's native store on macOS, Windows, and Linux.
Treat unavailable or insecurely configured desktop stores as unsupported and require the passphrase.
Do not implement a standalone low-entropy PIN verifier.

- [ ] **Step 4: Add CLI and TUI enrollment flows**

Require an unlocked recovery session before enrollment.
Explain that recovery still requires the passphrase on another device.
Expose removal and list only device-local slot metadata.
Add CLI parsing, configuration, JSON output, and explicit commands for device list, enroll, and remove.
Wire TUI app actions, keymap, view-model states, native approval progress, denial, fallback, disabled residue, and removal confirmation or failure dialogs.

- [ ] **Step 5: Run the complete presentation-integration gate**

Drive built-process CLI and pseudo-terminal TUI journeys through generated and custom initialization, whole-vault open, lock during operations, cleanup failure, onboarding, sync, rollback warning, conflict display and resolution, backup, backup readback failure, indeterminate publication, `BackendCopy`, `CompromiseRekey`, device enrollment, device denial, removal failure, passphrase fallback, and clean-device recovery.
Assert every parser option reaches one typed service command, every terminal result maps to stable CLI and TUI state, and no action requires manual encrypted-object manipulation.
Assert the recovery phrase appears only in its one-time protected initialization surface and no warning is downgraded to success.

- [ ] **Step 6: Verify Checkpoint C and commit**

Run: `cargo test -p notecrypt-device-unlock --test keyring && cargo test -p notecrypt-service --test device_unlock && cargo test -p notecrypt-cli && cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test git_sync --test presentation_journey --test recovery_journey`

Expected: supported stores unlock locally, denial and removal failures fall back safely, all Task 16 through 19 journeys are complete in both user surfaces, and clean-device recovery remains recovery-phrase based.

Commit: `feat(unlock): add native device-bound vault access`

---

### Task 20: Harden crash, parser, plaintext, and cross-platform behavior

**Files:**

- Create: `tests/notecrypt-e2e/tests/crash_recovery.rs`
- Modify: fuzz targets under `crates/notecrypt-format/fuzz/`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/security/threat-model.md`
- Create: `docs/security/recovery.md`
- Create: `docs/decisions/0001-rust-core-and-ui.md`
- Modify: `tests/notecrypt-e2e/tests/presentation_journey.rs`
- Modify: `tests/notecrypt-e2e/tests/recovery_journey.rs`

**Interfaces:**

- Produces: documented guarantees and limitations backed by automated evidence.
- Produces: full macOS, Linux, and Windows release checks.

- [ ] **Step 1: Add adversarial end-to-end tests**

Inject process termination at every transaction phase, full disk, short write, permission loss, interrupted cleanup, malformed remote object, rollback, Git cancellation, replication limit failure, quarantine cleanup failure, stable-source replacement, lock during encryption, and system suspend notification.
Assert no trusted head references missing or unauthenticated data.

- [ ] **Step 2: Add plaintext-canary coverage to all observability surfaces**

Scan repository paths, object bytes, Git history, logs, structured diagnostics, error text, process arguments, cleanup registry, and benchmark output.
Fail the test on content, logical name, extension, vault label, or exact sensitive size.

- [ ] **Step 3: Add dependency and unsafe-code gates**

Run `cargo deny check`, `cargo audit`, and a workspace scan for `unsafe` blocks.
Require a written safety invariant and focused test for every accepted `unsafe` block.
Fail CI on unreviewed new runtime dependencies.

- [ ] **Step 4: Add platform behavior tests**

Exercise APFS and FSEvents behavior on macOS, inotify and watch limits on Linux, and NTFS rename, sharing, reserved-name, and antivirus-interference paths on Windows.
Run x86-64 and ARM64 where the CI provider supports dedicated workers.

- [ ] **Step 5: Write security and recovery documentation**

Copy the approved threat boundaries, rollback limitation, fixed-base cleanup limitation, generated recovery phrase flow, custom-passphrase policy, offline-verifier disclosure, exact KDF bounds and cancellation honesty, Git bootstrap and history verification, and new-device recovery warning into focused user documentation.
Explain that same-root-key rewrapping is credential maintenance rather than revocation because prior wrappers remain in public history.
Define `BackendCopy` as same-vault graph and history migration and `CompromiseRekey` as a new vault with all-new keys and identities plus a parentless current-state snapshot.
Warn that compromise rekey copies no prior object or history and cannot restore confidentiality to already exposed ciphertext, keys, or plaintext.
Do not claim resistance to a compromised unlocked endpoint.
Keep `README.md` limited to user-facing installation, setup, and usage and put all security, architecture, recovery detail, and release evidence under `docs/`.

- [ ] **Step 6: Record the architecture decision**

Explain the Rust-only phase 1, separated core and TUI, in-process service contract, deferred bindings, and backend portability boundary.

- [ ] **Step 7: Verify and commit**

Run: `cargo test --workspace && cargo test -p notecrypt-e2e --test crash_recovery --test plaintext_canary --test presentation_journey --test recovery_journey && cargo deny check && cargo audit && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`

Expected: all hardening, platform, policy, and documentation checks pass.

Commit: `test(security): add adversarial and platform hardening gates`

---

### Task 21: Calibrate performance and certify the phase 1 release candidate

**Files:**

- Modify: `benches/src/crypto.rs`
- Modify: `benches/src/store.rs`
- Modify: `benches/src/targeted_edit.rs`
- Modify: `benches/src/tui_latency.rs`
- Create: `benches/src/git_history.rs`
- Create: `docs/performance-baseline.md`
- Create: `docs/release-readiness.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**

- Produces: platform performance baselines, regression thresholds, and the final release-readiness report.

- [ ] **Step 1: Run the complete synthetic corpus**

Measure cold and warm cache behavior for 1 KiB, 1 MiB, 100 MiB, 1 GiB, 10 GiB, 10,000 tiny files, 100,000 metadata entries, sparse rejection, rapid saves, and 100 Git revisions.
Record p50, p95, p99, throughput, peak resident memory, queue depth, and worker utilization.

- [ ] **Step 2: Profile before changing any tuning value**

Separate KDF, editor startup, crypto, filesystem durability, Git, network, terminal render, and antivirus costs.
Change chunk size, worker concurrency, debounce, or buffer count only when a measured bottleneck justifies it.

- [ ] **Step 3: Enforce hard performance gates**

On dedicated platform workers require CLI startup p95 below 75 ms, TUI response p95 below 50 ms, targeted editor request p95 below 200 ms for 1 MiB after unlock, durable save p95 below 350 ms including debounce, throughput at least 150 MiB per second, and large-file memory below 128 MiB above KDF allocation.
Treat stretch targets as informational.

- [ ] **Step 4: Verify security invariants after optimization**

Re-run every cryptographic-profile substitution test, KDF floor and ceiling test, pre-call and post-call cancellation test, CSPRNG failure test, nonce uniqueness test, durability test, revocation-per-chunk test, stable-source test, fixed-base cleanup test, replication-budget test, bootstrap test, Git history-verification test, conflict test, canary test, backend-copy test, compromise-rekey test, and clean-device recovery test.
Reject any optimization that weakens KDF floors or ceilings, authentication, durability, cleanup ownership, graph completeness, Git isolation, bounded memory, or explicit leakage policy.

- [ ] **Step 5: Conduct independent security review**

Provide the threat model, durable cryptographic profile, recovery policy, compromise semantics, key hierarchy, transaction ordering, parser and replication limits, cleanup ownership, backend bootstrap, Git runner and history verifier, conflict model, complete CLI and TUI integration evidence, and test evidence to an independent reviewer.
Resolve every critical finding and document accepted lower-severity residual risks before release.

- [ ] **Step 6: Run the final user journey**

On macOS, Linux, and Windows initialize with generated recovery and the explicit custom warning path, edit through a real blocking editor, use the TUI, lock during an operation, reopen, open a bounded whole-vault workspace, exercise cleanup failure, onboard Git, synchronize two devices, observe rollback and indeterminate-publication warnings, create and resolve a conflict, run backup, inject backup readback failure, perform `BackendCopy`, perform `CompromiseRekey`, exercise device denial and removal failure, fall back to the recovery phrase, and recover on a clean device.
Verify no step requires manual encrypted-object manipulation.
Record the exact release evidence and residual concerns in `docs/release-readiness.md`, not `README.md`.

- [ ] **Step 7: Verify and commit**

Run: `cargo test --workspace && cargo test -p notecrypt-e2e --test cli_journey --test tui_journey --test whole_vault --test git_sync --test presentation_journey --test recovery_journey --test plaintext_canary --test crash_recovery && cargo bench -p notecrypt-benches && cargo deny check && cargo audit`

Expected: every acceptance criterion and hard performance budget passes, with no unresolved critical review finding.

Commit: `perf(release): establish phase one performance baseline`

## Plan Self-Review Checklist

- [ ] Every phase 1 requirement in the design specification maps to at least one task.
- [ ] Every durable or public interface is introduced before a consumer uses it.
- [ ] Every task has exact files, tests, commands, expected results, and one commit.
- [ ] No implementation task requires choosing between unstated alternatives.
- [ ] Performance tuning follows measurement and preserves security floors.
- [ ] The first user-testable CLI and TUI checkpoint arrives before Git and device-unlock integration.
- [ ] Final verification covers macOS, Linux, Windows, x86-64, and ARM64 where available.
