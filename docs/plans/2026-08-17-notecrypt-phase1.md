# Notecrypt Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `common:subagent-driven-development` (recommended) or `common:executing-plans` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a secure, responsive Rust encrypted-file vault with a usable CLI and TUI, supervised external editing, whole-vault sessions, and portable Git synchronization.

**Architecture:** A Cargo workspace separates deterministic domain behavior, durable formats, cryptography, transactional encrypted storage, backend contracts, replication, and application orchestration.
The CLI and TUI consume one in-process service facade whose worker model keeps all blocking work outside the terminal event loop.

**Tech Stack:** Rust 1.96.1, Cargo resolver 3, Argon2id, XChaCha20-Poly1305, HKDF-SHA-256, keyed BLAKE3, `minicbor`, `zeroize`, `secrecy`, `serde`, `serde_json`, `thiserror`, `uuid`, `tempfile`, `crossbeam-channel`, `notify`, `clap`, `ratatui`, `crossterm`, `keyring`, `rpassword`, `tracing`, Criterion, Proptest, Trybuild, cargo-fuzz, cargo-deny, cargo-audit, and the installed Git executable.

**Design specification:** `docs/plans/2026-08-17-notecrypt-phase1-design.md`

## Global Constraints

- Work on a feature branch and never commit directly to `main` or `master`.
- Plaintext content and logical paths must never be written inside the encrypted vault repository.
- Targeted editing must not scan, decrypt, or encrypt the entire vault.
- TUI rendering and input handling must never perform blocking cryptography, filesystem traversal, keyring, Git, or network work.
- File processing must stream through bounded buffers and remain bounded in memory for 10 GiB inputs.
- Every durable decoder must reject malformed, oversized, unsupported, non-canonical, reordered, duplicated, and truncated input.
- Save acknowledgement must distinguish detected, encrypting, locally durable, and synchronized states.
- A failed local transaction must never advance the trusted local head.
- A failed remote publish must never overwrite an unexpected remote head.
- Phase 1 supports regular files and directories only.
- Durable format, snapshot layout, backend SPI, and CLI JSON versions evolve independently.
- No public API may expose Tokio, Git implementation, `anyhow`, serializer, or cryptographic-library types.
- Dependencies must be reviewed, locked in `Cargo.lock`, audited, and denied by default when licenses are outside the repository policy.
- Every implementation task follows test-driven development and ends in one conventional commit with a lowercase scope and no trailing period.

## Delivery Checkpoints

- Checkpoint A after Task 15 is a runnable local vault with CLI, TUI, passphrase unlock, targeted editing, lock, and reopen.
- Checkpoint B after Task 17 adds arbitrary-file whole-vault sessions and deterministic conflict reconciliation.
- Checkpoint C after Task 19 adds Git synchronization, verified backup, and device-local unlock.
- Checkpoint D after Task 21 is the hardened phase 1 release candidate.

## Specification Traceability

| Specification area | Implementation tasks |
| --- | --- |
| Workspace boundaries and dependency rules | 1, 20 |
| Domain identities, logical tree, tombstones, and conflicts | 2, 17 |
| Key hierarchy, passphrase recovery, and authenticated chunks | 3, 4, 19 |
| Durable formats and independent versioning | 5, 7, 14 |
| Crash-consistent local transactions and rollback detection | 6, 20 |
| Portable backend SPI and migration | 7, 17 |
| Runtime-neutral service, sessions, progress, cancellation, and lock | 8, 9, 10, 11, 13, 16 |
| Complete local application use cases | 10, 11 |
| Targeted editing and local plaintext minimization | 12, 13, 20 |
| CLI and polished TUI | 14, 15 |
| Whole-vault autosave and filesystem safety | 16 |
| Authenticated synchronization and conflict preservation | 17 |
| Git onboarding, synchronization, hooks, and backup | 18 |
| Native device unlock and recovery fallback | 19 |
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
crates/notecrypt-format/src/{lib.rs,error.rs,limits.rs,header.rs,object.rs,manifest.rs,snapshot.rs}
crates/notecrypt-crypto/src/{lib.rs,error.rs,secret.rs,kdf.rs,keys.rs,aead.rs,stream.rs}
crates/notecrypt-store/src/{lib.rs,error.rs,layout.rs,repository.rs,journal.rs,transaction.rs,recovery.rs,trusted_state.rs,durability/mod.rs,durability/unix.rs,durability/windows.rs}
crates/notecrypt-backend/src/{lib.rs,error.rs,types.rs,backend.rs,conformance.rs}
crates/notecrypt-replication/src/{lib.rs,error.rs,plan.rs,reconcile.rs,sync.rs,migration.rs}
crates/notecrypt-service/src/{lib.rs,command.rs,error.rs,event.rs,operation.rs,ports.rs,session.rs,service.rs,local_use_cases.rs}
adapters/notecrypt-backend-git/src/{lib.rs,error.rs,runner.rs,repository.rs,backend.rs,hooks.rs}
adapters/notecrypt-device-unlock/src/{lib.rs,error.rs,native.rs}
adapters/notecrypt-editor-workspace/src/{lib.rs,error.rs,editor.rs,permissions.rs,workspace.rs,watcher.rs}
ui/notecrypt-tui/src/{lib.rs,app.rs,event_loop.rs,keymap.rs,view_model.rs,widgets.rs,dialogs.rs}
apps/notecrypt-cli/src/{main.rs,args.rs,config.rs,commands.rs,output.rs,password.rs}
tests/notecrypt-e2e/Cargo.toml
tests/notecrypt-e2e/src/{lib.rs,workspace_policy.rs,test_editor.rs}
tests/notecrypt-e2e/tests/{local_facade.rs,local_vault.rs,cli_journey.rs,tui_journey.rs,whole_vault.rs,git_sync.rs,plaintext_canary.rs,crash_recovery.rs}
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

- Create: `crates/notecrypt-crypto/src/error.rs`
- Create: `crates/notecrypt-crypto/src/secret.rs`
- Create: `crates/notecrypt-crypto/src/kdf.rs`
- Create: `crates/notecrypt-crypto/src/keys.rs`
- Create: `crates/notecrypt-crypto/src/aead.rs`
- Modify: `crates/notecrypt-crypto/src/lib.rs`
- Test: `crates/notecrypt-crypto/tests/domain_separation.rs`

**Interfaces:**

- Produces: non-formatting secret key types.
- Produces: versioned Argon2id derivation and Vault Root Key wrapping.

- [ ] **Step 1: Write compile-fail and domain-separation tests**

Use `trybuild` to prove that root and derived secret types cannot be cloned, debug-formatted, displayed, or serialized.
Assert that changing any authenticated context field makes decryption fail.

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

pub fn calibrate_argon2id(
    target: std::time::Duration,
    minimum: Argon2idParameters,
) -> Result<Argon2idParameters, CryptoError>;

pub fn derive_recovery_wrapping_key(
    passphrase: &RecoveryPassphrase,
    salt: &[u8; 16],
    parameters: Argon2idParameters,
) -> Result<RecoveryWrappingKey, CryptoError>;

pub fn derive_vault_keys(root: &VaultRootKey) -> Result<VaultKeys, CryptoError>;
```

Set the minimum to 65,536 KiB, three iterations, and one lane.
Calibration targets 750 to 1,500 ms and never reduces the minimum.

- [ ] **Step 3: Write failing key-slot tests**

Cover recovery wrapping, wrong passphrase, modified salt, modified vault ID, modified algorithm identifier, and independent derived subkeys.

- [ ] **Step 4: Implement key wrapping and derivation**

Derive metadata, snapshot-authentication, chunk-fingerprint, content-wrapping, and local-verification subkeys with distinct fixed HKDF labels.
Wrap the Vault Root Key with XChaCha20-Poly1305 using a random nonce and authenticated vault-header context.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-crypto`

Expected: secret compile-fail, KDF floor, wrapping, wrong-passphrase, and domain-separation tests pass.

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

- Consumes: chunk-fingerprint and content-wrapping keys from Task 3.
- Produces: independently authenticated chunk encryption with bounded memory and measured chunk-size evidence.

- [ ] **Step 1: Write failing streaming integrity tests**

Cover 0 bytes, 1 byte, every chunk boundary around 1 MiB, 2 MiB, and 4 MiB, a 64 MiB generated smoke stream, modified chunks, wrong file identity, wrong object identity, wrong plaintext length, and cancellation.
Mark the 1 GiB and 10 GiB corpus tests ignored in ordinary package runs and execute them on dedicated performance workers in Task 21.
Format and store tests cover revision-manifest reordering, missing chunks, duplicated chunks, wrong revision, and wrong total length.

- [ ] **Step 2: Implement the bounded streaming API**

```rust
pub struct ChunkStreamContext {
    pub vault_id: [u8; 16],
    pub file_id: [u8; 16],
    pub format_version: u16,
    pub algorithm_id: u16,
    pub object_kind: u8,
    pub chunk_size: u32,
}

pub struct EncryptedChunkDescriptor {
    pub object_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub sequence: u64,
    pub plaintext_bytes: u32,
}

pub struct EncryptSummary {
    pub plaintext_bytes: u64,
    pub chunk_count: u32,
    pub chunk_descriptors: Vec<EncryptedChunkDescriptor>,
}

pub fn encrypt_stream<R: std::io::Read>(
    reader: R,
    context: &ChunkStreamContext,
    fingerprint_key: &ChunkFingerprintKey,
    wrapping_key: &ContentWrappingKey,
    sink: &mut dyn EncryptedChunkSink,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<EncryptSummary, CryptoError>;

pub fn decrypt_stream<W: std::io::Write>(
    chunks: &mut dyn EncryptedChunkSource,
    context: &ChunkStreamContext,
    wrapping_key: &ContentWrappingKey,
    writer: W,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<u64, CryptoError>;
```

Generate a fresh random object identity and data key for every newly encrypted chunk.
Use a random 128-bit nonce domain plus a checked 64-bit sequence value for each newly encrypted stream.
Authenticate vault ID, file ID, object ID, plaintext length, format version, and algorithm identifier on each chunk.
Authenticate object kind and checked chunk sequence as well.
Return keyed fingerprints only to the unlocked store pipeline so it can reuse a prior descriptor at the same file position.
Keep at most two chunk buffers live per pipeline.

- [ ] **Step 3: Establish streaming baselines**

Measure 1 KiB, 1 MiB, and 100 MiB generated inputs for chunk-size selection.
Record throughput and peak resident memory without real paths or exact user sizes.
Select 1 MiB, 2 MiB, or 4 MiB only after the comparison and record the machine-readable evidence in `benches/baselines/chunk-size-v1.json`.
Task 5 consumes that evidence when it records the durable-format decision.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-crypto && cargo bench -p notecrypt-benches --bench crypto`

Expected: integrity tests pass, memory remains bounded, and the selected chunk size has recorded evidence.

Commit: `feat(crypto): add bounded streaming encryption`

---

### Task 5: Freeze the versioned bootstrap and encrypted object formats

**Files:**

- Create: `crates/notecrypt-format/src/error.rs`
- Create: `crates/notecrypt-format/src/limits.rs`
- Create: `crates/notecrypt-format/src/header.rs`
- Create: `crates/notecrypt-format/src/object.rs`
- Create: `crates/notecrypt-format/src/manifest.rs`
- Create: `crates/notecrypt-format/src/snapshot.rs`
- Modify: `crates/notecrypt-format/src/lib.rs`
- Create: `crates/notecrypt-format/tests/golden.rs`
- Create: `crates/notecrypt-format/tests/malformed.rs`
- Create: `crates/notecrypt-format/tests/fixtures/v1/`
- Create: `docs/decisions/0002-encrypted-object-format.md`
- Create: `docs/decisions/0003-chunk-reuse-leakage.md`

**Interfaces:**

- Produces: canonical version-1 encoders and bounded decoders.
- Produces: stable fixture bytes for bootstrap header, object envelope, file manifest, logical tree, and snapshot.

- [ ] **Step 1: Write failing canonical-format tests**

Assert byte-for-byte deterministic encoding, rejection of indefinite collections, duplicate fields, unknown critical fields, trailing bytes, unsupported major versions, oversized collections, and integer overflow.

- [ ] **Step 2: Define explicit limits**

```rust
pub struct DecodeLimits {
    pub max_header_bytes: usize,
    pub max_object_bytes: u64,
    pub max_chunks_per_file: u32,
    pub max_tree_entries: u32,
    pub max_snapshot_parents: u8,
    pub max_name_bytes: u16,
}

impl DecodeLimits {
    pub const PHASE_1: Self = Self {
        max_header_bytes: 1_048_576,
        max_object_bytes: 1_099_511_627_776,
        max_chunks_per_file: 1_048_576,
        max_tree_entries: 1_000_000,
        max_snapshot_parents: 2,
        max_name_bytes: 1_024,
    };
}
```

- [ ] **Step 3: Implement canonical `minicbor` schemas**

Use fixed-position arrays with explicit version and object-kind fields.
Reject non-canonical encodings before constructing domain objects.
Keep schema records separate from domain types and convert explicitly.
Encode each chunk envelope with its random object identity, nonce domain and sequence, wrapped random data key, plaintext length, ciphertext, and authentication tag.
Encode each encrypted revision manifest with ordered chunk identities, keyed plaintext fingerprints, per-chunk lengths, and total plaintext length.

- [ ] **Step 4: Add chunk-reuse security decision**

Record that phase 1 reuses unchanged fixed-size chunks within the same logical file so aligned or in-place edits avoid re-encrypting unchanged regions.
Record that insertion or deletion can shift subsequent boundaries and require re-encrypting the remainder of the file.
Record the leak of unchanged fixed-size regions across revisions, the absence of cross-file deduplication, and the rejected alternative of full-file re-encryption on every save.

- [ ] **Step 5: Generate and lock golden fixtures**

Generate each fixture once from deterministic test keys and non-sensitive canary text.
Check fixture hashes into the golden test and prohibit fixture replacement without an explicit format-version decision.

- [ ] **Step 6: Fuzz decoder entry points**

Add cargo-fuzz targets for header, object, manifest, tree, and snapshot decoding.
Set allocation and recursion limits before decoding attacker-controlled lengths.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-format`

Run from `crates/notecrypt-format`: `cargo fuzz run decode_object -- -max_total_time=60`

Expected: canonical and malformed tests pass and the bounded fuzz run finds no crash or unbounded allocation.

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
- Create: `crates/notecrypt-store/src/durability/mod.rs`
- Create: `crates/notecrypt-store/src/durability/unix.rs`
- Create: `crates/notecrypt-store/src/durability/windows.rs`
- Modify: `crates/notecrypt-store/src/lib.rs`
- Test: `crates/notecrypt-store/tests/transaction_faults.rs`
- Test: `crates/notecrypt-store/tests/rollback.rs`
- Benchmark: `benches/src/store.rs`

**Interfaces:**

- Consumes: core identities, format codecs, and crypto operations.
- Produces: `VaultRepository`, `VaultStore`, revocable authenticated capabilities, and an injectable durability seam.

- [ ] **Step 1: Write failing repository-layout tests**

Assert exact locations for `.notecrypt-vault`, sharded object IDs, `head`, transaction staging, journal, trusted local state, and cleanup registry.
Assert that no logical path is accepted as a repository path.

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
    fn initialize(&self, request: InitializeRepository) -> Result<RepositorySnapshot, StoreError>;
    fn unlock(&self, request: UnlockRepository) -> Result<Box<dyn UnlockedVault>, StoreError>;
    fn list_device_slots(&self) -> Result<Vec<LocalDeviceSlotRecord>, StoreError>;
}

pub trait UnlockedVault: Send + Sync {
    fn acquire_lease(&self) -> Result<Box<dyn UnlockedVaultLease>, StoreError>;
    fn begin_close(&self);
    fn close(self: Box<Self>) -> Result<(), StoreError>;
}

pub trait UnlockedVaultLease: Send {
    fn list(&self, request: ListRepositoryEntries) -> Result<Vec<RepositoryEntry>, StoreError>;
    fn apply(&self, request: RepositoryMutation) -> Result<RepositorySnapshot, StoreError>;
    fn export(&self, request: ExportRepositoryFile) -> Result<ExportedFile, StoreError>;
    fn authenticate_remote_head(&self, bytes: &[u8]) -> Result<AuthenticatedHead, StoreError>;
    fn import_encrypted_object(&self, input: ImportEncryptedObject) -> Result<(), StoreError>;
    fn export_encrypted_object(&self, input: ExportEncryptedObject) -> Result<(), StoreError>;
    fn commit_replicated_snapshot(
        &self,
        input: CommitReplicatedSnapshot,
    ) -> Result<RepositorySnapshot, StoreError>;
    fn enroll_device_slot(
        &self,
        input: EnrollLocalDeviceSlot,
    ) -> Result<LocalDeviceSlotRecord, StoreError>;
    fn remove_device_slot(&self, id: LocalDeviceSlotId) -> Result<(), StoreError>;
}

pub struct LocalDeviceSlotId([u8; 16]);

impl LocalDeviceSlotId {
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
Leases reference that cell and never copy root or derived keys into lease-owned storage.
Every key-required repository operation, including replication authentication and import, is available only through a lease.
Keep all raw `VaultStore` helpers crate-private.
`enroll_device_slot` performs root-key wrapping, local-record authentication, and atomic persistence inside the store because only that capability may access both the root key and supplied device-wrapping key.
`begin_close` rejects new leases and makes existing leases fail with `StoreError::Locked` at the next chunk or transaction boundary.
`close` zeroizes the central cell even if cancelled worker objects have not yet dropped.

- [ ] **Step 3: Write a failure test for every transaction boundary**

Inject failure before and after staging write, staged-file flush, staged verification, immutable publication, journal write, head replacement, directory flush, trusted-state update, and completion marker.
Assert that recovery yields either the old complete snapshot or the new complete snapshot.

- [ ] **Step 4: Implement transaction commit and recovery**

Implement the ten-step transaction order from the design specification.
Implement Unix and macOS durability with file and directory synchronization plus same-filesystem rename.
Implement Windows durability with explicit file flush and replace semantics behind `windows-sys`.
Expose capability differences and fail vault initialization if the required head-replacement guarantee is unavailable.
Use a deterministic fake to inject every crash-test failure point.
Never overwrite an immutable object with different bytes.

- [ ] **Step 5: Implement rollback detection**

Persist the last trusted local and observed remote snapshot identities outside the repository.
Authenticate trusted-head, migration, cleanup, and device-slot local records with the derived `LocalVerificationKey` and a record-type domain label.
After passphrase unlock, derive the key and verify all existing trusted records before applying rollback decisions.
During device unlock, unwrap the root key with the OS-protected key first, derive the local-verification key, and then verify the complete slot record and trusted state before exposing an unlocked capability.
Treat records returned by locked `list_device_slots` as untrusted candidates and use their provider references only to attempt authenticated root-key unwrap.
Treat local-record authentication failure as `StoreError::LocalStateAuthenticationFailed`, refuse device-slot use, and require passphrase recovery plus explicit local-state repair.
Return `StoreError::RollbackDetected` before modifying state when a presented head is behind or excludes the trusted snapshot.

- [ ] **Step 6: Benchmark transaction overhead**

Measure object publication separately from cryptography for 1 KiB, 1 MiB, 100 MiB, 10,000 tiny objects, cold cache, and warm cache.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-store && cargo bench -p notecrypt-benches --bench store`

Expected: all fault points recover to a valid authenticated head.

Commit: `feat(store): add crash-consistent encrypted object storage`

---

### Task 7: Define and prove the portable backend contract

**Files:**

- Create: `crates/notecrypt-backend/src/error.rs`
- Create: `crates/notecrypt-backend/src/types.rs`
- Create: `crates/notecrypt-backend/src/backend.rs`
- Create: `crates/notecrypt-backend/src/conformance.rs`
- Modify: `crates/notecrypt-backend/src/lib.rs`
- Test: `crates/notecrypt-backend/tests/memory_backend.rs`
- Create: `docs/decisions/0004-backend-contract.md`

**Interfaces:**

- Produces: a synchronous backend SPI suitable for blocking worker execution.
- Produces: a conformance suite reusable by Git and future adapters.

- [ ] **Step 1: Write a failing conformance suite against an in-memory backend**

Test idempotent staged objects, paginated inventory, missing object behavior, atomic publication success, stale expected-head rejection, readback, batch limits, abort, cancellation, unreachable leftovers, and injected transient errors.

- [ ] **Step 2: Implement the exact backend contract**

```rust
pub struct OpaqueObjectId([u8; 32]);
pub struct HeadValue(Vec<u8>);
pub struct HeadVersion(Vec<u8>);

pub struct ObservedHead {
    pub version: HeadVersion,
    pub value: HeadValue,
}

impl OpaqueObjectId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32];
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

Limit `HeadValue` to 64 KiB and `HeadVersion` to 1 KiB at construction.
Treat both as opaque transport bytes until replication asks the store to authenticate the head value.
`BackendPublication::commit` must make every staged object readable with the replacement head or leave the prior head unchanged.
A stale expected version leaves the prior head unchanged but may leave unreachable immutable objects.
Git stages objects and tree state in its local object database and publishes them only through the final fast-forward push.
Object-store adapters may upload immutable objects during staging and conditionally replace their head during commit.
`PublishOutcome::Indeterminate` means the backend cannot tell whether the remote accepted the publication, so callers must reread the head before retrying.

- [ ] **Step 3: Add capabilities and safe error categories**

Represent conditional-head support, maximum object size, inventory page size, batch size, and safe concurrency.
Classify errors as authentication, authorization, unavailable, rate-limited, corrupt response, unsupported, stale head, cancelled, and permanent.

- [ ] **Step 4: Record the contract decision**

Explain why the backend SPI is the sole dedicated contracts crate, why it contains no Git types, and why a backend without conditional replacement requires explicit single-writer mode.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-backend`

Expected: the in-memory adapter passes every conformance test.

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
    Initialize(InitializeVault),
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
    pub vault_id: VaultId,
    pub repository_root: std::path::PathBuf,
}

pub struct VaultWorkspaceRequest {
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
pub struct LogicalWorkspacePath(std::path::PathBuf);

impl SuppressionToken {
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
}

impl LogicalWorkspacePath {
    pub fn new(path: std::path::PathBuf) -> Result<Self, HostPortError>;
    pub fn as_path(&self) -> &std::path::Path;
}

pub struct CleanupReport {
    pub removed: usize,
    pub remaining: usize,
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
    fn cleanup_registered(&self) -> Result<CleanupReport, HostPortError>;
}

pub trait WorkspaceWatch: Send {
    fn next_event(&mut self, timeout: std::time::Duration) -> Result<Option<WorkspaceEvent>, HostPortError>;
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
Make `DeviceUnlockSecret` non-cloneable and non-formatting, and do not expose `secrecy` or raw key bytes through the port.
Give the service an internal consuming conversion from `DeviceUnlockSecret` to the store's `DeviceWrappingKey` input without exposing bytes to a UI or loggable DTO.
Permit the service crate's otherwise narrow dependency on `notecrypt-crypto` only for this opaque secret container, and enforce with dependency tests that no service command, result, event, or UI-facing port exposes it.
Provide fake implementations for service tests and an unavailable device-unlock implementation for Checkpoint A.

- [ ] **Step 2: Write failing unlock and lock tests**

Cover wrong passphrase, KDF cancellation boundaries, saturated ordinary queue, inactivity timeout, absolute deadline, explicit lock, system suspend notification, coalesced trusted TUI activity, cleanup failure, and a pending durable save.
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
Call `begin_close` when lock begins so new leases fail, close the capability after active leases reach a safe boundary or the final-save grace expires, and rely on capability drop to erase store-owned key material.

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

**Interfaces:**

- Consumes: `Arc<dyn VaultRepository>` plus fake host ports.
- Produces: typed initialize, in-process unlock, status, list, priority lock control, and reopen behavior before any CLI or TUI adaptation.

- [ ] **Step 1: Write failing command-to-result contract tests**

Submit initialize, unlock, status, list, lock control, and reopen through `ServiceHandle` against a temporary `VaultStore`.
Assert the exact `OperationResult`, event sequence, error category, session-state transition, and repository-head transition for each command.

- [ ] **Step 2: Implement initialization and reopen**

Create the bootstrap header, recovery key slot, empty logical tree, first authenticated snapshot, local trusted state, and cleanup registry.
On reopen, validate the bootstrap and trusted head before accepting a passphrase.

- [ ] **Step 3: Implement unlocked read use cases**

Implement list and status through authenticated cached metadata scoped to the unlock session.
Return immutable `EntrySummary` values and never expose store or crypto types to UI consumers.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-service --test local_use_cases`

Expected: initialization, passphrase unlock, authenticated browsing, priority lock, and reopen pass through the service facade.

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

Assert that workspace paths are outside the repository, permissions are restrictive, random names reveal no logical filename, cleanup registration precedes plaintext creation, materialized files publish atomically with suppression generations, arming establishes a baseline, and indexing exclusions are attempted without claiming guarantees.

- [ ] **Step 2: Implement the service-owned workspace ports**

Implement `WorkspaceProvider` and `WorkspaceWatch` from `notecrypt-service` without redefining their types in the adapter.
Register cleanup before writing plaintext and unregister only after verified removal.
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

Expected: workspace creation, cleanup registration, editor profiles, strict supervision, and process termination pass on the current platform.

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

- [ ] **Step 2: Implement per-path debounce and stable-source validation**

Start with a 100 ms quiet interval within the approved 75 to 150 ms calibration range.
Open a stable handle, record source metadata and generation, stream encryption to transaction staging, and verify the generation before publication.
Discard superseded temporary ciphertext without advancing the head.

- [ ] **Step 3: Complete the targeted edit vertical path**

Wire service command, selected revision decryption, editor launch, save events, transactional encryption, final save, cleanup, and lock.
Emit `SaveDetected`, `Encrypting`, `RevisionDurable`, `CleanupRequired`, and terminal events.

- [ ] **Step 4: Benchmark targeted edit**

Measure fixed overhead and throughput separately.
Enforce p95 below 200 ms to request editor launch for a 1 MiB file after unlock and p95 below 350 ms from final event to durable ciphertext for a 1 MiB save.
Verify sustained streaming throughput of at least 150 MiB per second and bounded memory for 10 GiB.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-editor-workspace -p notecrypt-service && cargo test -p notecrypt-e2e --test local_vault`

Expected: all editor, watcher, lock, and plaintext-boundary tests pass.

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
- Produces: one-shot `notecrypt init`, `create`, `list`, `edit`, `status`, `import`, `export`, `rm`, `mv`, and `mkdir` commands.
- Produces: CLI JSON envelope version 1.

- [ ] **Step 1: Write failing CLI contract tests**

Test `--vault-root`, `NOTECRYPT_VAULT_ROOT`, precedence, protected passphrase prompt, refusal of passphrase command arguments, stable exit codes, human output, and JSON fixtures.
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

- [ ] **Step 3: Adapt every proven local service use case**

Map each CLI subcommand to one typed service command and typed result.
For every protected command, construct the process-local service, prompt for the recovery passphrase, unlock, perform the requested operation, call `ServiceHandle::control(Control::LockNow)`, and await cleanup before exit.
Keep persistent unlock and immediate lock actions inside the TUI process.
Do not claim cross-process session control until a separately specified authenticated IPC owner exists.
Map stable error categories to documented exit codes and JSON errors.
Do not parse human output internally.

- [ ] **Step 4: Add a process-level CLI journey**

Spawn the built binary to initialize, then run one-shot create, import, edit through the blocking test editor, list, export, and delete invocations using protected test input for each protected command.
Verify every process locks and completes workspace cleanup before exit, then reopen through a new process.
Verify exit codes, JSON fixtures, durable bytes, and absence of plaintext canaries.

- [ ] **Step 5: Enforce CLI startup performance**

Measure `notecrypt --help` and locked `notecrypt status` in a release build.
Enforce p95 below 75 ms without unlock or repository scan.

- [ ] **Step 6: Verify and commit**

Run: `cargo test -p notecrypt-cli && cargo test -p notecrypt-e2e --test cli_journey`

Expected: every local use case works through the built CLI and JSON fixtures remain stable.

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

Use `ratatui::backend::TestBackend` to snapshot locked, unlocking, tree, activity, warning, and cleanup-required screens at 80x24, 120x40, and the minimum supported size.
Test keyboard-only navigation, clear focus, secret-input masking, and zeroization of the passphrase input buffer after submission.

- [ ] **Step 2: Implement the view model and event loop**

Poll terminal input and service events without blocking.
Render the status header, virtualized tree, details and activity pane, hint bar, unlock dialog, create dialog, confirmation dialog, and progress state.
Coalesce progress to the terminal refresh rate and preserve warning and terminal events.
Send coalesced `Control::UserActivity` for trusted local keyboard and navigation input.

- [ ] **Step 3: Adapt all local user flows**

Wire initialize, unlock, browse, create, import, edit, rename, move, delete, export, and status to service commands.
Wire the TUI lock action directly to `ServiceHandle::control(Control::LockNow)`.
Show dirty, encrypting, durable, and cleanup-required states distinctly.
Add a Checkpoint A quick start to `README.md` with build and one-shot CLI examples plus the persistent TUI unlock, edit, lock, and reopen flow.

- [ ] **Step 4: Enforce responsiveness budgets**

Measure input-to-render p50, p95, and p99 while fake 10 GiB encryption and blocking Git operations run on workers.
Enforce p95 below 50 ms and idle CPU below 1 percent.

- [ ] **Step 5: Run real CLI and pseudo-terminal TUI journeys**

Drive the built CLI through initialize and one-shot protected operations, with each invocation unlocking and locking internally.
Drive a pseudo-terminal TUI journey through initialize, unlock, create, edit, lock, reopen, and content verification.
Assert the same durable result through both adapters.

- [ ] **Step 6: Verify and commit**

Run: `cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test cli_journey --test tui_journey --test local_vault`

Expected: both built user interfaces complete the Checkpoint A journey and the TUI meets its response budget.

Commit: `feat(tui): deliver runnable local encrypted vault`

---

### Task 16: Add whole-vault sessions and autosave

**Files:**

- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/session.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Modify: `adapters/notecrypt-editor-workspace/src/workspace.rs`
- Modify: `adapters/notecrypt-editor-workspace/src/watcher.rs`
- Test: `tests/notecrypt-e2e/tests/whole_vault.rs`
- Test: `adapters/notecrypt-editor-workspace/tests/path_safety.rs`

**Interfaces:**

- Consumes: store transactions and workspace leases.
- Produces: `OpenWholeVault`, progressive materialization, autosave, tombstones, bounded locking, and startup cleanup.

- [ ] **Step 1: Write failing progressive-materialization tests**

Test metadata-first traversal, small-file priority, bounded worker count, progress, cancellation, no zero-byte placeholders, cleanup of a partially materialized workspace, suppression of Notecrypt-created events, and a genuine edit racing with later materialization.

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
Process the cleanup registry before the next unlock.

- [ ] **Step 6: Verify and commit**

Run: `cargo test -p notecrypt-editor-workspace --test path_safety && cargo test -p notecrypt-service --test lock_deadline && cargo test -p notecrypt-e2e --test whole_vault`

Expected: all supported changes survive reopen and all unsupported objects fail without publication.

Commit: `feat(vault): add bounded whole-vault autosave sessions`

---

### Task 17: Implement authenticated replication and conflict preservation

**Files:**

- Create: `crates/notecrypt-replication/src/error.rs`
- Create: `crates/notecrypt-replication/src/plan.rs`
- Create: `crates/notecrypt-replication/src/reconcile.rs`
- Create: `crates/notecrypt-replication/src/sync.rs`
- Create: `crates/notecrypt-replication/src/migration.rs`
- Modify: `crates/notecrypt-replication/src/lib.rs`
- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Test: `crates/notecrypt-replication/tests/sync_matrix.rs`
- Test: `crates/notecrypt-replication/tests/migration.rs`

**Interfaces:**

- Consumes: `VaultBackend`, a revocable `UnlockedVaultLease`, and deterministic core reconciliation.
- Produces: authenticated fetch, reconciliation, conditional publish, retry, and resumable migration.
- Produces: explicit byte-preserving conversion between core `ObjectId` and backend `OpaqueObjectId` without exposing either private field.

- [ ] **Step 1: Write failing synchronization-matrix tests**

Cover empty remote, equal heads, local ahead, remote ahead, independent edits, same-file edits, rename conflict, delete-versus-modify, missing object, corrupt object, stale conditional head, bounded retry, rollback, cancellation, and unavailable backend.

- [ ] **Step 2: Implement a side-effect-free sync plan**

```rust
pub enum SyncAction {
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
Perform every head-authentication, encrypted-object import or export, and replicated snapshot commit through the revocable lease supplied by the active service session.
Treat `StoreError::Locked` as cancellation and never retain a raw `VaultStore` handle in replication state.
Begin a backend publication with the observed head version, stream missing immutable objects through bounded `stage_object` calls, and commit the authenticated replacement head.
Treat a stale publication result as a refetch and reconciliation retry.
Treat an indeterminate publication result by rereading the remote head and authenticating it before deciding whether the attempted replacement committed or needs reconciliation.
Verify the published head and reachable objects through readback before recording sync success.

- [ ] **Step 4: Implement conflict preservation**

Use the core deterministic result to commit a two-parent snapshot.
Emit conflict events containing unlocked logical details only to the active local session.

- [ ] **Step 5: Implement resumable migration**

Persist source head, target backend identity, verified object cursor, and target head state outside the vault repository.
Switch the active backend only after all reachable objects and the target head verify.

- [ ] **Step 6: Verify Checkpoint B and commit**

Run: `cargo test -p notecrypt-core && cargo test -p notecrypt-replication --test sync_matrix`

Expected: every concurrent case preserves all authenticated content and no stale head is overwritten.

Commit: `feat(sync): add authenticated replication and conflicts`

---

### Task 18: Implement the Git backend, onboarding hooks, and verified backup

**Files:**

- Create: `adapters/notecrypt-backend-git/src/error.rs`
- Create: `adapters/notecrypt-backend-git/src/runner.rs`
- Create: `adapters/notecrypt-backend-git/src/repository.rs`
- Create: `adapters/notecrypt-backend-git/src/backend.rs`
- Create: `adapters/notecrypt-backend-git/src/hooks.rs`
- Modify: `adapters/notecrypt-backend-git/src/lib.rs`
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Test: `adapters/notecrypt-backend-git/tests/conformance.rs`
- Test: `tests/notecrypt-e2e/tests/git_sync.rs`
- Test: `tests/notecrypt-e2e/tests/plaintext_canary.rs`

**Interfaces:**

- Produces: `GitBackend` implementing the complete backend conformance suite.
- Produces: `notecrypt vault onboard`, `notecrypt sync`, and `notecrypt vault backup`.

- [ ] **Step 1: Write failing Git runner security tests**

Use a fake executable to capture argument boundaries.
Test spaces, leading dashes, Unicode, malicious remote names, ref injection, shell metacharacters, hostile Git output, non-repository paths, and an unexpected worktree layout.
Test that an unrelated existing branch or worktree cannot enter the dedicated Notecrypt branch.

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
Use exact built-in subcommands, validated remote and branch names, literal pathspec handling, bounded output capture, cancellation, and safe environment variables.
Never execute Git aliases or interpolate a shell command.

- [ ] **Step 3: Implement Git backend conformance**

Implement onboarding for a local encrypted vault that is not yet a Git repository and recovery into a clean dedicated clone.
Create and validate one dedicated branch with no unrelated files or history, and reject embedding in a general-purpose repository.
Implement `begin_publication` as an isolated local Git publication state rooted at the observed dedicated-branch commit and addressed through a private temporary ref.
Implement `stage_object` with `git hash-object -w --no-filters` and retain the resulting object-to-path mapping only in that publication state.
On commit, construct validated trees with `git mktree`, create one commit with `git commit-tree`, update only the private temporary ref, and push that ref to the remote dedicated branch with normal fast-forward protection.
Advance the visible local tracking ref only after `git ls-remote` verifies the expected remote commit.
If push might have succeeded but its response or verification read is unavailable, return `PublishOutcome::Indeterminate` without retrying or moving visible local state.
On abort or cancellation, discard publication state while allowing unreachable local Git objects to remain for Git maintenance.
Repository attributes, content filters, and hooks cannot alter or execute during Notecrypt publication.
Use a fixed `Notecrypt <notecrypt@local.invalid>` author and committer identity plus a constant non-sensitive commit-message prefix.
Fetch before publish, create the commit based on the observed remote branch, use a normal fast-forward push, and treat rejection as a stale-head result.
Verify the final branch identity with `git ls-remote`.

- [ ] **Step 4: Add managed onboarding hooks**

Install a versioned pre-commit hook that invokes `notecrypt vault validate --staged`.
The validator rejects unexpected paths, registered plaintext workspaces, known plaintext canaries, malformed bootstrap data, and unauthenticated layout changes.
Document that `--no-verify` bypasses hooks and that the core security boundary remains encryption before repository writes.

- [ ] **Step 5: Implement verified backup**

Validate the repository, construct a Git tree from only allowed encrypted paths through the plumbing path, create a commit when changes exist, and push when a remote exists.
When no remote exists, stop after the local commit and report that state explicitly.
Read back the remote ref after push and compare it with the committed identity.

- [ ] **Step 6: Run two-device and canary tests**

Create two local clones and a bare remote.
Exercise independent changes, same-file conflicts, push races, remote deletion, malformed remote objects, and recovery.
Scan every Git commit, path, blob, log line, and process argument for unique plaintext canaries and logical names.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-backend-git --test conformance && cargo test -p notecrypt-e2e --test git_sync --test plaintext_canary`

Expected: Git passes backend conformance, two-device tests preserve conflicts, and canary scans find no plaintext.

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
- Modify: `apps/notecrypt-cli/src/commands.rs`
- Modify: `ui/notecrypt-tui/src/dialogs.rs`
- Test: `adapters/notecrypt-device-unlock/tests/keyring.rs`
- Test: `crates/notecrypt-service/tests/device_unlock.rs`

**Interfaces:**

- Consumes: the service-owned `DeviceUnlockProvider` port and `DeviceUnlockSecret` result type defined in Task 9.
- Produces: a platform-native port implementation.
- Produces: device-slot enrollment, unlock, removal, and fallback to passphrase.

- [ ] **Step 1: Write failing device-slot tests**

Cover enrollment after recovery unlock, native approval, denial, missing item, locked keyring, corrupt wrapped slot, local-slot transaction failure, removal, and passphrase fallback.
Test device-binding behavior only on a provider that explicitly advertises a verifiable device-binding capability.

- [ ] **Step 2: Implement device-local slot persistence and orchestration**

Use the existing service-owned port to generate and store a random device-wrapping key in the native credential store.
Consume the returned `DeviceUnlockSecret` into an `EnrollLocalDeviceSlot` request and invoke `UnlockedVaultLease::enroll_device_slot`.
The store capability wraps the current Vault Root Key, authenticates the record, and persists the wrapped bytes plus non-secret provider reference as a versioned `LocalDeviceSlotRecord` in trusted local state.
Commit the local record before reporting enrollment success and remove both sides with recoverable ordering during removal.
Never store the recovery passphrase.

- [ ] **Step 3: Implement native credential storage**

Use the `keyring` crate's native store on macOS, Windows, and Linux.
Treat unavailable or insecurely configured desktop stores as unsupported and require the passphrase.
Do not implement a standalone low-entropy PIN verifier.

- [ ] **Step 4: Add CLI and TUI enrollment flows**

Require an unlocked recovery session before enrollment.
Explain that recovery still requires the passphrase on another device.
Expose removal and list only device-local slot metadata.

- [ ] **Step 5: Verify Checkpoint C and commit**

Run: `cargo test -p notecrypt-device-unlock --test keyring && cargo test -p notecrypt-service --test device_unlock && cargo test -p notecrypt-e2e --test git_sync`

Expected: supported stores unlock locally, failures fall back safely, and recovery remains passphrase-based.

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
- Modify: `README.md`

**Interfaces:**

- Produces: documented guarantees and limitations backed by automated evidence.
- Produces: full macOS, Linux, and Windows release checks.

- [ ] **Step 1: Add adversarial end-to-end tests**

Inject process termination at every transaction phase, full disk, short write, permission loss, interrupted cleanup, malformed remote object, rollback, Git cancellation, and system suspend notification.
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

Copy the approved threat boundaries, rollback limitation, cleanup limitation, passphrase recovery flow, Git backup verification, and new-device recovery warning into focused user documentation.
Do not claim resistance to a compromised unlocked endpoint.

- [ ] **Step 6: Record the architecture decision**

Explain the Rust-only phase 1, separated core and TUI, in-process service contract, deferred bindings, and backend portability boundary.

- [ ] **Step 7: Verify and commit**

Run: `cargo test --workspace && cargo deny check && cargo audit && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`

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
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

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

Re-run domain-separation, nonce uniqueness, durability, cancellation, stale-source, lock, cleanup, conflict, canary, and recovery tests.
Reject any optimization that weakens KDF floors, authentication, durability, cleanup, bounded memory, or explicit leakage policy.

- [ ] **Step 5: Conduct independent security review**

Provide the threat model, durable format, key hierarchy, transaction ordering, parser limits, Git adapter, conflict model, and test evidence to an independent reviewer.
Resolve every critical finding and document accepted lower-severity residual risks before release.

- [ ] **Step 6: Run the final user journey**

On macOS, Linux, and Windows initialize a vault, edit through a real blocking editor, use the TUI, lock, reopen, open a bounded whole-vault workspace, synchronize two devices, create and inspect a conflict, run backup, and recover on a clean device.
Verify no step requires manual encrypted-object manipulation.

- [ ] **Step 7: Verify and commit**

Run: `cargo test --workspace && cargo bench -p notecrypt-benches && cargo deny check && cargo audit`

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
