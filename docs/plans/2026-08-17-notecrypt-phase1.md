# Notecrypt Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `common:subagent-driven-development` (recommended) or `common:executing-plans` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a secure, responsive Rust encrypted-file vault with a usable CLI and TUI, supervised external editing, whole-vault sessions, and portable Git synchronization.

**Architecture:** A Cargo workspace separates deterministic domain behavior, durable formats, cryptography, transactional encrypted storage, backend contracts, replication, and application orchestration.
The CLI and TUI consume one in-process service facade whose worker model keeps all blocking work outside the terminal event loop.

**Tech Stack:** Rust 1.96.1, Cargo resolver 3, Argon2id, XChaCha20-Poly1305, HKDF-SHA-256, keyed BLAKE3, `bip39`, `minicbor`, `zeroize`, `secrecy`, `serde`, `serde_json`, `thiserror`, `uuid`, `tempfile`, `crossbeam-channel`, `notify`, `clap`, `ratatui`, `crossterm`, `keyring`, `rpassword`, `tracing`, Criterion, Proptest, Trybuild, `nightly-2026-08-01`, cargo-fuzz 0.13.1, cargo-deny, cargo-audit, and the installed Git executable.

**Design specification:** `docs/plans/2026-08-17-notecrypt-phase1-design.md`

## Global Constraints

- Work on a feature branch and never commit directly to `main` or `master`.
- Plaintext content and logical paths must never be written inside the encrypted vault repository.
- Targeted editing must not scan, decrypt, or encrypt the entire vault.
- TUI rendering and input handling must never perform blocking cryptography, filesystem traversal, keyring, Git, or network work.
- File processing must stream through bounded buffers and remain bounded in memory for 10 GiB inputs.
- Every durable decoder must reject malformed, oversized, unsupported, non-canonical, reordered, duplicated, and truncated input.
- Cryptographic profile 1, Argon2id profile 1, custom-passphrase policy 1, and replication budget profile 1 use the exact identifiers, limits, AAD, MAC, and key domains in the design specification.
- Outer AEAD AAD contains only allowed public envelope fields, while protected identities, graph shape, counts, sequence, and plaintext lengths remain encrypted and are checked after decryption.
- The content-chunk public envelope contains only object ID, random 24-byte nonce, ciphertext length, wrapped-key envelope when applicable, ciphertext, and tag, with no additional nonce metadata.
- Store proof tokens and service pending capabilities have private binding state, crate-owned construction, linear consumption, and compile-fail non-forgeability tests.
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
- Reachability, replicated commit, trusted-remote recording, and compromise rekey use non-cloneable one-time capabilities that cannot be replayed across observations, limits, sessions, operations, or targets.
- Live plaintext workspaces are protected by OS-backed base and per-workspace ownership locks, and cleanup never deletes a workspace whose ownership lock is held.
- Clean-device recovery requires an explicit `FreshnessUnprovable` acknowledgement before the first trusted baseline is recorded.
- Phase 1 supports regular files and directories only.
- Durable format, snapshot layout, backend SPI, and CLI JSON versions evolve independently.
- No public API may expose Tokio, Git implementation, `anyhow`, serializer, or cryptographic-library types.
- Dependencies must be reviewed, locked in `Cargo.lock`, audited, and denied by default when licenses are outside the repository policy.
- Every implementation task follows test-driven development and ends in one conventional commit with a lowercase scope and no trailing period.

## Delivery Checkpoints

- Checkpoint A after Task 15 is a runnable local vault with CLI, TUI, passphrase unlock, targeted editing, lock, and reopen.
- Checkpoint B after Task 17 adds arbitrary-file whole-vault sessions, linear budgeted authenticated replication, deterministic conflict reconciliation, and in-memory `BackendCopy` and `CompromiseRekey` state-machine proof.
- Checkpoint C after Task 19 adds hardened Git synchronization, production Git `BackendCopy` and `CompromiseRekey` journeys, verified backup, freshness acknowledgement, device-local unlock, and the explicit CLI and TUI presentation-integration gate.
- Checkpoint D after Task 21 is the hardened phase 1 release candidate.

## Specification Traceability

| Specification area | Implementation tasks |
| --- | --- |
| Workspace boundaries and dependency rules | 1, 20 |
| Domain identities, logical tree, tombstones, and conflicts | 2, 17 |
| Key hierarchy, generated recovery, KDF bounds, compromise rekey, and authenticated chunks | 3, 4, 10, 14, 15, 17, 20 |
| Confidential durable cryptographic profiles, typed APIs, formats, and independent versioning | 3, 4, 5, 6, 20 |
| Crash-consistent local transactions, cleanup ownership, and rollback detection | 6, 9, 12, 16, 20 |
| Portable backend SPI, immutable bootstrap, linear `BackendCopy`, and `CompromiseRekey` | 6, 7, 10, 17, 18, 20 |
| Runtime-neutral service, sessions, progress, cancellation, and lock | 8, 9, 10, 11, 13, 16 |
| Complete local application use cases | 10, 11 |
| Targeted editing, stable sources, revocation, and local plaintext minimization | 6, 9, 12, 13, 20 |
| Complete CLI and polished TUI | 10, 14, 15, 16, 17, 18, 19, 20 |
| Whole-vault autosave and filesystem safety | 9, 12, 16, 20 |
| Budgeted authenticated synchronization and conflict preservation | 6, 7, 17, 20 |
| Hardened functional Git authentication, bounded ingestion, history verification, synchronization, and backup | 7, 18, 20, 21 |
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
adapters/notecrypt-backend-git/src/{lib.rs,error.rs,runner.rs,repository.rs,backend.rs,hooks.rs,auth.rs,limits.rs,quarantine.rs,verify.rs}
adapters/notecrypt-device-unlock/src/{lib.rs,error.rs,native.rs}
adapters/notecrypt-editor-workspace/src/{lib.rs,error.rs,editor.rs,permissions.rs,workspace.rs,watcher.rs}
ui/notecrypt-tui/src/{lib.rs,app.rs,event_loop.rs,keymap.rs,view_model.rs,widgets.rs,dialogs.rs}
apps/notecrypt-cli/src/{main.rs,args.rs,config.rs,commands.rs,output.rs,password.rs}
tests/notecrypt-e2e/Cargo.toml
tests/notecrypt-e2e/src/{lib.rs,workspace_policy.rs,test_editor.rs}
tests/notecrypt-e2e/tests/{local_facade.rs,local_vault.rs,cli_journey.rs,tui_journey.rs,whole_vault.rs,git_sync.rs,presentation_journey.rs,recovery_journey.rs,plaintext_canary.rs,crash_recovery.rs}
tests/notecrypt-crypto-format/{Cargo.toml,src/lib.rs,tests/profile_integration.rs,tests/public_wire.rs}
fuzz/targets.toml
fuzz/format/{Cargo.toml,fuzz_targets/decode_header.rs,fuzz_targets/decode_object.rs,fuzz_targets/decode_manifest.rs,fuzz_targets/decode_tree.rs,fuzz_targets/decode_snapshot.rs,fuzz_targets/decode_bootstrap.rs,fuzz_targets/decode_head.rs,fuzz_targets/decode_crypto_envelope.rs}
fuzz/backend/{Cargo.toml,fuzz_targets/decode_backend_bootstrap.rs,fuzz_targets/decode_backend_head.rs,fuzz_targets/decode_backend_inventory.rs,fuzz_targets/decode_backend_response.rs}
fuzz/git/{Cargo.toml,fuzz_targets/parse_remote_url.rs,fuzz_targets/parse_config.rs,fuzz_targets/parse_commit.rs,fuzz_targets/parse_tree.rs,fuzz_targets/parse_ref.rs,fuzz_targets/parse_output.rs}
fuzz/replication/{Cargo.toml,fuzz_targets/decode_graph_metadata.rs,fuzz_targets/decode_limits.rs}
scripts/verify-fuzz-targets.sh
scripts/run-fuzz-manifest.sh
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
Permit `notecrypt-store/test-support` only through workspace dev-dependencies and make the workspace-policy test reject it from every normal, build, target, and transitive production dependency path.
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
- Test: `crates/notecrypt-crypto/tests/envelope_parts.rs`
- Test: `crates/notecrypt-crypto/tests/compile_fail/envelope_construct.rs`
- Test: `crates/notecrypt-crypto/tests/compile_fail/envelope_debug.rs`
- Test: `crates/notecrypt-crypto/tests/compile_fail/envelope_serialize.rs`

**Interfaces:**

- Produces: non-formatting secret key types.
- Produces: 128-bit generated recovery phrases, custom-passphrase policy version 1, strictly bounded Argon2id profile 1, Vault Root Key wrapping, and crypto-owned non-streaming typed contexts.

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

pub struct PublicEnvelopeIdentity {
    pub profile_id: u16,
    pub vault_id: [u8; 16],
    pub object_kind: u8,
    pub format_version: u16,
    pub object_id: [u8; 32],
}

pub struct RecoverySlotContext(PublicEnvelopeIdentity);
pub struct DeviceSlotContext(PublicEnvelopeIdentity);
pub struct MetadataContext(PublicEnvelopeIdentity);
pub struct TreeContext(PublicEnvelopeIdentity);
pub struct ManifestContext(PublicEnvelopeIdentity);
pub struct SnapshotContext(PublicEnvelopeIdentity);
pub struct AuthenticatedHeadContext(PublicEnvelopeIdentity);
pub struct LocalStateContext(PublicEnvelopeIdentity);

pub struct RecoverySlotPlaintext(Vec<u8>);
pub struct DeviceSlotPlaintext(Vec<u8>);
pub struct MetadataPlaintext(Vec<u8>);
pub struct TreePlaintext(Vec<u8>);
pub struct ManifestPlaintext(Vec<u8>);
pub struct SnapshotPlaintext(Vec<u8>);

pub struct AeadEnvelopeParts {
    identity: PublicEnvelopeIdentity,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

impl AeadEnvelopeParts {
    pub fn try_new(identity: PublicEnvelopeIdentity, nonce: &[u8], ciphertext: Vec<u8>, tag: &[u8]) -> Result<Self, CryptoError>;
    pub fn identity(&self) -> &PublicEnvelopeIdentity;
    pub fn nonce(&self) -> &[u8; 24];
    pub fn ciphertext(&self) -> &[u8];
    pub fn tag(&self) -> &[u8; 16];
}

pub trait TypedAeadEnvelope: Sized {
    fn try_from_parts(parts: AeadEnvelopeParts) -> Result<Self, CryptoError>;
    fn parts(&self) -> &AeadEnvelopeParts;
    fn into_parts(self) -> AeadEnvelopeParts;
}

pub struct RecoverySlotEnvelope(AeadEnvelopeParts);
pub struct DeviceSlotEnvelope(AeadEnvelopeParts);
pub struct MetadataEnvelope(AeadEnvelopeParts);
pub struct TreeEnvelope(AeadEnvelopeParts);
pub struct ManifestEnvelope(AeadEnvelopeParts);
pub struct SnapshotEnvelope {
    encrypted: AeadEnvelopeParts,
    outer_authenticator: [u8; 32],
}
pub struct HeadAuthenticator([u8; 32]);
pub struct LocalStateAuthenticator([u8; 32]);

impl SnapshotEnvelope {
    pub fn try_new(encrypted: AeadEnvelopeParts, outer_authenticator: &[u8]) -> Result<Self, CryptoError>;
    pub fn encrypted_parts(&self) -> &AeadEnvelopeParts;
    pub fn outer_authenticator(&self) -> &[u8; 32];
    pub fn into_parts(self) -> (AeadEnvelopeParts, [u8; 32]);
}

impl HeadAuthenticator {
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
    pub fn as_bytes(&self) -> &[u8; 32];
}

impl LocalStateAuthenticator {
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
    pub fn as_bytes(&self) -> &[u8; 32];
}

pub fn encrypt_recovery_slot(context: &RecoverySlotContext, value: RecoverySlotPlaintext, key: &RecoveryWrappingKey, random: &mut dyn SecureRandom) -> Result<RecoverySlotEnvelope, CryptoError>;
pub fn decrypt_recovery_slot(context: &RecoverySlotContext, envelope: &RecoverySlotEnvelope, key: &RecoveryWrappingKey) -> Result<RecoverySlotPlaintext, CryptoError>;
pub fn encrypt_device_slot(context: &DeviceSlotContext, value: DeviceSlotPlaintext, key: &DeviceWrappingKey, random: &mut dyn SecureRandom) -> Result<DeviceSlotEnvelope, CryptoError>;
pub fn decrypt_device_slot(context: &DeviceSlotContext, envelope: &DeviceSlotEnvelope, key: &DeviceWrappingKey) -> Result<DeviceSlotPlaintext, CryptoError>;
pub fn encrypt_metadata(context: &MetadataContext, value: MetadataPlaintext, key: &MetadataKey, random: &mut dyn SecureRandom) -> Result<MetadataEnvelope, CryptoError>;
pub fn decrypt_metadata(context: &MetadataContext, envelope: &MetadataEnvelope, key: &MetadataKey) -> Result<MetadataPlaintext, CryptoError>;
pub fn encrypt_tree(context: &TreeContext, value: TreePlaintext, key: &MetadataKey, random: &mut dyn SecureRandom) -> Result<TreeEnvelope, CryptoError>;
pub fn decrypt_tree(context: &TreeContext, envelope: &TreeEnvelope, key: &MetadataKey) -> Result<TreePlaintext, CryptoError>;
pub fn encrypt_manifest(context: &ManifestContext, value: ManifestPlaintext, key: &MetadataKey, random: &mut dyn SecureRandom) -> Result<ManifestEnvelope, CryptoError>;
pub fn decrypt_manifest(context: &ManifestContext, envelope: &ManifestEnvelope, key: &MetadataKey) -> Result<ManifestPlaintext, CryptoError>;
pub fn encrypt_snapshot(context: &SnapshotContext, value: SnapshotPlaintext, metadata_key: &MetadataKey, authentication_key: &SnapshotAuthenticationKey, random: &mut dyn SecureRandom) -> Result<SnapshotEnvelope, CryptoError>;
pub fn decrypt_snapshot(context: &SnapshotContext, envelope: &SnapshotEnvelope, metadata_key: &MetadataKey, authentication_key: &SnapshotAuthenticationKey) -> Result<SnapshotPlaintext, CryptoError>;
pub fn authenticate_head(context: &AuthenticatedHeadContext, canonical_head: &[u8], key: &SnapshotAuthenticationKey) -> Result<HeadAuthenticator, CryptoError>;
pub fn verify_head(context: &AuthenticatedHeadContext, canonical_head: &[u8], authenticator: &HeadAuthenticator, key: &SnapshotAuthenticationKey) -> Result<(), CryptoError>;
pub fn authenticate_local_state(context: &LocalStateContext, canonical_record: &[u8], key: &LocalVerificationKey) -> Result<LocalStateAuthenticator, CryptoError>;
pub fn verify_local_state(context: &LocalStateContext, canonical_record: &[u8], authenticator: &LocalStateAuthenticator, key: &LocalVerificationKey) -> Result<(), CryptoError>;

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
Each Task 3 context newtype has a checked constructor that accepts only `PublicEnvelopeIdentity` and rejects the wrong object kind or profile.
Implement `TypedAeadEnvelope` for `RecoverySlotEnvelope`, `DeviceSlotEnvelope`, `MetadataEnvelope`, `TreeEnvelope`, and `ManifestEnvelope`.
Each typed constructor validates its exact kind, profile, public identity, ciphertext bound, nonce length, and tag length before construction.
Keep every envelope and authenticator field private, expose no unchecked constructor, and implement neither formatting nor serialization.
Accessors expose only public identity, nonce, ciphertext, tag, or authenticator bytes required by Task 5 neutral conversion and never expose plaintext, a key, or protected semantics.
Encryption constructs AAD internally from the public identity, generated public nonce, and resulting ciphertext length.
No context accepts logical file or revision IDs, snapshot parents or device IDs, tree or chunk counts, total plaintext length, sequence, provider reference, or other protected semantics.
Typed plaintext constructors keep those semantics encrypted, and store conversion validates them against authenticated parent references after decryption.
Custom policy version 1 accepts 20 through 1,024 UTF-8 bytes, at least five whitespace-delimited words, no NUL, and no implicit normalization.
Set the profile floor to 65,536 KiB, three iterations, and one lane and the ceiling to 1,048,576 KiB, ten iterations, and sixteen lanes.
Construct `ValidatedArgon2idParameters` only through checked validation before allocation or integer conversion.
Calibration targets 750 to 1,500 ms, stays within both bounds, and never reduces the floor.
Check cancellation before calling Argon2id and after it returns but before returning or publishing a key.
Do not claim or simulate interruption inside one Argon2id library call.

- [ ] **Step 3: Write failing key-slot tests**

Cover generated phrase entropy and checksum, deterministic decoding, custom policy boundaries, recovery wrapping, wrong passphrase, modified salt, modified vault ID, modified algorithm identifier, independent derived subkeys, and offline-verifier disclosure text.
Round-trip each non-streaming typed envelope through its checked parts accessors, reject wrong kind, profile, nonce, tag, authenticator, and per-kind length, and use Trybuild to reject direct field construction, debug formatting, and serialization.
Test each KDF field at its minimum, maximum, maximum plus one, zero, and `u32::MAX` together with checked byte-count and platform allocation overflow.
Test cancellation before Argon2id and cancellation set after computation but before derived-key publication using an instrumented KDF seam.

- [ ] **Step 4: Implement key wrapping and derivation**

Derive metadata, snapshot-authentication, chunk-fingerprint, content-wrapping, and local-verification subkeys with distinct fixed HKDF labels.
Wrap the Vault Root Key with XChaCha20-Poly1305 using a random nonce and authenticated vault-header context.
Use the exact recovery-slot profile, nonce length, canonical AAD fields, tag length, and size limit from cryptographic profile 1.
Treat failure to generate the Vault Root Key, salt, slot ID, or nonce as a hard error with no returned bootstrap material.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p notecrypt-crypto`

Expected: generated recovery, custom policy, CSPRNG failure, secret compile-fail, KDF floors and ceilings, cancellation boundaries, and all non-streaming typed-context tests pass without format schemas.

Commit: `feat(crypto): add passphrase recovery and key hierarchy`

---

### Task 4: Implement and benchmark bounded streaming cryptography

**Files:**

- Create: `crates/notecrypt-crypto/src/stream.rs`
- Modify: `crates/notecrypt-crypto/src/lib.rs`
- Test: `crates/notecrypt-crypto/tests/stream_integrity.rs`
- Test: `crates/notecrypt-crypto/tests/chunk_envelope_parts.rs`
- Test: `crates/notecrypt-crypto/tests/compile_fail/chunk_envelope_debug.rs`
- Test: `crates/notecrypt-crypto/tests/compile_fail/chunk_fingerprint_serialize.rs`
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
pub struct EncryptedChunkDescriptor {
    pub object_id: [u8; 32],
    pub fingerprint: ChunkFingerprint,
    pub sequence: u64,
    pub plaintext_bytes: u32,
}

pub struct EncryptedChunk {
    pub descriptor: EncryptedChunkDescriptor,
    pub encoded: Vec<u8>,
}

pub struct ChunkKeyWrapContext(PublicEnvelopeIdentity);
pub struct ContentChunkContext(PublicEnvelopeIdentity);
pub struct ChunkFingerprintContext;
pub struct ChunkKeyPlaintext(secrecy::SecretBox<[u8; 32]>);
pub struct ContentChunkPlaintext(Vec<u8>);
pub struct ChunkKeyEnvelope(AeadEnvelopeParts);
pub struct ContentChunkEnvelope(AeadEnvelopeParts);
pub struct ChunkFingerprint([u8; 32]);

impl ChunkFingerprint {
    pub fn try_from_protected_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
    pub fn into_protected_bytes(self) -> [u8; 32];
}

pub fn wrap_chunk_key(context: &ChunkKeyWrapContext, value: ChunkKeyPlaintext, key: &ContentWrappingKey, random: &mut dyn SecureRandom) -> Result<ChunkKeyEnvelope, CryptoError>;
pub fn unwrap_chunk_key(context: &ChunkKeyWrapContext, envelope: &ChunkKeyEnvelope, key: &ContentWrappingKey) -> Result<ChunkKeyPlaintext, CryptoError>;
pub fn encrypt_content_chunk(context: &ContentChunkContext, value: ContentChunkPlaintext, key: &ChunkKeyPlaintext, random: &mut dyn SecureRandom) -> Result<ContentChunkEnvelope, CryptoError>;
pub fn decrypt_content_chunk(context: &ContentChunkContext, envelope: &ContentChunkEnvelope, key: &ChunkKeyPlaintext) -> Result<ContentChunkPlaintext, CryptoError>;
pub fn fingerprint_chunk(context: &ChunkFingerprintContext, protected_semantics: &[u8], plaintext: &[u8], key: &ChunkFingerprintKey) -> Result<ChunkFingerprint, CryptoError>;
pub fn verify_chunk_fingerprint(context: &ChunkFingerprintContext, protected_semantics: &[u8], plaintext: &[u8], expected: &ChunkFingerprint, key: &ChunkFingerprintKey) -> Result<(), CryptoError>;

```

Implement the Task 4 `fingerprint_chunk`, `verify_chunk_fingerprint`, `wrap_chunk_key`, `unwrap_chunk_key`, `encrypt_content_chunk`, and `decrypt_content_chunk` signatures without adding a whole-stream key-bearing API.
Implement Task 3's `TypedAeadEnvelope` contract for `ChunkKeyEnvelope` and `ContentChunkEnvelope` with exact kind, profile, public-identity, nonce, ciphertext-bound, and tag checks.
Keep `ChunkFingerprint` private-field, non-formatting, and non-serializable, accept only exactly 32 protected bytes, and expose those bytes only through its consuming protected-value accessor for Task 5 conversion.
These functions borrow key material for one bounded chunk call only.
The store owns the reader loop, session-generation checks, descriptor reuse decision, and bounded buffers in Task 6.
Generate a fresh data key, 24-byte wrapping nonce, and independent 24-byte content nonce for every newly encrypted chunk.
Use the exact content-chunk, chunk-key-wrapper, and same-position-fingerprint contexts from cryptographic profile 1.
Keep sequence, file identity, plaintext length, and comparison semantics inside encrypted manifest or chunk plaintext and never encode them in public AAD or a structured public nonce.
Encode the public chunk envelope with only object ID, independent random 24-byte nonce, ciphertext length, wrapped-key envelope when applicable, ciphertext, and tag.
Do not define or encode additional public nonce metadata.
Return keyed fingerprints only to the unlocked store pipeline so it can compare the prior descriptor at the same file position before choosing reuse or fresh encryption.
Reject plaintext above 4 MiB and keep at most two chunk buffers live per store pipeline.
Return no descriptor or encoded bytes after a CSPRNG, wrap, encryption, authentication, or length failure.
Round-trip the two chunk envelopes and fingerprint through checked constructors and accessors, reject every wrong length or kind, and use Trybuild to reject direct construction, formatting, and serialization.

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
- Create: `tests/notecrypt-crypto-format/Cargo.toml`
- Create: `tests/notecrypt-crypto-format/src/lib.rs`
- Create: `tests/notecrypt-crypto-format/tests/profile_integration.rs`
- Create: `tests/notecrypt-crypto-format/tests/public_wire.rs`
- Create: `fuzz/targets.toml`
- Create: `fuzz/format/Cargo.toml`
- Create: `fuzz/format/fuzz_targets/decode_header.rs`
- Create: `fuzz/format/fuzz_targets/decode_object.rs`
- Create: `fuzz/format/fuzz_targets/decode_manifest.rs`
- Create: `fuzz/format/fuzz_targets/decode_tree.rs`
- Create: `fuzz/format/fuzz_targets/decode_snapshot.rs`
- Create: `docs/decisions/0002-encrypted-object-format.md`
- Create: `docs/decisions/0003-chunk-reuse-leakage.md`

**Interfaces:**

- Produces: canonical version-1 encoders, format-owned numeric cryptographic identifiers, and bounded decoders.
- Produces: stable fixture bytes for bootstrap, every cryptographic-profile kind, file manifest, logical tree, snapshot, authenticated head, and local-state records.

- [ ] **Step 1: Write failing canonical-format tests**

Assert byte-for-byte deterministic encoding, rejection of indefinite collections, duplicate fields, unknown critical fields, trailing bytes, unsupported major versions, oversized collections, and integer overflow.
Keep package tests structural and canonical only, including numeric identifiers, public-field placement, nonce and tag lengths, ciphertext length, bounds, and rejection of protected semantic fields in public envelopes.
Create and run the neutral integration package in this task after schemas exist and before fixtures freeze.

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
For non-chunk AEAD envelopes expose only profile ID, vault ID, object kind, format version, object ID, nonce, and ciphertext length when applicable.
Encode logical IDs, graph references, counts, sequence, plaintext lengths, and other protected semantics only inside ciphertext.
Encode each public chunk envelope with only its random object identity, fresh random 24-byte nonce, ciphertext length, wrapped-key envelope when applicable, ciphertext, and authentication tag.
Encode chunk sequence and plaintext length inside the encrypted payload, and define no additional public nonce metadata.
Encode each encrypted revision manifest with ordered chunk identities, keyed plaintext fingerprints, per-chunk lengths, and total plaintext length.
Encode recovery slots, device slots, metadata, trees, manifests, snapshots, authenticated heads, chunk-key wrappers, content chunks, and local-state records with their exact profile identifiers, nonce lengths, tag lengths, and per-kind bounds.

- [ ] **Step 4: Prove cross-format confidentiality and integration**

Build the neutral `notecrypt-crypto-format-tests` package with dependencies on `notecrypt-format` and `notecrypt-crypto` and no dependency on store or service.
Round-trip every profile row between canonical format envelopes and the exact Task 3 and Task 4 typed crypto APIs.
Convert every named crypto-owned envelope, authenticator, and fingerprint through only its checked constructor and accessor surface and prove canonical format conversion needs no private-field or secret access.
Prove cross-kind, cross-vault, wrong-object, wrong-version, wrong-length, wrong-slot, modified public AAD, modified ciphertext, and modified authenticator rejection.
Scan public wire bytes to prove logical file and revision IDs, snapshot parents and device IDs, tree entry counts, chunk counts, total plaintext lengths, content sequence, graph shape, and per-file structure do not appear.

- [ ] **Step 5: Add chunk-reuse security decision**

Record that phase 1 reuses unchanged fixed-size chunks within the same logical file so aligned or in-place edits avoid re-encrypting unchanged regions.
Record that insertion or deletion can shift subsequent boundaries and require re-encrypting the remainder of the file.
Record the leak of unchanged fixed-size regions across revisions, the absence of cross-file deduplication, and the rejected alternative of full-file re-encryption on every save.

- [ ] **Step 6: Generate and lock golden fixtures**

Generate each fixture once from deterministic test keys and non-sensitive canary text after the complete cross-context test matrix passes.
Check fixture hashes into the golden test and prohibit fixture replacement without an explicit format-version decision.

- [ ] **Step 7: Create and smoke-test the format fuzz project**

Create `fuzz/format/Cargo.toml` with cargo-fuzz target entries for header, object, manifest, tree, and snapshot decoding.
Create the root `fuzz/targets.toml` as the sole inventory, list each initial format target exactly once, and assign `decode_object` only to the format tree.
Set allocation and recursion limits before decoding attacker-controlled lengths.
Pin execution to `nightly-2026-08-01` and cargo-fuzz `0.13.1`, fail if `cargo fuzz --version` is not exactly compatible, and run through `cargo +nightly-2026-08-01 fuzz` only.

- [ ] **Step 8: Verify and commit**

Run: `cargo test -p notecrypt-format && cargo test -p notecrypt-crypto-format-tests`

Run: `rustup toolchain install nightly-2026-08-01 --profile minimal && cargo install cargo-fuzz --version 0.13.1 --locked && test "$(cargo +nightly-2026-08-01 fuzz --version)" = "cargo-fuzz 0.13.1" && cargo +nightly-2026-08-01 fuzz run --fuzz-dir fuzz/format decode_object -- -max_total_time=60`

Expected: profile, neutral cross-format, public-wire, canonical, malformed, and golden tests pass, the pinned tool versions match exactly, and the bounded format fuzz run finds no crash or unbounded allocation.

Commit: `feat(format): define versioned encrypted vault formats`

---

### Task 6: Build crash-consistent encrypted local storage

**Files:**

- Modify: `crates/notecrypt-store/Cargo.toml`
- Create: `crates/notecrypt-store/src/error.rs`
- Create: `crates/notecrypt-store/src/layout.rs`
- Create: `crates/notecrypt-store/src/repository.rs`
- Create: `crates/notecrypt-store/src/journal.rs`
- Create: `crates/notecrypt-store/src/transaction.rs`
- Create: `crates/notecrypt-store/src/recovery.rs`
- Create: `crates/notecrypt-store/src/trusted_state.rs`
- Create: `crates/notecrypt-store/src/cleanup.rs`
- Create: `crates/notecrypt-store/src/replication.rs`
- Create: `crates/notecrypt-store/src/test_support.rs`
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
- Test: `crates/notecrypt-store/tests/reachability_tokens.rs`
- Test: `crates/notecrypt-store/tests/compile_fail/reachability_construct.rs`
- Test: `crates/notecrypt-store/tests/compile_fail/reachability_clone.rs`
- Test: `crates/notecrypt-store/tests/compile_fail/reachability_serialize.rs`
- Test: `crates/notecrypt-store/tests/compile_fail/reachability_debug.rs`
- Test: `crates/notecrypt-store/tests/compromise_capabilities.rs`
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
    fn initialize(&self, request: InitializeRepository) -> Result<RepositorySnapshot, StoreError>;
    fn begin_pending_target(&self, request: BeginPendingVaultTarget) -> Result<Box<dyn PendingVaultTarget>, StoreError>;
    fn unlock(&self, request: UnlockRepository) -> Result<Box<dyn UnlockedVault>, StoreError>;
    fn list_device_slots(&self) -> Result<Vec<LocalDeviceSlotRecord>, StoreError>;
}

pub trait UnlockedVault: Send + Sync {
    fn acquire_lease(&self) -> Result<Box<dyn UnlockedVaultLease>, StoreError>;
    fn acquire_replication_lease(
        &self,
        limits: ReplicationLimits,
    ) -> Result<Box<dyn ReplicationLease>, StoreError>;
    fn acquire_compromise_rekey_source(&self) -> Result<Box<dyn CompromiseRekeySource>, StoreError>;
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
    fn verify_reachable(
        &self,
        head: &AuthenticatedHead,
        observation: BackendObservationFingerprint,
        operation: ReplicationOperationId,
        visitor: &mut dyn ReachableObjectVisitor,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<VerifiedReachableHead, StoreError>;
    fn export_encrypted(
        &self,
        id: &ObjectId,
        output: &mut dyn std::io::Write,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, StoreError>;
    fn commit_replicated_snapshot(
        &self,
        verified: VerifiedReachableHead,
        input: CommitReplicatedSnapshot,
    ) -> Result<CommittedReachableHead, StoreError>;
    fn accept_current_verified(
        &self,
        verified: VerifiedReachableHead,
    ) -> Result<CommittedReachableHead, StoreError>;
    fn record_trusted_remote(
        &self,
        committed: CommittedReachableHead,
        provenance: TrustedRemoteProvenance,
    ) -> Result<(), StoreError>;
}

pub struct BackendObservationFingerprint(Vec<u8>);
struct VerifiedReachableBinding {
    vault: VaultId,
    session_generation: u64,
    bootstrap_commitment: [u8; 32],
    head_commitment: [u8; 32],
    reachable_set_commitment: [u8; 32],
    effective_limits_commitment: [u8; 32],
    observation: BackendObservationFingerprint,
    operation: ReplicationOperationId,
}
enum CommittedTransition {
    FastForward,
    Reconciled,
    NoLocalCommit,
}
struct CommittedReachableBinding {
    verified: VerifiedReachableBinding,
    local_snapshot: SnapshotId,
    transition: CommittedTransition,
}
pub struct VerifiedReachableHead {
    binding: VerifiedReachableBinding,
}
pub struct CommittedReachableHead {
    binding: CommittedReachableBinding,
}
pub struct ReplicationOperationId([u8; 16]);

pub enum TrustedRemoteProvenance {
    FreshnessProven,
    FreshnessUnprovableAcknowledged,
}

pub trait CompromiseRekeySource: Send {
    fn next_entry(&mut self) -> Result<Option<AuthenticatedLogicalEntry>, StoreError>;
    fn stream_plaintext(
        &mut self,
        entry: &AuthenticatedLogicalEntry,
        output: &mut dyn std::io::Write,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, StoreError>;
}

pub trait PendingVaultTarget: Send {
    fn stage_entry(
        &mut self,
        source: &mut dyn std::io::Read,
        logical_metadata: NewLogicalIdentity,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<StagedTargetEntry, StoreError>;
    fn verify_complete(&mut self, cancel: &std::sync::atomic::AtomicBool) -> Result<(), StoreError>;
    fn activate(self: Box<Self>) -> Result<ActivatedVaultTarget, StoreError>;
    fn abort(self: Box<Self>) -> Result<(), StoreError>;
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
Keep `VerifiedReachableBinding` and `CommittedReachableBinding` private to `notecrypt-store`, expose no token constructor or public field, and construct tokens only after the corresponding store-owned verification or commit transition succeeds.
Make `VerifiedReachableHead`, `CommittedReachableHead`, `CompromiseRekeySource`, and `PendingVaultTarget` non-cloneable, non-serializable, non-formatting, non-defaultable, and bound to the active session generation.
Bind `VerifiedReachableHead` to the vault, authenticated bootstrap and head, exact reachable identities, effective limits, canonical `BackendObservationFingerprint`, and operation ID.
Require the consuming sequence `verify_reachable` to either `commit_replicated_snapshot` or `accept_current_verified`, then to consuming `record_trusted_remote`.
Map a successfully applied `ReplicatedCommitMode` into private `CommittedTransition::FastForward` or `CommittedTransition::Reconciled`, and make `accept_current_verified` construct only `CommittedTransition::NoLocalCommit` after proving the local head is already current.
Never retain caller-supplied `ReplicatedCommitMode` inside `CommittedReachableBinding`.
Reject partial traversal, stale generation, changed limits, changed observation, changed operation, duplicate use, or unmatched provenance before local or trusted-remote state changes.
Use Trybuild callers outside the store crate to prove construction, clone, serialization, and debug formatting fail for both proof types.
Use runtime tests to prove token reuse and every vault, generation, bootstrap, head, reachable-set, limits, observation, operation, and provenance mismatch fail closed.
Behind the development-only `test-support` feature, expose a scripted repository that accepts test graph inputs but obtains proof tokens only by executing the same private store verification and transition code as production.
Do not expose a token factory or binding constructor through `test-support`.
Let the scripted repository request a replay attempt by prior operation ID so the store can exercise its spent-token registry without returning or reconstructing a token.
`PendingVaultTarget` uses a distinct empty target and all-new vault, root, recovery, logical, revision, and object identities, cleans staged state on abort or drop, activates only after complete verification, and cannot be reused after abort or activation.
Reject source and target aliasing and any old identity, object, parent, or history in target staging.
Keep all raw `VaultStore` helpers crate-private.
`enroll_device_slot` performs root-key wrapping, local-record authentication, and atomic persistence inside the store because only that capability may access both the root key and supplied device-wrapping key.
`begin_close` rejects new leases and makes existing leases fail with `StoreError::Locked` at the next chunk or transaction boundary.
`close` zeroizes the central cell even if cancelled worker objects have not yet dropped.
Set `ReplicationLimits::PHASE_1` to 1 MiB bootstrap, 64 KiB head, 4 MiB plus 4 KiB chunk object, 64 MiB manifest, 256 MiB tree, 1 MiB snapshot, 1 TiB aggregate, 10,000,000 objects, 100,000 graph edges, 30 minutes total, 30 seconds progress interval, the smaller of 1 TiB and 80 percent of starting free space for quarantine, and a 1 GiB free-space reserve.
Apply the strictest store profile, backend capability, and available-space limit for each operation.
On cancellation, lock, timeout, stalled progress, authentication failure, or any budget failure, remove that operation's quarantine tree before returning.
Workspace lifecycle is reserve, authenticated register, adapter creation and permission verification, authenticated activate, plaintext use, adapter removal and absence verification, then authenticated unregister.
At startup `WorkspaceProvider::cleanup_owned_base` holds the OS-backed base coordination lock, enumerates only direct random-ID children below the fixed canonical Notecrypt-owned base without following links, attempts each per-workspace ownership lock non-blockingly, and skips held live workspaces without treating them as failures.
Cleanup exposes no unlock until every unheld owned workspace is safely removed, while a held live workspace remains protected by its lifetime ownership guard.
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
Exercise partial traversal, stale session, different effective limits, different observation fingerprints, different operation IDs, proof reuse, fast-forward, reconciliation, exact no-local-commit construction, rejection of caller-selected no-local-commit state, commit failure, record failure, and attempted trusted-state advancement without the exact linear token sequence.
Exercise source and target aliasing, partial activation, old identity injection, old history injection, abort cleanup, activation reuse, abort reuse, and revocation while streaming compromise plaintext.
Exercise startup base enumeration, reserve/register/activate/remove/unregister failures, stale records, symlinks, junctions, reparse points, and attempts to register arbitrary paths.

- [ ] **Step 6: Benchmark transaction overhead**

Measure object publication separately from cryptography for 1 KiB, 1 MiB, 100 MiB, 10,000 tiny objects, cold cache, and warm cache.

- [ ] **Step 7: Verify and commit**

Run: `cargo test -p notecrypt-store --test transaction_faults --test rollback --test chunk_revocation --test cleanup_lifecycle --test replication_limits --test reachability_tokens --test compromise_capabilities && cargo bench -p notecrypt-benches --bench store`

Expected: all fault points recover to a valid authenticated head, revoked chunks never publish, proof tokens cannot be forged or reused, the test-support seam runs production verification, replication budgets clean quarantine, and cleanup remains confined to the fixed base.

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

Recovery initialization, confirmation, unlock, compromise-rekey recovery confirmation, and post-authentication freshness acknowledgement do not implement `Command` or `OperationResult` and use the dedicated linear bridges defined in Task 9.

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
- Test: `crates/notecrypt-service/tests/recovery_secret_boundary.rs`
- Test: `crates/notecrypt-service/tests/compile_fail/recovery_secret_command.rs`
- Test: `crates/notecrypt-service/tests/compile_fail/recovery_presentation_clone.rs`
- Test: `crates/notecrypt-service/tests/compile_fail/recovery_presentation_forge.rs`
- Test: `crates/notecrypt-service/tests/compile_fail/recovery_presentation_dto.rs`
- Test: `crates/notecrypt-service/tests/compile_fail/pending_security_transition_forge.rs`

**Interfaces:**

- Consumes: an injected `Arc<dyn VaultRepository>` that returns an opaque `UnlockedVault` capability.
- Produces: session policies, scoped capability ownership, the dedicated recovery-secret bridge, and every consumer-owned host-port DTO and trait.

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
    ownership: Box<dyn WorkspaceOwnershipGuard>,
}

pub trait WorkspaceOwnershipGuard: Send {}

pub struct StartupCleanupReport {
    pub removed: usize,
    pub skipped_live: usize,
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
pub struct RecoverySecretInput(zeroize::Zeroizing<Vec<u8>>);
pub struct RecoverySecretPresentation {
    generation: u64,
    payload: zeroize::Zeroizing<Vec<u8>>,
}
struct PendingTransitionGuard {
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub struct PendingRecoveryInitialization {
    generation: u64,
    operation: OperationId,
    guard: PendingTransitionGuard,
}
pub struct PendingCompromiseRekey {
    generation: u64,
    operation: OperationId,
    guard: PendingTransitionGuard,
}
pub struct PendingFreshnessAcknowledgement {
    generation: u64,
    operation: OperationId,
    guard: PendingTransitionGuard,
}
pub struct FreshnessAcknowledgementView {
    pub warning_code: &'static str,
    pub authenticated_snapshot: SnapshotId,
    pub consequence: &'static str,
}

impl RecoverySecretInput {
    pub fn from_protected_bytes(bytes: Vec<u8>) -> Result<Self, HostPortError>;
    pub(crate) fn into_crypto_passphrase(self) -> notecrypt_crypto::RecoveryPassphrase;
    pub(crate) fn into_store_unlock(self) -> UnlockRepositorySecret;
}

impl RecoverySecretPresentation {
    pub fn present_once(self, presenter: &mut dyn RecoverySecretPresenter) -> Result<(), HostPortError>;
}

pub trait RecoverySecretPresenter: Send {
    fn present(&mut self, secret: &[u8]) -> Result<(), HostPortError>;
}

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
    fn cleanup_owned_base(&self) -> Result<StartupCleanupReport, HostPortError>;
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

impl ServiceHandle {
    pub fn begin_recovery_initialization(
        &self,
        request: BeginRecoveryInitialization,
    ) -> Result<(PendingRecoveryInitialization, Option<RecoverySecretPresentation>), ServiceError>;
    pub fn confirm_recovery_initialization(
        &self,
        pending: PendingRecoveryInitialization,
        confirmation: RecoverySecretInput,
    ) -> Result<VaultSummary, ServiceError>;
    pub fn cancel_recovery_initialization(
        &self,
        pending: PendingRecoveryInitialization,
    ) -> Result<(), ServiceError>;
    pub fn unlock_with_recovery(
        &self,
        secret: RecoverySecretInput,
    ) -> Result<SessionSummary, ServiceError>;
    pub fn begin_compromise_rekey(
        &self,
        request: BeginCompromiseRekey,
    ) -> Result<(PendingCompromiseRekey, Option<RecoverySecretPresentation>), ServiceError>;
    pub fn confirm_compromise_rekey(
        &self,
        pending: PendingCompromiseRekey,
        confirmation: RecoverySecretInput,
    ) -> Result<OperationHandle, ServiceError>;
    pub fn cancel_compromise_rekey(
        &self,
        pending: PendingCompromiseRekey,
    ) -> Result<(), ServiceError>;
    pub fn begin_freshness_acknowledgement(
        &self,
        operation: OperationId,
    ) -> Result<(PendingFreshnessAcknowledgement, FreshnessAcknowledgementView), ServiceError>;
    pub fn acknowledge_unprovable_freshness(
        &self,
        pending: PendingFreshnessAcknowledgement,
    ) -> Result<(), ServiceError>;
    pub fn cancel_freshness_acknowledgement(
        &self,
        pending: PendingFreshnessAcknowledgement,
    ) -> Result<(), ServiceError>;
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
The provider never accepts a caller-supplied base or cleanup path.
It holds a short-lived OS-backed base coordination lock during enumeration and creation and acquires the per-workspace ownership lock before releasing that base lock.
`WorkspaceLease` retains the ownership guard until verified removal.
`cleanup_owned_base` holds the base lock, attempts each ownership lock non-blockingly, removes only acquired workspaces, skips held locks as live, and never treats PID or timestamp metadata as deletion authority.
Use Unix `flock` or `fcntl` and Windows file-sharing or `LockFileEx` through this service-owned port.
Make `RecoverySecretInput` zeroizing, bounded to 1,024 bytes, non-cloneable, non-formatting, and non-serializable.
Give `RecoverySecretPresentation`, `PendingRecoveryInitialization`, `PendingCompromiseRekey`, and `PendingFreshnessAcknowledgement` private fields, crate-private constructors, non-forgeable session-generation and operation bindings, and no clone, formatting, serialization, default, or general DTO conversion.
Make `RecoverySecretPresentation` own its zeroizing payload, consume itself through `present_once`, and zeroize unpresented or failed payload bytes on drop.
Keep `PendingTransitionGuard` private to the service and make its drop path atomically cancel the exact still-pending operation before releasing any staged secret or target state.
Make every pending transition consuming and linear.
Dropping or cancelling pending initialization or compromise rekey aborts and cleans unpublished target state, while dropping or cancelling pending freshness acknowledgement records no baseline or provenance.
Keep `BeginCompromiseRekey` free of secret material so it carries only validated target selection and recovery-policy choice.
Allow `begin_freshness_acknowledgement` only for the exact operation paused after complete graph authentication at `FreshnessUnprovable`, and return only the safe non-secret explanatory view.
Make all secret and pending types impossible to embed in `Command`, `OperationResult`, `OperationEvent`, `ServiceSnapshot`, JSON output, logs, or diagnostics.
The narrow consuming conversions are crate-private and expose no borrowed secret bytes outside the conversion call.
Make `DeviceUnlockSecret` non-cloneable and non-formatting, and do not expose `secrecy` or raw key bytes through the port.
Give the service an internal consuming conversion from `DeviceUnlockSecret` to the store's `DeviceWrappingKey` input without exposing bytes to a UI or loggable DTO.
Permit the service crate's otherwise narrow dependency on `notecrypt-crypto` only for the recovery and device secret bridges, and enforce with compile-fail dependency tests that no general service or UI DTO exposes either.
Provide fake implementations for service tests and an unavailable device-unlock implementation for Checkpoint A.

- [ ] **Step 2: Write failing unlock and lock tests**

Cover wrong passphrase, KDF cancellation before start and after computation before publication, one-time recovery presentation, second-presentation refusal, presentation and pending-state forgery, clone, formatting, serialization, DTO compile failures, stale generation, wrong operation, drop cleanup, cancel cleanup, saturated ordinary queue, pre-unlock fixed-base cleanup failure, live-workspace skip, inactivity timeout, absolute deadline, explicit lock, system suspend notification, coalesced trusted TUI activity, cleanup failure, and a pending durable save.
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
Run `WorkspaceProvider::cleanup_owned_base` before entering `Unlocking` and expose no unlocked session while that coordination pass is incomplete.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p notecrypt-service && cargo test -p notecrypt-service --test recovery_secret_boundary`

Expected: responsiveness and deadline tests pass without sleeping on arbitrary timing assumptions, and recovery presentation plus every pending security transition is non-forgeable, generation-bound, linear, secret-safe, and fail-closed on drop.

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

Exercise begin-initialize, confirmation, cancellation, and unlock through the dedicated `ServiceHandle` recovery-secret methods and status, list, lock control, and reopen through ordinary commands against a temporary `VaultStore`.
Assert the exact dedicated result or ordinary `OperationResult`, event sequence, error category, session-state transition, and repository-head transition for each operation.
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
- Test: `adapters/notecrypt-editor-workspace/tests/ownership_locks.rs`

**Interfaces:**

- Consumes: service-owned `WorkspaceProvider`, `EditorSupervisor`, and their request and result DTOs.
- Produces: secure workspace and editor-supervision adapters without creating adapter-owned contract types.

- [ ] **Step 1: Write failing workspace-boundary tests**

Assert that workspaces are direct random-ID children of the fixed canonical Notecrypt-owned base, paths are outside the repository, permissions are restrictive, random names reveal no logical filename, authenticated register and activate precede plaintext creation, materialized files publish atomically with suppression generations, arming establishes a baseline, and indexing exclusions are attempted without claiming guarantees.
Reject arbitrary bases and paths, nested cleanup targets, preexisting children, symlinks, junctions, reparse points, and workspace IDs not reserved by the store capability.
Use two processes to cover simultaneous creation and cleanup, held ownership skip, crashed-owner lock release, PID reuse, stale records, base-lock failure, ownership-lock failure, and cleanup retry.

- [ ] **Step 2: Implement the service-owned workspace ports**

Implement `WorkspaceProvider` and `WorkspaceWatch` from `notecrypt-service` without redefining their types in the adapter.
Consume a store-reserved ID, let the store authenticate registered state, create only the derived fixed-base child, verify restrictive permissions, let the store activate the record, and write no plaintext before activation.
Hold the short-lived base lock while creating the child and acquiring its ownership lock, keep the ownership guard inside `WorkspaceLease` for the complete plaintext lifetime, and release it only after verified removal.
Cleanup holds the base lock and attempts ownership locks non-blockingly, skips held live workspaces without failure, and deletes only after acquiring ownership.
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

Run: `cargo test -p notecrypt-editor-workspace --test editor_profiles --test workspace_boundary --test ownership_locks`

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
Test the dedicated `RecoverySecretPresentation` is consumed once and a second presentation attempt is impossible through the built CLI harness.
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
Test the TUI consumes `RecoverySecretPresentation` exactly once and cannot recover it from app state, view models, events, snapshots, or render fixtures after leaving the presentation screen.
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
- Modify: `apps/notecrypt-cli/src/output.rs`
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
- Modify: `crates/notecrypt-replication/Cargo.toml`
- Modify: `crates/notecrypt-replication/src/lib.rs`
- Modify: `crates/notecrypt-service/src/command.rs`
- Modify: `crates/notecrypt-service/src/service.rs`
- Test: `crates/notecrypt-replication/tests/sync_matrix.rs`
- Test: `crates/notecrypt-replication/tests/migration.rs`
- Test: `crates/notecrypt-replication/tests/limits.rs`
- Test: `crates/notecrypt-replication/tests/reachability_proof.rs`
- Test: `crates/notecrypt-replication/tests/compromise_rekey.rs`
- Test: `crates/notecrypt-service/tests/recovery_freshness.rs`
- Test: `crates/notecrypt-service/tests/security_transitions.rs`

**Interfaces:**

- Consumes: `VaultBackend`, bounded immutable bootstrap operations, an object-safe revocable `ReplicationLease`, and deterministic core reconciliation.
- Produces: linear budgeted authenticated fetch, reconciliation, conditional publish, retry, clean-device freshness gating, in-memory `BackendCopy`, and history-free `CompromiseRekey` state-machine proof.
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
Perform bounded existence checks, authenticated imports returning typed referenced-object metadata, authenticated snapshot, tree, and manifest reads, reachable verification, encrypted export, replicated snapshot commits, and trusted-remote recording only through the object-safe revocable lease supplied by the active service session.
Use the strictest profile-1, backend-advertised, and available-space limit for every object kind, aggregate bytes, object count, graph depth, timeout, progress interval, and quarantine disk.
Treat `StoreError::Locked` as cancellation and never retain a raw `VaultStore` handle in replication state.
Begin a backend publication with the observed head version, stream missing immutable objects through bounded `stage_object` calls, and commit the authenticated replacement head.
Treat a stale publication result as a refetch and reconciliation retry.
Treat an indeterminate publication result by rereading the remote head and authenticating it before deciding whether the attempted replacement committed or needs reconciliation.
Convert the backend observation into bounded canonical `BackendObservationFingerprint` bytes, call `verify_reachable`, consume its `VerifiedReachableHead` through either `commit_replicated_snapshot` or `accept_current_verified`, then consume `CommittedReachableHead` through `record_trusted_remote`.
Verify the bootstrap, published head, and complete reachable graph through independent readback before beginning this linear sequence or reporting sync success.
Reject partial, stale, differently limited, differently observed, differently identified, revoked, or reused proofs without advancing local or trusted-remote state.
Remove quarantine on cancellation, lock, timeout, stalled trickle input, authentication failure, or any limit failure.

For a clean device, return `RecoveryFreshness::UnprovableOnCleanDevice` after graph verification and before `record_trusted_remote` establishes the first baseline.
Keep `RecoveryFreshness::Proven`, `RecoveryFreshness::UnprovableOnCleanDevice`, and `RollbackDetected` as distinct typed outcomes.
Pause the exact service operation at this post-authentication gate and require `begin_freshness_acknowledgement` to return its generation-bound pending capability and safe explanatory DTO.
Only consuming `acknowledge_unprovable_freshness` may resume the operation with `TrustedRemoteProvenance::FreshnessUnprovableAcknowledged`; cancel, drop, or mismatch fails closed and consumes no proof into trusted state.

```rust
pub enum RecoveryFreshness {
    Proven,
    UnprovableOnCleanDevice {
        snapshot: SnapshotId,
        observation: BackendObservationFingerprint,
    },
}
```

- [ ] **Step 4: Implement conflict preservation**

Use the core deterministic result to commit a two-parent snapshot.
Emit conflict events containing unlocked logical details only to the active local session.
Expose typed conflict inspection and explicit keep-local, keep-remote, keep-both, rename, and tombstone-aware resolution requests without merging file bytes.

- [ ] **Step 5: Implement `BackendCopy` and `CompromiseRekey`**

Define `BackendCopy` as migration of the same vault ID, Vault Root Key, bootstrap, authenticated Notecrypt snapshot graph, and encrypted objects to a separately configured backend.
Do not promise identical backend-native Git commit IDs or history.
Persist source head, target backend identity, verified object cursor, bootstrap state, and target head state outside the vault repository.
Transfer and independently read back the immutable bootstrap, authenticate and copy every reachable encrypted object, publish the same head conditionally, and switch the active backend only after the target graph verifies.
Acquire a revocable `CompromiseRekeySource` that enumerates authenticated logical entries and streams bounded plaintext from the active source session.
Create a linear `PendingVaultTarget` with a distinct empty target, new vault ID, Vault Root Key, generated or explicitly confirmed custom recovery credential, file and revision identities, object identities, bootstrap, staged objects, verification, abort cleanup, and one-way activation.
Enter this flow only through `begin_compromise_rekey`, present generated recovery only through the returned `RecoverySecretPresentation`, and require consuming `confirm_compromise_rekey` with `RecoverySecretInput` before streaming or activation.
Make `cancel_compromise_rekey` and pending-capability drop abort and clean every unpublished target artifact.
Stream current authenticated plaintext from the source capability into fresh target encryption without copying any old wrapper, identity, object, snapshot parent, Git commit, or backend history.
Reject source and target aliasing, non-empty targets, partial activation, reuse after abort or activation, and state explicitly that already exposed ciphertext and keys cannot be made confidential again.
Never route suspected compromise to `BackendCopy` or recovery-slot rewrapping.

Use the in-memory backend to prove abort cleanup, drop cleanup, complete verification before activation, revocation, source-target distinction, new logical identities, parentless target head, and one-time capability consumption.

- [ ] **Step 6: Prove linear replication, freshness, copy, and rekey contracts**

Use the in-memory backend and the store-internal scripted repository enabled only by the `notecrypt-store/test-support` dev-dependency to prove the exact `VerifiedReachableHead` to `CommittedReachableHead` to trusted-remote sequence, including the explicit no-local-commit transition.
The scripted repository must obtain tokens only by running the same store-owned verification seam and cannot construct or mutate token bindings.
Prove partial, stale, differently limited, differently observed, differently operated, revoked, or reused tokens cannot advance state.
Prove an older but cryptographically valid clean-device remote returns `FreshnessUnprovable`, establishes no baseline on pending-capability forgery, mismatch, cancel, or drop, records unprovable provenance only after consuming acknowledgement, and is never labeled latest or verified-fresh.
Prove `BackendCopy` preserves the Notecrypt snapshot graph without promising backend-native history and prove `CompromiseRekeySource` and `PendingVaultTarget` state transitions entirely against in-memory backends.

- [ ] **Step 7: Verify Checkpoint B and commit**

Run: `cargo test -p notecrypt-core && cargo test -p notecrypt-replication --test sync_matrix --test migration --test limits --test reachability_proof --test compromise_rekey && cargo test -p notecrypt-service --test recovery_freshness --test security_transitions`

Expected: bounded sync preserves authenticated content, limits clean quarantine, the dev-only scripted repository cannot forge proof tokens, linear proofs prevent misuse, freshness acknowledgement records exact provenance only after consuming confirmation, `security_transitions` gates compromise-rekey credentials plus pending-capability forge, mismatch, cancel, and drop behavior, backend copy preserves the Notecrypt graph, compromise rekey creates a distinct verified history-free target, and no stale head is overwritten.

Commit: `feat(sync): add authenticated replication and conflicts`

---

### Task 18: Implement the Git backend, onboarding hooks, and verified backup

**Files:**

- Create: `adapters/notecrypt-backend-git/src/error.rs`
- Create: `adapters/notecrypt-backend-git/src/runner.rs`
- Create: `adapters/notecrypt-backend-git/src/repository.rs`
- Create: `adapters/notecrypt-backend-git/src/backend.rs`
- Create: `adapters/notecrypt-backend-git/src/hooks.rs`
- Create: `adapters/notecrypt-backend-git/src/auth.rs`
- Create: `adapters/notecrypt-backend-git/src/limits.rs`
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
- Test: `adapters/notecrypt-backend-git/tests/transport_auth.rs`
- Test: `adapters/notecrypt-backend-git/tests/verification_limits.rs`
- Test: `tests/notecrypt-e2e/tests/git_sync.rs`
- Create: `tests/notecrypt-e2e/tests/presentation_journey.rs`
- Create: `tests/notecrypt-e2e/tests/recovery_journey.rs`
- Test: `tests/notecrypt-e2e/tests/plaintext_canary.rs`

**Interfaces:**

- Produces: `GitBackend` implementing the complete backend conformance suite.
- Produces: fully parsed and presented `notecrypt vault onboard`, `notecrypt sync`, and `notecrypt vault backup` CLI and TUI journeys with verified bootstrap, history, and graph readback.

- [ ] **Step 1: Write failing Git runner security tests**

Use a fake executable to capture argument boundaries.
Test spaces, leading dashes, Unicode, malicious remote names, ref injection, shell metacharacters, hostile Git output, non-repository paths, unexpected worktree layout, hostile hooks, `include` and `includeIf`, aliases, filters, submodules, pagers, custom SSH commands, external remote helpers, inherited `GIT_*` variables, replace objects, repository alternates, and local `file` transport without the separate local capability.
Test successful HTTPS through only the trusted Git-shipped helper under the selected Git installation's canonical exec path, successful SSH through one approved canonical executable with controlled arguments and the approved agent connection, and successful use of one selected trusted credential provider imported into isolated configuration.
Reject every non-allowlisted or repository-controlled helper, credential provider, SSH executable, exec-path substitution, configuration, hook, filter, replace reference, pager, and environment substitution.
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
    pub verification_limits: Option<GitVerificationLimits>,
}

pub struct GitVerificationLimits {
    pub max_pack_bytes: u64,
    pub max_inflated_object_bytes: u64,
    pub max_aggregate_expanded_bytes: u64,
    pub max_quarantine_bytes: u64,
    pub max_object_count: u64,
    pub max_commit_count: u64,
    pub max_ancestry_depth: u32,
    pub max_delta_depth: u32,
    pub max_process_tree_rss_bytes: u64,
    pub max_process_address_space_bytes: u64,
    pub max_processes: u32,
    pub max_worker_threads_per_process: u32,
    pub max_total_threads_per_process: u32,
    pub max_aggregate_process_tree_cpu: std::time::Duration,
    pub max_wall_time: std::time::Duration,
    pub progress_interval: std::time::Duration,
    pub free_space_reserve_bytes: u64,
}
```

Invoke `git` directly with argument arrays.
Use this one runner policy for onboarding, fetch, sync, backup, `BackendCopy`, and recovery.
Use exact built-in subcommands, validated remote and branch names, literal pathspec handling, bounded output capture, cancellation, and a sanitized environment.
Remove every inherited `GIT_*` variable, then set only Notecrypt-controlled `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `GIT_TERMINAL_PROMPT`, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_GLOBAL`, and `GIT_PAGER` values.
For every invocation set `core.hooksPath` to an empty trusted Notecrypt-owned directory, disable pagers and replace objects, use `push --no-verify` for internal publication, bypass system and global configuration, and reject local includes or any key outside the documented allowlist.
Reject aliases, filters, submodules, custom SSH commands, repository alternates, unknown remote-helper schemes, `ext`, and local `file` transport unless the caller holds the separate local or test capability.
Allow only explicitly configured HTTPS or SSH remotes for normal operations and set protocol policy to deny everything else.
Resolve only the canonical allowlisted Git-shipped HTTPS helper below the selected Git executable's canonical exec path.
Invoke one explicitly approved canonical SSH executable with controlled arguments and import only the approved SSH agent connection.
Generate an isolated configuration containing exactly one canonical allowlisted selected trusted credential provider and no repository-controlled credential keys.
Reject every other helper or provider, including non-allowlisted, repository-controlled, path-substituted, and remote-scheme-selected helpers.
Never execute Git aliases, hooks, non-allowlisted external helpers, pagers, filters, or a shell.
Before every operation validate the repository marker, canonical absolute Git directory, worktree relationship, dedicated branch, configured remote, selected transport, and complete allowed local configuration.
Set `GitVerificationLimits::PHASE_1` to 1 TiB raw pack bytes, 256 MiB for one inflated object, 1 TiB aggregate expanded bytes reduced further by available space and operation limits, the smaller of 1 TiB and 80 percent of starting free space for quarantine, 20,000,000 Git objects, 100,000 commits, 100,000 ancestry edges, delta depth 50, 1 GiB aggregate process-tree RSS, 1.5 GiB per-process address space, 8 processes, 2 worker threads and 3 total threads per process, 3,600 seconds aggregate process-tree CPU, 30 minutes wall time, 30 seconds progress interval, and a 1 GiB free-space reserve.

- [ ] **Step 3: Implement Git backend conformance**

Implement onboarding for a local encrypted vault that is not yet a Git repository and recovery into a clean dedicated clone.
Create or read the bounded immutable bootstrap first, reject any mismatch, and require independent bootstrap readback for onboarding, backup, `BackendCopy`, and clean-device recovery.
Create and validate one dedicated branch with no unrelated files or history, and reject embedding in a general-purpose repository.
Implement `begin_publication` as an isolated local Git publication state rooted at the observed dedicated-branch commit and addressed through a private temporary ref.
Implement `stage_object` with `git hash-object -w --no-filters` and retain the resulting object-to-path mapping only in that publication state.
On commit, construct validated trees with `git mktree`, create one commit with `git commit-tree`, update only the private temporary ref, and push that ref with `--no-verify` to the remote dedicated branch with normal fast-forward protection.
Treat `ls-remote` as ref discovery only.
Fetch the exact discovered candidate into an isolated quarantine repository with no alternates before advancing visible state.
Pass `GitVerificationLimits` into every candidate fetch and ancestry verification before Git starts.
Before ingestion begins set trusted command-line configuration for `fetch.parallel=1`, `pack.threads=2`, `index.threads=2`, `pack.depth=50`, `pack.windowMemory=256m`, and `core.deltaBaseCacheLimit=256m`, then independently enforce at most two worker threads and three total threads per process plus the harder process-tree and parsed-pack ceilings.
Monitor raw downloaded pack bytes, single inflated object bytes, aggregate expanded bytes, quarantine disk, Git object and commit counts, ancestry and delta depth, aggregate process-tree RSS and CPU, per-process address space, process and thread counts, wall time, bounded progress, and free-space reserve while the complete process tree runs.
On Linux require a dedicated cgroup with `cpu.stat` `usage_usec`, `cpu.max` capped at two cores, memory and process limits, plus per-process `RLIMIT_AS` at 1.5 GiB, or use an `RLIMIT` plus process-tree watchdog fallback only when it proves the same complete child-tree attachment and aggregate accounting.
On Windows require one Job Object with per-job user-time, CPU rate control, memory, process, and child-assignment enforcement plus watchdog accounting of each process's virtual address space.
On macOS require one process group and a 50 ms watchdog that sums process-group CPU and RSS, with `RLIMIT_CPU` and address-space limits only as secondary controls.
Fail closed before Git starts when complete child-tree attachment or accounting is unavailable.
On breach or cancellation terminate the whole process tree, remove quarantine, and return no candidate.
After successful unpacking apply the independent replication limits before store graph parsing and never treat replication limits as pack-ingestion protection.
Validate every newly introduced commit, tree, path, mode, and blob from the last trusted commit through the candidate, or the full ancestry when no trusted commit exists, including intermediate ancestry whose tip is clean.
Accept only the repository marker, byte-identical immutable bootstrap, authenticated head, allowed encrypted object paths, and regular-file or directory modes.
Reject unexpected paths, executable modes, symlinks, submodules, transient plaintext commits, malformed or unauthenticated vault blobs, missing blobs, corrupt objects, replacement references, and an incomplete reachable graph.
Ask replication to authenticate the bootstrap, head, and complete reachable Notecrypt graph through its bounded revocable lease, then record the trusted remote observation atomically.
Advance the visible local tracking ref only after isolated fetch, history validation, and complete graph authentication succeed.
If push might have succeeded but its response or verification read is unavailable, return `PublishOutcome::Indeterminate` without retrying or moving visible local state.
On abort or cancellation, discard publication state while allowing unreachable local Git objects to remain for Git maintenance.
Repository attributes, content filters, hooks, pagers, includes, replace objects, SSH overrides, and non-allowlisted external helpers cannot alter or execute during Notecrypt publication.
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
Exercise a 256 MiB plus one byte inflated object, aggregate expanded-byte exhaustion, raw-pack and quarantine exhaustion, excessive object and commit counts, ancestry depth, delta depth 51, aggregate process-tree RSS above 1 GiB, per-process address space above 1.5 GiB, a ninth process, a third worker thread, a fourth total thread, aggregate process-tree CPU above 3,600 seconds through fake accounting, trickle fetch, cancellation, 30-minute wall timeout, escaped-child attempts, unavailable complete-tree accounting, and independent post-unpack replication-limit failure.
Assert each platform controller attaches every descendant before work, measures aggregate CPU correctly, kills the whole tree on breach, preserves the free-space reserve, and removes quarantine on every failure.
Scan every Git commit, path, blob, log line, and process argument for unique plaintext canaries and logical names.

- [ ] **Step 7: Run production Git copy, rekey, and recovery journeys**

Run real Git-backed `BackendCopy` and prove it preserves the Notecrypt snapshot graph while allowing different target Git commit identities and history.
Run real Git-backed `CompromiseRekey` through `begin_compromise_rekey`, one-time `RecoverySecretPresentation`, consuming `confirm_compromise_rekey`, `CompromiseRekeySource`, and `PendingVaultTarget`.
Prove source and target cannot alias, cancel and drop clean all target state, partial state cannot activate, and successful activation has a new bootstrap, new identities, fresh objects, and a parentless snapshot.
Recover an older but cryptographically valid remote on a clean device and produce `FreshnessUnprovable` after graph authentication but before the first trusted baseline.
Prove CLI automation fails without `--acknowledge-unprovable-freshness`, TUI recovery uses the safe `FreshnessAcknowledgementView` in a non-dismissible deliberate confirmation, only consuming `PendingFreshnessAcknowledgement` records unprovable provenance atomically, cancel or drop records nothing, and no output says latest or verified-fresh.

- [ ] **Step 8: Complete Git CLI and TUI integration**

Add onboarding remote, dedicated branch, transport, prompt policy, sync retry, and backup configuration to CLI parsing and typed JSON output.
Wire TUI onboarding, sync, and backup actions through the app, keymap, view model, progress pane, and dialogs.
Show rollback, conflict, stale-head retry, no-remote backup, indeterminate publication, and verification failure states without claiming success.
Drive built-process CLI and pseudo-terminal TUI journeys through onboarding, sync, backup, conflict display and resolution, rollback warning, freshness-unprovable acknowledgement, indeterminate warning, backup readback failure, `BackendCopy`, and `CompromiseRekey` including recovery-phrase presentation and confirmation.

- [ ] **Step 9: Verify and commit**

Run: `cargo test -p notecrypt-backend-git --test conformance --test hardening --test history_verification --test transport_auth --test verification_limits && cargo test -p notecrypt-cli && cargo test -p notecrypt-tui && cargo test -p notecrypt-e2e --test git_sync --test plaintext_canary --test presentation_journey --test recovery_journey`

Expected: approved HTTPS, SSH, and credential-provider flows work; hostile substitutions fail; Git ingestion limits terminate and clean adversarial fetches; linear graph verification, production copy and rekey, freshness acknowledgement, CLI and TUI warnings, conflict preservation, and canary scans pass.

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
- Modify: `fuzz/targets.toml`
- Create: `scripts/verify-fuzz-targets.sh`
- Create: `scripts/run-fuzz-manifest.sh`
- Modify: `fuzz/format/Cargo.toml`
- Modify: `fuzz/format/fuzz_targets/decode_header.rs`
- Modify: `fuzz/format/fuzz_targets/decode_object.rs`
- Modify: `fuzz/format/fuzz_targets/decode_manifest.rs`
- Modify: `fuzz/format/fuzz_targets/decode_tree.rs`
- Modify: `fuzz/format/fuzz_targets/decode_snapshot.rs`
- Create: `fuzz/format/fuzz_targets/decode_bootstrap.rs`
- Create: `fuzz/format/fuzz_targets/decode_head.rs`
- Create: `fuzz/format/fuzz_targets/decode_crypto_envelope.rs`
- Create: `fuzz/backend/Cargo.toml`
- Create: `fuzz/backend/fuzz_targets/decode_backend_bootstrap.rs`
- Create: `fuzz/backend/fuzz_targets/decode_backend_head.rs`
- Create: `fuzz/backend/fuzz_targets/decode_backend_inventory.rs`
- Create: `fuzz/backend/fuzz_targets/decode_backend_response.rs`
- Create: `fuzz/git/Cargo.toml`
- Create: `fuzz/git/fuzz_targets/parse_remote_url.rs`
- Create: `fuzz/git/fuzz_targets/parse_config.rs`
- Create: `fuzz/git/fuzz_targets/parse_commit.rs`
- Create: `fuzz/git/fuzz_targets/parse_tree.rs`
- Create: `fuzz/git/fuzz_targets/parse_ref.rs`
- Create: `fuzz/git/fuzz_targets/parse_output.rs`
- Create: `fuzz/replication/Cargo.toml`
- Create: `fuzz/replication/fuzz_targets/decode_graph_metadata.rs`
- Create: `fuzz/replication/fuzz_targets/decode_limits.rs`
- Create: `tests/fuzz-regressions/`
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

- [ ] **Step 3: Add and execute the complete fuzz manifest**

Extend the Task 5 root `fuzz/targets.toml` as the sole inventory with every durable decoder and cryptographic envelope; bootstrap, head, inventory, and backend response parser; Git remote URL, configuration, commit, tree, ref, and output parser; and replication graph-metadata and limit parser listed above.
Give the format, backend, Git, and replication fuzz trees their own explicit cargo-fuzz `Cargo.toml` and assign every target to exactly one tree, including `decode_object` only in `fuzz/format`.
Make `scripts/verify-fuzz-targets.sh` compare the sole root manifest, all four fuzz Cargo manifests, target files, CI smoke matrix, scheduled matrix, and release command bidirectionally and fail on a missing, duplicate, or unlisted target.
Make `scripts/run-fuzz-manifest.sh` require `nightly-2026-08-01`, require exact cargo-fuzz `0.13.1`, invoke only `cargo +nightly-2026-08-01 fuzz`, run every manifest target with a selected duration and replay mode, enforce per-target input, allocation, recursion, memory, and timeout limits, and collect corpus paths without secrets.
Pure Git parser targets call pure parser entry points, never spawn Git, and fail a test if a process-spawn seam is reached.
Install cargo-fuzz with `cargo install cargo-fuzz --version 0.13.1 --locked`, verify its exact reported version, and fail before execution on any nightly or cargo-fuzz drift.
Run every target for at least 10 seconds in CI on each change through the pinned runner.
Run scheduled Linux sanitizer campaigns for at least 30 minutes per target through the pinned runner and retain corpora as CI artifacts for 30 days.
Retain manifest-completeness output, exact tool versions, and every per-target smoke and scheduled result as Task 20 execution evidence.
Persist every crashing input as an ordinary deterministic fixture under `tests/fuzz-regressions/` and replay all fixtures in `cargo test --workspace`.

- [ ] **Step 4: Add dependency and unsafe-code gates**

Run `cargo deny check`, `cargo audit`, and a workspace scan for `unsafe` blocks.
Require a written safety invariant and focused test for every accepted `unsafe` block.
Fail CI on unreviewed new runtime dependencies.

- [ ] **Step 5: Add platform behavior tests**

Exercise APFS and FSEvents behavior on macOS, inotify and watch limits on Linux, and NTFS rename, sharing, reserved-name, and antivirus-interference paths on Windows.
Run x86-64 and ARM64 where the CI provider supports dedicated workers.

- [ ] **Step 6: Write security and recovery documentation**

Copy the approved threat boundaries, rollback limitation, fixed-base cleanup limitation, generated recovery phrase flow, custom-passphrase policy, offline-verifier disclosure, exact KDF bounds and cancellation honesty, Git bootstrap and history verification, and new-device recovery warning into focused user documentation.
Explain that same-root-key rewrapping is credential maintenance rather than revocation because prior wrappers remain in public history.
Define `BackendCopy` as same-vault graph and history migration and `CompromiseRekey` as a new vault with all-new keys and identities plus a parentless current-state snapshot.
Warn that compromise rekey copies no prior object or history and cannot restore confidentiality to already exposed ciphertext, keys, or plaintext.
Do not claim resistance to a compromised unlocked endpoint.
Keep `README.md` limited to user-facing installation, setup, and usage and put all security, architecture, recovery detail, and release evidence under `docs/`.

- [ ] **Step 7: Record the architecture decision**

Explain the Rust-only phase 1, separated core and TUI, in-process service contract, deferred bindings, and backend portability boundary.

- [ ] **Step 8: Verify and commit**

Run: `rustup toolchain install nightly-2026-08-01 --profile minimal && cargo install cargo-fuzz --version 0.13.1 --locked && test "$(cargo +nightly-2026-08-01 fuzz --version)" = "cargo-fuzz 0.13.1" && scripts/verify-fuzz-targets.sh && scripts/run-fuzz-manifest.sh --toolchain nightly-2026-08-01 --cargo-fuzz-version 0.13.1 --seconds-per-target 10 && cargo test --workspace && cargo test -p notecrypt-e2e --test crash_recovery --test plaintext_canary --test presentation_journey --test recovery_journey && cargo deny check && cargo audit && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`

Expected: manifest completeness, every fuzz smoke target, regression replay, hardening, platform, policy, and documentation checks pass.

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
- Modify: `fuzz/targets.toml`
- Modify: `scripts/verify-fuzz-targets.sh`
- Modify: `scripts/run-fuzz-manifest.sh`

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
Install cargo-fuzz `0.13.1` exactly, verify that version under `nightly-2026-08-01`, run every checked-in fuzz target for at least 10 minutes through the pinned manifest runner, and replay the full retained and deterministic regression corpus.
Retain the manifest-completeness output, exact tool versions, per-target duration and sanitizer result, corpus replay result, and crash-fixture result as release evidence.
Reject any optimization that weakens KDF floors or ceilings, authentication, durability, cleanup ownership, graph completeness, Git isolation, bounded memory, or explicit leakage policy.

- [ ] **Step 5: Conduct independent security review**

Provide the threat model, durable cryptographic profile, recovery policy, compromise semantics, key hierarchy, transaction ordering, parser and replication limits, cleanup ownership, backend bootstrap, Git runner and history verifier, conflict model, complete CLI and TUI integration evidence, and test evidence to an independent reviewer.
Resolve every critical finding and document accepted lower-severity residual risks before release.

- [ ] **Step 6: Run the final user journey**

On macOS, Linux, and Windows initialize with generated recovery and the explicit custom warning path, edit through a real blocking editor, use the TUI, lock during an operation, reopen, open a bounded whole-vault workspace, exercise cleanup failure, onboard Git, synchronize two devices, observe rollback and indeterminate-publication warnings, create and resolve a conflict, run backup, inject backup readback failure, perform `BackendCopy`, perform `CompromiseRekey`, exercise device denial and removal failure, fall back to the recovery phrase, and recover on a clean device.
Verify no step requires manual encrypted-object manipulation.
Record the exact release evidence and residual concerns in `docs/release-readiness.md`, not `README.md`.

- [ ] **Step 7: Verify and commit**

Run: `rustup toolchain install nightly-2026-08-01 --profile minimal && cargo install cargo-fuzz --version 0.13.1 --locked && test "$(cargo +nightly-2026-08-01 fuzz --version)" = "cargo-fuzz 0.13.1" && scripts/verify-fuzz-targets.sh && scripts/run-fuzz-manifest.sh --toolchain nightly-2026-08-01 --cargo-fuzz-version 0.13.1 --seconds-per-target 600 --replay-all && cargo test --workspace && cargo test -p notecrypt-e2e --test cli_journey --test tui_journey --test whole_vault --test git_sync --test presentation_journey --test recovery_journey --test plaintext_canary --test crash_recovery && cargo bench -p notecrypt-benches && cargo deny check && cargo audit`

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
