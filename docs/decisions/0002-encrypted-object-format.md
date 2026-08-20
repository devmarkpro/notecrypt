# 2. Use canonical versioned encrypted object formats

Date: 2026-08-18

## Status

Accepted

## Context

Vault data must remain readable across devices and future Notecrypt implementations without exposing logical names, graph structure, or plaintext semantics in a public repository.
Readers also need firm allocation and collection bounds because every repository byte is attacker-controlled before authentication.
We considered self-describing maps, library-derived serialization, and one permissive object record.
Those options allow ambiguous encodings, accidental public fields, or invalid combinations that become difficult to reject before cryptographic use.

## Decision

The format crate owns the canonical typed outer envelope and record-type domain for local records.
Each consuming component owns the canonical, versioned, bounded schema of its inner local payload.
Journal records use the distinct frozen local record type value `6`.
Vault-availability records use the distinct frozen local record type value `7`, and unknown value `8` remains rejected under format version 1.

We will use independently versioned, canonical CBOR schemas with definite fixed-position arrays, checked profile and algorithm identifiers, exact field types, and bounded decode entry points.
Ordinary AEAD objects, snapshots, authenticated records, and content chunks use distinct public schemas.
Protected logical identifiers, counts, graph references, sequence values, and plaintext lengths stay inside authenticated ciphertext or MAC payloads.
Logical revision IDs and immutable manifest object IDs are distinct identities joined by an opaque `RevisionLocator`.
A file tree entry remains a fixed array of five values whose last value is `[revision_id, manifest_object_id]`.
A tombstone remains a fixed array of seven values whose last value is either the same locator pair or null.
Logical snapshot IDs and immutable snapshot object IDs are distinct identities joined by an opaque `SnapshotParentLocator`.
Snapshot payloads remain fixed arrays of six values and encode each parent as `[snapshot_id, snapshot_object_id]`, sorted lexicographically by the complete pair with duplicate logical or object identities rejected.
The store authenticates every located object, cross-checks its protected logical identity, and enforces a tree-wide revision-to-object bijection within replication budgets.
Because no format version 1 vault has been released, this locator correction replaces the draft version 1 schema and its four affected golden fixtures in place rather than adding a dual decoder or version 2.
Readers reject unsupported identifiers, non-canonical encodings, trailing bytes, invalid lengths, and limit violations before constructing cryptographic or domain types.
Version 1 is frozen by non-sensitive golden fixtures and their locked hashes.

## Consequences

Independent clients can implement the format from a small deterministic contract, and malformed repository data fails before decryption or unbounded allocation.
Distinct schemas prevent invalid field combinations and make confidentiality checks direct.
The fixed layouts are less flexible than maps, and adding a critical field requires an explicit format or cryptographic-profile version decision.
Canonical validation and bounds add parser code that must remain covered by fixtures, mutation tests, and fuzzing.
