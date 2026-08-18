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

We will use independently versioned, canonical CBOR schemas with definite fixed-position arrays, checked profile and algorithm identifiers, exact field types, and bounded decode entry points.
Ordinary AEAD objects, snapshots, authenticated records, and content chunks use distinct public schemas.
Protected logical identifiers, counts, graph references, sequence values, and plaintext lengths stay inside authenticated ciphertext or MAC payloads.
Readers reject unsupported identifiers, non-canonical encodings, trailing bytes, invalid lengths, and limit violations before constructing cryptographic or domain types.
Version 1 is frozen by non-sensitive golden fixtures and their locked hashes.

## Consequences

Independent clients can implement the format from a small deterministic contract, and malformed repository data fails before decryption or unbounded allocation.
Distinct schemas prevent invalid field combinations and make confidentiality checks direct.
The fixed layouts are less flexible than maps, and adding a critical field requires an explicit format or cryptographic-profile version decision.
Canonical validation and bounds add parser code that must remain covered by fixtures, mutation tests, and fuzzing.
