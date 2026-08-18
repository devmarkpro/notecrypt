# 4. Use one portable encrypted-object backend contract

Date: 2026-08-18

## Status

Accepted

## Context

Notecrypt must synchronize encrypted vaults through Git first and through other storage systems later without letting transport details enter domain, store, or replication policy.
Adapters operate on attacker-controlled remote bytes and may differ in conditional update, pagination, object-size, batch-size, and concurrency support.
The immutable bootstrap is required before a device can authenticate a vault, while heads and objects remain opaque until the store validates them.

## Decision

The backend crate is the only dedicated contracts crate and defines a synchronous, bounded, cancellation-aware transport SPI for immutable bootstrap bytes, opaque objects, inventory cursors, and conditionally replaced opaque heads.
Immutable bootstrap read and create-if-absent operations live in the same contract because onboarding, recovery, backup, and backend copy require exact transfer and independent readback through every adapter.
Backend publication atomicity covers only staged encrypted bytes and their replacement head.
The store and replication layers still authenticate the bootstrap, head, and complete reachable graph before recording success.
The contract contains no Git types, plaintext semantics, secret material, asynchronous runtime types, or store authentication logic.
Fetched objects flow only into a caller-owned transactional quarantine sink through a non-blocking transfer handoff that never makes staged bytes visible.
The store caller separately consumes its quarantine finalizer to authenticate the bytes, return typed metadata or store errors, and publish only validated content.
Transfer failures invoke a non-blocking abort marker, while the caller retains ownership of dropping the quarantine and any potentially blocking cleanup.
The contract exposes a bounded opaque backend namespace identity so migration can reject source and target aliasing.
Adapter construction derives and persists that stable identity from canonical storage configuration without including credentials, tokens, or user information.
An adapter without conditional head replacement must advertise that limitation and may run only after the application explicitly selects single-writer mode.
Publication abort detaches only non-blocking adapter-local staging, while potentially blocking remote cleanup runs through a separate cancellable maintenance operation.
The caller enforces advertised safe concurrency per local adapter handle before dispatching synchronous calls.
Independent handles and devices still require atomic conditional publication and snapshot-safe inventory against the same namespace.

## Consequences

Git and future adapters share one black-box conformance suite and expose the same bounded failure and indeterminate-outcome semantics.
Opaque bounded types and private validated capabilities prevent adapters from bypassing transport limits through ordinary construction.
Synchronous methods fit the service blocking-worker runtime, while adapters remain responsible for bounded I/O and cooperative cancellation at each backend boundary.
An indeterminate publication requires a fresh head read before retry, and a stale expected version never authorizes overwriting the observed head.
Backend atomicity cannot substitute for cryptographic authentication or reachability verification.
