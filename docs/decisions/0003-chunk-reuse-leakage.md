# 3. Reuse unchanged same-file chunks

Date: 2026-08-18

## Status

Accepted

## Context

Targeted editing must save large files without re-encrypting the complete file after every small change.
Full-file re-encryption hides unchanged regions but makes save time and cancellation latency scale with total file size.
Content-defined chunking and cross-file deduplication reveal broader equality relationships and add a more complicated attack surface.
Fixed-size chunks provide a simpler bounded streaming model, but their reuse remains observable across revisions.

## Decision

We will split file content into fixed 1 MiB chunks and reuse an encrypted chunk only at the same checked position in the same logical file when its keyed fingerprint matches.
Each newly encrypted chunk receives a fresh random data key, nonce, and object identity.
We will not deduplicate across files or vaults.
We accept that repository observers can identify unchanged aligned chunk regions across revisions.

## Consequences

Aligned or in-place edits can save quickly because unchanged regions need no encryption or upload.
Cancellation points remain close together and per-operation memory stays bounded.
An insertion or deletion can shift every following boundary and require re-encrypting the rest of the file.
Observers learn which fixed-size regions were reused, although they do not learn plaintext, filenames, or cross-file equality from the reuse mechanism.
Users who require full-file change hiding need a future profile with different leakage and performance trade-offs.
