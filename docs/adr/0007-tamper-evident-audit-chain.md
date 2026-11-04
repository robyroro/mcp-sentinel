# ADR 0007: Tamper-evident audit chain

## Status

Accepted — 2026-07-16.

## Context

Investigations need evidence that reveals edits, deletion/reordering within an export, and artifact corruption, while the local deployment cannot depend on a hosted ledger.

## Decision

Canonically serialize sanitized events, chain them with SHA-256, hash export artifacts, and sign the manifest with Ed25519. Provide an offline verifier.

## Consequences

Accidental or unauthorized post-export modification is detectable when verification keys are trusted. This is tamper-evidence, not immutability; a party controlling the source database and signing key can forge replacement history.

## Alternatives Considered

- Plain database audit table: no cryptographic edit evidence.
- Blockchain/public transparency log: operational/privacy complexity inappropriate for local-first operation.
- HMAC only: verification requires sharing the secret and cannot safely support third-party verification.
