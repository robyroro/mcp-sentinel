# ADR 0009: Synthetic demo fixtures

## Status

Accepted — 2026-07-16.

## Context

Security demonstrations need secret-shaped, malicious, and personal-looking data, but public fixtures must never contain real private information or working credentials.

## Decision

Generate deterministic synthetic workspaces, identities, sessions, approvals, malicious content, and invalid secret patterns. Reset/seed them reproducibly for tests and screenshots.

## Consequences

Screenshots and tests are stable and safe to publish. Synthetic distributions do not represent production frequency and should not be used to tune detection accuracy claims.

## Alternatives Considered

- Anonymized production data: re-identification and secret-leak risk.
- Random fixtures: realistic variation but non-deterministic screenshots/tests.
- Tiny hand-written fixtures only: insufficient workflow and table coverage.
