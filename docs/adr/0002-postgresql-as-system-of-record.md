# ADR 0002: PostgreSQL as system of record

## Status

Accepted — 2026-07-16.

## Context

Identities, policy versions, sessions, approval races, audit sequences, and report metadata require transactions, constraints, indexes, and JSON-shaped protocol evidence.

## Decision

Use PostgreSQL as the production source of truth through SQLAlchemy and Alembic. Use UUID identifiers and JSON/JSONB-compatible columns. Permit SQLite only for deterministic local/browser tests.

## Consequences

Approval coordination and workspace-scoped records have durable transactional semantics. Operators must run and back up PostgreSQL, manage migrations, and plan partitioning for high event volume. Tests must avoid relying on PostgreSQL-only behavior without coverage.

## Alternatives Considered

- SQLite for production: operationally simple but insufficient for concurrent reviewers and scale.
- Event store only: good history semantics but adds projection/operational complexity.
- Redis as authority: fast but not appropriate as the durable approval/audit source of truth.
