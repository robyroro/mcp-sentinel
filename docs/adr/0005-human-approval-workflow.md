# ADR 0005: Human approval workflow

## Status

Accepted — 2026-07-16.

## Context

Some legitimate operations are too contextual for static allow/deny rules. Multiple reviewers may act concurrently, and a gateway may restart or lose its client.

## Decision

Persist approvals in PostgreSQL with a request fingerprint, expiry, status/version, reviewed arguments, and audit context. Decide via one conditional atomic update; the gateway polls with a bounded deadline and fails closed.

## Consequences

Decisions survive process restarts and races have one winner. Approval adds latency and a control-plane dependency. Human review can still authorize harmful actions, and downstream tools need their own idempotency.

## Alternatives Considered

- In-memory channel only: low latency but loses state and cannot coordinate replicas.
- Webhook callback directly to gateway: complicates reachability and restart safety.
- Automatic risk threshold only: lacks human context and accountability.
