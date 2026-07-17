# ADR 0010: OpenTelemetry observability

## Status

Accepted in architecture; collector topology implemented and SDK instrumentation pending — 2026-07-16.

## Context

Gateway, API, worker, policy, approval, and sandbox latency must be correlatable without coupling the project to one commercial backend or leaking raw payloads.

## Decision

Standardize future traces/metrics on OpenTelemetry and ship an optional local collector/Jaeger profile. SDK emission from the gateway, API, and worker is a follow-up and is not claimed in v0.1. Keep raw protocol content out of telemetry by default and bound label cardinality.

## Consequences

Operators can select a compatible backend and correlate request IDs across services. Instrumentation and sampling require maintenance, and telemetry is best-effort rather than the authoritative audit trail.

## Alternatives Considered

- Vendor-specific agents: richer integrations but creates lock-in and may require paid services.
- Logs only: simple but weak cross-service causality and metrics.
- Audit database as telemetry: durable but too expensive and semantically different from operational observability.
