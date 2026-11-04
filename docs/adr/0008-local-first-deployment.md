# ADR 0008: Local-first deployment

## Status

Accepted — 2026-07-16.

## Context

Developers and researchers need a complete system without paid APIs, cloud accounts, or sending sensitive MCP payloads to third parties.

## Decision

Ship Docker Compose with PostgreSQL, Redis, MinIO, Mailpit, API, worker, web, gateway, demo server, and optional sandbox/telemetry profiles. Keep classifiers deterministic and local.

## Consequences

The repository is inspectable and reproducible on one workstation. Compose is not a production orchestrator, host resources vary, and operators must add TLS, backups, key management, and high availability.

## Alternatives Considered

- Cloud-only SaaS: easier centralized operation but contradicts privacy and offline goals.
- Embedded single-process application: simpler startup but obscures production boundaries and gateway independence.
