# ADR 0004: Fail-closed security default

## Status

Accepted — 2026-07-16.

## Context

If policy evaluation, approvals, validation, or durable evidence fails, forwarding a high-impact MCP request can create irreversible side effects.

## Decision

Deny requests when security evaluation is absent, malformed, timed out, or unavailable. Keep an explicit development inspect mode for non-terminal findings, while structural limits and hard safety checks always remain active.

## Consequences

Control-plane incidents can reduce availability but do not silently bypass enforcement. Operators need resilient APIs/databases and clear denial diagnostics. Inspect mode must not be confused with production enforcement.

## Alternatives Considered

- Fail open: better availability but violates the gateway's primary security contract.
- Cached last decision for all requests: unsafe for new arguments/context; version-keyed policy caches remain acceptable as inputs to deterministic evaluation.
