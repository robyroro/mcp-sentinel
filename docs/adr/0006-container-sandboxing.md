# ADR 0006: Container sandboxing

## Status

Accepted — 2026-07-16.

## Context

Local MCP servers execute code and may need controlled filesystem/network access. The complete demo must run on ordinary developer machines without paid isolation infrastructure.

## Decision

Offer Docker-based isolation with non-root execution, dropped capabilities, restricted mounts/network, resource limits, deadlines, and cleanup. Use an API argument vector and an optional Docker socket proxy. State clearly that containers share the host kernel.

## Consequences

The demo gains practical local containment and reproducibility. Docker access remains privileged, platform behavior varies, and hostile multitenant code requires stronger VM/microVM isolation.

## Alternatives Considered

- Direct host execution: simplest but does not constrain untrusted servers.
- Kubernetes: powerful policy surface but conflicts with local-first simplicity.
- MicroVMs: stronger boundary but materially higher setup and platform cost for v0.1.
