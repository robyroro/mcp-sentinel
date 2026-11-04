# Architecture decision records

Accepted decisions describe the initial `0.1.0` architecture. A material reversal creates a new ADR that supersedes the old record; accepted history is not rewritten.

| ADR | Decision |
|---|---|
| [0001](0001-use-rust-or-go-for-the-gateway.md) | Use Go for the gateway |
| [0002](0002-postgresql-as-system-of-record.md) | PostgreSQL is the system of record |
| [0003](0003-declarative-policy-engine.md) | Use a constrained declarative YAML policy engine |
| [0004](0004-fail-closed-security-default.md) | Fail closed for security decisions |
| [0005](0005-human-approval-workflow.md) | Persist human approvals with race protection |
| [0006](0006-container-sandboxing.md) | Offer Docker isolation with explicit limitations |
| [0007](0007-tamper-evident-audit-chain.md) | Hash-chain events and sign exports |
| [0008](0008-local-first-deployment.md) | Keep the full demo local-first |
| [0009](0009-synthetic-demo-fixtures.md) | Use deterministic synthetic fixtures |
| [0010](0010-opentelemetry-observability.md) | Standardize optional telemetry on OpenTelemetry |
