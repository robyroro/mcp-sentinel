# ADR 0003: Declarative policy engine

## Status

Accepted — 2026-07-16.

## Context

Policies need deterministic, explainable matching and safe local operation. Allowing arbitrary code or templates in an authorization path expands the attack surface.

## Decision

Implement a constrained YAML language compiled to internal typed matchers. Return decision traces, conflicts, transformations, and limits. Do not execute policy-provided code or perform policy-time network calls.

## Consequences

Policies are readable, testable, portable, and work without a paid/external service. The language implements a smaller ecosystem than Rego/Cedar and requires deliberate versioning as features grow.

## Alternatives Considered

- OPA/Rego: mature and expressive, but introduces another runtime/language and makes constrained transformation UX harder.
- Cedar: strong authorization model, but less natural for payload transforms/redaction and tool-specific matchers.
- General Python/JavaScript rules: flexible but unsafe and non-deterministic for untrusted policy authors.
