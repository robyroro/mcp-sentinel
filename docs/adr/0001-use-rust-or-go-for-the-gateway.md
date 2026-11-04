# ADR 0001: Use Go for the gateway

## Status

Accepted — 2026-07-16.

## Context

The gateway is a security-critical, independently deployable proxy that must supervise stdio processes, proxy streaming HTTP, preserve protocol frames, and enforce bounded concurrency without unsafe memory behavior. The project considered Rust and Go.

## Decision

Implement the gateway in Go using the standard HTTP, JSON, process, and concurrency libraries. Keep policy/risk logic behind the typed internal control-plane API and keep the data-plane binary small.

## Consequences

Go provides memory safety, mature networking, simple static builds, and maintainable concurrency. The repository has two backend languages, and developers must keep cross-language schemas/tests aligned. Streaming parsing and extension handling require discipline despite the type system.

## Alternatives Considered

- Rust/Tokio/Axum: stronger compile-time constraints and excellent performance, but higher contribution and iteration cost for this repository.
- Python gateway: least fragmentation, but less suitable for a small independently shipped data-plane binary and high-concurrency stream supervision.
