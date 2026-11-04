# Audit integrity

MCP Sentinel creates a per-stream tamper-evident chain and can export signed evidence bundles.

## Event chain

Before storage, payload fields are sanitized according to the workspace mode. An event is canonically serialized with stable key ordering and compact JSON encoding. Its hash is:

```text
SHA-256(previous_event_hash || canonical_event_bytes)
```

The first event uses a defined empty predecessor. Sequence numbers, payload hashes, decision metadata, and redaction summaries are inside the canonical record. A verifier recomputes every link and rejects gaps, reordering, edits, or malformed records.

## Export bundle

An authorized report job writes JSONL evidence plus human-readable HTML, Markdown, and PDF summaries. A manifest records each artifact SHA-256. The manifest digest is signed with Ed25519, and the public verification material accompanies the bundle. The CLI verifies path safety, file hashes, the signature, and event chains without executing bundle content.

## Verification

```bash
mcp-sentinel audit verify path/to/audit-bundle.zip
```

A successful result means the bundle matches the holder of the referenced signing key and that the included chain is internally consistent. It does not prove the source host was uncompromised or that omitted events never existed.

## Operations

- Protect signing keys separately from PostgreSQL and object storage.
- Version and retain public keys for the evidence lifetime.
- Export to object-lock/WORM storage when immutability is required.
- Monitor sequence gaps, persistence lag, signature failures, and unexpected key changes.
- Never include plaintext secrets solely for evidentiary completeness.
