# Data retention

Retention is workspace-configurable and processed by an idempotent worker job. The development default for raw/redacted payloads is seven days.

## Recommended classes

| Class | Example retention | Notes |
|---|---:|---|
| Raw payloads | 0–7 days | disable unless explicitly needed |
| Redacted protocol events | 30–90 days | investigation window |
| Metadata and metrics | 90–365 days | aggregate before long retention |
| Pending/expired approvals | 30–90 days | retain decision evidence as required |
| Signed audit exports | policy/legal requirement | copy to controlled object-lock storage |
| Sandbox/build logs | 7–30 days | sanitize and cap size |

## Cleanup behavior

Cleanup selects expired records in bounded batches, preserves required audit metadata/hashes, deletes object artifacts after database eligibility is recorded, and retries idempotently. A failed object deletion remains visible for retry. Legal holds and active investigations must suspend affected cleanup.

## Operational controls

Monitor retained bytes, oldest eligible record, deletion backlog, object/database mismatch, and worker failures. Test restore and deletion paths. Shortening retention does not remove copies already exported or held by external notification/storage systems.
