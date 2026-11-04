# Privacy

MCP traffic can contain source code, documents, credentials, personal data, and business records. Configure Sentinel to retain the least data required for operations and evidence.

## Payload modes

| Mode | Stored content | Use |
|---|---|---|
| `metadata_only` | method, timing, sizes, hashes, decisions, findings | strongest default for sensitive deployments |
| `redacted` | sanitized structured payload plus detector summaries | local demo and most investigations |
| `full` | raw payload where enabled | exceptional, short-lived forensic use only |

Redaction applies to arguments, responses, resources, prompts, protocol metadata, logs, and reports. Detectors can miss secrets and can redact benign high-entropy content. Never use Sentinel storage as the system of record for sensitive payloads.

## Access and sharing

Workspace RBAC controls records and exports. Report bundles may contain sensitive sanitized context and should be encrypted, shared narrowly, and expired. Notification adapters receive summaries only. Object storage and database operators remain privileged processors.

## Data-subject and compliance needs

Organizations are responsible for lawful basis, notices, access/deletion workflows, residency, and retention obligations. Audit integrity requirements may conflict with deletion; define that policy before collecting user-linked payloads. Pseudonymize user identities where operationally possible.

## Development fixtures

All seeded users, tokens, secrets, hosts, repositories, and events are synthetic. Fake secret strings are intentionally invalid and must never be replaced with real credentials in committed fixtures.
