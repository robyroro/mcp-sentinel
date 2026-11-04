# Security architecture

MCP Sentinel assumes clients, models, server packages, tool descriptions, arguments, and returned content may be hostile. Its core control is a gateway mediation point backed by deterministic policy decisions and durable approval state.

## Control layers

1. **Transport controls:** JSON parsing, JSON-RPC shape validation, bounded payloads, request deadlines, HTTP method handling, and browser `Origin` validation.
2. **Identity controls:** signed HttpOnly sessions, Argon2 password hashing, CSRF verification, workspace membership, and role-based approval/export permissions.
3. **Policy controls:** deny-by-default YAML policies, explicit client/server/tool/environment matching, deny/terminate precedence, transformations, redaction, and limits.
4. **Context inspection:** path traversal and sensitive-path checks, DNS/IP/SSRF checks, command token checks, injection heuristics, secret detectors, and explainable risk scoring.
5. **Human control:** durable approvals with expiry, optimistic concurrency, reviewed argument changes, and gateway fail-closed polling.
6. **Execution isolation:** optional non-root Docker containers with restricted mounts, network policy, capabilities, resource ceilings, and cleanup.
7. **Evidence:** sanitized event storage, hash chains, signed exports, retention, and offline verification.

## Security invariants

- A request is not forwarded until structural validation and the effective policy decision succeed.
- A missing, invalid, or timed-out security decision is a denial.
- Deny and terminate rules override allow and approval rules.
- Plaintext credentials are not returned by management APIs or written to audit records.
- Approval writes are conditional on `pending` state and the expected version.
- MCP request IDs are preserved; unsupported extension fields pass only when their values can be safely serialized.
- Sandboxed command configuration is an argument vector, never a shell interpolation.
- Audit reports sign artifact hashes; verification does not trust filenames or bundle order.

## Key management

Development defaults generate or load local signing/configuration material. Production must provide unique session, gateway-internal, secret-encryption, and Ed25519 signing keys from a secret manager. Rotate keys with a documented overlap period and retain public audit verification keys for the evidence lifetime. Keep signing keys outside the database and application image.

## Data protection

Payload modes are `metadata_only`, `redacted`, and `full`. `redacted` is the recommended maximum for general operation; `full` requires explicit risk acceptance and short retention. Detector fingerprints are one-way and contextualized; they are not a substitute for removing the exposed secret at its source. TLS is required between production components.

## Browser and API

The console relies on the API session cookie, not browser storage. State-changing browser requests require a CSRF token. API records are scoped by workspace membership, and approval decisions additionally require reviewer roles. Rendered JSON is treated as text. Production reverse proxies should add CSP, HSTS, frame-ancestor restrictions, and request limits.

## Gateway-to-control-plane authentication

Internal evaluation routes use a shared internal credential in the local deployment. Production should use mutually authenticated TLS or workload identity, rotate the credential, restrict routes at the network layer, and separate management and gateway ingress.

## Assurance boundary

Sentinel can constrain requests it observes. It cannot prove a server truthfully describes its effects, contain a host kernel compromise, prevent an authorized reviewer from approving harm, or detect every encoded secret/injection. See [Threat model](THREAT_MODEL.md) and [Sandbox security](SANDBOX_SECURITY.md).
