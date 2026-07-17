# Threat model

## Scope and assets

Protected assets include credentials, local files, source repositories, internal networks, databases, deployment control, approval authority, protocol evidence, policy definitions, and signing keys. The gateway, control plane, storage services, workers, browser, Docker runtime, MCP endpoints, and notification adapters are in scope.

## Adversaries

- A malicious or compromised MCP server that advertises misleading tools or returns hostile content.
- A compromised client/model that attempts excessive, destructive, secret-seeking, or obfuscated calls.
- A low-privilege workspace member trying to cross workspace or role boundaries.
- A dependency or server package containing a supply-chain payload.
- A network attacker where TLS or origin controls are misconfigured.
- A privileged operator or host attacker modifying evidence.

## Primary threats and mitigations

| Threat | Example | Principal mitigations | Residual risk |
|---|---|---|---|
| Tool abuse | destructive shell or database mutation | deny defaults, command/path rules, approval, limits | semantic variants and reviewer error |
| Secret theft | `.env`, bearer token, private key response | path policy, secret detectors, redaction, metadata-only logs | unknown formats, side channels |
| SSRF | metadata endpoint, loopback, rebinding | URL parse, DNS resolution, IP classification, domain policy | TOCTOU DNS changes without egress proxy |
| Path escape | traversal, symlink, alternate separator | canonical path checks, allowed roots, sandbox mounts | filesystem races and platform-specific edge cases |
| Prompt injection | returned instructions that influence later calls | content indicators, risk findings, human context | probabilistic false positives/negatives |
| Approval race | two reviewers decide differently | optimistic conditional update, idempotency, audit | downstream action itself may lack idempotency |
| Protocol smuggling | malformed JSON-RPC or oversized frame | strict decode, message limits, method/time bounds | parser or protocol implementation defect |
| Cross-workspace access | guessed UUID | membership-scoped queries and role checks | application authorization defect |
| Container escape | hostile local server exploits kernel | non-root, capabilities dropped, read-only root, limits | containers share host kernel |
| Evidence tampering | database rows rewritten | canonical hash chain, signed exports, verifier | database + key compromise can forge history |
| Supply-chain compromise | poisoned dependency/image | pinned locks, CI audit, CodeQL, Trivy, Gitleaks | scanners are incomplete |
| Availability attack | floods, slow server, approval starvation | size/rate/runtime/concurrency limits, timeouts | resource exhaustion at outer proxy/host |

## Abuse cases

The security suite exercises traversal, sensitive filenames, private and metadata network targets, destructive/obfuscated command fragments, encoded or high-entropy secret fixtures, prompt-injection indicators, malformed messages, deny precedence, and audit tampering. Fixtures are synthetic and deliberately non-working.

## Out of scope

- Protecting traffic that bypasses the Sentinel endpoint.
- Proving a remote service's actual side effects match its MCP schema.
- Defending a fully compromised host, Docker daemon, database administrator, or signing-key custodian.
- Replacing endpoint security, network egress enforcement, database permissions, or organizational review processes.

## Reporting

Do not open public issues for suspected vulnerabilities. Follow [`SECURITY.md`](../SECURITY.md) and include version, deployment mode, reproduction, impact, and proposed embargo needs.
