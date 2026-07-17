# Policy reference

## Minimal policy

```yaml
version: "1"
name: restricted-development
defaults:
  decision: deny

clients:
  include: [codex-local]
servers:
  include: [development-tools]

rules:
  - id: allow-project-read
    action: allow
    match:
      tool: filesystem.read_file
      arguments:
        path:
          within: [/workspace/project]

  - id: approve-write
    action: require_approval
    match:
      tool:
        any_of: [filesystem.write_file, filesystem.delete_file]

  - id: deny-secrets
    action: deny
    match:
      arguments:
        path:
          matches_any: ["**/.env", "**/.ssh/**", "**/credentials*"]

limits:
  max_tool_calls_per_session: 100
  max_concurrent_calls: 5
  max_runtime_seconds: 900
  max_payload_bytes: 1048576
```

## Top-level fields

| Field | Required | Meaning |
|---|---:|---|
| `version` | yes | policy-language version; currently `"1"` |
| `name` | yes | stable human-readable identifier |
| `description` | no | reviewer context |
| `extends` | no | base policy names/versions to merge |
| `defaults.decision` | yes | decision when no rule matches |
| `clients` / `servers` | no | policy-level include/exclude selectors |
| `rules` | yes | ordered rules with unique IDs |
| `limits` | no | session/concurrency/runtime/payload ceilings |

## Actions

| Action | Result |
|---|---|
| `allow` | forward unchanged unless a transform is declared |
| `deny` | return a safe policy error |
| `require_approval` | persist and pause for a reviewer |
| `transform` | allow with reviewed argument operations |
| `redact_response` | allow and apply configured response redaction |
| `audit_only` | record a finding without blocking in inspect mode |
| `rate_limit` | enforce the rule/session limit |
| `terminate_session` | reject and mark the session terminated |

## Match object

Rules can select `client`, `server`, `tool`, `method`, `resource_uri`, `environment`, `user_role`, `arguments`, and a time window. Scalar selectors are exact by default; selector objects may use `any_of`, `starts_with_any`, `contains_any`, `matches_any`, or a bounded `regex`.

Argument fields accept exact values and string/path selector objects. `within` performs normalized path containment rather than a raw prefix comparison. Network destinations must also pass the network guard, which resolves and classifies target IP addresses.

## Domain and response example

```yaml
rules:
  - id: docs-network-only
    action: allow
    match:
      tool: http.fetch
      arguments:
        url:
          domain_in: [docs.example.test]

  - id: redact-output-tokens
    action: redact_response
    match:
      tool: repository.inspect
    redact:
      mode: replace
      detectors: [bearer_token, private_key, high_entropy]
```

The URL must still pass SSRF and IP classification even if its hostname is allowlisted. Domain policy is not a DNS rebinding defense by itself.

## Command example

```yaml
rules:
  - id: allow-tests
    action: allow
    match:
      tool: terminal.execute
      arguments:
        command:
          starts_with_any: ["pnpm test", "pytest", "go test"]

  - id: destructive-shell
    action: deny
    match:
      tool: terminal.execute
      arguments:
        command:
          contains_any: ["rm -rf /", "mkfs", "shutdown", "curl | sh"]
```

The command guard separately tokenizes and flags shell metacharacters/obfuscation. An allow rule cannot override a matching terminal deny.

## Validation and testing

Use `mcp-sentinel policy validate FILE` and `mcp-sentinel policy test FILE REQUEST.json`. The web tester exposes the same trace, transformations, conflicts, risk findings, and duration. Keep regression requests beside policy changes.
