# Architecture

MCP Sentinel is a control plane and data-plane gateway for Model Context Protocol (MCP) traffic. The Go gateway is the enforcement point. FastAPI owns identities, configuration, policy evaluation, approval state, and durable records. The Next.js application is a management console; it is never on the trusted forwarding path.

## System context

```mermaid
flowchart LR
    subgraph Untrusted[Untrusted and semi-trusted boundary]
      Client[MCP client]
      Native[Native stdio server]
      Sandboxed[Containerized MCP server]
    end
    subgraph DataPlane[Sentinel data plane]
      Gateway[Go gateway<br/>HTTP + stdio supervisor]
      Inspect[Message validation<br/>response inspection]
    end
    subgraph ControlPlane[Sentinel control plane]
      API[FastAPI API]
      Policy[Deterministic policy engine]
      Risk[Explainable risk engine]
      Approval[Approval service]
      Redact[Secret and content inspection]
      Sandbox[Docker sandbox manager]
      Worker[Celery worker]
    end
    subgraph Management[Management boundary]
      Browser[Next.js console]
      CLI[Sentinel CLI]
      Reviewer[Human reviewer]
    end
    subgraph Storage[Storage boundary]
      DB[(PostgreSQL)]
      Redis[(Redis)]
      S3[(MinIO / S3)]
    end
    subgraph Integrations[Optional integrations]
      Notify[Webhook / development mail]
      OTel[Optional OTel endpoint<br/>SDK emission pending]
      Trace[Jaeger]
    end

    Client --> Gateway
    Gateway --> Inspect
    Gateway --> Native
    Gateway --> Sandboxed
    Gateway -->|internal authenticated API| API
    API --> Policy
    API --> Risk
    API --> Redact
    API --> Approval
    API --> Sandbox
    API --> DB
    API --> Redis
    API --> S3
    API --> Worker
    Browser --> API
    CLI --> API
    Reviewer --> Browser
    Worker --> DB
    Worker --> S3
    Worker --> Notify
    Sandbox --> Sandboxed
    OTel --> Trace
```

## Request sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as MCP client
    participant G as Go gateway
    participant A as FastAPI control plane
    participant P as Policy and risk engines
    participant H as Approval service
    participant S as MCP server
    participant D as PostgreSQL

    C->>G: initialize(version, capabilities)
    G->>S: initialize (ID and extensions preserved)
    S-->>G: negotiated version and capabilities
    G->>A: record negotiation
    A->>D: session and protocol event
    G-->>C: initialization response
    G->>S: tools/list, resources/list, prompts/list
    S-->>G: discovered capabilities
    G->>A: capability evidence
    A->>D: tools and risk metadata
    C->>G: tools/call(request ID, arguments)
    G->>G: validate JSON-RPC, size, origin, timeout
    G->>A: evaluate sanitized request
    A->>P: deterministic policy + contextual risk
    P-->>A: decision, trace, signals, transformations
    alt denied or terminated
      A->>D: decision and audit event
      A-->>G: deny with safe explanation
      G-->>C: JSON-RPC error
    else approval required
      A->>H: create idempotent pending approval
      H->>D: persist pending request
      A-->>G: approval ID and polling deadline
      loop bounded wait
        G->>H: poll decision
        H-->>G: pending / approved / denied / expired
      end
      H->>D: atomic reviewer decision
      G->>S: approved or modified call
    else allowed
      G->>S: original or transformed call
    end
    S-->>G: response or protocol error
    G->>A: inspect response
    A->>P: redaction and injection inspection
    P-->>A: sanitized payload and findings
    A->>D: hash-chained audit and event data
    A-->>G: safe response payload
    G-->>C: response with original request ID
```

The gateway fails closed when the evaluation API is unavailable, malformed, or times out. Inspection-only mode still enforces hard message-size, origin, parser, and timeout limits.

## Approval sequence and races

```mermaid
sequenceDiagram
    participant G as Gateway
    participant A as Approval API
    participant DB as PostgreSQL
    participant N as Notification worker
    participant R1 as Reviewer A
    participant R2 as Reviewer B

    G->>A: create(request fingerprint)
    A->>DB: INSERT pending (unique fingerprint)
    DB-->>A: approval ID (existing or new)
    A->>N: enqueue in-app notification
    N-->>R1: pending approval
    N-->>R2: pending approval
    par competing decisions
      R1->>A: approve once, version=0
      R2->>A: deny, version=0
    end
    A->>DB: UPDATE ... WHERE status=pending AND version=0
    DB-->>A: one row updated
    A-->>R1: accepted decision
    A->>DB: second conditional UPDATE
    DB-->>A: zero rows updated
    A-->>R2: 409 already decided
    loop bounded polling
      G->>A: decision status
      A-->>G: approved / denied / expired / cancelled
    end
    alt approved
      G->>G: apply reviewed argument patch
      G->>G: continue original request
    else denied, expired, cancelled, or restart timeout
      G-->>G: fail closed
    end
    A->>DB: append audit decision
```

Approval state is durable. A restarted gateway can resume polling by approval ID, but a request is never forwarded twice by the approval API; upstream servers still require their own idempotency for side-effecting calls.

## Sandbox lifecycle

```mermaid
stateDiagram-v2
    [*] --> Validating: configuration submitted
    Validating --> Rejected: unsafe mount, image, env, or argv
    Validating --> Creating: validated argv and limits
    Creating --> Configuring: non-root user, read-only root, caps dropped
    Configuring --> Networking: none or allowlisted network
    Networking --> Starting: mounts and tmpfs attached
    Starting --> Unhealthy: health deadline exceeded
    Starting --> Ready: MCP health and initialize succeed
    Ready --> Running: gateway session attached
    Running --> Terminating: CPU, memory, PID, or time limit
    Running --> Terminating: operator stop or server exit
    Unhealthy --> Cleaning
    Terminating --> Cleaning: stop then bounded kill
    Cleaning --> [*]: container and transient data removed
    Rejected --> [*]
```

The manager constructs an argument vector and uses the Docker API; it does not interpolate a shell command. The Compose sandbox profile grants a restricted Docker socket proxy rather than mounting the daemon socket directly into the API. See [Sandbox security](SANDBOX_SECURITY.md).

## Audit data flow

```mermaid
flowchart LR
    Event[Protocol or management event] --> Sanitize[Classify and redact]
    Sanitize --> Canon[Canonical JSON serialization]
    Canon --> Chain[SHA-256 of previous hash + event]
    Chain --> DB[(Append to PostgreSQL)]
    DB --> Select[Authorized report selection]
    Select --> Bundle[JSONL + HTML + Markdown + PDF]
    Bundle --> Digest[Artifact SHA-256 manifest]
    Digest --> Sign[Ed25519 signature]
    Sign --> Store[(MinIO / S3 or local artifact)]
    Store --> Verify[Offline CLI verifier]
    Verify --> Result[Chain, hashes, signature result]
```

The chain is tamper-evident, not immutable: an actor controlling the database and signing key can replace history. Production deployments should isolate signing material and copy exports to immutable retention storage.

## Deployment

```mermaid
flowchart TB
    Internet[Operator network] --> TLS[External TLS reverse proxy]
    TLS --> Web[Next.js web]
    TLS --> API[FastAPI management API]
    ClientNet[MCP client network] --> GWLB[Gateway service / load balancer]
    GWLB --> G1[Gateway replica 1]
    GWLB --> G2[Gateway replica 2]
    G1 --> API
    G2 --> API
    G1 --> Servers[MCP server network]
    G2 --> Servers
    API --> PG[(PostgreSQL)]
    API --> R[(Redis)]
    API --> O[(S3-compatible storage)]
    R --> W1[Worker replica 1]
    R --> W2[Worker replica 2]
    W1 --> PG
    W2 --> PG
    W1 --> O
    W2 --> O
    subgraph Optional telemetry topology
      OT[OTel collector<br/>SDK emission pending] --> J[Jaeger / monitoring backend]
    end
```

The repository's Compose deployment uses one replica of each service plus Mailpit, MinIO, PostgreSQL, and Redis. The optional collector/Jaeger profile is a deployment extension point; application SDK span emission is not wired in v0.1. TLS termination, production key management, backups, and a real secret provider are operator responsibilities.

## Data model

```mermaid
erDiagram
    WORKSPACE ||--o{ MEMBERSHIP : has
    USER ||--o{ MEMBERSHIP : joins
    WORKSPACE ||--o{ MCP_CLIENT : owns
    WORKSPACE ||--o{ MCP_SERVER : owns
    MCP_SERVER ||--o{ TOOL : exposes
    MCP_SERVER ||--o{ RESOURCE : exposes
    WORKSPACE ||--o{ POLICY : defines
    POLICY ||--o{ POLICY_VERSION : versions
    POLICY ||--o{ SESSION : governs
    MCP_CLIENT ||--o{ SESSION : initiates
    MCP_SERVER ||--o{ SESSION : targets
    USER ||--o{ SESSION : acts_as
    SESSION ||--o{ PROTOCOL_EVENT : contains
    PROTOCOL_EVENT ||--o{ POLICY_DECISION : evaluated_as
    PROTOCOL_EVENT ||--o{ RISK_FINDING : identifies
    PROTOCOL_EVENT ||--o| APPROVAL : pauses_for
    USER ||--o{ APPROVAL : reviews
    PROTOCOL_EVENT ||--o{ SECRET_DETECTION : redacts
    MCP_SERVER ||--o{ SANDBOX : runs_in
    SESSION ||--o{ REPORT : evidences
    WORKSPACE ||--o{ AUDIT_EVENT : records
    APPROVAL ||--o{ NOTIFICATION_DELIVERY : notifies

    WORKSPACE {
      uuid id PK
      string slug UK
      json settings
    }
    USER {
      uuid id PK
      string email UK
      string password_hash
      string status
    }
    SESSION {
      uuid id PK
      uuid workspace_id FK
      string protocol_version
      string status
      json risk_summary
    }
    PROTOCOL_EVENT {
      uuid id PK
      uuid session_id FK
      int sequence
      string request_id
      json sanitized_payload
      string payload_hash
    }
    APPROVAL {
      uuid id PK
      string status
      int version
      json original_arguments
      json approved_arguments
    }
    AUDIT_EVENT {
      uuid id PK
      string previous_hash
      string event_hash
      json metadata
    }
```

The current SQLAlchemy schema combines some logical records—policy versions are represented by policy version fields, policy/risk decisions live on protocol events, and notification delivery is handled by worker adapters. The diagram makes these logical relationships explicit without claiming separate physical tables where none exist.

## Trust boundaries

| Boundary | Trusted inputs | Controls | Residual risk |
|---|---|---|---|
| User browser | Authenticated user actions | HttpOnly signed session, SameSite cookie, CSRF, RBAC | Compromised browser or approved harmful action |
| Management API | Validated JSON and authorized identity | Pydantic validation, workspace scoping, roles, audit | API/runtime compromise |
| MCP client | JSON-RPC frames | size limits, JSON validation, origin checks, timeouts | semantic abuse and extension ambiguity |
| Gateway | Compiled configuration and internal API | fail-closed enforcement, fixed deadlines, ID preservation | gateway host compromise |
| MCP server | Protocol responses | response inspection, redaction, timeout, sandbox option | opaque behavior and covert channels |
| Sandbox | Explicit image, argv, mounts, limits | non-root, dropped capabilities, network policy, resource limits | container escape or kernel exploit |
| Container runtime | Docker API | optional socket proxy, least privileges | daemon compromise controls host |
| Data storage | Sanitized records | encryption-in-transit/deployment, redaction, retention, hashes | privileged database access |
| Notification | Sanitized approval summary | adapter boundary, no plaintext secrets | third-party retention and metadata |
| Observability | Labels and sanitized traces | no raw payloads by default | high-cardinality or accidental custom labels |

## Failure modes

| Failure | Enforcement behavior | Recovery |
|---|---|---|
| Gateway unavailable | Connection fails closed | client retry or another replica |
| Policy API/engine unavailable | sensitive request denied | restore API; no bypass is automatic |
| PostgreSQL unavailable | new durable decisions denied; reads may fail | restore primary, verify audit sequence |
| Redis unavailable | synchronous gateway checks continue; jobs/notifications queue locally or fail visibly | restore Redis and requeue idempotent jobs |
| Reviewer unavailable | approval expires and request is denied | assign reviewer or resubmit request |
| MCP server timeout | bounded gateway error, session remains auditable | health-check or restart server |
| Sandbox startup failure | no connection is exposed | inspect sanitized build/runtime log |
| Audit persistence backlog | gateway rejects when durable evidence is required | drain worker queue and monitor lag |
| Object storage unavailable | live enforcement continues; exports remain pending | retry report job |
| OTel unavailable | product continues; telemetry is dropped/buffered | restore collector; audit records remain authoritative |

Fail-open is intentionally not implemented for security-sensitive evaluation. Operators may use development inspect mode, which records non-critical policy findings but retains structural safety limits.

## Scaling strategy

- Run stateless gateway replicas behind an MCP-aware load balancer. Long-lived streams need connection affinity for their lifetime.
- Cache compiled, version-keyed policies in each gateway/API process and invalidate via Redis pub/sub or version polling.
- Coordinate approvals and idempotency in PostgreSQL; Redis is acceleration and job transport, not the approval source of truth.
- Batch protocol-event inserts while preserving per-session sequence order and audit hashes.
- Partition high-volume protocol events by workspace/time and archive sanitized payload artifacts to object storage.
- Scale Celery workers by queue (reports, retention, sandbox builds, notifications), each with idempotent job keys.
- Use object storage lifecycle rules for report and large-payload retention.
- Export bounded-cardinality metrics for decisions, latency, denials, queue depth, and sandbox failures.

## Repository components

| Path | Responsibility |
|---|---|
| `apps/gateway` | Go data-plane proxy and stdio supervisor |
| `apps/api` | FastAPI management/evaluation API and migrations |
| `apps/web` | Next.js management console |
| `apps/worker` | Celery asynchronous work |
| `apps/cli` | Typer operator commands and audit verifier |
| `packages/sentinel_core` | Policy, risk, inspection, redaction, and audit primitives |
| `examples` | Synthetic MCP servers, client, policies, and demo workspace |
| `tests` | Unit, protocol, backend, and security tests |

## Related decisions

Architecture choices are captured in [`docs/adr`](adr/README.md). Security details are in [Security architecture](SECURITY_ARCHITECTURE.md), [Threat model](THREAT_MODEL.md), and [Protocol support](PROTOCOL_SUPPORT.md).
