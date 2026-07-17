from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel_core.audit import canonical_json
from sentinel_core.policy import PolicyEngine
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import hash_password
from .models import (
    Approval,
    AuditLog,
    MCPClient,
    MCPServer,
    Membership,
    Policy,
    ProtocolEvent,
    Report,
    Sandbox,
    SecretDetection,
    Tool,
    User,
    Workspace,
)
from .models import (
    Session as MCPSession,
)

NAMESPACE = uuid.UUID("2f00dfd8-ea04-4b88-a484-f173f7ce47f0")
DEMO_PASSWORD = "SentinelDemo!2026"


def did(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))


POLICY_YAML = """version: "1"
name: coding-agent-restricted
revision: 1.2.0
defaults:
  decision: deny
rules:
  - id: deny-secret-access
    description: Credential locations are blocked.
    action: deny
    match:
      tool: filesystem.read_file
      arguments:
        path:
          matches_any: ["**/.env", "**/.ssh/**", "**/credentials*"]
  - id: deny-destructive-shell
    description: Destructive commands are blocked.
    action: deny
    match:
      tool: terminal.execute
      arguments:
        command:
          contains_any: ["rm -rf", "mkfs", "shutdown", "curl | sh"]
  - id: allow-repository-read
    description: Reads inside the project are allowed.
    action: allow
    match:
      tool: filesystem.read_file
      arguments:
        path:
          within: ["/workspace/project"]
  - id: require-approval-for-write
    description: Filesystem writes require review.
    action: require_approval
    match:
      tool:
        any_of: [filesystem.write_file, filesystem.delete_file]
  - id: allow-tests
    description: Known test commands are allowed.
    action: allow
    match:
      tool: terminal.execute
      arguments:
        command:
          starts_with_any: ["pnpm test", "npm test", "pytest", "go test"]
limits:
  max_tool_calls_per_session: 100
  max_concurrent_calls: 5
  max_runtime_seconds: 900
  max_payload_bytes: 1048576
"""


def seed_database(database: Session, *, force: bool = False) -> dict[str, int | str]:
    existing = database.scalar(select(func.count()).select_from(Workspace))
    if existing and not force:
        return {"status": "already_seeded", "workspaces": int(existing)}
    if force:
        for model in (
            SecretDetection,
            Approval,
            ProtocolEvent,
            Sandbox,
            Report,
            MCPSession,
            Tool,
            Policy,
            MCPClient,
            MCPServer,
            AuditLog,
            Membership,
            User,
            Workspace,
        ):
            database.query(model).delete()
        database.commit()

    workspaces = [
        Workspace(
            id=did("workspace-acme"),
            name="Acme Security Lab",
            slug="acme-security",
            plan_type="community",
            settings={"privacy_mode": "redacted", "retention_days": 30, "locale": "en"},
        ),
        Workspace(
            id=did("workspace-northstar"),
            name="Northstar Engineering",
            slug="northstar",
            plan_type="community",
            settings={"privacy_mode": "standard"},
        ),
        Workspace(
            id=did("workspace-research"),
            name="Sentinel Research",
            slug="research",
            plan_type="community",
            settings={"privacy_mode": "metadata_only"},
        ),
    ]
    database.add_all(workspaces)
    roles = ["owner", "administrator", "security_reviewer", "developer", "auditor", "viewer"]
    names = [
        "Mara Ionescu",
        "Alex Morgan",
        "Priya Shah",
        "David Chen",
        "Elena Popescu",
        "Sam Taylor",
    ]
    users: list[User] = []
    password_hash = hash_password(DEMO_PASSWORD)
    for index, (role, name) in enumerate(zip(roles, names, strict=True)):
        email = "admin@example.com" if index == 0 else f"{role}@example.com"
        user = User(
            id=did(f"user-{role}"),
            email=email,
            display_name=name,
            password_hash=password_hash,
            last_login=datetime.now(UTC) - timedelta(hours=index * 3),
        )
        users.append(user)
        database.add(user)
        database.add(
            Membership(
                id=did(f"membership-{role}"),
                workspace_id=workspaces[0].id,
                user_id=user.id,
                role=role,
            )
        )

    clients: list[MCPClient] = []
    client_specs = [
        ("Codex Local", "codex-local", "stdio", "development", "medium"),
        ("Claude Desktop", "claude-desktop", "stdio", "development", "medium"),
        ("CI Security Agent", "ci-security-agent", "streamable_http", "ci", "high"),
        ("Research Harness", "research-harness", "streamable_http", "research", "high"),
        ("VS Code Agent", "vscode-agent", "stdio", "development", "low"),
    ]
    for index, client_spec in enumerate(client_specs):
        item = MCPClient(
            id=did(f"client-{index}"),
            workspace_id=workspaces[0].id,
            name=client_spec[0],
            client_identifier=client_spec[1],
            version="1.4.0",
            transport=client_spec[2],
            environment=client_spec[3],
            owner_id=users[index % len(users)].id,
            last_seen=datetime.now(UTC) - timedelta(minutes=index * 7),
            risk_level=client_spec[4],
        )
        clients.append(item)
        database.add(item)

    server_specs: list[tuple[str, str, str, int, str, str]] = [
        ("Safe Filesystem", "stdio", "trusted", 18, "healthy", "running"),
        ("Risky Shell", "stdio", "restricted", 92, "healthy", "running"),
        ("Demo Database", "streamable_http", "reviewed", 58, "healthy", "not_configured"),
        ("Demo Messaging", "streamable_http", "reviewed", 64, "healthy", "not_configured"),
        ("Malicious Fixture", "stdio", "quarantined", 98, "isolated", "running"),
        ("Git Repository", "stdio", "trusted", 31, "healthy", "not_configured"),
        ("Cloud Inspector", "streamable_http", "unreviewed", 76, "degraded", "stopped"),
        ("Browser Research", "streamable_http", "restricted", 71, "healthy", "running"),
    ]
    servers: list[MCPServer] = []
    tool_names = [
        [
            "filesystem.list_files",
            "filesystem.read_file",
            "filesystem.write_file",
            "filesystem.delete_file",
            "filesystem.stat",
        ],
        [
            "terminal.execute",
            "terminal.install_package",
            "terminal.read_environment",
            "terminal.list_processes",
            "terminal.kill_process",
        ],
        [
            "database.query",
            "database.update",
            "database.insert",
            "database.delete",
            "database.schema",
        ],
        [
            "messaging.create_draft",
            "messaging.send_message",
            "messaging.list_drafts",
            "messaging.delete_draft",
            "messaging.lookup_recipient",
        ],
        [
            "fixture.injection",
            "fixture.fake_secret",
            "fixture.encoded_content",
            "fixture.policy_bypass",
            "fixture.oversized_payload",
        ],
        ["git.status", "git.diff", "git.commit", "git.push", "git.reset"],
        [
            "cloud.list_resources",
            "cloud.read_secret",
            "cloud.deploy",
            "cloud.delete_resource",
            "cloud.audit",
        ],
        ["network.fetch", "network.search", "network.download", "network.post", "network.resolve"],
    ]
    for index, server_spec in enumerate(server_specs):
        level = (
            "critical"
            if server_spec[3] >= 85
            else "high"
            if server_spec[3] >= 60
            else "medium"
            if server_spec[3] >= 35
            else "low"
        )
        server = MCPServer(
            id=did(f"server-{index}"),
            workspace_id=workspaces[0].id,
            name=server_spec[0],
            description=f"Synthetic local {server_spec[0].lower()} MCP server for deterministic security demonstrations.",
            transport=server_spec[1],
            connection_config={
                "url": f"http://{server_spec[0].lower().replace(' ', '-').replace('fixture', 'fixture-server')}:900{index}"
            }
            if server_spec[1] == "streamable_http"
            else {},
            command_config={
                "command": "python",
                "args": [f"examples/{server_spec[0].lower().replace(' ', '-')}-server/server.py"],
            }
            if server_spec[1] == "stdio"
            else {},
            version="1.0.0-demo",
            capabilities={"tools": {"listChanged": False}, "resources": {"subscribe": False}},
            risk_score=server_spec[3],
            risk_level=level,
            trust_status=server_spec[2],
            sandbox_config={"profile": "no_network", "memory_mb": 256, "cpus": 0.5, "pids": 64},
            sandbox_status=server_spec[5],
            last_health_check=datetime.now(UTC) - timedelta(minutes=index * 2),
            last_scanned=datetime.now(UTC) - timedelta(hours=index + 1),
            health=server_spec[4],
        )
        servers.append(server)
        database.add(server)
        for tool_index, name in enumerate(tool_names[index]):
            combined = name.lower()
            risky = any(
                key in combined
                for key in (
                    "execute",
                    "delete",
                    "secret",
                    "deploy",
                    "kill",
                    "send",
                    "push",
                    "reset",
                    "install",
                )
            )
            score = min(100, server_spec[3] + (12 if risky else -12))
            tool_level = (
                "critical"
                if score >= 85
                else "high"
                if score >= 60
                else "medium"
                if score >= 35
                else "low"
            )
            schema = {
                "type": "object",
                "properties": {
                    "path"
                    if "file" in combined
                    else "command"
                    if "terminal" in combined
                    else "input": {"type": "string"}
                },
                "additionalProperties": False,
            }
            database.add(
                Tool(
                    id=did(f"tool-{index}-{tool_index}"),
                    workspace_id=workspaces[0].id,
                    server_id=server.id,
                    name=name,
                    description=f"Synthetic {name} capability.",
                    input_schema=schema,
                    category=name.split(".")[0],
                    risk_level=tool_level,
                    risk_score=score,
                    side_effect="write" if risky else "read",
                    schema_hash=hashlib.sha256(canonical_json(schema)).hexdigest(),
                    review_status="reviewed"
                    if server_spec[2] in {"trusted", "reviewed"}
                    else "unreviewed",
                )
            )

    policies: list[Policy] = []
    policy_names = [
        "coding-agent-restricted",
        "read-only-baseline",
        "ci-controlled",
        "shell-deny-all",
        "filesystem-workspace-only",
        "network-public-only",
        "database-read-mostly",
        "messaging-approval",
        "research-inspect",
        "quarantine",
        "incident-lockdown",
        "coding-agent-restricted-v2",
    ]
    for index, name in enumerate(policy_names):
        definition = POLICY_YAML.replace("coding-agent-restricted", name).replace(
            "1.2.0", f"1.{index}.0"
        )
        compiled = PolicyEngine.compile(definition)
        policy = Policy(
            id=did(f"policy-{index}"),
            workspace_id=workspaces[0].id,
            name=name,
            description=f"Deterministic controls for {name.replace('-', ' ')}.",
            version=f"1.{index}.0",
            status="active" if index < 9 else "draft",
            raw_definition=definition,
            compiled=compiled,
            created_by=users[0].id,
            reviewed_by=users[2].id if index < 9 else None,
            effective_at=datetime.now(UTC) - timedelta(days=index) if index < 9 else None,
        )
        policies.append(policy)
        database.add(policy)

    sessions: list[MCPSession] = []
    base_time = datetime.now(UTC).replace(second=0, microsecond=0)
    scenario_methods = [
        "initialize",
        "tools/list",
        "filesystem.read_file",
        "filesystem.write_file",
        "terminal.execute",
        "resources/read",
        "network.fetch",
        "fixture.fake_secret",
        "fixture.injection",
    ]
    event_counter = 0
    for index in range(30):
        active = index < 5
        risk_level = ["low", "medium", "high", "critical"][index % 4]
        started = base_time - timedelta(minutes=index * 37)
        session = MCPSession(
            id=did(f"session-{index}"),
            workspace_id=workspaces[0].id,
            client_id=clients[index % 5].id,
            server_id=servers[index % 8].id,
            policy_id=policies[index % 9].id,
            user_id=users[index % 6].id,
            environment=clients[index % 5].environment,
            started_at=started,
            ended_at=None if active else started + timedelta(minutes=4 + index % 11),
            status="active" if active else ("blocked" if index % 7 == 0 else "completed"),
            tool_call_count=10 + index % 9,
            denied_call_count=2 if index % 4 == 0 else 0,
            approval_count=1 if index % 3 == 0 else 0,
            risk_summary={
                "level": risk_level,
                "score": [18, 46, 73, 96][index % 4],
                "top_signal": [
                    "read_only",
                    "filesystem_write",
                    "shell_execution",
                    "destructive_command",
                ][index % 4],
            },
            cost_estimate=round(index * 0.013, 3),
        )
        sessions.append(session)
        database.add(session)
        previous = "0" * 64
        count = 18 if index < 10 else 17
        for sequence in range(1, count + 1):
            method = scenario_methods[(sequence + index) % len(scenario_methods)]
            is_deny = method == "terminal.execute" and index % 4 == 0
            is_secret = method == "fixture.fake_secret"
            is_injection = method == "fixture.injection"
            decision = (
                "deny"
                if is_deny
                else "require_approval"
                if method == "filesystem.write_file" and sequence % 2 == 0
                else "allow"
            )
            payload = {
                "jsonrpc": "2.0",
                "id": sequence,
                "method": method,
                "params": {
                    "name": method,
                    "arguments": {
                        "path": "/workspace/project/README.md",
                        "fixture": "[REDACTED]" if is_secret else "synthetic",
                    },
                },
            }
            timestamp = started + timedelta(seconds=sequence * 11)
            body = {
                "sequence": sequence,
                "timestamp": timestamp.isoformat(),
                "method": method,
                "payload": payload,
                "policy": decision,
            }
            event_hash = hashlib.sha256(previous.encode() + canonical_json(body)).hexdigest()
            event = ProtocolEvent(
                id=did(f"event-{index}-{sequence}"),
                workspace_id=workspaces[0].id,
                session_id=session.id,
                sequence=sequence,
                timestamp=timestamp,
                direction="client_to_server" if sequence % 2 else "server_to_client",
                message_type="request" if sequence % 2 else "response",
                request_id=str(sequence),
                method=method,
                sanitized_payload=payload,
                payload_hash=hashlib.sha256(canonical_json(payload)).hexdigest(),
                previous_hash=previous,
                event_hash=event_hash,
                response_status="blocked" if is_deny else "success",
                duration_ms=round(1.4 + sequence * 0.31, 2),
                policy_result={
                    "decision": decision,
                    "rule": "deny-destructive-shell" if is_deny else "allow-repository-read",
                    "explanation": "Synthetic deterministic policy result.",
                },
                risk_result={
                    "level": "critical" if is_deny else "high" if is_injection else "low",
                    "score": 96 if is_deny else 72 if is_injection else 18,
                    "signals": ["destructive_command"]
                    if is_deny
                    else ["instruction_override"]
                    if is_injection
                    else [],
                },
                redaction_summary=[
                    {
                        "kind": "openai_project_key",
                        "path": "$.result",
                        "fingerprint": "synthetic00000001",
                    }
                ]
                if is_secret
                else [],
            )
            database.add(event)
            previous = event_hash
            event_counter += 1

    approval_statuses = (
        ["pending"] * 8 + ["approved"] * 10 + ["denied"] * 7 + ["expired"] * 3 + ["escalated"] * 2
    )
    for index, approval_status in enumerate(approval_statuses):
        session = sessions[index % len(sessions)]
        requested = base_time - timedelta(minutes=index * 19)
        database.add(
            Approval(
                id=did(f"approval-{index}"),
                workspace_id=workspaces[0].id,
                session_id=session.id,
                request_id=f"req-{index:03d}",
                tool_name=[
                    "filesystem.write_file",
                    "terminal.execute",
                    "messaging.send_message",
                    "cloud.deploy",
                ][index % 4],
                status=approval_status,
                requested_at=requested,
                expires_at=requested + timedelta(hours=2),
                decided_at=None
                if approval_status == "pending"
                else requested + timedelta(minutes=3),
                reviewer_id=None if approval_status == "pending" else users[2].id,
                decision_type=None
                if approval_status == "pending"
                else ("approve_once" if approval_status == "approved" else approval_status),
                original_arguments={
                    "path": "/workspace/project/release-notes.md",
                    "content": "Synthetic release note",
                    "environment": "staging",
                },
                approved_arguments={
                    "path": "/workspace/project/drafts/release-notes.md",
                    "content": "Synthetic release note",
                    "environment": "staging",
                }
                if approval_status == "approved"
                else None,
                justification="Synthetic reviewer decision for the local demonstration."
                if approval_status != "pending"
                else None,
                policy_context={
                    "policy": "coding-agent-restricted",
                    "rule": "require-approval-for-write",
                },
                risk_context={
                    "score": 74 + index % 20,
                    "level": "high",
                    "signals": ["filesystem_write", "external_side_effect"],
                },
                version=2 if approval_status != "pending" else 1,
            )
        )

    for index in range(15):
        database.add(
            SecretDetection(
                id=did(f"secret-{index}"),
                workspace_id=workspaces[0].id,
                session_id=sessions[index].id,
                event_id=did(f"event-{index}-{8 if index < 10 else 7}"),
                kind=["openai_project_key", "github_token", "authorization", "database_url"][
                    index % 4
                ],
                path="$.result.content[0].text",
                fingerprint=f"synthetic{index:08d}",
                action="redacted",
                detected_at=base_time - timedelta(hours=index),
            )
        )

    for index in range(8):
        database.add(
            Sandbox(
                id=did(f"sandbox-{index}"),
                workspace_id=workspaces[0].id,
                server_id=servers[index].id,
                profile=[
                    "no_network",
                    "read_only_workspace",
                    "development_workspace",
                    "restricted_network",
                ][index % 4],
                status=["running", "stopped", "terminated", "healthy"][index % 4],
                container_id=f"demo-{index:012x}",
                config={"memory_mb": 256, "cpus": 0.5, "pids": 64, "network": index % 4 == 3},
                image_digest=f"sha256:{hashlib.sha256(f'demo-{index}'.encode()).hexdigest()}",
                started_at=base_time - timedelta(hours=index + 1),
                stopped_at=None
                if index % 4 in {0, 3}
                else base_time - timedelta(minutes=index * 4),
                termination_reason="runtime limit exceeded" if index % 4 == 2 else None,
            )
        )

    reports_dir = Path("reports/generated")
    reports_dir.mkdir(parents=True, exist_ok=True)
    for index, report_type in enumerate(
        [
            "Session Security Report",
            "MCP Server Risk Assessment",
            "Policy Compliance Report",
            "Approval Activity Report",
            "Workspace Security Summary",
        ]
    ):
        content = f"# {report_type}\n\nSynthetic local report generated for Acme Security Lab.\n"
        path = reports_dir / f"seed-report-{index + 1}.md"
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode()).hexdigest()
        database.add(
            Report(
                id=did(f"report-{index}"),
                workspace_id=workspaces[0].id,
                report_type=report_type,
                format="markdown",
                status="ready",
                artifact_path=str(path),
                sha256=digest,
                signature="synthetic-seed-report-not-signed",
                created_by=users[0].id,
                generated_at=base_time - timedelta(days=index),
            )
        )

    previous = "0" * 64
    for sequence in range(1, 41):
        payload = {
            "sequence": sequence,
            "action": ["auth.login", "policy.evaluate", "approval.decide", "server.scan"][
                sequence % 4
            ],
            "outcome": "success",
        }
        event_hash = hashlib.sha256(previous.encode() + canonical_json(payload)).hexdigest()
        database.add(
            AuditLog(
                id=did(f"audit-{sequence}"),
                workspace_id=workspaces[0].id,
                sequence=sequence,
                actor_id=users[sequence % 6].id,
                action=payload["action"],
                resource_type=["session", "policy", "approval", "server"][sequence % 4],
                resource_id=None,
                timestamp=base_time - timedelta(minutes=sequence * 3),
                request_id=f"audit-req-{sequence}",
                outcome="success",
                metadata_json={"synthetic": True},
                previous_hash=previous,
                event_hash=event_hash,
            )
        )
        previous = event_hash

    database.commit()
    return {
        "status": "seeded",
        "workspaces": 3,
        "users": 6,
        "clients": 5,
        "servers": 8,
        "tools": 40,
        "policies": 12,
        "sessions": 30,
        "events": event_counter,
        "approvals": 30,
        "secret_detections": 15,
        "sandboxes": 8,
        "reports": 5,
        "demo_email": "admin@example.com",
        "demo_password": DEMO_PASSWORD,
    }
