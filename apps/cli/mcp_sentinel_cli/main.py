from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import keyring
import typer
from mcp_sentinel_api.services import verify_bundle
from rich.console import Console
from rich.table import Table
from sentinel_core.policy import PolicyEngine, PolicyError

app = typer.Typer(
    help="Operate MCP Sentinel servers, policies, sessions, approvals, sandboxes, and audit bundles.",
    no_args_is_help=True,
)
server_app = typer.Typer(help="Register and inspect MCP servers.")
client_app = typer.Typer(help="Configure MCP clients.")
policy_app = typer.Typer(help="Validate, test, and apply policies.")
session_app = typer.Typer(help="List and inspect sessions.")
replay_app = typer.Typer(help="Simulate session replay.")
approvals_app = typer.Typer(help="List and decide approval requests.")
audit_app = typer.Typer(help="Export and verify tamper-evident audit bundles.")
sandbox_app = typer.Typer(help="Run and stop isolated MCP servers.")
app.add_typer(server_app, name="server")
app.add_typer(client_app, name="client")
app.add_typer(policy_app, name="policy")
app.add_typer(session_app, name="session")
app.add_typer(replay_app, name="replay")
app.add_typer(approvals_app, name="approvals")
app.add_typer(audit_app, name="audit")
app.add_typer(sandbox_app, name="sandbox")
console = Console(stderr=True)
SERVICE = "mcp-sentinel-cli"


def api_url() -> str:
    return os.getenv("SENTINEL_API_URL", "http://localhost:8000").rstrip("/")


def credentials() -> tuple[str, str]:
    token = keyring.get_password(SERVICE, api_url())
    csrf = keyring.get_password(SERVICE, api_url() + ":csrf")
    if not token or not csrf:
        console.print("[red]Not authenticated.[/] Run [bold]mcp-sentinel login[/].")
        raise typer.Exit(3)
    return token, csrf


def request(method: str, path: str, *, payload: Any = None, authenticated: bool = True) -> Any:
    headers: dict[str, str] = {"X-Request-ID": "sentinel-cli"}
    cookies: dict[str, str] = {}
    if authenticated:
        token, csrf = credentials()
        cookies["sentinel_session"] = token
        if method != "GET":
            headers["X-CSRF-Token"] = csrf
            headers["Idempotency-Key"] = os.urandom(12).hex()
    try:
        response = httpx.request(
            method, api_url() + path, json=payload, headers=headers, cookies=cookies, timeout=90
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]API connection failed:[/] {exc}")
        raise typer.Exit(4) from exc
    if response.status_code >= 400:
        console.print(f"[red]API returned {response.status_code}:[/] {response.text}")
        raise typer.Exit(5)
    return response.json() if response.content else {}


def render_items(items: list[dict[str, Any]], columns: list[str], json_output: bool) -> None:
    if json_output:
        print(json.dumps(items, indent=2, default=str))
        return
    table = Table(show_header=True, header_style="bold cyan")
    for column in columns:
        table.add_column(column.replace("_", " ").title())
    for item in items:
        table.add_row(*(str(item.get(column, "")) for column in columns))
    console.print(table)


@app.command()
def login(
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
) -> None:
    try:
        response = httpx.post(
            api_url() + "/api/v1/auth/login",
            json={"email": email, "password": password},
            timeout=30,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]Login failed:[/] {exc}")
        raise typer.Exit(2) from exc
    token = response.cookies.get("sentinel_session")
    body = response.json()
    if not token:
        console.print("[red]API did not return a secure session cookie.[/]")
        raise typer.Exit(2)
    keyring.set_password(SERVICE, api_url(), token)
    keyring.set_password(SERVICE, api_url() + ":csrf", body["csrf_token"])
    console.print(
        f"Authenticated as [bold]{body['user']['email']}[/] with role [cyan]{body['role']}[/]. Session stored in the OS credential store."
    )


@app.command()
def status(json_output: bool = typer.Option(False, "--json")) -> None:
    data = request("GET", "/api/v1/health", authenticated=False)
    if json_output:
        print(json.dumps(data, indent=2))
    else:
        console.print(
            f"API: [green]{data['status']}[/] · version {data['version']} · policy {data['gateway_policy']}"
        )


@server_app.command("list")
def server_list(json_output: bool = typer.Option(False, "--json")) -> None:
    render_items(
        request("GET", "/api/v1/servers")["items"],
        ["name", "transport", "trust_status", "risk_score", "health"],
        json_output,
    )


@server_app.command("scan")
def server_scan(server_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    data = request("POST", f"/api/v1/servers/{server_id}/scan")
    print(json.dumps(data, indent=2)) if json_output else console.print(
        f"Scanned {data['tools_scanned']} tools · risk [bold]{data['risk_score']} {data['risk_level']}[/]"
    )


@server_app.command("add")
def server_add() -> None:
    console.print(
        "Interactive credential registration is not available in v0.1. Add reviewed server configuration through deployment/seed configuration; the CLI will not accept credentials on a command line."
    )


@client_app.command("configure")
def client_configure(server: str, output: Path = Path("mcp-sentinel-client.json")) -> None:
    config = {
        "mcpServers": {
            server: {
                "command": "sentinel-gateway",
                "args": ["stdio", "--", "python", "server.py"],
                "env": {"SENTINEL_SERVER_NAME": server, "SENTINEL_API_URL": api_url()},
            }
        }
    }
    output.write_text(json.dumps(config, indent=2), encoding="utf-8")
    console.print(
        f"Wrote client configuration to {output}. Add SENTINEL_GATEWAY_API_TOKEN through a secret manager, not this file."
    )


@policy_app.command("validate")
def policy_validate(path: Path, json_output: bool = typer.Option(False, "--json")) -> None:
    try:
        engine = PolicyEngine(path.read_text(encoding="utf-8"))
    except (OSError, PolicyError) as exc:
        console.print(f"[red]Invalid policy:[/] {exc}")
        raise typer.Exit(2) from exc
    result = {
        "valid": True,
        "name": engine.document["name"],
        "rules": len(engine.document.get("rules", [])),
        "canonical_sha256": __import__("hashlib").sha256(engine.canonical().encode()).hexdigest(),
    }
    print(json.dumps(result, indent=2)) if json_output else console.print(
        f"[green]Valid[/] {result['name']} · {result['rules']} rules · {result['canonical_sha256'][:12]}"
    )


@policy_app.command("test")
def policy_test(
    path: Path, request_path: Path, json_output: bool = typer.Option(False, "--json")
) -> None:
    engine = PolicyEngine(path.read_text(encoding="utf-8"))
    result = engine.evaluate(json.loads(request_path.read_text(encoding="utf-8")), dry_run=True)
    data = {
        "decision": result.decision.value,
        "matched_rules": result.matched_rules,
        "explanation": result.explanation,
        "evaluation_ms": result.evaluation_ms,
        "conflicts": result.conflicts,
    }
    print(json.dumps(data, indent=2)) if json_output else console.print(
        f"Decision [bold]{data['decision']}[/] · {data['explanation']} · {data['evaluation_ms']} ms"
    )


@policy_app.command("apply")
def policy_apply() -> None:
    console.print(
        "Policy activation requires administrator review in the web console; validate and test locally before activation."
    )


@session_app.command("list")
def session_list(json_output: bool = typer.Option(False, "--json")) -> None:
    render_items(
        request("GET", "/api/v1/sessions")["items"],
        ["started_at", "client", "server", "status", "risk_summary", "event_count"],
        json_output,
    )


@session_app.command("inspect")
def session_inspect(session_id: str) -> None:
    print(json.dumps(request("GET", f"/api/v1/sessions/{session_id}"), indent=2, default=str))


@replay_app.command("simulate")
def replay_simulate(session_id: str, policy_path: Path) -> None:
    session = request("GET", f"/api/v1/sessions/{session_id}")
    engine = PolicyEngine(policy_path.read_text(encoding="utf-8"))
    changes = []
    for event in session["events"]["items"]:
        payload = event.get("sanitized_payload") or {}
        if payload.get("method") != "tools/call":
            continue
        params = payload.get("params") or {}
        new = engine.evaluate(
            {"tool": params.get("name"), "arguments": params.get("arguments", {})}, dry_run=True
        )
        old = (event.get("policy_result") or {}).get("decision")
        if old != new.decision.value:
            changes.append(
                {
                    "sequence": event["sequence"],
                    "original": old,
                    "simulated": new.decision.value,
                    "rules": new.matched_rules,
                }
            )
    print(json.dumps({"mode": "simulation", "server_called": False, "changes": changes}, indent=2))


@approvals_app.command("list")
def approvals_list(json_output: bool = typer.Option(False, "--json")) -> None:
    render_items(
        request("GET", "/api/v1/approvals")["items"],
        ["id", "tool_name", "status", "requested_at", "expires_at", "version"],
        json_output,
    )


@approvals_app.command("approve")
def approvals_approve(approval_id: str, expected_version: int, justification: str) -> None:
    data = request(
        "POST",
        f"/api/v1/approvals/{approval_id}/decision",
        payload={
            "decision": "approve_once",
            "expected_version": expected_version,
            "justification": justification,
        },
    )
    console.print(f"Approval {approval_id}: [green]{data['status']}[/]")


@audit_app.command("export")
def audit_export() -> None:
    data = request("POST", "/api/v1/audit/export")
    console.print(f"Created signed bundle {data['artifact_path']} · sha256 {data['sha256']}")


@audit_app.command("verify")
def audit_verify(bundle: Path, json_output: bool = typer.Option(False, "--json")) -> None:
    valid, messages = verify_bundle(bundle)
    data = {"valid": valid, "messages": messages}
    print(json.dumps(data, indent=2)) if json_output else console.print(
        ("[green]PASS[/] " if valid else "[red]FAIL[/] ") + " · ".join(messages)
    )
    if not valid:
        raise typer.Exit(1)


@sandbox_app.command("run")
def sandbox_run(server_id: str, image: str, profile: str = "no_network") -> None:
    data = request(
        "POST",
        "/api/v1/sandboxes",
        payload={
            "server_id": server_id,
            "profile": profile,
            "image": image,
            "memory_mb": 256,
            "cpus": 0.5,
            "pids": 64,
            "timeout_seconds": 900,
            "network": False,
            "mounts": [],
        },
    )
    console.print(f"Sandbox {data['id']}: [green]{data['status']}[/]")


@app.command()
def doctor() -> None:
    checks = []
    checks.append(("Python", sys.version.split()[0], sys.version_info >= (3, 12)))
    checks.append(
        (
            "API",
            api_url(),
            request("GET", "/api/v1/health", authenticated=False).get("status") == "healthy",
        )
    )
    checks.append(("OS credential store", keyring.get_keyring().__class__.__name__, True))
    table = Table("Check", "Value", "Result")
    for name, value, valid in checks:
        table.add_row(name, str(value), "PASS" if valid else "FAIL")
    console.print(table)
    if not all(item[2] for item in checks):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
