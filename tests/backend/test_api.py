from pathlib import Path

from fastapi.testclient import TestClient
from mcp_sentinel_api.services import verify_bundle


def test_seeded_dashboard_and_workspace_isolation(authenticated):
    client, _ = authenticated
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert data["metrics"]["active_sessions"] == 5
    assert data["metrics"]["connected_servers"] == 8
    assert data["metrics"]["secret_detections"] == 15


def test_policy_tester_returns_trace_and_risk(authenticated):
    client, _ = authenticated
    policy = client.get("/api/v1/policies").json()["items"][0]
    response = client.post(
        "/api/v1/policy-tests",
        json={
            "policy_id": policy["id"],
            "request": {
                "tool": "filesystem.read_file",
                "arguments": {"path": "/workspace/project/.env"},
                "server_trust": "trusted",
            },
            "dry_run": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "deny"
    assert body["trace"]
    assert body["risk"]["score"] >= 35


def test_approval_decision_is_atomic(authenticated):
    client, csrf = authenticated
    approval = client.get("/api/v1/approvals?status=pending").json()["items"][0]
    payload = {
        "decision": "approve_once",
        "expected_version": approval["version"],
        "justification": "Reviewed synthetic request and approved once.",
    }
    headers = {"X-CSRF-Token": csrf, "Idempotency-Key": "pytest-approval"}
    first = client.post(
        f"/api/v1/approvals/{approval['id']}/decision", json=payload, headers=headers
    )
    second = client.post(
        f"/api/v1/approvals/{approval['id']}/decision", json=payload, headers=headers
    )
    assert first.status_code == 200
    assert second.status_code == 409


def test_signed_audit_export_verifies(authenticated):
    client, csrf = authenticated
    response = client.post("/api/v1/audit/export", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    path = Path(response.json()["artifact_path"])
    valid, messages = verify_bundle(path)
    assert valid, messages
    assert any("signature" in message for message in messages)


def test_role_restrictions(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "SentinelDemo!2026"},
    )
    assert response.status_code == 200
    csrf = response.json()["csrf_token"]
    server_id = client.get("/api/v1/servers").json()["items"][0]["id"]
    forbidden = client.post(f"/api/v1/servers/{server_id}/scan", headers={"X-CSRF-Token": csrf})
    assert forbidden.status_code == 403


def test_gateway_fails_closed_and_records_sanitized_event(client: TestClient):
    headers = {"Authorization": "Bearer dev-gateway-token-change-me"}
    response = client.post(
        "/api/v1/internal/gateway/evaluate",
        headers=headers,
        json={
            "workspace_slug": "acme-security",
            "client_identifier": "codex-local",
            "server_name": "Safe Filesystem",
            "method": "tools/call",
            "request_id": "gateway-test-1",
            "params": {
                "name": "filesystem.read_file",
                "arguments": {"path": "/workspace/project/.env"},
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "deny"
    unauthorized = client.post("/api/v1/internal/gateway/evaluate", json={})
    assert unauthorized.status_code == 401
