from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)


class PolicyTestRequest(BaseModel):
    policy_id: str | None = None
    definition: str | None = None
    request: dict[str, Any]
    dry_run: bool = True


class ApprovalDecisionRequest(BaseModel):
    decision: Literal[
        "approve_once",
        "approve_session",
        "approve_modified",
        "approve_similar",
        "deny",
        "deny_and_block",
        "escalate",
    ]
    expected_version: int = Field(ge=1)
    arguments: dict[str, Any] | None = None
    justification: str = Field(min_length=4, max_length=2000)


class GatewayEvaluateRequest(BaseModel):
    workspace_slug: str = "acme-security"
    session_id: str | None = None
    client_identifier: str
    server_name: str
    method: str
    request_id: str | int | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    protocol_version: str = "2025-11-25"


class GatewayRecordResponse(BaseModel):
    session_id: str
    request_id: str | int | None = None
    method: str | None = None
    payload: dict[str, Any]
    duration_ms: float | None = None
    is_error: bool = False


class SandboxRequest(BaseModel):
    server_id: str
    profile: Literal[
        "no_network", "read_only_workspace", "development_workspace", "restricted_network", "custom"
    ]
    image: str = Field(pattern=r"^[a-zA-Z0-9./:_@-]+$")
    memory_mb: int = Field(default=256, ge=64, le=4096)
    cpus: float = Field(default=0.5, gt=0, le=4)
    pids: int = Field(default=64, ge=16, le=512)
    timeout_seconds: int = Field(default=900, ge=10, le=86_400)
    network: bool = False
    mounts: list[dict[str, Any]] = Field(default_factory=list, max_length=16)
