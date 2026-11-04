from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    plan_type: Mapped[str] = mapped_column(String(30), default="community")
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(30), default="active")
    auth_state: Mapped[str] = mapped_column(String(30), default="password")
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("workspace_id", "user_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(40))
    workspace: Mapped[Workspace] = relationship()
    user: Mapped[User] = relationship()


class MCPClient(Base, TimestampMixin):
    __tablename__ = "mcp_clients"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    client_identifier: Mapped[str] = mapped_column(String(120), index=True)
    version: Mapped[str] = mapped_column(String(40), default="unknown")
    transport: Mapped[str] = mapped_column(String(30))
    environment: Mapped[str] = mapped_column(String(30), default="development")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    authentication_method: Mapped[str] = mapped_column(String(40), default="gateway_token")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class MCPServer(Base, TimestampMixin):
    __tablename__ = "mcp_servers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    transport: Mapped[str] = mapped_column(String(30))
    connection_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    command_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    repository_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    version: Mapped[str] = mapped_column(String(40), default="unknown")
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), default="informational")
    trust_status: Mapped[str] = mapped_column(String(30), default="unreviewed")
    sandbox_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sandbox_status: Mapped[str] = mapped_column(String(30), default="not_configured")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_health_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health: Mapped[str] = mapped_column(String(30), default="unknown")


class Tool(Base):
    __tablename__ = "tools"
    __table_args__ = (UniqueConstraint("server_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    server_id: Mapped[str] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(180), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    output_schema: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    category: Mapped[str] = mapped_column(String(50), default="unknown")
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    side_effect: Mapped[str] = mapped_column(String(30), default="unknown")
    schema_hash: Mapped[str] = mapped_column(String(64))
    review_status: Mapped[str] = mapped_column(String(30), default="unreviewed")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    status: Mapped[str] = mapped_column(String(30), default="draft")
    language: Mapped[str] = mapped_column(String(20), default="sentinel-yaml")
    raw_definition: Mapped[str] = mapped_column(Text)
    compiled: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("mcp_clients.id"), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    environment: Mapped[str] = mapped_column(String(30))
    protocol_version: Mapped[str] = mapped_column(String(20), default="2025-11-25")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="active")
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0)
    denied_call_count: Mapped[int] = mapped_column(Integer, default=0)
    approval_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    cost_estimate: Mapped[float] = mapped_column(Float, default=0)


class ProtocolEvent(Base):
    __tablename__ = "protocol_events"
    __table_args__ = (
        UniqueConstraint("session_id", "sequence"),
        Index("ix_events_workspace_timestamp", "workspace_id", "timestamp"),
        Index("ix_events_session_method", "session_id", "method"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    sequence: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    direction: Mapped[str] = mapped_column(String(30))
    message_type: Mapped[str] = mapped_column(String(40))
    request_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    method: Mapped[str | None] = mapped_column(String(180), nullable=True)
    sanitized_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64))
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    response_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    policy_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    risk_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    redaction_summary: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    request_id: Mapped[str] = mapped_column(String(100), index=True)
    tool_name: Mapped[str] = mapped_column(String(180), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decision_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    original_arguments: Mapped[dict[str, Any]] = mapped_column(JSON)
    approved_arguments: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_context: Mapped[dict[str, Any]] = mapped_column(JSON)
    risk_context: Mapped[dict[str, Any]] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(Integer, default=1)


class SecretDetection(Base):
    __tablename__ = "secret_detections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    event_id: Mapped[str | None] = mapped_column(ForeignKey("protocol_events.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(60))
    path: Mapped[str] = mapped_column(String(300))
    fingerprint: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(30), default="redacted")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Sandbox(Base):
    __tablename__ = "sandboxes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("mcp_servers.id"), index=True)
    profile: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), default="created")
    container_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON)
    image_digest: Mapped[str | None] = mapped_column(String(200), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    termination_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    report_type: Mapped[str] = mapped_column(String(80))
    format: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default="ready")
    artifact_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_workspace_sequence", "workspace_id", "sequence", unique=True),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120))
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    request_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    outcome: Mapped[str] = mapped_column(String(30))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
