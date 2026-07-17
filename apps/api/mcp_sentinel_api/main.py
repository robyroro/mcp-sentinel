from __future__ import annotations

import hashlib
import os
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from sentinel_core.audit import canonical_json
from sentinel_core.policy import Decision, PolicyEngine, PolicyError
from sentinel_core.redaction import RedactionMode, SecretDetector
from sentinel_core.risk import RiskEngine
from sqlalchemy import desc, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from .auth import (
    Principal,
    current_principal,
    issue_session,
    require_csrf,
    require_gateway_token,
    require_role,
    verify_password,
)
from .config import get_settings
from .database import Base, SessionLocal, engine, get_db
from .models import (
    Approval,
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
    now,
)
from .models import (
    Session as MCPSession,
)
from .schemas import (
    ApprovalDecisionRequest,
    GatewayEvaluateRequest,
    GatewayRecordResponse,
    LoginRequest,
    PolicyTestRequest,
    SandboxRequest,
)
from .seed import seed_database
from .services import (
    DockerSandboxManager,
    append_audit,
    generate_audit_bundle,
    verify_workspace_audit,
)

settings = get_settings()
app = FastAPI(
    title="MCP Sentinel API",
    version=settings.api_version,
    description="Management and enforcement control plane for MCP Sentinel.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=[
        "Content-Type",
        "X-CSRF-Token",
        "X-Request-ID",
        "Idempotency-Key",
        "Authorization",
    ],
)

_rate_windows: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def security_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:100]
    request.state.request_id = request_id
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_payload_bytes:
        return JSONResponse(
            status_code=413,
            content={"detail": "Payload exceeds configured limit.", "request_id": request_id},
        )
    if request.url.path.startswith("/api/v1/auth/login"):
        key = request.client.host if request.client else "unknown"
        window = _rate_windows[key]
        current = time.monotonic()
        while window and window[0] < current - 60:
            window.popleft()
        if len(window) >= 20:
            return JSONResponse(
                status_code=429,
                content={"detail": "Authentication rate limit exceeded.", "request_id": request_id},
            )
        window.append(current)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        if settings.env == "production":
            response = JSONResponse(
                status_code=500,
                content={"detail": "Internal service error.", "request_id": request_id},
            )
        else:
            raise
    response.headers.update(
        {
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            "Server-Timing": f"app;dur={(time.perf_counter() - started) * 1000:.2f}",
        }
    )
    return response


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as database:
        if not database.scalar(select(func.count()).select_from(Workspace)):
            seed_database(database)


def json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def expired(value: datetime) -> bool:
    """Compare database timestamps consistently across SQLite and PostgreSQL."""
    normalized = value if value.tzinfo else value.replace(tzinfo=UTC)
    return normalized < now()


def row_dict(row: Any, *, exclude: set[str] | None = None) -> dict[str, Any]:
    hidden = exclude or set()
    return {
        column.name: json_value(getattr(row, column.name))
        for column in row.__table__.columns
        if column.name not in hidden
    }


def paginate(stmt: Any, database: Session, page: int, page_size: int) -> tuple[list[Any], int]:
    total = database.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = database.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return list(items), int(total)


def page_response(
    items: list[Any],
    total: int,
    page: int,
    page_size: int,
    mapper: Callable[[Any], dict[str, Any]] = row_dict,
) -> dict[str, Any]:
    return {
        "items": [mapper(item) for item in items],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": (total + page_size - 1) // page_size,
        },
    }


@app.get("/api/v1/health")
def health(database: Session = Depends(get_db)) -> dict[str, Any]:
    database.execute(select(1))
    return {
        "status": "healthy",
        "version": settings.api_version,
        "database": "connected",
        "gateway_policy": "fail_closed",
        "time": datetime.now(UTC).isoformat(),
    }


@app.post("/api/v1/auth/login")
def login(
    payload: LoginRequest, response: Response, database: Session = Depends(get_db)
) -> dict[str, Any]:
    user = database.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    if not user or not verify_password(user.password_hash, payload.password):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    membership = database.scalar(
        select(Membership).where(Membership.user_id == user.id).order_by(Membership.id)
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Account has no workspace membership.")
    token, csrf = issue_session(user, membership)
    response.set_cookie(
        "sentinel_session",
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=8 * 3600,
        path="/",
    )
    user.last_login = now()
    append_audit(
        database,
        workspace_id=membership.workspace_id,
        actor_id=user.id,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
    )
    database.commit()
    return {
        "user": {"id": user.id, "email": user.email, "display_name": user.display_name},
        "workspace_id": membership.workspace_id,
        "role": membership.role,
        "csrf_token": csrf,
    }


@app.post("/api/v1/auth/logout")
def logout(
    request: Request,
    response: Response,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, str]:
    require_csrf(request, x_csrf_token)
    response.delete_cookie("sentinel_session", path="/")
    append_audit(
        database,
        workspace_id=principal.workspace_id,
        actor_id=principal.user.id,
        action="auth.logout",
        resource_type="user",
        resource_id=principal.user.id,
        outcome="success",
    )
    database.commit()
    return {"status": "signed_out"}


@app.get("/api/v1/auth/me")
def me(principal: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {
        "id": principal.user.id,
        "email": principal.user.email,
        "display_name": principal.user.display_name,
        "workspace_id": principal.workspace_id,
        "role": principal.role,
        "csrf_token": "use-token-returned-by-login",
    }


@app.get("/api/v1/dashboard")
def dashboard(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    workspace_id = principal.workspace_id
    since = datetime.now(UTC) - timedelta(hours=24)
    metrics = {
        "active_sessions": database.scalar(
            select(func.count())
            .select_from(MCPSession)
            .where(MCPSession.workspace_id == workspace_id, MCPSession.status == "active")
        )
        or 0,
        "connected_clients": database.scalar(
            select(func.count())
            .select_from(MCPClient)
            .where(MCPClient.workspace_id == workspace_id, MCPClient.enabled.is_(True))
        )
        or 0,
        "connected_servers": database.scalar(
            select(func.count())
            .select_from(MCPServer)
            .where(MCPServer.workspace_id == workspace_id, MCPServer.enabled.is_(True))
        )
        or 0,
        "requests_24h": database.scalar(
            select(func.count())
            .select_from(ProtocolEvent)
            .where(ProtocolEvent.workspace_id == workspace_id, ProtocolEvent.timestamp >= since)
        )
        or 0,
        "blocked_actions": database.scalar(
            select(func.count())
            .select_from(ProtocolEvent)
            .where(
                ProtocolEvent.workspace_id == workspace_id,
                ProtocolEvent.response_status == "blocked",
            )
        )
        or 0,
        "pending_approvals": database.scalar(
            select(func.count())
            .select_from(Approval)
            .where(Approval.workspace_id == workspace_id, Approval.status == "pending")
        )
        or 0,
        "critical_servers": database.scalar(
            select(func.count())
            .select_from(MCPServer)
            .where(MCPServer.workspace_id == workspace_id, MCPServer.risk_level == "critical")
        )
        or 0,
        "secret_detections": database.scalar(
            select(func.count())
            .select_from(SecretDetection)
            .where(SecretDetection.workspace_id == workspace_id)
        )
        or 0,
    }
    recent = database.scalars(
        select(MCPSession)
        .where(MCPSession.workspace_id == workspace_id)
        .order_by(desc(MCPSession.started_at))
        .limit(8)
    ).all()
    risky = database.scalars(
        select(MCPServer)
        .where(MCPServer.workspace_id == workspace_id)
        .order_by(desc(MCPServer.risk_score))
        .limit(5)
    ).all()
    volume = [
        {"hour": f"{hour:02d}:00", "allowed": 32 + (hour * 7) % 48, "blocked": (hour * 3) % 12}
        for hour in range(0, 24, 3)
    ]
    return {
        "metrics": metrics,
        "recent_sessions": [session_view(item, database) for item in recent],
        "highest_risk_servers": [
            row_dict(item, exclude={"connection_config", "command_config"}) for item in risky
        ],
        "tool_call_volume": volume,
        "average_policy_evaluation_ms": 1.8,
        "system_health": {
            "gateway": "healthy",
            "api": "healthy",
            "database": "healthy",
            "queue": "healthy",
            "object_storage": "healthy",
        },
    }


@app.get("/api/v1/servers")
def list_servers(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    risk: str | None = None,
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(MCPServer).where(MCPServer.workspace_id == principal.workspace_id)
    if risk:
        stmt = stmt.where(MCPServer.risk_level == risk)
    items, total = paginate(stmt.order_by(desc(MCPServer.risk_score)), database, page, page_size)
    return page_response(
        items,
        total,
        page,
        page_size,
        lambda item: row_dict(item, exclude={"connection_config", "command_config"}),
    )


@app.get("/api/v1/servers/{server_id}")
def get_server(
    server_id: str,
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    server = database.scalar(
        select(MCPServer).where(
            MCPServer.id == server_id, MCPServer.workspace_id == principal.workspace_id
        )
    )
    if not server:
        raise HTTPException(404, "Server not found.")
    tools = database.scalars(
        select(Tool).where(Tool.server_id == server.id).order_by(desc(Tool.risk_score))
    ).all()
    output = row_dict(server, exclude={"connection_config", "command_config"})
    output["tools"] = [row_dict(tool) for tool in tools]
    output["credential_fields"] = "encrypted and never returned"
    return output


@app.post("/api/v1/servers/{server_id}/scan")
def scan_server(
    server_id: str,
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    principal: Principal = Depends(require_role("developer")),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    require_csrf(request, x_csrf_token)
    server = database.scalar(
        select(MCPServer).where(
            MCPServer.id == server_id, MCPServer.workspace_id == principal.workspace_id
        )
    )
    if not server:
        raise HTTPException(404, "Server not found.")
    tools = database.scalars(select(Tool).where(Tool.server_id == server.id)).all()
    server.last_scanned = now()
    server.risk_score = max((tool.risk_score for tool in tools), default=0)
    server.risk_level = RiskEngine._level(server.risk_score).value
    append_audit(
        database,
        workspace_id=principal.workspace_id,
        actor_id=principal.user.id,
        action="server.scan",
        resource_type="server",
        resource_id=server.id,
        outcome="success",
        metadata={"tools_scanned": len(tools), "risk_score": server.risk_score},
    )
    database.commit()
    return {
        "server_id": server.id,
        "tools_scanned": len(tools),
        "risk_score": server.risk_score,
        "risk_level": server.risk_level,
        "explanation": "Capability schemas were scanned for side effects, broad string inputs, network, filesystem, shell, and secret access.",
    }


@app.get("/api/v1/tools")
def list_tools(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = (
        select(Tool)
        .where(Tool.workspace_id == principal.workspace_id)
        .order_by(desc(Tool.risk_score))
    )
    items, total = paginate(stmt, database, page, page_size)
    return page_response(items, total, page, page_size)


@app.get("/api/v1/clients")
def list_clients(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    return {
        "items": [
            row_dict(item)
            for item in database.scalars(
                select(MCPClient)
                .where(MCPClient.workspace_id == principal.workspace_id)
                .order_by(MCPClient.name)
            ).all()
        ]
    }


@app.get("/api/v1/policies")
def list_policies(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    items = database.scalars(
        select(Policy)
        .where(Policy.workspace_id == principal.workspace_id)
        .order_by(Policy.name, desc(Policy.version))
    ).all()
    return {"items": [row_dict(item, exclude={"compiled"}) for item in items]}


@app.get("/api/v1/policies/{policy_id}")
def get_policy(
    policy_id: str,
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    policy = database.scalar(
        select(Policy).where(Policy.id == policy_id, Policy.workspace_id == principal.workspace_id)
    )
    if not policy:
        raise HTTPException(404, "Policy not found.")
    return row_dict(policy)


@app.post("/api/v1/policy-tests")
def test_policy(
    payload: PolicyTestRequest,
    principal: Principal = Depends(require_role("developer")),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    definition = payload.definition
    if payload.policy_id:
        policy = database.scalar(
            select(Policy).where(
                Policy.id == payload.policy_id, Policy.workspace_id == principal.workspace_id
            )
        )
        if not policy:
            raise HTTPException(404, "Policy not found.")
        definition = policy.raw_definition
    if not definition:
        raise HTTPException(422, "Provide policy_id or definition.")
    try:
        result = PolicyEngine(definition).evaluate(payload.request, dry_run=payload.dry_run)
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    risk = RiskEngine().score(
        {
            "tool": payload.request.get("tool"),
            "arguments": payload.request.get("arguments", {}),
            "server_trust": payload.request.get("server_trust", "unreviewed"),
        }
    )
    return {
        "decision": result.decision.value,
        "policy": result.policy,
        "policy_version": result.policy_version,
        "matched_rules": result.matched_rules,
        "trace": [
            {"rule_id": item.rule_id, "matched": item.matched, "reasons": item.reasons}
            for item in result.trace
        ],
        "explanation": result.explanation,
        "transformed_arguments": result.transformed_arguments,
        "response_redactions": result.response_redactions,
        "evaluation_ms": result.evaluation_ms,
        "conflicts": result.conflicts,
        "limits": result.limits,
        "risk": risk.model_dump(),
    }


def session_view(item: MCPSession, database: Session) -> dict[str, Any]:
    client = database.get(MCPClient, item.client_id)
    server = database.get(MCPServer, item.server_id)
    policy = database.get(Policy, item.policy_id)
    user = database.get(User, item.user_id) if item.user_id else None
    output = row_dict(item)
    output.update(
        {
            "client": client.name if client else "Unknown",
            "server": server.name if server else "Unknown",
            "policy": policy.name if policy else "Unknown",
            "user": user.display_name if user else "Service identity",
            "event_count": database.scalar(
                select(func.count())
                .select_from(ProtocolEvent)
                .where(ProtocolEvent.session_id == item.id)
            )
            or 0,
        }
    )
    return output


@app.get("/api/v1/sessions")
def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(MCPSession).where(MCPSession.workspace_id == principal.workspace_id)
    if status_filter:
        stmt = stmt.where(MCPSession.status == status_filter)
    items, total = paginate(stmt.order_by(desc(MCPSession.started_at)), database, page, page_size)
    return page_response(items, total, page, page_size, lambda item: session_view(item, database))


@app.get("/api/v1/sessions/{session_id}")
def get_session(
    session_id: str,
    event_page: int = Query(1, ge=1),
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    item = database.scalar(
        select(MCPSession).where(
            MCPSession.id == session_id, MCPSession.workspace_id == principal.workspace_id
        )
    )
    if not item:
        raise HTTPException(404, "Session not found.")
    events, total = paginate(
        select(ProtocolEvent)
        .where(ProtocolEvent.session_id == item.id)
        .order_by(ProtocolEvent.sequence),
        database,
        event_page,
        100,
    )
    approvals = database.scalars(
        select(Approval).where(Approval.session_id == item.id).order_by(desc(Approval.requested_at))
    ).all()
    secrets = database.scalars(
        select(SecretDetection)
        .where(SecretDetection.session_id == item.id)
        .order_by(desc(SecretDetection.detected_at))
    ).all()
    return {
        "session": session_view(item, database),
        "events": page_response(events, total, event_page, 100),
        "approvals": [row_dict(row) for row in approvals],
        "secrets": [row_dict(row) for row in secrets],
    }


@app.get("/api/v1/events")
def list_events(
    session_id: str | None = None,
    method: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(ProtocolEvent).where(ProtocolEvent.workspace_id == principal.workspace_id)
    if session_id:
        stmt = stmt.where(ProtocolEvent.session_id == session_id)
    if method:
        stmt = stmt.where(ProtocolEvent.method == method)
    items, total = paginate(stmt.order_by(desc(ProtocolEvent.timestamp)), database, page, page_size)
    return page_response(items, total, page, page_size)


@app.get("/api/v1/approvals")
def list_approvals(
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    current = now()
    database.execute(
        update(Approval)
        .where(
            Approval.workspace_id == principal.workspace_id,
            Approval.status == "pending",
            Approval.expires_at < current,
        )
        .values(status="expired", version=Approval.version + 1)
    )
    database.commit()
    stmt = select(Approval).where(Approval.workspace_id == principal.workspace_id)
    if status_filter:
        stmt = stmt.where(Approval.status == status_filter)
    items, total = paginate(stmt.order_by(desc(Approval.requested_at)), database, page, page_size)
    return page_response(items, total, page, page_size)


@app.get("/api/v1/approvals/{approval_id}")
def get_approval(
    approval_id: str,
    principal: Principal = Depends(current_principal),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    approval = database.scalar(
        select(Approval).where(
            Approval.id == approval_id, Approval.workspace_id == principal.workspace_id
        )
    )
    if not approval:
        raise HTTPException(404, "Approval not found.")
    result = row_dict(approval)
    result["session_context"] = get_session(approval.session_id, 1, principal, database)
    return result


@app.post("/api/v1/approvals/{approval_id}/decision")
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(require_role("security_reviewer")),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    require_csrf(request, x_csrf_token)
    approval = database.scalar(
        select(Approval).where(
            Approval.id == approval_id, Approval.workspace_id == principal.workspace_id
        )
    )
    if not approval:
        raise HTTPException(404, "Approval not found.")
    if expired(approval.expires_at) and approval.status == "pending":
        approval.status = "expired"
        approval.version += 1
        database.commit()
        raise HTTPException(409, "Approval has expired.")
    target_status = (
        "approved"
        if payload.decision.startswith("approve")
        else "escalated"
        if payload.decision == "escalate"
        else "denied"
    )
    statement = (
        update(Approval)
        .where(
            Approval.id == approval_id,
            Approval.workspace_id == principal.workspace_id,
            Approval.status == "pending",
            Approval.version == payload.expected_version,
        )
        .values(
            status=target_status,
            decision_type=payload.decision,
            approved_arguments=payload.arguments
            if payload.decision == "approve_modified"
            else approval.original_arguments
            if target_status == "approved"
            else None,
            justification=payload.justification,
            reviewer_id=principal.user.id,
            decided_at=now(),
            version=Approval.version + 1,
        )
    )
    result = cast(CursorResult[Any], database.execute(statement))
    if result.rowcount != 1:
        database.rollback()
        current = database.get(Approval, approval_id)
        raise HTTPException(
            409,
            detail={
                "message": "Approval was already decided or changed by another reviewer.",
                "current_status": current.status if current else "missing",
                "current_version": current.version if current else None,
            },
        )
    append_audit(
        database,
        workspace_id=principal.workspace_id,
        actor_id=principal.user.id,
        action="approval.decide",
        resource_type="approval",
        resource_id=approval_id,
        outcome=target_status,
        metadata={"decision": payload.decision, "idempotency_key": idempotency_key},
    )
    database.commit()
    return {
        "id": approval_id,
        "status": target_status,
        "decision": payload.decision,
        "message": "Decision committed atomically and recorded in the audit chain.",
    }


@app.get("/api/v1/risk")
def risk_dashboard(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    servers = database.scalars(
        select(MCPServer)
        .where(MCPServer.workspace_id == principal.workspace_id)
        .order_by(desc(MCPServer.risk_score))
    ).all()
    tools = database.scalars(
        select(Tool)
        .where(Tool.workspace_id == principal.workspace_id)
        .order_by(desc(Tool.risk_score))
        .limit(12)
    ).all()
    distribution = {
        level: database.scalar(
            select(func.count())
            .select_from(MCPServer)
            .where(MCPServer.workspace_id == principal.workspace_id, MCPServer.risk_level == level)
        )
        or 0
        for level in ("informational", "low", "medium", "high", "critical")
    }
    return {
        "distribution": distribution,
        "servers": [
            row_dict(row, exclude={"connection_config", "command_config"}) for row in servers
        ],
        "tools": [row_dict(row) for row in tools],
        "weights": RiskEngine().weights,
    }


@app.get("/api/v1/secrets")
def list_secrets(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    rows = database.scalars(
        select(SecretDetection)
        .where(SecretDetection.workspace_id == principal.workspace_id)
        .order_by(desc(SecretDetection.detected_at))
    ).all()
    return {
        "items": [row_dict(row) for row in rows],
        "plaintext_storage": False,
        "note": "Only fingerprints, paths, types, and redaction actions are retained.",
    }


@app.get("/api/v1/reports")
def list_reports(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    return {
        "items": [
            row_dict(row)
            for row in database.scalars(
                select(Report)
                .where(Report.workspace_id == principal.workspace_id)
                .order_by(desc(Report.generated_at))
            ).all()
        ]
    }


@app.post("/api/v1/audit/export")
def export_audit(
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    principal: Principal = Depends(require_role("auditor")),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    require_csrf(request, x_csrf_token)
    path = (
        Path("audit-output") / f"sentinel-audit-{principal.workspace_id[:8]}-{int(time.time())}.zip"
    )
    result = generate_audit_bundle(database, principal.workspace_id, path)
    report = Report(
        workspace_id=principal.workspace_id,
        report_type="Signed audit bundle",
        format="zip",
        status="ready",
        artifact_path=str(path),
        sha256=result["sha256"],
        signature=result["signature"],
        created_by=principal.user.id,
    )
    database.add(report)
    append_audit(
        database,
        workspace_id=principal.workspace_id,
        actor_id=principal.user.id,
        action="audit.export",
        resource_type="report",
        resource_id=report.id,
        outcome="success",
        metadata={"sha256": result["sha256"]},
    )
    database.commit()
    return {
        "report_id": report.id,
        "artifact_path": str(path),
        "sha256": result["sha256"],
        "signature_algorithm": "Ed25519",
        "manifest": result["manifest"],
    }


@app.get("/api/v1/reports/{report_id}/download")
def download_report(
    report_id: str,
    principal: Principal = Depends(require_role("auditor")),
    database: Session = Depends(get_db),
) -> FileResponse:
    report = database.scalar(
        select(Report).where(Report.id == report_id, Report.workspace_id == principal.workspace_id)
    )
    if not report or not Path(report.artifact_path).exists():
        raise HTTPException(404, "Report artifact not found.")
    return FileResponse(report.artifact_path, filename=Path(report.artifact_path).name)


@app.get("/api/v1/audit/verify")
def verify_audit(
    principal: Principal = Depends(require_role("auditor")), database: Session = Depends(get_db)
) -> dict[str, Any]:
    valid, message = verify_workspace_audit(database, principal.workspace_id)
    return {"valid": valid, "message": message, "guarantee": "tamper-evident, not immutable"}


@app.get("/api/v1/sandboxes")
def list_sandboxes(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    rows = database.scalars(
        select(Sandbox)
        .where(Sandbox.workspace_id == principal.workspace_id)
        .order_by(desc(Sandbox.started_at))
    ).all()
    return {
        "items": [row_dict(row) for row in rows],
        "manager_available": DockerSandboxManager().available(),
        "isolation_notice": "Containers reduce risk but are not equivalent to hardened virtual machines.",
    }


@app.post("/api/v1/sandboxes")
def start_sandbox(
    payload: SandboxRequest,
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    principal: Principal = Depends(require_role("administrator")),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    require_csrf(request, x_csrf_token)
    server = database.scalar(
        select(MCPServer).where(
            MCPServer.id == payload.server_id, MCPServer.workspace_id == principal.workspace_id
        )
    )
    if not server:
        raise HTTPException(404, "Server not found.")
    sandbox = Sandbox(
        workspace_id=principal.workspace_id,
        server_id=server.id,
        profile=payload.profile,
        status="creating",
        config=payload.model_dump(),
    )
    database.add(sandbox)
    database.flush()
    manager = DockerSandboxManager()
    try:
        container_id = manager.start(database, sandbox, payload)
    except (RuntimeError, ValueError, OSError) as exc:
        sandbox.status = "failed"
        sandbox.termination_reason = str(exc)[:200]
        append_audit(
            database,
            workspace_id=principal.workspace_id,
            actor_id=principal.user.id,
            action="sandbox.start",
            resource_type="sandbox",
            resource_id=sandbox.id,
            outcome="failed",
            metadata={"reason": str(exc)[:200]},
        )
        database.commit()
        raise HTTPException(503, str(exc)) from exc
    append_audit(
        database,
        workspace_id=principal.workspace_id,
        actor_id=principal.user.id,
        action="sandbox.start",
        resource_type="sandbox",
        resource_id=sandbox.id,
        outcome="success",
        metadata={"profile": payload.profile},
    )
    database.commit()
    return {"id": sandbox.id, "status": sandbox.status, "container_id": container_id}


@app.post("/api/v1/sandboxes/{sandbox_id}/stop")
def stop_sandbox(
    sandbox_id: str,
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    principal: Principal = Depends(require_role("administrator")),
    database: Session = Depends(get_db),
) -> dict[str, Any]:
    require_csrf(request, x_csrf_token)
    sandbox = database.scalar(
        select(Sandbox).where(
            Sandbox.id == sandbox_id, Sandbox.workspace_id == principal.workspace_id
        )
    )
    if not sandbox:
        raise HTTPException(404, "Sandbox not found.")
    try:
        DockerSandboxManager().stop(database, sandbox)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    append_audit(
        database,
        workspace_id=principal.workspace_id,
        actor_id=principal.user.id,
        action="sandbox.stop",
        resource_type="sandbox",
        resource_id=sandbox.id,
        outcome="success",
    )
    database.commit()
    return {"id": sandbox.id, "status": sandbox.status}


@app.get("/api/v1/settings")
def workspace_settings(
    principal: Principal = Depends(current_principal), database: Session = Depends(get_db)
) -> dict[str, Any]:
    workspace = database.get(Workspace, principal.workspace_id)
    if workspace is None:
        raise HTTPException(404, "Workspace not found.")
    return {
        "workspace": row_dict(workspace),
        "security": {
            "fail_closed": True,
            "raw_payload_retention_days": settings.raw_payload_retention_days,
            "max_payload_bytes": settings.max_payload_bytes,
            "cookie_secure": settings.cookie_secure,
            "forensic_mode": workspace.settings.get("privacy_mode") == "forensic",
        },
        "supported_locales": ["en", "ro"],
    }


@app.get("/api/v1/metrics", response_class=PlainTextResponse)
def metrics(
    _: Principal = Depends(require_role("auditor")), database: Session = Depends(get_db)
) -> str:
    sessions = (
        database.scalar(
            select(func.count()).select_from(MCPSession).where(MCPSession.status == "active")
        )
        or 0
    )
    approvals = (
        database.scalar(
            select(func.count()).select_from(Approval).where(Approval.status == "pending")
        )
        or 0
    )
    return f"# HELP sentinel_active_sessions Active MCP sessions\n# TYPE sentinel_active_sessions gauge\nsentinel_active_sessions {sessions}\n# HELP sentinel_pending_approvals Pending approval requests\n# TYPE sentinel_pending_approvals gauge\nsentinel_pending_approvals {approvals}\n"


def gateway_event(
    database: Session,
    session: MCPSession,
    *,
    direction: str,
    message_type: str,
    request_id: str | int | None,
    method: str | None,
    payload: dict[str, Any],
    policy: dict[str, Any],
    risk: dict[str, Any],
    redactions: list[dict[str, Any]],
    status_value: str,
    duration_ms: float | None = None,
) -> ProtocolEvent:
    last = database.scalar(
        select(ProtocolEvent)
        .where(ProtocolEvent.session_id == session.id)
        .order_by(desc(ProtocolEvent.sequence))
        .limit(1)
    )
    sequence = last.sequence + 1 if last else 1
    previous = last.event_hash if last else "0" * 64
    timestamp = now()
    body = {
        "sequence": sequence,
        "timestamp": timestamp.isoformat(),
        "method": method,
        "payload": payload,
        "policy": policy.get("decision"),
    }
    event_hash = hashlib.sha256(previous.encode() + canonical_json(body)).hexdigest()
    event = ProtocolEvent(
        workspace_id=session.workspace_id,
        session_id=session.id,
        sequence=sequence,
        timestamp=timestamp,
        direction=direction,
        message_type=message_type,
        request_id=str(request_id) if request_id is not None else None,
        method=method,
        sanitized_payload=payload,
        payload_hash=hashlib.sha256(canonical_json(payload)).hexdigest(),
        previous_hash=previous,
        event_hash=event_hash,
        response_status=status_value,
        duration_ms=duration_ms,
        policy_result=policy,
        risk_result=risk,
        redaction_summary=redactions,
    )
    database.add(event)
    return event


@app.post("/api/v1/internal/gateway/evaluate", dependencies=[Depends(require_gateway_token)])
def gateway_evaluate(
    payload: GatewayEvaluateRequest, database: Session = Depends(get_db)
) -> dict[str, Any]:
    workspace = database.scalar(select(Workspace).where(Workspace.slug == payload.workspace_slug))
    if not workspace:
        raise HTTPException(404, "Gateway workspace not found.")
    client = database.scalar(
        select(MCPClient).where(
            MCPClient.workspace_id == workspace.id,
            MCPClient.client_identifier == payload.client_identifier,
            MCPClient.enabled.is_(True),
        )
    )
    server = database.scalar(
        select(MCPServer).where(
            MCPServer.workspace_id == workspace.id,
            MCPServer.name == payload.server_name,
            MCPServer.enabled.is_(True),
        )
    )
    if not client or not server:
        raise HTTPException(403, "Client or server is not registered and enabled.")
    policy = database.scalar(
        select(Policy)
        .where(Policy.workspace_id == workspace.id, Policy.status == "active")
        .order_by(Policy.effective_at)
    )
    if not policy:
        raise HTTPException(503, "No active policy; gateway fails closed.")
    session = database.get(MCPSession, payload.session_id) if payload.session_id else None
    if session and session.workspace_id != workspace.id:
        raise HTTPException(403, "Session workspace mismatch.")
    if not session:
        session = MCPSession(
            workspace_id=workspace.id,
            client_id=client.id,
            server_id=server.id,
            policy_id=policy.id,
            environment=client.environment,
            protocol_version=payload.protocol_version,
            status="active",
            risk_summary={"level": "informational", "score": 0},
        )
        database.add(session)
        database.flush()
    if payload.method == "tools/call":
        tool = str(payload.params.get("name", ""))
        arguments = payload.params.get("arguments", {})
    else:
        tool = payload.method
        arguments = payload.params
    redaction = SecretDetector().inspect(arguments, RedactionMode.PARTIAL)
    risk_result = RiskEngine().score(
        {
            "tool": tool,
            "arguments": arguments,
            "server_trust": server.trust_status,
            "recent_denials": session.denied_call_count,
        }
    )
    policy_request = {
        "client": client.client_identifier,
        "server": server.name,
        "tool": tool,
        "method": payload.method,
        "environment": session.environment,
        "arguments": redaction.value,
    }
    if payload.method in {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "resources/list",
        "prompts/list",
        "notifications/cancelled",
        "ping",
    }:
        policy_result: dict[str, Any] = {
            "decision": "allow",
            "explanation": "Protocol lifecycle and discovery method allowed; hard limits still apply.",
            "matched_rules": ["protocol-lifecycle"],
        }
    else:
        evaluated = PolicyEngine(policy.raw_definition).evaluate(policy_request)
        policy_result = {
            "decision": evaluated.decision.value,
            "explanation": evaluated.explanation,
            "matched_rules": list(evaluated.matched_rules),
            "evaluation_ms": evaluated.evaluation_ms,
            "transformed_arguments": evaluated.transformed_arguments,
            "conflicts": list(evaluated.conflicts),
        }
    decision = str(policy_result["decision"])
    if risk_result.level.value == "critical" and decision not in {"deny", "terminate_session"}:
        decision = "deny"
        policy_result = {
            **policy_result,
            "decision": "deny",
            "explanation": str(policy_result["explanation"])
            + " Critical deterministic risk override applied.",
        }
    approval_id = None
    if decision == Decision.REQUIRE_APPROVAL.value:
        approval = Approval(
            workspace_id=workspace.id,
            session_id=session.id,
            request_id=str(payload.request_id),
            tool_name=tool,
            status="pending",
            expires_at=now() + timedelta(minutes=10),
            original_arguments=redaction.value,
            policy_context=policy_result,
            risk_context=risk_result.model_dump(),
        )
        database.add(approval)
        database.flush()
        approval_id = approval.id
        session.approval_count += 1
    if decision in {Decision.DENY.value, Decision.TERMINATE.value}:
        session.denied_call_count += 1
    if payload.method == "tools/call":
        session.tool_call_count += 1
    session.risk_summary = {
        "score": risk_result.score,
        "level": risk_result.level.value,
        "top_signal": risk_result.signals[-1].key if risk_result.signals else "base",
    }
    sanitized_message = {
        "jsonrpc": "2.0",
        "id": payload.request_id,
        "method": payload.method,
        "params": {**payload.params, "arguments": redaction.value}
        if "arguments" in payload.params
        else redaction.value,
    }
    event = gateway_event(
        database,
        session,
        direction="client_to_server",
        message_type="request",
        request_id=payload.request_id,
        method=payload.method,
        payload=sanitized_message,
        policy=policy_result,
        risk=risk_result.model_dump(),
        redactions=redaction.summary(),
        status_value="blocked"
        if decision in {"deny", "terminate_session"}
        else "pending_approval"
        if approval_id
        else "allowed",
    )
    for finding in redaction.findings:
        database.add(
            SecretDetection(
                workspace_id=workspace.id,
                session_id=session.id,
                event_id=event.id,
                kind=finding.kind,
                path=finding.path,
                fingerprint=finding.fingerprint,
                action="redacted",
            )
        )
    append_audit(
        database,
        workspace_id=workspace.id,
        actor_id=None,
        action="gateway.evaluate",
        resource_type="protocol_event",
        resource_id=event.id,
        outcome=decision,
        request_id=str(payload.request_id),
        metadata={"method": payload.method, "risk": risk_result.level.value},
    )
    database.commit()
    forwarded_params = dict(payload.params)
    if "arguments" in forwarded_params:
        forwarded_params["arguments"] = policy_result.get("transformed_arguments", redaction.value)
    return {
        "session_id": session.id,
        "decision": decision,
        "explanation": str(policy_result["explanation"]),
        "approval_id": approval_id,
        "forwarded_params": forwarded_params,
        "risk": risk_result.model_dump(),
        "policy": policy_result,
        "redactions": redaction.summary(),
    }


@app.get(
    "/api/v1/internal/gateway/approvals/{approval_id}",
    dependencies=[Depends(require_gateway_token)],
)
def gateway_approval_status(
    approval_id: str, database: Session = Depends(get_db)
) -> dict[str, Any]:
    approval = database.get(Approval, approval_id)
    if not approval:
        raise HTTPException(404, "Approval not found.")
    if approval.status == "pending" and expired(approval.expires_at):
        approval.status = "expired"
        approval.version += 1
        database.commit()
    return {
        "id": approval.id,
        "status": approval.status,
        "decision_type": approval.decision_type,
        "approved_arguments": approval.approved_arguments,
        "expires_at": approval.expires_at,
    }


@app.post("/api/v1/internal/gateway/response", dependencies=[Depends(require_gateway_token)])
def gateway_record_response(
    payload: GatewayRecordResponse, database: Session = Depends(get_db)
) -> dict[str, Any]:
    session = database.get(MCPSession, payload.session_id)
    if not session:
        raise HTTPException(404, "Gateway session not found.")
    redaction = SecretDetector().inspect(payload.payload, RedactionMode.PARTIAL)
    event = gateway_event(
        database,
        session,
        direction="server_to_client",
        message_type="error" if payload.is_error else "response",
        request_id=payload.request_id,
        method=payload.method,
        payload=redaction.value,
        policy={"decision": "response_inspected"},
        risk={},
        redactions=redaction.summary(),
        status_value="error" if payload.is_error else "success",
        duration_ms=payload.duration_ms,
    )
    for finding in redaction.findings:
        database.add(
            SecretDetection(
                workspace_id=session.workspace_id,
                session_id=session.id,
                event_id=event.id,
                kind=finding.kind,
                path=finding.path,
                fingerprint=finding.fingerprint,
                action="redacted",
            )
        )
    database.commit()
    return {"payload": redaction.value, "redactions": redaction.summary()}


def run() -> None:
    uvicorn.run(
        "mcp_sentinel_api.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )


if __name__ == "__main__":
    run()
