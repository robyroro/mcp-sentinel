from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from celery import Celery
from mcp_sentinel_api.config import get_settings
from mcp_sentinel_api.database import SessionLocal
from mcp_sentinel_api.models import MCPServer, ProtocolEvent, Tool, Workspace
from mcp_sentinel_api.services import generate_audit_bundle
from sqlalchemy import delete, func, select

settings = get_settings()
celery = Celery(
    "mcp-sentinel",
    broker=settings.redis_url if hasattr(settings, "redis_url") else "redis://redis:6379/0",
)
celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "retention-cleanup-hourly": {"task": "sentinel.retention_cleanup", "schedule": 3600.0},
        "server-health-five-minutes": {"task": "sentinel.server_health", "schedule": 300.0},
    },
)


@celery.task(
    name="sentinel.analyze_server", autoretry_for=(RuntimeError,), retry_backoff=True, max_retries=3
)
def analyze_server(server_id: str) -> dict:
    with SessionLocal.begin() as database:
        server = database.get(MCPServer, server_id)
        if not server:
            raise RuntimeError("server not found")
        scores = database.scalars(select(Tool.risk_score).where(Tool.server_id == server_id)).all()
        server.risk_score = max(scores, default=0)
        server.risk_level = (
            "critical"
            if server.risk_score >= 85
            else "high"
            if server.risk_score >= 60
            else "medium"
            if server.risk_score >= 35
            else "low"
        )
        server.last_scanned = datetime.now(UTC)
        return {"server_id": server_id, "risk_score": server.risk_score, "tools": len(scores)}


@celery.task(name="sentinel.generate_report")
def generate_report(workspace_id: str) -> dict:
    destination = Path("/data/reports") / f"sentinel-audit-{workspace_id}.zip"
    with SessionLocal() as database:
        return generate_audit_bundle(database, workspace_id, destination)


@celery.task(name="sentinel.retention_cleanup")
def retention_cleanup() -> dict:
    deleted = 0
    with SessionLocal.begin() as database:
        workspaces = database.scalars(select(Workspace)).all()
        for workspace in workspaces:
            days = int(
                workspace.settings.get("retention_days", settings.raw_payload_retention_days)
            )
            cutoff = datetime.now(UTC) - timedelta(days=days)
            result = database.execute(
                delete(ProtocolEvent).where(
                    ProtocolEvent.workspace_id == workspace.id, ProtocolEvent.timestamp < cutoff
                )
            )
            deleted += result.rowcount or 0
    return {"deleted": deleted, "mode": "workspace_retention"}


@celery.task(name="sentinel.server_health")
def server_health() -> dict:
    with SessionLocal.begin() as database:
        count = database.scalar(select(func.count()).select_from(MCPServer)) or 0
    return {"registered_servers": count, "checked_at": datetime.now(UTC).isoformat()}


@celery.task(
    name="sentinel.notification_delivery",
    autoretry_for=(OSError,),
    retry_backoff=True,
    max_retries=5,
)
def notification_delivery(notification_id: str, destination: str) -> dict:
    return {
        "notification_id": notification_id,
        "destination": destination,
        "status": "queued_for_adapter",
    }
