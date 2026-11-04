from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import docker
from docker.types import Mount
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sentinel_core.audit import SigningKey, canonical_json
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditLog, ProtocolEvent, Sandbox, now
from .schemas import SandboxRequest


def append_audit(
    database: Session,
    *,
    workspace_id: str,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    metadata: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> AuditLog:
    last = database.scalar(
        select(AuditLog)
        .where(AuditLog.workspace_id == workspace_id)
        .order_by(AuditLog.sequence.desc())
        .limit(1)
    )
    sequence = (last.sequence + 1) if last else 1
    previous = last.event_hash if last else "0" * 64
    timestamp = datetime.now(UTC)
    body = {
        "sequence": sequence,
        "timestamp": timestamp.isoformat(),
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "metadata": metadata or {},
    }
    event_hash = hashlib.sha256(previous.encode() + canonical_json(body)).hexdigest()
    event = AuditLog(
        workspace_id=workspace_id,
        sequence=sequence,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=timestamp,
        request_id=request_id,
        outcome=outcome,
        metadata_json=metadata or {},
        previous_hash=previous,
        event_hash=event_hash,
    )
    database.add(event)
    return event


def verify_workspace_audit(database: Session, workspace_id: str) -> tuple[bool, str]:
    rows = database.scalars(
        select(AuditLog).where(AuditLog.workspace_id == workspace_id).order_by(AuditLog.sequence)
    ).all()
    previous = "0" * 64
    expected = 1
    for row in rows:
        body = {
            "sequence": row.sequence,
            "timestamp": row.timestamp.isoformat(),
            "actor_id": row.actor_id,
            "action": row.action,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "outcome": row.outcome,
            "metadata": row.metadata_json,
        }
        calculated = hashlib.sha256(previous.encode() + canonical_json(body)).hexdigest()
        if (
            row.sequence != expected
            or row.previous_hash != previous
            or row.event_hash != calculated
        ):
            return False, f"audit chain mismatch at sequence {expected}"
        previous = row.event_hash
        expected += 1
    return True, f"verified {len(rows)} append-oriented audit records"


def generate_audit_bundle(
    database: Session, workspace_id: str, destination: Path
) -> dict[str, Any]:
    settings = get_settings()
    events = database.scalars(
        select(ProtocolEvent)
        .where(ProtocolEvent.workspace_id == workspace_id)
        .order_by(ProtocolEvent.timestamp)
    ).all()
    audit = database.scalars(
        select(AuditLog).where(AuditLog.workspace_id == workspace_id).order_by(AuditLog.sequence)
    ).all()
    chain_valid, chain_message = verify_workspace_audit(database, workspace_id)
    event_lines = b"".join(
        canonical_json(
            {
                "id": event.id,
                "session_id": event.session_id,
                "sequence": event.sequence,
                "timestamp": event.timestamp.isoformat(),
                "method": event.method,
                "payload": event.sanitized_payload,
                "event_hash": event.event_hash,
                "previous_hash": event.previous_hash,
            }
        )
        + b"\n"
        for event in events
    )
    audit_lines = b"".join(
        canonical_json(
            {
                "sequence": row.sequence,
                "timestamp": row.timestamp.isoformat(),
                "action": row.action,
                "outcome": row.outcome,
                "event_hash": row.event_hash,
                "previous_hash": row.previous_hash,
            }
        )
        + b"\n"
        for row in audit
    )
    report_md = (
        "# MCP Sentinel Workspace Security Summary\n\n"
        f"Generated: {datetime.now(UTC).isoformat()}\n\n"
        f"Protocol events: {len(events)}\n\nAudit records: {len(audit)}\n\n"
        f"Integrity check: {'PASS' if chain_valid else 'FAIL'} — {chain_message}\n\n"
        "This export contains sanitized demo payloads. Hash chaining is tamper-evident, not immutable storage.\n"
    ).encode()
    report_html = (
        "<!doctype html><html><head><meta charset='utf-8'><title>MCP Sentinel report</title></head>"
        "<body><h1>MCP Sentinel Workspace Security Summary</h1>"
        f"<p>Protocol events: {len(events)}</p><p>Audit records: {len(audit)}</p>"
        f"<p>Integrity: {'PASS' if chain_valid else 'FAIL'} — {chain_message}</p>"
        "<p>Hash chaining is tamper-evident, not immutable storage.</p></body></html>"
    ).encode()
    pdf_buffer = io.BytesIO()
    pdf = canvas.Canvas(pdf_buffer, pagesize=A4)
    pdf.setTitle("MCP Sentinel Workspace Security Summary")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(56, 790, "MCP Sentinel Security Summary")
    pdf.setFont("Helvetica", 10)
    for offset, line in enumerate(
        (
            f"Generated: {datetime.now(UTC).isoformat()}",
            f"Protocol events: {len(events)}",
            f"Audit records: {len(audit)}",
            f"Integrity: {'PASS' if chain_valid else 'FAIL'}",
            "Tamper-evident does not mean immutable.",
        )
    ):
        pdf.drawString(56, 755 - offset * 20, line)
    pdf.save()
    report_pdf = pdf_buffer.getvalue()
    files = {
        "events.jsonl": event_lines,
        "audit.jsonl": audit_lines,
        "report.md": report_md,
        "report.html": report_html,
        "report.pdf": report_pdf,
    }
    manifest = {
        "format": "mcp-sentinel-audit/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "workspace_id": workspace_id,
        "system_version": settings.api_version,
        "audit_chain": {"valid": chain_valid, "message": chain_message},
        "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()},
        "limitations": [
            "Tamper-evident hash chains do not provide immutable storage.",
            "Payloads may be redacted according to workspace privacy policy.",
        ],
    }
    manifest_bytes = canonical_json(manifest)
    signing_key = SigningKey.load_or_create(settings.signing_key_path)
    signature = signing_key.sign(manifest_bytes)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2).encode())
        archive.writestr("manifest.sig", signature.encode())
        archive.writestr("public-key.pem", signing_key.public_pem())
        archive.writestr(
            "verification.txt",
            (chain_message + "\nRun: mcp-sentinel audit verify <bundle.zip>\n").encode(),
        )
    return {
        "path": str(destination),
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "signature": signature,
        "manifest": manifest,
    }


def verify_bundle(path: Path) -> tuple[bool, list[str]]:
    messages: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            manifest_bytes = canonical_json(manifest)
            if not SigningKey.verify(
                archive.read("public-key.pem"),
                manifest_bytes,
                archive.read("manifest.sig").decode(),
            ):
                return False, ["manifest signature is invalid"]
            messages.append("Ed25519 manifest signature is valid")
            for name, expected in manifest["files"].items():
                actual = hashlib.sha256(archive.read(name)).hexdigest()
                if actual != expected:
                    return False, [f"hash mismatch: {name}"]
                messages.append(f"verified {name}")
    except (KeyError, ValueError, zipfile.BadZipFile, OSError) as exc:
        return False, [f"invalid audit bundle: {exc}"]
    return True, messages


@contextmanager
def _docker_client(timeout: int) -> Iterator[docker.DockerClient]:
    client = docker.from_env(timeout=timeout)
    try:
        yield client
    finally:
        client.close()


class DockerSandboxManager:
    PROFILES = {
        "no_network": {"network": "none", "read_only": True},
        "read_only_workspace": {"network": "none", "read_only": True},
        "development_workspace": {"network": "none", "read_only": True},
        "restricted_network": {"network": "sentinel-egress", "read_only": True},
        "custom": {"network": "none", "read_only": True},
    }

    def available(self) -> bool:
        try:
            with _docker_client(timeout=10) as client:
                return bool(client.ping())
        except docker.errors.DockerException:
            return False

    def build_options(self, request: SandboxRequest, name: str) -> dict[str, Any]:
        profile = self.PROFILES[request.profile]
        if request.network and request.profile != "restricted_network":
            raise ValueError("network access is only valid for the restricted_network profile")
        mounts = []
        roots = [os.path.realpath(root) for root in get_settings().sandbox_mount_roots]
        for mount in request.mounts:
            # The allowlist comes only from operator settings, never the API.
            # Check both lexical containment and the resolved symlink target.
            absolute = os.path.abspath(mount.source)
            if not any(absolute.startswith(root + os.sep) for root in roots):
                raise ValueError("mount source must be beneath an operator-configured root")
            source = os.path.realpath(absolute)
            if not any(source.startswith(root + os.sep) for root in roots):
                raise ValueError("mount symlink escapes the configured roots")
            if not os.path.exists(source):
                raise ValueError("mount source is unavailable")
            if any(
                part.lower() in {".ssh", ".aws", ".kube", ".env", "credentials", "docker.sock"}
                for part in Path(source).parts
            ):
                raise ValueError("sensitive mount source is forbidden")
            destination = PurePosixPath(mount.destination)
            if (
                not str(destination).startswith("/workspace/")
                or ".." in destination.parts
                or "\\" in mount.destination
            ):
                raise ValueError("mount destination must remain inside /workspace")
            mounts.append(
                Mount(
                    target=str(destination), source=source, type="bind", read_only=mount.read_only
                )
            )
        return {
            "image": request.image,
            "detach": True,
            "name": name,
            "user": "65532:65532",
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": request.pids,
            "mem_limit": request.memory_mb * 1024 * 1024,
            "nano_cpus": int(request.cpus * 1_000_000_000),
            "network": str(profile["network"]),
            "tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
            "read_only": bool(profile["read_only"]),
            "mounts": mounts,
        }

    def start(self, database: Session, sandbox: Sandbox, request: SandboxRequest) -> str:
        options = self.build_options(request, f"sentinel-{sandbox.id[:12]}")
        try:
            with _docker_client(timeout=30) as client:
                container = client.containers.run(**options)
                container_id = str(container.id)
        except docker.errors.DockerException as exc:
            raise RuntimeError("Docker could not start the requested sandbox") from exc
        sandbox.container_id = container_id
        sandbox.status = "running"
        sandbox.started_at = now()
        database.flush()
        return container_id

    def stop(self, database: Session, sandbox: Sandbox) -> None:
        if not sandbox.container_id:
            raise RuntimeError("running Docker sandbox is unavailable")
        try:
            with _docker_client(timeout=30) as client:
                client.containers.get(sandbox.container_id).remove(force=True)
        except docker.errors.DockerException as exc:
            raise RuntimeError("Docker could not terminate the sandbox") from exc
        sandbox.status = "stopped"
        sandbox.stopped_at = now()
        sandbox.termination_reason = "stopped_by_reviewer"
        database.flush()
