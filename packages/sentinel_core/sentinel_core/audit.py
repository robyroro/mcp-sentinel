from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    timestamp: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditChain:
    def __init__(self, events: Iterable[AuditEvent] = ()):
        self.events = list(events)

    def append(
        self, event_type: str, actor: str, payload: dict[str, Any], *, timestamp: str | None = None
    ) -> AuditEvent:
        sequence = len(self.events) + 1
        previous = self.events[-1].event_hash if self.events else "0" * 64
        now = timestamp or datetime.now(UTC).isoformat()
        digest = self._hash(sequence, now, event_type, actor, payload, previous)
        event = AuditEvent(sequence, now, event_type, actor, payload, previous, digest)
        self.events.append(event)
        return event

    @staticmethod
    def _hash(
        sequence: int,
        timestamp: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        previous: str,
    ) -> str:
        body = {
            "sequence": sequence,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
        }
        return hashlib.sha256(previous.encode() + canonical_json(body)).hexdigest()

    def verify(self) -> tuple[bool, str]:
        previous = "0" * 64
        for expected, event in enumerate(self.events, 1):
            if event.sequence != expected:
                return False, f"sequence mismatch at event {expected}"
            if event.previous_hash != previous:
                return False, f"previous hash mismatch at event {expected}"
            calculated = self._hash(
                event.sequence,
                event.timestamp,
                event.event_type,
                event.actor,
                event.payload,
                previous,
            )
            if calculated != event.event_hash:
                return False, f"event hash mismatch at event {expected}"
            previous = event.event_hash
        return True, f"verified {len(self.events)} chained events"


class SigningKey:
    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: Path) -> SigningKey:
        if path.exists():
            loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError("signing key is not Ed25519")
            return cls(loaded)
        key = cls.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            key.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return key

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self.private_key.sign(payload)).decode()

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def verify(public_pem: bytes, payload: bytes, signature: str) -> bool:
        try:
            public = serialization.load_pem_public_key(public_pem)
            if not isinstance(public, Ed25519PublicKey):
                return False
            public.verify(base64.b64decode(signature), payload)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
