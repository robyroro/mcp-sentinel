from __future__ import annotations

import hashlib
import math
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class RedactionMode(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    HASH = "hash"
    REMOVE = "remove"
    BLOCK = "block"
    APPROVAL = "require_approval"


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    path: str
    fingerprint: str
    confidence: float
    preview: str


@dataclass(frozen=True)
class RedactionResult:
    value: Any
    findings: tuple[SecretFinding, ...]
    blocked: bool

    def summary(self) -> list[dict[str, Any]]:
        return [asdict(finding) for finding in self.findings]


class SecretDetector:
    """Detect and immediately replace likely secrets without retaining plaintext."""

    _PATTERNS = (
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.99),
        (
            "authorization",
            re.compile(
                r"(?i)\b(?:authorization\s*[:=]\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"
            ),
            0.96,
        ),
        (
            "jwt",
            re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
            0.94,
        ),
        (
            "github_token",
            re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b"),
            0.98,
        ),
        ("openai_project_key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"), 0.98),
        ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"), 0.98),
        ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0.98),
        (
            "database_url",
            re.compile(
                r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@[^\s]+"
            ),
            0.97,
        ),
        (
            "generic_api_key",
            re.compile(
                r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{12,})"
            ),
            0.88,
        ),
    )
    _SENSITIVE_KEYS = re.compile(
        r"(?i)^(?:password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key)$"
    )

    def __init__(self, *, fingerprint_salt: str = "mcp-sentinel", entropy_threshold: float = 4.25):
        self.salt = fingerprint_salt.encode()
        self.entropy_threshold = entropy_threshold

    def inspect(
        self, value: Any, mode: RedactionMode = RedactionMode.PARTIAL, path: str = "$"
    ) -> RedactionResult:
        findings: list[SecretFinding] = []
        blocked = False

        def walk(item: Any, current_path: str, sensitive_key: bool = False) -> Any:
            nonlocal blocked
            if isinstance(item, dict):
                output: dict[str, Any] = {}
                for key, child in item.items():
                    key_path = f"{current_path}.{key}"
                    key_sensitive = bool(self._SENSITIVE_KEYS.search(str(key)))
                    replaced = walk(child, key_path, key_sensitive)
                    if mode is not RedactionMode.REMOVE or not key_sensitive:
                        output[key] = replaced
                return output
            if isinstance(item, list):
                return [walk(child, f"{current_path}[{index}]") for index, child in enumerate(item)]
            if not isinstance(item, str):
                return item

            spans: list[tuple[int, int, str, float]] = []
            if sensitive_key and len(item) >= 4:
                spans.append((0, len(item), "sensitive_field", 0.99))
            for kind, pattern, confidence in self._PATTERNS:
                spans.extend((m.start(), m.end(), kind, confidence) for m in pattern.finditer(item))
            if not spans and self._looks_high_entropy(item):
                spans.append((0, len(item), "high_entropy", 0.62))
            if not spans:
                return item

            for start, end, kind, confidence in spans:
                secret = item[start:end]
                findings.append(
                    SecretFinding(
                        kind,
                        current_path,
                        self._fingerprint(secret),
                        confidence,
                        self._mask(secret),
                    )
                )
            if mode in {RedactionMode.BLOCK, RedactionMode.APPROVAL}:
                blocked = True
            if mode is RedactionMode.REMOVE:
                return None
            if mode is RedactionMode.HASH:
                return f"[sha256:{self._fingerprint(item)}]"
            if mode is RedactionMode.FULL:
                return "[REDACTED]"
            redacted = item
            for start, end, _, _ in sorted(spans, reverse=True):
                redacted = redacted[:start] + self._mask(redacted[start:end]) + redacted[end:]
            return redacted

        result = walk(value, path)
        return RedactionResult(result, tuple(findings), blocked)

    def _fingerprint(self, value: str) -> str:
        return hashlib.sha256(self.salt + value.encode()).hexdigest()[:16]

    @staticmethod
    def _mask(value: str) -> str:
        if len(value) <= 8:
            return "*" * len(value)
        return value[:3] + "*" * min(24, max(5, len(value) - 7)) + value[-4:]

    def _looks_high_entropy(self, value: str) -> bool:
        candidate = value.strip()
        if len(candidate) < 24 or len(candidate) > 512 or " " in candidate:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate):
            return False
        counts = {char: candidate.count(char) for char in set(candidate)}
        entropy = -sum(
            (count / len(candidate)) * math.log2(count / len(candidate))
            for count in counts.values()
        )
        return entropy >= self.entropy_threshold
