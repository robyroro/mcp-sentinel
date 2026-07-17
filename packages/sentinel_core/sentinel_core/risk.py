from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .inspection import CommandGuard, InjectionDetector, NetworkGuard
from .redaction import SecretDetector


class RiskLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskSignal:
    key: str
    weight: int
    explanation: str


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: RiskLevel
    signals: tuple[RiskSignal, ...]
    explanation: str
    recommended_action: str
    confidence: float
    false_positive_considerations: str

    def model_dump(self) -> dict[str, Any]:
        result = asdict(self)
        result["level"] = self.level.value
        return result


DEFAULT_WEIGHTS = {
    "base": 5,
    "shell": 35,
    "write": 20,
    "destructive": 45,
    "network": 15,
    "private_network": 45,
    "secret": 35,
    "credential_path": 40,
    "database_mutation": 25,
    "deployment": 30,
    "message_send": 25,
    "financial": 50,
    "large_payload": 10,
    "encoded": 15,
    "injection": 35,
    "untrusted_server": 15,
    "known_server": -10,
    "repeated_denials": 20,
}


class RiskEngine:
    def __init__(self, weights: dict[str, int] | None = None):
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.secrets = SecretDetector()
        self.injections = InjectionDetector()

    def score(self, context: dict[str, Any]) -> RiskResult:
        signals: list[RiskSignal] = []

        def add(key: str, explanation: str) -> None:
            if not any(signal.key == key for signal in signals):
                signals.append(RiskSignal(key, self.weights[key], explanation))

        add("base", "Base risk for invoking an external MCP capability.")
        tool = str(context.get("tool", "")).lower()
        arguments = context.get("arguments") or {}
        raw = json.dumps(arguments, default=str)
        if any(word in tool for word in ("shell", "execute", "terminal", "command")):
            add("shell", "Tool can execute commands.")
            command = str(arguments.get("command", ""))
            guard = CommandGuard(("npm", "pnpm", "pytest", "cargo", "go", "git"))
            result = guard.validate(command) if command else None
            if result and "destructive_command" in result.signals:
                add("destructive", "Command matches destructive or download-and-execute controls.")
        if re.search(r"(?i)(write|delete|update|create|install|send|deploy)", tool):
            add("write", "Capability name indicates side effects.")
        if re.search(r"(?i)(delete|drop|destroy|format|shutdown)", tool + raw):
            add("destructive", "Request indicates destructive behavior.")
        if "url" in arguments or re.search(r"https?://", raw):
            add("network", "Arguments include a network destination.")
            urls = re.findall(r"https?://[^\s\"']+", raw)
            for url in urls:
                if not NetworkGuard(allow_private=False).validate(url).allowed:
                    add("private_network", "Destination failed private/special IP restrictions.")
                    break
        if self.secrets.inspect(arguments).findings:
            add("secret", "Arguments contain a credential-shaped value.")
        if re.search(r"(?i)(?:\.ssh|\.env|\.aws|credentials|id_rsa)", raw):
            add("credential_path", "Request references a sensitive credential path.")
        if re.search(r"(?i)(insert|update|delete|drop|alter|truncate)", tool + raw):
            add("database_mutation", "Request resembles a database mutation.")
        if re.search(r"(?i)(deploy|terraform apply|kubectl apply|release)", tool + raw):
            add("deployment", "Request can change deployed infrastructure or software.")
        if re.search(r"(?i)(send_message|send_email|publish|post_public)", tool):
            add("message_send", "Request can communicate externally.")
        if re.search(r"(?i)(payment|transfer|purchase|trade)", tool):
            add("financial", "Request may cause a financial operation.")
        if len(raw.encode()) > 100_000:
            add("large_payload", "Payload is unusually large.")
        if re.search(r"[A-Za-z0-9+/=]{80,}", raw):
            add("encoded", "Payload includes long encoded content.")
        if self.injections.inspect(raw, source="tool_arguments"):
            add("injection", "Content contains suspicious instruction patterns.")
        if context.get("server_trust") in {"unreviewed", "restricted", "quarantined"}:
            add("untrusted_server", "Server trust state is not trusted.")
        elif context.get("server_trust") == "trusted":
            add("known_server", "Reviewed trusted server reduces, but does not remove, risk.")
        if int(context.get("recent_denials", 0)) >= 3:
            add("repeated_denials", "Session has repeated recent policy denials.")

        score = max(0, min(100, sum(signal.weight for signal in signals)))
        level = self._level(score)
        recommendation = "allow"
        if level is RiskLevel.MEDIUM:
            recommendation = "allow_with_controls"
        elif level is RiskLevel.HIGH:
            recommendation = "require_approval"
        elif level is RiskLevel.CRITICAL:
            recommendation = "deny"
        explanation = " ".join(signal.explanation for signal in signals)
        confidence = min(0.98, 0.55 + 0.055 * len(signals))
        return RiskResult(
            score,
            level,
            tuple(signals),
            explanation,
            recommendation,
            round(confidence, 2),
            "Names and argument patterns are contextual signals; review unusual but legitimate administrative workflows.",
        )

    @staticmethod
    def _level(score: int) -> RiskLevel:
        if score >= 85:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 35:
            return RiskLevel.MEDIUM
        if score >= 15:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL
