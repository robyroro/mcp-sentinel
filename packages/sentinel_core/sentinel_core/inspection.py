from __future__ import annotations

import base64
import ipaddress
import os
import re
import shlex
import socket
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    reason: str
    signals: tuple[str, ...] = ()


class NetworkGuard:
    def __init__(
        self,
        *,
        allowed_domains: tuple[str, ...] = (),
        blocked_domains: tuple[str, ...] = (),
        allowed_ports: tuple[int, ...] = (80, 443),
        allow_private: bool = False,
        resolver: Callable[[str, int], list[tuple[Any, ...]]] | None = None,
    ):
        self.allowed_domains = tuple(domain.lower() for domain in allowed_domains)
        self.blocked_domains = tuple(domain.lower() for domain in blocked_domains)
        self.allowed_ports = allowed_ports
        self.allow_private = allow_private
        self.resolver = resolver or (
            lambda host, port: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )

    def validate(self, url: str) -> GuardResult:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return GuardResult(False, "Unsupported URL protocol.", ("unsupported_protocol",))
        if parsed.username or parsed.password:
            return GuardResult(False, "Credentials in URLs are forbidden.", ("url_credentials",))
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host:
            return GuardResult(False, "URL has no hostname.", ("invalid_url",))
        if self._domain_match(host, self.blocked_domains):
            return GuardResult(False, "Destination domain is blocked.", ("blocked_domain",))
        if self.allowed_domains and not self._domain_match(host, self.allowed_domains):
            return GuardResult(
                False, "Destination is not in the domain allowlist.", ("domain_not_allowed",)
            )
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.allowed_ports:
            return GuardResult(False, f"Destination port {port} is not allowed.", ("blocked_port",))
        try:
            addresses = self._resolve(host, port)
        except (OSError, ValueError):
            return GuardResult(False, "DNS resolution failed safely.", ("dns_failure",))
        blocked = [str(address) for address in addresses if self._blocked_ip(address)]
        if blocked and not self.allow_private:
            return GuardResult(
                False,
                f"Destination resolves to restricted address {blocked[0]}.",
                ("private_or_special_ip",),
            )
        return GuardResult(True, "Destination passed domain, port, protocol, and IP checks.")

    def validate_redirect(self, source: str, destination: str) -> GuardResult:
        del source
        result = self.validate(destination)
        if not result.allowed:
            return GuardResult(
                False, "Redirect blocked: " + result.reason, ("unsafe_redirect",) + result.signals
            )
        return result

    def _resolve(self, host: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        try:
            return {ipaddress.ip_address(host)}
        except ValueError:
            return {ipaddress.ip_address(info[4][0]) for info in self.resolver(host, port)}

    @staticmethod
    def _domain_match(host: str, domains: tuple[str, ...]) -> bool:
        return any(host == domain or host.endswith("." + domain) for domain in domains)

    @staticmethod
    def _blocked_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        metadata = ipaddress.ip_address("169.254.169.254")
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address == metadata
        )


class PathGuard:
    SENSITIVE_PARTS = {".ssh", ".aws", ".kube", ".env", "credentials", "id_rsa", "id_ed25519"}

    def __init__(
        self,
        allowed_roots: list[Path],
        *,
        write_roots: list[Path] | None = None,
        max_bytes: int = 10_000_000,
    ):
        self.allowed_roots = [path.resolve(strict=True) for path in allowed_roots]
        self.write_roots = [path.resolve(strict=True) for path in (write_roots or [])]
        self.max_bytes = max_bytes

    def validate(
        self, candidate: str | Path, *, write: bool = False, expected_bytes: int = 0
    ) -> GuardResult:
        raw = Path(candidate)
        if any(part == ".." for part in raw.parts):
            return GuardResult(False, "Path traversal segments are forbidden.", ("path_traversal",))
        try:
            resolved = raw.resolve(strict=False)
        except (OSError, RuntimeError):
            return GuardResult(False, "Path could not be resolved safely.", ("invalid_path",))
        roots = self.write_roots if write else self.allowed_roots
        if not roots or not any(self._within(resolved, root) for root in roots):
            return GuardResult(
                False, "Resolved path is outside the allowed roots.", ("path_escape",)
            )
        if any(part.lower() in self.SENSITIVE_PARTS for part in resolved.parts):
            return GuardResult(False, "Sensitive credential path is blocked.", ("sensitive_path",))
        if expected_bytes > self.max_bytes:
            return GuardResult(False, "File exceeds configured size limit.", ("file_too_large",))
        return GuardResult(True, "Canonical path is within an allowed root.")

    @staticmethod
    def _within(path: Path, root: Path) -> bool:
        try:
            return os.path.commonpath((str(path), str(root))) == str(root)
        except ValueError:
            return False


class CommandGuard:
    _SHELL_META = re.compile(r"(?:\|\||&&|[|;<>`]|[\r\n]|\$\(|\$\{)")
    _DESTRUCTIVE = (
        re.compile(r"(?i)(?:^|\s)rm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\b"),
        re.compile(r"(?i)\b(?:mkfs|shutdown|reboot|poweroff|dd)\b"),
        re.compile(r"(?i)\bchmod\s+-R\s+777\b"),
        re.compile(r"(?i)\b(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh)\b"),
        re.compile(r"(?i)\b(?:sudo|runas)\b"),
        re.compile(r"(?i)\b(?:cat|type)\b.*(?:\.ssh|history|credentials)"),
    )

    def __init__(
        self,
        executables: tuple[str, ...],
        command_prefixes: tuple[str, ...] = (),
        max_length: int = 4096,
    ):
        self.executables = {item.lower() for item in executables}
        self.prefixes = command_prefixes
        self.max_length = max_length

    def validate(self, command: str) -> GuardResult:
        if not command or len(command) > self.max_length or "\x00" in command:
            return GuardResult(
                False, "Command is empty, oversized, or contains NUL.", ("invalid_command",)
            )
        signals: list[str] = []
        if self._SHELL_META.search(command):
            signals.append("shell_metacharacters")
        if any(pattern.search(command) for pattern in self._DESTRUCTIVE):
            signals.append("destructive_command")
        if self._encoded_payload(command):
            signals.append("encoded_payload")
        try:
            argv = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return GuardResult(False, "Command has invalid quoting.", ("parse_error",))
        executable = Path(argv[0]).name.lower() if argv else ""
        if executable not in self.executables:
            signals.append("executable_not_allowed")
        if self.prefixes and not any(command.startswith(prefix) for prefix in self.prefixes):
            signals.append("command_prefix_not_allowed")
        if signals:
            return GuardResult(
                False, "Command violates deterministic execution controls.", tuple(signals)
            )
        return GuardResult(True, "Command is within the executable and prefix allowlists.")

    @staticmethod
    def _encoded_payload(command: str) -> bool:
        if re.search(r"(?i)(?:base64\s+-d|frombase64string|-enc(?:odedcommand)?)", command):
            return True
        for token in re.findall(r"[A-Za-z0-9+/=]{40,}", command):
            try:
                decoded = base64.b64decode(token + "===", validate=False)
            except ValueError:
                continue
            if any(
                word in decoded.lower() for word in (b"curl", b"powershell", b"/bin/sh", b"invoke-")
            ):
                return True
        return False


@dataclass(frozen=True)
class InjectionFinding:
    signal: str
    confidence: float
    source: str
    suggested_response: str
    false_positive_warning: str


class InjectionDetector:
    PATTERNS = (
        (
            "instruction_override",
            re.compile(
                r"(?i)\b(ignore|disregard|override)\b.{0,60}\b(previous|prior|system|developer)\b.{0,20}\b(instruction|message|prompt)s?\b"
            ),
            0.88,
        ),
        (
            "secret_exfiltration",
            re.compile(
                r"(?i)\b(reveal|print|send|upload|exfiltrat\w*)\b.{0,50}\b(secret|token|password|credential|\.env)\b"
            ),
            0.92,
        ),
        (
            "policy_bypass",
            re.compile(
                r"(?i)\b(bypass|disable|evade|ignore)\b.{0,40}\b(policy|guard|approval|security|sentinel)\b"
            ),
            0.94,
        ),
        ("system_impersonation", re.compile(r"(?i)(?:^|\n)\s*(?:system|developer)\s*:\s*"), 0.82),
        (
            "forced_tool_call",
            re.compile(
                r"(?i)\b(must|immediately|now)\b.{0,40}\b(call|execute|run)\b.{0,40}\b(tool|command|shell)\b"
            ),
            0.72,
        ),
    )

    def inspect(self, content: str, *, source: str = "unknown") -> tuple[InjectionFinding, ...]:
        findings = [
            InjectionFinding(
                signal,
                confidence,
                source,
                "Warn and require review; deterministic policy remains authoritative.",
                "Rule-based detection can produce false positives and false negatives.",
            )
            for signal, pattern, confidence in self.PATTERNS
            if pattern.search(content)
        ]
        for token in re.findall(r"[A-Za-z0-9+/=]{48,}", content):
            try:
                decoded = base64.b64decode(token + "===", validate=False).decode("utf-8", "ignore")
            except ValueError:
                continue
            if any(pattern.search(decoded) for _, pattern, _ in self.PATTERNS):
                findings.append(
                    InjectionFinding(
                        "encoded_suspicious_instructions",
                        0.86,
                        source,
                        "Block or require approval and inspect decoded content.",
                        "Encoded benign documents may trigger this heuristic.",
                    )
                )
                break
        return tuple(findings)
