"""Deterministically validate repository documentation and screenshot references."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCS = {
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "ROADMAP.md",
    "GOVERNANCE.md",
    "CITATION.cff",
    *{
        f"docs/{name}.md"
        for name in (
            "ARCHITECTURE",
            "SECURITY_ARCHITECTURE",
            "THREAT_MODEL",
            "PROTOCOL_SUPPORT",
            "POLICY_ENGINE",
            "POLICY_REFERENCE",
            "RISK_ENGINE",
            "APPROVALS",
            "SANDBOX_SECURITY",
            "AUDIT_INTEGRITY",
            "DEPLOYMENT",
            "DEVELOPMENT",
            "PRIVACY",
            "DATA_RETENTION",
            "ETHICS",
            "CLI",
            "API",
            "DEMO_ENVIRONMENT",
            "TROUBLESHOOTING",
        )
    },
}

REQUIRED_ADRS = {
    "0001-use-rust-or-go-for-the-gateway.md",
    "0002-postgresql-as-system-of-record.md",
    "0003-declarative-policy-engine.md",
    "0004-fail-closed-security-default.md",
    "0005-human-approval-workflow.md",
    "0006-container-sandboxing.md",
    "0007-tamper-evident-audit-chain.md",
    "0008-local-first-deployment.md",
    "0009-synthetic-demo-fixtures.md",
    "0010-opentelemetry-observability.md",
}

REQUIRED_SCREENSHOTS = {
    "01-dashboard.png",
    "02-server-registry.png",
    "03-server-risk-assessment.png",
    "04-tool-capabilities.png",
    "05-policy-list.png",
    "06-policy-editor.png",
    "07-policy-tester.png",
    "08-live-sessions.png",
    "09-session-overview.png",
    "10-session-timeline.png",
    "11-tool-request-details.png",
    "12-approval-queue.png",
    "13-approval-details.png",
    "14-secret-redaction.png",
    "15-injection-warning.png",
    "16-sandbox-manager.png",
    "17-risk-dashboard.png",
    "18-replay-comparison.png",
    "19-report-builder.png",
    "20-audit-export.png",
    "21-settings.png",
    "22-mobile-dashboard.png",
    "23-mobile-approval.png",
    "24-mobile-session.png",
}

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
HTML_ASSET = re.compile(r"(?:href|src)=[\"']([^\"']+)[\"']")


def local_target(raw: str) -> str | None:
    value = raw.strip().split(maxsplit=1)[0].strip("<>")
    if not value or value.startswith(("#", "http://", "https://", "mailto:", "data:")):
        return None
    return unquote(value.split("#", 1)[0].split("?", 1)[0]) or None


def main() -> int:
    errors: list[str] = []
    for required in sorted(REQUIRED_DOCS):
        if not (ROOT / required).exists():
            errors.append(f"missing required document: {required}")

    adr_dir = ROOT / "docs" / "adr"
    for name in sorted(REQUIRED_ADRS):
        path = adr_dir / name
        if not path.exists():
            errors.append(f"missing ADR: docs/adr/{name}")
            continue
        text = path.read_text(encoding="utf-8")
        for heading in ("Status", "Context", "Decision", "Consequences", "Alternatives Considered"):
            if f"## {heading}" not in text:
                errors.append(f"docs/adr/{name}: missing heading {heading!r}")

    screenshot_dir = ROOT / "screenshots"
    for name in sorted(REQUIRED_SCREENSHOTS):
        path = screenshot_dir / name
        if not path.is_file() or path.stat().st_size < 10_000:
            errors.append(f"missing or implausibly small screenshot: screenshots/{name}")

    markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    for source in markdown_files:
        if not source.exists():
            continue
        text = source.read_text(encoding="utf-8")
        if text.count("```mermaid") > text.count("```"):
            errors.append(f"{source.relative_to(ROOT)}: unclosed Mermaid fence")
        targets = [*MARKDOWN_LINK.findall(text), *HTML_ASSET.findall(text)]
        for raw in targets:
            target = local_target(raw)
            if target is None:
                continue
            resolved = (source.parent / target).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"{source.relative_to(ROOT)}: link escapes repository: {raw}")
                continue
            if not resolved.exists():
                errors.append(f"{source.relative_to(ROOT)}: broken local link: {raw}")

    if errors:
        print("Documentation validation failed:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print(
        f"Documentation valid: {len(markdown_files)} Markdown files, "
        f"{len(REQUIRED_ADRS)} ADRs, {len(REQUIRED_SCREENSHOTS)} screenshots."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
