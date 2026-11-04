from pathlib import Path

import pytest
from sentinel_core.policy import Decision, PolicyEngine, PolicyError

POLICY = Path("examples/policy-examples/coding-agent-restricted.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("tool", "arguments", "decision", "rule"),
    [
        (
            "filesystem.read_file",
            {"path": "/workspace/project/README.md"},
            Decision.ALLOW,
            "allow-repository-read",
        ),
        (
            "filesystem.read_file",
            {"path": "/workspace/project/.env"},
            Decision.DENY,
            "deny-secret-access",
        ),
        (
            "filesystem.write_file",
            {"path": "/workspace/project/a.md"},
            Decision.REQUIRE_APPROVAL,
            "require-approval-for-write",
        ),
        (
            "terminal.execute",
            {"command": "rm -rf /tmp/demo"},
            Decision.DENY,
            "deny-destructive-shell",
        ),
        ("terminal.execute", {"command": "pytest -q"}, Decision.ALLOW, "allow-tests"),
    ],
)
def test_policy_decisions(tool, arguments, decision, rule):
    result = PolicyEngine(POLICY).evaluate({"tool": tool, "arguments": arguments})
    assert result.decision is decision
    assert rule in result.matched_rules
    assert result.explanation
    assert result.evaluation_ms >= 0


def test_deny_precedence_and_conflict_explanation():
    definition = {
        "version": "1",
        "name": "conflict",
        "defaults": {"decision": "allow"},
        "rules": [
            {"id": "allow-x", "action": "allow", "match": {"tool": "x"}},
            {"id": "deny-x", "action": "deny", "match": {"tool": "x"}},
        ],
    }
    result = PolicyEngine(definition).evaluate({"tool": "x"})
    assert result.decision is Decision.DENY
    assert result.conflicts


def test_invalid_policy_rejected():
    with pytest.raises(PolicyError):
        PolicyEngine("version: '2'\nname: bad\nrules: []")
