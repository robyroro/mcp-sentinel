from __future__ import annotations

import copy
import fnmatch
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

import re2
import yaml


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    TRANSFORM = "allow_with_transformation"
    REDACT = "allow_with_response_redaction"
    AUDIT = "audit_only"
    RATE_LIMIT = "rate_limit"
    TERMINATE = "terminate_session"


@dataclass(frozen=True)
class RuleTrace:
    rule_id: str
    matched: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    policy: str
    policy_version: str
    matched_rules: tuple[str, ...]
    trace: tuple[RuleTrace, ...]
    explanation: str
    transformed_arguments: dict[str, Any]
    response_redactions: tuple[str, ...] = ()
    evaluation_ms: float = 0.0
    conflicts: tuple[str, ...] = ()
    limits: dict[str, int] = field(default_factory=dict)


class PolicyError(ValueError):
    pass


class PolicyEngine:
    """Bounded, deterministic YAML policy evaluator.

    Rules are evaluated in document order. A deny/terminate decision always wins;
    otherwise the first matched rule wins. This precedence is deliberate and is
    surfaced through ``conflicts`` instead of being implicit.
    """

    _MAX_PATTERN = 512
    _MAX_RULES = 500

    def __init__(self, definition: str | dict[str, Any]):
        try:
            parsed = (
                yaml.safe_load(definition)
                if isinstance(definition, str)
                else copy.deepcopy(definition)
            )
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid YAML: {exc}") from exc
        if not isinstance(parsed, dict):
            raise PolicyError("policy must be a YAML object")
        self.document = parsed
        self._validate()

    def _validate(self) -> None:
        if str(self.document.get("version")) != "1":
            raise PolicyError("supported policy version is '1'")
        if not self.document.get("name"):
            raise PolicyError("policy name is required")
        rules = self.document.get("rules", [])
        if not isinstance(rules, list) or len(rules) > self._MAX_RULES:
            raise PolicyError(f"rules must be a list with at most {self._MAX_RULES} entries")
        seen: set[str] = set()
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict) or not rule.get("id"):
                raise PolicyError(f"rule {index} requires an id")
            if rule["id"] in seen:
                raise PolicyError(f"duplicate rule id: {rule['id']}")
            seen.add(rule["id"])
            try:
                Decision(rule.get("action", ""))
            except ValueError as exc:
                raise PolicyError(f"rule {rule['id']} has unsupported action") from exc
            self._validate_patterns(rule.get("match", {}))

    def _validate_patterns(self, value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"regex", "matches"} and isinstance(child, str):
                    if len(child) > self._MAX_PATTERN:
                        raise PolicyError("regex exceeds safe length")
                    try:
                        re2.compile(child)
                    except re2.error as exc:
                        raise PolicyError("invalid or unsupported RE2 regex") from exc
                elif key in {"regex", "matches"}:
                    raise PolicyError("regex must be a string")
                self._validate_patterns(child)
        elif isinstance(value, list):
            for child in value:
                self._validate_patterns(child)

    @classmethod
    def compile(cls, definition: str | dict[str, Any]) -> dict[str, Any]:
        engine = cls(definition)
        return copy.deepcopy(engine.document)

    def evaluate(self, request: dict[str, Any], *, dry_run: bool = False) -> PolicyResult:
        started = time.perf_counter()
        traces: list[RuleTrace] = []
        matches: list[dict[str, Any]] = []
        for rule in self.document.get("rules", []):
            matched, reasons = self._matches(rule.get("match", {}), request)
            traces.append(RuleTrace(str(rule["id"]), matched, tuple(reasons)))
            if matched:
                matches.append(rule)

        conflicts = self._conflicts(matches)
        selected = self._select(matches)
        default = self.document.get("defaults", {}).get("decision", "deny")
        action = Decision(selected.get("action", default) if selected else default)
        arguments = copy.deepcopy(request.get("arguments") or {})
        redactions: tuple[str, ...] = ()
        if selected and action is Decision.TRANSFORM:
            for path, value in (selected.get("transform") or {}).items():
                self._set_path(arguments, path, value)
        if selected and action is Decision.REDACT:
            redactions = tuple(selected.get("redact", ["$"]))
        explanation = (
            f"Matched {selected['id']}: {selected.get('description', action.value)}"
            if selected
            else f"No rule matched; applied default decision {action.value}."
        )
        if dry_run:
            explanation = "Dry run — " + explanation
        elapsed = (time.perf_counter() - started) * 1000
        return PolicyResult(
            decision=action,
            policy=str(self.document["name"]),
            policy_version=str(self.document.get("revision", "1.0.0")),
            matched_rules=tuple(str(rule["id"]) for rule in matches),
            trace=tuple(traces),
            explanation=explanation,
            transformed_arguments=arguments,
            response_redactions=redactions,
            evaluation_ms=round(elapsed, 3),
            conflicts=conflicts,
            limits={k: int(v) for k, v in self.document.get("limits", {}).items()},
        )

    def _select(self, matches: list[dict[str, Any]]) -> dict[str, Any] | None:
        for action in (Decision.TERMINATE, Decision.DENY):
            found = next((r for r in matches if r["action"] == action.value), None)
            if found:
                return found
        return matches[0] if matches else None

    @staticmethod
    def _conflicts(matches: list[dict[str, Any]]) -> tuple[str, ...]:
        actions = {rule["action"] for rule in matches}
        if len(actions) < 2:
            return ()
        return (
            "Multiple matching rules yield different actions; deny/terminate precedence applied.",
        )

    def _matches(self, match: dict[str, Any], request: dict[str, Any]) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        for key, expected in match.items():
            if key == "arguments":
                actual = request.get("arguments", {})
                ok, detail = self._match_arguments(expected, actual)
            else:
                actual = request.get(key)
                ok = self._match_value(expected, actual)
                detail = f"{key} {'matched' if ok else 'did not match'}"
            reasons.append(detail)
            if not ok:
                return False, reasons
        return True, reasons or ["unconditional rule"]

    def _match_arguments(self, expected: Any, actual: Any, prefix: str = "") -> tuple[bool, str]:
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            ok = self._match_value(expected, actual)
            return ok, f"argument {prefix or '$'} {'matched' if ok else 'did not match'}"
        for key, condition in expected.items():
            path = f"{prefix}.{key}" if prefix else key
            if key not in actual:
                return False, f"argument {path} is missing"
            value = actual[key]
            if isinstance(condition, dict) and not self._is_operator(condition):
                ok, detail = self._match_arguments(condition, value, path)
            else:
                ok = self._match_value(condition, value)
                detail = f"argument {path} {'matched' if ok else 'did not match'}"
            if not ok:
                return False, detail
        return True, f"arguments under {prefix or '$'} matched"

    @staticmethod
    def _is_operator(value: dict[str, Any]) -> bool:
        return bool(
            set(value)
            & {
                "any_of",
                "not_any_of",
                "contains_any",
                "starts_with_any",
                "matches_any",
                "within",
                "regex",
                "equals",
                "exists",
                "less_than",
                "greater_than",
            }
        )

    def _match_value(self, expected: Any, actual: Any) -> bool:
        if not isinstance(expected, dict):
            return bool(actual == expected)
        if "equals" in expected and actual != expected["equals"]:
            return False
        if "exists" in expected and bool(actual is not None) != bool(expected["exists"]):
            return False
        text = "" if actual is None else str(actual)
        if "any_of" in expected and actual not in expected["any_of"]:
            return False
        if "not_any_of" in expected and actual in expected["not_any_of"]:
            return False
        if "contains_any" in expected and not any(
            str(part).lower() in text.lower() for part in expected["contains_any"]
        ):
            return False
        if "starts_with_any" in expected and not any(
            text.startswith(str(part)) for part in expected["starts_with_any"]
        ):
            return False
        if "matches_any" in expected and not any(
            fnmatch.fnmatch(text, str(pattern)) for pattern in expected["matches_any"]
        ):
            return False
        if "regex" in expected and re2.search(str(expected["regex"]), text) is None:
            return False
        if "within" in expected and not self._within(text, expected["within"]):
            return False
        if "less_than" in expected and not float(actual) < float(expected["less_than"]):
            return False
        return not (
            "greater_than" in expected and not float(actual) > float(expected["greater_than"])
        )

    @staticmethod
    def _within(value: str, roots: list[str]) -> bool:
        candidate = PurePosixPath(value.replace("\\", "/"))
        if ".." in candidate.parts:
            return False
        candidate_s = "/" + str(candidate).lstrip("/")
        return any(
            candidate_s == root.rstrip("/") or candidate_s.startswith(root.rstrip("/") + "/")
            for root in roots
        )

    @staticmethod
    def _set_path(target: dict[str, Any], dotted: str, value: Any) -> None:
        current = target
        parts = dotted.split(".")
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                child = {}
                current[part] = child
            current = child
        current[parts[-1]] = value

    def canonical(self) -> str:
        return json.dumps(self.document, sort_keys=True, separators=(",", ":"))
