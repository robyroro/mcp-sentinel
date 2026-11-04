# Policy engine

The policy engine in `packages/sentinel_core/sentinel_core/policy.py` compiles a constrained YAML document into deterministic matchers. It does not evaluate arbitrary code, templates, shell expressions, or network lookups.

## Evaluation

An evaluation context contains the workspace, client, server, tool or protocol method, arguments, resource URI, environment, user role, timestamp, and session counters. The engine evaluates applicable rules in declaration order and returns:

- the effective decision;
- matching and skipped rule traces;
- conflicts and precedence explanation;
- transformed arguments;
- response-redaction instructions;
- relevant limits and evaluation duration.

`deny` and `terminate_session` have precedence over approvals and allows. A matching approval has precedence over a plain allow. If no rule matches, `defaults.decision` applies; the recommended default is `deny`.

## Matchers

Supported matchers include exact values, `any_of`, bounded regular expressions, glob-like path patterns, `within` roots, string prefix/substring tests, client/server/tool/method/environment/role selectors, resource URIs, and time windows. Domain, path, and command safety decisions also use the dedicated inspection primitives rather than relying on string policy alone.

## Transformations and redaction

Argument transformations operate on named fields and produce a new argument object plus a diff; the input is not mutated. Response redaction instructions are applied after server execution. A transformation never changes the JSON-RPC request ID or method.

## Inheritance and versions

Policies may inherit base definitions before compilation. Cycles and conflicting terminal decisions are rejected or surfaced as conflicts. Stored policies carry an immutable version label and compiled representation; sessions retain the selected policy/version for replay evidence.

## Simulation

Dry-run and replay use the same evaluator with synthetic or recorded sanitized contexts. Simulation never forwards a request. A result includes the rule trace and risk signals so a reviewer can compare old and candidate policy outcomes.

## Safety properties

- Invalid policy syntax is not activated.
- Regex inputs and patterns are bounded; policies cannot run executable code.
- Missing context does not become a wildcard authorization.
- Terminal deny rules cannot be overridden by a later allow.
- Evaluation errors become fail-closed results at the gateway boundary.

See [Policy reference](POLICY_REFERENCE.md) for the document format.
