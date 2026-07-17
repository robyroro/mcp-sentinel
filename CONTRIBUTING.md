# Contributing to MCP Sentinel

Thank you for improving MCP security. Contributions must preserve fail-closed behavior, accurate protocol claims, synthetic fixtures, and explainable decisions.

## Development setup

1. Install Python 3.12+, Go 1.20+, Node 22+, pnpm 11+, and Docker Compose v2.
2. Run `make setup` and `make seed`.
3. Run `make test-unit` before editing and `make test` before opening a pull request.

Never add real credentials, customer data, or private prompts. All security samples must be unmistakably synthetic.

## Change categories

- **Protocol:** add compatibility fixtures under `tests/protocol`, link the relevant stable MCP specification, and update `docs/PROTOCOL_SUPPORT.md` without claiming partial behavior as complete.
- **Risk rule:** document the signal, weight, explanation, false-positive considerations, and tests. Classifiers cannot grant permission.
- **Policy feature:** update schema validation, full rule traces, conflict handling, dry-run tests, reference docs, and migration concerns.
- **Security control:** include threat, trust boundary, bypass analysis, deterministic tests, and failure behavior.
- **UI:** preserve keyboard access, visible focus, reduced motion, non-color labels, mobile layout, and screenshot coverage.

## Pull requests

Keep changes scoped. Describe the threat or user outcome, tests run, protocol impact, migrations, compatibility, and security tradeoffs. All checks must pass. Maintainers may request two reviews for enforcement, approval, authentication, audit, signing, or sandbox changes.

Use `ruff format`, not manual Python formatting, and `gofmt` for Go. Do not weaken a test to make a security regression pass.

## Reporting compatibility and security issues

Use the MCP compatibility issue template for interoperability bugs. Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
