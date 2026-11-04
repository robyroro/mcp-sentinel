# Development

## Prerequisites

- Python 3.12+
- Go 1.20+
- Node.js 20+ and pnpm 10+
- Docker Engine with Compose v2 for the complete local environment
- GNU Make (or run the commands from `Makefile` directly)

## Setup

```bash
python -m venv .venv
# Activate .venv for your shell
python -m pip install -e ".[dev,postgres,worker]"
pnpm install --frozen-lockfile
cp .env.example .env
```

Start all services with `make dev`, or use a native SQLite development API:

```bash
set SENTINEL_DATABASE_URL=sqlite:///./sentinel-dev.db
alembic upgrade head
python -m mcp_sentinel_api.seed_cli --force
uvicorn mcp_sentinel_api.main:app --reload
```

On POSIX shells, use `export` instead of `set`.

## Commands

`make setup`, `dev`, `build`, `seed`, `test`, `test-unit`, `test-integration`, `test-e2e`, `lint`, `format`, `screenshots`, `docs`, `reset`, `demo`, and `audit-demo` are the supported entry points. `make reset` destroys only Compose-managed development volumes.

## Migrations

```bash
alembic upgrade head
alembic revision --autogenerate -m "describe change"
alembic downgrade -1
```

Review generated migrations for constraints, indexes, PostgreSQL/SQLite compatibility, and destructive operations. Schema changes require migration and model tests.

## Test layers

- `pytest tests/unit tests/security tests/protocol` — pure engine and protocol behavior.
- `pytest tests/backend tests/integration` — API, authentication, approvals, reports, and persistence.
- `go test ./...` in `apps/gateway` — handlers and transport behavior.
- `pnpm --dir apps/web typecheck` and `lint` — frontend static checks.
- `pnpm --dir apps/web test:e2e` — seeded browser and accessibility workflows.
- `make screenshots` — deterministic 1440×1000 and 390×844 capture.

## Contribution expectations

Add focused regression tests for security decisions, keep fixtures synthetic, do not log raw credentials, and update protocol/support documentation for behavior changes. Run `make lint`, `make test`, `make build`, and `make docs` before a pull request.
