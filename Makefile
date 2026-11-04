.PHONY: setup dev build seed test test-unit test-integration test-e2e lint format screenshots docs reset demo audit-demo

PYTHON := .venv/Scripts/python.exe
ifeq ($(OS),Windows_NT)
  PYTHON := .venv/Scripts/python.exe
else
  PYTHON := .venv/bin/python
endif

setup:
	python -m venv .venv
	$(PYTHON) -m pip install -e ".[dev,postgres,worker]"
	pnpm install --frozen-lockfile

dev:
	docker compose up --build

build:
	$(PYTHON) -m build --wheel
	cd apps/gateway && go build ./cmd/sentinel-gateway
	pnpm --dir apps/web build

seed:
	$(PYTHON) -m mcp_sentinel_api.seed_cli --force

test:
	$(PYTHON) -m pytest
	cd apps/gateway && go test ./...
	pnpm --dir apps/web typecheck
	pnpm --dir apps/web test:e2e

test-unit:
	$(PYTHON) -m pytest tests/unit tests/security tests/protocol

test-integration:
	$(PYTHON) -m pytest tests/backend tests/integration

test-e2e:
	pnpm --dir apps/web test:e2e

lint:
	$(PYTHON) -m ruff check packages apps tests examples scripts
	pnpm --dir apps/web lint
	cd apps/gateway && go vet ./...

format:
	$(PYTHON) -m ruff format packages apps tests examples scripts
	cd apps/gateway && gofmt -w cmd

screenshots:
	pnpm --dir apps/web screenshots

docs:
	$(PYTHON) scripts/check_docs.py

reset:
	docker compose down --volumes
	docker compose up --build --detach

demo:
	$(PYTHON) examples/demo-client/client.py

audit-demo:
	mcp-sentinel audit export
