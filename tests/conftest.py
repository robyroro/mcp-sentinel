from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_DATABASE = Path("pytest-sentinel.db")
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///./{TEST_DATABASE.name}"
os.environ["SENTINEL_SIGNING_KEY_PATH"] = ".sentinel/pytest-signing-key.pem"
os.environ["SENTINEL_SESSION_SECRET"] = "pytest-session-secret-with-more-than-32-characters"

from mcp_sentinel_api.database import engine  # noqa: E402
from mcp_sentinel_api.main import app  # noqa: E402
from mcp_sentinel_api.seed import DEMO_PASSWORD  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def clean_database():
    if TEST_DATABASE.exists():
        TEST_DATABASE.unlink()
    yield
    engine.dispose()
    if TEST_DATABASE.exists():
        TEST_DATABASE.unlink()


@pytest.fixture(scope="session")
def client(clean_database):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def authenticated(client: TestClient) -> tuple[TestClient, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    return client, response.json()["csrf_token"]
