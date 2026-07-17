from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "sqlite:///./sentinel.db"
    redis_url: str = "redis://redis:6379/0"
    s3_endpoint: str = "http://minio:9000"
    s3_bucket: str = "sentinel-artifacts"
    session_secret: str = "development-only-session-secret-change-this"
    gateway_api_token: str = "dev-gateway-token-change-me"
    cookie_secure: bool = False
    allow_registration: bool = False
    max_payload_bytes: int = 1_048_576
    signing_key_path: Path = Path(".sentinel/signing-key.pem")
    raw_payload_retention_days: int = Field(default=7, ge=0, le=3650)
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    api_version: str = "0.1.0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
