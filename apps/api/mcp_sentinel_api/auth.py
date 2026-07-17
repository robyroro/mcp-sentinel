from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import Membership, User

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
ROLE_LEVEL = {
    "viewer": 1,
    "auditor": 2,
    "developer": 3,
    "security_reviewer": 4,
    "administrator": 5,
    "owner": 6,
}


@dataclass(frozen=True)
class Principal:
    user: User
    membership: Membership

    @property
    def workspace_id(self) -> str:
        return self.membership.workspace_id

    @property
    def role(self) -> str:
        return self.membership.role


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def issue_session(user: User, membership: Membership) -> tuple[str, str]:
    settings = get_settings()
    csrf = secrets.token_urlsafe(24)
    payload = {
        "sub": user.id,
        "workspace": membership.workspace_id,
        "role": membership.role,
        "csrf": csrf,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=8),
        "iss": "mcp-sentinel",
        "aud": "mcp-sentinel-web",
    }
    token = jwt.encode(payload, settings.session_secret, algorithm="HS256")
    return token, csrf


def decode_session(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.session_secret,
            algorithms=["HS256"],
            issuer="mcp-sentinel",
            audience="mcp-sentinel-web",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid or expired."
        ) from exc


def current_principal(
    request: Request,
    session: str | None = Cookie(default=None, alias="sentinel_session"),
    database: Session = Depends(get_db),
) -> Principal:
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    claims = decode_session(session)
    user = database.get(User, claims["sub"])
    membership = database.scalar(
        select(Membership).where(
            Membership.user_id == claims["sub"],
            Membership.workspace_id == claims["workspace"],
        )
    )
    if not user or not membership or user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is unavailable."
        )
    request.state.session_claims = claims
    return Principal(user, membership)


def require_role(minimum: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if ROLE_LEVEL.get(principal.role, 0) < ROLE_LEVEL[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This action requires a higher workspace role.",
            )
        return principal

    return dependency


def require_csrf(
    request: Request,
    token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> None:
    claims = getattr(request.state, "session_claims", None)
    if not claims or not token or not secrets.compare_digest(str(claims.get("csrf", "")), token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token is missing or invalid."
        )


def require_gateway_token(authorization: str | None = Header(default=None)) -> None:
    expected = "Bearer " + get_settings().gateway_api_token
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Gateway authentication failed."
        )
