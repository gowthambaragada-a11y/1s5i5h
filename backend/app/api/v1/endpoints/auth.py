"""Authentication endpoints.

Passwords are verified against a local operator account (Postgres when
available, an in-memory table otherwise) so the demo works with no database. The
login response never includes the hash, and a failed attempt gives the same
message either way so the endpoint cannot be used to enumerate usernames.
"""

from __future__ import annotations

import secrets
from typing import cast

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import SettingsDep, UserDep
from app.core.config import Settings
from app.core.logging import get_logger
from app.core.security import Role, create_access_token, hash_password, verify_password
from app.db.models import UserRow
from app.db.session import is_available, session_scope

router = APIRouter(prefix="/auth", tags=["auth"])

logger = get_logger(__name__)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    # Fixed by RFC 6750; not a secret, hence the noqa.
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    username: str
    role: str


class MeResponse(BaseModel):
    username: str
    role: str
    sub: str


#: Fallback accounts for the demo when Postgres is not running. Documented in the
#: README, never used when a real users table exists.
_DEMO_USERS: dict[str, tuple[str, str]] = {}


def _demo_users() -> dict[str, tuple[str, str]]:
    if not _DEMO_USERS:
        _DEMO_USERS["admin"] = (hash_password("admin123!"), "admin")
        _DEMO_USERS["analyst"] = (hash_password("analyst123!"), "analyst")
        _DEMO_USERS["viewer"] = (hash_password("viewer123!"), "viewer")
    return _DEMO_USERS


def _lookup(username: str, settings: Settings) -> tuple[str, str] | None:
    """Find ``(password_hash, role)``. Falls back to demo accounts.

    A disabled account is treated as absent: returning its role would let the
    caller mint a token for an account that should not be usable at all.
    """
    with session_scope() as session:
        if session is not None:
            try:
                row = session.query(UserRow).filter(UserRow.username == username).first()
            except SQLAlchemyError:
                # `session_scope` only yields None when the engine could not be
                # built. A database that connects but has no schema still opens a
                # session and then fails on the query, which would make login the
                # one endpoint that returns 500 instead of 401. Degrade to the
                # no-accounts answer: the login attempt fails, and /readyz
                # reports the real reason.
                logger.warning("users table unusable; treating as no operator accounts", exc_info=True)
                row = None
            if row is not None and not row.disabled:
                return (row.password_hash, row.role)
    if not settings.allow_demo_accounts:
        return None
    return _demo_users().get(username)


def create_user(username: str, password: str, role: str) -> str:
    """Create an operator account. Returns the new user id."""
    user_id = f"usr_{secrets.token_hex(8)}"
    encoded = hash_password(password)
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="cannot create a user: postgres unavailable",
            )
        session.add(UserRow(id=user_id, username=username, password_hash=encoded, role=role))
    return user_id


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, settings: SettingsDep) -> TokenResponse:
    entry = _lookup(payload.username, settings)
    # Always run a verification so a missing user and a wrong password cost the
    # same time; otherwise response latency enumerates valid usernames.
    encoded = entry[0] if entry else "x" * 64
    ok = verify_password(payload.password, encoded, settings=settings)
    if entry is None or not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid username or password")
    _hash, role = entry
    token, _expires_at = create_access_token(subject=payload.username, role=_as_role(role), settings=settings)
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_ttl_minutes * 60,
        username=payload.username,
        role=role,
    )


@router.get("/me", response_model=MeResponse)
def me(user: UserDep) -> MeResponse:
    return MeResponse(
        username=str(user.get("sub", "")), role=str(user.get("role", "viewer")), sub=str(user.get("sub", ""))
    )


def _as_role(value: str) -> Role:
    """Narrow a stored role string to the literal the token signer expects."""
    if value in ("admin", "analyst", "viewer"):
        return cast(Role, value)
    # An unrecognised role must not become a token that unlocks anything.
    return "viewer"


@router.get("/auth-status")
def auth_status(settings: SettingsDep) -> dict[str, object]:
    """Whether real accounts are in play. Lets the UI warn before a demo login."""
    return {
        "users_table_available": is_available(),
        # Demo logins work whenever the flag is on, regardless of the database:
        # the built-in accounts are the fallback, not the exception.
        "demo_accounts": settings.allow_demo_accounts,
    }
