"""Shared FastAPI dependencies: settings, pipeline, auth, uploads.

Authentication is deliberately boring: a signed JWT, verified on every request,
with the role read from the token rather than from anything the client sends. A
viewer must not be able to promote themselves by posting ``{"role": "admin"}``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings
from app.core.security import Role, decode_access_token, validate_upload
from app.pipeline.orchestrator import Pipeline

#: ``auto_error=False`` so we can return a JSON body rather than FastAPI's
#: default 403 shape, which the frontend does not know how to render.
_bearer = HTTPBearer(auto_error=False)

SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_pipeline() -> Pipeline:
    """One pipeline per process.

    The rule engine and detector are stateless between scans (the detector holds
    only a fitted baseline), so sharing is safe and avoids re-parsing every rule
    pack on each request.
    """
    global _pipeline
    if _pipeline is None:
        _pipeline = Pipeline.build()
    return _pipeline


PipelineDep = Annotated[Pipeline, Depends(get_pipeline)]


def get_db() -> Iterator[object]:
    """Yield a database session, or ``None`` when Postgres is unreachable."""
    from app.db.session import session_scope

    with session_scope() as session:
        yield session


DbDep = Annotated[object, Depends(get_db)]


async def current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, object]:
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_access_token(creds.credentials)
    except Exception as exc:  # noqa: BLE001 - any failure is an auth failure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if claims.get("disabled"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")
    return claims


UserDep = Annotated[dict[str, object], Depends(current_user)]


def require_role(*roles: Role) -> object:
    """Dependency factory enforcing a minimum role."""

    def _dep(user: UserDep) -> dict[str, object]:
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires one of: {', '.join(roles)}",
            )
        return user

    return _dep


AnalystDep = Annotated[dict[str, object], Depends(require_role("admin", "analyst"))]
AdminDep = Annotated[dict[str, object], Depends(require_role("admin"))]


async def read_config_upload(
    file: Annotated[UploadFile, Depends()],
    settings: SettingsDep,
) -> bytes:
    """Read an uploaded config, enforcing size and suffix limits.

    Validation happens on the *declared* size before the read where possible, and
    on the actual byte count afterwards -- a client can lie about Content-Length,
    so the post-read check is the one that actually protects us.
    """
    name = file.filename or ""
    validate_upload(name, 0, settings=settings)
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"config exceeds {settings.max_upload_bytes} bytes",
        )
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
    return data


UploadDep = Annotated[bytes, Depends(read_config_upload)]


async def optional_user(
    x_api_token: Annotated[str | None, Header()] = None,
) -> dict[str, object] | None:
    """For endpoints that are public in dev but should log who called them."""
    if not x_api_token:
        return None
    try:
        return decode_access_token(x_api_token)
    except Exception:  # noqa: BLE001
        return None


_pipeline: Pipeline | None = None


def reset_pipeline() -> None:
    """Drop the cached pipeline. Used by tests."""
    global _pipeline
    _pipeline = None
