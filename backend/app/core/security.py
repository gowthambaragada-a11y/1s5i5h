"""Security primitives: password hashing, JWT issue/verify, and upload hardening.

Design notes
------------
* Passwords use Argon2id (via ``argon2-cffi``) -- memory-hard, so GPU cracking
  buys the attacker nothing. Kept as an optional dep with a scrypt fallback from
  stdlib so the demo runs without native wheels.
* JWTs are signed HS256 with an env-provided secret. ``sub`` carries the user id
  and ``role`` carries the authorization role; role is *never* read from request
  bodies.
* Filenames supplied by clients are discarded entirely (see ``safe_filename``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import jwt
from jwt import InvalidTokenError

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

Role = Literal["admin", "analyst", "viewer"]


class TokenError(Exception):
    """Raised when a bearer token is missing, malformed, expired or tampered."""


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
try:  # pragma: no cover - import path depends on installed extras
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ARGON2 = True
    #: Errors that mean "wrong password / malformed hash" rather than a bug.
    _VERIFY_ERRORS: tuple[type[Exception], ...] = (VerifyMismatchError, ValueError, TypeError)
except ImportError:  # pragma: no cover
    _ARGON2 = False
    _VERIFY_ERRORS = (ValueError, TypeError)


def hash_password(password: str, *, settings: Settings | None = None) -> str:
    s = settings or get_settings()
    if _ARGON2:
        hasher = PasswordHasher(
            time_cost=s.pwd_hash_time_cost, memory_cost=s.pwd_hash_memory_cost_kib, parallelism=2
        )
        return hasher.hash(password)
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str, *, settings: Settings | None = None) -> bool:
    """Constant-time verification; never raises on malformed input."""
    try:
        if encoded.startswith("scrypt$"):
            _, n, r, p, salt_hex, dk_hex = encoded.split("$")
            dk = hashlib.scrypt(
                password.encode(),
                salt=bytes.fromhex(salt_hex),
                n=int(n),
                r=int(r),
                p=int(p),
                dklen=len(bytes.fromhex(dk_hex)),
            )
            return hmac.compare_digest(dk.hex(), dk_hex)
        if _ARGON2:
            PasswordHasher().verify(encoded, password)
            return True
    except _VERIFY_ERRORS:
        return False
    return False


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def create_access_token(
    *, subject: str, role: Role, settings: Settings | None = None, expires_delta: timedelta | None = None
) -> tuple[str, datetime]:
    s = settings or get_settings()
    now = datetime.now(UTC)
    exp = now + (expires_delta or timedelta(minutes=s.access_token_ttl_minutes))
    payload = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, s.secret_key, algorithm=s.jwt_algorithm), exp


def decode_access_token(token: str, *, settings: Settings | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    try:
        claims = jwt.decode(token, s.secret_key, algorithms=[s.jwt_algorithm])
    except InvalidTokenError as exc:
        # Deliberately vague to the caller -- never leak why validation failed.
        raise TokenError("invalid or expired token") from exc
    if not claims.get("sub"):
        raise TokenError("token missing subject")
    return claims


# --------------------------------------------------------------------------- #
# Upload hardening
# --------------------------------------------------------------------------- #
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_MAX_NAME_LEN = 96


def safe_filename(raw: str | None, *, fallback: str = "config.cfg") -> str:
    """Derive a traversal-proof filename from untrusted client input.

    Strips directory components (both POSIX and Windows separators), normalizes
    Unicode, drops control characters, and bounds the length. The result is only
    ever used for display; the on-disk name is a generated UUID.
    """
    if not raw:
        return fallback
    # Defeats "..\\..\\etc\\passwd" and unicode-escape style tricks.
    candidate = unicodedata.normalize("NFKD", raw)
    candidate = candidate.replace("\\", "/").split("/")[-1]
    candidate = "".join(ch for ch in candidate if ch.isprintable() and not _UNSAFE_CHARS.match(ch))
    candidate = candidate.lstrip(".") or fallback
    return candidate[:_MAX_NAME_LEN]


def validate_upload_name(filename: str, *, settings: Settings | None = None) -> str:
    """Check only the suffix. Size is unknowable until the body is read."""
    s = settings or get_settings()
    suffix = Path(safe_filename(filename)).suffix.lower()
    if suffix not in s.allowed_upload_suffixes:
        raise ValueError(f"unsupported file type '{suffix or 'none'}'")
    return suffix


def validate_upload_size(size: int, *, settings: Settings | None = None) -> None:
    """Check the byte count of an upload that has already been read."""
    s = settings or get_settings()
    if size <= 0:
        raise ValueError("empty upload")
    if size > s.max_upload_bytes:
        raise ValueError(f"upload exceeds {s.max_upload_bytes} bytes")


def validate_upload(filename: str, size: int, *, settings: Settings | None = None) -> None:
    """Validate suffix and size together, for callers that know both up front."""
    validate_upload_name(filename, settings=settings)
    validate_upload_size(size, settings=settings)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def generate_api_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
