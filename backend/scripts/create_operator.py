"""Create or update a real operator account.

Production runs with ``ALLOW_DEMO_ACCOUNTS=false``, which means there is no
built-in way in -- someone has to seed the first account. This script is that
someone. Run it once against the same ``POSTGRES_DSN`` the service uses::

    export POSTGRES_DSN='postgresql+psycopg://user:pass@host/db?sslmode=require'
    python -m scripts.create_operator --username operator --role admin

Pass the password through the environment rather than ``--password``: argv is
visible to every other process on the machine and is kept in shell history.

Why this exists instead of an admin endpoint: a route that can mint an
administrator token has to be reachable *before* anyone is authenticated, which
means it is reachable by anyone who can reach the service. A CLI that runs with
the operator's own database credentials cannot be.
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import get_settings
from app.core.security import Role, hash_password
from app.db.models import UserRow
from app.db.session import create_all, get_engine, session_scope

#: Argon2id cost is tuned for an interactive login. Applying it to a handful of
#: accounts is negligible, so this reuses the same settings rather than
#: inventing a second, weaker path.
_ROLES: tuple[Role, ...] = ("admin", "analyst", "viewer")


def _read_password() -> str:
    """Prefer the environment; fall back to a hidden prompt.

    A plain prompt is rejected so a password cannot end up in a transcript or a
    CI log via a shell that echoes input.
    """
    from_env = os.getenv("OPERATOR_PASSWORD")
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        sys.exit("set OPERATOR_PASSWORD, or run this in an interactive terminal")
    return getpass.getpass("password: ")


def _validate_password(password: str) -> None:
    """Reject what the demo accounts taught reviewers to guess.

    Length is the only rule that reliably matters; complexity rules mostly
    produce `Passw0rd!`. Twelve characters also subsumes the three documented
    demo passwords (9-11 characters), so no separate blocklist is needed.
    """
    if len(password) < 12:
        sys.exit("password must be at least 12 characters")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--username", required=True, help="login name, e.g. operator")
    parser.add_argument("--role", default="admin", choices=_ROLES, help="authorization role (default: admin)")
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="reset an existing account's password and re-enable it instead of failing",
    )
    args = parser.parse_args()

    engine = get_engine()
    if engine is None:
        # The single most common way to fail here is an unset or malformed DSN,
        # so name the variable rather than reporting a driver error.
        sys.exit(
            "no database: set POSTGRES_DSN to a postgres:// or postgresql+psycopg:// URL.\n"
            "  Render: read it from the service's Environment tab."
        )

    # Idempotent so the same command can be re-run after a schema change.
    if not create_all(engine):
        sys.exit("could not create the schema")

    password = _read_password()
    _validate_password(password)
    encoded = hash_password(password)

    try:
        with session_scope() as session:
            if session is None:
                sys.exit("no database: could not open a session")
            row = session.query(UserRow).filter(UserRow.username == args.username).first()
            if row is None:
                session.add(
                    UserRow(
                        id=f"usr_{secrets.token_hex(8)}",
                        username=args.username,
                        password_hash=encoded,
                        role=args.role,
                    )
                )
                action = "created"
            elif args.rotate:
                # Replace rather than add a second row: the unique constraint on
                # username means a second insert fails, and a stale admin row is a
                # security problem, not a data-entry error.
                row.password_hash = encoded
                row.role = args.role
                row.disabled = False
                action = "rotated"
            else:
                sys.exit(f"user '{args.username}' already exists; pass --rotate to reset it")
    except SQLAlchemyError as exc:
        sys.exit(f"database error: {exc}")

    print(f"{action} '{args.username}' with role {args.role}")
    if action == "rotated":
        # Tokens are stateless and only check the signing key, so a rotated
        # password does not revoke them. Say so instead of implying a lockout.
        print(f"tokens already issued stay valid for up to {get_settings().access_token_ttl_minutes} minutes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())