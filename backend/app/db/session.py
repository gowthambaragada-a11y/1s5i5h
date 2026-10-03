"""Database engine and session management.

The pipeline must run without PostgreSQL. Not as a fallback mode for convenience
-- because a developer evaluating the project, or a reviewer running the test
suite, will not have a database to hand. Every entry point therefore goes through
:func:`session_scope`, which yields ``None`` when no database is reachable, and
callers are required to say so in their response rather than inventing data.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None
_unavailable_reason: str | None = None

#: Probed to decide whether the schema is actually there. Every other table is
#: created in the same `create_all` call, so its absence means none of them are.
_SCHEMA_PROBE_TABLE = "users"


def _build_engine() -> Engine | None:
    """Construct the engine. Returns ``None`` if the DSN or driver is unusable.

    Deliberately does *not* check the schema: `create_all` needs a raw engine to
    create the schema in the first place.
    """
    settings = get_settings()
    try:
        return create_engine(
            settings.postgres_dsn,
            echo=settings.db_echo,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            future=True,
        )
    except Exception as exc:  # noqa: BLE001 - a missing driver is "no database"
        # SQLAlchemy raises ImportError (not SQLAlchemyError) when the DBAPI
        # driver is absent, and raises plain SQLAlchemyError subclasses on a
        # bad DSN. Both mean the same thing to a caller: not available.
        _unavailable_reason = f"could not build engine: {type(exc).__name__}: {exc}"
        logger.warning("postgres unavailable: %s", _unavailable_reason)
        return None


def _schema_exists(engine: Engine) -> bool:
    """Whether the application tables have been created.

    This check is the reason a freshly provisioned Postgres does not turn every
    endpoint into a 500. A brand-new Neon or Supabase project accepts connections
    immediately, so a bare ``SELECT 1`` probe reports "available" and the first
    real query fails with ``relation "users" does not exist`` -- surfacing to an
    operator as an internal server error instead of the 503 that every caller
    already knows how to handle.
    """
    try:
        # `has_table` rather than a probe query: it is a metadata lookup, and it
        # needs no SQL string at all.
        return bool(inspect(engine).has_table(_SCHEMA_PROBE_TABLE))
    except SQLAlchemyError:
        return False


def get_engine() -> Engine | None:
    """Lazily build the engine. ``None`` when Postgres is unusable.

    "Unusable" covers a bad DSN, a missing driver, and a reachable database with
    no schema -- all three mean the same thing to a caller, which cannot do any
    of the work it was asked for.
    """
    global _engine, _unavailable_reason
    if _engine is not None:
        return _engine
    if _unavailable_reason is not None:
        return None

    engine = _build_engine()
    if engine is None:
        return None

    if not _schema_exists(engine):
        _unavailable_reason = (
            f"connected to postgres but table '{_SCHEMA_PROBE_TABLE}' is missing; "
            "run 'python -m scripts.create_operator' to create the schema"
        )
        engine.dispose()
        logger.warning("postgres schema missing: %s", _unavailable_reason)
        return None

    _engine = engine
    return _engine


def get_session_factory() -> sessionmaker[Session] | None:
    global _SessionFactory
    if _SessionFactory is not None:
        return _SessionFactory
    engine = get_engine()
    if engine is None:
        return None
    _SessionFactory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return _SessionFactory


@contextmanager
def session_scope() -> Iterator[Session | None]:
    """Yield a session, or ``None`` when Postgres is unavailable.

    Callers must treat ``None`` as "results are not persisted", never as
    "there are no results". Those are very different answers.
    """
    factory = get_session_factory()
    if factory is None:
        yield None
        return
    session = factory()
    try:
        yield session
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.close()


def is_available() -> bool:
    """True when Postgres is reachable *and* the schema exists."""
    engine = get_engine()
    if engine is None:
        return False
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as exc:
        logger.info("postgres probe failed: %s", exc)
        return False


def unavailable_reason() -> str | None:
    """Why the database is unavailable, for surfacing on ``/readyz``."""
    return _unavailable_reason


def create_all(engine: Engine | None = None) -> bool:
    """Create the schema. Returns False when there is no database to create it in.

    Builds a raw engine when none is given, bypassing the schema check in
    :func:`get_engine` -- otherwise the database could never be initialised,
    since a missing schema is exactly what this is called to fix.
    """
    target = engine or _build_engine()
    if target is None:
        return False
    from app.db.models import Base

    Base.metadata.create_all(target)
    # `get_engine` may already have cached "unusable" from an earlier probe.
    reset_state()
    return True


def dispose() -> None:
    """Release pooled connections. Used on shutdown and in tests."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None


def reset_state() -> None:
    """Forget the cached failure so a later call can retry. Used by tests."""
    global _unavailable_reason
    _unavailable_reason = None
