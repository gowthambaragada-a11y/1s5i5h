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

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None
_unavailable_reason: str | None = None


def get_engine() -> Engine | None:
    """Lazily build the engine. Returns ``None`` if the DSN is unusable."""
    global _engine, _unavailable_reason
    if _engine is not None:
        return _engine
    if _unavailable_reason is not None:
        return None

    settings = get_settings()
    try:
        _engine = create_engine(
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
    """True when a trivial round-trip to Postgres succeeds."""
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
    """Why the database is unavailable, for surfacing on ``/healthz``."""
    return _unavailable_reason


def create_all(engine: Engine | None = None) -> bool:
    """Create the schema. Returns False when there is no database to create it in."""
    target = engine or get_engine()
    if target is None:
        return False
    from app.db.models import Base

    Base.metadata.create_all(target)
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
