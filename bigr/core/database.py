"""Async SQLAlchemy engine, session factory, and FastAPI dependency."""

from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from bigr.core.settings import settings


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


def get_database_url(url: str | None = None) -> str:
    """Convert a user-facing DATABASE_URL to an async SQLAlchemy URL.

    Handles:
    - ``sqlite:///...`` → ``sqlite+aiosqlite:///...``
    - ``postgresql://...`` → ``postgresql+asyncpg://...``
    - ``?sslmode=require`` → stripped (asyncpg uses ``ssl=True`` via connect_args)
    - ``~`` expansion in sqlite paths
    """
    raw = url or settings.DATABASE_URL
    result = raw

    if result.startswith("sqlite:///"):
        # Expand ~ in path
        path_part = result[len("sqlite:///"):]
        if path_part.startswith("~"):
            path_part = str(Path(path_part).expanduser())
            # Ensure parent dir exists
            Path(path_part).parent.mkdir(parents=True, exist_ok=True)
        result = f"sqlite+aiosqlite:///{path_part}"
    elif result.startswith("postgresql://"):
        result = result.replace("postgresql://", "postgresql+asyncpg://", 1)
        # Strip sslmode param (asyncpg handles SSL differently)
        result = result.replace("?sslmode=require", "").replace("&sslmode=require", "")
    elif result.startswith("postgres://"):
        result = result.replace("postgres://", "postgresql+asyncpg://", 1)
        result = result.replace("?sslmode=require", "").replace("&sslmode=require", "")

    return result


# Lazy singletons
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(url: str | None = None) -> AsyncEngine:
    """Return the shared async engine (created on first call)."""
    global _engine
    if _engine is not None:
        return _engine

    db_url = get_database_url(url)
    kwargs: dict = {}

    if "asyncpg" in db_url:
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 10
        # SSL for Neon
        if "neon.tech" in db_url:
            import ssl

            ssl_ctx = ssl.create_default_context()
            kwargs["connect_args"] = {"ssl": ssl_ctx}
    else:
        # SQLite: no pooling needed, but echo for debug
        kwargs["echo"] = settings.DEBUG

    _engine = create_async_engine(db_url, **kwargs)

    # Enforce foreign keys on SQLite connections
    if "aiosqlite" in db_url:

        @event.listens_for(_engine.sync_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return _engine


def get_session_factory(url: str | None = None) -> async_sessionmaker[AsyncSession]:
    """Return the shared session factory."""
    global _session_factory
    if _session_factory is not None:
        return _session_factory
    _session_factory = async_sessionmaker(
        get_engine(url), expire_on_commit=False
    )
    return _session_factory


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields an async session."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


def reset_engine() -> None:
    """Reset engine and session factory (for testing)."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
