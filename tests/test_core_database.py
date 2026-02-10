"""Tests for bigr.core.database module."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import (
    Base,
    get_database_url,
    get_engine,
    get_session_factory,
    reset_engine,
)


class TestGetDatabaseUrl:
    """URL conversion logic."""

    def test_sqlite_to_aiosqlite(self):
        url = get_database_url("sqlite:///test.db")
        assert url == "sqlite+aiosqlite:///test.db"

    def test_sqlite_tilde_expansion(self):
        url = get_database_url("sqlite:///~/.bigr/bigr.db")
        assert "aiosqlite" in url
        assert "~" not in url  # tilde expanded

    def test_postgresql_to_asyncpg(self):
        url = get_database_url("postgresql://user:pass@host/db")
        assert url == "postgresql+asyncpg://user:pass@host/db"

    def test_postgres_shorthand(self):
        url = get_database_url("postgres://user:pass@host/db")
        assert url == "postgresql+asyncpg://user:pass@host/db"

    def test_sslmode_stripped(self):
        url = get_database_url("postgresql://u:p@h/d?sslmode=require")
        assert "sslmode" not in url
        assert url == "postgresql+asyncpg://u:p@h/d"

    def test_sslmode_stripped_with_ampersand(self):
        url = get_database_url("postgresql://u:p@h/d?foo=bar&sslmode=require")
        assert "sslmode" not in url

    def test_already_async_url_passthrough(self):
        url = get_database_url("sqlite+aiosqlite:///test.db")
        # Not double-converted
        assert url == "sqlite+aiosqlite:///test.db"


class TestEngineCreation:
    """Engine and session factory tests using in-memory SQLite."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_engine()
        yield
        reset_engine()

    def test_get_engine_sqlite(self):
        engine = get_engine("sqlite+aiosqlite:///:memory:")
        assert engine is not None
        assert "aiosqlite" in str(engine.url)

    def test_get_engine_singleton(self):
        e1 = get_engine("sqlite+aiosqlite:///:memory:")
        e2 = get_engine()
        assert e1 is e2

    def test_session_factory_returns_maker(self):
        factory = get_session_factory("sqlite+aiosqlite:///:memory:")
        assert factory is not None

    async def test_session_yields_async_session(self):
        factory = get_session_factory("sqlite+aiosqlite:///:memory:")
        async with factory() as session:
            assert isinstance(session, AsyncSession)

    async def test_create_all_tables(self):
        engine = get_engine("sqlite+aiosqlite:///:memory:")
        # Import models to register them on Base
        import bigr.core.models_db  # noqa: F401

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Verify tables exist
        from sqlalchemy import inspect

        async with engine.connect() as conn:
            table_names = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )
        assert "scans" in table_names
        assert "assets" in table_names
        assert "scan_assets" in table_names
        assert "asset_changes" in table_names
        assert "subnets" in table_names
        assert "switches" in table_names
        assert "certificates" in table_names
