"""Alembic async environment for BİGR Discovery."""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from bigr.core.database import Base, get_database_url

# Import all models so Base.metadata is populated
import bigr.core.models_db  # noqa: F401
import bigr.threat.models  # noqa: F401
import bigr.guardian.models  # noqa: F401
# collective_signals is in bigr.core.models_db (CollectiveSignalDB)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    """Read DATABASE_URL from env (fresh each call) and convert to async."""
    raw = os.environ.get("DATABASE_URL")
    return get_database_url(raw)


_VERSION_TABLE = "bigr_alembic_version"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=_VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    """Helper called inside a sync connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table=_VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode using async engine."""
    url = _get_url()
    kwargs: dict = {"poolclass": pool.NullPool}

    # Neon requires SSL — get_database_url strips ?sslmode=require
    # so we must add SSL context explicitly (mirrors database.py logic)
    if "neon.tech" in url:
        import ssl

        ssl_ctx = ssl.create_default_context()
        kwargs["connect_args"] = {"ssl": ssl_ctx}

    connectable = create_async_engine(url, **kwargs)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
