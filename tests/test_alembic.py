"""Tests for Alembic migration lifecycle."""

from __future__ import annotations

import os
import tempfile

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


@pytest.fixture
def alembic_cfg():
    """Create an Alembic config pointing at a temp SQLite."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_url = f"sqlite:///{tmp.name}"

    cfg = Config("alembic.ini")
    # Override the URL via env so alembic/env.py picks it up
    os.environ["DATABASE_URL"] = db_url
    yield cfg, tmp.name, db_url
    os.unlink(tmp.name)
    os.environ.pop("DATABASE_URL", None)


class TestAlembicMigrations:
    def test_upgrade_head_creates_all_tables(self, alembic_cfg):
        cfg, db_path, db_url = alembic_cfg
        command.upgrade(cfg, "head")

        engine = create_engine(db_url)
        table_names = set(inspect(engine).get_table_names())
        engine.dispose()

        expected = {
            "scans", "assets", "scan_assets", "asset_changes",
            "subnets", "switches", "certificates", "alembic_version",
        }
        assert expected.issubset(table_names), f"Missing: {expected - table_names}"

    def test_downgrade_base_drops_all(self, alembic_cfg):
        cfg, db_path, db_url = alembic_cfg
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")

        engine = create_engine(db_url)
        table_names = set(inspect(engine).get_table_names())
        engine.dispose()

        # Only alembic_version may remain (or empty)
        app_tables = table_names - {"alembic_version"}
        assert len(app_tables) == 0, f"Tables not dropped: {app_tables}"

    def test_upgrade_is_idempotent(self, alembic_cfg):
        cfg, db_path, db_url = alembic_cfg
        command.upgrade(cfg, "head")
        # Running again should not fail
        command.upgrade(cfg, "head")

        engine = create_engine(db_url)
        table_names = inspect(engine).get_table_names()
        engine.dispose()
        assert "scans" in table_names
