"""Tests for Guardian ORM models."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.guardian.models import (
    GuardianBlockedDomainDB,
    GuardianBlocklistDB,
    GuardianCustomRuleDB,
    GuardianQueryStatsDB,
    GuardianTopDomainDB,
)


@pytest.fixture
async def session():
    """Create an in-memory SQLite session with Guardian tables."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


class TestGuardianBlocklistDB:
    async def test_create_blocklist(self, session: AsyncSession):
        bl = GuardianBlocklistDB(
            id="bl-1",
            name="StevenBlack",
            url="https://example.com/hosts",
            format="hosts",
            category="malware",
            domain_count=50000,
        )
        session.add(bl)
        await session.commit()

        result = await session.execute(
            select(GuardianBlocklistDB).where(GuardianBlocklistDB.id == "bl-1")
        )
        row = result.scalar_one()
        assert row.name == "StevenBlack"
        assert row.domain_count == 50000
        assert row.is_enabled == 1

    async def test_blocklist_defaults(self, session: AsyncSession):
        bl = GuardianBlocklistDB(
            id="bl-2", name="Test", url="https://test.com"
        )
        session.add(bl)
        await session.commit()

        result = await session.execute(
            select(GuardianBlocklistDB).where(GuardianBlocklistDB.id == "bl-2")
        )
        row = result.scalar_one()
        assert row.format == "hosts"
        assert row.category == "malware"
        assert row.domain_count == 0
        assert row.is_enabled == 1


class TestGuardianBlockedDomainDB:
    async def test_create_blocked_domain(self, session: AsyncSession):
        bl = GuardianBlocklistDB(
            id="bl-1", name="Test", url="https://test.com"
        )
        session.add(bl)
        await session.flush()

        domain = GuardianBlockedDomainDB(
            domain="ads.example.com",
            blocklist_id="bl-1",
            category="ad",
        )
        session.add(domain)
        await session.commit()

        result = await session.execute(
            select(GuardianBlockedDomainDB).where(
                GuardianBlockedDomainDB.domain == "ads.example.com"
            )
        )
        row = result.scalar_one()
        assert row.blocklist_id == "bl-1"
        assert row.category == "ad"


class TestGuardianCustomRuleDB:
    async def test_create_block_rule(self, session: AsyncSession):
        rule = GuardianCustomRuleDB(
            id="rule-1",
            action="block",
            domain="malware.example.com",
            category="malware",
            reason="Known malware domain",
            created_at="2026-02-12T00:00:00Z",
        )
        session.add(rule)
        await session.commit()

        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == "rule-1")
        )
        row = result.scalar_one()
        assert row.action == "block"
        assert row.domain == "malware.example.com"
        assert row.hit_count == 0
        assert row.is_active == 1

    async def test_create_allow_rule(self, session: AsyncSession):
        rule = GuardianCustomRuleDB(
            id="rule-2",
            action="allow",
            domain="safe.example.com",
            reason="Whitelisted",
            created_at="2026-02-12T00:00:00Z",
        )
        session.add(rule)
        await session.commit()

        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == "rule-2")
        )
        row = result.scalar_one()
        assert row.action == "allow"

    async def test_hit_count_increment(self, session: AsyncSession):
        rule = GuardianCustomRuleDB(
            id="rule-3",
            action="block",
            domain="test.com",
            created_at="2026-02-12T00:00:00Z",
        )
        session.add(rule)
        await session.commit()

        rule.hit_count += 1
        await session.commit()

        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == "rule-3")
        )
        assert result.scalar_one().hit_count == 1


class TestGuardianQueryStatsDB:
    async def test_create_stats(self, session: AsyncSession):
        stats = GuardianQueryStatsDB(
            date="2026-02-12",
            hour=14,
            total_queries=1000,
            blocked_queries=150,
            allowed_queries=850,
            cache_hits=600,
        )
        session.add(stats)
        await session.commit()

        result = await session.execute(select(GuardianQueryStatsDB))
        row = result.scalar_one()
        assert row.date == "2026-02-12"
        assert row.hour == 14
        assert row.total_queries == 1000

    async def test_unique_date_hour(self, session: AsyncSession):
        stats1 = GuardianQueryStatsDB(
            date="2026-02-12", hour=10, total_queries=100
        )
        session.add(stats1)
        await session.commit()

        stats2 = GuardianQueryStatsDB(
            date="2026-02-12", hour=10, total_queries=200
        )
        session.add(stats2)
        with pytest.raises(Exception):  # IntegrityError
            await session.commit()


class TestGuardianTopDomainDB:
    async def test_create_top_domain(self, session: AsyncSession):
        td = GuardianTopDomainDB(
            domain="ads.tracker.com",
            block_count=500,
            category="tracker",
            last_blocked="2026-02-12T14:00:00Z",
        )
        session.add(td)
        await session.commit()

        result = await session.execute(
            select(GuardianTopDomainDB).where(
                GuardianTopDomainDB.domain == "ads.tracker.com"
            )
        )
        row = result.scalar_one()
        assert row.block_count == 500
        assert row.category == "tracker"


class TestTableCreation:
    async def test_all_tables_exist(self, session: AsyncSession):
        """Verify all Guardian tables are created."""
        tables = await session.run_sync(
            lambda sync_session: inspect(sync_session.bind).get_table_names()
        )
        expected = [
            "guardian_blocklists",
            "guardian_blocked_domains",
            "guardian_custom_rules",
            "guardian_query_stats",
            "guardian_top_domains",
        ]
        for table in expected:
            assert table in tables, f"Missing table: {table}"
