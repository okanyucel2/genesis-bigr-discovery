"""Tests for stats tracker."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.guardian.models import GuardianQueryStatsDB, GuardianTopDomainDB
from bigr.guardian.stats import StatsTracker


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


@pytest.fixture
def tracker():
    return StatsTracker(flush_interval=300, top_domains_limit=10)


class TestRecordQuery:
    def test_record_allowed(self, tracker: StatsTracker):
        tracker.record_query("example.com", "allow", "default_allow")
        stats = tracker.get_stats_summary()
        assert stats["current_period"]["total_queries"] == 1
        assert stats["current_period"]["allowed_queries"] == 1
        assert stats["current_period"]["blocked_queries"] == 0

    def test_record_blocked(self, tracker: StatsTracker):
        tracker.record_query("evil.com", "block", "blocklist")
        stats = tracker.get_stats_summary()
        assert stats["current_period"]["blocked_queries"] == 1
        assert stats["current_period"]["block_rate"] == 1.0

    def test_record_cache_hit(self, tracker: StatsTracker):
        tracker.record_query("cached.com", "allow", "cache_hit", is_cache_hit=True)
        stats = tracker.get_stats_summary()
        assert stats["current_period"]["cache_hits"] == 1

    def test_block_rate_calculation(self, tracker: StatsTracker):
        for _ in range(3):
            tracker.record_query("evil.com", "block", "blocklist")
        for _ in range(7):
            tracker.record_query("good.com", "allow", "default_allow")

        stats = tracker.get_stats_summary()
        assert stats["current_period"]["block_rate"] == pytest.approx(0.3)

    def test_lifetime_counters(self, tracker: StatsTracker):
        tracker.record_query("a.com", "allow", "default")
        tracker.record_query("b.com", "block", "blocklist")
        stats = tracker.get_stats_summary()
        assert stats["lifetime"]["total_queries"] == 2
        assert stats["lifetime"]["blocked_queries"] == 1


class TestTopBlockedDomains:
    def test_tracks_top_domains(self, tracker: StatsTracker):
        for _ in range(10):
            tracker.record_query("top1.com", "block", "blocklist")
        for _ in range(5):
            tracker.record_query("top2.com", "block", "blocklist")
        for _ in range(1):
            tracker.record_query("top3.com", "block", "blocklist")

        stats = tracker.get_stats_summary()
        top = stats["top_blocked_domains"]
        assert len(top) == 3
        assert top[0]["domain"] == "top1.com"
        assert top[0]["count"] == 10
        assert top[1]["domain"] == "top2.com"

    def test_respects_limit(self):
        tracker = StatsTracker(top_domains_limit=2)
        for i in range(5):
            tracker.record_query(f"domain{i}.com", "block", "bl")
        stats = tracker.get_stats_summary()
        assert len(stats["top_blocked_domains"]) == 2


class TestFlushToDB:
    async def test_flush_creates_stats(self, tracker: StatsTracker, session: AsyncSession):
        tracker.record_query("example.com", "allow", "default")
        tracker.record_query("evil.com", "block", "blocklist")

        await tracker.flush_to_db(session)

        result = await session.execute(select(GuardianQueryStatsDB))
        row = result.scalar_one()
        assert row.total_queries == 2
        assert row.blocked_queries == 1
        assert row.allowed_queries == 1

    async def test_flush_resets_period_counters(
        self, tracker: StatsTracker, session: AsyncSession
    ):
        tracker.record_query("a.com", "allow", "default")
        await tracker.flush_to_db(session)

        stats = tracker.get_stats_summary()
        assert stats["current_period"]["total_queries"] == 0
        # Lifetime should still be tracked
        assert stats["lifetime"]["total_queries"] == 1

    async def test_flush_accumulates_hourly(
        self, tracker: StatsTracker, session: AsyncSession
    ):
        tracker.record_query("a.com", "allow", "default")
        await tracker.flush_to_db(session)

        tracker.record_query("b.com", "block", "bl")
        await tracker.flush_to_db(session)

        result = await session.execute(select(GuardianQueryStatsDB))
        row = result.scalar_one()
        assert row.total_queries == 2

    async def test_flush_empty_does_nothing(
        self, tracker: StatsTracker, session: AsyncSession
    ):
        await tracker.flush_to_db(session)
        result = await session.execute(select(GuardianQueryStatsDB))
        rows = result.scalars().all()
        assert len(rows) == 0

    async def test_flush_updates_top_domains(
        self, tracker: StatsTracker, session: AsyncSession
    ):
        for _ in range(5):
            tracker.record_query("top.com", "block", "bl")
        await tracker.flush_to_db(session)

        result = await session.execute(
            select(GuardianTopDomainDB).where(
                GuardianTopDomainDB.domain == "top.com"
            )
        )
        row = result.scalar_one()
        assert row.block_count == 5
        assert row.last_blocked is not None


class TestGetStatsSummary:
    def test_empty_stats(self, tracker: StatsTracker):
        stats = tracker.get_stats_summary()
        assert stats["current_period"]["total_queries"] == 0
        assert stats["current_period"]["block_rate"] == 0.0
        assert stats["top_blocked_domains"] == []
