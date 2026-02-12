"""End-to-end integration test for Guardian DNS filtering."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dnslib import DNSRecord, RR, A, QTYPE
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.guardian.config import BlocklistSource, GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.cache import DNSCache
from bigr.guardian.dns.decision import DecisionAction, QueryDecisionEngine
from bigr.guardian.dns.resolver import UpstreamResolver
from bigr.guardian.dns.rules import CustomRulesManager
from bigr.guardian.dns.server import GuardianDNSServer
from bigr.guardian.health import GuardianHealthChecker
from bigr.guardian.stats import StatsTracker


def _make_upstream_response(domain: str, ip: str = "93.184.216.34") -> DNSRecord:
    q = DNSRecord.question(domain, "A")
    q.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=300))
    return q


@pytest.fixture
async def db_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
async def session(db_factory):
    async with db_factory() as sess:
        yield sess


class TestGuardianE2E:
    """Full integration: blocklist → rules → decision → server → stats."""

    async def test_full_flow(self, session: AsyncSession, db_factory):
        # --- Setup ---
        config = GuardianConfig(
            dns_port=15353,
            sinkhole_ip="0.0.0.0",
            blocklists=[
                BlocklistSource(
                    name="Test", url="https://test.com/hosts", category="ad"
                )
            ],
        )

        # Initialize components
        cache = DNSCache(max_size=100, default_ttl=60)
        resolver = UpstreamResolver()
        blocklist = BlocklistManager(config)
        rules = CustomRulesManager()
        stats = StatsTracker()

        # --- Blocklist load (mocked download) ---
        mock_hosts = "0.0.0.0 ads.doubleclick.net\n0.0.0.0 tracker.example.com\n"
        with patch("bigr.guardian.dns.blocklist.httpx.AsyncClient") as mock_client_class:
            mock_response = MagicMock()
            mock_response.text = mock_hosts
            mock_response.raise_for_status = MagicMock()
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client
            await blocklist.update_all_blocklists(session)

        assert blocklist.domain_count == 2

        # --- Custom rules ---
        allow_id = await rules.add_rule(
            session, action="allow", domain="tracker.example.com", reason="False positive"
        )
        block_id = await rules.add_rule(
            session, action="block", domain="custom-blocked.com", reason="Manual block"
        )

        # --- Decision engine ---
        engine = QueryDecisionEngine(
            blocklist_manager=blocklist,
            rules_manager=rules,
            sinkhole_ip="0.0.0.0",
        )

        # --- DNS server ---
        server = GuardianDNSServer(
            decision_engine=engine,
            resolver=resolver,
            cache=cache,
            host="127.0.0.1",
            port=15353,
            stats_callback=stats.record_query,
        )

        # Mock upstream resolver
        resolver.resolve = AsyncMock(
            return_value=_make_upstream_response("example.com")
        )

        # --- Test 1: Blocked domain (via blocklist) → sinkhole ---
        query = DNSRecord.question("ads.doubleclick.net", "A").pack()
        response = await server.handle_query(query)
        parsed = DNSRecord.parse(response)
        assert str(parsed.rr[0].rdata) == "0.0.0.0"

        # --- Test 2: Allowed domain → upstream resolve ---
        query = DNSRecord.question("example.com", "A").pack()
        response = await server.handle_query(query)
        parsed = DNSRecord.parse(response)
        assert str(parsed.rr[0].rdata) == "93.184.216.34"

        # --- Test 3: Custom allow overrides blocklist ---
        resolver.resolve = AsyncMock(
            return_value=_make_upstream_response("tracker.example.com", "1.2.3.4")
        )
        query = DNSRecord.question("tracker.example.com", "A").pack()
        response = await server.handle_query(query)
        parsed = DNSRecord.parse(response)
        # Should resolve normally (not sinkholes) because of custom allow
        assert str(parsed.rr[0].rdata) == "1.2.3.4"

        # --- Test 4: Custom block → sinkhole ---
        query = DNSRecord.question("custom-blocked.com", "A").pack()
        response = await server.handle_query(query)
        parsed = DNSRecord.parse(response)
        assert str(parsed.rr[0].rdata) == "0.0.0.0"

        # --- Test 5: Cache hit ---
        resolver.resolve = AsyncMock(
            return_value=_make_upstream_response("example.com")
        )
        query = DNSRecord.question("example.com", "A").pack()
        response = await server.handle_query(query)
        # Should be from cache (resolver should NOT be called again for example.com)
        # But we mocked it again so it would work either way — verify via cache stats
        cache_stats = await cache.stats()
        assert cache_stats.hits >= 1

        # --- Test 6: Stats verification ---
        summary = stats.get_stats_summary()
        assert summary["current_period"]["total_queries"] >= 4
        assert summary["current_period"]["blocked_queries"] >= 2
        assert summary["current_period"]["allowed_queries"] >= 2

        # --- Test 7: Stats flush to DB ---
        await stats.flush_to_db(session)
        from sqlalchemy import select
        from bigr.guardian.models import GuardianQueryStatsDB
        result = await session.execute(select(GuardianQueryStatsDB))
        row = result.scalar_one()
        assert row.total_queries >= 4

        # --- Test 8: Health check ---
        health = GuardianHealthChecker(
            resolver=resolver, blocklist=blocklist, cache=cache, config=config
        )
        resolver.resolve = AsyncMock(
            return_value=_make_upstream_response("example.com")
        )
        health_result = await health.check_all()
        assert health_result["status"] == "healthy"

    async def test_subdomain_blocking(self, session: AsyncSession):
        """Test that subdomains of blocked domains are also blocked."""
        config = GuardianConfig(sinkhole_ip="0.0.0.0")
        blocklist = BlocklistManager(config)
        blocklist._blocked_domains = {"evil.com"}
        blocklist._domain_categories = {"evil.com": "malware"}

        rules = CustomRulesManager()
        engine = QueryDecisionEngine(
            blocklist_manager=blocklist,
            rules_manager=rules,
            sinkhole_ip="0.0.0.0",
        )

        resolver = UpstreamResolver()
        cache = DNSCache()
        server = GuardianDNSServer(
            decision_engine=engine,
            resolver=resolver,
            cache=cache,
        )

        # sub.evil.com should be blocked
        query = DNSRecord.question("sub.evil.com", "A").pack()
        response = await server.handle_query(query)
        parsed = DNSRecord.parse(response)
        assert str(parsed.rr[0].rdata) == "0.0.0.0"

        # deep.sub.evil.com should also be blocked
        query = DNSRecord.question("deep.sub.evil.com", "A").pack()
        response = await server.handle_query(query)
        parsed = DNSRecord.parse(response)
        assert str(parsed.rr[0].rdata) == "0.0.0.0"
