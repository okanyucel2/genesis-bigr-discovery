"""Tests for blocklist manager."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.guardian.config import BlocklistSource, GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.models import GuardianBlockedDomainDB, GuardianBlocklistDB


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
def config():
    return GuardianConfig(
        blocklists=[
            BlocklistSource(
                name="Test Hosts",
                url="https://test.com/hosts",
                format="hosts",
                category="malware",
            ),
        ]
    )


@pytest.fixture
def manager(config):
    return BlocklistManager(config)


class TestParseBlocklist:
    def test_parse_hosts_format(self):
        raw = """# Comment
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
127.0.0.1 malware.example.com
# Another comment
"""
        domains = BlocklistManager._parse_blocklist(raw, "hosts")
        assert "ads.example.com" in domains
        assert "tracker.example.com" in domains
        assert "malware.example.com" in domains
        assert len(domains) == 3

    def test_parse_domains_format(self):
        raw = """# Comment
ads.example.com
tracker.example.com
! Another comment
"""
        domains = BlocklistManager._parse_blocklist(raw, "domains")
        assert "ads.example.com" in domains
        assert "tracker.example.com" in domains
        assert len(domains) == 2

    def test_skips_localhost(self):
        raw = "0.0.0.0 localhost\n0.0.0.0 evil.com\n"
        domains = BlocklistManager._parse_blocklist(raw, "hosts")
        assert "localhost" not in domains
        assert "evil.com" in domains

    def test_skips_empty_lines(self):
        raw = "\n\n0.0.0.0 test.com\n\n"
        domains = BlocklistManager._parse_blocklist(raw, "hosts")
        assert len(domains) == 1

    def test_lowercases_domains(self):
        raw = "0.0.0.0 ADS.Example.COM\n"
        domains = BlocklistManager._parse_blocklist(raw, "hosts")
        assert "ads.example.com" in domains

    def test_deduplicates(self):
        raw = "0.0.0.0 dup.com\n0.0.0.0 dup.com\n"
        domains = BlocklistManager._parse_blocklist(raw, "hosts")
        assert len(domains) == 1


class TestIsBlocked:
    def test_exact_match(self, manager: BlocklistManager):
        manager._blocked_domains = {"evil.com"}
        manager._domain_categories = {"evil.com": "malware"}
        blocked, cat = manager.is_blocked("evil.com")
        assert blocked is True
        assert cat == "malware"

    def test_not_blocked(self, manager: BlocklistManager):
        manager._blocked_domains = {"evil.com"}
        blocked, cat = manager.is_blocked("good.com")
        assert blocked is False
        assert cat == ""

    def test_parent_domain_match(self, manager: BlocklistManager):
        manager._blocked_domains = {"tracker.com"}
        manager._domain_categories = {"tracker.com": "tracker"}
        blocked, cat = manager.is_blocked("ads.tracker.com")
        assert blocked is True
        assert cat == "tracker"

    def test_subdomain_of_blocked(self, manager: BlocklistManager):
        manager._blocked_domains = {"doubleclick.net"}
        manager._domain_categories = {"doubleclick.net": "ad"}
        blocked, cat = manager.is_blocked("ad.doubleclick.net")
        assert blocked is True

    def test_trailing_dot_handled(self, manager: BlocklistManager):
        manager._blocked_domains = {"evil.com"}
        blocked, _ = manager.is_blocked("evil.com.")
        assert blocked is True

    def test_case_insensitive(self, manager: BlocklistManager):
        manager._blocked_domains = {"evil.com"}
        blocked, _ = manager.is_blocked("EVIL.COM")
        assert blocked is True


class TestUpdateBlocklist:
    async def test_download_and_store(self, manager: BlocklistManager, session: AsyncSession):
        mock_hosts = "0.0.0.0 ads.test.com\n0.0.0.0 tracker.test.com\n"

        with patch("bigr.guardian.dns.blocklist.httpx.AsyncClient") as mock_client_class:
            mock_response = MagicMock()
            mock_response.text = mock_hosts
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            results = await manager.update_all_blocklists(session)

        assert "Test Hosts" in results
        assert results["Test Hosts"]["status"] == "ok"
        assert results["Test Hosts"]["domains"] == 2
        assert manager.domain_count == 2

    async def test_load_from_db(self, manager: BlocklistManager, session: AsyncSession):
        # Insert test data
        bl = GuardianBlocklistDB(
            id="bl-test", name="Test", url="https://test.com"
        )
        session.add(bl)
        await session.flush()

        for domain in ["a.com", "b.com", "c.com"]:
            session.add(
                GuardianBlockedDomainDB(
                    domain=domain, blocklist_id="bl-test", category="malware"
                )
            )
        await session.commit()

        count = await manager.load_from_db(session)
        assert count == 3
        assert manager.is_blocked("a.com")[0] is True
