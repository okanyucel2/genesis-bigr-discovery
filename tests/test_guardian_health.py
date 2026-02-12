"""Tests for Guardian health checker."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from dnslib import DNSRecord, RR, A, QTYPE

from bigr.guardian.config import GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.cache import DNSCache
from bigr.guardian.dns.resolver import UpstreamResolver
from bigr.guardian.health import GuardianHealthChecker


def _make_dns_response(domain: str) -> DNSRecord:
    q = DNSRecord.question(domain, "A")
    q.add_answer(RR(domain, QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
    return q


@pytest.fixture
def config():
    return GuardianConfig()


@pytest.fixture
def resolver():
    return UpstreamResolver()


@pytest.fixture
def blocklist(config):
    mgr = BlocklistManager(config)
    mgr._blocked_domains = {"evil.com"}
    return mgr


@pytest.fixture
def cache():
    return DNSCache()


@pytest.fixture
def checker(resolver, blocklist, cache, config):
    return GuardianHealthChecker(
        resolver=resolver, blocklist=blocklist, cache=cache, config=config
    )


class TestCheckDNSResolution:
    async def test_resolution_success(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(
            return_value=_make_dns_response("example.com")
        )
        result = await checker.check_dns_resolution()
        assert result is True

    async def test_resolution_failure(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(return_value=None)
        result = await checker.check_dns_resolution()
        assert result is False

    async def test_resolution_exception(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(side_effect=Exception("Network error"))
        result = await checker.check_dns_resolution()
        assert result is False


class TestCheckUpstreamReachable:
    async def test_upstream_reachable(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(
            return_value=_make_dns_response("cloudflare.com")
        )
        result = await checker.check_upstream_reachable()
        assert result is True

    async def test_upstream_unreachable(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(return_value=None)
        result = await checker.check_upstream_reachable()
        assert result is False


class TestCheckBlocklistFreshness:
    def test_has_domains(self, checker: GuardianHealthChecker):
        assert checker.check_blocklist_freshness() is True

    def test_empty_blocklist(self, config):
        empty_bl = BlocklistManager(config)
        empty_checker = GuardianHealthChecker(
            resolver=UpstreamResolver(),
            blocklist=empty_bl,
            cache=DNSCache(),
            config=config,
        )
        assert empty_checker.check_blocklist_freshness() is False


class TestCheckAll:
    async def test_all_healthy(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(
            return_value=_make_dns_response("example.com")
        )
        result = await checker.check_all()
        assert result["status"] == "healthy"
        assert result["checks"]["dns_resolution"]["ok"] is True
        assert result["checks"]["upstream_reachable"]["ok"] is True
        assert result["checks"]["blocklist_fresh"]["ok"] is True
        assert "cache" in result["checks"]

    async def test_degraded_when_resolution_fails(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(return_value=None)
        result = await checker.check_all()
        assert result["status"] == "degraded"

    async def test_includes_fallback_info(self, checker: GuardianHealthChecker):
        checker._resolver.resolve = AsyncMock(return_value=None)
        result = await checker.check_all()
        assert "fallback_dns" in result
