"""Tests for Guardian DNS server."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from dnslib import DNSRecord, RR, A, QTYPE

from bigr.guardian.config import GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.cache import DNSCache
from bigr.guardian.dns.decision import DecisionAction, QueryDecisionEngine
from bigr.guardian.dns.resolver import UpstreamResolver
from bigr.guardian.dns.rules import CustomRulesManager
from bigr.guardian.dns.server import (
    GuardianDNSServer,
    build_nxdomain_response,
    build_servfail_response,
    build_sinkhole_response,
)


def _make_query(domain: str, qtype: str = "A") -> bytes:
    """Build a wire-format DNS query."""
    return DNSRecord.question(domain, qtype).pack()


def _make_upstream_response(domain: str, ip: str = "93.184.216.34") -> DNSRecord:
    """Build a DNS response as if from upstream."""
    q = DNSRecord.question(domain, "A")
    q.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=300))
    return q


@pytest.fixture
def blocklist():
    config = GuardianConfig()
    mgr = BlocklistManager(config)
    mgr._blocked_domains = {"ads.doubleclick.net", "malware.com"}
    mgr._domain_categories = {
        "ads.doubleclick.net": "ad",
        "malware.com": "malware",
    }
    return mgr


@pytest.fixture
def rules():
    mgr = CustomRulesManager()
    mgr._rules = {
        "whitelisted.com": ("allow", "rule-1", "custom"),
    }
    return mgr


@pytest.fixture
def engine(blocklist, rules):
    return QueryDecisionEngine(
        blocklist_manager=blocklist,
        rules_manager=rules,
        sinkhole_ip="0.0.0.0",
    )


@pytest.fixture
def cache():
    return DNSCache(max_size=100, default_ttl=300)


@pytest.fixture
def resolver():
    return UpstreamResolver()


@pytest.fixture
def server(engine, resolver, cache):
    stats_calls = []
    return GuardianDNSServer(
        decision_engine=engine,
        resolver=resolver,
        cache=cache,
        host="127.0.0.1",
        port=5353,
        stats_callback=lambda *args: stats_calls.append(args),
    ), stats_calls


class TestBuildResponses:
    def test_sinkhole_response(self):
        request = DNSRecord.parse(_make_query("evil.com"))
        reply = build_sinkhole_response(request, "0.0.0.0")
        assert len(reply.rr) == 1
        assert str(reply.rr[0].rdata) == "0.0.0.0"

    def test_nxdomain_response(self):
        request = DNSRecord.parse(_make_query("nonexistent.com"))
        reply = build_nxdomain_response(request)
        assert reply.header.rcode == 3

    def test_servfail_response(self):
        request = DNSRecord.parse(_make_query("error.com"))
        reply = build_servfail_response(request)
        assert reply.header.rcode == 2


class TestHandleQueryBlocked:
    async def test_blocked_domain_returns_sinkhole(self, server):
        srv, stats = server
        query = _make_query("malware.com")
        response_bytes = await srv.handle_query(query)

        response = DNSRecord.parse(response_bytes)
        assert len(response.rr) == 1
        assert str(response.rr[0].rdata) == "0.0.0.0"

    async def test_blocked_domain_recorded_in_stats(self, server):
        srv, stats = server
        await srv.handle_query(_make_query("malware.com"))
        assert len(stats) == 1
        assert stats[0][1] == "block"  # action


class TestHandleQueryAllowed:
    async def test_allowed_domain_resolves_upstream(self, server):
        srv, stats = server
        upstream_response = _make_upstream_response("example.com", "93.184.216.34")

        srv._resolver.resolve = AsyncMock(return_value=upstream_response)

        response_bytes = await srv.handle_query(_make_query("example.com"))
        response = DNSRecord.parse(response_bytes)
        assert len(response.rr) > 0

    async def test_upstream_failure_returns_servfail(self, server):
        srv, stats = server
        srv._resolver.resolve = AsyncMock(return_value=None)

        response_bytes = await srv.handle_query(_make_query("fail.com"))
        response = DNSRecord.parse(response_bytes)
        assert response.header.rcode == 2  # SERVFAIL


class TestHandleQueryCache:
    async def test_cache_hit(self, server):
        srv, stats = server

        # Pre-populate cache
        upstream_response = _make_upstream_response("cached.com")
        cache_key = "cached.com:A"
        await srv._cache.set(cache_key, upstream_response.pack(), ttl=300)

        response_bytes = await srv.handle_query(_make_query("cached.com"))
        response = DNSRecord.parse(response_bytes)
        assert len(response.rr) > 0

        # Should record as cache hit
        assert stats[0][3] is True  # is_cache_hit

    async def test_resolved_response_cached(self, server):
        srv, stats = server
        upstream_response = _make_upstream_response("tocache.com")
        srv._resolver.resolve = AsyncMock(return_value=upstream_response)

        await srv.handle_query(_make_query("tocache.com"))

        # Now check cache has it
        cached = await srv._cache.get("tocache.com:A")
        assert cached is not None


class TestHandleQueryParsing:
    async def test_invalid_data_returns_empty(self, server):
        srv, _ = server
        result = await srv.handle_query(b"\x00\x00invalid")
        # Should not crash, returns empty or valid response
        # The parser may or may not fail — we just verify no exception


class TestHandleQueryWhitelist:
    async def test_whitelisted_domain_resolves(self, server):
        srv, stats = server
        upstream_response = _make_upstream_response("whitelisted.com")
        srv._resolver.resolve = AsyncMock(return_value=upstream_response)

        response_bytes = await srv.handle_query(_make_query("whitelisted.com"))
        response = DNSRecord.parse(response_bytes)
        assert len(response.rr) > 0
        assert stats[0][1] == "allow"
