"""Tests for DNS cache."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

from bigr.guardian.dns.cache import CacheEntry, CacheStats, DNSCache


@pytest.fixture
def cache():
    return DNSCache(max_size=5, default_ttl=60)


class TestCacheStats:
    def test_hit_rate_no_queries(self):
        s = CacheStats()
        assert s.hit_rate == 0.0

    def test_hit_rate_calculation(self):
        s = CacheStats(hits=3, misses=7)
        assert s.hit_rate == pytest.approx(0.3)


class TestDNSCacheGet:
    async def test_miss_returns_none(self, cache: DNSCache):
        result = await cache.get("nonexistent.com:A")
        assert result is None

    async def test_hit_returns_entry(self, cache: DNSCache):
        await cache.set("example.com:A", b"\x00\x01")
        entry = await cache.get("example.com:A")
        assert entry is not None
        assert entry.record == b"\x00\x01"

    async def test_expired_returns_none(self, cache: DNSCache):
        await cache.set("expired.com:A", b"\x00\x02", ttl=0)
        # Wait a tiny bit to ensure expiry
        await asyncio.sleep(0.01)
        entry = await cache.get("expired.com:A")
        assert entry is None


class TestDNSCacheSet:
    async def test_set_and_retrieve(self, cache: DNSCache):
        await cache.set("test.com:A", b"\x01\x02\x03")
        entry = await cache.get("test.com:A")
        assert entry is not None
        assert entry.record == b"\x01\x02\x03"

    async def test_overwrite_existing(self, cache: DNSCache):
        await cache.set("test.com:A", b"\x01")
        await cache.set("test.com:A", b"\x02")
        entry = await cache.get("test.com:A")
        assert entry.record == b"\x02"

    async def test_custom_ttl(self, cache: DNSCache):
        await cache.set("ttl.com:A", b"\x01", ttl=3600)
        entry = await cache.get("ttl.com:A")
        assert entry is not None

    async def test_qtype_stored(self, cache: DNSCache):
        await cache.set("mx.com:MX", b"\x01", qtype="MX")
        entry = await cache.get("mx.com:MX")
        assert entry.qtype == "MX"


class TestDNSCacheEviction:
    async def test_lru_eviction(self):
        cache = DNSCache(max_size=3, default_ttl=60)
        await cache.set("a.com:A", b"\x01")
        await cache.set("b.com:A", b"\x02")
        await cache.set("c.com:A", b"\x03")
        # This should evict a.com
        await cache.set("d.com:A", b"\x04")

        assert await cache.get("a.com:A") is None
        assert await cache.get("b.com:A") is not None
        assert await cache.get("d.com:A") is not None

    async def test_access_prevents_eviction(self):
        cache = DNSCache(max_size=3, default_ttl=60)
        await cache.set("a.com:A", b"\x01")
        await cache.set("b.com:A", b"\x02")
        await cache.set("c.com:A", b"\x03")
        # Access a.com to move it to end (most recently used)
        await cache.get("a.com:A")
        # This should evict b.com (least recently used) not a.com
        await cache.set("d.com:A", b"\x04")

        assert await cache.get("a.com:A") is not None
        assert await cache.get("b.com:A") is None


class TestDNSCacheStats:
    async def test_stats_tracking(self, cache: DNSCache):
        await cache.set("hit.com:A", b"\x01")
        await cache.get("hit.com:A")  # hit
        await cache.get("miss.com:A")  # miss

        stats = await cache.stats()
        assert stats.hits == 1
        assert stats.misses == 1
        assert stats.size == 1

    async def test_eviction_counted(self):
        cache = DNSCache(max_size=2, default_ttl=60)
        await cache.set("a.com:A", b"\x01")
        await cache.set("b.com:A", b"\x02")
        await cache.set("c.com:A", b"\x03")  # evicts a

        stats = await cache.stats()
        assert stats.evictions == 1


class TestDNSCacheClear:
    async def test_clear_removes_all(self, cache: DNSCache):
        await cache.set("a.com:A", b"\x01")
        await cache.set("b.com:A", b"\x02")
        await cache.clear()
        assert cache.size == 0
        assert await cache.get("a.com:A") is None
