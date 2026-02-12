"""LRU DNS cache with TTL expiry."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class CacheEntry:
    """Single cached DNS record."""

    record: bytes  # Wire-format DNS response
    expires_at: float
    qtype: str = "A"


@dataclass
class CacheStats:
    """Cache hit/miss statistics."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


class DNSCache:
    """Async-safe LRU DNS cache with TTL-based expiry.

    Parameters
    ----------
    max_size:
        Maximum number of entries before LRU eviction.
    default_ttl:
        Default TTL in seconds if not specified per entry.
    """

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats = CacheStats()

    async def get(self, key: str) -> CacheEntry | None:
        """Retrieve a cache entry if it exists and is not expired."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._stats.misses += 1
                return None

            if time.monotonic() > entry.expires_at:
                del self._cache[key]
                self._stats.misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._stats.hits += 1
            return entry

    async def set(self, key: str, record: bytes, ttl: int | None = None, qtype: str = "A") -> None:
        """Store a DNS record in the cache with TTL."""
        effective_ttl = ttl if ttl is not None else self._default_ttl
        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = CacheEntry(
                record=record,
                expires_at=time.monotonic() + effective_ttl,
                qtype=qtype,
            )
            # LRU eviction
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
                self._stats.evictions += 1

    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()

    async def stats(self) -> CacheStats:
        """Return cache statistics."""
        async with self._lock:
            self._stats.size = len(self._cache)
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=len(self._cache),
            )

    @property
    def size(self) -> int:
        """Current number of entries (not thread-safe, for quick checks)."""
        return len(self._cache)
