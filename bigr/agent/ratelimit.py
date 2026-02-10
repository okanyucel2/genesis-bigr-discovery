"""Simple in-memory per-token rate limiter for agent ingest endpoints.

Uses a sliding window counter per bearer token. No external dependencies.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status


@dataclass
class _TokenBucket:
    """Token bucket for a single agent."""

    tokens: float
    last_refill: float
    max_tokens: float
    refill_rate: float  # tokens per second

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class IngestRateLimiter:
    """Per-agent rate limiter using token bucket algorithm.

    Parameters
    ----------
    max_requests:
        Maximum burst size (bucket capacity).
    window_seconds:
        Time window over which max_requests are spread (refill period).
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60) -> None:
        self._max = float(max_requests)
        self._rate = max_requests / window_seconds
        self._buckets: dict[str, _TokenBucket] = {}

    def check(self, agent_token_hash: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        if agent_token_hash not in self._buckets:
            self._buckets[agent_token_hash] = _TokenBucket(
                tokens=self._max,
                last_refill=time.monotonic(),
                max_tokens=self._max,
                refill_rate=self._rate,
            )
        return self._buckets[agent_token_hash].consume()

    def cleanup(self, max_idle_seconds: float = 600) -> int:
        """Remove stale buckets. Returns count removed."""
        now = time.monotonic()
        stale = [
            k for k, v in self._buckets.items()
            if (now - v.last_refill) > max_idle_seconds
        ]
        for k in stale:
            del self._buckets[k]
        return len(stale)


# Global singleton — 30 requests per 60 seconds per agent
ingest_limiter = IngestRateLimiter(max_requests=30, window_seconds=60)
