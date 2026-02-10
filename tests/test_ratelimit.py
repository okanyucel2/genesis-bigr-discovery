"""Tests for agent ingest rate limiting."""

from __future__ import annotations

import pytest

from bigr.agent.ratelimit import IngestRateLimiter


class TestTokenBucket:
    def test_allows_within_limit(self):
        limiter = IngestRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.check("agent-1") is True

    def test_blocks_over_limit(self):
        limiter = IngestRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            assert limiter.check("agent-1") is True
        assert limiter.check("agent-1") is False

    def test_separate_agents_independent(self):
        limiter = IngestRateLimiter(max_requests=2, window_seconds=60)
        assert limiter.check("agent-1") is True
        assert limiter.check("agent-1") is True
        assert limiter.check("agent-1") is False
        # Different agent should still have its own bucket
        assert limiter.check("agent-2") is True
        assert limiter.check("agent-2") is True
        assert limiter.check("agent-2") is False

    def test_cleanup_removes_stale(self):
        limiter = IngestRateLimiter(max_requests=5, window_seconds=60)
        limiter.check("agent-1")
        limiter.check("agent-2")
        assert len(limiter._buckets) == 2
        # Force stale by setting last_refill far in the past
        import time
        for b in limiter._buckets.values():
            b.last_refill = time.monotonic() - 999
        removed = limiter.cleanup(max_idle_seconds=600)
        assert removed == 2
        assert len(limiter._buckets) == 0
