"""Tests for AbuseIPDB integration.

Covers: AbuseIPDBClient, AbuseIPDBFeedParser, API endpoints,
ThreatIngestor integration, and settings.
"""

from __future__ import annotations

import json
import time
from datetime import date
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from httpx import Response

from bigr.threat.feeds.abuseipdb import AbuseIPDBClient
from bigr.threat.feeds.abuseipdb_feed import AbuseIPDBFeedParser
from bigr.threat.ingestor import FEED_WEIGHTS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> AbuseIPDBClient:
    """Create a fresh AbuseIPDB client with a test API key."""
    return AbuseIPDBClient(api_key="test-key-123", daily_limit=1000)


@pytest.fixture
def client_no_key() -> AbuseIPDBClient:
    """Create a client without an API key."""
    return AbuseIPDBClient(api_key="", daily_limit=1000)


@pytest.fixture
def feed_parser() -> AbuseIPDBFeedParser:
    """Create a feed parser with a test API key."""
    return AbuseIPDBFeedParser(api_key="test-key-123", daily_limit=1000)


def _make_check_response(
    ip: str = "1.2.3.4",
    confidence: int = 87,
    total_reports: int = 42,
    country: str = "CN",
) -> dict:
    """Build a mock AbuseIPDB CHECK API response body."""
    return {
        "data": {
            "ipAddress": ip,
            "isPublic": True,
            "abuseConfidenceScore": confidence,
            "totalReports": total_reports,
            "numDistinctUsers": 15,
            "lastReportedAt": "2026-02-01T12:00:00+00:00",
            "countryCode": country,
            "isp": "Example ISP",
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }


def _make_blacklist_response(count: int = 3) -> dict:
    """Build a mock AbuseIPDB BLACKLIST API response body."""
    entries = []
    for i in range(count):
        entries.append(
            {
                "ipAddress": f"10.0.0.{i + 1}",
                "abuseConfidenceScore": 100 - i,
                "countryCode": "US",
            }
        )
    return {"data": entries}


def _mock_httpx_response(json_data: dict, status_code: int = 200) -> Response:
    """Create a mock httpx.Response."""
    return Response(
        status_code=status_code,
        json=json_data,
        request=httpx.Request("GET", "https://api.abuseipdb.com/api/v2/test"),
    )


# ---------------------------------------------------------------------------
# AbuseIPDBClient — Score Normalization
# ---------------------------------------------------------------------------


class TestScoreNormalization:
    """Test _normalize_score converts 0-100 to 0.0-1.0 correctly."""

    def test_zero_score(self, client: AbuseIPDBClient):
        assert client._normalize_score(0) == 0.0

    def test_fifty_score(self, client: AbuseIPDBClient):
        assert client._normalize_score(50) == 0.5

    def test_hundred_score(self, client: AbuseIPDBClient):
        assert client._normalize_score(100) == 1.0

    def test_low_score(self, client: AbuseIPDBClient):
        assert client._normalize_score(25) == 0.25

    def test_high_score(self, client: AbuseIPDBClient):
        assert client._normalize_score(87) == 0.87

    def test_clamp_above_100(self, client: AbuseIPDBClient):
        """Scores above 100 should clamp to 1.0."""
        assert client._normalize_score(150) == 1.0

    def test_clamp_below_0(self, client: AbuseIPDBClient):
        """Negative scores should clamp to 0.0."""
        assert client._normalize_score(-10) == 0.0


# ---------------------------------------------------------------------------
# AbuseIPDBClient — Rate Limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Test daily rate limit enforcement."""

    def test_initial_remaining(self, client: AbuseIPDBClient):
        """Fresh client should have full remaining calls."""
        assert client.remaining_calls == 1000

    def test_rate_limit_enforced(self, client: AbuseIPDBClient):
        """Client should report rate limited after hitting daily limit."""
        client._calls_today = 1000
        client._calls_date = date.today()
        assert client._is_rate_limited() is True
        assert client.remaining_calls == 0

    def test_rate_limit_not_hit(self, client: AbuseIPDBClient):
        """Client below limit should not be rate limited."""
        client._calls_today = 500
        client._calls_date = date.today()
        assert client._is_rate_limited() is False
        assert client.remaining_calls == 500

    def test_daily_reset(self, client: AbuseIPDBClient):
        """Counter should reset when the date changes."""
        client._calls_today = 999
        client._calls_date = date(2025, 1, 1)  # Yesterday or earlier
        # This should trigger a reset since _calls_date != today
        assert client._is_rate_limited() is False
        assert client._calls_today == 0

    @pytest.mark.asyncio
    async def test_check_ip_returns_none_when_rate_limited(
        self, client: AbuseIPDBClient
    ):
        """check_ip should return None when rate limited."""
        client._calls_today = 1000
        client._calls_date = date.today()
        result = await client.check_ip("1.2.3.4")
        assert result is None

    @pytest.mark.asyncio
    async def test_blacklist_returns_empty_when_rate_limited(
        self, client: AbuseIPDBClient
    ):
        """get_blacklist should return empty list when rate limited."""
        client._calls_today = 1000
        client._calls_date = date.today()
        result = await client.get_blacklist()
        assert result == []


# ---------------------------------------------------------------------------
# AbuseIPDBClient — Caching
# ---------------------------------------------------------------------------


class TestCaching:
    """Test in-memory cache behavior."""

    def test_cache_hit(self, client: AbuseIPDBClient):
        """Cached result should be returned within TTL."""
        test_data = {"ip": "1.2.3.4", "score": 87}
        client._set_cached("1.2.3.4", test_data)
        assert client._get_cached("1.2.3.4") == test_data

    def test_cache_miss_different_ip(self, client: AbuseIPDBClient):
        """Different IP should not return cached result."""
        test_data = {"ip": "1.2.3.4", "score": 87}
        client._set_cached("1.2.3.4", test_data)
        assert client._get_cached("5.6.7.8") is None

    def test_cache_miss_expired(self, client: AbuseIPDBClient):
        """Expired cache entries should return None."""
        test_data = {"ip": "1.2.3.4", "score": 87}
        # Set with a timestamp in the past (beyond TTL)
        client._cache["1.2.3.4"] = (test_data, time.time() - 7200)
        assert client._get_cached("1.2.3.4") is None
        # Expired entry should be removed
        assert "1.2.3.4" not in client._cache

    def test_cache_size(self, client: AbuseIPDBClient):
        """cache_size should reflect number of cached entries."""
        assert client.cache_size == 0
        client._set_cached("1.2.3.4", {"score": 1})
        client._set_cached("5.6.7.8", {"score": 2})
        assert client.cache_size == 2

    @pytest.mark.asyncio
    async def test_check_ip_uses_cache(self, client: AbuseIPDBClient):
        """Second call for same IP should use cache, not HTTP."""
        cached_data = {
            "ip": "1.2.3.4",
            "is_public": True,
            "abuse_confidence_score": 87,
            "total_reports": 42,
            "num_distinct_users": 15,
            "last_reported_at": "2026-02-01T12:00:00+00:00",
            "country_code": "CN",
            "isp": "Example ISP",
            "usage_type": "Data Center/Web Hosting/Transit",
            "bigr_threat_score": 0.87,
        }
        client._set_cached("1.2.3.4", cached_data)

        # This should return cached result without making HTTP call
        result = await client.check_ip("1.2.3.4")
        assert result is not None
        assert result["abuse_confidence_score"] == 87
        # Calls count should not increase (no HTTP call made)
        assert client._calls_today == 0


# ---------------------------------------------------------------------------
# AbuseIPDBClient — No API Key
# ---------------------------------------------------------------------------


class TestNoApiKey:
    """Test graceful degradation when no API key is configured."""

    @pytest.mark.asyncio
    async def test_check_ip_no_key(self, client_no_key: AbuseIPDBClient):
        """check_ip should return None without API key."""
        result = await client_no_key.check_ip("1.2.3.4")
        assert result is None

    @pytest.mark.asyncio
    async def test_blacklist_no_key(self, client_no_key: AbuseIPDBClient):
        """get_blacklist should return empty list without API key."""
        result = await client_no_key.get_blacklist()
        assert result == []


# ---------------------------------------------------------------------------
# AbuseIPDBClient — check_ip HTTP (mocked)
# ---------------------------------------------------------------------------


class TestCheckIPHTTP:
    """Test check_ip with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_check_ip_success(self, client: AbuseIPDBClient):
        """Successful CHECK should return normalized data."""
        mock_response = _mock_httpx_response(_make_check_response())

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await client.check_ip("1.2.3.4", client=mock_client)

        assert result is not None
        assert result["ip"] == "1.2.3.4"
        assert result["abuse_confidence_score"] == 87
        assert result["total_reports"] == 42
        assert result["country_code"] == "CN"
        assert result["bigr_threat_score"] == 0.87
        assert client._calls_today == 1

    @pytest.mark.asyncio
    async def test_check_ip_http_error(self, client: AbuseIPDBClient):
        """HTTP errors should return None gracefully."""
        error_response = _mock_httpx_response({"errors": [{"detail": "Forbidden"}]}, 403)

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "Forbidden",
                request=httpx.Request("GET", "https://test"),
                response=error_response,
            )
        )

        result = await client.check_ip("1.2.3.4", client=mock_client)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_ip_network_error(self, client: AbuseIPDBClient):
        """Network errors should return None gracefully."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        result = await client.check_ip("1.2.3.4", client=mock_client)
        assert result is None


# ---------------------------------------------------------------------------
# AbuseIPDBClient — get_blacklist HTTP (mocked)
# ---------------------------------------------------------------------------


class TestBlacklistHTTP:
    """Test get_blacklist with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_blacklist_success(self, client: AbuseIPDBClient):
        """Successful BLACKLIST should return normalized entries."""
        mock_response = _mock_httpx_response(_make_blacklist_response(3))

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await client.get_blacklist(client=mock_client)

        assert len(result) == 3
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["confidence"] == 100
        assert result[0]["country"] == "US"
        assert client._calls_today == 1

    @pytest.mark.asyncio
    async def test_blacklist_empty(self, client: AbuseIPDBClient):
        """Empty blacklist should return empty list."""
        mock_response = _mock_httpx_response({"data": []})

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await client.get_blacklist(client=mock_client)
        assert result == []


# ---------------------------------------------------------------------------
# AbuseIPDBFeedParser
# ---------------------------------------------------------------------------


class TestFeedParser:
    """Test AbuseIPDBFeedParser follows existing feed pattern."""

    @pytest.mark.asyncio
    async def test_parse_returns_feed_indicators(self, feed_parser: AbuseIPDBFeedParser):
        """Parser should return FeedIndicator objects."""
        mock_response = _mock_httpx_response(_make_blacklist_response(3))

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await feed_parser.fetch(client=mock_client)

        assert len(result) == 3
        assert result[0].ip == "10.0.0.1"
        assert result[0].indicator_type == "malicious"
        assert result[0].source_feed == "abuseipdb"

    @pytest.mark.asyncio
    async def test_parse_empty_blacklist(self, feed_parser: AbuseIPDBFeedParser):
        """Empty blacklist should return empty list."""
        mock_response = _mock_httpx_response({"data": []})

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await feed_parser.fetch(client=mock_client)
        assert result == []

    def test_feed_configs(self):
        """Feed configs should be properly structured."""
        configs = AbuseIPDBFeedParser.get_feed_configs()
        assert len(configs) == 1
        assert configs[0]["name"] == "abuseipdb"
        assert configs[0]["feed_type"] == "json_api"
        assert "abuseipdb.com" in configs[0]["feed_url"]


# ---------------------------------------------------------------------------
# ThreatIngestor Integration
# ---------------------------------------------------------------------------


class TestIngestorIntegration:
    """Test ThreatIngestor includes AbuseIPDB correctly."""

    def test_feed_weights_includes_abuseipdb(self):
        """FEED_WEIGHTS should include abuseipdb with appropriate weight."""
        assert "abuseipdb" in FEED_WEIGHTS
        assert FEED_WEIGHTS["abuseipdb"] == 0.85

    def test_feed_weights_abuseipdb_is_high(self):
        """AbuseIPDB weight should be among the highest (commercial source)."""
        abuseipdb_weight = FEED_WEIGHTS["abuseipdb"]
        # Only firehol_level1 (0.9) should be higher
        higher_feeds = [k for k, v in FEED_WEIGHTS.items() if v > abuseipdb_weight]
        assert len(higher_feeds) <= 1  # At most firehol_level1


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestSettings:
    """Test AbuseIPDB settings integration."""

    def test_default_api_key_empty(self):
        """Default ABUSEIPDB_API_KEY should be empty string."""
        from bigr.core.settings import Settings

        s = Settings(DATABASE_URL="sqlite:///test.db")
        assert s.ABUSEIPDB_API_KEY == ""

    def test_default_daily_limit(self):
        """Default ABUSEIPDB_DAILY_LIMIT should be 1000 (free tier)."""
        from bigr.core.settings import Settings

        s = Settings(DATABASE_URL="sqlite:///test.db")
        assert s.ABUSEIPDB_DAILY_LIMIT == 1000


# ---------------------------------------------------------------------------
# API Endpoints (mocked)
# ---------------------------------------------------------------------------


class TestAPIEndpoints:
    """Test AbuseIPDB FastAPI endpoints."""

    @pytest.mark.asyncio
    async def test_status_endpoint_no_key(self):
        """Status endpoint should work even without API key."""
        from bigr.threat.abuseipdb_api import abuseipdb_status

        import bigr.threat.abuseipdb_api as api_module

        # Directly create a client with no key for this test
        api_module._client = AbuseIPDBClient(api_key="", daily_limit=1000)

        result = await abuseipdb_status()

        assert result["enabled"] is False
        assert result["api_key_set"] is False
        assert result["remaining_calls"] == 1000
        assert result["daily_limit"] == 1000
        assert result["cache_size"] == 0

        # Clean up
        api_module._client = None

    @pytest.mark.asyncio
    async def test_status_endpoint_with_key(self):
        """Status endpoint should show enabled when API key is set."""
        from bigr.threat.abuseipdb_api import abuseipdb_status

        import bigr.threat.abuseipdb_api as api_module

        api_module._client = AbuseIPDBClient(api_key="test-key", daily_limit=5000)

        result = await abuseipdb_status()

        assert result["enabled"] is True
        assert result["api_key_set"] is True
        assert result["daily_limit"] == 5000

        # Clean up
        api_module._client = None

    @pytest.mark.asyncio
    async def test_check_endpoint_invalid_ip(self):
        """Check endpoint should reject invalid IP addresses."""
        from bigr.threat.abuseipdb_api import check_ip

        import bigr.threat.abuseipdb_api as api_module

        api_module._client = AbuseIPDBClient(api_key="test-key", daily_limit=1000)

        with pytest.raises(Exception) as exc_info:
            await check_ip("not-an-ip")

        # FastAPI HTTPException
        assert exc_info.value.status_code == 400

        # Clean up
        api_module._client = None

    @pytest.mark.asyncio
    async def test_check_endpoint_no_api_key(self):
        """Check endpoint should return 503 without API key."""
        from bigr.threat.abuseipdb_api import check_ip

        import bigr.threat.abuseipdb_api as api_module

        api_module._client = AbuseIPDBClient(api_key="", daily_limit=1000)

        with pytest.raises(Exception) as exc_info:
            await check_ip("1.2.3.4")

        assert exc_info.value.status_code == 503

        # Clean up
        api_module._client = None

    @pytest.mark.asyncio
    async def test_enrichment_endpoint_combines_sources(self):
        """Enrichment should combine AbuseIPDB + local threat data."""
        from bigr.threat.abuseipdb_api import enrich_asset

        import bigr.threat.abuseipdb_api as api_module

        # Set up a client that returns mock data
        mock_client = AbuseIPDBClient(api_key="test-key", daily_limit=1000)
        mock_result = {
            "ip": "1.2.3.4",
            "is_public": True,
            "abuse_confidence_score": 80,
            "total_reports": 30,
            "num_distinct_users": 10,
            "last_reported_at": None,
            "country_code": "CN",
            "isp": "Test ISP",
            "usage_type": "Hosting",
            "bigr_threat_score": 0.80,
        }
        mock_client._set_cached("1.2.3.4", mock_result)
        api_module._client = mock_client

        # Mock the ingestor's lookup_subnet
        with patch(
            "bigr.threat.abuseipdb_api._get_ingestor"
        ) as mock_get_ingestor:
            mock_ingestor = AsyncMock()
            mock_ingestor.lookup_subnet = AsyncMock(return_value=None)
            mock_get_ingestor.return_value = mock_ingestor

            # Create a mock db session
            mock_db = AsyncMock()

            result = await enrich_asset("1.2.3.4", db=mock_db)

        assert result["ip"] == "1.2.3.4"
        assert result["abuseipdb"] is not None
        assert result["abuseipdb"]["abuse_confidence_score"] == 80
        assert result["combined_threat_score"] == 0.80
        assert "abuseipdb" in result["sources"]
        assert result["status"] == "flagged"

        # Clean up
        api_module._client = None


# ---------------------------------------------------------------------------
# Custom cache_ttl
# ---------------------------------------------------------------------------


class TestCustomCacheTTL:
    """Test configurable cache TTL."""

    def test_short_ttl(self):
        """Short TTL should expire faster."""
        c = AbuseIPDBClient(api_key="test", daily_limit=100, cache_ttl=1)
        assert c._cache_ttl == 1

    def test_long_ttl(self):
        """Long TTL should persist longer."""
        c = AbuseIPDBClient(api_key="test", daily_limit=100, cache_ttl=86400)
        assert c._cache_ttl == 86400


# ---------------------------------------------------------------------------
# AbuseIPDBClient — calls counter increments
# ---------------------------------------------------------------------------


class TestCallsCounter:
    """Test that API calls properly increment the counter."""

    @pytest.mark.asyncio
    async def test_check_increments_counter(self, client: AbuseIPDBClient):
        """Successful check_ip should increment _calls_today."""
        mock_response = _mock_httpx_response(_make_check_response())
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.get = AsyncMock(return_value=mock_response)

        assert client._calls_today == 0
        await client.check_ip("1.2.3.4", client=mock_http)
        assert client._calls_today == 1
        await client.check_ip("5.6.7.8", client=mock_http)
        assert client._calls_today == 2

    @pytest.mark.asyncio
    async def test_blacklist_increments_counter(self, client: AbuseIPDBClient):
        """Successful get_blacklist should increment _calls_today."""
        mock_response = _mock_httpx_response(_make_blacklist_response(1))
        mock_http = AsyncMock(spec=httpx.AsyncClient)
        mock_http.get = AsyncMock(return_value=mock_response)

        assert client._calls_today == 0
        await client.get_blacklist(client=mock_http)
        assert client._calls_today == 1
