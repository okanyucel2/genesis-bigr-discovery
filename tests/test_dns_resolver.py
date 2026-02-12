"""Tests for upstream DNS resolver."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dnslib import DNSRecord, RR, A, QTYPE

from bigr.guardian.dns.resolver import UpstreamResolver


def _make_dns_response(domain: str, ip: str = "93.184.216.34") -> bytes:
    """Build a wire-format DNS response for testing."""
    q = DNSRecord.question(domain, "A")
    q.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=300))
    return q.pack()


@pytest.fixture
def resolver():
    return UpstreamResolver(
        doh_url="https://1.1.1.1/dns-query",
        fallback_ip="9.9.9.9",
        timeout=5.0,
    )


class TestUpstreamResolverDoH:
    async def test_doh_success(self, resolver: UpstreamResolver):
        response_bytes = _make_dns_response("example.com")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = response_bytes
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        resolver._client = mock_client

        result = await resolver.resolve("example.com", "A")
        assert result is not None
        assert len(result.rr) > 0
        # Verify DoH was called with correct content-type
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs.kwargs["headers"]["Content-Type"] == "application/dns-message"

    async def test_doh_failure_triggers_fallback(self, resolver: UpstreamResolver):
        """When DoH fails, the resolver should try plain DNS fallback."""
        response_bytes = _make_dns_response("fallback.com")

        # Mock DoH to fail
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("DoH down"))
        mock_client.is_closed = False
        resolver._client = mock_client

        # Mock plain DNS fallback
        with patch.object(
            resolver, "_resolve_plain", new_callable=AsyncMock
        ) as mock_plain:
            mock_plain.return_value = DNSRecord.parse(response_bytes)
            result = await resolver.resolve("fallback.com", "A")
            assert result is not None
            mock_plain.assert_called_once_with("fallback.com", "A")

    async def test_doh_timeout(self, resolver: UpstreamResolver):
        """When DoH times out, fallback should be tried."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ReadTimeout("timeout"))
        mock_client.is_closed = False
        resolver._client = mock_client

        with patch.object(
            resolver, "_resolve_plain", new_callable=AsyncMock
        ) as mock_plain:
            mock_plain.return_value = DNSRecord.parse(
                _make_dns_response("timeout.com")
            )
            result = await resolver.resolve("timeout.com", "A")
            assert result is not None


class TestUpstreamResolverFallback:
    async def test_both_fail_returns_none(self, resolver: UpstreamResolver):
        """When both DoH and plain DNS fail, resolve returns None."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("DoH down"))
        mock_client.is_closed = False
        resolver._client = mock_client

        with patch.object(
            resolver, "_resolve_plain", new_callable=AsyncMock
        ) as mock_plain:
            mock_plain.side_effect = Exception("Plain DNS also down")
            result = await resolver.resolve("noresolve.com", "A")
            assert result is None


class TestUpstreamResolverQueryTypes:
    async def test_aaaa_query(self, resolver: UpstreamResolver):
        """Resolver should support AAAA queries."""
        q = DNSRecord.question("example.com", "AAAA")
        response_bytes = q.pack()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = response_bytes
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        resolver._client = mock_client

        result = await resolver.resolve("example.com", "AAAA")
        assert result is not None


class TestUpstreamResolverClose:
    async def test_close_client(self, resolver: UpstreamResolver):
        mock_client = AsyncMock()
        mock_client.is_closed = False
        resolver._client = mock_client

        await resolver.close()
        mock_client.aclose.assert_called_once()
        assert resolver._client is None

    async def test_close_without_client(self, resolver: UpstreamResolver):
        # Should not raise
        await resolver.close()


# Import httpx for exception types in tests
import httpx
