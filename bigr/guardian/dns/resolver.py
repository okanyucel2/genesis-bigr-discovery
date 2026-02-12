"""Upstream DNS resolver using DNS-over-HTTPS (DoH) with plain DNS fallback."""

from __future__ import annotations

import asyncio
import logging

import httpx
from dnslib import DNSRecord, QTYPE

logger = logging.getLogger(__name__)


class UpstreamResolver:
    """Resolve DNS queries via upstream DoH or plain DNS fallback.

    Parameters
    ----------
    doh_url:
        DNS-over-HTTPS endpoint (e.g. https://1.1.1.1/dns-query).
    fallback_ip:
        Plain DNS server IP for fallback (e.g. 9.9.9.9).
    timeout:
        Timeout in seconds for upstream queries.
    """

    def __init__(
        self,
        doh_url: str = "https://1.1.1.1/dns-query",
        fallback_ip: str = "9.9.9.9",
        timeout: float = 5.0,
    ) -> None:
        self._doh_url = doh_url
        self._fallback_ip = fallback_ip
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def resolve(self, domain: str, qtype: str = "A") -> DNSRecord | None:
        """Resolve a domain via DoH, falling back to plain DNS on failure.

        Parameters
        ----------
        domain:
            Domain name to resolve (e.g. "example.com").
        qtype:
            Query type string (e.g. "A", "AAAA", "CNAME", "MX").

        Returns
        -------
        DNSRecord or None if resolution fails entirely.
        """
        # Try DoH first
        try:
            return await self._resolve_doh(domain, qtype)
        except Exception as exc:
            logger.warning("DoH resolution failed for %s: %s", domain, exc)

        # Fallback to plain DNS
        try:
            return await self._resolve_plain(domain, qtype)
        except Exception as exc:
            logger.error("Plain DNS fallback also failed for %s: %s", domain, exc)
            return None

    async def _resolve_doh(self, domain: str, qtype: str) -> DNSRecord:
        """Resolve via DNS-over-HTTPS (RFC 8484 wire format)."""
        # Build DNS wire-format query
        q = DNSRecord.question(domain, qtype)
        wire_query = q.pack()

        client = await self._get_client()
        resp = await client.post(
            self._doh_url,
            content=wire_query,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        )
        resp.raise_for_status()
        return DNSRecord.parse(resp.content)

    async def _resolve_plain(self, domain: str, qtype: str) -> DNSRecord:
        """Resolve via plain DNS over UDP (port 53)."""
        q = DNSRecord.question(domain, qtype)
        wire_query = q.pack()

        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UDPDNSProtocol(loop),
            remote_addr=(self._fallback_ip, 53),
        )
        try:
            protocol: _UDPDNSProtocol
            transport.sendto(wire_query)
            data = await asyncio.wait_for(protocol.response_future, timeout=self._timeout)
            return DNSRecord.parse(data)
        finally:
            transport.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class _UDPDNSProtocol(asyncio.DatagramProtocol):
    """Simple UDP protocol for receiving a single DNS response."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.response_future: asyncio.Future[bytes] = loop.create_future()

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.response_future.done():
            self.response_future.set_exception(exc)
