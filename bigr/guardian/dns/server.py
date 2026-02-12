"""Guardian DNS server — UDP+TCP DNS server with filtering."""

from __future__ import annotations

import asyncio
import logging

from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

from bigr.guardian.dns.cache import DNSCache
from bigr.guardian.dns.decision import DecisionAction, QueryDecisionEngine
from bigr.guardian.dns.resolver import UpstreamResolver

logger = logging.getLogger(__name__)


def build_sinkhole_response(request: DNSRecord, sinkhole_ip: str, ttl: int = 300) -> DNSRecord:
    """Build a sinkhole DNS response (A record pointing to sinkhole IP)."""
    reply = request.reply()
    qname = request.q.qname
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(sinkhole_ip), ttl=ttl))
    return reply


def build_nxdomain_response(request: DNSRecord) -> DNSRecord:
    """Build an NXDOMAIN response."""
    reply = request.reply()
    reply.header.rcode = 3  # NXDOMAIN
    return reply


def build_servfail_response(request: DNSRecord) -> DNSRecord:
    """Build a SERVFAIL response."""
    reply = request.reply()
    reply.header.rcode = 2  # SERVFAIL
    return reply


class GuardianDNSServer:
    """DNS server with filtering, caching, and upstream resolution.

    Parameters
    ----------
    decision_engine:
        Query decision engine for block/allow decisions.
    resolver:
        Upstream DNS resolver.
    cache:
        DNS cache for responses.
    host:
        Bind address for the DNS server.
    port:
        Port for the DNS server.
    stats_callback:
        Optional callback for recording query statistics.
    """

    def __init__(
        self,
        decision_engine: QueryDecisionEngine,
        resolver: UpstreamResolver,
        cache: DNSCache,
        host: str = "0.0.0.0",
        port: int = 53,
        stats_callback=None,
    ) -> None:
        self._engine = decision_engine
        self._resolver = resolver
        self._cache = cache
        self._host = host
        self._port = port
        self._stats_callback = stats_callback
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        """Start both UDP and TCP DNS listeners."""
        loop = asyncio.get_running_loop()

        # UDP server
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSDatagramProtocol(self),
            local_addr=(self._host, self._port),
        )

        # TCP server
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            host=self._host,
            port=self._port,
        )

        self._running = True
        logger.info(
            "Guardian DNS server listening on %s:%d (UDP+TCP)",
            self._host,
            self._port,
        )

    async def stop(self) -> None:
        """Stop the DNS server."""
        self._running = False
        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
        await self._resolver.close()
        logger.info("Guardian DNS server stopped")

    async def handle_query(self, data: bytes) -> bytes:
        """Process a raw DNS query and return a response.

        Flow: Parse → Cache check → Decision → Sinkhole/Resolve → Cache set → Stats
        """
        try:
            request = DNSRecord.parse(data)
        except Exception:
            logger.debug("Failed to parse DNS query")
            return b""

        domain = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # 1. Cache check
        cache_key = f"{domain}:{qtype}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            # Rebuild response with correct transaction ID
            try:
                cached_record = DNSRecord.parse(cached.record)
                cached_record.header.id = request.header.id
                self._record_stats(domain, "allow", "cache_hit", is_cache_hit=True)
                return cached_record.pack()
            except Exception:
                pass  # If cache entry is corrupt, fall through

        # 2. Decision engine
        decision = self._engine.decide(domain)

        # 3. Build response
        if decision.action == DecisionAction.BLOCK:
            reply = build_sinkhole_response(request, decision.sinkhole_ip)
            self._record_stats(domain, "block", decision.reason.value)
            return reply.pack()

        # 4. Resolve upstream
        try:
            upstream_response = await self._resolver.resolve(domain, qtype)
            if upstream_response is None:
                reply = build_servfail_response(request)
                self._record_stats(domain, "error", "upstream_failed")
                return reply.pack()

            # Fix transaction ID
            upstream_response.header.id = request.header.id
            response_bytes = upstream_response.pack()

            # 5. Cache the response
            ttl = min(
                (rr.ttl for rr in upstream_response.rr),
                default=300,
            )
            await self._cache.set(cache_key, response_bytes, ttl=ttl, qtype=qtype)

            self._record_stats(domain, "allow", decision.reason.value)
            return response_bytes

        except Exception as exc:
            logger.error("Upstream resolution failed for %s: %s", domain, exc)
            reply = build_servfail_response(request)
            self._record_stats(domain, "error", "exception")
            return reply.pack()

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a TCP DNS client connection."""
        try:
            # TCP DNS: 2-byte length prefix
            length_data = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
            length = int.from_bytes(length_data, "big")
            data = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)

            response = await self.handle_query(data)
            if response:
                writer.write(len(response).to_bytes(2, "big") + response)
                await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            logger.debug("TCP handler error: %s", exc)
        finally:
            writer.close()

    def _record_stats(
        self, domain: str, action: str, reason: str, is_cache_hit: bool = False
    ) -> None:
        """Fire-and-forget stats recording."""
        if self._stats_callback:
            try:
                self._stats_callback(domain, action, reason, is_cache_hit)
            except Exception:
                pass


class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for DNS queries."""

    def __init__(self, server: GuardianDNSServer) -> None:
        self._server = server
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple) -> None:
        try:
            response = await self._server.handle_query(data)
            if response and self._transport:
                self._transport.sendto(response, addr)
        except Exception as exc:
            logger.debug("UDP handler error: %s", exc)
