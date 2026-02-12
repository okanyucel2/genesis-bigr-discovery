"""Guardian health checker — periodic self-tests."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from bigr.guardian.config import GuardianConfig
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.cache import DNSCache
from bigr.guardian.dns.resolver import UpstreamResolver

logger = logging.getLogger(__name__)


class GuardianHealthChecker:
    """Run health checks on Guardian components.

    Parameters
    ----------
    resolver:
        Upstream resolver to test.
    blocklist:
        Blocklist manager to check freshness.
    cache:
        DNS cache for stats.
    config:
        Guardian configuration.
    """

    def __init__(
        self,
        resolver: UpstreamResolver,
        blocklist: BlocklistManager,
        cache: DNSCache,
        config: GuardianConfig,
    ) -> None:
        self._resolver = resolver
        self._blocklist = blocklist
        self._cache = cache
        self._config = config

    async def check_all(self) -> dict:
        """Run all health checks and return combined status."""
        dns_ok = await self.check_dns_resolution()
        upstream_ok = await self.check_upstream_reachable()
        blocklist_fresh = self.check_blocklist_freshness()
        cache_stats = await self._cache.stats()

        all_ok = dns_ok and upstream_ok and blocklist_fresh

        return {
            "status": "healthy" if all_ok else "degraded",
            "checks": {
                "dns_resolution": {
                    "ok": dns_ok,
                    "detail": "Can resolve example.com" if dns_ok else "DNS resolution failed",
                },
                "upstream_reachable": {
                    "ok": upstream_ok,
                    "detail": f"DoH endpoint reachable ({self._config.upstream_doh_url})"
                    if upstream_ok
                    else f"DoH endpoint unreachable. Fallback: {self._config.upstream_fallback_ip}",
                },
                "blocklist_fresh": {
                    "ok": blocklist_fresh,
                    "detail": f"{self._blocklist.domain_count} domains loaded"
                    if blocklist_fresh
                    else "Blocklist may be stale (>48h) or empty",
                },
                "cache": {
                    "size": cache_stats.size,
                    "hit_rate": round(cache_stats.hit_rate, 3),
                    "hits": cache_stats.hits,
                    "misses": cache_stats.misses,
                },
            },
            "fallback_dns": self._config.upstream_fallback_ip,
        }

    async def check_dns_resolution(self) -> bool:
        """Check if we can resolve a known domain."""
        try:
            result = await self._resolver.resolve("example.com", "A")
            return result is not None
        except Exception:
            return False

    async def check_upstream_reachable(self) -> bool:
        """Check if the upstream DoH endpoint is reachable."""
        try:
            result = await self._resolver.resolve("cloudflare.com", "A")
            return result is not None
        except Exception:
            return False

    def check_blocklist_freshness(self) -> bool:
        """Check if blocklists have domains loaded (basic freshness check)."""
        return self._blocklist.domain_count > 0
