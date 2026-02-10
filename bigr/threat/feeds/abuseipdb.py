"""AbuseIPDB API client with rate limiting and caching.

AbuseIPDB is the most widely used IP reputation database. This client
supports both the CHECK endpoint (single IP lookup) and the BLACKLIST
endpoint (bulk blocklist sync).

Free tier: 1,000 checks/day.  Basic paid: 10,000 checks/day.
"""

from __future__ import annotations

import logging
import time
from datetime import date

import httpx

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient:
    """AbuseIPDB API client with rate limiting and caching."""

    BASE_URL = ABUSEIPDB_BASE_URL

    def __init__(self, api_key: str, daily_limit: int = 1000, cache_ttl: int = 3600):
        """Initialize the AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key.
            daily_limit: Maximum API calls per day (free=1000, basic=10000).
            cache_ttl: Cache time-to-live in seconds (default 1 hour).
        """
        self.api_key = api_key
        self.daily_limit = daily_limit
        self._calls_today = 0
        self._calls_date: date | None = None
        self._cache: dict[str, tuple[dict, float]] = {}  # ip -> (result, timestamp)
        self._cache_ttl = cache_ttl

    def _reset_daily_counter_if_needed(self) -> None:
        """Reset the daily call counter if the date has changed."""
        today = date.today()
        if self._calls_date != today:
            self._calls_today = 0
            self._calls_date = today

    def _is_rate_limited(self) -> bool:
        """Check if we've exceeded the daily API call limit."""
        self._reset_daily_counter_if_needed()
        return self._calls_today >= self.daily_limit

    def _get_cached(self, ip: str) -> dict | None:
        """Return cached result for an IP if still within TTL.

        Args:
            ip: IP address to look up in cache.

        Returns:
            Cached result dict or None if not found / expired.
        """
        if ip in self._cache:
            result, cached_at = self._cache[ip]
            if time.time() - cached_at < self._cache_ttl:
                return result
            # Expired — remove from cache
            del self._cache[ip]
        return None

    def _set_cached(self, ip: str, result: dict) -> None:
        """Store a result in the cache.

        Args:
            ip: IP address key.
            result: API result to cache.
        """
        self._cache[ip] = (result, time.time())

    @property
    def remaining_calls(self) -> int:
        """How many API calls remain today."""
        self._reset_daily_counter_if_needed()
        return max(0, self.daily_limit - self._calls_today)

    @property
    def cache_size(self) -> int:
        """Number of entries currently in the cache."""
        return len(self._cache)

    def _normalize_score(self, abuse_confidence: int) -> float:
        """Convert AbuseIPDB 0-100 score to BIGR 0.0-1.0 threat score.

        Args:
            abuse_confidence: AbuseIPDB confidence score (0-100).

        Returns:
            Normalized float between 0.0 and 1.0.
        """
        clamped = max(0, min(100, abuse_confidence))
        return round(clamped / 100.0, 2)

    async def check_ip(
        self,
        ip: str,
        max_age_days: int = 90,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> dict | None:
        """Check single IP reputation via AbuseIPDB CHECK endpoint.

        Args:
            ip: IP address to check.
            max_age_days: Maximum age of reports to consider (1-365).
            client: Optional shared httpx client.

        Returns:
            Dict with abuseConfidenceScore, totalReports, numDistinctUsers,
            lastReportedAt, countryCode, isp, usageType, and bigr_threat_score.
            Returns None if rate limited or API key not set.
        """
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None

        # Check cache first
        cached = self._get_cached(ip)
        if cached is not None:
            logger.debug("AbuseIPDB cache hit for %s", ip)
            return cached

        # Check rate limit
        if self._is_rate_limited():
            logger.warning(
                "AbuseIPDB daily rate limit reached (%d/%d)",
                self._calls_today,
                self.daily_limit,
            )
            return None

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days),
        }

        try:
            if client is None:
                async with httpx.AsyncClient(timeout=30.0) as c:
                    response = await c.get(
                        f"{self.BASE_URL}/check",
                        headers=headers,
                        params=params,
                    )
            else:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params=params,
                )

            response.raise_for_status()
            self._calls_today += 1

            data = response.json().get("data", {})
            result = {
                "ip": data.get("ipAddress", ip),
                "is_public": data.get("isPublic", True),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "bigr_threat_score": self._normalize_score(
                    data.get("abuseConfidenceScore", 0)
                ),
            }

            # Cache the result
            self._set_cached(ip, result)
            return result

        except httpx.HTTPStatusError as exc:
            logger.error(
                "AbuseIPDB CHECK failed for %s: HTTP %d - %s",
                ip,
                exc.response.status_code,
                exc.response.text[:200],
            )
            return None
        except httpx.HTTPError as exc:
            logger.error("AbuseIPDB CHECK network error for %s: %s", ip, exc)
            return None

    async def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: int = 10000,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[dict]:
        """Get bulk blacklist for feed sync via AbuseIPDB BLACKLIST endpoint.

        Args:
            confidence_minimum: Minimum confidence score (0-100).
            limit: Maximum number of entries to return.
            client: Optional shared httpx client.

        Returns:
            List of dicts with keys: ip, confidence, country.
            Returns empty list on error.
        """
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return []

        # Check rate limit (blacklist counts as 1 call)
        if self._is_rate_limited():
            logger.warning(
                "AbuseIPDB daily rate limit reached (%d/%d)",
                self._calls_today,
                self.daily_limit,
            )
            return []

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "confidenceMinimum": str(confidence_minimum),
            "limit": str(limit),
        }

        try:
            if client is None:
                async with httpx.AsyncClient(timeout=60.0) as c:
                    response = await c.get(
                        f"{self.BASE_URL}/blacklist",
                        headers=headers,
                        params=params,
                    )
            else:
                response = await client.get(
                    f"{self.BASE_URL}/blacklist",
                    headers=headers,
                    params=params,
                )

            response.raise_for_status()
            self._calls_today += 1

            raw_data = response.json().get("data", [])
            results = []
            for entry in raw_data:
                results.append(
                    {
                        "ip": entry.get("ipAddress", ""),
                        "confidence": entry.get("abuseConfidenceScore", 0),
                        "country": entry.get("countryCode"),
                    }
                )

            logger.info(
                "AbuseIPDB blacklist: fetched %d entries (min confidence=%d)",
                len(results),
                confidence_minimum,
            )
            return results

        except httpx.HTTPStatusError as exc:
            logger.error(
                "AbuseIPDB BLACKLIST failed: HTTP %d - %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return []
        except httpx.HTTPError as exc:
            logger.error("AbuseIPDB BLACKLIST network error: %s", exc)
            return []
