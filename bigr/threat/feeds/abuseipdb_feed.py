"""AbuseIPDB feed parser for bulk blacklist sync.

Wraps AbuseIPDBClient to follow the existing feed parser pattern used
by FireHOL, Abuse.ch, AlienVault OTX, and CINS Army parsers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bigr.threat.feeds.abuseipdb import AbuseIPDBClient
from bigr.threat.feeds.cins import FeedIndicator

logger = logging.getLogger(__name__)


class AbuseIPDBFeedParser:
    """Parses AbuseIPDB blacklist as a threat feed.

    Uses the BLACKLIST endpoint to fetch IPs with high abuse confidence
    and returns them as FeedIndicator objects compatible with ThreatIngestor.
    """

    def __init__(
        self,
        api_key: str,
        daily_limit: int = 1000,
        confidence_minimum: int = 90,
    ):
        """Initialize the feed parser.

        Args:
            api_key: AbuseIPDB API key.
            daily_limit: Daily API call limit.
            confidence_minimum: Minimum confidence for blacklist entries.
        """
        self._client = AbuseIPDBClient(api_key=api_key, daily_limit=daily_limit)
        self._confidence_minimum = confidence_minimum

    async def fetch(
        self,
        *,
        client=None,
    ) -> list[FeedIndicator]:
        """Fetch blacklist and return normalized indicators.

        Args:
            client: Optional shared httpx client (passed to AbuseIPDBClient).

        Returns:
            List of FeedIndicator objects.
        """
        raw = await self._client.get_blacklist(
            confidence_minimum=self._confidence_minimum,
            client=client,
        )

        results: list[FeedIndicator] = []
        for entry in raw:
            ip_addr = entry.get("ip", "")
            if not ip_addr:
                continue

            results.append(
                FeedIndicator(
                    ip=ip_addr,
                    indicator_type="malicious",
                    source_feed="abuseipdb",
                )
            )

        logger.info("AbuseIPDB feed: parsed %d indicators", len(results))
        return results

    @staticmethod
    def get_feed_configs() -> list[dict]:
        """Return feed registration config for AbuseIPDB."""
        return [
            {
                "name": "abuseipdb",
                "feed_url": "https://api.abuseipdb.com/api/v2/blacklist",
                "feed_type": "json_api",
            },
        ]
