"""CINS Army List feed parser.

CINS (Collective Intelligence Network Security) publishes a curated list
of IPs exhibiting malicious behavior observed by the Sentinel IPS network.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

CINS_ARMY_URL = "https://cinsscore.com/list/ci-badguys.txt"


@dataclass
class FeedIndicator:
    """A single parsed indicator from a feed."""

    ip: str
    indicator_type: str
    source_feed: str


class CINSArmyParser:
    """Parse the CINS Army bad-guys IP list.

    Simple plain-text format with one IP per line. No comments or headers.
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def fetch(
        self,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[FeedIndicator]:
        """Download and parse the CINS Army IP list.

        Args:
            client: Optional shared httpx client.

        Returns:
            List of FeedIndicator with extracted IPs.
        """
        try:
            if client is None:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    response = await c.get(CINS_ARMY_URL)
            else:
                response = await client.get(CINS_ARMY_URL)

            response.raise_for_status()
            text = response.text
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch CINS Army list: %s", exc)
            return []

        return self._parse_ip_list(text)

    def _parse_ip_list(self, text: str) -> list[FeedIndicator]:
        """Parse plain-text IP list."""
        indicators: list[FeedIndicator] = []

        for line in text.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                ipaddress.ip_address(line)
                indicators.append(
                    FeedIndicator(
                        ip=line,
                        indicator_type="malicious",
                        source_feed="cins_army",
                    )
                )
            except ValueError:
                continue

        logger.info("Parsed %d indicators from CINS Army", len(indicators))
        return indicators

    @staticmethod
    def get_feed_configs() -> list[dict]:
        """Return feed registration config for CINS Army."""
        return [
            {
                "name": "cins_army",
                "feed_url": CINS_ARMY_URL,
                "feed_type": "ip_list",
            },
        ]
