"""FireHOL blocklist IP list parser.

Downloads FireHOL level1/level2/level3 IP blocklists and extracts
individual IPs and CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

FIREHOL_URLS = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "firehol_level3": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
}

# Map firehol levels to indicator types
LEVEL_INDICATOR_TYPES = {
    "firehol_level1": "malicious",
    "firehol_level2": "scanner",
    "firehol_level3": "suspicious",
}


@dataclass
class FeedIndicator:
    """A single parsed indicator from a feed."""

    ip: str
    indicator_type: str
    source_feed: str


class FireHOLParser:
    """Parse FireHOL blocklist-ipsets netset files.

    Each file is a plain text list with:
    - Comment lines starting with #
    - Individual IPs (1.2.3.4)
    - CIDR ranges (1.2.3.0/24)
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def fetch(
        self,
        feed_name: str = "firehol_level1",
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[FeedIndicator]:
        """Download and parse a FireHOL netset file.

        Args:
            feed_name: One of "firehol_level1", "firehol_level2", "firehol_level3".
            client: Optional shared httpx client.

        Returns:
            List of FeedIndicator with extracted IPs.
        """
        url = FIREHOL_URLS.get(feed_name)
        if not url:
            logger.error("Unknown FireHOL feed: %s", feed_name)
            return []

        indicator_type = LEVEL_INDICATOR_TYPES.get(feed_name, "malicious")

        try:
            if client is None:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    response = await c.get(url)
            else:
                response = await client.get(url)

            response.raise_for_status()
            text = response.text
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch %s: %s", feed_name, exc)
            return []

        return self._parse_netset(text, feed_name, indicator_type)

    def _parse_netset(
        self, text: str, feed_name: str, indicator_type: str
    ) -> list[FeedIndicator]:
        """Parse a netset file and expand CIDR ranges to representative IPs."""
        indicators: list[FeedIndicator] = []

        for line in text.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            try:
                if "/" in line:
                    # CIDR notation — use the network address as representative
                    network = ipaddress.ip_network(line, strict=False)
                    # For /24 or larger subnets, just record the network address
                    # For smaller subnets (/25-/32), expand individual IPs
                    if network.prefixlen <= 24:
                        indicators.append(
                            FeedIndicator(
                                ip=str(network.network_address),
                                indicator_type=indicator_type,
                                source_feed=feed_name,
                            )
                        )
                    else:
                        for host in network.hosts():
                            indicators.append(
                                FeedIndicator(
                                    ip=str(host),
                                    indicator_type=indicator_type,
                                    source_feed=feed_name,
                                )
                            )
                            # Limit expansion to avoid memory issues
                            if len(indicators) > 500_000:
                                logger.warning(
                                    "Indicator limit reached for %s", feed_name
                                )
                                return indicators
                else:
                    # Single IP
                    ipaddress.ip_address(line)  # validate
                    indicators.append(
                        FeedIndicator(
                            ip=line,
                            indicator_type=indicator_type,
                            source_feed=feed_name,
                        )
                    )
            except ValueError:
                # Skip invalid lines
                continue

        logger.info("Parsed %d indicators from %s", len(indicators), feed_name)
        return indicators

    @staticmethod
    def get_feed_configs() -> list[dict]:
        """Return feed registration configs for all FireHOL feeds."""
        return [
            {
                "name": name,
                "feed_url": url,
                "feed_type": "ip_list",
            }
            for name, url in FIREHOL_URLS.items()
        ]
