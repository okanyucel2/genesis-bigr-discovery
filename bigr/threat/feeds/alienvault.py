"""AlienVault OTX (Open Threat Exchange) feed parser.

Fetches pulse-based threat indicators from the free OTX API.
Requires an OTX API key (free registration at otx.alienvault.com).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_SUBSCRIBED_URL = f"{OTX_BASE_URL}/pulses/subscribed"

# OTX indicator type to our indicator type mapping
OTX_TYPE_MAP = {
    "IPv4": "malicious",
    "IPv6": "malicious",
    "URL": "malware_delivery",
    "domain": "malicious",
    "hostname": "malicious",
}


@dataclass
class FeedIndicator:
    """A single parsed indicator from a feed."""

    ip: str
    indicator_type: str
    source_feed: str


class AlienVaultOTXParser:
    """Parse AlienVault OTX pulse subscriptions for IPv4 indicators.

    Requires an OTX API key (free). If no key is provided, the feed
    is skipped gracefully.
    """

    def __init__(self, api_key: str | None = None, timeout: float = 30.0):
        self.api_key = api_key
        self.timeout = timeout

    async def fetch(
        self,
        limit: int = 50,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[FeedIndicator]:
        """Fetch subscribed pulse indicators from OTX.

        Args:
            limit: Maximum number of pulses to process.
            client: Optional shared httpx client.

        Returns:
            List of FeedIndicator with extracted IPv4 addresses.
        """
        if not self.api_key:
            logger.info("OTX API key not configured, skipping AlienVault feed")
            return []

        headers = {"X-OTX-API-KEY": self.api_key}
        params = {"limit": limit, "page": 1}

        try:
            if client is None:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    response = await c.get(
                        OTX_SUBSCRIBED_URL, headers=headers, params=params
                    )
            else:
                response = await client.get(
                    OTX_SUBSCRIBED_URL, headers=headers, params=params
                )

            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                logger.error("OTX API key is invalid or expired")
            else:
                logger.error("OTX API error: %s", exc)
            return []
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch OTX pulses: %s", exc)
            return []
        except Exception as exc:
            logger.error("Failed to parse OTX response: %s", exc)
            return []

        return self._parse_pulses(data.get("results", []))

    def _parse_pulses(self, pulses: list[dict]) -> list[FeedIndicator]:
        """Extract IPv4 indicators from OTX pulses."""
        indicators: list[FeedIndicator] = []
        seen_ips: set[str] = set()

        for pulse in pulses:
            pulse_name = pulse.get("name", "unknown")
            pulse_tags = pulse.get("tags", [])

            # Derive indicator type from pulse tags
            indicator_type = self._classify_pulse(pulse_tags)

            for indicator in pulse.get("indicators", []):
                ioc_type = indicator.get("type", "")
                ioc_value = indicator.get("indicator", "")

                # Only process IPv4 indicators
                if ioc_type != "IPv4":
                    continue

                try:
                    ipaddress.ip_address(ioc_value)
                except ValueError:
                    continue

                if ioc_value not in seen_ips:
                    seen_ips.add(ioc_value)
                    indicators.append(
                        FeedIndicator(
                            ip=ioc_value,
                            indicator_type=indicator_type,
                            source_feed="alienvault_otx",
                        )
                    )

        logger.info("Parsed %d indicators from OTX (%d pulses)", len(indicators), len(pulses))
        return indicators

    def _classify_pulse(self, tags: list[str]) -> str:
        """Classify indicator type based on pulse tags."""
        tag_set = {t.lower() for t in tags}

        if tag_set & {"c2", "c&c", "command and control", "rat"}:
            return "malware_c2"
        if tag_set & {"botnet", "ddos"}:
            return "botnet"
        if tag_set & {"scanner", "scanning", "brute force", "bruteforce"}:
            return "scanner"
        if tag_set & {"spam", "phishing"}:
            return "spam"
        if tag_set & {"ransomware", "malware", "trojan"}:
            return "malware_c2"
        if tag_set & {"apt", "targeted attack"}:
            return "apt"

        return "malicious"

    @staticmethod
    def get_feed_configs() -> list[dict]:
        """Return feed registration config for AlienVault OTX."""
        return [
            {
                "name": "alienvault_otx",
                "feed_url": OTX_SUBSCRIBED_URL,
                "feed_type": "json_api",
            },
        ]
