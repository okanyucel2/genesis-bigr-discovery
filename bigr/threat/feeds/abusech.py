"""Abuse.ch ThreatFox and URLhaus feed parsers.

ThreatFox: IOC database with C2, botnet, and malware indicators.
URLhaus: Active malware distribution URLs with IP extraction.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# ThreatFox IOC type to our indicator type mapping
THREATFOX_TYPE_MAP = {
    "botnet_cc": "botnet_c2",
    "cc": "malware_c2",
    "payload_delivery": "malware_delivery",
}


@dataclass
class FeedIndicator:
    """A single parsed indicator from a feed."""

    ip: str
    indicator_type: str
    source_feed: str


class AbuseCHFeedParser:
    """Parse Abuse.ch ThreatFox IOCs and URLhaus data.

    ThreatFox provides structured IOC data via POST API.
    URLhaus provides recent malware distribution URLs.
    """

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout

    async def fetch_threatfox(
        self,
        days: int = 7,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[FeedIndicator]:
        """Fetch recent IOCs from ThreatFox API.

        Args:
            days: Number of days to look back (max 7 for free API).
            client: Optional shared httpx client.

        Returns:
            List of FeedIndicator with extracted IPs.
        """
        payload = {"query": "get_iocs", "days": min(days, 7)}

        try:
            if client is None:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    response = await c.post(THREATFOX_API_URL, json=payload)
            else:
                response = await client.post(THREATFOX_API_URL, json=payload)

            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch ThreatFox IOCs: %s", exc)
            return []
        except Exception as exc:
            logger.error("Failed to parse ThreatFox response: %s", exc)
            return []

        if data.get("query_status") != "ok":
            logger.warning("ThreatFox query status: %s", data.get("query_status"))
            return []

        return self._parse_threatfox_iocs(data.get("data", []))

    def _parse_threatfox_iocs(self, iocs: list[dict]) -> list[FeedIndicator]:
        """Extract IPs from ThreatFox IOC entries."""
        indicators: list[FeedIndicator] = []

        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "")
            ioc_value = ioc.get("ioc", "")
            threat_type = ioc.get("threat_type", "")

            # Determine indicator type from ThreatFox classification
            indicator_type = THREATFOX_TYPE_MAP.get(threat_type, "malware_c2")

            # Extract IP from different IOC formats
            ip = self._extract_ip(ioc_value, ioc_type)
            if ip:
                indicators.append(
                    FeedIndicator(
                        ip=ip,
                        indicator_type=indicator_type,
                        source_feed="abusech_threatfox",
                    )
                )

        logger.info("Parsed %d indicators from ThreatFox", len(indicators))
        return indicators

    async def fetch_urlhaus(
        self,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[FeedIndicator]:
        """Fetch recent malware URLs from URLhaus and extract IPs.

        Returns:
            List of FeedIndicator with extracted IPs from malware URLs.
        """
        try:
            if client is None:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    response = await c.get(URLHAUS_RECENT_URL)
            else:
                response = await client.get(URLHAUS_RECENT_URL)

            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch URLhaus data: %s", exc)
            return []
        except Exception as exc:
            logger.error("Failed to parse URLhaus response: %s", exc)
            return []

        return self._parse_urlhaus(data.get("urls", []))

    def _parse_urlhaus(self, urls: list[dict]) -> list[FeedIndicator]:
        """Extract IPs from URLhaus URL entries."""
        indicators: list[FeedIndicator] = []
        seen_ips: set[str] = set()

        for entry in urls:
            url = entry.get("url", "")
            if not url:
                continue

            try:
                parsed = urlparse(url)
                host = parsed.hostname
                if not host:
                    continue

                # Check if host is an IP address
                try:
                    ipaddress.ip_address(host)
                    ip = host
                except ValueError:
                    # It's a domain, skip (we only care about IPs)
                    continue

                if ip not in seen_ips:
                    seen_ips.add(ip)
                    indicators.append(
                        FeedIndicator(
                            ip=ip,
                            indicator_type="malware_delivery",
                            source_feed="abusech_urlhaus",
                        )
                    )
            except Exception:
                continue

        logger.info("Parsed %d indicators from URLhaus", len(indicators))
        return indicators

    def _extract_ip(self, ioc_value: str, ioc_type: str) -> str | None:
        """Extract an IP address from an IOC value.

        Handles formats like:
        - "1.2.3.4:443" (ip:port)
        - "1.2.3.4" (plain IP)
        - "http://1.2.3.4/path" (URL with IP)
        """
        if not ioc_value:
            return None

        # Handle ip:port format
        if ioc_type in ("ip:port", "ip_port"):
            parts = ioc_value.rsplit(":", 1)
            candidate = parts[0]
        elif ioc_type == "url":
            try:
                parsed = urlparse(ioc_value)
                candidate = parsed.hostname or ""
            except Exception:
                return None
        else:
            candidate = ioc_value

        # Validate as IP
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None

    @staticmethod
    def get_feed_configs() -> list[dict]:
        """Return feed registration configs for Abuse.ch feeds."""
        return [
            {
                "name": "abusech_threatfox",
                "feed_url": THREATFOX_API_URL,
                "feed_type": "json_api",
            },
            {
                "name": "abusech_urlhaus",
                "feed_url": URLHAUS_RECENT_URL,
                "feed_type": "json_api",
            },
        ]
