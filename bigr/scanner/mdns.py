"""mDNS/Bonjour service discovery for network asset enrichment.

Listens for multicast DNS (mDNS) service advertisements on the local network.
Apple devices, Chromecast, printers, smart speakers, and many IoT devices
announce their presence via mDNS, providing hostnames, service types, and
metadata without requiring any special privileges.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

from bigr.models import Asset

logger = logging.getLogger(__name__)


# Service types commonly found on home and enterprise networks
INTERESTING_SERVICES = [
    "_http._tcp.local.",           # Web servers
    "_ipp._tcp.local.",            # Printers (IPP)
    "_printer._tcp.local.",        # Printers
    "_airplay._tcp.local.",        # Apple TV / AirPlay
    "_raop._tcp.local.",           # AirPlay audio
    "_googlecast._tcp.local.",     # Chromecast
    "_smb._tcp.local.",            # File sharing (Windows/Samba)
    "_afpovertcp._tcp.local.",     # Apple File Sharing
    "_ssh._tcp.local.",            # SSH servers
    "_rtsp._tcp.local.",           # IP cameras
    "_hap._tcp.local.",            # HomeKit
    "_homekit._tcp.local.",        # HomeKit devices
    "_companion-link._tcp.local.", # Apple Companion (iPhone/iPad)
    "_spotify-connect._tcp.local.",# Spotify Connect speakers
    "_sonos._tcp.local.",          # Sonos speakers
]


@dataclass
class MdnsService:
    """A single mDNS service discovered on the network."""

    name: str              # e.g., "Living Room Speaker"
    service_type: str      # e.g., "_googlecast._tcp.local."
    ip: str                # IPv4 address
    port: int              # Service port number
    hostname: str | None = None       # e.g., "chromecast-abc123.local."
    properties: dict = field(default_factory=dict)  # TXT record key-value pairs


class _MdnsCollector(ServiceListener):
    """Internal listener that collects discovered mDNS services."""

    def __init__(self) -> None:
        self.services: list[MdnsService] = []
        self._zc: Zeroconf | None = None

    def set_zeroconf(self, zc: Zeroconf) -> None:
        """Store reference to Zeroconf instance for service resolution."""
        self._zc = zc

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a new service is discovered."""
        self._resolve_and_add(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is removed. We don't track removals."""
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is updated. Re-resolve."""
        self._resolve_and_add(zc, type_, name)

    def _resolve_and_add(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Resolve service info and add to collection."""
        try:
            info = zc.get_service_info(type_, name)
            if info is None:
                return

            # Get IPv4 addresses
            addresses = info.parsed_addresses()
            if not addresses:
                return

            ip = addresses[0]

            # Parse TXT record properties
            properties: dict[str, str] = {}
            if info.properties:
                for key, value in info.properties.items():
                    try:
                        k = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
                        if value is not None:
                            v = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
                        else:
                            v = ""
                        properties[k] = v
                    except Exception:
                        continue

            service = MdnsService(
                name=name,
                service_type=type_,
                ip=ip,
                port=info.port or 0,
                hostname=info.server,
                properties=properties,
            )

            # Avoid exact duplicates (same name + type + ip)
            for existing in self.services:
                if existing.name == service.name and existing.service_type == service.service_type and existing.ip == service.ip:
                    return

            self.services.append(service)
            logger.debug("mDNS discovered: %s (%s) at %s:%d", name, type_, ip, service.port)

        except Exception as exc:
            logger.debug("Failed to resolve mDNS service %s: %s", name, exc)


def discover_mdns_services(timeout: float = 8.0) -> list[MdnsService]:
    """Listen for mDNS service advertisements on the local network.

    Args:
        timeout: How long to listen for services (seconds).

    Returns:
        List of discovered mDNS services.
    """
    collector = _MdnsCollector()

    try:
        zc = Zeroconf()
    except Exception as exc:
        logger.warning("Failed to initialize Zeroconf: %s", exc)
        return []

    collector.set_zeroconf(zc)

    browsers: list[ServiceBrowser] = []
    try:
        for svc_type in INTERESTING_SERVICES:
            try:
                browser = ServiceBrowser(zc, svc_type, collector)
                browsers.append(browser)
            except Exception as exc:
                logger.debug("Failed to browse %s: %s", svc_type, exc)

        # Wait for discovery period
        time.sleep(timeout)

    finally:
        try:
            zc.close()
        except Exception:
            pass

    logger.info("mDNS discovery found %d services in %.1fs", len(collector.services), timeout)
    return collector.services


def enrich_assets_with_mdns(
    assets: list[Asset],
    services: list[MdnsService],
) -> list[Asset]:
    """Match discovered mDNS services to assets by IP and enrich them.

    For each asset, finds all mDNS services with a matching IP address
    and enriches the asset with:
    - hostname (from mDNS server field, if asset has none)
    - mdns_services list in raw_evidence

    Args:
        assets: List of assets to enrich.
        services: List of discovered mDNS services.

    Returns:
        The same list of assets, enriched in-place.
    """
    # Build IP -> services lookup
    ip_to_services: dict[str, list[MdnsService]] = {}
    for svc in services:
        ip_to_services.setdefault(svc.ip, []).append(svc)

    for asset in assets:
        matched = ip_to_services.get(asset.ip, [])
        if not matched:
            continue

        # Enrich hostname from mDNS if asset doesn't have one
        if asset.hostname is None:
            for svc in matched:
                if svc.hostname:
                    asset.hostname = svc.hostname
                    break

        # Add service evidence to raw_evidence
        mdns_evidence = []
        for svc in matched:
            mdns_evidence.append({
                "name": svc.name,
                "service_type": svc.service_type,
                "port": svc.port,
                "hostname": svc.hostname,
                "properties": svc.properties,
            })

        asset.raw_evidence["mdns_services"] = mdns_evidence

    return assets
