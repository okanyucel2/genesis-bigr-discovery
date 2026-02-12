"""Guardian DNS filtering configuration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BlocklistSource:
    """A blocklist source definition."""

    name: str
    url: str
    format: str = "hosts"  # "hosts" or "domains"
    category: str = "malware"


# Default blocklist sources
DEFAULT_BLOCKLISTS: list[BlocklistSource] = [
    BlocklistSource(
        name="StevenBlack Unified",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        format="hosts",
        category="malware",
    ),
    BlocklistSource(
        name="OISD Basic",
        url="https://basic.oisd.nl/",
        format="domains",
        category="ad",
    ),
]


@dataclass
class GuardianConfig:
    """Runtime configuration for Guardian DNS server."""

    dns_host: str = "0.0.0.0"
    dns_port: int = 53
    upstream_doh_url: str = "https://1.1.1.1/dns-query"
    upstream_fallback_ip: str = "9.9.9.9"
    cache_size: int = 10000
    cache_ttl: int = 3600
    blocklist_update_hours: int = 24
    sinkhole_ip: str = "0.0.0.0"
    blocklists: list[BlocklistSource] = field(default_factory=lambda: list(DEFAULT_BLOCKLISTS))


def load_guardian_config() -> GuardianConfig:
    """Load Guardian config from settings (environment variables)."""
    from bigr.core.settings import settings

    return GuardianConfig(
        dns_host=getattr(settings, "GUARDIAN_DNS_HOST", "0.0.0.0"),
        dns_port=getattr(settings, "GUARDIAN_DNS_PORT", 53),
        upstream_doh_url=getattr(
            settings, "GUARDIAN_UPSTREAM_DOH", "https://1.1.1.1/dns-query"
        ),
        upstream_fallback_ip=getattr(settings, "GUARDIAN_UPSTREAM_FALLBACK", "9.9.9.9"),
        cache_size=getattr(settings, "GUARDIAN_CACHE_SIZE", 10000),
        cache_ttl=getattr(settings, "GUARDIAN_CACHE_TTL", 3600),
        blocklist_update_hours=getattr(settings, "GUARDIAN_BLOCKLIST_UPDATE_HOURS", 24),
        sinkhole_ip=getattr(settings, "GUARDIAN_SINKHOLE_IP", "0.0.0.0"),
    )
