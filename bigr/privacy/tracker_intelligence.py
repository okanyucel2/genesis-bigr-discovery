"""Tracker intelligence — categorize blocked domains from Guardian stats."""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.guardian.models import GuardianBlockedDomainDB, GuardianTopDomainDB


# Category mapping: Guardian/blocklist categories → tracker display categories
_CATEGORY_MAP: dict[str, str] = {
    "ads": "advertising",
    "adware": "advertising",
    "ad-network": "advertising",
    "adserver": "advertising",
    "advertising": "advertising",
    "analytics": "analytics",
    "tracking": "analytics",
    "telemetry": "analytics",
    "tracker": "analytics",
    "social": "social",
    "facebook": "social",
    "social-tracking": "social",
    "fingerprinting": "fingerprinting",
    "canvas-fingerprint": "fingerprinting",
}

# Domain keyword → category (fallback when no blocklist category)
_DOMAIN_KEYWORDS: dict[str, str] = {
    "analytics": "analytics",
    "tracker": "analytics",
    "tracking": "analytics",
    "telemetry": "analytics",
    "pixel": "social",
    "adserver": "advertising",
    "ads.": "advertising",
    "ad.": "advertising",
    "doubleclick": "advertising",
    "adsystem": "advertising",
    "facebook": "social",
    "fbcdn": "social",
    "twitter": "social",
    "fingerprint": "fingerprinting",
}

TRACKER_CATEGORIES = ("advertising", "analytics", "social", "fingerprinting")


def _resolve_tracker_category(
    domain: str, blocklist_category: str | None = None
) -> str | None:
    """Resolve a domain + optional blocklist category to a tracker display category."""
    # Try blocklist category first
    if blocklist_category:
        cat_lower = blocklist_category.lower()
        if cat_lower in _CATEGORY_MAP:
            return _CATEGORY_MAP[cat_lower]

    # Keyword-based fallback
    domain_lower = domain.lower()
    for keyword, category in _DOMAIN_KEYWORDS.items():
        if keyword in domain_lower:
            return category

    return None


@dataclass
class TrackerStats:
    total_blocked: int = 0
    by_category: dict[str, int] = field(default_factory=lambda: {
        "advertising": 0,
        "analytics": 0,
        "social": 0,
        "fingerprinting": 0,
    })
    period: str = "weekly"

    def to_dict(self) -> dict:
        return {
            "total_blocked": self.total_blocked,
            "by_category": dict(self.by_category),
            "period": self.period,
        }


@dataclass
class TrackerEvent:
    domain: str
    category: str
    block_count: int
    last_blocked: str | None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "category": self.category,
            "block_count": self.block_count,
            "last_blocked": self.last_blocked,
        }


@dataclass
class DeviceTrackerReport:
    ip: str
    tracker_attempts: int = 0
    domains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "tracker_attempts": self.tracker_attempts,
            "domains": self.domains,
        }


async def get_tracker_stats(session: AsyncSession) -> TrackerStats:
    """Extract tracker category stats from Guardian top domains."""
    stats = TrackerStats()

    # Get top blocked domains with their categories
    stmt = select(GuardianTopDomainDB).where(
        GuardianTopDomainDB.block_count > 0
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()

    for row in rows:
        cat = _resolve_tracker_category(row.domain, row.category)
        if cat and cat in stats.by_category:
            stats.by_category[cat] += row.block_count
            stats.total_blocked += row.block_count

    return stats


async def get_tracker_events(
    session: AsyncSession, limit: int = 20
) -> list[TrackerEvent]:
    """Return recent tracker blocking events."""
    # Join top domains with blocked domains for category info
    stmt = (
        select(
            GuardianTopDomainDB.domain,
            GuardianTopDomainDB.block_count,
            GuardianTopDomainDB.last_blocked,
            GuardianTopDomainDB.category,
        )
        .where(GuardianTopDomainDB.block_count > 0)
        .order_by(desc(GuardianTopDomainDB.block_count))
        .limit(limit)
    )
    result = await session.execute(stmt)

    events: list[TrackerEvent] = []
    for row in result.all():
        cat = _resolve_tracker_category(row.domain, row.category)
        if cat:
            events.append(TrackerEvent(
                domain=row.domain,
                category=cat,
                block_count=row.block_count,
                last_blocked=row.last_blocked,
            ))

    return events


async def get_device_tracker_report(
    session: AsyncSession, ip: str
) -> DeviceTrackerReport:
    """Get tracker communication report for a specific device.

    NOTE: This is a simplified version. Full cross-referencing with
    firewall events would require correlating source IPs from firewall
    logs with blocked domains. For now, returns an empty report as
    device-level DNS query attribution requires the Shield agent.
    """
    return DeviceTrackerReport(ip=ip)
