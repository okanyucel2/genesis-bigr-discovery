"""Blocklist manager — download, parse, and query domain blocklists."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.guardian.config import BlocklistSource, GuardianConfig
from bigr.guardian.models import GuardianBlockedDomainDB, GuardianBlocklistDB

logger = logging.getLogger(__name__)

# Domains to never block (system-critical)
_NEVER_BLOCK = frozenset({
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
})


def _categorize_domain(domain: str, blocklist_name: str) -> str | None:
    """Categorize a domain based on blocklist source name and domain patterns.

    Returns a category string like "advertising", "analytics", "social",
    "fingerprinting", "malware", or None if unknown.
    """
    bl_lower = blocklist_name.lower()

    # Blocklist-source-based categorization
    if any(kw in bl_lower for kw in ("ads", "adguard", "easylist")):
        return "advertising"
    if any(kw in bl_lower for kw in ("track", "analytic", "telemetry")):
        return "analytics"
    if any(kw in bl_lower for kw in ("social", "facebook", "twitter")):
        return "social"
    if any(kw in bl_lower for kw in ("fingerprint",)):
        return "fingerprinting"
    if any(kw in bl_lower for kw in ("malware", "phishing", "ransomware")):
        return "malware"

    # Domain-pattern-based fallback
    domain_lower = domain.lower()
    if any(kw in domain_lower for kw in ("ads.", "ad.", "adserver", "doubleclick", "adsystem")):
        return "advertising"
    if any(kw in domain_lower for kw in ("tracker", "tracking", "analytics", "telemetry")):
        return "analytics"
    if any(kw in domain_lower for kw in ("pixel", "facebook", "fbcdn", "twitter")):
        return "social"
    if "fingerprint" in domain_lower:
        return "fingerprinting"

    return None


class BlocklistManager:
    """Manage domain blocklists: download, parse, store, and query.

    Parameters
    ----------
    config:
        Guardian configuration with blocklist sources.
    """

    def __init__(self, config: GuardianConfig) -> None:
        self._config = config
        self._blocked_domains: set[str] = set()
        self._domain_categories: dict[str, str] = {}

    @property
    def domain_count(self) -> int:
        return len(self._blocked_domains)

    async def load_from_db(self, session: AsyncSession) -> int:
        """Load blocked domains from database into memory."""
        result = await session.execute(select(GuardianBlockedDomainDB))
        rows = result.scalars().all()
        self._blocked_domains = {r.domain for r in rows}
        self._domain_categories = {r.domain: r.category for r in rows}
        logger.info("Loaded %d blocked domains from DB", len(self._blocked_domains))
        return len(self._blocked_domains)

    async def update_all_blocklists(self, session: AsyncSession) -> dict:
        """Download and update all enabled blocklists.

        Returns
        -------
        Summary dict with counts per blocklist.
        """
        results = {}
        for source in self._config.blocklists:
            try:
                count = await self._update_blocklist(session, source)
                results[source.name] = {"status": "ok", "domains": count}
            except Exception as exc:
                logger.error("Failed to update blocklist %s: %s", source.name, exc)
                results[source.name] = {"status": "error", "error": str(exc)}

        # Reload in-memory set after DB update
        await self.load_from_db(session)
        return results

    async def _update_blocklist(
        self, session: AsyncSession, source: BlocklistSource
    ) -> int:
        """Download and parse a single blocklist source."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(source.url)
            resp.raise_for_status()
            raw_text = resp.text

        domains = self._parse_blocklist(raw_text, source.format)

        # Upsert blocklist metadata
        bl_id = f"bl-{source.name.lower().replace(' ', '-')}"
        existing = await session.execute(
            select(GuardianBlocklistDB).where(GuardianBlocklistDB.id == bl_id)
        )
        bl = existing.scalar_one_or_none()
        if bl is None:
            bl = GuardianBlocklistDB(
                id=bl_id,
                name=source.name,
                url=source.url,
                format=source.format,
                category=source.category,
            )
            session.add(bl)

        bl.domain_count = len(domains)
        bl.last_updated = datetime.now(timezone.utc).isoformat()

        # Delete existing domains for this blocklist and re-insert
        await session.execute(
            delete(GuardianBlockedDomainDB).where(
                GuardianBlockedDomainDB.blocklist_id == bl_id
            )
        )
        await session.flush()

        for domain in domains:
            cat = _categorize_domain(domain, source.name) or source.category
            session.add(
                GuardianBlockedDomainDB(
                    domain=domain, blocklist_id=bl_id, category=cat
                )
            )

        await session.commit()
        logger.info("Updated blocklist %s: %d domains", source.name, len(domains))
        return len(domains)

    @staticmethod
    def _parse_blocklist(raw_text: str, format: str) -> set[str]:
        """Parse blocklist text into a set of domain names."""
        domains: set[str] = set()
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            if format == "hosts":
                # Format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = parts[1].lower().strip()
                    if domain and domain not in _NEVER_BLOCK:
                        domains.add(domain)
            elif format == "domains":
                # Format: domain.com (one per line)
                domain = line.lower().strip()
                if domain and domain not in _NEVER_BLOCK:
                    domains.add(domain)

        return domains

    def is_blocked(self, domain: str) -> tuple[bool, str]:
        """Check if a domain is blocked (exact + parent domain match).

        Returns
        -------
        (is_blocked, category) — category is empty if not blocked.
        """
        domain = domain.lower().rstrip(".")

        # Exact match
        if domain in self._blocked_domains:
            return True, self._domain_categories.get(domain, "")

        # Parent domain match: ads.tracker.com → check tracker.com
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._blocked_domains:
                return True, self._domain_categories.get(parent, "")

        return False, ""
