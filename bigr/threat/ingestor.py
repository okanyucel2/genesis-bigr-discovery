"""Threat Intelligence Ingestor Service.

Ingests open-source threat feeds, normalizes indicators to /24 subnet
scores, and stores them with GDPR/KVKK-compliant IP hashing.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from bigr.threat.feeds.abusech import AbuseCHFeedParser
from bigr.threat.feeds.alienvault import AlienVaultOTXParser
from bigr.threat.feeds.cins import CINSArmyParser
from bigr.threat.feeds.firehol import FireHOLParser
from bigr.threat.models import ThreatFeedDB, ThreatIndicatorDB

logger = logging.getLogger(__name__)

# Feed reliability weights (higher = more trusted)
FEED_WEIGHTS: dict[str, float] = {
    "firehol_level1": 0.9,
    "firehol_level2": 0.7,
    "firehol_level3": 0.5,
    "abusech_threatfox": 0.85,
    "abusech_urlhaus": 0.8,
    "alienvault_otx": 0.75,
    "cins_army": 0.7,
}

# Indicator type severity weights
TYPE_WEIGHTS: dict[str, float] = {
    "malware_c2": 0.95,
    "botnet_c2": 0.9,
    "botnet": 0.85,
    "apt": 0.95,
    "malware_delivery": 0.8,
    "scanner": 0.5,
    "malicious": 0.7,
    "suspicious": 0.4,
    "spam": 0.3,
}

# RFC 1918 / RFC 6598 private ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]

DEFAULT_EXPIRY_DAYS = 90


class ThreatIngestor:
    """Ingests open-source threat feeds, normalizes to /24 subnet scores."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        hmac_key: str,
        otx_api_key: str | None = None,
        expiry_days: int = DEFAULT_EXPIRY_DAYS,
    ):
        self.session_factory = session_factory
        self.hmac_key = hmac_key
        self.otx_api_key = otx_api_key
        self.expiry_days = expiry_days

        # Initialize parsers
        self._firehol = FireHOLParser()
        self._abusech = AbuseCHFeedParser()
        self._alienvault = AlienVaultOTXParser(api_key=otx_api_key)
        self._cins = CINSArmyParser()

    async def sync_all_feeds(self) -> dict:
        """Run all enabled feeds. Returns summary stats.

        Returns:
            Dict with keys: feeds_synced, total_indicators, errors, details.
        """
        async with self.session_factory() as session:
            # Ensure feeds are registered
            await self._ensure_feeds_registered(session)

            # Get enabled feeds
            stmt = select(ThreatFeedDB).where(ThreatFeedDB.enabled == 1)
            result = await session.execute(stmt)
            feeds = result.scalars().all()

        summary = {
            "feeds_synced": 0,
            "total_indicators": 0,
            "errors": [],
            "details": {},
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            for feed in feeds:
                try:
                    result = await self._sync_single_feed(feed.name, client=client)
                    summary["feeds_synced"] += 1
                    summary["total_indicators"] += result.get("indicators_processed", 0)
                    summary["details"][feed.name] = result
                except Exception as exc:
                    error_msg = f"{feed.name}: {exc}"
                    logger.error("Feed sync failed: %s", error_msg)
                    summary["errors"].append(error_msg)
                    summary["details"][feed.name] = {"error": str(exc)}

        # Clean up expired indicators
        expired_count = await self._cleanup_expired()
        summary["expired_cleaned"] = expired_count

        return summary

    async def sync_feed(self, feed_name: str) -> dict:
        """Sync a single feed by name.

        Args:
            feed_name: The registered feed name.

        Returns:
            Dict with sync results for that feed.
        """
        async with httpx.AsyncClient(timeout=60.0) as client:
            return await self._sync_single_feed(feed_name, client=client)

    async def lookup_subnet(self, ip: str) -> dict | None:
        """Look up threat score for an IP's /24 subnet.

        Args:
            ip: The IP address to look up.

        Returns:
            Dict with threat indicator data or None if not found.
        """
        subnet = self._ip_to_subnet24(ip)
        subnet_hash = self._hash_subnet(subnet)

        async with self.session_factory() as session:
            stmt = select(ThreatIndicatorDB).where(
                ThreatIndicatorDB.subnet_hash == subnet_hash,
                ThreatIndicatorDB.expires_at > datetime.now(timezone.utc).isoformat(),
            )
            result = await session.execute(stmt)
            indicator = result.scalar_one_or_none()

            if indicator is None:
                return None

            return {
                "subnet_hash": indicator.subnet_hash,
                "subnet_prefix": indicator.subnet_prefix,
                "threat_score": indicator.threat_score,
                "source_feeds": json.loads(indicator.source_feeds),
                "indicator_types": json.loads(indicator.indicator_types),
                "cve_refs": json.loads(indicator.cve_refs) if indicator.cve_refs else [],
                "first_seen": indicator.first_seen,
                "last_seen": indicator.last_seen,
                "report_count": indicator.report_count,
                "expires_at": indicator.expires_at,
            }

    def _hash_subnet(self, subnet: str) -> str:
        """HMAC-SHA256 hash of subnet for GDPR compliance.

        Args:
            subnet: The /24 subnet prefix (e.g., "192.168.1.0/24").

        Returns:
            Hex-encoded HMAC-SHA256 hash.
        """
        return hmac.new(
            self.hmac_key.encode("utf-8"),
            subnet.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _ip_to_subnet24(self, ip: str) -> str:
        """Convert IP to /24 subnet prefix.

        Args:
            ip: An IPv4 address string.

        Returns:
            The /24 network prefix (e.g., "192.168.1.0/24").
        """
        addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(f"{addr}/24", strict=False)
        return str(network)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is in a private range."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in PRIVATE_NETWORKS)
        except ValueError:
            return False

    def _calculate_threat_score(
        self, sources: list[str], types: list[str]
    ) -> float:
        """Weighted scoring based on feed reliability and indicator type.

        The score combines:
        1. Feed reliability (average weight of contributing feeds)
        2. Indicator severity (max weight of indicator types)
        3. Report diversity bonus (more sources = higher confidence)

        Returns:
            Float between 0.0 and 1.0.
        """
        if not sources and not types:
            return 0.0

        # Feed reliability: average of source weights
        feed_scores = [FEED_WEIGHTS.get(s, 0.5) for s in sources]
        avg_feed_score = sum(feed_scores) / len(feed_scores) if feed_scores else 0.5

        # Indicator severity: max of type weights
        type_scores = [TYPE_WEIGHTS.get(t, 0.5) for t in types]
        max_type_score = max(type_scores) if type_scores else 0.5

        # Diversity bonus: more sources = more confidence (up to 0.15 bonus)
        diversity_bonus = min(len(set(sources)) * 0.05, 0.15)

        # Combine: 40% feed reliability + 45% indicator severity + 15% diversity
        raw_score = (
            avg_feed_score * 0.40 + max_type_score * 0.45 + diversity_bonus
        )

        return round(min(max(raw_score, 0.0), 1.0), 4)

    async def _sync_single_feed(
        self, feed_name: str, *, client: httpx.AsyncClient
    ) -> dict:
        """Fetch and process a single feed."""
        logger.info("Syncing feed: %s", feed_name)
        indicators = await self._fetch_feed_indicators(feed_name, client=client)

        if not indicators:
            return {"indicators_fetched": 0, "indicators_processed": 0}

        # Group indicators by /24 subnet
        subnet_data: dict[str, dict] = {}
        for ind in indicators:
            subnet = self._ip_to_subnet24(ind.ip)
            if subnet not in subnet_data:
                subnet_data[subnet] = {
                    "ips": set(),
                    "types": set(),
                    "feeds": set(),
                }
            subnet_data[subnet]["ips"].add(ind.ip)
            subnet_data[subnet]["types"].add(ind.indicator_type)
            subnet_data[subnet]["feeds"].add(ind.source_feed)

        # Upsert indicators into database
        processed = 0
        now_iso = datetime.now(timezone.utc).isoformat()
        expires_iso = (
            datetime.now(timezone.utc) + timedelta(days=self.expiry_days)
        ).isoformat()

        async with self.session_factory() as session:
            for subnet, data in subnet_data.items():
                subnet_hash = self._hash_subnet(subnet)

                # Check if public or private for GDPR compliance
                sample_ip = next(iter(data["ips"]))
                is_private = self._is_private_ip(sample_ip)
                subnet_prefix = subnet if is_private else None

                # Look up existing indicator
                stmt = select(ThreatIndicatorDB).where(
                    ThreatIndicatorDB.subnet_hash == subnet_hash
                )
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()

                feeds_list = sorted(data["feeds"])
                types_list = sorted(data["types"])

                if existing:
                    # Merge with existing data
                    old_feeds = set(json.loads(existing.source_feeds))
                    old_types = set(json.loads(existing.indicator_types))

                    merged_feeds = sorted(old_feeds | set(feeds_list))
                    merged_types = sorted(old_types | set(types_list))

                    existing.source_feeds = json.dumps(merged_feeds)
                    existing.indicator_types = json.dumps(merged_types)
                    existing.threat_score = self._calculate_threat_score(
                        merged_feeds, merged_types
                    )
                    existing.last_seen = now_iso
                    existing.report_count = existing.report_count + 1
                    existing.expires_at = expires_iso
                    if is_private and not existing.subnet_prefix:
                        existing.subnet_prefix = subnet_prefix
                else:
                    # Create new indicator
                    threat_score = self._calculate_threat_score(feeds_list, types_list)
                    session.add(
                        ThreatIndicatorDB(
                            id=str(uuid.uuid4()),
                            subnet_hash=subnet_hash,
                            subnet_prefix=subnet_prefix,
                            threat_score=threat_score,
                            source_feeds=json.dumps(feeds_list),
                            indicator_types=json.dumps(types_list),
                            cve_refs=None,
                            first_seen=now_iso,
                            last_seen=now_iso,
                            report_count=1,
                            expires_at=expires_iso,
                        )
                    )

                processed += 1

            # Update feed metadata
            await session.execute(
                update(ThreatFeedDB)
                .where(ThreatFeedDB.name == feed_name)
                .values(
                    last_synced_at=now_iso,
                    entries_count=len(indicators),
                    updated_at=now_iso,
                )
            )

            await session.commit()

        logger.info(
            "Feed %s: fetched %d indicators, processed %d subnets",
            feed_name,
            len(indicators),
            processed,
        )

        return {
            "indicators_fetched": len(indicators),
            "indicators_processed": processed,
            "subnets_affected": len(subnet_data),
        }

    async def _fetch_feed_indicators(
        self, feed_name: str, *, client: httpx.AsyncClient
    ) -> list:
        """Dispatch to the correct parser for a feed."""
        if feed_name.startswith("firehol_"):
            return await self._firehol.fetch(feed_name, client=client)
        elif feed_name == "abusech_threatfox":
            return await self._abusech.fetch_threatfox(client=client)
        elif feed_name == "abusech_urlhaus":
            return await self._abusech.fetch_urlhaus(client=client)
        elif feed_name == "alienvault_otx":
            return await self._alienvault.fetch(client=client)
        elif feed_name == "cins_army":
            return await self._cins.fetch(client=client)
        else:
            logger.warning("Unknown feed: %s", feed_name)
            return []

    async def _ensure_feeds_registered(self, session: AsyncSession) -> None:
        """Register all known feeds in the database if not already present."""
        now_iso = datetime.now(timezone.utc).isoformat()

        all_configs = (
            FireHOLParser.get_feed_configs()
            + AbuseCHFeedParser.get_feed_configs()
            + AlienVaultOTXParser.get_feed_configs()
            + CINSArmyParser.get_feed_configs()
        )

        for config in all_configs:
            stmt = select(ThreatFeedDB).where(ThreatFeedDB.name == config["name"])
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is None:
                session.add(
                    ThreatFeedDB(
                        id=str(uuid.uuid4()),
                        name=config["name"],
                        feed_url=config["feed_url"],
                        feed_type=config["feed_type"],
                        enabled=1,
                        entries_count=0,
                        created_at=now_iso,
                        updated_at=now_iso,
                    )
                )

        await session.commit()

    async def _cleanup_expired(self) -> int:
        """Remove expired threat indicators from the database.

        Returns:
            Number of expired indicators removed.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        async with self.session_factory() as session:
            stmt = delete(ThreatIndicatorDB).where(
                ThreatIndicatorDB.expires_at < now_iso
            )
            result = await session.execute(stmt)
            await session.commit()

            deleted = result.rowcount  # type: ignore[union-attr]
            if deleted > 0:
                logger.info("Cleaned up %d expired threat indicators", deleted)
            return deleted

    async def get_stats(self) -> dict:
        """Return overall threat intelligence statistics.

        Returns:
            Dict with total_indicators, total_feeds, active_feeds, etc.
        """
        async with self.session_factory() as session:
            # Count active indicators
            now_iso = datetime.now(timezone.utc).isoformat()
            indicator_count = (
                await session.execute(
                    select(func.count(ThreatIndicatorDB.id)).where(
                        ThreatIndicatorDB.expires_at > now_iso
                    )
                )
            ).scalar() or 0

            # Count feeds
            total_feeds = (
                await session.execute(
                    select(func.count(ThreatFeedDB.id))
                )
            ).scalar() or 0

            enabled_feeds = (
                await session.execute(
                    select(func.count(ThreatFeedDB.id)).where(
                        ThreatFeedDB.enabled == 1
                    )
                )
            ).scalar() or 0

            # Average threat score
            avg_score = (
                await session.execute(
                    select(func.avg(ThreatIndicatorDB.threat_score)).where(
                        ThreatIndicatorDB.expires_at > now_iso
                    )
                )
            ).scalar()

            # Score distribution
            high_threat = (
                await session.execute(
                    select(func.count(ThreatIndicatorDB.id)).where(
                        ThreatIndicatorDB.threat_score >= 0.7,
                        ThreatIndicatorDB.expires_at > now_iso,
                    )
                )
            ).scalar() or 0

            medium_threat = (
                await session.execute(
                    select(func.count(ThreatIndicatorDB.id)).where(
                        ThreatIndicatorDB.threat_score >= 0.4,
                        ThreatIndicatorDB.threat_score < 0.7,
                        ThreatIndicatorDB.expires_at > now_iso,
                    )
                )
            ).scalar() or 0

            low_threat = (
                await session.execute(
                    select(func.count(ThreatIndicatorDB.id)).where(
                        ThreatIndicatorDB.threat_score < 0.4,
                        ThreatIndicatorDB.expires_at > now_iso,
                    )
                )
            ).scalar() or 0

            return {
                "total_indicators": indicator_count,
                "total_feeds": total_feeds,
                "enabled_feeds": enabled_feeds,
                "average_threat_score": round(avg_score, 4) if avg_score else 0.0,
                "score_distribution": {
                    "high": high_threat,
                    "medium": medium_threat,
                    "low": low_threat,
                },
            }
