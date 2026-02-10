"""Collective Intelligence Engine.

Manages the lifecycle of anonymized threat signals:
1. Agents submit signals (privacy-protected)
2. Engine aggregates them into community-level reports
3. Only verified (k-anonymity met) signals are exposed
4. Expired signals are cleaned up periodically
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.collective.models import (
    CollectiveSignalReport,
    CollectiveStats,
    ContributionStatus,
    ThreatSignal,
)
from bigr.collective.privacy import DifferentialPrivacy
from bigr.core.models_db import CollectiveSignalDB

logger = logging.getLogger(__name__)


class CollectiveEngine:
    """Manages collective threat intelligence sharing.

    Every signal goes through the differential-privacy pipeline before
    being stored.  Only aggregated, k-anonymous reports are ever exposed
    to the community.
    """

    def __init__(
        self,
        hmac_key: str,
        epsilon: float = 1.0,
        k_anonymity: int = 3,
    ) -> None:
        self._hmac_key = hmac_key
        self._privacy = DifferentialPrivacy(epsilon=epsilon, k_anonymity=k_anonymity)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def submit_signal(
        self, signal: ThreatSignal, db: AsyncSession
    ) -> dict:
        """Submit a new threat signal from this agent.

        The signal is anonymized before storage:
        1. Agent ID is already hashed by the caller
        2. Subnet is already hashed by the caller
        3. Severity gets Laplace noise added
        4. Randomized response may suppress the signal entirely

        Returns:
            Dict with status and signal details.
        """
        # Randomized response: should we report this at all?
        should_report = self._privacy.randomized_response(True)
        if not should_report:
            logger.debug("Signal suppressed by randomized response")
            return {"status": "suppressed", "reason": "privacy_randomization"}

        # Add noise to severity
        noised_severity = self._privacy.add_noise_to_severity(signal.severity)

        now_iso = datetime.now(timezone.utc).isoformat()

        row = CollectiveSignalDB(
            subnet_hash=signal.subnet_hash,
            signal_type=signal.signal_type,
            severity=noised_severity,
            port=signal.port,
            agent_hash=signal.agent_hash,
            reported_at=signal.timestamp or now_iso,
            is_noised=1,
        )
        db.add(row)
        await db.commit()

        logger.info(
            "Collective signal stored: type=%s severity=%.2f (noised)",
            signal.signal_type,
            noised_severity,
        )

        return {
            "status": "accepted",
            "noised_severity": noised_severity,
            "signal_type": signal.signal_type,
        }

    async def get_community_threats(
        self,
        db: AsyncSession,
        min_confidence: float = 0.5,
    ) -> list[CollectiveSignalReport]:
        """Get verified community threat signals.

        Only returns signals that meet k-anonymity threshold AND
        whose confidence exceeds ``min_confidence``.
        """
        # Fetch all non-expired signals
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=72)
        ).isoformat()
        stmt = select(CollectiveSignalDB).where(
            CollectiveSignalDB.reported_at >= cutoff
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()

        reports = self._aggregate_signals(rows)

        # Filter by verification and confidence
        return [
            r
            for r in reports
            if r.is_verified and r.confidence >= min_confidence
        ]

    async def get_stats(self, db: AsyncSession) -> CollectiveStats:
        """Get collective intelligence network stats."""
        now = datetime.now(timezone.utc)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        cutoff_72h = (now - timedelta(hours=72)).isoformat()

        # Total signals (last 72h)
        total = (
            await db.execute(
                select(func.count(CollectiveSignalDB.id)).where(
                    CollectiveSignalDB.reported_at >= cutoff_72h
                )
            )
        ).scalar() or 0

        # Active agents (last 24h)
        active_agents = (
            await db.execute(
                select(
                    func.count(func.distinct(CollectiveSignalDB.agent_hash))
                ).where(CollectiveSignalDB.reported_at >= cutoff_24h)
            )
        ).scalar() or 0

        # Subnets monitored
        subnets = (
            await db.execute(
                select(
                    func.count(func.distinct(CollectiveSignalDB.subnet_hash))
                ).where(CollectiveSignalDB.reported_at >= cutoff_72h)
            )
        ).scalar() or 0

        # Count verified threats (need to aggregate to check k-anonymity)
        all_rows_stmt = select(CollectiveSignalDB).where(
            CollectiveSignalDB.reported_at >= cutoff_72h
        )
        result = await db.execute(all_rows_stmt)
        all_rows = result.scalars().all()
        aggregated = self._aggregate_signals(all_rows)
        verified_count = sum(1 for r in aggregated if r.is_verified)

        # Community protection score (heuristic):
        # Base = 20 + (active_agents * 5, max 30) + (verified_threats * 3, max 30) + (subnets * 2, max 20)
        agent_score = min(30.0, active_agents * 5.0)
        threat_score = min(30.0, verified_count * 3.0)
        subnet_score = min(20.0, subnets * 2.0)
        protection = round(min(100.0, 20.0 + agent_score + threat_score + subnet_score), 1)

        return CollectiveStats(
            total_signals=total,
            active_agents=active_agents,
            verified_threats=verified_count,
            subnets_monitored=subnets,
            community_protection_score=protection,
            last_updated=now.isoformat(),
        )

    async def get_contribution_status(
        self, agent_hash: str, db: AsyncSession
    ) -> ContributionStatus:
        """Get this agent's contribution status."""
        # Signals contributed by this agent
        contributed = (
            await db.execute(
                select(func.count(CollectiveSignalDB.id)).where(
                    CollectiveSignalDB.agent_hash == agent_hash
                )
            )
        ).scalar() or 0

        # Total verified signals the agent can receive
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=72)
        ).isoformat()
        all_rows_stmt = select(CollectiveSignalDB).where(
            CollectiveSignalDB.reported_at >= cutoff
        )
        result = await db.execute(all_rows_stmt)
        all_rows = result.scalars().all()
        aggregated = self._aggregate_signals(all_rows)
        received = sum(1 for r in aggregated if r.is_verified)

        is_contributing = contributed > 0

        return ContributionStatus(
            signals_contributed=contributed,
            signals_received=received,
            is_contributing=is_contributing,
            opt_in=is_contributing,
            privacy_level="standard",
        )

    async def cleanup_expired(
        self, db: AsyncSession, max_age_hours: int = 72
    ) -> int:
        """Remove signals older than max_age_hours.

        Returns:
            Number of signals removed.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()
        stmt = delete(CollectiveSignalDB).where(
            CollectiveSignalDB.reported_at < cutoff
        )
        result = await db.execute(stmt)
        await db.commit()
        deleted = result.rowcount  # type: ignore[union-attr]
        if deleted > 0:
            logger.info("Cleaned up %d expired collective signals", deleted)
        return deleted

    async def get_feed(
        self, db: AsyncSession, limit: int = 20
    ) -> list[CollectiveSignalReport]:
        """Get the latest collective signals (verified only) for the feed.

        Returns up to ``limit`` most recent verified signals.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=72)
        ).isoformat()
        stmt = select(CollectiveSignalDB).where(
            CollectiveSignalDB.reported_at >= cutoff
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()

        reports = self._aggregate_signals(rows)
        verified = [r for r in reports if r.is_verified]
        # Sort by last_seen descending (most recent first)
        verified.sort(key=lambda r: r.last_seen, reverse=True)
        return verified[:limit]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _aggregate_signals(
        self, signals: list[CollectiveSignalDB]
    ) -> list[CollectiveSignalReport]:
        """Aggregate raw signals into community-level reports.

        Groups by (subnet_hash, signal_type), counts unique agents,
        calculates average severity, and applies k-anonymity check.
        """
        groups: dict[tuple[str, str], list[CollectiveSignalDB]] = defaultdict(
            list
        )
        for sig in signals:
            key = (sig.subnet_hash, sig.signal_type)
            groups[key].append(sig)

        reports: list[CollectiveSignalReport] = []
        for (subnet_hash, signal_type), group in groups.items():
            unique_agents = {s.agent_hash for s in group}
            reporter_count = len(unique_agents)
            severities = [s.severity for s in group]
            avg_severity = round(sum(severities) / len(severities), 2)

            # Consistency: 1.0 - standard deviation (higher = more consistent)
            if len(severities) > 1:
                mean = avg_severity
                variance = sum((s - mean) ** 2 for s in severities) / len(
                    severities
                )
                std_dev = variance**0.5
                consistency = round(max(0.0, 1.0 - std_dev), 2)
            else:
                consistency = 0.5  # Single report, moderate confidence

            confidence = self._privacy.calculate_confidence(
                reporter_count, consistency
            )
            is_verified = self._privacy.meets_k_anonymity(reporter_count)

            timestamps = [s.reported_at for s in group]
            first_seen = min(timestamps)
            last_seen = max(timestamps)

            reports.append(
                CollectiveSignalReport(
                    subnet_hash=subnet_hash,
                    signal_type=signal_type,
                    reporter_count=reporter_count,
                    avg_severity=avg_severity,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    confidence=confidence,
                    is_verified=is_verified,
                )
            )

        return reports

    def _hash_value(self, value: str) -> str:
        """HMAC-SHA256 hash of a value for privacy compliance."""
        return hmac.new(
            self._hmac_key.encode("utf-8"),
            value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
