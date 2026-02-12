"""Query statistics tracker with memory buffer and periodic DB flush."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.guardian.models import GuardianQueryStatsDB, GuardianTopDomainDB

logger = logging.getLogger(__name__)


class StatsTracker:
    """Track DNS query statistics in memory with periodic DB flush.

    Parameters
    ----------
    flush_interval:
        Seconds between DB flushes (default: 300 = 5 minutes).
    top_domains_limit:
        Maximum number of top blocked domains to track.
    """

    def __init__(
        self,
        flush_interval: int = 300,
        top_domains_limit: int = 100,
    ) -> None:
        self._flush_interval = flush_interval
        self._top_domains_limit = top_domains_limit

        # Memory counters (reset after flush)
        self._total_queries = 0
        self._blocked_queries = 0
        self._allowed_queries = 0
        self._cache_hits = 0
        self._blocked_domains: dict[str, int] = defaultdict(int)
        self._blocked_categories: dict[str, str] = {}

        # Cumulative (not reset)
        self._lifetime_total = 0
        self._lifetime_blocked = 0

        self._flush_task: asyncio.Task | None = None
        self._running = False

    def record_query(
        self,
        domain: str,
        action: str,
        reason: str,
        is_cache_hit: bool = False,
    ) -> None:
        """Record a DNS query (non-blocking, in-memory)."""
        self._total_queries += 1
        self._lifetime_total += 1

        if is_cache_hit:
            self._cache_hits += 1

        if action == "block":
            self._blocked_queries += 1
            self._lifetime_blocked += 1
            self._blocked_domains[domain] += 1
        elif action == "allow":
            self._allowed_queries += 1

    def get_stats_summary(self) -> dict:
        """Return current statistics summary (memory + lifetime)."""
        top_blocked = sorted(
            self._blocked_domains.items(), key=lambda x: x[1], reverse=True
        )[: self._top_domains_limit]

        return {
            "current_period": {
                "total_queries": self._total_queries,
                "blocked_queries": self._blocked_queries,
                "allowed_queries": self._allowed_queries,
                "cache_hits": self._cache_hits,
                "block_rate": (
                    self._blocked_queries / self._total_queries
                    if self._total_queries > 0
                    else 0.0
                ),
            },
            "lifetime": {
                "total_queries": self._lifetime_total,
                "blocked_queries": self._lifetime_blocked,
            },
            "top_blocked_domains": [
                {"domain": d, "count": c} for d, c in top_blocked
            ],
        }

    async def flush_to_db(self, session: AsyncSession) -> None:
        """Flush current period stats to database and reset counters."""
        if self._total_queries == 0:
            return

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        hour = now.hour

        # Upsert hourly stats
        existing = await session.execute(
            select(GuardianQueryStatsDB).where(
                GuardianQueryStatsDB.date == date_str,
                GuardianQueryStatsDB.hour == hour,
            )
        )
        stats_row = existing.scalar_one_or_none()
        if stats_row is None:
            stats_row = GuardianQueryStatsDB(
                date=date_str,
                hour=hour,
                total_queries=0,
                blocked_queries=0,
                allowed_queries=0,
                cache_hits=0,
            )
            session.add(stats_row)
            await session.flush()

        stats_row.total_queries += self._total_queries
        stats_row.blocked_queries += self._blocked_queries
        stats_row.allowed_queries += self._allowed_queries
        stats_row.cache_hits += self._cache_hits

        # Update top blocked domains
        for domain, count in self._blocked_domains.items():
            existing_td = await session.execute(
                select(GuardianTopDomainDB).where(
                    GuardianTopDomainDB.domain == domain
                )
            )
            td = existing_td.scalar_one_or_none()
            if td is None:
                td = GuardianTopDomainDB(domain=domain, block_count=0)
                session.add(td)
            td.block_count += count
            td.last_blocked = now.isoformat()

        await session.commit()
        logger.info(
            "Flushed stats: %d total, %d blocked, %d allowed",
            self._total_queries,
            self._blocked_queries,
            self._allowed_queries,
        )

        # Reset period counters
        self._total_queries = 0
        self._blocked_queries = 0
        self._allowed_queries = 0
        self._cache_hits = 0
        self._blocked_domains.clear()

    async def start_flush_loop(self, session_factory) -> None:
        """Start periodic flush loop (call this in the daemon)."""
        self._running = True
        self._flush_task = asyncio.create_task(
            self._flush_loop(session_factory)
        )

    async def stop_flush_loop(self) -> None:
        """Stop the periodic flush loop."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

    async def _flush_loop(self, session_factory) -> None:
        """Periodic flush task."""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            try:
                async with session_factory() as session:
                    await self.flush_to_db(session)
            except Exception as exc:
                logger.error("Stats flush failed: %s", exc)
