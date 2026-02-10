"""Monthly AI spending budget manager for the BİGR inference router.

Tracks per-tier, per-query-type spending and enforces a configurable
monthly cap. Thread-safe via a simple lock.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class _SpendEvent:
    """Internal record of a single spending event."""

    amount: float
    tier: str
    query_type: str
    timestamp: datetime


@dataclass
class BudgetManager:
    """Tracks and enforces monthly AI spending limits.

    Parameters:
        monthly_budget: Maximum spend allowed per calendar month (USD).
    """

    monthly_budget: float = 50.0
    _current_month_spend: float = field(default=0.0, repr=False)
    _month_start: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ),
        repr=False,
    )
    _events: list[_SpendEvent] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ------------------------------------------------------------------
    # Month boundary
    # ------------------------------------------------------------------

    def _maybe_reset_month(self) -> None:
        """Reset counters if the calendar month has changed.

        Must be called while ``_lock`` is held.
        """
        now = datetime.now(timezone.utc)
        current_month_start = now.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        if current_month_start > self._month_start:
            logger.info(
                "Budget month rolled over. Previous spend: $%.4f",
                self._current_month_spend,
            )
            self._current_month_spend = 0.0
            self._month_start = current_month_start
            self._events.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def can_spend(self, amount: float) -> bool:
        """Check if spending *amount* USD is within the monthly budget.

        Also handles month rollover.

        Args:
            amount: The cost to check against remaining budget.

        Returns:
            True if the spend is allowed, False otherwise.
        """
        with self._lock:
            self._maybe_reset_month()
            return (self._current_month_spend + amount) <= self.monthly_budget

    def record_spend(self, amount: float, tier: str, query_type: str) -> None:
        """Record a completed spend event.

        Args:
            amount: Cost in USD.
            tier: The tier that was used (e.g. "L1_haiku").
            query_type: The type of query (e.g. "port_analysis").
        """
        if amount <= 0:
            return

        with self._lock:
            self._maybe_reset_month()
            self._current_month_spend += amount
            self._events.append(
                _SpendEvent(
                    amount=amount,
                    tier=tier,
                    query_type=query_type,
                    timestamp=datetime.now(timezone.utc),
                )
            )
            logger.debug(
                "Budget: recorded $%.6f for %s/%s (total: $%.4f / $%.2f)",
                amount,
                tier,
                query_type,
                self._current_month_spend,
                self.monthly_budget,
            )

    def get_remaining(self) -> float:
        """Return the remaining budget for the current month (USD)."""
        with self._lock:
            self._maybe_reset_month()
            return round(
                max(self.monthly_budget - self._current_month_spend, 0.0), 4
            )

    def get_current_spend(self) -> float:
        """Return total spend so far this month (USD)."""
        with self._lock:
            self._maybe_reset_month()
            return round(self._current_month_spend, 4)

    def get_summary(self) -> dict[str, Any]:
        """Return a spending summary broken down by tier and query type.

        Returns:
            Dict with "monthly_budget", "current_spend", "remaining",
            "by_tier", "by_query_type", and "month_start" keys.
        """
        with self._lock:
            self._maybe_reset_month()

            by_tier: dict[str, float] = defaultdict(float)
            by_query_type: dict[str, float] = defaultdict(float)

            for evt in self._events:
                by_tier[evt.tier] += evt.amount
                by_query_type[evt.query_type] += evt.amount

            return {
                "monthly_budget": self.monthly_budget,
                "current_spend": round(self._current_month_spend, 4),
                "remaining": round(
                    max(
                        self.monthly_budget - self._current_month_spend, 0.0
                    ),
                    4,
                ),
                "by_tier": {
                    k: round(v, 6) for k, v in sorted(by_tier.items())
                },
                "by_query_type": {
                    k: round(v, 6)
                    for k, v in sorted(by_query_type.items())
                },
                "month_start": self._month_start.isoformat(),
                "event_count": len(self._events),
            }
