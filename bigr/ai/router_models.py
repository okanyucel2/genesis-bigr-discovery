"""Data models for the BİGR Hybrid Inference Router.

Defines the query, result, and metrics types that flow through the
L0/L1/L2 routing pipeline.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Tier constants
# ---------------------------------------------------------------------------

TIER_L0_LOCAL = "L0_local"
TIER_L1_HAIKU = "L1_haiku"
TIER_L2_OPUS = "L2_opus"
TIER_HEURISTIC = "heuristic"


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


@dataclass
class InferenceQuery:
    """A query to be routed through the inference stack.

    Attributes:
        query_type: Semantic type of the query. One of:
            "port_analysis", "network_analysis", "classification",
            "text_gen", "remediation", "incident", "forensic",
            "cve_analysis".
        prompt: The user/system prompt text.
        system_prompt: Optional system prompt for model guidance.
        context: Additional context (port number, fingerprint, etc.).
        preferred_tier: Explicit tier preference. "auto" lets the router
            decide, "local" forces L0, "l1" forces L1, "l2" forces L2.
        max_tier: Maximum tier the router may escalate to.
        user_plan: User's subscription plan. Affects L2 access when
            ``l2_requires_premium`` is enabled. One of "free", "nomad",
            "family".
    """

    query_type: str
    prompt: str
    system_prompt: str | None = None
    context: dict[str, Any] | None = None
    preferred_tier: str = "auto"  # "auto", "local", "l1", "l2"
    max_tier: str = "l2"  # "local", "l1", "l2"
    user_plan: str = "free"  # "free", "nomad", "family"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class InferenceResult:
    """Result from the inference router with full provenance.

    Attributes:
        content: The generated text / analysis result.
        tier_used: Which tier produced this result.
        model: Actual model name used (e.g. "gemma3:4b", "claude-haiku-4-5-20251001").
        confidence: 0.0-1.0 confidence in the result.
        cost_usd: Monetary cost of this inference call.
        latency_ms: Wall-clock time in milliseconds.
        escalated: True if the query was escalated from a lower tier.
        escalation_reason: Why escalation happened (if it did).
        tokens_used: Total tokens consumed (prompt + completion).
    """

    content: str
    tier_used: str
    model: str
    confidence: float
    cost_usd: float
    latency_ms: float
    escalated: bool = False
    escalation_reason: str | None = None
    tokens_used: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "content": self.content,
            "tier_used": self.tier_used,
            "model": self.model,
            "confidence": self.confidence,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "escalated": self.escalated,
            "escalation_reason": self.escalation_reason,
            "tokens_used": self.tokens_used,
        }


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class RouterMetrics:
    """Thread-safe routing decision and cost tracker.

    All mutation methods are protected by a lock so they are safe to call
    from concurrent async tasks.
    """

    total_queries: int = 0
    l0_queries: int = 0
    l1_queries: int = 0
    l2_queries: int = 0
    heuristic_queries: int = 0
    total_cost_usd: float = 0.0
    escalation_count: int = 0
    _confidence_sum: float = field(default=0.0, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record(self, result: InferenceResult) -> None:
        """Record a completed inference result."""
        with self._lock:
            self.total_queries += 1
            self.total_cost_usd += result.cost_usd
            self._confidence_sum += result.confidence

            if result.tier_used == TIER_L0_LOCAL:
                self.l0_queries += 1
            elif result.tier_used == TIER_L1_HAIKU:
                self.l1_queries += 1
            elif result.tier_used == TIER_L2_OPUS:
                self.l2_queries += 1
            elif result.tier_used == TIER_HEURISTIC:
                self.heuristic_queries += 1

            if result.escalated:
                self.escalation_count += 1

    @property
    def avg_confidence(self) -> float:
        """Average confidence across all recorded results."""
        with self._lock:
            if self.total_queries == 0:
                return 0.0
            return round(self._confidence_sum / self.total_queries, 4)

    def get_tier_distribution(self) -> dict[str, float]:
        """Return percentage distribution across tiers.

        Returns:
            Dict with keys "L0", "L1", "L2", "heuristic" and float
            percentage values (0-100).
        """
        with self._lock:
            total = self.total_queries
            if total == 0:
                return {"L0": 0.0, "L1": 0.0, "L2": 0.0, "heuristic": 0.0}
            return {
                "L0": round((self.l0_queries / total) * 100, 1),
                "L1": round((self.l1_queries / total) * 100, 1),
                "L2": round((self.l2_queries / total) * 100, 1),
                "heuristic": round(
                    (self.heuristic_queries / total) * 100, 1
                ),
            }

    def to_dict(self) -> dict[str, Any]:
        """Serialize metrics to a JSON-friendly dictionary."""
        with self._lock:
            return {
                "total_queries": self.total_queries,
                "l0_queries": self.l0_queries,
                "l1_queries": self.l1_queries,
                "l2_queries": self.l2_queries,
                "heuristic_queries": self.heuristic_queries,
                "total_cost_usd": round(self.total_cost_usd, 4),
                "escalation_count": self.escalation_count,
                "avg_confidence": self.avg_confidence,
                "tier_distribution": self.get_tier_distribution(),
            }
