"""Data models for the BİGR AI analysis layer.

Defines response types for local LLM inference, classification results,
threat assessments, and network assessments.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Local LLM response types
# ---------------------------------------------------------------------------


@dataclass
class LocalLLMResponse:
    """Unified response from a local Ollama model."""

    content: str
    model: str
    provider: str = "local"
    tokens_used: int = 0
    latency_ms: float = 0.0
    cost: float = 0.0  # Always $0 for local inference
    confidence: float | None = None  # Self-reported confidence if parsed


@dataclass
class ClassificationResult:
    """Result of an AI-powered text classification."""

    category: str
    confidence: float
    reasoning: str | None = None
    escalate_to_cloud: bool = False  # True when local model is uncertain


# ---------------------------------------------------------------------------
# Threat / Network assessment types
# ---------------------------------------------------------------------------


@dataclass
class ThreatAssessment:
    """Assessment of a single port or service risk.

    Attributes:
        risk_level: One of "safe", "low", "medium", "high", "critical".
        confidence: 0.0 to 1.0 confidence in the assessment.
        explanation: Human-friendly description of the risk.
        remediation: Actionable "fix it" guidance (if applicable).
        analyzed_by: Provider and model that produced this result,
            e.g. "local:gemma3:4b" or "cloud:haiku".
        cost: Monetary cost of this analysis (0.0 for local).
    """

    risk_level: str
    confidence: float
    explanation: str
    remediation: str | None = None
    analyzed_by: str = "local"
    cost: float = 0.0


@dataclass
class NetworkAssessment:
    """High-level assessment of a network fingerprint.

    Attributes:
        safety_score: 0.0 (dangerous) to 1.0 (safe).
        risk_factors: List of identified risk factors.
        recommendation: Human-friendly overall recommendation.
        analyzed_by: Provider and model string.
    """

    safety_score: float
    risk_factors: list[str] = field(default_factory=list)
    recommendation: str = ""
    analyzed_by: str = "local"
