"""Configuration for the BİGR Hybrid Inference Router.

Defines routing thresholds, model tiers, and cost parameters for the
L0 (local) / L1 (Haiku) / L2 (Opus) inference stack.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class RouterConfig:
    """Full configuration for the hybrid inference router.

    Attributes:
        ollama_url: Base URL of the local Ollama server.
        local_model: Primary local model for L0 inference.
        local_fallback_model: Smallest/fastest local fallback.
        local_timeout: HTTP timeout for Ollama requests (seconds).
        l1_provider: Cloud provider for L1 tier ("anthropic" or "openai").
        l1_model: Model ID for L1 (Haiku-class).
        l1_api_key: API key for L1 provider.
        l1_cost_per_query: Estimated average cost per L1 query in USD.
        l1_timeout: HTTP timeout for L1 cloud requests (seconds).
        l2_provider: Cloud provider for L2 tier.
        l2_model: Model ID for L2 (Opus-class).
        l2_api_key: API key for L2 provider.
        l2_cost_per_query: Estimated average cost per L2 query in USD.
        l2_timeout: HTTP timeout for L2 cloud requests (seconds).
        escalation_threshold: Confidence below this triggers escalation
            from L0 to L1.
        auto_escalate_types: Query types that bypass L0 and go directly
            to L1 or L2.
        monthly_budget_usd: Maximum cloud spend per calendar month.
        l2_requires_premium: Whether L2 tier requires a premium user plan.
    """

    # Local (L0)
    ollama_url: str = "http://localhost:11434"
    local_model: str = "gemma3:4b"
    local_fallback_model: str = "qwen3:0.6b"
    local_timeout: int = 30

    # Cloud L1 (Haiku)
    l1_provider: str = "anthropic"
    l1_model: str = "claude-haiku-4-5-20251001"
    l1_api_key: str | None = None
    l1_cost_per_query: float = 0.01
    l1_timeout: int = 60

    # Cloud L2 (Opus)
    l2_provider: str = "anthropic"
    l2_model: str = "claude-opus-4-6"
    l2_api_key: str | None = None
    l2_cost_per_query: float = 0.50
    l2_timeout: int = 120

    # Routing thresholds
    escalation_threshold: float = 0.7
    auto_escalate_types: list[str] = field(
        default_factory=lambda: ["incident", "forensic", "cve_analysis"]
    )

    # Cost controls
    monthly_budget_usd: float = 50.0
    l2_requires_premium: bool = True

    @classmethod
    def from_env(cls) -> RouterConfig:
        """Build configuration from environment variables.

        Recognised env vars::

            OLLAMA_URL                - Ollama base URL
            BIGR_DEFAULT_MODEL        - Default local model
            BIGR_FALLBACK_MODEL       - Fallback local model
            BIGR_OLLAMA_TIMEOUT       - Timeout in seconds for Ollama
            BIGR_L1_PROVIDER          - L1 cloud provider
            BIGR_L1_MODEL             - L1 model ID
            BIGR_L1_API_KEY           - L1 API key
            BIGR_L1_COST              - L1 cost per query
            BIGR_L1_TIMEOUT           - L1 timeout in seconds
            BIGR_L2_PROVIDER          - L2 cloud provider
            BIGR_L2_MODEL             - L2 model ID
            BIGR_L2_API_KEY           - L2 API key
            BIGR_L2_COST              - L2 cost per query
            BIGR_L2_TIMEOUT           - L2 timeout in seconds
            BIGR_ESCALATION_THRESHOLD - Confidence escalation threshold
            BIGR_MONTHLY_BUDGET       - Monthly budget in USD
            BIGR_L2_REQUIRES_PREMIUM  - "true"/"false"
            ANTHROPIC_API_KEY         - Fallback API key for Anthropic
        """
        # Resolve API keys: specific vars take precedence, then shared
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        l1_key = os.getenv("BIGR_L1_API_KEY") or anthropic_key
        l2_key = os.getenv("BIGR_L2_API_KEY") or anthropic_key

        return cls(
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            local_model=os.getenv("BIGR_DEFAULT_MODEL", "gemma3:4b"),
            local_fallback_model=os.getenv("BIGR_FALLBACK_MODEL", "qwen3:0.6b"),
            local_timeout=int(os.getenv("BIGR_OLLAMA_TIMEOUT", "30")),
            l1_provider=os.getenv("BIGR_L1_PROVIDER", "anthropic"),
            l1_model=os.getenv(
                "BIGR_L1_MODEL", "claude-haiku-4-5-20251001"
            ),
            l1_api_key=l1_key,
            l1_cost_per_query=float(os.getenv("BIGR_L1_COST", "0.01")),
            l1_timeout=int(os.getenv("BIGR_L1_TIMEOUT", "60")),
            l2_provider=os.getenv("BIGR_L2_PROVIDER", "anthropic"),
            l2_model=os.getenv("BIGR_L2_MODEL", "claude-opus-4-6"),
            l2_api_key=l2_key,
            l2_cost_per_query=float(os.getenv("BIGR_L2_COST", "0.50")),
            l2_timeout=int(os.getenv("BIGR_L2_TIMEOUT", "120")),
            escalation_threshold=float(
                os.getenv("BIGR_ESCALATION_THRESHOLD", "0.7")
            ),
            monthly_budget_usd=float(
                os.getenv("BIGR_MONTHLY_BUDGET", "50.0")
            ),
            l2_requires_premium=os.getenv(
                "BIGR_L2_REQUIRES_PREMIUM", "true"
            ).lower()
            == "true",
        )
