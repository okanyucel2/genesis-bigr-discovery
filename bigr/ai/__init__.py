"""BİGR AI analysis layer -- hybrid local + cloud inference.

This package provides:
    - :class:`InferenceRouter`: Hybrid L0/L1/L2 inference router.
    - :class:`RouterConfig`: Router configuration.
    - :class:`InferenceQuery`, :class:`InferenceResult`: Router I/O models.
    - :class:`RouterMetrics`: Routing metrics tracker.
    - :class:`BudgetManager`: Monthly AI spend tracker.
    - :class:`CloudLLMProvider`: Lightweight Anthropic/cloud client.
    - :class:`LocalLLMProvider`: Ollama-compatible local LLM client.
    - :class:`ThreatAnalyzer`: AI-powered threat analysis.
    - :class:`LocalAIConfig`: Local AI configuration dataclass.
    - Data models: :class:`LocalLLMResponse`, :class:`ClassificationResult`,
      :class:`ThreatAssessment`, :class:`NetworkAssessment`.
    - FastAPI router at ``/api/ai/``.

Quick start::

    from bigr.ai import InferenceRouter, RouterConfig

    config = RouterConfig.from_env()
    router = InferenceRouter(config)
    result = await router.analyze_port(port=445, service="SMB")
    print(result.tier_used, result.confidence, result.cost_usd)
"""

from bigr.ai.budget import BudgetManager
from bigr.ai.cloud_provider import CloudLLMProvider, CloudLLMResponse
from bigr.ai.config import LocalAIConfig
from bigr.ai.local_provider import LocalLLMProvider
from bigr.ai.models import (
    ClassificationResult,
    LocalLLMResponse,
    NetworkAssessment,
    ThreatAssessment,
)
from bigr.ai.router import InferenceRouter
from bigr.ai.router_config import RouterConfig
from bigr.ai.router_models import (
    InferenceQuery,
    InferenceResult,
    RouterMetrics,
)
from bigr.ai.threat_analyzer import ThreatAnalyzer

__all__ = [
    "BudgetManager",
    "ClassificationResult",
    "CloudLLMProvider",
    "CloudLLMResponse",
    "InferenceQuery",
    "InferenceResult",
    "InferenceRouter",
    "LocalAIConfig",
    "LocalLLMProvider",
    "LocalLLMResponse",
    "NetworkAssessment",
    "RouterConfig",
    "RouterMetrics",
    "ThreatAnalyzer",
    "ThreatAssessment",
]
