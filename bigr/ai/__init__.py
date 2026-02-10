"""BİGR AI analysis layer -- hybrid local + cloud inference.

This package provides:
    - :class:`LocalLLMProvider`: Ollama-compatible local LLM client.
    - :class:`ThreatAnalyzer`: AI-powered threat analysis.
    - :class:`LocalAIConfig`: Configuration dataclass.
    - Data models: :class:`LocalLLMResponse`, :class:`ClassificationResult`,
      :class:`ThreatAssessment`, :class:`NetworkAssessment`.
    - FastAPI router at ``/api/ai/``.

Quick start::

    from bigr.ai import ThreatAnalyzer, LocalAIConfig

    config = LocalAIConfig.from_env()
    analyzer = ThreatAnalyzer(config)
    result = await analyzer.analyze_port(port=445, service="SMB")
"""

from bigr.ai.config import LocalAIConfig
from bigr.ai.local_provider import LocalLLMProvider
from bigr.ai.models import (
    ClassificationResult,
    LocalLLMResponse,
    NetworkAssessment,
    ThreatAssessment,
)
from bigr.ai.threat_analyzer import ThreatAnalyzer

__all__ = [
    "ClassificationResult",
    "LocalAIConfig",
    "LocalLLMProvider",
    "LocalLLMResponse",
    "NetworkAssessment",
    "ThreatAnalyzer",
    "ThreatAssessment",
]
