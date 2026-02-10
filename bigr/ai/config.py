"""Configuration for the BİGR AI analysis layer.

Centralizes all tunables for local (Ollama) and optional cloud providers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class LocalAIConfig:
    """Configuration for the hybrid local + cloud AI analysis layer.

    Attributes:
        ollama_url: Base URL of the local Ollama server.
        default_model: Primary model to use for local inference.
        fallback_model: Smallest/fastest fallback if default is unavailable.
        timeout_seconds: HTTP timeout for Ollama requests.
        escalation_threshold: Confidence below this triggers cloud escalation.
        max_local_tokens: Maximum tokens for local generation.
        cloud_provider: Optional cloud provider for escalation.
        cloud_api_key: API key for cloud provider (resolved from env if None).
        cloud_model: Cloud model ID used when escalating.
    """

    ollama_url: str = "http://localhost:11434"
    default_model: str = "gemma3:4b"
    fallback_model: str = "qwen3:0.6b"
    timeout_seconds: int = 30
    escalation_threshold: float = 0.7
    max_local_tokens: int = 512

    # Cloud fallback (optional)
    cloud_provider: str | None = None  # "anthropic", "openai"
    cloud_api_key: str | None = None
    cloud_model: str = "claude-haiku-4-5-20251001"

    @classmethod
    def from_env(cls) -> LocalAIConfig:
        """Build configuration from environment variables.

        Recognised env vars:
            OLLAMA_URL          - Ollama base URL
            BIGR_DEFAULT_MODEL  - Default local model
            BIGR_FALLBACK_MODEL - Fallback local model
            BIGR_OLLAMA_TIMEOUT - Timeout in seconds
            BIGR_ESCALATION_THRESHOLD - Confidence threshold
            BIGR_CLOUD_PROVIDER - Cloud provider name
            BIGR_CLOUD_API_KEY  - Cloud API key
            BIGR_CLOUD_MODEL    - Cloud model ID
        """
        return cls(
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            default_model=os.getenv("BIGR_DEFAULT_MODEL", "gemma3:4b"),
            fallback_model=os.getenv("BIGR_FALLBACK_MODEL", "qwen3:0.6b"),
            timeout_seconds=int(os.getenv("BIGR_OLLAMA_TIMEOUT", "30")),
            escalation_threshold=float(
                os.getenv("BIGR_ESCALATION_THRESHOLD", "0.7")
            ),
            cloud_provider=os.getenv("BIGR_CLOUD_PROVIDER"),
            cloud_api_key=os.getenv("BIGR_CLOUD_API_KEY"),
            cloud_model=os.getenv(
                "BIGR_CLOUD_MODEL", "claude-haiku-4-5-20251001"
            ),
        )
