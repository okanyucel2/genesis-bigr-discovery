"""Local LLM provider via Ollama API.

Provides zero-cost, zero-internet inference using locally-running models.

Supported models (any Ollama-compatible model works):
    - Gemma 3 1B/4B  (Google, good for classification)
    - Llama 3.2 3B   (Meta, edge-optimised)
    - Phi-4-Mini      (Microsoft, reasoning)
    - Qwen3 0.6B     (smallest, fastest)

All inference is FREE -- zero API cost, zero internet required.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from bigr.ai.config import LocalAIConfig
from bigr.ai.models import ClassificationResult, LocalLLMResponse

logger = logging.getLogger(__name__)


class LocalLLMProvider:
    """Ollama-compatible local LLM client.

    Parameters:
        config: Configuration object.  When *None* a default
            :class:`LocalAIConfig` is used.
    """

    def __init__(self, config: LocalAIConfig | None = None) -> None:
        self.config = config or LocalAIConfig()
        self.base_url = self.config.ollama_url.rstrip("/")
        self.model = self.config.default_model
        self.timeout = self.config.timeout_seconds

    # ------------------------------------------------------------------
    # Core inference
    # ------------------------------------------------------------------

    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 512,
        model: str | None = None,
    ) -> LocalLLMResponse:
        """Generate a text completion via Ollama ``/api/generate``.

        Args:
            prompt: The user prompt.
            system: Optional system prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            model: Override model for this request.

        Returns:
            A :class:`LocalLLMResponse` with the generated text.
        """
        target_model = model or self.model
        payload: dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate", json=payload
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.ConnectError:
            logger.warning(
                "Ollama not reachable at %s -- is it running?", self.base_url
            )
            return LocalLLMResponse(
                content="[ERROR] Ollama not reachable",
                model=target_model,
                provider="local",
            )
        except httpx.HTTPStatusError as exc:
            logger.error("Ollama HTTP error: %s", exc)
            return LocalLLMResponse(
                content=f"[ERROR] Ollama returned {exc.response.status_code}",
                model=target_model,
                provider="local",
            )

        latency = (time.monotonic() - start) * 1000
        content = data.get("response", "")
        tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)

        return LocalLLMResponse(
            content=content.strip(),
            model=target_model,
            provider="local",
            tokens_used=tokens,
            latency_ms=round(latency, 2),
            cost=0.0,
        )

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 512,
        model: str | None = None,
    ) -> LocalLLMResponse:
        """Chat completion via Ollama ``/api/chat`` (OpenAI-compatible format).

        Args:
            messages: List of ``{"role": ..., "content": ...}`` dicts.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            model: Override model for this request.

        Returns:
            A :class:`LocalLLMResponse`.
        """
        target_model = model or self.model
        payload: dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/chat", json=payload
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.ConnectError:
            logger.warning(
                "Ollama not reachable at %s -- is it running?", self.base_url
            )
            return LocalLLMResponse(
                content="[ERROR] Ollama not reachable",
                model=target_model,
                provider="local",
            )
        except httpx.HTTPStatusError as exc:
            logger.error("Ollama HTTP error: %s", exc)
            return LocalLLMResponse(
                content=f"[ERROR] Ollama returned {exc.response.status_code}",
                model=target_model,
                provider="local",
            )

        latency = (time.monotonic() - start) * 1000
        msg = data.get("message", {})
        content = msg.get("content", "")
        tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)

        return LocalLLMResponse(
            content=content.strip(),
            model=target_model,
            provider="local",
            tokens_used=tokens,
            latency_ms=round(latency, 2),
            cost=0.0,
        )

    # ------------------------------------------------------------------
    # Classification helper
    # ------------------------------------------------------------------

    async def classify(
        self, text: str, categories: list[str]
    ) -> ClassificationResult:
        """Classify *text* into one of *categories*.

        Uses a structured prompt designed for small models.  The model is
        asked to return JSON so the result can be parsed deterministically.

        Args:
            text: The text to classify.
            categories: List of valid category labels.

        Returns:
            A :class:`ClassificationResult`.
        """
        categories_str = ", ".join(f'"{c}"' for c in categories)
        system_prompt = (
            "You are a cybersecurity classification assistant. "
            "Respond ONLY with a JSON object, no other text."
        )
        user_prompt = (
            f"Classify the following text into exactly one of these categories: "
            f"[{categories_str}].\n\n"
            f"Text: {text}\n\n"
            f"Respond with a JSON object with these fields:\n"
            f'  "category": one of the allowed categories,\n'
            f'  "confidence": a number between 0.0 and 1.0,\n'
            f'  "reasoning": a brief one-sentence explanation.\n\n'
            f"JSON response:"
        )

        response = await self.generate(
            prompt=user_prompt,
            system=system_prompt,
            temperature=0.05,
            max_tokens=256,
        )

        return self._parse_classification(response, categories)

    # ------------------------------------------------------------------
    # Health / introspection
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Check if Ollama is running and responsive."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """List model names available on the local Ollama instance."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception as exc:
            logger.warning("Failed to list Ollama models: %s", exc)
            return []

    async def pull_model(self, model_name: str) -> bool:
        """Pull a model if not already available.

        This can take a long time for large models.  Uses a generous
        10-minute timeout.
        """
        try:
            async with httpx.AsyncClient(timeout=600) as client:
                resp = await client.post(
                    f"{self.base_url}/api/pull",
                    json={"name": model_name, "stream": False},
                )
                resp.raise_for_status()
                logger.info("Successfully pulled model %s", model_name)
                return True
        except Exception as exc:
            logger.error("Failed to pull model %s: %s", model_name, exc)
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_classification(
        response: LocalLLMResponse, valid_categories: list[str]
    ) -> ClassificationResult:
        """Parse a JSON classification from the model response.

        Falls back gracefully if the model does not return valid JSON.
        """
        raw = response.content.strip()

        # Attempt to extract JSON from the response
        json_match = re.search(r"\{[^}]+\}", raw, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                category = str(parsed.get("category", "")).strip().lower()
                confidence = float(parsed.get("confidence", 0.5))
                reasoning = parsed.get("reasoning")

                # Validate category
                normalised_valid = {c.lower(): c for c in valid_categories}
                if category in normalised_valid:
                    return ClassificationResult(
                        category=normalised_valid[category],
                        confidence=min(max(confidence, 0.0), 1.0),
                        reasoning=reasoning,
                        escalate_to_cloud=confidence < 0.7,
                    )
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        # Fallback: try to find any valid category mentioned in the text
        raw_lower = raw.lower()
        for cat in valid_categories:
            if cat.lower() in raw_lower:
                return ClassificationResult(
                    category=cat,
                    confidence=0.3,
                    reasoning="Extracted from unstructured response",
                    escalate_to_cloud=True,
                )

        # Complete fallback
        return ClassificationResult(
            category=valid_categories[0] if valid_categories else "unknown",
            confidence=0.1,
            reasoning="Failed to parse model output",
            escalate_to_cloud=True,
        )
