"""Lightweight cloud LLM provider for L1 (Haiku) and L2 (Opus) tiers.

Uses ``httpx`` to call the Anthropic Messages API directly -- no heavy
SDK dependency.  Supports the Anthropic format; OpenAI support can be
added later by extending :meth:`generate`.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Anthropic Messages API constants
# ---------------------------------------------------------------------------

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


@dataclass
class CloudLLMResponse:
    """Response from a cloud LLM provider."""

    content: str
    model: str
    provider: str
    tokens_used: int
    cost_usd: float
    latency_ms: float


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class CloudLLMProvider:
    """Cloud LLM provider for L1 (Haiku) and L2 (Opus) tiers.

    Parameters:
        provider: Provider name ("anthropic").
        api_key: API key for the provider.
        model: Model ID to use.
        timeout: HTTP timeout in seconds.
        cost_per_query: Estimated cost per query for cost tracking.
    """

    def __init__(
        self,
        provider: str,
        api_key: str,
        model: str,
        timeout: int = 60,
        cost_per_query: float = 0.01,
    ) -> None:
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.cost_per_query = cost_per_query

    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> CloudLLMResponse:
        """Call the cloud API and return the response.

        Currently supports the Anthropic Messages API format:

        .. code-block:: text

            POST https://api.anthropic.com/v1/messages
            Headers: x-api-key, anthropic-version, content-type
            Body: { model, max_tokens, system?, messages }

        Args:
            prompt: User message text.
            system: Optional system prompt.
            temperature: Sampling temperature (0.0-1.0).
            max_tokens: Maximum response tokens.

        Returns:
            A :class:`CloudLLMResponse`.
        """
        if self.provider == "anthropic":
            return await self._call_anthropic(
                prompt, system, temperature, max_tokens
            )
        else:
            # Unsupported provider -- return a clear error
            return CloudLLMResponse(
                content=f"[ERROR] Unsupported cloud provider: {self.provider}",
                model=self.model,
                provider=self.provider,
                tokens_used=0,
                cost_usd=0.0,
                latency_ms=0.0,
            )

    async def is_available(self) -> bool:
        """Check whether the cloud API is reachable and the key is valid.

        Sends a minimal request to check connectivity. Returns False on
        any error.
        """
        if not self.api_key:
            return False

        try:
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            }
            payload = {
                "model": self.model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    _ANTHROPIC_API_URL, headers=headers, json=payload
                )
                # 200 = success, 401 = bad key, 400 = model issue
                return resp.status_code == 200
        except Exception as exc:
            logger.debug("Cloud availability check failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Anthropic implementation
    # ------------------------------------------------------------------

    async def _call_anthropic(
        self,
        prompt: str,
        system: str | None,
        temperature: float,
        max_tokens: int,
    ) -> CloudLLMResponse:
        """Call the Anthropic Messages API."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        payload: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    _ANTHROPIC_API_URL, headers=headers, json=payload
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.ConnectError:
            logger.warning("Cloud API not reachable at %s", _ANTHROPIC_API_URL)
            return CloudLLMResponse(
                content="[ERROR] Cloud API not reachable",
                model=self.model,
                provider=self.provider,
                tokens_used=0,
                cost_usd=0.0,
                latency_ms=round((time.monotonic() - start) * 1000, 2),
            )
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            body = ""
            try:
                body = exc.response.json().get("error", {}).get("message", "")
            except Exception:
                pass
            logger.error(
                "Cloud API returned HTTP %d: %s", status, body or str(exc)
            )
            return CloudLLMResponse(
                content=f"[ERROR] Cloud API returned {status}: {body}",
                model=self.model,
                provider=self.provider,
                tokens_used=0,
                cost_usd=0.0,
                latency_ms=round((time.monotonic() - start) * 1000, 2),
            )
        except httpx.TimeoutException:
            logger.warning(
                "Cloud API timed out after %ds for model %s",
                self.timeout,
                self.model,
            )
            return CloudLLMResponse(
                content="[ERROR] Cloud API timed out",
                model=self.model,
                provider=self.provider,
                tokens_used=0,
                cost_usd=0.0,
                latency_ms=round((time.monotonic() - start) * 1000, 2),
            )

        latency = (time.monotonic() - start) * 1000

        # Extract content from Anthropic response
        content_blocks = data.get("content", [])
        content = ""
        for block in content_blocks:
            if block.get("type") == "text":
                content += block.get("text", "")

        # Token usage
        usage = data.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        total_tokens = input_tokens + output_tokens

        # Estimate actual cost from token counts
        # Haiku: ~$0.25/$1.25 per 1M tokens (input/output)
        # Opus: ~$15/$75 per 1M tokens (input/output)
        cost = self._estimate_cost(input_tokens, output_tokens)

        return CloudLLMResponse(
            content=content.strip(),
            model=data.get("model", self.model),
            provider=self.provider,
            tokens_used=total_tokens,
            cost_usd=cost,
            latency_ms=round(latency, 2),
        )

    def _estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost from token counts.

        Uses per-model pricing. Falls back to the configured
        ``cost_per_query`` if the model is not recognized.
        """
        model_lower = self.model.lower()

        # Anthropic pricing (per 1M tokens)
        if "haiku" in model_lower:
            input_rate = 0.25 / 1_000_000
            output_rate = 1.25 / 1_000_000
        elif "sonnet" in model_lower:
            input_rate = 3.0 / 1_000_000
            output_rate = 15.0 / 1_000_000
        elif "opus" in model_lower:
            input_rate = 15.0 / 1_000_000
            output_rate = 75.0 / 1_000_000
        else:
            # Unknown model -- use flat rate
            return self.cost_per_query

        cost = (input_tokens * input_rate) + (output_tokens * output_rate)
        return round(cost, 6)
