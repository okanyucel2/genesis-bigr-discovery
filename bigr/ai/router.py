"""Hybrid Inference Router -- the central routing engine for BİGR AI.

Routes AI queries to the optimal tier based on complexity, confidence,
and user plan:

    L0 (Local, Free)  -- Ollama on-device models. Simple classifications,
                         port risk checks.  Always tried first.
    L1 (Cloud Haiku)   -- False positive validation, enriched remediation.
                         ~$0.01 per query.
    L2 (Cloud Opus)    -- Deep forensic analysis, incident response.
                         ~$0.50 per query.  Premium users only.

Design goals:
    - 80%+ of queries stay local (L0) -- zero cost.
    - Cloud escalation only when local confidence is low.
    - Works fully offline (Ollama unavailable -> heuristic fallback).
    - Cost tracking on every query.
    - Thread-safe metrics.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from bigr.ai.budget import BudgetManager
from bigr.ai.cloud_provider import CloudLLMProvider
from bigr.ai.config import LocalAIConfig
from bigr.ai.local_provider import LocalLLMProvider
from bigr.ai.router_config import RouterConfig
from bigr.ai.router_models import (
    TIER_HEURISTIC,
    TIER_L0_LOCAL,
    TIER_L1_HAIKU,
    TIER_L2_OPUS,
    InferenceQuery,
    InferenceResult,
    RouterMetrics,
)
from bigr.ai.threat_analyzer import ThreatAnalyzer

logger = logging.getLogger(__name__)


class InferenceRouter:
    """Routes AI queries to the optimal tier.

    Routing strategy:

    1. ALL queries start at L0 (local) -- free, fast, private.
    2. If L0 confidence < threshold -- escalate to L1 (Haiku).
    3. L2 (Opus) only for explicit "deep analysis" requests + premium.
    4. If local model unavailable -- fall through to L1 directly.
    5. If no cloud key -- stay on local + heuristics.
    6. If monthly budget exhausted -- refuse L1/L2, fall back to local.

    Parameters:
        config: Router configuration.  When *None* a default
            :class:`RouterConfig` is built from environment variables.
    """

    def __init__(self, config: RouterConfig | None = None) -> None:
        self.config = config or RouterConfig.from_env()

        # L0: local provider via Ollama
        local_cfg = LocalAIConfig(
            ollama_url=self.config.ollama_url,
            default_model=self.config.local_model,
            fallback_model=self.config.local_fallback_model,
            timeout_seconds=self.config.local_timeout,
            escalation_threshold=self.config.escalation_threshold,
        )
        self.local = LocalLLMProvider(local_cfg)

        # Threat analyzer for heuristic fallbacks
        self._threat_analyzer = ThreatAnalyzer(local_cfg)

        # L1: cloud Haiku provider (created lazily on first use)
        self._l1: CloudLLMProvider | None = None
        # L2: cloud Opus provider (created lazily on first use)
        self._l2: CloudLLMProvider | None = None

        # Budget manager
        self.budget = BudgetManager(
            monthly_budget=self.config.monthly_budget_usd
        )

        # Metrics
        self.metrics = RouterMetrics()

    # ------------------------------------------------------------------
    # Lazy cloud provider initialization
    # ------------------------------------------------------------------

    def _get_l1(self) -> CloudLLMProvider | None:
        """Return the L1 cloud provider, or None if no API key."""
        if self._l1 is None and self.config.l1_api_key:
            self._l1 = CloudLLMProvider(
                provider=self.config.l1_provider,
                api_key=self.config.l1_api_key,
                model=self.config.l1_model,
                timeout=self.config.l1_timeout,
                cost_per_query=self.config.l1_cost_per_query,
            )
        return self._l1

    def _get_l2(self) -> CloudLLMProvider | None:
        """Return the L2 cloud provider, or None if no API key."""
        if self._l2 is None and self.config.l2_api_key:
            self._l2 = CloudLLMProvider(
                provider=self.config.l2_provider,
                api_key=self.config.l2_api_key,
                model=self.config.l2_model,
                timeout=self.config.l2_timeout,
                cost_per_query=self.config.l2_cost_per_query,
            )
        return self._l2

    # ------------------------------------------------------------------
    # Main routing logic
    # ------------------------------------------------------------------

    async def route(self, query: InferenceQuery) -> InferenceResult:
        """Route a query to the optimal tier and execute it.

        This is the main entry point for the inference router.

        Args:
            query: The inference query to route.

        Returns:
            An :class:`InferenceResult` with full provenance.
        """
        start = time.monotonic()

        # Determine the effective tier
        tier = self._determine_tier(query)

        logger.info(
            "Routing %s query (preferred=%s, effective=%s, plan=%s)",
            query.query_type,
            query.preferred_tier,
            tier,
            query.user_plan,
        )

        result: InferenceResult

        if tier == "l2":
            result = await self._execute_l2(query, start)
        elif tier == "l1":
            result = await self._execute_l1(query, start, escalated=False)
        elif tier == "local":
            result = await self._execute_local_with_escalation(query, start)
        else:
            # "auto" -- start at L0, escalate as needed
            result = await self._execute_local_with_escalation(query, start)

        self.metrics.record(result)
        return result

    def _determine_tier(self, query: InferenceQuery) -> str:
        """Determine which tier to use for a query.

        Applies these rules in order:
        1. Explicit preferred_tier (if not "auto")
        2. Auto-escalate types go to L1 minimum
        3. L2 requires premium plan (if configured)
        4. Budget enforcement -- refuse cloud if exhausted
        5. Default: "auto" (start at L0)
        """
        preferred = query.preferred_tier

        # Explicit tier request
        if preferred == "l2":
            # Check premium requirement
            if (
                self.config.l2_requires_premium
                and query.user_plan == "free"
            ):
                logger.info(
                    "L2 requested but user plan is free; downgrading to l1"
                )
                preferred = "l1"
            # Check budget
            elif not self.budget.can_spend(self.config.l2_cost_per_query):
                logger.warning("L2 requested but monthly budget exhausted")
                preferred = "l1"
            if preferred == "l2":
                return "l2"

        if preferred == "l1":
            if not self.budget.can_spend(self.config.l1_cost_per_query):
                logger.warning("L1 requested but monthly budget exhausted")
                return "local"
            return "l1"

        if preferred == "local":
            return "local"

        # Auto mode: check auto-escalate types
        if query.query_type in self.config.auto_escalate_types:
            # These types need at least L1
            max_tier = query.max_tier
            if max_tier == "l2" and query.user_plan != "free":
                if self.budget.can_spend(self.config.l2_cost_per_query):
                    return "l2"
            if max_tier in ("l1", "l2"):
                if self.budget.can_spend(self.config.l1_cost_per_query):
                    return "l1"
            # Budget exhausted for auto-escalate -- still try local
            return "local"

        # Default auto: start at local
        return "auto"

    # ------------------------------------------------------------------
    # Tier execution methods
    # ------------------------------------------------------------------

    async def _execute_local_with_escalation(
        self, query: InferenceQuery, start: float
    ) -> InferenceResult:
        """Execute at L0, escalate to L1 if confidence is low.

        If Ollama is unreachable, falls through to L1 directly (if available)
        or to heuristic fallback.
        """
        # Try L0 (local)
        local_available = await self.local.is_available()

        if local_available:
            local_response = await self.local.generate(
                prompt=query.prompt,
                system=query.system_prompt,
                temperature=0.1,
                max_tokens=512,
            )
            latency = (time.monotonic() - start) * 1000

            # Check if local model returned an error
            if local_response.content.startswith("[ERROR]"):
                logger.info(
                    "L0 returned error, escalating: %s",
                    local_response.content[:100],
                )
                return await self._escalate_from_local(
                    query, start, reason="model_unavailable"
                )

            # Extract confidence from response
            confidence = self._extract_confidence(local_response.content)

            # Decide: keep or escalate
            if confidence >= self.config.escalation_threshold:
                return InferenceResult(
                    content=local_response.content,
                    tier_used=TIER_L0_LOCAL,
                    model=local_response.model,
                    confidence=confidence,
                    cost_usd=0.0,
                    latency_ms=round(latency, 2),
                    escalated=False,
                    tokens_used=local_response.tokens_used,
                )
            else:
                logger.info(
                    "L0 confidence %.2f < threshold %.2f, escalating to L1",
                    confidence,
                    self.config.escalation_threshold,
                )
                return await self._escalate_from_local(
                    query, start, reason="low_confidence"
                )
        else:
            # Ollama not available -- try cloud directly
            logger.info("Ollama not available, skipping L0")
            return await self._escalate_from_local(
                query, start, reason="model_unavailable"
            )

    async def _escalate_from_local(
        self, query: InferenceQuery, start: float, reason: str
    ) -> InferenceResult:
        """Escalate from L0 to L1, or fall back to heuristic.

        Args:
            query: The original query.
            start: Monotonic start time for latency tracking.
            reason: Why escalation happened.
        """
        # Check max_tier allows L1
        if query.max_tier == "local":
            return self._heuristic_fallback(query, start, reason)

        # Check budget for L1
        if not self.budget.can_spend(self.config.l1_cost_per_query):
            logger.warning("Budget exhausted, falling back to heuristic")
            return self._heuristic_fallback(query, start, "budget_exhausted")

        l1 = self._get_l1()
        if l1 is None:
            logger.info("No L1 cloud provider configured, using heuristic")
            return self._heuristic_fallback(query, start, reason)

        # Execute on L1
        cloud_resp = await l1.generate(
            prompt=query.prompt,
            system=query.system_prompt,
            temperature=0.1,
            max_tokens=1024,
        )
        latency = (time.monotonic() - start) * 1000

        if cloud_resp.content.startswith("[ERROR]"):
            logger.warning("L1 also failed: %s", cloud_resp.content[:100])
            return self._heuristic_fallback(query, start, reason)

        # Record cost
        self.budget.record_spend(
            cloud_resp.cost_usd, TIER_L1_HAIKU, query.query_type
        )

        confidence = self._extract_confidence(cloud_resp.content)

        return InferenceResult(
            content=cloud_resp.content,
            tier_used=TIER_L1_HAIKU,
            model=cloud_resp.model,
            confidence=max(confidence, 0.75),  # Cloud results get a boost
            cost_usd=cloud_resp.cost_usd,
            latency_ms=round(latency, 2),
            escalated=True,
            escalation_reason=reason,
            tokens_used=cloud_resp.tokens_used,
        )

    async def _execute_l1(
        self,
        query: InferenceQuery,
        start: float,
        escalated: bool = False,
    ) -> InferenceResult:
        """Execute directly on L1 (Haiku).

        Falls back to L0 or heuristic if L1 is not available.
        """
        if not self.budget.can_spend(self.config.l1_cost_per_query):
            logger.warning("Budget exhausted for L1, falling back")
            return await self._execute_local_with_escalation(query, start)

        l1 = self._get_l1()
        if l1 is None:
            logger.info("No L1 provider configured, falling back to L0")
            return await self._execute_local_with_escalation(query, start)

        cloud_resp = await l1.generate(
            prompt=query.prompt,
            system=query.system_prompt,
            temperature=0.1,
            max_tokens=1024,
        )
        latency = (time.monotonic() - start) * 1000

        if cloud_resp.content.startswith("[ERROR]"):
            logger.warning("L1 failed, falling back to L0")
            return await self._execute_local_with_escalation(query, start)

        self.budget.record_spend(
            cloud_resp.cost_usd, TIER_L1_HAIKU, query.query_type
        )

        confidence = self._extract_confidence(cloud_resp.content)

        return InferenceResult(
            content=cloud_resp.content,
            tier_used=TIER_L1_HAIKU,
            model=cloud_resp.model,
            confidence=max(confidence, 0.75),
            cost_usd=cloud_resp.cost_usd,
            latency_ms=round(latency, 2),
            escalated=escalated,
            escalation_reason="user_request" if not escalated else None,
            tokens_used=cloud_resp.tokens_used,
        )

    async def _execute_l2(
        self, query: InferenceQuery, start: float
    ) -> InferenceResult:
        """Execute on L2 (Opus).

        Falls back through L1 -> L0 -> heuristic if L2 is not available.
        """
        # Premium check
        if (
            self.config.l2_requires_premium
            and query.user_plan == "free"
        ):
            logger.info("L2 requires premium, downgrading to L1")
            return await self._execute_l1(
                query, start, escalated=False
            )

        # Budget check
        if not self.budget.can_spend(self.config.l2_cost_per_query):
            logger.warning("Budget exhausted for L2, downgrading to L1")
            return await self._execute_l1(
                query, start, escalated=False
            )

        l2 = self._get_l2()
        if l2 is None:
            logger.info("No L2 provider configured, downgrading to L1")
            return await self._execute_l1(
                query, start, escalated=False
            )

        cloud_resp = await l2.generate(
            prompt=query.prompt,
            system=query.system_prompt,
            temperature=0.1,
            max_tokens=2048,
        )
        latency = (time.monotonic() - start) * 1000

        if cloud_resp.content.startswith("[ERROR]"):
            logger.warning("L2 failed, falling back to L1")
            return await self._execute_l1(
                query, start, escalated=True
            )

        self.budget.record_spend(
            cloud_resp.cost_usd, TIER_L2_OPUS, query.query_type
        )

        confidence = self._extract_confidence(cloud_resp.content)

        return InferenceResult(
            content=cloud_resp.content,
            tier_used=TIER_L2_OPUS,
            model=cloud_resp.model,
            confidence=max(confidence, 0.85),  # Opus results get a high boost
            cost_usd=cloud_resp.cost_usd,
            latency_ms=round(latency, 2),
            escalated=False,
            escalation_reason=None,
            tokens_used=cloud_resp.tokens_used,
        )

    # ------------------------------------------------------------------
    # Heuristic fallback
    # ------------------------------------------------------------------

    def _heuristic_fallback(
        self, query: InferenceQuery, start: float, reason: str
    ) -> InferenceResult:
        """Generate a heuristic response when no model is available.

        Uses context from the query to generate a rule-based response
        when both local and cloud providers are unavailable.
        """
        latency = (time.monotonic() - start) * 1000
        context = query.context or {}

        content: str
        confidence: float

        if query.query_type == "port_analysis":
            port = context.get("port", 0)
            service = context.get("service")
            assessment = ThreatAnalyzer._heuristic_port_assessment(
                port, service
            )
            content = json.dumps(
                {
                    "risk_level": assessment.risk_level,
                    "confidence": assessment.confidence,
                    "explanation": assessment.explanation,
                    "remediation": assessment.remediation,
                }
            )
            confidence = assessment.confidence

        elif query.query_type == "network_analysis":
            open_ports = context.get("open_ports", [])
            assessment = ThreatAnalyzer._heuristic_network_assessment(
                open_ports
            )
            content = json.dumps(
                {
                    "safety_score": assessment.safety_score,
                    "risk_factors": assessment.risk_factors,
                    "recommendation": assessment.recommendation,
                }
            )
            confidence = assessment.safety_score

        elif query.query_type == "remediation":
            content = ThreatAnalyzer._heuristic_remediation(context)
            confidence = 0.6

        else:
            content = (
                "Unable to process this request: no AI model is available "
                "and no heuristic rule matches the query type "
                f"'{query.query_type}'. Please ensure Ollama is running "
                "or configure a cloud API key."
            )
            confidence = 0.1

        return InferenceResult(
            content=content,
            tier_used=TIER_HEURISTIC,
            model="rule-based",
            confidence=confidence,
            cost_usd=0.0,
            latency_ms=round(latency, 2),
            escalated=True,
            escalation_reason=reason,
            tokens_used=0,
        )

    # ------------------------------------------------------------------
    # Confidence extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_confidence(text: str) -> float:
        """Extract a confidence value from model output.

        Tries to parse JSON with a "confidence" field.  Falls back to 0.5
        if the text cannot be parsed.
        """
        try:
            json_match = re.search(r"\{[^}]+\}", text, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                conf = parsed.get("confidence")
                if conf is not None:
                    return min(max(float(conf), 0.0), 1.0)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return 0.5

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    async def analyze_port(
        self,
        port: int,
        service: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> InferenceResult:
        """Route a port analysis query.

        Args:
            port: The port number.
            service: Optional detected service name.
            context: Optional extra context.

        Returns:
            An :class:`InferenceResult`.
        """
        ctx = {"port": port}
        if service:
            ctx["service"] = service
        if context:
            ctx.update(context)

        # Build the same prompt as ThreatAnalyzer
        system = (
            "You are a network security analyst. Assess the risk of an open "
            "port. Respond ONLY with a JSON object. Do not include any other "
            "text."
        )
        from bigr.ai.threat_analyzer import _HIGH_RISK_PORTS, _SAFE_PORTS

        ctx_parts: list[str] = []
        if port in _HIGH_RISK_PORTS:
            ctx_parts.append(f"Known risk: {_HIGH_RISK_PORTS[port]}")
        elif port in _SAFE_PORTS:
            ctx_parts.append(f"Generally safe: {_SAFE_PORTS[port]}")
        if service:
            ctx_parts.append(f"Detected service: {service}")
        if context:
            for k, v in context.items():
                ctx_parts.append(f"{k}: {v}")
        context_str = "; ".join(ctx_parts) if ctx_parts else "No additional context"

        prompt = (
            f"Assess the security risk of port {port} being open on a "
            f"network device.\n\n"
            f"Context: {context_str}\n\n"
            f"Respond with a JSON object:\n"
            f'{{"risk_level": "safe|low|medium|high|critical", '
            f'"confidence": 0.0-1.0, '
            f'"explanation": "human-friendly description", '
            f'"remediation": "what to do about it or null"}}\n\n'
            f"JSON:"
        )

        query = InferenceQuery(
            query_type="port_analysis",
            prompt=prompt,
            system_prompt=system,
            context=ctx,
        )
        return await self.route(query)

    async def analyze_network(
        self, fingerprint: dict[str, Any]
    ) -> InferenceResult:
        """Route a network analysis query.

        Args:
            fingerprint: Dict with keys like ``open_ports``, ``hostname``,
                ``vendor``, ``os_hint``.

        Returns:
            An :class:`InferenceResult`.
        """
        open_ports = fingerprint.get("open_ports", [])
        hostname = fingerprint.get("hostname", "unknown")
        vendor = fingerprint.get("vendor", "unknown")
        os_hint = fingerprint.get("os_hint", "unknown")

        system = (
            "You are a network security analyst. Assess the overall safety "
            "of a network device. Respond ONLY with a JSON object."
        )
        prompt = (
            f"Assess the security posture of this network device:\n"
            f"  Hostname: {hostname}\n"
            f"  Vendor: {vendor}\n"
            f"  OS: {os_hint}\n"
            f"  Open ports: {open_ports}\n\n"
            f"Respond with JSON:\n"
            f'{{"safety_score": 0.0-1.0, '
            f'"risk_factors": ["factor1", ...], '
            f'"recommendation": "overall advice"}}\n\n'
            f"JSON:"
        )

        query = InferenceQuery(
            query_type="network_analysis",
            prompt=prompt,
            system_prompt=system,
            context={"open_ports": open_ports},
        )
        return await self.route(query)

    async def generate_text(
        self,
        prompt: str,
        system: str | None = None,
        tier: str = "auto",
    ) -> InferenceResult:
        """General text generation with tier selection.

        Args:
            prompt: The user prompt.
            system: Optional system prompt.
            tier: "auto", "local", "l1", or "l2".

        Returns:
            An :class:`InferenceResult`.
        """
        query = InferenceQuery(
            query_type="text_gen",
            prompt=prompt,
            system_prompt=system,
            preferred_tier=tier,
        )
        return await self.route(query)

    async def classify(
        self, text: str, categories: list[str]
    ) -> InferenceResult:
        """Classification with automatic escalation.

        Uses the local model's structured classification first.  If
        confidence is low, escalates to L1.

        Args:
            text: Text to classify.
            categories: Valid category labels.

        Returns:
            An :class:`InferenceResult`.
        """
        categories_str = ", ".join(f'"{c}"' for c in categories)
        system = (
            "You are a cybersecurity classification assistant. "
            "Respond ONLY with a JSON object, no other text."
        )
        prompt = (
            f"Classify the following text into exactly one of these "
            f"categories: [{categories_str}].\n\n"
            f"Text: {text}\n\n"
            f'Respond with a JSON object: '
            f'{{"category": "...", "confidence": 0.0-1.0, '
            f'"reasoning": "brief explanation"}}\n\n'
            f"JSON:"
        )

        query = InferenceQuery(
            query_type="classification",
            prompt=prompt,
            system_prompt=system,
            context={"categories": categories},
        )
        return await self.route(query)

    # ------------------------------------------------------------------
    # Status / introspection
    # ------------------------------------------------------------------

    async def get_status(self) -> dict[str, Any]:
        """Return full router status including tier availability.

        Returns:
            Dict with "local", "l1", "l2", "budget", "metrics" keys.
        """
        local_ok = await self.local.is_available()

        l1_status: dict[str, Any] = {"configured": False, "available": False}
        l1 = self._get_l1()
        if l1 is not None:
            l1_status["configured"] = True
            l1_status["model"] = self.config.l1_model
            # Skip availability check for cost reasons (it makes a real API call)

        l2_status: dict[str, Any] = {"configured": False, "available": False}
        l2 = self._get_l2()
        if l2 is not None:
            l2_status["configured"] = True
            l2_status["model"] = self.config.l2_model
            l2_status["requires_premium"] = self.config.l2_requires_premium

        return {
            "local": {
                "available": local_ok,
                "model": self.config.local_model,
                "fallback_model": self.config.local_fallback_model,
                "ollama_url": self.config.ollama_url,
            },
            "l1": l1_status,
            "l2": l2_status,
            "budget": self.budget.get_summary(),
            "metrics": self.metrics.to_dict(),
            "escalation_threshold": self.config.escalation_threshold,
        }
