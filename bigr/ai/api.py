"""FastAPI routes for the BİGR AI analysis layer.

Provides REST endpoints for:
    - AI-powered threat analysis (port, network, remediation)
    - Hybrid inference router (L0/L1/L2 tier routing)
    - Router metrics, budget, and configuration
    - Local model status
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from bigr.ai.config import LocalAIConfig
from bigr.ai.local_provider import LocalLLMProvider
from bigr.ai.router import InferenceRouter
from bigr.ai.router_config import RouterConfig
from bigr.ai.router_models import InferenceQuery
from bigr.ai.threat_analyzer import ThreatAnalyzer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai-analysis"])

# ---------------------------------------------------------------------------
# Singleton instances (lazy-initialised)
# ---------------------------------------------------------------------------

_config: LocalAIConfig | None = None
_analyzer: ThreatAnalyzer | None = None
_provider: LocalLLMProvider | None = None
_router: InferenceRouter | None = None
_router_config: RouterConfig | None = None


def _get_config() -> LocalAIConfig:
    global _config
    if _config is None:
        _config = LocalAIConfig.from_env()
    return _config


def _get_analyzer() -> ThreatAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = ThreatAnalyzer(_get_config())
    return _analyzer


def _get_provider() -> LocalLLMProvider:
    global _provider
    if _provider is None:
        _provider = LocalLLMProvider(_get_config())
    return _provider


def _get_router_config() -> RouterConfig:
    global _router_config
    if _router_config is None:
        _router_config = RouterConfig.from_env()
    return _router_config


def _get_router() -> InferenceRouter:
    global _router
    if _router is None:
        _router = InferenceRouter(_get_router_config())
    return _router


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class PortAnalysisRequest(BaseModel):
    """Request body for port risk analysis."""

    port: int = Field(..., ge=1, le=65535, description="Port number to analyse")
    service: str | None = Field(None, description="Detected service name")
    context: dict[str, Any] | None = Field(
        None, description="Extra context (vendor, os, etc.)"
    )


class PortAnalysisResponse(BaseModel):
    """Response for port risk analysis."""

    risk_level: str
    confidence: float
    explanation: str
    remediation: str | None = None
    analyzed_by: str
    cost: float = 0.0
    tier_used: str | None = None
    escalated: bool = False


class NetworkAnalysisRequest(BaseModel):
    """Request body for network fingerprint analysis."""

    fingerprint: dict[str, Any] = Field(
        ..., description="Network fingerprint with open_ports, hostname, etc."
    )


class NetworkAnalysisResponse(BaseModel):
    """Response for network analysis."""

    safety_score: float
    risk_factors: list[str]
    recommendation: str
    analyzed_by: str
    tier_used: str | None = None
    escalated: bool = False


class RemediationRequest(BaseModel):
    """Request body for remediation text generation."""

    port: int | None = None
    service: str | None = None
    risk_level: str | None = None
    explanation: str | None = None


class AIStatusResponse(BaseModel):
    """Response for local AI status check."""

    available: bool
    ollama_url: str
    default_model: str
    fallback_model: str
    loaded_models: list[str]


class AIModelEntry(BaseModel):
    """A single model entry."""

    name: str


class InferenceQueryRequest(BaseModel):
    """Request body for the general inference router endpoint."""

    query_type: str = Field(
        ...,
        description=(
            "Query type: port_analysis, network_analysis, classification, "
            "text_gen, remediation, incident, forensic, cve_analysis"
        ),
    )
    prompt: str = Field(..., description="The prompt text")
    system_prompt: str | None = Field(None, description="Optional system prompt")
    context: dict[str, Any] | None = Field(
        None, description="Additional context"
    )
    preferred_tier: str = Field(
        "auto", description="Tier preference: auto, local, l1, l2"
    )
    max_tier: str = Field(
        "l2", description="Maximum allowed tier: local, l1, l2"
    )
    user_plan: str = Field(
        "free", description="User plan: free, nomad, family"
    )


class InferenceResultResponse(BaseModel):
    """Response from the inference router."""

    content: str
    tier_used: str
    model: str
    confidence: float
    cost_usd: float
    latency_ms: float
    escalated: bool
    escalation_reason: str | None = None
    tokens_used: int = 0


class RouterConfigUpdate(BaseModel):
    """Request body for updating router configuration at runtime."""

    escalation_threshold: float | None = Field(
        None, ge=0.0, le=1.0, description="Escalation confidence threshold"
    )
    monthly_budget_usd: float | None = Field(
        None, ge=0.0, description="Monthly budget in USD"
    )
    l2_requires_premium: bool | None = Field(
        None, description="Whether L2 requires premium plan"
    )


# ---------------------------------------------------------------------------
# Existing routes (updated to use router internally)
# ---------------------------------------------------------------------------


@router.post("/analyze/port", response_model=PortAnalysisResponse)
async def analyze_port(req: PortAnalysisRequest) -> PortAnalysisResponse:
    """Analyse the security risk of an open port.

    Routes through the hybrid inference router (L0 -> L1 escalation).
    """
    inference_router = _get_router()
    result = await inference_router.analyze_port(
        port=req.port,
        service=req.service,
        context=req.context,
    )

    # Parse the result content for structured fields
    import json
    import re

    risk_level = "medium"
    explanation = result.content
    remediation = None

    try:
        json_match = re.search(r"\{[^}]+\}", result.content, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            risk_level = str(parsed.get("risk_level", "medium")).lower()
            if risk_level not in ("safe", "low", "medium", "high", "critical"):
                risk_level = "medium"
            explanation = str(
                parsed.get("explanation", result.content)
            )
            remediation = parsed.get("remediation")
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return PortAnalysisResponse(
        risk_level=risk_level,
        confidence=result.confidence,
        explanation=explanation,
        remediation=remediation,
        analyzed_by=f"{result.tier_used}:{result.model}",
        cost=result.cost_usd,
        tier_used=result.tier_used,
        escalated=result.escalated,
    )


@router.post("/analyze/network", response_model=NetworkAnalysisResponse)
async def analyze_network(
    req: NetworkAnalysisRequest,
) -> NetworkAnalysisResponse:
    """Analyse overall network safety from a device fingerprint.

    Routes through the hybrid inference router.
    """
    inference_router = _get_router()
    result = await inference_router.analyze_network(req.fingerprint)

    # Parse structured fields from result
    import json
    import re

    safety_score = 0.5
    risk_factors: list[str] = []
    recommendation = result.content

    try:
        json_match = re.search(r"\{[^}]+\}", result.content, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            safety_score = min(
                max(float(parsed.get("safety_score", 0.5)), 0.0), 1.0
            )
            factors = parsed.get("risk_factors", [])
            if isinstance(factors, list):
                risk_factors = factors
            elif isinstance(factors, str):
                risk_factors = [factors]
            recommendation = str(
                parsed.get("recommendation", result.content)
            )
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return NetworkAnalysisResponse(
        safety_score=safety_score,
        risk_factors=risk_factors,
        recommendation=recommendation,
        analyzed_by=f"{result.tier_used}:{result.model}",
        tier_used=result.tier_used,
        escalated=result.escalated,
    )


@router.post("/remediate")
async def generate_remediation(req: RemediationRequest) -> dict[str, str]:
    """Generate human-friendly remediation text for a finding."""
    analyzer = _get_analyzer()
    finding = {
        "port": req.port,
        "service": req.service,
        "risk_level": req.risk_level,
        "explanation": req.explanation,
    }
    text = await analyzer.generate_remediation(finding)
    return {"remediation": text}


@router.get("/status", response_model=AIStatusResponse)
async def ai_status() -> AIStatusResponse:
    """Check local AI model status and availability."""
    provider = _get_provider()
    config = _get_config()
    available = await provider.is_available()

    models: list[str] = []
    if available:
        models = await provider.list_models()

    return AIStatusResponse(
        available=available,
        ollama_url=config.ollama_url,
        default_model=config.default_model,
        fallback_model=config.fallback_model,
        loaded_models=models,
    )


@router.get("/models")
async def list_models() -> dict[str, list[str]]:
    """List all models available on the local Ollama instance."""
    provider = _get_provider()
    models = await provider.list_models()
    return {"models": models}


# ---------------------------------------------------------------------------
# New router-aware endpoints
# ---------------------------------------------------------------------------


@router.post("/query", response_model=InferenceResultResponse)
async def route_query(req: InferenceQueryRequest) -> InferenceResultResponse:
    """Route any query through the hybrid inference stack.

    This is the general-purpose entry point for the L0/L1/L2 router.
    The router will automatically determine the optimal tier based on
    query type, confidence, user plan, and budget.
    """
    inference_router = _get_router()
    query = InferenceQuery(
        query_type=req.query_type,
        prompt=req.prompt,
        system_prompt=req.system_prompt,
        context=req.context,
        preferred_tier=req.preferred_tier,
        max_tier=req.max_tier,
        user_plan=req.user_plan,
    )
    result = await inference_router.route(query)
    return InferenceResultResponse(
        content=result.content,
        tier_used=result.tier_used,
        model=result.model,
        confidence=result.confidence,
        cost_usd=result.cost_usd,
        latency_ms=result.latency_ms,
        escalated=result.escalated,
        escalation_reason=result.escalation_reason,
        tokens_used=result.tokens_used,
    )


@router.get("/router/stats")
async def router_stats() -> dict[str, Any]:
    """Return router metrics: tier distribution, costs, avg confidence."""
    inference_router = _get_router()
    return inference_router.metrics.to_dict()


@router.get("/router/budget")
async def router_budget() -> dict[str, Any]:
    """Return budget status: remaining, spent by tier and query type."""
    inference_router = _get_router()
    return inference_router.budget.get_summary()


@router.post("/router/config")
async def update_router_config(req: RouterConfigUpdate) -> dict[str, Any]:
    """Update routing configuration at runtime.

    Only specified fields are updated; others remain unchanged.
    """
    inference_router = _get_router()

    if req.escalation_threshold is not None:
        inference_router.config.escalation_threshold = req.escalation_threshold
        logger.info(
            "Router escalation_threshold updated to %.2f",
            req.escalation_threshold,
        )

    if req.monthly_budget_usd is not None:
        inference_router.config.monthly_budget_usd = req.monthly_budget_usd
        inference_router.budget.monthly_budget = req.monthly_budget_usd
        logger.info(
            "Router monthly_budget updated to $%.2f",
            req.monthly_budget_usd,
        )

    if req.l2_requires_premium is not None:
        inference_router.config.l2_requires_premium = req.l2_requires_premium
        logger.info(
            "Router l2_requires_premium updated to %s",
            req.l2_requires_premium,
        )

    return {
        "status": "updated",
        "escalation_threshold": inference_router.config.escalation_threshold,
        "monthly_budget_usd": inference_router.config.monthly_budget_usd,
        "l2_requires_premium": inference_router.config.l2_requires_premium,
    }


@router.get("/router/status")
async def router_full_status() -> dict[str, Any]:
    """Return full router status including tier availability and budget."""
    inference_router = _get_router()
    return await inference_router.get_status()
