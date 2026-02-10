"""FastAPI routes for the BİGR AI analysis layer.

Provides REST endpoints for local AI-powered threat analysis,
network assessment, remediation text generation, and model status.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from bigr.ai.config import LocalAIConfig
from bigr.ai.local_provider import LocalLLMProvider
from bigr.ai.threat_analyzer import ThreatAnalyzer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai-analysis"])

# ---------------------------------------------------------------------------
# Singleton instances (lazy-initialised)
# ---------------------------------------------------------------------------

_config: LocalAIConfig | None = None
_analyzer: ThreatAnalyzer | None = None
_provider: LocalLLMProvider | None = None


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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/analyze/port", response_model=PortAnalysisResponse)
async def analyze_port(req: PortAnalysisRequest) -> PortAnalysisResponse:
    """Analyse the security risk of an open port.

    Uses local AI first, with heuristic fallback if Ollama is unavailable.
    """
    analyzer = _get_analyzer()
    assessment = await analyzer.analyze_port(
        port=req.port,
        service=req.service,
        context=req.context,
    )
    return PortAnalysisResponse(
        risk_level=assessment.risk_level,
        confidence=assessment.confidence,
        explanation=assessment.explanation,
        remediation=assessment.remediation,
        analyzed_by=assessment.analyzed_by,
        cost=assessment.cost,
    )


@router.post("/analyze/network", response_model=NetworkAnalysisResponse)
async def analyze_network(
    req: NetworkAnalysisRequest,
) -> NetworkAnalysisResponse:
    """Analyse overall network safety from a device fingerprint."""
    analyzer = _get_analyzer()
    assessment = await analyzer.analyze_network(req.fingerprint)
    return NetworkAnalysisResponse(
        safety_score=assessment.safety_score,
        risk_factors=assessment.risk_factors,
        recommendation=assessment.recommendation,
        analyzed_by=assessment.analyzed_by,
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
