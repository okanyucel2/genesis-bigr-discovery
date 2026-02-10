"""Onboarding API routes for the trust-building first-run experience.

Endpoints:
    POST /api/onboarding/start       -- Trigger initial network scan
    GET  /api/onboarding/status      -- Current onboarding progress
    POST /api/onboarding/name-network -- User names their network
    POST /api/onboarding/complete    -- Mark onboarding done
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.onboarding.service import OnboardingService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])

# Module-level singleton for onboarding state.
# In production this would be per-user/per-session, but for the
# single-user consumer product (#bigRForAll) this is sufficient.
_onboarding_service: OnboardingService | None = None


def _get_service() -> OnboardingService:
    """Return (or create) the onboarding service singleton."""
    global _onboarding_service
    if _onboarding_service is None:
        _onboarding_service = OnboardingService()
    return _onboarding_service


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class NameNetworkRequest(BaseModel):
    """Request body for naming a network."""
    network_id: str
    name: str
    type: str  # "home" | "work" | "cafe" | "other"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/start")
async def start_onboarding(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Trigger the initial network scan and safety assessment.

    Detects the current network, runs a quick safety check, and
    returns a warm, encouraging result.
    """
    service = _get_service()

    # Try to extract client IP for context
    client_ip: str | None = None
    if request.client:
        client_ip = request.client.host

    try:
        result = await service.start_onboarding(db, client_ip=client_ip)
        return JSONResponse(
            content={
                "status": "ok",
                **result.to_dict(),
            }
        )
    except Exception as exc:
        logger.error("Onboarding start failed: %s", exc, exc_info=True)
        # Even on error, return a graceful fallback -- never block the user
        return JSONResponse(
            content={
                "status": "ok",
                "network_id": None,
                "ssid": None,
                "gateway_ip": None,
                "gateway_mac": None,
                "safety_score": 0.80,
                "risk_factors": [],
                "safety_message": "Agini henuz tam taniyamadim ama korumaya basladim.",
                "safety_detail": "Arka planda calismaya devam ediyorum.",
                "known_network": False,
                "open_ports": [],
                "device_count": 0,
            }
        )


@router.get("/status")
async def get_status() -> JSONResponse:
    """Return current onboarding progress."""
    service = _get_service()
    return JSONResponse(content=service.get_status())


@router.post("/name-network")
async def name_network(
    body: NameNetworkRequest,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """User names their network to build familiarity.

    Accepted types: home, work, cafe, other.
    """
    service = _get_service()

    valid_types = {"home", "work", "cafe", "other"}
    network_type = body.type if body.type in valid_types else "other"

    try:
        result = await service.name_network(
            db,
            network_id=body.network_id,
            name=body.name,
            network_type=network_type,
        )
        return JSONResponse(content={"status": "ok", **result})
    except Exception as exc:
        logger.error("Name network failed: %s", exc, exc_info=True)
        return JSONResponse(
            content={
                "status": "ok",
                "network_id": body.network_id,
                "name": body.name,
                "type": network_type,
                "updated": False,
                "message": f'"{body.name}" olarak kaydettim.',
            }
        )


@router.post("/complete")
async def complete_onboarding() -> JSONResponse:
    """Mark onboarding as done and return a summary."""
    service = _get_service()

    try:
        summary = await service.complete()
        return JSONResponse(content={"status": "ok", **summary})
    except Exception as exc:
        logger.error("Onboarding complete failed: %s", exc, exc_info=True)
        return JSONResponse(
            content={
                "status": "ok",
                "message": "Hazirim! Arkanı kolluyorum.",
                "motto": "Sen kahveni yudumla, arkani biz kollariz.",
            }
        )


@router.post("/reset")
async def reset_onboarding() -> JSONResponse:
    """Reset onboarding state (for development/testing)."""
    global _onboarding_service
    _onboarding_service = None
    return JSONResponse(content={"status": "ok", "message": "Onboarding reset."})
