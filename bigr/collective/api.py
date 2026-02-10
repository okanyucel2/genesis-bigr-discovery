"""Collective Intelligence API endpoints.

Endpoints:
    POST /api/collective/signal       -- Submit a threat signal
    GET  /api/collective/threats      -- Get community threats (verified only)
    GET  /api/collective/stats        -- Network-wide stats
    GET  /api/collective/contribution -- This agent's contribution status
    POST /api/collective/cleanup      -- Trigger expired signal cleanup
    GET  /api/collective/feed         -- Real-time collective feed
"""

from __future__ import annotations

import hashlib
import os

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.collective.engine import CollectiveEngine
from bigr.collective.models import ThreatSignal
from bigr.core.database import get_db
from bigr.core.settings import settings

router = APIRouter(prefix="/api/collective", tags=["collective-intel"])


def _get_hmac_key() -> str:
    """Get the HMAC key for hashing, generating a default if not set."""
    key = settings.THREAT_HMAC_KEY or os.environ.get("THREAT_HMAC_KEY")
    if not key:
        key = hashlib.sha256(b"bigr-collective-default-key").hexdigest()
    return key


def _get_engine() -> CollectiveEngine:
    """Create a CollectiveEngine with current settings."""
    return CollectiveEngine(
        hmac_key=_get_hmac_key(),
        epsilon=settings.COLLECTIVE_EPSILON,
        k_anonymity=settings.COLLECTIVE_K_ANONYMITY,
    )


@router.post("/signal")
async def submit_signal(
    signal: ThreatSignal,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Submit an anonymized threat signal to the collective network.

    The signal goes through the differential-privacy pipeline:
    1. Randomized response may suppress the signal
    2. Severity gets Laplace noise added
    3. Only agents hashed IDs are stored (never plain text)
    """
    if not settings.COLLECTIVE_ENABLED:
        return JSONResponse(
            {"status": "disabled", "message": "Collective intelligence is disabled"},
            status_code=503,
        )

    engine = _get_engine()
    result = await engine.submit_signal(signal, db)
    return JSONResponse(content=result)


@router.get("/threats")
async def get_threats(
    min_confidence: float = 0.5,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get verified community threat signals.

    Only returns signals that:
    - Meet the k-anonymity threshold (multiple reporters)
    - Have confidence >= min_confidence
    """
    engine = _get_engine()
    threats = await engine.get_community_threats(db, min_confidence=min_confidence)
    return {
        "threats": [t.model_dump() for t in threats],
        "total": len(threats),
        "min_confidence": min_confidence,
    }


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get network-wide collective intelligence statistics.

    Includes active agents, verified threats, monitored subnets,
    and the community protection score.
    """
    engine = _get_engine()
    stats = await engine.get_stats(db)
    return stats.model_dump()


@router.get("/contribution")
async def get_contribution(
    agent_hash: str = "",
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get this agent's contribution status to the collective.

    Args:
        agent_hash: The HMAC-hashed agent ID. If empty, returns zeroes.
    """
    engine = _get_engine()
    status = await engine.get_contribution_status(agent_hash, db)
    return status.model_dump()


@router.post("/cleanup")
async def cleanup(
    max_age_hours: int | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Trigger cleanup of expired collective signals.

    Args:
        max_age_hours: Override the default TTL. If not set, uses
            COLLECTIVE_SIGNAL_TTL_HOURS from settings.
    """
    engine = _get_engine()
    ttl = max_age_hours or settings.COLLECTIVE_SIGNAL_TTL_HOURS
    removed = await engine.cleanup_expired(db, max_age_hours=ttl)
    return {"status": "ok", "removed": removed, "max_age_hours": ttl}


@router.get("/feed")
async def get_feed(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get the real-time collective threat feed.

    Returns the latest verified signals, sorted by most recent.
    """
    engine = _get_engine()
    feed = await engine.get_feed(db, limit=limit)
    return {
        "signals": [s.model_dump() for s in feed],
        "total": len(feed),
    }
