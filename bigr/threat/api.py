"""Threat Intelligence API endpoints."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db, get_session_factory
from bigr.threat.ingestor import ThreatIngestor
from bigr.threat.models import ThreatFeedDB

router = APIRouter(prefix="/api/threat", tags=["threat-intel"])


def _get_hmac_key() -> str:
    """Get the HMAC key for IP hashing, generating a default if not set."""
    key = os.environ.get("THREAT_HMAC_KEY")
    if not key:
        # Use a deterministic default derived from a fixed seed.
        # In production, THREAT_HMAC_KEY should be set explicitly.
        import hashlib

        key = hashlib.sha256(b"bigr-threat-default-key").hexdigest()
    return key


def _get_ingestor() -> ThreatIngestor:
    """Create a ThreatIngestor instance with current settings."""
    return ThreatIngestor(
        session_factory=get_session_factory(),
        hmac_key=_get_hmac_key(),
        otx_api_key=os.environ.get("OTX_API_KEY"),
        expiry_days=int(os.environ.get("THREAT_EXPIRY_DAYS", "90")),
    )


@router.get("/feeds")
async def list_feeds(db: AsyncSession = Depends(get_db)) -> dict:
    """List all registered threat feeds with sync status."""
    stmt = select(ThreatFeedDB).order_by(ThreatFeedDB.name)
    result = await db.execute(stmt)
    feeds = result.scalars().all()

    return {
        "feeds": [
            {
                "id": f.id,
                "name": f.name,
                "feed_url": f.feed_url,
                "feed_type": f.feed_type,
                "enabled": bool(f.enabled),
                "last_synced_at": f.last_synced_at,
                "entries_count": f.entries_count,
                "created_at": f.created_at,
                "updated_at": f.updated_at,
            }
            for f in feeds
        ],
        "total": len(feeds),
    }


@router.post("/feeds/sync")
async def sync_all_feeds() -> JSONResponse:
    """Trigger sync of all enabled threat feeds.

    This may take several minutes depending on feed sizes.
    Returns a summary of sync results.
    """
    ingestor = _get_ingestor()

    try:
        result = await ingestor.sync_all_feeds()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Feed sync failed: {exc}",
        )

    return JSONResponse(content=result)


@router.post("/feeds/{name}/sync")
async def sync_single_feed(name: str) -> JSONResponse:
    """Sync a single threat feed by name.

    Args:
        name: The feed name (e.g., "firehol_level1", "cins_army").
    """
    ingestor = _get_ingestor()

    # Verify feed exists
    async with ingestor.session_factory() as session:
        stmt = select(ThreatFeedDB).where(ThreatFeedDB.name == name)
        result = await session.execute(stmt)
        feed = result.scalar_one_or_none()

    if feed is None:
        raise HTTPException(
            status_code=404,
            detail=f"Feed '{name}' not found. Use GET /api/threat/feeds to list available feeds.",
        )

    try:
        result = await ingestor.sync_feed(name)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Feed sync failed: {exc}",
        )

    return JSONResponse(content=result)


@router.get("/lookup/{ip}")
async def lookup_ip(ip: str) -> dict:
    """Look up threat score for an IP's /24 subnet.

    Args:
        ip: The IP address to look up. The response will be for its /24 subnet.

    Returns:
        Threat indicator data or 404 if no threat data exists.
    """
    # Validate IP
    import ipaddress

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IP address: {ip}",
        )

    ingestor = _get_ingestor()
    result = await ingestor.lookup_subnet(ip)

    if result is None:
        return {
            "ip": ip,
            "threat_score": 0.0,
            "status": "clean",
            "message": "No threat data found for this subnet.",
        }

    return {
        "ip": ip,
        "status": "flagged",
        **result,
    }


@router.get("/stats")
async def threat_stats() -> dict:
    """Return overall threat intelligence statistics.

    Includes total indicators, feed counts, score distribution, and coverage.
    """
    ingestor = _get_ingestor()

    try:
        stats = await ingestor.get_stats()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get stats: {exc}",
        )

    return stats
