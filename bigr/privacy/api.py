"""Privacy API — tracker intelligence endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.privacy.tracker_intelligence import (
    get_tracker_stats,
    get_tracker_events,
    get_device_tracker_report,
)

router = APIRouter(prefix="/api/privacy", tags=["privacy"])


@router.get("/stats")
async def privacy_stats(db: AsyncSession = Depends(get_db)):
    """Tracker blocking statistics by category."""
    try:
        stats = await get_tracker_stats(db)
        return stats.to_dict()
    except Exception:
        return {"total_blocked": 0, "by_category": {}, "period": "weekly"}


@router.get("/events")
async def privacy_events(
    limit: int = 20, db: AsyncSession = Depends(get_db)
):
    """Recent tracker blocking events."""
    try:
        events = await get_tracker_events(db, limit=limit)
        return [e.to_dict() for e in events]
    except Exception:
        return []


@router.get("/device/{ip}")
async def privacy_device_report(
    ip: str, db: AsyncSession = Depends(get_db)
):
    """Tracker communication report for a specific device."""
    try:
        report = await get_device_tracker_report(db, ip)
        return report.to_dict()
    except Exception:
        return JSONResponse(
            {"error": "Rapor olusturulamadi"}, status_code=500
        )
