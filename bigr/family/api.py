"""Family Shield API endpoints for the parent dashboard.

Endpoints:
    GET    /api/family/overview              -- Family overview dashboard data
    GET    /api/family/devices               -- List all family devices
    POST   /api/family/devices               -- Add device to family
    PUT    /api/family/devices/{device_id}   -- Update device info
    DELETE /api/family/devices/{device_id}   -- Remove device
    GET    /api/family/devices/{device_id}   -- Device detail
    GET    /api/family/alerts                -- Family-wide alerts
    GET    /api/family/timeline              -- Activity timeline
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.family.models import (
    AddDeviceRequest,
    FamilyAlert,
    FamilyDevice,
    FamilyOverview,
    FamilyTimelineEntry,
    UpdateDeviceRequest,
)
from bigr.family.service import FamilyService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/family", tags=["family-shield"])

# Module-level singleton
_service: FamilyService | None = None


def _get_service() -> FamilyService:
    """Return (or create) the family service singleton."""
    global _service
    if _service is None:
        _service = FamilyService()
    return _service


@router.get("/overview")
async def family_overview(
    subscription_id: str = Query(..., description="Active subscription ID"),
    db: AsyncSession = Depends(get_db),
) -> FamilyOverview:
    """Get the Family Shield dashboard overview.

    Returns device list with safety scores, online status, threats, etc.
    """
    service = _get_service()
    try:
        return await service.get_overview(subscription_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/devices")
async def list_devices(
    subscription_id: str = Query(..., description="Active subscription ID"),
    db: AsyncSession = Depends(get_db),
) -> list[FamilyDevice]:
    """List all devices in the family group."""
    service = _get_service()
    try:
        overview = await service.get_overview(subscription_id, db)
        return overview.devices
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/devices", status_code=201)
async def add_device(
    body: AddDeviceRequest,
    subscription_id: str = Query(..., description="Active subscription ID"),
    db: AsyncSession = Depends(get_db),
) -> FamilyDevice:
    """Add a new device to the family group.

    Enforces the plan device limit (Family Shield = 5).
    """
    service = _get_service()
    try:
        return await service.add_device(subscription_id, body, db)
    except ValueError as exc:
        error_msg = str(exc)
        if "limiti" in error_msg or "limit" in error_msg.lower():
            raise HTTPException(status_code=400, detail=error_msg)
        raise HTTPException(status_code=404, detail=error_msg)


@router.put("/devices/{device_id}")
async def update_device(
    device_id: str,
    body: UpdateDeviceRequest,
    db: AsyncSession = Depends(get_db),
) -> FamilyDevice:
    """Update a family device's name, type, or owner."""
    service = _get_service()
    try:
        return await service.update_device(device_id, body, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/devices/{device_id}")
async def remove_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Remove a device from the family group (soft delete)."""
    service = _get_service()
    try:
        return await service.remove_device(device_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/devices/{device_id}")
async def device_detail(
    device_id: str,
    db: AsyncSession = Depends(get_db),
) -> FamilyDevice:
    """Get detailed info for a single family device."""
    service = _get_service()
    try:
        return await service.get_device_detail(device_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/alerts")
async def family_alerts(
    subscription_id: str = Query(..., description="Active subscription ID"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[FamilyAlert]:
    """Get recent alerts across all family devices."""
    service = _get_service()
    try:
        return await service.get_family_alerts(subscription_id, db, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/timeline")
async def family_timeline(
    subscription_id: str = Query(..., description="Active subscription ID"),
    limit: int = Query(30, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> list[FamilyTimelineEntry]:
    """Get activity timeline across all family devices."""
    service = _get_service()
    try:
        return await service.get_family_timeline(subscription_id, db, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
