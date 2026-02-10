"""Firewall API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.firewall.models import FirewallConfig, FirewallRule
from bigr.firewall.service import FirewallService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/firewall", tags=["firewall"])

# Module-level singleton
_service = FirewallService()


@router.get("/status")
async def get_firewall_status(db: AsyncSession = Depends(get_db)) -> dict:
    """Get current firewall status."""
    try:
        status = await _service.get_status(db)
        return status.model_dump()
    except Exception as exc:
        logger.error("Failed to get firewall status: %s", exc)
        raise HTTPException(status_code=500, detail=f"Durum alinamadi: {exc}")


@router.get("/rules")
async def get_firewall_rules(
    rule_type: str | None = Query(default=None),
    active_only: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List firewall rules."""
    try:
        rules = await _service.get_rules(db, rule_type=rule_type, active_only=active_only)
        return {
            "rules": [r.model_dump() for r in rules],
            "total": len(rules),
        }
    except Exception as exc:
        logger.error("Failed to get firewall rules: %s", exc)
        return {"rules": [], "total": 0}


@router.post("/rules")
async def add_firewall_rule(
    rule: FirewallRule,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Add a new firewall rule."""
    try:
        created = await _service.add_rule(rule, db)
        return {
            "status": "ok",
            "rule": created.model_dump(),
            "message": "Kural eklendi.",
        }
    except Exception as exc:
        logger.error("Failed to add firewall rule: %s", exc)
        raise HTTPException(status_code=500, detail=f"Kural eklenemedi: {exc}")


@router.delete("/rules/{rule_id}")
async def remove_firewall_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Remove (deactivate) a firewall rule."""
    try:
        result = await _service.remove_rule(rule_id, db)
        if result["status"] == "error":
            raise HTTPException(status_code=404, detail=result["message"])
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to remove firewall rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail=f"Kural silinemedi: {exc}")


@router.put("/rules/{rule_id}/toggle")
async def toggle_firewall_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Toggle a rule's active state."""
    try:
        toggled = await _service.toggle_rule(rule_id, db)
        if toggled is None:
            raise HTTPException(status_code=404, detail="Kural bulunamadi.")
        return {
            "status": "ok",
            "rule": toggled.model_dump(),
            "message": "Kural durumu degistirildi.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to toggle firewall rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail=f"Kural degistirilemedi: {exc}")


@router.post("/sync/threats")
async def sync_threat_rules(db: AsyncSession = Depends(get_db)) -> dict:
    """Sync firewall rules from threat intelligence."""
    try:
        result = await _service.sync_threat_rules(db)
        return result
    except Exception as exc:
        logger.error("Failed to sync threat rules: %s", exc)
        raise HTTPException(status_code=500, detail=f"Tehdit senkronizasyonu basarisiz: {exc}")


@router.post("/sync/ports")
async def sync_port_rules(db: AsyncSession = Depends(get_db)) -> dict:
    """Sync high-risk port block rules from remediation engine."""
    try:
        result = await _service.sync_port_rules(db)
        return result
    except Exception as exc:
        logger.error("Failed to sync port rules: %s", exc)
        raise HTTPException(status_code=500, detail=f"Port senkronizasyonu basarisiz: {exc}")


@router.get("/events")
async def get_firewall_events(
    limit: int = Query(default=100, le=500),
    action: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get recent firewall events."""
    try:
        events = await _service.get_events(db, limit=limit, action=action)
        return {
            "events": [e.model_dump() for e in events],
            "total": len(events),
        }
    except Exception as exc:
        logger.error("Failed to get firewall events: %s", exc)
        return {"events": [], "total": 0}


@router.get("/config")
async def get_firewall_config() -> dict:
    """Get firewall configuration."""
    config = await _service.get_config()
    return config.model_dump()


@router.put("/config")
async def update_firewall_config(config: FirewallConfig) -> dict:
    """Update firewall configuration."""
    try:
        updated = await _service.update_config(config)
        return {
            "status": "ok",
            "config": updated.model_dump(),
            "message": "Yapilandirma guncellendi.",
        }
    except Exception as exc:
        logger.error("Failed to update firewall config: %s", exc)
        raise HTTPException(status_code=500, detail=f"Yapilandirma guncellenemedi: {exc}")


@router.get("/stats/daily")
async def get_daily_stats(db: AsyncSession = Depends(get_db)) -> dict:
    """Get today's block/allow statistics."""
    try:
        stats = await _service.get_daily_stats(db)
        return stats
    except Exception as exc:
        logger.error("Failed to get daily stats: %s", exc)
        return {"date": "", "blocked": 0, "allowed": 0, "total": 0, "block_rate": 0.0}


@router.post("/adapter/install")
async def install_adapter() -> dict:
    """Install platform-specific firewall adapter."""
    try:
        result = await _service.install_adapter()
        return result
    except Exception as exc:
        logger.error("Failed to install adapter: %s", exc)
        raise HTTPException(status_code=500, detail=f"Adapter yuklenemedi: {exc}")
