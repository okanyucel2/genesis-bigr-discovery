"""Remediation and Dead Man Switch API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.remediation.deadman import DeadManSwitch
from bigr.remediation.engine import RemediationEngine
from bigr.remediation.models import DeadManSwitchConfig

logger = logging.getLogger(__name__)

router = APIRouter(tags=["remediation"])

# Module-level singletons
_engine = RemediationEngine()
_deadman = DeadManSwitch()


# ---------------------------------------------------------------------------
# Remediation endpoints
# ---------------------------------------------------------------------------


@router.get("/api/remediation/plan/{ip}")
async def get_remediation_plan(
    ip: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get remediation plan for a specific asset."""
    try:
        plan = await _engine.generate_plan(ip, db)
        return plan.model_dump()
    except Exception as exc:
        logger.error("Failed to generate remediation plan for %s: %s", ip, exc)
        raise HTTPException(status_code=500, detail=f"Plan olusturulamadi: {exc}")


@router.get("/api/remediation/plan")
async def get_network_remediation_plan(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get network-wide remediation plan."""
    try:
        plan = await _engine.generate_network_plan(db)
        return plan.model_dump()
    except Exception as exc:
        logger.error("Failed to generate network remediation plan: %s", exc)
        raise HTTPException(status_code=500, detail=f"Ag plani olusturulamadi: {exc}")


@router.post("/api/remediation/execute/{action_id}")
async def execute_remediation(
    action_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Execute a remediation action.

    Creates an agent command for auto-fixable actions, or marks
    as manual for actions requiring human intervention.
    """
    try:
        result = await _engine.execute_action(action_id, db)
        return result
    except Exception as exc:
        logger.error("Failed to execute remediation %s: %s", action_id, exc)
        raise HTTPException(status_code=500, detail=f"Onarim basarisiz: {exc}")


@router.get("/api/remediation/history")
async def get_remediation_history(
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get past remediation actions."""
    try:
        history = await _engine.get_history(db, limit=limit)
        return {"history": history, "total": len(history)}
    except Exception as exc:
        logger.error("Failed to get remediation history: %s", exc)
        return {"history": [], "total": 0}


# ---------------------------------------------------------------------------
# Dead Man Switch endpoints
# ---------------------------------------------------------------------------


@router.get("/api/deadman/status")
async def get_deadman_status(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get all agents' Dead Man Switch status."""
    try:
        statuses = await _deadman.check_agents(db)
        alive_count = sum(1 for s in statuses if s.is_alive)
        alert_count = sum(1 for s in statuses if s.alert_triggered)

        return {
            "statuses": [s.model_dump() for s in statuses],
            "total_agents": len(statuses),
            "alive_count": alive_count,
            "alert_count": alert_count,
            "config": _deadman.config.model_dump(),
            "summary_tr": (
                f"{alive_count} ajan aktif, {alert_count} ajan sessiz."
                if statuses
                else "Kayitli ajan bulunamadi."
            ),
        }
    except Exception as exc:
        logger.error("Dead man switch check failed: %s", exc)
        return {
            "statuses": [],
            "total_agents": 0,
            "alive_count": 0,
            "alert_count": 0,
            "config": _deadman.config.model_dump(),
            "summary_tr": "Kontrol basarisiz.",
        }


@router.get("/api/deadman/status/{agent_id}")
async def get_deadman_agent_status(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get Dead Man Switch status for a specific agent."""
    status = await _deadman.get_status(agent_id, db)
    if status is None:
        raise HTTPException(status_code=404, detail="Ajan bulunamadi.")
    return status.model_dump()


@router.put("/api/deadman/config")
async def update_deadman_config(
    config: DeadManSwitchConfig,
) -> dict:
    """Update Dead Man Switch configuration."""
    await _deadman.update_config(config)
    return {
        "status": "ok",
        "config": _deadman.config.model_dump(),
        "message_tr": "Olum Anahtari yapilandirmasi guncellendi.",
    }


@router.post("/api/deadman/check")
async def force_deadman_check(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Force check all agents now.

    Useful for immediate status verification after incident response.
    """
    try:
        statuses = await _deadman.check_agents(db)
        alerts = [s for s in statuses if s.alert_triggered]

        return {
            "status": "ok",
            "checked": len(statuses),
            "alerts_triggered": len(alerts),
            "alerts": [s.model_dump() for s in alerts],
            "message_tr": (
                f"Kontrol tamamlandi. {len(alerts)} ajan sessiz."
                if alerts
                else "Kontrol tamamlandi. Tum ajanlar aktif."
            ),
        }
    except Exception as exc:
        logger.error("Force dead man check failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Kontrol basarisiz: {exc}")
