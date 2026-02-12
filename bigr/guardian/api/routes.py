"""Guardian API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/guardian", tags=["guardian"])

# Lazy-initialized components (set by daemon or startup)
_blocklist_manager = None
_rules_manager = None
_stats_tracker = None
_dns_server = None
_health_checker = None


def set_components(blocklist=None, rules=None, stats=None, dns_server=None, health=None):
    """Inject Guardian components (called by daemon on startup)."""
    global _blocklist_manager, _rules_manager, _stats_tracker, _dns_server, _health_checker
    if blocklist is not None:
        _blocklist_manager = blocklist
    if rules is not None:
        _rules_manager = rules
    if stats is not None:
        _stats_tracker = stats
    if dns_server is not None:
        _dns_server = dns_server
    if health is not None:
        _health_checker = health


class AddRuleRequest(BaseModel):
    action: str  # "block" or "allow"
    domain: str
    category: str = "custom"
    reason: str = ""


class AddRuleResponse(BaseModel):
    id: str
    action: str
    domain: str


@router.get("/status")
async def guardian_status():
    """Return Guardian status in ShieldStatus format for frontend."""
    is_running = _dns_server is not None and _dns_server._running

    stats = {}
    if _stats_tracker:
        stats = _stats_tracker.get_stats_summary()

    blocklist_count = 0
    if _blocklist_manager:
        blocklist_count = _blocklist_manager.domain_count

    return {
        "guardian_active": is_running,
        "dns_filtering": is_running,
        "blocked_domains_count": blocklist_count,
        "stats": stats.get("current_period", {}),
        "lifetime_stats": stats.get("lifetime", {}),
    }


@router.get("/stats")
async def guardian_stats():
    """Return detailed query statistics."""
    if _stats_tracker is None:
        return {"error": "Guardian not running", "stats": {}}
    return _stats_tracker.get_stats_summary()


@router.get("/rules")
async def guardian_rules(db: AsyncSession = Depends(get_db)):
    """Return all active custom rules."""
    if _rules_manager is None:
        return {"rules": []}
    rules = await _rules_manager.get_all_rules(db)
    return {"rules": rules, "total": len(rules)}


@router.post("/rules", status_code=201)
async def add_guardian_rule(
    body: AddRuleRequest,
    db: AsyncSession = Depends(get_db),
) -> AddRuleResponse:
    """Add a new custom rule."""
    if _rules_manager is None:
        raise HTTPException(status_code=503, detail="Guardian not running")

    try:
        rule_id = await _rules_manager.add_rule(
            session=db,
            action=body.action,
            domain=body.domain,
            category=body.category,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return AddRuleResponse(id=rule_id, action=body.action, domain=body.domain)


@router.delete("/rules/{rule_id}")
async def delete_guardian_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete (deactivate) a custom rule."""
    if _rules_manager is None:
        raise HTTPException(status_code=503, detail="Guardian not running")

    removed = await _rules_manager.remove_rule(db, rule_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted", "id": rule_id}


@router.post("/blocklist/update")
async def update_blocklists(db: AsyncSession = Depends(get_db)):
    """Trigger manual blocklist update."""
    if _blocklist_manager is None:
        raise HTTPException(status_code=503, detail="Guardian not running")

    results = await _blocklist_manager.update_all_blocklists(db)
    return {"status": "updated", "results": results}


@router.get("/blocklists")
async def list_blocklists(db: AsyncSession = Depends(get_db)):
    """Return configured blocklist sources and their status."""
    from sqlalchemy import select
    from bigr.guardian.models import GuardianBlocklistDB

    result = await db.execute(select(GuardianBlocklistDB))
    rows = result.scalars().all()
    return {
        "blocklists": [
            {
                "id": bl.id,
                "name": bl.name,
                "url": bl.url,
                "format": bl.format,
                "category": bl.category,
                "domain_count": bl.domain_count,
                "is_enabled": bl.is_enabled,
                "last_updated": bl.last_updated,
            }
            for bl in rows
        ]
    }


@router.get("/health")
async def guardian_health():
    """Return Guardian health status."""
    if _health_checker is None:
        return {
            "status": "offline",
            "checks": {},
            "message": "Guardian not running",
        }
    return await _health_checker.check_all()
