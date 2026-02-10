"""Agent API router — registration, heartbeat, ingest endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.agent.auth import generate_token, hash_token, verify_agent_token
from bigr.agent.models import (
    AgentHeartbeatRequest,
    AgentRegisterRequest,
    AgentRegisterResponse,
    IngestDiscoveryRequest,
    IngestShieldRequest,
)
from bigr.core import services
from bigr.core.database import get_db
from bigr.agent.alerts import alert_critical_finding, alert_service, alert_stale_agent
from bigr.agent.ratelimit import ingest_limiter
from bigr.core.models_db import AgentDB, ShieldFindingDB, ShieldScanDB
from bigr.core.settings import settings

router = APIRouter(tags=["agents"])


def _check_rate_limit(agent: AgentDB) -> None:
    """Raise 429 if agent exceeds ingest rate limit."""
    if not ingest_limiter.check(agent.token_hash):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )


@router.post("/api/agents/register", response_model=AgentRegisterResponse)
async def register_agent(
    body: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> AgentRegisterResponse:
    """Register a new agent and return a one-time plaintext token."""
    # If a registration secret is configured, require it
    if settings.AGENT_REGISTRATION_SECRET:
        if body.secret != settings.AGENT_REGISTRATION_SECRET:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid registration secret.",
            )

    agent_id = str(uuid.uuid4())
    token = generate_token()
    now_iso = datetime.now(timezone.utc).isoformat()

    agent = AgentDB(
        id=agent_id,
        name=body.name,
        site_name=body.site_name,
        location=body.location,
        token_hash=hash_token(token),
        is_active=1,
        registered_at=now_iso,
        status="online",
        subnets=json.dumps(body.subnets) if body.subnets else None,
    )
    db.add(agent)
    await db.commit()

    return AgentRegisterResponse(agent_id=agent_id, token=token)


@router.post("/api/agents/heartbeat")
async def agent_heartbeat(
    body: AgentHeartbeatRequest,
    agent: AgentDB = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update agent last_seen timestamp and status."""
    now_iso = datetime.now(timezone.utc).isoformat()
    values: dict = {"last_seen": now_iso, "status": body.status}
    if body.version:
        values["version"] = body.version
    if body.subnets is not None:
        values["subnets"] = json.dumps(body.subnets)

    stmt = update(AgentDB).where(AgentDB.id == agent.id).values(**values)
    await db.execute(stmt)
    await db.commit()

    return {"status": "ok", "agent_id": agent.id, "last_seen": now_iso}


@router.post("/api/agents/rotate-token")
async def rotate_token(
    agent: AgentDB = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Rotate an agent's bearer token. Returns the new token (shown once)."""
    new_token = generate_token()
    stmt = update(AgentDB).where(AgentDB.id == agent.id).values(
        token_hash=hash_token(new_token),
    )
    await db.execute(stmt)
    await db.commit()
    return {
        "status": "ok",
        "agent_id": agent.id,
        "token": new_token,
        "message": "Token rotated. Update your agent config with the new token.",
    }


@router.get("/api/agents")
async def list_agents(db: AsyncSession = Depends(get_db)) -> dict:
    """List all registered agents with their status."""
    stmt = select(AgentDB).order_by(AgentDB.registered_at)
    result = await db.execute(stmt)
    agents = []
    now = datetime.now(timezone.utc)

    for a in result.scalars().all():
        # Mark stale agents (no heartbeat in 5 minutes)
        effective_status = a.status
        if a.last_seen:
            try:
                last = datetime.fromisoformat(a.last_seen)
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if (now - last).total_seconds() > 300:
                    effective_status = "stale"
                    if a.status != "stale":
                        alert_stale_agent(a.name, a.id, a.last_seen)
            except (ValueError, TypeError):
                pass

        subnets = []
        if a.subnets:
            try:
                subnets = json.loads(a.subnets)
            except (json.JSONDecodeError, TypeError):
                pass

        agents.append({
            "id": a.id,
            "name": a.name,
            "site_name": a.site_name,
            "location": a.location,
            "is_active": bool(a.is_active),
            "registered_at": a.registered_at,
            "last_seen": a.last_seen,
            "status": effective_status,
            "version": a.version,
            "subnets": subnets,
        })

    return {"agents": agents}


@router.post("/api/ingest/discovery")
async def ingest_discovery(
    body: IngestDiscoveryRequest,
    agent: AgentDB = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Accept discovery scan results from a remote agent.

    Delegates to ``save_scan_async`` with agent_id and site_name injected.
    """
    _check_rate_limit(agent)
    scan_dict = {
        "target": body.target,
        "scan_method": body.scan_method,
        "started_at": body.started_at,
        "completed_at": body.completed_at,
        "is_root": body.is_root,
        "assets": body.assets,
        "agent_id": agent.id,
        "site_name": agent.site_name,
    }
    scan_id = await services.save_scan_async(db, scan_dict)

    # Update agent last_seen
    now_iso = datetime.now(timezone.utc).isoformat()
    stmt = update(AgentDB).where(AgentDB.id == agent.id).values(
        last_seen=now_iso, status="online"
    )
    await db.execute(stmt)
    await db.commit()

    return {"status": "ok", "scan_id": scan_id, "assets_ingested": len(body.assets)}


@router.post("/api/ingest/shield")
async def ingest_shield(
    body: IngestShieldRequest,
    agent: AgentDB = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Accept shield scan results from a remote agent.

    Persists to ``shield_scans`` and ``shield_findings`` tables.
    """
    _check_rate_limit(agent)
    scan_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    shield_scan = ShieldScanDB(
        id=scan_id,
        agent_id=agent.id,
        site_name=agent.site_name,
        target=body.target,
        started_at=body.started_at,
        completed_at=body.completed_at or now_iso,
        modules_run=json.dumps(body.modules_run) if body.modules_run else None,
    )
    db.add(shield_scan)

    for finding in body.findings:
        db.add(ShieldFindingDB(
            scan_id=scan_id,
            module=finding.get("module", "unknown"),
            severity=finding.get("severity", "info"),
            title=finding.get("title"),
            detail=finding.get("detail"),
            target_ip=finding.get("target_ip"),
            remediation=finding.get("remediation"),
            raw_data=json.dumps(finding) if finding else None,
        ))

    # Update agent last_seen
    stmt = update(AgentDB).where(AgentDB.id == agent.id).values(
        last_seen=now_iso, status="online"
    )
    await db.execute(stmt)
    await db.commit()

    # Alert on critical findings
    for finding in body.findings:
        if finding.get("severity") in ("critical", "high"):
            alert_critical_finding(
                finding_title=finding.get("title", "Untitled"),
                target=body.target,
                site_name=agent.site_name,
                agent_name=agent.name,
            )

    return {
        "status": "ok",
        "scan_id": scan_id,
        "agent_id": agent.id,
        "modules_received": body.modules_run,
        "findings_count": len(body.findings),
    }


@router.get("/api/alerts")
async def list_alerts(limit: int = Query(default=50, le=200)) -> dict:
    """Return recent alerts from the alert service."""
    return {"alerts": alert_service.recent(limit)}


@router.get("/api/shield-findings")
async def list_shield_findings(
    site: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List agent-ingested shield findings with optional filters."""
    stmt = (
        select(ShieldFindingDB, ShieldScanDB)
        .join(ShieldScanDB, ShieldFindingDB.scan_id == ShieldScanDB.id)
        .order_by(ShieldFindingDB.id.desc())
    )
    if site:
        stmt = stmt.where(ShieldScanDB.site_name == site)
    if severity:
        stmt = stmt.where(ShieldFindingDB.severity == severity)
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    rows = result.all()

    findings = []
    for finding, scan in rows:
        findings.append({
            "id": finding.id,
            "scan_id": finding.scan_id,
            "module": finding.module,
            "severity": finding.severity,
            "title": finding.title,
            "detail": finding.detail,
            "target_ip": finding.target_ip,
            "remediation": finding.remediation,
            "target": scan.target,
            "site_name": scan.site_name,
            "agent_id": scan.agent_id,
            "scanned_at": scan.started_at,
        })

    # Summary counts by severity
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "findings": findings,
        "total": len(findings),
        "severity_counts": severity_counts,
    }


@router.get("/api/agents/version")
async def agent_version() -> dict:
    """Return the latest agent version (used by agents for auto-update check)."""
    from importlib.metadata import version as get_version

    try:
        current = get_version("bigr-discovery")
    except Exception:
        current = "0.1.0"
    return {
        "latest_version": current,
        "message": "",
    }
