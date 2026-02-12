"""Shield API endpoints."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.shield.models import ScanDepth
from bigr.shield.orchestrator import ShieldOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/shield", tags=["shield"])
orchestrator = ShieldOrchestrator()


_VALID_SENSITIVITY = {"fragile", "cautious", "safe"}


@router.post("/scan", status_code=202)
async def start_scan(
    target: str,
    depth: str = "quick",
    modules: list[str] | None = None,
    sensitivity: str | None = None,
) -> JSONResponse:
    """Start a new Shield scan (async).

    Returns immediately with scan ID. Use GET /api/shield/scan/{scan_id}
    to poll for status and results.
    """
    try:
        scan_depth = ScanDepth(depth)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid depth: '{depth}'. Valid values: quick, standard, deep",
        )

    if sensitivity is not None and sensitivity not in _VALID_SENSITIVITY:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sensitivity: '{sensitivity}'. Valid values: fragile, cautious, safe",
        )

    scan = await orchestrator.create_scan(
        target=target, depth=scan_depth, modules=modules, sensitivity=sensitivity,
    )

    # Run scan in background — return immediately so frontend can poll
    asyncio.create_task(_run_and_persist_certs(scan.id))

    return JSONResponse(status_code=202, content=scan.to_dict())


async def _run_and_persist_certs(scan_id: str) -> None:
    """Run scan and persist any discovered TLS certificates."""
    try:
        scan = await orchestrator.run_scan(scan_id)
    except Exception:
        return

    if scan.certificates:
        from bigr.core import services
        from bigr.core.database import get_session_factory

        try:
            factory = get_session_factory()
            async with factory() as session:
                for cert_data in scan.certificates:
                    try:
                        await services.save_certificate_async(session, cert_data)
                    except Exception:
                        logger.debug("Failed to persist certificate for %s", cert_data.get("ip"))
        except Exception:
            logger.debug("Failed to open DB session for certificate persistence")


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    """Get scan status and results."""
    scan = orchestrator.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return scan.to_dict()


@router.get("/scan/{scan_id}/findings")
async def get_findings(scan_id: str) -> dict:
    """Get all findings for a scan."""
    scan = orchestrator.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "total_findings": len(scan.findings),
        "findings": [f.to_dict() for f in scan.findings],
    }


@router.get("/modules")
async def list_modules() -> dict:
    """List available scan modules and their weights."""
    modules = []
    for name, mod in orchestrator._modules.items():
        modules.append({
            "name": mod.name,
            "weight": mod.weight,
            "available": mod.check_available(),
        })
    return {"modules": modules}


@router.post("/quick")
async def quick_scan(
    target: str,
    sensitivity: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Quick scan - creates, runs, and returns results inline.

    This is a convenience endpoint that runs a quick-depth scan
    and returns the full results in a single request.
    """
    if sensitivity is not None and sensitivity not in _VALID_SENSITIVITY:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sensitivity: '{sensitivity}'. Valid values: fragile, cautious, safe",
        )

    scan = await orchestrator.create_scan(
        target=target, depth=ScanDepth.QUICK, sensitivity=sensitivity,
    )

    try:
        await orchestrator.run_scan(scan.id)
    except Exception:
        pass

    # Persist any TLS certificates discovered during the scan
    if scan.certificates:
        from bigr.core import services

        for cert_data in scan.certificates:
            try:
                await services.save_certificate_async(db, cert_data)
            except Exception:
                logger.debug("Failed to persist certificate for %s", cert_data.get("ip"))

    return scan.to_dict()
