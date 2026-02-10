"""Shield API endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from bigr.shield.models import ScanDepth
from bigr.shield.orchestrator import ShieldOrchestrator

router = APIRouter(prefix="/api/shield", tags=["shield"])
orchestrator = ShieldOrchestrator()


@router.post("/scan", status_code=202)
async def start_scan(
    target: str,
    depth: str = "quick",
    modules: list[str] | None = None,
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

    scan = await orchestrator.create_scan(
        target=target, depth=scan_depth, modules=modules
    )

    # Run scan in background — return immediately so frontend can poll
    asyncio.create_task(orchestrator.run_scan(scan.id))

    return JSONResponse(status_code=202, content=scan.to_dict())


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
async def quick_scan(target: str) -> dict:
    """Quick scan - creates, runs, and returns results inline.

    This is a convenience endpoint that runs a quick-depth scan
    and returns the full results in a single request.
    """
    scan = await orchestrator.create_scan(
        target=target, depth=ScanDepth.QUICK
    )

    try:
        await orchestrator.run_scan(scan.id)
    except Exception:
        pass

    return scan.to_dict()
