"""Watcher REST API endpoints."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from bigr.watcher import WatcherDaemon, WatcherStatus, get_watcher_status

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/watcher", tags=["watcher"])

# Shared watcher instance — set by dashboard lifespan or start endpoint.
_watcher: WatcherDaemon | None = None
_watcher_thread: threading.Thread | None = None
_lock = threading.Lock()


def get_watcher() -> WatcherDaemon | None:
    """Return the current watcher instance (if any)."""
    return _watcher


def set_watcher(watcher: WatcherDaemon | None) -> None:
    """Set the shared watcher instance."""
    global _watcher
    _watcher = watcher


@router.get("/status")
async def watcher_status() -> dict:
    """Get watcher daemon status.

    Returns running state, PID, uptime, targets, and scan count.
    """
    # First check PID-file based status
    pid_status: WatcherStatus = get_watcher_status()

    watcher = get_watcher()
    if watcher and watcher._running:
        uptime = time.time() - watcher.started_at if watcher.started_at else 0
        last_scan = None
        history = watcher.scan_history
        if history:
            last_scan = history[0].get("completed_at")

        return {
            "is_running": True,
            "pid": pid_status.pid,
            "uptime_seconds": round(uptime, 1),
            "targets": watcher.targets,
            "last_scan_at": last_scan,
            "scan_count": watcher.scan_count,
        }

    return {
        "is_running": pid_status.is_running,
        "pid": pid_status.pid,
        "uptime_seconds": 0,
        "targets": [],
        "last_scan_at": None,
        "scan_count": 0,
    }


@router.get("/history")
async def watcher_history(
    limit: int = Query(default=20, le=100),
) -> dict:
    """Get recent scan history.

    Returns the last N scans with subnet, timing, asset count, and changes.
    """
    watcher = get_watcher()
    if not watcher:
        return {"scans": [], "total": 0}

    history = watcher.scan_history[:limit]
    return {
        "scans": history,
        "total": len(watcher.scan_history),
    }


@router.get("/alerts")
async def watcher_alerts(
    limit: int = Query(default=50, le=200),
) -> dict:
    """Get recent alert history.

    Returns the last N alerts dispatched by the watcher.
    """
    watcher = get_watcher()
    if not watcher:
        return {"alerts": [], "total": 0}

    alerts = watcher.alert_history[:limit]
    return {
        "alerts": alerts,
        "total": len(watcher.alert_history),
    }


@router.post("/scan-now")
async def scan_now(subnet: str | None = None) -> dict:
    """Trigger an immediate scan.

    If subnet is provided, scans only that subnet.
    Otherwise scans the first configured target.
    """
    watcher = get_watcher()
    if not watcher:
        raise HTTPException(
            status_code=404,
            detail="Watcher calismiyor. Once baslatin.",
        )

    targets = watcher.targets
    if not targets:
        raise HTTPException(
            status_code=400,
            detail="Yapilandirilmis hedef yok.",
        )

    target_subnet = subnet
    if not target_subnet:
        target_subnet = targets[0].get("subnet", "")

    # Reset the last scan time so _should_scan returns True
    watcher._last_scan_time.pop(target_subnet, None)

    # Run one cycle (will pick up the target since we cleared its timer)
    try:
        watcher._run_single_cycle()
    except Exception as exc:
        logger.error("Scan-now failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Tarama basarisiz: {exc}")

    return {"status": "triggered", "subnet": target_subnet}


@router.post("/start")
async def start_watcher() -> dict:
    """Start the watcher daemon in a background thread."""
    global _watcher, _watcher_thread

    with _lock:
        if _watcher and _watcher._running:
            return {"status": "already_running", "message": "Watcher zaten calisiyor."}

        if not _watcher:
            raise HTTPException(
                status_code=400,
                detail="Watcher yapilandirilmamis. Config yukleyin.",
            )

        def _run():
            try:
                _watcher.start()
            except Exception as exc:
                logger.error("Watcher thread error: %s", exc)

        _watcher_thread = threading.Thread(target=_run, daemon=True, name="bigr-watcher")
        _watcher_thread.start()

    return {"status": "started", "message": "Watcher baslatildi."}


@router.post("/stop")
async def stop_watcher() -> dict:
    """Stop the running watcher daemon."""
    watcher = get_watcher()
    if not watcher or not watcher._running:
        return {"status": "not_running", "message": "Watcher zaten durmus."}

    watcher.stop()
    return {"status": "stopped", "message": "Watcher durduruldu."}
