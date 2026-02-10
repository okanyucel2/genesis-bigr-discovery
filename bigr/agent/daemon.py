"""Agent daemon — scan + push cycle with heartbeat and PID management.

Reuses the WatcherDaemon pattern from bigr/watcher.py but pushes results
to a remote cloud API via httpx instead of saving locally.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import httpx

from bigr.agent.queue import OfflineQueue

_DEFAULT_DIR = Path.home() / ".bigr"


def _is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


class AgentDaemon:
    """Remote agent daemon that scans locally and pushes to cloud API.

    Parameters
    ----------
    api_url:
        Base URL of the cloud BİGR Discovery API (e.g. https://bigr-api.onrender.com).
    token:
        Bearer token for authenticating with the cloud API.
    targets:
        List of subnet CIDRs to scan (e.g. ["192.168.1.0/24"]).
    interval_seconds:
        Seconds between scan cycles.
    shield:
        If True, also run shield security modules after discovery.
    bigr_dir:
        Base directory for PID/log files (default: ~/.bigr).
    """

    def __init__(
        self,
        api_url: str,
        token: str,
        targets: list[str],
        interval_seconds: int = 300,
        shield: bool = False,
        bigr_dir: Path | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._token = token
        self._targets = targets
        self._interval = interval_seconds
        self._shield = shield
        self._dir = bigr_dir or _DEFAULT_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._pid_path = self._dir / "agent.pid"
        self._log_path = self._dir / "agent.log"
        self._running = False
        self._logger = self._setup_logger()
        self._queue = OfflineQueue(self._dir / "queue")
        self._client = httpx.Client(
            timeout=60.0,
            headers={"Authorization": f"Bearer {self._token}"},
        )

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(f"bigr.agent.{id(self)}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = RotatingFileHandler(
                self._log_path, maxBytes=5 * 1024 * 1024, backupCount=3,
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            logger.addHandler(handler)
        return logger

    # ------------------------------------------------------------------
    # PID lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the agent daemon. Writes PID and enters scan loop."""
        if self._pid_path.exists():
            try:
                existing = int(self._pid_path.read_text().strip())
            except (ValueError, OSError):
                existing = None
            if existing and _is_process_alive(existing):
                raise RuntimeError(
                    f"Agent already running (PID {existing}). Use 'bigr agent stop'."
                )
            self._pid_path.unlink(missing_ok=True)

        self._pid_path.write_text(str(os.getpid()))
        self._running = True
        self._logger.info(
            "Agent started (PID %d). API: %s, Targets: %s, Interval: %ds",
            os.getpid(), self._api_url, self._targets, self._interval,
        )
        self._run_loop()

    def stop(self) -> None:
        """Stop the daemon and clean up PID file."""
        self._running = False
        self._logger.info("Agent stopped.")
        if self._pid_path.exists():
            try:
                self._pid_path.unlink()
            except OSError:
                pass
        self._client.close()

    def get_status(self) -> dict:
        """Return current agent status from PID file."""
        if not self._pid_path.exists():
            return {"running": False, "message": "Not running (no PID file)."}
        try:
            pid = int(self._pid_path.read_text().strip())
        except (ValueError, OSError):
            return {"running": False, "message": "Invalid PID file."}
        if _is_process_alive(pid):
            return {"running": True, "pid": pid, "message": f"Running (PID {pid})."}
        self._pid_path.unlink(missing_ok=True)
        return {"running": False, "message": "Not running (stale PID cleaned)."}

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    _COMMAND_POLL_INTERVAL = 10  # Check for remote commands every 10s between cycles

    def _run_loop(self) -> None:
        cycle_count = 0
        try:
            while self._running:
                self._run_single_cycle()
                self._send_heartbeat()
                cycle_count += 1
                # Check for updates every 12 cycles (~1 hour at 5min interval)
                if cycle_count % 12 == 0:
                    self._check_for_update()
                # Sleep in small chunks, polling for remote commands in between
                self._interruptible_sleep(self._interval)
        except KeyboardInterrupt:
            self._logger.info("Keyboard interrupt.")
        finally:
            self.stop()

    def _interruptible_sleep(self, total_seconds: int) -> None:
        """Sleep in small chunks, checking for remote commands between chunks."""
        elapsed = 0
        while elapsed < total_seconds and self._running:
            chunk = min(self._COMMAND_POLL_INTERVAL, total_seconds - elapsed)
            time.sleep(chunk)
            elapsed += chunk
            if elapsed < total_seconds and self._running:
                self._poll_and_execute_commands()

    def _run_single_cycle(self) -> None:
        """Execute one scan cycle: drain queue, scan each target, push results."""
        # Detect current network fingerprint (may return None)
        from bigr.agent.network_fingerprint import detect_network_fingerprint

        fingerprint = detect_network_fingerprint()
        if fingerprint:
            self._logger.info(
                "Network: %s (SSID=%s, GW=%s)",
                fingerprint.fingerprint_hash[:12],
                fingerprint.ssid or "wired",
                fingerprint.gateway_ip,
            )

        # Drain any queued items from previous failures
        if self._queue.count() > 0:
            self._logger.info("Draining %d queued items...", self._queue.count())
            sent, failed = self._queue.drain(self._drain_send)
            self._logger.info("Drained: %d sent, %d failed", sent, failed)

        for target in self._targets:
            self._logger.info("Scanning %s ...", target)
            try:
                scan_result = self._scan_target(target)
            except Exception as exc:
                self._logger.error("Scan failed for %s: %s", target, exc)
                continue

            # Inject network fingerprint before pushing
            if fingerprint:
                scan_result["network_fingerprint"] = fingerprint.to_dict()

            try:
                self._push_discovery_results(scan_result)
                self._logger.info(
                    "Pushed %d assets for %s",
                    len(scan_result.get("assets", [])), target,
                )
            except Exception as exc:
                self._logger.warning(
                    "Push failed for %s: %s — queuing for retry", target, exc,
                )
                self._queue.enqueue(scan_result, "discovery")

            if self._shield:
                try:
                    shield_result = self._run_shield(target)
                except Exception as exc:
                    self._logger.error("Shield scan failed for %s: %s", target, exc)
                    continue

                try:
                    self._push_shield_results(shield_result)
                    self._logger.info("Shield pushed for %s", target)
                except Exception as exc:
                    self._logger.warning(
                        "Shield push failed for %s: %s — queuing", target, exc,
                    )
                    self._queue.enqueue(shield_result, "shield")

    def _drain_send(self, payload: dict, payload_type: str) -> None:
        """Send a queued payload. Used by OfflineQueue.drain()."""
        if payload_type == "shield":
            self._push_shield_results(payload)
        else:
            self._push_discovery_results(payload)

    # ------------------------------------------------------------------
    # Scanning (reuses existing bigr modules)
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_target(target: str) -> dict:
        """Run hybrid scan + classify on a target. Returns dict for ingest."""
        from bigr.classifier.bigr_mapper import classify_assets
        from bigr.scanner.hybrid import run_hybrid_scan

        result = run_hybrid_scan(target)
        classify_assets(result.assets, do_fingerprint=True)

        return {
            "target": result.target,
            "scan_method": result.scan_method,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "is_root": result.is_root,
            "assets": [a.to_dict() for a in result.assets],
        }

    @staticmethod
    def _run_shield(target: str) -> dict:
        """Run shield security modules on a target."""
        import asyncio

        from bigr.shield.models import ScanDepth
        from bigr.shield.orchestrator import ShieldOrchestrator

        async def _execute() -> dict:
            orchestrator = ShieldOrchestrator()
            scan = await orchestrator.create_scan(target, depth=ScanDepth.STANDARD)
            result = await orchestrator.run_scan(scan.id)
            return result.to_dict()

        return asyncio.run(_execute())

    # ------------------------------------------------------------------
    # Push to cloud
    # ------------------------------------------------------------------

    def _push_discovery_results(self, scan_result: dict) -> None:
        """POST /api/ingest/discovery with scan results."""
        resp = self._client.post(
            f"{self._api_url}/api/ingest/discovery",
            json=scan_result,
        )
        resp.raise_for_status()

    def _push_shield_results(self, shield_result: dict) -> None:
        """POST /api/ingest/shield with shield results."""
        resp = self._client.post(
            f"{self._api_url}/api/ingest/shield",
            json=shield_result,
        )
        resp.raise_for_status()

    def _send_heartbeat(self) -> None:
        """POST /api/agents/heartbeat. If pending commands, fetch and execute."""
        try:
            resp = self._client.post(
                f"{self._api_url}/api/agents/heartbeat",
                json={"status": "online"},
            )
            resp.raise_for_status()
            data = resp.json()
            self._logger.info("Heartbeat sent.")

            # Check for pending remote commands
            if data.get("pending_commands", 0) > 0:
                self._logger.info(
                    "%d pending command(s) — fetching...", data["pending_commands"],
                )
                self._execute_remote_commands()
        except Exception as exc:
            self._logger.warning("Heartbeat failed: %s", exc)

    def _poll_and_execute_commands(self) -> None:
        """Lightweight check for pending commands between scan cycles."""
        try:
            resp = self._client.get(f"{self._api_url}/api/agents/commands")
            resp.raise_for_status()
            commands = resp.json().get("commands", [])
            if commands:
                self._logger.info(
                    "%d pending command(s) detected between cycles", len(commands),
                )
                for cmd in commands:
                    cmd_id = cmd["id"]
                    cmd_type = cmd["command_type"]
                    params = cmd.get("params", {})
                    self._logger.info("Executing command %s (%s)", cmd_id, cmd_type)
                    self._update_command_status(cmd_id, "ack")
                    if cmd_type == "scan_now":
                        self._execute_scan_command(cmd_id, params)
                    else:
                        self._update_command_status(
                            cmd_id, "failed", {"error": f"Unknown command: {cmd_type}"},
                        )
        except Exception:
            pass  # Silent — this is a background poll

    def _execute_remote_commands(self) -> None:
        """Fetch and execute pending commands from the cloud API."""
        try:
            resp = self._client.get(f"{self._api_url}/api/agents/commands")
            resp.raise_for_status()
            commands = resp.json().get("commands", [])
        except Exception as exc:
            self._logger.warning("Failed to fetch commands: %s", exc)
            return

        for cmd in commands:
            cmd_id = cmd["id"]
            cmd_type = cmd["command_type"]
            params = cmd.get("params", {})
            self._logger.info("Executing command %s (%s)", cmd_id, cmd_type)

            # ACK
            self._update_command_status(cmd_id, "ack")

            if cmd_type == "scan_now":
                self._execute_scan_command(cmd_id, params)
            else:
                self._logger.warning("Unknown command type: %s", cmd_type)
                self._update_command_status(cmd_id, "failed", {"error": f"Unknown command: {cmd_type}"})

    def _execute_scan_command(self, cmd_id: str, params: dict) -> None:
        """Execute a scan_now command: scan targets and push results."""
        targets = params.get("targets", [])
        shield = params.get("shield", False)

        self._update_command_status(cmd_id, "running", {"step": "Starting scan..."})

        try:
            scanned = 0
            errors = []
            for i, target in enumerate(targets):
                step_prefix = f"[{i + 1}/{len(targets)}] " if len(targets) > 1 else ""
                self._logger.info("Remote scan: %s (shield=%s)", target, shield)

                # Discovery phase
                self._update_command_status(
                    cmd_id, "running",
                    {"step": f"{step_prefix}Discovery scan: {target}"},
                )
                try:
                    scan_result = self._scan_target(target)
                    asset_count = len(scan_result.get("assets", []))
                    self._update_command_status(
                        cmd_id, "running",
                        {"step": f"{step_prefix}Pushing {asset_count} assets..."},
                    )
                    self._push_discovery_results(scan_result)
                    scanned += asset_count
                    self._logger.info(
                        "Remote scan pushed %d assets for %s", asset_count, target,
                    )
                except Exception as exc:
                    self._logger.error("Remote scan failed for %s: %s", target, exc)
                    errors.append(f"{target}: {exc}")
                    continue

                # Shield phase
                if shield:
                    self._update_command_status(
                        cmd_id, "running",
                        {"step": f"{step_prefix}Shield security scan: {target}"},
                    )
                    try:
                        shield_result = self._run_shield(target)
                        self._update_command_status(
                            cmd_id, "running",
                            {"step": f"{step_prefix}Pushing shield results..."},
                        )
                        self._push_shield_results(shield_result)
                        self._logger.info("Remote shield pushed for %s", target)
                    except Exception as exc:
                        self._logger.error("Remote shield failed for %s: %s", target, exc)
                        errors.append(f"shield({target}): {exc}")

            result = {"assets_discovered": scanned, "targets_scanned": len(targets)}
            if errors:
                result["errors"] = errors
                if scanned == 0:
                    self._update_command_status(cmd_id, "failed", result)
                else:
                    self._update_command_status(cmd_id, "completed", result)
            else:
                self._update_command_status(cmd_id, "completed", result)
        except Exception as exc:
            self._logger.error("Command %s crashed: %s", cmd_id, exc)
            self._update_command_status(
                cmd_id, "failed", {"error": f"Unexpected error: {exc}"},
            )

    def _update_command_status(
        self, command_id: str, cmd_status: str, result: dict | None = None,
    ) -> None:
        """PATCH command status back to cloud API."""
        try:
            body: dict = {"status": cmd_status}
            if result is not None:
                body["result"] = result
            resp = self._client.patch(
                f"{self._api_url}/api/agents/commands/{command_id}",
                json=body,
            )
            resp.raise_for_status()
        except Exception as exc:
            self._logger.warning("Failed to update command %s: %s", command_id, exc)

    def _check_for_update(self) -> None:
        """Check cloud API for newer agent version and auto-update if available."""
        try:
            from bigr.agent.updater import check_for_update, perform_update

            update_info = check_for_update(self._api_url, self._token)
            if update_info and update_info.get("update_available"):
                self._logger.info(
                    "Update available: %s -> %s",
                    update_info["local_version"],
                    update_info["latest_version"],
                )
                if perform_update():
                    self._logger.info(
                        "Updated to %s. Restart the agent to apply.",
                        update_info["latest_version"],
                    )
                else:
                    self._logger.warning("Auto-update failed.")
        except Exception as exc:
            self._logger.debug("Update check failed: %s", exc)
