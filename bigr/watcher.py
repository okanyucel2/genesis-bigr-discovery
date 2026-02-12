"""Watcher daemon for scheduled BİGR scans."""

from __future__ import annotations

import logging
import os
import signal
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Callable

from bigr.alerts.channels import (
    AlertChannel,
    DesktopChannel,
    LogChannel,
    WebhookChannel,
    dispatch_alerts,
)
from bigr.alerts.engine import evaluate_diff
from bigr.diff import diff_scans

_DEFAULT_DIR = Path.home() / ".bigr"
_MAX_SCAN_HISTORY = 100
_MAX_ALERT_HISTORY = 200


@dataclass
class WatcherStatus:
    """Status of the watcher daemon."""

    is_running: bool = False
    pid: int | None = None
    message: str = ""


def get_pid_path() -> Path:
    """Return default PID file path: ~/.bigr/watcher.pid."""
    return _DEFAULT_DIR / "watcher.pid"


def get_log_path() -> Path:
    """Return default log file path: ~/.bigr/watcher.log."""
    return _DEFAULT_DIR / "watcher.log"


def _is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is alive."""
    try:
        os.kill(pid, 0)  # signal 0 = check existence, no actual signal sent
        return True
    except (OSError, ProcessLookupError):
        return False


def get_watcher_status(pid_path: Path | None = None) -> WatcherStatus:
    """Check whether the watcher daemon is currently running.

    Reads the PID file and verifies the process is alive.
    Cleans up stale PID files automatically.
    """
    path = pid_path or get_pid_path()

    if not path.exists():
        return WatcherStatus(is_running=False, message="Not running (no PID file).")

    try:
        pid = int(path.read_text().strip())
    except (ValueError, OSError):
        return WatcherStatus(is_running=False, message="Not running (invalid PID file).")

    if _is_process_alive(pid):
        return WatcherStatus(
            is_running=True,
            pid=pid,
            message=f"Running (PID {pid}).",
        )

    # Stale PID file - process is dead
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return WatcherStatus(is_running=False, message="Not running (stale PID cleaned).")


def build_channels(
    channel_configs: list[dict],
    default_log_path: Path | None = None,
) -> list[AlertChannel]:
    """Build alert channel instances from config dicts.

    Each dict must have a ``type`` key (log, webhook, desktop).
    """
    channels: list[AlertChannel] = []
    for ch in channel_configs:
        ch_type = ch.get("type", "")
        if ch_type == "log":
            path = ch.get("path", str(default_log_path or get_log_path()))
            channels.append(LogChannel(path))
        elif ch_type == "webhook":
            url = ch.get("url", "")
            if url:
                channels.append(WebhookChannel(url))
        elif ch_type == "desktop":
            channels.append(DesktopChannel())
    return channels


class WatcherDaemon:
    """Scheduled scan watcher daemon.

    Manages PID file lifecycle, logging, periodic scan execution,
    alert dispatch on detected changes, and per-target interval scheduling.

    Parameters
    ----------
    targets:
        List of target dicts, each with 'subnet' and 'interval_seconds'.
    bigr_dir:
        Base directory for PID/log files (default: ~/.bigr).
    pid_path:
        Override PID file location.
    log_path:
        Override log file location.
    scan_func:
        Callable that performs a scan given a subnet string.
        If None, uses a default that calls the hybrid scanner.
    db_path:
        Optional database path override.
    channels:
        Alert channels for dispatching scan-diff alerts.
    """

    def __init__(
        self,
        targets: list[dict],
        bigr_dir: Path | None = None,
        pid_path: Path | None = None,
        log_path: Path | None = None,
        scan_func: Callable[[str], Any] | None = None,
        db_path: Path | None = None,
        channels: list[AlertChannel] | None = None,
    ) -> None:
        self._bigr_dir = bigr_dir or _DEFAULT_DIR
        self._bigr_dir.mkdir(parents=True, exist_ok=True)

        self._pid_path = pid_path or (self._bigr_dir / "watcher.pid")
        self._log_path = log_path or (self._bigr_dir / "watcher.log")
        self._targets = targets
        self._scan_func = scan_func or self._default_scan
        self._db_path = db_path
        self._running = False
        self._started_at: float | None = None
        self._logger = self._setup_logger()
        self._channels: list[AlertChannel] = channels or []

        # Per-target scheduling
        self._last_scan_time: dict[str, float] = {}

        # In-memory history (bounded)
        self._scan_history: deque[dict] = deque(maxlen=_MAX_SCAN_HISTORY)
        self._alert_history: deque[dict] = deque(maxlen=_MAX_ALERT_HISTORY)
        self._scan_count = 0

        # Previous scan results for diffing (keyed by subnet)
        self._last_results: dict[str, list[dict]] = {}

    def _setup_logger(self) -> logging.Logger:
        """Configure a rotating file logger."""
        logger = logging.getLogger(f"bigr.watcher.{id(self)}")
        logger.setLevel(logging.INFO)

        # Avoid duplicate handlers if re-created
        if not logger.handlers:
            handler = RotatingFileHandler(
                self._log_path,
                maxBytes=5 * 1024 * 1024,  # 5 MB
                backupCount=3,
            )
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    @staticmethod
    def _default_scan(subnet: str) -> list[dict]:
        """Default scan function - runs hybrid scan + classify + save.

        Returns the list of asset dicts for change detection.
        """
        from bigr.classifier.bigr_mapper import classify_assets
        from bigr.db import save_scan
        from bigr.scanner.hybrid import run_hybrid_scan

        result = run_hybrid_scan(subnet)
        classify_assets(result.assets, do_fingerprint=True)
        save_scan(result)
        return [a.to_dict() if hasattr(a, "to_dict") else a for a in result.assets]

    def _handle_signal(self, signum: int, _frame: Any) -> None:
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        self._logger.info("Signal %d received, stopping...", signum)
        self._running = False

    def _should_scan(self, target: dict) -> bool:
        """Check if a target is due for scanning based on its interval."""
        subnet = target.get("subnet", "")
        interval = target.get("interval_seconds", 300)
        last = self._last_scan_time.get(subnet, 0)
        return (time.time() - last) >= interval

    @property
    def scan_history(self) -> list[dict]:
        """Return scan history as a list (most recent first)."""
        return list(reversed(self._scan_history))

    @property
    def alert_history(self) -> list[dict]:
        """Return alert history as a list (most recent first)."""
        return list(reversed(self._alert_history))

    @property
    def scan_count(self) -> int:
        """Total number of scans performed."""
        return self._scan_count

    @property
    def started_at(self) -> float | None:
        """Unix timestamp when the watcher was started."""
        return self._started_at

    @property
    def targets(self) -> list[dict]:
        """Current scan targets."""
        return list(self._targets)

    def start(self) -> None:
        """Start the watcher. Creates PID file, begins scheduling.

        Raises RuntimeError if another watcher is already running.
        """
        # Check for existing watcher
        if self._pid_path.exists():
            try:
                existing_pid = int(self._pid_path.read_text().strip())
            except (ValueError, OSError):
                existing_pid = None

            if existing_pid is not None and _is_process_alive(existing_pid):
                raise RuntimeError(
                    f"Watcher already running (PID {existing_pid}). "
                    f"Use 'bigr watch --stop' to stop it first."
                )

            # Stale PID file - clean it up
            self._pid_path.unlink(missing_ok=True)

        # Write our PID
        self._pid_path.write_text(str(os.getpid()))
        self._running = True
        self._started_at = time.time()
        self._logger.info("Watcher started (PID %d). Targets: %d", os.getpid(), len(self._targets))

        # Install signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self._run_loop()

    def stop(self) -> None:
        """Stop the watcher and clean up PID file."""
        self._running = False
        self._logger.info("Watcher stopped.")

        if self._pid_path.exists():
            try:
                self._pid_path.unlink()
            except OSError:
                pass

    def _run_loop(self) -> None:
        """Main loop - checks each target's interval and scans when due.

        Override or mock this for testing.
        """
        if not self._targets:
            return

        # Tick interval: check every 5 seconds (or min target interval if shorter)
        min_interval = min(
            t.get("interval_seconds", 300) for t in self._targets
        )
        tick = min(5, min_interval)

        try:
            # Run first cycle immediately
            self._run_single_cycle()
            while self._running:
                time.sleep(tick)
                self._run_single_cycle()
        except KeyboardInterrupt:
            self._logger.info("Keyboard interrupt received.")
        finally:
            self.stop()

    def _run_single_cycle(self) -> None:
        """Execute one scan cycle — only scans targets that are due."""
        for target in self._targets:
            subnet = target.get("subnet", "")
            if not subnet:
                continue

            if not self._should_scan(target):
                continue

            self._logger.info("Scanning %s ...", subnet)
            started_at = datetime.now(timezone.utc)
            asset_count = 0
            changes_count = 0

            try:
                result = self._scan_func(subnet)

                # Extract asset list for diffing
                if isinstance(result, list):
                    current_assets = result
                else:
                    current_assets = []

                asset_count = len(current_assets)
                self._last_scan_time[subnet] = time.time()
                self._scan_count += 1

                # Diff with previous scan and dispatch alerts
                if subnet in self._last_results and current_assets:
                    diff_result = diff_scans(current_assets, self._last_results[subnet])
                    changes_count = len(diff_result.new_assets) + len(diff_result.removed_assets) + len(diff_result.changed_assets)

                    if diff_result.has_changes and self._channels:
                        alerts = evaluate_diff(diff_result)
                        dispatch_alerts(alerts, self._channels)
                        for alert in alerts:
                            self._alert_history.append(alert.to_dict())

                    self._logger.info(
                        "Scan complete for %s: %d assets, %s",
                        subnet,
                        asset_count,
                        diff_result.summary,
                    )
                else:
                    self._logger.info("Scan complete for %s: %d assets (initial scan)", subnet, asset_count)

                # Store for next diff
                if current_assets:
                    self._last_results[subnet] = current_assets

            except Exception as exc:
                self._logger.error("Scan failed for %s: %s", subnet, exc)

            completed_at = datetime.now(timezone.utc)
            self._scan_history.append({
                "subnet": subnet,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "asset_count": asset_count,
                "changes_count": changes_count,
                "status": "completed" if asset_count >= 0 else "failed",
            })
