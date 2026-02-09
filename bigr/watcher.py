"""Watcher daemon for scheduled BİGR scans."""

from __future__ import annotations

import logging
import os
import signal
import time
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable

_DEFAULT_DIR = Path.home() / ".bigr"


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


class WatcherDaemon:
    """Scheduled scan watcher daemon.

    Manages PID file lifecycle, logging, and periodic scan execution.

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
    """

    def __init__(
        self,
        targets: list[dict],
        bigr_dir: Path | None = None,
        pid_path: Path | None = None,
        log_path: Path | None = None,
        scan_func: Callable[[str], None] | None = None,
        db_path: Path | None = None,
    ) -> None:
        self._bigr_dir = bigr_dir or _DEFAULT_DIR
        self._bigr_dir.mkdir(parents=True, exist_ok=True)

        self._pid_path = pid_path or (self._bigr_dir / "watcher.pid")
        self._log_path = log_path or (self._bigr_dir / "watcher.log")
        self._targets = targets
        self._scan_func = scan_func or self._default_scan
        self._db_path = db_path
        self._running = False
        self._logger = self._setup_logger()

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
    def _default_scan(subnet: str) -> None:
        """Default scan function - runs hybrid scan + classify + save."""
        from bigr.classifier.bigr_mapper import classify_assets
        from bigr.db import save_scan
        from bigr.scanner.hybrid import run_hybrid_scan

        result = run_hybrid_scan(subnet)
        classify_assets(result.assets, do_fingerprint=True)
        save_scan(result)

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
        self._logger.info("Watcher started (PID %d). Targets: %d", os.getpid(), len(self._targets))

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
        """Main loop - runs scan cycles at configured intervals.

        Override or mock this for testing.
        """
        if not self._targets:
            return

        # Calculate minimum interval across all targets
        min_interval = min(
            t.get("interval_seconds", 300) for t in self._targets
        )

        try:
            while self._running:
                self._run_single_cycle()
                time.sleep(min_interval)
        except KeyboardInterrupt:
            self._logger.info("Keyboard interrupt received.")
        finally:
            self.stop()

    def _run_single_cycle(self) -> None:
        """Execute one scan cycle for all targets."""
        for target in self._targets:
            subnet = target.get("subnet", "")
            if not subnet:
                continue

            self._logger.info("Scanning %s ...", subnet)
            try:
                self._scan_func(subnet)
                self._logger.info("Scan complete for %s", subnet)
            except Exception as exc:
                self._logger.error("Scan failed for %s: %s", subnet, exc)
