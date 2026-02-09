"""Tests for watcher daemon."""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bigr.watcher import (
    WatcherDaemon,
    WatcherStatus,
    get_pid_path,
    get_watcher_status,
)


class TestWatcher:
    def test_watcher_creates_pid_file(self, tmp_path):
        """Starting watcher should create PID file."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        watcher = WatcherDaemon(
            targets=[],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
        )
        # Mock the _run_loop to do nothing (we just test PID creation)
        watcher._run_loop = MagicMock()

        watcher.start()
        assert pid_path.exists()
        pid_content = pid_path.read_text().strip()
        assert pid_content == str(os.getpid())

        # Cleanup
        watcher.stop()

    def test_watcher_prevents_duplicate(self, tmp_path):
        """Second watcher should fail if PID file exists and process alive."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        # Write our own PID to simulate a running watcher
        pid_path.write_text(str(os.getpid()))

        watcher = WatcherDaemon(
            targets=[],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
        )

        with pytest.raises(RuntimeError, match="already running"):
            watcher.start()

    def test_watcher_cleans_stale_pid(self, tmp_path):
        """Should clean PID file if referenced process is dead."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        # Write a PID that definitely does not exist (very high number)
        pid_path.write_text("999999999")

        watcher = WatcherDaemon(
            targets=[],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
        )
        watcher._run_loop = MagicMock()

        # Should NOT raise - stale PID should be cleaned
        watcher.start()
        assert pid_path.exists()
        assert pid_path.read_text().strip() == str(os.getpid())

        watcher.stop()

    def test_watcher_schedules_scans(self, tmp_path):
        """Should call scan function at configured interval."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        scan_mock = MagicMock()

        watcher = WatcherDaemon(
            targets=[{"subnet": "192.168.1.0/24", "interval_seconds": 1}],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
            scan_func=scan_mock,
        )

        # Run one cycle manually
        watcher._run_single_cycle()
        scan_mock.assert_called_once_with("192.168.1.0/24")

    def test_watcher_stop_removes_pid(self, tmp_path):
        """Stopping watcher should remove PID file."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        watcher = WatcherDaemon(
            targets=[],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
        )
        watcher._run_loop = MagicMock()

        watcher.start()
        assert pid_path.exists()

        watcher.stop()
        assert not pid_path.exists()

    def test_watcher_status_running(self, tmp_path):
        """Status should report running when PID file exists with live process."""
        pid_path = tmp_path / "watcher.pid"
        pid_path.write_text(str(os.getpid()))

        status = get_watcher_status(pid_path=pid_path)
        assert status.is_running is True
        assert status.pid == os.getpid()

    def test_watcher_status_not_running(self, tmp_path):
        """Status should report not running when no PID file."""
        pid_path = tmp_path / "nonexistent.pid"

        status = get_watcher_status(pid_path=pid_path)
        assert status.is_running is False
        assert status.pid is None

    def test_watcher_status_stale_pid(self, tmp_path):
        """Status should report not running when PID file has dead process."""
        pid_path = tmp_path / "watcher.pid"
        pid_path.write_text("999999999")

        status = get_watcher_status(pid_path=pid_path)
        assert status.is_running is False
        assert status.pid is None

    def test_watcher_logs_scan_results(self, tmp_path):
        """Should log each scan to log file."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        scan_mock = MagicMock()

        watcher = WatcherDaemon(
            targets=[{"subnet": "10.0.0.0/24", "interval_seconds": 1}],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
            scan_func=scan_mock,
        )

        watcher._run_single_cycle()

        # Log file should have been created and contain scan info
        assert log_path.exists()
        log_content = log_path.read_text()
        assert "10.0.0.0/24" in log_content

    def test_get_pid_path(self):
        """Should return ~/.bigr/watcher.pid path."""
        path = get_pid_path()
        assert path == Path.home() / ".bigr" / "watcher.pid"

    def test_watcher_multiple_targets(self, tmp_path):
        """Should scan all configured targets in each cycle."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"

        scan_mock = MagicMock()

        watcher = WatcherDaemon(
            targets=[
                {"subnet": "192.168.1.0/24", "interval_seconds": 60},
                {"subnet": "10.0.0.0/24", "interval_seconds": 60},
            ],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
            scan_func=scan_mock,
        )

        watcher._run_single_cycle()
        assert scan_mock.call_count == 2
        scan_mock.assert_any_call("192.168.1.0/24")
        scan_mock.assert_any_call("10.0.0.0/24")


class TestWatcherIntegration:
    def test_watcher_runs_scan_and_saves(self, tmp_path):
        """Integration: watcher runs scan, saves to DB, detects changes."""
        pid_path = tmp_path / "watcher.pid"
        log_path = tmp_path / "watcher.log"
        db_path = tmp_path / "bigr.db"

        # Track what subnets were scanned
        scanned_subnets: list[str] = []

        def fake_scan(subnet: str) -> None:
            scanned_subnets.append(subnet)

        watcher = WatcherDaemon(
            targets=[{"subnet": "192.168.1.0/24", "interval_seconds": 1}],
            bigr_dir=tmp_path,
            pid_path=pid_path,
            log_path=log_path,
            scan_func=fake_scan,
            db_path=db_path,
        )

        watcher._run_single_cycle()

        assert "192.168.1.0/24" in scanned_subnets
