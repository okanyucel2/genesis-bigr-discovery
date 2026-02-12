"""Tests for Guardian daemon."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bigr.guardian.config import GuardianConfig
from bigr.guardian.daemon import GuardianDaemon, _is_process_alive


class TestIsProcessAlive:
    def test_current_process_alive(self):
        assert _is_process_alive(os.getpid()) is True

    def test_nonexistent_process(self):
        assert _is_process_alive(999999999) is False


class TestGuardianDaemonInit:
    def test_creates_pid_dir(self, tmp_path: Path):
        bigr_dir = tmp_path / "bigr"
        daemon = GuardianDaemon(
            config=GuardianConfig(dns_port=15353),
            bigr_dir=bigr_dir,
        )
        assert bigr_dir.exists()

    def test_default_config(self, tmp_path: Path):
        daemon = GuardianDaemon(
            config=GuardianConfig(),
            bigr_dir=tmp_path,
        )
        assert daemon._config.dns_port == 53


class TestGuardianDaemonStatus:
    def test_no_pid_file(self, tmp_path: Path):
        daemon = GuardianDaemon(
            config=GuardianConfig(),
            bigr_dir=tmp_path,
        )
        status = daemon.get_status()
        assert status["running"] is False
        assert "no PID" in status["message"]

    def test_valid_pid_file(self, tmp_path: Path):
        daemon = GuardianDaemon(
            config=GuardianConfig(),
            bigr_dir=tmp_path,
        )
        # Write current PID (alive process)
        pid_path = tmp_path / "guardian.pid"
        pid_path.write_text(str(os.getpid()))

        status = daemon.get_status()
        assert status["running"] is True
        assert status["pid"] == os.getpid()

    def test_stale_pid_cleaned(self, tmp_path: Path):
        daemon = GuardianDaemon(
            config=GuardianConfig(),
            bigr_dir=tmp_path,
        )
        # Write a PID that doesn't exist
        pid_path = tmp_path / "guardian.pid"
        pid_path.write_text("999999999")

        status = daemon.get_status()
        assert status["running"] is False
        assert "stale" in status["message"]
        assert not pid_path.exists()

    def test_invalid_pid_file(self, tmp_path: Path):
        daemon = GuardianDaemon(
            config=GuardianConfig(),
            bigr_dir=tmp_path,
        )
        pid_path = tmp_path / "guardian.pid"
        pid_path.write_text("not-a-number")

        status = daemon.get_status()
        assert status["running"] is False
