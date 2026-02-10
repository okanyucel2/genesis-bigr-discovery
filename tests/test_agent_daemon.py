"""Tests for AgentDaemon — scan cycle, heartbeat, PID lifecycle."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bigr.agent.daemon import AgentDaemon, _is_process_alive


@pytest.fixture
def tmp_bigr_dir(tmp_path):
    """Temporary ~/.bigr equivalent."""
    return tmp_path / "bigr"


@pytest.fixture
def daemon(tmp_bigr_dir):
    """Create an AgentDaemon that won't actually scan or connect."""
    return AgentDaemon(
        api_url="http://localhost:8090",
        token="test-token-abc",
        targets=["10.0.0.0/24"],
        interval_seconds=60,
        shield=False,
        bigr_dir=tmp_bigr_dir,
    )


class TestPIDLifecycle:
    def test_pid_file_created_on_start(self, daemon, tmp_bigr_dir):
        """Verify PID file is created when start is called (mocked loop)."""
        with patch.object(daemon, "_run_loop"):
            daemon.start()
        pid_path = tmp_bigr_dir / "agent.pid"
        assert pid_path.exists()
        assert int(pid_path.read_text().strip()) == os.getpid()
        daemon.stop()

    def test_pid_file_cleaned_on_stop(self, daemon, tmp_bigr_dir):
        with patch.object(daemon, "_run_loop"):
            daemon.start()
        daemon.stop()
        pid_path = tmp_bigr_dir / "agent.pid"
        assert not pid_path.exists()

    def test_start_fails_if_already_running(self, daemon, tmp_bigr_dir):
        """If PID file points to alive process, raise RuntimeError."""
        pid_path = tmp_bigr_dir / "agent.pid"
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(os.getpid()))  # our own PID is alive

        with pytest.raises(RuntimeError, match="already running"):
            daemon.start()

    def test_stale_pid_cleaned_on_start(self, daemon, tmp_bigr_dir):
        """Stale PID file should be cleaned up and start should succeed."""
        pid_path = tmp_bigr_dir / "agent.pid"
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text("999999999")  # very unlikely to be alive

        with patch.object(daemon, "_run_loop"):
            daemon.start()
        assert int(pid_path.read_text().strip()) == os.getpid()
        daemon.stop()

    def test_get_status_not_running(self, daemon):
        status = daemon.get_status()
        assert not status["running"]

    def test_get_status_running(self, daemon, tmp_bigr_dir):
        with patch.object(daemon, "_run_loop"):
            daemon.start()
        status = daemon.get_status()
        assert status["running"]
        assert status["pid"] == os.getpid()
        daemon.stop()


class TestIsProcessAlive:
    def test_current_process_is_alive(self):
        assert _is_process_alive(os.getpid()) is True

    def test_nonexistent_process(self):
        assert _is_process_alive(999999999) is False


class TestScanCycle:
    def test_single_cycle_calls_scan_and_push(self, daemon):
        """Mock the scan and push methods to verify they're called."""
        mock_result = {
            "target": "10.0.0.0/24",
            "scan_method": "hybrid",
            "started_at": "2026-01-01T00:00:00Z",
            "assets": [{"ip": "10.0.0.1"}],
        }
        with (
            patch.object(daemon, "_scan_target", return_value=mock_result) as mock_scan,
            patch.object(daemon, "_push_discovery_results") as mock_push,
        ):
            daemon._run_single_cycle()
            mock_scan.assert_called_once_with("10.0.0.0/24")
            mock_push.assert_called_once_with(mock_result)

    def test_single_cycle_with_shield(self, tmp_bigr_dir):
        """When shield=True, shield methods should also be called."""
        d = AgentDaemon(
            api_url="http://localhost:8090",
            token="t",
            targets=["10.0.0.0/24"],
            shield=True,
            bigr_dir=tmp_bigr_dir,
        )
        mock_scan_result = {"target": "10.0.0.0/24", "assets": []}
        mock_shield_result = {"target": "10.0.0.0/24", "findings": []}

        with (
            patch.object(d, "_scan_target", return_value=mock_scan_result),
            patch.object(d, "_push_discovery_results"),
            patch.object(d, "_run_shield", return_value=mock_shield_result) as mock_shield,
            patch.object(d, "_push_shield_results") as mock_shield_push,
        ):
            d._run_single_cycle()
            mock_shield.assert_called_once_with("10.0.0.0/24")
            mock_shield_push.assert_called_once_with(mock_shield_result)

    def test_scan_failure_logged_not_raised(self, daemon):
        """Scan errors should be logged but not crash the daemon."""
        with patch.object(daemon, "_scan_target", side_effect=RuntimeError("scan failed")):
            daemon._run_single_cycle()  # Should not raise


class TestHeartbeat:
    def test_heartbeat_posts_to_api(self, daemon):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch.object(daemon._client, "post", return_value=mock_response) as mock_post:
            daemon._send_heartbeat()
            mock_post.assert_called_once()
            url = mock_post.call_args[0][0]
            assert "/api/agents/heartbeat" in url

    def test_heartbeat_failure_logged_not_raised(self, daemon):
        with patch.object(daemon._client, "post", side_effect=Exception("network down")):
            daemon._send_heartbeat()  # Should not raise


class TestPushMethods:
    def test_push_discovery(self, daemon):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch.object(daemon._client, "post", return_value=mock_response) as mock_post:
            daemon._push_discovery_results({"target": "10.0.0.0/24", "assets": []})
            url = mock_post.call_args[0][0]
            assert "/api/ingest/discovery" in url

    def test_push_shield(self, daemon):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch.object(daemon._client, "post", return_value=mock_response) as mock_post:
            daemon._push_shield_results({"target": "10.0.0.0/24", "findings": []})
            url = mock_post.call_args[0][0]
            assert "/api/ingest/shield" in url
