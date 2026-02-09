"""Tests for CLI commands."""

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from bigr.cli import app
from bigr.models import Asset, BigrCategory, ScanMethod, ScanResult
from datetime import datetime, timezone

runner = CliRunner()


def _make_scan_result() -> ScanResult:
    """Create a test scan result."""
    return ScanResult(
        target="192.168.1.0/24",
        scan_method=ScanMethod.HYBRID,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        assets=[
            Asset(
                ip="192.168.1.1",
                mac="00:1e:bd:aa:bb:cc",
                hostname="router-01",
                open_ports=[22, 80, 443],
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.85,
            ),
            Asset(
                ip="192.168.1.50",
                mac="a4:14:37:00:11:22",
                hostname="cam-01",
                open_ports=[80, 554],
                bigr_category=BigrCategory.IOT,
                confidence_score=0.72,
            ),
        ],
    )


class TestVersion:
    def test_version_output(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "BİGR Discovery" in result.output


class TestReport:
    def test_report_file_not_found(self):
        result = runner.invoke(app, ["report", "--input", "nonexistent.json"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_report_summary(self, tmp_path: Path):
        scan_result = _make_scan_result()
        json_path = tmp_path / "test_assets.json"
        json_path.write_text(json.dumps(scan_result.to_dict()))

        result = runner.invoke(app, ["report", "--input", str(json_path), "--format", "summary"])
        assert result.exit_code == 0

    def test_report_detailed(self, tmp_path: Path):
        scan_result = _make_scan_result()
        json_path = tmp_path / "test_assets.json"
        json_path.write_text(json.dumps(scan_result.to_dict()))

        result = runner.invoke(app, ["report", "--input", str(json_path), "--format", "detailed"])
        assert result.exit_code == 0


class TestScan:
    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_basic(self, mock_classify, mock_scan, tmp_path: Path):
        mock_scan.return_value = _make_scan_result()
        mock_classify.return_value = mock_scan.return_value.assets

        output_file = str(tmp_path / "out.json")
        result = runner.invoke(app, ["scan", "192.168.1.0/24", "--output", output_file])
        assert result.exit_code == 0
        assert "Scan complete" in result.output
        mock_scan.assert_called_once()


class TestWatch:
    @patch("bigr.cli.get_watcher_status")
    def test_watch_status_not_running(self, mock_status):
        """bigr watch --status should show not running."""
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=False, message="Not running (no PID file)."
        )

        result = runner.invoke(app, ["watch", "--status"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower() or "Not running" in result.output

    @patch("bigr.cli.get_watcher_status")
    def test_watch_status_running(self, mock_status):
        """bigr watch --status should show running with PID."""
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=True, pid=12345, message="Running (PID 12345)."
        )

        result = runner.invoke(app, ["watch", "--status"])
        assert result.exit_code == 0
        assert "12345" in result.output

    @patch("bigr.cli.get_watcher_status")
    def test_watch_stop_not_running(self, mock_status):
        """bigr watch --stop when not running should show message."""
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=False, message="Not running."
        )

        result = runner.invoke(app, ["watch", "--stop"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower() or "No watcher" in result.output

    @patch("bigr.cli.get_watcher_status")
    @patch("bigr.cli.os.kill")
    def test_watch_stop_running(self, mock_kill, mock_status):
        """bigr watch --stop should kill the running watcher."""
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=True, pid=12345, message="Running (PID 12345)."
        )

        result = runner.invoke(app, ["watch", "--stop"])
        assert result.exit_code == 0
        mock_kill.assert_called_once()
        assert "stop" in result.output.lower() or "12345" in result.output
