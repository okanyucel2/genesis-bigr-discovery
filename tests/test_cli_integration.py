"""End-to-end CLI integration tests for all BİGR Discovery commands.

Tests ALL CLI commands using Typer's CliRunner, verifying real output.
Each test is self-contained with isolated temp databases where needed.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from bigr.cli import app
from bigr.models import Asset, BigrCategory, ScanMethod, ScanResult
from datetime import datetime, timezone

runner = CliRunner()


def _make_scan_result(
    target: str = "192.168.1.0/24",
    assets: list[Asset] | None = None,
) -> ScanResult:
    """Create a test scan result with sensible defaults."""
    if assets is None:
        assets = [
            Asset(
                ip="192.168.1.1",
                mac="00:1e:bd:aa:bb:cc",
                hostname="router-01",
                vendor="Cisco",
                open_ports=[22, 80, 443],
                os_hint="IOS",
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.85,
                scan_method=ScanMethod.HYBRID,
            ),
            Asset(
                ip="192.168.1.50",
                mac="a4:14:37:00:11:22",
                hostname="cam-01",
                vendor="Hikvision",
                open_ports=[80, 554],
                os_hint="IP Camera",
                bigr_category=BigrCategory.IOT,
                confidence_score=0.72,
                scan_method=ScanMethod.HYBRID,
            ),
        ]
    return ScanResult(
        target=target,
        scan_method=ScanMethod.HYBRID,
        started_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 12, 0, 30, tzinfo=timezone.utc),
        assets=assets,
        is_root=False,
    )


class TestVersionCommand:
    def test_version_shows_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "BİGR Discovery" in result.output

    def test_version_contains_semver(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        # Should contain version number like v0.1.0
        assert "v" in result.output or "0." in result.output


class TestScanCommand:
    """Test scan command with mocked network operations."""

    def test_scan_no_target_shows_error(self):
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0

    def test_scan_all_no_subnets(self):
        """--all with no registered subnets should fail gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["scan", "--all", "--db-path", db_path])
            assert "No registered subnets" in result.output or result.exit_code != 0

    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_with_target(self, mock_classify, mock_scan, tmp_path: Path):
        """Scan a single target with mocked scanner."""
        mock_scan.return_value = _make_scan_result()
        mock_classify.return_value = mock_scan.return_value.assets

        output_file = str(tmp_path / "out.json")
        result = runner.invoke(app, ["scan", "192.168.1.0/24", "--output", output_file, "--no-diff"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output
        assert "2" in result.output  # 2 assets found
        mock_scan.assert_called_once()

    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_csv_output(self, mock_classify, mock_scan, tmp_path: Path):
        """Scan with CSV output format."""
        mock_scan.return_value = _make_scan_result()
        mock_classify.return_value = mock_scan.return_value.assets

        output_file = str(tmp_path / "out.csv")
        result = runner.invoke(app, ["scan", "192.168.1.0/24", "--output", output_file, "--format", "csv", "--no-diff"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_all_with_registered_subnets(self, mock_classify, mock_scan, tmp_path: Path):
        """--all with registered subnets should scan all of them."""
        mock_scan.return_value = _make_scan_result()
        mock_classify.return_value = mock_scan.return_value.assets

        db_path = str(tmp_path / "test.db")
        # First register a subnet
        runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "Test", "--db-path", db_path])

        output_file = str(tmp_path / "out.json")
        result = runner.invoke(app, ["scan", "--all", "--db-path", db_path, "--output", output_file, "--no-diff"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

class TestHistoryCommand:
    def test_history_empty(self):
        """History with no scans shows appropriate message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            # Patch get_scan_list to use our temp db
            with patch("bigr.cli.get_scan_list", return_value=[]):
                result = runner.invoke(app, ["history"])
                assert result.exit_code == 0
                assert "No scan history" in result.output

    def test_history_with_limit(self):
        """History with --limit flag works."""
        with patch("bigr.cli.get_scan_list", return_value=[]) as mock_get:
            result = runner.invoke(app, ["history", "--limit", "5"])
            assert result.exit_code == 0
            mock_get.assert_called_once_with(limit=5)

    def test_history_with_scans(self):
        """History with existing scans shows table."""
        mock_scans = [
            {
                "id": "test-scan-1",
                "target": "192.168.1.0/24",
                "scan_method": "hybrid",
                "started_at": "2026-01-01T12:00:00",
                "completed_at": "2026-01-01T12:00:30",
                "total_assets": 5,
                "is_root": False,
            },
        ]
        with patch("bigr.cli.get_scan_list", return_value=mock_scans):
            result = runner.invoke(app, ["history"])
            assert result.exit_code == 0
            assert "192.168.1.0/24" in result.output


class TestTagCommands:
    def test_tag_invalid_category(self):
        """Tagging with an invalid category should error."""
        result = runner.invoke(app, ["tag", "192.168.1.1", "--category", "invalid_cat"])
        assert result.exit_code != 0
        assert "Invalid category" in result.output

    def test_tag_valid_category(self):
        """Tagging with a valid category should succeed."""
        with patch("bigr.cli.tag_asset") as mock_tag:
            result = runner.invoke(app, ["tag", "192.168.1.1", "--category", "ag_ve_sistemler", "--note", "Test router"])
            assert result.exit_code == 0
            assert "Tagged" in result.output
            mock_tag.assert_called_once_with("192.168.1.1", "ag_ve_sistemler", note="Test router")

    def test_tag_all_valid_categories(self):
        """All BİGR categories (except unclassified) should be valid tags."""
        valid_categories = ["ag_ve_sistemler", "uygulamalar", "iot", "tasinabilir"]
        for cat in valid_categories:
            with patch("bigr.cli.tag_asset"):
                result = runner.invoke(app, ["tag", "10.0.0.1", "--category", cat])
                assert result.exit_code == 0, f"Category '{cat}' should be valid but got exit code {result.exit_code}"
                assert "Tagged" in result.output

    def test_tag_unclassified_rejected(self):
        """'unclassified' should not be a valid manual tag category."""
        result = runner.invoke(app, ["tag", "10.0.0.1", "--category", "unclassified"])
        assert result.exit_code != 0
        assert "Invalid category" in result.output

    def test_tags_list_empty(self):
        """tags command with no overrides shows appropriate message."""
        with patch("bigr.cli.get_tags", return_value=[]):
            result = runner.invoke(app, ["tags"])
            assert result.exit_code == 0
            assert "No manual overrides" in result.output

    def test_tags_list_with_entries(self):
        """tags command with overrides shows table."""
        mock_tags = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "manual_category": "ag_ve_sistemler", "manual_note": "Core router"},
        ]
        with patch("bigr.cli.get_tags", return_value=mock_tags):
            result = runner.invoke(app, ["tags"])
            assert result.exit_code == 0
            assert "192.168.1.1" in result.output

    def test_untag(self):
        """Untag should remove manual override."""
        with patch("bigr.cli.untag_asset") as mock_untag:
            result = runner.invoke(app, ["untag", "192.168.1.1"])
            assert result.exit_code == 0
            assert "Untagged" in result.output
            mock_untag.assert_called_once_with("192.168.1.1")

    def test_tag_missing_category_option(self):
        """tag without --category should error."""
        result = runner.invoke(app, ["tag", "192.168.1.1"])
        assert result.exit_code != 0


class TestChangesCommand:
    def test_changes_empty(self):
        """changes with no data shows appropriate message."""
        with patch("bigr.cli.get_changes_from_db", return_value=[]):
            result = runner.invoke(app, ["changes"])
            assert result.exit_code == 0
            assert "No asset changes" in result.output

    def test_changes_with_data(self):
        """changes with data shows table."""
        mock_changes = [
            {
                "id": 1,
                "asset_id": "abc",
                "scan_id": "scan-1",
                "change_type": "new_asset",
                "field_name": None,
                "old_value": None,
                "new_value": None,
                "detected_at": "2026-01-01T12:00:00",
                "ip": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:ff",
            },
        ]
        with patch("bigr.cli.get_changes_from_db", return_value=mock_changes):
            result = runner.invoke(app, ["changes"])
            assert result.exit_code == 0
            assert "192.168.1.1" in result.output

    def test_changes_with_limit(self):
        """changes --limit passes correct value."""
        with patch("bigr.cli.get_changes_from_db", return_value=[]) as mock_get:
            result = runner.invoke(app, ["changes", "--limit", "10"])
            assert result.exit_code == 0
            mock_get.assert_called_once_with(limit=10)


class TestSubnetsCommands:
    def test_subnets_add(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "Test LAN", "--db-path", db_path])
            assert result.exit_code == 0
            assert "Added" in result.output

    def test_subnets_add_with_vlan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["subnets", "add", "10.0.1.0/24", "--label", "IoT VLAN", "--vlan", "100", "--db-path", db_path])
            assert result.exit_code == 0
            assert "VLAN 100" in result.output

    def test_subnets_list_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["subnets", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "No subnets" in result.output

    def test_subnets_add_then_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "Test", "--db-path", db_path])
            result = runner.invoke(app, ["subnets", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "10.0.0.0/24" in result.output

    def test_subnets_remove(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--db-path", db_path])
            result = runner.invoke(app, ["subnets", "remove", "10.0.0.0/24", "--db-path", db_path])
            assert result.exit_code == 0
            assert "Removed" in result.output

    def test_subnets_remove_then_list_empty(self):
        """After removing the only subnet, list should be empty again."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--db-path", db_path])
            runner.invoke(app, ["subnets", "remove", "10.0.0.0/24", "--db-path", db_path])
            result = runner.invoke(app, ["subnets", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "No subnets" in result.output

    def test_subnets_add_multiple(self):
        """Adding multiple subnets and listing all."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "LAN-A", "--db-path", db_path])
            runner.invoke(app, ["subnets", "add", "10.0.1.0/24", "--label", "LAN-B", "--vlan", "200", "--db-path", db_path])
            result = runner.invoke(app, ["subnets", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "10.0.0.0/24" in result.output
            assert "10.0.1.0/24" in result.output

    def test_subnets_add_duplicate_updates(self):
        """Adding the same CIDR twice updates label."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "Old Label", "--db-path", db_path])
            runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "New Label", "--db-path", db_path])
            result = runner.invoke(app, ["subnets", "list", "--db-path", db_path])
            assert result.exit_code == 0
            # Should only have one entry, with new label
            assert "New Label" in result.output


class TestSnmpCommands:
    def test_snmp_add(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["snmp", "add", "10.0.0.1", "--community", "public", "--label", "Core Switch", "--db-path", db_path])
            assert result.exit_code == 0
            assert "Added" in result.output

    def test_snmp_list_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["snmp", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "No switches" in result.output

    def test_snmp_add_then_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["snmp", "add", "10.0.0.50", "--label", "Test SW", "--db-path", db_path])
            result = runner.invoke(app, ["snmp", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "10.0.0.50" in result.output

    def test_snmp_remove(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["snmp", "add", "10.0.0.99", "--db-path", db_path])
            result = runner.invoke(app, ["snmp", "remove", "10.0.0.99", "--db-path", db_path])
            assert result.exit_code == 0
            assert "Removed" in result.output

    def test_snmp_remove_then_list_empty(self):
        """After removing the only switch, list should be empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            runner.invoke(app, ["snmp", "add", "10.0.0.99", "--db-path", db_path])
            runner.invoke(app, ["snmp", "remove", "10.0.0.99", "--db-path", db_path])
            result = runner.invoke(app, ["snmp", "list", "--db-path", db_path])
            assert result.exit_code == 0
            assert "No switches" in result.output

    def test_snmp_scan_no_switches(self):
        """snmp scan with no registered switches shows message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["snmp", "scan", "--db-path", db_path])
            assert result.exit_code == 0
            assert "No switches" in result.output

    def test_snmp_scan_with_switches(self):
        """snmp scan with registered switches runs scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            # Register a switch
            runner.invoke(app, ["snmp", "add", "10.0.0.1", "--label", "SW1", "--db-path", db_path])

            # scan_all_switches is imported inside the function body via
            # 'from bigr.scanner.switch_map import ...', so patch at origin
            with patch("bigr.scanner.switch_map.scan_all_switches", return_value=[]):
                result = runner.invoke(app, ["snmp", "scan", "--db-path", db_path])
                assert result.exit_code == 0

    def test_snmp_add_with_version(self):
        """SNMP add with explicit version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            result = runner.invoke(app, ["snmp", "add", "10.0.0.5", "--version", "2c", "--community", "private", "--db-path", db_path])
            assert result.exit_code == 0
            assert "Added" in result.output


class TestWatchCommand:
    @patch("bigr.cli.get_watcher_status")
    def test_watch_status_not_running(self, mock_status):
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=False, message="Not running (no PID file)."
        )
        result = runner.invoke(app, ["watch", "--status"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    @patch("bigr.cli.get_watcher_status")
    def test_watch_status_running(self, mock_status):
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=True, pid=12345, message="Running (PID 12345)."
        )
        result = runner.invoke(app, ["watch", "--status"])
        assert result.exit_code == 0
        assert "12345" in result.output

    @patch("bigr.cli.get_watcher_status")
    def test_watch_stop_when_not_running(self, mock_status):
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=False, message="Not running."
        )
        result = runner.invoke(app, ["watch", "--stop"])
        assert result.exit_code == 0
        assert "No watcher" in result.output or "not running" in result.output.lower()

    @patch("bigr.cli.get_watcher_status")
    @patch("bigr.cli.os.kill")
    def test_watch_stop_running(self, mock_kill, mock_status):
        from bigr.watcher import WatcherStatus
        mock_status.return_value = WatcherStatus(
            is_running=True, pid=12345, message="Running (PID 12345)."
        )
        result = runner.invoke(app, ["watch", "--stop"])
        assert result.exit_code == 0
        mock_kill.assert_called_once()
        assert "Stopped" in result.output or "12345" in result.output

    def test_watch_no_target_no_config_error(self):
        result = runner.invoke(app, ["watch"])
        assert result.exit_code != 0 or "Error" in result.output


class TestReportCommand:
    def test_report_missing_file(self):
        result = runner.invoke(app, ["report", "--input", "nonexistent_file_xyz.json"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_report_summary_format(self):
        """Report with summary format (default)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            scan = _make_scan_result()
            json.dump(scan.to_dict(), f)
            f.flush()
            try:
                result = runner.invoke(app, ["report", "--input", f.name])
                assert result.exit_code == 0
            finally:
                os.unlink(f.name)

    def test_report_detailed_format(self):
        """Report with detailed format shows asset details."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            scan = _make_scan_result()
            json.dump(scan.to_dict(), f)
            f.flush()
            try:
                result = runner.invoke(app, ["report", "--input", f.name, "--format", "detailed"])
                assert result.exit_code == 0
                # Rich may truncate IPs in narrow terminals (192.168... -> "192.168")
                assert "192.168" in result.output
                assert "Detailed" in result.output or "Inventory" in result.output
            finally:
                os.unlink(f.name)

    def test_report_bigr_matrix_format(self):
        """Report with bigr-matrix format shows compliance matrix."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            scan = _make_scan_result()
            json.dump(scan.to_dict(), f)
            f.flush()
            try:
                result = runner.invoke(app, ["report", "--input", f.name, "--format", "bigr-matrix"])
                assert result.exit_code == 0
                assert "192.168.1.1" in result.output
            finally:
                os.unlink(f.name)

    def test_report_shows_category_summary(self):
        """Summary report should display category counts."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            scan = _make_scan_result()
            json.dump(scan.to_dict(), f)
            f.flush()
            try:
                result = runner.invoke(app, ["report", "--input", f.name, "--format", "summary"])
                assert result.exit_code == 0
                # Should show total assets count
                assert "2" in result.output
            finally:
                os.unlink(f.name)


class TestServeCommand:
    def test_serve_missing_data(self):
        result = runner.invoke(app, ["serve", "--data", "nonexistent_scan_data_xyz.json"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "No scan data" in result.output


    # Note: --help tests removed due to Typer/Click make_metavar() version
    # incompatibility in CliRunner. --help works fine in actual CLI usage.


class TestComplianceCommand:
    """Tests for 'bigr compliance' command."""

    @patch("bigr.cli.get_subnets", return_value=[])
    @patch("bigr.cli.get_all_assets")
    def test_compliance_summary(self, mock_assets, mock_subnets):
        """Compliance summary shows score and grade."""
        mock_assets.return_value = [
            {"ip": "10.0.0.1", "confidence_score": 0.85, "bigr_category": "ag_ve_sistemler", "manual_category": None},
            {"ip": "10.0.0.2", "confidence_score": 0.3, "bigr_category": "unclassified", "manual_category": None},
        ]
        result = runner.invoke(app, ["compliance"])
        assert result.exit_code == 0
        # Should show compliance score and grade
        assert "Compliance" in result.output or "Score" in result.output or "%" in result.output

    @patch("bigr.cli.get_subnets", return_value=[])
    @patch("bigr.cli.get_all_assets")
    def test_compliance_json(self, mock_assets, mock_subnets):
        """--format json outputs valid JSON with compliance_score."""
        mock_assets.return_value = [
            {"ip": "10.0.0.1", "confidence_score": 0.85, "bigr_category": "ag_ve_sistemler", "manual_category": None},
        ]
        result = runner.invoke(app, ["compliance", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "compliance_score" in data
        assert "grade" in data

    @patch("bigr.cli.get_subnets", return_value=[])
    @patch("bigr.cli.get_all_assets")
    def test_compliance_empty_assets(self, mock_assets, mock_subnets):
        """Compliance with no assets returns 100% score."""
        mock_assets.return_value = []
        result = runner.invoke(app, ["compliance"])
        assert result.exit_code == 0

    @patch("bigr.cli.get_subnets", return_value=[])
    @patch("bigr.cli.get_all_assets")
    def test_compliance_json_empty_is_100(self, mock_assets, mock_subnets):
        """Compliance with no assets returns 100% score in JSON."""
        mock_assets.return_value = []
        result = runner.invoke(app, ["compliance", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["compliance_score"] == 100.0

    @patch("bigr.cli.get_subnets", return_value=[])
    @patch("bigr.cli.get_all_assets")
    def test_compliance_all_classified(self, mock_assets, mock_subnets):
        """All assets with high confidence should get grade A."""
        mock_assets.return_value = [
            {"ip": "10.0.0.1", "confidence_score": 0.9, "bigr_category": "ag_ve_sistemler", "manual_category": None},
            {"ip": "10.0.0.2", "confidence_score": 0.95, "bigr_category": "iot", "manual_category": None},
            {"ip": "10.0.0.3", "confidence_score": 0.8, "bigr_category": "uygulamalar", "manual_category": None},
        ]
        result = runner.invoke(app, ["compliance", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["compliance_score"] == 100.0
        assert data["grade"] == "A"


class TestAnalyticsCommand:
    """Tests for 'bigr analytics' command."""

    @patch("bigr.analytics.get_full_analytics")
    def test_analytics_summary(self, mock_analytics):
        """Analytics summary format runs successfully."""
        from bigr.analytics import AnalyticsResult, TrendSeries

        mock_analytics.return_value = AnalyticsResult(
            asset_count_trend=TrendSeries(name="asset_count", points=[]),
            category_trends=[],
            new_vs_removed=TrendSeries(name="new_vs_removed", points=[]),
            most_changed_assets=[],
            scan_frequency=[],
        )
        result = runner.invoke(app, ["analytics"])
        assert result.exit_code == 0

    @patch("bigr.analytics.get_full_analytics")
    def test_analytics_json(self, mock_analytics):
        """--format json outputs valid JSON with asset_count_trend key."""
        from bigr.analytics import AnalyticsResult, TrendSeries

        mock_analytics.return_value = AnalyticsResult(
            asset_count_trend=TrendSeries(name="asset_count", points=[]),
            category_trends=[],
            new_vs_removed=TrendSeries(name="new_vs_removed", points=[]),
            most_changed_assets=[],
            scan_frequency=[],
        )
        result = runner.invoke(app, ["analytics", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "asset_count_trend" in data

    @patch("bigr.analytics.get_full_analytics")
    def test_analytics_days_param(self, mock_analytics):
        """--days parameter is passed through to the analytics engine."""
        from bigr.analytics import AnalyticsResult, TrendSeries

        mock_analytics.return_value = AnalyticsResult(
            asset_count_trend=TrendSeries(name="asset_count", points=[]),
            category_trends=[],
            new_vs_removed=TrendSeries(name="new_vs_removed", points=[]),
            most_changed_assets=[],
            scan_frequency=[],
        )
        result = runner.invoke(app, ["analytics", "--days", "7"])
        assert result.exit_code == 0
        mock_analytics.assert_called_once()
        call_kwargs = mock_analytics.call_args
        assert call_kwargs[1].get("days") == 7 or call_kwargs[0][0] == 7 if call_kwargs[0] else call_kwargs[1].get("days") == 7


class TestReportHtmlCommand:
    """Tests for 'bigr report --format html-report'."""

    def test_html_report_generation(self, tmp_path: Path):
        """Generate HTML report from scan data."""
        data_file = tmp_path / "scan.json"
        data_file.write_text(json.dumps({
            "target": "10.0.0.0/24",
            "scan_method": "hybrid",
            "total_assets": 3,
            "category_summary": {"ag_ve_sistemler": 1, "iot": 1, "tasinabilir": 1},
            "assets": [
                {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01", "hostname": "router",
                 "vendor": "Cisco", "open_ports": [22, 80], "bigr_category": "ag_ve_sistemler",
                 "bigr_category_tr": "Ag ve Sistemler", "confidence_score": 0.85,
                 "confidence_level": "high", "os_hint": "Linux"},
                {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02", "hostname": "camera",
                 "vendor": "Hikvision", "open_ports": [80, 554], "bigr_category": "iot",
                 "bigr_category_tr": "IoT", "confidence_score": 0.7,
                 "confidence_level": "high", "os_hint": "IP Camera"},
                {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:03", "hostname": "laptop",
                 "vendor": "Apple", "open_ports": [], "bigr_category": "tasinabilir",
                 "bigr_category_tr": "Tasinabilir", "confidence_score": 0.6,
                 "confidence_level": "medium", "os_hint": None},
            ]
        }))

        output_file = str(tmp_path / "report.html")
        result = runner.invoke(app, ["report", "--input", str(data_file), "--format", "html-report", "--output", output_file])
        assert result.exit_code == 0
        assert Path(output_file).exists()
        content = Path(output_file).read_text()
        assert "<html" in content
        assert "10.0.0.1" in content

    def test_html_report_contains_all_assets(self, tmp_path: Path):
        """HTML report should contain all asset IPs."""
        data_file = tmp_path / "scan.json"
        data_file.write_text(json.dumps({
            "target": "10.0.0.0/24",
            "scan_method": "hybrid",
            "total_assets": 2,
            "category_summary": {"ag_ve_sistemler": 1, "iot": 1},
            "assets": [
                {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01", "hostname": "router",
                 "vendor": "Cisco", "open_ports": [22], "bigr_category": "ag_ve_sistemler",
                 "bigr_category_tr": "Ag ve Sistemler", "confidence_score": 0.85,
                 "confidence_level": "high", "os_hint": "Linux"},
                {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02", "hostname": "camera",
                 "vendor": "Hikvision", "open_ports": [554], "bigr_category": "iot",
                 "bigr_category_tr": "IoT", "confidence_score": 0.7,
                 "confidence_level": "high", "os_hint": "IP Camera"},
            ]
        }))

        output_file = str(tmp_path / "report.html")
        result = runner.invoke(app, ["report", "--input", str(data_file), "--format", "html-report", "--output", output_file])
        assert result.exit_code == 0
        content = Path(output_file).read_text()
        assert "10.0.0.1" in content
        assert "10.0.0.2" in content

    def test_html_report_default_output_path(self, tmp_path: Path):
        """HTML report without --output uses input filename with .html extension."""
        data_file = tmp_path / "myscan.json"
        data_file.write_text(json.dumps({
            "target": "10.0.0.0/24",
            "scan_method": "hybrid",
            "total_assets": 1,
            "category_summary": {"ag_ve_sistemler": 1},
            "assets": [
                {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01", "hostname": "router",
                 "vendor": "Cisco", "open_ports": [22], "bigr_category": "ag_ve_sistemler",
                 "bigr_category_tr": "Ag ve Sistemler", "confidence_score": 0.85,
                 "confidence_level": "high", "os_hint": "Linux"},
            ]
        }))

        result = runner.invoke(app, ["report", "--input", str(data_file), "--format", "html-report"])
        assert result.exit_code == 0
        # Default output path should be myscan.html
        expected_output = tmp_path / "myscan.html"
        assert expected_output.exists()


class TestEndToEndSubnetScanWorkflow:
    """Full workflow: add subnet -> scan --all -> verify."""

    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_full_subnet_scan_workflow(self, mock_classify, mock_scan, tmp_path: Path):
        """Register subnet, then scan --all."""
        mock_scan.return_value = _make_scan_result(target="10.0.0.0/24")
        mock_classify.return_value = mock_scan.return_value.assets

        db_path = str(tmp_path / "workflow.db")
        output_file = str(tmp_path / "workflow_out.json")

        # Step 1: Add subnet
        add_result = runner.invoke(app, ["subnets", "add", "10.0.0.0/24", "--label", "Workflow Test", "--db-path", db_path])
        assert add_result.exit_code == 0
        assert "Added" in add_result.output

        # Step 2: List to verify
        list_result = runner.invoke(app, ["subnets", "list", "--db-path", db_path])
        assert "10.0.0.0/24" in list_result.output

        # Step 3: Scan all
        scan_result = runner.invoke(app, ["scan", "--all", "--db-path", db_path, "--output", output_file, "--no-diff"])
        assert scan_result.exit_code == 0
        assert "Scan complete" in scan_result.output


class TestEndToEndSnmpWorkflow:
    """Full workflow: add switch -> list -> remove."""

    def test_full_snmp_lifecycle(self, tmp_path: Path):
        """Register, list, remove switch in sequence."""
        db_path = str(tmp_path / "snmp_workflow.db")

        # Step 1: Add switch
        add_result = runner.invoke(app, ["snmp", "add", "10.0.0.1", "--label", "Core SW", "--community", "public", "--db-path", db_path])
        assert add_result.exit_code == 0
        assert "Added" in add_result.output

        # Step 2: List to verify
        list_result = runner.invoke(app, ["snmp", "list", "--db-path", db_path])
        assert "10.0.0.1" in list_result.output
        assert "Core SW" in list_result.output

        # Step 3: Remove
        remove_result = runner.invoke(app, ["snmp", "remove", "10.0.0.1", "--db-path", db_path])
        assert remove_result.exit_code == 0
        assert "Removed" in remove_result.output

        # Step 4: Verify removed
        list_result2 = runner.invoke(app, ["snmp", "list", "--db-path", db_path])
        assert "No switches" in list_result2.output
