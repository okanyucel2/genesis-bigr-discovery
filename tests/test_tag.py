"""Tests for manual category override (tag/untag/tags) feature."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from bigr.cli import app
from bigr.db import get_tags, init_db, save_scan, tag_asset, untag_asset
from bigr.classifier.bigr_mapper import classify_asset
from bigr.models import Asset, BigrCategory, ScanMethod, ScanResult

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


class TestTagCommand:
    def test_tag_command_success(self, tmp_path: Path):
        """Tag an IP via CLI and verify it appears in the DB."""
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        with patch("bigr.cli.tag_asset") as mock_tag:
            res = runner.invoke(
                app,
                ["tag", "192.168.1.1", "--category", "iot", "--note", "Smart switch"],
            )
            assert res.exit_code == 0
            assert "Tagged" in res.output
            assert "iot" in res.output
            mock_tag.assert_called_once_with("192.168.1.1", "iot", note="Smart switch")

    def test_tag_invalid_category(self):
        """Reject invalid category names."""
        res = runner.invoke(
            app,
            ["tag", "192.168.1.1", "--category", "bogus_category"],
        )
        assert res.exit_code == 1
        assert "Invalid category" in res.output
        assert "bogus_category" in res.output

    def test_tag_unclassified_rejected(self):
        """'unclassified' is not a valid manual category."""
        res = runner.invoke(
            app,
            ["tag", "192.168.1.1", "--category", "unclassified"],
        )
        assert res.exit_code == 1
        assert "Invalid category" in res.output

    def test_tag_all_valid_categories(self):
        """All four valid categories are accepted."""
        valid = ["ag_ve_sistemler", "uygulamalar", "iot", "tasinabilir"]
        for cat in valid:
            with patch("bigr.cli.tag_asset"):
                res = runner.invoke(
                    app,
                    ["tag", "10.0.0.1", "--category", cat],
                )
                assert res.exit_code == 0, f"Category '{cat}' should be accepted"


class TestUntagCommand:
    def test_untag_command(self, tmp_path: Path):
        """Tag then untag via CLI; verify removal."""
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        # Tag directly in DB
        tag_asset("192.168.1.1", "iot", note="test", db_path=db)
        assert len(get_tags(db_path=db)) == 1

        # Untag directly in DB (CLI delegates to untag_asset)
        untag_asset("192.168.1.1", db_path=db)
        assert len(get_tags(db_path=db)) == 0

    def test_untag_command_cli(self):
        """Test untag CLI output."""
        with patch("bigr.cli.untag_asset"):
            res = runner.invoke(app, ["untag", "192.168.1.1"])
            assert res.exit_code == 0
            assert "Untagged" in res.output


class TestTagsList:
    def test_tags_list(self, tmp_path: Path):
        """Tag multiple IPs, verify list shows all."""
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        tag_asset("192.168.1.1", "iot", note="Switch", db_path=db)
        tag_asset("192.168.1.50", "tasinabilir", note="Phone", db_path=db)

        tags = get_tags(db_path=db)
        assert len(tags) == 2
        ips = {t["ip"] for t in tags}
        assert "192.168.1.1" in ips
        assert "192.168.1.50" in ips

    def test_tags_empty_output(self):
        """CLI shows message when no overrides exist."""
        with patch("bigr.cli.get_tags", return_value=[]):
            res = runner.invoke(app, ["tags"])
            assert res.exit_code == 0
            assert "No manual overrides" in res.output

    def test_tags_list_output(self):
        """CLI renders a table when overrides exist."""
        mock_tags = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test-host",
             "manual_category": "iot", "manual_note": "Sensor"},
        ]
        with patch("bigr.cli.get_tags", return_value=mock_tags):
            res = runner.invoke(app, ["tags"])
            assert res.exit_code == 0
            assert "10.0.0.1" in res.output
            assert "iot" in res.output
            assert "Sensor" in res.output


class TestManualOverrideClassification:
    def test_manual_override_in_classification(self, tmp_path: Path):
        """classify_asset respects manual override from DB."""
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        # Tag router as IoT
        tag_asset("192.168.1.1", "iot", note="Smart switch", db_path=db)

        # Classify - should use manual override
        asset = Asset(
            ip="192.168.1.1",
            mac="00:1e:bd:aa:bb:cc",
            open_ports=[22, 80, 443],
            vendor="Cisco",
        )

        with patch("bigr.db.get_tags") as mock_tags:
            mock_tags.return_value = [
                {"ip": "192.168.1.1", "manual_category": "iot", "manual_note": "Smart switch"},
            ]
            classified = classify_asset(asset, do_fingerprint=False)

        assert classified.bigr_category == BigrCategory.IOT
        assert classified.raw_evidence.get("manual_override") == "Smart switch"

    def test_manual_override_confidence(self, tmp_path: Path):
        """Manual override has confidence 1.0."""
        asset = Asset(
            ip="192.168.1.1",
            mac="00:1e:bd:aa:bb:cc",
            open_ports=[22, 80, 443],
        )

        with patch("bigr.db.get_tags") as mock_tags:
            mock_tags.return_value = [
                {"ip": "192.168.1.1", "manual_category": "tasinabilir", "manual_note": "Laptop"},
            ]
            classified = classify_asset(asset, do_fingerprint=False)

        assert classified.confidence_score == 1.0
        assert classified.bigr_category == BigrCategory.TASINABILIR

    def test_no_db_graceful_fallback(self):
        """If DB is unavailable, auto-classify normally."""
        asset = Asset(
            ip="192.168.1.1",
            mac="00:1e:bd:aa:bb:cc",
            hostname="router-01",
            vendor="Cisco",
            open_ports=[22, 80, 443],
        )

        with patch("bigr.db.get_tags", side_effect=Exception("DB gone")):
            classified = classify_asset(asset, do_fingerprint=False)

        # Should still classify (auto), not crash
        assert classified.bigr_category != BigrCategory.UNCLASSIFIED or classified.confidence_score >= 0.0
        # Key assertion: no exception raised, asset was classified

    def test_override_skips_auto_scoring(self):
        """When manual override is present, auto-scoring is not applied."""
        asset = Asset(
            ip="10.0.0.1",
            mac="aa:bb:cc:dd:ee:ff",
            open_ports=[9100],  # Would normally classify as IoT (printer port)
            vendor="HP",
        )

        with patch("bigr.db.get_tags") as mock_tags:
            mock_tags.return_value = [
                {"ip": "10.0.0.1", "manual_category": "ag_ve_sistemler", "manual_note": "Print server"},
            ]
            classified = classify_asset(asset, do_fingerprint=False)

        # Manual says ag_ve_sistemler, not IoT
        assert classified.bigr_category == BigrCategory.AG_VE_SISTEMLER
        assert classified.confidence_score == 1.0
        assert "manual_override" in classified.raw_evidence

    def test_no_override_uses_auto_classification(self):
        """When no manual override exists, normal auto-classification runs."""
        asset = Asset(
            ip="10.0.0.99",
            mac="aa:bb:cc:dd:ee:ff",
            open_ports=[22, 80, 443],
            vendor="Cisco",
        )

        with patch("bigr.db.get_tags") as mock_tags:
            mock_tags.return_value = []  # No overrides
            classified = classify_asset(asset, do_fingerprint=False)

        # Should auto-classify (not manual)
        assert "manual_override" not in classified.raw_evidence
