"""Tests for scan diff engine."""

from datetime import datetime, timezone
from pathlib import Path

from bigr.db import init_db, save_scan
from bigr.diff import AssetChange, DiffResult, diff_scans, get_changes_from_db
from bigr.models import Asset, BigrCategory, ScanMethod, ScanResult


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _asset_dict(
    ip: str = "192.168.1.1",
    mac: str | None = "00:1e:bd:aa:bb:cc",
    hostname: str | None = "host-01",
    vendor: str | None = "Cisco",
    open_ports: list[int] | None = None,
    bigr_category: str = "ag_ve_sistemler",
    confidence_score: float = 0.85,
) -> dict:
    """Build a minimal asset dict for diffing."""
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "open_ports": open_ports if open_ports is not None else [22, 80],
        "bigr_category": bigr_category,
        "confidence_score": confidence_score,
    }


def _make_scan_result(
    target: str = "192.168.1.0/24",
    assets: list[Asset] | None = None,
) -> ScanResult:
    if assets is None:
        assets = [
            Asset(
                ip="192.168.1.1",
                mac="00:1e:bd:aa:bb:cc",
                hostname="router-01",
                vendor="Cisco",
                open_ports=[22, 80, 443],
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.85,
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


# ---------------------------------------------------------------------------
# diff_scans tests
# ---------------------------------------------------------------------------


class TestDiffNewAssets:
    def test_diff_new_assets(self):
        """Assets in current but not in previous should appear as new."""
        previous = [_asset_dict(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01")]
        current = [
            _asset_dict(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"),
            _asset_dict(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02"),
        ]

        result = diff_scans(current, previous)

        assert len(result.new_assets) == 1
        assert result.new_assets[0]["ip"] == "10.0.0.2"

    def test_new_asset_mac_none(self):
        """New asset with mac=None should still be detected."""
        previous: list[dict] = []
        current = [_asset_dict(ip="10.0.0.1", mac=None)]

        result = diff_scans(current, previous)
        assert len(result.new_assets) == 1
        assert result.new_assets[0]["ip"] == "10.0.0.1"


class TestDiffRemovedAssets:
    def test_diff_removed_assets(self):
        """Assets in previous but not in current should appear as removed."""
        previous = [
            _asset_dict(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"),
            _asset_dict(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02"),
        ]
        current = [_asset_dict(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01")]

        result = diff_scans(current, previous)

        assert len(result.removed_assets) == 1
        assert result.removed_assets[0]["ip"] == "10.0.0.2"


class TestDiffChangedPorts:
    def test_diff_changed_ports(self):
        """Same asset with different open_ports should be detected."""
        previous = [_asset_dict(ip="10.0.0.1", open_ports=[22, 80])]
        current = [_asset_dict(ip="10.0.0.1", open_ports=[22, 80, 443])]

        result = diff_scans(current, previous)

        assert len(result.changed_assets) >= 1
        port_change = next(
            c for c in result.changed_assets if c.change_type == "port_change"
        )
        assert port_change.ip == "10.0.0.1"
        assert port_change.field == "open_ports"


class TestDiffChangedCategory:
    def test_diff_changed_category(self):
        """Same asset with different bigr_category should be detected."""
        previous = [_asset_dict(ip="10.0.0.1", bigr_category="unclassified")]
        current = [_asset_dict(ip="10.0.0.1", bigr_category="ag_ve_sistemler")]

        result = diff_scans(current, previous)

        assert len(result.changed_assets) >= 1
        cat_change = next(
            c for c in result.changed_assets if c.change_type == "category_change"
        )
        assert cat_change.old_value == "unclassified"
        assert cat_change.new_value == "ag_ve_sistemler"


class TestDiffUnchanged:
    def test_diff_unchanged(self):
        """Identical scans should produce no changes."""
        assets = [
            _asset_dict(ip="10.0.0.1"),
            _asset_dict(ip="10.0.0.2", mac="ff:ee:dd:cc:bb:aa"),
        ]

        result = diff_scans(assets, assets)

        assert not result.has_changes
        assert result.unchanged_count == 2
        assert result.new_assets == []
        assert result.removed_assets == []
        assert result.changed_assets == []


class TestDiffEmptyPrevious:
    def test_diff_empty_previous(self):
        """When previous is empty (first scan), everything is new."""
        current = [
            _asset_dict(ip="10.0.0.1"),
            _asset_dict(ip="10.0.0.2", mac="ff:ee:dd:cc:bb:aa"),
        ]

        result = diff_scans(current, [])

        assert len(result.new_assets) == 2
        assert result.removed_assets == []
        assert result.changed_assets == []
        assert result.unchanged_count == 0


class TestDiffSummaryString:
    def test_summary_all_types(self):
        """Verify summary format includes all change types."""
        result = DiffResult(
            new_assets=[_asset_dict(ip="10.0.0.1")],
            removed_assets=[_asset_dict(ip="10.0.0.2")],
            changed_assets=[
                AssetChange(
                    ip="10.0.0.3",
                    mac=None,
                    change_type="port_change",
                    field="open_ports",
                    old_value="[22]",
                    new_value="[22, 80]",
                ),
            ],
            unchanged_count=5,
        )

        summary = result.summary
        assert "+1 new" in summary
        assert "-1 removed" in summary
        assert "~1 changed" in summary
        assert "=5 unchanged" in summary

    def test_summary_no_changes(self):
        """When nothing changed, summary should only show unchanged count."""
        result = DiffResult(unchanged_count=10)
        assert result.summary == "=10 unchanged"

    def test_summary_only_new(self):
        """Summary with only new assets."""
        result = DiffResult(new_assets=[_asset_dict()], unchanged_count=3)
        assert "+1 new" in result.summary
        assert "=3 unchanged" in result.summary
        assert "removed" not in result.summary
        assert "~" not in result.summary  # no '~N changed' part


class TestDiffResultHasChanges:
    def test_has_changes_with_new(self):
        result = DiffResult(new_assets=[_asset_dict()])
        assert result.has_changes is True

    def test_has_changes_with_removed(self):
        result = DiffResult(removed_assets=[_asset_dict()])
        assert result.has_changes is True

    def test_has_changes_with_changed(self):
        result = DiffResult(
            changed_assets=[
                AssetChange(ip="10.0.0.1", mac=None, change_type="port_change")
            ]
        )
        assert result.has_changes is True

    def test_has_changes_false(self):
        result = DiffResult(unchanged_count=5)
        assert result.has_changes is False


class TestDiffVendorChange:
    def test_diff_vendor_change(self):
        """Detect vendor field change."""
        previous = [_asset_dict(ip="10.0.0.1", vendor="Cisco")]
        current = [_asset_dict(ip="10.0.0.1", vendor="Juniper")]

        result = diff_scans(current, previous)

        vendor_changes = [
            c for c in result.changed_assets if c.change_type == "vendor_change"
        ]
        assert len(vendor_changes) == 1
        assert vendor_changes[0].old_value == "Cisco"
        assert vendor_changes[0].new_value == "Juniper"


class TestDiffHostnameChange:
    def test_diff_hostname_change(self):
        """Detect hostname field change."""
        previous = [_asset_dict(ip="10.0.0.1", hostname="old-host")]
        current = [_asset_dict(ip="10.0.0.1", hostname="new-host")]

        result = diff_scans(current, previous)

        hostname_changes = [
            c for c in result.changed_assets if c.change_type == "hostname_change"
        ]
        assert len(hostname_changes) == 1
        assert hostname_changes[0].old_value == "old-host"
        assert hostname_changes[0].new_value == "new-host"


# ---------------------------------------------------------------------------
# get_changes_from_db integration tests
# ---------------------------------------------------------------------------


class TestGetChangesFromDb:
    def test_get_changes_from_db(self, tmp_path: Path):
        """New assets produce change records readable via get_changes_from_db."""
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        changes = get_changes_from_db(db_path=db)

        # save_scan logs a new_asset change for each asset in the first scan
        assert len(changes) >= 1
        assert all("ip" in c for c in changes)
        assert all("change_type" in c for c in changes)
        assert all("detected_at" in c for c in changes)

    def test_get_changes_from_db_field_change(self, tmp_path: Path):
        """Field changes are recorded and returned."""
        db = tmp_path / "test.db"
        r1 = _make_scan_result(assets=[
            Asset(
                ip="10.0.0.1",
                mac="aa:bb:cc:dd:ee:ff",
                bigr_category=BigrCategory.UNCLASSIFIED,
                confidence_score=0.3,
            ),
        ])
        save_scan(r1, db_path=db)

        r2 = _make_scan_result(assets=[
            Asset(
                ip="10.0.0.1",
                mac="aa:bb:cc:dd:ee:ff",
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.85,
            ),
        ])
        r2.started_at = datetime(2026, 2, 1, tzinfo=timezone.utc)
        r2.completed_at = datetime(2026, 2, 1, 0, 1, 0, tzinfo=timezone.utc)
        save_scan(r2, db_path=db)

        changes = get_changes_from_db(db_path=db)

        field_changes = [c for c in changes if c["change_type"] == "field_changed"]
        assert len(field_changes) >= 1
        changed_fields = {c["field_name"] for c in field_changes}
        assert "bigr_category" in changed_fields

    def test_get_changes_from_db_empty(self, tmp_path: Path):
        """Empty database returns empty list."""
        db = tmp_path / "test.db"
        init_db(db)
        assert get_changes_from_db(db_path=db) == []

    def test_get_changes_from_db_limit(self, tmp_path: Path):
        """Limit parameter restricts returned rows."""
        db = tmp_path / "test.db"
        # Save scan with 3 assets to get at least 3 new_asset changes
        r = _make_scan_result(assets=[
            Asset(ip=f"10.0.0.{i}", mac=f"aa:bb:cc:dd:ee:{i:02x}", confidence_score=0.5)
            for i in range(5)
        ])
        save_scan(r, db_path=db)

        all_changes = get_changes_from_db(limit=100, db_path=db)
        limited = get_changes_from_db(limit=2, db_path=db)

        assert len(all_changes) == 5
        assert len(limited) == 2
