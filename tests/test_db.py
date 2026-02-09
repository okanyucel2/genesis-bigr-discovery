"""Tests for SQLite persistence layer."""

from datetime import datetime, timezone
from pathlib import Path

from bigr.db import (
    get_all_assets,
    get_asset_history,
    get_latest_scan,
    get_scan_list,
    get_tags,
    init_db,
    save_scan,
    tag_asset,
    untag_asset,
)
from bigr.models import Asset, BigrCategory, ScanMethod, ScanResult


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


class TestInitDb:
    def test_init_creates_tables(self, tmp_path: Path):
        db = tmp_path / "test.db"
        init_db(db)

        import sqlite3

        conn = sqlite3.connect(str(db))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = sorted(row[0] for row in cursor.fetchall())
        conn.close()

        assert "assets" in tables
        assert "scans" in tables
        assert "scan_assets" in tables
        assert "asset_changes" in tables

    def test_init_is_idempotent(self, tmp_path: Path):
        db = tmp_path / "test.db"
        init_db(db)
        init_db(db)  # Should not raise


class TestSaveScan:
    def test_save_scan_creates_records(self, tmp_path: Path):
        db = tmp_path / "test.db"
        result = _make_scan_result()
        scan_id = save_scan(result, db_path=db)

        assert scan_id  # non-empty UUID string

        # Verify scan row
        scans = get_scan_list(db_path=db)
        assert len(scans) == 1
        assert scans[0]["target"] == "192.168.1.0/24"
        assert scans[0]["total_assets"] == 2

        # Verify assets
        assets = get_all_assets(db_path=db)
        assert len(assets) == 2
        ips = {a["ip"] for a in assets}
        assert "192.168.1.1" in ips
        assert "192.168.1.50" in ips

    def test_save_scan_upserts_assets(self, tmp_path: Path):
        """Second scan with same assets updates last_seen, does not duplicate."""
        db = tmp_path / "test.db"
        result1 = _make_scan_result()
        save_scan(result1, db_path=db)

        # Second scan with same assets but later timestamps
        result2 = _make_scan_result()
        result2.started_at = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
        result2.completed_at = datetime(2026, 2, 1, 12, 0, 45, tzinfo=timezone.utc)
        for asset in result2.assets:
            asset.last_seen = datetime(2026, 2, 1, 12, 0, 45, tzinfo=timezone.utc)
        save_scan(result2, db_path=db)

        # Should still have 2 assets, not 4
        assets = get_all_assets(db_path=db)
        assert len(assets) == 2

        # last_seen should be updated to the second scan's time
        router = next(a for a in assets if a["ip"] == "192.168.1.1")
        assert "2026-02-01" in router["last_seen"]

        # Should have 2 scans
        scans = get_scan_list(db_path=db)
        assert len(scans) == 2

    def test_save_scan_detects_new_asset(self, tmp_path: Path):
        """Second scan with a new IP creates a new asset row."""
        db = tmp_path / "test.db"
        result1 = _make_scan_result(assets=[
            Asset(
                ip="192.168.1.1",
                mac="00:1e:bd:aa:bb:cc",
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.80,
            ),
        ])
        save_scan(result1, db_path=db)
        assert len(get_all_assets(db_path=db)) == 1

        # Second scan introduces a new device
        result2 = _make_scan_result(assets=[
            Asset(
                ip="192.168.1.1",
                mac="00:1e:bd:aa:bb:cc",
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.80,
            ),
            Asset(
                ip="192.168.1.99",
                mac="ff:ee:dd:cc:bb:aa",
                hostname="new-device",
                bigr_category=BigrCategory.IOT,
                confidence_score=0.60,
            ),
        ])
        result2.started_at = datetime(2026, 2, 1, tzinfo=timezone.utc)
        result2.completed_at = datetime(2026, 2, 1, 0, 1, 0, tzinfo=timezone.utc)
        save_scan(result2, db_path=db)

        assets = get_all_assets(db_path=db)
        assert len(assets) == 2
        ips = {a["ip"] for a in assets}
        assert "192.168.1.99" in ips

    def test_save_scan_detects_field_changes(self, tmp_path: Path):
        """When an asset's category changes, a change record is created."""
        db = tmp_path / "test.db"
        result1 = _make_scan_result(assets=[
            Asset(
                ip="10.0.0.1",
                mac="aa:bb:cc:dd:ee:ff",
                bigr_category=BigrCategory.UNCLASSIFIED,
                confidence_score=0.30,
            ),
        ])
        save_scan(result1, db_path=db)

        # Second scan reclassifies the asset
        result2 = _make_scan_result(assets=[
            Asset(
                ip="10.0.0.1",
                mac="aa:bb:cc:dd:ee:ff",
                bigr_category=BigrCategory.AG_VE_SISTEMLER,
                confidence_score=0.85,
            ),
        ])
        result2.started_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
        result2.completed_at = datetime(2026, 3, 1, 0, 1, 0, tzinfo=timezone.utc)
        save_scan(result2, db_path=db)

        # Check asset_changes table
        import sqlite3

        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        changes = conn.execute(
            "SELECT * FROM asset_changes WHERE change_type = 'field_changed'"
        ).fetchall()
        conn.close()

        changed_fields = {row["field_name"] for row in changes}
        assert "bigr_category" in changed_fields
        assert "confidence_score" in changed_fields


class TestGetLatestScan:
    def test_get_latest_scan(self, tmp_path: Path):
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        latest = get_latest_scan(db_path=db)
        assert latest is not None
        assert latest["target"] == "192.168.1.0/24"
        assert latest["total_assets"] == 2
        assert len(latest["assets"]) == 2
        assert latest["duration_seconds"] == 30.0

    def test_get_latest_scan_empty_db(self, tmp_path: Path):
        db = tmp_path / "test.db"
        init_db(db)
        assert get_latest_scan(db_path=db) is None

    def test_get_latest_scan_by_target(self, tmp_path: Path):
        db = tmp_path / "test.db"
        r1 = _make_scan_result(target="10.0.0.0/24", assets=[
            Asset(ip="10.0.0.1", bigr_category=BigrCategory.IOT, confidence_score=0.5),
        ])
        r2 = _make_scan_result(target="192.168.1.0/24")
        save_scan(r1, db_path=db)
        save_scan(r2, db_path=db)

        latest = get_latest_scan(target="10.0.0.0/24", db_path=db)
        assert latest is not None
        assert latest["target"] == "10.0.0.0/24"


class TestGetAllAssets:
    def test_get_all_assets(self, tmp_path: Path):
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        assets = get_all_assets(db_path=db)
        assert len(assets) == 2
        # Should contain expected fields
        for a in assets:
            assert "ip" in a
            assert "mac" in a
            assert "bigr_category" in a
            assert "first_seen" in a
            assert "last_seen" in a

    def test_get_all_assets_empty(self, tmp_path: Path):
        db = tmp_path / "test.db"
        init_db(db)
        assert get_all_assets(db_path=db) == []


class TestGetScanList:
    def test_get_scan_list(self, tmp_path: Path):
        db = tmp_path / "test.db"
        for i in range(3):
            r = _make_scan_result()
            r.started_at = datetime(2026, 1, i + 1, tzinfo=timezone.utc)
            r.completed_at = datetime(2026, 1, i + 1, 0, 1, 0, tzinfo=timezone.utc)
            save_scan(r, db_path=db)

        scans = get_scan_list(db_path=db)
        assert len(scans) == 3
        # Most recent first
        assert scans[0]["started_at"] >= scans[1]["started_at"]

    def test_get_scan_list_limit(self, tmp_path: Path):
        db = tmp_path / "test.db"
        for i in range(5):
            r = _make_scan_result()
            r.started_at = datetime(2026, 1, i + 1, tzinfo=timezone.utc)
            r.completed_at = datetime(2026, 1, i + 1, 0, 1, 0, tzinfo=timezone.utc)
            save_scan(r, db_path=db)

        scans = get_scan_list(limit=3, db_path=db)
        assert len(scans) == 3


class TestTagAsset:
    def test_tag_and_untag_asset(self, tmp_path: Path):
        db = tmp_path / "test.db"
        result = _make_scan_result()
        save_scan(result, db_path=db)

        # Tag
        tag_asset("192.168.1.1", "iot", note="Actually a smart switch", db_path=db)
        tags = get_tags(db_path=db)
        assert len(tags) == 1
        assert tags[0]["ip"] == "192.168.1.1"
        assert tags[0]["manual_category"] == "iot"
        assert tags[0]["manual_note"] == "Actually a smart switch"

        # Untag
        untag_asset("192.168.1.1", db_path=db)
        tags = get_tags(db_path=db)
        assert len(tags) == 0

    def test_tag_nonexistent_ip(self, tmp_path: Path):
        """Tagging a non-existent IP should not raise (no-op)."""
        db = tmp_path / "test.db"
        init_db(db)
        tag_asset("99.99.99.99", "iot", db_path=db)
        assert get_tags(db_path=db) == []


class TestGetAssetHistory:
    def test_asset_history_by_ip(self, tmp_path: Path):
        db = tmp_path / "test.db"
        r1 = _make_scan_result(assets=[
            Asset(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", confidence_score=0.5),
        ])
        save_scan(r1, db_path=db)

        r2 = _make_scan_result(assets=[
            Asset(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", confidence_score=0.8),
        ])
        r2.started_at = datetime(2026, 2, 1, tzinfo=timezone.utc)
        r2.completed_at = datetime(2026, 2, 1, 0, 1, 0, tzinfo=timezone.utc)
        save_scan(r2, db_path=db)

        history = get_asset_history(ip="10.0.0.5", db_path=db)
        assert len(history) == 2

    def test_asset_history_empty(self, tmp_path: Path):
        db = tmp_path / "test.db"
        init_db(db)
        assert get_asset_history(ip="1.2.3.4", db_path=db) == []

    def test_asset_history_no_args(self, tmp_path: Path):
        db = tmp_path / "test.db"
        init_db(db)
        assert get_asset_history(db_path=db) == []
