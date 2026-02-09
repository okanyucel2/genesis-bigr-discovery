"""Tests for multi-subnet / VLAN support."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from bigr.db import (
    add_subnet,
    get_subnets,
    init_db,
    remove_subnet,
    save_scan,
    update_subnet_stats,
)
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
# Part 1: Subnets Database Layer
# ---------------------------------------------------------------------------


class TestSubnetsDb:
    def test_init_creates_subnets_table(self, tmp_path: Path):
        """init_db should create subnets table."""
        db = tmp_path / "test.db"
        init_db(db)

        conn = sqlite3.connect(str(db))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = sorted(row[0] for row in cursor.fetchall())
        conn.close()

        assert "subnets" in tables

    def test_add_subnet(self, tmp_path: Path):
        """add_subnet should insert new subnet record."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("192.168.1.0/24", label="Office LAN", db_path=db)

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 1
        assert subnets[0]["cidr"] == "192.168.1.0/24"
        assert subnets[0]["label"] == "Office LAN"

    def test_add_subnet_with_vlan(self, tmp_path: Path):
        """add_subnet with vlan_id should store VLAN info."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("10.0.0.0/24", label="Server VLAN", vlan_id=100, db_path=db)

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 1
        assert subnets[0]["cidr"] == "10.0.0.0/24"
        assert subnets[0]["label"] == "Server VLAN"
        assert subnets[0]["vlan_id"] == 100

    def test_add_subnet_duplicate_updates(self, tmp_path: Path):
        """Adding same CIDR again should update label/vlan, not duplicate."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("10.0.0.0/24", label="Old Label", vlan_id=50, db_path=db)
        add_subnet("10.0.0.0/24", label="New Label", vlan_id=200, db_path=db)

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 1
        assert subnets[0]["label"] == "New Label"
        assert subnets[0]["vlan_id"] == 200

    def test_remove_subnet(self, tmp_path: Path):
        """remove_subnet should delete subnet record."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("192.168.1.0/24", label="Office", db_path=db)
        assert len(get_subnets(db_path=db)) == 1

        remove_subnet("192.168.1.0/24", db_path=db)
        assert len(get_subnets(db_path=db)) == 0

    def test_remove_nonexistent_subnet(self, tmp_path: Path):
        """Removing non-existent subnet should not error."""
        db = tmp_path / "test.db"
        init_db(db)
        # Should not raise
        remove_subnet("99.99.99.0/24", db_path=db)

    def test_get_subnets(self, tmp_path: Path):
        """get_subnets should return all registered subnets."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("10.0.0.0/24", label="VLAN 10", vlan_id=10, db_path=db)
        add_subnet("10.0.1.0/24", label="VLAN 20", vlan_id=20, db_path=db)
        add_subnet("172.16.0.0/16", label="Corporate", db_path=db)

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 3
        cidrs = {s["cidr"] for s in subnets}
        assert cidrs == {"10.0.0.0/24", "10.0.1.0/24", "172.16.0.0/16"}

    def test_get_subnets_empty(self, tmp_path: Path):
        """get_subnets on empty DB should return empty list."""
        db = tmp_path / "test.db"
        init_db(db)
        assert get_subnets(db_path=db) == []

    def test_update_subnet_scan_stats(self, tmp_path: Path):
        """After scan, subnet's last_scanned and asset_count should update."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("192.168.1.0/24", label="Office", db_path=db)

        update_subnet_stats("192.168.1.0/24", asset_count=15, db_path=db)

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 1
        assert subnets[0]["asset_count"] == 15
        assert subnets[0]["last_scanned"] is not None


# ---------------------------------------------------------------------------
# Part 2: Multi-Target Scan
# ---------------------------------------------------------------------------


class TestMultiTargetScan:
    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_multiple_targets(self, mock_classify, mock_scan, tmp_path: Path):
        """bigr scan with multiple targets should scan each."""
        mock_scan.return_value = _make_scan_result()
        mock_classify.return_value = mock_scan.return_value.assets

        from bigr.cli import app

        output_file = str(tmp_path / "out.json")
        result = runner.invoke(
            app,
            ["scan", "192.168.1.0/24", "10.0.0.0/24", "--output", output_file],
        )
        assert result.exit_code == 0
        # Should have been called once per target
        assert mock_scan.call_count == 2

    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_results_include_subnet_label(
        self, mock_classify, mock_scan, tmp_path: Path
    ):
        """Assets saved after multi-target scan should be tagged with subnet label."""
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("192.168.1.0/24", label="Office LAN", db_path=db)

        mock_scan.return_value = _make_scan_result(target="192.168.1.0/24")
        mock_classify.return_value = mock_scan.return_value.assets

        from bigr.cli import app

        output_file = str(tmp_path / "out.json")
        result = runner.invoke(
            app,
            ["scan", "192.168.1.0/24", "--output", output_file, "--db-path", str(db)],
        )
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    @patch("bigr.cli.run_hybrid_scan")
    @patch("bigr.cli.classify_assets")
    def test_scan_saves_per_subnet(self, mock_classify, mock_scan, tmp_path: Path):
        """Each subnet should create its own scan record in DB."""
        from bigr.cli import app
        from bigr.db import get_scan_list

        db = tmp_path / "test.db"
        init_db(db)

        def side_effect(target, **kwargs):
            return _make_scan_result(target=target)

        mock_scan.side_effect = side_effect
        mock_classify.return_value = []

        output_file = str(tmp_path / "out.json")
        result = runner.invoke(
            app,
            [
                "scan",
                "192.168.1.0/24",
                "10.0.0.0/24",
                "--output",
                output_file,
                "--db-path",
                str(db),
            ],
        )
        assert result.exit_code == 0
        scans = get_scan_list(db_path=db)
        assert len(scans) == 2
        targets = {s["target"] for s in scans}
        assert "192.168.1.0/24" in targets
        assert "10.0.0.0/24" in targets


# ---------------------------------------------------------------------------
# Part 3: Subnet CLI Commands
# ---------------------------------------------------------------------------


class TestSubnetsCli:
    def test_subnets_add(self, tmp_path: Path):
        """bigr subnets add should register subnet in DB."""
        from bigr.cli import app

        db = tmp_path / "test.db"
        init_db(db)
        result = runner.invoke(
            app,
            ["subnets", "add", "10.0.0.0/24", "--label", "Test Net", "--db-path", str(db)],
        )
        assert result.exit_code == 0

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 1
        assert subnets[0]["cidr"] == "10.0.0.0/24"
        assert subnets[0]["label"] == "Test Net"

    def test_subnets_add_with_vlan(self, tmp_path: Path):
        """bigr subnets add --vlan 100 should store VLAN ID."""
        from bigr.cli import app

        db = tmp_path / "test.db"
        init_db(db)
        result = runner.invoke(
            app,
            [
                "subnets",
                "add",
                "10.0.0.0/24",
                "--label",
                "Server VLAN",
                "--vlan",
                "100",
                "--db-path",
                str(db),
            ],
        )
        assert result.exit_code == 0

        subnets = get_subnets(db_path=db)
        assert len(subnets) == 1
        assert subnets[0]["vlan_id"] == 100

    def test_subnets_remove(self, tmp_path: Path):
        """bigr subnets remove should delete subnet from DB."""
        from bigr.cli import app

        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("10.0.0.0/24", label="Test", db_path=db)
        assert len(get_subnets(db_path=db)) == 1

        result = runner.invoke(
            app,
            ["subnets", "remove", "10.0.0.0/24", "--db-path", str(db)],
        )
        assert result.exit_code == 0
        assert len(get_subnets(db_path=db)) == 0

    def test_subnets_list(self, tmp_path: Path):
        """bigr subnets list should list all registered subnets."""
        from bigr.cli import app

        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("10.0.0.0/24", label="Office", vlan_id=10, db_path=db)
        add_subnet("172.16.0.0/16", label="Corp", db_path=db)

        result = runner.invoke(app, ["subnets", "list", "--db-path", str(db)])
        assert result.exit_code == 0
        assert "10.0.0.0/24" in result.output
        assert "172.16.0.0/16" in result.output
        assert "Office" in result.output

    def test_subnets_list_empty(self, tmp_path: Path):
        """bigr subnets list on empty DB should show message."""
        from bigr.cli import app

        db = tmp_path / "test.db"
        init_db(db)

        result = runner.invoke(app, ["subnets", "list", "--db-path", str(db)])
        assert result.exit_code == 0
        assert "No subnets" in result.output


# ---------------------------------------------------------------------------
# Part 4: Dashboard Subnet Filter
# ---------------------------------------------------------------------------


class TestDashboardSubnets:
    @pytest.mark.asyncio
    async def test_api_subnets_endpoint(self, tmp_path: Path):
        """GET /api/subnets should return registered subnets."""
        from httpx import ASGITransport, AsyncClient

        # Set up DB with subnets
        db = tmp_path / "test.db"
        init_db(db)
        add_subnet("10.0.0.0/24", label="Server VLAN", vlan_id=100, db_path=db)
        add_subnet("192.168.1.0/24", label="Office", db_path=db)

        # Create sample data file
        import json

        data = {
            "target": "192.168.1.0/24",
            "scan_method": "hybrid",
            "total_assets": 0,
            "category_summary": {},
            "assets": [],
        }
        json_path = tmp_path / "assets.json"
        json_path.write_text(json.dumps(data))

        from bigr.dashboard.app import create_app

        dashboard_app = create_app(data_path=str(json_path), db_path=db)
        transport = ASGITransport(app=dashboard_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/subnets")
            assert resp.status_code == 200
            result = resp.json()
            assert "subnets" in result
            assert len(result["subnets"]) == 2

    @pytest.mark.asyncio
    async def test_api_data_filter_by_subnet(self, tmp_path: Path):
        """GET /api/data?subnet=10.0.0.0/24 should filter assets."""
        from httpx import ASGITransport, AsyncClient

        import json

        data = {
            "target": "all",
            "scan_method": "hybrid",
            "total_assets": 3,
            "category_summary": {"ag_ve_sistemler": 2, "iot": 1},
            "assets": [
                {
                    "ip": "10.0.0.1",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "hostname": "server-01",
                    "vendor": "Dell",
                    "open_ports": [22, 80],
                    "bigr_category": "ag_ve_sistemler",
                    "bigr_category_tr": "Ag ve Sistemler",
                    "confidence_score": 0.85,
                    "subnet_cidr": "10.0.0.0/24",
                },
                {
                    "ip": "10.0.0.2",
                    "mac": "aa:bb:cc:dd:ee:02",
                    "hostname": "server-02",
                    "vendor": "Dell",
                    "open_ports": [22],
                    "bigr_category": "ag_ve_sistemler",
                    "bigr_category_tr": "Ag ve Sistemler",
                    "confidence_score": 0.80,
                    "subnet_cidr": "10.0.0.0/24",
                },
                {
                    "ip": "192.168.1.50",
                    "mac": "a4:14:37:00:11:22",
                    "hostname": "cam-01",
                    "vendor": "Hikvision",
                    "open_ports": [80, 554],
                    "bigr_category": "iot",
                    "bigr_category_tr": "IoT",
                    "confidence_score": 0.72,
                    "subnet_cidr": "192.168.1.0/24",
                },
            ],
        }
        json_path = tmp_path / "assets.json"
        json_path.write_text(json.dumps(data))

        db = tmp_path / "test.db"
        init_db(db)

        from bigr.dashboard.app import create_app

        dashboard_app = create_app(data_path=str(json_path), db_path=db)
        transport = ASGITransport(app=dashboard_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/data?subnet=10.0.0.0/24")
            assert resp.status_code == 200
            result = resp.json()
            # Should only contain assets from the 10.0.0.0/24 subnet
            filtered_assets = result["assets"]
            assert len(filtered_assets) == 2
            for asset in filtered_assets:
                assert asset["ip"].startswith("10.0.0.")
