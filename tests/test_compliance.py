"""Tests for BİGR compliance scoring and metrics engine (Phase 5A)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

from bigr.compliance import (
    CategoryDistribution,
    ComplianceBreakdown,
    ComplianceReport,
    SubnetCompliance,
    calculate_compliance,
    calculate_subnet_compliance,
    generate_action_items,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# TestComplianceBreakdown
# ---------------------------------------------------------------------------


class TestComplianceBreakdown:
    """Tests for ComplianceBreakdown dataclass and scoring."""

    def test_compliance_score_all_classified(self):
        """10/10 fully classified -> 100%."""
        b = ComplianceBreakdown(
            total_assets=10,
            fully_classified=10,
            partially_classified=0,
            unclassified=0,
            manual_overrides=0,
        )
        assert b.compliance_score == 100.0

    def test_compliance_score_mixed(self):
        """5 full + 3 partial + 2 unclassified -> (5 + 3*0.5) / 10 * 100 = 65.0."""
        b = ComplianceBreakdown(
            total_assets=10,
            fully_classified=5,
            partially_classified=3,
            unclassified=2,
            manual_overrides=0,
        )
        assert b.compliance_score == 65.0

    def test_compliance_score_all_unclassified(self):
        """0 classified -> 0%."""
        b = ComplianceBreakdown(
            total_assets=10,
            fully_classified=0,
            partially_classified=0,
            unclassified=10,
            manual_overrides=0,
        )
        assert b.compliance_score == 0.0

    def test_compliance_score_empty(self):
        """0 assets -> 100% (compliant by default)."""
        b = ComplianceBreakdown()
        assert b.compliance_score == 100.0

    def test_compliance_score_manual_as_full(self):
        """Manual overrides count as fully classified.
        3 manual + 2 full + 5 unclass = (3+2)/10*100 = 50.0."""
        b = ComplianceBreakdown(
            total_assets=10,
            fully_classified=2,
            partially_classified=0,
            unclassified=5,
            manual_overrides=3,
        )
        assert b.compliance_score == 50.0

    def test_grade_a(self):
        """Score >= 90 -> grade A."""
        b = ComplianceBreakdown(total_assets=10, fully_classified=10)
        assert b.grade == "A"

    def test_grade_b(self):
        """Score 80-89 -> grade B."""
        b = ComplianceBreakdown(
            total_assets=10, fully_classified=8, partially_classified=0, unclassified=2,
        )
        assert b.compliance_score == 80.0
        assert b.grade == "B"

    def test_grade_c(self):
        """Score 70-79 -> grade C."""
        b = ComplianceBreakdown(
            total_assets=10, fully_classified=7, partially_classified=0, unclassified=3,
        )
        assert b.compliance_score == 70.0
        assert b.grade == "C"

    def test_grade_d(self):
        """Score 60-69 -> grade D."""
        b = ComplianceBreakdown(
            total_assets=10, fully_classified=6, partially_classified=0, unclassified=4,
        )
        assert b.compliance_score == 60.0
        assert b.grade == "D"

    def test_grade_f(self):
        """Score < 60 -> grade F."""
        b = ComplianceBreakdown(
            total_assets=10, fully_classified=5, partially_classified=0, unclassified=5,
        )
        assert b.compliance_score == 50.0
        assert b.grade == "F"


# ---------------------------------------------------------------------------
# TestCategoryDistribution
# ---------------------------------------------------------------------------


class TestCategoryDistribution:
    """Tests for CategoryDistribution dataclass."""

    def test_total(self):
        """Total is sum of all categories."""
        d = CategoryDistribution(
            ag_ve_sistemler=5, uygulamalar=3, iot=2, tasinabilir=1, unclassified=4,
        )
        assert d.total == 15

    def test_percentages(self):
        """Correct percentage calculation."""
        d = CategoryDistribution(
            ag_ve_sistemler=5, uygulamalar=3, iot=2, tasinabilir=0, unclassified=0,
        )
        pct = d.percentages()
        assert pct["ag_ve_sistemler"] == 50.0
        assert pct["uygulamalar"] == 30.0
        assert pct["iot"] == 20.0
        assert pct["tasinabilir"] == 0.0
        assert pct["unclassified"] == 0.0

    def test_percentages_empty(self):
        """0 total -> all 0%."""
        d = CategoryDistribution()
        pct = d.percentages()
        assert all(v == 0.0 for v in pct.values())

    def test_to_dict(self):
        """Dict has counts, percentages, and total."""
        d = CategoryDistribution(ag_ve_sistemler=4, uygulamalar=6)
        result = d.to_dict()
        assert "counts" in result
        assert "percentages" in result
        assert "total" in result
        assert result["total"] == 10
        assert result["counts"]["ag_ve_sistemler"] == 4
        assert result["counts"]["uygulamalar"] == 6
        assert result["percentages"]["ag_ve_sistemler"] == 40.0
        assert result["percentages"]["uygulamalar"] == 60.0


# ---------------------------------------------------------------------------
# TestCalculateCompliance
# ---------------------------------------------------------------------------


# Helper to build asset dicts for tests
def _make_asset(
    ip: str,
    confidence: float = 0.8,
    category: str = "ag_ve_sistemler",
    manual_category: str | None = None,
    hostname: str | None = None,
    subnet_cidr: str | None = None,
) -> dict:
    return {
        "ip": ip,
        "mac": None,
        "hostname": hostname,
        "vendor": None,
        "confidence_score": confidence,
        "bigr_category": category,
        "manual_category": manual_category,
        "subnet_cidr": subnet_cidr,
    }


class TestCalculateCompliance:
    """Tests for calculate_compliance() function."""

    def test_fully_classified_assets(self):
        """All high confidence -> 100% score."""
        assets = [_make_asset(f"10.0.0.{i}", confidence=0.9) for i in range(5)]
        report = calculate_compliance(assets)
        assert report.breakdown.compliance_score == 100.0

    def test_mixed_confidence_assets(self):
        """Mixed confidence levels produce correct score."""
        assets = [
            _make_asset("10.0.0.1", confidence=0.9),    # fully
            _make_asset("10.0.0.2", confidence=0.8),    # fully
            _make_asset("10.0.0.3", confidence=0.5),    # partially
            _make_asset("10.0.0.4", confidence=0.1),    # unclassified
        ]
        report = calculate_compliance(assets)
        # (2 + 0 manual + 1*0.5) / 4 * 100 = 62.5
        assert report.breakdown.compliance_score == 62.5

    def test_with_manual_overrides(self):
        """Manual overrides boost score."""
        assets = [
            _make_asset("10.0.0.1", confidence=0.1, manual_category="iot"),
            _make_asset("10.0.0.2", confidence=0.1, manual_category="uygulamalar"),
        ]
        report = calculate_compliance(assets)
        # Both have manual override -> both count as fully classified
        assert report.breakdown.manual_overrides == 2
        assert report.breakdown.compliance_score == 100.0

    def test_with_unclassified_only(self):
        """All unclassified -> low score."""
        assets = [_make_asset(f"10.0.0.{i}", confidence=0.1, category="unclassified") for i in range(5)]
        report = calculate_compliance(assets)
        assert report.breakdown.compliance_score == 0.0

    def test_empty_assets(self):
        """No assets -> 100%."""
        report = calculate_compliance([])
        assert report.breakdown.compliance_score == 100.0

    def test_category_distribution_correct(self):
        """Categories counted correctly."""
        assets = [
            _make_asset("10.0.0.1", category="ag_ve_sistemler"),
            _make_asset("10.0.0.2", category="ag_ve_sistemler"),
            _make_asset("10.0.0.3", category="iot"),
            _make_asset("10.0.0.4", category="uygulamalar"),
            _make_asset("10.0.0.5", category="unclassified"),
        ]
        report = calculate_compliance(assets)
        assert report.distribution.ag_ve_sistemler == 2
        assert report.distribution.iot == 1
        assert report.distribution.uygulamalar == 1
        assert report.distribution.unclassified == 1

    def test_returns_compliance_report(self):
        """Returns ComplianceReport type."""
        report = calculate_compliance([])
        assert isinstance(report, ComplianceReport)


# ---------------------------------------------------------------------------
# TestGenerateActionItems
# ---------------------------------------------------------------------------


class TestGenerateActionItems:
    """Tests for generate_action_items() function."""

    def test_unclassified_generates_classify(self):
        """Unclassified assets -> 'classify' action."""
        assets = [_make_asset("10.0.0.1", confidence=0.1, category="unclassified")]
        actions = generate_action_items(assets)
        classify_actions = [a for a in actions if a["type"] == "classify"]
        assert len(classify_actions) >= 1
        assert classify_actions[0]["ip"] == "10.0.0.1"

    def test_low_confidence_generates_review(self):
        """Low confidence assets -> 'review' action."""
        assets = [_make_asset("10.0.0.1", confidence=0.35, category="iot")]
        actions = generate_action_items(assets)
        review_actions = [a for a in actions if a["type"] == "review"]
        assert len(review_actions) >= 1
        assert review_actions[0]["ip"] == "10.0.0.1"

    def test_high_confidence_no_action(self):
        """High confidence assets -> no action needed."""
        assets = [_make_asset("10.0.0.1", confidence=0.95, category="ag_ve_sistemler")]
        actions = generate_action_items(assets)
        assert len(actions) == 0

    def test_action_items_have_priority(self):
        """Each action has priority field."""
        assets = [_make_asset("10.0.0.1", confidence=0.1, category="unclassified")]
        actions = generate_action_items(assets)
        for action in actions:
            assert "priority" in action
            assert action["priority"] in ("critical", "high", "normal")

    def test_action_items_sorted_by_priority(self):
        """Critical actions before normal actions."""
        assets = [
            _make_asset("10.0.0.1", confidence=0.5, category="iot"),       # review -> normal
            _make_asset("10.0.0.2", confidence=0.1, category="unclassified"),  # classify -> critical
        ]
        actions = generate_action_items(assets)
        if len(actions) >= 2:
            priority_order = {"critical": 0, "high": 1, "normal": 2}
            priorities = [priority_order.get(a["priority"], 99) for a in actions]
            assert priorities == sorted(priorities)

    def test_empty_assets_no_actions(self):
        """No assets -> no actions."""
        actions = generate_action_items([])
        assert actions == []


# ---------------------------------------------------------------------------
# TestSubnetCompliance
# ---------------------------------------------------------------------------


class TestSubnetCompliance:
    """Tests for calculate_subnet_compliance()."""

    def test_single_subnet(self):
        """Assets in one subnet -> correct score."""
        assets = [
            _make_asset("192.168.1.10", confidence=0.9, subnet_cidr="192.168.1.0/24"),
            _make_asset("192.168.1.20", confidence=0.8, subnet_cidr="192.168.1.0/24"),
        ]
        subnets = [{"cidr": "192.168.1.0/24", "label": "Office"}]
        result = calculate_subnet_compliance(assets, subnets)
        assert len(result) == 1
        assert result[0].cidr == "192.168.1.0/24"
        assert result[0].label == "Office"
        assert result[0].breakdown.compliance_score == 100.0

    def test_multiple_subnets(self):
        """Different scores per subnet."""
        assets = [
            _make_asset("192.168.1.10", confidence=0.9, subnet_cidr="192.168.1.0/24"),
            _make_asset("10.0.0.5", confidence=0.1, category="unclassified", subnet_cidr="10.0.0.0/24"),
        ]
        subnets = [
            {"cidr": "192.168.1.0/24", "label": "Office"},
            {"cidr": "10.0.0.0/24", "label": "DMZ"},
        ]
        result = calculate_subnet_compliance(assets, subnets)
        assert len(result) == 2
        scores = {sc.cidr: sc.breakdown.compliance_score for sc in result}
        assert scores["192.168.1.0/24"] == 100.0
        assert scores["10.0.0.0/24"] == 0.0

    def test_no_subnets(self):
        """No subnets -> empty list."""
        assets = [_make_asset("10.0.0.1")]
        result = calculate_subnet_compliance(assets, [])
        assert result == []


# ---------------------------------------------------------------------------
# TestComplianceReport
# ---------------------------------------------------------------------------


class TestComplianceReport:
    """Tests for ComplianceReport.to_dict()."""

    def test_to_dict(self):
        """Full serialization includes all keys."""
        report = ComplianceReport(
            breakdown=ComplianceBreakdown(total_assets=10, fully_classified=8, unclassified=2),
            distribution=CategoryDistribution(ag_ve_sistemler=8, unclassified=2),
        )
        d = report.to_dict()
        assert "compliance_score" in d
        assert "grade" in d
        assert "breakdown" in d
        assert "distribution" in d
        assert "subnet_compliance" in d
        assert "action_items" in d

    def test_to_dict_has_grade(self):
        """Grade included in serialization."""
        report = ComplianceReport(
            breakdown=ComplianceBreakdown(total_assets=10, fully_classified=10),
            distribution=CategoryDistribution(ag_ve_sistemler=10),
        )
        d = report.to_dict()
        assert d["grade"] == "A"

    def test_to_dict_has_action_items(self):
        """Action items included in serialization."""
        report = ComplianceReport(
            breakdown=ComplianceBreakdown(),
            distribution=CategoryDistribution(),
            action_items=[{"type": "classify", "ip": "10.0.0.1", "priority": "critical", "reason": "Unclassified"}],
        )
        d = report.to_dict()
        assert len(d["action_items"]) == 1
        assert d["action_items"][0]["type"] == "classify"

    def test_to_dict_has_subnet_compliance(self):
        """Subnet data included in serialization."""
        sc = SubnetCompliance(
            cidr="192.168.1.0/24",
            label="Office",
            breakdown=ComplianceBreakdown(total_assets=5, fully_classified=5),
        )
        report = ComplianceReport(
            breakdown=ComplianceBreakdown(total_assets=5, fully_classified=5),
            distribution=CategoryDistribution(ag_ve_sistemler=5),
            subnet_compliance=[sc],
        )
        d = report.to_dict()
        assert len(d["subnet_compliance"]) == 1
        assert d["subnet_compliance"][0]["cidr"] == "192.168.1.0/24"
        assert d["subnet_compliance"][0]["score"] == 100.0
        assert d["subnet_compliance"][0]["grade"] == "A"


# ---------------------------------------------------------------------------
# TestComplianceCli
# ---------------------------------------------------------------------------


class TestComplianceCli:
    """Tests for CLI compliance command."""

    def test_compliance_command_summary(self, tmp_path: Path):
        """CLI shows compliance summary."""
        from bigr.cli import app as cli_app

        # Create a minimal DB with assets
        db_path = tmp_path / "test.db"
        _seed_test_db(db_path)

        result = runner.invoke(cli_app, ["compliance", "--db-path", str(db_path)])
        assert result.exit_code == 0
        # Should contain compliance score or grade
        assert "Compliance" in result.output or "compliance" in result.output.lower()

    def test_compliance_command_json(self, tmp_path: Path):
        """CLI --format json outputs JSON."""
        from bigr.cli import app as cli_app

        db_path = tmp_path / "test.db"
        _seed_test_db(db_path)

        result = runner.invoke(cli_app, ["compliance", "--format", "json", "--db-path", str(db_path)])
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert "compliance_score" in data


# ---------------------------------------------------------------------------
# TestComplianceApi
# ---------------------------------------------------------------------------


class TestComplianceApi:
    """Tests for dashboard compliance endpoints."""

    @pytest.fixture
    def sample_data(self, tmp_path: Path) -> Path:
        """Create a sample assets.json for testing."""
        data = {
            "target": "192.168.1.0/24",
            "scan_method": "hybrid",
            "duration_seconds": 12.5,
            "total_assets": 3,
            "category_summary": {"ag_ve_sistemler": 2, "iot": 1},
            "assets": [
                {
                    "ip": "192.168.1.1",
                    "mac": "00:1e:bd:aa:bb:cc",
                    "hostname": "router-01",
                    "vendor": "Cisco",
                    "open_ports": [22, 80],
                    "bigr_category": "ag_ve_sistemler",
                    "confidence_score": 0.85,
                },
                {
                    "ip": "192.168.1.2",
                    "mac": "00:1e:bd:aa:bb:dd",
                    "hostname": "switch-01",
                    "vendor": "Cisco",
                    "open_ports": [22],
                    "bigr_category": "ag_ve_sistemler",
                    "confidence_score": 0.9,
                },
                {
                    "ip": "192.168.1.50",
                    "mac": "a4:14:37:00:11:22",
                    "hostname": "cam-01",
                    "vendor": "Hikvision",
                    "open_ports": [80, 554],
                    "bigr_category": "iot",
                    "confidence_score": 0.72,
                },
            ],
        }
        json_path = tmp_path / "assets.json"
        json_path.write_text(json.dumps(data))
        return json_path

    @pytest.fixture
    def app(self, sample_data: Path):
        from bigr.dashboard.app import create_app
        return create_app(data_path=str(sample_data))

    @pytest.mark.asyncio
    async def test_api_compliance_endpoint(self, app):
        """/api/compliance returns JSON with compliance data."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/compliance")
            assert resp.status_code == 200
            data = resp.json()
            assert "compliance_score" in data
            assert "grade" in data
            assert "breakdown" in data

    @pytest.mark.asyncio
    async def test_compliance_page_returns_html(self, app):
        """/compliance returns HTML page."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/compliance")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "Compliance" in resp.text


# ---------------------------------------------------------------------------
# Test DB helper
# ---------------------------------------------------------------------------


def _seed_test_db(db_path: Path) -> None:
    """Create a test database with sample assets for CLI tests."""
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            os_hint TEXT,
            bigr_category TEXT NOT NULL DEFAULT 'unclassified',
            confidence_score REAL NOT NULL DEFAULT 0.0,
            scan_method TEXT NOT NULL DEFAULT 'passive',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            manual_category TEXT,
            manual_note TEXT,
            is_ignored INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS subnets (
            cidr TEXT PRIMARY KEY,
            label TEXT DEFAULT '',
            vlan_id INTEGER,
            last_scanned TEXT,
            asset_count INTEGER DEFAULT 0
        );
    """)
    conn.execute(
        """INSERT INTO assets (id, ip, mac, hostname, vendor, bigr_category, confidence_score,
           scan_method, first_seen, last_seen)
           VALUES ('a1', '192.168.1.1', '00:11:22:33:44:55', 'router', 'Cisco',
                   'ag_ve_sistemler', 0.9, 'hybrid', '2026-01-01', '2026-01-01')"""
    )
    conn.execute(
        """INSERT INTO assets (id, ip, mac, hostname, vendor, bigr_category, confidence_score,
           scan_method, first_seen, last_seen)
           VALUES ('a2', '192.168.1.50', 'aa:bb:cc:dd:ee:ff', 'cam-01', 'Hikvision',
                   'iot', 0.5, 'hybrid', '2026-01-01', '2026-01-01')"""
    )
    conn.execute(
        """INSERT INTO assets (id, ip, mac, hostname, vendor, bigr_category, confidence_score,
           scan_method, first_seen, last_seen)
           VALUES ('a3', '192.168.1.100', NULL, NULL, NULL,
                   'unclassified', 0.1, 'passive', '2026-01-01', '2026-01-01')"""
    )
    conn.commit()
    conn.close()
