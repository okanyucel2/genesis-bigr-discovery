"""Tests for bigr.risk — Risk Scoring Engine (Phase 6B)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

from bigr.risk.models import RiskFactors, RiskProfile, RiskReport


class TestRiskFactors:
    """Tests for RiskFactors dataclass."""

    def test_defaults(self):
        """All factors should default to 0.0."""
        rf = RiskFactors()
        assert rf.cve_score == 0.0
        assert rf.exposure_score == 0.0
        assert rf.classification_score == 0.0
        assert rf.age_score == 0.0
        assert rf.change_score == 0.0

    def test_to_dict(self):
        """to_dict should include all factor fields."""
        rf = RiskFactors(cve_score=0.5, exposure_score=0.3)
        d = rf.to_dict()
        assert "cve_score" in d
        assert "exposure_score" in d
        assert "classification_score" in d
        assert "age_score" in d
        assert "change_score" in d
        assert d["cve_score"] == 0.5
        assert d["exposure_score"] == 0.3


class TestRiskProfile:
    """Tests for RiskProfile dataclass."""

    def test_level_critical(self):
        """Score >= 8.0 should be 'critical'."""
        assert RiskProfile.level_from_score(9.0) == "critical"
        assert RiskProfile.level_from_score(8.0) == "critical"

    def test_level_high(self):
        """Score >= 6.0 and < 8.0 should be 'high'."""
        assert RiskProfile.level_from_score(7.0) == "high"
        assert RiskProfile.level_from_score(6.0) == "high"

    def test_level_medium(self):
        """Score >= 4.0 and < 6.0 should be 'medium'."""
        assert RiskProfile.level_from_score(5.0) == "medium"
        assert RiskProfile.level_from_score(4.0) == "medium"

    def test_level_low(self):
        """Score >= 2.0 and < 4.0 should be 'low'."""
        assert RiskProfile.level_from_score(3.0) == "low"
        assert RiskProfile.level_from_score(2.0) == "low"

    def test_level_info(self):
        """Score < 2.0 should be 'info'."""
        assert RiskProfile.level_from_score(1.0) == "info"
        assert RiskProfile.level_from_score(0.0) == "info"

    def test_to_dict(self):
        """to_dict should serialize all fields."""
        rp = RiskProfile(
            ip="10.0.0.1",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="server1",
            vendor="Cisco",
            bigr_category="ag_ve_sistemler",
            risk_score=7.5,
            risk_level="high",
            top_cve="CVE-2024-1234",
        )
        d = rp.to_dict()
        assert d["ip"] == "10.0.0.1"
        assert d["mac"] == "aa:bb:cc:dd:ee:ff"
        assert d["hostname"] == "server1"
        assert d["vendor"] == "Cisco"
        assert d["bigr_category"] == "ag_ve_sistemler"
        assert d["risk_score"] == 7.5
        assert d["risk_level"] == "high"
        assert d["top_cve"] == "CVE-2024-1234"
        assert "factors" in d


class TestRiskReport:
    """Tests for RiskReport dataclass."""

    def test_top_risks_sorted(self):
        """top_risks should be sorted by risk_score descending."""
        profiles = [
            RiskProfile(ip="10.0.0.1", risk_score=3.0),
            RiskProfile(ip="10.0.0.2", risk_score=9.0),
            RiskProfile(ip="10.0.0.3", risk_score=6.0),
        ]
        report = RiskReport(profiles=profiles)
        top = report.top_risks
        assert top[0].ip == "10.0.0.2"
        assert top[1].ip == "10.0.0.3"
        assert top[2].ip == "10.0.0.1"

    def test_top_risks_limit_10(self):
        """top_risks should return at most 10 profiles."""
        profiles = [RiskProfile(ip=f"10.0.0.{i}", risk_score=float(i)) for i in range(20)]
        report = RiskReport(profiles=profiles)
        assert len(report.top_risks) == 10

    def test_to_dict(self):
        """to_dict should serialize all report fields."""
        report = RiskReport(
            profiles=[RiskProfile(ip="10.0.0.1", risk_score=5.0)],
            average_risk=5.0,
            max_risk=5.0,
            critical_count=0,
            high_count=0,
            medium_count=1,
            low_count=0,
        )
        d = report.to_dict()
        assert "profiles" in d
        assert "average_risk" in d
        assert "max_risk" in d
        assert "critical_count" in d
        assert "high_count" in d
        assert "medium_count" in d
        assert "low_count" in d
        assert "top_risks" in d
        assert len(d["profiles"]) == 1

    def test_empty_profiles(self):
        """Empty profiles should produce empty top_risks."""
        report = RiskReport()
        assert report.top_risks == []
        assert report.profiles == []


# ---------------------------------------------------------------------------
# Scorer Function Tests
# ---------------------------------------------------------------------------

from bigr.risk.scorer import (
    CATEGORY_RISK,
    HIGH_RISK_PORTS,
    WEIGHTS,
    assess_network_risk,
    calculate_age_score,
    calculate_change_score,
    calculate_classification_score,
    calculate_cve_score,
    calculate_exposure_score,
    calculate_risk,
)


class TestCalculateCveScore:
    """Tests for calculate_cve_score."""

    def test_max_cvss_10(self):
        """CVSS 10.0 should map to 1.0."""
        assert calculate_cve_score(10.0) == 1.0

    def test_max_cvss_0(self):
        """CVSS 0.0 should map to 0.0."""
        assert calculate_cve_score(0.0) == 0.0

    def test_max_cvss_mid(self):
        """CVSS 5.0 should map to 0.5."""
        assert calculate_cve_score(5.0) == 0.5

    def test_clamp_above_10(self):
        """CVSS above 10.0 should be clamped to 1.0."""
        assert calculate_cve_score(11.0) == 1.0


class TestCalculateExposureScore:
    """Tests for calculate_exposure_score."""

    def test_telnet_high_risk(self):
        """Telnet (port 23) should have high risk score (0.9)."""
        score = calculate_exposure_score([23])
        assert score >= 0.9

    def test_https_only(self):
        """HTTPS only (port 443) should be moderate."""
        score = calculate_exposure_score([443])
        assert 0.2 <= score <= 0.5

    def test_many_ports_multiplier(self):
        """More ports should produce higher score than fewer."""
        few = calculate_exposure_score([80])
        many = calculate_exposure_score([21, 22, 23, 80, 443, 445, 3389])
        assert many > few

    def test_no_ports(self):
        """No open ports should return 0.0."""
        assert calculate_exposure_score([]) == 0.0

    def test_unknown_port(self):
        """Unknown port should get a base score."""
        score = calculate_exposure_score([12345])
        assert 0.0 < score <= 0.3


class TestCalculateClassificationScore:
    """Tests for calculate_classification_score."""

    def test_iot_highest(self):
        """IoT category should have high risk (0.8)."""
        assert calculate_classification_score("iot") == 0.8

    def test_ag_lowest(self):
        """ag_ve_sistemler should have lowest risk (0.3)."""
        assert calculate_classification_score("ag_ve_sistemler") == 0.3

    def test_unclassified_very_high(self):
        """Unclassified should have very high risk (0.9)."""
        assert calculate_classification_score("unclassified") == 0.9

    def test_unknown_category(self):
        """Unknown category should default to unclassified risk."""
        score = calculate_classification_score("xxx")
        assert score == CATEGORY_RISK["unclassified"]


class TestCalculateAgeScore:
    """Tests for calculate_age_score."""

    def test_old_device(self):
        """Device seen 400 days ago should have score 1.0."""
        first_seen = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        assert calculate_age_score(first_seen) == 1.0

    def test_recent_device(self):
        """Device seen 10 days ago should have score 0.1."""
        first_seen = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        assert calculate_age_score(first_seen) == 0.1

    def test_90_days(self):
        """Device seen 100 days ago should have score 0.5."""
        first_seen = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        assert calculate_age_score(first_seen) == 0.5

    def test_none_first_seen(self):
        """None first_seen should return 0.0."""
        assert calculate_age_score(None) == 0.0


class TestCalculateChangeScore:
    """Tests for calculate_change_score."""

    def test_many_changes(self):
        """25 changes should return 1.0."""
        assert calculate_change_score(25) == 1.0

    def test_moderate_changes(self):
        """8 changes should return 0.5."""
        assert calculate_change_score(8) == 0.5

    def test_no_changes(self):
        """0 changes should return 0.0."""
        assert calculate_change_score(0) == 0.0


# ---------------------------------------------------------------------------
# Integration Tests: calculate_risk, assess_network_risk
# ---------------------------------------------------------------------------


def _make_asset(
    ip: str = "10.0.0.1",
    mac: str = "aa:bb:cc:dd:ee:ff",
    hostname: str | None = "device1",
    vendor: str | None = "Cisco",
    bigr_category: str = "ag_ve_sistemler",
    confidence_score: float = 0.8,
    open_ports: list[int] | None = None,
    first_seen: str | None = None,
) -> dict:
    """Helper to build an asset dict for testing."""
    if first_seen is None:
        first_seen = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "bigr_category": bigr_category,
        "confidence_score": confidence_score,
        "open_ports": open_ports or [],
        "first_seen": first_seen,
    }


class TestCalculateRisk:
    """Tests for calculate_risk (full risk profile for a single asset)."""

    def test_high_risk_iot_with_cves(self):
        """IoT device with critical CVE should have high risk score."""
        asset = _make_asset(
            bigr_category="iot",
            open_ports=[23, 80, 554],
            first_seen=(datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
        )
        profile = calculate_risk(asset, max_cvss=10.0, change_count=15)
        assert profile.risk_score >= 7.0
        assert profile.risk_level in ("critical", "high")

    def test_low_risk_managed_switch(self):
        """Managed switch with no CVE should have low risk."""
        asset = _make_asset(
            bigr_category="ag_ve_sistemler",
            open_ports=[443],
            first_seen=(datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
        )
        profile = calculate_risk(asset, max_cvss=0.0, change_count=0)
        assert profile.risk_score < 4.0
        assert profile.risk_level in ("low", "info")

    def test_unclassified_risky(self):
        """Unclassified device should have elevated risk."""
        asset = _make_asset(bigr_category="unclassified")
        profile = calculate_risk(asset, max_cvss=0.0, change_count=0)
        # Unclassified contributes 0.9 classification factor
        assert profile.factors.classification_score == 0.9

    def test_score_within_range(self):
        """Risk score should be between 0.0 and 10.0."""
        asset = _make_asset()
        profile = calculate_risk(asset)
        assert 0.0 <= profile.risk_score <= 10.0

    def test_risk_level_matches_score(self):
        """Risk level should match score range."""
        asset = _make_asset(
            bigr_category="iot",
            open_ports=[23, 445],
            first_seen=(datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
        )
        profile = calculate_risk(asset, max_cvss=9.5, change_count=25)
        expected_level = RiskProfile.level_from_score(profile.risk_score)
        assert profile.risk_level == expected_level

    def test_factors_populated(self):
        """All factors should have values when inputs are provided."""
        asset = _make_asset(
            bigr_category="iot",
            open_ports=[80],
            first_seen=(datetime.now(timezone.utc) - timedelta(days=50)).isoformat(),
        )
        profile = calculate_risk(asset, max_cvss=5.0, change_count=3)
        assert profile.factors.cve_score > 0
        assert profile.factors.exposure_score > 0
        assert profile.factors.classification_score > 0
        assert profile.factors.age_score > 0
        assert profile.factors.change_score > 0


class TestAssessNetworkRisk:
    """Tests for assess_network_risk (full network assessment)."""

    def test_returns_risk_report(self):
        """Should return a RiskReport instance."""
        assets = [_make_asset(ip=f"10.0.0.{i}") for i in range(3)]
        report = assess_network_risk(assets)
        assert isinstance(report, RiskReport)

    def test_counts_correct(self):
        """Critical/high/medium/low counts should match profiles."""
        assets = [
            _make_asset(ip="10.0.0.1", bigr_category="iot", open_ports=[23, 445]),
            _make_asset(ip="10.0.0.2", bigr_category="ag_ve_sistemler", open_ports=[443]),
            _make_asset(ip="10.0.0.3", bigr_category="unclassified", open_ports=[80]),
        ]
        report = assess_network_risk(assets)
        total = report.critical_count + report.high_count + report.medium_count + report.low_count
        # Total of categorized profiles should equal number of profiles
        # (some might be 'info' which is not counted in the four)
        info_count = sum(1 for p in report.profiles if p.risk_level == "info")
        assert total + info_count == len(report.profiles)

    def test_average_risk(self):
        """Average risk should be calculated correctly."""
        assets = [_make_asset(ip=f"10.0.0.{i}") for i in range(3)]
        report = assess_network_risk(assets)
        if report.profiles:
            expected_avg = sum(p.risk_score for p in report.profiles) / len(report.profiles)
            assert abs(report.average_risk - expected_avg) < 0.01

    def test_max_risk(self):
        """Max risk should be the highest profile score."""
        assets = [
            _make_asset(ip="10.0.0.1", bigr_category="iot", open_ports=[23]),
            _make_asset(ip="10.0.0.2", bigr_category="ag_ve_sistemler"),
        ]
        report = assess_network_risk(assets)
        if report.profiles:
            expected_max = max(p.risk_score for p in report.profiles)
            assert abs(report.max_risk - expected_max) < 0.01

    def test_empty_assets(self):
        """No assets should produce empty report."""
        report = assess_network_risk([])
        assert report.profiles == []
        assert report.average_risk == 0.0
        assert report.max_risk == 0.0

    def test_with_vuln_data(self):
        """Vulnerability summaries should boost CVE factor."""
        assets = [_make_asset(ip="10.0.0.1", bigr_category="iot")]
        vuln_summaries = [{"ip": "10.0.0.1", "max_cvss": 9.8, "top_cve": "CVE-2024-0001"}]
        report_with = assess_network_risk(assets, vuln_summaries=vuln_summaries)
        report_without = assess_network_risk(assets)
        # With vuln data should produce higher risk
        assert report_with.profiles[0].risk_score > report_without.profiles[0].risk_score


# ---------------------------------------------------------------------------
# CLI Tests
# ---------------------------------------------------------------------------

from typer.testing import CliRunner

from bigr.cli import app as cli_app

runner = CliRunner()

_SAMPLE_ASSETS = [
    _make_asset(ip="10.0.0.1", bigr_category="iot", open_ports=[23, 80]),
    _make_asset(ip="10.0.0.2", bigr_category="ag_ve_sistemler", open_ports=[443]),
    _make_asset(ip="10.0.0.3", bigr_category="unclassified"),
]


class TestRiskCli:
    """Tests for the 'bigr risk' CLI command."""

    @patch("bigr.cli.get_all_assets", return_value=_SAMPLE_ASSETS)
    def test_risk_command(self, mock_assets):
        """Risk command should run without error in summary mode."""
        result = runner.invoke(cli_app, ["risk"])
        assert result.exit_code == 0

    @patch("bigr.cli.get_all_assets", return_value=_SAMPLE_ASSETS)
    def test_risk_json(self, mock_assets):
        """--format json should output valid JSON."""
        result = runner.invoke(cli_app, ["risk", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "profiles" in data
        assert "average_risk" in data

    @patch("bigr.cli.get_all_assets", return_value=_SAMPLE_ASSETS)
    def test_risk_top10(self, mock_assets):
        """--format top10 should show a table."""
        result = runner.invoke(cli_app, ["risk", "--format", "top10"])
        assert result.exit_code == 0
        # Should contain IP addresses from our sample data
        assert "10.0.0.1" in result.output


# ---------------------------------------------------------------------------
# Dashboard API Tests
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient

from bigr.dashboard.app import create_app


class TestRiskApi:
    """Tests for risk dashboard API endpoints."""

    def setup_method(self):
        """Create a test client with mocked data."""
        self.app = create_app(data_path="nonexistent.json")
        self.client = TestClient(self.app)

    @patch("bigr.core.services.get_all_assets", new_callable=AsyncMock, return_value=_SAMPLE_ASSETS)
    def test_api_risk(self, mock_assets):
        """/api/risk should return JSON with risk data."""
        response = self.client.get("/api/risk")
        assert response.status_code == 200
        data = response.json()
        assert "profiles" in data
        assert "average_risk" in data
        assert "max_risk" in data

    @patch("bigr.core.services.get_all_assets", new_callable=AsyncMock, return_value=_SAMPLE_ASSETS)
    def test_risk_page(self, mock_assets):
        """/risk should return an HTML page."""
        response = self.client.get("/risk")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Risk" in response.text
