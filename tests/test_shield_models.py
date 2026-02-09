"""Tests for bigr.shield.models — Shield data models."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bigr.shield.models import (
    FindingSeverity,
    ModuleScore,
    ScanDepth,
    ScanStatus,
    ShieldFinding,
    ShieldGrade,
    ShieldPrediction,
    ShieldScan,
)


class TestShieldGrade:
    """Tests for ShieldGrade.from_score() at all grade boundaries."""

    def test_a_plus(self):
        assert ShieldGrade.from_score(95) == ShieldGrade.A_PLUS
        assert ShieldGrade.from_score(100) == ShieldGrade.A_PLUS

    def test_a(self):
        assert ShieldGrade.from_score(90) == ShieldGrade.A
        assert ShieldGrade.from_score(94.9) == ShieldGrade.A

    def test_b_plus(self):
        assert ShieldGrade.from_score(85) == ShieldGrade.B_PLUS
        assert ShieldGrade.from_score(89.9) == ShieldGrade.B_PLUS

    def test_b(self):
        assert ShieldGrade.from_score(75) == ShieldGrade.B
        assert ShieldGrade.from_score(84.9) == ShieldGrade.B

    def test_c_plus(self):
        assert ShieldGrade.from_score(70) == ShieldGrade.C_PLUS
        assert ShieldGrade.from_score(74.9) == ShieldGrade.C_PLUS

    def test_c(self):
        assert ShieldGrade.from_score(60) == ShieldGrade.C
        assert ShieldGrade.from_score(69.9) == ShieldGrade.C

    def test_d(self):
        assert ShieldGrade.from_score(40) == ShieldGrade.D
        assert ShieldGrade.from_score(59.9) == ShieldGrade.D

    def test_f(self):
        assert ShieldGrade.from_score(0) == ShieldGrade.F
        assert ShieldGrade.from_score(39.9) == ShieldGrade.F

    def test_exact_boundaries(self):
        """Verify exact boundary values land in the correct grade."""
        assert ShieldGrade.from_score(95).value == "A+"
        assert ShieldGrade.from_score(90).value == "A"
        assert ShieldGrade.from_score(85).value == "B+"
        assert ShieldGrade.from_score(75).value == "B"
        assert ShieldGrade.from_score(70).value == "C+"
        assert ShieldGrade.from_score(60).value == "C"
        assert ShieldGrade.from_score(40).value == "D"
        assert ShieldGrade.from_score(39).value == "F"

    def test_negative_score(self):
        """Negative scores should still produce F."""
        assert ShieldGrade.from_score(-10) == ShieldGrade.F


class TestShieldFinding:
    """Tests for ShieldFinding dataclass."""

    def test_defaults(self):
        f = ShieldFinding()
        assert f.module == ""
        assert f.severity == FindingSeverity.INFO
        assert f.title == ""
        assert f.cisa_kev is False
        assert f.evidence == {}
        assert f.id  # auto-generated UUID

    def test_to_dict_full(self):
        f = ShieldFinding(
            id="test-id-123",
            scan_id="sh_abc",
            module="tls",
            severity=FindingSeverity.CRITICAL,
            title="Certificate Expired",
            description="The cert is expired.",
            remediation="Renew the cert.",
            target_ip="10.0.0.1",
            target_port=443,
            evidence={"days_remaining": -5},
            attack_technique="T1557",
            attack_tactic="Credential Access",
            cve_id="CVE-2024-1234",
            cvss_score=9.8,
            epss_score=0.95,
            cisa_kev=True,
        )
        d = f.to_dict()
        assert d["id"] == "test-id-123"
        assert d["scan_id"] == "sh_abc"
        assert d["module"] == "tls"
        assert d["severity"] == "critical"
        assert d["title"] == "Certificate Expired"
        assert d["description"] == "The cert is expired."
        assert d["remediation"] == "Renew the cert."
        assert d["target_ip"] == "10.0.0.1"
        assert d["target_port"] == 443
        assert d["evidence"]["days_remaining"] == -5
        assert d["attack_technique"] == "T1557"
        assert d["attack_tactic"] == "Credential Access"
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["cvss_score"] == 9.8
        assert d["epss_score"] == 0.95
        assert d["cisa_kev"] is True

    def test_to_dict_minimal(self):
        """Minimal finding should serialize without errors."""
        f = ShieldFinding()
        d = f.to_dict()
        assert d["severity"] == "info"
        assert d["target_port"] is None
        assert d["cve_id"] is None
        assert d["cvss_score"] is None


class TestModuleScore:
    """Tests for ModuleScore dataclass."""

    def test_defaults(self):
        ms = ModuleScore(module="tls", score=85.0)
        assert ms.total_checks == 0
        assert ms.passed_checks == 0
        assert ms.findings_count == 0

    def test_to_dict(self):
        ms = ModuleScore(
            module="tls",
            score=92.55555,
            total_checks=10,
            passed_checks=8,
            findings_count=2,
        )
        d = ms.to_dict()
        assert d["module"] == "tls"
        assert d["score"] == 92.56  # rounded to 2 decimals
        assert d["total_checks"] == 10
        assert d["passed_checks"] == 8
        assert d["findings_count"] == 2


class TestShieldScan:
    """Tests for ShieldScan dataclass."""

    def test_id_prefix(self):
        scan = ShieldScan()
        assert scan.id.startswith("sh_")

    def test_defaults(self):
        scan = ShieldScan()
        assert scan.target == ""
        assert scan.target_type == "domain"
        assert scan.status == ScanStatus.QUEUED
        assert scan.scan_depth == ScanDepth.QUICK
        assert scan.modules_enabled == ["tls"]
        assert scan.findings == []
        assert scan.module_scores == {}
        assert scan.shield_score is None
        assert scan.grade is None

    def test_duration_seconds_none_when_incomplete(self):
        scan = ShieldScan()
        assert scan.duration_seconds is None

    def test_duration_seconds_calculated(self):
        now = datetime.now(timezone.utc)
        scan = ShieldScan(
            started_at=now,
            completed_at=now + timedelta(seconds=5.5),
        )
        assert scan.duration_seconds == pytest.approx(5.5)

    def test_to_dict_full(self):
        now = datetime.now(timezone.utc)
        finding = ShieldFinding(
            module="tls",
            severity=FindingSeverity.HIGH,
            title="Test Finding",
        )
        ms = ModuleScore(module="tls", score=85.0, total_checks=5, passed_checks=4, findings_count=1)
        scan = ShieldScan(
            id="sh_test123",
            target="example.com",
            target_type="domain",
            status=ScanStatus.COMPLETED,
            created_at=now,
            started_at=now,
            completed_at=now + timedelta(seconds=3),
            shield_score=85.0,
            grade=ShieldGrade.B_PLUS,
            scan_depth=ScanDepth.QUICK,
            modules_enabled=["tls"],
            total_checks=5,
            passed_checks=4,
            failed_checks=1,
            warning_checks=0,
            findings=[finding],
            module_scores={"tls": ms},
        )

        d = scan.to_dict()
        assert d["id"] == "sh_test123"
        assert d["target"] == "example.com"
        assert d["target_type"] == "domain"
        assert d["status"] == "completed"
        assert d["created_at"].endswith("+00:00")
        assert d["started_at"] is not None
        assert d["completed_at"] is not None
        assert d["duration_seconds"] == pytest.approx(3.0)
        assert d["shield_score"] == 85.0
        assert d["grade"] == "B+"
        assert d["scan_depth"] == "quick"
        assert d["modules_enabled"] == ["tls"]
        assert d["total_checks"] == 5
        assert d["passed_checks"] == 4
        assert d["failed_checks"] == 1
        assert d["warning_checks"] == 0
        assert d["findings_count"] == 1
        assert d["findings_summary"] == {"high": 1}
        assert len(d["findings"]) == 1
        assert d["findings"][0]["title"] == "Test Finding"
        assert "tls" in d["module_scores"]
        assert d["module_scores"]["tls"]["score"] == 85.0

    def test_to_dict_queued_scan(self):
        """A freshly created scan should serialize cleanly."""
        scan = ShieldScan(target="10.0.0.1")
        d = scan.to_dict()
        assert d["status"] == "queued"
        assert d["started_at"] is None
        assert d["completed_at"] is None
        assert d["duration_seconds"] is None
        assert d["shield_score"] is None
        assert d["grade"] is None
        assert d["findings_count"] == 0
        assert d["findings_summary"] == {}

    def test_findings_summary_counts_severities(self):
        """Verify findings_summary counts each severity correctly."""
        findings = [
            ShieldFinding(severity=FindingSeverity.CRITICAL),
            ShieldFinding(severity=FindingSeverity.CRITICAL),
            ShieldFinding(severity=FindingSeverity.HIGH),
            ShieldFinding(severity=FindingSeverity.LOW),
        ]
        scan = ShieldScan(findings=findings)
        d = scan.to_dict()
        assert d["findings_summary"] == {"critical": 2, "high": 1, "low": 1}


class TestShieldPrediction:
    """Tests for ShieldPrediction dataclass."""

    def test_id_prefix(self):
        pred = ShieldPrediction()
        assert pred.id.startswith("sp_")

    def test_defaults(self):
        pred = ShieldPrediction()
        assert pred.target == ""
        assert pred.predicted_score == 0.0
        assert pred.confidence == 0.0
        assert pred.likely_findings == []
        assert pred.similar_targets_count == 0
        assert pred.verified_by_scan is None
        assert pred.prediction_accuracy is None

    def test_to_dict(self):
        now = datetime.now(timezone.utc)
        pred = ShieldPrediction(
            id="sp_test456",
            target="example.com",
            fingerprint={"tls_version": "1.3", "server": "nginx"},
            predicted_score=87.5,
            confidence=0.9234,
            likely_findings=[{"title": "HSTS Missing", "severity": "low"}],
            similar_targets_count=15,
            created_at=now,
            verified_by_scan="sh_abc",
            prediction_accuracy=0.91,
        )
        d = pred.to_dict()
        assert d["id"] == "sp_test456"
        assert d["target"] == "example.com"
        assert d["fingerprint"] == {"tls_version": "1.3", "server": "nginx"}
        assert d["predicted_score"] == 87.5
        assert d["confidence"] == 0.9234
        assert d["likely_findings"] == [{"title": "HSTS Missing", "severity": "low"}]
        assert d["similar_targets_count"] == 15
        assert d["created_at"].endswith("+00:00")
        assert d["verified_by_scan"] == "sh_abc"
        assert d["prediction_accuracy"] == 0.91

    def test_to_dict_no_verification(self):
        """Unverified prediction should serialize nulls correctly."""
        pred = ShieldPrediction(target="test.com", predicted_score=50.0, confidence=0.5)
        d = pred.to_dict()
        assert d["verified_by_scan"] is None
        assert d["prediction_accuracy"] is None
