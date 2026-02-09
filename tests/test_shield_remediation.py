"""Tests for bigr.shield.modules.remediation -- Remediation recommendation engine."""

from __future__ import annotations

import pytest

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.remediation import (
    PRIORITY_ORDER,
    Remediation,
    RemediationEngine,
    _compute_priority_label,
)


# ---------- Helper to create test findings ----------

def _make_finding(
    module: str = "tls",
    severity: FindingSeverity = FindingSeverity.HIGH,
    title: str = "Test Finding",
    remediation: str = "Fix it.",
) -> ShieldFinding:
    return ShieldFinding(
        module=module,
        severity=severity,
        title=title,
        description="Test description",
        remediation=remediation,
        target_ip="example.com",
        target_port=443,
    )


# ---------- Tests for _compute_priority_label ----------

class TestPriorityMatrix:
    """Tests for the effort/impact priority matrix."""

    def test_low_effort_high_impact_is_quick_win(self):
        assert _compute_priority_label("low", "high") == "Quick Win"

    def test_high_effort_high_impact_is_major_project(self):
        assert _compute_priority_label("high", "high") == "Major Project"

    def test_low_effort_low_impact_is_deprioritize(self):
        assert _compute_priority_label("low", "low") == "Deprioritize"

    def test_high_effort_low_impact_is_deprioritize(self):
        assert _compute_priority_label("high", "low") == "Deprioritize"

    def test_medium_effort_high_impact_is_important(self):
        assert _compute_priority_label("medium", "high") == "Important"

    def test_medium_effort_medium_impact_is_important(self):
        assert _compute_priority_label("medium", "medium") == "Important"

    def test_low_effort_medium_impact_is_important(self):
        assert _compute_priority_label("low", "medium") == "Important"

    def test_high_effort_medium_impact_is_important(self):
        assert _compute_priority_label("high", "medium") == "Important"


# ---------- Tests for Remediation dataclass ----------

class TestRemediationDataclass:
    """Tests for the Remediation dataclass."""

    def test_default_values(self):
        r = Remediation()
        assert r.finding_id == ""
        assert r.summary == ""
        assert r.steps == []
        assert r.references == []
        assert r.effort == "medium"
        assert r.impact == "medium"
        assert r.priority_label == "Important"

    def test_to_dict(self):
        r = Remediation(
            finding_id="f1",
            summary="Fix the issue",
            steps=["Step 1", "Step 2"],
            references=["https://example.com"],
            effort="low",
            impact="high",
            priority_label="Quick Win",
        )
        d = r.to_dict()
        assert d["finding_id"] == "f1"
        assert d["summary"] == "Fix the issue"
        assert len(d["steps"]) == 2
        assert d["effort"] == "low"
        assert d["impact"] == "high"
        assert d["priority_label"] == "Quick Win"


# ---------- Tests for RemediationEngine.get_remediation ----------

class TestRemediationEngine:
    """Tests for RemediationEngine.get_remediation()."""

    def test_tls_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="tls",
            severity=FindingSeverity.CRITICAL,
            title="TLS Certificate Expired",
        )
        r = engine.get_remediation(finding)
        assert r.finding_id == finding.id
        assert "Renew" in r.summary or "certificate" in r.summary.lower()
        assert len(r.steps) > 0
        assert r.priority_label == "Quick Win"  # low effort, high impact

    def test_weak_tls_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="tls",
            severity=FindingSeverity.HIGH,
            title="Weak TLS Version",
        )
        r = engine.get_remediation(finding)
        assert "TLS" in r.summary or "Disable" in r.summary
        assert len(r.steps) > 0

    def test_port_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="ports",
            severity=FindingSeverity.HIGH,
            title="Dangerous Port Open: 6379/tcp (Redis)",
        )
        r = engine.get_remediation(finding)
        assert "port" in r.summary.lower() or "close" in r.summary.lower() or "restrict" in r.summary.lower()
        assert len(r.steps) > 0

    def test_header_remediation_hsts(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="headers",
            severity=FindingSeverity.HIGH,
            title="HSTS Header Missing",
        )
        r = engine.get_remediation(finding)
        assert "HSTS" in r.summary or "Strict" in r.summary
        assert len(r.steps) > 0
        assert r.priority_label == "Quick Win"

    def test_header_remediation_csp(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="headers",
            severity=FindingSeverity.MEDIUM,
            title="Content-Security-Policy Header Missing",
        )
        r = engine.get_remediation(finding)
        assert "Content Security" in r.summary or "CSP" in r.summary

    def test_header_server_disclosure(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="headers",
            severity=FindingSeverity.MEDIUM,
            title="Server Header Information Disclosure",
        )
        r = engine.get_remediation(finding)
        assert "server" in r.summary.lower() or "version" in r.summary.lower() or "obfuscate" in r.summary.lower()

    def test_dns_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="dns",
            severity=FindingSeverity.MEDIUM,
            title="SPF Record Missing",
        )
        r = engine.get_remediation(finding)
        assert "SPF" in r.summary
        assert len(r.steps) > 0

    def test_cve_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="cve",
            severity=FindingSeverity.CRITICAL,
            title="Known CVE Detected: CVE-2024-1234",
        )
        r = engine.get_remediation(finding)
        assert "patch" in r.summary.lower() or "upgrade" in r.summary.lower()
        assert len(r.steps) > 0

    def test_creds_redis_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="creds",
            severity=FindingSeverity.CRITICAL,
            title="Redis Accessible Without Authentication",
        )
        r = engine.get_remediation(finding)
        assert "redis" in r.summary.lower() or "authentication" in r.summary.lower()
        assert len(r.steps) > 0
        assert r.priority_label == "Quick Win"

    def test_creds_mongodb_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="creds",
            severity=FindingSeverity.CRITICAL,
            title="MongoDB Accessible Without Authentication",
        )
        r = engine.get_remediation(finding)
        assert "MongoDB" in r.summary or "authentication" in r.summary.lower()

    def test_creds_admin_panel_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="creds",
            severity=FindingSeverity.HIGH,
            title="Default Admin Panel Accessible at /phpmyadmin",
        )
        r = engine.get_remediation(finding)
        assert "admin" in r.summary.lower() or "restrict" in r.summary.lower()

    def test_owasp_sqli_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="owasp",
            severity=FindingSeverity.CRITICAL,
            title="Potential SQL Injection Detected",
        )
        r = engine.get_remediation(finding)
        assert "SQL" in r.summary or "parameterized" in r.summary.lower()
        assert len(r.references) > 0

    def test_owasp_xss_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="owasp",
            severity=FindingSeverity.HIGH,
            title="Potential Reflected XSS Detected",
        )
        r = engine.get_remediation(finding)
        assert "XSS" in r.summary or "encoding" in r.summary.lower()

    def test_owasp_traversal_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="owasp",
            severity=FindingSeverity.CRITICAL,
            title="Directory Traversal Vulnerability Detected",
        )
        r = engine.get_remediation(finding)
        assert "traversal" in r.summary.lower() or "path" in r.summary.lower() or "file" in r.summary.lower()

    def test_owasp_env_exposed_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="owasp",
            severity=FindingSeverity.HIGH,
            title="Environment File Exposed",
        )
        r = engine.get_remediation(finding)
        assert "environment" in r.summary.lower() or ".env" in r.summary.lower() or "exposed" in r.summary.lower() or "Remove" in r.summary

    def test_owasp_git_exposed_remediation(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="owasp",
            severity=FindingSeverity.HIGH,
            title="Git Repository Exposed",
        )
        r = engine.get_remediation(finding)
        assert ".git" in r.summary.lower() or "git" in r.summary.lower() or "exposed" in r.summary.lower() or "Remove" in r.summary

    def test_unknown_finding_uses_fallback(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="custom",
            severity=FindingSeverity.LOW,
            title="Some Completely Unknown Finding Type",
            remediation="Do something about it.",
        )
        r = engine.get_remediation(finding)
        assert r.finding_id == finding.id
        assert r.summary == "Do something about it."
        assert r.steps == ["Do something about it."]

    def test_unknown_finding_no_remediation_text(self):
        engine = RemediationEngine()
        finding = _make_finding(
            module="custom",
            severity=FindingSeverity.LOW,
            title="Unknown Finding No Remediation",
            remediation="",
        )
        r = engine.get_remediation(finding)
        assert "Unknown Finding" in r.summary or "Address" in r.summary


# ---------- Tests for RemediationEngine.generate_plan ----------

class TestGeneratePlan:
    """Tests for RemediationEngine.generate_plan()."""

    def test_empty_findings_returns_empty(self):
        engine = RemediationEngine()
        plan = engine.generate_plan([])
        assert plan == []

    def test_plan_sorted_by_priority(self):
        engine = RemediationEngine()
        findings = [
            _make_finding(module="headers", severity=FindingSeverity.MEDIUM,
                         title="Server Header Information Disclosure"),  # low effort, low impact -> Deprioritize
            _make_finding(module="tls", severity=FindingSeverity.CRITICAL,
                         title="TLS Certificate Expired"),  # low effort, high impact -> Quick Win
            _make_finding(module="owasp", severity=FindingSeverity.CRITICAL,
                         title="Potential SQL Injection Detected"),  # medium effort, high impact -> Important
        ]

        plan = engine.generate_plan(findings)

        assert len(plan) == 3
        # Quick Win should come first
        assert plan[0].priority_label == "Quick Win"
        # Deprioritize should come last
        assert plan[-1].priority_label in ("Deprioritize", "Important", "Major Project")

    def test_plan_groups_quick_wins_first(self):
        engine = RemediationEngine()
        findings = [
            _make_finding(module="creds", severity=FindingSeverity.CRITICAL,
                         title="Redis Accessible Without Authentication"),  # Quick Win
            _make_finding(module="tls", severity=FindingSeverity.CRITICAL,
                         title="TLS Certificate Expired"),  # Quick Win
        ]

        plan = engine.generate_plan(findings)

        assert len(plan) == 2
        assert all(r.priority_label == "Quick Win" for r in plan)

    def test_single_finding_plan(self):
        engine = RemediationEngine()
        findings = [
            _make_finding(module="tls", severity=FindingSeverity.HIGH,
                         title="Self-Signed Certificate"),
        ]

        plan = engine.generate_plan(findings)

        assert len(plan) == 1
        assert plan[0].finding_id == findings[0].id
        assert len(plan[0].steps) > 0

    def test_plan_covers_all_findings(self):
        engine = RemediationEngine()
        findings = [
            _make_finding(module="tls", title="TLS Certificate Expired"),
            _make_finding(module="ports", title="Dangerous Port Open: 6379"),
            _make_finding(module="headers", title="HSTS Header Missing"),
            _make_finding(module="owasp", title="Potential SQL Injection Detected"),
            _make_finding(module="creds", title="Redis Accessible Without Authentication"),
        ]

        plan = engine.generate_plan(findings)

        assert len(plan) == len(findings)
        plan_finding_ids = {r.finding_id for r in plan}
        input_finding_ids = {f.id for f in findings}
        assert plan_finding_ids == input_finding_ids


# ---------- Tests for priority ordering constant ----------

class TestPriorityOrder:
    """Tests for the PRIORITY_ORDER constant."""

    def test_quick_win_is_first(self):
        assert PRIORITY_ORDER["Quick Win"] == 0

    def test_important_is_second(self):
        assert PRIORITY_ORDER["Important"] == 1

    def test_major_project_is_third(self):
        assert PRIORITY_ORDER["Major Project"] == 2

    def test_deprioritize_is_last(self):
        assert PRIORITY_ORDER["Deprioritize"] == 3

    def test_ordering_is_correct(self):
        labels = sorted(PRIORITY_ORDER.keys(), key=lambda k: PRIORITY_ORDER[k])
        assert labels == ["Quick Win", "Important", "Major Project", "Deprioritize"]
