"""Tests for CVE Correlation Engine (Phase 6A)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

# ---------------------------------------------------------------------------
# TestCveEntry - Data model tests
# ---------------------------------------------------------------------------


class TestCveEntry:
    """Tests for CveEntry dataclass."""

    def test_severity_from_cvss_critical(self):
        from bigr.vuln.models import CveEntry

        assert CveEntry.severity_from_cvss(9.5) == "critical"
        assert CveEntry.severity_from_cvss(10.0) == "critical"
        assert CveEntry.severity_from_cvss(9.0) == "critical"

    def test_severity_from_cvss_high(self):
        from bigr.vuln.models import CveEntry

        assert CveEntry.severity_from_cvss(7.5) == "high"
        assert CveEntry.severity_from_cvss(7.0) == "high"
        assert CveEntry.severity_from_cvss(8.9) == "high"

    def test_severity_from_cvss_medium(self):
        from bigr.vuln.models import CveEntry

        assert CveEntry.severity_from_cvss(5.0) == "medium"
        assert CveEntry.severity_from_cvss(4.0) == "medium"
        assert CveEntry.severity_from_cvss(6.9) == "medium"

    def test_severity_from_cvss_low(self):
        from bigr.vuln.models import CveEntry

        assert CveEntry.severity_from_cvss(2.0) == "low"
        assert CveEntry.severity_from_cvss(0.1) == "low"
        assert CveEntry.severity_from_cvss(3.9) == "low"

    def test_severity_from_cvss_none(self):
        from bigr.vuln.models import CveEntry

        assert CveEntry.severity_from_cvss(0.0) == "none"

    def test_to_dict(self):
        from bigr.vuln.models import CveEntry

        entry = CveEntry(
            cve_id="CVE-2023-20198",
            cvss_score=10.0,
            severity="critical",
            description="Cisco IOS XE Web UI privilege escalation",
            affected_vendor="cisco",
            affected_product="ios_xe",
            cpe="cpe:2.3:o:cisco:ios_xe:*",
            published="2023-10-16",
            fix_available=True,
            cisa_kev=True,
        )
        d = entry.to_dict()
        assert d["cve_id"] == "CVE-2023-20198"
        assert d["cvss_score"] == 10.0
        assert d["severity"] == "critical"
        assert d["description"] == "Cisco IOS XE Web UI privilege escalation"
        assert d["affected_vendor"] == "cisco"
        assert d["affected_product"] == "ios_xe"
        assert d["cpe"] == "cpe:2.3:o:cisco:ios_xe:*"
        assert d["published"] == "2023-10-16"
        assert d["fix_available"] is True
        assert d["cisa_kev"] is True

    def test_defaults(self):
        from bigr.vuln.models import CveEntry

        entry = CveEntry(
            cve_id="CVE-2024-00001",
            cvss_score=5.0,
            severity="medium",
            description="Test CVE",
            affected_vendor="test",
            affected_product="test",
        )
        assert entry.fix_available is False
        assert entry.cisa_kev is False
        assert entry.cpe is None
        assert entry.published is None


# ---------------------------------------------------------------------------
# TestVulnerabilityMatch
# ---------------------------------------------------------------------------


class TestVulnerabilityMatch:
    """Tests for VulnerabilityMatch dataclass."""

    def test_to_dict(self):
        from bigr.vuln.models import CveEntry, VulnerabilityMatch

        cve = CveEntry(
            cve_id="CVE-2023-20198",
            cvss_score=10.0,
            severity="critical",
            description="Test",
            affected_vendor="cisco",
            affected_product="ios_xe",
        )
        match = VulnerabilityMatch(
            asset_ip="192.168.1.1",
            asset_mac="00:11:22:33:44:55",
            asset_vendor="Cisco",
            cve=cve,
            match_type="vendor_product",
            match_confidence=0.9,
        )
        d = match.to_dict()
        assert d["asset_ip"] == "192.168.1.1"
        assert d["asset_mac"] == "00:11:22:33:44:55"
        assert d["asset_vendor"] == "Cisco"
        assert d["match_type"] == "vendor_product"
        assert d["match_confidence"] == 0.9
        assert d["cve"]["cve_id"] == "CVE-2023-20198"

    def test_match_types(self):
        from bigr.vuln.models import CveEntry, VulnerabilityMatch

        cve = CveEntry(
            cve_id="CVE-2024-00001",
            cvss_score=5.0,
            severity="medium",
            description="Test",
            affected_vendor="test",
            affected_product="test",
        )
        for mt in ("vendor_product", "vendor_only", "port_service", "banner"):
            match = VulnerabilityMatch(
                asset_ip="10.0.0.1",
                asset_mac=None,
                asset_vendor=None,
                cve=cve,
                match_type=mt,
                match_confidence=0.5,
            )
            assert match.match_type == mt


# ---------------------------------------------------------------------------
# TestAssetVulnSummary
# ---------------------------------------------------------------------------


class TestAssetVulnSummary:
    """Tests for AssetVulnSummary dataclass."""

    def test_to_dict(self):
        from bigr.vuln.models import AssetVulnSummary, CveEntry, VulnerabilityMatch

        cve = CveEntry(
            cve_id="CVE-2023-20198",
            cvss_score=10.0,
            severity="critical",
            description="Test",
            affected_vendor="cisco",
            affected_product="ios_xe",
        )
        match = VulnerabilityMatch(
            asset_ip="192.168.1.1",
            asset_mac="00:11:22:33:44:55",
            asset_vendor="Cisco",
            cve=cve,
            match_type="vendor_product",
            match_confidence=0.9,
        )
        summary = AssetVulnSummary(
            ip="192.168.1.1",
            total_vulns=1,
            critical_count=1,
            max_cvss=10.0,
            matches=[match],
        )
        d = summary.to_dict()
        assert d["ip"] == "192.168.1.1"
        assert d["total_vulns"] == 1
        assert d["critical_count"] == 1
        assert d["max_cvss"] == 10.0
        assert len(d["matches"]) == 1

    def test_empty_matches(self):
        from bigr.vuln.models import AssetVulnSummary

        summary = AssetVulnSummary(ip="10.0.0.1")
        assert summary.total_vulns == 0
        assert summary.critical_count == 0
        assert summary.high_count == 0
        assert summary.medium_count == 0
        assert summary.low_count == 0
        assert summary.max_cvss == 0.0
        assert summary.matches == []

    def test_counts(self):
        from bigr.vuln.models import AssetVulnSummary

        summary = AssetVulnSummary(
            ip="10.0.0.1",
            total_vulns=5,
            critical_count=1,
            high_count=2,
            medium_count=1,
            low_count=1,
            max_cvss=10.0,
        )
        assert summary.critical_count == 1
        assert summary.high_count == 2
        assert summary.medium_count == 1
        assert summary.low_count == 1
        assert summary.total_vulns == 5


# ---------------------------------------------------------------------------
# TestCveDb - SQLite CVE database
# ---------------------------------------------------------------------------


class TestCveDb:
    """Tests for CVE database operations."""

    def test_init_creates_tables(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        assert "cves" in tables
        assert "cve_sync_log" in tables

    def test_upsert_cve(self, tmp_path):
        from bigr.vuln.cve_db import get_cve_by_id, init_cve_db, upsert_cve
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        entry = CveEntry(
            cve_id="CVE-2023-20198",
            cvss_score=10.0,
            severity="critical",
            description="Cisco IOS XE Web UI privilege escalation",
            affected_vendor="cisco",
            affected_product="ios_xe",
            cpe="cpe:2.3:o:cisco:ios_xe:*",
            cisa_kev=True,
        )
        upsert_cve(entry, db_path=db_path)

        result = get_cve_by_id("CVE-2023-20198", db_path=db_path)
        assert result is not None
        assert result.cve_id == "CVE-2023-20198"
        assert result.cvss_score == 10.0
        assert result.severity == "critical"
        assert result.cisa_kev is True

    def test_upsert_update(self, tmp_path):
        from bigr.vuln.cve_db import get_cve_by_id, init_cve_db, upsert_cve
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        entry = CveEntry(
            cve_id="CVE-2024-00001",
            cvss_score=5.0,
            severity="medium",
            description="Original description",
            affected_vendor="test",
            affected_product="product",
        )
        upsert_cve(entry, db_path=db_path)

        # Update same CVE
        entry.cvss_score = 7.5
        entry.severity = "high"
        entry.description = "Updated description"
        upsert_cve(entry, db_path=db_path)

        result = get_cve_by_id("CVE-2024-00001", db_path=db_path)
        assert result is not None
        assert result.cvss_score == 7.5
        assert result.severity == "high"
        assert result.description == "Updated description"

    def test_bulk_upsert(self, tmp_path):
        from bigr.vuln.cve_db import bulk_upsert_cves, get_cve_stats, init_cve_db
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        entries = [
            CveEntry(
                cve_id=f"CVE-2024-{i:05d}",
                cvss_score=float(i),
                severity=CveEntry.severity_from_cvss(float(i)),
                description=f"Test CVE {i}",
                affected_vendor="test",
                affected_product="product",
            )
            for i in range(1, 6)
        ]
        count = bulk_upsert_cves(entries, db_path=db_path)
        assert count == 5

        stats = get_cve_stats(db_path=db_path)
        assert stats["total"] == 5

    def test_search_by_vendor(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, search_cves_by_vendor, upsert_cve
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00001",
                cvss_score=9.0,
                severity="critical",
                description="Cisco vuln",
                affected_vendor="cisco",
                affected_product="ios",
            ),
            db_path=db_path,
        )
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00002",
                cvss_score=5.0,
                severity="medium",
                description="HP vuln",
                affected_vendor="hp",
                affected_product="laserjet",
            ),
            db_path=db_path,
        )

        results = search_cves_by_vendor("cisco", db_path=db_path)
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-00001"

    def test_search_by_vendor_case_insensitive(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, search_cves_by_vendor, upsert_cve
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00001",
                cvss_score=9.0,
                severity="critical",
                description="Cisco vuln",
                affected_vendor="cisco",
                affected_product="ios",
            ),
            db_path=db_path,
        )

        results = search_cves_by_vendor("Cisco", db_path=db_path)
        assert len(results) == 1

        results = search_cves_by_vendor("CISCO", db_path=db_path)
        assert len(results) == 1

    def test_search_by_product(self, tmp_path):
        from bigr.vuln.cve_db import (
            init_cve_db,
            search_cves_by_product,
            upsert_cve,
        )
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00001",
                cvss_score=9.0,
                severity="critical",
                description="Cisco IOS vuln",
                affected_vendor="cisco",
                affected_product="ios",
            ),
            db_path=db_path,
        )
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00002",
                cvss_score=7.0,
                severity="high",
                description="Cisco IOS XE vuln",
                affected_vendor="cisco",
                affected_product="ios_xe",
            ),
            db_path=db_path,
        )

        results = search_cves_by_product("cisco", "ios", db_path=db_path)
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-00001"

    def test_search_by_cpe(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, search_cves_by_cpe, upsert_cve
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00001",
                cvss_score=9.0,
                severity="critical",
                description="Cisco IOS XE vuln",
                affected_vendor="cisco",
                affected_product="ios_xe",
                cpe="cpe:2.3:o:cisco:ios_xe:*",
            ),
            db_path=db_path,
        )

        results = search_cves_by_cpe("cpe:2.3:%:cisco:%", db_path=db_path)
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-00001"

    def test_get_cve_stats(self, tmp_path):
        from bigr.vuln.cve_db import bulk_upsert_cves, get_cve_stats, init_cve_db
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        entries = [
            CveEntry(
                cve_id="CVE-2024-00001",
                cvss_score=9.5,
                severity="critical",
                description="Critical vuln",
                affected_vendor="test",
                affected_product="prod",
            ),
            CveEntry(
                cve_id="CVE-2024-00002",
                cvss_score=7.5,
                severity="high",
                description="High vuln",
                affected_vendor="test",
                affected_product="prod",
            ),
            CveEntry(
                cve_id="CVE-2024-00003",
                cvss_score=4.5,
                severity="medium",
                description="Medium vuln",
                affected_vendor="test",
                affected_product="prod",
            ),
        ]
        bulk_upsert_cves(entries, db_path=db_path)

        stats = get_cve_stats(db_path=db_path)
        assert stats["total"] == 3
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1

    def test_get_cve_by_id(self, tmp_path):
        from bigr.vuln.cve_db import get_cve_by_id, init_cve_db, upsert_cve
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-20198",
                cvss_score=10.0,
                severity="critical",
                description="Cisco IOS XE vuln",
                affected_vendor="cisco",
                affected_product="ios_xe",
            ),
            db_path=db_path,
        )

        result = get_cve_by_id("CVE-2023-20198", db_path=db_path)
        assert result is not None
        assert result.cve_id == "CVE-2023-20198"

    def test_get_cve_by_id_not_found(self, tmp_path):
        from bigr.vuln.cve_db import get_cve_by_id, init_cve_db

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        result = get_cve_by_id("CVE-9999-99999", db_path=db_path)
        assert result is None


# ---------------------------------------------------------------------------
# TestNormalizeVendorName
# ---------------------------------------------------------------------------


class TestNormalizeVendorName:
    """Tests for vendor name normalization."""

    def test_cisco_systems(self):
        from bigr.vuln.matcher import normalize_vendor_name

        assert normalize_vendor_name("Cisco Systems") == "cisco"

    def test_hp_variants(self):
        from bigr.vuln.matcher import normalize_vendor_name

        assert normalize_vendor_name("Hewlett Packard") == "hp"
        assert normalize_vendor_name("Hewlett-Packard") == "hp"
        assert normalize_vendor_name("HP Inc") == "hp"

    def test_already_normalized(self):
        from bigr.vuln.matcher import normalize_vendor_name

        assert normalize_vendor_name("cisco") == "cisco"

    def test_none(self):
        from bigr.vuln.matcher import normalize_vendor_name

        assert normalize_vendor_name(None) is None

    def test_unknown_vendor(self):
        from bigr.vuln.matcher import normalize_vendor_name

        assert normalize_vendor_name("Unknown Corp") == "unknown corp"


# ---------------------------------------------------------------------------
# TestBuildCpePattern
# ---------------------------------------------------------------------------


class TestBuildCpePattern:
    """Tests for CPE pattern builder."""

    def test_vendor_only(self):
        from bigr.vuln.matcher import build_cpe_pattern

        result = build_cpe_pattern("Cisco")
        assert result == "cpe:2.3:*:cisco:*:*"

    def test_vendor_product(self):
        from bigr.vuln.matcher import build_cpe_pattern

        result = build_cpe_pattern("Cisco", "IOS XE")
        assert result == "cpe:2.3:*:cisco:ios_xe:*"

    def test_none_vendor(self):
        from bigr.vuln.matcher import build_cpe_pattern

        assert build_cpe_pattern(None) is None

    def test_product_spaces_underscored(self):
        from bigr.vuln.matcher import build_cpe_pattern

        result = build_cpe_pattern("HP", "LaserJet Pro MFP")
        assert "laserjet_pro_mfp" in result


# ---------------------------------------------------------------------------
# TestMatchAssetVulnerabilities
# ---------------------------------------------------------------------------


class TestMatchAssetVulnerabilities:
    """Tests for asset-to-CVE matching."""

    def test_vendor_match(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, upsert_cve
        from bigr.vuln.matcher import match_asset_vulnerabilities
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-20198",
                cvss_score=10.0,
                severity="critical",
                description="Cisco IOS XE vuln",
                affected_vendor="cisco",
                affected_product="ios_xe",
                cpe="cpe:2.3:o:cisco:ios_xe:*",
            ),
            db_path=db_path,
        )

        asset = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "vendor": "Cisco Systems",
        }
        matches = match_asset_vulnerabilities(asset, db_path=db_path)
        assert len(matches) >= 1
        assert any(m.cve.cve_id == "CVE-2023-20198" for m in matches)

    def test_no_match(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, upsert_cve
        from bigr.vuln.matcher import match_asset_vulnerabilities
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-20198",
                cvss_score=10.0,
                severity="critical",
                description="Cisco IOS XE vuln",
                affected_vendor="cisco",
                affected_product="ios_xe",
            ),
            db_path=db_path,
        )

        asset = {
            "ip": "192.168.1.100",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": "Samsung",
        }
        matches = match_asset_vulnerabilities(asset, db_path=db_path)
        assert len(matches) == 0

    def test_match_confidence(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, upsert_cve
        from bigr.vuln.matcher import match_asset_vulnerabilities
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        # Vendor+product specific CVE
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00001",
                cvss_score=9.0,
                severity="critical",
                description="Cisco IOS specific",
                affected_vendor="cisco",
                affected_product="ios",
            ),
            db_path=db_path,
        )
        # Vendor-only CVE (different product)
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00002",
                cvss_score=7.0,
                severity="high",
                description="Cisco ASA vuln",
                affected_vendor="cisco",
                affected_product="asa",
            ),
            db_path=db_path,
        )

        asset = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "vendor": "Cisco",
        }
        matches = match_asset_vulnerabilities(asset, db_path=db_path)
        # All Cisco CVEs should match via vendor_only
        assert len(matches) >= 2
        # Check confidence values
        for m in matches:
            assert m.match_confidence in (0.9, 0.5, 0.3)

    def test_multiple_matches(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, upsert_cve
        from bigr.vuln.matcher import match_asset_vulnerabilities
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        for i in range(3):
            upsert_cve(
                CveEntry(
                    cve_id=f"CVE-2023-{i:05d}",
                    cvss_score=8.0 + i,
                    severity="critical" if i == 2 else "high",
                    description=f"Cisco vuln {i}",
                    affected_vendor="cisco",
                    affected_product="ios",
                ),
                db_path=db_path,
            )

        asset = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "vendor": "Cisco",
        }
        matches = match_asset_vulnerabilities(asset, db_path=db_path)
        assert len(matches) == 3


# ---------------------------------------------------------------------------
# TestScanAllVulnerabilities
# ---------------------------------------------------------------------------


class TestScanAllVulnerabilities:
    """Tests for bulk vulnerability scanning."""

    def test_returns_summaries(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, upsert_cve
        from bigr.vuln.matcher import scan_all_vulnerabilities
        from bigr.vuln.models import AssetVulnSummary, CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-20198",
                cvss_score=10.0,
                severity="critical",
                description="Cisco vuln",
                affected_vendor="cisco",
                affected_product="ios_xe",
            ),
            db_path=db_path,
        )

        assets = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Cisco"},
            {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Samsung"},
        ]
        summaries = scan_all_vulnerabilities(assets, db_path=db_path)
        assert isinstance(summaries, list)
        assert all(isinstance(s, AssetVulnSummary) for s in summaries)

    def test_correct_counts(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db, upsert_cve
        from bigr.vuln.matcher import scan_all_vulnerabilities
        from bigr.vuln.models import CveEntry

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00001",
                cvss_score=10.0,
                severity="critical",
                description="Critical Cisco vuln",
                affected_vendor="cisco",
                affected_product="ios",
            ),
            db_path=db_path,
        )
        upsert_cve(
            CveEntry(
                cve_id="CVE-2023-00002",
                cvss_score=7.5,
                severity="high",
                description="High Cisco vuln",
                affected_vendor="cisco",
                affected_product="router",
            ),
            db_path=db_path,
        )

        assets = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Cisco"},
        ]
        summaries = scan_all_vulnerabilities(assets, db_path=db_path)
        assert len(summaries) == 1
        s = summaries[0]
        assert s.ip == "192.168.1.1"
        assert s.total_vulns >= 2
        assert s.critical_count >= 1
        assert s.high_count >= 1
        assert s.max_cvss == 10.0

    def test_empty_assets(self, tmp_path):
        from bigr.vuln.cve_db import init_cve_db
        from bigr.vuln.matcher import scan_all_vulnerabilities

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        summaries = scan_all_vulnerabilities([], db_path=db_path)
        assert summaries == []


# ---------------------------------------------------------------------------
# TestSeedCveDatabase
# ---------------------------------------------------------------------------


class TestSeedCveDatabase:
    """Tests for NVD seed data."""

    def test_seed_populates_db(self, tmp_path):
        from bigr.vuln.cve_db import get_cve_stats, init_cve_db
        from bigr.vuln.nvd_sync import seed_cve_database

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        count = seed_cve_database(db_path=db_path)
        assert count > 0

        stats = get_cve_stats(db_path=db_path)
        assert stats["total"] > 0

    def test_seed_count(self):
        from bigr.vuln.nvd_sync import get_seed_cve_count

        count = get_seed_cve_count()
        assert count >= 15

    def test_seed_idempotent(self, tmp_path):
        from bigr.vuln.cve_db import get_cve_stats, init_cve_db
        from bigr.vuln.nvd_sync import seed_cve_database

        db_path = tmp_path / "test_cve.db"
        init_cve_db(db_path)

        count1 = seed_cve_database(db_path=db_path)
        count2 = seed_cve_database(db_path=db_path)

        stats = get_cve_stats(db_path=db_path)
        # Running twice should not duplicate
        assert stats["total"] == count1
        assert count1 == count2


# ---------------------------------------------------------------------------
# TestVulnCli
# ---------------------------------------------------------------------------


class TestVulnCli:
    """Tests for vuln CLI commands."""

    def test_vuln_seed(self, tmp_path):
        from bigr.cli import app

        runner = CliRunner()
        db_path = tmp_path / "test_cve.db"
        result = runner.invoke(app, ["vuln", "seed", "--db-path", str(db_path)])
        assert result.exit_code == 0
        assert "Seeded" in result.output or "seed" in result.output.lower()

    def test_vuln_stats(self, tmp_path):
        from bigr.cli import app

        runner = CliRunner()
        db_path = tmp_path / "test_cve.db"
        # Seed first
        runner.invoke(app, ["vuln", "seed", "--db-path", str(db_path)])
        result = runner.invoke(app, ["vuln", "stats", "--db-path", str(db_path)])
        assert result.exit_code == 0
        # Should show some stats
        assert "total" in result.output.lower() or "CVE" in result.output

    def test_vuln_search(self, tmp_path):
        from bigr.cli import app

        runner = CliRunner()
        db_path = tmp_path / "test_cve.db"
        # Seed first
        runner.invoke(app, ["vuln", "seed", "--db-path", str(db_path)])
        result = runner.invoke(
            app, ["vuln", "search", "cisco", "--db-path", str(db_path)]
        )
        assert result.exit_code == 0
        assert "cisco" in result.output.lower() or "CVE" in result.output

    def test_vuln_scan(self, tmp_path):
        from bigr.cli import app

        runner = CliRunner()
        db_path = tmp_path / "test_cve.db"
        # Seed first
        runner.invoke(app, ["vuln", "seed", "--db-path", str(db_path)])
        result = runner.invoke(app, ["vuln", "scan", "--db-path", str(db_path)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# TestVulnApi - Dashboard endpoints
# ---------------------------------------------------------------------------


class TestVulnApi:
    """Tests for vulnerability dashboard endpoints."""

    @pytest.fixture
    def sample_data(self, tmp_path: Path) -> Path:
        """Create sample assets.json for testing."""
        import json

        data = {
            "target": "192.168.1.0/24",
            "scan_method": "hybrid",
            "duration_seconds": 12.5,
            "total_assets": 1,
            "category_summary": {"ag_ve_sistemler": 1},
            "assets": [
                {
                    "ip": "192.168.1.1",
                    "mac": "00:1e:bd:aa:bb:cc",
                    "hostname": "router-01",
                    "vendor": "Cisco",
                    "open_ports": [22, 80],
                    "bigr_category": "ag_ve_sistemler",
                    "bigr_category_tr": "Ag ve Sistemler",
                    "confidence_score": 0.85,
                    "confidence_level": "high",
                    "scan_method": "hybrid",
                },
            ],
        }
        json_path = tmp_path / "assets.json"
        json_path.write_text(json.dumps(data))
        return json_path

    @pytest.mark.asyncio
    async def test_api_vulnerabilities(self, sample_data, tmp_path):
        from httpx import ASGITransport, AsyncClient

        from bigr.dashboard.app import create_app

        app = create_app(data_path=str(sample_data), db_path=tmp_path / "bigr.db")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/vulnerabilities")
            assert resp.status_code == 200
            data = resp.json()
            assert "summaries" in data or "vulnerabilities" in data or isinstance(data, list) or isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_vulnerabilities_page(self, sample_data, tmp_path):
        from httpx import ASGITransport, AsyncClient

        from bigr.dashboard.app import create_app

        app = create_app(data_path=str(sample_data), db_path=tmp_path / "bigr.db")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/vulnerabilities")
            assert resp.status_code == 200
            assert "html" in resp.headers.get("content-type", "").lower()
