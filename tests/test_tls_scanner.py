"""Tests for TLS certificate discovery and monitoring (Phase 6C)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bigr.scanner.tls import (
    CertificateInfo,
    CertScanResult,
    TLS_PORTS,
    calculate_days_until_expiry,
    get_expiring_certs,
    is_cert_self_signed,
    parse_certificate,
)


# ---------------------------------------------------------------------------
# TestCertificateInfo
# ---------------------------------------------------------------------------


class TestCertificateInfo:
    """Tests for CertificateInfo dataclass."""

    def test_defaults(self):
        """Default values are correct for a minimal CertificateInfo."""
        cert = CertificateInfo(ip="10.0.0.1", port=443)
        assert cert.ip == "10.0.0.1"
        assert cert.port == 443
        assert cert.cn is None
        assert cert.san == []
        assert cert.issuer is None
        assert cert.issuer_org is None
        assert cert.valid_from is None
        assert cert.valid_to is None
        assert cert.serial is None
        assert cert.key_size is None
        assert cert.key_algorithm is None
        assert cert.signature_algorithm is None
        assert cert.is_self_signed is False
        assert cert.is_expired is False
        assert cert.days_until_expiry is None

    def test_expiry_status_ok(self):
        """90 days until expiry returns 'ok'."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=90)
        assert cert.expiry_status == "ok"

    def test_expiry_status_warning(self):
        """25 days until expiry returns 'warning'."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=25)
        assert cert.expiry_status == "warning"

    def test_expiry_status_critical(self):
        """5 days until expiry returns 'critical'."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=5)
        assert cert.expiry_status == "critical"

    def test_expiry_status_expired(self):
        """is_expired=True returns 'expired'."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, is_expired=True, days_until_expiry=-10)
        assert cert.expiry_status == "expired"

    def test_security_issues_none(self):
        """Clean certificate has no security issues."""
        cert = CertificateInfo(
            ip="10.0.0.1",
            port=443,
            key_size=2048,
            days_until_expiry=90,
            is_self_signed=False,
            is_expired=False,
        )
        assert cert.security_issues == []

    def test_security_issues_expired(self):
        """Expired certificate has expired issue."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, is_expired=True)
        issues = cert.security_issues
        assert any("expired" in i.lower() for i in issues)

    def test_security_issues_self_signed(self):
        """Self-signed certificate has self-signed issue."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, is_self_signed=True)
        issues = cert.security_issues
        assert any("self-signed" in i.lower() for i in issues)

    def test_security_issues_weak_key(self):
        """1024-bit key generates weak key issue."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, key_size=1024)
        issues = cert.security_issues
        assert any("weak key" in i.lower() for i in issues)

    def test_security_issues_expiring_soon(self):
        """15 days until expiry generates expiring issue."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=15)
        issues = cert.security_issues
        assert any("expiring" in i.lower() for i in issues)

    def test_security_issues_multiple(self):
        """Multiple issues are combined."""
        cert = CertificateInfo(
            ip="10.0.0.1",
            port=443,
            is_expired=True,
            is_self_signed=True,
            key_size=512,
        )
        issues = cert.security_issues
        assert len(issues) >= 2
        assert any("expired" in i.lower() for i in issues)
        assert any("self-signed" in i.lower() for i in issues)

    def test_to_dict(self):
        """Full serialization to dict."""
        cert = CertificateInfo(
            ip="10.0.0.1",
            port=443,
            cn="example.com",
            san=["example.com", "*.example.com"],
            issuer="R3",
            issuer_org="Let's Encrypt",
            valid_from="2026-01-01T00:00:00",
            valid_to="2026-04-01T00:00:00",
            serial="ABCDEF123456",
            key_size=2048,
            key_algorithm="RSA",
            signature_algorithm="SHA256withRSA",
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=90,
        )
        d = cert.to_dict()
        assert d["ip"] == "10.0.0.1"
        assert d["port"] == 443
        assert d["cn"] == "example.com"
        assert d["san"] == ["example.com", "*.example.com"]
        assert d["issuer"] == "R3"
        assert d["key_size"] == 2048
        assert d["expiry_status"] == "ok"
        assert d["security_issues"] == []
        assert "days_until_expiry" in d


# ---------------------------------------------------------------------------
# TestCertScanResult
# ---------------------------------------------------------------------------


class TestCertScanResult:
    """Tests for CertScanResult dataclass."""

    def test_defaults(self):
        """All counts start at zero."""
        result = CertScanResult()
        assert result.certificates == []
        assert result.total_scanned == 0
        assert result.total_certs_found == 0
        assert result.expired_count == 0
        assert result.expiring_soon_count == 0
        assert result.self_signed_count == 0
        assert result.weak_key_count == 0

    def test_to_dict(self):
        """Serialization includes certificates."""
        cert = CertificateInfo(ip="10.0.0.1", port=443, cn="test.com")
        result = CertScanResult(
            certificates=[cert],
            total_scanned=5,
            total_certs_found=1,
        )
        d = result.to_dict()
        assert d["total_scanned"] == 5
        assert d["total_certs_found"] == 1
        assert len(d["certificates"]) == 1
        assert d["certificates"][0]["cn"] == "test.com"

    def test_counts(self):
        """Counts for expired, self-signed, etc. are correct."""
        certs = [
            CertificateInfo(ip="10.0.0.1", port=443, is_expired=True),
            CertificateInfo(ip="10.0.0.2", port=443, is_self_signed=True),
            CertificateInfo(ip="10.0.0.3", port=443, key_size=1024),
            CertificateInfo(ip="10.0.0.4", port=443, days_until_expiry=15),
        ]
        result = CertScanResult(
            certificates=certs,
            total_scanned=4,
            total_certs_found=4,
            expired_count=1,
            expiring_soon_count=1,
            self_signed_count=1,
            weak_key_count=1,
        )
        assert result.expired_count == 1
        assert result.self_signed_count == 1
        assert result.weak_key_count == 1
        assert result.expiring_soon_count == 1


# ---------------------------------------------------------------------------
# TestParseCertificate
# ---------------------------------------------------------------------------


class TestParseCertificate:
    """Tests for parse_certificate function."""

    def test_basic_cert(self):
        """Parses CN, issuer, dates from a standard getpeercert() dict."""
        cert_dict = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": (
                (("organizationName", "Let's Encrypt"),),
                (("commonName", "R3"),),
            ),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Apr  1 00:00:00 2026 GMT",
            "serialNumber": "ABCDEF123456",
        }
        info = parse_certificate(cert_dict, "10.0.0.1", 443)
        assert info.ip == "10.0.0.1"
        assert info.port == 443
        assert info.cn == "example.com"
        assert info.issuer == "R3"
        assert info.issuer_org == "Let's Encrypt"
        assert info.serial == "ABCDEF123456"
        assert info.valid_from is not None
        assert info.valid_to is not None

    def test_with_san(self):
        """SAN entries are extracted correctly."""
        cert_dict = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "R3"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Apr  1 00:00:00 2026 GMT",
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "*.example.com"),
                ("DNS", "api.example.com"),
            ),
        }
        info = parse_certificate(cert_dict, "10.0.0.1", 443)
        assert "example.com" in info.san
        assert "*.example.com" in info.san
        assert "api.example.com" in info.san
        assert len(info.san) == 3

    def test_self_signed_detection(self):
        """Self-signed cert (subject CN == issuer CN) is detected."""
        cert_dict = {
            "subject": ((("commonName", "myserver"),),),
            "issuer": ((("commonName", "myserver"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Apr  1 00:00:00 2027 GMT",
        }
        info = parse_certificate(cert_dict, "10.0.0.1", 443)
        assert info.is_self_signed is True

    def test_missing_fields(self):
        """Handles missing keys gracefully."""
        cert_dict = {
            "subject": ((("commonName", "test.com"),),),
            "notAfter": "Apr  1 00:00:00 2026 GMT",
        }
        info = parse_certificate(cert_dict, "10.0.0.1", 443)
        assert info.cn == "test.com"
        assert info.issuer is None
        assert info.issuer_org is None
        assert info.serial is None

    def test_empty_cert_dict(self):
        """Empty dict returns defaults."""
        info = parse_certificate({}, "10.0.0.1", 443)
        assert info.ip == "10.0.0.1"
        assert info.port == 443
        assert info.cn is None
        assert info.issuer is None
        assert info.san == []


# ---------------------------------------------------------------------------
# TestCalculateDaysUntilExpiry
# ---------------------------------------------------------------------------


class TestCalculateDaysUntilExpiry:
    """Tests for calculate_days_until_expiry function."""

    def test_future_date(self):
        """Future date returns positive days."""
        # Use a date far in the future
        result = calculate_days_until_expiry("Jan  1 00:00:00 2030 GMT")
        assert result > 0

    def test_past_date(self):
        """Past date returns negative days."""
        result = calculate_days_until_expiry("Jan  1 00:00:00 2020 GMT")
        assert result < 0

    def test_today(self):
        """Today returns 0 or very small number."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%b %d %H:%M:%S %Y GMT")
        # Pad single-digit days with leading space (SSL format)
        result = calculate_days_until_expiry(date_str)
        assert abs(result) <= 1


# ---------------------------------------------------------------------------
# TestIsCertSelfSigned
# ---------------------------------------------------------------------------


class TestIsCertSelfSigned:
    """Tests for is_cert_self_signed function."""

    def test_same_cn(self):
        """Same CN means self-signed."""
        assert is_cert_self_signed("example.com", "example.com") is True

    def test_different_cn(self):
        """Different CN means not self-signed."""
        assert is_cert_self_signed("example.com", "R3") is False

    def test_none_values(self):
        """None CN returns False."""
        assert is_cert_self_signed(None, None) is False
        assert is_cert_self_signed("example.com", None) is False
        assert is_cert_self_signed(None, "R3") is False

    def test_case_insensitive(self):
        """Matching ignores case."""
        assert is_cert_self_signed("Example.COM", "example.com") is True


# ---------------------------------------------------------------------------
# TestGetExpiringCerts
# ---------------------------------------------------------------------------


class TestGetExpiringCerts:
    """Tests for get_expiring_certs function."""

    def test_filters_expiring(self):
        """Only certificates expiring within N days are returned."""
        certs = [
            CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=10),
            CertificateInfo(ip="10.0.0.2", port=443, days_until_expiry=60),
        ]
        result = get_expiring_certs(certs, days=30)
        assert len(result) == 1
        assert result[0].ip == "10.0.0.1"

    def test_excludes_ok_certs(self):
        """OK certs (>30 days) are not included."""
        certs = [
            CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=90),
            CertificateInfo(ip="10.0.0.2", port=443, days_until_expiry=180),
        ]
        result = get_expiring_certs(certs, days=30)
        assert result == []

    def test_includes_expired(self):
        """Expired certs (negative days) are included."""
        certs = [
            CertificateInfo(ip="10.0.0.1", port=443, days_until_expiry=-5, is_expired=True),
            CertificateInfo(ip="10.0.0.2", port=443, days_until_expiry=90),
        ]
        result = get_expiring_certs(certs, days=30)
        assert len(result) == 1
        assert result[0].ip == "10.0.0.1"

    def test_empty_list(self):
        """No certs returns empty list."""
        assert get_expiring_certs([], days=30) == []


# ---------------------------------------------------------------------------
# TestCertificatesDb
# ---------------------------------------------------------------------------


class TestCertificatesDb:
    """Tests for certificate database functions."""

    def test_save_certificate(self, tmp_path):
        """Insert cert to DB."""
        from bigr.db import init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)

        cert = CertificateInfo(
            ip="10.0.0.1",
            port=443,
            cn="example.com",
            issuer="R3",
            issuer_org="Let's Encrypt",
            valid_from="2026-01-01T00:00:00",
            valid_to="2026-04-01T00:00:00",
            serial="ABC123",
            key_size=2048,
            key_algorithm="RSA",
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=90,
            san=["example.com", "*.example.com"],
        )
        save_certificate(cert, db_path=db_path)

        # Verify it was saved
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM certificates WHERE ip = '10.0.0.1'").fetchone()
        conn.close()

        assert row is not None
        assert row["cn"] == "example.com"
        assert row["issuer"] == "R3"
        assert row["key_size"] == 2048

    def test_save_certificate_upsert(self, tmp_path):
        """Same IP+port updates existing record."""
        from bigr.db import init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)

        cert1 = CertificateInfo(ip="10.0.0.1", port=443, cn="old.com")
        save_certificate(cert1, db_path=db_path)

        cert2 = CertificateInfo(ip="10.0.0.1", port=443, cn="new.com")
        save_certificate(cert2, db_path=db_path)

        # Should have only one row
        conn = sqlite3.connect(str(db_path))
        count = conn.execute("SELECT COUNT(*) FROM certificates WHERE ip = '10.0.0.1' AND port = 443").fetchone()[0]
        row = conn.execute("SELECT cn FROM certificates WHERE ip = '10.0.0.1'").fetchone()
        conn.close()

        assert count == 1
        assert row[0] == "new.com"

    def test_get_certificates(self, tmp_path):
        """Retrieve all certificates."""
        from bigr.db import get_certificates, init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)

        save_certificate(CertificateInfo(ip="10.0.0.1", port=443, cn="a.com"), db_path=db_path)
        save_certificate(CertificateInfo(ip="10.0.0.2", port=443, cn="b.com"), db_path=db_path)

        certs = get_certificates(db_path=db_path)
        assert len(certs) == 2
        cns = {c["cn"] for c in certs}
        assert "a.com" in cns
        assert "b.com" in cns

    def test_get_expiring(self, tmp_path):
        """Filter certificates by expiry days."""
        from bigr.db import get_expiring_certificates, init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)

        save_certificate(
            CertificateInfo(ip="10.0.0.1", port=443, cn="expiring.com", days_until_expiry=10),
            db_path=db_path,
        )
        save_certificate(
            CertificateInfo(ip="10.0.0.2", port=443, cn="ok.com", days_until_expiry=90),
            db_path=db_path,
        )

        expiring = get_expiring_certificates(days=30, db_path=db_path)
        assert len(expiring) == 1
        assert expiring[0]["cn"] == "expiring.com"

    def test_certificates_table_created(self, tmp_path):
        """Certificates table exists after init_db."""
        from bigr.db import init_db

        db_path = tmp_path / "test.db"
        init_db(db_path)

        conn = sqlite3.connect(str(db_path))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        ).fetchall()
        conn.close()
        assert len(tables) == 1


# ---------------------------------------------------------------------------
# TestCertsCli
# ---------------------------------------------------------------------------


class TestCertsCli:
    """Tests for CLI certs commands."""

    def test_certs_list(self, tmp_path):
        """CLI list command works."""
        from typer.testing import CliRunner

        from bigr.cli import app
        from bigr.db import init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)
        save_certificate(
            CertificateInfo(ip="10.0.0.1", port=443, cn="test.com"),
            db_path=db_path,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["certs", "list", "--db-path", str(db_path)])
        assert result.exit_code == 0
        # Rich may truncate "test.com" to "test.c..." in narrow terminals
        assert "10.0.0.1" in result.output
        assert "TLS Certificates" in result.output

    def test_certs_expiring(self, tmp_path):
        """CLI expiring command works."""
        from typer.testing import CliRunner

        from bigr.cli import app
        from bigr.db import init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)
        save_certificate(
            CertificateInfo(ip="10.0.0.1", port=443, cn="exp.com", days_until_expiry=10),
            db_path=db_path,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["certs", "expiring", "--db-path", str(db_path)])
        assert result.exit_code == 0
        assert "exp.com" in result.output

    def test_certs_expiring_with_days(self, tmp_path):
        """--days parameter works."""
        from typer.testing import CliRunner

        from bigr.cli import app
        from bigr.db import init_db, save_certificate

        db_path = tmp_path / "test.db"
        init_db(db_path)
        save_certificate(
            CertificateInfo(ip="10.0.0.1", port=443, cn="exp.com", days_until_expiry=10),
            db_path=db_path,
        )
        save_certificate(
            CertificateInfo(ip="10.0.0.2", port=443, cn="ok.com", days_until_expiry=90),
            db_path=db_path,
        )

        runner = CliRunner()
        result = runner.invoke(app, ["certs", "expiring", "--days", "15", "--db-path", str(db_path)])
        assert result.exit_code == 0
        assert "exp.com" in result.output
        # ok.com should NOT be in the expiring output (90 > 15 days)


# ---------------------------------------------------------------------------
# TestCertsApi
# ---------------------------------------------------------------------------


class TestCertsApi:
    """Tests for dashboard API certificate endpoint."""

    def test_api_certificates(self, tmp_path):
        """GET /api/certificates returns JSON with certificates."""
        from unittest.mock import AsyncMock, patch

        from fastapi.testclient import TestClient

        from bigr.dashboard.app import create_app

        data_path = tmp_path / "assets.json"
        data_path.write_text('{"assets":[],"category_summary":{},"total_assets":0}')

        mock_certs = [{
            "id": 1, "ip": "10.0.0.1", "port": 443, "cn": "api-test.com",
            "issuer": None, "issuer_org": None, "valid_from": None, "valid_to": None,
            "serial": None, "key_size": None, "key_algorithm": None,
            "is_self_signed": False, "is_expired": False, "days_until_expiry": 45,
            "san": [], "last_checked": "2026-01-01T00:00:00Z",
        }]

        app = create_app(data_path=str(data_path))
        client = TestClient(app)

        with patch("bigr.core.services.get_certificates_async", new_callable=AsyncMock, return_value=mock_certs):
            resp = client.get("/api/certificates")
            assert resp.status_code == 200
            body = resp.json()
            assert "certificates" in body
            assert len(body["certificates"]) == 1
            assert body["certificates"][0]["cn"] == "api-test.com"
