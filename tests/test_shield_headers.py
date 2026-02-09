"""Tests for bigr.shield.modules.http_headers -- HTTP security headers module."""

from __future__ import annotations

import urllib.error
from http.client import HTTPMessage
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.http_headers import (
    HttpHeadersModule,
    _has_version_info,
    _fetch_headers,
)


# ---------- Helper to build mock headers ----------

def _make_headers_dict(**kwargs: str) -> dict[str, str]:
    """Build a lowercase headers dict from keyword arguments."""
    return {k.lower().replace("_", "-"): v for k, v in kwargs.items()}


ALL_SECURE_HEADERS = _make_headers_dict(
    strict_transport_security="max-age=31536000; includeSubDomains; preload",
    content_security_policy="default-src 'self'",
    x_frame_options="DENY",
    x_content_type_options="nosniff",
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy="camera=(), microphone=(), geolocation=()",
)


# ---------- Tests for check_available ----------

class TestHttpHeadersCheckAvailable:
    """Tests for HttpHeadersModule.check_available()."""

    def test_always_available(self):
        """HTTP headers module uses stdlib, should always be available."""
        mod = HttpHeadersModule()
        assert mod.check_available() is True

    def test_module_metadata(self):
        mod = HttpHeadersModule()
        assert mod.name == "headers"
        assert mod.weight == 10


# ---------- Tests for _has_version_info ----------

class TestHasVersionInfo:
    """Tests for the version info detection helper."""

    def test_nginx_with_version(self):
        assert _has_version_info("nginx/1.18.0") is True

    def test_apache_with_version(self):
        assert _has_version_info("Apache/2.4.41 (Ubuntu)") is True

    def test_numeric_version_pattern(self):
        assert _has_version_info("MyServer 2.3") is True

    def test_plain_name_no_version(self):
        assert _has_version_info("nginx") is False

    def test_empty_string(self):
        assert _has_version_info("") is False


# ---------- Tests for scan() with all headers present ----------

class TestHttpHeadersAllPresent:
    """Test scan() when all security headers are present."""

    @pytest.mark.asyncio
    async def test_all_headers_present(self):
        mod = HttpHeadersModule()

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(ALL_SECURE_HEADERS, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        # No missing-header findings expected
        missing_header_findings = [
            f for f in findings
            if "Missing" in f.title
        ]
        assert len(missing_header_findings) == 0

    @pytest.mark.asyncio
    async def test_no_info_leak_when_no_leak_headers(self):
        mod = HttpHeadersModule()

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(ALL_SECURE_HEADERS, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        # No info leak findings
        leak_findings = [f for f in findings if "Disclosure" in f.title]
        assert len(leak_findings) == 0


# ---------- Tests for scan() with missing HSTS ----------

class TestHttpHeadersMissingHSTS:
    """Test scan() when HSTS header is missing."""

    @pytest.mark.asyncio
    async def test_missing_hsts_is_high(self):
        mod = HttpHeadersModule()

        headers = dict(ALL_SECURE_HEADERS)
        del headers["strict-transport-security"]

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(headers, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        hsts_findings = [f for f in findings if "HSTS" in f.title]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == FindingSeverity.HIGH
        assert hsts_findings[0].evidence["missing_header"] == "Strict-Transport-Security"


# ---------- Tests for scan() with missing CSP ----------

class TestHttpHeadersMissingCSP:
    """Test scan() when Content-Security-Policy header is missing."""

    @pytest.mark.asyncio
    async def test_missing_csp_is_medium(self):
        mod = HttpHeadersModule()

        headers = dict(ALL_SECURE_HEADERS)
        del headers["content-security-policy"]

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(headers, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        csp_findings = [f for f in findings if "Content-Security-Policy" in f.title]
        assert len(csp_findings) == 1
        assert csp_findings[0].severity == FindingSeverity.MEDIUM


# ---------- Tests for scan() with Server header leaking version ----------

class TestHttpHeadersServerLeak:
    """Test scan() when Server header reveals version information."""

    @pytest.mark.asyncio
    async def test_server_header_with_version(self):
        mod = HttpHeadersModule()

        headers = dict(ALL_SECURE_HEADERS)
        headers["server"] = "nginx/1.19.0"

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(headers, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        server_findings = [f for f in findings if "Server" in f.title and "Disclosure" in f.title]
        assert len(server_findings) == 1
        assert server_findings[0].severity == FindingSeverity.MEDIUM
        assert server_findings[0].evidence["value"] == "nginx/1.19.0"

    @pytest.mark.asyncio
    async def test_server_header_without_version_no_finding(self):
        """Server header with just name (no version) should not be flagged."""
        mod = HttpHeadersModule()

        headers = dict(ALL_SECURE_HEADERS)
        headers["server"] = "nginx"

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(headers, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        server_findings = [f for f in findings if "Server" in f.title and "Disclosure" in f.title]
        assert len(server_findings) == 0


# ---------- Tests for X-Powered-By leak ----------

class TestHttpHeadersPoweredByLeak:
    """Test scan() when X-Powered-By header is present."""

    @pytest.mark.asyncio
    async def test_x_powered_by_present(self):
        mod = HttpHeadersModule()

        headers = dict(ALL_SECURE_HEADERS)
        headers["x-powered-by"] = "Express"

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(headers, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        powered_by = [f for f in findings if "X-Powered-By" in f.title]
        assert len(powered_by) == 1
        assert powered_by[0].severity == FindingSeverity.MEDIUM


# ---------- Tests for connection error ----------

class TestHttpHeadersConnectionError:
    """Test scan() when connection to target fails."""

    @pytest.mark.asyncio
    async def test_connection_error(self):
        mod = HttpHeadersModule()

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            side_effect=OSError("Connection refused"),
        ):
            findings = await mod.scan("unreachable.example.com")

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert "Connection Failed" in findings[0].title

    @pytest.mark.asyncio
    async def test_url_error(self):
        mod = HttpHeadersModule()

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            side_effect=urllib.error.URLError("Name resolution failed"),
        ):
            findings = await mod.scan("bad.example.com")

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert "Connection Failed" in findings[0].title


# ---------- Tests for HTTPS fallback to HTTP ----------

class TestHttpHeadersHttpsFallback:
    """Test scan() HTTPS -> HTTP fallback behavior."""

    @pytest.mark.asyncio
    async def test_https_fallback_to_http(self):
        """When HTTPS fails, should fall back to HTTP and still check headers."""
        mod = HttpHeadersModule()

        # Return headers from HTTP URL (indicating fallback happened)
        headers = dict(ALL_SECURE_HEADERS)

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=(headers, "http://example.com"),
        ):
            findings = await mod.scan("example.com")

        # Should work fine with HTTP fallback
        # No connection error findings expected
        error_findings = [f for f in findings if "Failed" in f.title or "Error" in f.title]
        assert len(error_findings) == 0


# ---------- Tests for multiple missing headers ----------

class TestHttpHeadersMultipleMissing:
    """Test scan() with several missing security headers."""

    @pytest.mark.asyncio
    async def test_all_headers_missing(self):
        """When no security headers are set, should produce multiple findings."""
        mod = HttpHeadersModule()

        # Empty headers -- no security headers at all
        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=({}, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        # Should have 6 findings (one for each required header)
        missing_findings = [f for f in findings if "Missing" in f.title]
        assert len(missing_findings) == 6

        # Verify severity distribution
        severities = [f.severity for f in missing_findings]
        assert FindingSeverity.HIGH in severities      # HSTS
        assert FindingSeverity.MEDIUM in severities     # CSP, X-Frame-Options
        assert FindingSeverity.LOW in severities        # X-Content-Type, Referrer, Permissions

    @pytest.mark.asyncio
    async def test_attack_technique_on_missing_headers(self):
        mod = HttpHeadersModule()

        with patch(
            "bigr.shield.modules.http_headers._fetch_headers",
            return_value=({}, "https://example.com"),
        ):
            findings = await mod.scan("example.com")

        # All missing header findings should have MITRE ATT&CK mapping
        missing_findings = [f for f in findings if "Missing" in f.title]
        for f in missing_findings:
            assert f.attack_technique == "T1190"
