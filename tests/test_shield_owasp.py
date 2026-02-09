"""Tests for bigr.shield.modules.owasp_probes -- OWASP basic probes module."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.owasp_probes import (
    DISCLOSURE_PATHS,
    SQL_ERROR_PATTERNS,
    XSS_PAYLOAD,
    TRAVERSAL_SUCCESS_INDICATOR,
    REDIRECT_TEST_URL,
    OwaspProbesModule,
    _build_base_url,
    _check_info_disclosure,
    _check_open_redirect,
    _check_sql_injection,
    _check_xss,
    _check_directory_traversal,
    _http_get,
)


# ---------- Tests for module metadata ----------

class TestOwaspMetadata:
    """Tests for OwaspProbesModule metadata."""

    def test_module_name(self):
        mod = OwaspProbesModule()
        assert mod.name == "owasp"

    def test_module_weight(self):
        mod = OwaspProbesModule()
        assert mod.weight == 5

    def test_check_available(self):
        """Uses stdlib urllib, should always be available."""
        mod = OwaspProbesModule()
        assert mod.check_available() is True


# ---------- Tests for SQL injection detection ----------

class TestSqlInjectionDetection:
    """Tests for SQL injection probe."""

    def test_detects_sql_error_in_response(self):
        """SQL error pattern in response body should produce CRITICAL finding."""
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, "Error: you have an error in your sql syntax near 'OR 1=1'"),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].module == "owasp"
        assert "SQL Injection" in findings[0].title
        assert findings[0].attack_technique == "T1190"

    def test_detects_mysql_error(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(500, "Warning: mysql_fetch_array() failed"),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_detects_oracle_error(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(500, "ORA-01756: quoted string not properly terminated"),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 1

    def test_detects_postgres_error(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(500, "ERROR: syntax error at or near 'OR'"),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 1


class TestSqlInjectionNoError:
    """Tests for SQL injection probe when no vulnerability found."""

    def test_no_finding_when_no_sql_error(self):
        """Normal response should not trigger SQL injection finding."""
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, "<html><body>Welcome to our site</body></html>"),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 0

    def test_no_finding_when_connection_fails(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(-1, ""),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 0


# ---------- Tests for XSS detection ----------

class TestXssDetection:
    """Tests for reflected XSS probe."""

    def test_detects_reflected_payload(self):
        """XSS payload reflected in response should produce HIGH finding."""
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, f"Search results for: {XSS_PAYLOAD}"),
        ):
            findings = _check_xss("http://example.com", "example.com", 80)

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH
        assert findings[0].module == "owasp"
        assert "XSS" in findings[0].title
        assert findings[0].attack_technique == "T1059.007"

    def test_no_finding_when_payload_not_reflected(self):
        """Payload NOT reflected in response should produce no finding."""
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, "Search results for: sanitized_input"),
        ):
            findings = _check_xss("http://example.com", "example.com", 80)

        assert len(findings) == 0


# ---------- Tests for directory traversal ----------

class TestDirectoryTraversal:
    """Tests for directory traversal probe."""

    def test_detects_etc_passwd(self):
        """Response containing /root: indicates directory traversal."""
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, "root:x:0:0:root:/root:/bin/bash\n"),
        ):
            findings = _check_directory_traversal("http://example.com", "example.com", 80)

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert "Directory Traversal" in findings[0].title
        assert findings[0].attack_technique == "T1190"

    def test_no_finding_when_not_vulnerable(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(404, "File not found"),
        ):
            findings = _check_directory_traversal("http://example.com", "example.com", 80)

        assert len(findings) == 0


# ---------- Tests for information disclosure ----------

class TestInfoDisclosure:
    """Tests for information disclosure probe."""

    def test_finds_env_exposed(self):
        """/.env returning 200 with content should produce HIGH finding."""
        def mock_http_get(url, timeout=10):
            if "/.env" in url:
                return (200, "DB_PASSWORD=secret123\nAPI_KEY=abc")
            return (404, "")

        with patch("bigr.shield.modules.owasp_probes._http_get", side_effect=mock_http_get):
            findings = _check_info_disclosure("http://example.com", "example.com", 80)

        env_findings = [f for f in findings if "Environment File" in f.title]
        assert len(env_findings) == 1
        assert env_findings[0].severity == FindingSeverity.HIGH
        assert env_findings[0].evidence["path"] == "/.env"

    def test_finds_git_head_exposed(self):
        """/.git/HEAD returning 200 should produce HIGH finding."""
        def mock_http_get(url, timeout=10):
            if "/.git/HEAD" in url:
                return (200, "ref: refs/heads/main")
            return (404, "")

        with patch("bigr.shield.modules.owasp_probes._http_get", side_effect=mock_http_get):
            findings = _check_info_disclosure("http://example.com", "example.com", 80)

        git_findings = [f for f in findings if "Git Repository" in f.title]
        assert len(git_findings) == 1
        assert git_findings[0].severity == FindingSeverity.HIGH

    def test_finds_phpinfo_exposed(self):
        def mock_http_get(url, timeout=10):
            if "/phpinfo.php" in url:
                return (200, "<h1>PHP Version 8.2.3</h1>")
            return (404, "")

        with patch("bigr.shield.modules.owasp_probes._http_get", side_effect=mock_http_get):
            findings = _check_info_disclosure("http://example.com", "example.com", 80)

        php_findings = [f for f in findings if "PHPInfo" in f.title]
        assert len(php_findings) == 1


class TestInfoDisclosure404:
    """Test that 404 responses do not produce findings."""

    def test_no_finding_for_404_responses(self):
        def mock_http_get(url, timeout=10):
            return (404, "Not Found")

        with patch("bigr.shield.modules.owasp_probes._http_get", side_effect=mock_http_get):
            findings = _check_info_disclosure("http://example.com", "example.com", 80)

        assert len(findings) == 0

    def test_no_finding_for_empty_200(self):
        """HTTP 200 with empty body should not produce a finding."""
        def mock_http_get(url, timeout=10):
            return (200, "")

        with patch("bigr.shield.modules.owasp_probes._http_get", side_effect=mock_http_get):
            findings = _check_info_disclosure("http://example.com", "example.com", 80)

        assert len(findings) == 0


# ---------- Tests for open redirect ----------

class TestOpenRedirect:
    """Tests for open redirect probe."""

    def test_detects_redirect_to_external_url(self):
        """Redirect Location containing external URL should produce finding."""
        import urllib.error

        mock_headers = MagicMock()
        mock_headers.get = MagicMock(return_value=REDIRECT_TEST_URL)

        http_error = urllib.error.HTTPError(
            "http://example.com/?url=https://evil.example.com",
            302,
            "Found",
            mock_headers,
            None,
        )

        # Mock the opener
        mock_opener = MagicMock()
        mock_opener.open = MagicMock(side_effect=http_error)

        with patch("bigr.shield.modules.owasp_probes.urllib.request.build_opener", return_value=mock_opener):
            findings = _check_open_redirect("http://example.com", "example.com", 80)

        redirect_findings = [f for f in findings if "Redirect" in f.title]
        assert len(redirect_findings) == 1
        assert redirect_findings[0].severity == FindingSeverity.MEDIUM
        assert redirect_findings[0].attack_technique == "T1190"

    def test_no_redirect_no_finding(self):
        """No redirect should produce no finding."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read = MagicMock(return_value=b"Normal page content")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_opener = MagicMock()
        mock_opener.open = MagicMock(return_value=mock_resp)

        with patch("bigr.shield.modules.owasp_probes.urllib.request.build_opener", return_value=mock_opener):
            findings = _check_open_redirect("http://example.com", "example.com", 80)

        redirect_findings = [f for f in findings if "Redirect" in f.title]
        assert len(redirect_findings) == 0


# ---------- Tests for HTTP service unavailable ----------

class TestHttpUnavailable:
    """Test scan() when target has no HTTP service."""

    @pytest.mark.asyncio
    async def test_no_http_service(self):
        mod = OwaspProbesModule()

        with patch(
            "bigr.shield.modules.owasp_probes._build_base_url",
            return_value=None,
        ):
            findings = await mod.scan("no-web.example.com")

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO
        assert "HTTP Service Not Available" in findings[0].title
        assert findings[0].module == "owasp"


# ---------- Tests for probe timeout handling ----------

class TestProbeTimeout:
    """Test that probes handle timeouts gracefully."""

    @pytest.mark.asyncio
    async def test_timeouts_produce_no_crash(self):
        mod = OwaspProbesModule()

        def mock_http_get(url, timeout=10):
            return (-1, "")

        with patch(
            "bigr.shield.modules.owasp_probes._build_base_url",
            return_value="http://example.com",
        ), patch(
            "bigr.shield.modules.owasp_probes._http_get",
            side_effect=mock_http_get,
        ), patch(
            "bigr.shield.modules.owasp_probes._check_open_redirect",
            return_value=[],
        ):
            findings = await mod.scan("slow.example.com")

        # Should not crash; may return empty findings
        assert isinstance(findings, list)


# ---------- Tests for finding format ----------

class TestOwaspFindingFormat:
    """Test that OWASP findings have correct format."""

    def test_sql_injection_finding_format(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, "you have an error in your sql syntax"),
        ):
            findings = _check_sql_injection("http://example.com", "example.com", 80)

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "owasp"
        assert f.severity == FindingSeverity.CRITICAL
        assert f.attack_technique == "T1190"
        assert f.attack_tactic == "Initial Access"
        assert f.target_ip == "example.com"
        assert f.target_port == 80
        assert "url" in f.evidence

    def test_xss_finding_has_attack_technique(self):
        with patch(
            "bigr.shield.modules.owasp_probes._http_get",
            return_value=(200, f"Result: {XSS_PAYLOAD}"),
        ):
            findings = _check_xss("http://example.com", "example.com", 443)

        assert len(findings) == 1
        assert findings[0].attack_technique == "T1059.007"
        assert findings[0].attack_tactic == "Execution"


# ---------- Tests for _http_get helper ----------

class TestHttpGet:
    """Tests for the HTTP GET helper."""

    def test_successful_get(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read = MagicMock(return_value=b"Hello World")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("bigr.shield.modules.owasp_probes.urllib.request.urlopen", return_value=mock_resp):
            status, body = _http_get("http://example.com/")

        assert status == 200
        assert body == "Hello World"

    def test_connection_error_returns_negative(self):
        with patch(
            "bigr.shield.modules.owasp_probes.urllib.request.urlopen",
            side_effect=OSError("Connection refused"),
        ):
            status, body = _http_get("http://example.com/")

        assert status == -1
        assert body == ""

    def test_http_error_returns_status_and_body(self):
        error = urllib.error.HTTPError(
            "http://example.com/", 500,
            "Internal Server Error", {},
            MagicMock(read=MagicMock(return_value=b"Server Error Details")),
        )
        # The HTTPError's read method
        error.read = MagicMock(return_value=b"Server Error Details")

        with patch("bigr.shield.modules.owasp_probes.urllib.request.urlopen", side_effect=error):
            status, body = _http_get("http://example.com/")

        assert status == 500
        assert "Server Error" in body


# ---------- Tests for _build_base_url ----------

class TestBuildBaseUrl:
    """Tests for the base URL builder."""

    def test_https_preferred(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("bigr.shield.modules.owasp_probes.urllib.request.urlopen", return_value=mock_resp):
            url = _build_base_url("example.com")

        assert url == "https://example.com"

    def test_falls_back_to_http(self):
        call_count = {"n": 0}

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise urllib.error.URLError("SSL error")
            return mock_resp

        with patch("bigr.shield.modules.owasp_probes.urllib.request.urlopen", side_effect=side_effect):
            url = _build_base_url("example.com")

        assert url == "http://example.com"

    def test_returns_none_when_unreachable(self):
        with patch(
            "bigr.shield.modules.owasp_probes.urllib.request.urlopen",
            side_effect=OSError("Connection refused"),
        ):
            url = _build_base_url("unreachable.example.com")

        assert url is None


# ---------- Tests for full scan integration ----------

class TestOwaspFullScan:
    """Integration-style tests for the full scan() method."""

    @pytest.mark.asyncio
    async def test_scan_runs_all_probes(self):
        """Full scan should invoke all probe categories."""
        mod = OwaspProbesModule()

        with patch(
            "bigr.shield.modules.owasp_probes._build_base_url",
            return_value="http://example.com",
        ), patch(
            "bigr.shield.modules.owasp_probes._check_sql_injection",
            return_value=[],
        ) as mock_sqli, patch(
            "bigr.shield.modules.owasp_probes._check_xss",
            return_value=[],
        ) as mock_xss, patch(
            "bigr.shield.modules.owasp_probes._check_directory_traversal",
            return_value=[],
        ) as mock_traversal, patch(
            "bigr.shield.modules.owasp_probes._check_info_disclosure",
            return_value=[],
        ) as mock_disclosure, patch(
            "bigr.shield.modules.owasp_probes._check_open_redirect",
            return_value=[],
        ) as mock_redirect:
            findings = await mod.scan("example.com")

        mock_sqli.assert_called_once()
        mock_xss.assert_called_once()
        mock_traversal.assert_called_once()
        mock_disclosure.assert_called_once()
        mock_redirect.assert_called_once()
        assert findings == []
