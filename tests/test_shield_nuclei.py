"""Tests for bigr.shield.modules.nuclei_scanner -- Nuclei vulnerability scanner wrapper."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.nuclei_scanner import (
    NUCLEI_SEVERITY_MAP,
    NucleiScannerModule,
    _extract_cve_from_template,
    parse_nuclei_output,
    select_templates,
)


# ---------- Tests for NucleiScannerModule metadata ----------


class TestNucleiMetadata:
    """Tests for NucleiScannerModule class-level attributes."""

    def test_metadata(self):
        mod = NucleiScannerModule()
        assert mod.name == "nuclei_scanner"
        assert mod.weight == 0  # Supplementary module

    def test_available_when_nuclei_exists(self):
        mod = NucleiScannerModule()
        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ):
            assert mod.check_available() is True

    def test_unavailable_when_nuclei_missing(self):
        mod = NucleiScannerModule()
        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value=None,
        ):
            assert mod.check_available() is False


# ---------- Tests for select_templates ----------


class TestSelectTemplates:
    """Tests for template selection based on services."""

    def test_http_templates(self):
        templates = select_templates(["http"])
        assert "cves/" in templates
        assert "misconfiguration/" in templates
        assert "default-logins/" in templates

    def test_https_includes_ssl(self):
        templates = select_templates(["https"])
        assert "ssl/" in templates

    def test_ssh_templates(self):
        templates = select_templates(["ssh"])
        assert any("ssh" in t for t in templates)

    def test_default_templates(self):
        templates = select_templates(None)
        assert "cves/" in templates
        assert "misconfiguration/" in templates

    def test_empty_services_list(self):
        templates = select_templates([])
        assert "cves/" in templates
        assert "misconfiguration/" in templates

    def test_mixed_services(self):
        templates = select_templates(["http", "ssh", "redis"])
        assert "cves/" in templates
        assert any("ssh" in t for t in templates)
        assert any("redis" in t for t in templates)

    def test_no_duplicates(self):
        templates = select_templates(["http", "https"])
        # Both share "cves/" and "misconfiguration/" -- no duplicates
        assert templates.count("cves/") == 1
        assert templates.count("misconfiguration/") == 1

    def test_unknown_service_falls_back(self):
        templates = select_templates(["custom-unknown-svc"])
        # Should fall back to defaults
        assert "cves/" in templates
        assert "misconfiguration/" in templates


# ---------- Tests for _extract_cve_from_template ----------


class TestExtractCve:
    """Tests for CVE ID extraction from template identifiers."""

    def test_cve_in_template(self):
        assert _extract_cve_from_template("CVE-2023-44487-http2-rapid-reset") == "CVE-2023-44487"

    def test_no_cve(self):
        assert _extract_cve_from_template("misconfiguration-nginx-status") is None

    def test_case_insensitive(self):
        assert _extract_cve_from_template("cve-2021-44228-log4shell") == "CVE-2021-44228"

    def test_cve_with_long_number(self):
        assert _extract_cve_from_template("CVE-2024-123456") == "CVE-2024-123456"

    def test_cve_at_end(self):
        assert _extract_cve_from_template("template-CVE-2020-11022") == "CVE-2020-11022"

    def test_empty_template(self):
        assert _extract_cve_from_template("") is None


# ---------- Tests for parse_nuclei_output ----------


class TestParseNucleiOutput:
    """Tests for Nuclei JSON line output parsing."""

    def test_valid_json(self):
        output = '{"template-id": "CVE-2023-44487", "info": {"name": "HTTP/2 Rapid Reset", "severity": "high", "description": "DoS attack"}, "matched-at": "https://example.com"}\n'
        results = parse_nuclei_output(output)
        assert len(results) == 1
        assert results[0]["template-id"] == "CVE-2023-44487"
        assert results[0]["info"]["severity"] == "high"

    def test_empty_output(self):
        results = parse_nuclei_output("")
        assert results == []

    def test_invalid_json_skipped(self):
        output = "not valid json\n" '{"template-id": "valid", "info": {"name": "test", "severity": "info"}}\n' "also not json\n"
        results = parse_nuclei_output(output)
        assert len(results) == 1
        assert results[0]["template-id"] == "valid"

    def test_multiple_results(self):
        line1 = '{"template-id": "CVE-2023-44487", "info": {"name": "vuln1", "severity": "high"}}'
        line2 = '{"template-id": "misconfig-001", "info": {"name": "vuln2", "severity": "medium"}}'
        output = f"{line1}\n{line2}\n"
        results = parse_nuclei_output(output)
        assert len(results) == 2

    def test_blank_lines_skipped(self):
        output = "\n\n" '{"template-id": "test", "info": {"name": "t", "severity": "low"}}' "\n\n"
        results = parse_nuclei_output(output)
        assert len(results) == 1

    def test_whitespace_only(self):
        results = parse_nuclei_output("   \n   \n   ")
        assert results == []


# ---------- Tests for NucleiScannerModule.scan() ----------


class TestNucleiScan:
    """Tests for NucleiScannerModule.scan() method."""

    @pytest.mark.asyncio
    async def test_not_installed(self):
        """When nuclei is not installed, should return info finding."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value=None,
        ):
            findings = await mod.scan("example.com")

        assert len(findings) == 1
        assert "Not Installed" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
        assert findings[0].evidence["error"] == "nuclei_not_installed"
        assert findings[0].module == "nuclei_scanner"

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Scan timeout should produce medium finding."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
            side_effect=asyncio.TimeoutError,
        ):
            mock_proc = MagicMock()
            mock_exec.return_value = mock_proc

            findings = await mod.scan("slow.example.com")

        assert len(findings) == 1
        assert "Timeout" in findings[0].title
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert findings[0].evidence["error"] == "timeout"

    @pytest.mark.asyncio
    async def test_os_error(self):
        """OSError during execution should produce info finding."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
            side_effect=OSError("Permission denied"),
        ):
            findings = await mod.scan("target.example.com")

        assert len(findings) == 1
        assert "Execution Error" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
        assert "Permission denied" in findings[0].evidence["error"]

    @pytest.mark.asyncio
    async def test_successful_scan(self):
        """Successful scan should parse output into findings."""
        mod = NucleiScannerModule()

        nuclei_output = (
            '{"template-id": "CVE-2023-44487-rapid-reset", "info": {"name": "HTTP/2 Rapid Reset", "severity": "high", "description": "Denial of service via HTTP/2"}, "matched-at": "https://example.com"}\n'
            '{"template-id": "misconfig-nginx-status", "info": {"name": "Nginx Status Exposed", "severity": "medium", "description": "Nginx status page publicly accessible"}, "matched-at": "http://example.com/nginx_status"}\n'
        )

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (nuclei_output.encode(), b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            findings = await mod.scan("example.com")

        assert len(findings) == 2

        # First finding: CVE-based
        f1 = findings[0]
        assert f1.title == "HTTP/2 Rapid Reset"
        assert f1.severity == FindingSeverity.HIGH
        assert f1.cve_id == "CVE-2023-44487"
        assert f1.target_ip == "example.com"
        assert f1.evidence["template_id"] == "CVE-2023-44487-rapid-reset"
        assert f1.attack_technique == "T1190"

        # Second finding: misconfiguration (no CVE)
        f2 = findings[1]
        assert f2.title == "Nginx Status Exposed"
        assert f2.severity == FindingSeverity.MEDIUM
        assert f2.cve_id is None
        assert f2.evidence["template_id"] == "misconfig-nginx-status"

    @pytest.mark.asyncio
    async def test_severity_mapping(self):
        """All nuclei severity levels should map correctly."""
        mod = NucleiScannerModule()

        lines = []
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(
                f'{{"template-id": "test-{sev}", "info": {{"name": "{sev} finding", "severity": "{sev}", "description": "test"}}, "matched-at": "http://example.com"}}'
            )
        nuclei_output = "\n".join(lines) + "\n"

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (nuclei_output.encode(), b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            findings = await mod.scan("example.com")

        assert len(findings) == 5
        severity_set = {f.severity for f in findings}
        assert FindingSeverity.CRITICAL in severity_set
        assert FindingSeverity.HIGH in severity_set
        assert FindingSeverity.MEDIUM in severity_set
        assert FindingSeverity.LOW in severity_set
        assert FindingSeverity.INFO in severity_set

    @pytest.mark.asyncio
    async def test_empty_output(self):
        """Empty nuclei output should produce no findings."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (b"", b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            findings = await mod.scan("clean.example.com")

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_port_url_construction(self):
        """Port 443 should use https, other ports should use http."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (b"", b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            # Test with HTTPS port
            await mod.scan("example.com", port=443)
            call_args = mock_exec.call_args[0]
            target_arg_idx = list(call_args).index("-target") + 1
            assert "https://" in call_args[target_arg_idx]

    @pytest.mark.asyncio
    async def test_port_8443_uses_https(self):
        """Port 8443 should also use https."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (b"", b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            await mod.scan("example.com", port=8443)
            call_args = mock_exec.call_args[0]
            target_arg_idx = list(call_args).index("-target") + 1
            assert "https://example.com:8443" == call_args[target_arg_idx]

    @pytest.mark.asyncio
    async def test_port_8080_uses_http(self):
        """Port 8080 should use http."""
        mod = NucleiScannerModule()

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (b"", b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            await mod.scan("example.com", port=8080)
            call_args = mock_exec.call_args[0]
            target_arg_idx = list(call_args).index("-target") + 1
            assert "http://example.com:8080" == call_args[target_arg_idx]

    @pytest.mark.asyncio
    async def test_unknown_severity_defaults_to_info(self):
        """Unknown Nuclei severity should default to INFO."""
        mod = NucleiScannerModule()

        nuclei_output = '{"template-id": "test", "info": {"name": "Unknown Sev", "severity": "unknown_level", "description": "test"}, "matched-at": "http://example.com"}\n'

        with patch(
            "bigr.shield.modules.nuclei_scanner.shutil.which",
            return_value="/usr/local/bin/nuclei",
        ), patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.create_subprocess_exec",
        ) as mock_exec, patch(
            "bigr.shield.modules.nuclei_scanner.asyncio.wait_for",
        ) as mock_wait:
            mock_wait.return_value = (nuclei_output.encode(), b"")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            findings = await mod.scan("example.com")

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO
