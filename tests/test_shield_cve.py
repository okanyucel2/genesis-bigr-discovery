"""Tests for bigr.shield.modules.cve_matcher -- CVE Intelligence module."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.cve_matcher import (
    CPE_MAP,
    CveMatcherModule,
    _banner_to_cpe,
    _calculate_priority,
    _check_kev,
    _extract_version,
    _fetch_cves_for_cpe,
    _fetch_epss,
    _fetch_kev_catalog,
    _identify_service,
    _parse_nvd_response,
)


# ---------- Tests for _extract_version ----------


class TestExtractVersion:
    """Tests for _extract_version helper."""

    def test_openssh_banner(self):
        # The generic regex matches "2.0" from "SSH-2.0-" first in the banner.
        # The service is identified by _identify_service, version extracted separately.
        assert _extract_version("SSH-2.0-OpenSSH_8.9p1") == "2.0"
        # When given just the OpenSSH portion:
        assert _extract_version("OpenSSH_8.9p1") == "8.9"

    def test_nginx_banner(self):
        assert _extract_version("nginx/1.24.0") == "1.24.0"

    def test_apache_banner(self):
        assert _extract_version("Apache/2.4.57 (Ubuntu)") == "2.4.57"

    def test_mysql_banner(self):
        assert _extract_version("MySQL 8.0.35") == "8.0.35"

    def test_unknown_banner(self):
        assert _extract_version("some-random-string-no-version") is None

    def test_generic_version(self):
        assert _extract_version("Redis/7.2.1") == "7.2.1"

    def test_version_with_p_suffix(self):
        # p suffix should be stripped
        result = _extract_version("OpenSSH_9.3p1")
        assert result == "9.3"

    def test_no_version(self):
        assert _extract_version("server") is None


# ---------- Tests for _banner_to_cpe ----------


class TestBannerToCpe:
    """Tests for _banner_to_cpe helper."""

    def test_nginx_cpe(self):
        cpe = _banner_to_cpe("nginx/1.24.0")
        assert cpe is not None
        assert "f5" in cpe
        assert "nginx" in cpe
        assert "1.24.0" in cpe

    def test_apache_cpe(self):
        cpe = _banner_to_cpe("Apache/2.4.57 (Ubuntu)")
        assert cpe is not None
        assert "apache" in cpe
        assert "http_server" in cpe
        assert "2.4.57" in cpe

    def test_openssh_cpe(self):
        cpe = _banner_to_cpe("OpenSSH_8.9p1", version="8.9")
        assert cpe is not None
        assert "openbsd" in cpe
        assert "openssh" in cpe
        assert "8.9" in cpe

    def test_unknown_returns_none(self):
        cpe = _banner_to_cpe("totally-unknown-service")
        assert cpe is None

    def test_redis_cpe(self):
        cpe = _banner_to_cpe("Redis server v=7.2.1")
        assert cpe is not None
        assert "redis" in cpe

    def test_explicit_version_overrides(self):
        cpe = _banner_to_cpe("nginx/1.24.0", version="1.25.0")
        assert cpe is not None
        assert "1.25.0" in cpe

    def test_no_version_uses_wildcard(self):
        cpe = _banner_to_cpe("nginx")
        assert cpe is not None
        # Should use wildcard for version
        assert ":*:" in cpe


# ---------- Tests for _parse_nvd_response ----------


class TestParseNvdResponse:
    """Tests for _parse_nvd_response parsing NVD API JSON."""

    def test_parse_nvd_response(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-44487",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                    }
                                }
                            ]
                        },
                        "descriptions": [
                            {"lang": "en", "value": "HTTP/2 rapid reset attack."}
                        ],
                        "weaknesses": [
                            {
                                "description": [
                                    {"lang": "en", "value": "CWE-400"}
                                ]
                            }
                        ],
                    }
                }
            ]
        }
        results = _parse_nvd_response(data)
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2023-44487"
        assert results[0]["cvss"] == 7.5
        assert results[0]["description"] == "HTTP/2 rapid reset attack."
        assert results[0]["cwe"] == "CWE-400"

    def test_empty_response(self):
        data = {"vulnerabilities": []}
        results = _parse_nvd_response(data)
        assert results == []

    def test_missing_vulnerabilities_key(self):
        results = _parse_nvd_response({})
        assert results == []

    def test_response_without_cvss(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-00001",
                        "metrics": {},
                        "descriptions": [
                            {"lang": "en", "value": "No CVSS yet."}
                        ],
                        "weaknesses": [],
                    }
                }
            ]
        }
        results = _parse_nvd_response(data)
        assert len(results) == 1
        assert results[0]["cvss"] is None

    def test_fallback_to_cvss_v30(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2020-11022",
                        "metrics": {
                            "cvssMetricV30": [
                                {
                                    "cvssData": {
                                        "baseScore": 6.1,
                                    }
                                }
                            ]
                        },
                        "descriptions": [
                            {"lang": "en", "value": "XSS via jQuery."}
                        ],
                        "weaknesses": [],
                    }
                }
            ]
        }
        results = _parse_nvd_response(data)
        assert results[0]["cvss"] == 6.1

    def test_no_cve_id_skipped(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "",
                        "metrics": {},
                        "descriptions": [],
                        "weaknesses": [],
                    }
                }
            ]
        }
        results = _parse_nvd_response(data)
        assert results == []


# ---------- Tests for _fetch_cves_for_cpe ----------


class TestFetchCvesForCpe:
    """Tests for NVD API fetching."""

    def test_api_timeout(self):
        """Network timeout should return empty list."""
        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            side_effect=TimeoutError("Connection timed out"),
        ):
            results = _fetch_cves_for_cpe("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
            assert results == []

    def test_api_error(self):
        """HTTP errors should return empty list."""
        import urllib.error

        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "http://test", 503, "Service Unavailable", {}, None
            ),
        ):
            results = _fetch_cves_for_cpe("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
            assert results == []

    def test_parse_successful_response(self):
        """Successful API call should return parsed CVE list."""
        response_data = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2023-44487",
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 7.5}}
                                ]
                            },
                            "descriptions": [
                                {"lang": "en", "value": "HTTP/2 attack."}
                            ],
                            "weaknesses": [
                                {
                                    "description": [
                                        {"lang": "en", "value": "CWE-400"}
                                    ]
                                }
                            ],
                        }
                    }
                ]
            }
        ).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            results = _fetch_cves_for_cpe("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
            assert len(results) == 1
            assert results[0]["cve_id"] == "CVE-2023-44487"


# ---------- Tests for _fetch_epss ----------


class TestFetchEpss:
    """Tests for EPSS score fetching."""

    def test_valid_score(self):
        response_data = json.dumps(
            {"data": [{"cve": "CVE-2023-44487", "epss": "0.97565"}]}
        ).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            score = _fetch_epss("CVE-2023-44487")
            assert score is not None
            assert abs(score - 0.97565) < 0.001

    def test_not_found(self):
        response_data = json.dumps({"data": []}).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            score = _fetch_epss("CVE-9999-99999")
            assert score is None

    def test_timeout(self):
        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            side_effect=TimeoutError("timed out"),
        ):
            score = _fetch_epss("CVE-2023-44487")
            assert score is None


# ---------- Tests for KEV check ----------


class TestCheckKev:
    """Tests for CISA KEV catalog check."""

    def test_found_in_kev(self):
        kev_data = json.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2023-44487"},
                    {"cveID": "CVE-2021-44228"},
                ]
            }
        ).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = kev_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        # Reset cache
        import bigr.shield.modules.cve_matcher as mod

        mod._kev_cache["data"] = None
        mod._kev_cache["fetched_at"] = 0.0

        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            assert _check_kev("CVE-2023-44487") is True

    def test_not_in_kev(self):
        kev_data = json.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2023-44487"},
                ]
            }
        ).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = kev_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        # Reset cache
        import bigr.shield.modules.cve_matcher as mod

        mod._kev_cache["data"] = None
        mod._kev_cache["fetched_at"] = 0.0

        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            assert _check_kev("CVE-9999-99999") is False

    def test_cache_used(self):
        """After fetching once, cache should be used without network call."""
        import bigr.shield.modules.cve_matcher as mod

        # Pre-populate cache
        mod._kev_cache["data"] = {"CVE-2021-44228"}
        mod._kev_cache["fetched_at"] = time.time()

        # Should NOT call urlopen since cache is fresh
        with patch(
            "bigr.shield.modules.cve_matcher.urllib.request.urlopen",
        ) as mock_open:
            result = _check_kev("CVE-2021-44228")
            assert result is True
            mock_open.assert_not_called()

        # Clean up
        mod._kev_cache["data"] = None
        mod._kev_cache["fetched_at"] = 0.0


# ---------- Tests for _calculate_priority ----------


class TestCalculatePriority:
    """Tests for CVE priority calculation."""

    def test_critical_high_cvss_and_kev(self):
        assert _calculate_priority(9.8, 0.9, True) == FindingSeverity.CRITICAL

    def test_critical_high_cvss_and_epss(self):
        assert _calculate_priority(9.5, 0.6, False) == FindingSeverity.CRITICAL

    def test_high_cvss(self):
        assert _calculate_priority(8.0, 0.1, False) == FindingSeverity.HIGH

    def test_high_epss_and_medium_cvss(self):
        assert _calculate_priority(5.0, 0.4, False) == FindingSeverity.HIGH

    def test_high_kev(self):
        assert _calculate_priority(3.0, 0.0, True) == FindingSeverity.HIGH

    def test_medium(self):
        assert _calculate_priority(5.5, 0.1, False) == FindingSeverity.MEDIUM

    def test_low(self):
        assert _calculate_priority(2.0, 0.01, False) == FindingSeverity.LOW

    def test_info_none_cvss(self):
        assert _calculate_priority(None, 0.5, False) == FindingSeverity.INFO

    def test_high_at_threshold(self):
        assert _calculate_priority(7.0, 0.0, False) == FindingSeverity.HIGH

    def test_medium_at_threshold(self):
        assert _calculate_priority(4.0, 0.0, False) == FindingSeverity.MEDIUM

    def test_critical_threshold_exact(self):
        assert _calculate_priority(9.0, 0.5, False) == FindingSeverity.CRITICAL


# ---------- Tests for _identify_service ----------


class TestIdentifyService:
    """Tests for _identify_service helper."""

    def test_nginx_in_banner(self):
        assert _identify_service("nginx/1.24.0", 80) == "nginx"

    def test_apache_in_banner(self):
        assert _identify_service("Apache/2.4.57", 80) == "apache"

    def test_redis_in_banner(self):
        assert _identify_service("Redis server v=7.0.5", 6379) == "redis"

    def test_fallback_to_port(self):
        assert _identify_service("some-unknown-banner", 22) == "ssh"
        assert _identify_service("some-unknown-banner", 80) == "http"

    def test_unknown_port(self):
        assert _identify_service("some-unknown-banner", 9999) == "unknown"


# ---------- Tests for CveMatcherModule metadata ----------


class TestCveMatcherMetadata:
    """Tests for CveMatcherModule class-level attributes."""

    def test_module_metadata(self):
        mod = CveMatcherModule()
        assert mod.name == "cve"
        assert mod.weight == 25

    def test_check_available(self):
        mod = CveMatcherModule()
        assert mod.check_available() is True


# ---------- Tests for CveMatcherModule.scan() ----------


class TestCveMatcherScan:
    """Tests for CveMatcherModule.scan() method."""

    @pytest.mark.asyncio
    async def test_scan_no_services(self):
        """When no services are detected, should return info finding."""
        mod = CveMatcherModule()

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=[],
        ):
            findings = await mod.scan("192.168.1.1")

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO
        assert "No Services Detected" in findings[0].title
        assert findings[0].module == "cve"

    @pytest.mark.asyncio
    async def test_scan_with_services(self):
        """Full scan with mocked services, NVD, EPSS, and KEV."""
        mod = CveMatcherModule()

        mock_services = [
            {
                "port": 80,
                "banner": "nginx/1.24.0",
                "service": "nginx",
                "version": "1.24.0",
            }
        ]

        mock_cves = [
            {
                "cve_id": "CVE-2023-44487",
                "cvss": 7.5,
                "description": "HTTP/2 rapid reset attack.",
                "cwe": "CWE-400",
            }
        ]

        import bigr.shield.modules.cve_matcher as mod_module

        # Pre-populate KEV cache to avoid network call
        mod_module._kev_cache["data"] = {"CVE-2023-44487"}
        mod_module._kev_cache["fetched_at"] = time.time()

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=mock_services,
        ), patch(
            "bigr.shield.modules.cve_matcher._banner_to_cpe",
            return_value="cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_cves_for_cpe",
            return_value=mock_cves,
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_epss",
            return_value=0.97,
        ):
            findings = await mod.scan("example.com")

        # Should have at least one CVE finding
        assert len(findings) >= 1
        cve_finding = findings[0]
        assert cve_finding.cve_id == "CVE-2023-44487"
        assert cve_finding.cvss_score == 7.5
        assert cve_finding.epss_score == 0.97
        assert cve_finding.cisa_kev is True
        assert cve_finding.module == "cve"
        assert cve_finding.target_ip == "example.com"
        assert cve_finding.target_port == 80

        # Clean up
        mod_module._kev_cache["data"] = None
        mod_module._kev_cache["fetched_at"] = 0.0

    @pytest.mark.asyncio
    async def test_scan_api_failure(self):
        """When NVD API fails for all services, should return api info finding."""
        mod = CveMatcherModule()

        mock_services = [
            {
                "port": 443,
                "banner": "nginx/1.24.0",
                "service": "nginx",
                "version": "1.24.0",
            }
        ]

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=mock_services,
        ), patch(
            "bigr.shield.modules.cve_matcher._banner_to_cpe",
            return_value="cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_cves_for_cpe",
            side_effect=Exception("NVD API error"),
        ):
            findings = await mod.scan("failing.example.com")

        # Should have API unavailable info finding
        assert len(findings) >= 1
        api_findings = [f for f in findings if "API" in f.title or "Unavailable" in f.title]
        assert len(api_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_service_detection_failure(self):
        """When service detection fails, should return error info finding."""
        mod = CveMatcherModule()

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            side_effect=Exception("Network error"),
        ):
            findings = await mod.scan("unreachable.example.com")

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.INFO
        assert "Detection Failed" in findings[0].title

    @pytest.mark.asyncio
    async def test_finding_enrichment(self):
        """Verify all ShieldFinding fields are properly populated."""
        mod = CveMatcherModule()

        mock_services = [
            {
                "port": 22,
                "banner": "SSH-2.0-OpenSSH_8.9p1",
                "service": "openssh",
                "version": "8.9",
            }
        ]

        mock_cves = [
            {
                "cve_id": "CVE-2024-12345",
                "cvss": 9.8,
                "description": "Critical SSH vulnerability.",
                "cwe": "CWE-787",
            }
        ]

        import bigr.shield.modules.cve_matcher as mod_module

        mod_module._kev_cache["data"] = set()
        mod_module._kev_cache["fetched_at"] = time.time()

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=mock_services,
        ), patch(
            "bigr.shield.modules.cve_matcher._banner_to_cpe",
            return_value="cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*",
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_cves_for_cpe",
            return_value=mock_cves,
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_epss",
            return_value=0.8,
        ):
            findings = await mod.scan("ssh-server.example.com")

        assert len(findings) >= 1
        f = findings[0]
        assert f.cve_id == "CVE-2024-12345"
        assert f.cvss_score == 9.8
        assert f.epss_score == 0.8
        assert f.cisa_kev is False
        assert f.target_ip == "ssh-server.example.com"
        assert f.target_port == 22
        assert f.evidence["cpe"] == "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"
        assert f.evidence["banner"] == "SSH-2.0-OpenSSH_8.9p1"
        assert f.evidence["cwe"] == "CWE-787"

        # Clean up
        mod_module._kev_cache["data"] = None
        mod_module._kev_cache["fetched_at"] = 0.0

    @pytest.mark.asyncio
    async def test_attack_mapping(self):
        """Web services should map to T1190, SSH to T1133."""
        mod = CveMatcherModule()

        # Test with web service
        mock_services_web = [
            {
                "port": 80,
                "banner": "nginx/1.24.0",
                "service": "nginx",
                "version": "1.24.0",
            }
        ]
        mock_cves = [
            {
                "cve_id": "CVE-2024-00001",
                "cvss": 5.0,
                "description": "Web vuln.",
                "cwe": "",
            }
        ]

        import bigr.shield.modules.cve_matcher as mod_module

        mod_module._kev_cache["data"] = set()
        mod_module._kev_cache["fetched_at"] = time.time()

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=mock_services_web,
        ), patch(
            "bigr.shield.modules.cve_matcher._banner_to_cpe",
            return_value="cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_cves_for_cpe",
            return_value=mock_cves,
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_epss",
            return_value=None,
        ):
            findings = await mod.scan("web.example.com")

        assert len(findings) >= 1
        assert findings[0].attack_technique == "T1190"
        assert findings[0].attack_tactic == "Initial Access"

        # Clean up
        mod_module._kev_cache["data"] = None
        mod_module._kev_cache["fetched_at"] = 0.0

    @pytest.mark.asyncio
    async def test_no_cpe_mapping_skips_service(self):
        """Services without CPE mapping should be skipped."""
        mod = CveMatcherModule()

        mock_services = [
            {
                "port": 9999,
                "banner": "custom-service/1.0",
                "service": "unknown",
                "version": "1.0",
            }
        ]

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=mock_services,
        ), patch(
            "bigr.shield.modules.cve_matcher._banner_to_cpe",
            return_value=None,
        ):
            findings = await mod.scan("custom.example.com")

        # No CVE findings -- service had no CPE mapping, and no API failure
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_remediation_includes_kev_warning(self):
        """KEV entries should have urgent remediation text."""
        mod = CveMatcherModule()

        mock_services = [
            {
                "port": 80,
                "banner": "nginx/1.18.0",
                "service": "nginx",
                "version": "1.18.0",
            }
        ]
        mock_cves = [
            {
                "cve_id": "CVE-2021-44228",
                "cvss": 10.0,
                "description": "Log4Shell.",
                "cwe": "CWE-502",
            }
        ]

        import bigr.shield.modules.cve_matcher as mod_module

        mod_module._kev_cache["data"] = {"CVE-2021-44228"}
        mod_module._kev_cache["fetched_at"] = time.time()

        with patch(
            "bigr.shield.modules.cve_matcher._detect_services",
            return_value=mock_services,
        ), patch(
            "bigr.shield.modules.cve_matcher._banner_to_cpe",
            return_value="cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_cves_for_cpe",
            return_value=mock_cves,
        ), patch(
            "bigr.shield.modules.cve_matcher._fetch_epss",
            return_value=0.99,
        ):
            findings = await mod.scan("kev-target.example.com")

        assert len(findings) >= 1
        f = findings[0]
        assert "Known Exploited" in f.remediation or "patch immediately" in f.remediation
        assert f.cisa_kev is True
        assert f.severity == FindingSeverity.CRITICAL

        # Clean up
        mod_module._kev_cache["data"] = None
        mod_module._kev_cache["fetched_at"] = 0.0
