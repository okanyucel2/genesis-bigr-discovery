"""Tests for bigr.shield.modules.dns_security -- DNS security records module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.dns_security import (
    DnsSecurityModule,
    _is_ip_address,
    _parse_dmarc,
    _parse_spf,
    _strip_domain,
)


# ---------- Tests for helper functions ----------

class TestIsIpAddress:
    """Tests for _is_ip_address helper."""

    def test_ipv4_address(self):
        assert _is_ip_address("192.168.1.1") is True

    def test_ipv4_zeros(self):
        assert _is_ip_address("0.0.0.0") is True

    def test_ipv6_address(self):
        assert _is_ip_address("::1") is True

    def test_domain_name(self):
        assert _is_ip_address("example.com") is False

    def test_partial_ip(self):
        assert _is_ip_address("192.168.1") is False

    def test_ip_with_high_octet(self):
        assert _is_ip_address("256.1.1.1") is False


class TestStripDomain:
    """Tests for _strip_domain helper."""

    def test_plain_domain(self):
        assert _strip_domain("example.com") == "example.com"

    def test_https_prefix(self):
        assert _strip_domain("https://example.com") == "example.com"

    def test_http_prefix(self):
        assert _strip_domain("http://example.com") == "example.com"

    def test_with_port(self):
        assert _strip_domain("example.com:443") == "example.com"

    def test_with_path(self):
        assert _strip_domain("example.com/path/to/page") == "example.com"

    def test_full_url(self):
        assert _strip_domain("https://example.com:8080/path") == "example.com"


class TestParseSPF:
    """Tests for _parse_spf helper."""

    def test_valid_spf_hard_fail(self):
        records = ["v=spf1 include:_spf.google.com -all"]
        result = _parse_spf(records)
        assert result["found"] is True
        assert result["valid"] is True
        assert result["policy_strict"] is True

    def test_valid_spf_soft_fail(self):
        records = ["v=spf1 include:_spf.google.com ~all"]
        result = _parse_spf(records)
        assert result["found"] is True
        assert result["valid"] is True
        assert result["policy_strict"] is False

    def test_spf_no_all_mechanism(self):
        records = ["v=spf1 include:_spf.google.com"]
        result = _parse_spf(records)
        assert result["found"] is True
        assert result["valid"] is False

    def test_no_spf_record(self):
        records = ["some-other-txt-record", "another-record"]
        result = _parse_spf(records)
        assert result["found"] is False

    def test_empty_records(self):
        result = _parse_spf([])
        assert result["found"] is False


class TestParseDMARC:
    """Tests for _parse_dmarc helper."""

    def test_dmarc_reject(self):
        records = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        result = _parse_dmarc(records)
        assert result["found"] is True
        assert result["policy"] == "reject"

    def test_dmarc_quarantine(self):
        records = ["v=DMARC1; p=quarantine"]
        result = _parse_dmarc(records)
        assert result["found"] is True
        assert result["policy"] == "quarantine"

    def test_dmarc_none(self):
        records = ["v=DMARC1; p=none"]
        result = _parse_dmarc(records)
        assert result["found"] is True
        assert result["policy"] == "none"

    def test_no_dmarc_record(self):
        records = ["some-random-txt"]
        result = _parse_dmarc(records)
        assert result["found"] is False

    def test_empty_records(self):
        result = _parse_dmarc([])
        assert result["found"] is False


# ---------- Tests for check_available ----------

class TestDnsSecurityCheckAvailable:
    """Tests for DnsSecurityModule.check_available()."""

    def test_always_available(self):
        mod = DnsSecurityModule()
        assert mod.check_available() is True

    def test_module_metadata(self):
        mod = DnsSecurityModule()
        assert mod.name == "dns"
        assert mod.weight == 10


# ---------- Tests for scan() ----------

class TestDnsScanIpTarget:
    """Test scan() when target is an IP address."""

    @pytest.mark.asyncio
    async def test_ip_target_skips_dns(self):
        mod = DnsSecurityModule()
        findings = await mod.scan("192.168.1.1")

        assert len(findings) == 1
        assert "Skipped" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
        assert findings[0].evidence["target_type"] == "ip_address"

    @pytest.mark.asyncio
    async def test_ipv6_target_skips_dns(self):
        mod = DnsSecurityModule()
        findings = await mod.scan("::1")

        assert len(findings) == 1
        assert "Skipped" in findings[0].title


class TestDnsScanValidRecords:
    """Test scan() with valid SPF + DMARC reject (minimal findings)."""

    @pytest.mark.asyncio
    async def test_valid_spf_and_dmarc_reject(self):
        """Domain with proper SPF, DKIM, DMARC=reject should have minimal findings."""
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            if domain == "example.com":
                return ["v=spf1 include:_spf.google.com -all", "some-other-record"], None
            elif "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkq..."], None
            elif "_dmarc" in domain:
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"], None
            return [], None

        async def mock_query_caa(domain: str):
            return ['0 issue "letsencrypt.org"'], None

        async def mock_query_mx(domain: str):
            return ["10 mx.example.com."], None

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("example.com")

        # With everything configured properly, should have:
        # - INFO for MX records present
        # - No HIGH or CRITICAL findings
        high_critical = [
            f for f in findings
            if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
        ]
        assert len(high_critical) == 0

        # Should have an INFO finding for MX records
        mx_findings = [f for f in findings if "MX" in f.title]
        assert len(mx_findings) == 1
        assert mx_findings[0].severity == FindingSeverity.INFO


class TestDnsScanMissingSPF:
    """Test scan() when SPF record is missing."""

    @pytest.mark.asyncio
    async def test_missing_spf_produces_high(self):
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            if domain == "nosecurity.com":
                return ["some-unrelated-txt-record"], None
            elif "_domainkey" in domain:
                return [], None
            elif "_dmarc" in domain:
                return ["v=DMARC1; p=reject"], None
            return [], None

        async def mock_query_caa(domain: str):
            return [], None

        async def mock_query_mx(domain: str):
            return [], None

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("nosecurity.com")

        spf_findings = [f for f in findings if "SPF" in f.title and "Missing" in f.title]
        assert len(spf_findings) == 1
        assert spf_findings[0].severity == FindingSeverity.HIGH
        assert spf_findings[0].attack_technique == "T1566"


class TestDnsScanDMARCNone:
    """Test scan() when DMARC policy is none."""

    @pytest.mark.asyncio
    async def test_dmarc_none_produces_high(self):
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            if domain == "weak.com":
                return ["v=spf1 include:_spf.google.com -all"], None
            elif "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkq..."], None
            elif "_dmarc" in domain:
                return ["v=DMARC1; p=none; rua=mailto:dmarc@weak.com"], None
            return [], None

        async def mock_query_caa(domain: str):
            return ['0 issue "letsencrypt.org"'], None

        async def mock_query_mx(domain: str):
            return [], None

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("weak.com")

        dmarc_none_findings = [f for f in findings if "DMARC" in f.title and "None" in f.title]
        assert len(dmarc_none_findings) == 1
        assert dmarc_none_findings[0].severity == FindingSeverity.HIGH
        assert dmarc_none_findings[0].evidence["policy"] == "none"

    @pytest.mark.asyncio
    async def test_dmarc_quarantine_produces_low(self):
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            if domain == "moderate.com":
                return ["v=spf1 -all"], None
            elif "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=key"], None
            elif "_dmarc" in domain:
                return ["v=DMARC1; p=quarantine"], None
            return [], None

        async def mock_query_caa(domain: str):
            return ['0 issue "letsencrypt.org"'], None

        async def mock_query_mx(domain: str):
            return [], None

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("moderate.com")

        dmarc_quarantine = [f for f in findings if "DMARC" in f.title and "Quarantine" in f.title]
        assert len(dmarc_quarantine) == 1
        assert dmarc_quarantine[0].severity == FindingSeverity.LOW


class TestDnsScanDNSFailure:
    """Test scan() when DNS lookup fails."""

    @pytest.mark.asyncio
    async def test_dns_query_error(self):
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            return [], "DNS query timed out after 15s"

        async def mock_query_caa(domain: str):
            return [], "DNS query timed out after 15s"

        async def mock_query_mx(domain: str):
            return [], "DNS query timed out after 15s"

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("failing.example.com")

        # Should have at least one error-reporting finding
        error_findings = [f for f in findings if "Failed" in f.title]
        assert len(error_findings) >= 1
        assert error_findings[0].severity == FindingSeverity.INFO


class TestDnsScanNoDNSTools:
    """Test scan() when neither dig nor nslookup is available."""

    @pytest.mark.asyncio
    async def test_no_dns_tools(self):
        mod = DnsSecurityModule()

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value=None):
            findings = await mod.scan("example.com")

        assert len(findings) == 1
        assert "Not Available" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
        assert findings[0].evidence["error"] == "no_dns_tools"


class TestDnsScanMissingCAA:
    """Test scan() when CAA record is missing."""

    @pytest.mark.asyncio
    async def test_missing_caa_produces_low(self):
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            if "_domainkey" not in domain and "_dmarc" not in domain:
                return ["v=spf1 -all"], None
            elif "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=key"], None
            elif "_dmarc" in domain:
                return ["v=DMARC1; p=reject"], None
            return [], None

        async def mock_query_caa(domain: str):
            return [], None  # No CAA records, no error

        async def mock_query_mx(domain: str):
            return [], None

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("nocaa.example.com")

        caa_findings = [f for f in findings if "CAA" in f.title]
        assert len(caa_findings) == 1
        assert caa_findings[0].severity == FindingSeverity.LOW


class TestDnsScanMissingDKIM:
    """Test scan() when DKIM record is missing."""

    @pytest.mark.asyncio
    async def test_missing_dkim_produces_medium(self):
        mod = DnsSecurityModule()

        async def mock_query_txt(domain: str):
            if domain == "nodkim.com":
                return ["v=spf1 -all"], None
            elif "_domainkey" in domain:
                return [], None  # No DKIM
            elif "_dmarc" in domain:
                return ["v=DMARC1; p=reject"], None
            return [], None

        async def mock_query_caa(domain: str):
            return ['0 issue "letsencrypt.org"'], None

        async def mock_query_mx(domain: str):
            return [], None

        with patch("bigr.shield.modules.dns_security.shutil.which", return_value="/usr/bin/dig"), \
             patch("bigr.shield.modules.dns_security._query_dns_txt", side_effect=mock_query_txt), \
             patch("bigr.shield.modules.dns_security._query_dns_caa", side_effect=mock_query_caa), \
             patch("bigr.shield.modules.dns_security._query_dns_mx", side_effect=mock_query_mx):
            findings = await mod.scan("nodkim.com")

        dkim_findings = [f for f in findings if "DKIM" in f.title]
        assert len(dkim_findings) == 1
        assert dkim_findings[0].severity == FindingSeverity.MEDIUM
        assert dkim_findings[0].attack_technique == "T1566"
