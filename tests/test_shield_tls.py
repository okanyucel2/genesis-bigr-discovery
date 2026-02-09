"""Tests for bigr.shield.modules.tls_check — TLS validation module."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.tls_check import (
    TLSCheckModule,
    _check_san_match,
    _hostname_matches,
    _is_weak_cipher,
)


class TestTLSCheckAvailable:
    """Tests for TLSCheckModule.check_available()."""

    def test_always_available(self):
        """TLS module uses stdlib, should always be available."""
        mod = TLSCheckModule()
        assert mod.check_available() is True

    def test_module_metadata(self):
        mod = TLSCheckModule()
        assert mod.name == "tls"
        assert mod.weight == 20


class TestHostnameMatches:
    """Tests for _hostname_matches helper."""

    def test_exact_match(self):
        assert _hostname_matches("example.com", "example.com") is True

    def test_case_insensitive(self):
        assert _hostname_matches("Example.COM", "example.com") is True

    def test_wildcard_match(self):
        assert _hostname_matches("*.example.com", "www.example.com") is True

    def test_wildcard_no_multi_level(self):
        """Wildcard should not match multi-level subdomains."""
        assert _hostname_matches("*.example.com", "a.b.example.com") is False

    def test_wildcard_no_bare_domain(self):
        """Wildcard should not match the bare domain."""
        assert _hostname_matches("*.example.com", "example.com") is False

    def test_no_match(self):
        assert _hostname_matches("other.com", "example.com") is False


class TestCheckSanMatch:
    """Tests for _check_san_match helper."""

    def test_san_dns_match(self):
        cert = {"subjectAltName": (("DNS", "example.com"),)}
        assert _check_san_match(cert, "example.com") is True

    def test_san_wildcard_match(self):
        cert = {"subjectAltName": (("DNS", "*.example.com"),)}
        assert _check_san_match(cert, "www.example.com") is True

    def test_san_ip_match(self):
        cert = {"subjectAltName": (("IP Address", "10.0.0.1"),)}
        assert _check_san_match(cert, "10.0.0.1") is True

    def test_cn_fallback(self):
        cert = {
            "subjectAltName": (),
            "subject": ((("commonName", "example.com"),),),
        }
        assert _check_san_match(cert, "example.com") is True

    def test_no_match(self):
        cert = {
            "subjectAltName": (("DNS", "other.com"),),
            "subject": ((("commonName", "other.com"),),),
        }
        assert _check_san_match(cert, "example.com") is False


class TestIsWeakCipher:
    """Tests for _is_weak_cipher helper."""

    def test_rc4_weak(self):
        assert _is_weak_cipher("RC4-SHA") is True

    def test_des_weak(self):
        assert _is_weak_cipher("DES-CBC3-SHA") is True

    def test_null_weak(self):
        assert _is_weak_cipher("NULL-SHA256") is True

    def test_aes_not_weak(self):
        assert _is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384") is False

    def test_chacha_not_weak(self):
        assert _is_weak_cipher("TLS_CHACHA20_POLY1305_SHA256") is False


class TestTLSScanExpiredCert:
    """Test scan() with a mocked expired certificate."""

    @pytest.fixture
    def mock_ssl_connection(self):
        """Set up mocks for an expired certificate scenario."""
        expired_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
        cert_info = {
            "subject": ((("commonName", "expired.example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notAfter": expired_date,
            "notBefore": "Jan  1 00:00:00 2020 GMT",
            "subjectAltName": (("DNS", "expired.example.com"),),
        }
        return cert_info

    @pytest.mark.asyncio
    async def test_expired_cert_finding(self, mock_ssl_connection):
        mod = TLSCheckModule()
        cert_info = mock_ssl_connection

        with patch("bigr.shield.modules.tls_check.socket.create_connection") as mock_conn, \
             patch("bigr.shield.modules.tls_check.ssl.create_default_context") as mock_ctx_factory, \
             patch("bigr.shield.modules.tls_check._check_hsts", return_value=None), \
             patch("bigr.shield.modules.tls_check._extract_key_bits", return_value=2048):

            # Set up the ssl context mock
            mock_ctx = MagicMock()
            mock_ctx_factory.return_value = mock_ctx

            # Set up the socket mock
            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            # Set up the SSL socket mock
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.side_effect = lambda binary_form=False: (
                b"fake-der" if binary_form else cert_info
            )
            mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            findings = await mod.scan("expired.example.com", port=443)

        # Should have an expired cert finding
        expired_findings = [
            f for f in findings if "Expired" in f.title or "expired" in f.title.lower()
        ]
        assert len(expired_findings) >= 1
        assert expired_findings[0].severity == FindingSeverity.CRITICAL


class TestTLSScanValidCert:
    """Test scan() with a mocked valid certificate."""

    @pytest.mark.asyncio
    async def test_valid_cert_no_critical_findings(self):
        mod = TLSCheckModule()

        future_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
        cert_info = {
            "subject": ((("commonName", "valid.example.com"),),),
            "issuer": ((("commonName", "Trusted CA"),),),
            "notAfter": future_date,
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "subjectAltName": (("DNS", "valid.example.com"),),
        }

        with patch("bigr.shield.modules.tls_check.socket.create_connection") as mock_conn, \
             patch("bigr.shield.modules.tls_check.ssl.create_default_context") as mock_ctx_factory, \
             patch("bigr.shield.modules.tls_check._check_hsts", return_value=None), \
             patch("bigr.shield.modules.tls_check._extract_key_bits", return_value=4096):

            mock_ctx = MagicMock()
            mock_ctx_factory.return_value = mock_ctx

            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            mock_ssock = MagicMock()
            mock_ssock.getpeercert.side_effect = lambda binary_form=False: (
                b"fake-der" if binary_form else cert_info
            )
            mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            findings = await mod.scan("valid.example.com", port=443)

        # No critical or high findings expected for valid cert
        critical_high = [
            f for f in findings
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
        # Chain verification failure may still trigger (due to mock), so filter it
        non_chain = [f for f in critical_high if "Chain" not in f.title]
        assert len(non_chain) == 0


class TestTLSScanSelfSignedCert:
    """Test scan() with a mocked self-signed certificate."""

    @pytest.mark.asyncio
    async def test_self_signed_detected(self):
        mod = TLSCheckModule()

        future_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
        # Self-signed: issuer == subject
        cert_info = {
            "subject": ((("commonName", "selftest.local"),),),
            "issuer": ((("commonName", "selftest.local"),),),
            "notAfter": future_date,
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "subjectAltName": (("DNS", "selftest.local"),),
        }

        with patch("bigr.shield.modules.tls_check.socket.create_connection") as mock_conn, \
             patch("bigr.shield.modules.tls_check.ssl.create_default_context") as mock_ctx_factory, \
             patch("bigr.shield.modules.tls_check._check_hsts", return_value=None), \
             patch("bigr.shield.modules.tls_check._extract_key_bits", return_value=2048):

            mock_ctx = MagicMock()
            mock_ctx_factory.return_value = mock_ctx

            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            mock_ssock = MagicMock()
            mock_ssock.getpeercert.side_effect = lambda binary_form=False: (
                b"fake-der" if binary_form else cert_info
            )
            mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            # On the verification pass, simulate SSL error for self-signed
            def ctx_side_effect():
                ctx = MagicMock()
                # First call returns CERT_NONE context (already mocked above)
                # But create_default_context is called twice: once for info, once for verification
                # The second call wraps socket and raises SSLCertVerificationError
                ctx.wrap_socket.return_value.__enter__ = MagicMock(
                    side_effect=ssl.SSLCertVerificationError("self-signed certificate")
                )
                ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
                return ctx

            # We need to handle two calls to create_default_context
            call_count = [0]
            original_returns = [mock_ctx, ctx_side_effect()]

            def multi_ctx():
                idx = call_count[0]
                call_count[0] += 1
                if idx < len(original_returns):
                    return original_returns[idx]
                return MagicMock()

            mock_ctx_factory.side_effect = multi_ctx

            findings = await mod.scan("selftest.local", port=443)

        # Should detect self-signed
        self_signed = [f for f in findings if "Self-Signed" in f.title]
        assert len(self_signed) >= 1
        assert self_signed[0].severity == FindingSeverity.HIGH


class TestTLSScanWeakCipher:
    """Test scan() with a weak cipher suite."""

    @pytest.mark.asyncio
    async def test_weak_cipher_finding(self):
        mod = TLSCheckModule()

        future_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
        cert_info = {
            "subject": ((("commonName", "weak.example.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notAfter": future_date,
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "subjectAltName": (("DNS", "weak.example.com"),),
        }

        with patch("bigr.shield.modules.tls_check.socket.create_connection") as mock_conn, \
             patch("bigr.shield.modules.tls_check.ssl.create_default_context") as mock_ctx_factory, \
             patch("bigr.shield.modules.tls_check._check_hsts", return_value=None), \
             patch("bigr.shield.modules.tls_check._extract_key_bits", return_value=2048):

            mock_ctx = MagicMock()
            mock_ctx_factory.return_value = mock_ctx

            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            mock_ssock = MagicMock()
            mock_ssock.getpeercert.side_effect = lambda binary_form=False: (
                b"fake-der" if binary_form else cert_info
            )
            # Weak cipher: RC4
            mock_ssock.cipher.return_value = ("RC4-SHA", "TLSv1.2", 128)
            mock_ssock.version.return_value = "TLSv1.2"
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            findings = await mod.scan("weak.example.com", port=443)

        weak_cipher = [f for f in findings if "Weak Cipher" in f.title]
        assert len(weak_cipher) >= 1
        assert weak_cipher[0].severity == FindingSeverity.HIGH
        assert "RC4" in weak_cipher[0].evidence.get("cipher_name", "")


class TestTLSScanTimeout:
    """Test scan() timeout handling."""

    @pytest.mark.asyncio
    async def test_timeout_produces_finding(self):
        mod = TLSCheckModule()

        with patch(
            "bigr.shield.modules.tls_check.socket.create_connection",
            side_effect=socket.timeout("Connection timed out"),
        ):
            findings = await mod.scan("timeout.example.com", port=443)

        assert len(findings) == 1
        assert "Timeout" in findings[0].title
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert findings[0].evidence.get("error") == "timeout"


class TestTLSScanConnectionRefused:
    """Test scan() when connection is refused."""

    @pytest.mark.asyncio
    async def test_connection_refused_produces_finding(self):
        mod = TLSCheckModule()

        with patch(
            "bigr.shield.modules.tls_check.socket.create_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            findings = await mod.scan("refused.example.com", port=443)

        assert len(findings) == 1
        assert "Refused" in findings[0].title
        assert findings[0].severity == FindingSeverity.MEDIUM


class TestTLSScanDNSFailure:
    """Test scan() when DNS resolution fails."""

    @pytest.mark.asyncio
    async def test_dns_failure_produces_finding(self):
        mod = TLSCheckModule()

        with patch(
            "bigr.shield.modules.tls_check.socket.create_connection",
            side_effect=socket.gaierror("Name resolution failed"),
        ):
            findings = await mod.scan("nonexistent.invalid", port=443)

        assert len(findings) == 1
        assert "DNS" in findings[0].title
        assert findings[0].severity == FindingSeverity.HIGH
