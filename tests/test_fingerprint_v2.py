"""Tests for advanced device fingerprinting v2 - multi-signal approach.

TDD Protocol: RED -> GREEN -> REFACTOR
"""

from __future__ import annotations

import pytest

from bigr.classifier.fingerprint_v2 import (
    DeviceFingerprint,
    DhcpFingerprint,
    HttpFingerprint,
    TcpFingerprint,
    TlsFingerprint,
)
from bigr.classifier.tcp_fingerprint import (
    analyze_tcp_options,
    build_tcp_fingerprint,
    guess_os_by_ttl,
    guess_os_by_window_size,
)
from bigr.classifier.http_fingerprint import (
    extract_os_version,
    parse_user_agent,
)
from bigr.classifier.tls_fingerprint import (
    analyze_certificate,
    extract_device_from_cert,
)
from bigr.classifier.dhcp_fingerprint import (
    guess_os_by_dhcp_options,
    parse_vendor_class,
)
from bigr.classifier.bigr_mapper import ClassificationScores


# =========================================================================
# TCP Fingerprint Tests
# =========================================================================

class TestTcpFingerprint:
    """Tests for TCP/IP stack fingerprinting."""

    def test_guess_os_by_ttl_linux(self):
        """TTL 64 -> Linux."""
        assert guess_os_by_ttl(64) == "Linux"

    def test_guess_os_by_ttl_windows(self):
        """TTL 128 -> Windows."""
        assert guess_os_by_ttl(128) == "Windows"

    def test_guess_os_by_ttl_cisco(self):
        """TTL 255 -> Network Equipment."""
        result = guess_os_by_ttl(255)
        assert result is not None
        assert "Network Equipment" in result

    def test_guess_os_by_ttl_hop_decay(self):
        """TTL 60 (64 - 4 hops) -> still Linux."""
        assert guess_os_by_ttl(60) == "Linux"

    def test_guess_os_by_ttl_unknown(self):
        """TTL 42 -> None (unknown)."""
        assert guess_os_by_ttl(42) is None

    def test_guess_os_by_window_size_linux(self):
        """Window size 29200 -> Linux."""
        result = guess_os_by_window_size(29200)
        assert result is not None
        assert "Linux" in result

    def test_guess_os_by_window_size_windows(self):
        """Window size 65535 -> Windows."""
        result = guess_os_by_window_size(65535)
        assert result is not None
        assert "Windows" in result

    def test_analyze_tcp_options_linux(self):
        """Linux TCP option order detected."""
        linux_opts = ["MSS", "SACK_PERM", "Timestamps", "NOP", "Window_Scale"]
        result = analyze_tcp_options(linux_opts)
        assert result is not None
        assert "Linux" in result

    def test_analyze_tcp_options_windows(self):
        """Windows TCP option order detected."""
        windows_opts = ["MSS", "NOP", "Window_Scale", "NOP", "NOP", "SACK_PERM"]
        result = analyze_tcp_options(windows_opts)
        assert result is not None
        assert "Windows" in result

    def test_build_tcp_fingerprint(self):
        """All fields combined into TcpFingerprint."""
        fp = build_tcp_fingerprint(
            ttl=64,
            window_size=29200,
            df_bit=True,
            tcp_options=["MSS", "SACK_PERM", "Timestamps", "NOP", "Window_Scale"],
        )
        assert isinstance(fp, TcpFingerprint)
        assert fp.ttl == 64
        assert fp.window_size == 29200
        assert fp.df_bit is True
        assert fp.tcp_options == ["MSS", "SACK_PERM", "Timestamps", "NOP", "Window_Scale"]
        assert fp.os_guess is not None
        assert "Linux" in fp.os_guess


# =========================================================================
# HTTP Fingerprint Tests
# =========================================================================

class TestHttpFingerprint:
    """Tests for HTTP User-Agent parsing."""

    def test_parse_iphone_ua(self):
        """iPhone UA -> mobile, iOS, Apple."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
        fp = parse_user_agent(ua)
        assert isinstance(fp, HttpFingerprint)
        assert fp.device_type == "mobile"
        assert fp.os_name == "iOS"

    def test_parse_android_ua(self):
        """Android UA -> mobile, Android."""
        ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile"
        fp = parse_user_agent(ua)
        assert fp.device_type == "mobile"
        assert fp.os_name == "Android"

    def test_parse_ipad_ua(self):
        """iPad UA -> tablet, iPadOS."""
        ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
        fp = parse_user_agent(ua)
        assert fp.device_type == "tablet"
        assert fp.os_name == "iPadOS"

    def test_parse_macos_ua(self):
        """Macintosh UA -> desktop, macOS."""
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_1) AppleWebKit/605.1.15"
        fp = parse_user_agent(ua)
        assert fp.device_type == "desktop"
        assert fp.os_name == "macOS"

    def test_parse_windows_ua(self):
        """Windows NT UA -> desktop, Windows."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        fp = parse_user_agent(ua)
        assert fp.device_type == "desktop"
        assert fp.os_name == "Windows"

    def test_parse_linux_ua(self):
        """X11 Linux UA -> desktop, Linux."""
        ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        fp = parse_user_agent(ua)
        assert fp.device_type == "desktop"
        assert fp.os_name == "Linux"

    def test_parse_smart_tv_ua(self):
        """SmartTV -> smart_tv."""
        ua = "Mozilla/5.0 (SmartTV; SMART-TV; Linux)"
        fp = parse_user_agent(ua)
        assert fp.device_type == "smart_tv"

    def test_parse_bot_ua(self):
        """curl -> server."""
        ua = "curl/8.4.0"
        fp = parse_user_agent(ua)
        assert fp.device_type == "server"

    def test_parse_none(self):
        """None -> empty fingerprint."""
        fp = parse_user_agent(None)
        assert isinstance(fp, HttpFingerprint)
        assert fp.device_type is None
        assert fp.os_name is None

    def test_extract_ios_version(self):
        """iPhone OS 17_0 -> 17.0."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
        assert extract_os_version(ua, "iOS") == "17.0"

    def test_extract_windows_version(self):
        """Windows NT 10.0 -> 10."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        assert extract_os_version(ua, "Windows") == "10"

    def test_extract_android_version(self):
        """Android 14 -> 14."""
        ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8)"
        assert extract_os_version(ua, "Android") == "14"

    def test_extract_macos_version(self):
        """Mac OS X 14_1_1 -> 14.1.1."""
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_1)"
        assert extract_os_version(ua, "macOS") == "14.1.1"


# =========================================================================
# TLS Fingerprint Tests
# =========================================================================

class TestTlsFingerprint:
    """Tests for TLS certificate analysis."""

    def test_hp_printer_cert(self):
        """CN='HP LaserJet Pro' -> printer."""
        result = extract_device_from_cert("HP LaserJet Pro MFP M428")
        assert result == "printer"

    def test_hikvision_camera_cert(self):
        """CN='DS-2CD2032' -> ip_camera."""
        result = extract_device_from_cert("DS-2CD2032-I")
        assert result == "ip_camera"

    def test_synology_nas_cert(self):
        """CN='DiskStation' -> nas."""
        result = extract_device_from_cert("DiskStation")
        assert result == "nas"

    def test_ubiquiti_cert(self):
        """CN='UniFi AP' -> network_equipment."""
        result = extract_device_from_cert("UniFi AP AC Pro")
        assert result == "network_equipment"

    def test_self_signed_flag(self):
        """Self-signed certificate is detected."""
        fp = analyze_certificate(cn="test-device", is_self_signed=True)
        assert isinstance(fp, TlsFingerprint)
        assert fp.is_self_signed is True

    def test_normal_cert_no_device(self):
        """'example.com' -> no device hint."""
        result = extract_device_from_cert("example.com")
        assert result is None

    def test_none_cn(self):
        """None CN -> empty fingerprint."""
        fp = analyze_certificate(cn=None)
        assert isinstance(fp, TlsFingerprint)
        assert fp.device_hint is None


# =========================================================================
# DHCP Fingerprint Tests
# =========================================================================

class TestDhcpFingerprint:
    """Tests for DHCP option fingerprinting."""

    def test_windows_option55(self):
        """Windows option list -> Windows."""
        opts = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
        result = guess_os_by_dhcp_options(opts)
        assert result is not None
        assert "Windows" in result

    def test_android_option55(self):
        """Android option list -> Android."""
        opts = [1, 3, 6, 15, 26, 28, 51, 58, 59]
        result = guess_os_by_dhcp_options(opts)
        assert result is not None
        assert "Android" in result

    def test_linux_option55(self):
        """Linux option list -> Linux."""
        opts = [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121]
        result = guess_os_by_dhcp_options(opts)
        assert result is not None
        assert "Linux" in result

    def test_partial_match(self):
        """Subset of known options still matches."""
        # Partial Windows options (subset)
        opts = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47]
        result = guess_os_by_dhcp_options(opts)
        # Should still match Windows as best candidate
        assert result is not None
        assert "Windows" in result

    def test_unknown_options(self):
        """Unknown option list -> None."""
        opts = [200, 201, 202]
        result = guess_os_by_dhcp_options(opts)
        assert result is None

    def test_parse_vendor_class_msft(self):
        """'MSFT 5.0' -> Windows."""
        result = parse_vendor_class("MSFT 5.0")
        assert result is not None
        assert "Windows" in result

    def test_parse_vendor_class_android(self):
        """'android-dhcp-14' -> Android 14."""
        result = parse_vendor_class("android-dhcp-14")
        assert result is not None
        assert "Android" in result

    def test_parse_vendor_class_linux(self):
        """'dhcpcd-9.4.1:Linux-6.1' -> Linux."""
        result = parse_vendor_class("dhcpcd-9.4.1:Linux-6.1")
        assert result is not None
        assert "Linux" in result

    def test_parse_vendor_class_none(self):
        """None -> None."""
        assert parse_vendor_class(None) is None


# =========================================================================
# Combine Fingerprints Tests
# =========================================================================

class TestCombineFingerprints:
    """Tests for combining multiple fingerprint sources."""

    def test_combine_all_sources(self):
        """All 4 sources -> unified result with combined_os and device_type."""
        from bigr.classifier.fingerprint_v2 import DeviceFingerprint
        from bigr.classifier.combine_fingerprints import combine_fingerprints

        tcp = TcpFingerprint(ttl=64, os_guess="Linux")
        http = HttpFingerprint(device_type="mobile", os_name="Android")
        tls = TlsFingerprint(cn="test", device_hint=None)
        dhcp = DhcpFingerprint(os_guess="Android")

        result = combine_fingerprints(tcp=tcp, http=http, tls=tls, dhcp=dhcp)
        assert isinstance(result, DeviceFingerprint)
        assert result.tcp is tcp
        assert result.http is http
        assert result.tls is tls
        assert result.dhcp is dhcp
        assert result.combined_os is not None
        assert result.combined_device_type is not None

    def test_combine_partial(self):
        """Only TCP + HTTP -> still works."""
        from bigr.classifier.combine_fingerprints import combine_fingerprints

        tcp = TcpFingerprint(ttl=128, os_guess="Windows")
        http = HttpFingerprint(device_type="desktop", os_name="Windows")

        result = combine_fingerprints(tcp=tcp, http=http)
        assert result.tcp is tcp
        assert result.http is http
        assert result.tls is None
        assert result.dhcp is None
        assert result.combined_os is not None

    def test_combine_empty(self):
        """No sources -> empty fingerprint."""
        from bigr.classifier.combine_fingerprints import combine_fingerprints

        result = combine_fingerprints()
        assert isinstance(result, DeviceFingerprint)
        assert result.combined_os is None
        assert result.combined_device_type is None
        assert result.confidence == 0.0

    def test_confidence_calculation(self):
        """More sources -> higher confidence."""
        from bigr.classifier.combine_fingerprints import combine_fingerprints

        # Single source
        result_one = combine_fingerprints(
            tcp=TcpFingerprint(ttl=64, os_guess="Linux"),
        )

        # Multiple agreeing sources
        result_many = combine_fingerprints(
            tcp=TcpFingerprint(ttl=64, os_guess="Linux"),
            http=HttpFingerprint(device_type="desktop", os_name="Linux"),
            dhcp=DhcpFingerprint(os_guess="Linux (dhclient)"),
        )

        assert result_many.confidence > result_one.confidence


# =========================================================================
# Score By Fingerprint V2 Tests
# =========================================================================

class TestScoreByFingerprintV2:
    """Tests for fingerprint-based classification scoring."""

    def test_mobile_device_scoring(self):
        """HTTP says mobile -> tasinabilir boost."""
        from bigr.classifier.combine_fingerprints import score_by_fingerprint_v2

        scores = ClassificationScores()
        fp = DeviceFingerprint(
            http=HttpFingerprint(device_type="mobile", os_name="iOS"),
            combined_device_type="mobile",
        )
        score_by_fingerprint_v2(fp, scores)
        assert scores.tasinabilir > 0

    def test_printer_tls_scoring(self):
        """TLS says printer -> iot boost."""
        from bigr.classifier.combine_fingerprints import score_by_fingerprint_v2

        scores = ClassificationScores()
        fp = DeviceFingerprint(
            tls=TlsFingerprint(cn="HP LaserJet", device_hint="printer"),
            combined_device_type="printer",
        )
        score_by_fingerprint_v2(fp, scores)
        assert scores.iot > 0

    def test_network_equipment_tcp(self):
        """TCP TTL=255 -> ag_ve_sistemler boost."""
        from bigr.classifier.combine_fingerprints import score_by_fingerprint_v2

        scores = ClassificationScores()
        fp = DeviceFingerprint(
            tcp=TcpFingerprint(ttl=255, os_guess="Network Equipment (Cisco/Solaris)"),
            combined_device_type="network_equipment",
        )
        score_by_fingerprint_v2(fp, scores)
        assert scores.ag_ve_sistemler > 0

    def test_server_ua_scoring(self):
        """UA is curl -> uygulamalar boost."""
        from bigr.classifier.combine_fingerprints import score_by_fingerprint_v2

        scores = ClassificationScores()
        fp = DeviceFingerprint(
            http=HttpFingerprint(device_type="server"),
            combined_device_type="server",
        )
        score_by_fingerprint_v2(fp, scores)
        assert scores.uygulamalar > 0

    def test_no_fingerprint(self):
        """Empty fingerprint -> no score change."""
        from bigr.classifier.combine_fingerprints import score_by_fingerprint_v2

        scores = ClassificationScores()
        fp = DeviceFingerprint()
        score_by_fingerprint_v2(fp, scores)
        assert scores.ag_ve_sistemler == 0.0
        assert scores.uygulamalar == 0.0
        assert scores.iot == 0.0
        assert scores.tasinabilir == 0.0
