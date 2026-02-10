"""Tests for bigr.agent.network_fingerprint — network roaming detection."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bigr.agent.network_fingerprint import (
    NetworkFingerprint,
    compute_fingerprint_hash,
    detect_default_gateway_ip,
    detect_gateway_mac,
    detect_network_fingerprint,
    detect_ssid,
)


# ---------------------------------------------------------------------------
# detect_default_gateway_ip
# ---------------------------------------------------------------------------

class TestDetectDefaultGatewayIpMacOS:
    """Tests for macOS gateway detection via netstat."""

    NETSTAT_OUTPUT = """\
Routing tables

Internet:
Destination        Gateway            Flags    Netif Expire
default            192.168.1.1        UGScg    en0
127.0.0.1          127.0.0.1          UH       lo0
192.168.1.0/24     link#6             UCS      en0
"""

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Darwin")
    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_parses_gateway_from_netstat(self, mock_cmd):
        mock_cmd.return_value = self.NETSTAT_OUTPUT
        assert detect_default_gateway_ip() == "192.168.1.1"
        mock_cmd.assert_called_once_with(["netstat", "-rn"])

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Darwin")
    @patch("bigr.agent.network_fingerprint._run_cmd", return_value=None)
    def test_returns_none_on_failure(self, mock_cmd):
        assert detect_default_gateway_ip() is None

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Darwin")
    @patch("bigr.agent.network_fingerprint._run_cmd", return_value="no default route")
    def test_returns_none_when_no_default(self, mock_cmd):
        assert detect_default_gateway_ip() is None


class TestDetectDefaultGatewayIpLinux:
    """Tests for Linux gateway detection via ip route."""

    IP_ROUTE_OUTPUT = """\
default via 10.0.0.1 dev eth0 proto dhcp metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.50
"""

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Linux")
    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_parses_gateway_from_ip_route(self, mock_cmd):
        mock_cmd.return_value = self.IP_ROUTE_OUTPUT
        assert detect_default_gateway_ip() == "10.0.0.1"
        mock_cmd.assert_called_once_with(["ip", "route"])

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Linux")
    @patch("bigr.agent.network_fingerprint._run_cmd", return_value=None)
    def test_returns_none_on_failure(self, mock_cmd):
        assert detect_default_gateway_ip() is None


# ---------------------------------------------------------------------------
# detect_gateway_mac
# ---------------------------------------------------------------------------

class TestDetectGatewayMac:
    """Tests for ARP-based MAC resolution."""

    MACOS_ARP = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    LINUX_ARP = "192.168.1.1  ether  AA:BB:CC:DD:EE:FF  C  eth0"
    ARP_INCOMPLETE = "192.168.1.1  (incomplete)"

    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_parses_mac_from_macos_arp(self, mock_cmd):
        mock_cmd.return_value = self.MACOS_ARP
        assert detect_gateway_mac("192.168.1.1") == "aa:bb:cc:dd:ee:ff"

    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_parses_mac_from_linux_arp(self, mock_cmd):
        mock_cmd.return_value = self.LINUX_ARP
        assert detect_gateway_mac("192.168.1.1") == "aa:bb:cc:dd:ee:ff"

    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_normalizes_short_octets(self, mock_cmd):
        mock_cmd.return_value = "? (10.0.0.1) at a:b:c:d:e:f on en0"
        assert detect_gateway_mac("10.0.0.1") == "0a:0b:0c:0d:0e:0f"

    @patch("bigr.agent.network_fingerprint._run_cmd", return_value=None)
    def test_returns_none_on_failure(self, mock_cmd):
        assert detect_gateway_mac("192.168.1.1") is None

    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_returns_none_for_incomplete(self, mock_cmd):
        mock_cmd.return_value = self.ARP_INCOMPLETE
        assert detect_gateway_mac("192.168.1.1") is None


# ---------------------------------------------------------------------------
# detect_ssid
# ---------------------------------------------------------------------------

class TestDetectSsidMacOS:
    """Tests for macOS SSID detection."""

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Darwin")
    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_parses_ssid(self, mock_cmd):
        mock_cmd.return_value = "Current Wi-Fi Network: MyHomeWiFi"
        assert detect_ssid() == "MyHomeWiFi"

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Darwin")
    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_returns_none_when_not_connected(self, mock_cmd):
        mock_cmd.return_value = "You are not associated with an AirPort network."
        assert detect_ssid() is None

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Darwin")
    @patch("bigr.agent.network_fingerprint._run_cmd", return_value=None)
    def test_returns_none_on_cmd_failure(self, mock_cmd):
        assert detect_ssid() is None


class TestDetectSsidLinux:
    """Tests for Linux SSID detection."""

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Linux")
    @patch("bigr.agent.network_fingerprint._run_cmd")
    def test_parses_ssid(self, mock_cmd):
        mock_cmd.return_value = "OfficeNetwork"
        assert detect_ssid() == "OfficeNetwork"

    @patch("bigr.agent.network_fingerprint._SYSTEM", "Linux")
    @patch("bigr.agent.network_fingerprint._run_cmd", return_value="")
    def test_returns_none_when_empty(self, mock_cmd):
        assert detect_ssid() is None


# ---------------------------------------------------------------------------
# compute_fingerprint_hash
# ---------------------------------------------------------------------------

class TestComputeFingerprintHash:
    """Tests for deterministic hash generation."""

    def test_same_inputs_same_hash(self):
        h1 = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "MyWiFi")
        h2 = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "MyWiFi")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_different_mac_different_hash(self):
        h1 = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "MyWiFi")
        h2 = compute_fingerprint_hash("11:22:33:44:55:66", "MyWiFi")
        assert h1 != h2

    def test_different_ssid_different_hash(self):
        h1 = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "Home")
        h2 = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "Office")
        assert h1 != h2

    def test_none_ssid_wired(self):
        """Wired connections have no SSID but still produce a valid hash."""
        h = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", None)
        assert len(h) == 64

    def test_wired_vs_wifi_different(self):
        """Same gateway with/without SSID should produce different hashes."""
        h_wired = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", None)
        h_wifi = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "MyWiFi")
        assert h_wired != h_wifi

    def test_case_insensitive_mac(self):
        """MAC is lowercased before hashing."""
        h1 = compute_fingerprint_hash("AA:BB:CC:DD:EE:FF", "X")
        h2 = compute_fingerprint_hash("aa:bb:cc:dd:ee:ff", "X")
        assert h1 == h2


# ---------------------------------------------------------------------------
# detect_network_fingerprint (integration of the above)
# ---------------------------------------------------------------------------

class TestDetectNetworkFingerprint:
    """Tests for the top-level orchestrator."""

    @patch("bigr.agent.network_fingerprint.detect_ssid", return_value="TestWiFi")
    @patch("bigr.agent.network_fingerprint.detect_gateway_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("bigr.agent.network_fingerprint.detect_default_gateway_ip", return_value="192.168.1.1")
    def test_full_detection(self, mock_gw_ip, mock_gw_mac, mock_ssid):
        fp = detect_network_fingerprint()
        assert fp is not None
        assert fp.gateway_ip == "192.168.1.1"
        assert fp.gateway_mac == "aa:bb:cc:dd:ee:ff"
        assert fp.ssid == "TestWiFi"
        assert len(fp.fingerprint_hash) == 64

    @patch("bigr.agent.network_fingerprint.detect_default_gateway_ip", return_value=None)
    def test_returns_none_when_no_gateway(self, mock_gw_ip):
        assert detect_network_fingerprint() is None

    @patch("bigr.agent.network_fingerprint.detect_gateway_mac", return_value=None)
    @patch("bigr.agent.network_fingerprint.detect_default_gateway_ip", return_value="192.168.1.1")
    def test_returns_none_when_no_mac(self, mock_gw_ip, mock_gw_mac):
        assert detect_network_fingerprint() is None

    @patch("bigr.agent.network_fingerprint.detect_ssid", return_value=None)
    @patch("bigr.agent.network_fingerprint.detect_gateway_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("bigr.agent.network_fingerprint.detect_default_gateway_ip", return_value="10.0.0.1")
    def test_wired_connection(self, mock_gw_ip, mock_gw_mac, mock_ssid):
        """Wired connections should still produce a valid fingerprint."""
        fp = detect_network_fingerprint()
        assert fp is not None
        assert fp.ssid is None
        assert fp.gateway_mac == "aa:bb:cc:dd:ee:ff"
        assert len(fp.fingerprint_hash) == 64

    def test_to_dict(self):
        fp = NetworkFingerprint(
            fingerprint_hash="abc123",
            gateway_ip="192.168.1.1",
            gateway_mac="aa:bb:cc:dd:ee:ff",
            ssid="TestNet",
        )
        d = fp.to_dict()
        assert d == {
            "fingerprint_hash": "abc123",
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "aa:bb:cc:dd:ee:ff",
            "ssid": "TestNet",
        }

    @patch("bigr.agent.network_fingerprint.detect_ssid", return_value="WiFi_A")
    @patch("bigr.agent.network_fingerprint.detect_gateway_mac", return_value="11:22:33:44:55:66")
    @patch("bigr.agent.network_fingerprint.detect_default_gateway_ip", return_value="192.168.1.1")
    def test_same_cidr_different_gateway_different_hash(self, mock_gw_ip, mock_gw_mac, mock_ssid):
        """Core use case: same CIDR on different networks yields different fingerprints."""
        fp_a = detect_network_fingerprint()

        mock_gw_mac.return_value = "aa:bb:cc:dd:ee:ff"
        mock_ssid.return_value = "WiFi_B"
        fp_b = detect_network_fingerprint()

        assert fp_a is not None and fp_b is not None
        assert fp_a.fingerprint_hash != fp_b.fingerprint_hash
