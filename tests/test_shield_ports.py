"""Tests for bigr.shield.modules.port_scan -- Nmap port scanning module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.port_scan import (
    COMMON_PORTS,
    DANGEROUS_PORTS,
    OPEN_PORT_THRESHOLD,
    PortScanModule,
    _parse_nmap_xml,
)

# ---------- Sample nmap XML outputs ----------

NMAP_XML_DANGEROUS_PORTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT --top-ports 1000 -sV --open -oX - target.example.com">
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack"/>
        <service name="redis" product="Redis" version="7.0.5"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_SAFE_PORTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_MANY_PORTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      {ports}
    </ports>
  </host>
</nmaprun>
"""


def _generate_many_ports_xml(count: int) -> str:
    """Generate nmap XML with many open ports for excessive-port-count testing."""
    port_entries = []
    for i in range(count):
        port_num = 8000 + i
        port_entries.append(
            f'<port protocol="tcp" portid="{port_num}">'
            f'<state state="open" reason="syn-ack"/>'
            f'<service name="unknown"/>'
            f'</port>'
        )
    return NMAP_XML_MANY_PORTS.format(ports="\n".join(port_entries))


NMAP_XML_NO_OPEN = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


# ---------- Tests for check_available ----------

class TestPortScanCheckAvailable:
    """Tests for PortScanModule.check_available()."""

    def test_available_when_nmap_exists(self):
        mod = PortScanModule()
        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"):
            assert mod.check_available() is True

    def test_unavailable_when_nmap_missing(self):
        mod = PortScanModule()
        with patch("bigr.shield.modules.port_scan.shutil.which", return_value=None):
            assert mod.check_available() is False

    def test_module_metadata(self):
        mod = PortScanModule()
        assert mod.name == "ports"
        assert mod.weight == 20


# ---------- Tests for _parse_nmap_xml ----------

class TestParseNmapXml:
    """Tests for nmap XML parsing helper."""

    def test_parse_with_dangerous_ports(self):
        ports = _parse_nmap_xml(NMAP_XML_DANGEROUS_PORTS)
        assert len(ports) == 3
        port_numbers = {p["port"] for p in ports}
        assert 22 in port_numbers
        assert 80 in port_numbers
        assert 6379 in port_numbers

    def test_parse_service_info(self):
        ports = _parse_nmap_xml(NMAP_XML_DANGEROUS_PORTS)
        redis_port = [p for p in ports if p["port"] == 6379][0]
        assert redis_port["service"] == "redis"
        assert "Redis" in redis_port["version"]
        assert "7.0.5" in redis_port["version"]

    def test_parse_no_open_ports(self):
        ports = _parse_nmap_xml(NMAP_XML_NO_OPEN)
        assert len(ports) == 0

    def test_parse_invalid_xml(self):
        ports = _parse_nmap_xml("this is not xml at all")
        assert ports == []

    def test_parse_empty_string(self):
        ports = _parse_nmap_xml("")
        assert ports == []

    def test_parse_safe_ports(self):
        ports = _parse_nmap_xml(NMAP_XML_SAFE_PORTS)
        assert len(ports) == 2
        port_numbers = {p["port"] for p in ports}
        assert 80 in port_numbers
        assert 443 in port_numbers


# ---------- Tests for scan() ----------

def _make_subprocess_mock(stdout: bytes, returncode: int = 0, stderr: bytes = b""):
    """Create a mock for asyncio.create_subprocess_exec."""
    mock_proc = MagicMock()
    mock_proc.returncode = returncode

    async def communicate():
        return stdout, stderr

    mock_proc.communicate = communicate
    return mock_proc


class TestPortScanWithDangerousPorts:
    """Test scan() when dangerous ports are detected."""

    @pytest.mark.asyncio
    async def test_dangerous_port_produces_high_finding(self):
        mod = PortScanModule()

        mock_proc = _make_subprocess_mock(NMAP_XML_DANGEROUS_PORTS.encode())

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(NMAP_XML_DANGEROUS_PORTS.encode(), b"")):
            # Directly mock the method to avoid wait_for complications
            pass

        # Simpler approach: patch at the module level
        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for") as mock_wait:

            mock_wait.return_value = (NMAP_XML_DANGEROUS_PORTS.encode(), b"")
            mock_proc_obj = MagicMock()
            mock_proc_obj.returncode = 0
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("target.example.com")

        # Should have HIGH finding for Redis (6379)
        dangerous_findings = [
            f for f in findings
            if f.severity == FindingSeverity.HIGH
        ]
        assert len(dangerous_findings) >= 1

        redis_finding = [f for f in dangerous_findings if "6379" in f.title]
        assert len(redis_finding) == 1
        assert "Redis" in redis_finding[0].title
        assert redis_finding[0].attack_technique == "T1190"

    @pytest.mark.asyncio
    async def test_common_ports_produce_info_findings(self):
        mod = PortScanModule()

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for") as mock_wait:

            mock_wait.return_value = (NMAP_XML_DANGEROUS_PORTS.encode(), b"")
            mock_proc_obj = MagicMock()
            mock_proc_obj.returncode = 0
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("target.example.com")

        # Port 22 and 80 are common ports -- should produce INFO findings
        info_findings = [
            f for f in findings
            if f.severity == FindingSeverity.INFO
        ]
        port_22_info = [f for f in info_findings if "22/" in f.title]
        port_80_info = [f for f in info_findings if "80/" in f.title]
        assert len(port_22_info) == 1
        assert len(port_80_info) == 1


class TestPortScanNoDangerousPorts:
    """Test scan() when only safe ports are open."""

    @pytest.mark.asyncio
    async def test_no_dangerous_ports(self):
        mod = PortScanModule()

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for") as mock_wait:

            mock_wait.return_value = (NMAP_XML_SAFE_PORTS.encode(), b"")
            mock_proc_obj = MagicMock()
            mock_proc_obj.returncode = 0
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("safe.example.com")

        # No HIGH or CRITICAL findings expected
        high_critical = [
            f for f in findings
            if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
        ]
        assert len(high_critical) == 0

        # Should have INFO findings for common ports
        info = [f for f in findings if f.severity == FindingSeverity.INFO]
        assert len(info) >= 2


class TestPortScanNmapNotInstalled:
    """Test scan() when nmap is not available."""

    @pytest.mark.asyncio
    async def test_nmap_not_installed(self):
        mod = PortScanModule()

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value=None):
            findings = await mod.scan("target.example.com")

        assert len(findings) == 1
        assert "Nmap Not Installed" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
        assert findings[0].evidence.get("error") == "nmap_not_found"


class TestPortScanTimeout:
    """Test scan() when nmap times out."""

    @pytest.mark.asyncio
    async def test_timeout_produces_medium_finding(self):
        mod = PortScanModule()

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for", side_effect=asyncio.TimeoutError):

            mock_proc_obj = MagicMock()
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("slow.example.com")

        assert len(findings) == 1
        assert "Timeout" in findings[0].title
        assert findings[0].severity == FindingSeverity.MEDIUM
        assert findings[0].evidence.get("error") == "timeout"


class TestPortScanExcessivePorts:
    """Test scan() when too many ports are open."""

    @pytest.mark.asyncio
    async def test_excessive_open_ports(self):
        mod = PortScanModule()
        many_ports_xml = _generate_many_ports_xml(15)

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for") as mock_wait:

            mock_wait.return_value = (many_ports_xml.encode(), b"")
            mock_proc_obj = MagicMock()
            mock_proc_obj.returncode = 0
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("busy.example.com")

        # Should have a medium finding for excessive open ports
        excessive = [f for f in findings if "Excessive" in f.title]
        assert len(excessive) == 1
        assert excessive[0].severity == FindingSeverity.MEDIUM
        assert excessive[0].evidence["open_port_count"] == 15

    @pytest.mark.asyncio
    async def test_no_excessive_warning_under_threshold(self):
        mod = PortScanModule()
        few_ports_xml = _generate_many_ports_xml(5)

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for") as mock_wait:

            mock_wait.return_value = (few_ports_xml.encode(), b"")
            mock_proc_obj = MagicMock()
            mock_proc_obj.returncode = 0
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("normal.example.com")

        # Should NOT have excessive open ports warning
        excessive = [f for f in findings if "Excessive" in f.title]
        assert len(excessive) == 0


class TestPortScanNmapFailure:
    """Test scan() when nmap returns non-zero exit code."""

    @pytest.mark.asyncio
    async def test_nmap_exit_error(self):
        mod = PortScanModule()

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch("bigr.shield.modules.port_scan.asyncio.create_subprocess_exec") as mock_exec, \
             patch("bigr.shield.modules.port_scan.asyncio.wait_for") as mock_wait:

            mock_wait.return_value = (b"", b"Failed to resolve target")
            mock_proc_obj = MagicMock()
            mock_proc_obj.returncode = 1
            mock_exec.return_value = mock_proc_obj

            findings = await mod.scan("bad.example.com")

        assert len(findings) == 1
        assert "Port Scan Failed" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
        assert findings[0].evidence["return_code"] == 1


class TestPortScanOSError:
    """Test scan() when subprocess raises OSError."""

    @pytest.mark.asyncio
    async def test_os_error(self):
        mod = PortScanModule()

        with patch("bigr.shield.modules.port_scan.shutil.which", return_value="/usr/bin/nmap"), \
             patch(
                 "bigr.shield.modules.port_scan.asyncio.create_subprocess_exec",
                 side_effect=OSError("Permission denied"),
             ):
            findings = await mod.scan("target.example.com")

        assert len(findings) == 1
        assert "Port Scan Error" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFO
