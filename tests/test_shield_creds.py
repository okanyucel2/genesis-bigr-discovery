"""Tests for bigr.shield.modules.credential_check -- Default credential checker module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bigr.shield.models import FindingSeverity
from bigr.shield.modules.credential_check import (
    ADMIN_PANEL_PATHS,
    CONNECT_TIMEOUT,
    DEFAULT_CREDENTIALS,
    MAX_ATTEMPTS_PER_SERVICE,
    PORT_SERVICE_MAP,
    CredentialCheckModule,
    _check_admin_panel,
    _check_port_open,
    _check_redis_no_auth,
    _check_mongodb_no_auth,
    _get_service_banner,
)


# ---------- Tests for module metadata ----------

class TestCredentialCheckMetadata:
    """Tests for CredentialCheckModule metadata."""

    def test_module_name(self):
        mod = CredentialCheckModule()
        assert mod.name == "creds"

    def test_module_weight(self):
        mod = CredentialCheckModule()
        assert mod.weight == 10

    def test_check_available(self):
        """Uses stdlib only, should always be available."""
        mod = CredentialCheckModule()
        assert mod.check_available() is True


# ---------- Tests for PORT_SERVICE_MAP ----------

class TestPortServiceMap:
    """Tests for port-to-service mapping."""

    def test_ssh_port(self):
        assert PORT_SERVICE_MAP[22] == "ssh"

    def test_ftp_port(self):
        assert PORT_SERVICE_MAP[21] == "ftp"

    def test_mysql_port(self):
        assert PORT_SERVICE_MAP[3306] == "mysql"

    def test_postgresql_port(self):
        assert PORT_SERVICE_MAP[5432] == "postgresql"

    def test_redis_port(self):
        assert PORT_SERVICE_MAP[6379] == "redis"

    def test_mongodb_port(self):
        assert PORT_SERVICE_MAP[27017] == "mongodb"

    def test_http_ports(self):
        assert PORT_SERVICE_MAP[80] == "web_admin"
        assert PORT_SERVICE_MAP[443] == "web_admin"
        assert PORT_SERVICE_MAP[8080] == "web_admin"
        assert PORT_SERVICE_MAP[8443] == "web_admin"

    def test_unknown_port(self):
        assert PORT_SERVICE_MAP.get(9999) is None


# ---------- Tests for DEFAULT_CREDENTIALS ----------

class TestDefaultCredentials:
    """Tests for the credentials database."""

    def test_has_all_services(self):
        expected_services = {"ssh", "ftp", "mysql", "postgresql", "redis", "mongodb", "web_admin"}
        assert set(DEFAULT_CREDENTIALS.keys()) == expected_services

    def test_credentials_format(self):
        """Each credential entry must have username and password keys."""
        for service, creds in DEFAULT_CREDENTIALS.items():
            assert len(creds) > 0, f"No credentials for {service}"
            for cred in creds:
                assert "username" in cred, f"Missing username in {service}"
                assert "password" in cred, f"Missing password in {service}"

    def test_max_three_per_service(self):
        """No service should have more than MAX_ATTEMPTS_PER_SERVICE credentials."""
        for service, creds in DEFAULT_CREDENTIALS.items():
            assert len(creds) <= MAX_ATTEMPTS_PER_SERVICE, (
                f"Service {service} has {len(creds)} credentials, max is {MAX_ATTEMPTS_PER_SERVICE}"
            )


# ---------- Tests for _check_port_open ----------

class TestCheckPortOpen:
    """Tests for the port reachability helper."""

    @pytest.mark.asyncio
    async def test_port_open(self):
        """Port is open when connection succeeds."""
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "bigr.shield.modules.credential_check.asyncio.wait_for",
            return_value=(AsyncMock(), mock_writer),
        ):
            result = await _check_port_open("example.com", 6379)

        assert result is True

    @pytest.mark.asyncio
    async def test_port_closed(self):
        """Port is closed when connection fails."""
        with patch(
            "bigr.shield.modules.credential_check.asyncio.wait_for",
            side_effect=OSError("Connection refused"),
        ):
            result = await _check_port_open("example.com", 6379)

        assert result is False

    @pytest.mark.asyncio
    async def test_port_timeout(self):
        """Port check times out gracefully."""
        with patch(
            "bigr.shield.modules.credential_check.asyncio.wait_for",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await _check_port_open("example.com", 6379)

        assert result is False


# ---------- Tests for Redis no-auth check ----------

class TestRedisNoAuth:
    """Tests for Redis no-auth detection."""

    @pytest.mark.asyncio
    async def test_redis_pong_no_auth(self):
        """Redis responds to PING with +PONG: no auth required."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"+PONG\r\n")
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        async def fake_wait_for(coro, timeout):
            result = await coro
            if result is None:
                return mock_reader, mock_writer
            return result

        with patch(
            "bigr.shield.modules.credential_check.asyncio.wait_for",
            side_effect=fake_wait_for,
        ), patch(
            "bigr.shield.modules.credential_check.asyncio.open_connection",
            return_value=(mock_reader, mock_writer),
        ):
            result = await _check_redis_no_auth("example.com", 6379)

        assert result is True

    @pytest.mark.asyncio
    async def test_redis_auth_required(self):
        """Redis requires auth: PING returns error."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"-NOAUTH Authentication required.\r\n")
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        async def fake_wait_for(coro, timeout):
            result = await coro
            if result is None:
                return mock_reader, mock_writer
            return result

        with patch(
            "bigr.shield.modules.credential_check.asyncio.wait_for",
            side_effect=fake_wait_for,
        ), patch(
            "bigr.shield.modules.credential_check.asyncio.open_connection",
            return_value=(mock_reader, mock_writer),
        ):
            result = await _check_redis_no_auth("example.com", 6379)

        assert result is False

    @pytest.mark.asyncio
    async def test_redis_connection_refused(self):
        """Connection refused: returns False."""
        with patch(
            "bigr.shield.modules.credential_check.asyncio.wait_for",
            side_effect=OSError("Connection refused"),
        ):
            result = await _check_redis_no_auth("example.com", 6379)

        assert result is False


# ---------- Tests for scan() - Redis scenario ----------

class TestScanRedisNoAuth:
    """Test scan() when Redis is accessible without auth."""

    @pytest.mark.asyncio
    async def test_scan_finds_redis_no_auth(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 6379

        async def mock_redis_no_auth(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_redis_no_auth",
            side_effect=mock_redis_no_auth,
        ):
            findings = await mod.scan("target.example.com")

        redis_findings = [f for f in findings if "Redis" in f.title and "Without Authentication" in f.title]
        assert len(redis_findings) == 1
        assert redis_findings[0].severity == FindingSeverity.CRITICAL
        assert redis_findings[0].module == "creds"
        assert redis_findings[0].target_port == 6379
        assert redis_findings[0].attack_technique == "T1078"


# ---------- Tests for scan() - MongoDB scenario ----------

class TestScanMongoDBNoAuth:
    """Test scan() when MongoDB is accessible without auth."""

    @pytest.mark.asyncio
    async def test_scan_finds_mongodb_no_auth(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 27017

        async def mock_mongodb_no_auth(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_mongodb_no_auth",
            side_effect=mock_mongodb_no_auth,
        ):
            findings = await mod.scan("target.example.com")

        mongodb_findings = [f for f in findings if "MongoDB" in f.title and "Without Authentication" in f.title]
        assert len(mongodb_findings) == 1
        assert mongodb_findings[0].severity == FindingSeverity.CRITICAL
        assert mongodb_findings[0].module == "creds"


# ---------- Tests for scan() - HTTP admin panels ----------

class TestScanHttpAdminPanels:
    """Test scan() for HTTP admin panel detection."""

    @pytest.mark.asyncio
    async def test_scan_finds_phpmyadmin_accessible(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 80

        def mock_admin_panel(host, port, path, label):
            if path == "/phpmyadmin":
                return MagicMock(
                    module="creds",
                    severity=FindingSeverity.HIGH,
                    title="Default phpMyAdmin Accessible at /phpmyadmin",
                    evidence={"path": "/phpmyadmin", "status_code": 200},
                )
            return None

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_admin_panel",
            side_effect=mock_admin_panel,
        ):
            findings = await mod.scan("target.example.com")

        admin_findings = [f for f in findings if hasattr(f, 'severity') and "phpMyAdmin" in str(getattr(f, 'title', ''))]
        assert len(admin_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_no_finding_for_401_admin(self):
        """Admin panel returning 401 should NOT produce a finding."""
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 80

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_admin_panel",
            return_value=None,
        ):
            findings = await mod.scan("target.example.com")

        admin_findings = [f for f in findings if "Admin" in str(getattr(f, 'title', ''))]
        assert len(admin_findings) == 0


# ---------- Tests for service detection via banner ----------

class TestScanServiceDetection:
    """Test scan() service detection via banner."""

    @pytest.mark.asyncio
    async def test_ssh_banner_detected(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 22

        async def mock_get_banner(host, port):
            return "SSH-2.0-OpenSSH_8.9p1"

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._get_service_banner",
            side_effect=mock_get_banner,
        ):
            findings = await mod.scan("target.example.com")

        ssh_findings = [f for f in findings if "SSH" in f.title and "Detected" in f.title]
        assert len(ssh_findings) == 1
        assert ssh_findings[0].severity == FindingSeverity.MEDIUM
        assert "OpenSSH" in ssh_findings[0].evidence["banner"]
        assert ssh_findings[0].attack_technique == "T1110.001"

    @pytest.mark.asyncio
    async def test_ftp_banner_detected(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 21

        async def mock_get_banner(host, port):
            return "220 ProFTPD 1.3.7 Server ready"

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._get_service_banner",
            side_effect=mock_get_banner,
        ):
            findings = await mod.scan("target.example.com")

        ftp_findings = [f for f in findings if "FTP" in f.title and "Detected" in f.title]
        assert len(ftp_findings) == 1
        assert ftp_findings[0].severity == FindingSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_no_banner_produces_low_finding(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 22

        async def mock_get_banner(host, port):
            return ""

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._get_service_banner",
            side_effect=mock_get_banner,
        ):
            findings = await mod.scan("target.example.com")

        low_findings = [f for f in findings if f.severity == FindingSeverity.LOW and "22" in f.title]
        assert len(low_findings) == 1
        assert "Manual Credential Check" in low_findings[0].title


# ---------- Tests for rate limiting ----------

class TestRateLimiting:
    """Test that scan() respects rate limiting (max 3 attempts per service)."""

    @pytest.mark.asyncio
    async def test_web_admin_rate_limited(self):
        """Multiple web_admin ports should be rate-limited to MAX_ATTEMPTS_PER_SERVICE."""
        mod = CredentialCheckModule()

        call_count = {"web_admin": 0}

        async def mock_port_open(host, port):
            return port in (80, 443, 8080, 8443)

        original_check = _check_admin_panel

        def counting_admin_panel(host, port, path, label):
            call_count["web_admin"] += 1
            return None

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_admin_panel",
            side_effect=counting_admin_panel,
        ):
            await mod.scan("target.example.com")

        # With 4 web_admin ports but max 3 attempts, only 3 ports should be checked
        # Each port checks 3 admin paths, so max 9 calls
        assert call_count["web_admin"] <= MAX_ATTEMPTS_PER_SERVICE * len(ADMIN_PANEL_PATHS)


# ---------- Tests for scan() - No open ports ----------

class TestScanNoOpenPorts:
    """Test scan() when no ports are reachable."""

    @pytest.mark.asyncio
    async def test_no_open_ports_returns_empty(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return False

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ):
            findings = await mod.scan("unreachable.example.com")

        assert len(findings) == 0


# ---------- Tests for scan() - Port unreachable timeout ----------

class TestScanPortUnreachable:
    """Test scan() graceful timeout handling."""

    @pytest.mark.asyncio
    async def test_port_timeout_graceful(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return False  # All timeouts

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ):
            # Should not raise any exceptions
            findings = await mod.scan("slow.example.com")

        # No findings when nothing is reachable
        assert isinstance(findings, list)


# ---------- Tests for finding format ----------

class TestFindingFormat:
    """Test that findings have correct format and fields."""

    @pytest.mark.asyncio
    async def test_finding_has_correct_module_name(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 6379

        async def mock_redis_no_auth(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_redis_no_auth",
            side_effect=mock_redis_no_auth,
        ):
            findings = await mod.scan("target.example.com")

        for f in findings:
            assert f.module == "creds"

    @pytest.mark.asyncio
    async def test_finding_has_target_info(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 6379

        async def mock_redis_no_auth(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_redis_no_auth",
            side_effect=mock_redis_no_auth,
        ):
            findings = await mod.scan("10.0.0.1")

        assert len(findings) > 0
        for f in findings:
            assert f.target_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_finding_has_attack_technique(self):
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return port == 6379

        async def mock_redis_no_auth(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_redis_no_auth",
            side_effect=mock_redis_no_auth,
        ):
            findings = await mod.scan("target.example.com")

        redis_findings = [f for f in findings if "Redis" in f.title]
        assert len(redis_findings) == 1
        assert redis_findings[0].attack_technique in ("T1078", "T1110.001")


# ---------- Tests for specific port scan ----------

class TestScanSpecificPort:
    """Test scan() with explicit port parameter."""

    @pytest.mark.asyncio
    async def test_scan_specific_port_only(self):
        mod = CredentialCheckModule()
        port_checks = []

        async def mock_port_open(host, port):
            port_checks.append(port)
            return port == 6379

        async def mock_redis_no_auth(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ), patch(
            "bigr.shield.modules.credential_check._check_redis_no_auth",
            side_effect=mock_redis_no_auth,
        ):
            findings = await mod.scan("target.example.com", port=6379)

        # Should only check port 6379
        assert port_checks == [6379]
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_scan_unknown_port_returns_empty(self):
        """Scanning a port not in PORT_SERVICE_MAP returns nothing."""
        mod = CredentialCheckModule()

        async def mock_port_open(host, port):
            return True

        with patch(
            "bigr.shield.modules.credential_check._check_port_open",
            side_effect=mock_port_open,
        ):
            findings = await mod.scan("target.example.com", port=9999)

        assert len(findings) == 0


# ---------- Tests for _check_admin_panel ----------

class TestCheckAdminPanel:
    """Tests for the admin panel checker helper."""

    def test_admin_panel_200_returns_finding(self):
        """HTTP 200 on admin panel should return a finding."""
        import urllib.request
        import io

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("bigr.shield.modules.credential_check.urllib.request.urlopen", return_value=mock_resp):
            result = _check_admin_panel("example.com", 80, "/admin", "Admin Panel")

        assert result is not None
        assert result.severity == FindingSeverity.HIGH
        assert result.module == "creds"
        assert "/admin" in result.title

    def test_admin_panel_401_returns_none(self):
        """HTTP 401 on admin panel should return None (access restricted)."""
        import urllib.error

        with patch(
            "bigr.shield.modules.credential_check.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "http://example.com/admin", 401, "Unauthorized", {}, None
            ),
        ):
            result = _check_admin_panel("example.com", 80, "/admin", "Admin Panel")

        assert result is None

    def test_admin_panel_connection_error_returns_none(self):
        """Connection error returns None."""
        with patch(
            "bigr.shield.modules.credential_check.urllib.request.urlopen",
            side_effect=OSError("Connection refused"),
        ):
            result = _check_admin_panel("example.com", 80, "/admin", "Admin Panel")

        assert result is None
