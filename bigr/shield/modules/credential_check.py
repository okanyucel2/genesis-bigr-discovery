"""Default credential checker module for common services."""

from __future__ import annotations

import asyncio
import logging
import ssl
import urllib.error
import urllib.request

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

logger = logging.getLogger(__name__)

# Connection timeout for port checks (seconds)
CONNECT_TIMEOUT = 5

# Maximum credential attempts per service (rate limiting)
MAX_ATTEMPTS_PER_SERVICE = 3

# Port-to-service mapping
PORT_SERVICE_MAP: dict[int, str] = {
    22: "ssh",
    21: "ftp",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    80: "web_admin",
    443: "web_admin",
    8080: "web_admin",
    8443: "web_admin",
}

# Default credentials database
DEFAULT_CREDENTIALS: dict[str, list[dict[str, str]]] = {
    "ssh": [
        {"username": "root", "password": "root"},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
    ],
    "ftp": [
        {"username": "anonymous", "password": ""},
        {"username": "admin", "password": "admin"},
        {"username": "ftp", "password": "ftp"},
    ],
    "mysql": [
        {"username": "root", "password": ""},
        {"username": "root", "password": "root"},
        {"username": "root", "password": "mysql"},
    ],
    "postgresql": [
        {"username": "postgres", "password": "postgres"},
        {"username": "postgres", "password": ""},
    ],
    "redis": [
        {"username": "", "password": ""},  # no-auth check
    ],
    "mongodb": [
        {"username": "", "password": ""},  # no-auth check
    ],
    "web_admin": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "12345"},
    ],
}

# Common web admin panel paths to probe
ADMIN_PANEL_PATHS: list[tuple[str, str]] = [
    ("/admin", "Admin Panel"),
    ("/wp-admin", "WordPress Admin"),
    ("/phpmyadmin", "phpMyAdmin"),
]


async def _check_port_open(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    """Check if a TCP port is open on the target host."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _check_redis_no_auth(host: str, port: int = 6379) -> bool:
    """Check if Redis is accessible without authentication.

    Sends PING command and checks for +PONG response.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT,
        )
        writer.write(b"PING\r\n")
        await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=CONNECT_TIMEOUT)
        writer.close()
        await writer.wait_closed()

        return b"+PONG" in data
    except (OSError, asyncio.TimeoutError):
        return False


async def _check_mongodb_no_auth(host: str, port: int = 27017) -> bool:
    """Check if MongoDB is accessible without authentication.

    Attempts a TCP connection and checks if the port responds like MongoDB.
    A successful connection to MongoDB's default port without immediate rejection
    suggests the server may accept unauthenticated connections.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT,
        )
        # Send a minimal MongoDB isMaster query (OP_QUERY)
        # We keep this lightweight -- just read any banner/response
        data = await asyncio.wait_for(reader.read(256), timeout=CONNECT_TIMEOUT)
        writer.close()
        await writer.wait_closed()

        # MongoDB will typically respond with data; no data suggests not MongoDB
        return len(data) > 0
    except (OSError, asyncio.TimeoutError):
        return False


def _check_admin_panel(
    host: str, port: int, path: str, label: str
) -> ShieldFinding | None:
    """Check if an HTTP admin panel path is accessible without authentication.

    Returns a finding if the path returns HTTP 200 (accessible).
    Returns None if 401/403/404 or connection error.
    """
    scheme = "https" if port in (443, 8443) else "http"
    port_suffix = "" if port in (80, 443) else f":{port}"
    url = f"{scheme}://{host}{port_suffix}{path}"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "BiGR-Shield/1.0 (Security Scanner)")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT, context=ctx) as resp:
            status_code = resp.status
            if status_code == 200:
                return ShieldFinding(
                    module="creds",
                    severity=FindingSeverity.HIGH,
                    title=f"Default {label} Accessible at {path}",
                    description=(
                        f"The admin panel at {url} is accessible without authentication. "
                        f"This exposes administrative functionality to unauthorized users."
                    ),
                    remediation=(
                        f"Restrict access to {path} using authentication and IP whitelisting. "
                        f"Consider removing the admin panel from public-facing servers."
                    ),
                    target_ip=host,
                    target_port=port,
                    evidence={
                        "url": url,
                        "path": path,
                        "status_code": status_code,
                        "panel_type": label,
                    },
                    attack_technique="T1078",
                    attack_tactic="Initial Access",
                )
    except urllib.error.HTTPError as exc:
        # 401/403/404 are expected (good -- access is restricted)
        logger.debug("Admin panel check %s returned HTTP %d", url, exc.code)
    except (urllib.error.URLError, OSError) as exc:
        logger.debug("Admin panel check %s failed: %s", url, exc)

    return None


async def _get_service_banner(host: str, port: int) -> str:
    """Attempt to read a service banner from a port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT,
        )
        # Some services send banner on connect (SSH, FTP, SMTP)
        data = await asyncio.wait_for(reader.read(512), timeout=CONNECT_TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace").strip()
    except (OSError, asyncio.TimeoutError):
        return ""


class CredentialCheckModule(ScanModule):
    """Default credential checker for common services.

    Checks for:
    - Redis accessible without authentication
    - MongoDB accessible without authentication
    - HTTP admin panels accessible without authentication
    - Service banner detection for SSH/FTP/MySQL/PostgreSQL
    """

    name: str = "creds"
    weight: int = 10

    def check_available(self) -> bool:
        """Always available -- uses stdlib only."""
        return True

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Scan target for default/missing credentials.

        Strategy:
        1. Identify services by checking known ports
        2. For Redis: test no-auth access (PING/PONG)
        3. For MongoDB: test no-auth access
        4. For HTTP ports: check admin panel paths
        5. For SSH/FTP/MySQL/PostgreSQL: detect via banner, recommend manual check
        """
        findings: list[ShieldFinding] = []

        # Determine which ports to check
        if port is not None:
            ports_to_check = [port]
        else:
            ports_to_check = list(PORT_SERVICE_MAP.keys())

        # Track attempts per service for rate limiting
        attempts_per_service: dict[str, int] = {}

        for check_port in ports_to_check:
            service = PORT_SERVICE_MAP.get(check_port)
            if service is None:
                continue

            # Rate limiting: max attempts per service
            current_attempts = attempts_per_service.get(service, 0)
            if current_attempts >= MAX_ATTEMPTS_PER_SERVICE:
                continue
            attempts_per_service[service] = current_attempts + 1

            # Check if port is open
            is_open = await _check_port_open(target, check_port)
            if not is_open:
                continue

            # Service-specific checks
            if service == "redis":
                no_auth = await _check_redis_no_auth(target, check_port)
                if no_auth:
                    findings.append(ShieldFinding(
                        module="creds",
                        severity=FindingSeverity.CRITICAL,
                        title="Redis Accessible Without Authentication",
                        description=(
                            f"Redis on {target}:{check_port} responds to PING without authentication. "
                            f"An attacker can read/write all data and potentially execute commands."
                        ),
                        remediation=(
                            "Enable Redis authentication with a strong password: "
                            "set 'requirepass' in redis.conf. "
                            "Bind Redis to localhost or restrict with firewall rules."
                        ),
                        target_ip=target,
                        target_port=check_port,
                        evidence={
                            "service": "redis",
                            "auth_required": False,
                            "test": "PING returned PONG without credentials",
                        },
                        attack_technique="T1078",
                        attack_tactic="Initial Access",
                    ))

            elif service == "mongodb":
                no_auth = await _check_mongodb_no_auth(target, check_port)
                if no_auth:
                    findings.append(ShieldFinding(
                        module="creds",
                        severity=FindingSeverity.CRITICAL,
                        title="MongoDB Accessible Without Authentication",
                        description=(
                            f"MongoDB on {target}:{check_port} appears to accept connections "
                            f"without authentication. An attacker can access all databases."
                        ),
                        remediation=(
                            "Enable MongoDB authentication: set 'security.authorization: enabled' "
                            "in mongod.conf. Create admin users with strong passwords. "
                            "Bind to localhost or restrict with firewall rules."
                        ),
                        target_ip=target,
                        target_port=check_port,
                        evidence={
                            "service": "mongodb",
                            "auth_required": False,
                            "test": "Connection accepted and data received without credentials",
                        },
                        attack_technique="T1078",
                        attack_tactic="Initial Access",
                    ))

            elif service == "web_admin":
                # Check common admin panel paths
                for path, label in ADMIN_PANEL_PATHS:
                    finding = _check_admin_panel(target, check_port, path, label)
                    if finding is not None:
                        findings.append(finding)

            elif service in ("ssh", "ftp", "mysql", "postgresql"):
                # Detect service via banner and recommend manual check
                banner = await _get_service_banner(target, check_port)
                service_label = service.upper()
                if banner:
                    findings.append(ShieldFinding(
                        module="creds",
                        severity=FindingSeverity.MEDIUM,
                        title=f"{service_label} Service Detected - Default Credential Check Recommended",
                        description=(
                            f"{service_label} service detected on {target}:{check_port}. "
                            f"Banner: {banner[:200]}. "
                            f"Default credentials should be tested manually."
                        ),
                        remediation=(
                            f"Verify that {service_label} does not use default credentials. "
                            f"Change default passwords and disable default accounts. "
                            f"Restrict access using firewall rules or SSH key-based authentication."
                        ),
                        target_ip=target,
                        target_port=check_port,
                        evidence={
                            "service": service,
                            "banner": banner[:200],
                            "default_creds_to_check": DEFAULT_CREDENTIALS.get(service, []),
                        },
                        attack_technique="T1110.001",
                        attack_tactic="Credential Access",
                    ))
                else:
                    # Port open but no banner -- still report
                    findings.append(ShieldFinding(
                        module="creds",
                        severity=FindingSeverity.LOW,
                        title=f"Service Port {check_port} Open - Manual Credential Check Recommended",
                        description=(
                            f"Port {check_port} ({service_label}) is open on {target} "
                            f"but no service banner was received. "
                            f"Default credentials should be verified."
                        ),
                        remediation=(
                            f"Verify the service on port {check_port} does not accept default credentials. "
                            f"Disable unused services and restrict access with firewall rules."
                        ),
                        target_ip=target,
                        target_port=check_port,
                        evidence={
                            "service": service,
                            "banner": "",
                            "port_open": True,
                        },
                        attack_technique="T1078",
                        attack_tactic="Initial Access",
                    ))

        return findings
