"""Port scanning module using nmap subprocess."""

from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

logger = logging.getLogger(__name__)

# Ports that indicate potentially dangerous services
DANGEROUS_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    27017: "MongoDB",
    6379: "Redis",
    5432: "PostgreSQL",
    3306: "MySQL",
    11211: "Memcached",
    9200: "Elasticsearch",
}

# Common/expected ports that are informational only
COMMON_PORTS: set[int] = {80, 443, 22}

# Nmap process timeout in seconds
NMAP_TIMEOUT = 120

# Open port count threshold for medium finding
OPEN_PORT_THRESHOLD = 10


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML output and return a list of open port dicts.

    Each dict has keys: port, protocol, state, service, version.
    """
    ports: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning("Failed to parse nmap XML output")
        return ports

    for host in root.findall(".//host"):
        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None:
                continue

            state = state_elem.get("state", "")
            if state != "open":
                continue

            port_id = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")

            service_name = ""
            service_version = ""
            service_elem = port_elem.find("service")
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                if product:
                    service_version = product
                    if version:
                        service_version = f"{product} {version}"

            ports.append({
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": service_version,
            })

    return ports


class PortScanModule(ScanModule):
    """Port scanning module using nmap subprocess wrapper."""

    name: str = "ports"
    weight: int = 20

    def check_available(self) -> bool:
        """Check if nmap binary is available on the system."""
        return shutil.which("nmap") is not None

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Run nmap scan against the target and analyze open ports.

        Checks performed:
        1. Top 1000 ports scan with service version detection
        2. Dangerous port flagging (FTP, Telnet, SMB, RDP, etc.)
        3. Excessive open port count (>10 = medium finding)
        4. Common expected ports (80, 443, 22) = info findings
        """
        findings: list[ShieldFinding] = []

        # Check nmap availability at scan time as well
        if not shutil.which("nmap"):
            findings.append(ShieldFinding(
                module="ports",
                severity=FindingSeverity.INFO,
                title="Nmap Not Installed",
                description=(
                    "The nmap binary was not found on the system. "
                    "Port scanning requires nmap to be installed."
                ),
                remediation="Install nmap: apt-get install nmap (Debian/Ubuntu) or brew install nmap (macOS).",
                target_ip=target,
                target_port=None,
                evidence={"error": "nmap_not_found"},
            ))
            return findings

        # Build nmap command -- uses execv-style argument list (no shell)
        cmd = [
            "nmap",
            "-sT",               # TCP connect scan (no root needed)
            "--top-ports", "1000",
            "-sV",               # Service version detection
            "--open",            # Only show open ports
            "-oX", "-",          # XML output to stdout
            target,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=NMAP_TIMEOUT,
            )
        except asyncio.TimeoutError:
            findings.append(ShieldFinding(
                module="ports",
                severity=FindingSeverity.MEDIUM,
                title="Port Scan Timeout",
                description=f"Nmap scan of {target} timed out after {NMAP_TIMEOUT} seconds.",
                remediation="The target may be heavily filtered. Try scanning fewer ports.",
                target_ip=target,
                target_port=None,
                evidence={"error": "timeout", "timeout_seconds": NMAP_TIMEOUT},
            ))
            return findings
        except OSError as exc:
            findings.append(ShieldFinding(
                module="ports",
                severity=FindingSeverity.INFO,
                title="Port Scan Error",
                description=f"Failed to execute nmap: {exc}",
                remediation="Verify nmap is correctly installed and accessible.",
                target_ip=target,
                target_port=None,
                evidence={"error": str(exc)},
            ))
            return findings

        if proc.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
            findings.append(ShieldFinding(
                module="ports",
                severity=FindingSeverity.INFO,
                title="Port Scan Failed",
                description=f"Nmap exited with code {proc.returncode} for target {target}.",
                remediation="Check the target address and nmap permissions.",
                target_ip=target,
                target_port=None,
                evidence={"return_code": proc.returncode, "stderr": stderr_text[:500]},
            ))
            return findings

        # Parse XML output
        xml_output = stdout.decode("utf-8", errors="replace")
        open_ports = _parse_nmap_xml(xml_output)

        if not open_ports:
            findings.append(ShieldFinding(
                module="ports",
                severity=FindingSeverity.INFO,
                title="No Open Ports Detected",
                description=f"No open ports found in top 1000 ports scan of {target}.",
                remediation="No action needed. The target may be behind a firewall or all ports are filtered.",
                target_ip=target,
                target_port=None,
                evidence={"open_port_count": 0},
            ))
            return findings

        # Check each open port
        for port_info in open_ports:
            port_num = port_info["port"]
            service = port_info["service"]
            version = port_info["version"]

            if port_num in DANGEROUS_PORTS:
                svc_label = DANGEROUS_PORTS[port_num]
                findings.append(ShieldFinding(
                    module="ports",
                    severity=FindingSeverity.HIGH,
                    title=f"Dangerous Port Open: {port_num}/{port_info['protocol']} ({svc_label})",
                    description=(
                        f"Port {port_num} ({svc_label}) is open on {target}. "
                        f"This service should not be publicly exposed."
                        + (f" Detected service: {service}" if service else "")
                        + (f" version: {version}" if version else "")
                    ),
                    remediation=(
                        f"Close port {port_num} or restrict access using firewall rules. "
                        f"If {svc_label} is required, ensure it is not exposed to the public internet."
                    ),
                    target_ip=target,
                    target_port=port_num,
                    evidence={
                        "port": port_num,
                        "protocol": port_info["protocol"],
                        "service": service,
                        "version": version,
                        "dangerous_service": svc_label,
                    },
                    attack_technique="T1190",
                    attack_tactic="Initial Access",
                ))
            elif port_num in COMMON_PORTS:
                findings.append(ShieldFinding(
                    module="ports",
                    severity=FindingSeverity.INFO,
                    title=f"Common Port Open: {port_num}/{port_info['protocol']}",
                    description=(
                        f"Port {port_num} is open on {target}. "
                        f"This is a commonly expected port."
                        + (f" Service: {service}" if service else "")
                        + (f" version: {version}" if version else "")
                    ),
                    remediation="No action needed for standard services. Ensure the service is kept up to date.",
                    target_ip=target,
                    target_port=port_num,
                    evidence={
                        "port": port_num,
                        "protocol": port_info["protocol"],
                        "service": service,
                        "version": version,
                    },
                ))
            else:
                # Non-dangerous, non-common open port
                findings.append(ShieldFinding(
                    module="ports",
                    severity=FindingSeverity.LOW,
                    title=f"Open Port: {port_num}/{port_info['protocol']}",
                    description=(
                        f"Port {port_num} is open on {target}."
                        + (f" Service: {service}" if service else "")
                        + (f" version: {version}" if version else "")
                    ),
                    remediation=f"Verify port {port_num} is intentionally open. Close unnecessary services.",
                    target_ip=target,
                    target_port=port_num,
                    evidence={
                        "port": port_num,
                        "protocol": port_info["protocol"],
                        "service": service,
                        "version": version,
                    },
                ))

        # Check for excessive open ports
        if len(open_ports) > OPEN_PORT_THRESHOLD:
            findings.append(ShieldFinding(
                module="ports",
                severity=FindingSeverity.MEDIUM,
                title="Excessive Open Ports",
                description=(
                    f"{len(open_ports)} open ports detected on {target}, "
                    f"which exceeds the threshold of {OPEN_PORT_THRESHOLD}. "
                    "A large attack surface increases security risk."
                ),
                remediation=(
                    "Review all open ports and close unnecessary services. "
                    "Apply the principle of least privilege to exposed services."
                ),
                target_ip=target,
                target_port=None,
                evidence={
                    "open_port_count": len(open_ports),
                    "threshold": OPEN_PORT_THRESHOLD,
                    "ports": [p["port"] for p in open_ports],
                },
                attack_technique="T1046",
                attack_tactic="Discovery",
            ))

        return findings
