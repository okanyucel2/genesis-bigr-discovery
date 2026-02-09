"""Nuclei vulnerability scanner wrapper module."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

logger = logging.getLogger(__name__)

# Severity mapping from Nuclei to Shield
NUCLEI_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}

# Template selection based on common service types
SERVICE_TEMPLATES: dict[str, list[str]] = {
    "http": ["cves/", "misconfiguration/", "default-logins/"],
    "https": ["cves/", "misconfiguration/", "default-logins/", "ssl/"],
    "ssh": ["network/ssh-*.yaml"],
    "ftp": ["network/ftp-*.yaml"],
    "smtp": ["network/smtp-*.yaml"],
    "mysql": ["network/mysql-*.yaml"],
    "postgresql": ["network/postgresql-*.yaml"],
    "redis": ["network/redis-*.yaml"],
    "mongodb": ["network/mongodb-*.yaml"],
}

# Nuclei process timeout in seconds
NUCLEI_TIMEOUT = 300


def select_templates(services: list[str] | None = None) -> list[str]:
    """Select Nuclei templates based on discovered services."""
    if not services:
        # Default: scan for web vulnerabilities
        return ["cves/", "misconfiguration/"]

    templates: list[str] = []
    seen: set[str] = set()
    for svc in services:
        svc_lower = svc.lower()
        for key, tmpls in SERVICE_TEMPLATES.items():
            if key in svc_lower:
                for t in tmpls:
                    if t not in seen:
                        templates.append(t)
                        seen.add(t)
    return templates or ["cves/", "misconfiguration/"]


def _extract_cve_from_template(template_id: str) -> str | None:
    """Extract CVE ID from nuclei template ID if present."""
    m = re.search(r"(CVE-\d{4}-\d{4,})", template_id, re.IGNORECASE)
    return m.group(1).upper() if m else None


def parse_nuclei_output(output: str) -> list[dict]:
    """Parse Nuclei JSON output (one JSON object per line)."""
    results: list[dict] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append(data)
        except json.JSONDecodeError:
            logger.debug("Skipping invalid nuclei JSON line: %s", line[:80])
            continue
    return results


class NucleiScannerModule(ScanModule):
    """Nuclei vulnerability scanner wrapper."""

    name: str = "nuclei_scanner"
    weight: int = 0  # Supplementary module, doesn't affect score

    def check_available(self) -> bool:
        """Check if nuclei binary is installed."""
        return shutil.which("nuclei") is not None

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Run Nuclei against target and parse results."""
        findings: list[ShieldFinding] = []

        if not self.check_available():
            findings.append(
                ShieldFinding(
                    module="nuclei_scanner",
                    severity=FindingSeverity.INFO,
                    title="Nuclei Scanner Not Installed",
                    description="Nuclei binary not found. Install from "
                    "https://github.com/projectdiscovery/nuclei",
                    evidence={"error": "nuclei_not_installed"},
                )
            )
            return findings

        # Build target URL
        target_url = target
        if port:
            if port in (443, 8443):
                target_url = f"https://{target}:{port}"
            else:
                target_url = f"http://{target}:{port}"

        templates = select_templates()

        cmd = [
            "nuclei",
            "-target",
            target_url,
            "-json",
            "-rate-limit",
            "50",
            "-timeout",
            "10",
            "-severity",
            "critical,high,medium",
            "-silent",
        ]
        # Add templates
        for t in templates:
            cmd.extend(["-t", t])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=NUCLEI_TIMEOUT
            )
        except asyncio.TimeoutError:
            findings.append(
                ShieldFinding(
                    module="nuclei_scanner",
                    severity=FindingSeverity.MEDIUM,
                    title="Nuclei Scan Timeout",
                    description=f"Nuclei scan of {target} timed out after {NUCLEI_TIMEOUT} seconds.",
                    evidence={"error": "timeout", "target": target},
                )
            )
            return findings
        except OSError as e:
            findings.append(
                ShieldFinding(
                    module="nuclei_scanner",
                    severity=FindingSeverity.INFO,
                    title="Nuclei Execution Error",
                    description=f"Failed to run nuclei: {e}",
                    evidence={"error": str(e)},
                )
            )
            return findings

        output = stdout.decode("utf-8", errors="replace")
        parsed = parse_nuclei_output(output)

        for result in parsed:
            template_id = result.get("template-id", "")
            nuclei_severity = result.get("info", {}).get("severity", "info")
            name = result.get("info", {}).get("name", template_id)
            desc = result.get("info", {}).get("description", "")
            matched_at = result.get("matched-at", "")

            severity = NUCLEI_SEVERITY_MAP.get(nuclei_severity, FindingSeverity.INFO)
            cve_id = _extract_cve_from_template(template_id)

            findings.append(
                ShieldFinding(
                    module="nuclei_scanner",
                    severity=severity,
                    title=f"{name}",
                    description=desc[:500]
                    if desc
                    else f"Nuclei finding: {template_id}",
                    target_ip=target,
                    evidence={
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "nuclei_severity": nuclei_severity,
                    },
                    cve_id=cve_id,
                    attack_technique="T1190",
                    attack_tactic="Initial Access",
                )
            )

        return findings
