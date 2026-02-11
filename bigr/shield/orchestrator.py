"""Shield scan orchestrator - manages scan lifecycle."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from bigr.shield.models import (
    FindingSeverity,
    ModuleScore,
    ScanDepth,
    ScanStatus,
    ShieldScan,
)
from bigr.shield.modules.base import ScanModule
from bigr.shield.modules.credential_check import CredentialCheckModule
from bigr.shield.modules.cve_matcher import CveMatcherModule
from bigr.shield.modules.dns_security import DnsSecurityModule
from bigr.shield.modules.http_headers import HttpHeadersModule
from bigr.shield.modules.owasp_probes import OwaspProbesModule
from bigr.shield.modules.port_scan import PortScanModule
from bigr.shield.modules.tls_check import TLSCheckModule
from bigr.shield.scorer import calculate_shield_score

logger = logging.getLogger(__name__)

# Default modules enabled per scan depth
DEPTH_MODULES: dict[ScanDepth, list[str]] = {
    ScanDepth.QUICK: ["tls"],
    ScanDepth.STANDARD: ["tls", "ports", "headers", "dns"],
    ScanDepth.DEEP: ["tls", "ports", "cve", "headers", "dns", "creds", "owasp"],
}


class ShieldOrchestrator:
    """Orchestrates Shield scans across multiple modules."""

    def __init__(self) -> None:
        self._scans: dict[str, ShieldScan] = {}
        self._modules: dict[str, ScanModule] = {
            "tls": TLSCheckModule(),
            "ports": PortScanModule(),
            "cve": CveMatcherModule(),
            "headers": HttpHeadersModule(),
            "dns": DnsSecurityModule(),
            "creds": CredentialCheckModule(),
            "owasp": OwaspProbesModule(),
        }
        self._queue: asyncio.Queue[str] = asyncio.Queue()

    async def create_scan(
        self,
        target: str,
        depth: ScanDepth = ScanDepth.QUICK,
        modules: list[str] | None = None,
    ) -> ShieldScan:
        """Create and queue a new scan.

        Args:
            target: The target to scan (domain, IP, or CIDR).
            depth: Scan depth controlling which modules run.
            modules: Explicit module list (overrides depth default).

        Returns:
            The created ShieldScan instance.
        """
        if modules is None:
            modules = DEPTH_MODULES.get(depth, ["tls"])

        # Determine target type
        target_type = _detect_target_type(target)

        scan = ShieldScan(
            target=target,
            target_type=target_type,
            scan_depth=depth,
            modules_enabled=modules,
        )
        self._scans[scan.id] = scan
        await self._queue.put(scan.id)
        return scan

    def get_scan(self, scan_id: str) -> ShieldScan | None:
        """Get scan by ID."""
        return self._scans.get(scan_id)

    async def run_scan(self, scan_id: str) -> ShieldScan:
        """Execute a queued scan.

        Runs all enabled modules that are available, collects findings,
        calculates scores, and updates the scan status.
        """
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        if scan.status not in (ScanStatus.QUEUED, ScanStatus.FAILED):
            raise ValueError(f"Scan {scan_id} is not in a runnable state: {scan.status.value}")

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)

        try:
            all_findings = []
            module_scores: dict[str, ModuleScore] = {}

            for module_name in scan.modules_enabled:
                module = self._modules.get(module_name)
                if module is None or not module.check_available():
                    logger.warning("Module '%s' not available, skipping", module_name)
                    continue

                try:
                    findings = await module.scan(scan.target)
                except Exception as exc:
                    logger.error("Module '%s' failed: %s", module_name, exc)
                    findings = []

                # Tag findings with scan_id
                for f in findings:
                    f.scan_id = scan.id

                all_findings.extend(findings)

                # Collect certificate metadata from TLS module
                if module_name == "tls" and hasattr(module, "last_certificates"):
                    scan.certificates.extend(module.last_certificates)

                # Calculate module score from findings
                ms = _compute_module_score(module_name, findings)
                module_scores[module_name] = ms

            # Update scan with results
            scan.findings = all_findings
            scan.module_scores = module_scores

            # Aggregate check counts
            scan.total_checks = sum(ms.total_checks for ms in module_scores.values())
            scan.passed_checks = sum(ms.passed_checks for ms in module_scores.values())
            scan.failed_checks = scan.total_checks - scan.passed_checks
            scan.warning_checks = sum(
                1 for f in all_findings if f.severity == FindingSeverity.MEDIUM
            )

            # Calculate overall score
            score, grade = calculate_shield_score(module_scores)
            scan.shield_score = score
            scan.grade = grade

            scan.status = ScanStatus.COMPLETED

        except Exception as exc:
            logger.error("Scan %s failed: %s", scan_id, exc)
            scan.status = ScanStatus.FAILED
            raise

        finally:
            scan.completed_at = datetime.now(timezone.utc)

        return scan

    def list_scans(self, limit: int = 20) -> list[ShieldScan]:
        """List recent scans, ordered by creation time (most recent first)."""
        all_scans = sorted(
            self._scans.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )
        return all_scans[:limit]


def _detect_target_type(target: str) -> str:
    """Detect whether the target is an IP, domain, or CIDR."""
    if "/" in target:
        return "cidr"
    # Simple heuristic: if all parts are digits or dots, it's an IP
    parts = target.split(".")
    if len(parts) == 4:
        try:
            for p in parts:
                val = int(p)
                if not 0 <= val <= 255:
                    raise ValueError
            return "ip"
        except ValueError:
            pass
    return "domain"


def _compute_module_score(module_name: str, findings: list) -> ModuleScore:
    """Compute a ModuleScore from a list of findings.

    Scoring heuristic:
    - Start at 100
    - Critical finding: -25 each
    - High finding: -15 each
    - Medium finding: -8 each
    - Low finding: -3 each
    - Info: -0 (informational only)
    - Minimum score is 0
    """
    severity_penalties = {
        FindingSeverity.CRITICAL: 25,
        FindingSeverity.HIGH: 15,
        FindingSeverity.MEDIUM: 8,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 0,
    }

    score = 100.0
    for f in findings:
        penalty = severity_penalties.get(f.severity, 0)
        score -= penalty

    score = max(0.0, score)

    # The total_checks / passed_checks is a simplified estimate:
    # We consider each unique check type as 1 check.
    # A finding means that check "failed" (or at least generated a warning).
    non_info = [f for f in findings if f.severity != FindingSeverity.INFO]
    # Estimate: we ran at least (len(non_info) + 1) checks if there's any finding,
    # or 1 check if no findings (the connect check itself)
    total_checks = max(len(non_info), 1)
    passed_checks = max(total_checks - len(non_info), 0)

    return ModuleScore(
        module=module_name,
        score=round(score, 2),
        total_checks=total_checks,
        passed_checks=passed_checks,
        findings_count=len(findings),
    )
