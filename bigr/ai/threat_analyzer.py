"""AI-powered threat analysis using hybrid local + cloud inference.

Analysis tiers:
    L0 (Local, Free)  -- Simple classification: "Is this port dangerous?"
    L1 (Cloud Haiku)  -- False positive validation, enriched context.
    L2 (Cloud Opus)   -- Deep forensic analysis (premium only).

The analyzer uses a local Ollama model first, and escalates to a cloud
provider when confidence is below the configured threshold.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from bigr.ai.config import LocalAIConfig
from bigr.ai.local_provider import LocalLLMProvider
from bigr.ai.models import (
    LocalLLMResponse,
    NetworkAssessment,
    ThreatAssessment,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known port risk database (used as context for the LLM)
# ---------------------------------------------------------------------------

_HIGH_RISK_PORTS: dict[int, str] = {
    21: "FTP - unencrypted file transfer, credential sniffing risk",
    23: "Telnet - unencrypted remote shell, critical security risk",
    25: "SMTP - email relay, open relay abuse risk",
    135: "MSRPC - Windows RPC, lateral movement vector",
    137: "NetBIOS Name - information disclosure",
    138: "NetBIOS Datagram - information disclosure",
    139: "NetBIOS Session - SMB over NetBIOS, ransomware vector",
    445: "SMB - EternalBlue, WannaCry, major ransomware vector",
    1433: "MSSQL - database exposure, SQL injection target",
    1521: "Oracle DB - database exposure",
    3306: "MySQL - database exposure, brute force target",
    3389: "RDP - remote desktop, brute force and BlueKeep risk",
    5432: "PostgreSQL - database exposure",
    5900: "VNC - remote desktop, often unencrypted",
    5985: "WinRM HTTP - remote management, lateral movement",
    5986: "WinRM HTTPS - remote management",
    6379: "Redis - in-memory store, often unauthenticated",
    8080: "HTTP Proxy - potential open proxy or admin interface",
    8443: "HTTPS Alt - potential admin interface exposure",
    9200: "Elasticsearch - data exposure risk",
    27017: "MongoDB - database exposure, often unauthenticated",
}

_SAFE_PORTS: dict[int, str] = {
    22: "SSH - encrypted remote shell (ensure key-only auth)",
    53: "DNS - name resolution",
    80: "HTTP - web server (check for HTTPS redirect)",
    443: "HTTPS - encrypted web server",
    993: "IMAPS - encrypted email",
    995: "POP3S - encrypted email",
}


class ThreatAnalyzer:
    """AI-powered threat analysis with hybrid local + cloud inference.

    Parameters:
        config: AI configuration.  Defaults from environment when *None*.
    """

    def __init__(self, config: LocalAIConfig | None = None) -> None:
        self.config = config or LocalAIConfig.from_env()
        self.local = LocalLLMProvider(self.config)

    # ------------------------------------------------------------------
    # Port analysis
    # ------------------------------------------------------------------

    async def analyze_port(
        self,
        port: int,
        service: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ThreatAssessment:
        """Analyse whether an open port represents a security risk.

        Uses the local model first.  If the confidence is below the
        escalation threshold the result is marked for cloud verification,
        but cloud calls are *not* made automatically (caller decides).

        Args:
            port: The port number.
            service: Optional detected service name.
            context: Optional dict with extra context
                (e.g. ``{"vendor": "Cisco", "os": "IOS"}``)

        Returns:
            A :class:`ThreatAssessment`.
        """
        # Build context string
        ctx_parts: list[str] = []
        if port in _HIGH_RISK_PORTS:
            ctx_parts.append(f"Known risk: {_HIGH_RISK_PORTS[port]}")
        elif port in _SAFE_PORTS:
            ctx_parts.append(f"Generally safe: {_SAFE_PORTS[port]}")

        if service:
            ctx_parts.append(f"Detected service: {service}")
        if context:
            for k, v in context.items():
                ctx_parts.append(f"{k}: {v}")

        context_str = "; ".join(ctx_parts) if ctx_parts else "No additional context"

        system = (
            "You are a network security analyst. Assess the risk of an open port. "
            "Respond ONLY with a JSON object. Do not include any other text."
        )
        prompt = (
            f"Assess the security risk of port {port} being open on a network device.\n\n"
            f"Context: {context_str}\n\n"
            f"Respond with a JSON object:\n"
            f'{{"risk_level": "safe|low|medium|high|critical", '
            f'"confidence": 0.0-1.0, '
            f'"explanation": "human-friendly description", '
            f'"remediation": "what to do about it or null"}}\n\n'
            f"JSON:"
        )

        response = await self.local.generate(
            prompt=prompt,
            system=system,
            temperature=0.1,
            max_tokens=300,
        )

        assessment = self._parse_threat_assessment(response)

        # If local model was unreachable, use heuristic fallback
        if response.content.startswith("[ERROR]"):
            assessment = self._heuristic_port_assessment(port, service)

        return assessment

    # ------------------------------------------------------------------
    # Network analysis
    # ------------------------------------------------------------------

    async def analyze_network(
        self, fingerprint: dict[str, Any]
    ) -> NetworkAssessment:
        """Analyse network safety based on fingerprint data.

        Args:
            fingerprint: Dict containing network information such as
                ``open_ports``, ``hostname``, ``vendor``, ``os_hint``.

        Returns:
            A :class:`NetworkAssessment`.
        """
        open_ports = fingerprint.get("open_ports", [])
        hostname = fingerprint.get("hostname", "unknown")
        vendor = fingerprint.get("vendor", "unknown")
        os_hint = fingerprint.get("os_hint", "unknown")

        system = (
            "You are a network security analyst. Assess the overall safety of "
            "a network device. Respond ONLY with a JSON object."
        )
        prompt = (
            f"Assess the security posture of this network device:\n"
            f"  Hostname: {hostname}\n"
            f"  Vendor: {vendor}\n"
            f"  OS: {os_hint}\n"
            f"  Open ports: {open_ports}\n\n"
            f"Respond with JSON:\n"
            f'{{"safety_score": 0.0-1.0, '
            f'"risk_factors": ["factor1", ...], '
            f'"recommendation": "overall advice"}}\n\n'
            f"JSON:"
        )

        response = await self.local.generate(
            prompt=prompt,
            system=system,
            temperature=0.1,
            max_tokens=400,
        )

        return self._parse_network_assessment(response, open_ports)

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    async def generate_remediation(self, finding: dict[str, Any]) -> str:
        """Generate human-friendly remediation text for a finding.

        Uses a writing style inspired by NotebookLM's "Human Story"
        approach: empathetic, clear, actionable.

        Args:
            finding: Dict with keys like ``port``, ``risk_level``,
                ``service``, ``explanation``.

        Returns:
            A remediation text string.
        """
        system = (
            "You are a helpful security advisor writing for a non-technical audience. "
            "Use clear, empathetic language. Keep it under 3 sentences."
        )
        prompt = (
            f"Write a brief, friendly remediation recommendation for this finding:\n"
            f"  Port: {finding.get('port', 'N/A')}\n"
            f"  Service: {finding.get('service', 'N/A')}\n"
            f"  Risk Level: {finding.get('risk_level', 'N/A')}\n"
            f"  Issue: {finding.get('explanation', 'N/A')}\n\n"
            f"Remediation:"
        )

        response = await self.local.generate(
            prompt=prompt,
            system=system,
            temperature=0.3,
            max_tokens=200,
        )

        if response.content.startswith("[ERROR]"):
            return self._heuristic_remediation(finding)

        return response.content

    # ------------------------------------------------------------------
    # Escalation logic
    # ------------------------------------------------------------------

    async def should_escalate(self, local_result: LocalLLMResponse) -> bool:
        """Determine if a result needs cloud verification.

        Returns True if:
        - The content contains an error indicator, or
        - The self-reported confidence is below the escalation threshold.
        """
        if local_result.content.startswith("[ERROR]"):
            return True

        if local_result.confidence is not None:
            return local_result.confidence < self.config.escalation_threshold

        # Try to extract confidence from the response JSON
        try:
            json_match = re.search(
                r"\{[^}]+\}", local_result.content, re.DOTALL
            )
            if json_match:
                parsed = json.loads(json_match.group())
                conf = float(parsed.get("confidence", 0.5))
                return conf < self.config.escalation_threshold
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        # When in doubt, escalate
        return True

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_threat_assessment(
        self, response: LocalLLMResponse
    ) -> ThreatAssessment:
        """Parse a ThreatAssessment from model output."""
        raw = response.content.strip()
        json_match = re.search(r"\{[^}]+\}", raw, re.DOTALL)

        if json_match:
            try:
                parsed = json.loads(json_match.group())
                risk_level = str(
                    parsed.get("risk_level", "medium")
                ).lower()
                if risk_level not in (
                    "safe",
                    "low",
                    "medium",
                    "high",
                    "critical",
                ):
                    risk_level = "medium"

                confidence = min(
                    max(float(parsed.get("confidence", 0.5)), 0.0), 1.0
                )

                return ThreatAssessment(
                    risk_level=risk_level,
                    confidence=confidence,
                    explanation=str(
                        parsed.get("explanation", "Assessment from local AI")
                    ),
                    remediation=parsed.get("remediation"),
                    analyzed_by=f"local:{response.model}",
                    cost=0.0,
                )
            except (json.JSONDecodeError, ValueError, TypeError):
                logger.debug("Failed to parse threat JSON from model output")

        # Fallback: couldn't parse JSON
        return ThreatAssessment(
            risk_level="medium",
            confidence=0.3,
            explanation="Could not parse local model output; defaulting to medium risk",
            remediation="Manual review recommended",
            analyzed_by=f"local:{response.model}",
            cost=0.0,
        )

    def _parse_network_assessment(
        self,
        response: LocalLLMResponse,
        open_ports: list[int],
    ) -> NetworkAssessment:
        """Parse a NetworkAssessment from model output."""
        raw = response.content.strip()
        json_match = re.search(r"\{[^}]+\}", raw, re.DOTALL)

        if json_match:
            try:
                parsed = json.loads(json_match.group())
                safety = min(
                    max(float(parsed.get("safety_score", 0.5)), 0.0), 1.0
                )
                risk_factors = parsed.get("risk_factors", [])
                if isinstance(risk_factors, str):
                    risk_factors = [risk_factors]
                recommendation = str(
                    parsed.get("recommendation", "Review open ports")
                )
                return NetworkAssessment(
                    safety_score=safety,
                    risk_factors=risk_factors,
                    recommendation=recommendation,
                    analyzed_by=f"local:{response.model}",
                )
            except (json.JSONDecodeError, ValueError, TypeError):
                logger.debug("Failed to parse network JSON from model output")

        # Heuristic fallback when Ollama is down or output is garbled
        return self._heuristic_network_assessment(open_ports)

    # ------------------------------------------------------------------
    # Heuristic fallbacks (when Ollama is unavailable)
    # ------------------------------------------------------------------

    @staticmethod
    def _heuristic_port_assessment(
        port: int, service: str | None
    ) -> ThreatAssessment:
        """Rule-based port risk assessment without AI."""
        if port in _HIGH_RISK_PORTS:
            desc = _HIGH_RISK_PORTS[port]
            # Determine severity
            critical_ports = {23, 445, 3389}
            if port in critical_ports:
                level = "critical"
            else:
                level = "high"
            return ThreatAssessment(
                risk_level=level,
                confidence=0.85,
                explanation=desc,
                remediation=f"Close port {port} or restrict access via firewall rules",
                analyzed_by="heuristic",
                cost=0.0,
            )
        elif port in _SAFE_PORTS:
            return ThreatAssessment(
                risk_level="safe",
                confidence=0.9,
                explanation=_SAFE_PORTS[port],
                remediation=None,
                analyzed_by="heuristic",
                cost=0.0,
            )
        else:
            svc_str = f" ({service})" if service else ""
            return ThreatAssessment(
                risk_level="low",
                confidence=0.5,
                explanation=f"Port {port}{svc_str} is not in the well-known risk database",
                remediation="Verify this port is intentionally open",
                analyzed_by="heuristic",
                cost=0.0,
            )

    @staticmethod
    def _heuristic_network_assessment(
        open_ports: list[int],
    ) -> NetworkAssessment:
        """Rule-based network assessment without AI."""
        risk_factors: list[str] = []
        high_risk_found = 0

        for p in open_ports:
            if p in _HIGH_RISK_PORTS:
                risk_factors.append(f"Port {p}: {_HIGH_RISK_PORTS[p]}")
                high_risk_found += 1

        if high_risk_found == 0:
            safety = 0.9
            recommendation = "No high-risk ports detected. Maintain current posture."
        elif high_risk_found <= 2:
            safety = 0.6
            recommendation = (
                f"{high_risk_found} high-risk port(s) found. "
                "Review and restrict access where possible."
            )
        else:
            safety = max(0.1, 1.0 - (high_risk_found * 0.15))
            recommendation = (
                f"{high_risk_found} high-risk ports detected. "
                "Urgent review and firewall hardening recommended."
            )

        return NetworkAssessment(
            safety_score=round(safety, 2),
            risk_factors=risk_factors,
            recommendation=recommendation,
            analyzed_by="heuristic",
        )

    @staticmethod
    def _heuristic_remediation(finding: dict[str, Any]) -> str:
        """Generate remediation text without AI."""
        port = finding.get("port", "N/A")
        risk = finding.get("risk_level", "unknown")
        service = finding.get("service", "the service")

        if risk in ("critical", "high"):
            return (
                f"Port {port} ({service}) poses a {risk} risk. "
                f"Disable the service if not needed, or restrict access "
                f"to trusted IP ranges using firewall rules."
            )
        elif risk == "medium":
            return (
                f"Port {port} ({service}) has moderate risk. "
                f"Ensure the service is up-to-date and properly configured. "
                f"Consider restricting access."
            )
        else:
            return (
                f"Port {port} ({service}) appears to be low risk. "
                f"Keep the service patched and monitor for unusual activity."
            )
