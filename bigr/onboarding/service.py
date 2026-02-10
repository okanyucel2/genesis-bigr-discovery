"""Onboarding service -- orchestrates the first-run trust-building experience.

Philosophy: "Arac Degil, Ajan" (Not a tool, an agent).  The onboarding
flow should feel like meeting a protective companion for the first time,
not running a scary security audit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from bigr.agent.network_fingerprint import (
    NetworkFingerprint,
    detect_network_fingerprint,
)
from bigr.ai.threat_analyzer import ThreatAnalyzer, _HIGH_RISK_PORTS, _SAFE_PORTS
from bigr.core import services

logger = logging.getLogger(__name__)


class OnboardingStep(str, Enum):
    WELCOME = "welcome"
    NETWORK_SCAN = "network_scan"
    NAME_NETWORK = "name_network"
    READY = "ready"
    COMPLETE = "complete"


@dataclass
class OnboardingResult:
    """Result of the onboarding start scan."""

    network_id: str | None = None
    ssid: str | None = None
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    safety_score: float = 0.85  # Default optimistic
    risk_factors: list[str] = field(default_factory=list)
    safety_message: str = ""
    safety_detail: str = ""
    known_network: bool = False
    open_ports: list[int] = field(default_factory=list)
    device_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "network_id": self.network_id,
            "ssid": self.ssid,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "safety_score": self.safety_score,
            "risk_factors": self.risk_factors,
            "safety_message": self.safety_message,
            "safety_detail": self.safety_detail,
            "known_network": self.known_network,
            "open_ports": self.open_ports,
            "device_count": self.device_count,
        }


class OnboardingService:
    """Orchestrates the first-run trust-building experience."""

    def __init__(self) -> None:
        self._current_step: OnboardingStep = OnboardingStep.WELCOME
        self._completed_steps: list[str] = []
        self._result: OnboardingResult | None = None
        self._network_id: str | None = None
        self._network_name: str | None = None
        self._network_type: str | None = None

    async def start_onboarding(
        self,
        session: AsyncSession,
        client_ip: str | None = None,
    ) -> OnboardingResult:
        """Run the initial network detection and safety assessment.

        Steps:
        1. Detect current network (gateway MAC + SSID fingerprint)
        2. Heuristic port-based safety assessment on gateway
        3. Check if this is a known (returning) network
        4. Generate warm, human-friendly safety summary

        Returns an encouraging result even if issues are found.
        """
        result = OnboardingResult()

        # --- Step 1: Detect network ---
        fingerprint: NetworkFingerprint | None = None
        try:
            fingerprint = detect_network_fingerprint()
        except Exception:
            logger.warning("Network fingerprint detection failed", exc_info=True)

        if fingerprint:
            result.ssid = fingerprint.ssid
            result.gateway_ip = fingerprint.gateway_ip
            result.gateway_mac = fingerprint.gateway_mac

            # Resolve / register network in DB
            try:
                network_id = await services.resolve_network(
                    session, fingerprint.to_dict()
                )
                result.network_id = network_id
                self._network_id = network_id

                # Check if we've seen this network before
                networks = await services.get_networks_summary(session)
                for net in networks:
                    if net["id"] == network_id:
                        result.known_network = bool(net.get("friendly_name"))
                        result.device_count = net.get("asset_count", 0)
                        if net.get("friendly_name"):
                            self._network_name = net["friendly_name"]
                        break
            except Exception:
                logger.warning("Network resolve failed", exc_info=True)
        else:
            # Fallback: no fingerprint available (e.g. running in container)
            result.ssid = _detect_fallback_ssid()
            result.gateway_ip = _detect_fallback_gateway()

        # --- Step 2: Heuristic safety assessment ---
        safety_score, risk_factors = _heuristic_gateway_assessment(
            result.gateway_ip, result.open_ports
        )
        result.safety_score = safety_score
        result.risk_factors = risk_factors

        # --- Step 3: Try AI-powered assessment (non-blocking, fallback ok) ---
        try:
            analyzer = ThreatAnalyzer()
            assessment = await analyzer.analyze_network({
                "open_ports": result.open_ports,
                "hostname": result.ssid or "unknown",
                "vendor": "gateway",
                "os_hint": "router",
            })
            # Blend AI score with heuristic (AI gets 60% weight if available)
            if assessment.safety_score > 0:
                result.safety_score = round(
                    assessment.safety_score * 0.6 + safety_score * 0.4, 2
                )
                result.risk_factors = assessment.risk_factors or risk_factors
        except Exception:
            logger.debug("AI assessment unavailable, using heuristic only")

        # --- Step 4: Generate warm safety message ---
        result.safety_message, result.safety_detail = _generate_safety_message(
            result.safety_score,
            result.ssid,
            result.risk_factors,
            result.known_network,
        )

        self._result = result
        self._current_step = OnboardingStep.NETWORK_SCAN
        self._completed_steps.append(OnboardingStep.WELCOME.value)
        self._completed_steps.append(OnboardingStep.NETWORK_SCAN.value)

        return result

    async def name_network(
        self,
        session: AsyncSession,
        network_id: str,
        name: str,
        network_type: str,
    ) -> dict[str, Any]:
        """User labels their network -- builds familiarity and trust."""
        self._network_name = name
        self._network_type = network_type

        # Persist friendly name
        updated = await services.update_network_name(session, network_id, name)

        self._current_step = OnboardingStep.READY
        self._completed_steps.append(OnboardingStep.NAME_NETWORK.value)

        return {
            "network_id": network_id,
            "name": name,
            "type": network_type,
            "updated": updated is not None,
            "message": f'"{name}" olarak kaydettim. Seni her geldiginde taniyacagim.',
        }

    def get_status(self) -> dict[str, Any]:
        """Current onboarding progress."""
        return {
            "step": self._current_step.value,
            "completed_steps": self._completed_steps,
            "network_info": self._result.to_dict() if self._result else None,
            "network_name": self._network_name,
            "network_type": self._network_type,
            "safety_score": self._result.safety_score if self._result else None,
            "is_complete": self._current_step == OnboardingStep.COMPLETE,
        }

    async def complete(self) -> dict[str, Any]:
        """Finalize onboarding, return overall summary."""
        self._current_step = OnboardingStep.COMPLETE
        self._completed_steps.append(OnboardingStep.READY.value)

        summary: dict[str, Any] = {
            "status": "complete",
            "message": "Hazirim! Arkanı kolluyorum.",
            "motto": "Sen kahveni yudumla, arkani biz kollariz.",
        }

        if self._result:
            summary["network"] = {
                "ssid": self._result.ssid,
                "name": self._network_name,
                "type": self._network_type,
                "safety_score": self._result.safety_score,
                "risk_count": len(self._result.risk_factors),
            }

        return summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_fallback_ssid() -> str | None:
    """Try to detect SSID without full fingerprint pipeline."""
    try:
        from bigr.agent.network_fingerprint import detect_ssid
        return detect_ssid()
    except Exception:
        return None


def _detect_fallback_gateway() -> str | None:
    """Try to detect gateway IP without full fingerprint pipeline."""
    try:
        from bigr.agent.network_fingerprint import detect_default_gateway_ip
        return detect_default_gateway_ip()
    except Exception:
        return None


def _heuristic_gateway_assessment(
    gateway_ip: str | None,
    open_ports: list[int],
) -> tuple[float, list[str]]:
    """Quick heuristic safety assessment based on gateway and known ports.

    Returns (safety_score, risk_factors).
    """
    risk_factors: list[str] = []
    safety_score = 0.90  # Start optimistic

    if not gateway_ip:
        # Can't assess without gateway, give neutral score
        return 0.75, ["Ag gecidi tespit edilemedi"]

    # Check common risky ports on the gateway
    high_risk_found = 0
    for port in open_ports:
        if port in _HIGH_RISK_PORTS:
            risk_factors.append(f"Port {port}: {_HIGH_RISK_PORTS[port]}")
            high_risk_found += 1

    if high_risk_found == 0:
        safety_score = 0.92
    elif high_risk_found <= 2:
        safety_score = 0.65
    else:
        safety_score = max(0.25, 1.0 - (high_risk_found * 0.15))

    return round(safety_score, 2), risk_factors


def _generate_safety_message(
    score: float,
    ssid: str | None,
    risk_factors: list[str],
    known_network: bool,
) -> tuple[str, str]:
    """Generate warm, human-friendly safety messages.

    Returns (primary_message, detail_message).
    Never scary, always protective and encouraging.
    """
    network_name = ssid or "bu ag"

    if score >= 0.85:
        primary = f"{network_name} guvende gorunuyor."
        if known_network:
            detail = "Daha once buradaydin, her sey normal gorunuyor."
        else:
            detail = "Ilk bakista temiz gorunuyor. Seni korumaya devam edecegim."
    elif score >= 0.60:
        risk_count = len(risk_factors)
        primary = f"Bu agda {risk_count} dikkat noktasi var."
        detail = "Endiselenme, goz kulak oluyorum. Onemli bir sey olursa haber veririm."
    elif score >= 0.40:
        primary = "Bu ag biraz dikkat gerektiriyor."
        detail = "Birkac risk faktoru tespit ettim. Paranoyak Mod'u aktif etmeni oneriyorum."
    else:
        primary = "Bu agda dikkatli olmak lazim."
        detail = (
            "Yuksek riskli birkac durum tespit ettim. "
            "Seni korumak icin ekstra onlemler aliyorum."
        )

    return primary, detail
