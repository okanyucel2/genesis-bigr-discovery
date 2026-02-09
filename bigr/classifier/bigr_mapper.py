"""BİGR 4-group classification engine with confidence scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

from bigr.classifier.fingerprint import fingerprint_asset
from bigr.classifier.mac_lookup import get_vendor_category_hint, lookup_vendor
from bigr.models import is_randomized_mac
from bigr.classifier.rules_engine import (
    RuleSet,
    apply_hostname_rules,
    apply_port_rules,
    apply_service_rules,
    apply_vendor_rules,
    load_rules,
)
from bigr.models import Asset, BigrCategory


@dataclass
class ClassificationScores:
    ag_ve_sistemler: float = 0.0
    uygulamalar: float = 0.0
    iot: float = 0.0
    tasinabilir: float = 0.0
    evidence: dict = field(default_factory=dict)

    def add_scores(self, deltas: dict[str, float]) -> None:
        """Apply score deltas from a rule result."""
        for cat, delta in deltas.items():
            if hasattr(self, cat):
                setattr(self, cat, getattr(self, cat) + delta)

    @property
    def winner(self) -> BigrCategory:
        scores = {
            BigrCategory.AG_VE_SISTEMLER: self.ag_ve_sistemler,
            BigrCategory.UYGULAMALAR: self.uygulamalar,
            BigrCategory.IOT: self.iot,
            BigrCategory.TASINABILIR: self.tasinabilir,
        }
        max_cat = max(scores, key=lambda k: scores[k])
        return max_cat

    @property
    def confidence(self) -> float:
        total = self.ag_ve_sistemler + self.uygulamalar + self.iot + self.tasinabilir
        if total == 0:
            return 0.0
        max_score = max(self.ag_ve_sistemler, self.uygulamalar, self.iot, self.tasinabilir)
        return round(max_score / total, 4)


@lru_cache(maxsize=1)
def _get_ruleset() -> RuleSet:
    """Load YAML rules once and cache."""
    return load_rules()


# --- Scoring Rules (YAML-backed with hardcoded fallback) ---

def score_by_ports(open_ports: list[int], scores: ClassificationScores) -> None:
    """Score based on open port profile using YAML rules."""
    ruleset = _get_ruleset()

    if ruleset.port_rules:
        deltas, evidence = apply_port_rules(ruleset.port_rules, open_ports)
        scores.add_scores(deltas)
        if evidence:
            scores.evidence["port_rules"] = evidence
        return

    # Fallback: hardcoded rules
    _score_by_ports_hardcoded(open_ports, scores)


def score_by_vendor(vendor: str | None, scores: ClassificationScores) -> None:
    """Score based on MAC vendor using YAML rules."""
    ruleset = _get_ruleset()

    if ruleset.vendor_rules:
        deltas, evidence = apply_vendor_rules(ruleset.vendor_rules, vendor)
        scores.add_scores(deltas)
        if evidence:
            scores.evidence["vendor_rule"] = evidence
        return

    # Fallback: hardcoded rules
    _score_by_vendor_hardcoded(vendor, scores)


def score_by_hostname(hostname: str | None, scores: ClassificationScores) -> None:
    """Score based on hostname patterns using YAML rules."""
    ruleset = _get_ruleset()

    if ruleset.hostname_rules:
        deltas, evidence = apply_hostname_rules(ruleset.hostname_rules, hostname)
        scores.add_scores(deltas)
        if evidence:
            scores.evidence["hostname_rules"] = evidence
        return

    # Fallback: hardcoded rules
    _score_by_hostname_hardcoded(hostname, scores)


def score_by_os(os_hint: str | None, scores: ClassificationScores) -> None:
    """Score based on OS fingerprint (hardcoded - no YAML equivalent yet)."""
    if not os_hint:
        return

    os_lower = os_hint.lower()
    rule_evidence: str | None = None

    if "network equipment" in os_lower or "routeros" in os_lower:
        scores.ag_ve_sistemler += 0.4
        rule_evidence = f"OS '{os_hint}' → Ağ/Sistem"
    elif "linux (server)" in os_lower or "web server" in os_lower:
        scores.ag_ve_sistemler += 0.2
        scores.uygulamalar += 0.2
        rule_evidence = f"OS '{os_hint}' → Ağ/Sistem + Uygulama"
    elif "windows" in os_lower:
        scores.tasinabilir += 0.3
        rule_evidence = f"OS '{os_hint}' → Taşınabilir"
    elif "ip camera" in os_lower:
        scores.iot += 0.5
        rule_evidence = f"OS '{os_hint}' → IoT"
    elif "printer" in os_lower:
        scores.iot += 0.5
        rule_evidence = f"OS '{os_hint}' → IoT"
    elif "iot" in os_lower:
        scores.iot += 0.4
        rule_evidence = f"OS '{os_hint}' → IoT"

    if rule_evidence:
        scores.evidence["os_rule"] = rule_evidence


def score_by_services(raw_evidence: dict, scores: ClassificationScores) -> None:
    """Score based on mDNS service types using YAML rules.

    Reads mdns_services from the asset's raw_evidence and applies
    service classification rules from service_rules.yaml.

    Args:
        raw_evidence: Asset's raw_evidence dict (may contain 'mdns_services').
        scores: ClassificationScores to update.
    """
    mdns_services = raw_evidence.get("mdns_services", [])
    if not mdns_services:
        return

    # Extract unique service types from evidence
    service_types = list({svc.get("service_type", "") for svc in mdns_services if svc.get("service_type")})
    if not service_types:
        return

    ruleset = _get_ruleset()

    if ruleset.service_rules:
        deltas, evidence = apply_service_rules(ruleset.service_rules, service_types)
        scores.add_scores(deltas)
        if evidence:
            scores.evidence["service_rules"] = evidence


# --- Main Classifier ---

def classify_asset(asset: Asset, do_fingerprint: bool = True) -> Asset:
    """Classify a single asset into BİGR category.

    Checks for manual override first. If present, uses that category with
    confidence 1.0. Otherwise runs all scoring rules and assigns the winning
    category + confidence. Uses YAML rules if available, falls back to
    hardcoded rules.
    """
    # Check for manual override first
    from bigr.db import get_tags

    try:
        tags = get_tags()
        for tag in tags:
            if tag["ip"] == asset.ip:
                asset.bigr_category = BigrCategory(tag["manual_category"])
                asset.confidence_score = 1.0  # Manual = 100% confidence
                asset.raw_evidence = {"manual_override": tag.get("manual_note") or "User override"}
                return asset
    except Exception:
        pass  # DB not available, continue with auto-classification

    # Enrich vendor if not set
    if asset.vendor is None:
        asset.vendor = lookup_vendor(asset.mac)

    # Enrich OS hint if not set
    if asset.os_hint is None and do_fingerprint and asset.open_ports:
        asset.os_hint = fingerprint_asset(asset.ip, asset.open_ports)

    # Score
    scores = ClassificationScores()
    score_by_ports(asset.open_ports, scores)
    score_by_vendor(asset.vendor, scores)
    score_by_hostname(asset.hostname, scores)
    score_by_os(asset.os_hint, scores)
    score_by_services(asset.raw_evidence, scores)
    _score_by_mac_randomization(asset.mac, asset.open_ports, scores)

    # Preserve mDNS service evidence through classification
    mdns_services = asset.raw_evidence.get("mdns_services")

    # Assign
    if scores.confidence >= 0.3:
        asset.bigr_category = scores.winner
    else:
        asset.bigr_category = BigrCategory.UNCLASSIFIED

    asset.confidence_score = scores.confidence
    asset.raw_evidence = scores.evidence

    # Restore mDNS evidence so it persists in output
    if mdns_services:
        asset.raw_evidence["mdns_services"] = mdns_services

    return asset


def classify_assets(assets: list[Asset], do_fingerprint: bool = True) -> list[Asset]:
    """Classify all assets in a scan result."""
    return [classify_asset(asset, do_fingerprint=do_fingerprint) for asset in assets]


# =============================================================================
# Heuristic Rules (always applied)
# =============================================================================

def _score_by_mac_randomization(mac: str | None, open_ports: list[int], scores: ClassificationScores) -> None:
    """Score based on MAC randomization detection.

    Locally administered MACs (Apple/Android privacy) are a strong
    signal that the device is a mobile phone, tablet, or laptop.
    Combined with no open ports → very likely a consumer device.
    """
    if not is_randomized_mac(mac):
        return

    evidence: list[str] = []

    # Randomized MAC alone → mobile device signal
    scores.tasinabilir += 0.4
    evidence.append(f"Randomized MAC ({mac}) → Taşınabilir")

    # No open ports + randomized MAC → even stronger signal
    if not open_ports:
        scores.tasinabilir += 0.2
        evidence.append("No open ports + randomized MAC → likely phone/tablet")

    scores.evidence["mac_heuristic"] = evidence


# =============================================================================
# Hardcoded Fallback Rules (used when YAML rules not found)
# =============================================================================

def _score_by_ports_hardcoded(open_ports: list[int], scores: ClassificationScores) -> None:
    port_set = set(open_ports)
    rule_evidence: list[str] = []

    if {22, 80, 443}.issubset(port_set):
        scores.ag_ve_sistemler += 0.4
        rule_evidence.append("SSH+HTTP+HTTPS → Ağ/Sistem")
    elif 22 in port_set and len(port_set) >= 3:
        scores.ag_ve_sistemler += 0.3
        rule_evidence.append("SSH+multi-port → Ağ/Sistem")

    if port_set & {80, 443, 8080, 8443} and 22 not in port_set:
        scores.uygulamalar += 0.4
        rule_evidence.append("Web ports (no SSH) → Uygulama")
    elif port_set & {80, 443}:
        scores.uygulamalar += 0.2
        rule_evidence.append("Web ports → Uygulama (weak)")

    if 9100 in port_set:
        scores.iot += 0.5
        rule_evidence.append("Port 9100 (JetDirect) → IoT")
    if 554 in port_set:
        scores.iot += 0.5
        rule_evidence.append("Port 554 (RTSP) → IoT")
    if 1883 in port_set:
        scores.iot += 0.4
        rule_evidence.append("Port 1883 (MQTT) → IoT")
    if 3389 in port_set:
        scores.tasinabilir += 0.3
        rule_evidence.append("Port 3389 (RDP) → Taşınabilir")
    if 161 in port_set:
        scores.ag_ve_sistemler += 0.3
        rule_evidence.append("Port 161 (SNMP) → Ağ/Sistem")
    if port_set & {3306, 5432, 1433, 27017}:
        scores.ag_ve_sistemler += 0.2
        rule_evidence.append("Database port → Ağ/Sistem")

    if rule_evidence:
        scores.evidence["port_rules"] = rule_evidence


def _score_by_vendor_hardcoded(vendor: str | None, scores: ClassificationScores) -> None:
    hint = get_vendor_category_hint(vendor)
    if not hint:
        return

    weight = 0.5
    rule_evidence = f"{vendor} → {hint} (+{weight})"

    if hint == "ag_ve_sistemler":
        scores.ag_ve_sistemler += weight
    elif hint == "uygulamalar":
        scores.uygulamalar += weight
    elif hint == "iot":
        scores.iot += weight
    elif hint == "tasinabilir":
        scores.tasinabilir += weight

    scores.evidence["vendor_rule"] = rule_evidence


def _score_by_hostname_hardcoded(hostname: str | None, scores: ClassificationScores) -> None:
    if not hostname:
        return

    hn = hostname.lower()
    rule_evidence: list[str] = []

    net_patterns = [r"sw[\-_]", r"switch", r"fw[\-_]", r"firewall", r"router", r"gw[\-_]", r"gateway", r"ap[\-_\d]"]
    for pattern in net_patterns:
        if re.search(pattern, hn):
            scores.ag_ve_sistemler += 0.4
            rule_evidence.append(f"hostname '{hn}' matches {pattern} → Ağ/Sistem")
            break

    iot_patterns = [r"cam[\-_]", r"camera", r"printer", r"prn[\-_]", r"sensor", r"thermostat"]
    for pattern in iot_patterns:
        if re.search(pattern, hn):
            scores.iot += 0.4
            rule_evidence.append(f"hostname '{hn}' matches {pattern} → IoT")
            break

    pc_patterns = [r"laptop", r"nb[\-_]", r"desktop", r"pc[\-_]", r"workstation"]
    for pattern in pc_patterns:
        if re.search(pattern, hn):
            scores.tasinabilir += 0.4
            rule_evidence.append(f"hostname '{hn}' matches {pattern} → Taşınabilir")
            break

    app_patterns = [r"web[\-_]", r"app[\-_]", r"api[\-_]", r"srv[\-_]", r"server"]
    for pattern in app_patterns:
        if re.search(pattern, hn):
            scores.uygulamalar += 0.4
            rule_evidence.append(f"hostname '{hn}' matches {pattern} → Uygulama")
            break

    if rule_evidence:
        scores.evidence["hostname_rules"] = rule_evidence
