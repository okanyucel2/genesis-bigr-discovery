"""Risk scoring engine for BİGR Discovery assets."""

from __future__ import annotations

from datetime import datetime, timezone

from bigr.risk.models import RiskFactors, RiskProfile, RiskReport

# Risk weights — how much each factor contributes to the total score.
WEIGHTS = {
    "cve": 0.35,
    "exposure": 0.25,
    "classification": 0.20,
    "age": 0.10,
    "change": 0.10,
}

# BİGR category risk levels (IoT most risky, Ag/Sistem least).
CATEGORY_RISK = {
    "iot": 0.8,  # IoT devices often unpatched
    "tasinabilir": 0.5,  # Mobile devices moderate risk
    "uygulamalar": 0.4,  # Applications moderate
    "ag_ve_sistemler": 0.3,  # Network infra usually managed
    "unclassified": 0.9,  # Unknown = highest risk
}

# High-risk ports (internet-facing services).
HIGH_RISK_PORTS = {
    21: 0.7,  # FTP
    23: 0.9,  # Telnet (cleartext)
    25: 0.5,  # SMTP
    53: 0.3,  # DNS
    80: 0.4,  # HTTP
    443: 0.3,  # HTTPS
    445: 0.8,  # SMB
    554: 0.6,  # RTSP
    1433: 0.7,  # MSSQL
    3306: 0.7,  # MySQL
    3389: 0.6,  # RDP
    5432: 0.7,  # PostgreSQL
    8080: 0.5,  # HTTP alt
    9100: 0.5,  # Printer
    27017: 0.8,  # MongoDB
}

# Base risk for unknown ports.
_UNKNOWN_PORT_RISK = 0.2


def calculate_cve_score(max_cvss: float) -> float:
    """Normalize CVSS score to 0.0-1.0 risk factor.

    Input is highest CVSS score for this asset (0.0-10.0).
    """
    return min(max(max_cvss / 10.0, 0.0), 1.0)


def calculate_exposure_score(open_ports: list[int]) -> float:
    """Calculate exposure risk from open ports.

    Uses HIGH_RISK_PORTS weights.  Max of all port risks,
    with a multiplier that increases with port count.
    """
    if not open_ports:
        return 0.0

    # Get individual port risks
    port_risks = [HIGH_RISK_PORTS.get(p, _UNKNOWN_PORT_RISK) for p in open_ports]
    base = max(port_risks)

    # Port-count multiplier: more open ports = slightly higher risk
    # 1 port = 1.0x, 3 ports = 1.1x, 5+ ports = 1.2x, 10+ = 1.3x (capped)
    count = len(open_ports)
    if count >= 10:
        multiplier = 1.3
    elif count >= 5:
        multiplier = 1.2
    elif count >= 3:
        multiplier = 1.1
    else:
        multiplier = 1.0

    return min(base * multiplier, 1.0)


def calculate_classification_score(bigr_category: str) -> float:
    """Risk score based on BİGR category."""
    return CATEGORY_RISK.get(bigr_category, CATEGORY_RISK["unclassified"])


def calculate_age_score(first_seen: str | None, now: str | None = None) -> float:
    """Risk increases with time on network.

    >365 days = 1.0, >180 days = 0.7, >90 days = 0.5, >30 days = 0.3, else = 0.1
    """
    if first_seen is None:
        return 0.0

    try:
        fs = datetime.fromisoformat(first_seen)
        if fs.tzinfo is None:
            fs = fs.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return 0.0

    if now is not None:
        try:
            now_dt = datetime.fromisoformat(now)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            now_dt = datetime.now(timezone.utc)
    else:
        now_dt = datetime.now(timezone.utc)

    days = (now_dt - fs).days

    if days > 365:
        return 1.0
    if days > 180:
        return 0.7
    if days > 90:
        return 0.5
    if days > 30:
        return 0.3
    return 0.1


def calculate_change_score(change_count: int) -> float:
    """Risk from recent changes.  More changes = higher risk.

    >20 changes = 1.0, >10 = 0.7, >5 = 0.5, >0 = 0.3, else = 0.0
    """
    if change_count > 20:
        return 1.0
    if change_count > 10:
        return 0.7
    if change_count > 5:
        return 0.5
    if change_count > 0:
        return 0.3
    return 0.0


def calculate_risk(
    asset: dict,
    max_cvss: float = 0.0,
    change_count: int = 0,
) -> RiskProfile:
    """Calculate complete risk profile for an asset.

    Risk Score = sum(factor * weight for each factor) * 10

    Args:
        asset: Asset dict with ip, mac, hostname, vendor, bigr_category,
               confidence_score, open_ports, first_seen
        max_cvss: Highest CVSS score from vuln scan
        change_count: Number of changes in lookback period
    """
    ip = asset.get("ip", "")
    mac = asset.get("mac")
    hostname = asset.get("hostname")
    vendor = asset.get("vendor")
    bigr_category = asset.get("bigr_category", "unclassified")
    open_ports = asset.get("open_ports", [])
    first_seen = asset.get("first_seen")

    factors = RiskFactors(
        cve_score=calculate_cve_score(max_cvss),
        exposure_score=calculate_exposure_score(open_ports),
        classification_score=calculate_classification_score(bigr_category),
        age_score=calculate_age_score(first_seen),
        change_score=calculate_change_score(change_count),
    )

    # Weighted sum, scaled to 0-10
    raw_score = (
        factors.cve_score * WEIGHTS["cve"]
        + factors.exposure_score * WEIGHTS["exposure"]
        + factors.classification_score * WEIGHTS["classification"]
        + factors.age_score * WEIGHTS["age"]
        + factors.change_score * WEIGHTS["change"]
    ) * 10.0

    risk_score = round(min(max(raw_score, 0.0), 10.0), 2)
    risk_level = RiskProfile.level_from_score(risk_score)

    return RiskProfile(
        ip=ip,
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        bigr_category=bigr_category,
        risk_score=risk_score,
        risk_level=risk_level,
        factors=factors,
    )


def assess_network_risk(
    assets: list[dict],
    vuln_summaries: list[dict] | None = None,
    change_data: list[dict] | None = None,
) -> RiskReport:
    """Assess risk for entire network.

    Args:
        assets: All asset dicts
        vuln_summaries: Optional vulnerability scan results per asset
        change_data: Optional change counts per asset
    """
    if not assets:
        return RiskReport()

    # Build lookup dicts for vuln and change data
    vuln_by_ip: dict[str, dict] = {}
    if vuln_summaries:
        for v in vuln_summaries:
            vuln_by_ip[v.get("ip", "")] = v

    change_by_ip: dict[str, int] = {}
    if change_data:
        for c in change_data:
            change_by_ip[c.get("ip", "")] = c.get("change_count", 0)

    profiles: list[RiskProfile] = []
    for asset in assets:
        ip = asset.get("ip", "")
        vuln_info = vuln_by_ip.get(ip, {})
        max_cvss = vuln_info.get("max_cvss", 0.0)
        top_cve = vuln_info.get("top_cve")
        change_count = change_by_ip.get(ip, 0)

        profile = calculate_risk(asset, max_cvss=max_cvss, change_count=change_count)
        if top_cve:
            profile.top_cve = top_cve
        profiles.append(profile)

    # Aggregate stats
    scores = [p.risk_score for p in profiles]
    avg = sum(scores) / len(scores) if scores else 0.0
    mx = max(scores) if scores else 0.0

    critical = sum(1 for p in profiles if p.risk_level == "critical")
    high = sum(1 for p in profiles if p.risk_level == "high")
    medium = sum(1 for p in profiles if p.risk_level == "medium")
    low = sum(1 for p in profiles if p.risk_level == "low")

    return RiskReport(
        profiles=profiles,
        average_risk=round(avg, 2),
        max_risk=round(mx, 2),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
    )
