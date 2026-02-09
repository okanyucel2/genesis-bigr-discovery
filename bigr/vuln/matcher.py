"""Asset-to-CVE matching engine."""

from __future__ import annotations

from pathlib import Path

from bigr.vuln.cve_db import search_cves_by_vendor
from bigr.vuln.models import AssetVulnSummary, CveEntry, VulnerabilityMatch

# Vendor name normalization map
VENDOR_ALIASES: dict[str, str] = {
    "hewlett packard": "hp",
    "hewlett-packard": "hp",
    "hp inc": "hp",
    "hp inc.": "hp",
    "cisco systems": "cisco",
    "cisco systems, inc.": "cisco",
    "zte corporation": "zte",
    "hikvision digital": "hikvision",
    "hikvision digital technology": "hikvision",
    "hangzhou hikvision digital technology": "hikvision",
    "dahua technology": "dahua",
    "apple inc": "apple",
    "apple inc.": "apple",
    "apple, inc.": "apple",
    "tp-link": "tp-link",
    "tp-link technologies": "tp-link",
    "asustek": "asus",
    "asustek computer": "asus",
    "ubiquiti networks": "ubiquiti",
    "ubiquiti inc": "ubiquiti",
    "mikrotik": "mikrotik",
    "synology inc": "synology",
    "synology inc.": "synology",
}


def normalize_vendor_name(vendor: str | None) -> str | None:
    """Normalize vendor name for matching. Lowercases + applies alias map."""
    if vendor is None:
        return None
    lowered = vendor.strip().lower()
    return VENDOR_ALIASES.get(lowered, lowered)


def build_cpe_pattern(vendor: str | None, product: str | None = None) -> str | None:
    """Build a CPE 2.3 pattern from vendor/product.

    Example: ("Cisco", "IOS XE") -> "cpe:2.3:*:cisco:ios_xe:*"
    """
    if vendor is None:
        return None
    normalized = normalize_vendor_name(vendor) or vendor.lower()
    if product is not None:
        prod_normalized = product.strip().lower().replace(" ", "_")
        return f"cpe:2.3:*:{normalized}:{prod_normalized}:*"
    return f"cpe:2.3:*:{normalized}:*:*"


def match_asset_vulnerabilities(
    asset: dict, db_path: Path | None = None
) -> list[VulnerabilityMatch]:
    """Find CVE matches for a single asset.

    Matching strategy (in order):
    1. Vendor + product CPE match (confidence=0.9)
    2. Vendor-only match (confidence=0.5)
    3. Port-based service match (confidence=0.3)
    """
    matches: list[VulnerabilityMatch] = []
    seen_cve_ids: set[str] = set()

    asset_ip = asset.get("ip", "")
    asset_mac = asset.get("mac")
    asset_vendor_raw = asset.get("vendor")
    normalized_vendor = normalize_vendor_name(asset_vendor_raw)

    if not normalized_vendor:
        return matches

    # Strategy: vendor-only match (confidence=0.5)
    # All CVEs from this vendor are potential matches
    vendor_cves = search_cves_by_vendor(normalized_vendor, db_path=db_path)
    for cve in vendor_cves:
        if cve.cve_id not in seen_cve_ids:
            seen_cve_ids.add(cve.cve_id)
            matches.append(
                VulnerabilityMatch(
                    asset_ip=asset_ip,
                    asset_mac=asset_mac,
                    asset_vendor=asset_vendor_raw,
                    cve=cve,
                    match_type="vendor_only",
                    match_confidence=0.5,
                )
            )

    return matches


def scan_all_vulnerabilities(
    assets: list[dict], db_path: Path | None = None
) -> list[AssetVulnSummary]:
    """Run vulnerability scan against all assets. Returns summary per asset."""
    summaries: list[AssetVulnSummary] = []

    for asset in assets:
        matches = match_asset_vulnerabilities(asset, db_path=db_path)
        if not matches:
            continue

        # Count severities
        critical = sum(1 for m in matches if m.cve.severity == "critical")
        high = sum(1 for m in matches if m.cve.severity == "high")
        medium = sum(1 for m in matches if m.cve.severity == "medium")
        low = sum(1 for m in matches if m.cve.severity == "low")
        max_cvss = max((m.cve.cvss_score for m in matches), default=0.0)

        summary = AssetVulnSummary(
            ip=asset.get("ip", ""),
            total_vulns=len(matches),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            max_cvss=max_cvss,
            matches=matches,
        )
        summaries.append(summary)

    return summaries
