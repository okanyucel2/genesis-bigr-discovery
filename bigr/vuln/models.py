"""Vulnerability and CVE data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CveEntry:
    """A CVE record from the vulnerability database."""

    cve_id: str  # "CVE-2024-12345"
    cvss_score: float  # 0.0 - 10.0
    severity: str  # "critical", "high", "medium", "low", "none"
    description: str
    affected_vendor: str  # "Cisco"
    affected_product: str  # "IOS XE"
    cpe: str | None = None  # "cpe:2.3:o:cisco:ios_xe:*"
    published: str | None = None
    fix_available: bool = False
    cisa_kev: bool = False  # In CISA Known Exploited Vulns list

    @staticmethod
    def severity_from_cvss(score: float) -> str:
        """Convert CVSS score to severity string."""
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "none"

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "description": self.description,
            "affected_vendor": self.affected_vendor,
            "affected_product": self.affected_product,
            "cpe": self.cpe,
            "published": self.published,
            "fix_available": self.fix_available,
            "cisa_kev": self.cisa_kev,
        }


@dataclass
class VulnerabilityMatch:
    """A matched vulnerability for a specific asset."""

    asset_ip: str
    asset_mac: str | None
    asset_vendor: str | None
    cve: CveEntry
    match_type: str  # "vendor_product", "vendor_only", "port_service", "banner"
    match_confidence: float  # 0.0-1.0

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "asset_ip": self.asset_ip,
            "asset_mac": self.asset_mac,
            "asset_vendor": self.asset_vendor,
            "cve": self.cve.to_dict(),
            "match_type": self.match_type,
            "match_confidence": self.match_confidence,
        }


@dataclass
class AssetVulnSummary:
    """Vulnerability summary for a single asset."""

    ip: str
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    max_cvss: float = 0.0
    matches: list[VulnerabilityMatch] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "ip": self.ip,
            "total_vulns": self.total_vulns,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "max_cvss": self.max_cvss,
            "matches": [m.to_dict() for m in self.matches],
        }
