"""Risk scoring data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskFactors:
    """Individual risk factor scores (each 0.0 - 1.0)."""

    cve_score: float = 0.0  # Highest CVSS / 10
    exposure_score: float = 0.0  # Open ports exposure level
    classification_score: float = 0.0  # BİGR category risk
    age_score: float = 0.0  # How long on network
    change_score: float = 0.0  # Recent change frequency

    def to_dict(self) -> dict:
        return {
            "cve_score": self.cve_score,
            "exposure_score": self.exposure_score,
            "classification_score": self.classification_score,
            "age_score": self.age_score,
            "change_score": self.change_score,
        }


@dataclass
class RiskProfile:
    """Complete risk assessment for a single asset."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    bigr_category: str = "unclassified"
    risk_score: float = 0.0  # 0.0 - 10.0
    risk_level: str = "low"  # "critical", "high", "medium", "low", "info"
    factors: RiskFactors = field(default_factory=RiskFactors)
    top_cve: str | None = None  # Highest CVSS CVE ID

    @staticmethod
    def level_from_score(score: float) -> str:
        if score >= 8.0:
            return "critical"
        if score >= 6.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 2.0:
            return "low"
        return "info"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "bigr_category": self.bigr_category,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "factors": self.factors.to_dict(),
            "top_cve": self.top_cve,
        }


@dataclass
class RiskReport:
    """Risk assessment for entire network."""

    profiles: list[RiskProfile] = field(default_factory=list)
    average_risk: float = 0.0
    max_risk: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    @property
    def top_risks(self) -> list[RiskProfile]:
        """Top 10 riskiest assets."""
        return sorted(self.profiles, key=lambda p: p.risk_score, reverse=True)[:10]

    def to_dict(self) -> dict:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "average_risk": self.average_risk,
            "max_risk": self.max_risk,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "top_risks": [p.to_dict() for p in self.top_risks],
        }
