"""Core data models for BİGR Discovery."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class BigrCategory(str, enum.Enum):
    AG_VE_SISTEMLER = "ag_ve_sistemler"
    UYGULAMALAR = "uygulamalar"
    IOT = "iot"
    TASINABILIR = "tasinabilir"
    UNCLASSIFIED = "unclassified"

    @property
    def label_tr(self) -> str:
        labels = {
            "ag_ve_sistemler": "Ağ ve Sistemler",
            "uygulamalar": "Uygulamalar",
            "iot": "IoT",
            "tasinabilir": "Taşınabilir Cihazlar",
            "unclassified": "Sınıflandırılmamış",
        }
        return labels[self.value]


class ConfidenceLevel(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCLASSIFIED = "unclassified"

    @classmethod
    def from_score(cls, score: float) -> ConfidenceLevel:
        if score >= 0.7:
            return cls.HIGH
        if score >= 0.4:
            return cls.MEDIUM
        if score >= 0.3:
            return cls.LOW
        return cls.UNCLASSIFIED


class ScanMethod(str, enum.Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    HYBRID = "hybrid"


@dataclass
class Asset:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    open_ports: list[int] = field(default_factory=list)
    os_hint: str | None = None
    bigr_category: BigrCategory = BigrCategory.UNCLASSIFIED
    confidence_score: float = 0.0
    scan_method: ScanMethod = ScanMethod.PASSIVE
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_evidence: dict = field(default_factory=dict)

    @property
    def confidence_level(self) -> ConfidenceLevel:
        return ConfidenceLevel.from_score(self.confidence_score)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": self.open_ports,
            "os_hint": self.os_hint,
            "bigr_category": self.bigr_category.value,
            "bigr_category_tr": self.bigr_category.label_tr,
            "confidence_score": round(self.confidence_score, 4),
            "confidence_level": self.confidence_level.value,
            "scan_method": self.scan_method.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "raw_evidence": self.raw_evidence,
        }


@dataclass
class ScanResult:
    target: str
    scan_method: ScanMethod
    started_at: datetime
    completed_at: datetime | None = None
    assets: list[Asset] = field(default_factory=list)
    is_root: bool = False

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def category_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for asset in self.assets:
            key = asset.bigr_category.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_method": self.scan_method.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "is_root": self.is_root,
            "total_assets": len(self.assets),
            "category_summary": self.category_summary,
            "assets": [a.to_dict() for a in self.assets],
        }
