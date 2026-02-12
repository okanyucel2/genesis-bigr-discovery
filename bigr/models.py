"""Core data models for BİGR Discovery."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


def normalize_mac(mac: str | None) -> str | None:
    """Normalize MAC address to consistent aa:bb:cc:dd:ee:ff format.

    Handles inconsistent formats like:
      cc:8:fa:6d:fc:59  → cc:08:fa:6d:fc:59
      6:11:e5:ea:68:5c  → 06:11:e5:ea:68:5c
      AA-BB-CC-DD-EE-FF → aa:bb:cc:dd:ee:ff
    """
    if not mac:
        return None
    mac = mac.lower().replace("-", ":")
    octets = mac.split(":")
    if len(octets) != 6:
        return mac  # Can't normalize, return as-is
    return ":".join(o.zfill(2) for o in octets)


def is_randomized_mac(mac: str | None) -> bool:
    """Check if MAC is locally administered (randomized by Apple/Android).

    The second least significant bit of the first octet indicates
    locally administered (LA) address. If set, the MAC is likely
    randomized for privacy.

    Examples of randomized: 3e:xx, ba:xx, 06:xx (where first octet & 0x02 != 0)
    """
    if not mac:
        return False
    mac = normalize_mac(mac) or mac
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


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


class SensitivityLevel(str, enum.Enum):
    FRAGILE = "fragile"
    CAUTIOUS = "cautious"
    SAFE = "safe"


_FRAGILE_HOSTNAME_PATTERNS = {"cam", "camera", "sensor", "thermostat"}
_FRAGILE_OS_KEYWORDS = {"embedded"}


def derive_sensitivity(
    category: BigrCategory | str,
    vendor: str | None,
    hostname: str | None,
    os_hint: str | None,
) -> SensitivityLevel:
    """Derive device sensitivity level for safe-mode scanning.

    - fragile: IoT + hostname contains cam/camera/sensor/thermostat OR os_hint contains embedded
    - cautious: IoT (all remaining, including printers)
    - safe: everything else
    """
    cat_value = category.value if isinstance(category, BigrCategory) else category
    if cat_value != "iot":
        return SensitivityLevel.SAFE

    # IoT device — check for fragile indicators
    hn = (hostname or "").lower()
    for pattern in _FRAGILE_HOSTNAME_PATTERNS:
        if pattern in hn:
            return SensitivityLevel.FRAGILE

    os_lower = (os_hint or "").lower()
    for keyword in _FRAGILE_OS_KEYWORDS:
        if keyword in os_lower:
            return SensitivityLevel.FRAGILE

    return SensitivityLevel.CAUTIOUS


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
    sensitivity_level: str | None = None
    friendly_name: str | None = None
    device_model: str | None = None
    device_manufacturer: str | None = None

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
            "sensitivity_level": self.sensitivity_level,
            "friendly_name": self.friendly_name,
            "device_model": self.device_model,
            "device_manufacturer": self.device_manufacturer,
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
