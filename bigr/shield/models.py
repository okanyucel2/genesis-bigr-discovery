"""Shield data models."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


class ScanDepth(str, enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ShieldGrade(str, enum.Enum):
    A_PLUS = "A+"
    A = "A"
    B_PLUS = "B+"
    B = "B"
    C_PLUS = "C+"
    C = "C"
    D = "D"
    F = "F"

    @staticmethod
    def from_score(score: float) -> ShieldGrade:
        if score >= 95:
            return ShieldGrade.A_PLUS
        if score >= 90:
            return ShieldGrade.A
        if score >= 85:
            return ShieldGrade.B_PLUS
        if score >= 75:
            return ShieldGrade.B
        if score >= 70:
            return ShieldGrade.C_PLUS
        if score >= 60:
            return ShieldGrade.C
        if score >= 40:
            return ShieldGrade.D
        return ShieldGrade.F


@dataclass
class ShieldFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    module: str = ""  # "tls" | "ports" | "cve" | "headers" | "dns" | "creds" | "owasp"
    severity: FindingSeverity = FindingSeverity.INFO
    title: str = ""
    description: str = ""
    remediation: str = ""
    target_ip: str = ""
    target_port: int | None = None
    evidence: dict = field(default_factory=dict)
    attack_technique: str | None = None  # MITRE ATT&CK
    attack_tactic: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    cisa_kev: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "evidence": self.evidence,
            "attack_technique": self.attack_technique,
            "attack_tactic": self.attack_tactic,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "cisa_kev": self.cisa_kev,
        }


@dataclass
class ModuleScore:
    module: str
    score: float  # 0-100
    total_checks: int = 0
    passed_checks: int = 0
    findings_count: int = 0

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "score": round(self.score, 2),
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "findings_count": self.findings_count,
        }


@dataclass
class ShieldScan:
    id: str = field(default_factory=lambda: f"sh_{uuid.uuid4().hex[:8]}")
    target: str = ""
    target_type: str = "domain"  # "ip" | "domain" | "cidr"
    status: ScanStatus = ScanStatus.QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    shield_score: float | None = None
    grade: ShieldGrade | None = None
    scan_depth: ScanDepth = ScanDepth.QUICK
    modules_enabled: list[str] = field(default_factory=lambda: ["tls"])
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0
    findings: list[ShieldFinding] = field(default_factory=list)
    module_scores: dict[str, ModuleScore] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        severity_counts: dict[str, int] = {}
        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "id": self.id,
            "target": self.target,
            "target_type": self.target_type,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "shield_score": round(self.shield_score, 2) if self.shield_score is not None else None,
            "grade": self.grade.value if self.grade else None,
            "scan_depth": self.scan_depth.value,
            "modules_enabled": self.modules_enabled,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "warning_checks": self.warning_checks,
            "findings_count": len(self.findings),
            "findings_summary": severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "module_scores": {k: v.to_dict() for k, v in self.module_scores.items()},
        }


@dataclass
class ShieldPrediction:
    id: str = field(default_factory=lambda: f"sp_{uuid.uuid4().hex[:8]}")
    target: str = ""
    fingerprint: dict = field(default_factory=dict)
    predicted_score: float = 0.0
    confidence: float = 0.0
    likely_findings: list[dict] = field(default_factory=list)
    similar_targets_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified_by_scan: str | None = None
    prediction_accuracy: float | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "fingerprint": self.fingerprint,
            "predicted_score": round(self.predicted_score, 2),
            "confidence": round(self.confidence, 4),
            "likely_findings": self.likely_findings,
            "similar_targets_count": self.similar_targets_count,
            "created_at": self.created_at.isoformat(),
            "verified_by_scan": self.verified_by_scan,
            "prediction_accuracy": (
                round(self.prediction_accuracy, 4) if self.prediction_accuracy is not None else None
            ),
        }
