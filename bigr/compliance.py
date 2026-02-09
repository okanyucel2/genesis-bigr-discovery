"""BİGR compliance scoring and metrics engine."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class ComplianceBreakdown:
    """Breakdown of asset classification quality."""

    total_assets: int = 0
    fully_classified: int = 0      # confidence >= 0.7
    partially_classified: int = 0  # 0.3 <= confidence < 0.7
    unclassified: int = 0          # confidence < 0.3
    manual_overrides: int = 0      # has manual_category set

    @property
    def compliance_score(self) -> float:
        """BİGR compliance percentage (0-100).

        Formula: (fully + manual_overrides + partially * 0.5) / total * 100
        Manual overrides count as fully classified.
        """
        if self.total_assets == 0:
            return 100.0  # No assets = compliant
        classified = self.fully_classified + self.manual_overrides
        partial = self.partially_classified
        return round((classified + partial * 0.5) / self.total_assets * 100, 1)

    @property
    def grade(self) -> str:
        """Letter grade based on compliance score."""
        score = self.compliance_score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


@dataclass
class CategoryDistribution:
    """Distribution of assets across BİGR categories."""

    ag_ve_sistemler: int = 0
    uygulamalar: int = 0
    iot: int = 0
    tasinabilir: int = 0
    unclassified: int = 0

    @property
    def total(self) -> int:
        return (
            self.ag_ve_sistemler
            + self.uygulamalar
            + self.iot
            + self.tasinabilir
            + self.unclassified
        )

    def percentages(self) -> dict[str, float]:
        """Return percentage for each category."""
        t = self.total
        if t == 0:
            return {
                k: 0.0
                for k in [
                    "ag_ve_sistemler",
                    "uygulamalar",
                    "iot",
                    "tasinabilir",
                    "unclassified",
                ]
            }
        return {
            "ag_ve_sistemler": round(self.ag_ve_sistemler / t * 100, 1),
            "uygulamalar": round(self.uygulamalar / t * 100, 1),
            "iot": round(self.iot / t * 100, 1),
            "tasinabilir": round(self.tasinabilir / t * 100, 1),
            "unclassified": round(self.unclassified / t * 100, 1),
        }

    def to_dict(self) -> dict:
        return {
            "counts": {
                "ag_ve_sistemler": self.ag_ve_sistemler,
                "uygulamalar": self.uygulamalar,
                "iot": self.iot,
                "tasinabilir": self.tasinabilir,
                "unclassified": self.unclassified,
            },
            "percentages": self.percentages(),
            "total": self.total,
        }


@dataclass
class SubnetCompliance:
    """Compliance metrics for a specific subnet."""

    cidr: str
    label: str = ""
    breakdown: ComplianceBreakdown = field(default_factory=ComplianceBreakdown)
    distribution: CategoryDistribution = field(default_factory=CategoryDistribution)


@dataclass
class ComplianceReport:
    """Full BİGR compliance report."""

    breakdown: ComplianceBreakdown
    distribution: CategoryDistribution
    subnet_compliance: list[SubnetCompliance] = field(default_factory=list)
    action_items: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "compliance_score": self.breakdown.compliance_score,
            "grade": self.breakdown.grade,
            "breakdown": {
                "total_assets": self.breakdown.total_assets,
                "fully_classified": self.breakdown.fully_classified,
                "partially_classified": self.breakdown.partially_classified,
                "unclassified": self.breakdown.unclassified,
                "manual_overrides": self.breakdown.manual_overrides,
            },
            "distribution": self.distribution.to_dict(),
            "subnet_compliance": [
                {
                    "cidr": sc.cidr,
                    "label": sc.label,
                    "score": sc.breakdown.compliance_score,
                    "grade": sc.breakdown.grade,
                }
                for sc in self.subnet_compliance
            ],
            "action_items": self.action_items,
        }


def calculate_compliance(assets: list[dict]) -> ComplianceReport:
    """Calculate BİGR compliance metrics from asset inventory.

    Args:
        assets: List of asset dicts (from get_all_assets or similar).
                Each dict should have: confidence_score, bigr_category,
                manual_category (optional), ip, hostname.

    Returns:
        ComplianceReport with breakdown, distribution, and action items.
    """
    breakdown = ComplianceBreakdown()
    distribution = CategoryDistribution()

    breakdown.total_assets = len(assets)

    for asset in assets:
        confidence = asset.get("confidence_score", 0.0)
        category = asset.get("bigr_category", "unclassified")
        manual = asset.get("manual_category")

        # Count manual overrides
        if manual:
            breakdown.manual_overrides += 1
        elif confidence >= 0.7:
            breakdown.fully_classified += 1
        elif confidence >= 0.3:
            breakdown.partially_classified += 1
        else:
            breakdown.unclassified += 1

        # Category distribution (use manual_category if set, else bigr_category)
        effective_category = manual if manual else category
        if effective_category == "ag_ve_sistemler":
            distribution.ag_ve_sistemler += 1
        elif effective_category == "uygulamalar":
            distribution.uygulamalar += 1
        elif effective_category == "iot":
            distribution.iot += 1
        elif effective_category == "tasinabilir":
            distribution.tasinabilir += 1
        else:
            distribution.unclassified += 1

    action_items = generate_action_items(assets)

    return ComplianceReport(
        breakdown=breakdown,
        distribution=distribution,
        action_items=action_items,
    )


def generate_action_items(assets: list[dict]) -> list[dict]:
    """Generate prioritized action items for improving compliance.

    Action types:
    - "classify": Unclassified assets that need attention
    - "review": Low-confidence assets that may be misclassified
    - "tag": Assets that could benefit from manual override

    Returns list of dicts: {"type": str, "priority": str, "ip": str, "reason": str}
    """
    items: list[dict] = []

    for asset in assets:
        confidence = asset.get("confidence_score", 0.0)
        category = asset.get("bigr_category", "unclassified")
        manual = asset.get("manual_category")
        ip = asset.get("ip", "unknown")

        # Skip assets with manual overrides
        if manual:
            continue

        if confidence < 0.3 or category == "unclassified":
            items.append({
                "type": "classify",
                "priority": "critical",
                "ip": ip,
                "reason": f"Unclassified asset (confidence: {confidence:.2f})",
            })
        elif confidence < 0.7:
            items.append({
                "type": "review",
                "priority": "normal",
                "ip": ip,
                "reason": f"Low confidence classification ({confidence:.2f})",
            })

    # Sort by priority: critical first, then high, then normal
    priority_order = {"critical": 0, "high": 1, "normal": 2}
    items.sort(key=lambda x: priority_order.get(x["priority"], 99))

    return items


def calculate_subnet_compliance(
    assets: list[dict], subnets: list[dict]
) -> list[SubnetCompliance]:
    """Calculate per-subnet compliance scores."""
    if not subnets:
        return []

    results: list[SubnetCompliance] = []

    for subnet_info in subnets:
        cidr = subnet_info["cidr"]
        label = subnet_info.get("label", "")

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        # Filter assets belonging to this subnet
        subnet_assets = []
        for asset in assets:
            asset_ip = asset.get("ip", "")
            asset_subnet = asset.get("subnet_cidr")

            # Prefer explicit subnet_cidr tag, otherwise check IP in range
            if asset_subnet:
                if asset_subnet == cidr:
                    subnet_assets.append(asset)
            else:
                try:
                    if ipaddress.ip_address(asset_ip) in network:
                        subnet_assets.append(asset)
                except ValueError:
                    pass

        # Calculate compliance for this subnet's assets
        sub_report = calculate_compliance(subnet_assets)
        results.append(
            SubnetCompliance(
                cidr=cidr,
                label=label,
                breakdown=sub_report.breakdown,
                distribution=sub_report.distribution,
            )
        )

    return results
