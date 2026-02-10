"""Plan definitions for BİGR Discovery subscription tiers.

Three tiers designed by the multi-agent Neural Council:
    - Free ($0): Local AI only, 1 device, basic scanning
    - Nomad ($4.99/mo): L0+L1, 3 devices, threat intel, email alerts
    - Family Shield ($9.99/mo): All tiers, 5 devices, priority support, Dead Man Switch
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PlanDefinition:
    """Immutable definition of a subscription plan."""

    id: str
    name: str
    name_tr: str
    price_usd: float
    max_devices: int
    ai_tiers: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    features_tr: list[str] = field(default_factory=list)


PLANS: dict[str, PlanDefinition] = {
    "free": PlanDefinition(
        id="free",
        name="Free",
        name_tr="Ucretsiz",
        price_usd=0.0,
        max_devices=1,
        ai_tiers=["L0"],
        features=[
            "Local AI scanning",
            "Basic network map",
            "1 device",
        ],
        features_tr=[
            "Yerel AI tarama",
            "Temel ag haritasi",
            "1 cihaz",
        ],
    ),
    "nomad": PlanDefinition(
        id="nomad",
        name="Nomad",
        name_tr="Gocebe",
        price_usd=4.99,
        max_devices=3,
        ai_tiers=["L0", "L1"],
        features=[
            "Cloud AI validation",
            "Threat intelligence",
            "3 devices",
            "Email alerts",
        ],
        features_tr=[
            "Bulut AI dogrulama",
            "Tehdit istihbarati",
            "3 cihaz",
            "E-posta bildirimleri",
        ],
    ),
    "family": PlanDefinition(
        id="family",
        name="Family Shield",
        name_tr="Aile Kalkani",
        price_usd=9.99,
        max_devices=5,
        ai_tiers=["L0", "L1", "L2"],
        features=[
            "Deep AI forensics",
            "Priority support",
            "5 devices",
            "Dead Man Switch",
            "Family dashboard",
        ],
        features_tr=[
            "Derin AI analiz",
            "Oncelikli destek",
            "5 cihaz",
            "Olu Adam Anahtari",
            "Aile paneli",
        ],
    ),
}


def get_plan(plan_id: str) -> PlanDefinition | None:
    """Look up a plan by ID. Returns None if not found."""
    return PLANS.get(plan_id)


def get_all_plans() -> list[PlanDefinition]:
    """Return all plans in display order (free -> nomad -> family)."""
    return [PLANS["free"], PLANS["nomad"], PLANS["family"]]
