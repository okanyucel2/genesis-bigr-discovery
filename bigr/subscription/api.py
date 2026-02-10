"""Subscription API endpoints for BİGR Discovery pricing tiers.

Endpoints:
    GET  /api/subscription/plans       -- List all plans with features
    GET  /api/subscription/current     -- Current subscription for this device
    POST /api/subscription/activate    -- Activate a plan (mock payment)
    GET  /api/subscription/usage       -- AI usage stats for current period
    GET  /api/subscription/tier-access -- What AI tiers current plan allows
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.subscription.models import (
    ActivatePlanRequest,
    ActivatePlanResponse,
    PlanResponse,
    PlansListResponse,
    SubscriptionResponse,
    TierAccessResponse,
    UsageResponse,
)
from bigr.subscription.plans import get_all_plans, get_plan
from bigr.subscription.service import DEFAULT_DEVICE_ID, SubscriptionService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/subscription", tags=["subscription"])

# Module-level singleton -- single-user consumer product
_service: SubscriptionService | None = None


def _get_service() -> SubscriptionService:
    """Return (or create) the subscription service singleton."""
    global _service
    if _service is None:
        _service = SubscriptionService()
    return _service


def _plan_to_response(plan) -> PlanResponse:
    """Convert a PlanDefinition dataclass to a PlanResponse Pydantic model."""
    return PlanResponse(
        id=plan.id,
        name=plan.name,
        name_tr=plan.name_tr,
        price_usd=plan.price_usd,
        max_devices=plan.max_devices,
        ai_tiers=list(plan.ai_tiers),
        features=list(plan.features),
        features_tr=list(plan.features_tr),
    )


@router.get("/plans")
async def list_plans() -> PlansListResponse:
    """List all available subscription plans with features and pricing."""
    plans = get_all_plans()
    return PlansListResponse(
        plans=[_plan_to_response(p) for p in plans],
        total=len(plans),
    )


@router.get("/current")
async def get_current(
    device_id: str = DEFAULT_DEVICE_ID,
    db: AsyncSession = Depends(get_db),
) -> SubscriptionResponse:
    """Get the current subscription for a device.

    If no subscription exists, returns a free-tier subscription.
    """
    service = _get_service()
    plan, sub = await service.get_current_plan(db, device_id)

    return SubscriptionResponse(
        device_id=device_id,
        plan_id=plan.id,
        plan=_plan_to_response(plan),
        is_active=True if sub is None or sub.is_active == 1 else False,
        activated_at=sub.activated_at if sub else "never",
        expires_at=sub.expires_at if sub else None,
    )


@router.post("/activate")
async def activate_plan(
    body: ActivatePlanRequest,
    db: AsyncSession = Depends(get_db),
) -> ActivatePlanResponse:
    """Activate a subscription plan for a device.

    This is a mock activation (no real payment processing).
    Replaces any existing active subscription.
    """
    service = _get_service()
    device_id = body.device_id or DEFAULT_DEVICE_ID

    plan = get_plan(body.plan_id)
    if plan is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown plan: {body.plan_id}. Valid plans: free, nomad, family",
        )

    try:
        sub = await service.activate_plan(db, body.plan_id, device_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    plan_resp = _plan_to_response(plan)

    return ActivatePlanResponse(
        status="ok",
        message=f"Plan '{plan.name}' basariyla aktiflestirildi!",
        subscription=SubscriptionResponse(
            device_id=device_id,
            plan_id=plan.id,
            plan=plan_resp,
            is_active=True,
            activated_at=sub.activated_at,
            expires_at=sub.expires_at,
        ),
    )


@router.get("/usage")
async def get_usage(
    device_id: str = DEFAULT_DEVICE_ID,
    db: AsyncSession = Depends(get_db),
) -> UsageResponse:
    """Get AI usage statistics for the current billing period."""
    service = _get_service()
    usage = await service.get_usage(db, device_id)

    return UsageResponse(**usage)


@router.get("/tier-access")
async def get_tier_access(
    device_id: str = DEFAULT_DEVICE_ID,
    db: AsyncSession = Depends(get_db),
) -> TierAccessResponse:
    """Get what AI tiers the current plan allows.

    This is the key endpoint that the InferenceRouter should call
    to decide whether a user can access L1/L2 tiers.
    """
    service = _get_service()
    plan, _sub = await service.get_current_plan(db, device_id)

    allowed = service.get_allowed_tiers(plan.id)
    max_tier = service.get_max_tier(plan.id)

    return TierAccessResponse(
        plan_id=plan.id,
        allowed_tiers=allowed,
        max_tier=max_tier,
        can_use_l1="L1" in allowed,
        can_use_l2="L2" in allowed,
    )
