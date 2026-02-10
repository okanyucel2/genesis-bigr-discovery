"""Pydantic schemas for subscription API request/response models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PlanResponse(BaseModel):
    """A single plan's details for the pricing page."""

    id: str
    name: str
    name_tr: str
    price_usd: float
    max_devices: int
    ai_tiers: list[str]
    features: list[str]
    features_tr: list[str]


class PlansListResponse(BaseModel):
    """Response for GET /plans."""

    plans: list[PlanResponse]
    total: int


class SubscriptionResponse(BaseModel):
    """Current subscription state for a device."""

    device_id: str
    plan_id: str
    plan: PlanResponse
    is_active: bool
    activated_at: str
    expires_at: str | None = None


class ActivatePlanRequest(BaseModel):
    """Request body for POST /activate."""

    plan_id: str = Field(..., pattern="^(free|nomad|family)$")
    device_id: str | None = None  # Auto-detected if not provided


class ActivatePlanResponse(BaseModel):
    """Response for POST /activate."""

    status: str
    message: str
    subscription: SubscriptionResponse


class UsageResponse(BaseModel):
    """AI usage stats for the current billing period."""

    device_id: str
    plan_id: str
    ai_queries_l0: int = 0
    ai_queries_l1: int = 0
    ai_queries_l2: int = 0
    devices_active: int = 1
    devices_max: int = 1
    period_start: str
    period_end: str


class TierAccessResponse(BaseModel):
    """What AI tiers the current plan allows."""

    plan_id: str
    allowed_tiers: list[str]
    max_tier: str
    can_use_l1: bool
    can_use_l2: bool
