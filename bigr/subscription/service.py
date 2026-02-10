"""Subscription service -- manages plan activation, device limits, and usage tracking.

For the consumer MVP, subscriptions are keyed by device_id (the unique
device fingerprint generated during onboarding).  Payment is mocked --
no real Stripe integration yet.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.models_db import SubscriptionDB
from bigr.subscription.plans import PLANS, PlanDefinition, get_plan

logger = logging.getLogger(__name__)

# Default device ID for the single-user consumer product
DEFAULT_DEVICE_ID = "local-device-001"


class SubscriptionService:
    """Manages subscription state for devices.

    Methods are all async and accept a SQLAlchemy async session.
    """

    async def get_current_plan(
        self, db: AsyncSession, device_id: str = DEFAULT_DEVICE_ID
    ) -> tuple[PlanDefinition, SubscriptionDB | None]:
        """Get the current plan for a device.

        Returns a (PlanDefinition, SubscriptionDB | None) tuple.
        If no subscription exists, returns the free plan with None record.
        """
        stmt = (
            select(SubscriptionDB)
            .where(SubscriptionDB.device_id == device_id)
            .where(SubscriptionDB.is_active == 1)
        )
        result = await db.execute(stmt)
        sub = result.scalar_one_or_none()

        if sub is None:
            return PLANS["free"], None

        plan = get_plan(sub.plan_id)
        if plan is None:
            logger.warning(
                "Subscription %s has unknown plan_id=%s, defaulting to free",
                sub.id,
                sub.plan_id,
            )
            return PLANS["free"], sub

        # Check expiry
        if sub.expires_at:
            try:
                expires = datetime.fromisoformat(sub.expires_at)
                if expires < datetime.now(timezone.utc):
                    logger.info(
                        "Subscription %s expired at %s, returning free plan",
                        sub.id,
                        sub.expires_at,
                    )
                    return PLANS["free"], sub
            except ValueError:
                pass

        return plan, sub

    async def activate_plan(
        self,
        db: AsyncSession,
        plan_id: str,
        device_id: str = DEFAULT_DEVICE_ID,
    ) -> SubscriptionDB:
        """Activate a plan for a device.

        If the device already has an active subscription, it is deactivated
        and replaced with the new one.  No payment processing -- this is
        a mock for the MVP.

        Args:
            db: Async database session.
            plan_id: One of "free", "nomad", "family".
            device_id: Device fingerprint.

        Returns:
            The newly created SubscriptionDB record.

        Raises:
            ValueError: If plan_id is invalid.
        """
        plan = get_plan(plan_id)
        if plan is None:
            raise ValueError(f"Unknown plan: {plan_id}")

        # Deactivate existing subscription(s)
        stmt = (
            select(SubscriptionDB)
            .where(SubscriptionDB.device_id == device_id)
            .where(SubscriptionDB.is_active == 1)
        )
        result = await db.execute(stmt)
        existing = result.scalars().all()
        for old in existing:
            old.is_active = 0

        now = datetime.now(timezone.utc)

        # For paid plans, set 30-day expiry; free plan never expires
        expires_at: str | None = None
        if plan.price_usd > 0:
            expires_at = (now + timedelta(days=30)).isoformat()

        new_sub = SubscriptionDB(
            id=str(uuid.uuid4()),
            device_id=device_id,
            plan_id=plan_id,
            activated_at=now.isoformat(),
            expires_at=expires_at,
            is_active=1,
            stripe_customer_id=None,
        )
        db.add(new_sub)
        await db.commit()
        await db.refresh(new_sub)

        logger.info(
            "Activated plan %s for device %s (sub=%s)",
            plan_id,
            device_id,
            new_sub.id,
        )
        return new_sub

    async def get_usage(
        self, db: AsyncSession, device_id: str = DEFAULT_DEVICE_ID
    ) -> dict:
        """Get usage stats for the current billing period.

        Returns a dict with query counts and device info.
        Currently returns zeroes -- will be wired up to the InferenceRouter
        metrics once billing integration is live.
        """
        plan, sub = await self.get_current_plan(db, device_id)

        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        next_month = (period_start + timedelta(days=32)).replace(day=1)

        return {
            "device_id": device_id,
            "plan_id": plan.id,
            "ai_queries_l0": 0,
            "ai_queries_l1": 0,
            "ai_queries_l2": 0,
            "devices_active": 1,
            "devices_max": plan.max_devices,
            "period_start": period_start.isoformat(),
            "period_end": next_month.isoformat(),
        }

    async def check_device_limit(
        self, db: AsyncSession, device_id: str = DEFAULT_DEVICE_ID
    ) -> bool:
        """Check if the device can be added under the current plan's device limit.

        Returns True if within limits, False if at capacity.
        """
        plan, _sub = await self.get_current_plan(db, device_id)
        # For MVP: single device always passes. Multi-device support will
        # track registered devices in a separate table.
        return True

    def get_max_tier(self, plan_id: str) -> str:
        """Return the maximum AI tier allowed for a plan.

        Args:
            plan_id: One of "free", "nomad", "family".

        Returns:
            The highest tier string: "L0", "L1", or "L2".
        """
        plan = get_plan(plan_id)
        if plan is None:
            return "L0"
        if not plan.ai_tiers:
            return "L0"
        return plan.ai_tiers[-1]

    def get_allowed_tiers(self, plan_id: str) -> list[str]:
        """Return the list of allowed AI tiers for a plan.

        Args:
            plan_id: One of "free", "nomad", "family".

        Returns:
            List of tier strings, e.g. ["L0", "L1"].
        """
        plan = get_plan(plan_id)
        if plan is None:
            return ["L0"]
        return list(plan.ai_tiers) if plan.ai_tiers else ["L0"]
