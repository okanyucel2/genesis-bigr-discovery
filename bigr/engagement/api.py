"""Engagement API — streak endpoints."""

from __future__ import annotations

import uuid
from datetime import date

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.core.models_db import SafetyStreakDB
from bigr.engagement.streak import get_milestone, get_next_milestone

router = APIRouter(prefix="/api/engagement", tags=["engagement"])


@router.get("/streak")
async def get_streak(
    subscription_id: str = "default",
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get safety streak for a subscription."""
    try:
        stmt = select(SafetyStreakDB).where(
            SafetyStreakDB.subscription_id == subscription_id
        )
        row = (await db.execute(stmt)).scalar_one_or_none()
    except Exception:
        row = None

    if row is None:
        # No streak data yet — return defaults
        return {
            "current_streak_days": 0,
            "longest_streak_days": 0,
            "total_safe_days": 0,
            "milestone": None,
            "next_milestone": get_next_milestone(0),
        }

    days = row.current_streak_days
    milestone = get_milestone(days)

    return {
        "current_streak_days": days,
        "longest_streak_days": row.longest_streak_days,
        "total_safe_days": row.total_safe_days,
        "milestone": (
            {
                "badge": milestone.badge,
                "title_tr": milestone.title_tr,
                "days_required": milestone.days_required,
            }
            if milestone
            else None
        ),
        "next_milestone": get_next_milestone(days),
    }
