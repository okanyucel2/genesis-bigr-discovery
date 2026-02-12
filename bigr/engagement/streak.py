"""Safety Streak — Duolingo-style streak tracking for Kalkan Shield score."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


STREAK_THRESHOLD = 80  # Kalkan score >= 80 (green) keeps the streak alive


@dataclass
class StreakResult:
    current_streak_days: int
    longest_streak_days: int
    streak_broken: bool
    total_safe_days: int
    streak_broken_count: int


def calculate_streak(
    kalkan_score: float,
    current_streak: int,
    longest_streak: int,
    total_safe_days: int,
    streak_broken_count: int,
) -> StreakResult:
    """Calculate updated streak based on today's Kalkan score.

    If score >= STREAK_THRESHOLD (green), the streak continues.
    If score < STREAK_THRESHOLD, the streak is broken and resets to 0.
    """
    if kalkan_score >= STREAK_THRESHOLD:
        new_streak = current_streak + 1
        new_longest = max(longest_streak, new_streak)
        return StreakResult(
            current_streak_days=new_streak,
            longest_streak_days=new_longest,
            streak_broken=False,
            total_safe_days=total_safe_days + 1,
            streak_broken_count=streak_broken_count,
        )
    else:
        return StreakResult(
            current_streak_days=0,
            longest_streak_days=longest_streak,
            streak_broken=True,
            total_safe_days=total_safe_days,
            streak_broken_count=streak_broken_count + 1,
        )


# Milestone definitions
_MILESTONES = [
    (7, "fire", "Ilk Hafta"),
    (30, "shield", "Aylik Koruyucu"),
    (90, "star", "Ceyrek Sampiyonu"),
]


@dataclass
class Milestone:
    days_required: int
    badge: str
    title_tr: str


def get_milestone(days: int) -> Milestone | None:
    """Return the highest milestone achieved for the given streak days."""
    achieved = None
    for required, badge, title in _MILESTONES:
        if days >= required:
            achieved = Milestone(days_required=required, badge=badge, title_tr=title)
    return achieved


def get_next_milestone(days: int) -> dict | None:
    """Return the next milestone to achieve."""
    for required, badge, title in _MILESTONES:
        if days < required:
            return {
                "badge": badge,
                "title_tr": title,
                "days_required": required,
                "days_remaining": required - days,
            }
    return None
